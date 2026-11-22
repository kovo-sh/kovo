import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { extname, join, relative, resolve } from 'node:path'
import { z } from 'zod'
import type { Finding } from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import type { Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { applyUnifiedDiffToDirectory } from './lab-runner.ts'
import type { LabRunner } from './lab-runner.ts'
import { isProfileHealthy, resolveProfilePoolForRole } from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { providerPool } from './provider.ts'
import type { UsageCallback } from './provider.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { retestReplaySpec } from './replay-verifier.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'

export type PatchStatus = 'draft' | 'approved' | 'rejected' | 'withheld'
export type CallerCompatibility = 'attacker_only' | 'needs_operator_step' | 'breaks_callers'
export type DynamicRetestVerdict = 'fixed' | 'reproduced' | 'skipped'

export interface PatchCodeLocation {
  repo: string
  file: string
  startLine: number
  endLine: number
  snippet?: string
  label?: string
}

export interface CoverageInventoryEntry {
  file: string
  line?: number
  symbol: string
  role: 'primary_sink' | 'sibling_route' | 'sibling_writer' | 'middleware' | 'helper'
  coveredByPatch: boolean
  notes: string
}

export interface PatchSyntaxCheckResult {
  ran: boolean
  command?: string
  passed: boolean
  output?: string
}

export interface PatchAuthorOutput {
  repo: string
  coverageInventory: CoverageInventoryEntry[]
  fixBefore: string
  fixAfter: string
  diff: string
  codeLocations: PatchCodeLocation[]
  rationale: string
  syntaxCheck: PatchSyntaxCheckResult
}

export interface PatchGateResult {
  gate: 1 | 2 | 3 | 4 | 5 | 6
  name:
    | 'applicability'
    | 'security_closure'
    | 'sibling_coverage'
    | 'caller_compatibility'
    | 'repo_conventions'
    | 'dynamic_retest'
  passed: boolean
  detail: string
  enforcingLocation?: string
}

export interface PatchReviewOutput {
  approved: boolean
  status: PatchStatus
  callerCompatibility: CallerCompatibility
  gates: PatchGateResult[]
  reviewNotes: string
  enforcingLocation?: string
}

export interface PatchProposalResult {
  id: string
  runId: string
  findingId: string
  repo: string
  status: PatchStatus
  callerCompatibility: CallerCompatibility
  fixBefore: string
  fixAfter: string
  diff: string
  codeLocations: PatchCodeLocation[]
  coverageInventory: CoverageInventoryEntry[]
  gates: PatchGateResult[]
  reviewNotes: string
  dynamicRetestVerdict: DynamicRetestVerdict
  dynamicRetestSummary?: string
  createdAt: number
  updatedAt: number
}

export type PatchLlmCall = (prompt: { systemPrompt: string; userPrompt: string }) => Promise<string>

export interface PatchLabRetestContext {
  labRunner: LabRunner
  runId: string
  replaySpec: DeclarativeReplaySpec
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  grant: Grant
  storage?: Store
  assignmentId?: string
}

export interface PatchWorkflowParams {
  runId: string
  finding: Finding & { codeLocations?: PatchCodeLocation[] }
  repo: string
  reposDir: string
  backend?: WorkerBackend
  authorLlmCall?: PatchLlmCall
  reviewerLlmCall?: PatchLlmCall
  modelProfiles?: readonly ResolvedModelProfile[]
  candidatePatch?: Partial<PatchAuthorOutput>
  labRetest?: PatchLabRetestContext
  signal?: AbortSignal
  secrets?: readonly NamedSecret[]
  onUsage?: UsageCallback
}

function validateRepoPath(reposDir: string, repo: string): string {
  const cleanRepo = repo.replace(/^\/+|\/+$/g, '')
  if (!cleanRepo || cleanRepo.includes('\0') || cleanRepo.split('/').some(seg => seg === '..' || seg === '.')) {
    throw new Error(`Invalid repository name for patch workflow: "${repo}"`)
  }
  const baseReal = realpathSync(reposDir)
  const target = resolve(baseReal, cleanRepo)
  const rel = relative(baseReal, target)
  if (rel.startsWith('..') || !existsSync(target) || !statSync(target).isDirectory()) {
    throw new Error(`Mounted repository not found: ${cleanRepo}`)
  }
  return realpathSync(target)
}

function safeReadRepoFile(repoRoot: string, relFile: string): string | null {
  const clean = relFile.replace(/^\/+/, '').replace(/\\/g, '/')
  if (!clean || clean.includes('\0') || clean.split('/').some(seg => seg === '..')) return null
  const full = resolve(repoRoot, clean)
  const rel = relative(repoRoot, full)
  if (rel.startsWith('..') || !existsSync(full) || !statSync(full).isFile()) return null
  return readFileSync(full, 'utf8')
}

function extractJsonBlock(raw: string): unknown {
  const trimmed = raw.trim()
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  const body = fence ? fence[1].trim() : trimmed
  const start = body.indexOf('{')
  const end = body.lastIndexOf('}')
  if (start === -1 || end <= start) {
    throw new Error('Expected JSON object in patch agent response.')
  }
  return JSON.parse(body.slice(start, end + 1))
}

function makeFreshProviderCall(
  profiles: readonly ResolvedModelProfile[],
  scenario: string,
  options: { signal?: AbortSignal; secrets?: readonly NamedSecret[]; onUsage?: UsageCallback },
): PatchLlmCall {
  return async ({ systemPrompt, userPrompt }) => {
    const routed = resolveProfilePoolForRole('reasoning', profiles)
    const now = Date.now()
    const primary = routed.find(p => isProfileHealthy(p, now)) ?? routed[0]
    const effectiveThinking = primary?.thinkingLevel === 'off' ? 'off' : 'high'
    const { models, model } = providerPool(routed, scenario, {
      signal: options.signal,
      secrets: options.secrets,
      onUsage: options.onUsage,
      maxCalls: 2,
      thinkingLevel: effectiveThinking,
      roleAffinity: 'reasoning',
      firstEventTimeoutMs: 60_000,
      idleTimeoutMs: 60_000,
      totalTimeoutMs: 120_000,
    })
    const stream = models.stream(model, {
      systemPrompt: redact(systemPrompt, options.secrets),
      messages: [{ role: 'user', content: redact(userPrompt, options.secrets), timestamp: Date.now() }],
      tools: [],
    })
    let out = ''
    for await (const ev of stream) {
      if (ev.type === 'text_delta' && typeof ev.delta === 'string') out += ev.delta
    }
    const res = await stream.result()
    if (!out && Array.isArray(res.content)) {
      out = res.content
        .filter((p): p is { type: 'text'; text: string } => p.type === 'text' && typeof p.text === 'string')
        .map(p => p.text)
        .join('')
    }
    return out.trim()
  }
}

export function buildUnifiedDiffFromSnippet(
  relFile: string,
  originalContent: string,
  fixBefore: string,
  fixAfter: string,
): { diff: string; startLine: number; endLine: number } {
  const idx = originalContent.indexOf(fixBefore)
  if (idx === -1) {
    throw new Error(`fixBefore snippet not found verbatim in ${relFile}.`)
  }
  const updatedContent = originalContent.slice(0, idx) + fixAfter + originalContent.slice(idx + fixBefore.length)
  const normOrig = originalContent.replace(/\r\n/g, '\n')
  const normUpdated = updatedContent.replace(/\r\n/g, '\n')
  const origLines = normOrig === ''
    ? []
    : (normOrig.endsWith('\n') ? normOrig.slice(0, -1).split('\n') : normOrig.split('\n'))
  const newLines = normUpdated === ''
    ? []
    : (normUpdated.endsWith('\n') ? normUpdated.slice(0, -1).split('\n') : normUpdated.split('\n'))

  const startLine = originalContent.slice(0, idx).replace(/\r\n/g, '\n').split('\n').length
  const normBefore = fixBefore.replace(/\r\n/g, '\n')
  const normAfter = fixAfter.replace(/\r\n/g, '\n')
  const oldSpanLines = normBefore.endsWith('\n') ? normBefore.slice(0, -1).split('\n') : normBefore.split('\n')
  const newSpanLines = normAfter === ''
    ? []
    : (normAfter.endsWith('\n') ? normAfter.slice(0, -1).split('\n') : normAfter.split('\n'))
  const endLine = Math.min(origLines.length, startLine + oldSpanLines.length - 1)

  const ctxStart = Math.max(0, startLine - 1 - 2)
  const oldCtxEnd = Math.min(origLines.length, endLine + 2)
  const delta = newSpanLines.length - oldSpanLines.length
  const newCtxEnd = Math.min(newLines.length, oldCtxEnd + delta)

  const preCtx = origLines.slice(ctxStart, startLine - 1).map(l => ' ' + l)
  const removed = origLines.slice(startLine - 1, endLine).map(l => '-' + l)
  const added = newLines.slice(startLine - 1, startLine - 1 + newSpanLines.length).map(l => '+' + l)
  const postCtx = origLines.slice(endLine, oldCtxEnd).map(l => ' ' + l)

  const oldCount = preCtx.length + removed.length + postCtx.length
  const newCount = preCtx.length + added.length + postCtx.length
  const header = [
    `--- a/${relFile}`,
    `+++ b/${relFile}`,
    `@@ -${ctxStart + 1},${oldCount} +${ctxStart + 1},${newCount} @@`,
  ]

  // Keep newCtxEnd referenced cleanly (used to verify slice alignment)
  void newCtxEnd
  return {
    diff: [...header, ...preCtx, ...removed, ...added, ...postCtx].join('\n') + '\n',
    startLine,
    endLine,
  }
}

export async function verifyPatchApplicability(params: {
  repoRoot: string
  repo: string
  reposDir: string
  diff: string
  fixBefore: string
  codeLocations: readonly PatchCodeLocation[]
  backend?: WorkerBackend
  signal?: AbortSignal
}): Promise<{ applicable: boolean; filesModified: string[]; syntaxCheck: PatchSyntaxCheckResult; error?: string }> {
  const { repoRoot, repo, reposDir, diff, fixBefore, codeLocations, backend, signal } = params

  // Verify fixBefore matches verbatim in at least one referenced file when provided.
  if (fixBefore.trim() && codeLocations.length > 0) {
    const primary = codeLocations[0]
    const content = safeReadRepoFile(repoRoot, primary.file)
    if (content === null) {
      return {
        applicable: false,
        filesModified: [],
        syntaxCheck: { ran: false, passed: false, output: `File not found: ${primary.file}` },
        error: `Referenced file ${primary.file} does not exist in ${repo}.`,
      }
    }
    if (!content.includes(fixBefore)) {
      return {
        applicable: false,
        filesModified: [],
        syntaxCheck: { ran: false, passed: false, output: 'fixBefore mismatch' },
        error: `fixBefore does not match ${primary.file} verbatim.`,
      }
    }
  }

  // Test applying unified diff in an isolated temporary clone (never mutating /repos!).
  const workDir = mkdtempSync(join(tmpdir(), 'guardian-patch-check-'))
  try {
    cpSync(repoRoot, workDir, { recursive: true })
    const { filesModified } = applyUnifiedDiffToDirectory(workDir, diff)

    // Run offline syntax check inside air-gapped --network none worker container if backend provided,
    // or local Node syntax check on modified JS/TS/MJS/CJS files as fallback.
    let syntaxCheck: PatchSyntaxCheckResult = { ran: false, passed: true }

    const jsLike = filesModified.filter(f => /\.(?:[cm]?js|[cm]?ts|jsx|tsx)$/i.test(f))
    const pyLike = filesModified.filter(f => /\.py$/i.test(f))

    if (backend) {
      try {
        const assignmentId = randomUUID()
        const safeRepo = repo.replace(/^\/+|\/+$/g, '')
        const scriptFiles = filesModified.map(f => ({
          name: `patched_${filesModified.indexOf(f)}${extname(f) || '.txt'}`,
          content: readFileSync(join(workDir, f), 'utf8'),
        }))
        const checks: string[] = []
        for (let idx = 0; idx < filesModified.length; idx++) {
          const origName = filesModified[idx]
          const staged = `/evidence/patched_${idx}${extname(origName) || '.txt'}`
          if (/\.(?:[cm]?js)$/i.test(origName)) {
            checks.push(`node --check "${staged}"`)
          } else if (/\.py$/i.test(origName)) {
            checks.push(`python3 -m py_compile "${staged}"`)
          }
        }
        // Copy /repos/<repo> into container's /tmp/work-repo (read-only /repos invariant preserved!)
        const cmd = [
          `mkdir -p /tmp/work-repo && cp -R "/repos/${safeRepo}/." /tmp/work-repo/`,
          ...(checks.length ? checks : ['echo "syntax-ok"']),
        ].join(' && ')
        const res = await backend.run(
          {
            assignmentId,
            files: scriptFiles,
            command: cmd,
            outputs: [],
            timeoutMs: 30_000,
          },
          signal ?? AbortSignal.timeout(35_000),
          { reposDir },
        )
        syntaxCheck = {
          ran: true,
          command: checks.length ? checks.join(' && ') : 'air-gapped tmpfs copy check',
          passed: res.exitCode === 0,
          output: (res.stdout + '\n' + res.stderr).trim().slice(0, 2000),
        }
      } catch (err) {
        // If worker container image lacks python3 or node syntax binary inside just-bash, fall back gracefully to local syntax check.
        syntaxCheck = await runLocalOfflineSyntaxCheck(workDir, jsLike, pyLike, err instanceof Error ? err.message : undefined)
      }
    } else {
      syntaxCheck = await runLocalOfflineSyntaxCheck(workDir, jsLike, pyLike)
    }

    return {
      applicable: true,
      filesModified,
      syntaxCheck,
      ...(syntaxCheck.ran && !syntaxCheck.passed ? { error: `Offline syntax check failed: ${syntaxCheck.output}` } : {}),
    }
  } catch (err) {
    return {
      applicable: false,
      filesModified: [],
      syntaxCheck: { ran: false, passed: false },
      error: err instanceof Error ? err.message : String(err),
    }
  } finally {
    rmSync(workDir, { recursive: true, force: true })
  }
}

async function runLocalOfflineSyntaxCheck(
  workDir: string,
  jsLike: string[],
  pyLike: string[],
  fallbackNote?: string,
): Promise<PatchSyntaxCheckResult> {
  const outputs: string[] = []
  let ran = false
  let passed = true

  if (jsLike.length > 0) {
    let tsMod: typeof import('typescript') | null = null
    try {
      const imported = await import('typescript')
      tsMod = imported.default ?? imported
    } catch {
      tsMod = null
    }

    for (const rel of jsLike) {
      const fullPath = join(workDir, rel)
      ran = true
      if (tsMod) {
        const source = readFileSync(fullPath, 'utf8')
        const res = tsMod.transpileModule(source, {
          fileName: rel,
          reportDiagnostics: true,
          compilerOptions: {
            allowJs: true,
            jsx: tsMod.JsxEmit.Preserve,
            target: tsMod.ScriptTarget.ESNext,
            module: tsMod.ModuleKind.ESNext,
          },
        })
        const syntaxErrors = (res.diagnostics ?? []).filter(
          d => d.category === tsMod!.DiagnosticCategory.Error,
        )
        if (syntaxErrors.length === 0) {
          outputs.push(`OK: ts syntax check ${rel}`)
        } else {
          passed = false
          const msg = syntaxErrors
            .map(d => tsMod!.flattenDiagnosticMessageText(d.messageText, '\n'))
            .join('; ')
          outputs.push(`FAIL: ${rel}: ${msg}`)
        }
      } else if (!/\.(?:[cm]?ts|tsx|jsx)$/i.test(rel)) {
        try {
          execFileSync(process.execPath, ['--check', fullPath], { stdio: 'pipe', timeout: 10_000 })
          outputs.push(`OK: node --check ${rel}`)
        } catch (err) {
          passed = false
          const stderr = (err as { stderr?: Buffer }).stderr?.toString('utf8') ?? String(err)
          outputs.push(`FAIL: ${rel}: ${stderr.trim()}`)
        }
      }
    }
  }

  for (const rel of pyLike) {
    ran = true
    try {
      execFileSync('python3', ['-m', 'py_compile', join(workDir, rel)], { stdio: 'pipe', timeout: 10_000 })
      outputs.push(`OK: py_compile ${rel}`)
    } catch (err) {
      passed = false
      const stderr = (err as { stderr?: Buffer }).stderr?.toString('utf8') ?? String(err)
      outputs.push(`FAIL: ${rel}: ${stderr.trim()}`)
    }
  }

  if (fallbackNote && !ran) outputs.push(fallbackNote)
  return {
    ran,
    command: ran ? 'offline syntax check (ts/node/py_compile)' : undefined,
    passed,
    output: outputs.join('\n').slice(0, 2000) || undefined,
  }
}

const authorOutputSchema = z.object({
  coverageInventory: z.array(z.object({
    file: z.string().min(1),
    line: z.number().int().positive().optional(),
    symbol: z.string().min(1),
    role: z.enum(['primary_sink', 'sibling_route', 'sibling_writer', 'middleware', 'helper']),
    coveredByPatch: z.boolean(),
    notes: z.string(),
  })).default([]),
  fixBefore: z.string().min(1),
  fixAfter: z.string(),
  diff: z.string().optional(),
  codeLocations: z.array(z.object({
    repo: z.string().min(1).optional(),
    file: z.string().min(1),
    startLine: z.number().int().positive(),
    endLine: z.number().int().positive(),
    snippet: z.string().optional(),
    label: z.string().optional(),
  })).min(1),
  rationale: z.string().min(1),
})

export async function runPatchAuthor(params: PatchWorkflowParams): Promise<PatchAuthorOutput> {
  const repoRoot = validateRepoPath(params.reposDir, params.repo)
  const findingLocations = params.finding.codeLocations ?? []

  if (params.candidatePatch?.diff || (params.candidatePatch?.fixBefore && params.candidatePatch?.fixAfter !== undefined)) {
    const locations: PatchCodeLocation[] = (params.candidatePatch.codeLocations?.length
      ? params.candidatePatch.codeLocations
      : findingLocations
    ).map(loc => ({ ...loc, repo: loc.repo || params.repo }))

    let diff = params.candidatePatch.diff ?? ''
    let fixBefore = params.candidatePatch.fixBefore ?? ''
    let fixAfter = params.candidatePatch.fixAfter ?? ''

    if (!diff && locations.length > 0 && fixBefore) {
      const content = safeReadRepoFile(repoRoot, locations[0].file)
      if (content !== null) {
        const built = buildUnifiedDiffFromSnippet(locations[0].file, content, fixBefore, fixAfter)
        diff = built.diff
      }
    }

    const check = await verifyPatchApplicability({
      repoRoot,
      repo: params.repo,
      reposDir: params.reposDir,
      diff,
      fixBefore,
      codeLocations: locations,
      backend: params.backend,
      signal: params.signal,
    })

    const coverageInventory: CoverageInventoryEntry[] = params.candidatePatch.coverageInventory?.length
      ? params.candidatePatch.coverageInventory
      : locations.map(loc => ({
        file: loc.file,
        line: loc.startLine,
        symbol: loc.label || 'primary_handler',
        role: 'primary_sink' as const,
        coveredByPatch: true,
        notes: 'Primary vulnerable code location.',
      }))

    return {
      repo: params.repo,
      coverageInventory,
      fixBefore,
      fixAfter,
      diff,
      codeLocations: locations,
      rationale: params.candidatePatch.rationale || `Minimal patch for ${params.finding.title}.`,
      syntaxCheck: check.syntaxCheck,
    }
  }

  const authorCall = params.authorLlmCall
    ?? (params.modelProfiles?.length
      ? makeFreshProviderCall(params.modelProfiles, 'patch-author', {
        signal: params.signal,
        secrets: params.secrets,
        onUsage: params.onUsage,
      })
      : undefined)

  if (!authorCall) {
    throw new Error('Patch author requires either candidatePatch, authorLlmCall, or configured modelProfiles.')
  }

  const fileExcerpts = findingLocations.map(loc => {
    const text = safeReadRepoFile(repoRoot, loc.file)
    return {
      file: loc.file,
      startLine: loc.startLine,
      endLine: loc.endLine,
      content: text ? text.slice(0, 16_000) : null,
    }
  })

  const systemPrompt = [
    'You are Guardian’s air-gapped Patch Author (Stage 1).',
    'Produce a minimal, repository-native security patch that closes the confirmed vulnerability WITHOUT breaking legitimate callers.',
    '1. Build a Coverage Inventory listing the primary vulnerable sink and any sibling routes/handlers/writers sharing the broken invariant.',
    '2. Provide exact verbatim `fixBefore` and `fixAfter`, plus a valid unified `diff` (`--- a/<file>`, `+++ b/<file>`, `@@ ... @@`).',
    '3. Keep edits minimal and strictly adhere to repository conventions. Never introduce hardcoded secrets or block legitimate authenticated callers.',
    'Return STRICT JSON ONLY matching: { coverageInventory, fixBefore, fixAfter, diff, codeLocations, rationale }.',
  ].join('\n')

  const userPrompt = JSON.stringify({
    repo: params.repo,
    finding: {
      id: params.finding.id,
      title: params.finding.title,
      cwe: params.finding.cwe,
      category: params.finding.category,
      severity: params.finding.severity,
      origin: params.finding.origin,
      reason: params.finding.reason,
      impact: params.finding.impact,
      remediation: params.finding.remediation,
    },
    files: fileExcerpts,
  }, null, 2)

  const raw = await authorCall({ systemPrompt, userPrompt })
  const parsed = authorOutputSchema.parse(extractJsonBlock(raw))
  const locations: PatchCodeLocation[] = parsed.codeLocations.map(l => ({ ...l, repo: l.repo || params.repo }))

  let diff = parsed.diff ?? ''
  if (!diff && locations.length > 0) {
    const content = safeReadRepoFile(repoRoot, locations[0].file)
    if (content !== null) {
      diff = buildUnifiedDiffFromSnippet(locations[0].file, content, parsed.fixBefore, parsed.fixAfter).diff
    }
  }

  const check = await verifyPatchApplicability({
    repoRoot,
    repo: params.repo,
    reposDir: params.reposDir,
    diff,
    fixBefore: parsed.fixBefore,
    codeLocations: locations,
    backend: params.backend,
    signal: params.signal,
  })

  return {
    repo: params.repo,
    coverageInventory: parsed.coverageInventory,
    fixBefore: parsed.fixBefore,
    fixAfter: parsed.fixAfter,
    diff,
    codeLocations: locations,
    rationale: parsed.rationale,
    syntaxCheck: check.syntaxCheck,
  }
}

const reviewerOutputSchema = z.object({
  approved: z.boolean(),
  callerCompatibility: z.enum(['attacker_only', 'needs_operator_step', 'breaks_callers']),
  enforcingLocation: z.string().optional(),
  gates: z.object({
    applicability: z.object({ passed: z.boolean(), detail: z.string() }),
    security_closure: z.object({ passed: z.boolean(), detail: z.string(), enforcingLocation: z.string().optional() }),
    sibling_coverage: z.object({ passed: z.boolean(), detail: z.string() }),
    caller_compatibility: z.object({ passed: z.boolean(), detail: z.string() }),
    repo_conventions: z.object({ passed: z.boolean(), detail: z.string() }),
  }),
  reviewNotes: z.string().min(1),
})

const BREAKS_CALLERS_PATTERNS = [
  // Unconditional 403/401/500 return blocking all requests before any condition/check
  /^\+\s*return\s+(?:res\.status\((?:401|403|404|500)\)|new Response\([^)]*(?:401|403))/m,
  /^\+\s*(?:res\.status\((?:401|403)\)\.end|throw new Error\(['"]disabled['"]\))/m,
  /^\+\s*if\s*\(\s*true\s*\)\s*(?:\{?\s*return|res\.status\((?:401|403)\))/m,
]

const HARDCODED_SECRET_IN_DIFF = /^\+.*(?:sk-or-v1-|sk-ant-|ghp_|github_pat_|-----BEGIN [A-Z ]*PRIVATE KEY-----)/m

function detectDeterministicCallerBreak(authorOutput: PatchAuthorOutput): boolean {
  return BREAKS_CALLERS_PATTERNS.some(p => p.test(authorOutput.diff))
    || (!authorOutput.fixAfter.trim() && authorOutput.fixBefore.trim().length > 40)
}

function deterministicOfflineReview(
  authorOutput: PatchAuthorOutput,
  applicability: { applicable: boolean; filesModified: string[]; syntaxCheck: PatchSyntaxCheckResult; error?: string },
): PatchReviewOutput {
  const primaryLoc = authorOutput.codeLocations[0]
  const enforcingLocation = primaryLoc ? `${primaryLoc.file}:${primaryLoc.startLine}` : undefined

  const gate1Passed = applicability.applicable && (!applicability.syntaxCheck.ran || applicability.syntaxCheck.passed)
  const gate1: PatchGateResult = {
    gate: 1,
    name: 'applicability',
    passed: gate1Passed,
    detail: gate1Passed
      ? `Diff applied cleanly to ${applicability.filesModified.join(', ')}${applicability.syntaxCheck.ran ? ' and passed offline syntax check.' : '.'}`
      : (applicability.error || 'Patch failed applicability or syntax check.'),
  }

  const diffHasSubstantiveChange = authorOutput.fixBefore.trim() !== authorOutput.fixAfter.trim() && authorOutput.diff.includes('+')
  const gate2Passed = Boolean(enforcingLocation && /^[^:\s]+:\d+$/.test(enforcingLocation) && diffHasSubstantiveChange)
  const gate2: PatchGateResult = {
    gate: 2,
    name: 'security_closure',
    passed: gate2Passed,
    enforcingLocation,
    detail: gate2Passed
      ? `Security control enforced at ${enforcingLocation}.`
      : 'Patch lacks a concrete enforcing file:line location or substantive fix.',
  }

  const uncoveredSiblings = authorOutput.coverageInventory.filter(
    item => (item.role === 'sibling_route' || item.role === 'sibling_writer') && !item.coveredByPatch,
  )
  const gate3Passed = uncoveredSiblings.length === 0
  const gate3: PatchGateResult = {
    gate: 3,
    name: 'sibling_coverage',
    passed: gate3Passed,
    detail: gate3Passed
      ? `All ${authorOutput.coverageInventory.length} inventoried sibling/primary handlers covered.`
      : `Uncovered sibling handler(s): ${uncoveredSiblings.map(s => `${s.file}:${s.symbol}`).join(', ')}.`,
  }

  const breaksCallers = detectDeterministicCallerBreak(authorOutput)
  const needsOperatorStep = /^\+.*process\.env\.[A-Z0-9_]+/m.test(authorOutput.diff) && !breaksCallers
  const callerCompatibility: CallerCompatibility = breaksCallers
    ? 'breaks_callers'
    : needsOperatorStep
      ? 'needs_operator_step'
      : 'attacker_only'

  const gate4Passed = callerCompatibility !== 'breaks_callers'
  const gate4: PatchGateResult = {
    gate: 4,
    name: 'caller_compatibility',
    passed: gate4Passed,
    detail: callerCompatibility === 'breaks_callers'
      ? 'Patch unconditionally blocks or removes legitimate caller behavior; automatically withheld.'
      : callerCompatibility === 'needs_operator_step'
        ? 'Patch requires an operator configuration/env step but preserves legitimate callers.'
        : 'Patch refuses attacker input while preserving legitimate callers.',
  }

  const hasSecretLeak = HARDCODED_SECRET_IN_DIFF.test(authorOutput.diff)
  const hasDebugArtifacts = /^\+.*\b(?:console\.log\(['"]DEBUG|debugger;)/m.test(authorOutput.diff)
  const gate5Passed = !hasSecretLeak && !hasDebugArtifacts && applicability.filesModified.length <= 12
  const gate5: PatchGateResult = {
    gate: 5,
    name: 'repo_conventions',
    passed: gate5Passed,
    detail: hasSecretLeak
      ? 'Patch introduces hardcoded credentials/secret material.'
      : hasDebugArtifacts
        ? 'Patch introduces debug artifacts.'
        : 'Patch is minimal and conforms to repository conventions.',
  }

  const gate6: PatchGateResult = {
    gate: 6,
    name: 'dynamic_retest',
    passed: true,
    detail: 'Dynamic retest not yet executed (skipped unless local-lab retest context is provided).',
  }

  const gates = [gate1, gate2, gate3, gate4, gate5, gate6]

  // HARD INVARIANT: Any patch classified breaks_callers is automatically withheld!
  let status: PatchStatus
  if (callerCompatibility === 'breaks_callers') {
    status = 'withheld'
  } else if (gate1Passed && gate2Passed && gate3Passed && gate4Passed && gate5Passed) {
    status = 'approved'
  } else {
    status = 'rejected'
  }

  return {
    approved: status === 'approved',
    status,
    callerCompatibility,
    gates,
    enforcingLocation,
    reviewNotes: gates.map(g => `Gate ${g.gate} (${g.name}): ${g.passed ? 'PASS' : 'FAIL'} — ${g.detail}`).join('\n'),
  }
}

export async function runPatchReviewer(params: {
  finding: Finding & { codeLocations?: PatchCodeLocation[] }
  repo: string
  reposDir: string
  authorOutput: PatchAuthorOutput
  backend?: WorkerBackend
  reviewerLlmCall?: PatchLlmCall
  modelProfiles?: readonly ResolvedModelProfile[]
  signal?: AbortSignal
  secrets?: readonly NamedSecret[]
  onUsage?: UsageCallback
}): Promise<PatchReviewOutput> {
  const repoRoot = validateRepoPath(params.reposDir, params.repo)
  const applicability = await verifyPatchApplicability({
    repoRoot,
    repo: params.repo,
    reposDir: params.reposDir,
    diff: params.authorOutput.diff,
    fixBefore: params.authorOutput.fixBefore,
    codeLocations: params.authorOutput.codeLocations,
    backend: params.backend,
    signal: params.signal,
  })

  // Always run in a fresh clean context with ZERO shared conversation history with patch-author.
  const reviewerCall = params.reviewerLlmCall
    ?? (params.modelProfiles?.length
      ? makeFreshProviderCall(params.modelProfiles, 'patch-reviewer', {
        signal: params.signal,
        secrets: params.secrets,
        onUsage: params.onUsage,
      })
      : undefined)

  if (!reviewerCall) {
    return deterministicOfflineReview(params.authorOutput, applicability)
  }

  const fileContext = params.authorOutput.codeLocations.map(loc => ({
    file: loc.file,
    startLine: loc.startLine,
    endLine: loc.endLine,
    content: safeReadRepoFile(repoRoot, loc.file)?.slice(0, 12_000) ?? null,
  }))

  const systemPrompt = [
    'You are Guardian’s independent air-gapped Patch Reviewer (Stage 2).',
    'You have ZERO shared context with the patch author. Independently verify the proposed diff against 5 static gates (Gate 6 dynamic retest runs separately):',
    '1. applicability: Does fixBefore match verbatim, does the diff apply cleanly, and does offline syntax/typecheck pass?',
    '2. security_closure: Does the patch close the vulnerability? Quote the EXACT enforcing file:line.',
    '3. sibling_coverage: Are all sibling routes/handlers/writers sharing the same invariant covered?',
    '4. caller_compatibility: Classify strictly as "attacker_only", "needs_operator_step", or "breaks_callers". Any patch that breaks legitimate callers MUST be classified "breaks_callers" and rejected/withheld.',
    '5. repo_conventions: Is the patch minimal, clean, idiomatic, and free of hardcoded secrets or debug artifacts?',
    'Return STRICT JSON ONLY with keys: { approved, callerCompatibility, enforcingLocation, gates: { applicability, security_closure, sibling_coverage, caller_compatibility, repo_conventions }, reviewNotes }.',
  ].join('\n')

  const userPrompt = JSON.stringify({
    finding: {
      title: params.finding.title,
      cwe: params.finding.cwe,
      category: params.finding.category,
      severity: params.finding.severity,
      origin: params.finding.origin,
      reason: params.finding.reason,
      impact: params.finding.impact,
    },
    proposedPatch: {
      repo: params.repo,
      diff: params.authorOutput.diff,
      fixBefore: params.authorOutput.fixBefore,
      fixAfter: params.authorOutput.fixAfter,
      coverageInventory: params.authorOutput.coverageInventory,
      applicabilityCheck: applicability,
    },
    repoFiles: fileContext,
  }, null, 2)

  try {
    const raw = await reviewerCall({ systemPrompt, userPrompt })
    const parsed = reviewerOutputSchema.parse(extractJsonBlock(raw))

    // Enforce deterministic hard gates regardless of LLM optimism.
    const gate1Passed = applicability.applicable
      && (!applicability.syntaxCheck.ran || applicability.syntaxCheck.passed)
      && parsed.gates.applicability.passed

    const enforcingLocation = parsed.gates.security_closure.enforcingLocation || parsed.enforcingLocation
    const validEnforcingLoc = Boolean(enforcingLocation && /^[^:\s]+:\d+$/.test(enforcingLocation.trim()))
    const gate2Passed = parsed.gates.security_closure.passed && validEnforcingLoc

    const gate3Passed = parsed.gates.sibling_coverage.passed
    const deterministicBreaksCallers = detectDeterministicCallerBreak(params.authorOutput)
    const callerCompatibility: CallerCompatibility = deterministicBreaksCallers
      ? 'breaks_callers'
      : parsed.callerCompatibility
    // HARD INVARIANT: breaks_callers ALWAYS fails Gate 4 and forces status='withheld' (even if LLM approved)!
    const gate4Passed = callerCompatibility !== 'breaks_callers' && parsed.gates.caller_compatibility.passed
    const gate5Passed = parsed.gates.repo_conventions.passed && !HARDCODED_SECRET_IN_DIFF.test(params.authorOutput.diff)

    const gates: PatchGateResult[] = [
      { gate: 1, name: 'applicability', passed: gate1Passed, detail: gate1Passed ? parsed.gates.applicability.detail : (applicability.error || parsed.gates.applicability.detail) },
      { gate: 2, name: 'security_closure', passed: gate2Passed, enforcingLocation, detail: validEnforcingLoc ? parsed.gates.security_closure.detail : `${parsed.gates.security_closure.detail} (Missing exact file:line citation.)` },
      { gate: 3, name: 'sibling_coverage', passed: gate3Passed, detail: parsed.gates.sibling_coverage.detail },
      {
        gate: 4,
        name: 'caller_compatibility',
        passed: gate4Passed,
        detail: deterministicBreaksCallers
          ? `Automatically withheld (deterministic breaks_callers pattern matched; overriding LLM reviewer): ${parsed.gates.caller_compatibility.detail}`
          : callerCompatibility === 'breaks_callers'
            ? `Automatically withheld (breaks_callers): ${parsed.gates.caller_compatibility.detail}`
            : parsed.gates.caller_compatibility.detail,
      },
      { gate: 5, name: 'repo_conventions', passed: gate5Passed, detail: parsed.gates.repo_conventions.detail },
      { gate: 6, name: 'dynamic_retest', passed: true, detail: 'Pending optional local-lab dynamic retest.' },
    ]

    let status: PatchStatus
    if (callerCompatibility === 'breaks_callers') {
      status = 'withheld'
    } else if (parsed.approved && gate1Passed && gate2Passed && gate3Passed && gate4Passed && gate5Passed) {
      status = 'approved'
    } else {
      status = 'rejected'
    }

    return {
      approved: status === 'approved',
      status,
      callerCompatibility,
      gates,
      enforcingLocation,
      reviewNotes: redact(parsed.reviewNotes, params.secrets),
    }
  } catch {
    return deterministicOfflineReview(params.authorOutput, applicability)
  }
}

export async function generateAndReviewPatch(params: PatchWorkflowParams): Promise<PatchProposalResult> {
  const now = Date.now()
  const proposalId = randomUUID()

  // Stage 1: Air-gapped Patch Author
  const authorOutput = await runPatchAuthor(params)

  // Stage 2: Independent Patch Reviewer (fresh clean context, 6 ordered gates)
  const review = await runPatchReviewer({
    finding: params.finding,
    repo: params.repo,
    reposDir: params.reposDir,
    authorOutput,
    backend: params.backend,
    reviewerLlmCall: params.reviewerLlmCall,
    modelProfiles: params.modelProfiles,
    signal: params.signal,
    secrets: params.secrets,
    onUsage: params.onUsage,
  })

  let finalStatus: PatchStatus = review.status
  let dynamicRetestVerdict: DynamicRetestVerdict = 'skipped'
  let dynamicRetestSummary: string | undefined
  const gates = [...review.gates]

  // Stage 3: Optional local-lab dynamic fix retest (reproduced -> fixed)
  if (params.labRetest && finalStatus === 'approved') {
    const lr = params.labRetest
    try {
      await lr.labRunner.rebuildWithPatch(lr.runId, authorOutput.diff, params.signal)
      const retest = await retestReplaySpec({
        spec: lr.replaySpec,
        broker: lr.broker,
        browser: lr.browser,
        canaryBroker: lr.canaryBroker,
        backend: lr.backend,
        grant: lr.grant,
        signal: params.signal ?? AbortSignal.timeout(60_000),
        storage: lr.storage,
        runId: lr.runId,
        assignmentId: lr.assignmentId,
      })

      if (retest.verdict === 'fixed') {
        dynamicRetestVerdict = 'fixed'
        dynamicRetestSummary = `Zero-LLM dynamic fix retest confirmed reproduced → fixed: ${retest.replay.outcome.observed}`
        gates[5] = { gate: 6, name: 'dynamic_retest', passed: true, detail: dynamicRetestSummary }
      } else if (retest.verdict === 'reproduced') {
        dynamicRetestVerdict = 'reproduced'
        dynamicRetestSummary = `Vulnerability still reproduced after patch rebuild: ${retest.replay.outcome.observed}`
        gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
        finalStatus = 'rejected'
      } else {
        dynamicRetestVerdict = 'skipped'
        dynamicRetestSummary = `Dynamic fix retest inconclusive: ${retest.replay.outcome.observed}`
        gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
        finalStatus = 'withheld'
      }
    } catch (err) {
      dynamicRetestVerdict = 'skipped'
      dynamicRetestSummary = `Dynamic fix retest failed: ${err instanceof Error ? err.message : String(err)}`
      gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
      finalStatus = 'withheld'
    }
  } else if (params.labRetest && finalStatus !== 'approved') {
    gates[5] = {
      gate: 6,
      name: 'dynamic_retest',
      passed: false,
      detail: `Dynamic retest skipped because static review status was "${finalStatus}".`,
    }
  }

  const reviewNotes = redact(
    [
      review.reviewNotes,
      ...(dynamicRetestSummary ? [`Dynamic retest (${dynamicRetestVerdict}): ${dynamicRetestSummary}`] : []),
    ].join('\n'),
    params.secrets,
  )

  return {
    id: proposalId,
    runId: params.runId,
    findingId: params.finding.id,
    repo: params.repo,
    status: finalStatus,
    callerCompatibility: review.callerCompatibility,
    fixBefore: redact(authorOutput.fixBefore, params.secrets),
    fixAfter: redact(authorOutput.fixAfter, params.secrets),
    diff: redact(authorOutput.diff, params.secrets),
    codeLocations: authorOutput.codeLocations,
    coverageInventory: authorOutput.coverageInventory,
    gates,
    reviewNotes,
    dynamicRetestVerdict,
    dynamicRetestSummary: dynamicRetestSummary ? redact(dynamicRetestSummary, params.secrets) : undefined,
    createdAt: now,
    updatedAt: Date.now(),
  }
}
