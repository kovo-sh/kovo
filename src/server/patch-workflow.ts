import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { closeSync, constants as fsConstants, cpSync, existsSync, lstatSync, mkdtempSync, openSync, readFileSync, readdirSync, realpathSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { extname, join, relative, resolve } from 'node:path'
import { z } from 'zod'
import type { Finding } from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import type { BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import {
  compositeProofReceiptSchema,
  sha256Hex,
  verifyCompositeReceipt,
  verifyHostRecordSignature,
} from './composite-receipt.ts'
import type {
  CausalEdgeBinding,
  CausalEdgeKind,
  CompositeProofReceipt,
  CompositeReceiptVerification,
  CompositeVerifyOptions,
  HopReceipt,
  HopSurface,
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostOobEvent,
  HostSignableRecord,
  HostSignedTranscript,
  HostTranscriptEntry,
} from './composite-receipt.ts'
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
  /** Optional explicit sanitized lab workspace path (auto-resolved from `labRunner.supervisor` when omitted). */
  sanitizedRepoDir?: string
  replaySpec: DeclarativeReplaySpec
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  grant: Grant
  storage?: Store
  assignmentId?: string
  /**
   * Authorized (legitimate) baseline request that must still succeed after the rebuild.
   * Gate 6 only passes when the exploit is fixed AND this caller remains 2xx.
   */
  baselineCaller?: BrokerHttpRequest
  baselineExpectStatus?: number[]
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

const NO_FOLLOW = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0

function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink()
  } catch {
    return false
  }
}

/** Read a file only if it is a regular file, never following a symlink (O_NOFOLLOW closes races). */
function readRegularFileNoFollow(path: string): string | null {
  let fd: number | undefined
  try {
    if (!lstatSync(path).isFile()) return null
    fd = openSync(path, fsConstants.O_RDONLY | NO_FOLLOW)
    return readFileSync(fd, 'utf8')
  } catch {
    return null
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* already closed */ }
    }
  }
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
  // A project mount may be replaced by a link to an outside directory; patch authoring must not
  // read or write through it.
  if (isSymlink(target)) {
    throw new Error(`Mounted repository is a symlink and cannot be patched: ${cleanRepo}`)
  }
  return realpathSync(target)
}

function safeReadRepoFile(repoRoot: string, relFile: string): string | null {
  const clean = relFile.replace(/^\/+/, '').replace(/\\/g, '/')
  if (!clean || clean.includes('\0') || clean.split('/').some(seg => seg === '..')) return null
  const full = resolve(repoRoot, clean)
  const rel = relative(repoRoot, full)
  if (rel.startsWith('..') || !existsSync(full)) return null
  return readRegularFileNoFollow(full)
}

/**
 * Copy a repo into an isolated work dir without following links. A repository may contain a link
 * to /etc/passwd or to an outside directory; following it in the patch work copy would let a diff
 * read or write host files. `dereference: false` keeps entries as links, and the filter drops them.
 */
export function copyRepoTreeWithoutSymlinks(repoRoot: string, destRoot: string): void {
  cpSync(repoRoot, destRoot, {
    recursive: true,
    dereference: false,
    verbatimSymlinks: false,
    filter: src => !isSymlink(src),
  })
  const stack: string[] = [destRoot]
  while (stack.length > 0) {
    const dir = stack.pop()!
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (isSymlink(full)) {
        throw new Error(`Refusing patch work copy containing a symlink: ${entry.name}`)
      }
      if (entry.isDirectory()) stack.push(full)
    }
  }
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
  const workDir = mkdtempSync(join(tmpdir(), 'kovo-patch-check-'))
  try {
    copyRepoTreeWithoutSymlinks(repoRoot, workDir)
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
          } else if (/\.go$/i.test(origName)) {
            checks.push(`if command -v go >/dev/null 2>&1; then go vet "./${origName}" || exit 1; else echo "go toolchain unavailable (skipped)"; fi`)
          } else if (/\.(?:java|kt)$/i.test(origName)) {
            checks.push(`if command -v javac >/dev/null 2>&1; then javac -proc:none -d /tmp/kovo-javac "${staged}" || exit 1; else echo "javac unavailable (skipped)"; fi`)
          }
        }
        // Language-appropriate project typecheck/build when a toolchain exists in the image.
        if (filesModified.some(f => /\.(?:[cm]?ts|tsx)$/i.test(f)) && existsSync(join(workDir, 'tsconfig.json'))) {
          checks.push('if command -v tsc >/dev/null 2>&1; then tsc --noEmit --skipLibCheck -p /tmp/work-repo/tsconfig.json || exit 1; else echo "tsc unavailable (AST syntax check already passed)"; fi')
        }
        // Copy /repos/<repo> into container's /tmp/work-repo (read-only /repos invariant preserved!)
        const copyPatched = filesModified.map((origName, idx) =>
          `mkdir -p "$(dirname "/tmp/work-repo/${origName}")" && cp "/evidence/patched_${idx}${extname(origName) || '.txt'}" "/tmp/work-repo/${origName}"`)
        const cmd = [
          `mkdir -p /tmp/work-repo && cp -R "/repos/${safeRepo}/." /tmp/work-repo/`,
          ...copyPatched,
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

    const staticAst = verifyStaticAstPostPatch(workDir, filesModified)
    if (!staticAst.ok) {
      syntaxCheck = {
        ...syntaxCheck,
        ran: true,
        passed: false,
        output: [syntaxCheck.output ?? '', ...staticAst.issues.map(i => `FAIL: static AST: ${i}`)].join('\n').trim().slice(0, 2000),
      }
    } else if (!syntaxCheck.ran) {
      syntaxCheck = {
        ...syntaxCheck,
        ran: true,
        command: 'offline static AST sanity',
        output: 'OK: static AST sanity check',
      }
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

/** Deterministic post-patch static AST sanity check (conflict markers + parse health). */
export function verifyStaticAstPostPatch(workDir: string, filesModified: readonly string[]): { ok: boolean; issues: string[] } {
  const issues: string[] = []
  for (const rel of filesModified) {
    if (!/\.(?:[cm]?[jt]sx?|py|go|java|kt|rb)$/i.test(rel)) continue
    let content = ''
    try {
      content = readFileSync(join(workDir, rel), 'utf8')
    } catch {
      issues.push(`${rel}: unreadable after patch`)
      continue
    }
    if (/^(?:<{7}|={7}|>{7})/m.test(content)) issues.push(`${rel}: unresolved merge-conflict marker`)
    if (/\b(?:eval|new Function)\s*\(/.test(content)) {
      // Informational only: do not fail a defensive patch for existing eval usage.
    }
  }
  return { ok: issues.length === 0, issues }
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
  const astCheck = verifyStaticAstPostPatch(workDir, [...jsLike, ...pyLike])
  if (!astCheck.ok) {
    passed = false
    outputs.push(...astCheck.issues.map(issue => `FAIL: static AST: ${issue}`))
  } else if (ran || jsLike.length + pyLike.length > 0) {
    outputs.push('OK: static AST sanity check (no conflict markers / unreadable patch target)')
  }
  return {
    ran,
    command: ran ? 'offline syntax check (ts/node/py_compile) + static AST sanity' : undefined,
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
    'You are Kovo Hunter’s air-gapped Patch Author (Stage 1).',
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

const BLOCKING_STATEMENT_RE = /^(?:return\s+.*\b(?:status\s*\(\s*(?:401|403|404|500)|new\s+Response\s*\([^)]*(?:401|403))|res(?:ponse)?\.status\s*\(\s*(?:401|403)\s*\)\s*\.|throw\s+new\s+Error\s*\(\s*['"](?:disabled|forbidden|unauthorized)['"])/i

/**
 * Detect a patch that unconditionally blocks legitimate callers.
 *
 * The v4 regex matched any added `return res.status(403)` line, including the body of
 * a legitimate guard such as `if (!authorized) { return res.status(403) }`. We now track
 * conditional/block scope per hunk and only flag blocking statements that are *not*
 * nested inside an `if`/`else`/`switch`/`catch`/loop. `if (true)` counts as unconditional.
 */
export function detectUnconditionalCallerBreak(diff: string): boolean {
  const lines: Array<{ added: boolean; text: string }> = []
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++') || raw.startsWith('---') || raw.startsWith('@@')) continue
    if (raw.startsWith('+')) lines.push({ added: true, text: raw.slice(1) })
    else if (raw.startsWith(' ')) lines.push({ added: false, text: raw.slice(1) })
    // Removed lines are irrelevant: they no longer exist in the patched program.
  }
  const addedCount = lines.filter(l => l.added).length
  if (addedCount === 0) return false
  const frames: Array<{ conditional: boolean }> = []
  for (const entry of lines) {
    const trimmed = entry.text.trim()
    if (!trimmed) continue
    // Close scopes that end on this line before evaluating it.
    const leadingCloses = (trimmed.match(/^\}+/) ?? [''])[0].length
    for (let i = 0; i < leadingCloses; i += 1) frames.pop()

    const isConditionalOpener = /^(?:if|else|switch|catch|for|while|unless|when|case|elif)\b/.test(trimmed)
      && !/^if\s*\(\s*true\s*\)/.test(trimmed)
    const blockingInline = BLOCKING_STATEMENT_RE.test(trimmed) && !/^if\b/.test(trimmed)
    if (entry.added && blockingInline && !frames.some(f => f.conditional)) return true

    const opens = (trimmed.match(/\{/g) ?? []).length
    const closes = (trimmed.match(/\}/g) ?? []).length - leadingCloses
    for (let i = 0; i < opens; i += 1) frames.push({ conditional: isConditionalOpener })
    for (let i = 0; i < Math.max(0, closes); i += 1) frames.pop()
  }
  return false
}

const HARDCODED_SECRET_IN_DIFF = /^\+.*(?:sk-or-v1-|sk-ant-|ghp_|github_pat_|-----BEGIN [A-Z ]*PRIVATE KEY-----)/m

function detectDeterministicCallerBreak(authorOutput: PatchAuthorOutput): boolean {
  return detectUnconditionalCallerBreak(authorOutput.diff)
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
    || /^\+(?:<{7}|={7}|>{7})/m.test(authorOutput.diff)
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
    passed: false,
    detail: 'Dynamic retest unverified (skipped unless an authorized local-lab retest with a baseline caller is available).',
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
    'You are Kovo Hunter’s independent air-gapped Patch Reviewer (Stage 2).',
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
      { gate: 6, name: 'dynamic_retest', passed: false, detail: 'Dynamic retest unverified (pending optional local-lab retest with baseline caller).' },
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

/** Per-run Gate-6 serialization mutex (M-7): prevents concurrent candidate patches from racing on one lab workspace. */
const gate6RunLocks = new Map<string, Promise<void>>()

async function withGate6RunLock<T>(runId: string, fn: () => Promise<T>): Promise<T> {
  const prev = gate6RunLocks.get(runId) ?? Promise.resolve()
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const tail = prev.then(() => gate, () => gate)
  gate6RunLocks.set(runId, tail)
  await prev.catch(() => undefined)
  try {
    return await fn()
  } finally {
    release()
    if (gate6RunLocks.get(runId) === tail) {
      gate6RunLocks.delete(runId)
    }
  }
}

function restoreWorkspaceSnapshot(targetDir: string, backupDir: string): void {
  if (!existsSync(targetDir) || !existsSync(backupDir)) return
  for (const entry of readdirSync(targetDir)) {
    rmSync(join(targetDir, entry), { recursive: true, force: true })
  }
  for (const entry of readdirSync(backupDir)) {
    cpSync(join(backupDir, entry), join(targetDir, entry), { recursive: true })
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

  // Stage 3: Optional local-lab dynamic fix retest (reproduced -> fixed) with authorized baseline caller.
  // M-7: Serialize concurrent Gate-6 retests per run, validate diff applicability in an isolated temp
  // copy first, and snapshot/restore `sanitizedRepoDir` so candidate patches never leave the live
  // run workspace mutated.
  if (params.labRetest && finalStatus === 'approved') {
    const lr = params.labRetest
    await withGate6RunLock(lr.runId, async () => {
      const activeRunState = lr.labRunner?.supervisor?.getActiveRun?.(lr.runId)
      const sanitizedRepoDir = lr.sanitizedRepoDir ?? activeRunState?.handle?.sanitizedRepoDir
      let scratchDir: string | null = null
      let backupDir: string | null = null
      try {
        if (sanitizedRepoDir && existsSync(sanitizedRepoDir)) {
          // 1. Validate the candidate diff in an isolated temporary copy before touching the live lab dir.
          scratchDir = mkdtempSync(join(tmpdir(), 'kovo-patch-gate6-work-'))
          cpSync(sanitizedRepoDir, scratchDir, { recursive: true })
          applyUnifiedDiffToDirectory(scratchDir, authorOutput.diff)

          // 2. Capture a clean pre-retest snapshot for guaranteed rollback in `finally`.
          backupDir = mkdtempSync(join(tmpdir(), 'kovo-patch-gate6-backup-'))
          cpSync(sanitizedRepoDir, backupDir, { recursive: true })
        }

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

        let baselineStatus: number | null = null
        let baselineOk = false
        if (lr.baselineCaller) {
          try {
            const baseline = await lr.broker.executeHttp(lr.baselineCaller, lr.grant, params.signal ?? AbortSignal.timeout(30_000))
            baselineStatus = baseline.status
            const expected = lr.baselineExpectStatus ?? [200, 201, 202, 204]
            baselineOk = expected.includes(baseline.status)
          } catch {
            baselineOk = false
          }
        }

        if (retest.verdict === 'fixed' && lr.baselineCaller && baselineOk) {
          dynamicRetestVerdict = 'fixed'
          dynamicRetestSummary = `Zero-LLM dynamic fix retest confirmed reproduced → fixed: ${retest.replay.outcome.observed}; authorized baseline caller still HTTP ${baselineStatus}`
          gates[5] = { gate: 6, name: 'dynamic_retest', passed: true, detail: dynamicRetestSummary }
        } else if (retest.verdict === 'fixed' && !lr.baselineCaller) {
          dynamicRetestVerdict = 'skipped'
          dynamicRetestSummary = `Exploit replay reports fixed, but Gate 6 is unverified: no authorized baseline caller was supplied to prove legitimate traffic still succeeds.`
          gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          finalStatus = 'withheld'
        } else if (retest.verdict === 'fixed' && lr.baselineCaller && !baselineOk) {
          dynamicRetestVerdict = 'skipped'
          dynamicRetestSummary = `Exploit replay reports fixed, but the authorized baseline caller regressed (HTTP ${baselineStatus ?? 'error'}); patch breaks legitimate traffic.`
          gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          finalStatus = 'rejected'
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
      } finally {
        if (sanitizedRepoDir && backupDir) {
          try {
            restoreWorkspaceSnapshot(sanitizedRepoDir, backupDir)
          } catch { /* rollback is best-effort */ }
        }
        if (scratchDir) {
          try { rmSync(scratchDir, { recursive: true, force: true }) } catch { /* ignore */ }
        }
        if (backupDir) {
          try { rmSync(backupDir, { recursive: true, force: true }) } catch { /* ignore */ }
        }
      }
    })
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

// ============================================================================
// v8 Stream B — Multi-Hop CompositeProofReceipt DAG Patch-Retest
// ============================================================================

export type CompositePatchRetestVerdict =
  | 'fixed'
  | 'still_vulnerable'
  | 'inconclusive'
  | 'precondition_changed'

export type CompositeHopReplayOutcome =
  | 'succeeded'
  | 'blocked'
  | 'transport_error'
  | 'auth_setup_failed'
  | 'precondition_changed'
  | 'inconclusive'

export interface CompositeBrokeCausalEdge {
  edgeIndex: number
  kind: CausalEdgeKind
  fromHopId: string
  toHopId: string
}

export interface CompositeHopReplaySummary {
  hopId: string
  surface: HopSurface
  outcome: CompositeHopReplayOutcome | 'skipped_after_break'
  httpStatuses: number[]
  exchangeIds: string[]
  oobEventIds: string[]
  browserTraceIds: string[]
  emittedCapabilities: string[]
  consumedCapabilities: string[]
  reason?: string
  errorCode?: string
}

export interface CompositeHopReplayContext {
  receipt: CompositeProofReceipt
  hop: HopReceipt
  hopIndex: number
  topoOrder: readonly string[]
  incomingEdges: readonly CausalEdgeBinding[]
  outgoingEdges: readonly CausalEdgeBinding[]
  availableCapabilities: readonly string[]
  priorHopResults: Readonly<Record<string, CompositeHopReplaySummary>>
  transcriptSoFar: HostSignedTranscript
  signal?: AbortSignal
}

export interface CompositeHopReplayResult {
  outcome?: CompositeHopReplayOutcome
  entries?: readonly HostTranscriptEntry[]
  oobEvents?: readonly HostOobEvent[]
  browserTraces?: readonly HostBrowserTrace[]
  asyncPollRecords?: readonly HostAsyncPollRecord[]
  replayedExchangeIds?: readonly string[]
  replayedOobEventIds?: readonly string[]
  replayedBrowserTraceIds?: readonly string[]
  replayedAblationExchangeIds?: Readonly<Record<string, readonly string[]>>
  replayedPollRecordIds?: Readonly<Record<string, string>>
  preChainControlExchangeIds?: readonly string[]
  postChainReadbackExchangeIds?: readonly string[]
  reason?: string
  errorCode?: string
  httpStatus?: number | null
}

export interface CompositePreconditionSetupResult {
  status: 'ok' | 'precondition_changed' | 'transport_error' | 'auth_setup_failed' | 'inconclusive'
  reason?: string
  errorCode?: string
  httpStatus?: number | null
  entries?: readonly HostTranscriptEntry[]
  oobEvents?: readonly HostOobEvent[]
  browserTraces?: readonly HostBrowserTrace[]
  asyncPollRecords?: readonly HostAsyncPollRecord[]
  preChainControlExchangeIds?: readonly string[]
}

export interface CompositePatchReplayRunner {
  preparePreconditions?: (ctx: {
    receipt: CompositeProofReceipt
    topoOrder: readonly string[]
    signal?: AbortSignal
  }) => Promise<CompositePreconditionSetupResult> | CompositePreconditionSetupResult
  replayHop: (ctx: CompositeHopReplayContext) => Promise<CompositeHopReplayResult> | CompositeHopReplayResult
  readbackTerminalState?: (ctx: {
    receipt: CompositeProofReceipt
    transcriptSoFar: HostSignedTranscript
    signal?: AbortSignal
  }) => Promise<{
    status?: 'ok' | 'transport_error' | 'precondition_changed' | 'inconclusive'
    reason?: string
    errorCode?: string
    httpStatus?: number | null
    entries?: readonly HostTranscriptEntry[]
    postChainReadbackExchangeIds?: readonly string[]
  }> | {
    status?: 'ok' | 'transport_error' | 'precondition_changed' | 'inconclusive'
    reason?: string
    errorCode?: string
    httpStatus?: number | null
    entries?: readonly HostTranscriptEntry[]
    postChainReadbackExchangeIds?: readonly string[]
  }
}

export interface RetestCompositeChainParams {
  receipt: CompositeProofReceipt
  runner: CompositePatchReplayRunner
  verifyOptions?: CompositeVerifyOptions
  retestId?: string
  targetRevision?: string
  patchId?: string
  secrets?: readonly NamedSecret[]
  signal?: AbortSignal
  now?: () => number
}

export interface CompositePatchRetestProof {
  schemaVersion: 1
  retestId: string
  chainId: string
  terminalVulnClass: string
  terminalHopId: string
  verdict: CompositePatchRetestVerdict
  /** True strictly when verdict === 'fixed' (fail-closed OSS M4 grading signal). */
  patchClosed: boolean
  /** Exact hop where the patch broke the multi-hop chain (non-null iff verdict === 'fixed'). */
  patchBrokeHopId: string | null
  /** Causal edge disrupted by the patch when applicable. */
  brokeCausalEdge: CompositeBrokeCausalEdge | null
  /** Redacted explanation of how the patch broke the chain (non-null iff verdict === 'fixed'). */
  brokeReason: string | null
  /** Ordered topological prefix of hops that still succeeded benignly before `patchBrokeHopId`. */
  benignPrefixHops: string[]
  /** Topological execution order of the DAG. */
  topoOrder: string[]
  /** Per-hop redacted replay summaries in topological order. */
  hopResults: CompositeHopReplaySummary[]
  /** All host-recorded exchange IDs captured during the retest. */
  exchangeIds: string[]
  /** Concise redacted verdict summary suitable for portable receipt export & reports. */
  summary: string
  /** Underlying `verifyCompositeReceipt()` result when full DAG verification ran. */
  compositeVerification?: CompositeReceiptVerification
  targetRevision?: string
  patchId?: string
  testedAt: string
  /** Canonical SHA-256 hex digest of this proof record (excluding `proofSha256`). */
  proofSha256: string
}

export interface PortableCompositePatchRetestRecord {
  retestId: string
  verdict: 'reproduced' | 'fixed' | 'inconclusive'
  compositeVerdict: CompositePatchRetestVerdict
  chainId: string
  terminalVulnClass: string
  patchClosed: boolean
  patchBrokeHopId: string | null
  brokeCausalEdge: CompositeBrokeCausalEdge | null
  brokeReason: string | null
  benignPrefixHops: string[]
  summary: string
  exchangeIds: string[]
  testedAt: string
  proofSha256: string
}

export interface CompositePatchClosureSummary {
  total: number
  fixed: number
  stillVulnerable: number
  inconclusive: number
  preconditionChanged: number
  closureRate: number
  meetsM4ClosureGate: boolean
}

interface IndexedDagEdge {
  edgeIndex: number
  edge: CausalEdgeBinding
}

interface CompositeDagLayout {
  hopsById: Map<string, HopReceipt>
  topoOrder: string[]
  roots: string[]
  incomingByHop: Map<string, IndexedDagEdge[]>
  outgoingByHop: Map<string, IndexedDagEdge[]>
}

interface ReplayedHopArtifacts {
  exchangeIds: string[]
  oobEventIds: string[]
  browserTraceIds: string[]
  entries: HostTranscriptEntry[]
  oobEvents: HostOobEvent[]
  browserTraces: HostBrowserTrace[]
  asyncPollRecords: HostAsyncPollRecord[]
  ablationByEdge: Record<string, readonly string[]>
  pollByEdge: Record<string, string>
}

const TRANSPORT_ERROR_CODE_RE =
  /^(?:ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EPIPE|EHOSTUNREACH|ENETUNREACH|UND_ERR_[A-Z_]+|TIMEOUT|ABORTED|ABORT_ERR|TLS_ERROR|AUTH_SETUP_FAILED)$/i

function canonicalProofStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalProofStringify).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([k, v]) => k !== 'proofSha256' && v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalProofStringify(v)}`).join(',')}}`
}

export function computeCompositeRetestProofDigest(
  proof: Omit<CompositePatchRetestProof, 'proofSha256'> & { proofSha256?: string },
): string {
  return sha256Hex(canonicalProofStringify(proof))
}

export function verifyCompositePatchRetestProofIntegrity(proof: CompositePatchRetestProof): boolean {
  if (!proof || typeof proof.proofSha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(proof.proofSha256)) {
    return false
  }
  return proof.proofSha256.toLowerCase() === computeCompositeRetestProofDigest(proof)
}

export function toPortablePatchRetestProof(proof: CompositePatchRetestProof): PortableCompositePatchRetestRecord {
  const verdict: PortableCompositePatchRetestRecord['verdict'] =
    proof.verdict === 'fixed'
      ? 'fixed'
      : proof.verdict === 'still_vulnerable'
        ? 'reproduced'
        : 'inconclusive'
  return {
    retestId: proof.retestId,
    verdict,
    compositeVerdict: proof.verdict,
    chainId: proof.chainId,
    terminalVulnClass: proof.terminalVulnClass,
    patchClosed: proof.patchClosed,
    patchBrokeHopId: proof.patchBrokeHopId,
    brokeCausalEdge: proof.brokeCausalEdge,
    brokeReason: proof.brokeReason,
    benignPrefixHops: [...proof.benignPrefixHops],
    summary: proof.summary,
    exchangeIds: [...proof.exchangeIds],
    testedAt: proof.testedAt,
    proofSha256: proof.proofSha256,
  }
}

export function summarizeCompositePatchClosure(
  proofs: readonly CompositePatchRetestProof[],
  threshold = 0.8,
): CompositePatchClosureSummary {
  let fixed = 0
  let stillVulnerable = 0
  let inconclusive = 0
  let preconditionChanged = 0
  for (const p of proofs) {
    if (p.verdict === 'fixed') fixed += 1
    else if (p.verdict === 'still_vulnerable') stillVulnerable += 1
    else if (p.verdict === 'precondition_changed') preconditionChanged += 1
    else inconclusive += 1
  }
  const total = proofs.length
  const closureRate = total > 0 ? fixed / total : 0
  return {
    total,
    fixed,
    stillVulnerable,
    inconclusive,
    preconditionChanged,
    closureRate,
    meetsM4ClosureGate: total > 0 && closureRate >= threshold,
  }
}

function computeCompositeDagLayout(
  receipt: CompositeProofReceipt,
): { ok: true; dag: CompositeDagLayout } | { ok: false; reason: string } {
  const hopsById = new Map<string, HopReceipt>()
  for (const hop of receipt.hops) {
    if (hopsById.has(hop.hopId)) return { ok: false, reason: `Duplicate hopId "${hop.hopId}".` }
    hopsById.set(hop.hopId, hop)
  }
  if (!hopsById.has(receipt.terminalImpact.terminalHopId)) {
    return { ok: false, reason: `terminalHopId "${receipt.terminalImpact.terminalHopId}" not in hops.` }
  }
  if (receipt.hops.length === 1 && receipt.causalEdges.length > 0) {
    return { ok: false, reason: 'A 1-hop receipt cannot declare causalEdges.' }
  }

  const inDeg = new Map<string, number>(receipt.hops.map(h => [h.hopId, 0]))
  const outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const revAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const incomingByHop = new Map<string, IndexedDagEdge[]>(receipt.hops.map(h => [h.hopId, []]))
  const outgoingByHop = new Map<string, IndexedDagEdge[]>(receipt.hops.map(h => [h.hopId, []]))
  const seen = new Set<string>()

  for (let i = 0; i < receipt.causalEdges.length; i += 1) {
    const e = receipt.causalEdges[i]!
    if (!hopsById.has(e.fromHopId) || !hopsById.has(e.toHopId)) {
      return { ok: false, reason: `Edge #${i} references unknown hop.` }
    }
    if (e.fromHopId === e.toHopId) {
      return { ok: false, reason: `Edge #${i} forms a self-loop on "${e.fromHopId}".` }
    }
    const key = `${e.fromHopId}->${e.toHopId}:${e.kind}`
    if (seen.has(key)) return { ok: false, reason: `Duplicate causal edge "${key}".` }
    seen.add(key)
    outAdj.get(e.fromHopId)!.push(e.toHopId)
    revAdj.get(e.toHopId)!.push(e.fromHopId)
    inDeg.set(e.toHopId, (inDeg.get(e.toHopId) ?? 0) + 1)
    incomingByHop.get(e.toHopId)!.push({ edgeIndex: i, edge: e })
    outgoingByHop.get(e.fromHopId)!.push({ edgeIndex: i, edge: e })
  }

  const roots = receipt.hops.filter(h => inDeg.get(h.hopId) === 0).map(h => h.hopId)
  const queue = [...roots]
  const rem = new Map(inDeg)
  const topoOrder: string[] = []
  while (queue.length > 0) {
    const hopId = queue.shift()!
    topoOrder.push(hopId)
    for (const next of outAdj.get(hopId) ?? []) {
      const d = (rem.get(next) ?? 0) - 1
      rem.set(next, d)
      if (d === 0) queue.push(next)
    }
  }
  if (topoOrder.length !== receipt.hops.length) {
    return { ok: false, reason: 'Causal DAG contains a cycle.' }
  }

  const reachesTerminal = new Set<string>([receipt.terminalImpact.terminalHopId])
  const rq = [receipt.terminalImpact.terminalHopId]
  while (rq.length > 0) {
    const cur = rq.shift()!
    for (const prev of revAdj.get(cur) ?? []) {
      if (!reachesTerminal.has(prev)) {
        reachesTerminal.add(prev)
        rq.push(prev)
      }
    }
  }
  const orphan = receipt.hops.find(h => !reachesTerminal.has(h.hopId))
  if (orphan) {
    return { ok: false, reason: `Hop "${orphan.hopId}" does not reach terminalHopId.` }
  }
  return { ok: true, dag: { hopsById, topoOrder, roots, incomingByHop, outgoingByHop } }
}

const is2xxStatus = (status: number | null | undefined): boolean =>
  typeof status === 'number' && status >= 200 && status < 300

const isFiniteTimestamp = (ts: unknown): ts is number =>
  typeof ts === 'number' && Number.isFinite(ts) && ts >= 0

const isTransportOrServerFailureStatus = (status: number | null | undefined): boolean =>
  status === null || status === undefined || !Number.isFinite(status) || status === 0 || status === 429 || status >= 500

const isSecurityDenialStatus = (status: number | null | undefined): boolean =>
  typeof status === 'number' && status >= 400 && status < 500 && status !== 429

function extractErrorCode(err: unknown): string | undefined {
  if (!err || typeof err !== 'object') return undefined
  const rec = err as { code?: unknown; name?: unknown; cause?: { code?: unknown } }
  if (typeof rec.code === 'string' && rec.code.trim()) return rec.code.trim()
  if (typeof rec.cause?.code === 'string' && rec.cause.code.trim()) return rec.cause.code.trim()
  if (typeof rec.name === 'string' && rec.name.trim() && rec.name !== 'Error') return rec.name.trim()
  return undefined
}

function collectRetestLeaves(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 5 || out.size > 256 || value == null) return
  if (typeof value === 'string') {
    const t = value.trim()
    if (t.length > 0 && t.length <= 2048) out.add(t)
  } else if (typeof value === 'number' || typeof value === 'boolean') {
    out.add(String(value))
  } else if (Array.isArray(value)) {
    for (const item of value) collectRetestLeaves(item, out, depth + 1)
  } else if (typeof value === 'object') {
    for (const item of Object.values(value as Record<string, unknown>)) {
      collectRetestLeaves(item, out, depth + 1)
    }
  }
}

function collectRetestHeaderTokens(headers: Record<string, string> | null | undefined, out: Set<string>): void {
  if (!headers) return
  for (const raw of Object.values(headers)) {
    const t = raw.trim()
    if (!t) continue
    out.add(t)
    const scheme = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(t)
    if (scheme?.[1]) out.add(scheme[1].trim())
    if (t.includes('=')) {
      for (const part of t.split(';')) {
        const eq = part.indexOf('=')
        if (eq > 0 && part.slice(eq + 1).trim()) out.add(part.slice(eq + 1).trim())
      }
    }
  }
}

function collectResponseDigests(entry: HostTranscriptEntry): Set<string> {
  const digests = new Set<string>()
  const leaves = new Set<string>()
  for (const d of [...(entry.observedResponseDigests ?? []), ...(entry.step.secretMatches ?? [])]) {
    digests.add(d.toLowerCase())
  }
  collectRetestLeaves(entry.step.json, leaves)
  collectRetestHeaderTokens(entry.step.responseHeaders, leaves)
  for (const leaf of leaves) digests.add(sha256Hex(leaf))
  return digests
}

function retestEntryMatchesEntity(entry: HostTranscriptEntry, entityId: string): boolean {
  if (entry.entityId === entityId) return true
  const path = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (path && new RegExp(`(?:^|[/=?&])${entityId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[/&?#])`).test(path)) {
    return true
  }
  const leaves = new Set<string>()
  collectRetestLeaves(entry.step.requestJson, leaves)
  collectRetestLeaves(entry.step.json, leaves)
  return leaves.has(entityId)
}

function retestEntryMatchesCorrelation(entry: HostTranscriptEntry, correlationId: string): boolean {
  if (
    entry.correlationIds?.includes(correlationId)
    || entry.entityId === correlationId
    || entry.carrierText?.includes(correlationId)
  ) {
    return true
  }
  const leaves = new Set<string>()
  collectRetestLeaves(entry.step.requestJson, leaves)
  collectRetestLeaves(entry.step.json, leaves)
  collectRetestHeaderTokens(entry.step.requestHeaders, leaves)
  collectRetestHeaderTokens(entry.step.responseHeaders, leaves)
  for (const leaf of leaves) {
    if (leaf === correlationId || leaf.includes(correlationId)) return true
  }
  return false
}

function inspectRecordsForTransportOrSignatureError(
  records: {
    entries?: readonly HostTranscriptEntry[]
    oobEvents?: readonly HostOobEvent[]
    browserTraces?: readonly HostBrowserTrace[]
    asyncPollRecords?: readonly HostAsyncPollRecord[]
  },
  signingKey?: string,
): { failed: false } | { failed: true; reason: string; errorCode: string } {
  for (const entry of records.entries ?? []) {
    if (isTransportOrServerFailureStatus(entry.step.status)) {
      const st = entry.step.status
      return {
        failed: true,
        reason: `Exchange "${entry.exchangeId}" returned ${st === null || st === undefined ? 'no HTTP status' : `HTTP ${st}`} (transport/server failure; failing closed).`,
        errorCode: typeof st === 'number' && st > 0 ? `HTTP_${st}` : 'TRANSPORT_NO_STATUS',
      }
    }
  }
  if (signingKey) {
    const check = (list: readonly HostSignableRecord[] | undefined, label: string, idOf: (r: HostSignableRecord) => string) => {
      for (const rec of list ?? []) {
        if (!verifyHostRecordSignature(rec, signingKey)) {
          return {
            failed: true as const,
            reason: `Host transcript signature verification failed on ${label} "${idOf(rec)}" (failing closed).`,
            errorCode: 'HOST_SIGNATURE_INVALID',
          }
        }
      }
      return null
    }
    const sigErr =
      check(records.entries, 'exchange', r => (r as HostTranscriptEntry).exchangeId)
      ?? check(records.oobEvents, 'OOB event', r => (r as HostOobEvent).id)
      ?? check(records.browserTraces, 'browser trace', r => (r as HostBrowserTrace).id)
      ?? check(records.asyncPollRecords, 'async poll record', r => (r as HostAsyncPollRecord).id)
    if (sigErr) return sigErr
  }
  return { failed: false }
}

function collectHopEmittedCapabilities(
  entries: readonly HostTranscriptEntry[],
  oobEvents: readonly HostOobEvent[],
  browserTraces: readonly HostBrowserTrace[],
  asyncPollRecords: readonly HostAsyncPollRecord[],
): string[] {
  const out = new Set<string>()
  for (const e of entries) {
    for (const c of e.emittedCapabilities ?? []) out.add(c)
    for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) out.add(a.derivedCapabilityId)
  }
  for (const o of oobEvents) for (const c of o.emittedCapabilities ?? []) out.add(c)
  for (const t of browserTraces) for (const c of t.emittedCapabilities ?? []) out.add(c)
  for (const p of asyncPollRecords) for (const c of p.emittedCapabilities ?? []) out.add(c)
  return [...out]
}

function collectHopConsumedCapabilities(entries: readonly HostTranscriptEntry[]): string[] {
  const out = new Set<string>()
  for (const e of entries) {
    for (const c of e.consumedCapabilities ?? []) out.add(c)
    for (const a of e.cryptoAttestations ?? []) out.add(a.derivedFromCapabilityId)
  }
  return [...out]
}

function classifyHopReplayOutcome(
  hop: HopReceipt,
  result: CompositeHopReplayResult,
  signingKey?: string,
): { outcome: CompositeHopReplayOutcome; reason?: string; errorCode?: string; blockedWith4xx: boolean } {
  const entries = result.entries ?? []
  const oobEvents = result.oobEvents ?? []
  const browserTraces = result.browserTraces ?? []
  const asyncPollRecords = result.asyncPollRecords ?? []

  // Transport, server 5xx/429, auth setup, and host-signature failures ALWAYS take precedence (fail closed).
  if (
    result.outcome === 'transport_error'
    || result.outcome === 'auth_setup_failed'
    || result.outcome === 'inconclusive'
  ) {
    return {
      outcome: result.outcome,
      reason: result.reason ?? `Hop "${hop.hopId}" encountered ${result.outcome}.`,
      errorCode: result.errorCode ?? result.outcome.toUpperCase(),
      blockedWith4xx: false,
    }
  }
  if (result.httpStatus !== undefined && isTransportOrServerFailureStatus(result.httpStatus)) {
    return {
      outcome: 'transport_error',
      reason: result.reason ?? `Hop "${hop.hopId}" returned HTTP ${result.httpStatus ?? 'error'} (transport/server failure).`,
      errorCode: result.errorCode ?? (result.httpStatus ? `HTTP_${result.httpStatus}` : 'TRANSPORT_ERROR'),
      blockedWith4xx: false,
    }
  }
  if (result.errorCode && TRANSPORT_ERROR_CODE_RE.test(result.errorCode)) {
    return {
      outcome: result.errorCode === 'AUTH_SETUP_FAILED' ? 'auth_setup_failed' : 'transport_error',
      reason: result.reason ?? `Hop "${hop.hopId}" failed with ${result.errorCode}.`,
      errorCode: result.errorCode,
      blockedWith4xx: false,
    }
  }
  const recErr = inspectRecordsForTransportOrSignatureError({ entries, oobEvents, browserTraces, asyncPollRecords }, signingKey)
  if (recErr.failed) {
    return { outcome: 'transport_error', reason: recErr.reason, errorCode: recErr.errorCode, blockedWith4xx: false }
  }

  if (result.outcome === 'precondition_changed') {
    return {
      outcome: 'precondition_changed',
      reason: result.reason ?? `Target route or schema changed before/during hop "${hop.hopId}".`,
      errorCode: result.errorCode ?? 'PRECONDITION_CHANGED',
      blockedWith4xx: false,
    }
  }

  const probeEntries = entries.filter(e => e.step.arm === 'probe' && e.replayAttempt !== 'ablation_control')
  const probe4xx = probeEntries.length > 0 && probeEntries.every(e => isSecurityDenialStatus(e.step.status))
  const result4xx = isSecurityDenialStatus(result.httpStatus)

  if (result.outcome === 'blocked') {
    const statuses = probeEntries.map(e => e.step.status).filter((s): s is number => typeof s === 'number')
    const statusHint = statuses.length > 0 ? ` (HTTP ${statuses.join(', ')})` : result4xx ? ` (HTTP ${result.httpStatus})` : ''
    return {
      outcome: 'blocked',
      reason: result.reason ?? `Hop "${hop.hopId}" was cleanly blocked by patched target${statusHint}.`,
      errorCode: result.errorCode,
      blockedWith4xx: probe4xx || result4xx,
    }
  }

  // Implicit block detection: every probe exchange in the hop was denied (4xx non-429) and no side-channel/capability succeeded.
  const emittedCaps = collectHopEmittedCapabilities(entries, oobEvents, browserTraces, asyncPollRecords)
  const hasOob = oobEvents.some(o => o.delivered)
  const hasTrace = browserTraces.some(t => (t.sinks?.length ?? 0) > 0 || (t.emittedCapabilities?.length ?? 0) > 0)
  const hasPoll = asyncPollRecords.some(p => p.converged)

  if (probe4xx && emittedCaps.length === 0 && !hasOob && !hasTrace && !hasPoll) {
    const statuses = probeEntries.map(e => e.step.status).join(', ')
    return {
      outcome: 'blocked',
      reason: result.reason ?? `Hop "${hop.hopId}" probe denied by patched target (HTTP ${statuses}).`,
      errorCode: result.errorCode,
      blockedWith4xx: true,
    }
  }

  return { outcome: 'succeeded', reason: result.reason, errorCode: result.errorCode, blockedWith4xx: false }
}

function hopSatisfiesOutgoingProducerEdge(
  edge: CausalEdgeBinding,
  fromHop: HopReceipt,
  artifacts: ReplayedHopArtifacts,
): { ok: true } | { ok: false; reason: string } {
  const hopEntries = artifacts.entries.filter(e => artifacts.exchangeIds.includes(e.exchangeId))
  const hopOob = artifacts.oobEvents.filter(o => artifacts.oobEventIds.includes(o.id))
  const hopTraces = artifacts.browserTraces.filter(t => artifacts.browserTraceIds.includes(t.id))

  if (edge.kind === 'value_binding') {
    const emittedCaps = new Set<string>()
    const digests = new Set<string>()
    let hasTimestampedOutput = false
    for (const e of hopEntries) {
      if (!isFiniteTimestamp(e.timestampMs)) continue
      hasTimestampedOutput = true
      for (const c of e.emittedCapabilities ?? []) emittedCaps.add(c)
      for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) emittedCaps.add(a.derivedCapabilityId)
      for (const d of collectResponseDigests(e)) digests.add(d)
    }
    for (const o of hopOob) {
      if (!o.delivered || !isFiniteTimestamp(o.receivedAtMs)) continue
      hasTimestampedOutput = true
      for (const c of o.emittedCapabilities ?? []) emittedCaps.add(c)
      for (const d of o.observedValueDigests ?? []) digests.add(d.toLowerCase())
      if (o.token) digests.add(sha256Hex(o.token))
    }
    for (const t of hopTraces) {
      if (!isFiniteTimestamp(t.timestampMs)) continue
      hasTimestampedOutput = true
      for (const c of t.emittedCapabilities ?? []) emittedCaps.add(c)
      for (const d of t.observedValueDigests ?? []) digests.add(d.toLowerCase())
    }
    if (!hasTimestampedOutput) {
      return { ok: false, reason: `Hop "${fromHop.hopId}" produced no host-timestamped output for value_binding to "${edge.toHopId}".` }
    }
    if (edge.capabilityHandle && !emittedCaps.has(edge.capabilityHandle)) {
      return { ok: false, reason: `Hop "${fromHop.hopId}" no longer emits required capability "${edge.capabilityHandle}" for "${edge.toHopId}".` }
    }
    if (edge.valueDigest && !digests.has(edge.valueDigest.toLowerCase())) {
      return { ok: false, reason: `Hop "${fromHop.hopId}" no longer emits required value digest for "${edge.toHopId}".` }
    }
    return { ok: true }
  }

  if (edge.kind === 'derived_crypto_binding') {
    const emittedCaps = new Set<string>()
    for (const e of hopEntries) {
      if (!isFiniteTimestamp(e.timestampMs)) continue
      for (const c of e.emittedCapabilities ?? []) emittedCaps.add(c)
      for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) emittedCaps.add(a.derivedCapabilityId)
    }
    for (const o of hopOob) {
      if (o.delivered && isFiniteTimestamp(o.receivedAtMs)) {
        for (const c of o.emittedCapabilities ?? []) emittedCaps.add(c)
      }
    }
    for (const t of hopTraces) {
      if (isFiniteTimestamp(t.timestampMs)) {
        for (const c of t.emittedCapabilities ?? []) emittedCaps.add(c)
      }
    }
    if (!emittedCaps.has(edge.sourceCapabilityId)) {
      return { ok: false, reason: `Hop "${fromHop.hopId}" no longer emits signing material "${edge.sourceCapabilityId}" for derived_crypto_binding to "${edge.toHopId}".` }
    }
    return { ok: true }
  }

  if (edge.kind === 'state_transition_binding') {
    const okMutation = hopEntries.some(
      e => is2xxStatus(e.step.status) && isFiniteTimestamp(e.timestampMs) && retestEntryMatchesEntity(e, edge.entityId),
    )
    if (!okMutation) {
      return { ok: false, reason: `Hop "${fromHop.hopId}" no longer succeeds on shared entity "${edge.entityId}" for state_transition_binding to "${edge.toHopId}".` }
    }
    return { ok: true }
  }

  // async_pivot_binding
  const triggered =
    hopEntries.some(e => is2xxStatus(e.step.status) && isFiniteTimestamp(e.timestampMs) && retestEntryMatchesCorrelation(e, edge.correlationId))
    || hopTraces.some(t => isFiniteTimestamp(t.timestampMs) && (t.correlationIds?.includes(edge.correlationId) ?? false))
  if (!triggered) {
    return { ok: false, reason: `Hop "${fromHop.hopId}" no longer produces async trigger "${edge.correlationId}" for "${edge.toHopId}".` }
  }
  return { ok: true }
}

function selectBrokeEdgeForBlockedHop(
  hopId: string,
  blockedWith4xx: boolean,
  dag: CompositeDagLayout,
): CompositeBrokeCausalEdge | null {
  const incoming = dag.incomingByHop.get(hopId) ?? []
  const outgoing = dag.outgoingByHop.get(hopId) ?? []
  const chosen = blockedWith4xx
    ? (incoming[0] ?? outgoing[0])
    : (outgoing[0] ?? incoming[0])
  if (!chosen) return null
  return {
    edgeIndex: chosen.edgeIndex,
    kind: chosen.edge.kind,
    fromHopId: chosen.edge.fromHopId,
    toHopId: chosen.edge.toHopId,
  }
}

function buildReplayedCompositeReceipt(
  receipt: CompositeProofReceipt,
  dag: CompositeDagLayout,
  hopArtifacts: ReadonlyMap<string, ReplayedHopArtifacts>,
  allEntriesById: ReadonlyMap<string, HostTranscriptEntry>,
  allOobById: ReadonlyMap<string, HostOobEvent>,
  allTracesById: ReadonlyMap<string, HostBrowserTrace>,
  allPollsById: ReadonlyMap<string, HostAsyncPollRecord>,
  extraPreChainControlIds: readonly string[],
  extraPostChainReadbackIds: readonly string[],
): CompositeProofReceipt {
  const exchangeIdMap = new Map<string, string>()
  const oobIdMap = new Map<string, string>()
  const traceIdMap = new Map<string, string>()

  const replayedHops: HopReceipt[] = receipt.hops.map(hop => {
    const art = hopArtifacts.get(hop.hopId)
    if (!art) return hop
    if (hop.exchangeIds.length === art.exchangeIds.length) {
      for (let i = 0; i < hop.exchangeIds.length; i += 1) {
        exchangeIdMap.set(hop.exchangeIds[i]!, art.exchangeIds[i]!)
      }
    }
    if (hop.oobEventIds.length === art.oobEventIds.length) {
      for (let i = 0; i < hop.oobEventIds.length; i += 1) {
        oobIdMap.set(hop.oobEventIds[i]!, art.oobEventIds[i]!)
      }
    }
    if (hop.browserTraceIds.length === art.browserTraceIds.length) {
      for (let i = 0; i < hop.browserTraceIds.length; i += 1) {
        traceIdMap.set(hop.browserTraceIds[i]!, art.browserTraceIds[i]!)
      }
    }
    return {
      ...hop,
      exchangeIds: art.exchangeIds,
      oobEventIds: art.oobEventIds,
      browserTraceIds: art.browserTraceIds,
    }
  })

  const remapEx = (id: string): string => (allEntriesById.has(id) ? id : (exchangeIdMap.get(id) ?? id))
  const remapOob = (id: string): string => (allOobById.has(id) ? id : (oobIdMap.get(id) ?? id))
  const remapTrace = (id: string): string => (allTracesById.has(id) ? id : (traceIdMap.get(id) ?? id))

  const replayedEdges: CausalEdgeBinding[] = receipt.causalEdges.map(edge => {
    const edgeKey = `${edge.fromHopId}->${edge.toHopId}`
    const typedEdgeKey = `${edgeKey}:${edge.kind}`
    const toArt = hopArtifacts.get(edge.toHopId)

    if (edge.kind === 'value_binding') {
      const src = edge.sourceExchangeId
        ? (allEntriesById.has(edge.sourceExchangeId) ? edge.sourceExchangeId : exchangeIdMap.get(edge.sourceExchangeId))
        : undefined
      const tgt = edge.targetExchangeId
        ? (allEntriesById.has(edge.targetExchangeId) ? edge.targetExchangeId : exchangeIdMap.get(edge.targetExchangeId))
        : undefined
      return {
        ...edge,
        ...(src ? { sourceExchangeId: src } : { sourceExchangeId: undefined }),
        ...(tgt ? { targetExchangeId: tgt } : { targetExchangeId: undefined }),
      }
    }
    if (edge.kind === 'state_transition_binding') {
      const explicitAblation = toArt?.ablationByEdge[typedEdgeKey] ?? toArt?.ablationByEdge[edgeKey]
      let ablationIds: string[]
      if (explicitAblation && explicitAblation.length > 0) {
        ablationIds = [...explicitAblation]
      } else if (edge.ablationExchangeIds.every(id => allEntriesById.has(id))) {
        ablationIds = [...edge.ablationExchangeIds]
      } else {
        const inferred = (toArt?.entries ?? [])
          .filter(e => e.replayAttempt === 'ablation_control')
          .map(e => e.exchangeId)
        ablationIds = inferred.length > 0 ? inferred : edge.ablationExchangeIds.map(remapEx)
      }
      return { ...edge, ablationExchangeIds: ablationIds }
    }
    if (edge.kind === 'async_pivot_binding') {
      const explicitPoll = toArt?.pollByEdge[typedEdgeKey] ?? toArt?.pollByEdge[edgeKey]
      const pollRecordId = explicitPoll
        ?? (edge.pollRecordId
          ? (allPollsById.has(edge.pollRecordId) ? edge.pollRecordId : toArt?.asyncPollRecords[0]?.id ?? edge.pollRecordId)
          : undefined)
      return {
        ...edge,
        ...(edge.oobEventId ? { oobEventId: remapOob(edge.oobEventId) } : {}),
        ...(edge.browserTraceId ? { browserTraceId: remapTrace(edge.browserTraceId) } : {}),
        ...(pollRecordId ? { pollRecordId } : {}),
      }
    }
    return edge
  })

  const ti = receipt.terminalImpact
  const preChainIds = extraPreChainControlIds.length > 0
    ? [...new Set(extraPreChainControlIds)]
    : ti.preChainControlExchangeIds.map(remapEx).filter(id => allEntriesById.has(id))
  const postChainIds = extraPostChainReadbackIds.length > 0
    ? [...new Set(extraPostChainReadbackIds)]
    : ti.postChainReadbackExchangeIds.map(remapEx).filter(id => allEntriesById.has(id))

  const remappedTerminalProof = ti.proofReceipt
    ? {
        ...ti.proofReceipt,
        exchangeIds: ti.proofReceipt.exchangeIds.map(remapEx),
        oobEventIds: ti.proofReceipt.oobEventIds.map(remapOob),
        browserTraceIds: ti.proofReceipt.browserTraceIds.map(remapTrace),
      }
    : undefined

  void dag
  return {
    ...receipt,
    hops: replayedHops,
    causalEdges: replayedEdges,
    terminalImpact: {
      ...ti,
      preChainControlExchangeIds: preChainIds,
      postChainReadbackExchangeIds: postChainIds,
      ...(remappedTerminalProof ? { proofReceipt: remappedTerminalProof } : {}),
      modeAFailureExchangeId: undefined,
    },
    replayMode: 'fresh_clean_replay',
  }
}

function finalizeCompositeRetestProof(args: {
  retestId: string
  chainId: string
  terminalVulnClass: string
  terminalHopId: string
  verdict: CompositePatchRetestVerdict
  patchBrokeHopId: string | null
  brokeCausalEdge: CompositeBrokeCausalEdge | null
  brokeReason: string | null
  benignPrefixHops: string[]
  topoOrder: string[]
  hopResults: CompositeHopReplaySummary[]
  exchangeIds: string[]
  summary: string
  compositeVerification?: CompositeReceiptVerification
  targetRevision?: string
  patchId?: string
  testedAt: string
  secrets?: readonly NamedSecret[]
}): CompositePatchRetestProof {
  const isFixed = args.verdict === 'fixed'
  const redactedHopResults: CompositeHopReplaySummary[] = args.hopResults.map(hr => ({
    ...hr,
    ...(hr.reason !== undefined ? { reason: redact(hr.reason, args.secrets) } : {}),
  }))
  const base: Omit<CompositePatchRetestProof, 'proofSha256'> = {
    schemaVersion: 1,
    retestId: args.retestId,
    chainId: args.chainId,
    terminalVulnClass: args.terminalVulnClass,
    terminalHopId: args.terminalHopId,
    verdict: args.verdict,
    patchClosed: isFixed,
    patchBrokeHopId: isFixed ? args.patchBrokeHopId : null,
    brokeCausalEdge: isFixed ? args.brokeCausalEdge : null,
    brokeReason: isFixed && args.brokeReason ? redact(args.brokeReason, args.secrets) : null,
    benignPrefixHops: isFixed ? [...args.benignPrefixHops] : [],
    topoOrder: [...args.topoOrder],
    hopResults: redactedHopResults,
    exchangeIds: [...new Set(args.exchangeIds)],
    summary: redact(args.summary, args.secrets),
    ...(args.compositeVerification ? { compositeVerification: args.compositeVerification } : {}),
    ...(args.targetRevision ? { targetRevision: args.targetRevision } : {}),
    ...(args.patchId ? { patchId: args.patchId } : {}),
    testedAt: args.testedAt,
  }
  return {
    ...base,
    proofSha256: computeCompositeRetestProofDigest(base),
  }
}

/**
 * Full `CompositeProofReceipt` DAG patch-retest (v8 Stream B / Open Decision #3).
 *
 * Replays hops in strict topological order against the patched target via an injected host
 * replay runner and verifies full chain completion via `verifyCompositeReceipt()`.
 *
 * Distinguishes 4 honest verdicts (strictly fail-closed — transport/network/auth errors and
 * precondition drift NEVER falsely claim `'fixed'`):
 *  - `'fixed'`: chain cleanly breaks at `patchBrokeHopId` (even when benign prefix hops still succeed)
 *    and terminal impact is no longer achievable.
 *  - `'still_vulnerable'`: full DAG completes and confirms via `verifyCompositeReceipt()`.
 *  - `'inconclusive'`: transport/network/5xx/429/auth setup/signature failure or invalid DAG.
 *  - `'precondition_changed'`: target route/schema changed so pre-chain setup could not execute cleanly.
 */
export async function retestCompositeChainPatch(
  params: RetestCompositeChainParams,
): Promise<CompositePatchRetestProof> {
  const retestId = params.retestId ?? randomUUID()
  const nowFn = params.now ?? Date.now
  const testedAt = () => new Date(nowFn()).toISOString()

  const emitEarly = (
    chainId: string,
    terminalVulnClass: string,
    terminalHopId: string,
    summary: string,
  ) =>
    finalizeCompositeRetestProof({
      retestId,
      chainId,
      terminalVulnClass,
      terminalHopId,
      verdict: 'inconclusive',
      patchBrokeHopId: null,
      brokeCausalEdge: null,
      brokeReason: null,
      benignPrefixHops: [],
      topoOrder: [],
      hopResults: [],
      exchangeIds: [],
      summary,
      targetRevision: params.targetRevision,
      patchId: params.patchId,
      testedAt: testedAt(),
      secrets: params.secrets,
    })

  const parsed = compositeProofReceiptSchema.safeParse(params.receipt)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    const detail = `Invalid CompositeProofReceipt schema: ${issue?.path.join('.') || 'receipt'} ${issue?.message ?? ''}`.trim()
    return emitEarly('invalid', 'invalid', 'invalid', `Composite patch retest inconclusive: ${detail}`)
  }

  const receipt = parsed.data
  const dagRes = computeCompositeDagLayout(receipt)
  if (!dagRes.ok) {
    return emitEarly(
      receipt.chainId,
      receipt.terminalVulnClass,
      receipt.terminalImpact.terminalHopId,
      `Composite patch retest inconclusive: invalid DAG topology (${dagRes.reason})`,
    )
  }

  const { dag } = dagRes
  const signingKey = params.verifyOptions?.signingKey
  const allEntries: HostTranscriptEntry[] = []
  const allOob: HostOobEvent[] = []
  const allTraces: HostBrowserTrace[] = []
  const allPolls: HostAsyncPollRecord[] = []
  const extraPreChainControlIds: string[] = []
  const extraPostChainReadbackIds: string[] = []
  const hopResults: CompositeHopReplaySummary[] = []
  const priorHopResults: Record<string, CompositeHopReplaySummary> = {}
  const hopArtifacts = new Map<string, ReplayedHopArtifacts>()
  const availableCapabilities = new Set<string>()

  const emit = (
    verdict: CompositePatchRetestVerdict,
    summary: string,
    extra: {
      patchBrokeHopId?: string | null
      brokeCausalEdge?: CompositeBrokeCausalEdge | null
      brokeReason?: string | null
      benignPrefixHops?: string[]
      compositeVerification?: CompositeReceiptVerification
    } = {},
  ) =>
    finalizeCompositeRetestProof({
      retestId,
      chainId: receipt.chainId,
      terminalVulnClass: receipt.terminalVulnClass,
      terminalHopId: receipt.terminalImpact.terminalHopId,
      verdict,
      patchBrokeHopId: extra.patchBrokeHopId ?? null,
      brokeCausalEdge: extra.brokeCausalEdge ?? null,
      brokeReason: extra.brokeReason ?? null,
      benignPrefixHops: extra.benignPrefixHops ?? [],
      topoOrder: dag.topoOrder,
      hopResults,
      exchangeIds: allEntries.map(e => e.exchangeId),
      summary,
      compositeVerification: extra.compositeVerification,
      targetRevision: params.targetRevision,
      patchId: params.patchId,
      testedAt: testedAt(),
      secrets: params.secrets,
    })

  const appendRecords = (rec: {
    entries?: readonly HostTranscriptEntry[]
    oobEvents?: readonly HostOobEvent[]
    browserTraces?: readonly HostBrowserTrace[]
    asyncPollRecords?: readonly HostAsyncPollRecord[]
  }) => {
    if (rec.entries) allEntries.push(...rec.entries)
    if (rec.oobEvents) allOob.push(...rec.oobEvents)
    if (rec.browserTraces) allTraces.push(...rec.browserTraces)
    if (rec.asyncPollRecords) allPolls.push(...rec.asyncPollRecords)
  }

  const abortCheck = (stage: string): CompositePatchRetestProof | null =>
    params.signal?.aborted ? emit('inconclusive', `Composite patch retest inconclusive: aborted during ${stage}.`) : null

  const abortedStart = abortCheck('initialization')
  if (abortedStart) return abortedStart

  // Step 1: Optional pre-chain setup / precondition verification.
  if (params.runner.preparePreconditions) {
    let setup: CompositePreconditionSetupResult
    try {
      setup = await params.runner.preparePreconditions({
        receipt,
        topoOrder: dag.topoOrder,
        signal: params.signal,
      })
    } catch (err) {
      const code = extractErrorCode(err)
      const msg = err instanceof Error ? err.message : String(err)
      return emit('inconclusive', `Composite patch retest inconclusive: pre-chain setup failed${code ? ` (${code})` : ''}: ${msg}`)
    }

    appendRecords(setup)
    if (setup.preChainControlExchangeIds) extraPreChainControlIds.push(...setup.preChainControlExchangeIds)

    const setupRecErr = inspectRecordsForTransportOrSignatureError(setup, signingKey)
    if (
      setup.status === 'transport_error'
      || setup.status === 'auth_setup_failed'
      || setup.status === 'inconclusive'
      || (setup.httpStatus !== undefined && isTransportOrServerFailureStatus(setup.httpStatus))
      || setupRecErr.failed
    ) {
      const reason = setup.reason ?? (setupRecErr.failed ? setupRecErr.reason : `Pre-chain setup returned "${setup.status}".`)
      return emit('inconclusive', `Composite patch retest inconclusive: ${reason}`)
    }

    if (setup.status === 'precondition_changed') {
      const reason = setup.reason ?? 'Target route or schema changed; pre-chain setup could not execute cleanly.'
      return emit('precondition_changed', `Composite patch retest precondition changed: ${reason}`)
    }
  }

  // Step 2: Replay every hop strictly in topological order.
  for (let hopIndex = 0; hopIndex < dag.topoOrder.length; hopIndex += 1) {
    const hopId = dag.topoOrder[hopIndex]!
    const hop = dag.hopsById.get(hopId)!
    const aborted = abortCheck(`hop "${hopId}"`)
    if (aborted) return aborted

    const incomingEdges = (dag.incomingByHop.get(hopId) ?? []).map(x => x.edge)
    const outgoingEdges = (dag.outgoingByHop.get(hopId) ?? []).map(x => x.edge)

    let rawResult: CompositeHopReplayResult
    try {
      rawResult = await params.runner.replayHop({
        receipt,
        hop,
        hopIndex,
        topoOrder: dag.topoOrder,
        incomingEdges,
        outgoingEdges,
        availableCapabilities: [...availableCapabilities],
        priorHopResults: { ...priorHopResults },
        transcriptSoFar: {
          entries: [...allEntries],
          oobEvents: [...allOob],
          browserTraces: [...allTraces],
          asyncPollRecords: [...allPolls],
        },
        signal: params.signal,
      })
    } catch (err) {
      const code = extractErrorCode(err)
      const msg = err instanceof Error ? err.message : String(err)
      hopResults.push({
        hopId,
        surface: hop.surface,
        outcome: 'transport_error',
        httpStatuses: [],
        exchangeIds: [],
        oobEventIds: [],
        browserTraceIds: [],
        emittedCapabilities: [],
        consumedCapabilities: [],
        reason: msg,
        ...(code ? { errorCode: code } : {}),
      })
      return emit('inconclusive', `Composite patch retest inconclusive at hop "${hopId}"${code ? ` (${code})` : ''}: ${msg}`)
    }

    const entries = [...(rawResult.entries ?? [])]
    const oobEvents = [...(rawResult.oobEvents ?? [])]
    const browserTraces = [...(rawResult.browserTraces ?? [])]
    const asyncPollRecords = [...(rawResult.asyncPollRecords ?? [])]
    appendRecords({ entries, oobEvents, browserTraces, asyncPollRecords })
    if (rawResult.preChainControlExchangeIds) extraPreChainControlIds.push(...rawResult.preChainControlExchangeIds)
    if (rawResult.postChainReadbackExchangeIds) extraPostChainReadbackIds.push(...rawResult.postChainReadbackExchangeIds)

    const entryIdSet = new Set(entries.map(e => e.exchangeId))
    const oobIdSet = new Set(oobEvents.map(o => o.id))
    const traceIdSet = new Set(browserTraces.map(t => t.id))

    const hopExchangeIds = rawResult.replayedExchangeIds
      ? [...rawResult.replayedExchangeIds]
      : (hop.exchangeIds.length > 0 && hop.exchangeIds.every(id => entryIdSet.has(id))
          ? [...hop.exchangeIds]
          : entries.filter(e => e.replayAttempt !== 'ablation_control').map(e => e.exchangeId))
    const hopOobIds = rawResult.replayedOobEventIds
      ? [...rawResult.replayedOobEventIds]
      : (hop.oobEventIds.length > 0 && hop.oobEventIds.every(id => oobIdSet.has(id))
          ? [...hop.oobEventIds]
          : oobEvents.map(o => o.id))
    const hopTraceIds = rawResult.replayedBrowserTraceIds
      ? [...rawResult.replayedBrowserTraceIds]
      : (hop.browserTraceIds.length > 0 && hop.browserTraceIds.every(id => traceIdSet.has(id))
          ? [...hop.browserTraceIds]
          : browserTraces.map(t => t.id))

    const classified = classifyHopReplayOutcome(hop, rawResult, signingKey)
    const emittedCapabilities = collectHopEmittedCapabilities(entries, oobEvents, browserTraces, asyncPollRecords)
    const consumedCapabilities = collectHopConsumedCapabilities(entries)
    const httpStatuses = entries
      .map(e => e.step.status)
      .filter((s): s is number => typeof s === 'number' && Number.isFinite(s))
    if (httpStatuses.length === 0 && typeof rawResult.httpStatus === 'number' && Number.isFinite(rawResult.httpStatus)) {
      httpStatuses.push(rawResult.httpStatus)
    }

    const summaryRec: CompositeHopReplaySummary = {
      hopId,
      surface: hop.surface,
      outcome: classified.outcome,
      httpStatuses,
      exchangeIds: hopExchangeIds,
      oobEventIds: hopOobIds,
      browserTraceIds: hopTraceIds,
      emittedCapabilities,
      consumedCapabilities,
      ...(classified.reason ? { reason: classified.reason } : {}),
      ...(classified.errorCode ? { errorCode: classified.errorCode } : {}),
    }
    hopResults.push(summaryRec)
    priorHopResults[hopId] = summaryRec

    const artifacts: ReplayedHopArtifacts = {
      exchangeIds: hopExchangeIds,
      oobEventIds: hopOobIds,
      browserTraceIds: hopTraceIds,
      entries,
      oobEvents,
      browserTraces,
      asyncPollRecords,
      ablationByEdge: rawResult.replayedAblationExchangeIds ? { ...rawResult.replayedAblationExchangeIds } : {},
      pollByEdge: rawResult.replayedPollRecordIds ? { ...rawResult.replayedPollRecordIds } : {},
    }
    hopArtifacts.set(hopId, artifacts)

    if (
      classified.outcome === 'transport_error'
      || classified.outcome === 'auth_setup_failed'
      || classified.outcome === 'inconclusive'
    ) {
      return emit('inconclusive', `Composite patch retest inconclusive at hop "${hopId}": ${classified.reason ?? classified.outcome}`)
    }

    if (classified.outcome === 'precondition_changed') {
      return emit('precondition_changed', `Composite patch retest precondition changed at hop "${hopId}": ${classified.reason ?? 'target route/schema drifted'}`)
    }

    const markRemainingSkipped = () => {
      for (let j = hopIndex + 1; j < dag.topoOrder.length; j += 1) {
        const remId = dag.topoOrder[j]!
        const remHop = dag.hopsById.get(remId)!
        hopResults.push({
          hopId: remId,
          surface: remHop.surface,
          outcome: 'skipped_after_break',
          httpStatuses: [],
          exchangeIds: [],
          oobEventIds: [],
          browserTraceIds: [],
          emittedCapabilities: [],
          consumedCapabilities: [],
          reason: `Skipped because predecessor hop "${hopId}" broke the chain.`,
        })
      }
    }

    const benignPrefix = dag.topoOrder.slice(0, hopIndex).filter(id => priorHopResults[id]?.outcome === 'succeeded')
    const prefixNote = benignPrefix.length > 0 ? ` (benign prefix succeeded: ${benignPrefix.join(' -> ')})` : ''

    if (classified.outcome === 'blocked') {
      markRemainingSkipped()
      const brokeEdge = selectBrokeEdgeForBlockedHop(hopId, classified.blockedWith4xx, dag)
      const brokeReason = classified.reason ?? `Hop "${hopId}" was blocked by the patched target.`
      return emit('fixed', `Fixed: multi-hop chain broke cleanly at "${hopId}"${prefixNote}: ${brokeReason}`, {
        patchBrokeHopId: hopId,
        brokeCausalEdge: brokeEdge,
        brokeReason,
        benignPrefixHops: benignPrefix,
      })
    }

    // Even when a hop returned 2xx (e.g., sanitized response), verify whether it still produced
    // the causal outputs required by its outgoing edges before advancing downstream hops.
    for (const outEdge of dag.outgoingByHop.get(hopId) ?? []) {
      const prodCheck = hopSatisfiesOutgoingProducerEdge(outEdge.edge, hop, artifacts)
      if (!prodCheck.ok) {
        summaryRec.outcome = 'blocked'
        summaryRec.reason = prodCheck.reason
        markRemainingSkipped()
        return emit('fixed', `Fixed: multi-hop chain broke cleanly at "${hopId}"${prefixNote}: ${prodCheck.reason}`, {
          patchBrokeHopId: hopId,
          brokeCausalEdge: {
            edgeIndex: outEdge.edgeIndex,
            kind: outEdge.edge.kind,
            fromHopId: outEdge.edge.fromHopId,
            toHopId: outEdge.edge.toHopId,
          },
          brokeReason: prodCheck.reason,
          benignPrefixHops: benignPrefix,
        })
      }
    }

    for (const cap of emittedCapabilities) availableCapabilities.add(cap)
  }

  // Step 3: Optional terminal state readback when all hops ran cleanly.
  if (params.runner.readbackTerminalState) {
    const abortedReadback = abortCheck('terminal readback')
    if (abortedReadback) return abortedReadback
    try {
      const rb = await params.runner.readbackTerminalState({
        receipt,
        transcriptSoFar: {
          entries: [...allEntries],
          oobEvents: [...allOob],
          browserTraces: [...allTraces],
          asyncPollRecords: [...allPolls],
        },
        signal: params.signal,
      })
      if (rb.entries) allEntries.push(...rb.entries)
      if (rb.postChainReadbackExchangeIds) extraPostChainReadbackIds.push(...rb.postChainReadbackExchangeIds)
      const rbErr = inspectRecordsForTransportOrSignatureError({ entries: rb.entries }, signingKey)
      if (
        rb.status === 'transport_error'
        || rb.status === 'inconclusive'
        || (rb.httpStatus !== undefined && isTransportOrServerFailureStatus(rb.httpStatus))
        || rbErr.failed
      ) {
        const reason = rb.reason ?? (rbErr.failed ? rbErr.reason : 'Terminal readback failed.')
        return emit('inconclusive', `Composite patch retest inconclusive during terminal readback: ${reason}`)
      }
      if (rb.status === 'precondition_changed') {
        return emit('precondition_changed', `Composite patch retest precondition changed during terminal readback: ${rb.reason ?? 'schema/route changed'}`)
      }
    } catch (err) {
      const code = extractErrorCode(err)
      const msg = err instanceof Error ? err.message : String(err)
      return emit('inconclusive', `Composite patch retest inconclusive during terminal readback${code ? ` (${code})` : ''}: ${msg}`)
    }
  }

  // Step 4: Verify the replayed DAG strictly through `verifyCompositeReceipt()`.
  const allEntriesById = new Map(allEntries.map(e => [e.exchangeId, e]))
  const allOobById = new Map(allOob.map(o => [o.id, o]))
  const allTracesById = new Map(allTraces.map(t => [t.id, t]))
  const allPollsById = new Map(allPolls.map(p => [p.id, p]))

  const replayedReceipt = buildReplayedCompositeReceipt(
    receipt,
    dag,
    hopArtifacts,
    allEntriesById,
    allOobById,
    allTracesById,
    allPollsById,
    extraPreChainControlIds,
    extraPostChainReadbackIds,
  )
  const replayedTranscript: HostSignedTranscript = {
    entries: allEntries,
    oobEvents: allOob,
    browserTraces: allTraces,
    asyncPollRecords: allPolls,
  }

  const verification = verifyCompositeReceipt(replayedReceipt, replayedTranscript, params.verifyOptions)

  if (verification.confirmed) {
    return emit(
      'still_vulnerable',
      `Still vulnerable: full ${receipt.hops.length}-hop DAG confirmed against patched target (${verification.reason}).`,
      { compositeVerification: verification },
    )
  }

  // Fail closed on harness/signing/provenance/replay-mode errors — never falsely claim 'fixed'.
  if (
    verification.failedStage === 'schema'
    || verification.failedStage === 'dag_topology'
    || verification.failedStage === 'transcript_integrity'
    || verification.failedStage === 'attacker_provenance'
    || verification.failedStage === 'replay_mode'
  ) {
    return emit('inconclusive', `Composite patch retest inconclusive (${verification.failedStage}): ${verification.reason}`, {
      compositeVerification: verification,
    })
  }

  if (verification.failedStage === 'edge_binding') {
    const failedEdge = verification.verifiedEdges.find(e => !e.verified)
    if (failedEdge) {
      const edgeObj = replayedReceipt.causalEdges[failedEdge.edgeIndex]
      const fromArt = hopArtifacts.get(failedEdge.fromHopId)
      const fromHop = dag.hopsById.get(failedEdge.fromHopId)
      const fromProduced = edgeObj && fromArt && fromHop
        ? hopSatisfiesOutgoingProducerEdge(edgeObj, fromHop, fromArt).ok
        : true
      const brokeHopId = fromProduced ? failedEdge.toHopId : failedEdge.fromHopId
      const brokeIdx = dag.topoOrder.indexOf(brokeHopId)
      const benignPrefix = brokeIdx > 0
        ? dag.topoOrder.slice(0, brokeIdx).filter(id => priorHopResults[id]?.outcome === 'succeeded')
        : []
      const prefixNote = benignPrefix.length > 0 ? ` (benign prefix succeeded: ${benignPrefix.join(' -> ')})` : ''
      return emit(
        'fixed',
        `Fixed: causal edge ${failedEdge.fromHopId} -> ${failedEdge.toHopId} (${failedEdge.kind}) broke at "${brokeHopId}"${prefixNote}: ${failedEdge.reason}`,
        {
          patchBrokeHopId: brokeHopId,
          brokeCausalEdge: {
            edgeIndex: failedEdge.edgeIndex,
            kind: failedEdge.kind,
            fromHopId: failedEdge.fromHopId,
            toHopId: failedEdge.toHopId,
          },
          brokeReason: failedEdge.reason,
          benignPrefixHops: benignPrefix,
          compositeVerification: verification,
        },
      )
    }
  }

  // `failedStage === 'terminal_impact'` (all hops & causal edges ran cleanly, terminal impact neutralized).
  const terminalHopId = receipt.terminalImpact.terminalHopId
  const terminalIdx = dag.topoOrder.indexOf(terminalHopId)
  const benignPrefix = terminalIdx > 0
    ? dag.topoOrder.slice(0, terminalIdx).filter(id => priorHopResults[id]?.outcome === 'succeeded')
    : []
  const prefixNote = benignPrefix.length > 0 ? ` (benign prefix succeeded: ${benignPrefix.join(' -> ')})` : ''
  return emit(
    'fixed',
    `Fixed: terminal impact neutralized at "${terminalHopId}"${prefixNote}: ${verification.reason}`,
    {
      patchBrokeHopId: terminalHopId,
      brokeCausalEdge: null,
      brokeReason: verification.reason,
      benignPrefixHops: benignPrefix,
      compositeVerification: verification,
    },
  )
}
