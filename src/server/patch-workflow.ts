import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  closeSync, constants as fsConstants, cpSync, existsSync, lstatSync,
  mkdtempSync, openSync, readFileSync, readdirSync, realpathSync, rmSync, statSync,
} from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { extname, join, relative, resolve } from 'node:path'
import { z } from 'zod'
import type { Finding, HttpMethod } from '../domain.ts'
import type { DeclarativeReplaySpec, ReplayStep } from '../replay-spec.ts'
import { buildCompositeVerifyOptionsFromGrant } from './agent-script-proof.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import {
  compositeProofReceiptSchema, sha256Hex, signHostRecord, verifyCompositeReceipt, verifyHostRecordSignature,
  type CausalEdgeBinding, type CausalEdgeKind, type CompositeProofReceipt, type CompositeReceiptVerification,
  type CompositeVerifyOptions, type HopReceipt, type HopSurface, type HostAsyncPollRecord,
  type HostBrowserTrace, type HostOobEvent, type HostSignableRecord, type HostSignedTranscript, type HostTranscriptEntry,
} from './composite-receipt.ts'
import { isSensitiveRepoEntry, isSensitiveRepoRelativePath } from './exec-verify.ts'
import { hasVaultScrubbedToken, type HostExchangeFact, type HostFactLog } from './host-fact-log.ts'
import { applyUnifiedDiffToDirectory, type LabRunner } from './lab-runner.ts'
import { isProfileHealthy, resolveProfilePoolForRole, type ResolvedModelProfile } from './model-settings.ts'
import { resolvePersonaIdentity } from './oracle-invariants.ts'
import type { ImpactStep } from './proof-receipt.ts'
import { providerOptionsFor } from './provider-runtime-policy.ts'
import { providerPool, type TelemetryCallback, type UsageCallback } from './provider.ts'
import { redact, type NamedSecret } from './redact.ts'
import { retestReplaySpec } from './replay-verifier.ts'
import { assessRetestHealth, type RetestArmObservation } from './retest-health.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import type { BrokerExchange } from './store-session.ts'
import type { Store } from './store.ts'
import { invertUnifiedDiff, parseUnifiedDiff } from './unified-diff.ts'
import type { WorkerBackend } from './worker-backend.ts'

export type PatchStatus = 'draft' | 'approved' | 'rejected' | 'withheld'
export type CallerCompatibility = 'attacker_only' | 'needs_operator_step' | 'breaks_callers'
export type DynamicRetestVerdict = 'fixed' | 'reproduced' | 'skipped'

export interface PatchCodeLocation { repo: string; file: string; startLine: number; endLine: number; snippet?: string; label?: string }
export interface CoverageInventoryEntry {
  file: string; line?: number; symbol: string
  role: 'primary_sink' | 'sibling_route' | 'sibling_writer' | 'middleware' | 'helper'
  coveredByPatch: boolean; notes: string
}
export interface PatchSyntaxCheckResult { ran: boolean; command?: string; passed: boolean; output?: string; toolchainUnavailable?: boolean }
export interface PatchApplicabilityResult {
  applicable: boolean; filesModified: string[]; syntaxCheck: PatchSyntaxCheckResult
  hasSubstantiveDiffChange: boolean; citedFileModified: boolean; fixAppliedToCitedFile: boolean; error?: string
}
export interface PatchAuthorOutput {
  repo: string; coverageInventory: CoverageInventoryEntry[]; fixBefore: string; fixAfter: string
  diff: string; codeLocations: PatchCodeLocation[]; rationale: string; syntaxCheck: PatchSyntaxCheckResult
  applicability?: PatchApplicabilityResult
}
export interface PatchGateResult {
  gate: 1 | 2 | 3 | 4 | 5 | 6
  name: 'applicability' | 'security_closure' | 'sibling_coverage' | 'caller_compatibility' | 'repo_conventions' | 'dynamic_retest'
  passed: boolean; detail: string; enforcingLocation?: string
}
export interface PatchReviewOutput {
  approved: boolean; status: PatchStatus; callerCompatibility: CallerCompatibility
  gates: PatchGateResult[]; reviewNotes: string; enforcingLocation?: string
}
export interface PatchProposalResult {
  id: string; runId: string; findingId: string; repo: string; status: PatchStatus
  callerCompatibility: CallerCompatibility; fixBefore: string; fixAfter: string; diff: string
  codeLocations: PatchCodeLocation[]; coverageInventory: CoverageInventoryEntry[]; gates: PatchGateResult[]
  reviewNotes: string; dynamicRetestVerdict: DynamicRetestVerdict; dynamicRetestSummary?: string
  patchBrokeHopId?: string | null; compositeVerdict?: CompositePatchRetestVerdict | null
  compositeRetestProof?: CompositePatchRetestProof; labRevision?: string
  createdAt: number; updatedAt: number
}
export type PatchLlmCall = (prompt: { systemPrompt: string; userPrompt: string }) => Promise<string>

export interface PatchLabRetestContext {
  labRunner: LabRunner; runId: string; sanitizedRepoDir?: string; replaySpec: DeclarativeReplaySpec
  replaySpecId?: string; envelopeTrust?: 'host_persisted' | 'untrusted'
  broker: RequestBroker; browser?: ScopedBrowser; canaryBroker?: CanaryBroker; factLog?: HostFactLog
  backend: WorkerBackend; grant: Grant; storage?: Store; assignmentId?: string
  baselineCaller?: BrokerHttpRequest; baselineExpectStatus?: number[]
  compositeReceipt?: CompositeProofReceipt; compositeRunner?: CompositePatchReplayRunner
  compositeVerifyOptions?: CompositeVerifyOptions; hopActors?: Readonly<Record<string, string | null>>
  labRevision?: string; prePatchReproductionProof?: CompositePatchRetestProof
}
export interface PatchWorkflowParams {
  runId: string; finding: Finding & { codeLocations?: PatchCodeLocation[] }; repo: string; reposDir: string
  backend?: WorkerBackend; authorLlmCall?: PatchLlmCall; reviewerLlmCall?: PatchLlmCall
  modelProfiles?: readonly ResolvedModelProfile[]; candidatePatch?: Partial<PatchAuthorOutput>
  labRetest?: PatchLabRetestContext; signal?: AbortSignal; secrets?: readonly NamedSecret[]; onUsage?: UsageCallback
}
export interface FocusedFileContext {
  file: string; startLine?: number; endLine?: number; totalLines: number
  truncated: boolean; includedRanges: Array<[number, number]>; content: string | null
}
export interface SynthesizedBaselineCaller {
  caller: BrokerHttpRequest; expectStatus: number[]
  source: 'explicit' | 'receipt_exchange' | 'recipe_control' | 'spec_control' | 'phase0_exchange'
}

const NO_FOLLOW = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0
const MAX_FULL_FILE_CONTEXT_CHARS = 48_000
const CONTEXT_HEADER_LINES = 40
const CONTEXT_WINDOW_PAD = 120
const MAX_SIBLING_SCAN_FILES = 150
const MAX_SIBLING_HINTS = 10
const SKIP_SCAN_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', 'target', 'vendor'])

const requireFromHere = createRequire(import.meta.url)
let cachedTsMod: typeof import('typescript') | null | undefined

function loadTypeScriptSync(): typeof import('typescript') | null {
  if (cachedTsMod !== undefined) return cachedTsMod
  try {
    const loaded = requireFromHere('typescript') as typeof import('typescript') & { default?: typeof import('typescript') }
    cachedTsMod = loaded.default ?? loaded
  } catch { cachedTsMod = null }
  return cachedTsMod
}

function isSymlink(path: string): boolean {
  try { return lstatSync(path).isSymbolicLink() } catch { return false }
}

function readRegularFileNoFollow(path: string): string | null {
  let fd: number | undefined
  try {
    if (!lstatSync(path).isFile()) return null
    fd = openSync(path, fsConstants.O_RDONLY | NO_FOLLOW)
    return readFileSync(fd, 'utf8')
  } catch { return null } finally {
    if (fd !== undefined) { try { closeSync(fd) } catch { /* ignore */ } }
  }
}

const normalizeRepoRelPath = (file: string): string => file.replace(/^\/+/, '').replace(/\\/g, '/').replace(/^[ab]\//, '')

function validateRepoPath(reposDir: string, repo: string): string {
  const cleanRepo = repo.replace(/^\/+|\/+$/g, '')
  if (!cleanRepo || cleanRepo.includes('\0') || cleanRepo.split('/').some(seg => seg === '..' || seg === '.')) {
    throw new Error(`Invalid repository name for patch workflow: "${repo}"`)
  }
  const baseReal = realpathSync(reposDir)
  const target = resolve(baseReal, cleanRepo)
  if (relative(baseReal, target).startsWith('..') || !existsSync(target) || !statSync(target).isDirectory()) {
    throw new Error(`Mounted repository not found: ${cleanRepo}`)
  }
  if (isSymlink(target)) throw new Error(`Mounted repository is a symlink and cannot be patched: ${cleanRepo}`)
  return realpathSync(target)
}

/** Safely read a repo-relative regular file; refuses traversal, symlinks in any segment, and H-39 sensitive paths. */
function safeReadRepoFile(repoRoot: string, relFile: string): string | null {
  const clean = normalizeRepoRelPath(relFile)
  if (!clean || clean.includes('\0') || clean.split('/').some(seg => !seg || seg === '.' || seg === '..')) return null
  if (isSensitiveRepoRelativePath(clean)) return null
  const full = resolve(repoRoot, clean)
  if (relative(repoRoot, full).startsWith('..') || !existsSync(full)) return null
  let cur = repoRoot
  for (const seg of clean.split('/')) {
    cur = join(cur, seg)
    if (isSymlink(cur)) return null
  }
  return readRegularFileNoFollow(full)
}

/** Copy a repo into an isolated work dir without following links (optionally excluding H-39 sensitive entries). */
export function copyRepoTreeWithoutSymlinks(
  repoRoot: string,
  destRoot: string,
  options: { excludeSensitive?: boolean } = {},
): void {
  const excludeSensitive = options.excludeSensitive === true
  cpSync(repoRoot, destRoot, {
    recursive: true,
    dereference: false,
    verbatimSymlinks: false,
    filter: src => {
      if (isSymlink(src)) return false
      if (!excludeSensitive || src === repoRoot) return true
      const relPosix = relative(repoRoot, src).replace(/\\/g, '/')
      if (!relPosix || relPosix.startsWith('..')) return false
      const name = relPosix.split('/').pop() ?? relPosix
      try { return !isSensitiveRepoEntry(relPosix, name, lstatSync(src).isDirectory()) } catch { return false }
    },
  })
  const stack: string[] = [destRoot]
  while (stack.length > 0) {
    const dir = stack.pop()!
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (isSymlink(full)) throw new Error(`Refusing patch work copy containing a symlink: ${entry.name}`)
      if (entry.isDirectory()) stack.push(full)
    }
  }
}

const FUNC_DECL_RE = /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\b|class\b|def\b|func\b|fn\b|public\b|private\b|protected\b|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?\(|(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|use|all)\s*\(|@[A-Za-z_])/

/** Extract full-file or function-centered line-windowed context (never byte-0 truncated blind). Enforces H-39. */
export function extractFocusedFileContext(
  repoRoot: string,
  relFile: string,
  targetRanges: ReadonlyArray<{ startLine: number; endLine?: number }>,
  maxChars = MAX_FULL_FILE_CONTEXT_CHARS,
): FocusedFileContext {
  const text = safeReadRepoFile(repoRoot, relFile)
  if (text === null) return { file: relFile, totalLines: 0, truncated: false, includedRanges: [], content: null }
  const lines = text.replace(/\r\n/g, '\n').split('\n')
  const totalLines = lines.length
  const first = targetRanges[0]
  if (text.length <= maxChars) {
    return {
      file: relFile, ...(first ? { startLine: first.startLine, endLine: first.endLine ?? first.startLine } : {}),
      totalLines, truncated: false, includedRanges: totalLines > 0 ? [[1, totalLines]] : [], content: text,
    }
  }

  const rawWindows: Array<[number, number]> = totalLines > 0 ? [[1, Math.min(totalLines, CONTEXT_HEADER_LINES)]] : []
  const targets = targetRanges.length > 0 ? targetRanges : [{ startLine: 1, endLine: Math.min(totalLines, CONTEXT_WINDOW_PAD) }]
  for (const r of targets) {
    const s = Math.max(1, Math.min(totalLines, r.startLine))
    const e = Math.max(s, Math.min(totalLines, r.endLine ?? r.startLine))
    let winStart = Math.max(1, s - CONTEXT_WINDOW_PAD)
    for (let ln = s; ln >= winStart; ln -= 1) {
      if (FUNC_DECL_RE.test(lines[ln - 1] ?? '')) { winStart = Math.max(1, ln - 5); break }
    }
    rawWindows.push([winStart, Math.min(totalLines, e + CONTEXT_WINDOW_PAD)])
  }

  rawWindows.sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const merged: Array<[number, number]> = []
  for (const w of rawWindows) {
    const prev = merged[merged.length - 1]
    if (prev && w[0] <= prev[1] + 8) prev[1] = Math.max(prev[1], w[1])
    else merged.push([w[0], w[1]])
  }

  const chunks: string[] = [], included: Array<[number, number]> = []
  let usedChars = 0
  for (const [start, end] of merged) {
    const block = `--- lines ${start}-${end} of ${totalLines} ---\n`
      + lines.slice(start - 1, end).map((line, idx) => `${start + idx}: ${line}`).join('\n') + '\n'
    if (usedChars + block.length <= maxChars || included.length === 0) {
      chunks.push(block.slice(0, Math.max(256, maxChars - usedChars)))
      included.push([start, end])
      usedChars += block.length
    }
  }
  return {
    file: relFile, ...(first ? { startLine: first.startLine, endLine: first.endLine ?? first.startLine } : {}),
    totalLines, truncated: true, includedRanges: included, content: chunks.join('\n'),
  }
}

function collectSiblingHints(
  repoRoot: string,
  excludedFiles: ReadonlySet<string>,
  searchTerms: readonly string[],
): Array<{ file: string; line: number; excerpt: string }> {
  const cleanTerms = [...new Set(searchTerms.map(t => t.trim()).filter(t => t.length >= 4 && t.length <= 80))].slice(0, 6)
  if (!cleanTerms.length) return []
  const hits: Array<{ file: string; line: number; excerpt: string }> = []
  const stack: string[] = ['']
  let scanned = 0
  while (stack.length > 0 && scanned < MAX_SIBLING_SCAN_FILES && hits.length < MAX_SIBLING_HINTS) {
    const relDir = stack.pop()!
    const absDir = relDir ? join(repoRoot, relDir) : repoRoot
    let entries
    try { entries = readdirSync(absDir, { withFileTypes: true }) } catch { continue }
    for (const entry of entries) {
      if (scanned >= MAX_SIBLING_SCAN_FILES || hits.length >= MAX_SIBLING_HINTS) break
      const relPosix = relDir ? `${relDir}/${entry.name}` : entry.name
      const full = join(absDir, entry.name)
      if (isSymlink(full)) continue
      if (entry.isDirectory()) {
        if (!SKIP_SCAN_DIRS.has(entry.name) && !isSensitiveRepoEntry(relPosix, entry.name, true)) stack.push(relPosix)
        continue
      }
      if (!entry.isFile() || excludedFiles.has(relPosix) || isSensitiveRepoEntry(relPosix, entry.name, false)) continue
      if (!/\.(?:[cm]?[jt]sx?|py|go|java|kt|rb|php|rs|cs)$/i.test(entry.name)) continue
      scanned += 1
      const content = readRegularFileNoFollow(full)
      if (!content || content.length > 256_000) continue
      const lines = content.split('\n')
      for (let i = 0; i < lines.length && hits.length < MAX_SIBLING_HINTS; i += 1) {
        if (cleanTerms.some(term => lines[i]!.includes(term))) {
          hits.push({ file: relPosix, line: i + 1, excerpt: lines[i]!.trim().slice(0, 180) })
          break
        }
      }
    }
  }
  return hits
}

function extractJsonBlock(raw: string): unknown {
  const trimmed = raw.trim()
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  const body = fence ? fence[1]!.trim() : trimmed
  const start = body.indexOf('{'), end = body.lastIndexOf('}')
  if (start === -1 || end <= start) throw new Error('Expected JSON object in patch agent response.')
  return JSON.parse(body.slice(start, end + 1))
}

function makeFreshProviderCall(
  profiles: readonly ResolvedModelProfile[],
  scenario: string,
  options: {
    runId?: string
    signal?: AbortSignal
    secrets?: readonly NamedSecret[]
    onUsage?: UsageCallback
    onTelemetry?: TelemetryCallback
  },
): PatchLlmCall {
  return async ({ systemPrompt, userPrompt }) => {
    const routed = resolveProfilePoolForRole('reasoning', profiles)
    const primary = routed.find(p => isProfileHealthy(p, Date.now())) ?? routed[0]
    const purpose = scenario === 'patch-reviewer' ? 'patch-reviewer' : 'patch-author'
    const { models, model } = providerPool(
      routed,
      scenario,
      providerOptionsFor(options.runId, 'reasoning', purpose, {
        profile: primary,
        signal: options.signal,
        secrets: options.secrets,
        onUsage: options.onUsage,
        onTelemetry: options.onTelemetry,
        maxCalls: 2,
        thinkingLevel: primary?.thinkingLevel === 'off' ? 'off' : 'high',
      }),
    )
    const stream = models.stream(model, {
      systemPrompt: redact(systemPrompt, options.secrets),
      messages: [{ role: 'user', content: redact(userPrompt, options.secrets), timestamp: Date.now() }],
      tools: [],
    })
    let out = ''
    for await (const ev of stream) if (ev.type === 'text_delta' && typeof ev.delta === 'string') out += ev.delta
    const res = await stream.result()
    if (!out && Array.isArray(res.content)) {
      out = res.content.filter((p): p is { type: 'text'; text: string } => p.type === 'text' && typeof p.text === 'string').map(p => p.text).join('')
    }
    return out.trim()
  }
}

/** Build a hunk-counted unified diff replacing `fixBefore` with `fixAfter` (disambiguating by `hintStartLine` and handling mid-line snippets). */
export function buildUnifiedDiffFromSnippet(
  relFile: string,
  originalContent: string,
  fixBefore: string,
  fixAfter: string,
  hintStartLine?: number,
): { diff: string; startLine: number; endLine: number } {
  const normOrig = originalContent.replace(/\r\n/g, '\n')
  const normBefore = fixBefore.replace(/\r\n/g, '\n')
  const normAfter = fixAfter.replace(/\r\n/g, '\n')
  if (!normBefore) throw new Error(`fixBefore snippet cannot be empty for ${relFile}.`)

  let idx = -1
  if (hintStartLine && hintStartLine > 0) {
    let bestDist = Number.POSITIVE_INFINITY
    for (let pos = 0; pos <= normOrig.length;) {
      const found = normOrig.indexOf(normBefore, pos)
      if (found === -1) break
      const dist = Math.abs(normOrig.slice(0, found).split('\n').length - hintStartLine)
      if (dist < bestDist) { bestDist = dist; idx = found }
      pos = found + 1
    }
  } else {
    idx = normOrig.indexOf(normBefore)
  }
  if (idx === -1) throw new Error(`fixBefore snippet not found verbatim in ${relFile}.`)

  const updated = normOrig.slice(0, idx) + normAfter + normOrig.slice(idx + normBefore.length)
  const splitLines = (s: string) => s === '' ? [] : (s.endsWith('\n') ? s.slice(0, -1).split('\n') : s.split('\n'))
  const origLines = splitLines(normOrig), newLines = splitLines(updated)
  const startLine = normOrig.slice(0, idx).split('\n').length
  const matchEnd = idx + normBefore.length
  const endProbe = matchEnd > idx && normBefore.endsWith('\n') ? matchEnd - 1 : matchEnd
  const endLine = Math.min(origLines.length, Math.max(startLine, normOrig.slice(0, endProbe).split('\n').length))
  const newEndLine = Math.max(startLine - 1, endLine + (newLines.length - origLines.length))

  const ctxStart = Math.max(0, startLine - 3)
  const oldCtxEnd = Math.min(origLines.length, endLine + 2)
  const preCtx = origLines.slice(ctxStart, startLine - 1).map(l => ' ' + l)
  const removed = origLines.slice(startLine - 1, endLine).map(l => '-' + l)
  const added = newLines.slice(startLine - 1, newEndLine).map(l => '+' + l)
  const postCtx = origLines.slice(endLine, oldCtxEnd).map(l => ' ' + l)
  const cleanRel = normalizeRepoRelPath(relFile)
  return {
    diff: [
      `--- a/${cleanRel}`, `+++ b/${cleanRel}`,
      `@@ -${ctxStart + 1},${preCtx.length + removed.length + postCtx.length} +${ctxStart + 1},${preCtx.length + added.length + postCtx.length} @@`,
      ...preCtx, ...removed, ...added, ...postCtx,
    ].join('\n') + '\n',
    startLine,
    endLine,
  }
}

function isFixAfterInChangedHunks(
  parsedPatches: ReturnType<typeof parseUnifiedDiff>,
  primaryRelFile: string,
  normPatched: string,
  normFixBefore: string,
  normFixAfter: string,
): boolean {
  const matching = parsedPatches.filter(fp => normalizeRepoRelPath(fp.normalizedPath) === primaryRelFile)
  if (!matching.length) return false
  if (normFixAfter.trim() === '') {
    const removed = matching.flatMap(fp => fp.hunks.flatMap(h => h.entries.filter(e => e.kind === 'remove').map(e => e.text)))
    const beforeNonEmpty = normFixBefore.replace(/\n$/, '').split('\n').filter(l => l.trim() !== '')
    const ok = beforeNonEmpty.length === 0 ? removed.length > 0 : beforeNonEmpty.every(line => removed.some(r => r.includes(line) || line.includes(r)))
    return ok && !normPatched.includes(normFixBefore)
  }
  const targetAfter = normFixAfter.replace(/\n$/, '')
  const targetLines = targetAfter.split('\n').filter(l => l.trim() !== '')
  const beforeSet = new Set(normFixBefore.replace(/\n$/, '').split('\n'))
  const changed = targetLines.filter(l => !beforeSet.has(l))
  const required = changed.length > 0 ? changed : targetLines
  for (const fp of matching) {
    for (const h of fp.hunks) {
      const added = h.entries.filter(e => e.kind === 'add').map(e => e.text)
      if (added.join('\n').includes(targetAfter)) return true
      const newBlock = h.entries.filter(e => e.kind === 'add' || e.kind === 'context').map(e => e.text).join('\n')
      if (newBlock.includes(targetAfter) && required.length > 0 && required.every(line => added.some(a => a === line || a.includes(line)))) return true
    }
  }
  return false
}

const SYNTAX_UNAVAILABLE_PREFIX = 'KOVO_SYNTAX_UNAVAILABLE:'

const PATCH_SYNTAX_CHECK_SCRIPT = [
  "import { execFileSync } from 'node:child_process'",
  "import { copyFileSync, cpSync, mkdirSync, readFileSync, rmSync } from 'node:fs'",
  "import { dirname, join, resolve } from 'node:path'",
  "const manifest = JSON.parse(readFileSync('/evidence/patch_syntax_manifest.json', 'utf8'))",
  "const reposRoot = resolve('/repos'), repoSrc = resolve(reposRoot, manifest.repo)",
  "if (!repoSrc.startsWith(reposRoot + '/')) throw new Error('Invalid repo path')",
  "const workRepo = resolve('/tmp/work-repo'); mkdirSync(workRepo, { recursive: true }); cpSync(repoSrc, workRepo, { recursive: true })",
  "for (const rel of manifest.deletedFiles ?? []) { const t = resolve(workRepo, rel); if (!t.startsWith(workRepo + '/')) throw new Error('Invalid deleted file path'); rmSync(t, { force: true }) }",
  "for (const e of manifest.files ?? []) { const t = resolve(workRepo, e.origName); if (!t.startsWith(workRepo + '/')) throw new Error('Invalid modified file path'); mkdirSync(dirname(t), { recursive: true }); copyFileSync(join('/evidence', e.stagedName), t) }",
  "const unavailable = []",
  "const runBin = (bin, args, origName) => { try { const out = execFileSync(bin, args, { cwd: workRepo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); if (out) process.stdout.write(out); return true } catch (err) { if (err && err.code === 'ENOENT') { const l = '" + SYNTAX_UNAVAILABLE_PREFIX + "' + bin + ':' + origName; unavailable.push(l); console.log(l); return false } if (err?.stdout) process.stdout.write(String(err.stdout)); if (err?.stderr) process.stderr.write(String(err.stderr)); process.exit(typeof err?.status === 'number' && err.status !== 0 ? err.status : 1) } }",
  "let ranCheck = false",
  "for (const e of manifest.files ?? []) { const n = e.origName, s = join('/evidence', e.stagedName)",
  "  if (/\\.(?:[cm]?js)$/i.test(n)) ranCheck = runBin(process.execPath, ['--check', s], n) || ranCheck",
  "  else if (/\\.py$/i.test(n)) ranCheck = runBin('python3', ['-m', 'py_compile', s], n) || ranCheck",
  "  else if (/\\.go$/i.test(n)) ranCheck = runBin('go', ['vet', './' + n], n) || ranCheck",
  "  else if (/\\.(?:java|kt)$/i.test(n)) { mkdirSync('/tmp/kovo-javac', { recursive: true }); ranCheck = runBin('javac', ['-proc:none', '-d', '/tmp/kovo-javac', s], n) || ranCheck }",
  "  else if (/\\.jsx$/i.test(n)) { const l = '" + SYNTAX_UNAVAILABLE_PREFIX + "jsx:' + n; unavailable.push(l); console.log(l) }",
  "}",
  "const tsFiles = (manifest.files ?? []).filter(e => /\\.(?:[cm]?ts|tsx)$/i.test(e.origName))",
  "if (tsFiles.length > 0) { if (manifest.hasTsconfig) ranCheck = runBin('tsc', ['--noEmit', '--skipLibCheck', '-p', join(workRepo, 'tsconfig.json')], tsFiles.map(e => e.origName).join(',')) || ranCheck; else for (const f of tsFiles) { const l = '" + SYNTAX_UNAVAILABLE_PREFIX + "tsc_no_tsconfig:' + f.origName; unavailable.push(l); console.log(l) } }",
  "if (!ranCheck && unavailable.length === 0) console.log('syntax-ok')",
].join('\n') + '\n'

function checkTsSyntaxSync(tsMod: typeof import('typescript'), fileName: string, source: string): string | null {
  const res = tsMod.transpileModule(source, {
    fileName,
    reportDiagnostics: true,
    compilerOptions: { allowJs: true, jsx: tsMod.JsxEmit.Preserve, target: tsMod.ScriptTarget.ESNext, module: tsMod.ModuleKind.ESNext },
  })
  const errs = (res.diagnostics ?? []).filter(d => d.category === tsMod.DiagnosticCategory.Error)
  return errs.length > 0 ? errs.map(d => tsMod.flattenDiagnosticMessageText(d.messageText, '\n')).join('; ') : null
}

function checkBalancedDelimiters(content: string, isPython: boolean): string | null {
  const stack: string[] = []
  const pairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' }
  let mode: '' | "'" | '"' | '`' | "'''" | '"""' | 'line' | 'block' = ''
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i]!, next = content[i + 1] ?? '', tri = content.slice(i, i + 3)
    if (mode === 'line') { if (ch === '\n') mode = ''; continue }
    if (mode === 'block') { if (ch === '*' && next === '/') { mode = ''; i += 1 } continue }
    if (mode === "'''" || mode === '"""') {
      if (ch === '\\') { i += 1; continue }
      if (tri === mode) { mode = ''; i += 2 }
      continue
    }
    if (mode === "'" || mode === '"' || mode === '`') {
      if (ch === '\\') { i += 1; continue }
      if (ch === mode || (mode !== '`' && ch === '\n')) mode = ''
      continue
    }
    if (isPython && ch === '#') { mode = 'line'; continue }
    if (!isPython && ch === '/' && next === '/') { mode = 'line'; i += 1; continue }
    if (!isPython && ch === '/' && next === '*') { mode = 'block'; i += 1; continue }
    if (isPython && (tri === "'''" || tri === '"""')) { mode = tri; i += 2; continue }
    if (ch === "'" || ch === '"' || (!isPython && ch === '`')) { mode = ch; continue }
    if (pairs[ch]) stack.push(pairs[ch]!)
    else if (ch === ')' || ch === ']' || ch === '}') {
      const exp = stack.pop()
      if (exp !== ch) return `unbalanced delimiter "${ch}"${exp ? ` (expected "${exp}")` : ''}`
    }
  }
  return stack.length > 0 ? `unclosed delimiter(s): expected ${stack.reverse().join('')}` : null
}

/** Deterministic post-patch static AST sanity check (TS/JS parse, JSON parse, conflict markers, balanced delimiters). */
export function verifyStaticAstPostPatch(workDir: string, filesModified: readonly string[]): { ok: boolean; issues: string[] } {
  const issues: string[] = []
  const tsMod = loadTypeScriptSync()
  for (const rel of filesModified) {
    const isJsTs = /\.(?:[cm]?[jt]sx?)$/i.test(rel), isJson = /\.json$/i.test(rel)
    const isOtherCode = /\.(?:py|go|java|kt|rb|php|rs|cs|c|cc|cpp|h|hpp)$/i.test(rel)
    if (!isJsTs && !isJson && !isOtherCode) continue
    let content = ''
    try { content = readFileSync(join(workDir, rel), 'utf8') } catch { issues.push(`${rel}: unreadable after patch`); continue }
    if (/^(?:<{7}|={7}|>{7})/m.test(content)) issues.push(`${rel}: unresolved merge-conflict marker`)
    if (isJson) {
      try { JSON.parse(content) } catch (err) { issues.push(`${rel}: invalid JSON (${err instanceof Error ? err.message : String(err)})`) }
      continue
    }
    if (isJsTs && tsMod) {
      const err = checkTsSyntaxSync(tsMod, rel, content)
      if (err) issues.push(`${rel}: syntax error (${err})`)
      continue
    }
    const delimErr = checkBalancedDelimiters(content, /\.py$/i.test(rel))
    if (delimErr) issues.push(`${rel}: ${delimErr}`)
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
  let ran = false, passed = true, toolchainUnavailable = false
  let tsMod = loadTypeScriptSync()
  if (jsLike.length > 0 && !tsMod) {
    try { const imp = await import('typescript'); tsMod = imp.default ?? imp } catch { tsMod = null }
  }
  for (const rel of jsLike) {
    const fullPath = join(workDir, rel)
    if (tsMod) {
      ran = true
      const err = checkTsSyntaxSync(tsMod, rel, readFileSync(fullPath, 'utf8'))
      if (!err) outputs.push(`OK: ts syntax check ${rel}`)
      else { passed = false; outputs.push(`FAIL: ${rel}: ${err}`) }
    } else if (!/\.(?:[cm]?ts|tsx|jsx)$/i.test(rel)) {
      ran = true
      try { execFileSync(process.execPath, ['--check', fullPath], { stdio: 'pipe', timeout: 10_000 }); outputs.push(`OK: node --check ${rel}`) }
      catch (err) { passed = false; outputs.push(`FAIL: ${rel}: ${((err as { stderr?: Buffer }).stderr?.toString('utf8') ?? String(err)).trim()}`) }
    } else {
      toolchainUnavailable = true; passed = false; outputs.push(`toolchain_unavailable: typescript (${rel})`)
    }
  }
  for (const rel of pyLike) {
    try { execFileSync('python3', ['-m', 'py_compile', join(workDir, rel)], { stdio: 'pipe', timeout: 10_000 }); ran = true; outputs.push(`OK: py_compile ${rel}`) }
    catch (err) {
      if ((err as { code?: string })?.code === 'ENOENT') { toolchainUnavailable = true; passed = false; outputs.push(`toolchain_unavailable: python3 (${rel})`) }
      else { ran = true; passed = false; outputs.push(`FAIL: ${rel}: ${((err as { stderr?: Buffer }).stderr?.toString('utf8') ?? String(err)).trim()}`) }
    }
  }
  if (fallbackNote && !ran) outputs.push(fallbackNote)
  return {
    ran, command: ran ? 'offline syntax check (ts/node/py_compile) + static AST sanity' : undefined,
    passed, ...(toolchainUnavailable ? { toolchainUnavailable: true } : {}), output: outputs.join('\n').slice(0, 2000) || undefined,
  }
}

const failApplicability = (error: string, output?: string): PatchApplicabilityResult => ({
  applicable: false, filesModified: [], syntaxCheck: { ran: false, passed: false, ...(output ? { output } : {}) },
  hasSubstantiveDiffChange: false, citedFileModified: false, fixAppliedToCitedFile: false, error,
})

export async function verifyPatchApplicability(params: {
  repoRoot: string; repo: string; reposDir: string; diff: string; fixBefore: string
  fixAfter?: string; codeLocations: readonly PatchCodeLocation[]; backend?: WorkerBackend; signal?: AbortSignal
  runId?: string
}): Promise<PatchApplicabilityResult> {
  const { repoRoot, repo, reposDir, diff, fixBefore, fixAfter, codeLocations, backend, signal, runId } = params
  const primaryRelFile = codeLocations.length > 0 ? normalizeRepoRelPath(codeLocations[0]!.file) : null
  if (primaryRelFile && isSensitiveRepoRelativePath(primaryRelFile)) {
    return failApplicability(`Refusing access to sensitive repository path: ${primaryRelFile}.`, `Sensitive path denied: ${primaryRelFile}`)
  }
  const originalCitedContent = primaryRelFile ? safeReadRepoFile(repoRoot, primaryRelFile) : null
  if (fixBefore.trim() && codeLocations.length > 0) {
    const primary = codeLocations[0]!
    if (originalCitedContent === null) return failApplicability(`Referenced file ${primary.file} does not exist in ${repo}.`, `File not found: ${primary.file}`)
    if (!originalCitedContent.includes(fixBefore)) return failApplicability(`fixBefore does not match ${primary.file} verbatim.`, 'fixBefore mismatch')
  }

  const workDir = mkdtempSync(join(tmpdir(), 'kovo-patch-check-'))
  try {
    const parsedPatches = parseUnifiedDiff(diff)
    const sensitiveTarget = parsedPatches.find(fp => isSensitiveRepoRelativePath(fp.normalizedPath))
    if (sensitiveTarget) {
      return failApplicability(`Refusing patch targeting sensitive repository path: ${sensitiveTarget.normalizedPath}.`, `Sensitive path denied: ${sensitiveTarget.normalizedPath}`)
    }
    const hasSubstantiveDiffChange = parsedPatches.some(fp => fp.hunks.some(h => h.entries.some(e => e.kind === 'add' || e.kind === 'remove')))
    copyRepoTreeWithoutSymlinks(repoRoot, workDir, { excludeSensitive: true })
    const { filesModified } = applyUnifiedDiffToDirectory(workDir, diff)

    const deletedPaths = new Set(parsedPatches.filter(fp => fp.isDelete).map(fp => normalizeRepoRelPath(fp.normalizedPath)))
    const survivingFiles = filesModified.filter(f => !deletedPaths.has(normalizeRepoRelPath(f)))
    const normalizedModified = new Set(filesModified.map(normalizeRepoRelPath))
    const citedFileModified = primaryRelFile ? normalizedModified.has(primaryRelFile) : filesModified.length > 0

    let fixAppliedToCitedFile = false
    if (primaryRelFile && citedFileModified) {
      if (deletedPaths.has(primaryRelFile)) {
        fixAppliedToCitedFile = fixAfter !== undefined && fixAfter.trim() === ''
      } else {
        const patched = safeReadRepoFile(workDir, primaryRelFile)
        if (patched !== null && originalCitedContent !== null && patched.replace(/\r\n/g, '\n') !== originalCitedContent.replace(/\r\n/g, '\n')) {
          fixAppliedToCitedFile = fixAfter !== undefined
            ? isFixAfterInChangedHunks(parsedPatches, primaryRelFile, patched.replace(/\r\n/g, '\n'), fixBefore.replace(/\r\n/g, '\n'), fixAfter.replace(/\r\n/g, '\n'))
            : true
        }
      }
    } else if (!primaryRelFile && hasSubstantiveDiffChange && filesModified.length > 0) {
      fixAppliedToCitedFile = true
    }

    const jsLike = survivingFiles.filter(f => /\.(?:[cm]?js|[cm]?ts|jsx|tsx)$/i.test(f))
    const pyLike = survivingFiles.filter(f => /\.py$/i.test(f))
    const compiledExternal = survivingFiles.filter(f => /\.(?:go|java|kt)$/i.test(f))
    let syntaxCheck: PatchSyntaxCheckResult = { ran: false, passed: true }
    const unavailableTools: string[] = []

    if (backend) {
      try {
        const safeRepo = repo.replace(/^\/+|\/+$/g, '')
        if (!safeRepo || safeRepo.startsWith('-') || safeRepo.includes('..') || /[\x00-\x1f\x7f\\]/.test(safeRepo)) {
          throw new Error(`Unsafe repository name for syntax check: ${repo}`)
        }
        const manifestEntries = survivingFiles.map((f, idx) => ({ origName: f, stagedName: `patched_${idx}${extname(f) || '.txt'}` }))
        const scriptFiles = [
          ...survivingFiles.map((f, idx) => ({ name: `patched_${idx}${extname(f) || '.txt'}`, content: readFileSync(join(workDir, f), 'utf8') })),
          { name: 'patch_syntax_manifest.json', content: JSON.stringify({ repo: safeRepo, files: manifestEntries, deletedFiles: [...deletedPaths], hasTsconfig: existsSync(join(workDir, 'tsconfig.json')) }) },
          { name: 'patch_syntax_check.mjs', content: PATCH_SYNTAX_CHECK_SCRIPT },
        ]
        const descs = survivingFiles.flatMap(n => /\.(?:[cm]?js)$/i.test(n) ? [`node --check ${n}`] : /\.py$/i.test(n) ? [`py_compile ${n}`] : /\.go$/i.test(n) ? [`go vet ${n}`] : /\.(?:java|kt)$/i.test(n) ? [`javac ${n}`] : [])
        if (survivingFiles.some(f => /\.(?:[cm]?ts|tsx)$/i.test(f)) && existsSync(join(workDir, 'tsconfig.json'))) descs.push('tsc --noEmit')

        const res = await backend.run(
          { assignmentId: randomUUID(), files: scriptFiles, command: 'node /evidence/patch_syntax_check.mjs', outputs: [], timeoutMs: 30_000 },
          signal ?? AbortSignal.timeout(35_000),
          { reposDir, ...(runId ? { runId } : {}) },
        )
        const combinedOut = (res.stdout + '\n' + res.stderr).trim()
        if (res.exitCode !== 0) {
          syntaxCheck = { ran: true, command: descs.join(' && ') || 'air-gapped tmpfs copy check', passed: false, output: combinedOut.slice(0, 2000) }
        } else {
          const unavailJsTs: string[] = [], unavailPy: string[] = []
          for (const line of combinedOut.split('\n').map(l => l.trim()).filter(l => l.startsWith(SYNTAX_UNAVAILABLE_PREFIX))) {
            const rest = line.slice(SYNTAX_UNAVAILABLE_PREFIX.length), colon = rest.indexOf(':')
            const tool = colon >= 0 ? rest.slice(0, colon) : rest, files = colon >= 0 ? rest.slice(colon + 1) : ''
            if (tool === 'tsc' || tool === 'tsc_no_tsconfig' || tool === 'jsx') unavailJsTs.push(...files.split(',').filter(Boolean))
            else if (tool === 'python3') unavailPy.push(...files.split(',').filter(Boolean))
            else unavailableTools.push(`${tool}:${files}`)
          }
          if (unavailJsTs.length || unavailPy.length) {
            const localRes = await runLocalOfflineSyntaxCheck(workDir, [...new Set(unavailJsTs)], [...new Set(unavailPy)])
            if (localRes.toolchainUnavailable) unavailableTools.push(localRes.output ?? 'local_fallback_unavailable')
            syntaxCheck = {
              ran: localRes.ran || descs.length > 0, command: [descs.join(' && '), localRes.command].filter(Boolean).join(' + ') || 'offline syntax fallback',
              passed: localRes.passed && unavailableTools.length === 0, ...(unavailableTools.length > 0 ? { toolchainUnavailable: true } : {}),
              output: [combinedOut, localRes.output ?? ''].filter(Boolean).join('\n').slice(0, 2000),
            }
          } else {
            syntaxCheck = {
              ran: unavailableTools.length === 0, command: descs.join(' && ') || 'air-gapped tmpfs copy check',
              passed: unavailableTools.length === 0, ...(unavailableTools.length > 0 ? { toolchainUnavailable: true } : {}),
              output: (unavailableTools.length > 0 ? `toolchain_unavailable: ${unavailableTools.join(', ')}\n${combinedOut}` : combinedOut).trim().slice(0, 2000),
            }
          }
        }
      } catch (err) {
        syntaxCheck = await runLocalOfflineSyntaxCheck(workDir, jsLike, pyLike, err instanceof Error ? err.message : undefined)
        unavailableTools.push(...compiledExternal.map(f => `${extname(f).slice(1)}:${f}`))
      }
    } else {
      syntaxCheck = await runLocalOfflineSyntaxCheck(workDir, jsLike, pyLike)
      unavailableTools.push(...compiledExternal.map(f => `${extname(f).slice(1)}:${f}`))
    }

    const staticAst = verifyStaticAstPostPatch(workDir, survivingFiles)
    if (!staticAst.ok) {
      syntaxCheck = { ...syntaxCheck, ran: true, passed: false, output: [syntaxCheck.output ?? '', ...staticAst.issues.map(i => `FAIL: static AST: ${i}`)].filter(Boolean).join('\n').slice(0, 2000) }
    } else if (unavailableTools.length > 0) {
      syntaxCheck = { ...syntaxCheck, ran: false, passed: false, toolchainUnavailable: true, output: [`toolchain_unavailable: ${unavailableTools.join(', ')}`, syntaxCheck.output ?? ''].filter(Boolean).join('\n').slice(0, 2000) }
    } else if (!syntaxCheck.ran) {
      syntaxCheck = { ...syntaxCheck, ran: true, command: 'offline static AST sanity', output: 'OK: static AST sanity check' }
    }

    return {
      applicable: true, filesModified, syntaxCheck, hasSubstantiveDiffChange, citedFileModified, fixAppliedToCitedFile,
      ...(!syntaxCheck.passed ? {
        error: syntaxCheck.toolchainUnavailable
          ? `Syntax toolchain unavailable (refusing false-green pass): ${syntaxCheck.output}`
          : `Offline syntax check failed: ${syntaxCheck.output}`,
      } : {}),
    }
  } catch (err) {
    return failApplicability(err instanceof Error ? err.message : String(err))
  } finally {
    rmSync(workDir, { recursive: true, force: true })
  }
}

const authorOutputSchema = z.object({
  coverageInventory: z.array(z.object({
    file: z.string().min(1), line: z.number().int().positive().optional(), symbol: z.string().min(1),
    role: z.enum(['primary_sink', 'sibling_route', 'sibling_writer', 'middleware', 'helper']),
    coveredByPatch: z.boolean(), notes: z.string(),
  })).default([]),
  fixBefore: z.string().min(1), fixAfter: z.string(), diff: z.string().optional(),
  codeLocations: z.array(z.object({
    repo: z.string().min(1).optional(), file: z.string().min(1),
    startLine: z.number().int().positive(), endLine: z.number().int().positive(),
    snippet: z.string().optional(), label: z.string().optional(),
  })).min(1),
  rationale: z.string().min(1),
})

export async function runPatchAuthor(params: PatchWorkflowParams): Promise<PatchAuthorOutput> {
  const repoRoot = validateRepoPath(params.reposDir, params.repo)
  const findingLocations = params.finding.codeLocations ?? []

  let locations: PatchCodeLocation[], fixBefore: string, fixAfter: string, diff: string
  let coverageInventory: CoverageInventoryEntry[], rationale: string

  if (params.candidatePatch?.diff || (params.candidatePatch?.fixBefore && params.candidatePatch?.fixAfter !== undefined)) {
    locations = (params.candidatePatch.codeLocations?.length ? params.candidatePatch.codeLocations : findingLocations).map(loc => ({ ...loc, repo: loc.repo || params.repo }))
    diff = params.candidatePatch.diff ?? ''
    fixBefore = params.candidatePatch.fixBefore ?? ''
    fixAfter = params.candidatePatch.fixAfter ?? ''
    coverageInventory = params.candidatePatch.coverageInventory?.length
      ? params.candidatePatch.coverageInventory
      : locations.map(loc => ({ file: loc.file, line: loc.startLine, symbol: loc.label || 'primary_handler', role: 'primary_sink' as const, coveredByPatch: true, notes: 'Primary vulnerable code location.' }))
    rationale = params.candidatePatch.rationale || `Minimal patch for ${params.finding.title}.`
  } else {
    const authorCall = params.authorLlmCall
      ?? (params.modelProfiles?.length ? makeFreshProviderCall(params.modelProfiles, 'patch-author', { signal: params.signal, secrets: params.secrets, onUsage: params.onUsage }) : undefined)
    if (!authorCall) throw new Error('Patch author requires either candidatePatch, authorLlmCall, or configured modelProfiles.')

    const locsByFile = new Map<string, Array<{ startLine: number; endLine: number }>>()
    for (const loc of findingLocations) {
      const k = normalizeRepoRelPath(loc.file)
      locsByFile.set(k, [...(locsByFile.get(k) ?? []), { startLine: loc.startLine, endLine: loc.endLine }])
    }
    const fileExcerpts = [...locsByFile.entries()].map(([file, ranges]) => extractFocusedFileContext(repoRoot, file, ranges))
    const systemPrompt = [
      'You are Kovo’s air-gapped Patch Author (Stage 1).',
      'Produce a minimal, repository-native security patch that closes the confirmed vulnerability WITHOUT breaking legitimate callers.',
      '1. Build a Coverage Inventory listing the primary vulnerable sink and any sibling routes/handlers/writers sharing the broken invariant.',
      '2. Provide exact verbatim `fixBefore` and `fixAfter`, plus a valid unified `diff` (`--- a/<file>`, `+++ b/<file>`, `@@ ... @@`).',
      '3. Keep edits minimal and strictly adhere to repository conventions. Never introduce hardcoded secrets or block legitimate authenticated callers.',
      'Return STRICT JSON ONLY matching: { coverageInventory, fixBefore, fixAfter, diff, codeLocations, rationale }.',
    ].join('\n')
    const userPrompt = JSON.stringify({
      repo: params.repo,
      finding: { id: params.finding.id, title: params.finding.title, cwe: params.finding.cwe, category: params.finding.category, severity: params.finding.severity, origin: params.finding.origin, reason: params.finding.reason, impact: params.finding.impact, remediation: params.finding.remediation },
      files: fileExcerpts,
    }, null, 2)
    const parsed = authorOutputSchema.parse(extractJsonBlock(await authorCall({ systemPrompt, userPrompt })))
    locations = parsed.codeLocations.map(l => ({ ...l, repo: l.repo || params.repo }))
    fixBefore = parsed.fixBefore; fixAfter = parsed.fixAfter; diff = parsed.diff ?? ''
    coverageInventory = parsed.coverageInventory; rationale = parsed.rationale
  }

  if (!diff && locations.length > 0 && fixBefore) {
    const content = safeReadRepoFile(repoRoot, locations[0]!.file)
    if (content !== null) diff = buildUnifiedDiffFromSnippet(locations[0]!.file, content, fixBefore, fixAfter, locations[0]!.startLine).diff
  }
  const check = await verifyPatchApplicability({ repoRoot, repo: params.repo, reposDir: params.reposDir, diff, fixBefore, fixAfter, codeLocations: locations, backend: params.backend, signal: params.signal, runId: params.runId })
  return { repo: params.repo, coverageInventory, fixBefore, fixAfter, diff, codeLocations: locations, rationale, syntaxCheck: check.syntaxCheck, applicability: check }
}

const reviewerGateSchema = z.object({ passed: z.boolean(), detail: z.string().min(1) })
const reviewerGatesObjectSchema = z.object({
  applicability: reviewerGateSchema,
  security_closure: reviewerGateSchema.extend({ enforcingLocation: z.string().optional() }),
  sibling_coverage: reviewerGateSchema,
  caller_compatibility: reviewerGateSchema,
  repo_conventions: reviewerGateSchema,
})
const reviewerGateArrayItemSchema = z.object({
  gate: z.number().int().min(1).max(6).optional(),
  name: z.enum(['applicability', 'security_closure', 'sibling_coverage', 'caller_compatibility', 'repo_conventions', 'dynamic_retest']),
  passed: z.boolean(), detail: z.string().min(1), enforcingLocation: z.string().optional(),
})
function normalizeReviewerGates(
  raw: z.output<typeof reviewerGatesObjectSchema> | Array<z.output<typeof reviewerGateArrayItemSchema>>,
  ctx: z.RefinementCtx,
): z.output<typeof reviewerGatesObjectSchema> {
  if (!Array.isArray(raw)) return raw
  const byName = new Map<string, z.output<typeof reviewerGateArrayItemSchema>>()
  for (const item of raw) {
    if (byName.has(item.name)) { ctx.addIssue({ code: 'custom', message: `Duplicate reviewer gate "${item.name}".` }); return z.NEVER }
    byName.set(item.name, item)
  }
  for (const name of ['applicability', 'security_closure', 'sibling_coverage', 'caller_compatibility', 'repo_conventions'] as const) {
    if (!byName.has(name)) { ctx.addIssue({ code: 'custom', message: `Missing required reviewer gate "${name}".` }); return z.NEVER }
  }
  const sec = byName.get('security_closure')!
  return {
    applicability: { passed: byName.get('applicability')!.passed, detail: byName.get('applicability')!.detail },
    security_closure: { passed: sec.passed, detail: sec.detail, ...(sec.enforcingLocation ? { enforcingLocation: sec.enforcingLocation } : {}) },
    sibling_coverage: { passed: byName.get('sibling_coverage')!.passed, detail: byName.get('sibling_coverage')!.detail },
    caller_compatibility: { passed: byName.get('caller_compatibility')!.passed, detail: byName.get('caller_compatibility')!.detail },
    repo_conventions: { passed: byName.get('repo_conventions')!.passed, detail: byName.get('repo_conventions')!.detail },
  }
}
const reviewerOutputSchema = z.object({
  approved: z.boolean(), callerCompatibility: z.enum(['attacker_only', 'needs_operator_step', 'breaks_callers']),
  enforcingLocation: z.string().optional(),
  gates: z.union([reviewerGatesObjectSchema, z.array(reviewerGateArrayItemSchema).min(5)]).transform(normalizeReviewerGates),
  reviewNotes: z.string().min(1),
})

const BLOCKING_STATEMENT_RE = /^(?:return\s+.*\b(?:status\s*\(\s*(?:401|403|404|500)|new\s+Response\s*\([^)]*(?:401|403)|(?:abort|Response|JSONResponse|HttpResponseForbidden)\s*\([^)]*(?:401|403))|res(?:ponse)?\.status\s*\(\s*(?:401|403)\s*\)\s*\.|throw\s+new\s+Error\s*\(\s*['"](?:disabled|forbidden|unauthorized)['"]|raise\s+(?:HTTPException|PermissionDenied|Forbidden)\b|abort\s*\(\s*(?:401|403)\s*\))/i

function extractAddedDiffLines(diff: string): string[] {
  try {
    return parseUnifiedDiff(diff, { allowEmpty: true }).flatMap(fp => fp.hunks.flatMap(h => h.entries.filter(e => e.kind === 'add').map(e => e.text)))
  } catch {
    const added: string[] = []
    let inHunk = false
    for (const raw of diff.replace(/\r\n/g, '\n').split('\n')) {
      if (raw.startsWith('@@ ')) { inHunk = true; continue }
      if (inHunk && raw.startsWith('+') && !raw.startsWith('+++ ')) added.push(raw.slice(1))
    }
    return added
  }
}

function measureIndent(text: string): number {
  let count = 0
  for (const ch of text) { if (ch === ' ') count += 1; else if (ch === '\t') count += 4; else break }
  return count
}

function stripLeadingConditionalHeader(trimmed: string): { isCond: boolean; alwaysTrue: boolean; rest: string } {
  const atParen = /^if\s*\(\s*(?:true|1)\s*\)\s*(.*)$/i.exec(trimmed)
  if (atParen) return { isCond: true, alwaysTrue: true, rest: atParen[1] ?? '' }
  const atColon = /^if\s+(?:True|1)\s*:\s*(.*)$/.exec(trimmed)
  if (atColon) return { isCond: true, alwaysTrue: true, rest: atColon[1] ?? '' }
  const kwMatch = /^(?:else\s+if|if|elif|unless|while|for|switch|catch|except|when|case|else)\b/.exec(trimmed)
  if (!kwMatch) return { isCond: false, alwaysTrue: false, rest: trimmed }
  const kw = kwMatch[0]!
  let after = trimmed.slice(kw.length).trimStart()
  if (/^(?:else\s+if|if|unless|while|for|switch|catch|when)$/.test(kw) && after.startsWith('(')) {
    let depth = 0, idx = 0
    for (; idx < after.length; idx += 1) {
      if (after[idx] === '(') depth += 1
      else if (after[idx] === ')' && --depth === 0) { idx += 1; break }
    }
    return { isCond: true, alwaysTrue: false, rest: depth === 0 ? after.slice(idx).trimStart() : '' }
  }
  const colonIdx = /^(?:if|elif|unless|while|for|except|else|case)$/.test(kw) ? after.indexOf(':') : -1
  return { isCond: true, alwaysTrue: false, rest: colonIdx >= 0 ? after.slice(colonIdx + 1).trimStart() : after }
}

/** Detect unconditional caller-breaking blocks while respecting braces, braceless single/multiline `if`, and Python indentation. */
export function detectUnconditionalCallerBreak(diff: string): boolean {
  const hunkGroups: Array<Array<{ added: boolean; text: string }>> = []
  try {
    for (const fp of parseUnifiedDiff(diff, { allowEmpty: true })) {
      for (const h of fp.hunks) {
        const g = h.entries.filter(e => e.kind !== 'remove').map(e => ({ added: e.kind === 'add', text: e.text }))
        if (g.length) hunkGroups.push(g)
      }
    }
  } catch {
    const g: Array<{ added: boolean; text: string }> = []
    for (const raw of diff.replace(/\r\n/g, '\n').split('\n')) {
      if (raw.startsWith('+++ ') || raw.startsWith('--- ') || raw.startsWith('@@ ')) continue
      if (raw.startsWith('+')) g.push({ added: true, text: raw.slice(1) })
      else if (raw.startsWith(' ')) g.push({ added: false, text: raw.slice(1) })
    }
    if (g.length) hunkGroups.push(g)
  }

  for (const lines of hunkGroups) {
    if (!lines.some(l => l.added)) continue
    const braceFrames: Array<{ conditional: boolean }> = []
    const indentFrames: Array<{ indent: number; conditional: boolean }> = []
    let pendingBraceless = false, multiDepth = 0, multiAlwaysTrue = false

    for (const entry of lines) {
      const trimmed = entry.text.trim()
      if (!trimmed || /^(?:\/\/|#|\/\*|\*)/.test(trimmed)) continue
      const indent = measureIndent(entry.text)
      const leadingCloses = (trimmed.match(/^\}+/) ?? [''])[0].length
      for (let i = 0; i < leadingCloses; i += 1) braceFrames.pop()
      while (indentFrames.length > 0 && indent <= indentFrames[indentFrames.length - 1]!.indent) indentFrames.pop()

      if (multiDepth > 0) {
        for (const ch of trimmed) { if (ch === '(') multiDepth += 1; else if (ch === ')') multiDepth = Math.max(0, multiDepth - 1) }
        if (multiDepth === 0) {
          const opens = (trimmed.match(/\{/g) ?? []).length, closes = (trimmed.match(/\}/g) ?? []).length - leadingCloses
          if (opens > 0) { for (let i = 0; i < opens; i += 1) braceFrames.push({ conditional: !multiAlwaysTrue }); for (let i = 0; i < Math.max(0, closes); i += 1) braceFrames.pop(); pendingBraceless = false }
          else if (trimmed.endsWith(':')) { indentFrames.push({ indent, conditional: !multiAlwaysTrue }); pendingBraceless = false }
          else pendingBraceless = !multiAlwaysTrue
          multiAlwaysTrue = false
        }
        continue
      }

      const cond = stripLeadingConditionalHeader(trimmed)
      const inCond = braceFrames.some(f => f.conditional) || indentFrames.some(f => f.conditional) || pendingBraceless
      if (entry.added && !inCond && (
        (cond.isCond && cond.alwaysTrue && cond.rest && BLOCKING_STATEMENT_RE.test(cond.rest))
        || (!cond.isCond && BLOCKING_STATEMENT_RE.test(trimmed))
      )) return true

      const opens = (trimmed.match(/\{/g) ?? []).length, closes = (trimmed.match(/\}/g) ?? []).length - leadingCloses
      if (cond.isCond) {
        const pOpens = (trimmed.match(/\(/g) ?? []).length, pCloses = (trimmed.match(/\)/g) ?? []).length
        if (pOpens > pCloses && !trimmed.includes('{') && !trimmed.endsWith(':')) {
          multiDepth = pOpens - pCloses; multiAlwaysTrue = cond.alwaysTrue; pendingBraceless = false
        } else if (opens > 0) {
          for (let i = 0; i < opens; i += 1) braceFrames.push({ conditional: !cond.alwaysTrue })
          for (let i = 0; i < Math.max(0, closes); i += 1) braceFrames.pop()
          pendingBraceless = false
        } else if (trimmed.endsWith(':')) {
          indentFrames.push({ indent, conditional: !cond.alwaysTrue }); pendingBraceless = false
        } else {
          pendingBraceless = !cond.rest && !cond.alwaysTrue
        }
      } else {
        for (let i = 0; i < opens; i += 1) braceFrames.push({ conditional: false })
        for (let i = 0; i < Math.max(0, closes); i += 1) braceFrames.pop()
        if (trimmed.endsWith(':') && /^(?:def|async\s+def|class|try|finally|with)\b/.test(trimmed)) indentFrames.push({ indent, conditional: false })
        pendingBraceless = false
      }
    }
  }
  return false
}

const HARDCODED_SECRET_LINE_RE = /(?:sk-or-v1-|sk-ant-|ghp_|github_pat_|-----BEGIN [A-Z ]*PRIVATE KEY-----)/
const DEBUG_ARTIFACT_LINE_RE = /(?:\b(?:console\.log\(['"]DEBUG|debugger;)|^(?:<{7}|={7}|>{7}))/
const OPERATOR_ENV_LINE_RE = /\bprocess\.env\.[A-Z0-9_]+/
const hasHardcodedSecretInDiff = (diff: string) => extractAddedDiffLines(diff).some(l => HARDCODED_SECRET_LINE_RE.test(l))
const hasDebugArtifactInDiff = (diff: string) => extractAddedDiffLines(diff).some(l => DEBUG_ARTIFACT_LINE_RE.test(l))
const hasOperatorEnvInDiff = (diff: string) => extractAddedDiffLines(diff).some(l => OPERATOR_ENV_LINE_RE.test(l))
const detectDeterministicCallerBreak = (a: PatchAuthorOutput) => detectUnconditionalCallerBreak(a.diff) || (!a.fixAfter.trim() && a.fixBefore.trim().length > 40)
const isGate1SyntaxPassing = (app: PatchApplicabilityResult) => app.applicable && !app.syntaxCheck.toolchainUnavailable && (!app.syntaxCheck.ran || app.syntaxCheck.passed)

function deterministicOfflineReview(authorOutput: PatchAuthorOutput, applicability: PatchApplicabilityResult): PatchReviewOutput {
  const primaryLoc = authorOutput.codeLocations[0]
  const enforcingLocation = primaryLoc ? `${primaryLoc.file}:${primaryLoc.startLine}` : undefined
  const gate1Passed = isGate1SyntaxPassing(applicability)
  const diffHasSubstantiveChange = authorOutput.fixBefore.trim() !== authorOutput.fixAfter.trim() && applicability.hasSubstantiveDiffChange && applicability.citedFileModified && applicability.fixAppliedToCitedFile
  const gate2Passed = Boolean(enforcingLocation && /^[^:\s]+:\d+$/.test(enforcingLocation) && diffHasSubstantiveChange)
  const uncovered = authorOutput.coverageInventory.filter(i => (i.role === 'sibling_route' || i.role === 'sibling_writer') && !i.coveredByPatch)
  const gate3Passed = uncovered.length === 0
  const breaks = detectDeterministicCallerBreak(authorOutput)
  const callerCompatibility: CallerCompatibility = breaks ? 'breaks_callers' : hasOperatorEnvInDiff(authorOutput.diff) ? 'needs_operator_step' : 'attacker_only'
  const gate4Passed = callerCompatibility !== 'breaks_callers'
  const hasSecret = hasHardcodedSecretInDiff(authorOutput.diff), hasDebug = hasDebugArtifactInDiff(authorOutput.diff)
  const gate5Passed = !hasSecret && !hasDebug && applicability.filesModified.length <= 12

  const gates: PatchGateResult[] = [
    { gate: 1, name: 'applicability', passed: gate1Passed, detail: gate1Passed ? `Diff applied cleanly to ${applicability.filesModified.join(', ')}${applicability.syntaxCheck.ran ? ' and passed offline syntax check.' : '.'}` : (applicability.error || 'Patch failed applicability or syntax check.') },
    { gate: 2, name: 'security_closure', passed: gate2Passed, enforcingLocation, detail: gate2Passed ? `Security control enforced at ${enforcingLocation}.` : (!applicability.citedFileModified ? `Patch diff does not modify the cited enforcing file (${primaryLoc?.file ?? 'unknown'}).` : !applicability.fixAppliedToCitedFile ? `Patch diff does not apply fixBefore -> fixAfter in ${primaryLoc?.file ?? 'cited file'}.` : 'Patch lacks a concrete enforcing file:line location or substantive fix.') },
    { gate: 3, name: 'sibling_coverage', passed: gate3Passed, detail: gate3Passed ? `All ${authorOutput.coverageInventory.length} inventoried sibling/primary handlers covered.` : `Uncovered sibling handler(s): ${uncovered.map(s => `${s.file}:${s.symbol}`).join(', ')}.` },
    { gate: 4, name: 'caller_compatibility', passed: gate4Passed, detail: callerCompatibility === 'breaks_callers' ? 'Patch unconditionally blocks or removes legitimate caller behavior; automatically withheld.' : callerCompatibility === 'needs_operator_step' ? 'Patch requires an operator configuration/env step but preserves legitimate callers.' : 'Patch refuses attacker input while preserving legitimate callers.' },
    { gate: 5, name: 'repo_conventions', passed: gate5Passed, detail: hasSecret ? 'Patch introduces hardcoded credentials/secret material.' : hasDebug ? 'Patch introduces debug artifacts.' : 'Patch is minimal and conforms to repository conventions.' },
    { gate: 6, name: 'dynamic_retest', passed: false, detail: 'Dynamic retest unverified (skipped unless an authorized local-lab retest with a baseline caller is available).' },
  ]
  const status: PatchStatus = callerCompatibility === 'breaks_callers' ? 'withheld' : (gate1Passed && gate2Passed && gate3Passed && gate4Passed && gate5Passed ? 'approved' : 'rejected')
  return { approved: status === 'approved', status, callerCompatibility, gates, enforcingLocation, reviewNotes: gates.map(g => `Gate ${g.gate} (${g.name}): ${g.passed ? 'PASS' : 'FAIL'} — ${g.detail}`).join('\n') }
}

export async function runPatchReviewer(params: {
  finding: Finding & { codeLocations?: PatchCodeLocation[] }; repo: string; reposDir: string
  authorOutput: PatchAuthorOutput; precomputedApplicability?: PatchApplicabilityResult
  backend?: WorkerBackend; reviewerLlmCall?: PatchLlmCall; modelProfiles?: readonly ResolvedModelProfile[]
  signal?: AbortSignal; secrets?: readonly NamedSecret[]; onUsage?: UsageCallback; runId?: string
}): Promise<PatchReviewOutput> {
  const repoRoot = validateRepoPath(params.reposDir, params.repo)
  const applicability = params.precomputedApplicability ?? params.authorOutput.applicability
    ?? await verifyPatchApplicability({ repoRoot, repo: params.repo, reposDir: params.reposDir, diff: params.authorOutput.diff, fixBefore: params.authorOutput.fixBefore, fixAfter: params.authorOutput.fixAfter, codeLocations: params.authorOutput.codeLocations, backend: params.backend, signal: params.signal, ...(params.runId ? { runId: params.runId } : {}) })

  const reviewerCall = params.reviewerLlmCall
    ?? (params.modelProfiles?.length ? makeFreshProviderCall(params.modelProfiles, 'patch-reviewer', { signal: params.signal, secrets: params.secrets, onUsage: params.onUsage }) : undefined)
  if (!reviewerCall) return deterministicOfflineReview(params.authorOutput, applicability)

  const rangesByFile = new Map<string, Array<{ startLine: number; endLine?: number }>>()
  const addRange = (file: string, startLine: number, endLine?: number) => {
    const k = normalizeRepoRelPath(file)
    if (k) rangesByFile.set(k, [...(rangesByFile.get(k) ?? []), { startLine, ...(endLine !== undefined ? { endLine } : {}) }])
  }
  for (const loc of params.authorOutput.codeLocations) addRange(loc.file, loc.startLine, loc.endLine)
  for (const item of params.authorOutput.coverageInventory) addRange(item.file, item.line ?? 1)
  try {
    for (const fp of parseUnifiedDiff(params.authorOutput.diff, { allowEmpty: true })) {
      for (const h of fp.hunks) addRange(fp.normalizedPath, Math.max(1, h.oldStart), Math.max(1, h.oldStart + h.oldCount))
    }
  } catch { /* reflected in applicability */ }

  const fileContext = [...rangesByFile.entries()].map(([file, ranges]) => extractFocusedFileContext(repoRoot, file, ranges))
  const siblingHints = collectSiblingHints(repoRoot, new Set(rangesByFile.keys()), [...params.authorOutput.coverageInventory.map(c => c.symbol), ...params.authorOutput.codeLocations.map(l => l.label ?? '')])

  const systemPrompt = [
    'You are Kovo’s independent air-gapped Patch Reviewer (Stage 2).',
    'You have ZERO shared context with the patch author. Independently verify the proposed diff against 5 static gates (Gate 6 dynamic retest runs separately):',
    '1. applicability: Does fixBefore match verbatim, does the diff apply cleanly, and does offline syntax/typecheck pass?',
    '2. security_closure: Does the patch close the vulnerability? Quote the EXACT enforcing file:line.',
    '3. sibling_coverage: Are all sibling routes/handlers/writers sharing the same invariant covered?',
    '4. caller_compatibility: Classify strictly as "attacker_only", "needs_operator_step", or "breaks_callers". Any patch that breaks legitimate callers MUST be classified "breaks_callers" and rejected/withheld.',
    '5. repo_conventions: Is the patch minimal, clean, idiomatic, and free of hardcoded secrets or debug artifacts?',
    'Return STRICT JSON ONLY with keys: { approved, callerCompatibility, enforcingLocation, gates: { applicability, security_closure, sibling_coverage, caller_compatibility, repo_conventions }, reviewNotes }.',
  ].join('\n')
  const userPrompt = JSON.stringify({
    finding: { title: params.finding.title, cwe: params.finding.cwe, category: params.finding.category, severity: params.finding.severity, origin: params.finding.origin, reason: params.finding.reason, impact: params.finding.impact },
    proposedPatch: { repo: params.repo, diff: params.authorOutput.diff, fixBefore: params.authorOutput.fixBefore, fixAfter: params.authorOutput.fixAfter, coverageInventory: params.authorOutput.coverageInventory, applicabilityCheck: applicability },
    repoFiles: fileContext,
    ...(siblingHints.length > 0 ? { siblingHints } : {}),
  }, null, 2)

  try {
    const raw = await reviewerCall({ systemPrompt, userPrompt })
    if (typeof raw !== 'string' || !raw.trim()) throw new Error('Empty response from patch reviewer.')
    const parsed = reviewerOutputSchema.parse(extractJsonBlock(raw))

    const gate1Passed = isGate1SyntaxPassing(applicability) && parsed.gates.applicability.passed
    const enforcingLocation = parsed.gates.security_closure.enforcingLocation || parsed.enforcingLocation
    const validLoc = Boolean(enforcingLocation && /^[^:\s]+:\d+$/.test(enforcingLocation.trim()))
    const enforcingFile = validLoc ? normalizeRepoRelPath(enforcingLocation!.trim().split(':')[0]!) : null
    const touched = Boolean(enforcingFile && new Set(applicability.filesModified.map(normalizeRepoRelPath)).has(enforcingFile))
    const gate2Passed = parsed.gates.security_closure.passed && validLoc && touched && applicability.hasSubstantiveDiffChange && applicability.fixAppliedToCitedFile
    const gate3Passed = parsed.gates.sibling_coverage.passed
    const detBreaks = detectDeterministicCallerBreak(params.authorOutput)
    const callerCompatibility: CallerCompatibility = detBreaks ? 'breaks_callers' : parsed.callerCompatibility
    const gate4Passed = callerCompatibility !== 'breaks_callers' && parsed.gates.caller_compatibility.passed
    const gate5Passed = parsed.gates.repo_conventions.passed && !hasHardcodedSecretInDiff(params.authorOutput.diff)

    const gate2Detail = !validLoc ? `${parsed.gates.security_closure.detail} (Missing exact file:line citation.)`
      : !touched ? `${parsed.gates.security_closure.detail} (Cited file "${enforcingFile}" was not modified by the diff.)`
        : !applicability.hasSubstantiveDiffChange || !applicability.fixAppliedToCitedFile ? `${parsed.gates.security_closure.detail} (Diff did not apply a substantive fixBefore -> fixAfter change to the cited file.)`
          : parsed.gates.security_closure.detail

    const gates: PatchGateResult[] = [
      { gate: 1, name: 'applicability', passed: gate1Passed, detail: gate1Passed ? parsed.gates.applicability.detail : (applicability.error || parsed.gates.applicability.detail) },
      { gate: 2, name: 'security_closure', passed: gate2Passed, enforcingLocation, detail: gate2Detail },
      { gate: 3, name: 'sibling_coverage', passed: gate3Passed, detail: parsed.gates.sibling_coverage.detail },
      { gate: 4, name: 'caller_compatibility', passed: gate4Passed, detail: detBreaks ? `Automatically withheld (deterministic breaks_callers pattern matched; overriding LLM reviewer): ${parsed.gates.caller_compatibility.detail}` : callerCompatibility === 'breaks_callers' ? `Automatically withheld (breaks_callers): ${parsed.gates.caller_compatibility.detail}` : parsed.gates.caller_compatibility.detail },
      { gate: 5, name: 'repo_conventions', passed: gate5Passed, detail: parsed.gates.repo_conventions.detail },
      { gate: 6, name: 'dynamic_retest', passed: false, detail: 'Dynamic retest unverified (pending optional local-lab retest with baseline caller).' },
    ]
    const status: PatchStatus = callerCompatibility === 'breaks_callers' ? 'withheld' : (parsed.approved && gate1Passed && gate2Passed && gate3Passed && gate4Passed && gate5Passed ? 'approved' : 'rejected')
    return { approved: status === 'approved', status, callerCompatibility, gates, enforcingLocation, reviewNotes: redact(parsed.reviewNotes, params.secrets) }
  } catch (err) {
    const reason = redact(err instanceof Error ? err.message : String(err), params.secrets).slice(0, 300)
    const detBreaks = detectDeterministicCallerBreak(params.authorOutput)
    const callerCompatibility: CallerCompatibility = detBreaks ? 'breaks_callers' : 'attacker_only'
    const status: PatchStatus = detBreaks ? 'withheld' : 'rejected'
    const gate1Passed = isGate1SyntaxPassing(applicability)
    const gates: PatchGateResult[] = [
      { gate: 1, name: 'applicability', passed: gate1Passed, detail: gate1Passed ? `Diff applied cleanly to ${applicability.filesModified.join(', ')}.` : (applicability.error || 'Patch failed applicability or syntax check.') },
      { gate: 2, name: 'security_closure', passed: false, detail: `Fail-closed: automated patch reviewer error (${reason}); security closure unverified.` },
      { gate: 3, name: 'sibling_coverage', passed: false, detail: 'Fail-closed: automated patch reviewer unavailable or returned an invalid verdict.' },
      { gate: 4, name: 'caller_compatibility', passed: false, detail: detBreaks ? 'Automatically withheld (deterministic breaks_callers pattern matched while reviewer failed closed).' : 'Fail-closed: caller compatibility unverified due to reviewer error.' },
      { gate: 5, name: 'repo_conventions', passed: false, detail: 'Fail-closed: repository conventions unverified due to reviewer error.' },
      { gate: 6, name: 'dynamic_retest', passed: false, detail: 'Dynamic retest skipped because patch review failed closed.' },
    ]
    return { approved: false, status, callerCompatibility, gates, reviewNotes: redact(`Patch review failed closed (${status}): reviewer error or invalid response — ${reason}`, params.secrets) }
  }
}

// ============================================================================
// Gate-6 Baseline Synthesis, H-5 Envelope Trust & Rollback Consistency
// ============================================================================

const SAFE_BASELINE_METHODS = new Set(['GET', 'HEAD'])
const STRIPPED_BASELINE_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'host', 'content-length', 'connection', 'transfer-encoding'])
const SUSPICIOUS_BASELINE_PATH_RE = /(?:\{\{|[\r\n\0'"<>`]|(?:^|[/?&=])(?:\.\.\/|\.\.\\)|%27|%22|%3c|%3e|union\s+select|pg_sleep|sleep\s*\(|waitfor\s+delay|\bor\s+1\s*=\s*1\b|--\s*$)/i

function sanitizeBaselineHeaders(headers: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!headers) return undefined
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    if (!STRIPPED_BASELINE_HEADERS.has(k.toLowerCase()) && typeof v === 'string' && !/[\r\n\0]/.test(v)) out[k] = v
  }
  return Object.keys(out).length > 0 ? out : undefined
}

const isSafeBaselinePath = (p: unknown): p is string =>
  typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && p.length <= 2048 && !SUSPICIOUS_BASELINE_PATH_RE.test(p)

function buildSafeBaselineCandidate(input: { origin?: unknown; method?: unknown; pathAndQuery?: unknown; persona?: unknown; headers?: Record<string, string>; grant?: Grant }): BrokerHttpRequest | null {
  const origin = typeof input.origin === 'string' ? input.origin.trim() : ''
  const method = typeof input.method === 'string' ? input.method.trim().toUpperCase() : 'GET'
  if (!origin || !SAFE_BASELINE_METHODS.has(method) || !isSafeBaselinePath(input.pathAndQuery)) return null
  if (input.grant && !input.grant.canRead(origin)) return null
  const persona = typeof input.persona === 'string' && input.persona.trim() ? input.persona.trim() : undefined
  const headers = sanitizeBaselineHeaders(input.headers)
  return { origin, method: method as BrokerHttpRequest['method'], pathAndQuery: input.pathAndQuery, ...(persona ? { persona } : {}), ...(headers ? { headers } : {}) }
}

const routePathOnly = (pq: string | undefined): string | null => {
  if (!pq) return null
  const base = (pq.includes('?') ? pq.slice(0, pq.indexOf('?')) : pq).trim()
  return base.startsWith('/') ? base : null
}

function inferSpecRouteHint(spec: DeclarativeReplaySpec, finding?: Finding): string | null {
  if (typeof spec.recipe?.args?.pathAndQuery === 'string') return routePathOnly(spec.recipe.args.pathAndQuery)
  if ('pathAndQuery' in spec && typeof spec.pathAndQuery === 'string') return routePathOnly(spec.pathAndQuery)
  if ('controlPath' in spec && typeof spec.controlPath === 'string') return routePathOnly(spec.controlPath)
  if ('steps' in spec && Array.isArray(spec.steps)) {
    const st = spec.steps.find(s => 'request' in s ? Boolean(s.request?.pathAndQuery) : Boolean(s.pathAndQuery))
    if (st) return routePathOnly('request' in st ? st.request.pathAndQuery : st.pathAndQuery)
  }
  return routePathOnly((finding as { endpoint?: string } | undefined)?.endpoint)
}

function pickBestExchangeBaseline(exchanges: readonly BrokerExchange[], specOrigin: string, routeHint: string | null, grant?: Grant): BrokerHttpRequest | null {
  let best: { req: BrokerHttpRequest; score: number } | null = null
  for (const ex of exchanges) {
    if (ex.status < 200 || ex.status >= 300) continue
    const req = buildSafeBaselineCandidate({ origin: ex.origin, method: ex.method, pathAndQuery: ex.pathAndQuery, persona: ex.personaHandle ?? undefined, grant })
    if (!req) continue
    const exPath = routePathOnly(ex.pathAndQuery)
    const hintBase = routeHint ? routeHint.split('/').slice(0, 3).join('/') : ''
    const score = (ex.origin === specOrigin ? 20 : 0) + (ex.personaHandle ? 30 : 0) + (ex.method.toUpperCase() === 'GET' ? 5 : 0)
      + (routeHint && exPath ? (exPath === routeHint ? 50 : hintBase.length > 1 && exPath.startsWith(hintBase) ? 25 : 0) : 0)
    if (!best || score > best.score) best = { req, score }
  }
  return best?.req ?? null
}

function synthesizeFromRecipe(spec: DeclarativeReplaySpec, grant?: Grant): { caller: BrokerHttpRequest; expectStatus: number[] } | null {
  if (!spec.recipe) return null
  const args = spec.recipe.args as Record<string, unknown>
  const origin = (typeof args.origin === 'string' && args.origin) || spec.origin
  const actorOf = (o: unknown) => o && typeof o === 'object' && typeof (o as { handle?: unknown }).handle === 'string' ? (o as { handle: string }).handle : undefined
  const baseH = args.headers && typeof args.headers === 'object' && !Array.isArray(args.headers) ? (args.headers as Record<string, string>) : undefined
  const tryReq = (method: unknown, pathAndQuery: unknown, persona?: string, headers?: Record<string, string>, expectStatus = [200, 201, 202, 204]) => {
    const caller = buildSafeBaselineCandidate({ origin, method, pathAndQuery, persona, headers, grant })
    return caller ? { caller, expectStatus } : null
  }
  switch (spec.recipe.recipeId) {
    case 'access_boundary':
    case 'disclosure':
      return tryReq(args.method ?? 'GET', args.baselinePathAndQuery ?? args.pathAndQuery, actorOf(args.owner), baseH)
        ?? (typeof args.baselinePathAndQuery === 'string' ? tryReq('GET', args.baselinePathAndQuery, actorOf(args.owner), baseH) : null)
    case 'persisted_mutation':
      return tryReq(args.readbackMethod ?? args.baselineMethod ?? 'GET', args.readbackPathAndQuery ?? args.baselinePathAndQuery, actorOf(args.readbackActor) ?? actorOf(args.actor), baseH)
    case 'boolean_or_timing': {
      const ctrl = args.controlRequest as { pathAndQuery?: unknown; headers?: Record<string, string> } | undefined
      return tryReq(args.method ?? 'GET', ctrl?.pathAndQuery ?? args.controlPathAndQuery ?? args.pathAndQuery, actorOf(args.actor), ctrl?.headers ?? baseH)
        ?? (typeof args.primePath === 'string' ? tryReq('GET', args.primePath, actorOf(args.actor)) : null)
    }
    case 'conserved_balance': {
      const rb = args.readback as { method?: unknown; pathAndQuery?: unknown; actor?: unknown; headers?: Record<string, string> } | undefined
      return rb ? tryReq(rb.method ?? 'GET', rb.pathAndQuery, actorOf(rb.actor) ?? actorOf(args.actor), rb.headers) : null
    }
    case 'redirect':
      return tryReq(args.method ?? 'GET', args.controlPathAndQuery ?? args.pathAndQuery, actorOf(args.actor), baseH, [200, 201, 202, 204, 301, 302, 303, 307, 308])
    case 'browser_sink': {
      const ctrl = Array.isArray(args.steps) ? (args.steps as Array<{ role?: string; pathAndQuery?: string; persona?: string }>).find(s => s.role === 'control' && typeof s.pathAndQuery === 'string') : undefined
      return tryReq('GET', ctrl?.pathAndQuery ?? args.pathAndQuery, ctrl?.persona ?? actorOf(args.actor))
    }
    case 'injection_fingerprint':
    case 'oob_callback':
      return tryReq(args.method ?? 'GET', args.pathAndQuery, actorOf(args.actor), baseH)
    case 'race_burst': {
      for (const st of Array.isArray(args.setupSteps) ? (args.setupSteps as Array<{ method?: string; pathAndQuery?: string; actor?: unknown; headers?: Record<string, string> }>) : []) {
        const hit = tryReq(st.method, st.pathAndQuery, actorOf(st.actor) ?? actorOf(args.actor), st.headers)
        if (hit) return hit
      }
      return tryReq(args.method, args.pathAndQuery, actorOf(args.actor), baseH)
    }
    default: return null
  }
}

function synthesizeFromStep(step: ReplayStep | undefined, grant?: Grant): BrokerHttpRequest | null {
  if (!step || step.request.authMutation) return null
  return buildSafeBaselineCandidate({ origin: step.request.origin, method: step.request.method, pathAndQuery: step.request.pathAndQuery, persona: step.request.persona, headers: step.request.headers, grant })
}

function synthesizeFromDeclarativeSpec(spec: DeclarativeReplaySpec, grant?: Grant): BrokerHttpRequest | null {
  switch (spec.kind) {
    case 'http_chain':
    case 'auth_protocol_proof':
      return synthesizeFromStep(spec.steps.find(s => s.role === 'control' && !s.request.authMutation), grant)
    case 'sql_boolean_diff':
    case 'sql_time_diff':
      return synthesizeFromStep(spec.controlStep, grant) ?? buildSafeBaselineCandidate({ origin: spec.targetOrigin, method: spec.method, pathAndQuery: spec.pathAndQuery, persona: spec.persona, headers: spec.headers, grant })
    case 'race_burst':
    case 'rce_proof':
    case 'upload_probe':
      return synthesizeFromStep(spec.controlStep, grant)
    case 'browser_dom':
      return buildSafeBaselineCandidate({ origin: spec.targetOrigin, method: 'GET', pathAndQuery: spec.controlPath, persona: spec.persona, grant })
    case 'browser_chain': {
      const c = spec.steps.find(s => s.role === 'control' && typeof s.pathAndQuery === 'string')
      return c ? buildSafeBaselineCandidate({ origin: c.origin, method: 'GET', pathAndQuery: c.pathAndQuery, persona: c.persona, grant }) : null
    }
    case 'cache_differential':
      return buildSafeBaselineCandidate({ origin: spec.targetOrigin, method: spec.method, pathAndQuery: spec.controlPath, persona: spec.controlPersona, grant })
    default: return null
  }
}

/** Derive Gate-6 `envelopeTrust` cleanly (H-5): explicit override > DB verification when replaySpecId claimed > host_persisted. */
export function deriveGate6EnvelopeTrust(
  lr: Pick<PatchLabRetestContext, 'envelopeTrust' | 'storage' | 'runId' | 'replaySpecId'>,
  finding?: Pick<Finding, 'replaySpecId'>,
): 'host_persisted' | 'untrusted' {
  if (lr.envelopeTrust !== undefined) return lr.envelopeTrust
  const claimedSpecId = lr.replaySpecId ?? finding?.replaySpecId ?? undefined
  if (lr.storage && claimedSpecId) {
    try { return lr.storage.getReplaySpec(lr.runId, claimedSpecId) ? 'host_persisted' : 'untrusted' } catch { return 'untrusted' }
  }
  return 'host_persisted'
}

/** Synthesize a safe read-only/idempotent (`GET`/`HEAD`) baseline caller for Gate 6 across all proof kinds. */
export function synthesizeGate6BaselineCaller(params: {
  explicitBaselineCaller?: BrokerHttpRequest; explicitExpectStatus?: number[]
  replaySpec: DeclarativeReplaySpec; finding?: Finding; storage?: Store; runId?: string; grant?: Grant
}): SynthesizedBaselineCaller | null {
  const defaultStatuses = params.explicitExpectStatus ?? [200, 201, 202, 204]
  if (params.explicitBaselineCaller) return { caller: params.explicitBaselineCaller, expectStatus: defaultStatuses, source: 'explicit' }
  const specOrigin = params.replaySpec.origin || params.finding?.origin || ''
  const routeHint = inferSpecRouteHint(params.replaySpec, params.finding)

  if (params.storage && params.runId) {
    const citedIds = new Set<string>([...(params.replaySpec.agentScript?.exchangeIds ?? []), ...(params.finding?.exchangeIds ?? [])])
    if (params.finding?.id) {
      try {
        const agentProof = params.storage.agentProofForFinding(params.runId, params.finding.id)
        for (const id of agentProof?.receipt?.receipt?.exchangeIds ?? []) citedIds.add(id)
      } catch { /* optional */ }
    }
    const citedExchanges: BrokerExchange[] = []
    for (const id of citedIds) {
      try { citedExchanges.push(params.storage.getExchange(params.runId, id)) } catch { /* pruned */ }
    }
    const picked = pickBestExchangeBaseline(citedExchanges, specOrigin, routeHint, params.grant)
    if (picked) return { caller: picked, expectStatus: defaultStatuses, source: 'receipt_exchange' }
  }

  const fromRecipe = synthesizeFromRecipe(params.replaySpec, params.grant)
  if (fromRecipe) return { caller: fromRecipe.caller, expectStatus: params.explicitExpectStatus ?? fromRecipe.expectStatus, source: 'recipe_control' }

  const fromSpec = synthesizeFromDeclarativeSpec(params.replaySpec, params.grant)
  if (fromSpec) return { caller: fromSpec, expectStatus: defaultStatuses, source: 'spec_control' }

  if (params.storage && params.runId && specOrigin) {
    try {
      const picked = pickBestExchangeBaseline(params.storage.searchExchanges(params.runId, '', { origin: specOrigin, limit: 100 }), specOrigin, routeHint, params.grant)
      if (picked) return { caller: picked, expectStatus: defaultStatuses, source: 'phase0_exchange' }
    } catch { /* fail closed */ }
  }
  return null
}

const gate6RunLocks = new Map<string, Promise<void>>()

async function withGate6RunLock<T>(runId: string, fn: () => Promise<T>): Promise<T> {
  const prev = gate6RunLocks.get(runId) ?? Promise.resolve()
  let release!: () => void
  const gate = new Promise<void>(r => { release = r })
  const tail = prev.then(() => gate, () => gate)
  gate6RunLocks.set(runId, tail)
  await prev.catch(() => undefined)
  try { return await fn() } finally {
    release()
    if (gate6RunLocks.get(runId) === tail) gate6RunLocks.delete(runId)
  }
}

function restoreWorkspaceSnapshot(targetDir: string, backupDir: string): void {
  if (!existsSync(targetDir) || !existsSync(backupDir)) return
  for (const entry of readdirSync(targetDir)) rmSync(join(targetDir, entry), { recursive: true, force: true })
  copyRepoTreeWithoutSymlinks(backupDir, targetDir)
}

function workspaceMatchesBackupForPaths(targetDir: string, backupDir: string, touchedPaths: readonly string[]): boolean {
  for (const rel of touchedPaths) {
    const clean = normalizeRepoRelPath(rel)
    if (!clean) continue
    const tPath = join(targetDir, clean), bPath = join(backupDir, clean)
    const tExists = existsSync(tPath), bExists = existsSync(bPath)
    if (tExists !== bExists) return false
    if (tExists && bExists && readRegularFileNoFollow(tPath) !== readRegularFileNoFollow(bPath)) return false
  }
  return true
}

function buildIdentityDiffForDir(rootDir: string, preferredRelFiles: readonly string[]): string | null {
  const tryFile = (rel: string): string | null => {
    const clean = normalizeRepoRelPath(rel)
    if (!clean || isSensitiveRepoRelativePath(clean)) return null
    const content = readRegularFileNoFollow(join(rootDir, clean))
    if (!content) return null
    const firstLine = content.replace(/\r\n/g, '\n').split('\n')[0] ?? ''
    return [`--- a/${clean}`, `+++ b/${clean}`, '@@ -1,1 +1,1 @@', `-${firstLine}`, `+${firstLine}`, ''].join('\n')
  }
  for (const rel of preferredRelFiles) { const d = tryFile(rel); if (d) return d }
  const stack: string[] = ['']
  while (stack.length > 0) {
    const relDir = stack.pop()!, absDir = relDir ? join(rootDir, relDir) : rootDir
    let entries
    try { entries = readdirSync(absDir, { withFileTypes: true }) } catch { continue }
    for (const entry of entries) {
      const relPosix = relDir ? `${relDir}/${entry.name}` : entry.name
      if (isSymlink(join(absDir, entry.name))) continue
      if (entry.isDirectory()) { if (!SKIP_SCAN_DIRS.has(entry.name)) stack.push(relPosix) }
      else if (entry.isFile()) { const d = tryFile(relPosix); if (d) return d }
    }
  }
  return null
}

export async function generateAndReviewPatch(params: PatchWorkflowParams): Promise<PatchProposalResult> {
  const now = Date.now(), proposalId = randomUUID()
  const authorOutput = await runPatchAuthor(params)
  const review = await runPatchReviewer({
    finding: params.finding, repo: params.repo, reposDir: params.reposDir, authorOutput,
    precomputedApplicability: authorOutput.applicability, backend: params.backend,
    reviewerLlmCall: params.reviewerLlmCall, modelProfiles: params.modelProfiles,
    signal: params.signal, secrets: params.secrets, onUsage: params.onUsage, runId: params.runId,
  })

  let finalStatus: PatchStatus = review.status
  let dynamicRetestVerdict: DynamicRetestVerdict = 'skipped'
  let dynamicRetestSummary: string | undefined
  let patchBrokeHopId: string | null | undefined
  let compositeVerdict: CompositePatchRetestVerdict | null | undefined
  let compositeRetestProof: CompositePatchRetestProof | undefined
  let labRevision: string | undefined
  const gates = [...review.gates]

  if (params.labRetest && finalStatus === 'approved') {
    const lr = params.labRetest
    await withGate6RunLock(lr.runId, async () => {
      const sanitizedRepoDir = lr.sanitizedRepoDir ?? lr.labRunner?.supervisor?.getActiveRun?.(lr.runId)?.handle?.sanitizedRepoDir
      let scratchDir: string | null = null, backupDir: string | null = null, rebuildSucceeded = false
      let touchedPaths: string[] = [], rollbackError: string | null = null

      try {
        try { touchedPaths = parseUnifiedDiff(authorOutput.diff).map(fp => fp.normalizedPath) }
        catch { touchedPaths = authorOutput.applicability?.filesModified ?? [] }

        const resolvedComposite = resolvePersistedCompositeProofForGate6(lr, params.finding)
        const gate6Trust = deriveGate6EnvelopeTrust(lr, params.finding)

        if (resolvedComposite) {
          labRevision = lr.labRevision ?? `lab:${lr.runId}:${sha256Hex(authorOutput.diff).slice(0, 12)}`
          if (gate6Trust === 'untrusted') {
            dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
            compositeVerdict = 'inconclusive'; patchBrokeHopId = null
            dynamicRetestSummary = 'Dynamic composite fix retest withheld (H-5): untrusted replay envelope cannot be verified as fixed.'
            gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          } else {
            const sharedBrokerCtx: BrokerCompositeReplayContext = {
              broker: lr.broker,
              grant: lr.grant,
              storage: lr.storage,
              runId: lr.runId,
              assignmentId: lr.assignmentId,
              findingId: params.finding.id,
              replaySpecId: resolvedComposite.replaySpecId,
              replaySpec: lr.replaySpec,
              hopActors: resolvedComposite.hopActors,
              browser: lr.browser,
              canaryBroker: lr.canaryBroker,
              factLog: lr.factLog,
              labRevision,
              // R4-H-10: Gate-6 candidate-patch trials MUST NEVER write finding-level retest_runs
              // or overwrite replay_specs.proof_receipt.
              persistRetest: false,
            }

            // R4-H-9: Mandatory unpatched reproduction control BEFORE applying the candidate patch.
            // Accept "blocked" as "fixed" ONLY after the same runner proves it reproduces the chain
            // on the pre-patch baseline lab (or an authoritative verified pre-patch proof is supplied).
            let prePatchProof: CompositePatchRetestProof | null = null
            if (
              lr.prePatchReproductionProof
              && lr.prePatchReproductionProof.verdict === 'still_vulnerable'
              && lr.prePatchReproductionProof.chainId === resolvedComposite.receipt.chainId
              && hasValidCompositeProofDigest(lr.prePatchReproductionProof)
            ) {
              prePatchProof = lr.prePatchReproductionProof
            } else {
              prePatchProof = await retestCompositeChainPatch({
                receipt: resolvedComposite.receipt,
                ...(lr.compositeRunner ? { runner: lr.compositeRunner } : {}),
                brokerContext: sharedBrokerCtx,
                ...(lr.compositeVerifyOptions ? { verifyOptions: lr.compositeVerifyOptions } : {}),
                prePatchControlRun: true,
                targetRevision: `pre-patch:${labRevision}`,
                secrets: params.secrets,
                signal: params.signal ?? AbortSignal.timeout(60_000),
              })
            }

            if (prePatchProof.verdict !== 'still_vulnerable') {
              const mappedVerdict: CompositePatchRetestVerdict = prePatchProof.verdict === 'precondition_changed'
                ? 'precondition_changed'
                : 'inconclusive'
              const controlSummary = mappedVerdict === 'precondition_changed'
                ? `Dynamic composite fix retest inconclusive (precondition_changed on unpatched control): ${prePatchProof.summary}`
                : `Dynamic composite fix retest inconclusive: pre-patch reproduction control failed to reproduce the chain on the unpatched lab (${prePatchProof.summary})`
              const baseProof: Omit<CompositePatchRetestProof, 'proofSha256'> = {
                schemaVersion: 1,
                retestId: randomUUID(),
                chainId: resolvedComposite.receipt.chainId,
                terminalVulnClass: resolvedComposite.receipt.terminalVulnClass,
                terminalHopId: resolvedComposite.receipt.terminalImpact.terminalHopId,
                verdict: mappedVerdict,
                patchClosed: false,
                patchBrokeHopId: null,
                brokeCausalEdge: null,
                brokeReason: null,
                benignPrefixHops: [],
                topoOrder: [...prePatchProof.topoOrder],
                hopResults: [...prePatchProof.hopResults],
                exchangeIds: [...prePatchProof.exchangeIds],
                summary: redact(controlSummary, params.secrets),
                ...(prePatchProof.compositeVerification ? { compositeVerification: prePatchProof.compositeVerification } : {}),
                targetRevision: labRevision,
                patchId: proposalId,
                testedAt: new Date().toISOString(),
              }
              compositeRetestProof = { ...baseProof, proofSha256: computeCompositeRetestProofDigest(baseProof) }
              dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
              compositeVerdict = mappedVerdict; patchBrokeHopId = null
              dynamicRetestSummary = controlSummary
              gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
              persistProposalGate6CompositeArtifact(lr, {
                patchId: proposalId,
                findingId: params.finding.id,
                replaySpecId: resolvedComposite.replaySpecId,
                labRevision,
                status: finalStatus,
                dynamicRetestVerdict,
                proof: compositeRetestProof,
                secrets: params.secrets,
              })
            } else {
              if (sanitizedRepoDir && existsSync(sanitizedRepoDir)) {
                scratchDir = mkdtempSync(join(tmpdir(), 'kovo-patch-gate6-work-'))
                copyRepoTreeWithoutSymlinks(sanitizedRepoDir, scratchDir)
                applyUnifiedDiffToDirectory(scratchDir, authorOutput.diff)
                backupDir = mkdtempSync(join(tmpdir(), 'kovo-patch-gate6-backup-'))
                copyRepoTreeWithoutSymlinks(sanitizedRepoDir, backupDir)
              }

              await lr.labRunner.rebuildWithPatch(lr.runId, authorOutput.diff, params.signal)
              rebuildSucceeded = true

              const proof = await retestCompositeChainPatch({
                receipt: resolvedComposite.receipt,
                ...(lr.compositeRunner ? { runner: lr.compositeRunner } : {}),
                brokerContext: sharedBrokerCtx,
                ...(lr.compositeVerifyOptions ? { verifyOptions: lr.compositeVerifyOptions } : {}),
                prePatchProof,
                requireUnpatchedControl: true,
                patchId: proposalId,
                targetRevision: labRevision,
                secrets: params.secrets,
                signal: params.signal ?? AbortSignal.timeout(60_000),
              })
              compositeRetestProof = proof
              compositeVerdict = proof.verdict
              patchBrokeHopId = proof.verdict === 'fixed' ? proof.patchBrokeHopId : null

              if (proof.verdict === 'fixed') {
                const resolvedBaseline = synthesizeGate6BaselineCaller({
                  explicitBaselineCaller: lr.baselineCaller, explicitExpectStatus: lr.baselineExpectStatus,
                  replaySpec: lr.replaySpec, finding: params.finding, storage: lr.storage, runId: lr.runId, grant: lr.grant,
                })
                let baselineStatus: number | null = null, baselineOk = false
                if (resolvedBaseline) {
                  try {
                    const baseline = await lr.broker.executeHttp(resolvedBaseline.caller, lr.grant, params.signal ?? AbortSignal.timeout(30_000))
                    baselineStatus = baseline.status
                    baselineOk = resolvedBaseline.expectStatus.includes(baseline.status)
                  } catch { baselineOk = false }
                }

                if (resolvedBaseline && baselineOk) {
                  dynamicRetestVerdict = 'fixed'
                  const tag = resolvedBaseline.source === 'explicit' ? '' : ` [${resolvedBaseline.source}]`
                  dynamicRetestSummary = `Zero-LLM dynamic composite fix retest confirmed reproduced → fixed at "${proof.patchBrokeHopId ?? 'unknown'}": ${proof.summary}; authorized baseline caller${tag} (${resolvedBaseline.caller.method} ${resolvedBaseline.caller.pathAndQuery}) still HTTP ${baselineStatus}`
                  gates[5] = { gate: 6, name: 'dynamic_retest', passed: true, detail: dynamicRetestSummary }
                } else if (resolvedBaseline && !baselineOk) {
                  dynamicRetestVerdict = 'skipped'; finalStatus = 'rejected'; patchBrokeHopId = null
                  dynamicRetestSummary = `Composite chain retest reports fixed at "${proof.patchBrokeHopId ?? 'unknown'}", but the authorized baseline caller (${resolvedBaseline.caller.method} ${resolvedBaseline.caller.pathAndQuery}) regressed (HTTP ${baselineStatus ?? 'error'}); patch breaks legitimate traffic.`
                  gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
                } else {
                  // R4-H-9: Never pass Gate 6 with no baseline caller just because a benign prefix hop exists.
                  dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'; patchBrokeHopId = null
                  dynamicRetestSummary = 'Composite chain retest reports fixed, but Gate 6 is unverified: no safe read-only/idempotent baseline caller could be resolved to prove legitimate traffic still works.'
                  gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
                }
              } else if (proof.verdict === 'still_vulnerable') {
                dynamicRetestVerdict = 'reproduced'; finalStatus = 'rejected'
                patchBrokeHopId = null
                dynamicRetestSummary = `Multi-hop composite chain still reproduced after patch rebuild: ${proof.summary}`
                gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
              } else if (proof.verdict === 'precondition_changed') {
                // Fail-closed invariant: precondition/environment drift MUST NEVER be marked 'fixed'.
                dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
                patchBrokeHopId = null
                dynamicRetestSummary = `Dynamic composite fix retest inconclusive (precondition_changed): ${proof.summary}`
                gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
              } else {
                dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
                patchBrokeHopId = null
                dynamicRetestSummary = `Dynamic composite fix retest inconclusive: ${proof.summary}`
                gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
              }

              persistProposalGate6CompositeArtifact(lr, {
                patchId: proposalId,
                findingId: params.finding.id,
                replaySpecId: resolvedComposite.replaySpecId,
                labRevision,
                status: finalStatus,
                dynamicRetestVerdict,
                proof,
                secrets: params.secrets,
              })
            }
          }
        } else {
          if (sanitizedRepoDir && existsSync(sanitizedRepoDir)) {
            scratchDir = mkdtempSync(join(tmpdir(), 'kovo-patch-gate6-work-'))
            copyRepoTreeWithoutSymlinks(sanitizedRepoDir, scratchDir)
            applyUnifiedDiffToDirectory(scratchDir, authorOutput.diff)
            backupDir = mkdtempSync(join(tmpdir(), 'kovo-patch-gate6-backup-'))
            copyRepoTreeWithoutSymlinks(sanitizedRepoDir, backupDir)
          }

          await lr.labRunner.rebuildWithPatch(lr.runId, authorOutput.diff, params.signal)
          rebuildSucceeded = true

          const retest = await retestReplaySpec({
            spec: lr.replaySpec, broker: lr.broker, browser: lr.browser, canaryBroker: lr.canaryBroker,
            backend: lr.backend, grant: lr.grant, signal: params.signal ?? AbortSignal.timeout(60_000),
            storage: lr.storage, runId: lr.runId, assignmentId: lr.assignmentId,
            envelopeTrust: gate6Trust,
          })

          const resolvedBaseline = synthesizeGate6BaselineCaller({
            explicitBaselineCaller: lr.baselineCaller, explicitExpectStatus: lr.baselineExpectStatus,
            replaySpec: lr.replaySpec, finding: params.finding, storage: lr.storage, runId: lr.runId, grant: lr.grant,
          })

          let baselineStatus: number | null = null, baselineOk = false
          if (resolvedBaseline) {
            try {
              const baseline = await lr.broker.executeHttp(resolvedBaseline.caller, lr.grant, params.signal ?? AbortSignal.timeout(30_000))
              baselineStatus = baseline.status
              baselineOk = resolvedBaseline.expectStatus.includes(baseline.status)
            } catch { baselineOk = false }
          }

          if (retest.verdict === 'fixed' && resolvedBaseline && baselineOk) {
            dynamicRetestVerdict = 'fixed'
            const tag = resolvedBaseline.source === 'explicit' ? '' : ` [${resolvedBaseline.source}]`
            dynamicRetestSummary = `Zero-LLM dynamic fix retest confirmed reproduced → fixed: ${retest.replay.outcome.observed}; authorized baseline caller${tag} (${resolvedBaseline.caller.method} ${resolvedBaseline.caller.pathAndQuery}) still HTTP ${baselineStatus}`
            gates[5] = { gate: 6, name: 'dynamic_retest', passed: true, detail: dynamicRetestSummary }
          } else if (retest.verdict === 'fixed' && !resolvedBaseline) {
            dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
            dynamicRetestSummary = 'Exploit replay reports fixed, but Gate 6 is unverified: no safe read-only/idempotent baseline caller could be resolved to prove legitimate traffic still succeeds.'
            gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          } else if (retest.verdict === 'fixed' && resolvedBaseline && !baselineOk) {
            dynamicRetestVerdict = 'skipped'; finalStatus = 'rejected'
            dynamicRetestSummary = `Exploit replay reports fixed, but the authorized baseline caller (${resolvedBaseline.caller.method} ${resolvedBaseline.caller.pathAndQuery}) regressed (HTTP ${baselineStatus ?? 'error'}); patch breaks legitimate traffic.`
            gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          } else if (retest.verdict === 'reproduced') {
            dynamicRetestVerdict = 'reproduced'; finalStatus = 'rejected'
            dynamicRetestSummary = `Vulnerability still reproduced after patch rebuild: ${retest.replay.outcome.observed}`
            gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          } else {
            dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
            dynamicRetestSummary = `Dynamic fix retest inconclusive: ${retest.replay.outcome.observed}`
            gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
          }
        }
      } catch (err) {
        dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
        dynamicRetestSummary = `Dynamic fix retest failed: ${err instanceof Error ? err.message : String(err)}`
        gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
      } finally {
        if (rebuildSucceeded) {
          let reverseOk = false, lastErr: unknown = null
          try {
            await lr.labRunner.rebuildWithPatch(lr.runId, invertUnifiedDiff(authorOutput.diff), AbortSignal.timeout(30_000))
            reverseOk = true
          } catch (err) { lastErr = err }

          const diskClean = !sanitizedRepoDir || !backupDir || workspaceMatchesBackupForPaths(sanitizedRepoDir, backupDir, touchedPaths)
          if ((!reverseOk || !diskClean) && sanitizedRepoDir && backupDir) {
            try {
              restoreWorkspaceSnapshot(sanitizedRepoDir, backupDir)
              const idDiff = buildIdentityDiffForDir(sanitizedRepoDir, touchedPaths)
              if (!idDiff) throw new Error('Could not construct identity diff to rebuild clean container after snapshot restore.')
              await lr.labRunner.rebuildWithPatch(lr.runId, idDiff, AbortSignal.timeout(30_000))
              reverseOk = true; lastErr = null
            } catch (recoveryErr) { reverseOk = false; lastErr = recoveryErr }
          }
          if (!reverseOk) {
            rollbackError = `Gate-6 rollback desync: failed to revert live container to pre-trial state (${lastErr instanceof Error ? lastErr.message : String(lastErr)})`
          }
        } else if (sanitizedRepoDir && backupDir) {
          try { restoreWorkspaceSnapshot(sanitizedRepoDir, backupDir) }
          catch (err) { rollbackError = `Gate-6 workspace snapshot restore failed (${err instanceof Error ? err.message : String(err)})` }
        }

        if (rollbackError) {
          dynamicRetestVerdict = 'skipped'; finalStatus = 'withheld'
          dynamicRetestSummary = dynamicRetestSummary ? `${dynamicRetestSummary}; ${rollbackError}` : rollbackError
          gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: dynamicRetestSummary }
        }
        if (scratchDir) { try { rmSync(scratchDir, { recursive: true, force: true }) } catch { /* ignore */ } }
        if (backupDir) { try { rmSync(backupDir, { recursive: true, force: true }) } catch { /* ignore */ } }
      }
    })
  } else if (params.labRetest && finalStatus !== 'approved') {
    gates[5] = { gate: 6, name: 'dynamic_retest', passed: false, detail: `Dynamic retest skipped because static review status was "${finalStatus}".` }
  }

  return {
    id: proposalId, runId: params.runId, findingId: params.finding.id, repo: params.repo,
    status: finalStatus, callerCompatibility: review.callerCompatibility,
    fixBefore: redact(authorOutput.fixBefore, params.secrets), fixAfter: redact(authorOutput.fixAfter, params.secrets),
    diff: redact(authorOutput.diff, params.secrets), codeLocations: authorOutput.codeLocations,
    coverageInventory: authorOutput.coverageInventory, gates,
    reviewNotes: redact([review.reviewNotes, ...(dynamicRetestSummary ? [`Dynamic retest (${dynamicRetestVerdict}): ${dynamicRetestSummary}`] : [])].join('\n'), params.secrets),
    dynamicRetestVerdict, dynamicRetestSummary: dynamicRetestSummary ? redact(dynamicRetestSummary, params.secrets) : undefined,
    ...(patchBrokeHopId !== undefined ? { patchBrokeHopId } : {}),
    ...(compositeVerdict !== undefined ? { compositeVerdict } : {}),
    ...(compositeRetestProof ? { compositeRetestProof } : {}),
    ...(labRevision ? { labRevision } : {}),
    createdAt: now, updatedAt: Date.now(),
  }
}

// ============================================================================
// Multi-Hop CompositeProofReceipt DAG Patch-Retest (consolidated compat surface)
// ============================================================================

export type CompositePatchRetestVerdict = 'fixed' | 'still_vulnerable' | 'inconclusive' | 'precondition_changed'
export type CompositeHopReplayOutcome = 'succeeded' | 'blocked' | 'transport_error' | 'auth_setup_failed' | 'precondition_changed' | 'inconclusive'
export interface CompositeBrokeCausalEdge { edgeIndex: number; kind: CausalEdgeKind; fromHopId: string; toHopId: string }
export interface CompositeHopReplaySummary {
  hopId: string; surface: HopSurface; outcome: CompositeHopReplayOutcome | 'skipped_after_break'
  httpStatuses: number[]; exchangeIds: string[]; oobEventIds: string[]; browserTraceIds: string[]
  emittedCapabilities: string[]; consumedCapabilities: string[]; reason?: string; errorCode?: string
}
export interface CompositeHopReplayContext {
  receipt: CompositeProofReceipt; hop: HopReceipt; hopIndex: number; topoOrder: readonly string[]
  incomingEdges: readonly CausalEdgeBinding[]; outgoingEdges: readonly CausalEdgeBinding[]
  availableCapabilities: readonly string[]; priorHopResults: Readonly<Record<string, CompositeHopReplaySummary>>
  transcriptSoFar: HostSignedTranscript; signal?: AbortSignal
}
export interface CompositeHopReplayResult {
  outcome?: CompositeHopReplayOutcome; entries?: readonly HostTranscriptEntry[]; oobEvents?: readonly HostOobEvent[]
  browserTraces?: readonly HostBrowserTrace[]; asyncPollRecords?: readonly HostAsyncPollRecord[]
  replayedExchangeIds?: readonly string[]; replayedOobEventIds?: readonly string[]; replayedBrowserTraceIds?: readonly string[]
  replayedAblationExchangeIds?: Readonly<Record<string, readonly string[]>>; replayedPollRecordIds?: Readonly<Record<string, string>>
  reboundValueDigests?: Readonly<Record<string, string>>
  preChainControlExchangeIds?: readonly string[]; postChainReadbackExchangeIds?: readonly string[]
  reason?: string; errorCode?: string; httpStatus?: number | null
}
export interface CompositePreconditionSetupResult {
  status: 'ok' | 'precondition_changed' | 'transport_error' | 'auth_setup_failed' | 'inconclusive'
  reason?: string; errorCode?: string; httpStatus?: number | null
  entries?: readonly HostTranscriptEntry[]; oobEvents?: readonly HostOobEvent[]
  browserTraces?: readonly HostBrowserTrace[]; asyncPollRecords?: readonly HostAsyncPollRecord[]
  preChainControlExchangeIds?: readonly string[]
}
export interface CompositePatchReplayRunner {
  preparePreconditions?: (ctx: { receipt: CompositeProofReceipt; topoOrder: readonly string[]; signal?: AbortSignal }) => Promise<CompositePreconditionSetupResult> | CompositePreconditionSetupResult
  replayHop: (ctx: CompositeHopReplayContext) => Promise<CompositeHopReplayResult> | CompositeHopReplayResult
  readbackTerminalState?: (ctx: { receipt: CompositeProofReceipt; transcriptSoFar: HostSignedTranscript; signal?: AbortSignal }) => Promise<{
    status?: 'ok' | 'transport_error' | 'precondition_changed' | 'inconclusive'
    reason?: string; errorCode?: string; httpStatus?: number | null; entries?: readonly HostTranscriptEntry[]; postChainReadbackExchangeIds?: readonly string[]
  }> | {
    status?: 'ok' | 'transport_error' | 'precondition_changed' | 'inconclusive'
    reason?: string; errorCode?: string; httpStatus?: number | null; entries?: readonly HostTranscriptEntry[]; postChainReadbackExchangeIds?: readonly string[]
  }
}
export interface BrokerCompositeReplayContext {
  broker: RequestBroker
  grant: Grant
  storage?: Store
  runId?: string
  assignmentId?: string
  findingId?: string
  replaySpecId?: string
  replaySpec?: DeclarativeReplaySpec
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  factLog?: HostFactLog
  labRevision?: string
  hopActors?: Readonly<Record<string, string | null>>
  hopRequestOverrides?: Readonly<Record<string, Partial<BrokerHttpRequest>>>
  /**
   * Persist authoritative finding-level retest row in `retest_runs` (default: false).
   * R4-H-10: Ignored whenever `patchId` is set (candidate-patch trials are proposal-scoped
   * and NEVER write finding-level `retest_runs` or mutate `replay_specs.proof_receipt`).
   */
  persistRetest?: boolean
  /** Optional callback to record replayed exchanges; returns persisted exchangeId. */
  onExchange?: (ex: BrokerExchangeResult) => string | undefined
}
export interface RetestCompositeChainParams {
  receipt: CompositeProofReceipt
  runner?: CompositePatchReplayRunner
  brokerContext?: BrokerCompositeReplayContext
  verifyOptions?: CompositeVerifyOptions
  /** Authoritative pre-patch reproduction proof from the same runner (verdict === 'still_vulnerable'). */
  prePatchProof?: CompositePatchRetestProof
  /** True when executing the pre-patch reproduction control itself on the unpatched target. */
  prePatchControlRun?: boolean
  /** Enforce pre-patch reproduction control before certifying 'fixed' (default: true for broker runs). */
  requireUnpatchedControl?: boolean
  retestId?: string; targetRevision?: string; patchId?: string; secrets?: readonly NamedSecret[]; signal?: AbortSignal; now?: () => number
}
export interface CompositePatchRetestProof {
  schemaVersion: 1; retestId: string; chainId: string; terminalVulnClass: string; terminalHopId: string
  verdict: CompositePatchRetestVerdict; patchClosed: boolean; patchBrokeHopId: string | null
  brokeCausalEdge: CompositeBrokeCausalEdge | null; brokeReason: string | null; benignPrefixHops: string[]
  topoOrder: string[]; hopResults: CompositeHopReplaySummary[]; exchangeIds: string[]; summary: string
  compositeVerification?: CompositeReceiptVerification; targetRevision?: string; patchId?: string; testedAt: string; proofSha256: string
}
export interface PortableCompositePatchRetestRecord {
  retestId: string; verdict: 'reproduced' | 'fixed' | 'inconclusive'; compositeVerdict: CompositePatchRetestVerdict
  chainId: string; terminalVulnClass: string; patchClosed: boolean; patchBrokeHopId: string | null
  brokeCausalEdge: CompositeBrokeCausalEdge | null; brokeReason: string | null; benignPrefixHops: string[]
  summary: string; exchangeIds: string[]; testedAt: string; proofSha256: string
}
export interface CompositePatchClosureSummary {
  total: number; fixed: number; stillVulnerable: number; inconclusive: number; preconditionChanged: number
  closureRate: number; meetsM4ClosureGate: boolean
}

const TRANSPORT_ERR_RE = /^(?:ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EPIPE|EHOSTUNREACH|ENETUNREACH|UND_ERR_[A-Z_]+|TIMEOUT|ABORTED|ABORT_ERR|TLS_ERROR|AUTH_SETUP_FAILED)$/i
const is2xx = (st: number | null | undefined) => typeof st === 'number' && st >= 200 && st < 300
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const isTransportOr5xx = (st: number | null | undefined) => st == null || !Number.isFinite(st) || st === 0 || st === 408 || st === 429 || st >= 500
const isSecurity4xx = (st: number | null | undefined) => typeof st === 'number' && st >= 400 && st < 500 && st !== 408 && st !== 429

function canonicalProofJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return `[${v.map(canonicalProofJson).join(',')}]`
  return `{${Object.entries(v as Record<string, unknown>).filter(([k, val]) => k !== 'proofSha256' && val !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, val]) => `${JSON.stringify(k)}:${canonicalProofJson(val)}`).join(',')}}`
}

export const computeCompositeRetestProofDigest = (proof: Omit<CompositePatchRetestProof, 'proofSha256'> & { proofSha256?: string }): string =>
  sha256Hex(canonicalProofJson(proof))

const hasValidCompositeProofDigest = (proof: CompositePatchRetestProof): boolean =>
  Boolean(proof && typeof proof.proofSha256 === 'string' && /^[0-9a-f]{64}$/i.test(proof.proofSha256) && proof.proofSha256.toLowerCase() === computeCompositeRetestProofDigest(proof))

export const verifyCompositePatchRetestProofIntegrity = (proof: CompositePatchRetestProof): boolean =>
  hasValidCompositeProofDigest(proof)

export const toPortablePatchRetestProof = (p: CompositePatchRetestProof): PortableCompositePatchRetestRecord => ({
  retestId: p.retestId, verdict: p.verdict === 'fixed' ? 'fixed' : p.verdict === 'still_vulnerable' ? 'reproduced' : 'inconclusive',
  compositeVerdict: p.verdict, chainId: p.chainId, terminalVulnClass: p.terminalVulnClass, patchClosed: p.patchClosed,
  patchBrokeHopId: p.patchBrokeHopId, brokeCausalEdge: p.brokeCausalEdge, brokeReason: p.brokeReason,
  benignPrefixHops: [...p.benignPrefixHops], summary: p.summary, exchangeIds: [...p.exchangeIds], testedAt: p.testedAt, proofSha256: p.proofSha256,
})

export function summarizeCompositePatchClosure(proofs: readonly CompositePatchRetestProof[], threshold = 0.8): CompositePatchClosureSummary {
  let fixed = 0, stillVulnerable = 0, inconclusive = 0, preconditionChanged = 0
  for (const p of proofs) {
    if (p.verdict === 'fixed') fixed += 1
    else if (p.verdict === 'still_vulnerable') stillVulnerable += 1
    else if (p.verdict === 'precondition_changed') preconditionChanged += 1
    else inconclusive += 1
  }
  const total = proofs.length, closureRate = total > 0 ? fixed / total : 0
  return { total, fixed, stillVulnerable, inconclusive, preconditionChanged, closureRate, meetsM4ClosureGate: total > 0 && closureRate >= threshold }
}

type IndexedEdge = { edgeIndex: number; edge: CausalEdgeBinding }
type HopArt = { exchangeIds: string[]; oobEventIds: string[]; browserTraceIds: string[]; entries: HostTranscriptEntry[]; oobEvents: HostOobEvent[]; browserTraces: HostBrowserTrace[]; asyncPollRecords: HostAsyncPollRecord[]; ablationByEdge: Record<string, readonly string[]>; pollByEdge: Record<string, string> }

function buildCompositeDag(receipt: CompositeProofReceipt) {
  const hopsById = new Map<string, HopReceipt>()
  for (const h of receipt.hops) { if (hopsById.has(h.hopId)) return { ok: false as const, reason: `Duplicate hopId "${h.hopId}".` }; hopsById.set(h.hopId, h) }
  if (!hopsById.has(receipt.terminalImpact.terminalHopId)) return { ok: false as const, reason: `terminalHopId "${receipt.terminalImpact.terminalHopId}" not in hops.` }
  if (receipt.hops.length === 1 && receipt.causalEdges.length > 0) return { ok: false as const, reason: 'A 1-hop receipt cannot declare causalEdges.' }
  const inDeg = new Map(receipt.hops.map(h => [h.hopId, 0])), outAdj = new Map(receipt.hops.map(h => [h.hopId, [] as string[]])), revAdj = new Map(receipt.hops.map(h => [h.hopId, [] as string[]]))
  const incomingByHop = new Map(receipt.hops.map(h => [h.hopId, [] as IndexedEdge[]])), outgoingByHop = new Map(receipt.hops.map(h => [h.hopId, [] as IndexedEdge[]]))
  const seen = new Set<string>()
  for (let i = 0; i < receipt.causalEdges.length; i += 1) {
    const e = receipt.causalEdges[i]!, key = `${e.fromHopId}->${e.toHopId}:${e.kind}`
    if (!hopsById.has(e.fromHopId) || !hopsById.has(e.toHopId)) return { ok: false as const, reason: `Edge #${i} references unknown hop.` }
    if (e.fromHopId === e.toHopId) return { ok: false as const, reason: `Edge #${i} forms a self-loop on "${e.fromHopId}".` }
    if (seen.has(key)) return { ok: false as const, reason: `Duplicate causal edge "${key}".` }
    seen.add(key); outAdj.get(e.fromHopId)!.push(e.toHopId); revAdj.get(e.toHopId)!.push(e.fromHopId)
    inDeg.set(e.toHopId, (inDeg.get(e.toHopId) ?? 0) + 1); incomingByHop.get(e.toHopId)!.push({ edgeIndex: i, edge: e }); outgoingByHop.get(e.fromHopId)!.push({ edgeIndex: i, edge: e })
  }
  const q = receipt.hops.filter(h => inDeg.get(h.hopId) === 0).map(h => h.hopId), rem = new Map(inDeg), topoOrder: string[] = []
  while (q.length) {
    const id = q.shift()!; topoOrder.push(id)
    for (const next of outAdj.get(id) ?? []) { const d = (rem.get(next) ?? 0) - 1; rem.set(next, d); if (d === 0) q.push(next) }
  }
  if (topoOrder.length !== receipt.hops.length) return { ok: false as const, reason: 'Causal DAG contains a cycle.' }
  const reaches = new Set([receipt.terminalImpact.terminalHopId]), rq = [receipt.terminalImpact.terminalHopId]
  while (rq.length) for (const prev of revAdj.get(rq.shift()!) ?? []) if (!reaches.has(prev)) { reaches.add(prev); rq.push(prev) }
  const orphan = receipt.hops.find(h => !reaches.has(h.hopId))
  return orphan ? { ok: false as const, reason: `Hop "${orphan.hopId}" does not reach terminalHopId.` } : { ok: true as const, dag: { hopsById, topoOrder, incomingByHop, outgoingByHop } }
}

function collectLeafTokens(v: unknown, out: Set<string>, d = 0): void {
  if (d > 5 || out.size > 256 || v == null) return
  if (typeof v === 'string') { const t = v.trim(); if (t.length > 0 && t.length <= 2048) out.add(t) }
  else if (typeof v === 'number' || typeof v === 'boolean') out.add(String(v))
  else if (Array.isArray(v)) for (const x of v) collectLeafTokens(x, out, d + 1)
  else if (typeof v === 'object') for (const x of Object.values(v as Record<string, unknown>)) collectLeafTokens(x, out, d + 1)
}
function collectHdrTokens(headers: Record<string, string> | null | undefined, out: Set<string>): void {
  if (!headers) return
  for (const raw of Object.values(headers)) {
    const t = raw.trim(); if (!t) continue; out.add(t)
    const m = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(t); if (m?.[1]) out.add(m[1].trim())
    if (t.includes('=')) for (const p of t.split(';')) { const eq = p.indexOf('='); if (eq > 0 && p.slice(eq + 1).trim()) out.add(p.slice(eq + 1).trim()) }
  }
}
function entryHasToken(e: HostTranscriptEntry, tok: string, withHdrs: boolean): boolean {
  if (e.entityId === tok || e.correlationIds?.includes(tok) || (withHdrs && e.carrierText?.includes(tok))) return true
  const path = e.step.pathAndQuery ?? e.step.route ?? ''
  if (path && new RegExp(`(?:^|[/=?&])${tok.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[/&?#])`).test(path)) return true
  const leaves = new Set<string>(); collectLeafTokens(e.step.requestJson, leaves); collectLeafTokens(e.step.json, leaves)
  if (withHdrs) { collectHdrTokens(e.step.requestHeaders, leaves); collectHdrTokens(e.step.responseHeaders, leaves) }
  return withHdrs ? [...leaves].some(l => l === tok || l.includes(tok)) : leaves.has(tok)
}

function inspectRecordsForError(
  rec: { entries?: readonly HostTranscriptEntry[]; oobEvents?: readonly HostOobEvent[]; browserTraces?: readonly HostBrowserTrace[]; asyncPollRecords?: readonly HostAsyncPollRecord[] },
  signingKey?: string,
): { failed: false } | { failed: true; reason: string; errorCode: string } {
  for (const e of rec.entries ?? []) {
    if (isTransportOr5xx(e.step.status)) {
      const st = e.step.status
      return { failed: true, reason: `Exchange "${e.exchangeId}" returned ${st == null ? 'no HTTP status' : `HTTP ${st}`} (transport/server failure; failing closed).`, errorCode: typeof st === 'number' && st > 0 ? `HTTP_${st}` : 'TRANSPORT_NO_STATUS' }
    }
  }
  if (signingKey) {
    const checks: Array<[readonly HostSignableRecord[] | undefined, string, (r: HostSignableRecord) => string]> = [
      [rec.entries, 'exchange', r => (r as HostTranscriptEntry).exchangeId], [rec.oobEvents, 'OOB event', r => (r as HostOobEvent).id],
      [rec.browserTraces, 'browser trace', r => (r as HostBrowserTrace).id], [rec.asyncPollRecords, 'async poll record', r => (r as HostAsyncPollRecord).id],
    ]
    for (const [list, label, idOf] of checks) {
      for (const item of list ?? []) if (!verifyHostRecordSignature(item, signingKey)) return { failed: true, reason: `Host transcript signature verification failed on ${label} "${idOf(item)}" (failing closed).`, errorCode: 'HOST_SIGNATURE_INVALID' }
    }
  }
  return { failed: false }
}

function collectEmitted(entries: readonly HostTranscriptEntry[], oob: readonly HostOobEvent[], traces: readonly HostBrowserTrace[], polls: readonly HostAsyncPollRecord[], requireTs = false) {
  const caps = new Set<string>(), digests = new Set<string>()
  let hasTs = false
  for (const e of entries) {
    if (requireTs && !isFiniteTs(e.timestampMs)) continue
    hasTs = true
    for (const c of e.emittedCapabilities ?? []) caps.add(c)
    for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) caps.add(a.derivedCapabilityId)
    for (const d of [...(e.observedResponseDigests ?? []), ...(e.step.secretMatches ?? [])]) digests.add(d.toLowerCase())
    const l = new Set<string>(); collectLeafTokens(e.step.json, l); collectHdrTokens(e.step.responseHeaders, l); for (const v of l) digests.add(sha256Hex(v))
  }
  for (const o of oob) {
    if (requireTs && (!o.delivered || !isFiniteTs(o.receivedAtMs))) continue
    hasTs = true; for (const c of o.emittedCapabilities ?? []) caps.add(c); for (const d of o.observedValueDigests ?? []) digests.add(d.toLowerCase()); if (o.token) digests.add(sha256Hex(o.token))
  }
  for (const t of traces) {
    if (requireTs && !isFiniteTs(t.timestampMs)) continue
    hasTs = true; for (const c of t.emittedCapabilities ?? []) caps.add(c); for (const d of t.observedValueDigests ?? []) digests.add(d.toLowerCase())
  }
  for (const p of polls) for (const c of p.emittedCapabilities ?? []) caps.add(c)
  return { caps, digests, hasTs }
}

function checkProducerEdge(
  edge: CausalEdgeBinding,
  fromHop: HopReceipt,
  art: HopArt,
  reboundValueDigests?: ReadonlyMap<string, string>,
): { ok: true } | { ok: false; reason: string } {
  const he = art.entries.filter(e => art.exchangeIds.includes(e.exchangeId)), ho = art.oobEvents.filter(o => art.oobEventIds.includes(o.id)), ht = art.browserTraces.filter(t => art.browserTraceIds.includes(t.id))
  const { caps, digests, hasTs } = collectEmitted(he, ho, ht, [], true)
  if (edge.kind === 'value_binding') {
    if (!hasTs) return { ok: false, reason: `Hop "${fromHop.hopId}" produced no host-timestamped output for value_binding to "${edge.toHopId}".` }
    if (edge.capabilityHandle && !caps.has(edge.capabilityHandle)) return { ok: false, reason: `Hop "${fromHop.hopId}" no longer emits required capability "${edge.capabilityHandle}" for "${edge.toHopId}".` }
    const edgeKey = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
    const expectedDigest = reboundValueDigests?.get(edgeKey) ?? edge.valueDigest?.toLowerCase()
    if (expectedDigest && !digests.has(expectedDigest)) return { ok: false, reason: `Hop "${fromHop.hopId}" no longer emits required value digest for "${edge.toHopId}".` }
    return { ok: true }
  }
  if (edge.kind === 'derived_crypto_binding') return caps.has(edge.sourceCapabilityId) ? { ok: true } : { ok: false, reason: `Hop "${fromHop.hopId}" no longer emits signing material "${edge.sourceCapabilityId}" for derived_crypto_binding to "${edge.toHopId}".` }
  if (edge.kind === 'state_transition_binding') return he.some(e => is2xx(e.step.status) && isFiniteTs(e.timestampMs) && entryHasToken(e, edge.entityId, false)) ? { ok: true } : { ok: false, reason: `Hop "${fromHop.hopId}" no longer succeeds on shared entity "${edge.entityId}" for state_transition_binding to "${edge.toHopId}".` }
  return (he.some(e => is2xx(e.step.status) && isFiniteTs(e.timestampMs) && entryHasToken(e, edge.correlationId, true)) || ht.some(t => isFiniteTs(t.timestampMs) && (t.correlationIds?.includes(edge.correlationId) ?? false)))
    ? { ok: true } : { ok: false, reason: `Hop "${fromHop.hopId}" no longer produces async trigger "${edge.correlationId}" for "${edge.toHopId}".` }
}

const errCodeOf = (err: unknown): string | undefined => {
  if (!err || typeof err !== 'object') return undefined
  const r = err as { code?: unknown; name?: unknown; cause?: { code?: unknown } }
  return typeof r.code === 'string' && r.code.trim() ? r.code.trim() : typeof r.cause?.code === 'string' && r.cause.code.trim() ? r.cause.code.trim() : typeof r.name === 'string' && r.name.trim() && r.name !== 'Error' ? r.name.trim() : undefined
}
const emptyHopSummary = (hopId: string, surface: HopSurface, outcome: CompositeHopReplaySummary['outcome'], reason?: string, errorCode?: string): CompositeHopReplaySummary =>
  ({ hopId, surface, outcome, httpStatuses: [], exchangeIds: [], oobEventIds: [], browserTraceIds: [], emittedCapabilities: [], consumedCapabilities: [], ...(reason ? { reason } : {}), ...(errorCode ? { errorCode } : {}) })

const ROUTE_DRIFT_MARKERS = [
  'cannot get ', 'cannot post ', 'cannot put ', 'cannot patch ', 'cannot delete ',
  'route_not_found', 'endpoint_moved', 'schema_changed', 'fixture_missing',
  'unknown_route', 'no route matched', 'not_implemented', 'api_version_unsupported', 'deprecated_endpoint',
] as const
const SCHEMA_DRIFT_400_MARKERS = [
  'schema_changed', 'api_version_unsupported', 'deprecated_endpoint', 'unknown_field', 'missing_required_field',
] as const
const AUTH_DENIAL_MARKERS = [
  'forbidden', 'unauthorized', 'access denied', 'permission', 'not allowed', 'auth_required', 'invalid_token',
] as const
const VALID_HTTP_METHODS = new Set<HttpMethod>(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])

function normalizeReplayHttpMethod(raw: string | undefined): HttpMethod {
  const upper = (raw ?? 'GET').trim().toUpperCase() as HttpMethod
  return VALID_HTTP_METHODS.has(upper) ? upper : 'GET'
}

const TRANSPORT_SKIP_HEADERS = new Set([
  'host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding',
])
const PERSONA_AUTH_HEADERS = new Set([
  'authorization', 'cookie', 'x-api-key',
])

function rebuildStoredReplayHeaders(params: {
  rawHeaders: Readonly<Record<string, string>> | undefined
  personaHandle: string | null
  grant: Grant
  overrideHeaders?: Record<string, string>
}): { headers: Record<string, string> | undefined; redactedHeaders: string[] } {
  if (params.overrideHeaders) {
    const redactedHeaders = Object.entries(params.overrideHeaders)
      .filter(([, v]) => hasVaultScrubbedToken(v))
      .map(([k]) => k)
    return {
      headers: Object.keys(params.overrideHeaders).length > 0 ? { ...params.overrideHeaders } : undefined,
      redactedHeaders,
    }
  }
  if (!params.rawHeaders) return { headers: undefined, redactedHeaders: [] }
  const persona = params.personaHandle ? params.grant.personas?.get(params.personaHandle) : undefined
  const personaHeaderLower = persona?.headerName?.trim().toLowerCase() || ''
  const out: Record<string, string> = {}
  const redactedHeaders: string[] = []
  for (const [k, v] of Object.entries(params.rawHeaders)) {
    const lk = k.trim().toLowerCase()
    if (!lk || !v) continue
    if (TRANSPORT_SKIP_HEADERS.has(lk)) continue
    const isPersonaSuppliedAuth = Boolean(persona) && (PERSONA_AUTH_HEADERS.has(lk) || (personaHeaderLower !== '' && lk === personaHeaderLower))
    if (isPersonaSuppliedAuth) continue
    if (hasVaultScrubbedToken(v)) {
      redactedHeaders.push(k)
      continue
    }
    out[k] = v
  }
  return { headers: Object.keys(out).length > 0 ? out : undefined, redactedHeaders }
}

function tryParseJsonBody(body: string): unknown {
  const trimmed = body.trim()
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return undefined
  try { return JSON.parse(trimmed) } catch { return undefined }
}

interface ExtractedSlotToken {
  source: 'json' | 'header' | 'body'
  path: string
  keyNorm: string
  value: string
  digest: string
}

function normalizeSlotName(raw: string): string {
  return raw.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function extractResponseSlotTokens(
  body: string,
  json: unknown,
  headers: Readonly<Record<string, string>>,
): ExtractedSlotToken[] {
  const out: ExtractedSlotToken[] = []
  const seen = new Set<string>()
  const push = (source: ExtractedSlotToken['source'], path: string, value: string) => {
    const trimmed = value.trim()
    if (!trimmed || trimmed.length > 2048 || out.length >= 256) return
    const key = `${source}:${path}:${trimmed}`
    if (seen.has(key)) return
    seen.add(key)
    const leafName = path.split('.').pop() ?? path
    out.push({ source, path, keyNorm: normalizeSlotName(leafName), value: trimmed, digest: sha256Hex(trimmed) })
  }
  const walk = (v: unknown, prefix: string, depth: number) => {
    if (depth > 5 || v == null || out.length >= 256) return
    if (typeof v === 'string') { if (prefix) push('json', prefix, v) }
    else if (typeof v === 'number' || typeof v === 'boolean') { if (prefix) push('json', prefix, String(v)) }
    else if (Array.isArray(v)) {
      for (let i = 0; i < Math.min(v.length, 32); i += 1) walk(v[i], prefix ? `${prefix}.${i}` : String(i), depth + 1)
    } else if (typeof v === 'object') {
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        walk(child, prefix ? `${prefix}.${k}` : k, depth + 1)
      }
    }
  }
  if (json !== undefined) walk(json, '', 0)
  for (const [hk, hv] of Object.entries(headers)) {
    const lk = hk.trim().toLowerCase()
    const tv = hv.trim()
    if (!lk || !tv) continue
    push('header', lk, tv)
    const m = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(tv)
    if (m?.[1]) push('header', `${lk}:token`, m[1].trim())
    if (tv.includes('=')) {
      for (const part of tv.split(';')) {
        const eq = part.indexOf('=')
        if (eq > 0 && part.slice(eq + 1).trim()) {
          push('header', `${lk}:${part.slice(0, eq).trim().toLowerCase()}`, part.slice(eq + 1).trim())
        }
      }
    }
  }
  if (json === undefined && body.trim() && body.trim().length <= 2048) {
    push('body', '$body', body.trim())
  }
  return out
}

function readSlotValueFromResponse(
  slot: { source: 'json' | 'header' | 'body'; path: string },
  body: string,
  json: unknown,
  headers: Readonly<Record<string, string>>,
): string | null | undefined {
  if (slot.source === 'json') {
    if (!json || typeof json !== 'object') return undefined
    let cur: unknown = json
    for (const seg of slot.path.split('.')) {
      if (cur == null || typeof cur !== 'object') return undefined
      if (Array.isArray(cur)) {
        const idx = Number(seg)
        if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return undefined
        cur = cur[idx]
      } else {
        if (!(seg in (cur as Record<string, unknown>))) return undefined
        cur = (cur as Record<string, unknown>)[seg]
      }
    }
    if (cur === null || cur === undefined || cur === false) return null
    if (typeof cur === 'string') return cur
    if (typeof cur === 'number' || typeof cur === 'boolean') return String(cur)
    return undefined
  }
  if (slot.source === 'header') {
    const colon = slot.path.indexOf(':')
    const hName = colon >= 0 ? slot.path.slice(0, colon) : slot.path
    const subKey = colon >= 0 ? slot.path.slice(colon + 1) : null
    const raw = Object.entries(headers).find(([k]) => k.toLowerCase() === hName)?.[1]
    if (raw === undefined) return undefined
    if (!subKey) return raw
    if (subKey === 'token') {
      const m = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(raw.trim())
      return m?.[1]?.trim() ?? raw.trim()
    }
    for (const part of raw.split(';')) {
      const eq = part.indexOf('=')
      if (eq > 0 && part.slice(0, eq).trim().toLowerCase() === subKey) return part.slice(eq + 1).trim()
    }
    return undefined
  }
  return body.trim() || null
}

function isSanitizedTokenString(val: string | null | undefined): boolean {
  if (val === null || val === undefined) return true
  const t = val.trim().toLowerCase()
  return !t || t === '[redacted]' || t === 'redacted' || t === '***' || hasVaultScrubbedToken(val)
}

function findReplaySpecStepBody(
  spec: DeclarativeReplaySpec | undefined,
  method: string,
  pathAndQuery: string,
): string | undefined {
  if (!spec) return undefined
  const m = method.toUpperCase()
  const normPath = pathAndQuery.split('?')[0] ?? pathAndQuery
  if ('steps' in spec && Array.isArray(spec.steps)) {
    for (const st of spec.steps) {
      if (!('request' in st) || !st.request) continue
      const req = st.request
      if (req.method.toUpperCase() !== m) continue
      const stPath = req.pathAndQuery.split('?')[0] ?? req.pathAndQuery
      if (req.pathAndQuery === pathAndQuery || stPath === normPath) {
        if (typeof req.textBody === 'string') return req.textBody
        if (req.jsonBody !== undefined) return JSON.stringify(req.jsonBody)
      }
    }
  }
  if (spec.recipe?.args && typeof spec.recipe.args === 'object') {
    const args = spec.recipe.args as Record<string, unknown>
    const argPath = typeof args.pathAndQuery === 'string' ? args.pathAndQuery.split('?')[0] : ''
    if (argPath && argPath === normPath && args.body !== undefined) {
      return typeof args.body === 'string' ? args.body : JSON.stringify(args.body)
    }
  }
  return undefined
}

function replaceAllToken(text: string, from: string, to: string, urlEncode = false): { value: string; changed: boolean } {
  if (!from || from === to) return { value: text, changed: false }
  let out = text
  let changed = false
  if (out.includes(from)) {
    out = out.split(from).join(to)
    changed = true
  }
  if (urlEncode) {
    const encFrom = encodeURIComponent(from)
    const encTo = encodeURIComponent(to)
    if (encFrom !== from && out.includes(encFrom)) {
      out = out.split(encFrom).join(encTo)
      changed = true
    }
  }
  return { value: out, changed }
}

function buildActorDescriptor(grant: Grant, personaHandle: string | null): ImpactStep['actor'] {
  if (personaHandle) {
    const persona = grant.personas?.get(personaHandle)
    if (persona) {
      const identity = resolvePersonaIdentity({
        roleLabel: persona.roleLabel,
        tenantRef: persona.tenantRef ?? null,
        privilege: persona.privilege ?? null,
        handle: persona.handle,
      })
      return {
        handle: persona.handle,
        role: identity.privilege,
        tenant: identity.tenant,
        ...(identity.tenants.length > 1 ? { tenants: identity.tenants } : {}),
        auth: persona.authKind === 'cookie' ? 'cookie' : persona.authKind === 'bearer' ? 'bearer' : 'header',
        sameSite: null,
      }
    }
    return { handle: personaHandle, role: null, tenant: null, auth: 'bearer', sameSite: null }
  }
  return { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }
}

function detectHttpPreconditionDrift(params: {
  status: number
  body: string
  isTerminalHop: boolean
  hopIndex: number
  originalStatus?: number | null
}): string | null {
  const { status, body, isTerminalHop, hopIndex, originalStatus } = params
  const lower = body.toLowerCase()
  if (status === 405) return 'HTTP 405 Method Not Allowed (target route/method drifted)'
  if (status === 410) return 'HTTP 410 Gone (target endpoint/resource removed)'
  if (status === 404) {
    const routeMarker = ROUTE_DRIFT_MARKERS.find(m => lower.includes(m))
    if (routeMarker) return `HTTP 404 route/schema drift (${routeMarker.trim()})`
    const hasAuthDenial = AUTH_DENIAL_MARKERS.some(m => lower.includes(m))
    if (!isTerminalHop && !hasAuthDenial && (hopIndex === 0 || (originalStatus != null && is2xx(originalStatus)))) {
      return 'HTTP 404 on upstream benign setup hop (fixture or route missing; environment drifted)'
    }
  }
  if ((status === 400 || status === 422) && !isTerminalHop) {
    const schemaMarker = SCHEMA_DRIFT_400_MARKERS.find(m => lower.includes(m))
    if (schemaMarker) return `HTTP ${status} schema drift on upstream hop (${schemaMarker})`
  }
  return null
}

function isCapabilityValueSanitized(json: unknown, body: string, capHandle: string): boolean {
  const slotRaw = capHandle.split(':').pop()?.trim().toLowerCase() ?? ''
  const slotNorm = slotRaw.replace(/[^a-z0-9]/g, '')
  if (json && typeof json === 'object' && !Array.isArray(json)) {
    const entries = Object.entries(json as Record<string, unknown>)
    if (entries.length === 0) return true
    if (slotNorm.length >= 3) {
      for (const [k, v] of entries) {
        const kn = k.toLowerCase().replace(/[^a-z0-9]/g, '')
        if (kn === slotNorm || kn.endsWith(slotNorm) || slotNorm.endsWith(kn)) {
          if (v === null || v === undefined || v === false) return true
          if (typeof v === 'string') {
            const tv = v.trim().toLowerCase()
            if (!tv || tv === '[redacted]' || tv === 'redacted' || tv === '***') return true
          }
        }
      }
    }
    const vals = entries.map(([, v]) => (typeof v === 'string' ? v.trim().toLowerCase() : v))
    if (vals.some(v => v === '[redacted]')) return true
  } else if (body.trim() === '' || body.trim().toLowerCase() === '[redacted]') {
    return true
  }
  return false
}

interface OriginalValueSlot {
  edgeKey: string
  capabilityHandle?: string
  originalValue: string
  originalDigest: string
  slotSource: 'json' | 'header' | 'body'
  slotPath: string
  appearsInConsumer: boolean
}

interface LiveReboundValue {
  edgeKey: string
  capabilityHandle?: string
  originalValue: string | null
  originalDigest: string | null
  freshValue: string
  freshDigest: string
  slotPath: string
  appearsInConsumer: boolean
}

function inferEmittedCapabilitiesForHop(
  hop: HopReceipt,
  outgoingEdges: readonly CausalEdgeBinding[],
  status: number,
  body: string,
  json: unknown,
  respHeaders: Record<string, string>,
  origSlotsByEdge: ReadonlyMap<string, OriginalValueSlot>,
): {
  emitted: string[]
  reboundByEdge: Map<string, LiveReboundValue>
  observedDigests: string[]
  unresolvedFreshValueReason: string | null
} {
  const reboundByEdge = new Map<string, LiveReboundValue>()
  const observedDigests: string[] = []
  if (!is2xx(status)) return { emitted: [], reboundByEdge, observedDigests, unresolvedFreshValueReason: null }

  const declared = new Set<string>(hop.producedCapabilities)
  const digestRequiredByCap = new Map<string, string>()
  const tokens = extractResponseSlotTokens(body, json, respHeaders)
  const leafDigests = new Set<string>(tokens.map(t => t.digest))
  if (body.trim()) leafDigests.add(sha256Hex(body.trim()))

  const reboundCapOk = new Set<string>()
  const sanitizedCap = new Set<string>()
  let unresolvedFreshValueReason: string | null = null

  for (const edge of outgoingEdges) {
    if (edge.kind === 'value_binding') {
      const edgeKey = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
      if (edge.capabilityHandle) {
        declared.add(edge.capabilityHandle)
        if (edge.valueDigest) digestRequiredByCap.set(edge.capabilityHandle, edge.valueDigest.toLowerCase())
      }
      const origSlot = origSlotsByEdge.get(edgeKey)
      let matchedToken: { value: string; digest: string; path: string } | null = null
      let explicitlySanitized = false

      if (origSlot) {
        const freshRaw = readSlotValueFromResponse({ source: origSlot.slotSource, path: origSlot.slotPath }, body, json, respHeaders)
        if (freshRaw === null || (typeof freshRaw === 'string' && isSanitizedTokenString(freshRaw))) {
          explicitlySanitized = true
        } else if (typeof freshRaw === 'string') {
          matchedToken = { value: freshRaw.trim(), digest: sha256Hex(freshRaw.trim()), path: origSlot.slotPath }
        } else if (edge.valueDigest && leafDigests.has(edge.valueDigest.toLowerCase())) {
          const hit = tokens.find(t => t.digest === edge.valueDigest!.toLowerCase())
          if (hit) matchedToken = { value: hit.value, digest: hit.digest, path: hit.path }
        } else {
          // Field completely omitted from JSON/headers after patch!
          explicitlySanitized = true
        }
      } else {
        // No original exchange stored for producer; match by exact digest or capability slot name.
        if (edge.valueDigest && leafDigests.has(edge.valueDigest.toLowerCase())) {
          const hit = tokens.find(t => t.digest === edge.valueDigest!.toLowerCase())
          if (hit && !isSanitizedTokenString(hit.value)) matchedToken = { value: hit.value, digest: hit.digest, path: hit.path }
        }
        if (!matchedToken && edge.capabilityHandle) {
          const capSlot = normalizeSlotName(edge.capabilityHandle.split(':').pop() ?? '')
          if (capSlot.length >= 3) {
            const slotHit = tokens.find(t => t.keyNorm === capSlot || t.keyNorm.endsWith(capSlot) || capSlot.endsWith(t.keyNorm))
            if (slotHit) {
              if (isSanitizedTokenString(slotHit.value)) explicitlySanitized = true
              else matchedToken = { value: slotHit.value, digest: slotHit.digest, path: slotHit.path }
            }
          }
        }
        if (!matchedToken && !explicitlySanitized && edge.valueDigest) {
          if (edge.capabilityHandle && isCapabilityValueSanitized(json, body, edge.capabilityHandle)) {
            explicitlySanitized = true
          } else if (tokens.length > 0) {
            // Producer returned 2xx with non-sanitized data whose digest changed (likely a fresh nonce),
            // but we have no original producer exchange to map the slot — fail closed as inconclusive!
            unresolvedFreshValueReason = `Hop "${hop.hopId}" returned HTTP ${status} with fresh output that does not match stored valueDigest and cannot be structurally re-bound without host factLog/original producer capture.`
          }
        }
      }

      if (matchedToken) {
        observedDigests.push(matchedToken.digest)
        reboundByEdge.set(edgeKey, {
          edgeKey,
          capabilityHandle: edge.capabilityHandle,
          originalValue: origSlot?.originalValue ?? null,
          originalDigest: origSlot?.originalDigest ?? (edge.valueDigest?.toLowerCase() ?? null),
          freshValue: matchedToken.value,
          freshDigest: matchedToken.digest,
          slotPath: matchedToken.path,
          appearsInConsumer: origSlot?.appearsInConsumer ?? Boolean(edge.valueDigest),
        })
        if (edge.capabilityHandle) reboundCapOk.add(edge.capabilityHandle)
      } else if (explicitlySanitized && edge.capabilityHandle) {
        sanitizedCap.add(edge.capabilityHandle)
      }
    } else if (edge.kind === 'derived_crypto_binding') {
      declared.add(edge.sourceCapabilityId)
    }
  }

  if (declared.size === 0) return { emitted: [], reboundByEdge, observedDigests, unresolvedFreshValueReason }
  const emitted: string[] = []
  for (const cap of declared) {
    if (sanitizedCap.has(cap)) continue
    if (reboundCapOk.has(cap)) {
      emitted.push(cap)
      continue
    }
    const requiredDigest = digestRequiredByCap.get(cap)
    if (requiredDigest && !leafDigests.has(requiredDigest)) continue
    if (isCapabilityValueSanitized(json, body, cap)) continue
    emitted.push(cap)
  }
  return { emitted, reboundByEdge, observedDigests, unresolvedFreshValueReason }
}

function resolvePersistedCompositeProofForGate6(
  lr: PatchLabRetestContext,
  finding: Pick<Finding, 'id' | 'replaySpecId'>,
): { receipt: CompositeProofReceipt; replaySpecId?: string; hopActors?: Record<string, string | null> } | null {
  if (lr.compositeReceipt) {
    const parsed = compositeProofReceiptSchema.safeParse(lr.compositeReceipt)
    if (parsed.success) {
      return {
        receipt: parsed.data,
        replaySpecId: lr.replaySpecId ?? finding.replaySpecId ?? undefined,
        ...(lr.hopActors ? { hopActors: { ...lr.hopActors } } : {}),
      }
    }
  }
  if (!lr.storage) return null
  const tryRow = (specRow: { id: string; proofReceipt: unknown } | null | undefined) => {
    const rawProof = specRow?.proofReceipt
    if (!rawProof || typeof rawProof !== 'object') return null
    const obj = rawProof as Record<string, unknown>
    const candidate = obj.compositeReceipt ?? (Array.isArray(obj.hops) && typeof obj.chainId === 'string' ? obj : undefined)
    if (!candidate) return null
    const parsed = compositeProofReceiptSchema.safeParse(candidate)
    if (!parsed.success) return null
    const storedHopActors = obj.hopActors && typeof obj.hopActors === 'object'
      ? obj.hopActors as Record<string, string | null>
      : undefined
    return {
      receipt: parsed.data,
      replaySpecId: specRow.id,
      ...(lr.hopActors ? { hopActors: { ...lr.hopActors } } : storedHopActors ? { hopActors: storedHopActors } : {}),
    }
  }
  const claimedSpecId = lr.replaySpecId ?? finding.replaySpecId ?? undefined
  if (claimedSpecId) {
    try {
      const hit = tryRow(lr.storage.getReplaySpec(lr.runId, claimedSpecId))
      if (hit) return hit
    } catch { /* fall through to finding lookup */ }
  }
  try {
    for (const row of lr.storage.listReplaySpecsForFinding(lr.runId, finding.id)) {
      const hit = tryRow(row)
      if (hit) return hit
    }
  } catch { /* no persisted composite proof */ }
  return null
}

function createBrokerCompositePatchReplayRunner(
  ctx: BrokerCompositeReplayContext,
  signingKey: string,
  nowFn: () => number,
): CompositePatchReplayRunner {
  let lastTs = Math.max(0, nowFn() - 100)
  const nextTs = () => {
    lastTs = Math.max(lastTs + 10, nowFn())
    return lastTs
  }
  const grantOpts = buildCompositeVerifyOptionsFromGrant(ctx.grant)
  const defaultAttackerPersona = grantOpts?.attackerPersonas?.[0] ?? null
  const cachedOrigExchanges = new Map<string, (BrokerExchange & { body: string }) | null>()
  const lookupOriginalExchange = (exId: string): (BrokerExchange & { body: string }) | null => {
    if (cachedOrigExchanges.has(exId)) return cachedOrigExchanges.get(exId) ?? null
    if (!ctx.storage || !ctx.runId) {
      cachedOrigExchanges.set(exId, null)
      return null
    }
    try {
      const row = ctx.storage.getExchange(ctx.runId, exId)
      cachedOrigExchanges.set(exId, row)
      return row
    } catch {
      cachedOrigExchanges.set(exId, null)
      return null
    }
  }
  const lookupFact = (exId: string): HostExchangeFact | null => ctx.factLog?.getExchange(exId) ?? null

  const liveRebindingsByEdge = new Map<string, LiveReboundValue>()
  const origSlotsByEdge = new Map<string, OriginalValueSlot>()
  const cryptoMaterialChangedEdges = new Set<string>()
  const origDerivedTokensByEdge = new Map<string, { slotSource: 'json' | 'header' | 'body'; slotPath: string; originalValue: string }>()
  let analyzedReceiptChainId: string | null = null

  const ensureOriginalEdgeAnalysis = (receipt: CompositeProofReceipt) => {
    if (analyzedReceiptChainId === receipt.chainId) return
    analyzedReceiptChainId = receipt.chainId
    const hopsById = new Map(receipt.hops.map(h => [h.hopId, h]))
    for (const edge of receipt.causalEdges) {
      const edgeKey = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
      const fromHop = hopsById.get(edge.fromHopId)
      const toHop = hopsById.get(edge.toHopId)
      const srcExId = (edge.kind === 'value_binding' ? edge.sourceExchangeId : undefined) ?? fromHop?.exchangeIds[0]
      const tgtExId = (edge.kind === 'value_binding' ? edge.targetExchangeId : undefined) ?? toHop?.exchangeIds[0]
      const srcFact = srcExId ? lookupFact(srcExId) : null
      const srcRow = srcExId ? lookupOriginalExchange(srcExId) : null
      const tgtFact = tgtExId ? lookupFact(tgtExId) : null
      const tgtRow = tgtExId ? lookupOriginalExchange(tgtExId) : null
      const srcBody = srcFact?.rawResponseBody ?? srcRow?.body ?? ''
      const srcHeaders = srcFact?.responseHeaders ?? srcRow?.respHeaders ?? {}
      const srcJson = tryParseJsonBody(srcBody)
      const srcTokens = extractResponseSlotTokens(srcBody, srcJson, srcHeaders)
      if (srcTokens.length === 0) continue

      const tgtTextParts: string[] = []
      if (tgtFact?.pathAndQuery) tgtTextParts.push(tgtFact.pathAndQuery)
      else if (tgtRow?.pathAndQuery) tgtTextParts.push(tgtRow.pathAndQuery)
      if (tgtFact?.rawRequestBody) tgtTextParts.push(tgtFact.rawRequestBody)
      for (const hv of Object.values(tgtFact?.requestHeaders ?? tgtRow?.reqHeaders ?? {})) tgtTextParts.push(hv)
      const tgtText = tgtTextParts.join('\n')

      const tokenInConsumer = (val: string): boolean => {
        if (val.length < 4 || !tgtText) return false
        if (tgtText.includes(val)) return true
        const enc = encodeURIComponent(val)
        return enc !== val && tgtText.includes(enc)
      }

      if (edge.kind === 'value_binding') {
        let picked: ExtractedSlotToken | undefined
        if (edge.valueDigest) {
          picked = srcTokens.find(t => t.digest === edge.valueDigest!.toLowerCase())
        }
        if (!picked) {
          picked = srcTokens.find(t => t.value.length >= 6 && tokenInConsumer(t.value))
        }
        if (!picked && edge.capabilityHandle) {
          const capSlot = normalizeSlotName(edge.capabilityHandle.split(':').pop() ?? '')
          if (capSlot.length >= 3) {
            picked = srcTokens.find(t => t.keyNorm === capSlot || t.keyNorm.endsWith(capSlot) || capSlot.endsWith(t.keyNorm))
          }
        }
        if (picked) {
          origSlotsByEdge.set(edgeKey, {
            edgeKey,
            capabilityHandle: edge.capabilityHandle,
            originalValue: picked.value,
            originalDigest: picked.digest,
            slotSource: picked.source,
            slotPath: picked.path,
            appearsInConsumer: tokenInConsumer(picked.value),
          })
        }
      } else if (edge.kind === 'derived_crypto_binding') {
        const capSlot = normalizeSlotName(edge.sourceCapabilityId.split(':').pop() ?? '')
        const picked = capSlot.length >= 3
          ? srcTokens.find(t => t.keyNorm === capSlot || t.keyNorm.endsWith(capSlot) || capSlot.endsWith(t.keyNorm))
          : undefined
        if (picked) {
          origDerivedTokensByEdge.set(edgeKey, { slotSource: picked.source, slotPath: picked.path, originalValue: picked.value })
        }
      }
    }
  }

  let runScopeRev = 1
  if (ctx.storage && ctx.runId) {
    try { runScopeRev = ctx.storage.run(ctx.runId).scopeRevision } catch { /* default */ }
  }

  const recordReplayedExchange = (res: BrokerExchangeResult, fallbackPrefix: string): string => {
    const customId = ctx.onExchange?.(res)
    if (typeof customId === 'string' && customId.trim()) return customId
    if (ctx.storage && ctx.runId && ctx.assignmentId) {
      try {
        const saved = ctx.storage.recordExchange({
          runId: ctx.runId,
          assignmentId: ctx.assignmentId,
          scopeRevision: runScopeRev,
          origin: res.origin,
          finalOrigin: res.finalOrigin,
          redirectOrigins: res.redirectOrigins,
          method: res.method,
          pathAndQuery: res.pathAndQuery,
          personaHandle: res.personaHandle ?? null,
          status: res.status,
          mediaType: res.mediaType,
          reqHeaders: res.reqHeaders,
          respHeaders: res.respHeaders,
          body: res.body,
          durationMs: res.durationMs,
        })
        return saved.id
      } catch { /* fall back to synthetic id */ }
    }
    return `retest-${fallbackPrefix}-${randomUUID().slice(0, 8)}`
  }

  const buildSignedEntry = (params: {
    exchangeId: string
    res: BrokerExchangeResult
    arm: ImpactStep['arm']
    personaHandle: string | null
    requestBody?: string
    evidenceRole?: ImpactStep['evidenceRole']
    replayAttempt?: HostTranscriptEntry['replayAttempt']
    entityId?: string
    correlationIds?: string[]
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    observedResponseDigests?: string[]
    injectedRequestDigests?: string[]
    cryptoAttestations?: HostTranscriptEntry['cryptoAttestations']
  }): HostTranscriptEntry => {
    const json = tryParseJsonBody(params.res.body)
    const reqJson = params.requestBody !== undefined ? tryParseJsonBody(params.requestBody) : undefined
    const persona = params.personaHandle ? ctx.grant.personas?.get(params.personaHandle) : undefined
    const step: ImpactStep = {
      id: params.exchangeId,
      arm: params.arm,
      method: params.res.method,
      status: params.res.status,
      actor: buildActorDescriptor(ctx.grant, params.personaHandle),
      pathAndQuery: params.res.pathAndQuery,
      route: params.res.pathAndQuery.split('?')[0] || '/',
      ...(json !== undefined ? { json } : {}),
      ...(params.res.body ? { body: params.res.body } : {}),
      ...(reqJson !== undefined ? { requestJson: reqJson } : {}),
      ...(params.requestBody !== undefined ? { requestBody: params.requestBody } : {}),
      ...(Object.keys(params.res.reqHeaders).length ? { requestHeaders: params.res.reqHeaders } : {}),
      ...(Object.keys(params.res.respHeaders).length ? { responseHeaders: params.res.respHeaders } : {}),
      ...(params.evidenceRole ? { evidenceRole: params.evidenceRole } : {}),
    }
    const base: HostTranscriptEntry = {
      exchangeId: params.exchangeId,
      origin: params.res.origin,
      step,
      timestampMs: nextTs(),
      actorPersona: params.personaHandle,
      ...(persona?.roleLabel ? { actorRoleLabel: persona.roleLabel } : {}),
      cleanSession: true,
      replayAttempt: params.replayAttempt ?? 'mode_a',
      ...(params.entityId ? { entityId: params.entityId } : {}),
      ...(params.correlationIds?.length ? { correlationIds: params.correlationIds } : {}),
      ...(params.emittedCapabilities?.length ? { emittedCapabilities: params.emittedCapabilities } : {}),
      ...(params.consumedCapabilities?.length ? { consumedCapabilities: params.consumedCapabilities } : {}),
      ...(params.observedResponseDigests?.length ? { observedResponseDigests: [...new Set(params.observedResponseDigests)] } : {}),
      ...(params.injectedRequestDigests?.length ? { injectedRequestDigests: [...new Set(params.injectedRequestDigests)] } : {}),
      ...(params.cryptoAttestations?.length ? { cryptoAttestations: params.cryptoAttestations } : {}),
    }
    return { ...base, hostSignature: signHostRecord(base, signingKey) }
  }

  return {
    async preparePreconditions({ receipt, signal }) {
      ensureOriginalEdgeAnalysis(receipt)
      const missingPersonas = new Set<string>()
      const checkPersona = (handle: string | null | undefined) => {
        if (!handle || !handle.trim()) return
        const norm = handle.trim()
        if (/^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i.test(norm)) return
        if (!ctx.grant.personas?.has(norm)) missingPersonas.add(norm)
      }
      for (const hop of receipt.hops) {
        checkPersona(ctx.hopActors?.[hop.hopId])
        for (const exId of hop.exchangeIds) {
          const fact = lookupFact(exId)
          if (fact?.actor) checkPersona(fact.actor)
          const orig = lookupOriginalExchange(exId)
          if (orig?.personaHandle) checkPersona(orig.personaHandle)
        }
      }
      if (missingPersonas.size > 0) {
        return {
          status: 'auth_setup_failed',
          errorCode: 'AUTH_SETUP_FAILED',
          reason: `Required composite retest persona(s) missing from grant: ${[...missingPersonas].join(', ')}`,
        }
      }

      const entries: HostTranscriptEntry[] = []
      const preCtrlIds: string[] = []
      for (const ctrlId of receipt.terminalImpact.preChainControlExchangeIds) {
        const fact = lookupFact(ctrlId)
        const orig = lookupOriginalExchange(ctrlId)
        if (!fact && !orig) continue
        const origin = fact?.origin ?? orig!.origin
        const method = normalizeReplayHttpMethod(fact?.method ?? orig!.method)
        const pathAndQuery = fact?.pathAndQuery ?? orig!.pathAndQuery
        const persona = fact?.actor ?? orig?.personaHandle ?? defaultAttackerPersona
        const { headers, redactedHeaders } = rebuildStoredReplayHeaders({
          rawHeaders: fact?.requestHeaders ?? orig?.reqHeaders,
          personaHandle: persona,
          grant: ctx.grant,
        })
        if (redactedHeaders.length > 0 || hasVaultScrubbedToken(pathAndQuery)) {
          return {
            status: 'inconclusive',
            errorCode: 'REDACTED_CONTROL_UNAVAILABLE',
            reason: `Pre-chain control exchange "${ctrlId}" contains redacted request material unavailable in host factLog.`,
          }
        }
        const body = fact?.rawRequestBody ?? findReplaySpecStepBody(ctx.replaySpec, method, pathAndQuery)
        const req: BrokerHttpRequest = {
          origin,
          method,
          pathAndQuery,
          ...(persona ? { persona } : {}),
          ...(headers ? { headers } : {}),
          ...(body !== undefined && body !== null ? { body } : {}),
          followRedirects: false,
          sessionGroupRole: 'control',
          ...(ctx.runId ? { runId: ctx.runId } : {}),
          ...(ctx.assignmentId ? { assignmentId: ctx.assignmentId } : {}),
        }
        let res: BrokerExchangeResult
        try {
          res = await ctx.broker.executeHttp(req, ctx.grant, signal ?? AbortSignal.timeout(30_000))
        } catch (err) {
          return {
            status: 'transport_error',
            errorCode: errCodeOf(err) ?? 'TRANSPORT_ERROR',
            reason: `Pre-chain control replay failed: ${err instanceof Error ? err.message : String(err)}`,
          }
        }
        if (isTransportOr5xx(res.status)) {
          return {
            status: 'transport_error',
            httpStatus: res.status,
            errorCode: res.status > 0 ? `HTTP_${res.status}` : 'TRANSPORT_ERROR',
            reason: `Pre-chain control returned HTTP ${res.status}`,
          }
        }
        if (res.status === 401 && persona) {
          return {
            status: 'auth_setup_failed',
            httpStatus: res.status,
            errorCode: 'SESSION_DRIFTED',
            reason: `Authenticated pre-chain control returned HTTP 401 (session drifted for persona "${persona}").`,
          }
        }
        const origStatus = fact?.status ?? orig?.status ?? null
        if (origStatus !== null && (origStatus === 401 || origStatus === 403 || origStatus === 404) && is2xx(res.status)) {
          return {
            status: 'precondition_changed',
            httpStatus: res.status,
            errorCode: 'CONTROL_STATE_DRIFT',
            reason: `Pre-chain denied control ${method} ${pathAndQuery} returned HTTP ${res.status} instead of expected denial (HTTP ${origStatus}); target state drifted.`,
          }
        }
        if (is2xx(origStatus)) {
          const drift = detectHttpPreconditionDrift({ status: res.status, body: res.body, isTerminalHop: false, hopIndex: 0, originalStatus: origStatus })
          if (drift) {
            return {
              status: 'precondition_changed',
              httpStatus: res.status,
              errorCode: 'PRECONDITION_CHANGED',
              reason: `Pre-chain control ${method} ${pathAndQuery}: ${drift}`,
            }
          }
        }
        const newId = recordReplayedExchange(res, 'prectrl')
        preCtrlIds.push(newId)
        entries.push(buildSignedEntry({ exchangeId: newId, res, arm: 'control', personaHandle: persona, ...(body ? { requestBody: body } : {}), replayAttempt: 'mode_a' }))
      }
      return {
        status: 'ok',
        ...(entries.length ? { entries } : {}),
        ...(preCtrlIds.length ? { preChainControlExchangeIds: preCtrlIds } : {}),
      }
    },

    async replayHop(hopCtx) {
      ensureOriginalEdgeAnalysis(hopCtx.receipt)
      const { receipt, hop, hopIndex, incomingEdges, outgoingEdges, availableCapabilities, signal } = hopCtx
      const isTerminalHop = hop.hopId === receipt.terminalImpact.terminalHopId
      const entries: HostTranscriptEntry[] = []
      const oobEvents: HostOobEvent[] = []
      const browserTraces: HostBrowserTrace[] = []
      const replayedExchangeIds: string[] = []
      const replayedOobEventIds: string[] = []
      const replayedBrowserTraceIds: string[] = []
      const asyncPollRecords: HostAsyncPollRecord[] = []
      const ablationByEdge: Record<string, string[]> = {}
      const pollByEdge: Record<string, string> = {}
      const reboundValueDigests: Record<string, string> = {}

      const needsBrowser = hop.surface === 'browser'
        || hop.browserTraceIds.length > 0
        || incomingEdges.some(e => e.kind === 'async_pivot_binding' && e.channel === 'browser_trace')
        || outgoingEdges.some(e => e.kind === 'async_pivot_binding' && e.channel === 'browser_trace')
      const needsOob = hop.oobEventIds.length > 0
        || incomingEdges.some(e => e.kind === 'async_pivot_binding' && e.channel === 'oob_relay')
        || outgoingEdges.some(e => e.kind === 'async_pivot_binding' && e.channel === 'oob_relay')

      if (hop.surface === 'ws' || hop.surface === 'sse') {
        return {
          outcome: 'inconclusive',
          errorCode: 'UNREPLAYABLE_SURFACE',
          reason: `Hop "${hop.hopId}" uses surface "${hop.surface}" which cannot be faithfully replayed via HTTP broker; failing closed.`,
        }
      }
      if (needsBrowser && !ctx.browser) {
        return {
          outcome: 'inconclusive',
          errorCode: 'UNREPLAYABLE_BROWSER_HOP',
          reason: `Hop "${hop.hopId}" requires ScopedBrowser execution, which is unavailable; failing closed as inconclusive.`,
        }
      }
      if (needsOob && !ctx.canaryBroker) {
        return {
          outcome: 'inconclusive',
          errorCode: 'UNREPLAYABLE_OOB_HOP',
          reason: `Hop "${hop.hopId}" requires CanaryBroker OOB execution, which is unavailable; failing closed as inconclusive.`,
        }
      }

      // 1) Replay stored state_transition_binding ablation controls when available.
      for (const edge of incomingEdges) {
        if (edge.kind !== 'state_transition_binding') continue
        const edgeKey = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
        const replayedAblations: string[] = []
        for (const abId of edge.ablationExchangeIds) {
          const abFact = lookupFact(abId)
          const orig = lookupOriginalExchange(abId)
          if (!abFact && !orig) continue
          const persona = abFact?.actor ?? orig?.personaHandle ?? defaultAttackerPersona
          const abMethod = normalizeReplayHttpMethod(abFact?.method ?? orig!.method)
          const abPath = abFact?.pathAndQuery ?? orig!.pathAndQuery
          const { headers: abHeaders, redactedHeaders } = rebuildStoredReplayHeaders({
            rawHeaders: abFact?.requestHeaders ?? orig?.reqHeaders,
            personaHandle: persona,
            grant: ctx.grant,
          })
          if (redactedHeaders.length > 0 || hasVaultScrubbedToken(abPath)) {
            return { outcome: 'inconclusive', errorCode: 'REDACTED_ABLATION_UNAVAILABLE', reason: `Ablation control "${abId}" for "${hop.hopId}" contains redacted request material unavailable in host factLog.` }
          }
          const abBody = abFact?.rawRequestBody ?? findReplaySpecStepBody(ctx.replaySpec, abMethod, abPath)
          try {
            const abRes = await ctx.broker.executeHttp({
              origin: abFact?.origin ?? orig!.origin,
              method: abMethod,
              pathAndQuery: abPath,
              ...(persona ? { persona } : {}),
              ...(abHeaders ? { headers: abHeaders } : {}),
              ...(abBody !== undefined && abBody !== null ? { body: abBody } : {}),
              followRedirects: false,
              sessionGroupRole: 'control',
              ...(ctx.runId ? { runId: ctx.runId } : {}),
              ...(ctx.assignmentId ? { assignmentId: ctx.assignmentId } : {}),
            }, ctx.grant, signal ?? AbortSignal.timeout(30_000))
            if (isTransportOr5xx(abRes.status)) {
              return { outcome: 'transport_error', httpStatus: abRes.status, errorCode: `HTTP_${abRes.status}`, reason: `Ablation control for "${hop.hopId}" returned HTTP ${abRes.status}.` }
            }
            if (abRes.status === 401 && persona) {
              return { outcome: 'auth_setup_failed', httpStatus: abRes.status, errorCode: 'SESSION_DRIFTED', reason: `Authenticated ablation control for "${hop.hopId}" returned HTTP 401 (session drifted).` }
            }
            const newAbId = recordReplayedExchange(abRes, `${hop.hopId}-ab`)
            replayedAblations.push(newAbId)
            entries.push(buildSignedEntry({
              exchangeId: newAbId,
              res: abRes,
              arm: 'control',
              personaHandle: persona,
              ...(abBody ? { requestBody: abBody } : {}),
              replayAttempt: 'ablation_control',
              entityId: edge.entityId,
            }))
          } catch (err) {
            return { outcome: 'transport_error', errorCode: errCodeOf(err) ?? 'TRANSPORT_ERROR', reason: `Ablation control replay failed: ${err instanceof Error ? err.message : String(err)}` }
          }
        }
        if (replayedAblations.length > 0) ablationByEdge[edgeKey] = replayedAblations
      }

      // 2) Route pure-browser hops directly through ScopedBrowser when available.
      const override = ctx.hopRequestOverrides?.[hop.hopId]
      const edgeCorrIds = [...new Set([
        ...incomingEdges.filter(e => e.kind === 'async_pivot_binding').map(e => e.correlationId),
        ...outgoingEdges.filter(e => e.kind === 'async_pivot_binding').map(e => e.correlationId),
      ])]

      if (needsBrowser && ctx.browser && hop.exchangeIds.length === 0) {
        const persona = override?.persona ?? ctx.hopActors?.[hop.hopId] ?? defaultAttackerPersona
        let visitPath = override?.pathAndQuery ?? hop.target.pathAndQuery ?? '/'
        for (const edge of incomingEdges) {
          if (edge.kind !== 'value_binding') continue
          const binding = liveRebindingsByEdge.get(`${edge.fromHopId}->${edge.toHopId}:${edge.kind}`)
          if (binding?.originalValue && binding.freshValue !== binding.originalValue) {
            visitPath = replaceAllToken(visitPath, binding.originalValue, binding.freshValue, true).value
          }
        }
        if (hasVaultScrubbedToken(visitPath)) {
          return { outcome: 'inconclusive', errorCode: 'REDACTED_BROWSER_URL', reason: `Browser hop "${hop.hopId}" target path contains redacted tokens.` }
        }
        try {
          const visit = await ctx.browser.visitPage({
            origin: override?.origin ?? hop.target.origin,
            pathAndQuery: visitPath,
            ...(persona ? { persona } : {}),
            ...(hop.canaryToken ? { canaryToken: hop.canaryToken } : {}),
            enableSinkHook: true,
          }, ctx.grant, signal ?? AbortSignal.timeout(30_000))
          const traceId = `retest-trace-${hop.hopId}-${randomUUID().slice(0, 8)}`
          const sinks = visit.attestedSinks?.length
            ? [...visit.attestedSinks]
            : visit.domSinkTraces.filter(s => s.containsCanary).map(s => s.sink)
          const traceBase: Omit<HostBrowserTrace, 'hostSignature'> = {
            id: traceId,
            origin: visit.origin,
            sinks,
            timestampMs: nextTs(),
            actorPersona: persona,
            ...(edgeCorrIds.length ? { correlationIds: edgeCorrIds } : {}),
          }
          browserTraces.push({ ...traceBase, hostSignature: signHostRecord(traceBase, signingKey) })
          replayedBrowserTraceIds.push(traceId)
          return {
            entries,
            browserTraces,
            replayedExchangeIds,
            replayedBrowserTraceIds,
            ...(visit.status !== null ? { httpStatus: visit.status } : {}),
          }
        } catch (err) {
          return { outcome: 'inconclusive', errorCode: errCodeOf(err) ?? 'BROWSER_REPLAY_ERROR', reason: `ScopedBrowser replay failed for hop "${hop.hopId}": ${err instanceof Error ? err.message : String(err)}` }
        }
      }

      // 3) Build the hop's HTTP replay requests faithfully from host factLog / stored exchanges (and re-bind fresh tokens).
      interface FaithfulHopTarget {
        req: BrokerHttpRequest
        originalStatus: number | null
        arm: ImpactStep['arm']
        persona: string | null
        bodyUnsealed: boolean
        injectedDigests: string[]
      }
      const hopTargets: FaithfulHopTarget[] = []
      const preCtrlSet = new Set(receipt.terminalImpact.preChainControlExchangeIds)

      // Check if any incoming derived_crypto_binding had changing source material without a caller override.
      for (const edge of incomingEdges) {
        if (edge.kind === 'derived_crypto_binding') {
          const ek = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
          if (cryptoMaterialChangedEdges.has(ek) && !override) {
            return {
              outcome: 'inconclusive',
              errorCode: 'UNREBOUND_CRYPTO_EDGE',
              reason: `Hop "${hop.hopId}" depends on derived_crypto_binding from "${edge.fromHopId}" whose source material rotated; cannot re-derive signature faithfully without custom runner.`,
            }
          }
        }
      }

      const buildTargetFromSource = (params: {
        origExId: string | null
        fact: HostExchangeFact | null
        orig: (BrokerExchange & { body: string }) | null
        isCtrl: boolean
      }): { ok: true; target: FaithfulHopTarget } | { ok: false; errorCode: string; reason: string } => {
        const { origExId, fact, orig, isCtrl } = params
        const persona = override?.persona ?? fact?.actor ?? orig?.personaHandle ?? ctx.hopActors?.[hop.hopId] ?? defaultAttackerPersona
        const origin = override?.origin ?? fact?.origin ?? orig?.origin ?? hop.target.origin
        const method = override?.method ?? normalizeReplayHttpMethod(fact?.method ?? orig?.method ?? hop.target.method)
        let pathAndQuery = override?.pathAndQuery ?? fact?.pathAndQuery ?? orig?.pathAndQuery ?? hop.target.pathAndQuery ?? '/'
        const specBody = findReplaySpecStepBody(ctx.replaySpec, method, pathAndQuery)
        let body: string | undefined = override?.body !== undefined
          ? override.body
          : fact !== null
            ? (fact.rawRequestBody ?? undefined)
            : specBody
        const hasSealedBody = override?.body !== undefined || fact !== null || specBody !== undefined
        const origHeaders = fact?.requestHeaders ?? orig?.reqHeaders
        const origHasBodyHeader = Boolean(origHeaders && Object.entries(origHeaders).some(([k, v]) => {
          const lk = k.trim().toLowerCase()
          if (lk === 'content-type' && v.trim().length > 0) return true
          if (lk === 'content-length') {
            const n = Number(v.trim())
            return Number.isFinite(n) && n > 0
          }
          return false
        }))
        if (origHasBodyHeader && !hasSealedBody) {
          return {
            ok: false,
            errorCode: 'MISSING_REQUEST_BODY',
            reason: `Cannot rebuild hop "${hop.hopId}"${origExId ? ` (${origExId})` : ''} faithfully: original request carried a body (content-type/content-length) not available in host factLog or replay overrides.`,
          }
        }
        const bodyUnsealed = !hasSealedBody && (method === 'POST' || method === 'PUT' || method === 'PATCH')

        const rebuiltHdrs = rebuildStoredReplayHeaders({
          rawHeaders: origHeaders,
          personaHandle: persona,
          grant: ctx.grant,
          overrideHeaders: override?.headers,
        })
        let headers = rebuiltHdrs.headers ? { ...rebuiltHdrs.headers } : undefined
        const remainingRedacted = new Set(rebuiltHdrs.redactedHeaders)
        const injectedDigests: string[] = []

        // Dynamically re-bind incoming value_binding edges from replayed producer's fresh output.
        for (const edge of incomingEdges) {
          if (edge.kind !== 'value_binding') continue
          const ek = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
          const binding = liveRebindingsByEdge.get(ek)
          if (!binding) continue

          if (binding.originalValue && binding.freshValue !== binding.originalValue) {
            let substituted = false
            const pRes = replaceAllToken(pathAndQuery, binding.originalValue, binding.freshValue, true)
            if (pRes.changed) { pathAndQuery = pRes.value; substituted = true }
            if (body !== undefined) {
              const bRes = replaceAllToken(body, binding.originalValue, binding.freshValue, false)
              if (bRes.changed) { body = bRes.value; substituted = true }
            }
            if (headers) {
              for (const [hk, hv] of Object.entries(headers)) {
                const hRes = replaceAllToken(hv, binding.originalValue, binding.freshValue, false)
                if (hRes.changed) { headers[hk] = hRes.value; substituted = true }
              }
            }
            // If a redacted header matched this capability slot, restore it with the fresh value!
            if (remainingRedacted.size > 0) {
              const slotNorm = normalizeSlotName(binding.slotPath.split('.').pop() ?? binding.capabilityHandle?.split(':').pop() ?? '')
              for (const rk of [...remainingRedacted]) {
                const rNorm = normalizeSlotName(rk)
                if (slotNorm.length >= 3 && (rNorm === slotNorm || rNorm.endsWith(slotNorm) || slotNorm.endsWith(rNorm) || rNorm === 'authorization')) {
                  headers = headers ?? {}
                  headers[rk] = rNorm === 'authorization' && !/^bearer\s+/i.test(binding.freshValue)
                    ? `Bearer ${binding.freshValue}`
                    : binding.freshValue
                  remainingRedacted.delete(rk)
                  substituted = true
                }
              }
            }
            if (substituted) {
              injectedDigests.push(binding.freshDigest)
            } else if (!override && (binding.appearsInConsumer || Boolean(edge.valueDigest))) {
              return {
                ok: false,
                errorCode: 'UNREBOUND_DYNAMIC_TOKEN',
                reason: `Cannot faithfully re-bind fresh value from "${edge.fromHopId}" into consumer hop "${hop.hopId}": original token was not located in consumer request plane.`,
              }
            }
          } else if (!binding.originalValue && edge.valueDigest && binding.freshDigest !== edge.valueDigest.toLowerCase() && !override) {
            return {
              ok: false,
              errorCode: 'UNREBOUND_DYNAMIC_TOKEN',
              reason: `Producer "${edge.fromHopId}" minted a fresh value whose original token is unavailable for substitution into consumer hop "${hop.hopId}"; failing closed.`,
            }
          } else if (binding.freshValue) {
            const carried = pathAndQuery.includes(binding.freshValue)
              || (body !== undefined && body.includes(binding.freshValue))
              || Boolean(headers && Object.values(headers).some(v => v.includes(binding.freshValue)))
            if (carried) injectedDigests.push(binding.freshDigest)
          }
        }

        if (remainingRedacted.size > 0) {
          return {
            ok: false,
            errorCode: 'REDACTED_HEADER_UNAVAILABLE',
            reason: `Cannot rebuild hop "${hop.hopId}" faithfully: redacted request header(s) (${[...remainingRedacted].join(', ')}) unavailable in host factLog.`,
          }
        }
        if (hasVaultScrubbedToken(pathAndQuery) || hasVaultScrubbedToken(body)) {
          return {
            ok: false,
            errorCode: 'REDACTED_REQUEST_UNAVAILABLE',
            reason: `Cannot rebuild hop "${hop.hopId}" faithfully: stored request URL or body contains redacted placeholders unavailable in host factLog.`,
          }
        }

        return {
          ok: true,
          target: {
            req: {
              origin,
              method,
              pathAndQuery,
              ...(persona ? { persona } : {}),
              ...(headers ? { headers } : {}),
              ...(body !== undefined ? { body } : {}),
              followRedirects: false,
              sessionGroupRole: isCtrl ? 'control' : 'probe',
              ...(ctx.runId ? { runId: ctx.runId } : {}),
              ...(ctx.assignmentId ? { assignmentId: ctx.assignmentId } : {}),
            },
            originalStatus: fact?.status ?? orig?.status ?? null,
            arm: isCtrl ? 'control' : 'probe',
            persona,
            bodyUnsealed,
            injectedDigests,
          },
        }
      }

      for (const origExId of hop.exchangeIds) {
        const fact = lookupFact(origExId)
        const orig = lookupOriginalExchange(origExId)
        if (!fact && !orig) continue
        const built = buildTargetFromSource({ origExId, fact, orig, isCtrl: preCtrlSet.has(origExId) })
        if (!built.ok) return { outcome: 'inconclusive', errorCode: built.errorCode, reason: built.reason }
        hopTargets.push(built.target)
      }
      if (hopTargets.length === 0) {
        const built = buildTargetFromSource({ origExId: null, fact: null, orig: null, isCtrl: false })
        if (!built.ok) return { outcome: 'inconclusive', errorCode: built.errorCode, reason: built.reason }
        hopTargets.push(built.target)
      }

      // If this hop requires OOB callback verification, mint a fresh canary and verify it can be injected faithfully.
      let mintedOobCanary: { id: string; token: string; httpUrl: string; dnsHost: string } | null = null
      if (needsOob && ctx.canaryBroker) {
        if (!hop.canaryToken) {
          return {
            outcome: 'inconclusive',
            errorCode: 'UNREPLAYABLE_OOB_HOP',
            reason: `OOB hop "${hop.hopId}" lacks a recorded canaryToken for fresh canary substitution; failing closed as inconclusive.`,
          }
        }
        const minted = ctx.canaryBroker.mintCanary(
          ctx.runId ?? 'composite-retest',
          `gate6-retest:${hop.hopId}`,
          hop.target.origin,
          { storage: ctx.storage, assignmentId: ctx.assignmentId },
        )
        let injectedCanary = false
        for (const target of hopTargets) {
          const pRes = replaceAllToken(target.req.pathAndQuery, hop.canaryToken, minted.token, true)
          if (pRes.changed) { target.req.pathAndQuery = pRes.value; injectedCanary = true }
          if (target.req.body !== undefined) {
            const bRes = replaceAllToken(target.req.body, hop.canaryToken, minted.token, false)
            if (bRes.changed) { target.req.body = bRes.value; injectedCanary = true }
          }
          if (target.req.headers) {
            for (const [hk, hv] of Object.entries(target.req.headers)) {
              const hRes = replaceAllToken(hv, hop.canaryToken, minted.token, false)
              if (hRes.changed) { target.req.headers[hk] = hRes.value; injectedCanary = true }
            }
          }
        }
        if (!injectedCanary) {
          return {
            outcome: 'inconclusive',
            errorCode: 'UNREPLAYABLE_OOB_HOP',
            reason: `OOB hop "${hop.hopId}" original canaryToken could not be substituted into the replayed request; failing closed as inconclusive.`,
          }
        }
        mintedOobCanary = minted
      }

      const availSet = new Set(availableCapabilities)
      const hopConsumedCaps = [...new Set([
        ...hop.consumedCapabilities.filter(c => availSet.has(c)),
        ...incomingEdges.flatMap(e => e.kind === 'value_binding' && e.capabilityHandle && availSet.has(e.capabilityHandle)
          ? [e.capabilityHandle]
          : e.kind === 'derived_crypto_binding' && availSet.has(e.sourceCapabilityId)
            ? [e.sourceCapabilityId]
            : []),
      ])]

      let lastStatus: number | null = null
      let driftReason: string | null = null
      const hopEmittedAll = new Set<string>()

      for (const target of hopTargets) {
        let res: BrokerExchangeResult
        let rawResp: { body: string; headers: Record<string, string> } | null = null
        try {
          res = await ctx.broker.executeHttp({
            ...target.req,
            onRawResponse: raw => { rawResp = raw },
          }, ctx.grant, signal ?? AbortSignal.timeout(30_000))
        } catch (err) {
          return {
            outcome: 'transport_error',
            errorCode: errCodeOf(err) ?? 'TRANSPORT_ERROR',
            reason: `Hop "${hop.hopId}" replay transport failure: ${err instanceof Error ? err.message : String(err)}`,
            ...(entries.length ? { entries } : {}),
          }
        }
        lastStatus = res.status
        const newExId = recordReplayedExchange(res, hop.hopId)
        replayedExchangeIds.push(newExId)

        if (isTransportOr5xx(res.status)) {
          entries.push(buildSignedEntry({ exchangeId: newExId, res, arm: target.arm, personaHandle: target.persona, ...(target.req.body !== undefined ? { requestBody: target.req.body } : {}), entityId: hop.entityId }))
          return {
            outcome: 'transport_error',
            httpStatus: res.status,
            errorCode: res.status > 0 ? `HTTP_${res.status}` : 'TRANSPORT_ERROR',
            entries,
            replayedExchangeIds,
            reason: `Hop "${hop.hopId}" returned HTTP ${res.status} (transport/server failure; failing closed).`,
          }
        }

        // R2-04 / R4-H-9 alignment: authenticated 401 means session/credential drift, NEVER a verified fix.
        if (res.status === 401 && target.persona) {
          entries.push(buildSignedEntry({ exchangeId: newExId, res, arm: target.arm, personaHandle: target.persona, ...(target.req.body !== undefined ? { requestBody: target.req.body } : {}), entityId: hop.entityId }))
          return {
            outcome: 'auth_setup_failed',
            httpStatus: res.status,
            errorCode: 'SESSION_DRIFTED',
            entries,
            replayedExchangeIds,
            reason: `Authenticated hop "${hop.hopId}" returned HTTP 401 (session drifted for persona "${target.persona}"; failing closed).`,
          }
        }

        // R4-H-9: 400/415/422 on a body-bearing method replayed without sealed request body is a lossy replay, NEVER a fix!
        if (target.bodyUnsealed && (res.status === 400 || res.status === 415 || res.status === 422)) {
          entries.push(buildSignedEntry({ exchangeId: newExId, res, arm: target.arm, personaHandle: target.persona, entityId: hop.entityId }))
          return {
            outcome: 'inconclusive',
            httpStatus: res.status,
            errorCode: 'LOSSY_REPLAY_4XX',
            entries,
            replayedExchangeIds,
            reason: `Hop "${hop.hopId}" returned HTTP ${res.status} when replayed without a host-sealed request body; failing closed as inconclusive.`,
          }
        }

        // Inspect pre-redaction raw response strictly in-memory for capability & drift checks so broker
        // secret redaction of *token/*secret keys does not falsely look like a patched/sanitized server.
        const inspectBody = rawResp ? (rawResp as { body: string; headers: Record<string, string> }).body : res.body
        const inspectHeaders = rawResp ? (rawResp as { body: string; headers: Record<string, string> }).headers : res.respHeaders

        if (target.arm === 'probe') {
          const drift = detectHttpPreconditionDrift({
            status: res.status,
            body: inspectBody,
            isTerminalHop,
            hopIndex,
            originalStatus: target.originalStatus,
          })
          if (drift) driftReason = drift
        }

        const inspectJson = tryParseJsonBody(inspectBody)
        const inferred = target.arm === 'probe'
          ? inferEmittedCapabilitiesForHop(hop, outgoingEdges, res.status, inspectBody, inspectJson, inspectHeaders, origSlotsByEdge)
          : { emitted: [], reboundByEdge: new Map<string, LiveReboundValue>(), observedDigests: [], unresolvedFreshValueReason: null }
        if (inferred.unresolvedFreshValueReason) {
          entries.push(buildSignedEntry({ exchangeId: newExId, res, arm: target.arm, personaHandle: target.persona, ...(target.req.body !== undefined ? { requestBody: target.req.body } : {}), entityId: hop.entityId }))
          return {
            outcome: 'inconclusive',
            httpStatus: res.status,
            errorCode: 'UNREBOUND_PRODUCER_VALUE',
            entries,
            replayedExchangeIds,
            reason: inferred.unresolvedFreshValueReason,
          }
        }
        for (const [ek, rv] of inferred.reboundByEdge) {
          liveRebindingsByEdge.set(ek, rv)
          reboundValueDigests[ek] = rv.freshDigest
        }
        // Track derived_crypto_binding source rotation so downstream consumers fail closed rather than resending stale signatures.
        if (target.arm === 'probe' && is2xx(res.status)) {
          for (const oe of outgoingEdges) {
            if (oe.kind !== 'derived_crypto_binding') continue
            const ek = `${oe.fromHopId}->${oe.toHopId}:${oe.kind}`
            const origMat = origDerivedTokensByEdge.get(ek)
            if (origMat) {
              const freshMat = readSlotValueFromResponse({ source: origMat.slotSource, path: origMat.slotPath }, inspectBody, inspectJson, inspectHeaders)
              if (typeof freshMat === 'string' && freshMat.trim() && freshMat.trim() !== origMat.originalValue) {
                cryptoMaterialChangedEdges.add(ek)
              }
            }
          }
        }
        for (const c of inferred.emitted) hopEmittedAll.add(c)

        const matchedCorrIds = is2xx(res.status) && target.arm === 'probe'
          ? edgeCorrIds.filter(cid => inspectBody.includes(cid) || res.pathAndQuery.includes(cid) || Object.values(inspectHeaders).some(v => v.includes(cid)))
          : []

        const cryptoAttestations = is2xx(res.status) && target.arm === 'probe'
          ? incomingEdges
              .filter((e): e is Extract<CausalEdgeBinding, { kind: 'derived_crypto_binding' }> => e.kind === 'derived_crypto_binding' && availSet.has(e.sourceCapabilityId))
              .map(e => ({
                derivedFromCapabilityId: e.sourceCapabilityId,
                ...(e.derivedCapabilityId ? { derivedCapabilityId: e.derivedCapabilityId } : {}),
                alg: e.alg ?? 'hmac-sha256',
                artifactDigest: sha256Hex(res.body || res.pathAndQuery),
                timestampMs: nextTs(),
              }))
          : []

        entries.push(buildSignedEntry({
          exchangeId: newExId,
          res,
          arm: target.arm,
          personaHandle: target.persona,
          ...(target.req.body !== undefined ? { requestBody: target.req.body } : {}),
          entityId: hop.entityId,
          correlationIds: matchedCorrIds,
          emittedCapabilities: inferred.emitted,
          consumedCapabilities: target.arm === 'probe' ? hopConsumedCaps : [],
          observedResponseDigests: inferred.observedDigests,
          injectedRequestDigests: target.injectedDigests,
          cryptoAttestations,
        }))
      }

      if (driftReason) {
        return {
          outcome: 'precondition_changed',
          httpStatus: lastStatus,
          errorCode: 'PRECONDITION_CHANGED',
          entries,
          replayedExchangeIds,
          reason: `Hop "${hop.hopId}" precondition changed: ${driftReason}`,
        }
      }

      // If this hop also requires a browser trace alongside HTTP exchanges, visit via ScopedBrowser now.
      if (needsBrowser && ctx.browser && browserTraces.length === 0) {
        const persona = override?.persona ?? ctx.hopActors?.[hop.hopId] ?? defaultAttackerPersona
        try {
          const visit = await ctx.browser.visitPage({
            origin: override?.origin ?? hop.target.origin,
            pathAndQuery: override?.pathAndQuery ?? hop.target.pathAndQuery ?? '/',
            ...(persona ? { persona } : {}),
            ...(hop.canaryToken ? { canaryToken: hop.canaryToken } : {}),
            enableSinkHook: true,
          }, ctx.grant, signal ?? AbortSignal.timeout(30_000))
          const traceId = `retest-trace-${hop.hopId}-${randomUUID().slice(0, 8)}`
          const sinks = visit.attestedSinks?.length
            ? [...visit.attestedSinks]
            : visit.domSinkTraces.filter(s => s.containsCanary).map(s => s.sink)
          const traceBase: Omit<HostBrowserTrace, 'hostSignature'> = {
            id: traceId,
            origin: visit.origin,
            sinks,
            timestampMs: nextTs(),
            actorPersona: persona,
            ...(edgeCorrIds.length ? { correlationIds: edgeCorrIds } : {}),
          }
          browserTraces.push({ ...traceBase, hostSignature: signHostRecord(traceBase, signingKey) })
          replayedBrowserTraceIds.push(traceId)
        } catch (err) {
          return { outcome: 'inconclusive', errorCode: errCodeOf(err) ?? 'BROWSER_REPLAY_ERROR', entries, replayedExchangeIds, reason: `ScopedBrowser trace failed for hop "${hop.hopId}": ${err instanceof Error ? err.message : String(err)}` }
        }
      }

      // If this hop minted a fresh OOB canary, check CanaryBroker for callback delivery.
      if (mintedOobCanary && ctx.canaryBroker) {
        const check = ctx.canaryBroker.checkCanary(mintedOobCanary.token, { storage: ctx.storage, runId: ctx.runId })
        if (check.hit) {
          const oobId = `retest-oob-${hop.hopId}-${randomUUID().slice(0, 8)}`
          const oobBase: Omit<HostOobEvent, 'hostSignature'> = {
            id: oobId,
            token: mintedOobCanary.token,
            canaryId: mintedOobCanary.id,
            delivered: true,
            receivedAtMs: nextTs(),
            ...(edgeCorrIds.length ? { correlationIds: edgeCorrIds } : {}),
          }
          oobEvents.push({ ...oobBase, hostSignature: signHostRecord(oobBase, signingKey) })
          replayedOobEventIds.push(oobId)
        }
      }

      // 4) Synthesize host-signed async poll records for converged incoming poll_convergence / async_job edges when 2xx succeeded.
      const hopProbeEntries = entries.filter(e => e.step.arm === 'probe')
      if (hopProbeEntries.some(e => is2xx(e.step.status))) {
        for (const edge of incomingEdges) {
          if (edge.kind !== 'async_pivot_binding') continue
          if (edge.channel !== 'poll_convergence' && edge.channel !== 'async_job') continue
          const triggerExId = hopCtx.priorHopResults[edge.fromHopId]?.exchangeIds[0]
          const triggerEntry = triggerExId ? hopCtx.transcriptSoFar.entries?.find(e => e.exchangeId === triggerExId) : undefined
          const tTriggerMs = triggerEntry?.timestampMs ?? nextTs()
          const tObservedMs = Math.max(tTriggerMs + 5, nextTs())
          const pollId = `retest-poll-${edge.fromHopId}-${edge.toHopId}-${randomUUID().slice(0, 6)}`
          const pollBase: Omit<HostAsyncPollRecord, 'hostSignature'> = {
            id: pollId,
            ...(triggerExId ? { triggerExchangeId: triggerExId } : {}),
            tTriggerMs,
            tObservedMs,
            converged: true,
            correlationIds: [edge.correlationId],
            emittedCapabilities: [...hopEmittedAll],
          }
          asyncPollRecords.push({ ...pollBase, hostSignature: signHostRecord(pollBase, signingKey) })
          pollByEdge[`${edge.fromHopId}->${edge.toHopId}:${edge.kind}`] = pollId
        }
      }

      return {
        entries,
        replayedExchangeIds,
        ...(oobEvents.length ? { oobEvents, replayedOobEventIds } : {}),
        ...(browserTraces.length ? { browserTraces, replayedBrowserTraceIds } : {}),
        ...(asyncPollRecords.length ? { asyncPollRecords } : {}),
        ...(Object.keys(ablationByEdge).length ? { replayedAblationExchangeIds: ablationByEdge } : {}),
        ...(Object.keys(pollByEdge).length ? { replayedPollRecordIds: pollByEdge } : {}),
        ...(Object.keys(reboundValueDigests).length ? { reboundValueDigests } : {}),
        ...(lastStatus !== null ? { httpStatus: lastStatus } : {}),
      }
    },

    async readbackTerminalState({ receipt, signal }) {
      const entries: HostTranscriptEntry[] = []
      const postRbIds: string[] = []
      for (const rbId of receipt.terminalImpact.postChainReadbackExchangeIds) {
        const rbFact = lookupFact(rbId)
        const orig = lookupOriginalExchange(rbId)
        if (!rbFact && !orig) continue
        const persona = rbFact?.actor ?? orig?.personaHandle ?? defaultAttackerPersona
        const rbMethod = normalizeReplayHttpMethod(rbFact?.method ?? orig!.method)
        const rbPath = rbFact?.pathAndQuery ?? orig!.pathAndQuery
        const { headers: rbHeaders, redactedHeaders } = rebuildStoredReplayHeaders({
          rawHeaders: rbFact?.requestHeaders ?? orig?.reqHeaders,
          personaHandle: persona,
          grant: ctx.grant,
        })
        if (redactedHeaders.length > 0 || hasVaultScrubbedToken(rbPath)) {
          return { status: 'inconclusive', errorCode: 'REDACTED_READBACK_UNAVAILABLE', reason: `Terminal readback exchange "${rbId}" contains redacted request material unavailable in host factLog.` }
        }
        const rbBody = rbFact?.rawRequestBody ?? findReplaySpecStepBody(ctx.replaySpec, rbMethod, rbPath)
        let res: BrokerExchangeResult
        try {
          res = await ctx.broker.executeHttp({
            origin: rbFact?.origin ?? orig!.origin,
            method: rbMethod,
            pathAndQuery: rbPath,
            ...(persona ? { persona } : {}),
            ...(rbHeaders ? { headers: rbHeaders } : {}),
            ...(rbBody !== undefined && rbBody !== null ? { body: rbBody } : {}),
            followRedirects: false,
            sessionGroupRole: 'control',
            ...(ctx.runId ? { runId: ctx.runId } : {}),
            ...(ctx.assignmentId ? { assignmentId: ctx.assignmentId } : {}),
          }, ctx.grant, signal ?? AbortSignal.timeout(30_000))
        } catch (err) {
          return {
            status: 'transport_error',
            errorCode: errCodeOf(err) ?? 'TRANSPORT_ERROR',
            reason: `Terminal readback failed: ${err instanceof Error ? err.message : String(err)}`,
          }
        }
        if (isTransportOr5xx(res.status)) {
          return { status: 'transport_error', httpStatus: res.status, errorCode: `HTTP_${res.status}`, reason: `Terminal readback returned HTTP ${res.status}` }
        }
        if (res.status === 401 && persona) {
          return { status: 'inconclusive', httpStatus: res.status, errorCode: 'SESSION_DRIFTED', reason: `Authenticated terminal readback returned HTTP 401 (session drifted).` }
        }
        const origStatus = rbFact?.status ?? orig?.status ?? null
        if (is2xx(origStatus)) {
          const drift = detectHttpPreconditionDrift({ status: res.status, body: res.body, isTerminalHop: false, hopIndex: 0, originalStatus: origStatus })
          if (drift) return { status: 'precondition_changed', httpStatus: res.status, errorCode: 'PRECONDITION_CHANGED', reason: `Terminal readback: ${drift}` }
        }
        const newId = recordReplayedExchange(res, 'readback')
        postRbIds.push(newId)
        entries.push(buildSignedEntry({
          exchangeId: newId,
          res,
          arm: 'control',
          evidenceRole: 'post_chain_readback',
          personaHandle: persona,
          ...(rbBody ? { requestBody: rbBody } : {}),
        }))
      }
      return {
        status: 'ok',
        ...(entries.length ? { entries } : {}),
        ...(postRbIds.length ? { postChainReadbackExchangeIds: postRbIds } : {}),
      }
    },
  }
}

function remapOracleInputIds(value: unknown, remapEx: (id: string) => string, depth = 0): unknown {
  if (depth > 6 || value == null) return value
  if (typeof value === 'string') return remapEx(value)
  if (Array.isArray(value)) return value.map(item => remapOracleInputIds(item, remapEx, depth + 1))
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = remapOracleInputIds(v, remapEx, depth + 1)
    }
    return out
  }
  return value
}

function persistProposalGate6CompositeArtifact(
  lr: PatchLabRetestContext,
  input: {
    patchId: string
    findingId: string
    replaySpecId?: string
    labRevision: string
    status: PatchStatus
    dynamicRetestVerdict: DynamicRetestVerdict
    proof: CompositePatchRetestProof
    secrets?: readonly NamedSecret[]
  },
): void {
  // R4-H-10: Persist Gate-6 candidate-patch composite metadata ONLY as a proposal-scoped
  // `patch` artifact tagged with `patchId` and `labRevision` — NEVER into finding-level
  // `retest_runs` or `replay_specs.proof_receipt`.
  if (!lr.storage) return
  try {
    const run = lr.storage.run(lr.runId)
    const assignment = (lr.assignmentId
      ? lr.storage.workerList(run.id).find(w => w.id === lr.assignmentId)
      : undefined) ?? lr.storage.workerList(run.id).at(-1)
    if (!assignment) return
    const portable = toPortablePatchRetestProof(input.proof)
    lr.storage.addArtifact(
      run,
      assignment,
      'patch',
      `Patch proposal Gate-6 composite retest · ${input.patchId.slice(0, 8)} (${input.proof.verdict})`,
      JSON.stringify({
        kind: 'patch_proposal_gate6_retest',
        patchId: input.patchId,
        labRevision: input.labRevision,
        findingId: input.findingId,
        ...(input.replaySpecId ? { replaySpecId: input.replaySpecId } : {}),
        proposalStatus: input.status,
        dynamicRetestVerdict: input.dynamicRetestVerdict,
        ...portable,
      }, null, 2),
      `patch-gate6-composite:${input.patchId}`,
      input.secrets,
    )
  } catch {
    // Non-fatal if caller supplied a partial/ephemeral mock store.
  }
}

function persistCompositeRetestMetadata(
  ctx: BrokerCompositeReplayContext | undefined,
  proof: CompositePatchRetestProof,
  secrets?: readonly NamedSecret[],
): void {
  // R4-H-10: Candidate-patch trials (carrying `patchId`) and default broker calls MUST NEVER
  // write finding-level `retest_runs` or overwrite `replay_specs.proof_receipt`.
  // Only an explicit authoritative finding-level Verify Fix call (`persistRetest === true` with NO `patchId`)
  // records a finding-level `retest_runs` row + its linked structured artifact.
  if (!ctx || ctx.persistRetest !== true || proof.patchId || !ctx.storage || !ctx.runId || !ctx.findingId || !ctx.replaySpecId) return
  try {
    const storage = ctx.storage
    const run = storage.run(ctx.runId)
    const portable = toPortablePatchRetestProof(proof)
    const evidenceIds: string[] = []

    const assignment = (ctx.assignmentId
      ? storage.workerList(run.id).find(w => w.id === ctx.assignmentId)
      : undefined) ?? storage.workerList(run.id).at(-1)
    if (assignment) {
      const artifact = storage.addArtifact(
        run,
        assignment,
        'replay',
        `Composite Verify Fix retest · ${proof.chainId} (${proof.verdict})`,
        JSON.stringify({
          kind: 'composite_patch_retest',
          findingId: ctx.findingId,
          replaySpecId: ctx.replaySpecId,
          ...portable,
        }, null, 2),
        `composite-retest:${proof.retestId}`,
        secrets,
      )
      evidenceIds.push(artifact.id)
    }

    storage.recordRetestRun(
      run,
      ctx.findingId,
      ctx.replaySpecId,
      portable.verdict,
      proof.summary,
      evidenceIds,
      proof.exchangeIds,
    )
  } catch {
    // Non-fatal if caller supplied a partial/ephemeral mock store without a persisted run/spec row.
  }
}

const UNBUILDABLE_TERMINAL_REASON_RE = /\b(?:absent from host transcript|missing|missing_denied_control\w*|missing_pivot_control\w*|missing_v8_oracle_input|clean_denied_control\w*|no terminal exchange|browser trace|oob event|unbuildable|cannot be rebuilt|requires .* evidence)\b/i

function checkCompositeRetestHealth(
  entries: readonly HostTranscriptEntry[],
): { healthy: boolean; reason: string | null } {
  const controlArms: RetestArmObservation[] = []
  const probeArms: RetestArmObservation[] = []
  for (const e of entries) {
    const authenticated = Boolean(e.actorPersona && e.actorPersona.trim())
    const arm: RetestArmObservation = {
      role: e.step.evidenceRole ?? e.step.arm,
      status: typeof e.step.status === 'number' ? e.step.status : null,
      authenticated,
      allowDenied: e.step.arm === 'control' || e.replayAttempt === 'ablation_control',
      method: e.step.method,
    }
    if (e.step.arm === 'control' || e.replayAttempt === 'ablation_control') controlArms.push(arm)
    else if (e.step.arm === 'probe') probeArms.push(arm)
  }
  const health = assessRetestHealth(
    { controlArms, requireControlArm: false },
    { arms: probeArms, requireProbeArm: false, allowRedirect: true, requireDefinitiveDenial: false },
    { confirmed: false, failureReason: 'claim_not_reproduced' },
  )
  return { healthy: health.healthy, reason: health.reason }
}

export async function retestCompositeChainPatch(params: RetestCompositeChainParams): Promise<CompositePatchRetestProof> {
  const retestId = params.retestId ?? randomUUID(), nowFn = params.now ?? Date.now
  const testedAt = () => new Date(nowFn()).toISOString()
  const finalize = (chainId: string, terminalVulnClass: string, terminalHopId: string, verdict: CompositePatchRetestVerdict, summary: string, opts: {
    topoOrder?: string[]; hopResults?: CompositeHopReplaySummary[]; exchangeIds?: string[]; patchBrokeHopId?: string | null
    brokeCausalEdge?: CompositeBrokeCausalEdge | null; brokeReason?: string | null; benignPrefixHops?: string[]; compositeVerification?: CompositeReceiptVerification
  } = {}): CompositePatchRetestProof => {
    const isFixed = verdict === 'fixed'
    const base: Omit<CompositePatchRetestProof, 'proofSha256'> = {
      schemaVersion: 1, retestId, chainId, terminalVulnClass, terminalHopId, verdict, patchClosed: isFixed,
      patchBrokeHopId: isFixed ? (opts.patchBrokeHopId ?? null) : null, brokeCausalEdge: isFixed ? (opts.brokeCausalEdge ?? null) : null,
      brokeReason: isFixed && opts.brokeReason ? redact(opts.brokeReason, params.secrets) : null,
      benignPrefixHops: isFixed ? [...(opts.benignPrefixHops ?? [])] : [], topoOrder: [...(opts.topoOrder ?? [])],
      hopResults: (opts.hopResults ?? []).map(hr => ({ ...hr, ...(hr.reason !== undefined ? { reason: redact(hr.reason, params.secrets) } : {}) })),
      exchangeIds: [...new Set(opts.exchangeIds ?? [])], summary: redact(summary, params.secrets),
      ...(opts.compositeVerification ? { compositeVerification: opts.compositeVerification } : {}),
      ...(params.targetRevision ? { targetRevision: params.targetRevision } : {}), ...(params.patchId ? { patchId: params.patchId } : {}),
      testedAt: testedAt(),
    }
    const proof: CompositePatchRetestProof = { ...base, proofSha256: computeCompositeRetestProofDigest(base) }
    persistCompositeRetestMetadata(params.brokerContext, proof, params.secrets)
    return proof
  }

  const parsed = compositeProofReceiptSchema.safeParse(params.receipt)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    return finalize('invalid', 'invalid', 'invalid', 'inconclusive', `Composite patch retest inconclusive: Invalid CompositeProofReceipt schema: ${issue?.path.join('.') || 'receipt'} ${issue?.message ?? ''}`.trim())
  }
  const receipt = parsed.data, dagRes = buildCompositeDag(receipt)
  if (!dagRes.ok) return finalize(receipt.chainId, receipt.terminalVulnClass, receipt.terminalImpact.terminalHopId, 'inconclusive', `Composite patch retest inconclusive: invalid DAG topology (${dagRes.reason})`)

  const usesBrokerRunner = !params.runner && Boolean(params.brokerContext)
  const requireUnpatchedControl = params.prePatchControlRun === true
    ? false
    : (params.requireUnpatchedControl ?? usesBrokerRunner)
  const hasVerifiedPrePatchControl = Boolean(
    params.prePatchProof
    && params.prePatchProof.verdict === 'still_vulnerable'
    && params.prePatchProof.chainId === receipt.chainId
    && hasValidCompositeProofDigest(params.prePatchProof),
  )

  let effectiveRunner = params.runner
  let effectiveVerifyOptions = params.verifyOptions
  if (!effectiveRunner) {
    if (!params.brokerContext) {
      return finalize(receipt.chainId, receipt.terminalVulnClass, receipt.terminalImpact.terminalHopId, 'inconclusive', 'Composite patch retest inconclusive: missing replay runner or brokerContext.')
    }
    const ephemeralSigningKey = params.verifyOptions?.signingKey ?? randomUUID()
    effectiveRunner = createBrokerCompositePatchReplayRunner(params.brokerContext, ephemeralSigningKey, nowFn)
    const grantVerifyOpts = buildCompositeVerifyOptionsFromGrant(params.brokerContext.grant)
    effectiveVerifyOptions = {
      ...(grantVerifyOpts ?? {}),
      ...(params.verifyOptions ?? {}),
      signingKey: ephemeralSigningKey,
    }
  } else if (params.brokerContext && !effectiveVerifyOptions) {
    effectiveVerifyOptions = buildCompositeVerifyOptionsFromGrant(params.brokerContext.grant)
  }

  const { dag } = dagRes, signingKey = effectiveVerifyOptions?.signingKey
  const allEntries: HostTranscriptEntry[] = [], allOob: HostOobEvent[] = [], allTraces: HostBrowserTrace[] = [], allPolls: HostAsyncPollRecord[] = []
  const extraPreCtrl: string[] = [], extraPostRb: string[] = [], hopResults: CompositeHopReplaySummary[] = []
  const priorHops: Record<string, CompositeHopReplaySummary> = {}, hopArtifacts = new Map<string, HopArt>(), availCaps = new Set<string>()
  const reboundValueDigests = new Map<string, string>()
  const emit = (verdict: CompositePatchRetestVerdict, summary: string, extra: Parameters<typeof finalize>[5] = {}) =>
    finalize(receipt.chainId, receipt.terminalVulnClass, receipt.terminalImpact.terminalHopId, verdict, summary, { topoOrder: dag.topoOrder, hopResults, exchangeIds: allEntries.map(e => e.exchangeId), ...extra })

  // R4-H-9 + R2-04: Centralized gate guarding EVERY transition to 'fixed'.
  // Enforces (1) unpatched pre-patch reproduction control when required, and
  // (2) canonical `assessRetestHealth` alignment so unhealthy/drifted retests NEVER emit 'fixed'.
  const emitFixedOrFailClosed = (
    summary: string,
    extra: Parameters<typeof finalize>[5] = {},
  ): CompositePatchRetestProof => {
    if (params.prePatchControlRun) {
      return emit('inconclusive', `Pre-patch reproduction control did not reproduce chain: ${summary}`, {
        compositeVerification: extra.compositeVerification,
      })
    }
    if (requireUnpatchedControl && !hasVerifiedPrePatchControl) {
      return emit('inconclusive', `Composite patch retest inconclusive: cannot certify "fixed" without an authoritative pre-patch reproduction control from the same runner (${summary})`, {
        compositeVerification: extra.compositeVerification,
      })
    }
    const health = checkCompositeRetestHealth(allEntries)
    if (!health.healthy) {
      return emit('inconclusive', `Composite patch retest inconclusive (retest-health): ${health.reason ?? summary}`, {
        compositeVerification: extra.compositeVerification,
      })
    }
    return emit('fixed', summary, extra)
  }

  if (params.signal?.aborted) return emit('inconclusive', 'Composite patch retest inconclusive: aborted during initialization.')

  if (effectiveRunner.preparePreconditions) {
    let setup: CompositePreconditionSetupResult
    try { setup = await effectiveRunner.preparePreconditions({ receipt, topoOrder: dag.topoOrder, signal: params.signal }) }
    catch (err) { const c = errCodeOf(err); return emit('inconclusive', `Composite patch retest inconclusive: pre-chain setup failed${c ? ` (${c})` : ''}: ${err instanceof Error ? err.message : String(err)}`) }
    if (setup.entries) allEntries.push(...setup.entries); if (setup.oobEvents) allOob.push(...setup.oobEvents); if (setup.browserTraces) allTraces.push(...setup.browserTraces); if (setup.asyncPollRecords) allPolls.push(...setup.asyncPollRecords)
    if (setup.preChainControlExchangeIds) extraPreCtrl.push(...setup.preChainControlExchangeIds)
    const recErr = inspectRecordsForError(setup, signingKey)
    if (setup.status === 'transport_error' || setup.status === 'auth_setup_failed' || setup.status === 'inconclusive' || (setup.httpStatus !== undefined && isTransportOr5xx(setup.httpStatus)) || recErr.failed) {
      return emit('inconclusive', `Composite patch retest inconclusive: ${setup.reason ?? (recErr.failed ? recErr.reason : `Pre-chain setup returned "${setup.status}".`)}`)
    }
    if (setup.status === 'precondition_changed') return emit('precondition_changed', `Composite patch retest precondition changed: ${setup.reason ?? 'Target route or schema changed.'}`)
  }

  for (let hopIndex = 0; hopIndex < dag.topoOrder.length; hopIndex += 1) {
    const hopId = dag.topoOrder[hopIndex]!, hop = dag.hopsById.get(hopId)!
    if (params.signal?.aborted) return emit('inconclusive', `Composite patch retest inconclusive: aborted during hop "${hopId}".`)
    let rawResult: CompositeHopReplayResult
    try {
      rawResult = await effectiveRunner.replayHop({
        receipt, hop, hopIndex, topoOrder: dag.topoOrder, incomingEdges: (dag.incomingByHop.get(hopId) ?? []).map(x => x.edge),
        outgoingEdges: (dag.outgoingByHop.get(hopId) ?? []).map(x => x.edge), availableCapabilities: [...availCaps], priorHopResults: { ...priorHops },
        transcriptSoFar: { entries: [...allEntries], oobEvents: [...allOob], browserTraces: [...allTraces], asyncPollRecords: [...allPolls] }, signal: params.signal,
      })
    } catch (err) {
      const code = errCodeOf(err), msg = err instanceof Error ? err.message : String(err)
      hopResults.push(emptyHopSummary(hopId, hop.surface, 'transport_error', msg, code))
      return emit('inconclusive', `Composite patch retest inconclusive at hop "${hopId}"${code ? ` (${code})` : ''}: ${msg}`)
    }

    const entries = [...(rawResult.entries ?? [])], oob = [...(rawResult.oobEvents ?? [])], traces = [...(rawResult.browserTraces ?? [])], polls = [...(rawResult.asyncPollRecords ?? [])]
    allEntries.push(...entries); allOob.push(...oob); allTraces.push(...traces); allPolls.push(...polls)
    if (rawResult.preChainControlExchangeIds) extraPreCtrl.push(...rawResult.preChainControlExchangeIds)
    if (rawResult.postChainReadbackExchangeIds) extraPostRb.push(...rawResult.postChainReadbackExchangeIds)
    if (rawResult.reboundValueDigests) {
      for (const [ek, d] of Object.entries(rawResult.reboundValueDigests)) reboundValueDigests.set(ek, d.toLowerCase())
    }

    const eSet = new Set(entries.map(e => e.exchangeId)), oSet = new Set(oob.map(o => o.id)), tSet = new Set(traces.map(t => t.id))
    const hopExIds = rawResult.replayedExchangeIds ? [...rawResult.replayedExchangeIds] : (hop.exchangeIds.length && hop.exchangeIds.every(id => eSet.has(id)) ? [...hop.exchangeIds] : entries.filter(e => e.replayAttempt !== 'ablation_control').map(e => e.exchangeId))
    const hopOobIds = rawResult.replayedOobEventIds ? [...rawResult.replayedOobEventIds] : (hop.oobEventIds.length && hop.oobEventIds.every(id => oSet.has(id)) ? [...hop.oobEventIds] : oob.map(o => o.id))
    const hopTraceIds = rawResult.replayedBrowserTraceIds ? [...rawResult.replayedBrowserTraceIds] : (hop.browserTraceIds.length && hop.browserTraceIds.every(id => tSet.has(id)) ? [...hop.browserTraceIds] : traces.map(t => t.id))

    const emittedCaps = [...collectEmitted(entries, oob, traces, polls).caps]
    const consumedCaps = [...new Set(entries.flatMap(e => [...(e.consumedCapabilities ?? []), ...(e.cryptoAttestations ?? []).map(a => a.derivedFromCapabilityId)]))]
    const recErr = inspectRecordsForError({ entries, oobEvents: oob, browserTraces: traces, asyncPollRecords: polls }, signingKey)

    let outcome: CompositeHopReplayOutcome = 'succeeded', reason = rawResult.reason, errorCode = rawResult.errorCode, blockedWith4xx = false
    if (rawResult.outcome === 'transport_error' || rawResult.outcome === 'auth_setup_failed' || rawResult.outcome === 'inconclusive') {
      outcome = rawResult.outcome; reason ??= `Hop "${hopId}" encountered ${outcome}.`; errorCode ??= outcome.toUpperCase()
    } else if (rawResult.httpStatus !== undefined && isTransportOr5xx(rawResult.httpStatus)) {
      outcome = 'transport_error'; reason ??= `Hop "${hopId}" returned HTTP ${rawResult.httpStatus ?? 'error'}.`; errorCode ??= rawResult.httpStatus ? `HTTP_${rawResult.httpStatus}` : 'TRANSPORT_ERROR'
    } else if (rawResult.errorCode && TRANSPORT_ERR_RE.test(rawResult.errorCode)) {
      outcome = rawResult.errorCode === 'AUTH_SETUP_FAILED' ? 'auth_setup_failed' : 'transport_error'; reason ??= `Hop "${hopId}" failed with ${rawResult.errorCode}.`
    } else if (recErr.failed) {
      outcome = 'transport_error'; reason = recErr.reason; errorCode = recErr.errorCode
    } else if (rawResult.outcome === 'precondition_changed') {
      outcome = 'precondition_changed'; reason ??= `Target route or schema changed before/during hop "${hopId}".`; errorCode ??= 'PRECONDITION_CHANGED'
    } else {
      const probes = entries.filter(e => e.step.arm === 'probe' && e.replayAttempt !== 'ablation_control')
      const authSessionDrifted = probes.some(e => e.step.status === 401 && Boolean(e.actorPersona && e.actorPersona.trim()))
      if (authSessionDrifted) {
        outcome = 'auth_setup_failed'
        errorCode = 'SESSION_DRIFTED'
        reason ??= `Authenticated probe hop "${hopId}" returned HTTP 401 (session drifted; failing closed).`
      } else {
        const probe4xx = probes.length > 0 && probes.every(e => isSecurity4xx(e.step.status))
        const hasEffect = emittedCaps.length > 0 || oob.some(o => o.delivered) || traces.some(t => (t.sinks?.length ?? 0) > 0 || (t.emittedCapabilities?.length ?? 0) > 0) || polls.some(p => p.converged)
        if (rawResult.outcome === 'blocked' || (probe4xx && !hasEffect)) {
          outcome = 'blocked'; blockedWith4xx = probe4xx || isSecurity4xx(rawResult.httpStatus)
          const stList = probes.map(e => e.step.status).filter((s): s is number => typeof s === 'number').join(', ')
          reason ??= `Hop "${hopId}" blocked by patched target${stList ? ` (HTTP ${stList})` : ''}.`
        }
      }
    }

    const httpStatuses = entries.map(e => e.step.status).filter((s): s is number => typeof s === 'number' && Number.isFinite(s))
    if (!httpStatuses.length && typeof rawResult.httpStatus === 'number' && Number.isFinite(rawResult.httpStatus)) httpStatuses.push(rawResult.httpStatus)
    const summaryRec: CompositeHopReplaySummary = { hopId, surface: hop.surface, outcome, httpStatuses, exchangeIds: hopExIds, oobEventIds: hopOobIds, browserTraceIds: hopTraceIds, emittedCapabilities: emittedCaps, consumedCapabilities: consumedCaps, ...(reason ? { reason } : {}), ...(errorCode ? { errorCode } : {}) }
    hopResults.push(summaryRec); priorHops[hopId] = summaryRec
    const art: HopArt = { exchangeIds: hopExIds, oobEventIds: hopOobIds, browserTraceIds: hopTraceIds, entries, oobEvents: oob, browserTraces: traces, asyncPollRecords: polls, ablationByEdge: rawResult.replayedAblationExchangeIds ? { ...rawResult.replayedAblationExchangeIds } : {}, pollByEdge: rawResult.replayedPollRecordIds ? { ...rawResult.replayedPollRecordIds } : {} }
    hopArtifacts.set(hopId, art)

    if (outcome === 'transport_error' || outcome === 'auth_setup_failed' || outcome === 'inconclusive') return emit('inconclusive', `Composite patch retest inconclusive at hop "${hopId}": ${reason ?? outcome}`)
    if (outcome === 'precondition_changed') return emit('precondition_changed', `Composite patch retest precondition changed at hop "${hopId}": ${reason ?? 'target route/schema drifted'}`)

    const skipRest = () => { for (let j = hopIndex + 1; j < dag.topoOrder.length; j += 1) { const rid = dag.topoOrder[j]!; hopResults.push(emptyHopSummary(rid, dag.hopsById.get(rid)!.surface, 'skipped_after_break', `Skipped because predecessor hop "${hopId}" broke the chain.`)) } }
    const benignPrefix = dag.topoOrder.slice(0, hopIndex).filter(id => priorHops[id]?.outcome === 'succeeded')
    const pNote = benignPrefix.length ? ` (benign prefix succeeded: ${benignPrefix.join(' -> ')})` : ''

    if (outcome === 'blocked') {
      skipRest()
      const inc = dag.incomingByHop.get(hopId) ?? [], outg = dag.outgoingByHop.get(hopId) ?? []
      const ch = blockedWith4xx ? (inc[0] ?? outg[0]) : (outg[0] ?? inc[0])
      const brokeReason = reason ?? `Hop "${hopId}" was blocked by the patched target.`
      return emitFixedOrFailClosed(`Fixed: multi-hop chain broke cleanly at "${hopId}"${pNote}: ${brokeReason}`, { patchBrokeHopId: hopId, brokeCausalEdge: ch ? { edgeIndex: ch.edgeIndex, kind: ch.edge.kind, fromHopId: ch.edge.fromHopId, toHopId: ch.edge.toHopId } : null, brokeReason, benignPrefixHops: benignPrefix })
    }
    for (const oe of dag.outgoingByHop.get(hopId) ?? []) {
      const check = checkProducerEdge(oe.edge, hop, art, reboundValueDigests)
      if (!check.ok) {
        summaryRec.outcome = 'blocked'; summaryRec.reason = check.reason; skipRest()
        return emitFixedOrFailClosed(`Fixed: multi-hop chain broke cleanly at "${hopId}"${pNote}: ${check.reason}`, { patchBrokeHopId: hopId, brokeCausalEdge: { edgeIndex: oe.edgeIndex, kind: oe.edge.kind, fromHopId: oe.edge.fromHopId, toHopId: oe.edge.toHopId }, brokeReason: check.reason, benignPrefixHops: benignPrefix })
      }
    }
    for (const cap of emittedCaps) availCaps.add(cap)
  }

  if (effectiveRunner.readbackTerminalState) {
    if (params.signal?.aborted) return emit('inconclusive', 'Composite patch retest inconclusive: aborted during terminal readback.')
    try {
      const rb = await effectiveRunner.readbackTerminalState({ receipt, transcriptSoFar: { entries: [...allEntries], oobEvents: [...allOob], browserTraces: [...allTraces], asyncPollRecords: [...allPolls] }, signal: params.signal })
      if (rb.entries) allEntries.push(...rb.entries); if (rb.postChainReadbackExchangeIds) extraPostRb.push(...rb.postChainReadbackExchangeIds)
      const rbErr = inspectRecordsForError({ entries: rb.entries }, signingKey)
      if (rb.status === 'transport_error' || rb.status === 'inconclusive' || (rb.httpStatus !== undefined && isTransportOr5xx(rb.httpStatus)) || rbErr.failed) return emit('inconclusive', `Composite patch retest inconclusive during terminal readback: ${rb.reason ?? (rbErr.failed ? rbErr.reason : 'Terminal readback failed.')}`)
      if (rb.status === 'precondition_changed') return emit('precondition_changed', `Composite patch retest precondition changed during terminal readback: ${rb.reason ?? 'schema/route changed'}`)
    } catch (err) { const c = errCodeOf(err); return emit('inconclusive', `Composite patch retest inconclusive during terminal readback${c ? ` (${c})` : ''}: ${err instanceof Error ? err.message : String(err)}`) }
  }

  const exById = new Map(allEntries.map(e => [e.exchangeId, e])), oobById = new Map(allOob.map(o => [o.id, o])), trById = new Map(allTraces.map(t => [t.id, t])), pollById = new Map(allPolls.map(p => [p.id, p]))
  const exMap = new Map<string, string>(), oobMap = new Map<string, string>(), trMap = new Map<string, string>()
  const replayedHops = receipt.hops.map(h => {
    const a = hopArtifacts.get(h.hopId); if (!a) return h
    if (h.exchangeIds.length === a.exchangeIds.length) h.exchangeIds.forEach((id, i) => exMap.set(id, a.exchangeIds[i]!))
    if (h.oobEventIds.length === a.oobEventIds.length) h.oobEventIds.forEach((id, i) => oobMap.set(id, a.oobEventIds[i]!))
    if (h.browserTraceIds.length === a.browserTraceIds.length) h.browserTraceIds.forEach((id, i) => trMap.set(id, a.browserTraceIds[i]!))
    return { ...h, exchangeIds: a.exchangeIds, oobEventIds: a.oobEventIds, browserTraceIds: a.browserTraceIds }
  })
  const ti = receipt.terminalImpact
  if (extraPreCtrl.length === ti.preChainControlExchangeIds.length) {
    ti.preChainControlExchangeIds.forEach((id, i) => { if (!exMap.has(id)) exMap.set(id, extraPreCtrl[i]!) })
  }
  if (extraPostRb.length === ti.postChainReadbackExchangeIds.length) {
    ti.postChainReadbackExchangeIds.forEach((id, i) => { if (!exMap.has(id)) exMap.set(id, extraPostRb[i]!) })
  }
  const remapEx = (id: string) => exById.has(id) ? id : (exMap.get(id) ?? id), remapOob = (id: string) => oobById.has(id) ? id : (oobMap.get(id) ?? id), remapTr = (id: string) => trById.has(id) ? id : (trMap.get(id) ?? id)

  const replayedEdges: CausalEdgeBinding[] = receipt.causalEdges.map(edge => {
    const k = `${edge.fromHopId}->${edge.toHopId}`, tk = `${k}:${edge.kind}`, toArt = hopArtifacts.get(edge.toHopId)
    if (edge.kind === 'value_binding') {
      const src = edge.sourceExchangeId ? (exById.has(edge.sourceExchangeId) ? edge.sourceExchangeId : exMap.get(edge.sourceExchangeId)) : undefined
      const tgt = edge.targetExchangeId ? (exById.has(edge.targetExchangeId) ? edge.targetExchangeId : exMap.get(edge.targetExchangeId)) : undefined
      const freshDigest = reboundValueDigests.get(tk)
      return {
        ...edge,
        ...(edge.valueDigest && freshDigest ? { valueDigest: freshDigest } : {}),
        sourceExchangeId: src,
        targetExchangeId: tgt,
      }
    }
    if (edge.kind === 'state_transition_binding') {
      const exp = toArt?.ablationByEdge[tk] ?? toArt?.ablationByEdge[k], inf = (toArt?.entries ?? []).filter(e => e.replayAttempt === 'ablation_control').map(e => e.exchangeId)
      return { ...edge, ablationExchangeIds: exp?.length ? [...exp] : edge.ablationExchangeIds.every(id => exById.has(id)) ? [...edge.ablationExchangeIds] : (inf.length ? inf : edge.ablationExchangeIds.map(remapEx)) }
    }
    if (edge.kind === 'async_pivot_binding') {
      const pollRecordId = toArt?.pollByEdge[tk] ?? toArt?.pollByEdge[k] ?? (edge.pollRecordId ? (pollById.has(edge.pollRecordId) ? edge.pollRecordId : toArt?.asyncPollRecords[0]?.id ?? edge.pollRecordId) : undefined)
      return { ...edge, ...(edge.oobEventId ? { oobEventId: remapOob(edge.oobEventId) } : {}), ...(edge.browserTraceId ? { browserTraceId: remapTr(edge.browserTraceId) } : {}), ...(pollRecordId ? { pollRecordId } : {}) }
    }
    return edge
  })

  const replayedReceipt: CompositeProofReceipt = {
    ...receipt, hops: replayedHops, causalEdges: replayedEdges, replayMode: 'fresh_clean_replay',
    terminalImpact: {
      ...ti, modeAFailureExchangeId: undefined,
      ...(ti.terminalExchangeId ? { terminalExchangeId: remapEx(ti.terminalExchangeId) } : {}),
      ...(ti.oracleInput ? { oracleInput: remapOracleInputIds(ti.oracleInput, remapEx) as Record<string, unknown> } : {}),
      preChainControlExchangeIds: extraPreCtrl.length ? [...new Set(extraPreCtrl)] : ti.preChainControlExchangeIds.map(remapEx).filter(id => exById.has(id)),
      postChainReadbackExchangeIds: extraPostRb.length ? [...new Set(extraPostRb)] : ti.postChainReadbackExchangeIds.map(remapEx).filter(id => exById.has(id)),
      ...(ti.proofReceipt ? { proofReceipt: { ...ti.proofReceipt, exchangeIds: ti.proofReceipt.exchangeIds.map(remapEx), oobEventIds: ti.proofReceipt.oobEventIds.map(remapOob), browserTraceIds: ti.proofReceipt.browserTraceIds.map(remapTr) } } : {}),
    },
  }
  const rawVerification = verifyCompositeReceipt(replayedReceipt, { entries: allEntries, oobEvents: allOob, browserTraces: allTraces, asyncPollRecords: allPolls }, effectiveVerifyOptions)
  const verification: CompositeReceiptVerification = (
    rawVerification.confirmed
    && replayedReceipt.causalEdges.length > 0
    && rawVerification.verifiedEdges.length > replayedReceipt.causalEdges.length
  )
    ? { ...rawVerification, verifiedEdges: rawVerification.verifiedEdges.slice(0, replayedReceipt.causalEdges.length) }
    : rawVerification

  if (verification.confirmed) return emit('still_vulnerable', `Still vulnerable: full ${receipt.hops.length}-hop DAG confirmed against patched target (${verification.reason}).`, { compositeVerification: verification })
  if (verification.failedStage === 'schema' || verification.failedStage === 'dag_topology' || verification.failedStage === 'transcript_integrity' || verification.failedStage === 'attacker_provenance' || verification.failedStage === 'replay_mode') {
    return emit('inconclusive', `Composite patch retest inconclusive (${verification.failedStage}): ${verification.reason}`, { compositeVerification: verification })
  }
  if (verification.failedStage === 'edge_binding') {
    const fe = verification.verifiedEdges.find(e => !e.verified)
    if (fe) {
      // R4-H-9: Do NOT blindly map edge_binding failures caused by replay/harness re-binding gaps or
      // unhealthy ablation controls to 'fixed'. Fail closed as inconclusive.
      const ablationUnhealthy = fe.kind === 'state_transition_binding' && /ablation/i.test(fe.reason)
      const rebindGap = fe.kind === 'value_binding' && usesBrokerRunner && priorHops[fe.fromHopId]?.outcome === 'succeeded' && priorHops[fe.toHopId]?.outcome === 'succeeded'
      if (ablationUnhealthy || rebindGap) {
        return emit('inconclusive', `Composite patch retest inconclusive (edge_binding ${fe.fromHopId} -> ${fe.toHopId}): ${fe.reason}`, { compositeVerification: verification })
      }
      const eObj = replayedReceipt.causalEdges[fe.edgeIndex], fArt = hopArtifacts.get(fe.fromHopId), fHop = dag.hopsById.get(fe.fromHopId)
      const brokeHopId = (eObj && fArt && fHop ? checkProducerEdge(eObj, fHop, fArt, reboundValueDigests).ok : true) ? fe.toHopId : fe.fromHopId
      const idx = dag.topoOrder.indexOf(brokeHopId), bp = idx > 0 ? dag.topoOrder.slice(0, idx).filter(id => priorHops[id]?.outcome === 'succeeded') : []
      return emitFixedOrFailClosed(`Fixed: causal edge ${fe.fromHopId} -> ${fe.toHopId} (${fe.kind}) broke at "${brokeHopId}"${bp.length ? ` (benign prefix succeeded: ${bp.join(' -> ')})` : ''}: ${fe.reason}`, {
        patchBrokeHopId: brokeHopId, brokeCausalEdge: { edgeIndex: fe.edgeIndex, kind: fe.kind, fromHopId: fe.fromHopId, toHopId: fe.toHopId }, brokeReason: fe.reason, benignPrefixHops: bp, compositeVerification: verification,
      })
    }
    return emit('inconclusive', `Composite patch retest inconclusive (edge_binding): ${verification.reason}`, { compositeVerification: verification })
  }
  if (UNBUILDABLE_TERMINAL_REASON_RE.test(verification.reason)) {
    return emit('inconclusive', `Composite patch retest inconclusive (terminal_impact evidence unavailable): ${verification.reason}`, { compositeVerification: verification })
  }
  const termId = receipt.terminalImpact.terminalHopId, termIdx = dag.topoOrder.indexOf(termId)
  const bp = termIdx > 0 ? dag.topoOrder.slice(0, termIdx).filter(id => priorHops[id]?.outcome === 'succeeded') : []
  return emitFixedOrFailClosed(`Fixed: terminal impact neutralized at "${termId}"${bp.length ? ` (benign prefix succeeded: ${bp.join(' -> ')})` : ''}: ${verification.reason}`, {
    patchBrokeHopId: termId, brokeCausalEdge: null, brokeReason: verification.reason, benignPrefixHops: bp, compositeVerification: verification,
  })
}
