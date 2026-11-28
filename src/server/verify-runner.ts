/**
 * Layer-3 verification script preparation, dual-attempt independent re-run
 * orchestration (`verifyScript`), and local/sandbox script execution runner.
 *
 * Depends strictly downward on `verify-claims.ts`, `oracle-invariants.ts`,
 * and `redact.ts` (no dependency on `verify-rpc.ts`).
 */
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { redact } from './redact.ts'
import { registerRunDisposer } from './run-disposers.ts'
import { HostFactLog } from './host-fact-log.ts'
import { classifyBoundaryClaim, classifyImpactDescriptor } from './oracle-invariants.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RESULT_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VERIFY_RPC_TOKEN_NAME,
  TranscriptStore,
  causalFingerprints,
  evaluateClaims,
  normalizeDynamic,
  parseVerifyScriptResult,
} from './verify-claims.ts'
import type {
  CausalFingerprint,
  TranscriptSummary,
  VerifyCanaryBroker,
  VerifyScriptResult,
} from './verify-claims.ts'

// ---------------------------------------------------------------------------
// Independent re-run: verifyScript()
// ---------------------------------------------------------------------------

export const KOVO_VERIFY_STDERR_PREVIEW_MAX_CHARS = 400

export const KOVO_VERIFY_USAGE_HINT =
  'Inline TS scripts receive `ctx` directly (no imports required): `await ctx.prove_access_boundary({ controlPersona, probePersona, route }); return ctx.result({ title: "..." })` (or `export default async (ctx) => { ... }`).'

/**
 * Structured keys for host-observed `kovo_verify` tool-arg and script/SDK alias hits.
 * Counted host-side before any future alias pruning so telemetry shows which aliases
 * models actually rely on.
 */
export type KovoVerifyAliasKey =
  | 'tool_arg:code'
  | 'tool_arg:source'
  | 'script:code_fence'
  | 'script:bare_sdk_import'
  | 'script:define_verification'
  | 'script:export_default'
  | 'script:named_verify_fn'
  | 'sdk_arg:persona'
  | 'sdk_arg:variant'
  | 'sdk_arg:edges'
  | 'sdk_arg:ablationExchange'
  | 'sdk_arg:endpoint_target'

export interface KovoVerifyAliasUsageSnapshot {
  totalCalls: number
  totalAliasHits: number
  byAlias: Record<string, number>
}

const CODE_FENCE_RE = /^```[a-zA-Z0-9_-]*[ \t]*\r?\n([\s\S]*?)\r?\n```$/
const BARE_SDK_IMPORT_RE = /\b(?:from\s*|import\(\s*)(['"])(?:\.\/)?kovo_verify(?:\.(?:mts|js|mjs))?\1/
const DEFINE_VERIFICATION_RE = /\bdefineVerification\s*\(/
const EXPORT_DEFAULT_ALIAS_RE = /(^|;[ \t]*|\n[ \t]*)export\s+default\s+/
const NAMED_VERIFY_ALIAS_RE = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+verify\s*\(|(?:const|let|var)\s+verify\s*=)/m
const SDK_PERSONA_ALIAS_RE = /[{,]\s*persona\s*:/
const SDK_VARIANT_ALIAS_RE = /[{,]\s*variant\s*:/
const SDK_EDGES_ALIAS_RE = /[{,]\s*edges\s*:/
const SDK_ABLATION_ALIAS_RE = /[{,]\s*ablationExchange\s*:/
const SDK_ENDPOINT_TARGET_ALIAS_RE = /[{,]\s*endpoint\s*:/

/** Pure static detector for authoring/SDK aliases inside a raw `kovo_verify` script. */
export function detectKovoVerifyScriptAliases(rawCode: string): KovoVerifyAliasKey[] {
  const hits: KovoVerifyAliasKey[] = []
  const trimmed = (rawCode ?? '').trim()
  if (!trimmed) return hits
  if (CODE_FENCE_RE.test(trimmed)) hits.push('script:code_fence')
  const unfenced = stripCodeFences(rawCode)
  if (BARE_SDK_IMPORT_RE.test(unfenced)) hits.push('script:bare_sdk_import')
  if (DEFINE_VERIFICATION_RE.test(unfenced)) hits.push('script:define_verification')
  if (EXPORT_DEFAULT_ALIAS_RE.test(unfenced)) hits.push('script:export_default')
  else if (NAMED_VERIFY_ALIAS_RE.test(unfenced)) hits.push('script:named_verify_fn')
  if (SDK_PERSONA_ALIAS_RE.test(unfenced)) hits.push('sdk_arg:persona')
  if (SDK_VARIANT_ALIAS_RE.test(unfenced)) hits.push('sdk_arg:variant')
  if (SDK_EDGES_ALIAS_RE.test(unfenced)) hits.push('sdk_arg:edges')
  if (SDK_ABLATION_ALIAS_RE.test(unfenced)) hits.push('sdk_arg:ablationExchange')
  if (SDK_ENDPOINT_TARGET_ALIAS_RE.test(unfenced)) hits.push('sdk_arg:endpoint_target')
  return hits
}

/** Mutable counter aggregating `kovo_verify` alias hits for a run or test scope. */
export class KovoVerifyAliasCounter {
  private totalCalls = 0
  private totalAliasHits = 0
  private readonly counts = new Map<string, number>()

  recordCall(aliases: readonly KovoVerifyAliasKey[] = []): void {
    this.totalCalls += 1
    for (const key of aliases) {
      this.totalAliasHits += 1
      this.counts.set(key, (this.counts.get(key) ?? 0) + 1)
    }
  }

  recordScript(rawCode: string, extraAliases: readonly KovoVerifyAliasKey[] = []): KovoVerifyAliasKey[] {
    const detected = [...extraAliases, ...detectKovoVerifyScriptAliases(rawCode)]
    this.recordCall(detected)
    return detected
  }

  snapshot(): KovoVerifyAliasUsageSnapshot {
    const byAlias: Record<string, number> = {}
    for (const [key, count] of [...this.counts.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      byAlias[key] = count
    }
    return {
      totalCalls: this.totalCalls,
      totalAliasHits: this.totalAliasHits,
      byAlias,
    }
  }

  reset(): void {
    this.totalCalls = 0
    this.totalAliasHits = 0
    this.counts.clear()
  }
}

const runAliasCounters = new Map<string, KovoVerifyAliasCounter>()

/** Record one `kovo_verify` invocation's alias hits under a run ID for telemetry reporting. */
export function recordKovoVerifyAliasUsage(
  runId: string,
  aliases: readonly KovoVerifyAliasKey[],
): KovoVerifyAliasUsageSnapshot {
  let counter = runAliasCounters.get(runId)
  if (!counter) {
    counter = new KovoVerifyAliasCounter()
    runAliasCounters.set(runId, counter)
  }
  counter.recordCall(aliases)
  return counter.snapshot()
}

/** Read current host-side `kovo_verify` alias-usage telemetry for a run. */
export function getKovoVerifyAliasUsage(runId: string): KovoVerifyAliasUsageSnapshot {
  return runAliasCounters.get(runId)?.snapshot() ?? { totalCalls: 0, totalAliasHits: 0, byAlias: {} }
}

/** Clear stored `kovo_verify` alias counters for a run (e.g. test cleanup / run disposal). */
export function resetKovoVerifyAliasUsage(runId?: string): void {
  if (runId === undefined) {
    runAliasCounters.clear()
    return
  }
  runAliasCounters.delete(runId)
}

registerRunDisposer('verify-runner:alias-counters', runId => {
  resetKovoVerifyAliasUsage(runId)
})

/** Strip accidental outer markdown code fences (```ts ... ```) from LLM scripts. */
function stripCodeFences(rawCode: string): string {
  const trimmed = rawCode.trim()
  const match = /^```[a-zA-Z0-9_-]*[ \t]*\r?\n([\s\S]*?)\r?\n```$/.exec(trimmed)
  return match ? match[1]! : rawCode
}

/** Redact credential-shaped tokens and bound stderr preview to 400 chars for repair feedback. */
export function redactStderrPreview(raw: string, maxChars = KOVO_VERIFY_STDERR_PREVIEW_MAX_CHARS): string {
  const cleaned = redact(raw ?? '').replace(/\u001b\[[0-9;]*m/g, '').trim()
  if (!cleaned) return ''
  return cleaned.length <= maxChars ? cleaned : `${cleaned.slice(0, Math.max(0, maxChars - 3))}...`
}

function normalizeTsSdkImports(code: string): string {
  return code
    .replace(/(\bfrom\s*)(['"])(?:\.\/)?kovo_verify(?:\.(?:ts|mts|js|mjs))?\2/g, "$1'./kovo_verify.ts'")
    .replace(/\bimport\(\s*(['"])(?:\.\/)?kovo_verify(?:\.(?:ts|mts|js|mjs))?\1\s*\)/g, "import('./kovo_verify.ts')")
}

function splitLeadingTsImports(code: string): { imports: string; body: string } {
  const lines = code.split(/\r?\n/)
  const importLines: string[] = []
  let i = 0
  let inBlockComment = false
  let inImport = false
  while (i < lines.length) {
    const line = lines[i]!
    const trimmed = line.trim()
    if (inImport) {
      importLines.push(line)
      if (/\bfrom\s*['"][^'"]+['"]\s*;?$/.test(trimmed) || /^import\s*['"][^'"]+['"]\s*;?$/.test(trimmed)) {
        inImport = false
      }
      i += 1
      continue
    }
    if (inBlockComment) {
      importLines.push(line)
      if (trimmed.includes('*/')) inBlockComment = false
      i += 1
      continue
    }
    if (!trimmed || trimmed.startsWith('//')) {
      importLines.push(line)
      i += 1
      continue
    }
    if (trimmed.startsWith('/*')) {
      importLines.push(line)
      if (!trimmed.includes('*/')) inBlockComment = true
      i += 1
      continue
    }
    if (/^import\s+(?!\()/.test(trimmed)) {
      importLines.push(line)
      const completeSingle = /\bfrom\s*['"][^'"]+['"]\s*;?$/.test(trimmed)
        || /^import\s*['"][^'"]+['"]\s*;?$/.test(trimmed)
        || /^import\s+\w+\s*=\s*require\(/.test(trimmed)
      if (!completeSingle) inImport = true
      i += 1
      continue
    }
    break
  }
  const hasRealImport = importLines.some(line => /^\s*import\s+(?!\()/.test(line))
  if (!hasRealImport) return { imports: '', body: code }
  return {
    imports: importLines.join('\n'),
    body: lines.slice(i).join('\n'),
  }
}

/**
 * Normalize an inline `kovo_verify` script so every documented authoring style works identically:
 *   1. Explicit `runVerification(...)` / `runEntrypoint(...)` / `KOVO_PROOF_RESULT_FILE` -> run as-is (with SDK import paths normalized).
 *   2. `export default async (ctx) => ...` / `export default defineVerification(...)` / `export default { verify(ctx) {} }` -> invoke via `runEntrypoint`.
 *   3. Named `export async function verify(ctx)` / `async function verify(ctx)` -> invoke via `runEntrypoint`.
 *   4. Bare inline script body using `ctx` (`await ctx.prove_access_boundary(...)`) -> wrap in `runEntrypoint(async (ctx) => { ... })`.
 *   5. Standalone scripts without `ctx` (e.g. stdout-only or raw probes) -> run verbatim (fail closed as `claims_missing`).
 *
 * Idempotent: calling twice produces the exact same output. Never fabricates claims.
 */
export function prepareVerifyScript(rawCode: string, runtime: 'ts' = 'ts', defaultTitle?: string): string {
  if (runtime !== 'ts') {
    throw new Error(`Unsupported verification runtime: ${String(runtime)}. kovo_verify supports TypeScript only (runtime='ts').`)
  }
  const unfenced = stripCodeFences(rawCode)
  const trimmed = unfenced.trim()
  if (!trimmed) return rawCode
  const titleLiteral = JSON.stringify(defaultTitle?.trim() || 'Verification script proof')

  // TypeScript runtime
  const normalized = normalizeTsSdkImports(unfenced)
  if (
    /\b(?:runVerification|runEntrypoint|__kovo_run)\s*\(/.test(normalized)
    || /\bKOVO_PROOF_RESULT_FILE\b/.test(normalized)
  ) {
    return normalized
  }

  const needsDefineAlias = /\bdefineVerification\s*\(/.test(normalized)
    && !/\bimport\b[^;]*\bdefineVerification\b/.test(normalized)
  const sdkImport = needsDefineAlias
    ? "import { defineVerification, runEntrypoint as __kovo_run } from './kovo_verify.ts'\n"
    : "import { runEntrypoint as __kovo_run } from './kovo_verify.ts'\n"

  const exportDefaultRe = /(^|;[ \t]*|\n[ \t]*)export\s+default\s+/
  if (exportDefaultRe.test(normalized)) {
    const rewritten = normalized.replace(exportDefaultRe, '$1const __kovo_default_export = ')
    return `${sdkImport}${rewritten}\n;\nawait __kovo_run(__kovo_default_export, ${titleLiteral})\n`
  }

  const hasExportVerify = /^[ \t]*export\s+(?:(?:async\s+)?function\s+verify\s*\(|(?:const|let|var)\s+verify\s*=)/m.test(normalized)
  const hasTopLevelVerify = /^[ \t]*(?:async\s+)?function\s+verify\s*\(/m.test(normalized)
  if (hasExportVerify || hasTopLevelVerify) {
    const hasSetup = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+setup\s*\(|(?:const|let|var)\s+setup\s*=)/m.test(normalized)
    const hasCleanup = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+cleanup\s*\(|(?:const|let|var)\s+cleanup\s*=)/m.test(normalized)
    const hooks = ['verify', ...(hasSetup ? ['setup'] : []), ...(hasCleanup ? ['cleanup'] : [])].join(', ')
    return `${sdkImport}${normalized}\n;\nawait __kovo_run({ ${hooks} }, ${titleLiteral})\n`
  }

  if (/\bctx\b/.test(normalized)) {
    const { imports, body } = splitLeadingTsImports(normalized)
    const prefix = imports ? `${sdkImport}${imports}\n` : sdkImport
    const bodyTrimmed = body.trim()
    // Standalone function expression (e.g. `async (ctx) => { ... }` or `async function(ctx) { ... }`)
    const isStandaloneFnExpr = /^(?:async\s+)?(?:\(\s*ctx\b[^)]*\)\s*=>|ctx\s*=>|function\s*(?:[A-Za-z_$][\w$]*)?\s*\(\s*ctx\b[^)]*\))/.test(bodyTrimmed)
    if (isStandaloneFnExpr) {
      const expr = bodyTrimmed.replace(/;\s*$/, '')
      return `${prefix}await __kovo_run((\n${expr}\n), ${titleLiteral})\n`
    }
    return `${prefix}await __kovo_run(async (ctx) => {\n${body}\n}, ${titleLiteral})\n`
  }

  return normalized
}

export interface VerificationCandidate {
  name: string
  runtime: 'ts'
  code: string
  title?: string
}

export interface AttemptExecution {
  result: unknown
  stdout: string
  stderr: string
  exitCode: number
  durationMs: number
  timedOut?: boolean
}

export interface VerifyAttemptSession {
  nonce: string
  transcript: TranscriptStore
  execute(candidate: VerificationCandidate, signal: AbortSignal): Promise<AttemptExecution>
  close(): Promise<void>
}

export type VerifyReason =
  | 'confirmed'
  | 'checkpoint_only'
  | 'execution_failed'
  | 'claims_missing'
  | 'claims_invalid'
  | 'oracle_failed'
  | 'transcript_mismatch'
  | 'nonce_reuse'
  | 'nonce_mismatch'

export interface VerifyAttemptReport {
  attempt: 1 | 2
  nonce: string
  exitCode: number
  durationMs: number
  oraclePassed: boolean
  failures: string[]
  claimCount: number
  exchangeCount: number
  transcriptDigest: string
  signaturesValid: boolean
  causal: CausalFingerprint[]
  title: string | null
  nonceMismatch: boolean
  /** First validator that rejected this attempt, so a repair can target it directly. */
  rejectedBy: string | null
  /** Exact missing transcript roles/preconditions. */
  missingEvidence: string[]
  /** Role-labelled transcript summary (control/probe/... ids, statuses, personas). */
  transcriptSummary: TranscriptSummary[]
  /** Last 2 KiB of redacted script stderr, useful when the helper throws before returning claims. */
  stderr?: string
}

export interface VerifyVerdict {
  confirmed: boolean
  reason: VerifyReason
  detail: string
  attempts: VerifyAttemptReport[]
  disagreements: string[]
  claimTitle: string | null
  rejectedBy: string | null
  missingEvidence: string[]
  transcriptSummary: TranscriptSummary[]
  /** Script exit code when the attempt failed or produced no valid proof document. */
  exitCode?: number
  /** Bounded, redacted first 400 chars of script stderr on execution/proof-document failure. */
  stderrPreview?: string
  /** Actionable 1-line usage hint surfaced on `claims_missing` / execution failure. */
  usageHint?: string
  /** Structured `kovo_verify` script/SDK alias keys detected on this verification call. */
  aliasHits?: KovoVerifyAliasKey[]
}

export interface VerifyScriptOptions {
  candidate: VerificationCandidate
  /** Must create a genuinely fresh session (new broker jars, new transcript) per attempt. */
  openAttempt: (input: { attempt: 1 | 2; nonce: string }) => Promise<VerifyAttemptSession>
  signal?: AbortSignal
  canary?: VerifyCanaryBroker
  timeoutMs?: number
  /** Skip Attempt 2 when Attempt 1 already failed with `execution` or `checkpoint` (used when `doubleReplay: true`). */
  fastFailOnAttempt1?: boolean
  /** Explicit opt-in to execute Attempt 2 and compare cross-attempt causal fingerprints (default: false — 1x clean host-signed replay). */
  doubleReplay?: boolean
}

interface CheckpointTranscriptSummary {
  hasCheckpointOps: boolean
  sealedHandles: string[]
  cryptoOpCount: number
  asyncPollCount: number
  httpShapes: string[]
}

function summarizeNonSecretHttpShape(transcript: TranscriptStore, record: ReturnType<TranscriptStore['list']>[number]): string | null {
  if (!record.request || (record.op !== 'http' && record.op !== 'http2' && record.op !== 'race')) return null
  const method = record.request.method.toUpperCase()
  const pathOnly = (record.request.pathAndQuery ?? '/').split(/[?#]/, 1)[0] || '/'
  const status = record.response?.status ?? 'err'
  let keySuffix = ''
  const rawBody = typeof transcript.body === 'function' ? transcript.body(record.exchangeId) : undefined
  if (typeof rawBody === 'string' && rawBody.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(rawBody) as unknown
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const keys = Object.keys(parsed as Record<string, unknown>)
          .map(k => k.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 32))
          .filter(Boolean)
          .slice(0, 8)
        if (keys.length > 0) keySuffix = ` keys=[${keys.join(',')}]`
      }
    } catch { /* ignore non-JSON */ }
  }
  return `${method} ${pathOnly.slice(0, 80)} -> ${status}${keySuffix}`
}

function inspectCheckpointTranscript(transcript: TranscriptStore): CheckpointTranscriptSummary {
  const sealedHandles = new Set<string>()
  const httpShapes: string[] = []
  let hasCheckpointOps = false
  let cryptoOpCount = 0
  let asyncPollCount = 0

  for (const record of transcript.list()) {
    if (record.error) continue
    const shape = summarizeNonSecretHttpShape(transcript, record)
    if (shape && httpShapes.length < 6) httpShapes.push(shape)
    const artifact = record.artifact
    const ext = record as unknown as Record<string, unknown>

    if (record.op === 'capability' || artifact?.kind === 'capability') {
      hasCheckpointOps = true
      if (typeof artifact?.capabilityHandle === 'string' && artifact.capabilityHandle.trim()) {
        sealedHandles.add(artifact.capabilityHandle.trim())
      }
    }
    if (record.op === 'crypto' || artifact?.kind === 'crypto') {
      hasCheckpointOps = true
      cryptoOpCount += 1
      if (typeof artifact?.derivedCapabilityId === 'string' && artifact.derivedCapabilityId.trim()) {
        sealedHandles.add(artifact.derivedCapabilityId.trim())
      }
      if (typeof artifact?.capabilityHandle === 'string' && artifact.capabilityHandle.trim()) {
        sealedHandles.add(artifact.capabilityHandle.trim())
      }
    }
    if (record.op === 'async_poll' || artifact?.kind === 'async_poll' || Boolean(artifact?.pollRecordId)) {
      hasCheckpointOps = true
      asyncPollCount += 1
    }
    if (typeof artifact?.capabilityHandle === 'string' && artifact.capabilityHandle.trim()) {
      hasCheckpointOps = true
      sealedHandles.add(artifact.capabilityHandle.trim())
    }
    if (typeof artifact?.derivedCapabilityId === 'string' && artifact.derivedCapabilityId.trim()) {
      hasCheckpointOps = true
      sealedHandles.add(artifact.derivedCapabilityId.trim())
    }
    if (ext.evidenceRole === 'host_capability_op' || ext.evidenceRole === 'host_crypto_op') {
      hasCheckpointOps = true
      if (ext.evidenceRole === 'host_crypto_op' && record.op !== 'crypto') cryptoOpCount += 1
    }
    if (Array.isArray(ext.emittedCapabilities)) {
      for (const cap of ext.emittedCapabilities) {
        if (typeof cap === 'string' && cap.trim()) {
          hasCheckpointOps = true
          sealedHandles.add(cap.trim())
        }
      }
    }
  }

  const tExt = transcript as unknown as Record<string, unknown>
  if (typeof tExt.capabilitiesSealed === 'number' && tExt.capabilitiesSealed > 0) {
    hasCheckpointOps = true
  }
  if (Array.isArray(tExt.polls) && tExt.polls.length > 0) {
    hasCheckpointOps = true
    asyncPollCount += tExt.polls.length
  }

  return {
    hasCheckpointOps,
    sealedHandles: [...sealedHandles],
    cryptoOpCount,
    asyncPollCount,
    httpShapes,
  }
}

function formatCheckpointNextStepHint(summary: CheckpointTranscriptSummary): string {
  const modeAGuidance = 'NO cross-script state saved — sealed handles expire when this script exits! Combine Hop 1->N in ONE ctx.chain(...).prove() (or ctx.prove_composite(...)) single kovo_verify script to confirm.'
  const shapeSuffix = summary.httpShapes.length > 0 ? ` Observed HTTP: ${summary.httpShapes.join('; ')}.` : ''
  if (summary.sealedHandles.length > 0) {
    const preview = summary.sealedHandles.slice(0, 8).join(', ')
    const extra = summary.sealedHandles.length > 8 ? ` (+${summary.sealedHandles.length - 8} more)` : ''
    return `Incomplete script — no proof claim submitted (ephemeral sealed: ${preview}${extra}). ${modeAGuidance}${shapeSuffix}`
  }
  const parts: string[] = []
  if (summary.cryptoOpCount > 0) parts.push(`${summary.cryptoOpCount} crypto op${summary.cryptoOpCount === 1 ? '' : 's'}`)
  if (summary.asyncPollCount > 0) parts.push(`${summary.asyncPollCount} async poll${summary.asyncPollCount === 1 ? '' : 's'}`)
  const label = parts.length > 0 ? parts.join(', ') : 'host ops without proof'
  return `Incomplete script — no proof claim submitted (${label}). ${modeAGuidance}${shapeSuffix}`
}

function describeFingerprint(fingerprint: CausalFingerprint): string {
  return `${fingerprint.kind}|${fingerprint.method}|${fingerprint.path}|${fingerprint.status}|${JSON.stringify(fingerprint.expectation)}|${JSON.stringify(fingerprint.observed)}`
}

function findUnhandledServerError5xx(
  transcript: TranscriptStore,
  claims: readonly VerifyScriptResult['claims'][number][],
) {
  const hasInjectionErrorClaim = claims.some(c =>
    (c.kind === 'impact' && c.impactClass === 'injection')
    || (c.kind === 'body_contains' && typeof c.vulnClass === 'string' && /sql|inject/i.test(c.vulnClass)),
  )
  if (hasInjectionErrorClaim) return null
  return transcript.list().find(rec =>
    (rec.op === 'http' || rec.op === 'http2' || rec.op === 'race')
    && typeof rec.response?.status === 'number'
    && rec.response.status >= 500
    && rec.response.status <= 599,
  ) ?? null
}

function compareDoubleReplayAttempts(
  first: { report: VerifyAttemptReport; fingerprints: string[] },
  second: { report: VerifyAttemptReport; fingerprints: string[] },
  normFirstTitle: string,
): { ok: true } | { ok: false; detail: string; disagreements: string[] } {
  const disagreements: string[] = []
  if (first.fingerprints.length !== second.fingerprints.length) {
    disagreements.push(`claim count differs: ${first.fingerprints.length} vs ${second.fingerprints.length}`)
  }
  const max = Math.max(first.fingerprints.length, second.fingerprints.length)
  for (let i = 0; i < max; i += 1) {
    if (first.fingerprints[i] !== second.fingerprints[i]) {
      disagreements.push(`claim ${i + 1}: ${first.fingerprints[i] ?? '<missing>'} !== ${second.fingerprints[i] ?? '<missing>'}`)
    }
  }
  if (disagreements.length > 0) {
    return { ok: false, detail: 'Both runs passed, but their transcripts disagree on the causal artifact.', disagreements }
  }
  const normSecondTitle = second.report.title ? normalizeDynamic(second.report.title.slice(0, 1024), second.report.nonce) : ''
  if (!normSecondTitle || normFirstTitle !== normSecondTitle) {
    return { ok: false, detail: 'Runs reported different proof titles.', disagreements: [`title: ${String(first.report.title)} vs ${String(second.report.title)}`] }
  }
  return { ok: true }
}

async function runAttempt(
  options: VerifyScriptOptions,
  attempt: 1 | 2,
  nonce: string,
): Promise<{ report: VerifyAttemptReport; fingerprints: string[]; checkpointOps?: CheckpointTranscriptSummary }> {
  const session = await options.openAttempt({ attempt, nonce })
  try {
    if (session.nonce !== nonce) {
      throw new Error('Attempt session did not adopt the freshly minted nonce.')
    }
    const timeout = AbortSignal.timeout(options.timeoutMs ?? 120_000)
    const deadline = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout
    const execution = await session.execute(options.candidate, deadline)
    const rawResultError = execution.result && typeof execution.result === 'object' && !Array.isArray(execution.result)
      && typeof (execution.result as { error?: unknown }).error === 'string'
      ? (execution.result as { error: string }).error.trim()
      : ''
    const trimmedStderr = execution.stderr.trim()
    const rawStderr = rawResultError && trimmedStderr && !trimmedStderr.includes(rawResultError)
      ? `${rawResultError}\n${trimmedStderr}`
      : (trimmedStderr || rawResultError)
    const base = {
      attempt,
      nonce,
      exitCode: execution.exitCode,
      durationMs: execution.durationMs,
      exchangeCount: session.transcript.size,
      transcriptDigest: session.transcript.digest(),
      signaturesValid: session.transcript.verifySignatures(),
      title: null as string | null,
      causal: [] as CausalFingerprint[],
      oraclePassed: false,
      failures: [] as string[],
      claimCount: 0,
      nonceMismatch: false,
      rejectedBy: null as string | null,
      missingEvidence: [] as string[],
      transcriptSummary: session.transcript.summaries(),
      stderr: redact(rawStderr).slice(0, 2_000),
    }
    if (execution.timedOut) {
      return { report: { ...base, failures: ['Verification script timed out.'], rejectedBy: 'execution', missingEvidence: ['script_completion'] }, fingerprints: [] }
    }
    let parsed: VerifyScriptResult
    try {
      parsed = parseVerifyScriptResult(execution.result)
    } catch (error) {
      const rawTitle = execution.result && typeof execution.result === 'object' && !Array.isArray(execution.result) && typeof (execution.result as { title?: unknown }).title === 'string'
        ? redact((execution.result as { title: string }).title)
        : null
      const latestComp = session.transcript.latestCompositeVerification()
      if (latestComp && !latestComp.confirmed) {
        const compRejectedBy = latestComp.rejectedBy ?? (latestComp.failedStage ? `composite_${latestComp.failedStage}` : 'composite_receipt')
        const compMissing = latestComp.missingEvidence.length > 0 ? latestComp.missingEvidence.map(m => redact(m)) : [compRejectedBy]
        return {
          report: {
            ...base,
            title: rawTitle,
            claimCount: 1,
            failures: [redact(`composite_receipt: CompositeProofReceipt rejected at stage '${latestComp.failedStage ?? 'unknown'}': ${latestComp.reason}`)],
            rejectedBy: compRejectedBy,
            missingEvidence: compMissing,
          },
          fingerprints: [],
        }
      }
      if (execution.exitCode !== 0 || rawResultError.length > 0) {
        const execDetail = redactStderrPreview(rawResultError || execution.stderr)
        const failureMessage = execDetail
          ? `Verification script execution failed (exitCode=${execution.exitCode}): ${execDetail}`
          : `Verification script exited non-zero (exitCode=${execution.exitCode}).`
        return {
          report: {
            ...base,
            title: rawTitle,
            failures: [failureMessage],
            rejectedBy: 'execution',
            missingEvidence: ['script_completion'],
          },
          fingerprints: [],
        }
      }
      const checkpointOps = inspectCheckpointTranscript(session.transcript)
      if (checkpointOps.hasCheckpointOps) {
        const checkpointHint = formatCheckpointNextStepHint(checkpointOps)
        return {
          report: {
            ...base,
            title: rawTitle,
            failures: [checkpointHint],
            rejectedBy: 'checkpoint',
            missingEvidence: ['composite_receipt'],
          },
          fingerprints: [],
          checkpointOps,
        }
      }
      return { report: { ...base, title: rawTitle, failures: [redact(error instanceof Error ? error.message : 'Invalid result.')], rejectedBy: 'claims', missingEvidence: ['valid_proof_document'] }, fingerprints: [] }
    }
    const safeTitle = typeof parsed.title === 'string' ? redact(parsed.title) : null
    if (typeof parsed.nonce === 'string' && parsed.nonce !== nonce) {
      return {
        report: { ...base, title: safeTitle, claimCount: parsed.claims.length, nonceMismatch: true, failures: ['Proof document nonce does not match this attempt; a stale result was replayed.'], rejectedBy: 'nonce', missingEvidence: ['fresh_nonce'] },
        fingerprints: [],
      }
    }
    const descriptorText = `${safeTitle ?? ''} ${parsed.description ?? ''}`
    const declaredCwe = /\bCWE-\d{1,4}\b/i.exec(descriptorText)?.[0] ?? null
    const factLog = HostFactLog.fromTranscriptStore(session.transcript)
    const oracle = evaluateClaims(session.transcript, parsed.claims, {
      factLog,
      ...(options.canary ? { canary: options.canary } : {}),
      allowedExchangeIds: new Set(session.transcript.list().map(record => record.exchangeId)),
      claimedImpact: classifyImpactDescriptor({
        cwe: declaredCwe,
        title: safeTitle ?? undefined,
        description: parsed.description,
      }),
      claimedBoundary: classifyBoundaryClaim({ title: safeTitle ?? undefined }),
    })
    const causal = causalFingerprints(session.transcript, oracle.checks, nonce)
    const serverError5xx = findUnhandledServerError5xx(session.transcript, parsed.claims)
    const oraclePassed = oracle.passed && !serverError5xx
    const serverErrorFailures = serverError5xx
      ? [`HTTP ${serverError5xx.response!.status} server error on ${serverError5xx.exchangeId} (${serverError5xx.request?.method ?? 'HTTP'} ${serverError5xx.request?.pathAndQuery ?? '/'}); verification fails closed on 5xx responses.`]
      : []
    const effectiveRejectedBy = oracle.passed && serverError5xx ? 'server_error' : (oracle.rejectedBy ?? null)
    const missingEvidence = oracle.passed && serverError5xx ? ['non_5xx_clean_response'] : (oracle.missingEvidence ?? []).map(item => redact(item))
    const repairFeedback = oraclePassed ? [] : [
      `rejected-by: ${effectiveRejectedBy ?? 'unknown'}`,
      ...missingEvidence.map(item => `missing-evidence: ${item}`),
      ...session.transcript.summaries().slice(0, 16).map(entry =>
        `transcript-role: ${entry.role ?? 'setup'} ${entry.exchangeId} ${entry.method ?? '-'} ${entry.pathAndQuery ?? '-'} -> ${entry.status ?? 'error'}${entry.personaHandle ? ` persona=${entry.personaHandle}` : ''}`),
    ]
    return {
      report: {
        ...base, title: safeTitle, oraclePassed, claimCount: parsed.claims.length, causal,
        failures: [...oracle.failures, ...serverErrorFailures, ...repairFeedback].map(item => redact(item)),
        rejectedBy: effectiveRejectedBy, missingEvidence,
      },
      fingerprints: causal.map(describeFingerprint),
    }
  } finally {
    await session.close().catch(() => undefined)
  }
}

async function runAttemptSafe(
  options: VerifyScriptOptions,
  attempt: 1 | 2,
  nonce: string,
): Promise<{ report: VerifyAttemptReport; fingerprints: string[]; checkpointOps?: CheckpointTranscriptSummary }> {
  try {
    return await runAttempt(options, attempt, nonce)
  } catch (error) {
    const errMsg = redact(error instanceof Error ? error.message : 'Verification attempt failed to start.')
    return {
      report: {
        attempt,
        nonce,
        exitCode: 1,
        durationMs: 0,
        oraclePassed: false,
        failures: [errMsg],
        claimCount: 0,
        exchangeCount: 0,
        transcriptDigest: '',
        signaturesValid: false,
        causal: [],
        title: null,
        nonceMismatch: false,
        rejectedBy: 'execution',
        missingEvidence: [error instanceof Error ? errMsg.slice(0, 120) : 'attempt_start'],
        transcriptSummary: [],
      },
      fingerprints: [],
    }
  }
}

/**
 * Run the candidate in a fresh isolated clean session with a host-minted cryptographic nonce
 * (1x clean host-signed replay default; pass `doubleReplay: true` to also execute Attempt 2
 * and require cross-attempt causal fingerprint agreement). Confirmation requires:
 *   1. clean execution with exitCode 0 (no crash, timeout, or unhandled 5xx),
 *   2. transcript-backed claims returned and passed by the host transcript oracle (stdout is never evidence),
 *   3. HMAC-signed transcript signatures verify,
 *   4. the proof document echoes its freshly minted attempt nonce,
 *   5. when `doubleReplay: true`, distinct nonces and matching normalized causal fingerprints & titles across both runs.
 */
export async function verifyScript(options: VerifyScriptOptions): Promise<VerifyVerdict> {
  const aliasHits = detectKovoVerifyScriptAliases(options.candidate.code)
  const runDoubleReplay = options.doubleReplay === true
  const nonces: [string, string] = [randomBytes(16).toString('hex'), randomBytes(16).toString('hex')]
  const first = await runAttemptSafe(options, 1, nonces[0])
  const fastFailFirst = options.fastFailOnAttempt1 === true
    && (first.report.rejectedBy === 'execution' || first.report.rejectedBy === 'checkpoint')
  const second = (runDoubleReplay && !fastFailFirst) ? await runAttemptSafe(options, 2, nonces[1]) : null
  const attempts = second ? [first.report, second.report] : [first.report]
  const detailBase = runDoubleReplay
    ? (second
        ? `first=${first.report.oraclePassed ? 'pass' : 'fail'} second=${second.report.oraclePassed ? 'pass' : 'fail'}`
        : `first=${first.report.oraclePassed ? 'pass' : 'fail'} second=skipped`)
    : `first=${first.report.oraclePassed ? 'pass' : 'fail'}`
  // The repair contract: name the rejecting validator, the exact missing evidence, and the
  // role-labelled transcript, so the agent can repair in one turn instead of guessing.
  const feedback = (includeScriptDiagnostics = false) => {
    const failed = attempts.filter(report => !report.oraclePassed)
    const source = failed.length > 0 ? failed : attempts
    const failingExit = source.find(report => report.exitCode !== 0)?.exitCode ?? source[0]?.exitCode
    const rawStderr = source.map(report => report.stderr ?? '').find(text => text.trim().length > 0) ?? ''
    const stderrPreview = redactStderrPreview(rawStderr)
    const showDiagnostics = includeScriptDiagnostics || (typeof failingExit === 'number' && failingExit !== 0) || stderrPreview.length > 0
    const primaryRejectedBy =
      source.find(report => report.rejectedBy !== null && report.rejectedBy !== 'checkpoint')?.rejectedBy
      ?? source.find(report => report.rejectedBy !== null)?.rejectedBy
      ?? null
    return {
      rejectedBy: primaryRejectedBy,
      missingEvidence: [...new Set(source.flatMap(report => report.missingEvidence.map(item => redact(item))))],
      transcriptSummary: source[0]?.transcriptSummary ?? [],
      ...(showDiagnostics && typeof failingExit === 'number' ? { exitCode: failingExit } : {}),
      ...(showDiagnostics ? { stderrPreview } : {}),
      ...(includeScriptDiagnostics ? { usageHint: KOVO_VERIFY_USAGE_HINT } : {}),
      ...(aliasHits.length > 0 ? { aliasHits } : {}),
    }
  }
  const withFeedback = <T extends Omit<VerifyVerdict, 'rejectedBy' | 'missingEvidence' | 'transcriptSummary'>>(
    value: T,
    includeScriptDiagnostics = false,
  ): VerifyVerdict => ({
    ...value,
    claimTitle: typeof value.claimTitle === 'string' ? redact(value.claimTitle) : value.claimTitle,
    disagreements: value.disagreements.map(item => redact(item)),
    detail: redact(value.detail),
    ...feedback(includeScriptDiagnostics),
  })

  if (second && first.report.nonce === second.report.nonce) {
    return withFeedback({ confirmed: false, reason: 'nonce_reuse', detail: 'Both attempts used the same nonce; sessions were not fresh.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (attempts.some(a => a.nonceMismatch)) {
    return withFeedback({ confirmed: false, reason: 'nonce_mismatch', detail: 'A proof document did not match its fresh attempt nonce.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  const checkpointSummaries = [first.checkpointOps, second?.checkpointOps]
    .filter((summary): summary is CheckpointTranscriptSummary => Boolean(summary?.hasCheckpointOps))
  if (
    checkpointSummaries.length > 0
    && attempts.every(a => a.exitCode === 0 && a.claimCount === 0 && a.rejectedBy !== 'execution' && a.signaturesValid)
  ) {
    const merged: CheckpointTranscriptSummary = {
      hasCheckpointOps: true,
      sealedHandles: [...new Set(checkpointSummaries.flatMap(s => s.sealedHandles))],
      cryptoOpCount: checkpointSummaries.reduce((acc, s) => acc + s.cryptoOpCount, 0),
      asyncPollCount: checkpointSummaries.reduce((acc, s) => acc + s.asyncPollCount, 0),
      httpShapes: [...new Set(checkpointSummaries.flatMap(s => s.httpShapes))].slice(0, 6),
    }
    const checkpointHint = formatCheckpointNextStepHint(merged)
    return {
      ...withFeedback({
        confirmed: false,
        reason: 'checkpoint_only',
        detail: checkpointHint,
        attempts,
        disagreements: [],
        claimTitle: first.report.title ?? second?.report.title ?? null,
        usageHint: checkpointHint,
      }, false),
      rejectedBy: 'checkpoint',
      missingEvidence: ['composite_receipt'],
    }
  }
  if (attempts.some(a => a.claimCount === 0)) {
    const diag = feedback(true)
    const suffix = diag.stderrPreview
      ? ` (exitCode=${diag.exitCode ?? 0}: ${diag.stderrPreview.slice(0, 200)})`
      : (typeof diag.exitCode === 'number' && diag.exitCode !== 0 ? ` (exitCode=${diag.exitCode})` : '')
    return withFeedback({
      confirmed: false,
      reason: 'claims_missing',
      detail: `At least one run returned no transcript-backed claims${suffix}.`,
      attempts,
      disagreements: [],
      claimTitle: first.report.title,
    }, true)
  }
  if (attempts.some(a => a.exitCode !== 0)) {
    const diag = feedback(true)
    const suffix = diag.stderrPreview ? `: ${diag.stderrPreview.slice(0, 200)}` : ''
    return {
      ...withFeedback({
        confirmed: false,
        reason: 'execution_failed',
        detail: `A verification run exited non-zero (${detailBase}, exitCode=${diag.exitCode ?? 1}${suffix}).`,
        attempts,
        disagreements: [],
        claimTitle: first.report.title,
      }, true),
      rejectedBy: diag.rejectedBy && diag.rejectedBy !== 'claims' ? diag.rejectedBy : 'execution',
    }
  }
  if (!attempts.every(a => a.signaturesValid)) {
    return withFeedback({ confirmed: false, reason: 'transcript_mismatch', detail: 'A transcript failed signature verification.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (!attempts.every(a => a.oraclePassed)) {
    const compFail = attempts.flatMap(a => a.failures).find(f => f.startsWith('composite_receipt:'))
    return withFeedback({
      confirmed: false,
      reason: 'oracle_failed',
      detail: compFail
        ? `${compFail} (${detailBase}).`
        : `Claims did not survive transcript re-check (${detailBase}).`,
      attempts,
      disagreements: [],
      claimTitle: first.report.title,
    })
  }
  const normFirstTitle = first.report.title ? normalizeDynamic(first.report.title.slice(0, 1024), first.report.nonce) : ''
  if (!normFirstTitle) {
    return withFeedback({ confirmed: false, reason: 'transcript_mismatch', detail: 'Verification run did not report a valid proof title.', attempts, disagreements: [`title: ${String(first.report.title)}`], claimTitle: first.report.title })
  }
  if (!runDoubleReplay) {
    return withFeedback({ confirmed: true, reason: 'confirmed', detail: `Fresh 1x clean host-signed replay passed the transcript oracle (${detailBase}).`, attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (!second) {
    return withFeedback({ confirmed: false, reason: 'execution_failed', detail: `Verification run failed on attempt 1 (${detailBase}).`, attempts, disagreements: [], claimTitle: first.report.title }, true)
  }
  const cmp = compareDoubleReplayAttempts(first, second, normFirstTitle)
  if (!cmp.ok) {
    return withFeedback({ confirmed: false, reason: 'transcript_mismatch', detail: cmp.detail, attempts, disagreements: cmp.disagreements, claimTitle: first.report.title })
  }
  return withFeedback({ confirmed: true, reason: 'confirmed', detail: `Both fresh runs passed the transcript oracle with identical causal artifacts (${detailBase}).`, attempts, disagreements: [], claimTitle: first.report.title })
}

// ---------------------------------------------------------------------------
// Local (host-side) attempt factory + script runner
// ---------------------------------------------------------------------------

const RESULT_FILE_MAX_BYTES = 1024 * 1024
const SCRIPT_OUTPUT_MAX_BYTES = 512 * 1024

function copySdkFiles(sdkDir: string, targetDir: string) {
  if (!existsSync(sdkDir)) throw new Error('kovo_verify SDK directory is missing.')
  const file = 'kovo_verify.ts'
  const source = join(sdkDir, file)
  if (!existsSync(source)) throw new Error('kovo_verify.ts SDK file is missing.')
  if (statSync(source).size > 256 * 1024) throw new Error('SDK file exceeds the size limit.')
  copyFileSync(source, join(targetDir, basename(file)))
  chmodSync(join(targetDir, basename(file)), 0o644)
}


export interface LocalAttemptServer {
  readonly hostDir: string
  readonly socketPath: string
  readonly transcript: TranscriptStore
  start(): Promise<unknown>
  close(): Promise<void>
}

export interface LocalAttemptFactoryBaseOptions {
  sdkDir: string
  nodePath?: string
  timeoutMs?: number
  /** Cap for stdout/stderr returned to the verifier (script stdout is never evidence anyway). */
  maxOutputBytes?: number
}

export function buildLocalAttemptFactory(
  options: LocalAttemptFactoryBaseOptions,
  createServer: (nonce: string, attempt: 1 | 2) => LocalAttemptServer,
) {
  return async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const server = createServer(input.nonce, input.attempt)
    await server.start()
    return {
      nonce: input.nonce,
      transcript: server.transcript,
      async execute(candidate, signal) {
        return runCandidateLocally(candidate, {
          socketPath: server.socketPath,
          tokenPath: join(server.hostDir, VERIFY_RPC_TOKEN_NAME),
          contextPath: join(server.hostDir, VERIFY_RPC_CONTEXT_NAME),
          nonce: input.nonce,
          sdkDir: options.sdkDir,
          ...(options.nodePath ? { nodePath: options.nodePath } : {}),
          ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
          ...(options.maxOutputBytes ? { maxOutputBytes: options.maxOutputBytes } : {}),
          signal,
        })
      },
      async close() {
        await server.close()
      },
    }
  }
}

export interface RunCandidateLocallyOptions {
  socketPath: string
  tokenPath: string
  contextPath: string
  nonce: string
  sdkDir: string
  nodePath?: string
  timeoutMs?: number
  maxOutputBytes?: number
  signal?: AbortSignal
}

export async function runCandidateLocally(
  candidate: VerificationCandidate,
  options: RunCandidateLocallyOptions,
): Promise<AttemptExecution> {
  if (candidate.runtime !== 'ts') {
    throw new Error(`Unsupported verification runtime: ${String(candidate.runtime)}. kovo_verify supports TypeScript only (runtime='ts').`)
  }
  const dir = mkdtempSync(join(tmpdir(), 'kovo-verify-candidate-'))
  const resultPath = join(dir, 'result.json')
  try {
    copySdkFiles(options.sdkDir, dir)
    const scriptPath = join(dir, 'candidate.ts')
    const preparedCode = prepareVerifyScript(candidate.code, 'ts', candidate.title)
    writeFileSync(scriptPath, preparedCode, { mode: 0o600 })
    const command = options.nodePath ?? process.execPath
    const args = [scriptPath]
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      [VERIFY_RPC_SOCKET_ENV]: options.socketPath,
      [VERIFY_RPC_TOKEN_ENV]: options.tokenPath,
      [VERIFY_RPC_CONTEXT_ENV]: options.contextPath,
      [VERIFY_NONCE_ENV]: options.nonce,
      [VERIFY_RESULT_ENV]: resultPath,
    }
    const started = Date.now()
    const outcome = await new Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }>((resolve, reject) => {
      const child = spawn(command, args, { cwd: dir, env, stdio: ['ignore', 'pipe', 'pipe'] })
      const maxBytes = options.maxOutputBytes ?? SCRIPT_OUTPUT_MAX_BYTES
      let stdout = ''
      let stderr = ''
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        try { child.kill('SIGKILL') } catch { /* ignore */ }
      }, options.timeoutMs ?? 90_000)
      timer.unref()
      child.stdout?.on('data', (chunk: Buffer) => { if (stdout.length < maxBytes) stdout += chunk.toString('utf8').slice(0, maxBytes - stdout.length) })
      child.stderr?.on('data', (chunk: Buffer) => { if (stderr.length < maxBytes) stderr += chunk.toString('utf8').slice(0, maxBytes - stderr.length) })
      const abortHandler = () => { try { child.kill('SIGKILL') } catch { /* ignore */ } }
      options.signal?.addEventListener('abort', abortHandler, { once: true })
      child.once('error', error => { clearTimeout(timer); options.signal?.removeEventListener('abort', abortHandler); reject(error) })
      child.once('close', code => {
        clearTimeout(timer)
        options.signal?.removeEventListener('abort', abortHandler)
        resolve({ code, stdout, stderr, timedOut: timedOut || Boolean(options.signal?.aborted) })
      })
    })
    let result: unknown = null
    if (existsSync(resultPath)) {
      const raw = readFileSync(resultPath, 'utf8')
      if (Buffer.byteLength(raw) <= RESULT_FILE_MAX_BYTES) {
        try { result = JSON.parse(raw) } catch { result = null }
      }
    }
    return {
      result,
      stdout: outcome.stdout,
      stderr: outcome.stderr,
      exitCode: outcome.code ?? (outcome.timedOut ? 124 : 1),
      durationMs: Date.now() - started,
      ...(outcome.timedOut ? { timedOut: true } : {}),
    }
  } finally {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
}
