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

export const GUARDIAN_VERIFY_STDERR_PREVIEW_MAX_CHARS = 400

export const GUARDIAN_VERIFY_USAGE_HINT =
  'Inline TS scripts receive `ctx` directly (no imports required): `await ctx.prove_access_boundary({ controlPersona, probePersona, route }); return ctx.result({ title: "..." })` (or `export default async (ctx) => { ... }`). Python `ctx.*` helpers are synchronous (no `await` needed).'

/** Strip accidental outer markdown code fences (```ts ... ``` / ```python ... ```) from LLM scripts. */
function stripCodeFences(rawCode: string): string {
  const trimmed = rawCode.trim()
  const match = /^```[a-zA-Z0-9_-]*[ \t]*\r?\n([\s\S]*?)\r?\n```$/.exec(trimmed)
  return match ? match[1]! : rawCode
}

/** Redact credential-shaped tokens and bound stderr preview to 400 chars for repair feedback. */
export function redactStderrPreview(raw: string, maxChars = GUARDIAN_VERIFY_STDERR_PREVIEW_MAX_CHARS): string {
  const cleaned = redact(raw ?? '').replace(/\u001b\[[0-9;]*m/g, '').trim()
  if (!cleaned) return ''
  return cleaned.length <= maxChars ? cleaned : `${cleaned.slice(0, Math.max(0, maxChars - 3))}...`
}

function normalizeTsSdkImports(code: string): string {
  return code
    .replace(/(\bfrom\s*)(['"])(?:\.\/)?guardian_verify(?:\.(?:ts|mts|js|mjs))?\2/g, "$1'./guardian_verify.ts'")
    .replace(/\bimport\(\s*(['"])(?:\.\/)?guardian_verify(?:\.(?:ts|mts|js|mjs))?\1\s*\)/g, "import('./guardian_verify.ts')")
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
 * Normalize an inline `guardian_verify` script so every documented authoring style works identically:
 *   1. Explicit `runVerification(...)` / `runEntrypoint(...)` / `GUARDIAN_PROOF_RESULT_FILE` -> run as-is (with SDK import paths normalized).
 *   2. `export default async (ctx) => ...` / `export default defineVerification(...)` / `export default { verify(ctx) {} }` -> invoke via `runEntrypoint`.
 *   3. Named `export async function verify(ctx)` / `async function verify(ctx)` -> invoke via `runEntrypoint`.
 *   4. Bare inline script body using `ctx` (`await ctx.prove_access_boundary(...)`) -> wrap in `runEntrypoint(async (ctx) => { ... })`.
 *   5. Standalone scripts without `ctx` (e.g. stdout-only or raw probes) -> run verbatim (fail closed as `claims_missing`).
 *
 * Idempotent: calling twice produces the exact same output. Never fabricates claims.
 */
export function prepareVerifyScript(rawCode: string, runtime: 'ts' | 'python', defaultTitle?: string): string {
  const unfenced = stripCodeFences(rawCode)
  const trimmed = unfenced.trim()
  if (!trimmed) return rawCode
  const titleLiteral = JSON.stringify(defaultTitle?.trim() || 'Verification script proof')

  if (runtime === 'python') {
    if (/\b(?:run|run_entrypoint|_guardian_run)\s*\(/.test(trimmed) || /\bGUARDIAN_PROOF_RESULT_FILE\b/.test(trimmed)) {
      return unfenced
    }
    if (/^[ \t]*(?:async\s+)?def\s+verify\s*\(/m.test(trimmed)) {
      return [
        unfenced,
        '',
        'from guardian_verify import run_entrypoint as _guardian_run',
        `_guardian_run(verify, setup=globals().get("setup"), cleanup=globals().get("cleanup"), default_title=${titleLiteral})`,
        '',
      ].join('\n')
    }
    if (/\bctx\b/.test(trimmed)) {
      const defPrefix = /\bawait\b/.test(trimmed) ? 'async def' : 'def'
      const indented = unfenced
        .split(/\r?\n/)
        .map(line => (line.trim() ? `    ${line}` : ''))
        .join('\n')
      return [
        'from guardian_verify import run_entrypoint as _guardian_run',
        '',
        `${defPrefix} _guardian_inline_verify(ctx):`,
        indented,
        '',
        `_guardian_run(_guardian_inline_verify, default_title=${titleLiteral})`,
        '',
      ].join('\n')
    }
    return unfenced
  }

  // TypeScript runtime
  const normalized = normalizeTsSdkImports(unfenced)
  if (
    /\b(?:runVerification|runEntrypoint|__guardian_run)\s*\(/.test(normalized)
    || /\bGUARDIAN_PROOF_RESULT_FILE\b/.test(normalized)
  ) {
    return normalized
  }

  const needsDefineAlias = /\bdefineVerification\s*\(/.test(normalized)
    && !/\bimport\b[^;]*\bdefineVerification\b/.test(normalized)
  const sdkImport = needsDefineAlias
    ? "import { defineVerification, runEntrypoint as __guardian_run } from './guardian_verify.ts'\n"
    : "import { runEntrypoint as __guardian_run } from './guardian_verify.ts'\n"

  const exportDefaultRe = /(^|;[ \t]*|\n[ \t]*)export\s+default\s+/
  if (exportDefaultRe.test(normalized)) {
    const rewritten = normalized.replace(exportDefaultRe, '$1const __guardian_default_export = ')
    return `${sdkImport}${rewritten}\n;\nawait __guardian_run(__guardian_default_export, ${titleLiteral})\n`
  }

  const hasExportVerify = /^[ \t]*export\s+(?:(?:async\s+)?function\s+verify\s*\(|(?:const|let|var)\s+verify\s*=)/m.test(normalized)
  const hasTopLevelVerify = /^[ \t]*(?:async\s+)?function\s+verify\s*\(/m.test(normalized)
  if (hasExportVerify || hasTopLevelVerify) {
    const hasSetup = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+setup\s*\(|(?:const|let|var)\s+setup\s*=)/m.test(normalized)
    const hasCleanup = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+cleanup\s*\(|(?:const|let|var)\s+cleanup\s*=)/m.test(normalized)
    const hooks = ['verify', ...(hasSetup ? ['setup'] : []), ...(hasCleanup ? ['cleanup'] : [])].join(', ')
    return `${sdkImport}${normalized}\n;\nawait __guardian_run({ ${hooks} }, ${titleLiteral})\n`
  }

  if (/\bctx\b/.test(normalized)) {
    const { imports, body } = splitLeadingTsImports(normalized)
    const prefix = imports ? `${sdkImport}${imports}\n` : sdkImport
    const bodyTrimmed = body.trim()
    // Standalone function expression (e.g. `async (ctx) => { ... }` or `async function(ctx) { ... }`)
    const isStandaloneFnExpr = /^(?:async\s+)?(?:\(\s*ctx\b[^)]*\)\s*=>|ctx\s*=>|function\s*(?:[A-Za-z_$][\w$]*)?\s*\(\s*ctx\b[^)]*\))/.test(bodyTrimmed)
    if (isStandaloneFnExpr) {
      const expr = bodyTrimmed.replace(/;\s*$/, '')
      return `${prefix}await __guardian_run((\n${expr}\n), ${titleLiteral})\n`
    }
    return `${prefix}await __guardian_run(async (ctx) => {\n${body}\n}, ${titleLiteral})\n`
  }

  return normalized
}

export interface VerificationCandidate {
  name: string
  runtime: 'ts' | 'python'
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
}

export interface VerifyScriptOptions {
  candidate: VerificationCandidate
  /** Must create a genuinely fresh session (new broker jars, new transcript) per attempt. */
  openAttempt: (input: { attempt: 1 | 2; nonce: string }) => Promise<VerifyAttemptSession>
  signal?: AbortSignal
  canary?: VerifyCanaryBroker
  timeoutMs?: number
}

function describeFingerprint(fingerprint: CausalFingerprint): string {
  return `${fingerprint.kind}|${fingerprint.method}|${fingerprint.path}|${fingerprint.status}|${JSON.stringify(fingerprint.expectation)}|${JSON.stringify(fingerprint.observed)}`
}

async function runAttempt(
  options: VerifyScriptOptions,
  attempt: 1 | 2,
  nonce: string,
): Promise<{ report: VerifyAttemptReport; fingerprints: string[] }> {
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
      ? (execution.result as { error: string }).error
      : ''
    const rawStderr = execution.stderr.trim() ? execution.stderr : rawResultError
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
      const latestComp = session.transcript.latestCompositeVerification()
      if (latestComp && !latestComp.confirmed) {
        const compRejectedBy = latestComp.rejectedBy ?? (latestComp.failedStage ? `composite_${latestComp.failedStage}` : 'composite_receipt')
        const compMissing = latestComp.missingEvidence.length > 0 ? latestComp.missingEvidence : [compRejectedBy]
        const rawTitle = execution.result && typeof execution.result === 'object' && !Array.isArray(execution.result) && typeof (execution.result as { title?: unknown }).title === 'string'
          ? (execution.result as { title: string }).title
          : null
        return {
          report: {
            ...base,
            title: rawTitle,
            claimCount: 1,
            failures: [`composite_receipt: CompositeProofReceipt rejected at stage '${latestComp.failedStage ?? 'unknown'}': ${latestComp.reason}`],
            rejectedBy: compRejectedBy,
            missingEvidence: compMissing,
          },
          fingerprints: [],
        }
      }
      return { report: { ...base, failures: [error instanceof Error ? error.message : 'Invalid result.'], rejectedBy: 'claims', missingEvidence: ['valid_proof_document'] }, fingerprints: [] }
    }
    if (typeof parsed.nonce === 'string' && parsed.nonce !== nonce) {
      return {
        report: { ...base, title: parsed.title ?? null, claimCount: parsed.claims.length, nonceMismatch: true, failures: ['Proof document nonce does not match this attempt; a stale result was replayed.'], rejectedBy: 'nonce', missingEvidence: ['fresh_nonce'] },
        fingerprints: [],
      }
    }
    const descriptorText = `${parsed.title ?? ''} ${parsed.description ?? ''}`
    const declaredCwe = /\bCWE-\d{1,4}\b/i.exec(descriptorText)?.[0] ?? null
    const oracle = evaluateClaims(session.transcript, parsed.claims, {
      ...(options.canary ? { canary: options.canary } : {}),
      allowedExchangeIds: new Set(session.transcript.list().map(record => record.exchangeId)),
      claimedImpact: classifyImpactDescriptor({
        cwe: declaredCwe,
        title: parsed.title,
        description: parsed.description,
      }),
      claimedBoundary: classifyBoundaryClaim({ title: parsed.title }),
    })
    const causal = causalFingerprints(session.transcript, oracle.checks, nonce)
    const missingEvidence = oracle.missingEvidence ?? []
    const repairFeedback = oracle.passed ? [] : [
      `rejected-by: ${oracle.rejectedBy ?? 'unknown'}`,
      ...missingEvidence.map(item => `missing-evidence: ${item}`),
      ...session.transcript.summaries().slice(0, 16).map(entry =>
        `transcript-role: ${entry.role ?? 'setup'} ${entry.exchangeId} ${entry.method ?? '-'} ${entry.pathAndQuery ?? '-'} -> ${entry.status ?? 'error'}${entry.personaHandle ? ` persona=${entry.personaHandle}` : ''}`),
    ]
    return {
      report: {
        ...base,
        title: parsed.title ?? null,
        oraclePassed: oracle.passed,
        failures: [...oracle.failures, ...repairFeedback],
        claimCount: parsed.claims.length,
        causal,
        rejectedBy: oracle.rejectedBy ?? null,
        missingEvidence,
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
): Promise<{ report: VerifyAttemptReport; fingerprints: string[] }> {
  try {
    return await runAttempt(options, attempt, nonce)
  } catch (error) {
    return {
      report: {
        attempt,
        nonce,
        exitCode: 1,
        durationMs: 0,
        oraclePassed: false,
        failures: [error instanceof Error ? error.message : 'Verification attempt failed to start.'],
        claimCount: 0,
        exchangeCount: 0,
        transcriptDigest: '',
        signaturesValid: false,
        causal: [],
        title: null,
        nonceMismatch: false,
        rejectedBy: 'execution',
        missingEvidence: [error instanceof Error ? error.message.slice(0, 120) : 'attempt_start'],
        transcriptSummary: [],
      },
      fingerprints: [],
    }
  }
}

/**
 * Run the candidate twice from scratch with fresh nonces/sessions. Confirmation requires:
 *   1. both runs executed and returned claims,
 *   2. both transcript oracles passed (stdout is never evidence),
 *   3. both transcripts' signatures verify,
 *   4. the causal fingerprints agree across runs,
 *   5. the nonces differ and each proof document echoes its own attempt nonce.
 */
export async function verifyScript(options: VerifyScriptOptions): Promise<VerifyVerdict> {
  const nonces: [string, string] = [randomBytes(16).toString('hex'), randomBytes(16).toString('hex')]
  const first = await runAttemptSafe(options, 1, nonces[0])
  const second = await runAttemptSafe(options, 2, nonces[1])
  const attempts = [first.report, second.report]
  const detailBase = `first=${first.report.oraclePassed ? 'pass' : 'fail'} second=${second.report.oraclePassed ? 'pass' : 'fail'}`
  // The repair contract: name the rejecting validator, the exact missing evidence, and the
  // role-labelled transcript, so the agent can repair in one turn instead of guessing.
  const feedback = (includeScriptDiagnostics = false) => {
    const failed = attempts.filter(report => !report.oraclePassed)
    const source = failed.length > 0 ? failed : attempts
    const failingExit = source.find(report => report.exitCode !== 0)?.exitCode ?? source[0]?.exitCode
    const rawStderr = source.map(report => report.stderr ?? '').find(text => text.trim().length > 0) ?? ''
    const stderrPreview = redactStderrPreview(rawStderr)
    const showDiagnostics = includeScriptDiagnostics || (typeof failingExit === 'number' && failingExit !== 0) || stderrPreview.length > 0
    return {
      rejectedBy: source.find(report => report.rejectedBy !== null)?.rejectedBy ?? null,
      missingEvidence: [...new Set(source.flatMap(report => report.missingEvidence))],
      transcriptSummary: source[0]?.transcriptSummary ?? [],
      ...(showDiagnostics && typeof failingExit === 'number' ? { exitCode: failingExit } : {}),
      ...(showDiagnostics ? { stderrPreview } : {}),
      ...(includeScriptDiagnostics ? { usageHint: GUARDIAN_VERIFY_USAGE_HINT } : {}),
    }
  }
  const withFeedback = <T extends Omit<VerifyVerdict, 'rejectedBy' | 'missingEvidence' | 'transcriptSummary'>>(
    value: T,
    includeScriptDiagnostics = false,
  ): VerifyVerdict => ({ ...value, ...feedback(includeScriptDiagnostics) })

  if (first.report.nonce === second.report.nonce) {
    return withFeedback({ confirmed: false, reason: 'nonce_reuse', detail: 'Both attempts used the same nonce; sessions were not fresh.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (attempts.some(a => a.nonceMismatch)) {
    return withFeedback({ confirmed: false, reason: 'nonce_mismatch', detail: 'A proof document did not match its fresh attempt nonce.', attempts, disagreements: [], claimTitle: first.report.title })
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
    return withFeedback({
      confirmed: false,
      reason: 'execution_failed',
      detail: `A verification run exited non-zero (${detailBase}, exitCode=${diag.exitCode ?? 1}${suffix}).`,
      attempts,
      disagreements: [],
      claimTitle: first.report.title,
    }, true)
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
    return withFeedback({
      confirmed: false,
      reason: 'transcript_mismatch',
      detail: 'Both runs passed, but their transcripts disagree on the causal artifact.',
      attempts,
      disagreements,
      claimTitle: first.report.title,
    })
  }
  if (!first.report.title || !second.report.title || first.report.title !== second.report.title) {
    return withFeedback({
      confirmed: false,
      reason: 'transcript_mismatch',
      detail: 'Runs reported different proof titles.',
      attempts,
      disagreements: [`title: ${String(first.report.title)} vs ${String(second.report.title)}`],
      claimTitle: first.report.title,
    })
  }
  return withFeedback({
    confirmed: true,
    reason: 'confirmed',
    detail: `Both fresh runs passed the transcript oracle with identical causal artifacts (${detailBase}).`,
    attempts,
    disagreements: [],
    claimTitle: first.report.title,
  })
}

// ---------------------------------------------------------------------------
// Local (host-side) attempt factory + script runner
// ---------------------------------------------------------------------------

const RESULT_FILE_MAX_BYTES = 1024 * 1024
const SCRIPT_OUTPUT_MAX_BYTES = 512 * 1024

function copySdkFiles(sdkDir: string, targetDir: string) {
  if (!existsSync(sdkDir)) throw new Error('guardian_verify SDK directory is missing.')
  for (const file of ['guardian_verify.ts', 'guardian_verify.py']) {
    const source = join(sdkDir, file)
    if (!existsSync(source)) continue
    if (statSync(source).size > 256 * 1024) throw new Error('SDK file exceeds the size limit.')
    copyFileSync(source, join(targetDir, basename(file)))
    chmodSync(join(targetDir, basename(file)), 0o644)
  }
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
  pythonPath?: string
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
          ...(options.pythonPath ? { pythonPath: options.pythonPath } : {}),
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
  pythonPath?: string
  timeoutMs?: number
  maxOutputBytes?: number
  signal?: AbortSignal
}

export async function runCandidateLocally(
  candidate: VerificationCandidate,
  options: RunCandidateLocallyOptions,
): Promise<AttemptExecution> {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-verify-candidate-'))
  const resultPath = join(dir, 'result.json')
  try {
    copySdkFiles(options.sdkDir, dir)
    const extension = candidate.runtime === 'python' ? '.py' : '.ts'
    const scriptPath = join(dir, `candidate${extension}`)
    const preparedCode = prepareVerifyScript(candidate.code, candidate.runtime, candidate.title)
    writeFileSync(scriptPath, preparedCode, { mode: 0o600 })
    const command = candidate.runtime === 'python'
      ? (options.pythonPath ?? 'python3')
      : (options.nodePath ?? process.execPath)
    const args = candidate.runtime === 'python' ? ['-s', scriptPath] : [scriptPath]
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
