#!/usr/bin/env node
/**
 * Move 1 — 3-Second Offline Receipt / Transcript Replay Harness.
 *
 * Replays captured `CompositeProofReceipt` + `HostSignedTranscript` bundles from live runs
 * against the current `verifyCompositeReceipt()` (with `defaultTerminalOracleRegistry`) and
 * optionally grades a `ProductGradeInput` bundle via `gradeRun`, in <3 seconds for $0.
 *
 * Strictly prints sanitized structured diff metrics only — never raw HTTP bodies, credentials,
 * or probe strings.
 *
 * Usage:
 *   node --experimental-strip-types scripts/replay-v8-receipts.ts \
 *     --dir <corpus-dir> [--only-failed] [--grade-bundle <path>] [--json <out.json>] [--fail-on-regression]
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, join, posix, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type CompositeReceiptVerification,
  type CompositeVerifyOptions,
  type HostSignableRecord,
  type HostSignedTranscript,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import { redact } from '../src/server/redact.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'

export const REPLAY_TEST_SIGNING_KEY = 'kovo-offline-replay-deterministic-signing-key-v1'

export interface CapturedVerdict {
  confirmed: boolean
  failedStage?: string | null
  rejectedBy?: string | null
  reason?: string | null
  terminalOracleFamily?: string | null
  terminalEndpoint?: string | null
}

export interface VerifyCorpusCapture {
  schemaVersion?: number
  capturedAt?: string
  app?: string
  runId?: string
  assignmentId?: string
  expected?: {
    confirmed?: boolean
    side?: 'tp' | 'fp'
  }
  receipt: CompositeProofReceipt | unknown
  transcript: HostSignedTranscript
  signingKey?: string
  verifyOptions?: Omit<CompositeVerifyOptions, 'signingKey' | 'factLog' | 'oracleEvaluator' | 'verifyTerminalImpact'>
  verdict: CapturedVerdict
  gradeBundle?: Record<string, unknown>
}

export type ReplayDiffBucket = 'flipped_pass' | 'regressed_fail' | 'still_pass' | 'still_fail'

export interface ReplayCaseResult {
  file: string
  index: number
  app: string
  runId: string
  chainId: string
  terminalVulnClass: string
  bucket: ReplayDiffBucket
  isTpRegression: boolean
  resigned: boolean
  prevConfirmed: boolean
  nextConfirmed: boolean
  prevRejectedBy: string
  prevReasonSig: string
  nextRejectedBy: string
  nextFailedStage: string | null
  nextReasonSig: string
  elapsedMs: number
}

export interface ReplayHistogramEntry {
  rejectedBy: string
  reasonSig: string
  count: number
}

export interface ReplayGradeSummary {
  source: string
  app: string
  seed: number | null
  mode: string
  recall: number
  precision: number
  confirmedChains: number
  expectedChains: number
  fpCount: number
}

export interface ReplayCorpusReport {
  dir: string
  onlyFailed: boolean
  totalLoaded: number
  totalReplayed: number
  skippedPassing: number
  durationMs: number
  parseErrors: Array<{ file: string; error: string }>
  flippedFailToPass: {
    count: number
    byOriginalReason: ReplayHistogramEntry[]
    cases: ReplayCaseResult[]
  }
  regressedPassToFail: {
    count: number
    tpCount: number
    cases: ReplayCaseResult[]
  }
  stillPassing: {
    count: number
  }
  stillFailing: {
    count: number
    histogram: ReplayHistogramEntry[]
  }
  gradeSummary?: ReplayGradeSummary
}

export interface ReplayCorpusOptions {
  dir: string
  onlyFailed?: boolean
  forceResign?: boolean
  gradeBundlePath?: string
  signingKey?: string
}

/**
 * Sanitize a rejection or failure reason into a compact, secret-free signature (<= 140 chars).
 * Strips PEM keys, raw HTTP/HTML/JSON bodies, tokens/JWTs/credentials, and dynamic IDs/ports.
 */
export function sanitizeReplayReason(raw: unknown): string {
  if (typeof raw !== 'string') return 'unknown'
  const pemScrubbed = raw.replace(/-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g, '<scrubbed>')
  const lines = pemScrubbed.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  if (!lines.length) return 'unknown'
  let picked = lines[0]!
  if (lines.length > 1) {
    const errLine = lines.find(l => /\b(?:[A-Z][A-Za-z0-9]*Error|Exception|ERR_[A-Z0-9_]+|AssertionError)\b/.test(l))
    if (errLine) picked = errLine
  }
  const bodyStripped = picked
    .replace(/^CompositeProofReceipt rejected at stage ['"][^'"]+['"]:\s*/i, '')
    .replace(/\b(body|responseBody|response|payload)\s*[:=]\s*(?:[\[{<]|["'][\[{<]).*$/i, '$1=<scrubbed>')
    .replace(/<!DOCTYPE[^>]*>.*$/i, '<html>')
    .replace(/<(?:html|head|body)\b[^>]*>.*$/i, '<html>')
    .replace(/\bHTTP\/\d(?:\.\d)?\s+\d{3}\b.*$/i, '<http>')
  let s = redact(bodyStripped)
    .replace(/\b(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id)\s*[:=]\s*(?:Bearer\s+|Basic\s+)?[^\s,;}"']+/gi, '$1=<scrubbed>')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]+/g, '<scrubbed>')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,})\b/g, '<scrubbed>')
    .replace(/\{[^{}]{32,}\}/g, '<json>')
    .replace(/\{[^{}]{32,}\}/g, '<json>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<id>')
    .replace(/\bcap:[A-Za-z0-9._:-]+/g, '<id>')
    .replace(/\bgx[-_][A-Za-z0-9_-]+/gi, '<id>')
    .replace(/\b(?:ex|chain|job|run|sess|req|resp|oob|poll|spec|finding|worker|assign|gv)[-_](?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+/gi, '<id>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<id>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b/g, '<id>:<id>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<id>')
    .replace(/:(\d{2,5})(?=[/\s"'`),;]|$)/g, ':<id>')
    .replace(/\bport\s+\d{2,5}\b/gi, 'port <id>')
    .replace(/(?<=\b[a-z]+_)\d+\b/gi, '<id>')
    .replace(/#\d+\b/g, '#<id>')
    .replace(/\b\d+\b/g, '<id>')
    .replace(/<id>(?:,\s*<id>)+/g, '<id>')
    .replace(/\s+/g, ' ')
    .trim()
  if (!s) return 'unknown'
  if (s.length > 140) s = s.slice(0, 140).trimEnd()
  return s || 'unknown'
}

function signRecords<T extends HostSignableRecord>(records: readonly T[] | undefined, signingKey: string): T[] | undefined {
  if (!records) return undefined
  return records.map(rec => {
    const { hostSignature: _ignored, ...rest } = rec as T & { hostSignature?: string }
    const clone = rest as unknown as T
    return { ...clone, hostSignature: signHostRecord(clone, signingKey) }
  })
}

/**
 * Clone a `HostSignedTranscript` and re-sign all host-signable records with a deterministic key.
 * Enables faithful verification of sanitized live captures whose original ephemeral signing key
 * was stripped before writing to disk.
 */
export function resignTranscriptForReplay(
  transcript: HostSignedTranscript,
  signingKey: string = REPLAY_TEST_SIGNING_KEY,
): HostSignedTranscript {
  return {
    ...transcript,
    ...(transcript.entries ? { entries: signRecords(transcript.entries, signingKey) } : {}),
    ...(transcript.oobEvents ? { oobEvents: signRecords(transcript.oobEvents, signingKey) } : {}),
    ...(transcript.browserTraces ? { browserTraces: signRecords(transcript.browserTraces, signingKey) } : {}),
    ...(transcript.asyncPollRecords ? { asyncPollRecords: signRecords(transcript.asyncPollRecords, signingKey) } : {}),
  }
}

function normalizeRejectedBy(primary: unknown, fallbackStage?: unknown): string {
  for (const cand of [primary, fallbackStage]) {
    if (typeof cand === 'string' && cand.trim()) {
      return cand.trim().replace(/\s+/g, '_').slice(0, 64)
    }
  }
  return 'unknown'
}

function toPosixRelative(rootDir: string, absPath: string): string {
  const rel = relative(rootDir, absPath)
  return sep === '/' ? rel : rel.split(sep).join(posix.sep)
}

function collectCorpusFiles(rootDir: string): string[] {
  const out: string[] = []
  const walk = (dir: string): void => {
    const entries = readdirSync(dir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue
      if (entry.isSymbolicLink()) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase()
        if (ext === '.json' || ext === '.jsonl') out.push(full)
      }
    }
  }
  walk(rootDir)
  return out
}

function isCaptureLike(value: unknown): value is VerifyCorpusCapture {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const rec = value as Record<string, unknown>
  return rec.receipt !== undefined
    && rec.transcript !== undefined
    && typeof rec.transcript === 'object'
    && rec.transcript !== null
    && typeof rec.verdict === 'object'
    && rec.verdict !== null
    && typeof (rec.verdict as Record<string, unknown>).confirmed === 'boolean'
}

function loadCapturesFromFile(absPath: string): { captures: VerifyCorpusCapture[]; error?: string } {
  const raw = readFileSync(absPath, 'utf8')
  const ext = extname(absPath).toLowerCase()
  if (ext === '.jsonl') {
    const captures: VerifyCorpusCapture[] = []
    const lines = raw.split(/\r?\n/)
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]!.trim()
      if (!line) continue
      let parsed: unknown
      try {
        parsed = JSON.parse(line)
      } catch (err) {
        return { captures, error: `line ${i + 1}: ${(err as Error).message}` }
      }
      if (!isCaptureLike(parsed)) {
        return { captures, error: `line ${i + 1}: missing required receipt/transcript/verdict fields` }
      }
      captures.push(parsed)
    }
    return { captures }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    return { captures: [], error: (err as Error).message }
  }
  if (Array.isArray(parsed)) {
    const captures: VerifyCorpusCapture[] = []
    for (let i = 0; i < parsed.length; i += 1) {
      if (!isCaptureLike(parsed[i])) {
        return { captures, error: `element[${i}]: missing required receipt/transcript/verdict fields` }
      }
      captures.push(parsed[i]!)
    }
    return { captures }
  }
  if (!isCaptureLike(parsed)) {
    return { captures: [], error: 'missing required receipt/transcript/verdict fields' }
  }
  return { captures: [parsed] }
}

/**
 * Replay a single captured `CompositeProofReceipt` + `HostSignedTranscript` bundle against
 * `verifyCompositeReceipt()` using `defaultTerminalOracleRegistry`.
 */
export function replayCaptureRecord(
  capture: VerifyCorpusCapture,
  sourceFile: string,
  index = 0,
  options: { forceResign?: boolean; signingKey?: string } = {},
): ReplayCaseResult {
  const t0 = performance.now()
  const hasNativeSigningKey = typeof capture.signingKey === 'string' && capture.signingKey.trim().length > 0
  const shouldResign = Boolean(options.forceResign) || !hasNativeSigningKey
  const signingKey = shouldResign
    ? (options.signingKey ?? REPLAY_TEST_SIGNING_KEY)
    : capture.signingKey!.trim()

  const preparedTranscript = shouldResign
    ? resignTranscriptForReplay(capture.transcript, signingKey)
    : capture.transcript

  const factLog = HostFactLog.fromTranscript(preparedTranscript)
  const verification: CompositeReceiptVerification = verifyCompositeReceipt(
    capture.receipt,
    preparedTranscript,
    {
      ...(capture.verifyOptions ?? {}),
      signingKey,
      factLog,
      oracleEvaluator: defaultTerminalOracleRegistry,
    },
  )

  const prevConfirmed = capture.verdict.confirmed === true
  const nextConfirmed = verification.confirmed === true
  const bucket: ReplayDiffBucket = !prevConfirmed && nextConfirmed
    ? 'flipped_pass'
    : prevConfirmed && !nextConfirmed
      ? 'regressed_fail'
      : prevConfirmed && nextConfirmed
        ? 'still_pass'
        : 'still_fail'

  const isFpExpected = capture.expected?.side === 'fp' || capture.expected?.confirmed === false
  const isTpRegression = bucket === 'regressed_fail' && !isFpExpected

  const rawReceipt = (capture.receipt && typeof capture.receipt === 'object' && !Array.isArray(capture.receipt))
    ? capture.receipt as Record<string, unknown>
    : {}
  const chainId = verification.chainId && verification.chainId !== 'invalid'
    ? verification.chainId
    : (typeof rawReceipt.chainId === 'string' ? rawReceipt.chainId : 'unknown')
  const terminalVulnClass = verification.terminalVulnClass && verification.terminalVulnClass !== 'invalid'
    ? verification.terminalVulnClass
    : (typeof rawReceipt.terminalVulnClass === 'string' ? rawReceipt.terminalVulnClass : 'unknown')

  return {
    file: sourceFile,
    index,
    app: typeof capture.app === 'string' && capture.app.trim() ? capture.app.trim() : 'unknown',
    runId: typeof capture.runId === 'string' && capture.runId.trim() ? capture.runId.trim() : 'unknown',
    chainId,
    terminalVulnClass,
    bucket,
    isTpRegression,
    resigned: shouldResign,
    prevConfirmed,
    nextConfirmed,
    prevRejectedBy: prevConfirmed
      ? 'none'
      : normalizeRejectedBy(capture.verdict.rejectedBy, capture.verdict.failedStage),
    prevReasonSig: prevConfirmed ? 'confirmed' : sanitizeReplayReason(capture.verdict.reason),
    nextRejectedBy: nextConfirmed
      ? 'none'
      : normalizeRejectedBy(verification.rejectedBy, verification.failedStage),
    nextFailedStage: verification.failedStage ?? null,
    nextReasonSig: nextConfirmed ? 'confirmed' : sanitizeReplayReason(verification.reason),
    elapsedMs: Math.round((performance.now() - t0) * 100) / 100,
  }
}

function buildHistogram(
  cases: readonly ReplayCaseResult[],
  pick: (c: ReplayCaseResult) => { rejectedBy: string; reasonSig: string },
): ReplayHistogramEntry[] {
  const map = new Map<string, ReplayHistogramEntry>()
  for (const c of cases) {
    const { rejectedBy, reasonSig } = pick(c)
    const key = `${rejectedBy}\0${reasonSig}`
    const prev = map.get(key)
    if (prev) prev.count += 1
    else map.set(key, { rejectedBy, reasonSig, count: 1 })
  }
  return [...map.values()].sort(
    (a, b) => b.count - a.count
      || a.rejectedBy.localeCompare(b.rejectedBy)
      || a.reasonSig.localeCompare(b.reasonSig),
  )
}

async function runOptionalGradeBundle(gradeBundlePath: string): Promise<ReplayGradeSummary> {
  const absPath = resolve(gradeBundlePath)
  const raw = JSON.parse(readFileSync(absPath, 'utf8')) as Record<string, unknown>
  const runnerMod = (await import('../benchmarks/multihop-saas/run.ts')) as unknown as {
    gradeRun?: (input: Record<string, unknown>) => Record<string, unknown>
  }
  if (typeof runnerMod.gradeRun !== 'function') {
    throw new Error('benchmarks/multihop-saas/run.ts does not export gradeRun')
  }
  const card = runnerMod.gradeRun(raw)
  const chains = Array.isArray(card.chains) ? card.chains as Array<Record<string, unknown>> : []
  const confirmedChains = chains.filter(c => c.confirmed === true || c.passed === true).length
  const fpCount = typeof card.falsePositives === 'number'
    ? card.falsePositives
    : (typeof card.fpCount === 'number' ? card.fpCount : 0)
  return {
    source: absPath,
    app: typeof card.app === 'string' ? card.app : 'unknown',
    seed: typeof card.seed === 'number' ? card.seed : null,
    mode: typeof card.mode === 'string' ? card.mode : 'unknown',
    recall: typeof card.recall === 'number' ? Math.round(card.recall * 10000) / 10000 : 0,
    precision: typeof card.precision === 'number' ? Math.round(card.precision * 10000) / 10000 : 0,
    confirmedChains,
    expectedChains: chains.length,
    fpCount,
  }
}

/**
 * Replay every captured `*.json` / `*.jsonl` verification bundle in `options.dir`.
 */
export async function replayVerifyCorpus(options: ReplayCorpusOptions): Promise<ReplayCorpusReport> {
  const t0 = performance.now()
  const rootDir = resolve(options.dir)
  if (!existsSync(rootDir) || !statSync(rootDir).isDirectory()) {
    throw new Error(`Corpus directory not found: ${rootDir}`)
  }

  const files = collectCorpusFiles(rootDir)
  const parseErrors: Array<{ file: string; error: string }> = []
  const results: ReplayCaseResult[] = []
  let totalLoaded = 0
  let skippedPassing = 0

  for (const absPath of files) {
    const relFile = toPosixRelative(rootDir, absPath)
    const loaded = loadCapturesFromFile(absPath)
    if (loaded.error) {
      parseErrors.push({ file: relFile, error: sanitizeReplayReason(loaded.error) })
      continue
    }
    for (let i = 0; i < loaded.captures.length; i += 1) {
      const cap = loaded.captures[i]!
      totalLoaded += 1
      if (options.onlyFailed && cap.verdict.confirmed === true) {
        skippedPassing += 1
        continue
      }
      results.push(replayCaptureRecord(cap, relFile, i, {
        forceResign: options.forceResign,
        signingKey: options.signingKey,
      }))
    }
  }

  const flipped = results.filter(r => r.bucket === 'flipped_pass')
  const regressed = results.filter(r => r.bucket === 'regressed_fail')
  const stillPassing = results.filter(r => r.bucket === 'still_pass')
  const stillFailing = results.filter(r => r.bucket === 'still_fail')
  const gradeSummary = options.gradeBundlePath
    ? await runOptionalGradeBundle(options.gradeBundlePath)
    : undefined

  return {
    dir: rootDir,
    onlyFailed: Boolean(options.onlyFailed),
    totalLoaded,
    totalReplayed: results.length,
    skippedPassing,
    durationMs: Math.round((performance.now() - t0) * 100) / 100,
    parseErrors,
    flippedFailToPass: {
      count: flipped.length,
      byOriginalReason: buildHistogram(flipped, r => ({ rejectedBy: r.prevRejectedBy, reasonSig: r.prevReasonSig })),
      cases: flipped,
    },
    regressedPassToFail: {
      count: regressed.length,
      tpCount: regressed.filter(r => r.isTpRegression).length,
      cases: regressed,
    },
    stillPassing: {
      count: stillPassing.length,
    },
    stillFailing: {
      count: stillFailing.length,
      histogram: buildHistogram(stillFailing, r => ({ rejectedBy: r.nextRejectedBy, reasonSig: r.nextReasonSig })),
    },
    ...(gradeSummary ? { gradeSummary } : {}),
  }
}

/** Format a crisp, secret-free human-readable diff report for terminal display. */
export function formatReplayDiffReport(report: ReplayCorpusReport): string {
  const lines: string[] = []
  lines.push(
    `Offline Receipt Replay: ${report.totalReplayed}/${report.totalLoaded} replayed in ${report.durationMs}ms`
    + (report.onlyFailed ? ` (--only-failed, skipped ${report.skippedPassing} passing)` : ''),
  )
  lines.push(`Corpus: ${report.dir}`)
  lines.push('')
  lines.push('Summary:')
  lines.push(`  FLIPPED FAIL -> PASS : ${report.flippedFailToPass.count}`)
  lines.push(
    `  REGRESSED PASS -> FAIL: ${report.regressedPassToFail.count}`
    + (report.regressedPassToFail.tpCount > 0
      ? ` (CRITICAL: ${report.regressedPassToFail.tpCount} TP regression(s)!)`
      : ' (0 TP regressions)'),
  )
  lines.push(`  STILL PASSING        : ${report.stillPassing.count}`)
  lines.push(`  STILL FAILING        : ${report.stillFailing.count}`)
  if (report.parseErrors.length > 0) {
    lines.push(`  PARSE ERRORS         : ${report.parseErrors.length}`)
  }

  if (report.flippedFailToPass.count > 0) {
    lines.push('')
    lines.push('FLIPPED FAIL -> PASS (by original rejectedBy / reason):')
    for (const h of report.flippedFailToPass.byOriginalReason) {
      lines.push(`  ${String(h.count).padStart(4)}  [${h.rejectedBy}] ${h.reasonSig}`)
    }
  }

  if (report.regressedPassToFail.count > 0) {
    lines.push('')
    lines.push('REGRESSED PASS -> FAIL:')
    for (const c of report.regressedPassToFail.cases) {
      const tag = c.isTpRegression ? 'TP-REGRESSION' : 'FP-FIXED'
      lines.push(`  [${tag}] ${c.file} app=${c.app} chain=${c.chainId} -> [${c.nextRejectedBy}] ${c.nextReasonSig}`)
    }
  }

  if (report.stillFailing.count > 0) {
    lines.push('')
    lines.push('STILL FAILING (histogram by rejectedBy / normalized reason):')
    for (const h of report.stillFailing.histogram) {
      lines.push(`  ${String(h.count).padStart(4)}  [${h.rejectedBy}] ${h.reasonSig}`)
    }
  }

  if (report.parseErrors.length > 0) {
    lines.push('')
    lines.push('PARSE ERRORS:')
    for (const e of report.parseErrors) {
      lines.push(`  ${e.file}: ${e.error}`)
    }
  }

  if (report.gradeSummary) {
    const g = report.gradeSummary
    lines.push('')
    lines.push(
      `Grade Bundle (${g.app}, seed=${g.seed ?? 'n/a'}, mode=${g.mode}): `
      + `confirmed=${g.confirmedChains}/${g.expectedChains} recall=${g.recall} precision=${g.precision} fp=${g.fpCount}`,
    )
  }

  return `${lines.join('\n')}\n`
}

interface ParsedCliArgs {
  dir: string | null
  onlyFailed: boolean
  forceResign: boolean
  failOnRegression: boolean
  gradeBundlePath?: string
  jsonOut?: string
  help: boolean
}

function parseCliArgs(argv: readonly string[]): ParsedCliArgs {
  const out: ParsedCliArgs = {
    dir: null,
    onlyFailed: false,
    forceResign: false,
    failOnRegression: false,
    help: false,
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '-h' || arg === '--help') {
      out.help = true
    } else if (arg === '--only-failed') {
      out.onlyFailed = true
    } else if (arg === '--resign') {
      out.forceResign = true
    } else if (arg === '--fail-on-regression') {
      out.failOnRegression = true
    } else if (arg === '--dir') {
      out.dir = argv[++i] ?? null
    } else if (arg.startsWith('--dir=')) {
      out.dir = arg.slice('--dir='.length)
    } else if (arg === '--grade-bundle') {
      out.gradeBundlePath = argv[++i]
    } else if (arg.startsWith('--grade-bundle=')) {
      out.gradeBundlePath = arg.slice('--grade-bundle='.length)
    } else if (arg === '--json') {
      const next = argv[i + 1]
      if (next && !next.startsWith('-')) {
        out.jsonOut = argv[++i]
      } else {
        out.jsonOut = '-'
      }
    } else if (arg.startsWith('--json=')) {
      out.jsonOut = arg.slice('--json='.length)
    } else if (!arg.startsWith('-') && !out.dir) {
      out.dir = arg
    } else {
      throw new Error(`Unknown argument: ${arg}`)
    }
  }
  return out
}

const USAGE = [
  'Usage: node --experimental-strip-types scripts/replay-v8-receipts.ts --dir <corpus-dir> [options]',
  '',
  'Options:',
  '  --dir <path>           Directory of captured *.json / *.jsonl receipt bundles (required)',
  '  --only-failed          Replay only captures whose original verdict was confirmed=false',
  '  --resign               Force re-signing transcripts with deterministic offline test key',
  '  --grade-bundle <path>  Optional ProductGradeInput JSON to score via gradeRun',
  '  --json [out.json]      Write structured JSON report to file (or stdout with "-" / bare flag)',
  '  --fail-on-regression   Exit 1 if any TP regression (PASS -> FAIL) is detected',
  '  -h, --help             Show this help',
].join('\n')

async function main(): Promise<void> {
  const args = parseCliArgs(process.argv.slice(2))
  if (args.help) {
    process.stdout.write(`${USAGE}\n`)
    return
  }
  if (!args.dir) {
    process.stderr.write(`Error: --dir <corpus-dir> is required.\n\n${USAGE}\n`)
    process.exit(2)
  }

  const report = await replayVerifyCorpus({
    dir: args.dir,
    onlyFailed: args.onlyFailed,
    forceResign: args.forceResign,
    gradeBundlePath: args.gradeBundlePath,
  })

  if (args.jsonOut === '-') {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  } else {
    process.stdout.write(formatReplayDiffReport(report))
    if (args.jsonOut) {
      const outPath = resolve(args.jsonOut)
      mkdirSync(dirname(outPath), { recursive: true })
      writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8')
      process.stdout.write(`Wrote JSON report: ${outPath}\n`)
    }
  }

  if (args.failOnRegression && report.regressedPassToFail.tpCount > 0) {
    process.exit(1)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(err => {
    process.stderr.write(`replay-v8-receipts error: ${(err as Error).message}\n`)
    process.exit(1)
  })
}
