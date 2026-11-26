import { redact, SENSITIVE_HTTP_HEADER_RE } from './redact.ts'
import { isStuckTerminalAssignmentStatus, isTerminalRunStatus } from './run-status.ts'

export const QA_ANOMALIES_MAX_ENTRIES = 200

export const qaAnomalyKinds = [
  'swallowed_nav_error',
  'interactive_proxy_denied',
  'unexpected_ui_rpc_error',
  'orphaned_running_assignment',
  'zero_runtime_from_static',
  'ui_console_error',
  'layout_violation',
] as const

export type QaAnomalyKind = typeof qaAnomalyKinds[number]

export interface QaAnomalyRecord {
  id: string
  ts: number
  kind: QaAnomalyKind
  routeOrOrigin: string
  summary: string
  detail?: Record<string, unknown>
}

export interface QaAnomalyInput {
  kind: QaAnomalyKind
  routeOrOrigin: string
  summary: string
  detail?: Record<string, unknown>
  ts?: number
}

export interface QaAnomalyRecordOptions {
  env?: NodeJS.ProcessEnv
  force?: boolean
}

export interface QaAnomalyListOptions {
  kind?: QaAnomalyKind
  limit?: number
  sinceTs?: number
}

export interface QaInspectableRun {
  id: string
  status: string
  phase?: string | null
  origin?: string | null
  candidates?: readonly { origin: string }[] | null
}

export interface QaInspectableAssignment {
  id: string
  status: string
  phase?: string | null
  title?: string | null
  sourceOrigins?: readonly string[] | null
}

export interface QaInspectableFinding {
  id?: string
  status?: string | null
  verificationTier?: string | null
  verificationClass?: string | null
  verification?: string | null
  findingKind?: string | null
  origin?: string | null
  supersededByFindingId?: string | null
}

const MAX_ROUTE_LEN = 256
const MAX_SUMMARY_LEN = 320
const MAX_DETAIL_STRING_LEN = 240
const MAX_DETAIL_DEPTH = 4
const MAX_DETAIL_KEYS = 24
const MAX_DETAIL_ARRAY_LEN = 16

/**
 * Keys whose values may hold cookies, auth headers, tokens, secrets, or raw HTTP bodies.
 * Any matching key is omitted completely from sanitized anomaly `detail` payloads.
 */
const DISALLOWED_DETAIL_KEY_RE =
  /cookie|set[-_]?cookie|authorization|proxy[-_]?authorization|auth[-_]?header|token|jwt|secret|password|passwd|api[-_]?key|credential|session[-_]?(?:id|key|cookie|token|state)|storage[-_]?state|bootstrap|private[-_]?key|csrf|xsrf|headers?|req[-_]?headers?|resp[-_]?headers?|request[-_]?headers?|response[-_]?headers?|body|raw[-_]?body|http[-_]?body|request[-_]?body|response[-_]?body|body[-_]?preview|html|raw[-_]?html|payload/i

const INLINE_AUTH_OR_COOKIE_RE = /\b(?:cookie|set-cookie2?|authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-xsrf-token)\s*[:=]\s*[^\n\r;,]*/gi
const QUERY_SECRET_RE = /([?&](?:bootstrap|token|access_token|refresh_token|id_token|code|ticket|session|session_id|key|api_key|apikey|secret|password|auth|sig|signature|jwt)=)[^&#\s]+/gi
const HTML_DOC_RE = /<(?:!doctype|html|head|body|script|style|form)\b[\s\S]*/i

export function isQaAnomaliesEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.KOVO_QA_ANOMALIES === '1'
}

function normalizeControlChars(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim()
}

function stripSensitiveSubstrings(raw: string): string {
  let out = normalizeControlChars(raw)
  if (!out) return ''
  // Cut off anything that looks like an embedded HTML/HTTP body dump.
  const htmlMatch = HTML_DOC_RE.exec(out)
  if (htmlMatch && htmlMatch.index >= 0) {
    out = `${out.slice(0, htmlMatch.index).trim()} [body-omitted]`.trim()
  }
  out = out.replace(QUERY_SECRET_RE, '$1[redacted]')
  out = out.replace(INLINE_AUTH_OR_COOKIE_RE, '[redacted]')
  out = redact(out)
  return normalizeControlChars(out)
}

function sanitizeRouteOrOrigin(raw: string): string {
  const trimmed = normalizeControlChars(String(raw ?? ''))
  if (!trimmed) return 'unknown'

  // If it looks like a URL, keep only scheme + host + pathname (never credentials, query, or hash).
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed)
      const safePath = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : ''
      const sanitized = stripSensitiveSubstrings(`${parsed.origin}${safePath}`)
      return (sanitized || 'unknown').slice(0, MAX_ROUTE_LEN)
    } catch {
      // Fall through to path/string sanitization.
    }
  }

  // Strip query string and fragment from relative routes (e.g. `/?bootstrap=...` -> `/`).
  const withoutQuery = trimmed.split(/[?#]/, 1)[0] ?? trimmed
  const sanitized = stripSensitiveSubstrings(withoutQuery)
  return (sanitized || 'unknown').slice(0, MAX_ROUTE_LEN)
}

function sanitizeSummary(raw: string): string {
  const sanitized = stripSensitiveSubstrings(String(raw ?? ''))
  if (!sanitized) return 'QA anomaly recorded'
  return sanitized.length > MAX_SUMMARY_LEN
    ? `${sanitized.slice(0, MAX_SUMMARY_LEN - 1)}…`
    : sanitized
}

function isDisallowedKey(key: string): boolean {
  const trimmed = key.trim()
  if (!trimmed) return true
  if (SENSITIVE_HTTP_HEADER_RE.test(trimmed)) return true
  return DISALLOWED_DETAIL_KEY_RE.test(trimmed)
}

function sanitizeDetailValue(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) return value
  const t = typeof value
  if (t === 'boolean') return value
  if (t === 'number') return Number.isFinite(value) ? value : null
  if (t === 'string') {
    const cleaned = stripSensitiveSubstrings(value as string)
    return cleaned.length > MAX_DETAIL_STRING_LEN
      ? `${cleaned.slice(0, MAX_DETAIL_STRING_LEN - 1)}…`
      : cleaned
  }
  if (t === 'bigint') return String(value)
  if (t !== 'object') return undefined

  const obj = value as object
  if (seen.has(obj)) return '[circular]'
  if (depth >= MAX_DETAIL_DEPTH) return '[truncated]'

  seen.add(obj)
  try {
    if (Array.isArray(obj)) {
      const out: unknown[] = []
      const len = Math.min(obj.length, MAX_DETAIL_ARRAY_LEN)
      for (let i = 0; i < len; i += 1) {
        const sanitizedItem = sanitizeDetailValue(obj[i], depth + 1, seen)
        if (sanitizedItem !== undefined) out.push(sanitizedItem)
      }
      return out
    }

    const out: Record<string, unknown> = {}
    let kept = 0
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (kept >= MAX_DETAIL_KEYS) break
      if (isDisallowedKey(k)) continue
      const sanitizedVal = sanitizeDetailValue(v, depth + 1, seen)
      if (sanitizedVal === undefined) continue
      out[k] = sanitizedVal
      kept += 1
    }
    return out
  } finally {
    seen.delete(obj)
  }
}

function sanitizeDetail(detail: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!detail || typeof detail !== 'object' || Array.isArray(detail)) return undefined
  const seen = new WeakSet<object>()
  const sanitized = sanitizeDetailValue(detail, 0, seen)
  if (!sanitized || typeof sanitized !== 'object' || Array.isArray(sanitized)) return undefined
  const record = sanitized as Record<string, unknown>
  return Object.keys(record).length > 0 ? record : undefined
}

function cloneRecord(rec: QaAnomalyRecord): QaAnomalyRecord {
  return {
    id: rec.id,
    ts: rec.ts,
    kind: rec.kind,
    routeOrOrigin: rec.routeOrOrigin,
    summary: rec.summary,
    ...(rec.detail !== undefined ? { detail: structuredClone(rec.detail) } : {}),
  }
}

export interface QaAnomalyRecorder {
  readonly maxEntries: number
  record(input: QaAnomalyInput, options?: QaAnomalyRecordOptions): QaAnomalyRecord | null
  list(options?: QaAnomalyListOptions): QaAnomalyRecord[]
  clear(): void
  size(): number
}

/**
 * Create a bounded ring-buffer QA anomaly recorder (`maxEntries = 200` by default).
 * Completely no-op when `KOVO_QA_ANOMALIES !== '1'` unless `options.force` is set.
 */
function createQaAnomalyRecorder(maxEntries = QA_ANOMALIES_MAX_ENTRIES): QaAnomalyRecorder {
  const capacity = Math.max(1, Math.floor(maxEntries))
  const slots: Array<QaAnomalyRecord | undefined> = new Array(capacity)
  let head = 0
  let count = 0
  let seq = 0

  function record(input: QaAnomalyInput, options?: QaAnomalyRecordOptions): QaAnomalyRecord | null {
    if (!options?.force && !isQaAnomaliesEnabled(options?.env)) {
      return null
    }
    seq += 1
    const ts = typeof input.ts === 'number' && Number.isFinite(input.ts) ? Math.floor(input.ts) : Date.now()
    const detail = sanitizeDetail(input.detail)
    const entry: QaAnomalyRecord = {
      id: `qa_${seq}_${ts}`,
      ts,
      kind: input.kind,
      routeOrOrigin: sanitizeRouteOrOrigin(input.routeOrOrigin),
      summary: sanitizeSummary(input.summary),
      ...(detail !== undefined ? { detail } : {}),
    }

    if (count < capacity) {
      slots[(head + count) % capacity] = entry
      count += 1
    } else {
      slots[head] = entry
      head = (head + 1) % capacity
    }
    return cloneRecord(entry)
  }

  function list(options?: QaAnomalyListOptions): QaAnomalyRecord[] {
    if (count === 0) return []
    const out: QaAnomalyRecord[] = []
    for (let i = 0; i < count; i += 1) {
      const entry = slots[(head + i) % capacity]
      if (!entry) continue
      if (options?.kind && entry.kind !== options.kind) continue
      if (typeof options?.sinceTs === 'number' && entry.ts < options.sinceTs) continue
      out.push(cloneRecord(entry))
    }
    if (typeof options?.limit === 'number' && Number.isFinite(options.limit)) {
      const lim = Math.max(0, Math.floor(options.limit))
      return lim === 0 ? [] : out.slice(-lim)
    }
    return out
  }

  function clear(): void {
    slots.fill(undefined)
    head = 0
    count = 0
  }

  function size(): number {
    return count
  }

  return { maxEntries: capacity, record, list, clear, size }
}

const defaultRecorder = createQaAnomalyRecorder(QA_ANOMALIES_MAX_ENTRIES)

export function recordQaAnomaly(
  input: QaAnomalyInput,
  options?: QaAnomalyRecordOptions,
): QaAnomalyRecord | null {
  return defaultRecorder.record(input, options)
}

export function listQaAnomalies(options?: QaAnomalyListOptions): QaAnomalyRecord[] {
  return defaultRecorder.list(options)
}

export function clearQaAnomalies(): void {
  defaultRecorder.clear()
}

function isStaticVerifiedFinding(f: QaInspectableFinding): boolean {
  return (
    f.status === 'static_verified' ||
    f.verificationTier === 'static_verified' ||
    f.verificationClass === 'static_verified'
  )
}

function isRuntimeConfirmedFinding(f: QaInspectableFinding): boolean {
  if (isStaticVerifiedFinding(f)) return false
  if (f.verificationTier === 'runtime_confirmed' || f.verificationClass === 'runtime_confirmed') {
    return true
  }
  if (f.verification === 'runtime_confirmed') return true
  if (f.status === 'confirmed') {
    if (f.verificationTier === 'baseline_confirmed' || f.findingKind === 'baseline_check') {
      return false
    }
    return true
  }
  return false
}

function resolveRunRouteOrOrigin(
  run: QaInspectableRun,
  assignments: readonly QaInspectableAssignment[],
  findings: readonly QaInspectableFinding[],
): string {
  if (run.origin && run.origin.trim()) return run.origin
  const firstCandidate = run.candidates?.find(c => Boolean(c?.origin))?.origin
  if (firstCandidate) return firstCandidate
  const firstAssignmentOrigin = assignments.find(a => (a.sourceOrigins?.length ?? 0) > 0)?.sourceOrigins?.[0]
  if (firstAssignmentOrigin) return firstAssignmentOrigin
  const firstFindingOrigin = findings.find(f => Boolean(f.origin))?.origin
  if (firstFindingOrigin) return firstFindingOrigin
  return `/runs/${run.id}`
}

/**
 * Inspect a completed/terminal run for post-completion QA invariants:
 *   1. Orphaned `running`/`queued` assignments still left active on a terminal run
 *      (`kind: 'orphaned_running_assignment'`).
 *   2. `static_verified > 0 && runtime_confirmed === 0` (`kind: 'zero_runtime_from_static'`).
 *
 * Returns `[]` with zero overhead when `KOVO_QA_ANOMALIES !== '1'` (unless `options.force` is set).
 */
export function inspectRunPostCompletionAnomalies(
  run: QaInspectableRun,
  assignments: readonly QaInspectableAssignment[],
  findings: readonly QaInspectableFinding[],
  options?: QaAnomalyRecordOptions,
): QaAnomalyRecord[] {
  if (!options?.force && !isQaAnomaliesEnabled(options?.env)) {
    return []
  }

  const normalizedRunStatus = String(run.status ?? '').toLowerCase()
  const isTerminal =
    isTerminalRunStatus(normalizedRunStatus) ||
    String(run.phase ?? '').toLowerCase() === 'complete'
  if (!isTerminal) {
    return []
  }

  const recorded: QaAnomalyRecord[] = []
  const routeOrOrigin = resolveRunRouteOrOrigin(run, assignments, findings)

  // 1. Stuck `running` / `queued` assignments on a terminal run.
  const orphaned = assignments.filter(a => isStuckTerminalAssignmentStatus(a.status))
  if (orphaned.length > 0) {
    const runningCount = orphaned.filter(a => String(a.status).toLowerCase() === 'running').length
    const queuedCount = orphaned.filter(a => String(a.status).toLowerCase() === 'queued').length
    const rec = recordQaAnomaly(
      {
        kind: 'orphaned_running_assignment',
        routeOrOrigin,
        summary: `Terminal run ${run.id} (${normalizedRunStatus}) still has ${orphaned.length} orphaned assignment(s) (${runningCount} running, ${queuedCount} queued).`,
        detail: {
          runId: run.id,
          runStatus: normalizedRunStatus,
          runPhase: run.phase ?? null,
          orphanedCount: orphaned.length,
          runningCount,
          queuedCount,
          orphanedAssignmentIds: orphaned.slice(0, MAX_DETAIL_ARRAY_LEN).map(a => a.id),
        },
      },
      options,
    )
    if (rec) recorded.push(rec)
  }

  // 2. `static_verified > 0 && runtime_confirmed === 0` on active (non-superseded) findings.
  const activeFindings = findings.filter(f => !f.supersededByFindingId)
  let staticVerifiedCount = 0
  let runtimeConfirmedCount = 0
  for (const f of activeFindings) {
    if (isStaticVerifiedFinding(f)) {
      staticVerifiedCount += 1
    } else if (isRuntimeConfirmedFinding(f)) {
      runtimeConfirmedCount += 1
    }
  }

  if (staticVerifiedCount > 0 && runtimeConfirmedCount === 0) {
    const rec = recordQaAnomaly(
      {
        kind: 'zero_runtime_from_static',
        routeOrOrigin,
        summary: `Terminal run ${run.id} produced ${staticVerifiedCount} static_verified advisory finding(s) with 0 runtime_confirmed findings.`,
        detail: {
          runId: run.id,
          runStatus: normalizedRunStatus,
          runPhase: run.phase ?? null,
          staticVerifiedCount,
          runtimeConfirmedCount,
          totalFindings: activeFindings.length,
        },
      },
      options,
    )
    if (rec) recorded.push(rec)
  }

  return recorded
}
