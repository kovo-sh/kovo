#!/usr/bin/env node
/**
 * Move 2 — Live Mid-Run Watchdog / Peek Script.
 *
 * Read-only inspection of an in-progress `benchmark-multihop.ts` `--out-dir` (or multiple
 * directories such as `{wb,gb}`) without disturbing active SQLite WAL writers.
 *
 * Discovers active cell SQLite DBs (`<out-dir>/data/<slug>/kovo.sqlite` or nested) and prints
 * ONLY structured counts & short sanitized signatures — never raw HTTP bodies, credentials, or
 * probe strings. Flags `ABORT_RECOMMENDED` when systemic errors or high worker failure rates
 * cross configurable thresholds.
 *
 * Usage:
 *   node --experimental-strip-types scripts/peek-v8-live.ts \
 *     --out-dir <path> [--out-dir <path2> ...] [--json [out.json]] \
 *     [--systemic-threshold <N>] [--worker-fail-rate <0..1>] [--min-workers <N>]
 */
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { basename, dirname, join, posix, relative, resolve, sep } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { pathToFileURL } from 'node:url'
import { redact } from '../src/server/redact.ts'

export interface WatchdogThresholds {
  /** Minimum count of any systemic error class in a cell to recommend abort (default: 3). */
  systemicThreshold: number
  /** Worker failure rate threshold above which abort is recommended (default: 0.50). */
  workerFailureRateThreshold: number
  /** Minimum finished workers before evaluating workerFailureRateThreshold (default: 2). */
  minFinishedWorkers: number
}

export const DEFAULT_WATCHDOG_THRESHOLDS: Readonly<WatchdogThresholds> = Object.freeze({
  systemicThreshold: 3,
  workerFailureRateThreshold: 0.5,
  minFinishedWorkers: 2,
})

export interface ConfirmedFindingSummary {
  kind: string
  cwe: string
  route: string
}

export interface RejectReasonSummary {
  reason: string
  signature: string
  count: number
}

export interface SystemicErrorCounts {
  terminal_class_unmapped: number
  composite_schema: number
  checkpoint_blocked: number
}

export interface WorkerHealthSummary {
  total: number
  running: number
  completed: number
  failed: number
  finished: number
  failureRate: number
}

export interface CellLivePeek {
  cell: string
  dbPath: string
  runId: string | null
  phase: string
  status: string
  costUsd: number
  elapsedMin: number
  turnsUsed: number
  requestsUsed: number
  workers: WorkerHealthSummary
  confirmedFindings: ConfirmedFindingSummary[]
  topRejectReasons: RejectReasonSummary[]
  systemicErrors: SystemicErrorCounts
  abortRecommended: boolean
  abortReasons: string[]
  readError?: string
}

export interface LivePeekReport {
  scannedAt: string
  roots: string[]
  thresholds: WatchdogThresholds
  cellsFound: number
  totalCostUsd: number
  totalConfirmedFindings: number
  abortRecommended: boolean
  abortCells: string[]
  cells: CellLivePeek[]
}

export interface PeekLiveOptions {
  outDirs: readonly string[]
  thresholds?: Partial<WatchdogThresholds>
  nowMs?: number
}

type SqliteRow = Record<string, unknown>

const TERMINAL_CLASS_UNMAPPED_RE = /\bterminal_class_unmapped\b|unmapped\s+terminal|no\s+confirmation\s+rule|unknown\s+terminal\s+(?:vuln\s*)?class/i
const COMPOSITE_SCHEMA_RE = /\bcomposite_schema\b|\bschema\s+validation\s+failed\b|rejected\s+at\s+stage\s+['"]schema['"]|^schema$/i
const CHECKPOINT_BLOCKED_RE = /\bcheckpoint_blocked\b|\bcheckpoint_only\b|circuit\s+breaker.*checkpoint/i

function toPosixRelative(rootDir: string, absPath: string): string {
  const rel = relative(rootDir, absPath)
  return sep === '/' ? rel : rel.split(sep).join(posix.sep)
}

function safeJsonParse(raw: unknown): unknown {
  if (typeof raw !== 'string' || !raw.trim()) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function finiteNum(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

/**
 * Sanitize a rejection signature into a short, secret-free diagnostic string (<= 120 chars).
 * Strips raw HTTP/HTML/JSON bodies, auth headers, tokens, JWTs, and volatile IDs/ports.
 */
export function sanitizeLiveSignature(raw: unknown): string {
  if (typeof raw !== 'string') return 'unknown'
  const line = raw
    .replace(/-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g, '<scrubbed>')
    .split(/\r?\n/)
    .map(l => l.trim())
    .find(Boolean)
  if (!line) return 'unknown'
  const stripped = line
    .replace(/^CompositeProofReceipt rejected at stage ['"][^'"]+['"]:\s*/i, '')
    .replace(/\b(body|responseBody|response|payload)\s*[:=]\s*(?:[\[{<]|["'][\[{<]).*$/i, '$1=<scrubbed>')
    .replace(/<!DOCTYPE[^>]*>.*$/i, '<html>')
    .replace(/<(?:html|head|body)\b[^>]*>.*$/i, '<html>')
    .replace(/\bHTTP\/\d(?:\.\d)?\s+\d{3}\b.*$/i, '<http>')
  let s = redact(stripped)
    .replace(/\b(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id)\s*[:=]\s*(?:Bearer\s+|Basic\s+)?[^\s,;}"']+/gi, '$1=<scrubbed>')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]+/g, '<scrubbed>')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,})\b/g, '<scrubbed>')
    .replace(/\{[^{}]{32,}\}/g, '<json>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<id>')
    .replace(/\bcap:[A-Za-z0-9._:-]+/g, '<id>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<id>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\b/g, '<id>')
    .replace(/:(\d{2,5})(?=[/\s"'`),;]|$)/g, ':<id>')
    .replace(/\s+/g, ' ')
    .trim()
  if (!s) return 'unknown'
  return s.length > 120 ? s.slice(0, 120).trimEnd() : s
}

function sanitizeRoutePath(raw: unknown): string {
  if (typeof raw !== 'string') return '(unknown)'
  const trimmed = raw.trim()
  if (!trimmed) return '(unknown)'
  let pathPart = trimmed
  try {
    if (/^https?:\/\//i.test(trimmed)) {
      pathPart = new URL(trimmed).pathname
    } else {
      const qIdx = trimmed.indexOf('?')
      pathPart = qIdx >= 0 ? trimmed.slice(0, qIdx) : trimmed
    }
  } catch {
    const qIdx = trimmed.indexOf('?')
    pathPart = qIdx >= 0 ? trimmed.slice(0, qIdx) : trimmed
  }
  const cleaned = redact(pathPart)
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<id>')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]+/g, '<scrubbed>')
    .replace(/\s+/g, ' ')
    .trim()
  return (cleaned || '(unknown)').slice(0, 120)
}

function normalizeRejectKey(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const cleaned = redact(raw).replace(/\s+/g, ' ').trim()
  if (!cleaned) return null
  return cleaned.slice(0, 64)
}

function classifySystemicError(reason: string, signature: string, counts: SystemicErrorCounts, delta = 1): void {
  const combined = `${reason} ${signature}`
  if (TERMINAL_CLASS_UNMAPPED_RE.test(combined)) counts.terminal_class_unmapped += delta
  if (COMPOSITE_SCHEMA_RE.test(reason) || COMPOSITE_SCHEMA_RE.test(signature)) counts.composite_schema += delta
  if (CHECKPOINT_BLOCKED_RE.test(combined)) counts.checkpoint_blocked += delta
}

/**
 * Evaluate watchdog abort conditions for a single cell.
 */
export function evaluateWatchdogAlerts(
  systemicErrors: SystemicErrorCounts,
  workers: WorkerHealthSummary,
  thresholds: WatchdogThresholds = DEFAULT_WATCHDOG_THRESHOLDS,
): { abortRecommended: boolean; abortReasons: string[] } {
  const abortReasons: string[] = []
  if (systemicErrors.terminal_class_unmapped >= thresholds.systemicThreshold) {
    abortReasons.push(
      `terminal_class_unmapped=${systemicErrors.terminal_class_unmapped} (>=${thresholds.systemicThreshold})`,
    )
  }
  if (systemicErrors.composite_schema >= thresholds.systemicThreshold) {
    abortReasons.push(
      `composite_schema=${systemicErrors.composite_schema} (>=${thresholds.systemicThreshold})`,
    )
  }
  if (systemicErrors.checkpoint_blocked >= thresholds.systemicThreshold) {
    abortReasons.push(
      `checkpoint_blocked=${systemicErrors.checkpoint_blocked} (>=${thresholds.systemicThreshold})`,
    )
  }
  if (
    workers.finished >= thresholds.minFinishedWorkers
    && workers.failureRate > thresholds.workerFailureRateThreshold
  ) {
    const pct = Math.round(workers.failureRate * 1000) / 10
    const thrPct = Math.round(thresholds.workerFailureRateThreshold * 1000) / 10
    abortReasons.push(
      `workerFailureRate=${pct}% (${workers.failed}/${workers.finished} > ${thrPct}%)`,
    )
  }
  return { abortRecommended: abortReasons.length > 0, abortReasons }
}

/**
 * Discover active cell `kovo.sqlite` databases under one or more `--out-dir` paths.
 * Supports `<out-dir>/data/<slug>/kovo.sqlite`, `<parent>/{wb,gb}/data/<slug>/kovo.sqlite`,
 * or direct `<cell-dir>/kovo.sqlite`.
 */
export function discoverCellDatabases(outDirs: readonly string[], maxDepth = 5): Array<{ cell: string; dbPath: string }> {
  const found: Array<{ cell: string; dbPath: string }> = []
  const seen = new Set<string>()
  const skipDirs = new Set(['node_modules', '.git', 'agent-sessions', 'repos', 'artifacts', 'tmp'])

  for (const rawRoot of outDirs) {
    const root = resolve(rawRoot)
    if (!existsSync(root)) continue
    const st = statSync(root)
    if (st.isFile() && basename(root) === 'kovo.sqlite') {
      if (!seen.has(root)) {
        seen.add(root)
        found.push({ cell: basename(dirname(root)), dbPath: root })
      }
      continue
    }
    if (!st.isDirectory()) continue

    const rootLabel = outDirs.length > 1 ? basename(root) : ''
    const walk = (dir: string, depth: number): void => {
      if (depth > maxDepth) return
      let entries
      try {
        entries = readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }
      entries.sort((a, b) => a.name.localeCompare(b.name))
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue
        const full = join(dir, entry.name)
        if (entry.isFile() && entry.name === 'kovo.sqlite') {
          if (seen.has(full)) continue
          seen.add(full)
          let rel = toPosixRelative(root, dirname(full))
          rel = rel.replace(/^data\//, '').replace(/\/data\//g, '/')
          const label = rel && rel !== '.'
            ? (rootLabel ? `${rootLabel}/${rel}` : rel)
            : (rootLabel || basename(root))
          found.push({ cell: label, dbPath: full })
        } else if (entry.isDirectory() && !entry.name.startsWith('.') && !skipDirs.has(entry.name)) {
          walk(full, depth + 1)
        }
      }
    }
    walk(root, 0)
  }

  return found.sort((a, b) => a.cell.localeCompare(b.cell))
}

function listTables(db: DatabaseSync): Set<string> {
  const rows = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as SqliteRow[]
  return new Set(rows.map(r => (typeof r.name === 'string' ? r.name : '')).filter(Boolean))
}

function listColumns(db: DatabaseSync, table: string): Set<string> {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as SqliteRow[]
  return new Set(rows.map(r => (typeof r.name === 'string' ? r.name : '')).filter(Boolean))
}

/**
 * Inspect a single cell's `kovo.sqlite` strictly read-only (`DatabaseSync(..., { readOnly: true })`).
 */
export function peekCellDatabase(
  dbPath: string,
  cellLabel: string,
  thresholds: WatchdogThresholds = DEFAULT_WATCHDOG_THRESHOLDS,
  nowMs: number = Date.now(),
): CellLivePeek {
  const emptySystemic: SystemicErrorCounts = {
    terminal_class_unmapped: 0,
    composite_schema: 0,
    checkpoint_blocked: 0,
  }
  const emptyWorkers: WorkerHealthSummary = {
    total: 0,
    running: 0,
    completed: 0,
    failed: 0,
    finished: 0,
    failureRate: 0,
  }

  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    try {
      db.exec('PRAGMA busy_timeout = 1500')
    } catch {
      // Read-only pragma fallback is non-fatal.
    }

    const tables = listTables(db)
    let runId: string | null = null
    let phase = 'unknown'
    let status = 'unknown'
    let costUsd = 0
    let turnsUsed = 0
    let requestsUsed = 0
    let runCreatedAt: number | null = null

    if (tables.has('runs')) {
      const cols = listColumns(db, 'runs')
      const want = ['id', 'phase', 'status', 'spent_usd', 'turns_used', 'spent_requests', 'created_at'].filter(c => cols.has(c))
      if (want.length > 0) {
        const orderCol = cols.has('created_at') ? 'created_at DESC' : 'rowid DESC'
        const row = db.prepare(`SELECT ${want.join(', ')} FROM runs ORDER BY ${orderCol} LIMIT 1`).get() as SqliteRow | undefined
        if (row) {
          runId = typeof row.id === 'string' ? row.id : null
          phase = typeof row.phase === 'string' ? row.phase : 'unknown'
          status = typeof row.status === 'string' ? row.status : 'unknown'
          costUsd = Math.round((finiteNum(row.spent_usd) ?? 0) * 10000) / 10000
          turnsUsed = Math.floor(finiteNum(row.turns_used) ?? 0)
          requestsUsed = Math.floor(finiteNum(row.spent_requests) ?? 0)
          runCreatedAt = finiteNum(row.created_at)
        }
      }
    }

    // --- Workers / assignments ---
    const workers: WorkerHealthSummary = { ...emptyWorkers }
    const sessionIds = new Set<string>()
    if (tables.has('assignments')) {
      const cols = listColumns(db, 'assignments')
      const want = ['status', 'session_id'].filter(c => cols.has(c))
      if (want.length > 0) {
        const sql = runId && cols.has('run_id')
          ? `SELECT ${want.join(', ')} FROM assignments WHERE run_id = ?`
          : `SELECT ${want.join(', ')} FROM assignments`
        const rows = (runId && cols.has('run_id')
          ? db.prepare(sql).all(runId)
          : db.prepare(sql).all()) as SqliteRow[]
        for (const row of rows) {
          workers.total += 1
          const st = typeof row.status === 'string' ? row.status.toLowerCase() : ''
          if (st === 'running' || st === 'active' || st === 'in_progress' || st === 'leased' || st === 'pending' || st === 'queued') {
            workers.running += 1
          } else if (st === 'complete' || st === 'completed' || st === 'done' || st === 'succeeded') {
            workers.completed += 1
          } else if (st === 'failed' || st === 'error' || st === 'stalled' || st === 'canceled' || st === 'cancelled' || st === 'timed_out') {
            workers.failed += 1
          }
          if (typeof row.session_id === 'string' && row.session_id.trim()) {
            sessionIds.add(row.session_id.trim())
          }
        }
      }
    }

    // --- Confirmed findings (structured metadata ONLY: kind, cwe, route) ---
    const confirmedFindings: ConfirmedFindingSummary[] = []
    if (tables.has('findings')) {
      const cols = listColumns(db, 'findings')
      const want = ['status', 'finding_kind', 'check_id', 'cwe', 'finding'].filter(c => cols.has(c))
      if (want.length > 0) {
        const sql = runId && cols.has('run_id')
          ? `SELECT ${want.join(', ')} FROM findings WHERE run_id = ?`
          : `SELECT ${want.join(', ')} FROM findings`
        const rows = (runId && cols.has('run_id')
          ? db.prepare(sql).all(runId)
          : db.prepare(sql).all()) as SqliteRow[]
        for (const row of rows) {
          const parsed = safeJsonParse(row.finding)
          const fObj = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
            ? parsed as Record<string, unknown>
            : null
          const rowStatus = typeof row.status === 'string' ? row.status.toLowerCase() : ''
          const jsonStatus = typeof fObj?.status === 'string' ? fObj.status.toLowerCase() : ''
          if (rowStatus !== 'confirmed' && jsonStatus !== 'confirmed') continue

          const ev = fObj?.evidence && typeof fObj.evidence === 'object' && !Array.isArray(fObj.evidence)
            ? fObj.evidence as Record<string, unknown>
            : null
          const compVer = ev?.compositeVerification && typeof ev.compositeVerification === 'object'
            ? ev.compositeVerification as Record<string, unknown>
            : null
          const kind = String(
            (typeof row.finding_kind === 'string' && row.finding_kind.trim())
              ? row.finding_kind.trim()
              : (typeof fObj?.kind === 'string' && fObj.kind.trim())
                ? fObj.kind.trim()
                : (typeof row.check_id === 'string' && row.check_id.trim())
                  ? row.check_id.trim()
                  : 'unknown',
          )
          const cwe = String(
            (typeof row.cwe === 'string' && row.cwe.trim())
              ? row.cwe.trim()
              : (typeof fObj?.cwe === 'string' && fObj.cwe.trim())
                ? fObj.cwe.trim()
                : 'n/a',
          )
          const route = sanitizeRoutePath(
            compVer?.terminalEndpoint
              ?? ev?.terminalEndpoint
              ?? fObj?.route
              ?? fObj?.endpoint
              ?? fObj?.path
              ?? fObj?.url,
          )
          confirmedFindings.push({ kind, cwe, route })
        }
      }
    }

    // --- Reject reasons + systemic error detection (events, replay_specs, agent-sessions) ---
    const rejectMap = new Map<string, RejectReasonSummary>()
    const systemicErrors: SystemicErrorCounts = { ...emptySystemic }
    let latestEventAt: number | null = null
    let eventWorkerCompleted = 0
    let eventWorkerFailed = 0

    const recordReject = (rawReason: unknown, rawSig?: unknown): void => {
      const reason = normalizeRejectKey(rawReason) ?? 'rejected'
      const signature = sanitizeLiveSignature(rawSig ?? rawReason)
      const key = `${reason}\0${signature}`
      const prev = rejectMap.get(key)
      if (prev) prev.count += 1
      else rejectMap.set(key, { reason, signature, count: 1 })
      classifySystemicError(reason, signature, systemicErrors, 1)
    }

    if (tables.has('events')) {
      const cols = listColumns(db, 'events')
      const want = ['kind', 'detail', 'created_at'].filter(c => cols.has(c))
      if (cols.has('kind')) {
        const sql = runId && cols.has('run_id')
          ? `SELECT ${want.join(', ')} FROM events WHERE run_id = ?`
          : `SELECT ${want.join(', ')} FROM events`
        const rows = (runId && cols.has('run_id')
          ? db.prepare(sql).all(runId)
          : db.prepare(sql).all()) as SqliteRow[]
        for (const row of rows) {
          const kind = typeof row.kind === 'string' ? row.kind : ''
          const ts = finiteNum(row.created_at)
          if (ts !== null && ts > 0) latestEventAt = latestEventAt === null ? ts : Math.max(latestEventAt, ts)
          const parsed = safeJsonParse(row.detail)
          const detail = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
            ? parsed as Record<string, unknown>
            : {}

          if (kind === 'worker.complete') eventWorkerCompleted += 1
          else if (kind === 'worker.failed' || kind === 'worker.stall_failed' || kind === 'worker.canceled') {
            eventWorkerFailed += 1
          }

          const isRejectEvent = kind === 'composite.rejected'
            || kind === 'kovo_verify.rejected'
            || kind === 'kovo_verify.failed'
            || kind === 'agent.script_proof_rejected'
            || kind === 'verify_rpc.rejected'
            || kind === 'verify_rpc.error'
            || kind === 'proof_receipt.shadow_reject'
            || kind === 'oob.receipt_rejected'
            || kind === 'agent.verify_checkpoint_blocked'
            || ((kind === 'verify_rpc.call' || kind === 'verify_rpc.op' || kind === 'kovo_verify.rpc' || kind === 'composite.verify')
              && (detail.ok === false || detail.confirmed === false))

          if (isRejectEvent) {
            const rawReason = detail.rejectedBy ?? detail.failedStage ?? detail.rejectReason ?? detail.errorCode ?? detail.reason ?? kind
            const rawSig = detail.reason ?? detail.detail ?? detail.error ?? detail.message ?? rawReason
            recordReject(rawReason, rawSig)
          }
        }
      }
    }

    if (tables.has('replay_specs')) {
      const cols = listColumns(db, 'replay_specs')
      const want = ['proof_verdict', 'proof_receipt', 'last_verification_diff'].filter(c => cols.has(c))
      if (want.length > 0) {
        const sql = runId && cols.has('run_id')
          ? `SELECT ${want.join(', ')} FROM replay_specs WHERE run_id = ?`
          : `SELECT ${want.join(', ')} FROM replay_specs`
        const rows = (runId && cols.has('run_id')
          ? db.prepare(sql).all(runId)
          : db.prepare(sql).all()) as SqliteRow[]
        for (const row of rows) {
          const pr = safeJsonParse(row.proof_receipt) as Record<string, unknown> | null
          const compVer = (pr?.compositeVerification ?? pr?.verification) as Record<string, unknown> | undefined
          if (compVer && compVer.confirmed === false) {
            recordReject(compVer.rejectedBy ?? compVer.failedStage ?? compVer.reason, compVer.reason ?? compVer.failedStage)
          }
          const diff = safeJsonParse(row.last_verification_diff) as Record<string, unknown> | null
          if (diff && typeof diff.verdict === 'string' && diff.verdict !== 'confirmed') {
            const summary = diff.assertionSummary && typeof diff.assertionSummary === 'object'
              ? diff.assertionSummary as Record<string, unknown>
              : null
            recordReject(summary?.reason ?? diff.reason ?? diff.verdict, summary?.reason ?? diff.reason)
          }
        }
      }
    }

    // Optional read-only agent-sessions toolResult scan for kovo_verify rejections (never prints script/bodies).
    const sessionsDir = join(dirname(dbPath), 'agent-sessions')
    if (sessionIds.size > 0 && existsSync(sessionsDir)) {
      for (const sid of sessionIds) {
        const sessionPath = join(sessionsDir, `${sid}.sqlite`)
        if (!existsSync(sessionPath)) continue
        let sdb: DatabaseSync | undefined
        try {
          sdb = new DatabaseSync(sessionPath, { readOnly: true })
          const rows = sdb.prepare('SELECT record FROM entries ORDER BY commit_seq ASC').all() as Array<{ record?: unknown }>
          const verifyCallIds = new Set<string>()
          for (const r of rows) {
            const parsed = safeJsonParse(r.record) as { model?: Array<Record<string, unknown>> } | null
            for (const msg of Array.isArray(parsed?.model) ? parsed.model : []) {
              if (msg.role === 'assistant' && Array.isArray(msg.content)) {
                for (const block of msg.content as Array<Record<string, unknown>>) {
                  if (block.type === 'toolCall' && block.name === 'kovo_verify' && typeof block.id === 'string') {
                    verifyCallIds.add(block.id)
                  }
                }
              } else if (msg.role === 'toolResult' && typeof msg.toolCallId === 'string' && verifyCallIds.has(msg.toolCallId)) {
                const text = typeof msg.content === 'string'
                  ? msg.content
                  : Array.isArray(msg.content)
                    ? (msg.content as Array<{ text?: unknown }>).map(p => (typeof p?.text === 'string' ? p.text : '')).join('\n')
                    : ''
                const obj = safeJsonParse(text) as Record<string, unknown> | null
                if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue
                const verdict = obj.verdict && typeof obj.verdict === 'object' ? obj.verdict as Record<string, unknown> : null
                const cr = obj.compositeReceipt && typeof obj.compositeReceipt === 'object'
                  ? obj.compositeReceipt as Record<string, unknown>
                  : null
                if (obj.confirmed === false || verdict?.confirmed === false || cr?.confirmed === false || obj.checkpointBlocked === true) {
                  const rawReason = obj.checkpointBlocked === true
                    ? 'checkpoint_blocked'
                    : (cr?.rejectedBy ?? cr?.failedStage ?? verdict?.reason ?? obj.rejectedBy ?? obj.reason ?? obj.errorCode)
                  const rawSig = cr?.reason ?? verdict?.detail ?? obj.detail ?? obj.reason ?? rawReason
                  recordReject(rawReason, rawSig)
                }
              }
            }
          }
        } catch {
          // Best-effort read-only session peek; skip locked/partial WAL sessions.
        } finally {
          try { sdb?.close() } catch { /* ignore */ }
        }
      }
    }

    if (workers.completed === 0 && workers.failed === 0 && (eventWorkerCompleted > 0 || eventWorkerFailed > 0)) {
      workers.completed = eventWorkerCompleted
      workers.failed = eventWorkerFailed
      workers.total = Math.max(workers.total, eventWorkerCompleted + eventWorkerFailed)
    }
    workers.finished = workers.completed + workers.failed
    workers.failureRate = workers.finished > 0
      ? Math.round((workers.failed / workers.finished) * 10000) / 10000
      : 0

    const isTerminalStatus = status === 'complete' || status === 'completed' || status === 'failed' || status === 'canceled' || status === 'cancelled'
    const endTs = isTerminalStatus && latestEventAt !== null ? latestEventAt : nowMs
    const elapsedMin = runCreatedAt !== null && runCreatedAt > 0
      ? Math.round(Math.max(0, endTs - runCreatedAt) / 600) / 100
      : 0

    const topRejectReasons = [...rejectMap.values()]
      .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason) || a.signature.localeCompare(b.signature))
      .slice(0, 8)

    const alert = evaluateWatchdogAlerts(systemicErrors, workers, thresholds)

    return {
      cell: cellLabel,
      dbPath,
      runId,
      phase,
      status,
      costUsd,
      elapsedMin,
      turnsUsed,
      requestsUsed,
      workers,
      confirmedFindings,
      topRejectReasons,
      systemicErrors,
      abortRecommended: alert.abortRecommended,
      abortReasons: alert.abortReasons,
    }
  } catch (err) {
    return {
      cell: cellLabel,
      dbPath,
      runId: null,
      phase: 'unreadable',
      status: 'unreadable',
      costUsd: 0,
      elapsedMin: 0,
      turnsUsed: 0,
      requestsUsed: 0,
      workers: emptyWorkers,
      confirmedFindings: [],
      topRejectReasons: [],
      systemicErrors: emptySystemic,
      abortRecommended: false,
      abortReasons: [],
      readError: sanitizeLiveSignature((err as Error).message),
    }
  } finally {
    try { db?.close() } catch { /* ignore */ }
  }
}

/**
 * Inspect all active cell SQLite DBs under one or more `--out-dir` directories.
 */
export function peekLiveOutDir(options: PeekLiveOptions): LivePeekReport {
  const thresholds: WatchdogThresholds = {
    systemicThreshold: options.thresholds?.systemicThreshold ?? DEFAULT_WATCHDOG_THRESHOLDS.systemicThreshold,
    workerFailureRateThreshold: options.thresholds?.workerFailureRateThreshold ?? DEFAULT_WATCHDOG_THRESHOLDS.workerFailureRateThreshold,
    minFinishedWorkers: options.thresholds?.minFinishedWorkers ?? DEFAULT_WATCHDOG_THRESHOLDS.minFinishedWorkers,
  }
  const nowMs = options.nowMs ?? Date.now()
  const roots = options.outDirs.map(d => resolve(d))
  const discovered = discoverCellDatabases(roots)
  const cells = discovered.map(item => peekCellDatabase(item.dbPath, item.cell, thresholds, nowMs))
  const abortCells = cells.filter(c => c.abortRecommended).map(c => c.cell)
  const totalCostUsd = Math.round(cells.reduce((sum, c) => sum + c.costUsd, 0) * 10000) / 10000
  const totalConfirmedFindings = cells.reduce((sum, c) => sum + c.confirmedFindings.length, 0)

  return {
    scannedAt: new Date(nowMs).toISOString(),
    roots,
    thresholds,
    cellsFound: cells.length,
    totalCostUsd,
    totalConfirmedFindings,
    abortRecommended: abortCells.length > 0,
    abortCells,
    cells,
  }
}

/** Render a concise, secret-free watchdog table for terminal display. */
export function formatLivePeekReport(report: LivePeekReport): string {
  const lines: string[] = []
  lines.push(
    `Live Mid-Run Watchdog (${report.scannedAt}) — cells=${report.cellsFound}, `
    + `confirmed=${report.totalConfirmedFindings}, cost=$${report.totalCostUsd.toFixed(4)}`,
  )
  if (report.abortRecommended) {
    lines.push(`!!! ABORT_RECOMMENDED on ${report.abortCells.length} cell(s): ${report.abortCells.join(', ')} !!!`)
  } else {
    lines.push('Watchdog status: HEALTHY (no abort triggers)')
  }

  if (report.cells.length === 0) {
    lines.push(`No active kovo.sqlite cell databases found under: ${report.roots.join(', ')}`)
    return `${lines.join('\n')}\n`
  }

  for (const c of report.cells) {
    lines.push('')
    const flag = c.abortRecommended ? ' [ABORT_RECOMMENDED]' : ''
    lines.push(
      `Cell: ${c.cell}${flag} | phase=${c.phase} status=${c.status} `
      + `elapsed=${c.elapsedMin.toFixed(2)}m cost=$${c.costUsd.toFixed(4)} `
      + `workers=${c.workers.completed}/${c.workers.total} (run=${c.workers.running}, fail=${c.workers.failed}, failRate=${Math.round(c.workers.failureRate * 100)}%)`,
    )
    if (c.readError) {
      lines.push(`  readError: ${c.readError}`)
      continue
    }
    if (c.abortReasons.length > 0) {
      lines.push(`  ABORT_RECOMMENDED: ${c.abortReasons.join('; ')}`)
    }
    if (c.confirmedFindings.length > 0) {
      lines.push(`  confirmedFindings (${c.confirmedFindings.length}):`)
      for (const f of c.confirmedFindings) {
        lines.push(`    - kind=${f.kind} cwe=${f.cwe} route=${f.route}`)
      }
    } else {
      lines.push('  confirmedFindings (0)')
    }
    if (c.topRejectReasons.length > 0) {
      lines.push('  topRejectReasons:')
      for (const r of c.topRejectReasons.slice(0, 5)) {
        lines.push(`    ${String(r.count).padStart(4)}x [${r.reason}] ${r.signature}`)
      }
    }
  }

  return `${lines.join('\n')}\n`
}

interface ParsedPeekArgs {
  outDirs: string[]
  systemicThreshold?: number
  workerFailureRateThreshold?: number
  minFinishedWorkers?: number
  jsonOut?: string
  help: boolean
}

function parsePeekArgs(argv: readonly string[]): ParsedPeekArgs {
  const out: ParsedPeekArgs = { outDirs: [], help: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '-h' || arg === '--help') {
      out.help = true
    } else if (arg === '--out-dir') {
      const val = argv[++i]
      if (!val) throw new Error('--out-dir requires a path')
      out.outDirs.push(val)
    } else if (arg.startsWith('--out-dir=')) {
      out.outDirs.push(arg.slice('--out-dir='.length))
    } else if (arg === '--systemic-threshold') {
      out.systemicThreshold = Number(argv[++i])
    } else if (arg.startsWith('--systemic-threshold=')) {
      out.systemicThreshold = Number(arg.slice('--systemic-threshold='.length))
    } else if (arg === '--worker-fail-rate') {
      out.workerFailureRateThreshold = Number(argv[++i])
    } else if (arg.startsWith('--worker-fail-rate=')) {
      out.workerFailureRateThreshold = Number(arg.slice('--worker-fail-rate='.length))
    } else if (arg === '--min-workers') {
      out.minFinishedWorkers = Number(argv[++i])
    } else if (arg.startsWith('--min-workers=')) {
      out.minFinishedWorkers = Number(arg.slice('--min-workers='.length))
    } else if (arg === '--json') {
      const next = argv[i + 1]
      if (next && !next.startsWith('-')) out.jsonOut = argv[++i]
      else out.jsonOut = '-'
    } else if (arg.startsWith('--json=')) {
      out.jsonOut = arg.slice('--json='.length)
    } else if (!arg.startsWith('-')) {
      out.outDirs.push(arg)
    } else {
      throw new Error(`Unknown argument: ${arg}`)
    }
  }
  return out
}

const USAGE = [
  'Usage: node --experimental-strip-types scripts/peek-v8-live.ts --out-dir <path> [options]',
  '',
  'Options:',
  '  --out-dir <path>           Benchmark out-dir to inspect (repeatable; positional paths also accepted)',
  '  --systemic-threshold <N>   Systemic error count trigger for ABORT_RECOMMENDED (default: 3)',
  '  --worker-fail-rate <0..1>  Worker failure rate trigger for ABORT_RECOMMENDED (default: 0.5)',
  '  --min-workers <N>          Minimum finished workers before fail-rate check (default: 2)',
  '  --json [out.json]          Output structured JSON (stdout with "-" / bare flag, or write to file)',
  '  -h, --help                 Show this help',
].join('\n')

function main(): void {
  const args = parsePeekArgs(process.argv.slice(2))
  if (args.help) {
    process.stdout.write(`${USAGE}\n`)
    return
  }
  if (args.outDirs.length === 0) {
    process.stderr.write(`Error: at least one --out-dir <path> is required.\n\n${USAGE}\n`)
    process.exit(2)
  }

  const report = peekLiveOutDir({
    outDirs: args.outDirs,
    thresholds: {
      ...(args.systemicThreshold !== undefined && Number.isFinite(args.systemicThreshold)
        ? { systemicThreshold: args.systemicThreshold }
        : {}),
      ...(args.workerFailureRateThreshold !== undefined && Number.isFinite(args.workerFailureRateThreshold)
        ? { workerFailureRateThreshold: args.workerFailureRateThreshold }
        : {}),
      ...(args.minFinishedWorkers !== undefined && Number.isFinite(args.minFinishedWorkers)
        ? { minFinishedWorkers: args.minFinishedWorkers }
        : {}),
    },
  })

  if (args.jsonOut === '-') {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  } else {
    process.stdout.write(formatLivePeekReport(report))
    if (args.jsonOut) {
      const outPath = resolve(args.jsonOut)
      mkdirSync(dirname(outPath), { recursive: true })
      writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8')
      process.stdout.write(`Wrote JSON report: ${outPath}\n`)
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main()
  } catch (err) {
    process.stderr.write(`peek-v8-live error: ${(err as Error).message}\n`)
    process.exit(1)
  }
}
