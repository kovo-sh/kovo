/**
 * Process-wide registry of per-run in-memory state disposers (R2-08).
 *
 * Any module under `src/server/**` that maintains module-level state keyed by
 * `runId` / `assignmentId` / `persona` registers its synchronous disposer here
 * at module load time. `Execution.cleanupRunState(runId)` drains every
 * registered disposer deterministically when a run finishes, cancels, or is
 * disposed — preventing silent memory growth and cross-run state bleed.
 */

export type RunDisposerFn = (runId: string) => void

export interface RunDisposerDrainResult {
  readonly runId: string
  readonly invoked: number
  readonly errors: ReadonlyArray<{ name: string; error: string }>
}

const runDisposers = new Map<string, RunDisposerFn>()

/**
 * Register (or replace by name) a synchronous per-run disposer invoked during
 * `Execution.cleanupRunState(runId)`. Returns an idempotent unregister handle.
 */
export function registerRunDisposer(name: string, fn: RunDisposerFn): () => void {
  const key = name.trim()
  if (!key) throw new Error('registerRunDisposer requires a non-empty disposer name.')
  runDisposers.set(key, fn)
  return () => {
    if (runDisposers.get(key) === fn) {
      runDisposers.delete(key)
    }
  }
}

/**
 * Drain every registered per-run disposer for `runId`.
 * Each disposer runs in isolation so a single throw never skips later disposers.
 */
export function runAllRunDisposers(runId: string): RunDisposerDrainResult {
  const normalized = typeof runId === 'string' ? runId.trim() : ''
  if (!normalized) {
    return { runId: '', invoked: 0, errors: [] }
  }
  let invoked = 0
  const errors: Array<{ name: string; error: string }> = []
  for (const [name, fn] of [...runDisposers.entries()]) {
    invoked += 1
    try {
      fn(normalized)
    } catch (err) {
      errors.push({
        name,
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }
  return { runId: normalized, invoked, errors }
}

// ---------------------------------------------------------------------------
// R3-07: Structured lifecycle settlement reporting with known-race classification
// ---------------------------------------------------------------------------

export type KnownSettlementRaceKind =
  | 'run_not_found'
  | 'assignment_not_found'
  | 'store_closed'
  | 'already_terminal'
  | 'aborted'

export type SettlementErrorReporter = (
  runId: string,
  kind: string,
  message: string,
  detail?: Record<string, unknown>,
) => void

export interface SettlementResult<T = void> {
  readonly ok: boolean
  readonly value?: T
  readonly race?: KnownSettlementRaceKind
  readonly error?: string
}

const RUN_NOT_FOUND_RE = /\brun\s+not\s+found\b|foreign\s+key\s+constraint\s+failed|\bno\s+such\s+run\b/i
const ASSIGNMENT_NOT_FOUND_RE = /\b(?:assignment|worker)\s+not\s+found\b/i
const STORE_CLOSED_RE = /database(?:\s+connection)?\s+is\s+not\s+open|sqlite_misuse|store(?:\s+is)?\s+closed|connection\s+closed/i
const ALREADY_TERMINAL_RE = /already\s+(?:terminal|complete|completed|canceled|cancelled|failed|stopped|settled)|cannot\s+(?:park|resume|settle)\s+an?\s+assignment\s+in\s+state\s+(?:complete|failed|canceled)/i
const ABORTED_RE = /\babort(?:ed|error)\b|signal\s+is\s+aborted/i

function formatSettlementError(err: unknown): string {
  if (err instanceof Error) return err.message || err.name
  return String(err)
}

/**
 * Classify benign, expected lifecycle races (deleted run, closed store during teardown,
 * already-terminal row, or explicit abort) so `settleOrReport` suppresses noisy
 * `lifecycle.settlement_failed` alerts while still surfacing real settlement failures.
 */
export function classifyKnownSettlementRace(error: unknown): KnownSettlementRaceKind | null {
  if (error instanceof Error && error.name === 'AbortError') return 'aborted'
  const msg = formatSettlementError(error)
  if (STORE_CLOSED_RE.test(msg)) return 'store_closed'
  if (RUN_NOT_FOUND_RE.test(msg)) return 'run_not_found'
  if (ASSIGNMENT_NOT_FOUND_RE.test(msg)) return 'assignment_not_found'
  if (ALREADY_TERMINAL_RE.test(msg)) return 'already_terminal'
  if (ABORTED_RE.test(msg)) return 'aborted'
  return null
}

function handleSettlementFailure<T>(
  runId: string,
  kind: string,
  err: unknown,
  report?: SettlementErrorReporter,
  detail?: Record<string, unknown>,
): SettlementResult<T> {
  const error = formatSettlementError(err).slice(0, 400)
  const race = classifyKnownSettlementRace(err)
  if (race) {
    return { ok: false, race, error }
  }
  if (report && runId) {
    try {
      report(
        runId,
        'lifecycle.settlement_failed',
        `Lifecycle settlement failed (${kind}): ${error}`,
        { settlementKind: kind, error, ...(detail ?? {}) },
      )
    } catch (reportErr) {
      // Never cascade if the store/event sink itself failed concurrently.
      void reportErr
    }
  }
  return { ok: false, error }
}

/**
 * Execute a synchronous lifecycle settlement/reconciliation action and emit a structured
 * `lifecycle.settlement_failed` event on unexpected errors (while quietly suppressing
 * classified known races such as a deleted run or already-closed store).
 */
export function settleOrReport<T>(
  runId: string,
  kind: string,
  fn: () => T,
  report?: SettlementErrorReporter,
  detail?: Record<string, unknown>,
): SettlementResult<T> {
  try {
    const value = fn()
    return { ok: true, value }
  } catch (err) {
    return handleSettlementFailure<T>(runId, kind, err, report, detail)
  }
}

/**
 * Async counterpart to `settleOrReport` for promise-returning settlement, eviction, or
 * audit hooks (e.g., `warm-pool:evict`, `runSourceFirstCodeAudit`).
 */
export async function settleOrReportAsync<T>(
  runId: string,
  kind: string,
  fn: () => Promise<T>,
  report?: SettlementErrorReporter,
  detail?: Record<string, unknown>,
): Promise<SettlementResult<T>> {
  try {
    const value = await fn()
    return { ok: true, value }
  } catch (err) {
    return handleSettlementFailure<T>(runId, kind, err, report, detail)
  }
}
