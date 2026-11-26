/**
 * v6 bounded pre-report OOB drain.
 *
 * A background worker can trigger an SSRF/XXE/webhook callback long after the HTTP response
 * (Fixture #2: 15–30 s). Finalizing the report as soon as verification workers settle dropped
 * exactly those callbacks. This waits up to `KOVO_OOB_DRAIN_MS` (default 45 s), promotes late
 * callbacks on every poll, and returns the recorded metrics. It never waits when nothing is
 * pending, so local-lab benchmark runs keep their zero-latency behavior.
 */
import { eq } from 'drizzle-orm'
import { reports } from './schema.ts'
import type { Assignment, Run, Store } from './store.ts'

/** Bounded grace the report waits for late async OOB callbacks (Fixture #2: 15–30 s). */
export const DEFAULT_OOB_DRAIN_MS = 45_000
/** How often the drain promotes pending subscriptions while it waits. */
export const OOB_DRAIN_POLL_MS = 1_000

/** Resolve the bounded pre-report OOB drain grace (`KOVO_OOB_DRAIN_MS`, default 45 s). */
export function resolveOobDrainMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.KOVO_OOB_DRAIN_MS)
  if (!Number.isFinite(raw) || raw < 0) return DEFAULT_OOB_DRAIN_MS
  return Math.min(10 * 60_000, Math.round(raw))
}

export interface OobDrainRelay {
  promoteLate(options: { runId: string; now: number }): unknown[]
  pending(runId?: string): unknown[]
}

export interface OobDrainError {
  phase: 'preflight_pending' | 'promote_late' | 'pending_check' | 'drain'
  message: string
  code?: string
  at: number
}

export interface OobDrainResult {
  oobDrainMs: number
  promotedLate: number
  remaining: number
  /** Structured diagnostics for relay/SQLite errors observed during drain (omitted when healthy). */
  errors?: OobDrainError[]
  /** True when relay/SQLite failures prevented verifying or promoting pending OOB callbacks. */
  degraded?: boolean
  /** Explicit report coverage gap line when `degraded` is true. */
  coverageGap?: string
}

export interface OobDrainOptions {
  graceMs?: number
  pollMs?: number
  /** Injected clock (fake-clock tests); defaults to `Date.now`. */
  now?: () => number
  sleep?: (ms: number) => Promise<void>
  /** Optional abort signal to cancel waiting early (e.g. run stopped/deleted). */
  signal?: AbortSignal
  /** Optional observer invoked whenever a non-deletion relay/storage error occurs during drain. */
  onError?: (error: unknown) => void
}

const MAX_RECORDED_DRAIN_ERRORS = 20

function formatDrainError(phase: OobDrainError['phase'], error: unknown, at: number): OobDrainError {
  const err = error && typeof error === 'object' ? (error as { message?: unknown; code?: unknown }) : null
  const rawMessage = typeof err?.message === 'string' && err.message.trim()
    ? err.message.trim()
    : (typeof error === 'string' && error.trim() ? error.trim() : String(error))
  const code = typeof err?.code === 'string' && err.code.trim() ? err.code.trim() : undefined
  return {
    phase,
    message: rawMessage.slice(0, 300),
    ...(code ? { code } : {}),
    at,
  }
}

/** Build an explicit report coverage gap line for relay/SQLite errors during pre-report OOB drain. */
export function buildOobDrainCoverageGap(errors: readonly OobDrainError[]): string {
  const phases = [...new Set(errors.map(e => e.phase))].join(', ') || 'drain'
  const first = errors[0]
  const codeSuffix = first?.code ? ` [${first.code}]` : ''
  const detail = first?.message ? `: ${first.message}` : ''
  return `OOB callback drain degraded (${errors.length} relay/storage error${errors.length === 1 ? '' : 's'} during ${phases}${codeSuffix})${detail}; late async OOB callbacks could not be verified before finalizing.`
}

const activeDrainControllers = new Map<string, Set<AbortController>>()
const activeFinalizingRuns = new Set<string>()

/** True while a run has an active OOB drain poll or async finalization in flight. */
export function isOobDrainActive(runId: string): boolean {
  return activeFinalizingRuns.has(runId) || (activeDrainControllers.get(runId)?.size ?? 0) > 0
}

/** Abort any in-flight OOB drain poll for `runId` (called when stopping/deleting a run). */
export function cancelOobDrainForRun(runId: string): void {
  const controllers = activeDrainControllers.get(runId)
  if (!controllers) return
  for (const controller of [...controllers]) {
    try { controller.abort(new Error('Run deleted during OOB drain.')) } catch { /* ignore */ }
  }
}

/**
 * Identify benign race errors raised when a run is deleted concurrently while async finalization
 * or OOB drain is completing. Genuine unexpected storage failures (e.g. disk I/O, corruption)
 * return `false` so they are never silently swallowed.
 */
export function isDeletedRunRaceError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const err = error as { message?: unknown; code?: unknown; errstr?: unknown; cause?: unknown }
  const message = typeof err.message === 'string' ? err.message : ''
  const errstr = typeof err.errstr === 'string' ? err.errstr : ''
  const code = typeof err.code === 'string' ? err.code : ''
  if (/\brun not found\b/i.test(message)) return true
  if (/FOREIGN KEY constraint failed/i.test(message) || /FOREIGN KEY constraint failed/i.test(errstr)) return true
  if (code === 'SQLITE_CONSTRAINT_FOREIGNKEY') return true
  if (err.cause && err.cause !== error) return isDeletedRunRaceError(err.cause)
  return false
}

function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve()
  return new Promise<void>(resolve => {
    const onAbort = () => {
      clearTimeout(timer)
      resolve()
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

/** Promote late callbacks within a bounded grace window and report the drained metrics. */
export async function drainPendingOob(
  relay: OobDrainRelay,
  runId: string,
  options: OobDrainOptions = {},
): Promise<OobDrainResult> {
  const controller = new AbortController()
  let set = activeDrainControllers.get(runId)
  if (!set) {
    set = new Set()
    activeDrainControllers.set(runId, set)
  }
  set.add(controller)
  const signal = options.signal ? AbortSignal.any([controller.signal, options.signal]) : controller.signal

  const now = options.now ?? (() => Date.now())
  const sleep = options.sleep ?? ((ms: number) => abortableSleep(ms, signal))
  const graceMs = Math.max(0, options.graceMs ?? resolveOobDrainMs())
  const pollMs = Math.max(1, options.pollMs ?? OOB_DRAIN_POLL_MS)
  const started = now()
  let promotedLate = 0
  let lastKnownRemaining = 0
  let lastPromoteOk = true
  let lastPendingOk = true
  const errors: OobDrainError[] = []

  const recordError = (phase: OobDrainError['phase'], error: unknown): void => {
    if (errors.length < MAX_RECORDED_DRAIN_ERRORS) {
      errors.push(formatDrainError(phase, error, now()))
    }
    options.onError?.(error)
  }

  const promote = (): boolean => {
    try {
      promotedLate += relay.promoteLate({ runId, now: now() }).length
      lastPromoteOk = true
      return true
    } catch (error) {
      if (isDeletedRunRaceError(error)) throw error
      lastPromoteOk = false
      recordError('promote_late', error)
      return false
    }
  }
  const pendingCount = (): { count: number; ok: boolean } => {
    try {
      const count = relay.pending(runId).length
      lastKnownRemaining = count
      lastPendingOk = true
      return { count, ok: true }
    } catch (error) {
      if (isDeletedRunRaceError(error)) throw error
      lastPendingOk = false
      recordError('pending_check', error)
      return { count: lastKnownRemaining, ok: false }
    }
  }

  const buildResult = (oobDrainMs: number, remaining: number): OobDrainResult => {
    const degraded = !lastPromoteOk || !lastPendingOk || (errors.length > 0 && remaining > 0)
    if (errors.length === 0) {
      return { oobDrainMs, promotedLate, remaining }
    }
    return {
      oobDrainMs,
      promotedLate,
      remaining,
      errors,
      ...(degraded ? { degraded: true, coverageGap: buildOobDrainCoverageGap(errors) } : {}),
    }
  }

  try {
    if (signal.aborted) {
      const check = pendingCount()
      return buildResult(0, check.count)
    }
    promote()
    let check = pendingCount()
    let remaining = check.count
    const maxPolls = Math.ceil(graceMs / pollMs) + 2
    let polls = 0
    while (!signal.aborted && check.ok && remaining > 0 && now() - started < graceMs && polls < maxPolls) {
      polls += 1
      const budget = graceMs - (now() - started)
      await sleep(Math.max(1, Math.min(pollMs, budget)))
      if (signal.aborted) break
      promote()
      check = pendingCount()
      remaining = check.count
    }
    return buildResult(Math.max(0, now() - started), remaining)
  } finally {
    set.delete(controller)
    if (set.size === 0) activeDrainControllers.delete(runId)
  }
}

/** Minimal store surface needed to finalize a verification report. */
export interface FinalizeStore {
  run(id: string): Run
  transaction<T>(fn: () => T, options?: { behavior?: string }): T
  updateRun(id: string, patch: { phase?: string; status?: string }): Run
  writeReport(run: Run, partial: boolean): string
  message(runId: string, authorId: string, authorRole: string, body: string): unknown
  workerList?(runId: string): Assignment[]
  db?: Store['db']
}

export interface FinalizeHost {
  storage: FinalizeStore
  relay: OobDrainRelay
  /** runIds whose report is waiting on the bounded drain (single-flight). */
  draining: Set<string>
  /** Last drain outcome per run, surfaced in report meta. */
  lastDrain: Map<string, OobDrainResult>
  /** Optional drain entry point (tests/benchmarks can substitute a fake-clock drain). */
  drain?: (runId: string, signal?: AbortSignal) => Promise<OobDrainResult>
  /** Optional structured task spawner (e.g. `RunActor.spawn`) to avoid detached `void` async chains. */
  spawn?: (label: string, fn: (signal: AbortSignal) => Promise<void>) => unknown
  /** Optional callback returning explicit gap lines for failed/exhausted verification workers (`H-27`). */
  collectFailureGaps?: (run: Run) => string[]
  /** Optional callback fired after `commitFinalReport` completes (sync or async). */
  onFinalized?: (runId: string) => void
  /** Optional observer for unexpected non-deletion storage errors during async finalization. */
  onError?: (error: unknown) => void
}

/** Build explicit report gap lines for failed verification workers in the current goal revision (`H-27`). */
export function collectVerificationFailureGaps(
  workers: readonly Assignment[],
  goalRevision: number,
): string[] {
  const gaps: string[] = []
  for (const w of workers) {
    if (w.phase !== 'verification' || w.goalRevision !== goalRevision || w.status !== 'failed') continue
    const attempts = w.attempt > 0 ? ` after ${w.attempt} attempt${w.attempt === 1 ? '' : 's'}` : ''
    const detail = (w.outcome ?? '').trim() || 'verification worker failed before completion'
    gaps.push(`Verification worker failed${attempts} (${w.title}): ${detail}`)
  }
  return gaps
}

/**
 * Single-flight finalize: drain pending async OOB subscriptions first when any exist, then write
 * the complete report exactly once. Never waits when nothing is pending.
 */
export function scheduleFinalReport(host: FinalizeHost, run: Run): void {
  if (host.draining.has(run.id)) return
  let pending = 0
  let preflightError: OobDrainError | null = null
  try {
    pending = host.relay.pending(run.id).length
  } catch (error) {
    if (isDeletedRunRaceError(error)) {
      host.lastDrain.delete(run.id)
      return
    }
    preflightError = formatDrainError('preflight_pending', error, Date.now())
    host.onError?.(error)
  }
  if (preflightError) {
    host.lastDrain.set(run.id, {
      oobDrainMs: 0,
      promotedLate: 0,
      remaining: 0,
      degraded: true,
      errors: [preflightError],
      coverageGap: buildOobDrainCoverageGap([preflightError]),
    })
    commitFinalReport(host, run)
    host.onFinalized?.(run.id)
    return
  }
  if (pending === 0) {
    commitFinalReport(host, run)
    host.onFinalized?.(run.id)
    return
  }
  host.draining.add(run.id)
  activeFinalizingRuns.add(run.id)
  const drain = host.drain ?? ((runId: string, signal?: AbortSignal) => drainPendingOob(host.relay, runId, {
    signal,
    ...(host.onError ? { onError: host.onError } : {}),
  }))
  const runAsyncFinalize = async (signal?: AbortSignal) => {
    try {
      try {
        const result = await drain(run.id, signal)
        host.lastDrain.set(run.id, result)
      } catch (error) {
        if (isDeletedRunRaceError(error)) {
          host.lastDrain.delete(run.id)
          return
        }
        // Surface unexpected drain failures as an explicit coverage gap rather than silently finalizing clean.
        const drainErr = formatDrainError('drain', error, Date.now())
        host.lastDrain.set(run.id, {
          oobDrainMs: 0,
          promotedLate: 0,
          remaining: pending,
          degraded: true,
          errors: [drainErr],
          coverageGap: buildOobDrainCoverageGap([drainErr]),
        })
        host.onError?.(error)
      }
      if (signal?.aborted) return
      commitFinalReport(host, run)
      host.onFinalized?.(run.id)
    } catch (error) {
      if (isDeletedRunRaceError(error)) {
        host.lastDrain.delete(run.id)
        return
      }
      if (host.onError) {
        host.onError(error)
      } else {
        console.error('[kovo] OOB report finalization failed for run', run.id, error)
      }
    } finally {
      host.draining.delete(run.id)
      activeFinalizingRuns.delete(run.id)
    }
  }
  if (host.spawn) {
    const task = host.spawn('oob-final-report', signal => runAsyncFinalize(signal))
    if (task && typeof task === 'object' && 'started' in task && (task as { started?: boolean }).started === false) {
      host.draining.delete(run.id)
      activeFinalizingRuns.delete(run.id)
    }
  } else {
    void runAsyncFinalize()
  }
}

export function commitFinalReport(host: FinalizeHost, run: Run): void {
  try {
    host.storage.transaction(() => {
      let current: Run
      try {
        current = host.storage.run(run.id)
      } catch (error) {
        if (isDeletedRunRaceError(error)) {
          host.lastDrain.delete(run.id)
          return
        }
        throw error
      }
      if (current.status !== 'running' || current.phase !== 'verification') return
      const failureGaps = host.collectFailureGaps
        ? host.collectFailureGaps(current)
        : collectVerificationFailureGaps(host.storage.workerList?.(current.id) ?? [], current.goalRevision)
      const drain = host.lastDrain.get(current.id)
      const drainGaps: string[] = []
      if (drain?.degraded) {
        drainGaps.push(drain.coverageGap ?? buildOobDrainCoverageGap(drain.errors ?? [{
          phase: 'drain',
          message: 'OOB relay drain reported degraded state',
          at: Date.now(),
        }]))
      }
      const allGaps = [...failureGaps, ...drainGaps]
      const partial = allGaps.length > 0
      const complete = host.storage.updateRun(current.id, { phase: 'complete', status: 'complete' })
      const reportId = host.storage.writeReport(complete, partial)
      if (partial && host.storage.db) {
        try {
          const row = host.storage.db.select().from(reports).where(eq(reports.id, reportId)).get()
          if (row && row.body) {
            const existing = Array.isArray(row.body.gaps) ? row.body.gaps : []
            const mergedGaps = [...existing]
            for (const line of allGaps) {
              if (!mergedGaps.includes(line)) mergedGaps.push(line)
            }
            host.storage.db.update(reports)
              .set({ body: { ...row.body, gaps: mergedGaps } })
              .where(eq(reports.id, reportId))
              .run()
          }
        } catch { /* best-effort gap merge */ }
      }
      const drainNote = drain && drain.promotedLate > 0
        ? ` ${drain.promotedLate} late async callback(s) were promoted before finalizing.`
        : ''
      const degradedNote = drainGaps.length > 0
        ? ' OOB callback drain encountered relay/storage errors; recorded an explicit coverage gap.'
        : ''
      const summary = partial
        ? (failureGaps.length > 0
            ? `Verification finished with ${failureGaps.length} failed verification worker${failureGaps.length === 1 ? '' : 's'}. A partial report is ready.${drainNote}${degradedNote}`
            : `Verification finished with an OOB drain coverage gap. A partial report is ready.${drainNote}${degradedNote}`)
        : `Verification finished. The complete report is ready.${drainNote}`
      host.storage.message(current.id, current.coordinatorId, 'kovo', summary)
    }, { behavior: 'immediate' })
  } catch (error) {
    if (isDeletedRunRaceError(error)) {
      host.lastDrain.delete(run.id)
      return
    }
    throw error
  }
}
