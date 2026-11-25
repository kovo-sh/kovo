/**
 * v6 bounded pre-report OOB drain.
 *
 * A background worker can trigger an SSRF/XXE/webhook callback long after the HTTP response
 * (Fixture #2: 15–30 s). Finalizing the report as soon as verification workers settle dropped
 * exactly those callbacks. This waits up to `KOVO_OOB_DRAIN_MS` (default 45 s), promotes late
 * callbacks on every poll, and returns the recorded metrics. It never waits when nothing is
 * pending, so local-lab benchmark runs keep their zero-latency behavior.
 */
import type { Run } from './store.ts'

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

export interface OobDrainResult {
  oobDrainMs: number
  promotedLate: number
  remaining: number
}

export interface OobDrainOptions {
  graceMs?: number
  pollMs?: number
  /** Injected clock (fake-clock tests); defaults to `Date.now`. */
  now?: () => number
  sleep?: (ms: number) => Promise<void>
  /** Optional abort signal to cancel waiting early (e.g. run stopped/deleted). */
  signal?: AbortSignal
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
  const promote = () => {
    try {
      promotedLate += relay.promoteLate({ runId, now: now() }).length
    } catch { /* relay unavailable: there is nothing to promote */ }
  }
  const pendingCount = (): number => {
    try { return relay.pending(runId).length } catch { return 0 }
  }

  try {
    if (signal.aborted) {
      return { oobDrainMs: 0, promotedLate: 0, remaining: pendingCount() }
    }
    promote()
    let remaining = pendingCount()
    const maxPolls = Math.ceil(graceMs / pollMs) + 2
    let polls = 0
    while (!signal.aborted && remaining > 0 && now() - started < graceMs && polls < maxPolls) {
      polls += 1
      const budget = graceMs - (now() - started)
      await sleep(Math.max(1, Math.min(pollMs, budget)))
      if (signal.aborted) break
      promote()
      remaining = pendingCount()
    }
    return { oobDrainMs: Math.max(0, now() - started), promotedLate, remaining }
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
}

export interface FinalizeHost {
  storage: FinalizeStore
  relay: OobDrainRelay
  /** runIds whose report is waiting on the bounded drain (single-flight). */
  draining: Set<string>
  /** Last drain outcome per run, surfaced in report meta. */
  lastDrain: Map<string, OobDrainResult>
  /** Optional drain entry point (tests/benchmarks can substitute a fake-clock drain). */
  drain?: (runId: string) => Promise<OobDrainResult>
  /** Optional observer for unexpected non-deletion storage errors during async finalization. */
  onError?: (error: unknown) => void
}

/**
 * Single-flight finalize: drain pending async OOB subscriptions first when any exist, then write
 * the complete report exactly once. Never waits when nothing is pending.
 */
export function scheduleFinalReport(host: FinalizeHost, run: Run): void {
  if (host.draining.has(run.id)) return
  let pending = 0
  try { pending = host.relay.pending(run.id).length } catch { pending = 0 }
  if (pending === 0) {
    commitFinalReport(host, run)
    return
  }
  host.draining.add(run.id)
  activeFinalizingRuns.add(run.id)
  const drain = host.drain ?? ((runId: string) => drainPendingOob(host.relay, runId))
  void (async () => {
    try {
      try {
        const result = await drain(run.id)
        host.lastDrain.set(run.id, result)
      } catch (error) {
        if (isDeletedRunRaceError(error)) {
          host.lastDrain.delete(run.id)
          return
        }
        // Transient drain failure must not block report finalization when the run still exists.
      }
      commitFinalReport(host, run)
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
  })()
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
      const complete = host.storage.updateRun(current.id, { phase: 'complete', status: 'complete' })
      host.storage.writeReport(complete, false)
      const drain = host.lastDrain.get(current.id)
      const drainNote = drain && drain.promotedLate > 0
        ? ` ${drain.promotedLate} late async callback(s) were promoted before finalizing.`
        : ''
      host.storage.message(current.id, current.coordinatorId, 'kovo',
        `Verification finished. The complete report is ready.${drainNote}`)
    }, { behavior: 'immediate' })
  } catch (error) {
    if (isDeletedRunRaceError(error)) {
      host.lastDrain.delete(run.id)
      return
    }
    throw error
  }
}
