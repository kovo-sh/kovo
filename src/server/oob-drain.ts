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
}

/** Promote late callbacks within a bounded grace window and report the drained metrics. */
export async function drainPendingOob(
  relay: OobDrainRelay,
  runId: string,
  options: OobDrainOptions = {},
): Promise<OobDrainResult> {
  const now = options.now ?? (() => Date.now())
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)))
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
  promote()
  let remaining = pendingCount()
  const maxPolls = Math.ceil(graceMs / pollMs) + 2
  let polls = 0
  while (remaining > 0 && now() - started < graceMs && polls < maxPolls) {
    polls += 1
    const budget = graceMs - (now() - started)
    await sleep(Math.max(1, Math.min(pollMs, budget)))
    promote()
    remaining = pendingCount()
  }
  return { oobDrainMs: Math.max(0, now() - started), promotedLate, remaining }
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
  const drain = host.drain ?? ((runId: string) => drainPendingOob(host.relay, runId))
  void drain(run.id)
    .then((result) => {
      host.lastDrain.set(run.id, result)
      commitFinalReport(host, run)
    })
    .catch(() => { commitFinalReport(host, run) })
    .finally(() => { host.draining.delete(run.id) })
}

function commitFinalReport(host: FinalizeHost, run: Run): void {
  host.storage.transaction(() => {
    const current = host.storage.run(run.id)
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
}
