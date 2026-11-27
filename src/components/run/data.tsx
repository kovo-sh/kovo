// Run data layer: the live run detail, the event stream, the run index,
// and the command bus. One provider per mounted run.
//
//   useRun()        → { detail, model, events, counts, runs, connection, … }
//   useRunModel()   → the memoised RunModel (selectors, indexes, verdict inputs)
//   useFullExchange(id) → one exchange with headers and body (shared cache)
//
// Live updates: one EventSource on /api/runs/:id/events?since=<initialCursor>
// streams new events after the loader snapshot, while an initial bounded
// historical backfill hydrates events up to <initialCursor> without triggering
// DB refresh storms. Incoming live events newer than the loaded snapshot
// schedule a 350ms debounced `runData` refresh, and only refresh `runShellData`
// when a run-status or finding-count-changing event arrives.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { commandRun, readExchange, readRunEventsPage, runData, runShellData } from '../../actions.ts'
import type { RunCommand } from '../../domain.ts'
import { buildRunModel, buildVerdict } from './model.ts'
import type { Detail, RunEvent, RunModel, Verdict } from './model.ts'

/** A run command without the envelope fields (runId, requestId) the data layer adds. */
export type Command = RunCommand extends infer C ? C extends RunCommand ? Omit<C, 'requestId' | 'runId'> : never : never

export type RunIndexEntry = Awaited<ReturnType<typeof runShellData>>['runs'][number]
export type Connection = 'connecting' | 'live' | 'reconnecting'

export interface RunContextValue {
  detail: Detail
  model: RunModel
  /** Single shared expiry clock (epoch ms) synchronized across banner, queue, and rail. */
  now: number
  /** Bounded live event window, oldest first (grows live; older history fetched on demand). */
  events: RunEvent[]
  /** True once the initial event replay has settled. */
  eventsReady: boolean
  /** True when older historical events exist before `events[0]` and can be loaded on demand. */
  hasOlderEvents: boolean
  /** True while an on-demand older-history page fetch is in flight. */
  loadingOlderEvents: boolean
  /** Load an older slice of run events before the current oldest loaded event id. */
  loadOlderEvents: (limit?: number) => Promise<number>
  /** True totals: the detail caps inline slices and exposes exact totals. */
  counts: { exchanges: number; events: number }
  /** Every run in the workspace, newest first, for the rail, palette and [ / ] switching. */
  runs: RunIndexEntry[]
  connection: Connection
  refresh: () => Promise<void>
  /** Send a real run command. Resolves after the command succeeded and the detail refreshed; rejects on failure. */
  send: (command: Command) => Promise<unknown>
  /** Number of commands in flight. */
  pending: number
  /** Last command error, if any (also surfaced as a toast by the shell). */
  error: string
  clearError: () => void
}

const RunContext = createContext<RunContextValue | null>(null)

export function useRun(): RunContextValue {
  const v = useContext(RunContext)
  if (!v) throw new Error('useRun() must be used inside <RunDataProvider>')
  return v
}
export const useRunModel = () => useRun().model

// ---------------------------------------------------------------- full exchanges (headers + body)

/** One exchange with headers and body, read by id (GET `readExchange`). */
export type FullExchange = Awaited<ReturnType<typeof readExchange>>
const exValues = new Map<string, FullExchange>()
const exPending = new Map<string, Promise<FullExchange>>()

/** Shared, de-duplicated loader. Successful reads are cached (newest 300); failures are retried next time. */
export function loadExchange(runId: string, id: string): Promise<FullExchange> {
  const hit = exValues.get(id)
  if (hit) return Promise.resolve(hit)
  let p = exPending.get(id)
  if (!p) {
    p = readExchange({ data: { runId, exchangeId: id } }).then(x => {
      exValues.set(id, x)
      if (exValues.size > 300) exValues.delete(exValues.keys().next().value!)
      return x
    }).finally(() => exPending.delete(id))
    exPending.set(id, p)
  }
  return p
}

/** The full exchange: `undefined` while loading (or disabled and not cached), `null` if it could not be read. */
export function useFullExchange(id: string, enabled = true): FullExchange | null | undefined {
  const { detail } = useRun()
  const [state, setState] = useState<{ id: string; x: FullExchange | null } | undefined>()
  useEffect(() => {
    if (!enabled || exValues.has(id)) return
    let live = true
    loadExchange(detail.run.id, id).then(x => { if (live) setState({ id, x }) }, () => { if (live) setState({ id, x: null }) })
    return () => { live = false }
  }, [id, enabled, detail.run.id])
  return exValues.get(id) ?? (state?.id === id ? state.x : undefined)
}

/** Verdict headline + confidence (B's wording). Depends on the event stream for the "restarted" note. */
export function useVerdict(): Verdict {
  const { detail, model, events } = useRun()
  const interrupted = useMemo(() => events.some(e => e.kind === 'interrupted'), [events])
  return useMemo(() => buildVerdict(detail, model.findings, interrupted), [detail, model, interrupted])
}

/** Coalescing delay for SSE-triggered `runData` refreshes to prevent per-tick DB storms. */
export const SSE_REFRESH_DEBOUNCE_MS = 350

/** Maximum live events retained in browser RAM by default before on-demand pagination. */
export const MAX_CLIENT_RUN_EVENTS = 2000

/** Iterative maximum over any numeric iterable — safe on 100k+ items without spread stack overflow. */
export function iterativeMax(values: Iterable<number>, fallback = 0): number {
  let found = false
  let best = -Infinity
  for (const v of values) {
    if (typeof v === 'number' && Number.isFinite(v)) {
      if (!found || v > best) {
        best = v
        found = true
      }
    }
  }
  return found ? best : fallback
}

/** Iterative minimum over any numeric iterable — safe on 100k+ items without spread stack overflow. */
export function iterativeMin(values: Iterable<number>, fallback = Infinity): number {
  let found = false
  let best = Infinity
  for (const v of values) {
    if (typeof v === 'number' && Number.isFinite(v)) {
      if (!found || v < best) {
        best = v
        found = true
      }
    }
  }
  return found ? best : fallback
}

/**
 * Compute milliseconds until the next pending approval expires so one shared expiry clock
 * ticks at exact expiry boundaries (capped at `maxIntervalMs`) with zero cross-view drift.
 */
export function nextApprovalExpiryDelayMs(
  approvals: readonly { status: string; expiresAt?: number | null }[],
  now: number,
  maxIntervalMs = 15_000,
): number | null {
  let earliest = Infinity
  for (const ap of approvals) {
    if (ap.status !== 'pending') continue
    const exp = ap.expiresAt
    if (typeof exp === 'number' && Number.isFinite(exp) && exp > now && exp < earliest) {
      earliest = exp
    }
  }
  if (!Number.isFinite(earliest)) return null
  return Math.max(50, Math.min(maxIntervalMs, earliest - now))
}

export interface SseRefreshCoalescer {
  schedule: (needsShell: boolean) => void
  forceSync: (needsShell?: boolean) => void
  dispose: () => void
  readonly pendingTimer: boolean
  readonly inFlight: boolean
}

/**
 * Coalesces rapid SSE bursts into bounded 350ms refreshes while guaranteeing that a burst
 * arriving mid-flight always triggers a trailing refresh (never dropping the final tick).
 */
export function createSseRefreshCoalescer(opts: {
  debounceMs?: number
  refreshDetail: () => Promise<unknown>
  refreshShell: () => Promise<unknown>
  setTimeoutFn?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout> | number
  clearTimeoutFn?: (timer: ReturnType<typeof setTimeout> | number) => void
}): SseRefreshCoalescer {
  const debounceMs = opts.debounceMs ?? SSE_REFRESH_DEBOUNCE_MS
  const scheduleTimeout = opts.setTimeoutFn ?? ((fn: () => void, ms: number) => setTimeout(fn, ms))
  const cancelTimeout = opts.clearTimeoutFn ?? ((t: ReturnType<typeof setTimeout> | number) => clearTimeout(t as ReturnType<typeof setTimeout>))
  let disposed = false
  let refreshing = false
  let again = false
  let pendingShell = false
  let refreshTimer: ReturnType<typeof setTimeout> | number | undefined

  const runRefresh = () => {
    if (disposed) return
    if (refreshing) {
      again = true
      return
    }
    const refreshShellNow = pendingShell
    pendingShell = false
    refreshing = true
    const tasks: Promise<unknown>[] = [opts.refreshDetail()]
    if (refreshShellNow) tasks.push(opts.refreshShell())
    void Promise.all(tasks).finally(() => {
      refreshing = false
      if (disposed || !again) return
      again = false
      schedule(false)
    })
  }

  const schedule = (needsShell: boolean) => {
    if (disposed) return
    if (needsShell) pendingShell = true
    if (refreshing) {
      again = true
      return
    }
    if (refreshTimer !== undefined) return
    refreshTimer = scheduleTimeout(() => {
      refreshTimer = undefined
      runRefresh()
    }, debounceMs)
  }

  const forceSync = (needsShell = true) => {
    if (disposed) return
    if (needsShell) pendingShell = true
    if (refreshTimer !== undefined) {
      cancelTimeout(refreshTimer)
      refreshTimer = undefined
    }
    if (refreshing) {
      again = true
      return
    }
    runRefresh()
  }

  const dispose = () => {
    disposed = true
    again = false
    pendingShell = false
    if (refreshTimer !== undefined) {
      cancelTimeout(refreshTimer)
      refreshTimer = undefined
    }
  }

  return {
    schedule,
    forceSync,
    dispose,
    get pendingTimer() { return refreshTimer !== undefined },
    get inFlight() { return refreshing },
  }
}

const SHELL_REFRESH_PREFIXES = ['run.', 'finding.', 'report.', 'project.'] as const
const SHELL_REFRESH_EXACT = new Set([
  'goal.revised',
  'interrupted',
  'recovery.completed',
  'scope.approved',
  'scope.revoked',
  'discovery.consented',
  'discovery.complete',
  'phase0.completed',
  'threat_model.saved',
  'threat_model.failed',
  'verification.started',
  'retest.complete',
  'agent.script_proof_confirmed',
  'oob.receipt_confirmed',
])

/** True only when an SSE event can change the run switcher status/phase or finding count. */
export function shouldRefreshRunShell(eventKind: string): boolean {
  if (SHELL_REFRESH_EXACT.has(eventKind)) return true
  return SHELL_REFRESH_PREFIXES.some(prefix => eventKind.startsWith(prefix))
}

/** Starting SSE cursor: resume from the loaded snapshot cursor instead of replaying from 0. */
export function sseStreamSinceCursor(initialCursor: number): number {
  return Number.isSafeInteger(initialCursor) && initialCursor > 0 ? initialCursor : 0
}

/**
 * Merge two event slices into an ascending, deduplicated list by numeric event id,
 * bounded to the newest `maxEvents` entries (pass `0` for an explicitly expanded history window).
 */
export function mergeRunEvents(
  existing: readonly RunEvent[],
  incoming: readonly RunEvent[],
  maxEvents = MAX_CLIENT_RUN_EVENTS,
): RunEvent[] {
  if (!incoming.length) {
    if (maxEvents > 0 && existing.length > maxEvents) return existing.slice(existing.length - maxEvents)
    return existing as RunEvent[]
  }
  const byId = new Map<number, RunEvent>()
  for (const ev of existing) byId.set(ev.id, ev)
  for (const ev of incoming) byId.set(ev.id, ev)
  const sorted = [...byId.values()].sort((a, b) => a.id - b.id)
  if (maxEvents > 0 && sorted.length > maxEvents) {
    return sorted.slice(sorted.length - maxEvents)
  }
  return sorted
}

/** Parse complete SSE frames from a text buffer, returning parsed `RunEvent`s and leftover partial text. */
export function parseSseEventsChunk(carry: string, chunk: string): { events: RunEvent[]; carry: string } {
  const combined = carry + chunk
  const parts = combined.split(/\r?\n\r?\n/)
  const nextCarry = parts.pop() ?? ''
  const events: RunEvent[] = []
  for (const frame of parts) {
    if (!frame.trim()) continue
    const dataLines: string[] = []
    for (const line of frame.split(/\r?\n/)) {
      if (!line || line.startsWith(':')) continue
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).replace(/^ /, ''))
      }
    }
    if (!dataLines.length) continue
    try {
      const parsed = JSON.parse(dataLines.join('\n')) as RunEvent
      if (parsed && Number.isFinite(parsed.id)) events.push(parsed)
    } catch {
      // Ignore malformed SSE frames.
    }
  }
  return { events, carry: nextCarry }
}

/**
 * Hydrate historical events (`id <= targetCursor`) from the SSE endpoint when a page reloads
 * or opens a finished run whose snapshot cursor is already > 0. Aborts immediately once
 * `targetCursor` is reached (or after a brief idle pause if the cursor row was pruned),
 * without triggering any `runData` or `runShellData` refreshes.
 */
export async function hydrateHistoricalEvents(
  runId: string,
  targetCursor: number,
  opts: {
    signal: AbortSignal
    onBatch: (batch: RunEvent[]) => void
    fetchImpl?: typeof fetch
    idleMs?: number
    maxEvents?: number
  },
): Promise<void> {
  if (targetCursor <= 0 || opts.signal.aborted) return
  const fetcher = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined)
  if (!fetcher) return
  const maxEvents = opts.maxEvents ?? MAX_CLIENT_RUN_EVENTS
  const localAbort = new AbortController()
  const forwardAbort = () => localAbort.abort()
  opts.signal.addEventListener('abort', forwardAbort, { once: true })
  let idleTimer: ReturnType<typeof setTimeout> | undefined
  const idleMs = opts.idleMs ?? 450
  const armIdle = (ms: number) => {
    if (idleTimer !== undefined) clearTimeout(idleTimer)
    idleTimer = setTimeout(() => localAbort.abort(), ms)
  }
  try {
    armIdle(Math.max(idleMs, 2500))
    const response = await fetcher(`/api/runs/${runId}/events`, {
      headers: { Accept: 'text/event-stream' },
      signal: localAbort.signal,
    })
    if (!response.ok || !response.body) return
    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let carry = ''
    let maxSeenId = 0
    armIdle(idleMs)
    while (!localAbort.signal.aborted) {
      const { value, done } = await reader.read()
      if (done) break
      armIdle(idleMs)
      const parsed = parseSseEventsChunk(carry, decoder.decode(value, { stream: true }))
      carry = parsed.carry
      if (parsed.events.length) {
        const historical: RunEvent[] = []
        for (const ev of parsed.events) {
          if (ev.id > maxSeenId) maxSeenId = ev.id
          if (ev.id <= targetCursor) historical.push(ev)
        }
        if (historical.length) {
          const bounded = maxEvents > 0 && historical.length > maxEvents
            ? historical.slice(historical.length - maxEvents)
            : historical
          opts.onBatch(bounded)
        }
        if (maxSeenId >= targetCursor) {
          localAbort.abort()
          break
        }
      }
    }
    try { await reader.cancel() } catch { /* ignore */ }
  } catch {
    // Expected AbortError once targetCursor is reached or on cleanup/offline.
  } finally {
    if (idleTimer !== undefined) clearTimeout(idleTimer)
    opts.signal.removeEventListener('abort', forwardAbort)
  }
}

export function RunDataProvider({ initial, children, onError }: {
  initial: Detail
  children: ReactNode
  onError?: (message: string) => void
}) {
  const [snapshot, setSnapshot] = useState<Detail>()
  const detail = snapshot && snapshot.run.id === initial.run.id && snapshot.cursor >= initial.cursor ? snapshot : initial
  const runId = initial.run.id
  const [now, setNow] = useState(() => Date.now())
  const model = useMemo(() => buildRunModel(detail, now), [detail, now])
  const [events, setEvents] = useState<RunEvent[]>([])
  const [eventsReady, setEventsReady] = useState(false)
  const [loadingOlderEvents, setLoadingOlderEvents] = useState(false)
  const [noOlderEventsOnServer, setNoOlderEventsOnServer] = useState(false)
  const eventWindowCapRef = useRef(MAX_CLIENT_RUN_EVENTS)
  const [shell, setShell] = useState<Awaited<ReturnType<typeof runShellData>>>()
  const [connection, setConnection] = useState<Connection>('connecting')
  const [pending, setPending] = useState(0)
  const [error, setError] = useState('')
  const onErrorRef = useRef(onError)
  onErrorRef.current = onError
  const needsSyncRef = useRef(false)
  const initialCursorRef = useRef(sseStreamSinceCursor(initial.cursor))
  initialCursorRef.current = sseStreamSinceCursor(initial.cursor)

  // Single shared expiry clock across the run workspace: ticks right when the next pending approval expires.
  useEffect(() => {
    const delay = nextApprovalExpiryDelayMs(detail.approvals, now)
    if (delay === null) return
    const timer = window.setTimeout(() => setNow(Date.now()), delay)
    return () => window.clearTimeout(timer)
  }, [detail.approvals, now])

  const loadShell = useCallback(async () => {
    try { setShell(await runShellData({ data: { runId } })) } catch { /* keep the last index */ }
  }, [runId])

  const refreshDetail = useCallback(async () => {
    try {
      const latest = await runData({ data: { runId } })
      setSnapshot(prev => !prev || prev.run.id !== latest.run.id || latest.cursor >= prev.cursor ? latest : prev)
      setNow(Date.now())
      needsSyncRef.current = false
    } catch {
      // Mark dirty so reconnect / next open forces reconciliation with server truth.
      needsSyncRef.current = true
    }
  }, [runId])

  const refresh = useCallback(async () => {
    await refreshDetail()
    void loadShell()
  }, [refreshDetail, loadShell])

  const loadOlderEvents = useCallback(async (limit = 200): Promise<number> => {
    if (loadingOlderEvents) return 0
    const oldestId = events.length ? events[0]!.id : undefined
    if (oldestId !== undefined && oldestId <= 1) {
      setNoOlderEventsOnServer(true)
      return 0
    }
    setLoadingOlderEvents(true)
    try {
      const page = await readRunEventsPage({
        data: {
          runId,
          ...(oldestId !== undefined ? { beforeId: oldestId } : {}),
          limit,
        },
      })
      if (!page.hasMore) setNoOlderEventsOnServer(true)
      if (page.events.length) {
        const nextCap = Math.max(eventWindowCapRef.current, events.length + page.events.length)
        eventWindowCapRef.current = nextCap
        setEvents(prev => mergeRunEvents(page.events as RunEvent[], prev, nextCap))
      }
      return page.events.length
    } catch {
      return 0
    } finally {
      setLoadingOlderEvents(false)
    }
  }, [events, loadingOlderEvents, runId])

  useEffect(() => { void loadShell() }, [loadShell])

  // Event stream: resume live updates from initial snapshot cursor (debounced 350ms) and
  // hydrate bounded historical events up to startCursor without triggering refresh storms.
  const cursor = useRef(sseStreamSinceCursor(initial.cursor))
  useEffect(() => {
    const startCursor = initialCursorRef.current
    cursor.current = startCursor
    eventWindowCapRef.current = MAX_CLIENT_RUN_EVENTS
    let disposed = false
    let liveReady = false
    let historyDone = startCursor <= 0
    let buffer: RunEvent[] = []
    let flushTimer: ReturnType<typeof setTimeout> | undefined
    let settleTimer: ReturnType<typeof setTimeout> | undefined
    let refreshTimer: ReturnType<typeof setTimeout> | undefined
    let lastId = startCursor
    const backfillAbort = new AbortController()
    const coalescer = createSseRefreshCoalescer({
      debounceMs: SSE_REFRESH_DEBOUNCE_MS,
      refreshDetail,
      refreshShell: loadShell,
      setTimeoutFn: ((fn: () => void, ms: number) => {
        refreshTimer = setTimeout(() => {
          refreshTimer = undefined
          fn()
        }, ms)
        return refreshTimer
      }) as typeof setTimeout,
      clearTimeoutFn: ((t: ReturnType<typeof setTimeout>) => {
        clearTimeout(t)
        if (refreshTimer === t) refreshTimer = undefined
      }) as typeof clearTimeout,
    })
    setEvents([])
    setEventsReady(false)
    setNoOlderEventsOnServer(false)
    const maybeReady = () => {
      if (!disposed && liveReady && historyDone) setEventsReady(true)
    }
    const flush = () => {
      flushTimer = undefined
      if (!buffer.length || disposed) return
      const batch = buffer
      buffer = []
      setEvents(prev => mergeRunEvents(prev, batch, eventWindowCapRef.current))
    }
    const settle = () => {
      clearTimeout(settleTimer)
      settleTimer = setTimeout(() => {
        if (disposed) return
        liveReady = true
        maybeReady()
      }, 350)
    }
    if (startCursor > 0) {
      void hydrateHistoricalEvents(runId, startCursor, {
        signal: backfillAbort.signal,
        maxEvents: MAX_CLIENT_RUN_EVENTS,
        onBatch: batch => {
          if (disposed) return
          setEvents(prev => mergeRunEvents(prev, batch, eventWindowCapRef.current))
        },
      }).finally(() => {
        if (disposed) return
        historyDone = true
        maybeReady()
      })
    }
    const source = new EventSource(`/api/runs/${runId}/events?since=${startCursor}`)
    source.onopen = () => {
      setConnection('live')
      settle()
      if (needsSyncRef.current) {
        needsSyncRef.current = false
        coalescer.forceSync(true)
      }
    }
    source.onerror = () => {
      needsSyncRef.current = true
      setConnection('reconnecting')
    }
    source.onmessage = message => {
      const id = Number(message.lastEventId)
      if (!Number.isFinite(id) || id <= lastId) return
      lastId = id
      let parsed: RunEvent | undefined
      try {
        parsed = JSON.parse(message.data) as RunEvent
        buffer.push(parsed)
      } catch { /* ignore malformed */ }
      flushTimer ??= setTimeout(flush, 60)
      settle()
      if (id > cursor.current) {
        cursor.current = id
        coalescer.schedule(parsed ? shouldRefreshRunShell(parsed.kind) : false)
      }
    }
    return () => {
      disposed = true
      backfillAbort.abort()
      coalescer.dispose()
      clearTimeout(flushTimer)
      clearTimeout(settleTimer)
      clearTimeout(refreshTimer)
      refreshTimer = undefined
      source.close()
    }
  }, [runId, refreshDetail, loadShell])

  const send = useCallback(async (command: Command) => {
    setPending(p => p + 1)
    setError('')
    try {
      const result = await commandRun({ data: { ...command, runId, requestId: crypto.randomUUID() } as RunCommand })
      await refresh()
      return result
    } catch (failure) {
      const message = failure instanceof Error ? failure.message : 'Kovo could not complete the action.'
      setError(message)
      onErrorRef.current?.(message)
      if (command.action === 'scope') await refresh()
      throw failure
    } finally {
      setPending(p => p - 1)
    }
  }, [runId, refresh])

  const totalExchanges = Math.max(
    shell?.counts.exchanges ?? 0,
    detail.projection?.totals.exchanges ?? 0,
    detail.exchangesSummary.length,
  )
  const totalEvents = Math.max(
    shell?.counts.events ?? 0,
    detail.projection?.totals.events ?? 0,
    events.length,
  )
  const hasOlderEvents = !noOlderEventsOnServer && events.length > 0 && totalEvents > events.length

  const value = useMemo<RunContextValue>(() => ({
    detail, model, now, events, eventsReady, hasOlderEvents, loadingOlderEvents, loadOlderEvents,
    counts: {
      exchanges: totalExchanges,
      events: totalEvents,
    },
    runs: shell?.runs ?? [],
    connection, refresh, send, pending, error, clearError: () => setError(''),
  }), [detail, model, now, events, eventsReady, hasOlderEvents, loadingOlderEvents, loadOlderEvents, totalExchanges, totalEvents, shell, connection, refresh, send, pending, error])

  return <RunContext.Provider value={value}>{children}</RunContext.Provider>
}
