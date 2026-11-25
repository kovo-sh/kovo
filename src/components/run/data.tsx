// Run data layer: the live run detail, the event stream, the run index,
// and the command bus. One provider per mounted run.
//
//   useRun()        → { detail, model, events, counts, runs, connection, … }
//   useRunModel()   → the memoised RunModel (selectors, indexes, verdict inputs)
//   useFullExchange(id) → one exchange with headers and body (shared cache)
//
// Live updates: one EventSource on /api/runs/:id/events?since=0 replays the
// run's full event history (used by Activity, the traffic histogram, replay)
// and then streams new events. Any event newer than the loaded snapshot
// schedules a coalesced `runData` refresh, so paused/running runs update in place.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { commandRun, readExchange, runData, runShellData } from '../../actions.ts'
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
  /** Every event of the run, oldest first (grows live). */
  events: RunEvent[]
  /** True once the initial event replay has settled. */
  eventsReady: boolean
  /** True totals: the detail caps exchanges at the newest 500. */
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

export function RunDataProvider({ initial, children, onError }: {
  initial: Detail
  children: ReactNode
  onError?: (message: string) => void
}) {
  const [snapshot, setSnapshot] = useState<Detail>()
  const detail = snapshot && snapshot.cursor >= initial.cursor ? snapshot : initial
  const runId = initial.run.id
  const model = useMemo(() => buildRunModel(detail), [detail])
  const [events, setEvents] = useState<RunEvent[]>([])
  const [eventsReady, setEventsReady] = useState(false)
  const [shell, setShell] = useState<Awaited<ReturnType<typeof runShellData>>>()
  const [connection, setConnection] = useState<Connection>('connecting')
  const [pending, setPending] = useState(0)
  const [error, setError] = useState('')
  const onErrorRef = useRef(onError)
  onErrorRef.current = onError

  const loadShell = useCallback(async () => {
    try { setShell(await runShellData({ data: { runId } })) } catch { /* keep the last index */ }
  }, [runId])

  const refresh = useCallback(async () => {
    try {
      const latest = await runData({ data: { runId } })
      setSnapshot(prev => !prev || latest.cursor >= prev.cursor ? latest : prev)
    } catch {
      // Keep the last committed view while the local server restarts.
    }
    void loadShell()
  }, [runId, loadShell])

  useEffect(() => { void loadShell() }, [loadShell])

  // Event stream: full replay, then live. Coalesce refreshes.
  const cursor = useRef(initial.cursor)
  useEffect(() => {
    let disposed = false
    let refreshing = false
    let again = false
    let buffer: RunEvent[] = []
    let flushTimer: ReturnType<typeof setTimeout> | undefined
    let settleTimer: ReturnType<typeof setTimeout> | undefined
    let lastId = 0
    setEvents([])
    setEventsReady(false)
    const requestRefresh = () => {
      if (refreshing) { again = true; return }
      refreshing = true
      void refresh().finally(() => {
        refreshing = false
        if (disposed || !again) return
        again = false
        requestRefresh()
      })
    }
    const flush = () => {
      flushTimer = undefined
      if (!buffer.length || disposed) return
      const batch = buffer
      buffer = []
      setEvents(prev => prev.concat(batch))
    }
    const settle = () => {
      clearTimeout(settleTimer)
      settleTimer = setTimeout(() => { if (!disposed) setEventsReady(true) }, 350)
    }
    const source = new EventSource(`/api/runs/${runId}/events?since=0`)
    source.onopen = () => { setConnection('live'); settle() }
    source.onerror = () => setConnection('reconnecting')
    source.onmessage = message => {
      const id = Number(message.lastEventId)
      if (!Number.isFinite(id) || id <= lastId) return
      lastId = id
      try { buffer.push(JSON.parse(message.data) as RunEvent) } catch { /* ignore malformed */ }
      flushTimer ??= setTimeout(flush, 60)
      settle()
      if (id > cursor.current) {
        cursor.current = id
        requestRefresh()
      }
    }
    return () => {
      disposed = true
      clearTimeout(flushTimer)
      clearTimeout(settleTimer)
      source.close()
    }
  }, [runId, refresh])

  const send = useCallback(async (command: Command) => {
    setPending(p => p + 1)
    setError('')
    try {
      const result = await commandRun({ data: { ...command, runId, requestId: crypto.randomUUID() } as RunCommand })
      await refresh()
      return result
    } catch (failure) {
      const message = failure instanceof Error ? failure.message : 'Kovo Hunter could not complete the action.'
      setError(message)
      onErrorRef.current?.(message)
      if (command.action === 'scope') await refresh()
      throw failure
    } finally {
      setPending(p => p - 1)
    }
  }, [runId, refresh])

  const value = useMemo<RunContextValue>(() => ({
    detail, model, events, eventsReady,
    counts: {
      exchanges: Math.max(shell?.counts.exchanges ?? 0, detail.exchangesSummary.length),
      events: Math.max(shell?.counts.events ?? 0, events.length),
    },
    runs: shell?.runs ?? [],
    connection, refresh, send, pending, error, clearError: () => setError(''),
  }), [detail, model, events, eventsReady, shell, connection, refresh, send, pending, error])

  return <RunContext.Provider value={value}>{children}</RunContext.Provider>
}
