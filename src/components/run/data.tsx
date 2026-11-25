// Run data layer: the live run detail, the event stream, the run index,
// and the command bus. One provider per mounted run.
//
//   useRun()        → { detail, model, events, counts, runs, connection, … }
//   useRunModel()   → the memoised RunModel (selectors, indexes, verdict inputs)
//   useFullExchange(id) → one exchange with headers and body (shared cache)
//
// Live updates: one EventSource on /api/runs/:id/events?since=<initialCursor>
// streams new events after the loader snapshot. Incoming events newer than the
// loaded snapshot schedule a 350ms debounced `runData` refresh, and only refresh
// `runShellData` when a run-status or finding-count-changing event arrives.
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

/** Coalescing delay for SSE-triggered `runData` refreshes to prevent per-tick DB storms. */
export const SSE_REFRESH_DEBOUNCE_MS = 350

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
  const initialCursorRef = useRef(sseStreamSinceCursor(initial.cursor))
  initialCursorRef.current = sseStreamSinceCursor(initial.cursor)

  const loadShell = useCallback(async () => {
    try { setShell(await runShellData({ data: { runId } })) } catch { /* keep the last index */ }
  }, [runId])

  const refreshDetail = useCallback(async () => {
    try {
      const latest = await runData({ data: { runId } })
      setSnapshot(prev => !prev || latest.cursor >= prev.cursor ? latest : prev)
    } catch {
      // Keep the last committed view while the local server restarts.
    }
  }, [runId])

  const refresh = useCallback(async () => {
    await refreshDetail()
    void loadShell()
  }, [refreshDetail, loadShell])

  useEffect(() => { void loadShell() }, [loadShell])

  // Event stream: resume from initial snapshot cursor and debounce refreshes (350ms).
  const cursor = useRef(sseStreamSinceCursor(initial.cursor))
  useEffect(() => {
    const startCursor = initialCursorRef.current
    cursor.current = startCursor
    let disposed = false
    let refreshing = false
    let again = false
    let pendingShell = false
    let buffer: RunEvent[] = []
    let flushTimer: ReturnType<typeof setTimeout> | undefined
    let settleTimer: ReturnType<typeof setTimeout> | undefined
    let refreshTimer: ReturnType<typeof setTimeout> | undefined
    let lastId = startCursor
    setEvents([])
    setEventsReady(false)
    const runRefresh = () => {
      if (disposed) return
      if (refreshing) { again = true; return }
      const refreshShellNow = pendingShell
      pendingShell = false
      refreshing = true
      const tasks: Promise<unknown>[] = [refreshDetail()]
      if (refreshShellNow) tasks.push(loadShell())
      void Promise.all(tasks).finally(() => {
        refreshing = false
        if (disposed || !again) return
        again = false
        scheduleRefresh(false)
      })
    }
    const scheduleRefresh = (needsShell: boolean) => {
      if (disposed) return
      if (needsShell) pendingShell = true
      if (refreshing) {
        again = true
        return
      }
      if (refreshTimer !== undefined) return
      refreshTimer = setTimeout(() => {
        refreshTimer = undefined
        runRefresh()
      }, SSE_REFRESH_DEBOUNCE_MS)
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
    const source = new EventSource(`/api/runs/${runId}/events?since=${startCursor}`)
    source.onopen = () => { setConnection('live'); settle() }
    source.onerror = () => setConnection('reconnecting')
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
        scheduleRefresh(parsed ? shouldRefreshRunShell(parsed.kind) : false)
      }
    }
    return () => {
      disposed = true
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
