// Navigation, selection and the inspector stack.
//
// The URL holds the view and the open selection, so every state is linkable:
//   /runs/<id>?view=findings&sel=finding:<findingId>
//   /runs/<id>/workers/<workerId>   (legacy deep link → Workflow + that worker)
//
//   const nav = useNav()
//   nav.setView('surface')                         // restores that view's last selection
//   nav.select({ kind: 'finding', id })            // open in the inspector (current view)
//   nav.open('workflow', { kind: 'worker', id })   // cross-link: switch view + select, pushes the stack
//   nav.back() / nav.close()                       // stack navigation (Esc pops)
//   nav.openChat({ label, key })                   // coordinator chat in the pane, optional context chip
//
// Prefer the typed helpers in `useLinks()` for cross-links between views.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useShortcuts } from './keyboard.tsx'
import type { ViewId } from './meta.ts'

const PANE_COLLAPSED_KEY = 'kovo-run-pane-collapsed'

export interface Sel { kind: string; id: string }
export const selKey = (s: Sel) => s.kind + ':' + s.id
export function parseSel(raw: unknown): Sel | null {
  if (typeof raw !== 'string') return null
  const i = raw.indexOf(':')
  if (i <= 0 || i === raw.length - 1) return null
  return { kind: raw.slice(0, i), id: raw.slice(i + 1) }
}
export const sameSel = (a: Sel | null | undefined, b: Sel | null | undefined) => (!a && !b) || (!!a && !!b && a.kind === b.kind && a.id === b.id)

export interface ChatContext {
  /** Shown in the composer chip and prefixed to the message as context. */
  label: string
  /** Optional selection to return to with "Back to item". */
  sel?: Sel
}

export interface NavApi {
  runId: string
  view: ViewId
  sel: Sel | null
  /** Back stack of earlier (view, selection) pairs, oldest first. */
  stack: { view: ViewId; sel: Sel | null }[]
  setView: (view: ViewId, opts?: { sel?: Sel | null }) => void
  select: (sel: Sel | null, opts?: { push?: boolean; anim?: 'up' | 'left' }) => void
  open: (view: ViewId, sel: Sel, opts?: { push?: boolean }) => void
  back: () => boolean
  close: () => void
  /** Pane shows the coordinator chat even though something is selected. */
  chat: boolean
  chatContext: ChatContext | null
  openChat: (ctx?: ChatContext | null) => void
  closeChat: () => void
  /** Inspector entrance for the next pane change ('left' slides in, used by queue advance). */
  paneAnim: 'up' | 'left'
  /** Right sidebar (inspector / board) collapsed state, persisted in localStorage. */
  paneCollapsed: boolean
  togglePane: () => void
  expandPane: () => void
  collapsePane: () => void
  switchRun: (runId: string, view?: ViewId) => void
}

const NavContext = createContext<NavApi | null>(null)
export function useNav(): NavApi {
  const v = useContext(NavContext)
  if (!v) throw new Error('useNav() must be used inside <NavProvider>')
  return v
}

export function NavProvider({ runId, view, sel, go, switchRun, hasPendingApprovals = false, children }: {
  runId: string
  view: ViewId
  sel: Sel | null
  /** Write view + selection to the URL. `push` adds a history entry (view switches). */
  go: (view: ViewId, sel: Sel | null, push: boolean) => void
  switchRun: (runId: string, view?: ViewId) => void
  /** When false on `report`, default the right pane collapsed so the document has full width. */
  hasPendingApprovals?: boolean
  children: ReactNode
}) {
  const remembered = useRef(new Map<ViewId, Sel | null>())
  remembered.current.set(view, sel)
  const [stack, setStack] = useState<{ view: ViewId; sel: Sel | null }[]>([])
  const [chat, setChat] = useState(false)
  const [chatContext, setChatContext] = useState<ChatContext | null>(null)
  const [paneAnim, setPaneAnim] = useState<'up' | 'left'>('up')
  const [userCollapsed, setUserCollapsed] = useState<boolean | null>(null)
  const [reportOverride, setReportOverride] = useState<boolean | null>(null)
  const cur = useRef({ view, sel })
  cur.current = { view, sel }

  useEffect(() => {
    try {
      const saved = localStorage.getItem(PANE_COLLAPSED_KEY)
      if (saved === '1') setUserCollapsed(true)
      else if (saved === '0') setUserCollapsed(false)
    } catch { /* ignore */ }
  }, [])

  // Reset the temporary report override when switching views.
  useEffect(() => {
    setReportOverride(null)
  }, [view])

  const reportAutoCollapse = view === 'report' && !hasPendingApprovals && !sel && !chat
  const paneCollapsed = reportAutoCollapse
    ? (reportOverride ?? true)
    : (userCollapsed ?? false)

  const writeUserCollapsed = useCallback((next: boolean) => {
    setUserCollapsed(next)
    try { localStorage.setItem(PANE_COLLAPSED_KEY, next ? '1' : '0') } catch { /* ignore */ }
  }, [])

  const togglePane = useCallback(() => {
    const next = !paneCollapsed
    if (reportAutoCollapse) {
      setReportOverride(next)
    } else {
      writeUserCollapsed(next)
    }
  }, [paneCollapsed, reportAutoCollapse, writeUserCollapsed])

  const expandPane = useCallback(() => {
    setReportOverride(false)
    if (userCollapsed) writeUserCollapsed(false)
  }, [userCollapsed, writeUserCollapsed])

  const collapsePane = useCallback(() => {
    setReportOverride(true)
    writeUserCollapsed(true)
  }, [writeUserCollapsed])

  const setView = useCallback((v: ViewId, opts?: { sel?: Sel | null }) => {
    const next = opts && 'sel' in opts ? opts.sel ?? null : remembered.current.get(v) ?? null
    setChat(false)
    setPaneAnim('up')
    if (opts && 'sel' in opts && opts.sel) expandPane()
    if (v === cur.current.view && sameSel(next, cur.current.sel)) return
    go(v, next, v !== cur.current.view)
  }, [go, expandPane])

  const select = useCallback((s: Sel | null, opts?: { push?: boolean; anim?: 'up' | 'left' }) => {
    setChat(false)
    setPaneAnim(opts?.anim ?? 'up')
    if (s) expandPane()
    const { view: v, sel: prev } = cur.current
    if (sameSel(s, prev)) return
    if (opts?.push && prev) setStack(st => [...st, { view: v, sel: prev }])
    go(v, s, false)
  }, [go, expandPane])

  const open = useCallback((v: ViewId, s: Sel, opts?: { push?: boolean }) => {
    setChat(false)
    setPaneAnim('up')
    expandPane()
    const { view: pv, sel: prev } = cur.current
    if (pv === v && sameSel(prev, s)) return
    if ((opts?.push ?? true) && prev) setStack(st => [...st, { view: pv, sel: prev }])
    go(v, s, v !== pv)
  }, [go, expandPane])

  const stackRef = useRef(stack)
  stackRef.current = stack
  const back = useCallback(() => {
    const st = stackRef.current
    const top = st[st.length - 1]
    if (!top) return false
    stackRef.current = st.slice(0, -1)
    setStack(stackRef.current)
    setChat(false)
    setPaneAnim('up')
    go(top.view, top.sel, top.view !== cur.current.view)
    return true
  }, [go])

  const close = useCallback(() => {
    setChat(false)
    setStack([])
    if (cur.current.sel) go(cur.current.view, null, false)
  }, [go])

  const openChat = useCallback((ctx?: ChatContext | null) => {
    setChatContext(ctx ?? null)
    setChat(true)
    expandPane()
  }, [expandPane])
  const closeChat = useCallback(() => { setChat(false) }, [])

  const value = useMemo<NavApi>(() => ({
    runId, view, sel, stack, setView, select, open, back, close,
    chat, chatContext, openChat, closeChat, paneAnim, paneCollapsed, togglePane, expandPane, collapsePane, switchRun,
  }), [runId, view, sel, stack, setView, select, open, back, close, chat, chatContext, openChat, closeChat, paneAnim, paneCollapsed, togglePane, expandPane, collapsePane, switchRun])
  return <NavContext.Provider value={value}>{children}</NavContext.Provider>
}

/**
 * Typed cross-links. Each opens the target view with the entity selected in
 * the inspector, and pushes the current selection so Back / Esc returns.
 */
export function useLinks() {
  const nav = useNav()
  return useMemo(() => ({
    view: (v: ViewId) => nav.setView(v),
    finding: (id: string) => nav.open('findings', { kind: 'finding', id }),
    worker: (id: string) => nav.open('workflow', { kind: 'worker', id }),
    exchange: (id: string) => nav.open('exchanges', { kind: 'exchange', id }),
    cell: (origin: string, category: string) => nav.open('surface', { kind: 'cell', id: origin + '|' + category }),
    host: (origin: string) => nav.open('surface', { kind: 'host', id: origin }),
    queueItem: (key: string) => nav.open('queue', { kind: 'queue', id: key }),
    event: (id: string | number) => nav.open('activity', { kind: 'event', id: String(id) }),
    /** Evidence opens in the inspector of the current view. */
    evidence: (id: string) => nav.select({ kind: 'evidence', id }, { push: true }),
    report: () => nav.setView('report'),
  }), [nav])
}

// ---------------------------------------------------------------- list helpers

const viewStateStore = new Map<string, unknown>()
/**
 * UI state that survives view switches (views unmount when you leave them):
 * tabs, grouping, filter text, collapsed groups, graph camera… Scoped per run.
 *   const [group, setGroup] = useViewState('findings.group', 'severity')
 */
export function useViewState<T>(key: string, initial: T): [T, (v: T | ((prev: T) => T)) => void] {
  const { runId } = useNav()
  const k = runId + ':' + key
  const [value, setValue] = useState<T>(() => (viewStateStore.has(k) ? viewStateStore.get(k) as T : initial))
  const set = useCallback((v: T | ((prev: T) => T)) => {
    setValue(prev => {
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v
      viewStateStore.set(k, next)
      return next
    })
  }, [k])
  return [value, set]
}

/**
 * Standard list keyboard model (F): J/K and ↓/↑ move the selection through
 * `ids` (in display order) and open each in the inspector; ↵/O opens the
 * first row when nothing is selected. Returns the selected index (-1 if none)
 * for scroll-into-view. Selection kind must match an inspector kind.
 */
export function useListNav({ ids, kind, enabled = true, anim }: { ids: readonly string[]; kind: string; enabled?: boolean; anim?: 'up' | 'left' }) {
  const nav = useNav()
  const index = nav.sel && nav.sel.kind === kind ? ids.indexOf(nav.sel.id) : -1
  const move = (d: number) => {
    if (!ids.length) return
    const i = index < 0 ? (d > 0 ? 0 : ids.length - 1) : Math.max(0, Math.min(ids.length - 1, index + d))
    nav.select({ kind, id: ids[i] }, { anim })
  }
  useShortcuts([
    { key: ['j', 'ArrowDown'], run: () => move(1) },
    { key: ['k', 'ArrowUp'], run: () => move(-1) },
    { key: ['Enter', 'o'], run: () => { if (index < 0) move(1); else nav.closeChat() } },
  ], { enabled })
  return { index, move }
}
