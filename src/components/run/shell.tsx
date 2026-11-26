// The run workspace shell: providers, rail, run line header, view outlet,
// resizable inspector pane, global keyboard model, palette, toasts.
import { Link, useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { BoardPane, useBoardSeen } from './coordinator.tsx'
import { RunDataProvider, useRun } from './data.tsx'
import { ACTIONS, approvalCommand, DecisionsProvider, useDecisions } from './decisions.tsx'
import { fmtN, fmtUsd, host, RUN_SUBMODE_PARAMS } from './format.ts'
import { RunHeader } from './header.tsx'
import { Icon } from './icons.tsx'
import { KeyboardProvider, useShortcuts } from './keyboard.tsx'
import { VIEWS } from './meta.ts'
import type { ViewId } from './meta.ts'
import type { Approval, Detail, RunEvent } from './model.ts'
import { useReducedMotion } from './motion.tsx'
import { NavProvider, selKey, useNav } from './nav.tsx'
import type { Sel } from './nav.tsx'
import { OverlaysProvider, useOverlays } from './overlays.tsx'
import { FallbackInspector } from './pane.tsx'
import { PaletteProvider, usePalette } from './palette.tsx'
import { Rail } from './rail.tsx'
import { useTheme } from './theme.ts'
import { ToastProvider, useToast } from './toast.tsx'
import { cn, runBtn } from './tw.ts'
import { ScopeOverlay } from './views/consent.tsx'
import { CHAT_FIRST_VIEWS, INSPECTORS, VIEW_COMPONENTS } from './views/index.tsx'

/** Landing view by run state: consent when waiting, the queue when decisions are pending, otherwise the overview. */
export function landingView(d: Detail): ViewId {
  if (d.run.status === 'waiting') return 'overview'
  if (d.approvals.some(a => a.status === 'pending')) return 'queue'
  return 'overview'
}

export function RunShell({ detail, view, sel }: { detail: Detail; view: ViewId; sel: Sel | null }) {
  const navigate = useNavigate()
  const runId = detail.run.id
  const curViewRef = useRef(view)
  curViewRef.current = view
  const go = useCallback((v: ViewId, s: Sel | null, push: boolean) => {
    const keepSubModes: [string, string][] = []
    if (v === curViewRef.current && typeof window !== 'undefined') {
      const sp = new URLSearchParams(window.location.search)
      for (const k of RUN_SUBMODE_PARAMS) {
        const val = sp.get(k)
        if (val) keepSubModes.push([k, val])
      }
    }
    void navigate({ to: '/runs/$runId', params: { runId }, search: { view: v, sel: s ? selKey(s) : undefined }, replace: !push, resetScroll: false }).then(() => {
      if (!keepSubModes.length || typeof window === 'undefined') return
      const url = new URL(window.location.href)
      let changed = false
      for (const [k, val] of keepSubModes) {
        if (url.searchParams.get(k) !== val) {
          url.searchParams.set(k, val)
          changed = true
        }
      }
      if (changed) window.history.replaceState(window.history.state, '', url.pathname + url.search + url.hash)
    })
  }, [navigate, runId])
  const switchRun = useCallback((id: string, v?: ViewId) => {
    void navigate({ to: '/runs/$runId', params: { runId: id }, search: v ? { view: v } : {} })
  }, [navigate])
  return <div className="relative h-screen overflow-hidden bg-bg font-sans text-[13px] leading-5 tracking-[-0.003em] text-fg antialiased">
    <KeyboardProvider>
      <ToastProvider>
        <DataWithToasts detail={detail}>
          <NavWithRun runId={runId} view={view} sel={sel} go={go} switchRun={switchRun}>
            <DecisionsProvider>
              <OverlaysProvider>
                <PaletteProvider>
                  <Workspace />
                </PaletteProvider>
              </OverlaysProvider>
            </DecisionsProvider>
          </NavWithRun>
        </DataWithToasts>
      </ToastProvider>
    </KeyboardProvider>
  </div>
}

function DataWithToasts({ detail, children }: { detail: Detail; children: ReactNode }) {
  const toast = useToast()
  return <RunDataProvider initial={detail} onError={m => toast.show(m, { tone: 'error' })}>{children}</RunDataProvider>
}

function NavWithRun({ runId, view, sel, go, switchRun, children }: {
  runId: string
  view: ViewId
  sel: Sel | null
  go: (view: ViewId, sel: Sel | null, push: boolean) => void
  switchRun: (runId: string, view?: ViewId) => void
  children: ReactNode
}) {
  const { detail } = useRun()
  const hasPendingApprovals = detail.approvals.some(a => a.status === 'pending')
  return <NavProvider runId={runId} view={view} sel={sel} go={go} switchRun={switchRun} hasPendingApprovals={hasPendingApprovals}>{children}</NavProvider>
}

const PANE_KEY = 'kovo-rw-pane'
const PANE_MIN = 320
const PANE_MAX = 640

/** Hide the right-hand Coordinator / Board pane until after scope approval. */
export function isBoardHiddenBeforeApproval(phase: string): boolean {
  return phase === 'consent' || phase === 'review'
}

function Workspace() {
  const { detail } = useRun()
  const nav = useNav()
  const overlays = useOverlays()
  const [paneW, setPaneW] = useState<number | null>(null)
  const [resizing, setResizing] = useState(false)
  const paneRef = useRef<HTMLElement>(null)
  const hideBoardBeforeApproval = isBoardHiddenBeforeApproval(detail.run.phase)
  useEffect(() => {
    const saved = Number(localStorage.getItem(PANE_KEY))
    if (saved >= PANE_MIN && saved <= PANE_MAX) setPaneW(saved)
  }, [])
  useGlobalShortcuts(hideBoardBeforeApproval)
  useBoardSeen()
  const View = VIEW_COMPONENTS[nav.view]
  const rm = useReducedMotion()
  const paneHidden = hideBoardBeforeApproval || nav.paneCollapsed
  const cols = paneHidden
    ? 'grid-cols-[232px_minmax(0,1fr)_0px]'
    : 'grid-cols-[232px_minmax(0,1fr)_var(--pane-w,404px)] max-[1180px]:[--pane-w:360px]'
  return <div
    className={cn(
      'grid h-screen',
      cols,
      !resizing && !rm && 'transition-[grid-template-columns] duration-[var(--d2)] ease-kovo',
    )}
    style={paneW && !paneHidden ? { ['--pane-w' as string]: paneW + 'px' } : undefined}
  >
    <Rail />
    <main className="relative flex min-h-0 min-w-0 flex-col bg-panel" aria-label="Run">
      <RunHeader />
      <RunBanners />
      <div key={nav.view} className="relative flex min-h-0 flex-1 flex-col" id="vh"><View /></div>
    </main>
    {!hideBoardBeforeApproval && <aside
      ref={paneRef}
      className={cn(
        'relative flex min-h-0 min-w-0 flex-col border-l border-line bg-panel transition-opacity duration-[var(--d2)] ease-kovo motion-reduce:transition-none',
        nav.paneCollapsed && 'pointer-events-none overflow-hidden border-l-transparent opacity-0 duration-[var(--d1)]',
      )}
      aria-label="Inspector"
      aria-hidden={nav.paneCollapsed || undefined}
    >
      {!nav.paneCollapsed && <Resizer paneRef={paneRef} onResize={setPaneW} onDraggingChange={setResizing} />}
      <div id="paneInner" className="flex min-h-0 flex-1 flex-col"><PaneContent /></div>
    </aside>}
    {overlays.scopeOpen && <ScopeOverlay />}
  </div>
}

function Resizer({ paneRef, onResize, onDraggingChange }: {
  paneRef: React.RefObject<HTMLElement | null>
  onResize: (w: number) => void
  onDraggingChange: (dragging: boolean) => void
}) {
  const [drag, setDrag] = useState(false)
  const start = useRef({ x: 0, w: 0 })
  useEffect(() => {
    onDraggingChange(drag)
    if (!drag) return
    const move = (e: PointerEvent) => onResize(Math.max(PANE_MIN, Math.min(PANE_MAX, start.current.w + (start.current.x - e.clientX))))
    const up = () => {
      setDrag(false)
      document.body.style.cursor = ''
      const w = paneRef.current?.getBoundingClientRect().width
      if (w) try { localStorage.setItem(PANE_KEY, String(Math.round(w))) } catch { /* ignore */ }
    }
    document.body.style.cursor = 'col-resize'
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up) }
  }, [drag, onResize, onDraggingChange, paneRef])
  return <div
    className={cn(
      'absolute -left-[3px] bottom-0 top-0 z-[5] w-1.5 cursor-col-resize hover:bg-[linear-gradient(90deg,transparent_2px,var(--accent-line)_2px,var(--accent-line)_4px,transparent_4px)]',
      drag && 'bg-[linear-gradient(90deg,transparent_2px,var(--accent-line)_2px,var(--accent-line)_4px,transparent_4px)]',
    )}
    role="separator"
    aria-orientation="vertical"
    aria-label="Resize inspector"
    title="Drag to resize · double-click to reset"
    onPointerDown={e => {
      e.preventDefault()
      start.current = { x: e.clientX, w: (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect().width }
      setDrag(true)
    }}
    onDoubleClick={() => { onResize(404); try { localStorage.removeItem(PANE_KEY) } catch { /* ignore */ } }}
  />
}

function PaneContent() {
  const nav = useNav()
  const sel = nav.sel
  const showChat = nav.chat || !sel || (CHAT_FIRST_VIEWS.includes(nav.view) && !sel)
  const key = showChat ? 'chat' : selKey(sel!)
  const Inspector = !showChat ? INSPECTORS[sel!.kind] ?? FallbackInspector : null
  return <div key={key} className="flex min-h-0 min-w-0 flex-1 flex-col">
    {showChat ? <BoardPane /> : Inspector && <Inspector sel={sel!} />}
  </div>
}

/** Return the most recent unresolved `persona.auth_failed` or `persona.refresh_failed` event, if any. */
export function latestAuthIssue(events: readonly RunEvent[]): RunEvent | null {
  const byKey = new Map<string, RunEvent>()
  let lastAuthOkId = -1
  for (const ev of events) {
    if (ev.kind === 'persona.authenticated') {
      const key = typeof ev.detail?.handle === 'string' && ev.detail.handle
        ? ev.detail.handle
        : typeof ev.detail?.personaId === 'string' && ev.detail.personaId
          ? ev.detail.personaId
          : '*'
      byKey.set(key, ev)
      if (ev.id > lastAuthOkId) lastAuthOkId = ev.id
    } else if (ev.kind === 'persona.auth_failed' || ev.kind === 'persona.refresh_failed') {
      const key = typeof ev.detail?.handle === 'string' && ev.detail.handle
        ? ev.detail.handle
        : typeof ev.detail?.personaId === 'string' && ev.detail.personaId
          ? ev.detail.personaId
          : '*'
      byKey.set(key, ev)
    }
  }
  let latest: RunEvent | null = null
  for (const [key, ev] of byKey.entries()) {
    if (ev.kind !== 'persona.auth_failed' && ev.kind !== 'persona.refresh_failed') continue
    if (key === '*' && lastAuthOkId > ev.id) continue
    if (!latest || ev.id > latest.id) latest = ev
  }
  return latest
}

function openHeaderBudgetPopover() {
  if (typeof document === 'undefined') return
  if (document.querySelector('[role="dialog"][aria-label="Budget and rate limit"]')) return
  const trigger = document.querySelector<HTMLButtonElement>('header [data-rl-btn][title^="Budget "]')
  trigger?.click()
}

/** Show the pinned top approval banner outside Queue and consent/review screens when active approvals wait. */
export function shouldShowApprovalBanner(input: {
  activeApprovalCount: number
  view: ViewId
  phase: string
}): boolean {
  if (input.activeApprovalCount <= 0) return false
  if (input.view === 'queue') return false
  if (isBoardHiddenBeforeApproval(input.phase)) return false
  return true
}

export function ApprovalBanner({
  approvals,
  submitting,
  onApprove,
  onDeny,
  onInspect,
  onReviewInQueue,
  onApproveAll,
}: {
  approvals: readonly Approval[]
  submitting: boolean
  onApprove: (ap: Approval) => void
  onDeny: (ap: Approval) => void
  onInspect: (ap: Approval) => void
  onReviewInQueue: () => void
  onApproveAll: () => void
}) {
  const count = approvals.length
  if (count <= 0) return null
  const first = approvals[0]!
  const target = `${first.method} ${host(first.origin)}${first.pathAndQuery}`
  return <div
    className="flex min-h-10 flex-none items-center gap-2.5 border-b border-accent-line bg-accent-soft py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted"
    role="status"
    aria-label="Pending approvals"
    data-testid="approval-banner"
  >
    <span className="relative inline-flex size-2 flex-none" aria-hidden="true">
      <span className="absolute inset-0 animate-ping rounded-full bg-accent opacity-50 motion-reduce:animate-none" />
      <span className="relative inline-block size-2 rounded-full bg-accent" />
    </span>
    {count === 1 ? <>
      <span className="min-w-0 flex-1 truncate" title={`1 approval waiting · ${target}`}>
        <b className="font-medium text-fg">1 approval waiting</b>
        {' · '}
        <span className="font-mono text-[12px] text-fg">
          <span className="font-semibold text-warn">{first.method}</span>
          {' '}
          {host(first.origin)}
          <span className="text-fg-subtle">{first.pathAndQuery}</span>
        </span>
      </span>
      <button
        type="button"
        className={runBtn({ variant: 'primary', size: 'sm' })}
        data-testid="approval-banner-approve"
        onClick={() => onApprove(first)}
      >
        <Icon name="check" />Approve
      </button>
      <button
        type="button"
        className={runBtn({ variant: 'ghost', size: 'sm' })}
        data-testid="approval-banner-deny"
        onClick={() => onDeny(first)}
      >
        Deny
      </button>
      <button
        type="button"
        className={runBtn({ variant: 'default', size: 'sm' })}
        data-testid="approval-banner-inspect"
        onClick={() => onInspect(first)}
      >
        Inspect
      </button>
    </> : <>
      <span className="min-w-0 flex-1 truncate" title={`${count} approvals waiting · ${target} (+${count - 1} more)`}>
        <b className="font-medium text-fg">{count} approvals waiting</b>
        {' · '}
        <span className="font-mono text-[12px] text-fg">
          <span className="font-semibold text-warn">{first.method}</span>
          {' '}
          {host(first.origin)}
          <span className="text-fg-subtle">{first.pathAndQuery}</span>
        </span>
        <span className="ml-1.5 text-fg-subtle">(+{count - 1} more)</span>
      </span>
      <button
        type="button"
        className={runBtn({ variant: 'default', size: 'sm' })}
        data-testid="approval-banner-review"
        onClick={onReviewInQueue}
      >
        Review in Queue
      </button>
      <button
        type="button"
        className={runBtn({ variant: 'primary', size: 'sm' })}
        disabled={submitting}
        data-testid="approval-banner-approve-all"
        onClick={onApproveAll}
      >
        <Icon name="check" />{submitting ? `Approving ${count}…` : `Approve all (${count})`}
      </button>
    </>}
  </div>
}

/** Pending approvals, budget-paused, auth-issue, model-missing, reconnecting: crisp one-line banners under the run line. */
function RunBanners() {
  const { detail, model, events, connection, pending } = useRun()
  const nav = useNav()
  const q = useDecisions()
  const r = detail.run
  const authIssue = latestAuthIssue(events)
  const showApprovalBanner = shouldShowApprovalBanner({
    activeApprovalCount: q.activePendingApprovals.length,
    view: nav.view,
    phase: r.phase,
  })
  const decideApproval = (ap: Approval, act: 'approve' | 'deny') => {
    q.decide('ap:' + ap.id, act, {
      command: approvalCommand(ap.id, act),
      message: `${ACTIONS[act].label} ${ap.method} ${host(ap.origin)}${ap.pathAndQuery}`,
    })
  }
  return <>
    {showApprovalBanner && <ApprovalBanner
      approvals={q.activePendingApprovals}
      submitting={pending > 0 || q.approvingAll}
      onApprove={ap => decideApproval(ap, 'approve')}
      onDeny={ap => decideApproval(ap, 'deny')}
      onInspect={ap => nav.open('queue', { kind: 'queue', id: 'ap:' + ap.id })}
      onReviewInQueue={() => nav.setView('queue')}
      onApproveAll={() => { void q.approveAllPending() }}
    />}
    {r.status === 'budget_paused' && <div
      className="flex min-h-10 flex-none items-center gap-2.5 border-b border-line bg-warn-soft py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted shadow-[inset_0_-1px_0_var(--warn-line)]"
      role="status"
      aria-label="Budget paused"
      data-testid="budget-paused-banner"
    >
      <Icon name="budget" className="text-warn" />
      <span className="min-w-0 flex-1 truncate">
        <b className="font-medium text-fg">Paused at the budget ceiling.</b> Spent {fmtUsd(r.spentUsd)} of {fmtUsd(r.budgetUsd)} and {fmtN(r.spentRequests)} of {r.budgetRequests ? fmtN(r.budgetRequests) : 'uncapped'} requests. A partial report is saved.
      </span>
      <button type="button" data-rl-btn="" className={runBtn({ variant: 'primary' })} onClick={openHeaderBudgetPopover}>
        <Icon name="budget" />Raise budget
      </button>
    </div>}
    {authIssue && <div
      className="flex min-h-10 flex-none items-center gap-2.5 border-b border-line bg-warn-soft py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted shadow-[inset_0_-1px_0_var(--warn-line)]"
      role="status"
      aria-label="Auth issue"
      data-testid="auth-issue-banner"
    >
      <Icon name="lock" className="text-warn" />
      <span className="min-w-0 flex-1 truncate" title={authIssue.message}>
        <b className="font-medium text-fg">Auth issue.</b> {authIssue.message}
      </span>
      <Link className={runBtn()} to="/projects/$projectId" params={{ projectId: detail.project.id }} search={{ tab: 'personas' }}>
        Manage test accounts<Icon name="arrowR" />
      </Link>
    </div>}
    {model.needsModel && <div className="flex min-h-10 flex-none items-center gap-2.5 border-b border-line bg-warn-soft py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted shadow-[inset_0_-1px_0_var(--warn-line)]" role="status">
      <Icon name="alert" className="text-warn" />
      <span className="min-w-0 flex-1"><b className="font-medium text-fg">Connect a model to continue.</b> No enabled model profile; settings bring you back here.</span>
      <Link className={runBtn()} to="/settings" search={{ runId: r.id }}>Set up model<Icon name="arrowR" /></Link>
    </div>}
    {connection === 'reconnecting' && <div className="flex min-h-10 flex-none items-center gap-2.5 border-b border-line bg-sunk py-2 pl-[18px] pr-3 text-[12.5px] text-fg-muted" role="status">
      <Icon name="activity" />
      <span className="min-w-0 flex-1">Reconnecting to Kovo Hunter… the view keeps the last data it had.</span>
    </div>}
  </>
}

/** Global keyboard model: ⌘K, ?, g+letter, 1–8, [ ], ⇧T, C, Esc stack. */
function useGlobalShortcuts(hideBoardBeforeApproval: boolean) {
  const nav = useNav()
  const pal = usePalette()
  const { runs, detail } = useRun()
  const { toggle } = useTheme()
  const switchBy = (d: number) => {
    const ids = runs.map(r => r.id)
    if (ids.length < 2) return
    let i = ids.indexOf(detail.run.id) + d
    i = (i + ids.length) % ids.length
    nav.switchRun(ids[i])
  }
  useShortcuts([
    { key: 'mod+k', allowInInput: true, run: () => (pal.isOpen ? pal.close() : pal.open()) },
    { key: '?', run: () => pal.openHelp() },
    { key: 'T', run: toggle },
    ...VIEWS.map((v, i) => ({ key: ['g ' + v.key, String(i + 1)], run: () => nav.setView(v.id) })),
    { key: '[', run: () => switchBy(-1) },
    { key: ']', run: () => { if (hideBoardBeforeApproval) return false; nav.togglePane() } },
    { key: 'c', run: () => { if (hideBoardBeforeApproval) return false; nav.openChat(null) } },
    { key: 'Escape', run: () => {
      if (nav.chat && nav.sel) { nav.closeChat(); return }
      if (nav.chat) { nav.closeChat(); return }
      if (nav.back()) return
      if (nav.sel) { nav.close(); return }
      return false
    } },
  ], { priority: 0 })
}
