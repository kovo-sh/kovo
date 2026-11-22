// The run workspace shell: providers, rail, run line header, view outlet,
// resizable inspector pane, global keyboard model, palette, toasts.
import { useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { CoordinatorPane } from './coordinator.tsx'
import { RunDataProvider, useRun } from './data.tsx'
import type { Detail } from './model.ts'
import { DecisionsProvider, useDecisions } from './decisions.tsx'
import { fmtUsd, fmtN } from './format.ts'
import { RunHeader } from './header.tsx'
import { Icon } from './icons.tsx'
import { KeyboardProvider, useShortcuts } from './keyboard.tsx'
import { VIEWS } from './meta.ts'
import type { ViewId } from './meta.ts'
import { useReducedMotion } from './motion.tsx'
import { NavProvider, selKey, useNav } from './nav.tsx'
import type { Sel } from './nav.tsx'
import { OverlaysProvider, useOverlays } from './overlays.tsx'
import { FallbackInspector } from './pane.tsx'
import { PaletteProvider, usePalette } from './palette.tsx'
import { Rail } from './rail.tsx'
import { useTheme } from './theme.ts'
import { ToastProvider, useToast } from './toast.tsx'
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
  const go = useCallback((v: ViewId, s: Sel | null, push: boolean) => {
    void navigate({ to: '/runs/$runId', params: { runId }, search: { view: v, sel: s ? selKey(s) : undefined }, replace: !push, resetScroll: false })
  }, [navigate, runId])
  const switchRun = useCallback((id: string, v?: ViewId) => {
    void navigate({ to: '/runs/$runId', params: { runId: id }, search: v ? { view: v } : {} })
  }, [navigate])
  return <div className="rw">
    <KeyboardProvider>
      <ToastProvider>
        <DataWithToasts detail={detail}>
          <NavProvider runId={runId} view={view} sel={sel} go={go} switchRun={switchRun}>
            <DecisionsProvider>
              <OverlaysProvider>
                <PaletteProvider>
                  <Workspace />
                </PaletteProvider>
              </OverlaysProvider>
            </DecisionsProvider>
          </NavProvider>
        </DataWithToasts>
      </ToastProvider>
    </KeyboardProvider>
  </div>
}

function DataWithToasts({ detail, children }: { detail: Detail; children: ReactNode }) {
  const toast = useToast()
  return <RunDataProvider initial={detail} onError={m => toast.show(m, { tone: 'error' })}>{children}</RunDataProvider>
}

const PANE_KEY = 'guardian-rw-pane'
const PANE_MIN = 320
const PANE_MAX = 640

function Workspace() {
  const nav = useNav()
  const overlays = useOverlays()
  const [paneW, setPaneW] = useState<number | null>(null)
  useEffect(() => {
    const saved = Number(localStorage.getItem(PANE_KEY))
    if (saved >= PANE_MIN && saved <= PANE_MAX) setPaneW(saved)
  }, [])
  useGlobalShortcuts()
  const View = VIEW_COMPONENTS[nav.view]
  const rm = useReducedMotion()
  return <div className="app" style={paneW ? { ['--pane-w' as string]: paneW + 'px' } : undefined}>
    <Rail />
    <main className="main" aria-label="Run">
      <RunHeader />
      <RunBanners />
      <div key={nav.view} className={'view-host' + (rm ? '' : ' view-in')} id="vh"><View /></div>
    </main>
    <aside className="pane" aria-label="Inspector">
      <Resizer onResize={setPaneW} />
      <div id="paneInner"><PaneContent /></div>
    </aside>
    {overlays.scopeOpen && <ScopeOverlay />}
  </div>
}

function Resizer({ onResize }: { onResize: (w: number) => void }) {
  const [drag, setDrag] = useState(false)
  const start = useRef({ x: 0, w: 0 })
  useEffect(() => {
    if (!drag) return
    const move = (e: PointerEvent) => onResize(Math.max(PANE_MIN, Math.min(PANE_MAX, start.current.w + (start.current.x - e.clientX))))
    const up = () => {
      setDrag(false)
      document.body.style.cursor = ''
      const w = document.querySelector('.rw .pane')?.getBoundingClientRect().width
      if (w) try { localStorage.setItem(PANE_KEY, String(Math.round(w))) } catch { /* ignore */ }
    }
    document.body.style.cursor = 'col-resize'
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up) }
  }, [drag, onResize])
  return <div className={'resizer' + (drag ? ' drag' : '')} role="separator" aria-orientation="vertical" aria-label="Resize inspector" title="Drag to resize · double-click to reset"
    onPointerDown={e => {
      e.preventDefault()
      start.current = { x: e.clientX, w: (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect().width }
      setDrag(true)
    }}
    onDoubleClick={() => { onResize(404); try { localStorage.removeItem(PANE_KEY) } catch { /* ignore */ } }} />
}

function PaneContent() {
  const nav = useNav()
  const rm = useReducedMotion()
  const sel = nav.sel
  const showChat = nav.chat || !sel || (CHAT_FIRST_VIEWS.includes(nav.view) && !sel)
  const key = showChat ? 'chat' : selKey(sel!)
  const Inspector = !showChat ? INSPECTORS[sel!.kind] ?? FallbackInspector : null
  const anim = rm ? '' : nav.paneAnim === 'left' ? ' pane-in-l' : ' pane-in'
  return <div key={key} className={'pane-tx' + anim}>
    {showChat ? <CoordinatorPane /> : Inspector && <Inspector sel={sel!} />}
  </div>
}

/** Budget-paused, model-missing, reconnecting: one-line banners under the run line. */
function RunBanners() {
  const { detail, model, connection, send, pending } = useRun()
  const r = detail.run
  const [usd, setUsd] = useState(() => Math.min(500, Math.max(r.budgetUsd + 10, Math.ceil(r.spentUsd + 10))))
  const [reqs, setReqs] = useState(0)
  return <>
    {r.status === 'budget_paused' && <form className="rbanner warn" aria-label="Budget paused" onSubmit={e => {
      e.preventDefault()
      void send({ action: 'raise_budget', budgetUsd: usd, budgetRequests: reqs, resume: true }).catch(() => {})
    }}>
      <Icon name="budget" />
      <span className="grow"><b>Paused at the budget ceiling.</b> Spent {fmtUsd(r.spentUsd)} of {fmtUsd(r.budgetUsd)} and {fmtN(r.spentRequests)} of {r.budgetRequests ? fmtN(r.budgetRequests) : 'uncapped'} requests. A partial report is saved; raise the limits to resume without repeating work.</span>
      <label>USD<input className="field-in num" type="number" min={0.1} max={500} step="any" required value={usd} onChange={e => setUsd(Number(e.target.value))} aria-label="New USD budget" /></label>
      <label>Requests<input className="field-in num" type="number" min={0} step={1} required value={reqs} onChange={e => setReqs(Number(e.target.value))} aria-label="New request cap (0 = uncapped)" title="0 = uncapped" /></label>
      <button type="submit" className="btn primary" disabled={pending > 0}>Raise and resume</button>
    </form>}
    {model.needsModel && <div className="rbanner warn" role="status">
      <Icon name="alert" />
      <span className="grow"><b>Connect a model to continue.</b> No enabled model profile; settings bring you back here.</span>
      <a className="btn" href={`/settings?runId=${encodeURIComponent(r.id)}`}>Set up model<Icon name="arrowR" /></a>
    </div>}
    {connection === 'reconnecting' && <div className="rbanner" role="status"><Icon name="activity" /><span className="grow">Reconnecting to Guardian… the view keeps the last data it had.</span></div>}
  </>
}

/** Global keyboard model (F): ⌘K, ?, g+letter, 1–8, [ ], ⇧T, C, Esc stack, Z / ⌘Z undo. */
function useGlobalShortcuts() {
  const nav = useNav()
  const pal = usePalette()
  const { runs, detail } = useRun()
  const { toggle } = useTheme()
  const toast = useToast()
  const q = useDecisions()
  const switchBy = (d: number) => {
    const ids = runs.map(r => r.id)
    if (ids.length < 2) return
    let i = ids.indexOf(detail.run.id) + d
    i = (i + ids.length) % ids.length
    nav.switchRun(ids[i])
  }
  const undo = () => { if (!toast.undoLast() && !q.undoLastLocal()) toast.show('Nothing to undo') }
  useShortcuts([
    { key: 'mod+k', allowInInput: true, run: () => (pal.isOpen ? pal.close() : pal.open()) },
    { key: '?', run: () => pal.openHelp() },
    { key: 'T', run: toggle },
    ...VIEWS.map((v, i) => ({ key: ['g ' + v.key, String(i + 1)], run: () => nav.setView(v.id) })),
    { key: '[', run: () => switchBy(-1) },
    { key: ']', run: () => switchBy(1) },
    { key: 'c', run: () => nav.openChat(null) },
    { key: 'mod+z', run: undo },
    { key: 'z', run: undo },
    { key: 'Escape', run: () => {
      if (nav.chat && nav.sel) { nav.closeChat(); return }
      if (nav.chat) { nav.closeChat(); return }
      if (nav.back()) return
      if (nav.sel) { nav.close(); return }
      return false
    } },
  ], { priority: 0 })
}
