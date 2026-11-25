// Shared left-rail application shell for /, /projects/$projectId, and /settings.
// Mirrors /runs/$runId's Rail (232px warm-stone/neutral-charcoal rail, monochrome
// Mark, ⌘K trigger, recent runs grouped by project, theme toggle & shortcut sheet).
import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { KovoHunterMark } from '../brand/KovoHunterMark.tsx'
import { KbdGroup } from '../run/display.tsx'
import { runLabel, short } from '../run/format.ts'
import { StatusGlyph } from '../run/glyphs.tsx'
import { Icon } from '../run/icons.tsx'
import { runStatusLabel } from '../run/meta.ts'
import { DevicesIcon, DevicesSessionModal } from '../settings/DevicesSessionModal.tsx'
import { GlobalHelpSheet, GlobalPalette } from './GlobalPalette.tsx'
import type { PoolHealth, ShellWorkspaceData } from './GlobalPalette.tsx'

export type { PoolHealth, ShellProjectItem, ShellRecentRun, ShellWorkspaceData } from './GlobalPalette.tsx'

const APPEARANCE_KEY = 'guardian-appearance'

function resolveEffectiveTheme(): 'light' | 'dark' {
  if (typeof document === 'undefined') return 'light'
  const a = document.documentElement.dataset.appearance
  if (a === 'dark' || a === 'light') return a
  const t = document.documentElement.dataset.theme
  if (t === 'dark' || t === 'light') return t
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function syncThemeAttributes(mode?: 'light' | 'dark' | 'system') {
  if (typeof document === 'undefined') return 'light' as const
  if (mode) {
    document.documentElement.dataset.appearance = mode
  }
  const resolved = resolveEffectiveTheme()
  if (document.documentElement.dataset.theme !== resolved) {
    document.documentElement.dataset.theme = resolved
  }
  return resolved
}

export function useShellTheme() {
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  useEffect(() => {
    setTheme(syncThemeAttributes())
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setTheme(syncThemeAttributes())
    mq.addEventListener('change', onChange)
    const mo = new MutationObserver(onChange)
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-appearance', 'data-theme'] })
    return () => {
      mq.removeEventListener('change', onChange)
      mo.disconnect()
    }
  }, [])

  const toggle = useCallback(() => {
    const next: 'light' | 'dark' = resolveEffectiveTheme() === 'dark' ? 'light' : 'dark'
    try { localStorage.setItem(APPEARANCE_KEY, next) } catch { /* ignore */ }
    setTheme(syncThemeAttributes(next))
  }, [])

  return { theme, toggle }
}

interface ShellContextApi {
  openPalette: (prefill?: string) => void
  closePalette: () => void
  openHelp: () => void
  openDevices: () => void
  openNewProject: () => void
  registerNewProjectHandler: (fn: (() => void) | null) => void
  theme: 'light' | 'dark'
  toggleTheme: () => void
  data: ShellWorkspaceData
}

const ShellContext = createContext<ShellContextApi | null>(null)

export function useShell() {
  return useContext(ShellContext)
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  const tag = target.tagName
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true
  if (target.isContentEditable) return true
  return Boolean(target.closest('[contenteditable="true"]'))
}

function poolHealthTitle(health: PoolHealth): string {
  if (health === 'healthy') return 'Model pool healthy'
  if (health === 'degraded') return 'Model pool degraded (circuit breaker active)'
  return 'No enabled model profile configured'
}

export function AppShell({ data, children }: { data: ShellWorkspaceData; children: ReactNode }) {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: state => state.location.pathname })
  const { theme, toggle: toggleTheme } = useShellTheme()
  const [palette, setPalette] = useState<{ open: boolean; prefill: string }>({ open: false, prefill: '' })
  const [helpOpen, setHelpOpen] = useState(false)
  const [devicesOpen, setDevicesOpen] = useState(false)
  const newProjectHandlerRef = useRef<(() => void) | null>(null)
  const chordRef = useRef<{ key: string; at: number } | null>(null)

  const openPalette = useCallback((prefill = '') => {
    setHelpOpen(false)
    setDevicesOpen(false)
    setPalette({ open: true, prefill })
  }, [])

  const closePalette = useCallback(() => {
    setPalette(s => ({ ...s, open: false }))
  }, [])

  const openHelp = useCallback(() => {
    setPalette(s => ({ ...s, open: false }))
    setDevicesOpen(false)
    setHelpOpen(true)
  }, [])

  const openDevices = useCallback(() => {
    setPalette(s => ({ ...s, open: false }))
    setHelpOpen(false)
    setDevicesOpen(true)
  }, [])

  const closeDevices = useCallback(() => {
    setDevicesOpen(false)
  }, [])

  const registerNewProjectHandler = useCallback((fn: (() => void) | null) => {
    newProjectHandlerRef.current = fn
  }, [])

  const openNewProject = useCallback(() => {
    if (newProjectHandlerRef.current) {
      newProjectHandlerRef.current()
    } else {
      void navigate({ to: '/', search: { new: '1' } })
    }
  }, [navigate])

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setHelpOpen(false)
        setDevicesOpen(false)
        setPalette(s => ({ open: !s.open, prefill: '' }))
        return
      }
      if (e.key === 'Escape') {
        if (palette.open) { e.preventDefault(); setPalette(s => ({ ...s, open: false })); return }
        if (helpOpen) { e.preventDefault(); setHelpOpen(false); return }
        return
      }
      if (palette.open || helpOpen || devicesOpen) return
      if (e.metaKey || e.ctrlKey || e.altKey) return
      if (isEditableTarget(e.target)) return

      const now = Date.now()
      const chord = chordRef.current
      if (chord && now - chord.at < 800 && chord.key === 'g') {
        chordRef.current = null
        const k = e.key.toLowerCase()
        if (k === 'p') {
          e.preventDefault()
          void navigate({ to: '/' })
          return
        }
        if (k === 's') {
          e.preventDefault()
          void navigate({ to: '/settings', search: {} })
          return
        }
      }

      if (e.key === 'g') {
        chordRef.current = { key: 'g', at: now }
        return
      }
      if (e.key === '?') {
        e.preventDefault()
        setHelpOpen(true)
        return
      }
      if (e.shiftKey && e.key === 'T') {
        e.preventDefault()
        toggleTheme()
        return
      }
      if (!e.shiftKey && e.key === 'n') {
        e.preventDefault()
        openNewProject()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [palette.open, helpOpen, devicesOpen, navigate, toggleTheme, openNewProject])

  const groupedRecent = useMemo(() => {
    const groups: { projectId: string; projectName: string; runs: ShellWorkspaceData['recentRuns'] }[] = []
    const byProject = new Map<string, (typeof groups)[number]>()
    for (const run of data.recentRuns) {
      let group = byProject.get(run.projectId)
      if (!group) {
        group = { projectId: run.projectId, projectName: run.projectName, runs: [] }
        byProject.set(run.projectId, group)
        groups.push(group)
      }
      group.runs.push(run)
    }
    return groups
  }, [data.recentRuns])

  const ctx = useMemo<ShellContextApi>(() => ({
    openPalette,
    closePalette,
    openHelp,
    openDevices,
    openNewProject,
    registerNewProjectHandler,
    theme,
    toggleTheme,
    data,
  }), [openPalette, closePalette, openHelp, openDevices, openNewProject, registerNewProjectHandler, theme, toggleTheme, data])

  const isProjectsActive = pathname === '/' || pathname.startsWith('/projects/')
  const isSettingsActive = pathname === '/settings' || pathname.startsWith('/settings/')
  const isDark = theme === 'dark'

  return <ShellContext.Provider value={ctx}>
    <div className="app-shell">
      <aside className="sh-rail" aria-label="Workspace navigation">
        <div className="sh-brand">
          <KovoHunterMark />
          <Link to="/" className="sh-brand-name" title="All projects" style={{ whiteSpace: 'nowrap' }}>Kovo Hunter</Link>
          <span className="sh-ws">Local</span>
        </div>

        <button type="button" className="sh-search" onClick={() => openPalette()}>
          <Icon name="search" />
          <span style={{ whiteSpace: 'nowrap' }}>Search…</span>
          <KbdGroup keys={['mod', 'K']} />
        </button>

        <div className="sh-rail-scroll">
          <div className="sh-rail-h"><span>Workspace</span></div>
          <nav aria-label="Workspace">
            <Link
              to="/"
              className={'sh-ritem' + (isProjectsActive ? ' on' : '')}
              aria-current={pathname === '/' ? 'page' : undefined}
            >
              <Icon name="grid" />
              <span className="lbl">Projects</span>
            </Link>
            <Link
              to="/settings"
              search={{}}
              className={'sh-ritem' + (isSettingsActive ? ' on' : '')}
              aria-current={isSettingsActive ? 'page' : undefined}
              title={poolHealthTitle(data.poolHealth)}
            >
              <Icon name="sliders" />
              <span className="lbl">Model settings</span>
              {data.poolHealth !== 'healthy' && (
                <span className={'sh-health-dot ' + data.poolHealth} aria-hidden="true" />
              )}
            </Link>
          </nav>

          <div className="sh-rail-h">
            <span>Recent runs</span>
            <span className="num" style={{ fontWeight: 400 }}>{data.recentRuns.length || ''}</span>
          </div>

          {groupedRecent.length === 0
            ? <div className="sh-rail-empty">No runs yet</div>
            : groupedRecent.map(group => <div key={group.projectId}>
              <Link
                to="/projects/$projectId"
                params={{ projectId: group.projectId }}
                className="sh-proj"
                title={group.projectName}
              >
                {group.projectName}
              </Link>
              {group.runs.map(r => <Link
                key={r.id}
                to="/runs/$runId"
                params={{ runId: r.id }}
                search={{}}
                className="sh-ritem run"
                title={r.goal}
              >
                <span className="g"><StatusGlyph status={r.status} /></span>
                <span className="lbl">
                  <span className="t">{runLabel(r.goal)}</span>
                  <span className="s">
                    <span className="mono" style={{ fontSize: 11 }}>{short(r.id)}</span>
                    <span>{runStatusLabel(r.status)}</span>
                    {r.confirmedCount > 0 && <span className="num" style={{ marginLeft: 'auto' }}>{r.confirmedCount}</span>}
                  </span>
                </span>
              </Link>)}
            </div>)}
        </div>

        <div className="sh-rail-session">
          <button
            type="button"
            className="sh-session-chip"
            onClick={openDevices}
            aria-haspopup="dialog"
            aria-expanded={devicesOpen}
            title="Devices & local session — pair another browser or phone"
          >
            <DevicesIcon />
            <span className="sh-session-label">Local session</span>
            <span className="sh-session-hint">Pair device</span>
            <Icon name="chevR" className="sh-session-chev" />
          </button>
        </div>

        <div className="sh-rail-foot">
          <button
            type="button"
            className="sh-icon-btn"
            onClick={toggleTheme}
            title="Toggle theme (⇧T)"
          >
            <Icon name={isDark ? 'sun' : 'moon'} />
            <span style={{ fontSize: 12 }}>{isDark ? 'Light' : 'Dark'}</span>
          </button>
          <span className="grow" />
          <button
            type="button"
            className="sh-icon-btn"
            onClick={openHelp}
            title="Keyboard shortcuts (?)"
            aria-label="Keyboard shortcuts"
          >
            <Icon name="keyboard" />
          </button>
        </div>
      </aside>

      <div className="sh-main">{children}</div>
    </div>

    <GlobalPalette
      open={palette.open}
      prefill={palette.prefill}
      onClose={closePalette}
      onOpenNewProject={openNewProject}
      onOpenHelp={openHelp}
      onOpenDevices={openDevices}
      theme={theme}
      toggleTheme={toggleTheme}
      data={data}
    />
    <GlobalHelpSheet open={helpOpen} onClose={() => setHelpOpen(false)} />
    {devicesOpen && <DevicesSessionModal onClose={closeDevices} />}
  </ShellContext.Provider>
}
