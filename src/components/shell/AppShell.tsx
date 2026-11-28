// Shared left-rail application shell for /, /projects/$projectId, and /settings.
// Mirrors /runs/$runId's Rail (232px warm-stone/neutral-charcoal rail, monochrome
// Mark, ⌘K trigger, recent runs grouped by project, theme toggle & shortcut sheet).
import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import { cva } from 'class-variance-authority'
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/cn.ts'
import { KovoMark } from '../brand/KovoMark.tsx'
import { KbdGroup } from '../run/display.tsx'
import { fmtN, runLabel } from '../run/format.ts'
import { StatusGlyph } from '../run/glyphs.tsx'
import { Icon } from '../run/icons.tsx'
import { runStatusLabel } from '../run/meta.ts'
import { useTheme } from '../run/theme.ts'
import { DevicesIcon, DevicesSessionModal } from '../settings/DevicesSessionModal.tsx'
import {
  formatFullDateTime,
  formatRelativeTime,
  GlobalHelpSheet,
  GlobalPalette,
  useNow,
} from './GlobalPalette.tsx'
import type { PoolHealth, ShellWorkspaceData } from './GlobalPalette.tsx'

export { formatFullDateTime, formatRelativeTime, useNow } from './GlobalPalette.tsx'
export type { PoolHealth, ShellProjectItem, ShellRecentRun, ShellWorkspaceData } from './GlobalPalette.tsx'

const railItemVariants = cva(
  // pointer-coarse:min-h-10: 40px touch rows; min-height also lets 2-line run rows grow.
  'relative flex w-full cursor-pointer select-none items-center gap-[9px] rounded-control border-0 bg-transparent px-2 text-left text-[13px] text-fg-muted transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg pointer-coarse:min-h-10',
  {
    variants: {
      kind: {
        nav: 'h-[30px] py-1',
        run: 'h-auto items-start py-1.5 font-normal',
      },
      active: {
        true: 'bg-press font-medium text-fg',
        false: '',
      },
    },
    defaultVariants: {
      kind: 'nav',
      active: false,
    },
  },
)

const healthDotVariants = cva('size-[7px] flex-none rounded-full', {
  variants: {
    health: {
      healthy: 'bg-ok',
      degraded: 'bg-warn',
      unconfigured: 'bg-transparent ring-[1.5px] ring-inset ring-fg-faint',
    },
  },
})

interface ShellContextApi {
  openPalette: (prefill?: string) => void
  closePalette: () => void
  openHelp: () => void
  openDevices: () => void
  openNewProject: () => void
  registerNewProjectHandler: (fn: (() => void) | null) => void
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

function hasOpenDialog(): boolean {
  if (typeof document === 'undefined') return false
  return Boolean(document.querySelector('[role="dialog"], [role="alertdialog"], [data-slot="dialog-content"]'))
}

function poolHealthTitle(health: PoolHealth): string {
  if (health === 'healthy') return 'Model pool healthy'
  if (health === 'degraded') return 'Model pool degraded (some profiles temporarily cooling down)'
  return 'No enabled model profile configured'
}

/**
 * Recent-run meta line: segments are joined only when present (no orphan "·"
 * for a missing time), the status truncates with an ellipsis, and the
 * confirmed count is protected on the right in grouped digits.
 */
function RecentRunMeta({ relTime, fullTime, startedAt, status, confirmedCount }: {
  relTime: string
  fullTime: string
  startedAt: number
  status: string
  confirmedCount: number
}) {
  const hasTime = Boolean(relTime) && Number.isFinite(startedAt)
  const segments = [
    hasTime
      ? <time
          key="time"
          className="flex-none tabular-nums"
          dateTime={new Date(startedAt).toISOString()}
          title={fullTime}
          suppressHydrationWarning
        >
          {relTime}
        </time>
      : null,
    status ? <span key="status" className="min-w-0 truncate" title={status}>{status}</span> : null,
  ].filter(Boolean)
  return (
    <span className="flex min-w-0 gap-1.5 whitespace-nowrap text-[11.5px] leading-4 text-fg-subtle">
      {segments.flatMap((segment, i) => (i === 0
        ? [segment]
        : [<span key={`sep-${i}`} className="flex-none" aria-hidden="true">·</span>, segment]))}
      {confirmedCount > 0 && (
        <span className="ml-auto flex-none pl-1.5 tabular-nums" title={`${fmtN(confirmedCount)} confirmed`}>
          {fmtN(confirmedCount)}
        </span>
      )}
    </span>
  )
}

export function AppShell({ data, children }: { data: ShellWorkspaceData; children: ReactNode }) {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: state => state.location.pathname })
  const { theme, toggle: toggleTheme } = useTheme()
  const now = useNow()
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
      // Escape is handled natively by each open @base-ui/react Dialog so only
      // the topmost modal dismisses without affecting anything underneath.
      if (e.key === 'Escape') return
      if (palette.open || helpOpen || devicesOpen || hasOpenDialog()) return
      if (e.metaKey || e.ctrlKey || e.altKey) return
      if (isEditableTarget(e.target)) return

      const ts = Date.now()
      const chord = chordRef.current
      if (chord && ts - chord.at < 800 && chord.key === 'g') {
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
        chordRef.current = { key: 'g', at: ts }
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

  // `theme` is deliberately not part of the context: the boot theme flips it
  // right after hydration, and a changed provider value would force any
  // still-dehydrated route boundary to client-render (a recoverable hydration
  // error on errored routes in dark mode). The shell reads `theme` locally.
  const ctx = useMemo<ShellContextApi>(() => ({
    openPalette,
    closePalette,
    openHelp,
    openDevices,
    openNewProject,
    registerNewProjectHandler,
    toggleTheme,
    data,
  }), [openPalette, closePalette, openHelp, openDevices, openNewProject, registerNewProjectHandler, toggleTheme, data])

  const isProjectsActive = pathname === '/' || pathname.startsWith('/projects/')
  const isSettingsActive = pathname === '/settings' || pathname.startsWith('/settings/')
  const isDark = theme === 'dark'

  return <ShellContext.Provider value={ctx}>
    <div className="grid h-screen grid-cols-[232px_minmax(0,1fr)] overflow-hidden bg-bg text-fg max-[720px]:grid-cols-[196px_minmax(0,1fr)] [&_svg]:block [&_svg]:flex-none">
      <aside className="flex min-h-0 flex-col border-r border-line bg-rail" aria-label="Workspace navigation">
        <div className="flex h-12 flex-none items-center gap-[9px] pl-4 pr-3.5">
          <KovoMark size={18} className="size-[18px] flex-none text-fg" />
          <Link to="/" className="whitespace-nowrap text-[13px] font-semibold tracking-[-0.01em] text-fg" title="All projects">
            Kovo
          </Link>
          <span className="ml-auto text-[12px] text-fg-subtle">Local</span>
        </div>

        <button
          type="button"
          className="mx-2.5 mb-2.5 mt-0.5 flex h-[30px] cursor-pointer items-center gap-2 rounded-[7px] border-0 bg-panel pl-[9px] pr-2 text-left text-[13px] font-normal text-fg-subtle shadow-hairline transition-colors duration-[var(--d1)] hover:bg-panel hover:text-fg-muted"
          onClick={() => openPalette()}
        >
          <Icon name="search" />
          <span className="whitespace-nowrap">Search…</span>
          <span className="ml-auto">
            <KbdGroup keys={['mod', 'K']} />
          </span>
        </button>

        {/* Static fade so a row cut by the footer reads as "more below", not a glitch. */}
        <div className="flex-1 overflow-auto px-2 pb-2 [mask-image:linear-gradient(to_bottom,black_calc(100%-20px),transparent)]">
          <div className="flex items-center justify-between px-2 pb-1 pt-2.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
            <span>Workspace</span>
          </div>
          <nav className="flex flex-col gap-px" aria-label="Workspace">
            <Link
              to="/"
              className={railItemVariants({ active: isProjectsActive })}
              aria-current={pathname === '/' ? 'page' : undefined}
            >
              <Icon name="grid" />
              <span className="min-w-0 flex-1 truncate">Projects</span>
            </Link>
            <Link
              to="/settings"
              search={{}}
              className={railItemVariants({ active: isSettingsActive })}
              aria-current={isSettingsActive ? 'page' : undefined}
              title={poolHealthTitle(data.poolHealth)}
            >
              <Icon name="sliders" />
              <span className="min-w-0 flex-1 truncate">Settings</span>
              {data.poolHealth !== 'healthy' && (
                <span className={healthDotVariants({ health: data.poolHealth })} aria-hidden="true" />
              )}
            </Link>
          </nav>

          <div className="flex items-center justify-between px-2 pb-1 pt-2.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
            <span>Recent runs</span>
            <span className="font-normal tabular-nums">{data.recentRuns.length || ''}</span>
          </div>

          {data.recentRuns.length === 0
            ? <div className="px-2 py-1.5 text-[12px] text-fg-subtle">No runs yet</div>
            : data.recentRuns.map(r => {
              const relTime = formatRelativeTime(r.startedAt, { compact: true, now })
              const fullTime = formatFullDateTime(r.startedAt)
              return <Link
                key={r.id}
                to="/runs/$runId"
                params={{ runId: r.id }}
                search={{}}
                className={railItemVariants({ kind: 'run' })}
                title={`${r.projectName} — ${runLabel(r.goal)} (${fullTime})`}
              >
                <span className="inline-flex size-3.5 flex-none items-center justify-center pt-[3px]">
                  <StatusGlyph status={r.status} />
                </span>
                <span className="flex min-w-0 flex-1 flex-col gap-0">
                  <span className="truncate text-inherit">{r.projectName}</span>
                  <RecentRunMeta
                    relTime={relTime}
                    fullTime={fullTime}
                    startedAt={r.startedAt}
                    status={runStatusLabel(r.status)}
                    confirmedCount={r.confirmedCount}
                  />
                </span>
              </Link>
            })}
        </div>

        <div className="flex-none border-t border-line px-2 py-1.5">
          <button
            type="button"
            className={cn(
              'group/sess flex h-8 min-h-8 w-full cursor-pointer items-center gap-2 whitespace-nowrap rounded-control border-0 bg-transparent px-2 text-left text-[12.5px] font-medium leading-none text-fg-muted shadow-none transition-colors duration-[var(--d1)]',
              'hover:bg-hover hover:text-fg active:scale-100 active:bg-press active:text-fg aria-expanded:bg-press aria-expanded:text-fg',
              // The descendant rule out-specifies the chevron's own classes, so it must
            // list `translate` too or the hover nudge snaps.
            '[&_.ico]:text-fg-subtle [&_.ico]:transition-[color,translate] hover:[&_.ico]:text-fg-muted aria-expanded:[&_.ico]:text-fg-muted',
            )}
            onClick={openDevices}
            aria-haspopup="dialog"
            aria-expanded={devicesOpen}
            title="Devices & local session — pair another browser or phone"
          >
            <DevicesIcon />
            <span className="min-w-0 flex-1 truncate">Local session</span>
            <span className="flex-none text-[11px] font-normal text-fg-subtle transition-colors duration-[var(--d1)] group-hover/sess:text-fg-muted max-[720px]:hidden">
              Pair device
            </span>
            <Icon
              name="chevR"
              className="flex-none text-fg-faint transition-[color,translate] duration-[var(--d1)] ease-kovo group-hover/sess:translate-x-[1px] group-hover/sess:text-fg-subtle"
            />
          </button>
        </div>

        <div className="flex flex-none items-center gap-1 border-t border-line p-2">
          <button
            type="button"
            className="inline-flex h-7 min-w-7 cursor-pointer items-center justify-center gap-1.5 rounded-control border-0 bg-transparent px-[7px] text-fg-subtle shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg"
            onClick={toggleTheme}
            title="Toggle theme (⇧T)"
          >
            <Icon name={isDark ? 'sun' : 'moon'} />
            <span className="text-[12px] font-medium">{isDark ? 'Light' : 'Dark'}</span>
          </button>
          <span className="flex-1" />
          <button
            type="button"
            className="inline-flex h-7 min-w-7 cursor-pointer items-center justify-center gap-1.5 rounded-control border-0 bg-transparent px-[7px] text-fg-subtle shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg"
            onClick={openHelp}
            title="Keyboard shortcuts (?)"
            aria-label="Keyboard shortcuts"
          >
            <Icon name="keyboard" />
          </button>
        </div>
      </aside>

      <div className="relative flex min-h-0 min-w-0 flex-col overflow-auto bg-panel">{children}</div>
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
    {/* Always mounted so Base UI runs the shared enter/exit transition. */}
    <DevicesSessionModal open={devicesOpen} onClose={closeDevices} />
  </ShellContext.Provider>
}
