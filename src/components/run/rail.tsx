// Left rail: brand, ⌘K search entry, #1 Investigation views, #2 Runs (current project
// first 5 + All runs link + collapsible Other projects), #3 collapsible Telemetry
// (persisted in localStorage), #4 compact Workspace block above the session/utility footer.
import { Link } from '@tanstack/react-router'
import { useEffect, useMemo, useRef, useState } from 'react'
import { KovoHunterMark } from '../brand/KovoHunterMark.tsx'
import { DevicesIcon, DevicesSessionModal } from '../settings/DevicesSessionModal.tsx'
import { Disclosure, DisclosureContent, DisclosureTrigger } from '../ui/disclosure.tsx'
import { useRun } from './data.tsx'
import { useDecisions } from './decisions.tsx'
import { KbdGroup } from './display.tsx'
import { fmtAgo, fmtFullDateTime, fmtN, runLabel, short } from './format.ts'
import { StatusGlyph } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import { runStatusLabel, VIEWS } from './meta.ts'
import type { ViewId } from './meta.ts'
import { usePulse } from './motion.tsx'
import { useNav } from './nav.tsx'
import { usePalette } from './palette.tsx'
import { useTheme } from './theme.ts'
import { cn, runIconBtn } from './tw.ts'

export const RAIL_CURRENT_PROJECT_RUN_LIMIT = 5
export const RAIL_OTHER_PROJECT_RUN_LIMIT = 3
export const TELEMETRY_OPEN_STORAGE_KEY = 'kovo.rail.telemetryOpen'

export interface RailProjectGroup<T extends { projectId: string; projectName: string }> {
  projectId: string
  projectName: string
  runs: T[]
  totalCount: number
}

/**
 * Partition workspace runs into the active project's capped recent list and
 * other projects' grouped runs (each capped to `otherProjectLimit`).
 */
export function partitionRailRuns<T extends { projectId: string; projectName: string }>(
  runs: readonly T[],
  currentProjectId: string,
  currentProjectLimit = RAIL_CURRENT_PROJECT_RUN_LIMIT,
  otherProjectLimit = RAIL_OTHER_PROJECT_RUN_LIMIT,
): {
  currentProjectRuns: T[]
  currentProjectTotal: number
  otherProjects: RailProjectGroup<T>[]
  otherProjectsRunCount: number
} {
  const currentAll: T[] = []
  const otherGroups: RailProjectGroup<T>[] = []
  const otherByProject = new Map<string, RailProjectGroup<T>>()
  let otherProjectsRunCount = 0

  for (const r of runs) {
    if (r.projectId === currentProjectId) {
      currentAll.push(r)
      continue
    }
    otherProjectsRunCount += 1
    let group = otherByProject.get(r.projectId)
    if (!group) {
      group = { projectId: r.projectId, projectName: r.projectName, runs: [], totalCount: 0 }
      otherByProject.set(r.projectId, group)
      otherGroups.push(group)
    }
    group.totalCount += 1
    if (group.runs.length < otherProjectLimit) {
      group.runs.push(r)
    }
  }

  return {
    currentProjectRuns: currentAll.slice(0, currentProjectLimit),
    currentProjectTotal: currentAll.length,
    otherProjects: otherGroups,
    otherProjectsRunCount,
  }
}

export function readTelemetryOpenPreference(storage?: Pick<Storage, 'getItem'> | null): boolean {
  const target = storage === undefined ? (typeof window !== 'undefined' ? window.localStorage : null) : storage
  if (!target) return false
  try {
    return target.getItem(TELEMETRY_OPEN_STORAGE_KEY) === 'true'
  } catch {
    return false
  }
}

export function writeTelemetryOpenPreference(open: boolean, storage?: Pick<Storage, 'setItem'> | null): void {
  const target = storage === undefined ? (typeof window !== 'undefined' ? window.localStorage : null) : storage
  if (!target) return
  try {
    target.setItem(TELEMETRY_OPEN_STORAGE_KEY, open ? 'true' : 'false')
  } catch {
    /* ignore storage failures */
  }
}

const railItemBase =
  'group/ri relative flex h-[30px] w-full cursor-pointer select-none items-center gap-2.5 rounded-[7px] border-0 bg-transparent px-2.5 py-1 text-left font-sans text-[13px] font-normal leading-[18px] text-fg-muted shadow-none transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg'

const railItemOn =
  'bg-accent-soft font-medium text-fg hover:bg-accent-soft hover:text-fg before:absolute before:bottom-[6px] before:left-0 before:top-[6px] before:w-[2.5px] before:rounded-r-[2px] before:bg-accent before:content-[""]'

const sectionHeadingClass =
  'flex items-center justify-between px-2.5 pb-1 pt-2.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle'

export function Rail() {
  const { detail, model, counts, runs } = useRun()
  const nav = useNav()
  const q = useDecisions()
  const pal = usePalette()
  const { theme, toggle } = useTheme()
  const [devicesOpen, setDevicesOpen] = useState(false)
  const [telemetryOpen, setTelemetryOpen] = useState(false)
  const pulse = usePulse(detail.run.id + ':' + q.openCount)
  const prevViewRef = useRef<ViewId>(nav.view)

  const investigationViews = useMemo(() => VIEWS.filter(v => v.group === 'investigation'), [])
  const telemetryViews = useMemo(() => VIEWS.filter(v => v.group === 'telemetry'), [])
  const isTelemetryView = useMemo(() => telemetryViews.some(v => v.id === nav.view), [telemetryViews, nav.view])

  useEffect(() => {
    setTelemetryOpen(readTelemetryOpenPreference())
  }, [])

  useEffect(() => {
    const prev = prevViewRef.current
    prevViewRef.current = nav.view
    if (prev !== nav.view && isTelemetryView) {
      setTelemetryOpen(true)
    }
  }, [nav.view, isTelemetryView])

  const toggleTelemetry = () => {
    setTelemetryOpen(prev => {
      const next = !prev
      writeTelemetryOpenPreference(next)
      return next
    })
  }

  const cnt: Partial<Record<ViewId, string>> = {
    findings: model.findings.length > 0 ? fmtN(model.findings.length) : '',
    workflow: detail.assignments.length > 0 ? fmtN(detail.assignments.length) : '',
    surface: model.surface.origins.length > 0 ? fmtN(model.surface.origins.length) : '',
    exchanges: counts.exchanges > 0 ? fmtN(counts.exchanges) : '',
    activity: counts.events > 0 ? fmtN(counts.events) : '',
    report: model.report ? 'v' + model.report.version : '',
  }

  const renderViewBtn = (v: (typeof VIEWS)[number]) => {
    const active = v.id === nav.view
    return <button
      key={v.id}
      type="button"
      className={cn(railItemBase, active && railItemOn)}
      aria-current={active ? 'page' : undefined}
      title={`${v.label} (G then ${v.key.toUpperCase()})`}
      onClick={() => nav.setView(v.id)}
    >
      <Icon name={v.icon} className={cn('transition-colors duration-[var(--d1)]', active ? 'text-accent' : 'text-fg-subtle group-hover/ri:text-fg-muted')} />
      <span className="min-w-0 flex-1 truncate">{v.label}</span>
      {v.id === 'queue'
        ? (q.openCount > 0 && (
          <span
            className={cn(
              'num inline-block h-[17px] min-w-[18px] rounded-[9px] px-[5px] text-center text-[11px] font-semibold leading-[17px] transition-transform duration-300',
              q.decideCount
                ? 'bg-warn-soft text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]'
                : 'bg-press text-fg-muted',
              pulse && 'scale-115',
            )}
            title={`${q.decideCount} to decide · ${q.openCount} open`}
          >
            {q.openCount}
          </span>
        ))
        : (cnt[v.id] ? <span className="num text-[12px] text-fg-subtle">{cnt[v.id]}</span> : null)}
    </button>
  }

  const {
    currentProjectRuns,
    currentProjectTotal,
    otherProjects,
    otherProjectsRunCount,
  } = useMemo(() => partitionRailRuns(runs, detail.run.projectId), [runs, detail.run.projectId])

  const renderRunRow = (r: (typeof runs)[number]) => {
    const active = r.id === detail.run.id
    return <Link
      key={r.id}
      to="/runs/$runId"
      params={{ runId: r.id }}
      search={{}}
      className={cn(
        railItemBase,
        'h-auto min-h-0 items-start gap-[9px] py-1.5 font-normal',
        active && cn(railItemOn, 'before:bottom-[7px] before:top-[7px]'),
      )}
      title={`${r.goal}\n${fmtFullDateTime(r.createdAt)} · Run ${short(r.id)}`}
      aria-current={active ? 'page' : undefined}
    >
      <span className="inline-flex size-3.5 flex-none items-center justify-center pt-[3px]"><StatusGlyph status={r.status} /></span>
      <span className="flex min-w-0 flex-1 flex-col gap-px">
        <span className="truncate text-inherit">{runLabel(r.goal)}</span>
        <span className="flex gap-1.5 overflow-hidden whitespace-nowrap text-[11.5px] leading-4 text-fg-subtle">
          <span className="num" suppressHydrationWarning>{fmtAgo(r.createdAt)}</span>
          <span>{runStatusLabel(r.status)}</span>
          {r.findings > 0 && <span className="num ml-auto">{r.findings}</span>}
        </span>
      </span>
    </Link>
  }

  const isDark = theme === 'dark'
  return <>
    <aside className="flex min-h-0 flex-col border-r border-line bg-rail" aria-label="Run navigation">
      <div className="flex h-12 flex-none items-center gap-[9px] pl-4 pr-3.5 text-[13px] font-normal tracking-[-0.003em] text-fg">
        <KovoHunterMark />
        <Link to="/" className="whitespace-nowrap font-semibold tracking-[-0.01em] text-fg" title="All projects">Kovo Hunter</Link>
        <span className="ml-auto text-[12px] text-fg-subtle">Local</span>
      </div>
      <button
        type="button"
        className="mx-2.5 mb-2 mt-0.5 flex h-[30px] flex-none cursor-pointer items-center gap-2 rounded-[7px] border-0 bg-panel pl-[9px] pr-2 font-sans text-[13px] font-normal text-fg-subtle shadow-hairline transition-colors duration-[var(--d1)] hover:bg-panel hover:text-fg-muted"
        onClick={() => pal.open()}
      >
        <Icon name="search" />
        <span className="whitespace-nowrap">Search…</span>
        <KbdGroup keys={['mod', 'K']} className="ml-auto" />
      </button>
      <div className="min-h-0 flex-1 overflow-auto px-2.5 pb-2 pt-0.5">
        <div className={cn(sectionHeadingClass, 'pt-1.5')}>
          <span>Investigation</span>
        </div>
        <nav className="flex flex-col gap-px" aria-label="Investigation views">
          {investigationViews.map(renderViewBtn)}
        </nav>

        <div className={sectionHeadingClass}>
          <span>Runs</span>
          <span className="num font-normal">{currentProjectTotal || ''}</span>
        </div>
        <div className="flex flex-col gap-px">
          {currentProjectRuns.map(renderRunRow)}
          <Link
            to="/projects/$projectId"
            params={{ projectId: detail.run.projectId }}
            search={{ tab: 'runs' }}
            className="mt-0.5 flex h-[28px] w-full items-center justify-between rounded-[7px] px-2.5 py-1 text-[12px] font-medium text-fg-subtle transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg"
            title="View all runs for this project"
          >
            <span className="truncate">All runs ({currentProjectTotal}) →</span>
          </Link>
        </div>

        {otherProjects.length > 0 && (
          <Disclosure defaultOpen={false} className="mt-1">
            <DisclosureTrigger className="h-[28px] px-2.5 py-1 text-[11.5px] font-medium text-fg-subtle hover:text-fg">
              <span className="truncate">Other projects</span>
              <span className="num ml-1 text-[11px] font-normal text-fg-faint">{otherProjectsRunCount}</span>
            </DisclosureTrigger>
            <DisclosureContent className="pt-0.5">
              {otherProjects.map(group => (
                <div key={group.projectId} className="mt-1 first:mt-0">
                  <Link
                    to="/projects/$projectId"
                    params={{ projectId: group.projectId }}
                    search={{ tab: 'runs' }}
                    className="block truncate px-2.5 pb-0.5 pt-1 text-[11.5px] font-medium text-fg-subtle hover:text-fg-muted"
                    title={group.projectName}
                  >
                    {group.projectName}
                  </Link>
                  <div className="flex flex-col gap-px">
                    {group.runs.map(renderRunRow)}
                  </div>
                </div>
              ))}
            </DisclosureContent>
          </Disclosure>
        )}

        <button
          type="button"
          className={cn(
            sectionHeadingClass,
            'w-full cursor-pointer rounded-[6px] border-0 bg-transparent shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg',
          )}
          aria-expanded={telemetryOpen}
          aria-controls="rail-telemetry-nav"
          onClick={toggleTelemetry}
        >
          <span className="flex items-center gap-1.5">
            <span>Telemetry</span>
            {!telemetryOpen && isTelemetryView && (
              <span className="inline-block size-1.5 rounded-full bg-accent" aria-hidden="true" />
            )}
          </span>
          <Icon
            name="chevR"
            className={cn(
              'text-fg-subtle transition-transform duration-150',
              telemetryOpen && 'rotate-90',
            )}
          />
        </button>
        {telemetryOpen && (
          <nav id="rail-telemetry-nav" className="flex flex-col gap-px" aria-label="Telemetry views">
            {telemetryViews.map(renderViewBtn)}
          </nav>
        )}
      </div>

      <div className="flex-none border-t border-line px-2.5 py-1.5">
        <div className="flex items-center justify-between px-2.5 pb-1 pt-0.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
          <span>Workspace</span>
        </div>
        <nav className="flex flex-col gap-px" aria-label="Workspace">
          <Link to="/" className={railItemBase} title="All projects">
            <Icon name="grid" className="text-fg-subtle transition-colors duration-[var(--d1)] group-hover/ri:text-fg-muted" />
            <span className="min-w-0 flex-1 truncate">Projects</span>
          </Link>
          <Link to="/settings" search={{ runId: detail.run.id }} className={railItemBase} title="Model and integration settings">
            <Icon name="sliders" className="text-fg-subtle transition-colors duration-[var(--d1)] group-hover/ri:text-fg-muted" />
            <span className="min-w-0 flex-1 truncate">Settings</span>
          </Link>
        </nav>
      </div>

      <div className="flex-none border-t border-line px-2 py-1.5">
        <button
          type="button"
          className={cn(
            'group/sess flex h-8 min-h-8 w-full cursor-pointer appearance-none items-center gap-2 whitespace-nowrap rounded-control border-0 bg-transparent px-2 text-left font-sans text-[12.5px] font-medium leading-none text-fg-muted shadow-none transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg active:bg-press active:text-fg',
            devicesOpen && 'bg-press text-fg',
          )}
          onClick={() => setDevicesOpen(true)}
          aria-haspopup="dialog"
          aria-expanded={devicesOpen}
          title="Devices & local session — pair another browser or phone"
        >
          <DevicesIcon />
          <span className="min-w-0 flex-1 truncate">Local session</span>
          <span className="flex-none text-[11px] font-normal text-fg-subtle">Pair device</span>
          <Icon name="chevR" className="flex-none text-fg-subtle transition-colors duration-[var(--d1)] group-hover/sess:text-fg" />
        </button>
      </div>
      <div className="flex flex-none items-center gap-1 border-t border-line px-2.5 py-2">
        <button type="button" className={runIconBtn()} onClick={toggle} title="Toggle theme (⇧T)">
          <Icon name={isDark ? 'sun' : 'moon'} />
          <span className="text-[12px]">{isDark ? 'Light' : 'Dark'}</span>
        </button>
        <span className="flex-1" />
        <button type="button" className={runIconBtn()} onClick={() => pal.openHelp()} title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">
          <Icon name="keyboard" />
        </button>
      </div>
    </aside>
    {devicesOpen && <DevicesSessionModal onClose={() => setDevicesOpen(false)} />}
  </>
}
