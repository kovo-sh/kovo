// Left rail: brand, ⌘K search entry, views with counts (Queue badge turns
// amber when something needs a decision and pulses when the count changes),
// workspace links, runs grouped by project, local session chip, theme toggle and shortcuts.
import { Link } from '@tanstack/react-router'
import { useMemo, useState } from 'react'
import { KovoHunterMark } from '../brand/KovoHunterMark.tsx'
import { DevicesIcon, DevicesSessionModal } from '../settings/DevicesSessionModal.tsx'
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

const railItemBase =
  'group/ri relative flex min-h-[34px] h-auto w-full cursor-pointer select-none items-center gap-2.5 rounded-[7px] border-0 bg-transparent px-2.5 py-2 text-left font-sans text-[13px] font-normal leading-[18px] text-fg-muted shadow-none transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg'

const railItemOn =
  'bg-accent-soft font-medium text-fg hover:bg-accent-soft hover:text-fg before:absolute before:bottom-[7px] before:left-0 before:top-[7px] before:w-[2.5px] before:rounded-r-[2px] before:bg-accent before:content-[""]'

export function Rail() {
  const { detail, model, counts, runs } = useRun()
  const nav = useNav()
  const q = useDecisions()
  const pal = usePalette()
  const { theme, toggle } = useTheme()
  const [devicesOpen, setDevicesOpen] = useState(false)
  const pulse = usePulse(detail.run.id + ':' + q.openCount)
  const cnt: Partial<Record<ViewId, string>> = {
    findings: model.findings.length > 0 ? fmtN(model.findings.length) : '',
    workflow: detail.assignments.length > 0 ? fmtN(detail.assignments.length) : '',
    surface: model.surface.origins.length > 0 ? fmtN(model.surface.origins.length) : '',
    exchanges: counts.exchanges > 0 ? fmtN(counts.exchanges) : '',
    activity: counts.events > 0 ? fmtN(counts.events) : '',
    report: model.report ? 'v' + model.report.version : '',
  }
  const investigationViews = VIEWS.filter(v => v.group === 'investigation')
  const telemetryViews = VIEWS.filter(v => v.group === 'telemetry')
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
  const projectGroups = useMemo(() => {
    const groups: { projectId: string; projectName: string; runs: typeof runs }[] = []
    const byProject = new Map<string, (typeof groups)[number]>()
    for (const r of runs) {
      let group = byProject.get(r.projectId)
      if (!group) {
        group = { projectId: r.projectId, projectName: r.projectName, runs: [] }
        byProject.set(r.projectId, group)
        groups.push(group)
      }
      group.runs.push(r)
    }
    return groups
  }, [runs])
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
        className="mx-2.5 mb-2.5 mt-0.5 flex h-[30px] flex-none cursor-pointer items-center gap-2 rounded-[7px] border-0 bg-panel pl-[9px] pr-2 font-sans text-[13px] font-normal text-fg-subtle shadow-hairline transition-colors duration-[var(--d1)] hover:bg-panel hover:text-fg-muted"
        onClick={() => pal.open()}
      >
        <Icon name="search" />
        <span className="whitespace-nowrap">Search…</span>
        <KbdGroup keys={['mod', 'K']} className="ml-auto" />
      </button>
      <div className="min-h-0 flex-1 overflow-auto px-2.5 pb-2.5 pt-0.5">
        <div className="flex items-center justify-between px-2.5 pb-1.5 pt-1.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
          <span>Investigation</span>
        </div>
        <nav className="flex flex-col gap-0.5" aria-label="Investigation views">
          {investigationViews.map(renderViewBtn)}
        </nav>
        <div className="flex items-center justify-between px-2.5 pb-1.5 pt-3.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
          <span>Telemetry</span>
        </div>
        <nav className="flex flex-col gap-0.5" aria-label="Telemetry views">
          {telemetryViews.map(renderViewBtn)}
        </nav>
        <div className="flex items-center justify-between px-2.5 pb-1.5 pt-3.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
          <span>Workspace</span>
        </div>
        <nav className="flex flex-col gap-0.5" aria-label="Workspace">
          <Link to="/" className={railItemBase} title="All projects">
            <Icon name="grid" className="text-fg-subtle transition-colors duration-[var(--d1)] group-hover/ri:text-fg-muted" />
            <span className="min-w-0 flex-1 truncate">Projects</span>
          </Link>
          <Link to="/settings" search={{ runId: detail.run.id }} className={railItemBase} title="Model and integration settings">
            <Icon name="sliders" className="text-fg-subtle transition-colors duration-[var(--d1)] group-hover/ri:text-fg-muted" />
            <span className="min-w-0 flex-1 truncate">Settings</span>
          </Link>
        </nav>
        <div className="flex items-center justify-between px-2.5 pb-1.5 pt-3.5 text-[11.5px] font-medium tracking-[0.01em] text-fg-subtle">
          <span>Runs</span>
          <span className="num font-normal">{runs.length || ''}</span>
        </div>
        {projectGroups.map(group => <div key={group.projectId}>
          <Link
            to="/projects/$projectId"
            params={{ projectId: group.projectId }}
            className="block truncate px-2.5 pb-1 pt-2.5 text-[11.5px] font-medium text-fg-subtle hover:text-fg-muted"
            title={group.projectName}
          >
            {group.projectName}
          </Link>
          {group.runs.map(r => {
            const active = r.id === detail.run.id
            return <Link
              key={r.id}
              to="/runs/$runId"
              params={{ runId: r.id }}
              search={{}}
              className={cn(
                railItemBase,
                'mt-0.5 min-h-0 items-start gap-[9px] py-2 font-normal first-of-type:mt-0',
                active && cn(railItemOn, 'before:bottom-[9px] before:top-[9px]'),
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
          })}
        </div>)}
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
