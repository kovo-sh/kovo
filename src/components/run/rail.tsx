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

export function Rail() {
  const { detail, model, counts, runs } = useRun()
  const nav = useNav()
  const q = useDecisions()
  const pal = usePalette()
  const { theme, toggle } = useTheme()
  const [devicesOpen, setDevicesOpen] = useState(false)
  const pulse = usePulse(detail.run.id + ':' + q.openCount)
  const cnt: Partial<Record<ViewId, string>> = {
    findings: fmtN(model.findings.length),
    workflow: fmtN(detail.assignments.length),
    surface: fmtN(model.surface.origins.length),
    exchanges: fmtN(counts.exchanges),
    activity: fmtN(counts.events),
    report: model.report ? 'v' + model.report.version : '',
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
    <aside className="rail" aria-label="Run navigation">
      <div className="brand"><KovoHunterMark /><Link to="/" className="brand-name" title="All projects" style={{ whiteSpace: 'nowrap' }}>Kovo Hunter</Link><span className="ws">Local</span></div>
      <button type="button" className="search" onClick={() => pal.open()}>
        <Icon name="search" /><span style={{ whiteSpace: 'nowrap' }}>Search…</span><KbdGroup keys={['mod', 'K']} />
      </button>
      <div className="rail-scroll">
        <div className="rail-h"><span>Run</span></div>
        <nav aria-label="Run views">
          {VIEWS.map(v => <button key={v.id} type="button" className={'ritem' + (v.id === nav.view ? ' on' : '')} aria-current={v.id === nav.view ? 'page' : undefined}
            title={`${v.label} (G then ${v.key.toUpperCase()})`} onClick={() => nav.setView(v.id)}>
            <Icon name={v.icon} />
            <span className="lbl">{v.label}</span>
            {v.id === 'queue'
              ? <span className={'badge num' + (q.decideCount ? ' hot' : '') + (pulse ? ' pulse' : '')} title={`${q.decideCount} to decide · ${q.openCount} open`}>{q.openCount}</span>
              : <span className="ct num">{cnt[v.id] ?? ''}</span>}
          </button>)}
        </nav>
        <div className="rail-h"><span>Workspace</span></div>
        <nav aria-label="Workspace">
          <Link to="/" className="ritem" title="All projects">
            <Icon name="grid" />
            <span className="lbl">Projects</span>
          </Link>
          <Link to="/settings" search={{ runId: detail.run.id }} className="ritem" title="Model and integration settings">
            <Icon name="sliders" />
            <span className="lbl">Settings</span>
          </Link>
        </nav>
        <div className="rail-h"><span>Runs</span><span className="num" style={{ fontWeight: 400 }}>{runs.length || ''}</span></div>
        {projectGroups.map(group => <div key={group.projectId}>
          <Link to="/projects/$projectId" params={{ projectId: group.projectId }} className="proj" style={{ display: 'block' }} title={group.projectName}>{group.projectName}</Link>
          {group.runs.map(r => <Link key={r.id} to="/runs/$runId" params={{ runId: r.id }} search={{}}
            className={'ritem run' + (r.id === detail.run.id ? ' on' : '')}
            title={`${r.goal}\n${fmtFullDateTime(r.createdAt)} · Run ${short(r.id)}`}
            aria-current={r.id === detail.run.id ? 'page' : undefined}>
            <span className="g"><StatusGlyph status={r.status} /></span>
            <span className="lbl">
              <span className="t">{runLabel(r.goal)}</span>
              <span className="s">
                <span className="num" suppressHydrationWarning>{fmtAgo(r.createdAt)}</span>
                <span>{runStatusLabel(r.status)}</span>
                {r.findings > 0 && <span className="num" style={{ marginLeft: 'auto' }}>{r.findings}</span>}
              </span>
            </span>
          </Link>)}
        </div>)}
      </div>
      <div className="sh-rail-session" style={{ color: 'var(--fg-2)' }}>
        <button
          type="button"
          className="sh-session-chip"
          style={{ padding: '0 8px', fontSize: 12.5, fontWeight: 500, lineHeight: 1 }}
          onClick={() => setDevicesOpen(true)}
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
      <div className="rail-foot">
        <button type="button" className="icon-btn" onClick={toggle} title="Toggle theme (⇧T)"><Icon name={isDark ? 'sun' : 'moon'} /><span style={{ fontSize: 12 }}>{isDark ? 'Light' : 'Dark'}</span></button>
        <span className="grow" />
        <button type="button" className="icon-btn" onClick={() => pal.openHelp()} title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts"><Icon name="keyboard" /></button>
      </div>
    </aside>
    {devicesOpen && <DevicesSessionModal onClose={() => setDevicesOpen(false)} />}
  </>
}
