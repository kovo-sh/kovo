// Activity: the run's full event stream, newest first (virtualised; real
// runs have thousands of events). Kind tabs + text filter; new events
// animate in at the top while the reader's scroll position is kept.
import { useMemo, useRef } from 'react'
import type { ReactNode } from 'react'
import { FilterBox, matchQ, Tabs, VList } from '../controls.tsx'
import { useRun, useRunModel } from '../data.tsx'
import { EmptyState, LinkRow, Props, Section, Skeleton, Tag } from '../display.tsx'
import { fmtAgo, fmtEventKind, fmtFullDateTime, fmtRel, fmtTimeS, host } from '../format.ts'
import { EventGlyph, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import type { RunEvent } from '../model.ts'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { useReducedMotion } from '../motion.tsx'

type Fam = 'all' | 'broker' | 'worker' | 'finding' | 'planner' | 'other'
export function actFam(k: string): Exclude<Fam, 'all'> {
  const f = k.split('.')[0]
  if (f === 'broker') return 'broker'
  if (f === 'worker') return 'worker'
  if (f === 'finding' || f === 'verification' || f === 'retest') return 'finding'
  if (f === 'planner' || f === 'chain_step' || f === 'graph') return 'planner'
  return 'other'
}
const FAMS: [Fam, string][] = [['all', 'All'], ['broker', 'Requests'], ['worker', 'Workers'], ['finding', 'Findings'], ['planner', 'Planner'], ['other', 'Other']]

export function ActivityView() {
  const { events, eventsReady, detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const rm = useReducedMotion()
  const [tab, setTab] = useViewState<Fam>('activity.tab', 'all')
  const [q, setQ] = useViewState('activity.q', '')
  // Events newer than this arrived while the view was open: they animate in.
  const seenMax = useRef<number | null>(null)
  if (seenMax.current == null && eventsReady) seenMax.current = events.length ? events[events.length - 1].id : 0
  const fresh = seenMax.current ?? Infinity

  const counts = useMemo(() => {
    const t: Record<string, number> = { all: events.length }
    for (const e of events) { const f = actFam(e.kind); t[f] = (t[f] ?? 0) + 1 }
    return t
  }, [events])
  const tabs = useMemo(() => FAMS.filter(([k]) => counts[k] || k === tab).map(([k, l]) => [k, l, counts[k] ?? 0] as [Fam, string, number]), [counts, tab])
  const items = useMemo(() => {
    const out: RunEvent[] = []
    for (let i = events.length - 1; i >= 0; i--) {
      const e = events[i]
      if ((tab === 'all' || actFam(e.kind) === tab) && matchQ(q, e.kind + ' ' + fmtEventKind(e.kind) + ' ' + e.message)) out.push(e)
    }
    return out
  }, [events, tab, q])
  const ids = useMemo(() => items.map(e => String(e.id)), [items])
  const { index } = useListNav({ ids, kind: 'event' })
  const selId = nav.sel?.kind === 'event' ? nav.sel.id : null
  const height = useMemo(() => () => 36, [])

  if (eventsReady && !events.length) {
    return <EmptyState icon="activity" title="Quiet so far"
      action={detail.run.status === 'waiting' ? <button type="button" className="btn" onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
      Run events stream here newest first: planner rounds, HTTP requests, worker lifecycle, and verification.
    </EmptyState>
  }
  return <>
    <div className="toolbar">
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <span className="tb-sp" />
      {detail.run.status === 'running' && <span className="sf-live" title="New events stream in live"><i />Live</span>}
      <FilterBox value={q} onChange={setQ} onEnter={() => ids[0] && nav.select({ kind: 'event', id: ids[0] })} />
    </div>
    {!eventsReady && !events.length ? <Skeleton /> :
      <VList items={items} itemKey={e => String(e.id)} height={height} anchor scrollToIndex={index}
        empty={<EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState>}
        render={(e, _i, style) => {
          const id = String(e.id)
          const label = fmtEventKind(e.kind)
          return <div key={id} style={style} data-id={id} className={'row' + (selId === id ? ' cur' : '') + (!rm && e.id > fresh ? ' sf-fresh' : '')}
            onClick={() => nav.select({ kind: 'event', id })}>
            <span className="c-time mono num" title={fmtFullDateTime(e.createdAt)}>{fmtRel(e.createdAt, model.base)}</span>
            <span className="g"><EventGlyph kind={e.kind} /></span>
            <span className="c-kind" title={`${e.kind} · Event #${e.id}`}>{label}</span>
            <span className={'title' + (e.kind === 'broker.denied' || e.kind === 'worker.failed' ? ' sf-bad' : '')}>{e.message}</span>
          </div>
        }} />}
  </>
}

// ---------------------------------------------------------------- inspector

const str = (v: unknown) => (typeof v === 'string' && v ? v : null)

function EventInspector({ sel }: InspectorProps) {
  const { events, eventsReady } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const e = useMemo(() => events.find(x => String(x.id) === sel.id), [events, sel.id])
  if (!e) return <>
    <PaneHeader title="Activity event" sub={<span title={`Event #${sel.id}`}>Not found</span>} />
    <PaneBody>{eventsReady ? <EmptyState icon="activity" title="Event not found">It may belong to another run.</EmptyState> : <div className="d"><Skeleton rows={5} /></div>}</PaneBody>
  </>
  const d = e.detail ?? {}
  const rel: ReactNode[] = []
  const exId = str(d.exchangeId)
  if (exId) {
    const ex = model.exchangeById.get(exId)
    rel.push(<LinkRow key="ex" icon="exchanges" title={`Exchange ${exId}`} onClick={() => links.exchange(exId)}>
      {ex ? <><span className="mono">{ex.method} {ex.pathAndQuery}</span> <span className="muted num">· {ex.status}</span></> : 'Open HTTP exchange'}
    </LinkRow>)
  }
  if (e.kind === 'broker.denied' || e.kind === 'broker.circuit_open') rel.push(<LinkRow key="den" icon="exchanges" onClick={() => links.exchange('ev:' + e.id)}>Show in Exchanges</LinkRow>)
  const wid = str(d.assignmentId) ?? str(d.workerId)
  const w = wid ? model.workerById.get(wid) : undefined
  if (w) rel.push(<LinkRow key="w" glyph={<StatusGlyph status={w.status} />} trailing="workflow" onClick={() => links.worker(w.id)}>{w.title}</LinkRow>)
  const fid = str(d.findingId)
  const f = fid ? model.findingById.get(fid) : undefined
  if (f) rel.push(<LinkRow key="f" glyph={<SevGlyph sev={f.severity} />} trailing="findings" onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)
  const apId = str(d.approvalId) ?? str(d.requestId)
  const ap = apId ? model.approvalById.get(apId) : undefined
  if (ap) {
    rel.push(<LinkRow key="ap" icon="queue" title={`Approval ${ap.id}`} onClick={() => links.queueItem('ap:' + ap.id)}>
      Approval: <span className="mono">{ap.method} {ap.pathAndQuery}</span>
    </LinkRow>)
  }
  for (const k of ['evidenceId', 'artifactId', 'analysisEvidenceId']) {
    const v = str(d[k])
    if (v && model.evidenceById.has(v)) rel.push(<LinkRow key={k} icon="fact" trailing="chevR" onClick={() => links.evidence(v)}>{model.evidenceById.get(v)!.title}</LinkRow>)
  }
  const origin = str(d.origin)
  if (origin) rel.push(<LinkRow key="o" icon="surface" onClick={() => links.host(origin)}><span className="mono">{host(origin)}</span> on the surface map</LinkRow>)
  if (str(d.reportId) || e.kind.startsWith('report.')) rel.push(<LinkRow key="r" icon="report" onClick={() => links.report()}>Open the report</LinkRow>)
  const label = fmtEventKind(e.kind)
  return <>
    <PaneHeader title={label} sub={<span title={`${fmtFullDateTime(e.createdAt)} · Event #${e.id} (${e.kind})`} suppressHydrationWarning>{fmtAgo(e.createdAt)}</span>} />
    <PaneBody><div className="d">
      <div className="d-meta"><Tag title={e.kind}><EventGlyph kind={e.kind} />{label}</Tag></div>
      <h2 style={{ fontSize: 14, lineHeight: '21px', fontWeight: 500 }}>{e.message}</h2>
      <Props rows={[
        ['Time', <span className="num" title={fmtFullDateTime(e.createdAt)}>{fmtTimeS(e.createdAt)} <span className="mono muted">{fmtRel(e.createdAt, model.base)}</span></span>],
        ['Event key', <span className="mono muted" title={`Event #${e.id}`}>{e.kind} · #{e.id}</span>],
      ]} />
      {rel.length > 0 && <Section title="Related">{rel}</Section>}
      <Section title="Detail"><pre className="block mono">{JSON.stringify(d, null, 2)}</pre></Section>
    </div></PaneBody>
  </>
}

/** Inspectors this view owns, keyed by selection kind ('event'). */
export const activityInspectors: InspectorMap = {
  event: EventInspector,
}
