// Activity: the run's full event stream, newest first (virtualised; real
// runs have thousands of events). Kind tabs + text filter; new events
// animate in at the top while the reader's scroll position is kept.
import { useMemo, useRef } from 'react'
import type { ReactNode } from 'react'
import { FilterBox, matchQ, Tabs, VList } from '../controls.tsx'
import { useRun, useRunModel } from '../data.tsx'
import { EmptyState, FindingTitle, LinkRow, Props, Section, Skeleton, Tag } from '../display.tsx'
import { fmtAgo, fmtEventKind, fmtFullDateTime, fmtN, fmtRel, fmtTimeS, host } from '../format.ts'
import { EventGlyph, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import type { RunEvent } from '../model.ts'
import { useReducedMotion } from '../motion.tsx'
import { useLinks, useListNav, useNav, useViewState } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { cn, runBtn, RW } from '../tw.ts'

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

const ERROR_ACTIVITY_KINDS = new Set([
  'broker.denied',
  'broker.circuit_open',
  'broker.persona_scope_mismatch',
  'worker.failed',
  'worker.stall_failed',
  'persona.auth_failed',
  'persona.refresh_failed',
  'threat_model.failed',
  'deterministic_lane.failed',
])

/** True for auth, scope, broker-denial, and failure events that should be highlighted in Activity. */
export function isErrorActivityEvent(kind: string): boolean {
  return ERROR_ACTIVITY_KINDS.has(kind)
}

export function ActivityView() {
  const { events, eventsReady, counts: runCounts, detail, refresh, hasOlderEvents, loadingOlderEvents, loadOlderEvents } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const rm = useReducedMotion()
  const [tab, setTab] = useViewState<Fam>('activity.tab', 'all')
  const [q, setQ] = useViewState('activity.q', '')
  // Events newer than this arrived while the view was open: they animate in.
  const seenRunRef = useRef<string>(detail.run.id)
  const seenMax = useRef<number | null>(null)
  if (seenRunRef.current !== detail.run.id) {
    seenRunRef.current = detail.run.id
    seenMax.current = null
  }
  if (seenMax.current == null && eventsReady) seenMax.current = events.length ? events[events.length - 1].id : 0
  const fresh = seenMax.current ?? Infinity

  const counts = useMemo(() => {
    const t: Record<string, number> = { all: events.length }
    for (const e of events) { const f = actFam(e.kind); t[f] = (t[f] ?? 0) + 1 }
    return t
  }, [events])
  // When older history is not loaded, "All" is the client window, not the run total: show "n of total".
  const tabs = useMemo(() => FAMS.filter(([k]) => counts[k] || k === tab)
    .map(([k, l]) => (k === 'all' && hasOlderEvents
      ? [k, l, counts[k] ?? 0, runCounts.events]
      : [k, l, counts[k] ?? 0]) as [Fam, string, number, number?]), [counts, tab, hasOlderEvents, runCounts.events])
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

  if (eventsReady && !events.length && runCounts.events === 0) {
    return <EmptyState icon="activity" title="Quiet so far"
      action={detail.run.status === 'waiting' ? <button type="button" className={runBtn()} onClick={() => nav.setView('overview')}>Review scope</button> : undefined}>
      Run events stream here newest first: planner rounds, HTTP requests, worker lifecycle, and verification.
    </EmptyState>
  }
  if (eventsReady && !events.length && runCounts.events > 0) {
    return <EmptyState icon="activity" title={`${fmtN(runCounts.events)} events recorded`}
      action={<button type="button" className={runBtn()} onClick={() => void refresh()}>Reload</button>}>
      Historical run events did not finish streaming. Reload to retry fetching the event log.
    </EmptyState>
  }
  return <>
    <div className={RW.toolbar}>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {detail.run.status === 'running' && (
        <span className="mr-1 inline-flex items-center gap-1.5 text-[12px] text-fg-subtle" title="New events stream in live">
          <span className="relative inline-block size-1.5 flex-none" aria-hidden="true">
            <span className="absolute inset-0 rounded-full bg-ok" />
            <span className="absolute -inset-[3px] animate-ping rounded-full border border-ok opacity-50 motion-reduce:animate-none" />
          </span>
          Live
        </span>
      )}
      <FilterBox value={q} onChange={setQ} onEnter={() => ids[0] && nav.select({ kind: 'event', id: ids[0] })} />
    </div>
    {!eventsReady && !events.length ? <Skeleton /> :
      <VList items={items} itemKey={e => String(e.id)} height={height} anchor scrollToIndex={index}
        footer={hasOlderEvents && items.length ? <OlderEventsFooter loaded={events.length} total={runCounts.events} loading={loadingOlderEvents} onLoad={() => { void loadOlderEvents() }} /> : undefined}
        empty={<EmptyState icon="search" title="Nothing matches" style={{ paddingTop: 80 }}>Try a different filter or switch tabs.</EmptyState>}
        render={(e, _i, style) => {
          const id = String(e.id)
          const label = fmtEventKind(e.kind)
          const isBad = isErrorActivityEvent(e.kind)
          return <div
            key={id}
            style={style}
            data-id={id}
            className={cn(
              RW.row,
              selId === id && RW.rowCur,
              isBad && selId !== id && 'bg-danger-soft/40',
              e.id > fresh && (rm
                ? '[transition:background-color_700ms_ease] starting:bg-accent-soft'
                : '[transition:opacity_150ms_cubic-bezier(.2,.8,.2,1),background-color_700ms_ease] starting:bg-accent-soft starting:opacity-0'),
            )}
            onClick={() => nav.select({ kind: 'event', id })}
          >
            <span className="w-[72px] flex-none whitespace-nowrap font-mono text-[12px] tabular-nums text-fg-subtle" title={fmtFullDateTime(e.createdAt)}>{fmtRel(e.createdAt, model.base)}</span>
            <span className="inline-flex size-3.5 flex-none items-center justify-center"><EventGlyph kind={e.kind} /></span>
            <span className={cn('w-[156px] flex-none truncate', isBad ? 'font-medium text-danger' : 'text-fg-subtle')} title={`${e.kind} · Event #${e.id}`}>{label}</span>
            <span className={cn('min-w-0 flex-1 truncate', isBad ? 'text-danger' : 'text-fg')}>{e.message}</span>
          </div>
        }} />}
  </>
}

// ---------------------------------------------------------------- inspector

/** List footer when the client holds only the newest window of a longer event log. */
function OlderEventsFooter({ loaded, total, loading, onLoad }: { loaded: number; total: number; loading: boolean; onLoad: () => void }) {
  return <div className={RW.listnote} data-activity-older="">
    <span className="tabular-nums">Showing the latest {fmtN(loaded)} of {fmtN(total)} events.</span>
    <button type="button" className={runBtn({ variant: 'ghost', size: 'sm' })} disabled={loading} aria-busy={loading} onClick={onLoad}>
      {loading ? 'Loading older…' : 'Load older'}
    </button>
  </div>
}

const str = (v: unknown) => (typeof v === 'string' && v ? v : null)

function EventInspector({ sel }: InspectorProps) {
  const { events, eventsReady } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const e = useMemo(() => events.find(x => String(x.id) === sel.id), [events, sel.id])
  if (!e) return <>
    <PaneHeader title="Activity event" sub={<span title={`Event #${sel.id}`}>Not found</span>} />
    <PaneBody>{eventsReady ? <EmptyState icon="activity" title="Event not found">It may belong to another run.</EmptyState> : <div className={RW.detail}><Skeleton rows={5} /></div>}</PaneBody>
  </>
  const d = e.detail ?? {}
  const rel: ReactNode[] = []
  const exId = str(d.exchangeId)
  if (exId) {
    const ex = model.exchangeById.get(exId)
    rel.push(<LinkRow key="ex" icon="exchanges" title={`Exchange ${exId}`} onClick={() => links.exchange(exId)}>
      {ex ? <><span className="font-mono text-[12px]">{ex.method} {ex.pathAndQuery}</span> <span className="tabular-nums text-fg-subtle">· {ex.status}</span></> : 'Open HTTP exchange'}
    </LinkRow>)
  }
  if (e.kind === 'broker.denied' || e.kind === 'broker.circuit_open') rel.push(<LinkRow key="den" icon="exchanges" onClick={() => links.exchange('ev:' + e.id)}>Show in Exchanges</LinkRow>)
  const wid = str(d.assignmentId) ?? str(d.workerId)
  const w = wid ? model.workerById.get(wid) : undefined
  if (w) rel.push(<LinkRow key="w" glyph={<StatusGlyph status={w.status} />} trailing="workflow" onClick={() => links.worker(w.id)}>{w.title}</LinkRow>)
  const fid = str(d.findingId)
  const f = fid ? model.findingById.get(fid) : undefined
  if (f) rel.push(<LinkRow key="f" glyph={<SevGlyph sev={f.severity} />} trailing="findings" onClick={() => links.finding(f.id)}><FindingTitle title={f.title} /></LinkRow>)
  const apId = str(d.approvalId) ?? str(d.requestId)
  const ap = apId ? model.approvalById.get(apId) : undefined
  if (ap) {
    rel.push(<LinkRow key="ap" icon="queue" title={`Approval ${ap.id}`} onClick={() => links.queueItem('ap:' + ap.id)}>
      Approval: <span className="font-mono text-[12px]">{ap.method} {ap.pathAndQuery}</span>
    </LinkRow>)
  }
  for (const k of ['evidenceId', 'artifactId', 'analysisEvidenceId']) {
    const v = str(d[k])
    if (v && model.evidenceById.has(v)) rel.push(<LinkRow key={k} icon="fact" trailing="chevR" onClick={() => links.evidence(v)}>{model.evidenceById.get(v)!.title}</LinkRow>)
  }
  const origin = str(d.origin)
  if (origin) rel.push(<LinkRow key="o" icon="surface" onClick={() => links.host(origin)}><span className="font-mono text-[12px]">{host(origin)}</span> on the surface map</LinkRow>)
  if (str(d.reportId) || e.kind.startsWith('report.')) rel.push(<LinkRow key="r" icon="report" onClick={() => links.report()}>Open the report</LinkRow>)
  const label = fmtEventKind(e.kind)
  return <>
    <PaneHeader title={label} sub={<span title={`${fmtFullDateTime(e.createdAt)} · Event #${e.id} (${e.kind})`} suppressHydrationWarning>{fmtAgo(e.createdAt)}</span>} />
    <PaneBody><div className={RW.detail}>
      <div className="mb-2.5 flex flex-wrap gap-1.5"><Tag title={e.kind}><EventGlyph kind={e.kind} />{label}</Tag></div>
      <h2 className="m-0 mb-3 break-words text-[14px] font-medium leading-[21px] text-fg">{e.message}</h2>
      <Props rows={[
        ['Time', <span className="tabular-nums" title={fmtFullDateTime(e.createdAt)}>{fmtTimeS(e.createdAt)} <span className="font-mono text-[12px] text-fg-subtle">{fmtRel(e.createdAt, model.base)}</span></span>],
        ['Event key', <span className="font-mono text-[12px] text-fg-subtle" title={`Event #${e.id}`}>{e.kind} · #{e.id}</span>],
      ]} />
      {rel.length > 0 && <Section title="Related">{rel}</Section>}
      <Section title="Detail"><pre className={RW.pre}>{JSON.stringify(d, null, 2)}</pre></Section>
    </div></PaneBody>
  </>
}

/** Inspectors this view owns, keyed by selection kind ('event'). */
export const activityInspectors: InspectorMap = {
  event: EventInspector,
}
