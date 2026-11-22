// Right-pane building blocks for inspectors.
//
// An inspector is a component registered for a selection kind (see
// views/index.tsx). It renders the whole pane content:
//
//   export function FindingInspector({ sel }: InspectorProps) {
//     return <>
//       <PaneHeader title="Finding" sub="3 of 68" />
//       <PaneBody><div className="d">…</div></PaneBody>
//       <PaneFooter>…sticky action bar…</PaneFooter>   // optional (F's .abar)
//     </>
//   }
//
// PaneHeader adds Back (when the stack has entries) and Close automatically.
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { readArtifact } from '../../actions.ts'
import { useBoardUnread } from './coordinator.tsx'
import { useFullExchange, useRun, useRunModel } from './data.tsx'
import { EmptyState, LinkRow, Props, Section } from './display.tsx'
import { fmtDate, host, short } from './format.ts'
import { StatusGlyph } from './glyphs.tsx'
import { Icon } from './icons.tsx'
import { PHASE_LABEL, stLabel } from './meta.ts'
import { useLinks, useNav } from './nav.tsx'
import type { Sel } from './nav.tsx'

export interface InspectorProps { sel: Sel }
export type InspectorMap = Record<string, (props: InspectorProps) => ReactNode>

export function PaneHeader({ title, sub, extra }: { title: ReactNode; sub?: ReactNode; extra?: ReactNode }) {
  const nav = useNav()
  const unread = useBoardUnread()
  return <div className="pane-h">
    {nav.stack.length > 0 && <button type="button" className="icon-btn" onClick={() => nav.back()} title="Back (Esc)" aria-label="Back"><Icon name="arrowL" /></button>}
    <span className="t">{title}{sub != null && <> <span className="muted">{sub}</span></>}</span>
    {extra}
    <button type="button" className="icon-btn b-btn" onClick={() => nav.openChat(null)} title={'Board (C)' + (unread ? ` · ${unread} new` : '')} aria-label="Board">
      <Icon name="chat" />{unread > 0 && <span className="b-badge num" data-testid="board-unread-badge">{unread}</span>}
    </button>
    <button type="button" className="icon-btn" onClick={() => nav.close()} title="Close (Esc)" aria-label="Close"><Icon name="close" /></button>
  </div>
}

export function PaneBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={'pane-body' + (className ? ' ' + className : '')}>{children}</div>
}

/** Sticky action bar at the bottom of the pane (F's `.abar`). */
export function PaneFooter({ children, stamped }: { children: ReactNode; stamped?: ReactNode }) {
  return <div className={'abar' + (stamped ? ' stamped' : '')}>{children}{stamped && <span className="rstamp">{stamped}</span>}</div>
}

/** Fallback for kinds no view has registered yet. */
export function FallbackInspector({ sel }: InspectorProps) {
  return <>
    <PaneHeader title={sel.kind.charAt(0).toUpperCase() + sel.kind.slice(1)} sub={<span className="mono">{sel.id.slice(0, 12)}</span>} />
    <PaneBody><EmptyState icon="node" title="TODO">The {sel.kind} inspector is built by its view.</EmptyState></PaneBody>
  </>
}

/** Evidence artifact (foundation-owned; any view can open it with `links.evidence(id)`). */
export function EvidenceInspector({ sel }: InspectorProps) {
  const { detail } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const [state, setState] = useState<{ content?: string; error?: string }>({})
  useEffect(() => {
    let live = true
    setState({})
    readArtifact({ data: { runId: detail.run.id, artifactId: sel.id } })
      .then(a => { if (live) setState({ content: a.content }) }, () => { if (live) setState({ error: 'This evidence is unavailable.' }) })
    return () => { live = false }
  }, [detail.run.id, sel.id])
  const ev = model.evidenceById.get(sel.id)
  const worker = ev ? model.workerById.get(ev.assignmentId) : undefined
  const cited = model.evidenceFindings.get(sel.id) ?? []
  return <>
    <PaneHeader title="Evidence" sub={ev?.kind} />
    <PaneBody><div className="d">
      <h2>{ev?.title ?? 'Evidence'}</h2>
      {ev && <Props rows={[['Recorded', fmtDate(ev.createdAt)], ['Scope revision', String(ev.scopeRevision)]]} />}
      {worker && <Section title="Recorded by">
        <LinkRow glyph={<StatusGlyph status={worker.status} />} right={PHASE_LABEL[worker.phase] ?? worker.phase} trailing="workflow" onClick={() => links.worker(worker.id)}>{worker.title}</LinkRow>
      </Section>}
      {cited.length > 0 && <Section title="Cited by" right={cited.length}>
        {cited.map(f => <LinkRow key={f.id} glyph={<StatusGlyph status={f.status} />} right={stLabel(f.status)} trailing="findings" onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)}
      </Section>}
      <Section title="Content">
        {state.error ? <p>{state.error}</p> : state.content == null ? <p>Loading…</p> : <pre className="block mono">{state.content}</pre>}
      </Section>
    </div></PaneBody>
  </>
}

/**
 * One exchange as a cross-link row: method · status · (host) path, opening it in
 * Exchanges. Exchanges outside the loaded newest-500 window are read by id.
 */
export function ExchangeLink({ id, showHost = true }: { id: string; showHost?: boolean }) {
  const model = useRunModel()
  const links = useLinks()
  const summary = model.exchangeById.get(id)
  const full = useFullExchange(id, !summary)
  const x = summary ?? full
  const open = () => links.exchange(id)
  return <div className="linkrow" role="button" tabIndex={0} onClick={open}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open() } }}>
    <span className="mono xl-m">{x ? x.method : '—'}</span>
    <span className={'mono xl-c code-' + String(x?.status ?? 0)[0]}>{x?.status ?? ''}</span>
    <span className="p mono">{x ? (showHost ? host(x.origin) : '') + x.pathAndQuery
      : <span className="muted">{full === null ? 'Exchange ' + short(id) : 'Loading…'}</span>}</span>
    <Icon name="ext" />
  </div>
}
