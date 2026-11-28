// Right-pane building blocks for inspectors.
//
// An inspector is a component registered for a selection kind (see
// views/index.tsx). It renders the whole pane content:
//
//   export function FindingInspector({ sel }: InspectorProps) {
//     return <>
//       <PaneHeader title="Finding" sub="3 of 68" />
//       <PaneBody><div className={RW.detail}>…</div></PaneBody>
//       <PaneFooter>…sticky action bar…</PaneFooter>
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
import { cn, httpCodeClass, runIconBtn, RW } from './tw.ts'

export interface InspectorProps { sel: Sel }
export type InspectorMap = Record<string, (props: InspectorProps) => ReactNode>

export function PaneHeader({ title, sub, extra }: { title: ReactNode; sub?: ReactNode; extra?: ReactNode }) {
  const nav = useNav()
  const unread = useBoardUnread()
  return <div className="flex h-11 flex-none items-center gap-1.5 border-b border-line pl-4 pr-2.5">
    {nav.stack.length > 0 && <button type="button" className={runIconBtn()} onClick={() => nav.back()} title="Back (Esc)" aria-label="Back"><Icon name="arrowL" /></button>}
    <span className="min-w-0 flex-1 truncate font-medium text-fg">
      {title}{sub != null && <> <span className="font-normal text-fg-subtle">{sub}</span></>}
    </span>
    {extra}
    <button
      type="button"
      className={cn(runIconBtn(), 'relative')}
      onClick={() => nav.openChat(null)}
      title={'Board (C)' + (unread ? ` · ${unread} new` : '')}
      aria-label="Board"
    >
      <Icon name="chat" />
      {unread > 0 && (
        <span
          className="num absolute right-0 top-px inline-grid h-[15px] min-w-[15px] place-items-center rounded-[8px] bg-accent px-1 text-[9.5px] font-semibold leading-none text-white"
          data-testid="board-unread-badge"
        >
          {unread}
        </span>
      )}
    </button>
    <button type="button" className={runIconBtn()} onClick={() => nav.close()} title="Close (Esc)" aria-label="Close"><Icon name="close" /></button>
  </div>
}

export function PaneBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('min-h-0 flex-1 overflow-auto', className)}>{children}</div>
}

/** Sticky action bar at the bottom of the pane. */
export function PaneFooter({ children, stamped }: { children: ReactNode; stamped?: ReactNode }) {
  return <div className="relative flex min-h-12 flex-none items-center gap-1.5 border-t border-line bg-panel px-3 py-2.5">
    <div className={cn('flex min-w-0 flex-1 items-center gap-1.5 transition-opacity duration-[var(--d1)]', stamped && 'pointer-events-none opacity-0')}>
      {children}
    </div>
    {stamped && (
      <span className="pointer-events-none absolute inset-x-3 inset-y-2.5 flex items-center gap-2 rounded-control px-3 text-[12.5px] font-semibold">
        {stamped}
      </span>
    )}
  </div>
}

/** Fallback for kinds no view has registered yet. */
export function FallbackInspector({ sel }: InspectorProps) {
  return <>
    <PaneHeader title={sel.kind.charAt(0).toUpperCase() + sel.kind.slice(1)} sub={<span className="font-mono text-[12px]">{sel.id.slice(0, 12)}</span>} />
    <PaneBody><EmptyState icon="node" title="Details unavailable">Detailed inspection for this {sel.kind} item isn’t available yet.</EmptyState></PaneBody>
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
    <PaneBody><div className={RW.detail}>
      <h2 className="m-0 mb-3 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{ev?.title ?? 'Evidence'}</h2>
      {ev && <Props rows={[['Recorded', fmtDate(ev.createdAt)], ['Scope revision', String(ev.scopeRevision)]]} />}
      {worker && <Section title="Recorded by">
        <LinkRow glyph={<StatusGlyph status={worker.status} />} right={PHASE_LABEL[worker.phase] ?? worker.phase} trailing="workflow" onClick={() => links.worker(worker.id)}>{worker.title}</LinkRow>
      </Section>}
      {cited.length > 0 && <Section title="Cited by" right={cited.length}>
        {cited.map(f => <LinkRow key={f.id} glyph={<StatusGlyph status={f.status} />} right={stLabel(f.status)} trailing="findings" onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)}
      </Section>}
      <Section title="Content">
        {state.error ? <p>{state.error}</p> : state.content == null ? <p>Loading…</p> : <pre className={RW.pre}>{state.content}</pre>}
      </Section>
    </div></PaneBody>
  </>
}

/** Middle-truncate a path so rows sharing a prefix still show their distinguishing tail. */
export function midTruncatePath(path: string, head = 18, tail = 24): string {
  return path.length > head + tail + 1 ? path.slice(0, head) + '…' + path.slice(-tail) : path
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
  const fullTitle = x ? [x.method, host(x.origin) + (x.pathAndQuery ?? '')].filter(Boolean).join(' ') : undefined
  return <div
    className="flex min-h-[30px] cursor-pointer items-center gap-2 -mx-2 rounded-control px-2 text-[12px] text-fg-muted transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg"
    role="button"
    tabIndex={0}
    data-slot="exchange-link"
    title={fullTitle}
    onClick={open}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open() } }}
  >
    <span className="w-11 flex-none font-mono text-[12px] text-fg-subtle">{x ? x.method : '—'}</span>
    <span className={cn('w-7 flex-none font-mono text-[12px] tabular-nums', httpCodeClass(x?.status))}>{x?.status ?? ''}</span>
    <span className="min-w-0 flex-1 truncate font-mono text-[12px]">
      {x ? (showHost ? host(x.origin) : '') + midTruncatePath(x.pathAndQuery ?? '')
        : <span className="text-fg-subtle">{full === null ? 'Exchange ' + short(id) : 'Loading…'}</span>}
    </span>
    <Icon name="ext" />
  </div>
}
