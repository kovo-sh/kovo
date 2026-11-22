// Workflow inspectors (Agent W): worker (summary · transcript · evidence),
// stack, queued steps, single chain step, and cold-graph digest.
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { readGraphDigest, readWorkerSessionAction } from '../../../actions.ts'
import type { WorkerSessionData } from '../../../server/worker-session-reader.ts'
import { useRun, useRunModel } from '../data.tsx'
import { EmptyState, LinkRow, Props, Section, Tag } from '../display.tsx'
import { fmtDate, fmtN, fmtRel, fmtTimeS, host, plural, short } from '../format.ts'
import { SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { normFStatus, PHASE_LABEL, prettyCat, stLabel } from '../meta.ts'
import type { Assignment, ChainStep, Fact, FindingRow } from '../model.ts'
import { Meter } from '../motion.tsx'
import { useLinks, useNav, useViewState } from '../nav.tsx'
import { ExchangeLink, PaneBody, PaneFooter, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { aggStatus, LiveGlyph } from './workflow-graph.tsx'
import { isLive, nodeLineage, QUEUE_ID, queuedSteps, requestCamera, setExpanded, useExpanded, useWorkflowLayout } from './workflow-layout.ts'
import type { WfLayout } from './workflow-layout.ts'

const OPEN_STEP = ['pending', 'ready', 'running', 'blocked']
const runEnded = (s: string) => s === 'complete' || s === 'stopped' || s === 'failed'

function FindingRows({ list, max = 10 }: { list: readonly FindingRow[]; max?: number }) {
  const links = useLinks()
  return <>
    {list.slice(0, max).map(f => <LinkRow key={f.id} glyph={<span style={{ display: 'inline-flex', gap: 6 }}><SevGlyph sev={f.severity} /><StatusGlyph status={normFStatus(f.status)} /></span>}
      right={<span className="mono">{host(f.origin)}</span>} trailing={null} onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)}
    {list.length > max && <p className="wf-more">+{list.length - max} more</p>}
  </>
}

/** Up/downstream link row: a worker or a stack, labelled by how it connects. */
function LineageRow({ L, id, other }: { L: WfLayout; id: string; other: string }) {
  const model = useRunModel()
  const nav = useNav()
  const e = L.edges.find(x => (x.from === other && x.to === id) || (x.from === id && x.to === other))
  const n = L.byId.get(other)
  const stack = n?.kind === 'stack'
  const a = model.workerById.get(other)
  const title = stack ? n!.g!.title + ' × ' + n!.members!.length : a?.title ?? other
  const status = stack ? aggStatus(n!.members!) : a?.status ?? 'complete'
  return <LinkRow glyph={<StatusGlyph status={status} />} right={(e?.kind === 'causal' ? 'via facts' : 'handoff') + (e && e.n > 1 ? ' · ' + e.n : '')} trailing={null}
    onClick={() => nav.select(stack ? { kind: 'stack', id: other } : { kind: 'worker', id: other }, { push: true })}>{title}</LinkRow>
}

function FactItem({ f }: { f: Fact }) {
  const links = useLinks()
  const [open, setOpen] = useState(false)
  return <div className="ctx-item">
    <span className="ci"><Icon name="fact" /></span>
    <div style={{ minWidth: 0 }}>
      <div className="ct"><b>{f.kind}</b> · <span className="mono">{host(f.origin)}</span>{f.tainted && <Tag className="wf-taint">tainted</Tag>}</div>
      <div className="cb">{f.summary}</div>
      <div className="wf-chips">
        {f.exchangeIds.slice(0, 6).map(x => <button key={x} type="button" className="wf-chip mono" onClick={() => links.exchange(x)} title="Open the exchange">ex:{short(x)}<Icon name="arrowR" /></button>)}
        {f.evidenceIds.slice(0, 6).map(x => <button key={x} type="button" className="wf-chip mono" onClick={() => links.evidence(x)} title="Open the evidence">ev:{short(x)}<Icon name="ext" /></button>)}
        <button type="button" className="wf-chip" onClick={() => setOpen(o => !o)} aria-expanded={open}>{open ? 'Hide data' : 'Data'}<Icon name={open ? 'chevU' : 'chevD'} /></button>
      </div>
      {open && <pre className="block mono wf-json">{JSON.stringify(f.data, null, 2)}</pre>}
    </div>
  </div>
}

// ---------------------------------------------------------------- worker session (transcript)

type SessionState = { data?: WorkerSessionData; loading: boolean; error?: boolean }
function useWorkerSession(runId: string, a: Assignment | undefined) {
  const [s, setS] = useState<SessionState>({ loading: true })
  useEffect(() => {
    if (!a) return
    let live = true
    setS(prev => ({ data: prev.data?.workerId === a.id ? prev.data : undefined, loading: true }))
    readWorkerSessionAction({ data: { runId, workerId: a.id } })
      .then(data => { if (live) setS({ data, loading: false }) }, () => { if (live) setS({ loading: false, error: true }) })
    return () => { live = false }
    // re-read as a live worker takes turns
  }, [runId, a?.id, a?.turnsUsed, a?.status])
  return s
}

function Transcript({ a, s }: { a: Assignment; s: SessionState }) {
  const model = useRunModel()
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const turns = s.data?.turns ?? []
  if (s.loading && !turns.length) return <div className="wf-load"><span className="wf-spin" />Loading the durable session…</div>
  if (!turns.length) {
    const msgs = model.detail.messages.filter(m => m.threadId === a.id && m.content.trim() !== (a.outcome ?? '').trim())
    if (msgs.length) {
      return <div className="wt">{msgs.map(m => <div key={m.id} className="wt-turn">
        <div className="wt-h"><span className="wt-n">{m.role}</span><span className="sp" /><span className="mono">{fmtTimeS(m.createdAt)}</span></div>
        <p className="wt-text">{m.content}</p>
      </div>)}</div>
    }
    return <p className="wf-none">{s.error ? 'The session transcript could not be read.' : a.status === 'queued' ? 'This worker has not taken a turn yet.' : 'No durable session transcript was recorded for this worker.'}</p>
  }
  return <div className="wt">
    {turns.map(t => <div key={t.turn} className="wt-turn">
      <div className="wt-h"><span className="wt-n">Turn {t.turn}</span>
        {t.durationMs != null && <span className="num">{(t.durationMs / 1000).toFixed(1)}s</span>}
        <span className="sp" />{t.timestamp != null && <span className="mono">{fmtRel(t.timestamp, model.base)}</span>}</div>
      {t.thinking && <p className="wt-think">{t.thinking}</p>}
      {t.text && t.text !== a.outcome && <p className="wt-text">{t.text}</p>}
      {t.tools.map(tc => {
        const k = t.turn + ':' + tc.id
        return <div key={tc.id} className={'wt-tool tk-' + tc.status}>
          <div className="wt-tool-h"><Icon name={tc.status === 'finding' ? 'findings' : tc.status === 'error' ? 'alert' : 'node'} />
            <span className="mono wt-tn">{tc.name}</span><span className={'wt-st s-' + tc.status}>{tc.status}</span>
            <span className="sp" />{tc.durationMs != null && <span className="num">{fmtN(tc.durationMs)} ms</span>}</div>
          {tc.argsPreview && <div className="wt-args mono">{tc.argsPreview}</div>}
          {tc.resultPreview && <>
            <button type="button" className="wf-chip" onClick={() => setOpen(o => ({ ...o, [k]: !o[k] }))} aria-expanded={!!open[k]}>{open[k] ? 'Hide result' : 'Show result'}<Icon name={open[k] ? 'chevU' : 'chevD'} /></button>
            {open[k] && <pre className="block mono wf-json">{tc.resultPreview}</pre>}
          </>}
        </div>
      })}
    </div>)}
    {s.loading && <div className="wf-load"><span className="wf-spin" />Refreshing…</div>}
  </div>
}

function Artifacts({ s }: { s: SessionState }) {
  const links = useLinks()
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const arts = s.data?.artifacts ?? []
  if (!arts.length) return null
  return <Section title="Shell & artifacts" right={arts.length}>
    {arts.map((art, i) => {
      const isOpen = open[art.id] ?? i === 0
      const shell = !!art.command
      return <div key={art.id} className={'wf-art' + (isOpen ? ' open' : '')}>
        <button type="button" className="wf-art-h" onClick={() => setOpen(o => ({ ...o, [art.id]: !isOpen }))} aria-expanded={isOpen}>
          {shell ? <span className={'wf-exit' + (art.exitStatus ? ' bad' : '')}>exit {art.exitStatus ?? 0}</span> : <Tag>{art.kind}</Tag>}
          <code className="wf-cmd">{shell ? art.command : art.title}</code>
          <Icon name={isOpen ? 'chevU' : 'chevD'} />
        </button>
        {isOpen && <div className="wf-art-b">
          <div className="wf-art-bar"><span>{art.title} · {fmtTimeS(art.createdAt)}</span>
            <button type="button" className="btn ghost" style={{ height: 22 }} onClick={() => links.evidence(art.id)}>Open<Icon name="ext" /></button></div>
          {shell ? <>
            {art.stdout && <pre className="block mono wf-json">{art.stdout}</pre>}
            {art.stderr && <pre className="block mono wf-json wf-stderr">{art.stderr}</pre>}
            {!art.stdout && !art.stderr && <p className="wf-none">No stdout or stderr.</p>}
          </> : <pre className="block mono wf-json">{art.preview || '(empty artifact)'}</pre>}
        </div>}
      </div>
    })}
  </Section>
}

// ---------------------------------------------------------------- cancel step

function useCancelStep(step: ChainStep | undefined) {
  const { detail, send } = useRun()
  const toast = useToast()
  const [pending, setPending] = useState<string | null>(null)
  const can = !!step && OPEN_STEP.includes(step.status) && !runEnded(detail.run.status) && pending !== step.id
  const cancel = () => {
    if (!step) return
    setPending(step.id)
    toast.undoable({
      message: 'Step #' + step.seq + ' canceled', sub: step.title, icon: 'stop',
      commit: () => send({ action: 'cancel_step', stepId: step.id }),
      undo: () => setPending(null),
    })
  }
  return { can, cancel, pending: !!step && pending === step.id }
}

function CancelFooter({ step, label }: { step: ChainStep; label?: ReactNode }) {
  const c = useCancelStep(step)
  if (!c.can && !c.pending) return null
  return <PaneFooter stamped={c.pending ? <><Icon name="stop" />Canceling step #{step.seq}… <span className="wf-dim" style={{ fontWeight: 400 }}>Z to undo</span></> : undefined}>
    <span className="wf-foot-t">{label ?? <>Step #{step.seq} · {stLabel(step.status)}</>}</span>
    <span className="sp" />
    <button type="button" className="btn" onClick={c.cancel} title="Cancel this chain step (the worker stops and the step is not retried)"><Icon name="stop" />Cancel step</button>
  </PaneFooter>
}

// ---------------------------------------------------------------- worker

type ITab = 'summary' | 'transcript' | 'evidence'

export function WorkerInspector({ sel }: InspectorProps) {
  const { detail } = useRun()
  const model = useRunModel()
  const L = useWorkflowLayout()
  const expanded = useExpanded(detail.run.id)
  const [tab, setTab] = useViewState<ITab>('wf.itab', 'summary')
  const a = model.workerById.get(sel.id)
  const session = useWorkerSession(detail.run.id, a)
  if (!a) {
    return <><PaneHeader title="Worker" sub={<span className="mono">{short(sel.id)}</span>} />
      <PaneBody><EmptyState icon="workers" title="Worker not found">It is not part of this run’s current data.</EmptyState></PaneBody></>
  }
  const step = a.stepId ? model.stepById.get(a.stepId) : model.stepByWorker.get(a.id)
  const msgs = detail.messages.filter(m => m.threadId === a.id)
  const exs = (model.exchangesByWorker.get(a.id) ?? []).slice().sort((x, y) => x.createdAt - y.createdAt)
  const facts = model.factsByWorker.get(a.id) ?? []
  const fs = model.workerFindings.get(a.id) ?? []
  const pct = a.maxTurns ? a.turnsUsed / a.maxTurns : 0
  const rid = L.byId.has(a.id) ? a.id : L.stacks.of.get(a.id) ?? a.id
  const ups = (L.inc.get(rid) ?? []).filter(x => x !== 'report')
  const downs = (L.out.get(rid) ?? []).filter(x => x !== 'report')
  const lin = nodeLineage(L, rid)
  const grp = L.stacks.of.get(a.id)
  const g = grp ? L.stacks.groups.get(grp) : undefined
  const hist = L.history.get(a.id)
  const nTurns = session.data ? session.data.turns.length : a.turnsUsed
  const nArts = session.data?.artifacts.length ?? 0
  return <>
    <PaneHeader title="Worker" sub={<span className="mono">{short(a.id)}</span>}
      extra={<button type="button" className="icon-btn" title="Center in graph (↵)" aria-label="Center in graph" onClick={() => requestCamera({ type: 'center', id: rid })}><Icon name="fit" /></button>} />
    <PaneBody><div className="d">
      <div className="d-meta">
        <Tag><span className="wf-tg"><LiveGlyph status={a.status} /></span>{stLabel(a.status)}</Tag>
        <Tag>{PHASE_LABEL[a.phase] ?? a.phase}</Tag>
        {step && <Tag className="num">Step #{step.seq} · P{step.priority}</Tag>}
        {step?.category && <Tag>{prettyCat(step.category)}</Tag>}
        {a.attempt > 0 && <Tag>Attempt {a.attempt + 1}</Tag>}
        {hist && <Tag tone="warn">{hist}</Tag>}
      </div>
      <h2>{a.title}</h2>
      <Props rows={[
        ['Turns', <><Meter id="wf.turns" value={pct} warn={isLive(a) && pct > 0.8} />{a.turnsUsed} of {a.maxTurns}</>],
        ['Requests', <>{fmtN(a.requestsUsed)}{exs.length > 0 && <span className="wf-dim">· {exs.length} in the loaded window</span>}</>],
        ...(a.sourceOrigins.length ? [['Origins', <span className="mono wf-origins" title={a.sourceOrigins.join('\n')}>{a.sourceOrigins.slice(0, 6).map(host).join(', ')}{a.sourceOrigins.length > 6 ? ' +' + (a.sourceOrigins.length - 6) : ''}</span>] as [ReactNode, ReactNode]] : []),
        ['Started', <>{fmtDate(a.createdAt)} <span className="wf-dim mono">{fmtRel(a.createdAt, model.base)}</span></>],
        ['Lineage', <>{lin.up.size} upstream · {[...lin.down].filter(x => x !== 'report').length} downstream</>],
      ]} />
      {g && <div className="banner"><Icon name="workflow" /><span>Part of the stack <b className="wf-b">{g.title}</b> × {g.members.length}</span>
        <button type="button" className="btn ghost" style={{ height: 24 }} onClick={() => setExpanded(detail.run.id, g.id, !expanded.has(g.id))}>{expanded.has(g.id) ? 'Collapse' : 'Expand'}</button></div>}

      <div className="tabs wf-itabs" role="tablist" aria-label="Worker sections">
        <button type="button" role="tab" aria-selected={tab === 'summary'} className={'tab' + (tab === 'summary' ? ' on' : '')} onClick={() => setTab('summary')}>Summary</button>
        <button type="button" role="tab" aria-selected={tab === 'transcript'} className={'tab' + (tab === 'transcript' ? ' on' : '')} onClick={() => setTab('transcript')}>Transcript<span className="ct num">{nTurns}</span></button>
        <button type="button" role="tab" aria-selected={tab === 'evidence'} className={'tab' + (tab === 'evidence' ? ' on' : '')} onClick={() => setTab('evidence')}>Evidence<span className="ct num">{facts.length + exs.length + nArts}</span></button>
      </div>

      {tab === 'summary' && <>
        {a.objective && <Section title="Objective"><p>{a.objective}</p></Section>}
        {step?.hypothesis && step.hypothesis !== a.objective && <Section title="Hypothesis"><p>{step.hypothesis}</p>
          {step.skills.length > 0 && <div className="chip-row">{step.skills.map(s => <Tag key={s} mono>{s}</Tag>)}</div>}</Section>}
        {a.outcome && <Section title="Outcome"><p className="lead">{a.outcome}</p></Section>}
        {ups.length > 0 && <Section title="Upstream" right={ups.length}>{ups.slice(0, 8).map(w => <LineageRow key={w} L={L} id={rid} other={w} />)}</Section>}
        {downs.length > 0 && <Section title="Downstream" right={downs.length}>{downs.slice(0, 8).map(w => <LineageRow key={w} L={L} id={rid} other={w} />)}</Section>}
        {fs.length > 0 && <Section title="Findings" right={fs.length}><FindingRows list={fs} /></Section>}
        {msgs.length > 0 && <Section title="Worker report">{msgs.map(m => <pre key={m.id} className="block wf-report">{m.content}</pre>)}</Section>}
        {!a.objective && !a.outcome && !ups.length && !downs.length && !fs.length && !msgs.length && <p className="wf-none">Nothing recorded yet.</p>}
      </>}
      {tab === 'transcript' && <Transcript a={a} s={session} />}
      {tab === 'evidence' && <>
        {facts.length > 0 && <Section title="Facts" right={facts.length}><div className="ctx">{facts.map(f => <FactItem key={f.id} f={f} />)}</div></Section>}
        <Artifacts s={session} />
        {exs.length > 0 && <Section title="Exchanges" right={exs.length < a.requestsUsed ? exs.length + ' of ' + fmtN(a.requestsUsed) : exs.length}>
          <ExchangeRows list={exs} /></Section>}
        {!facts.length && !exs.length && !nArts && <p className="wf-none">{session.loading ? 'Loading…' : 'No facts, artifacts or exchanges recorded by this worker.'}</p>}
      </>}
    </div></PaneBody>
    {step && <CancelFooter step={step} label={<>Step #{step.seq} · {isLive(a) ? stLabel(a.status) : stLabel(step.status)}</>} />}
  </>
}

function ExchangeRows({ list }: { list: readonly { id: string }[] }) {
  return <>{list.slice(0, 40).map(e => <ExchangeLink key={e.id} id={e.id} />)}{list.length > 40 && <p className="wf-more">+{list.length - 40} more in Exchanges</p>}</>
}

// ---------------------------------------------------------------- stack

export function StackInspector({ sel }: InspectorProps) {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const L = useWorkflowLayout()
  const expanded = useExpanded(detail.run.id)
  const g = L.stacks.groups.get(sel.id)
  if (!g) return <><PaneHeader title="Stack" /><PaneBody><EmptyState icon="workflow" title="Stack not found" /></PaneBody></>
  const ms = g.members.map(id => model.workerById.get(id)).filter((a): a is Assignment => !!a)
  const st = new Map<string, number>()
  ms.forEach(a => st.set(a.status, (st.get(a.status) ?? 0) + 1))
  const seen = new Set<string>()
  const fs = ms.flatMap(a => model.workerFindings.get(a.id) ?? []).filter(f => !seen.has(f.id) && !!seen.add(f.id))
  const fa = ms.reduce((s, a) => s + (model.factsByWorker.get(a.id) ?? []).length, 0)
  const exp = expanded.has(g.id)
  const lin = L.byId.has(g.id) ? nodeLineage(L, g.id) : null
  return <>
    <PaneHeader title="Stack" sub={PHASE_LABEL[g.phase] ?? g.phase}
      extra={<button type="button" className="btn ghost" style={{ height: 24 }} onClick={() => setExpanded(detail.run.id, g.id, !exp)}><Icon name={exp ? 'minus' : 'plus'} />{exp ? 'Collapse' : 'Expand'}</button>} />
    <PaneBody><div className="d">
      <div className="d-meta">{[...st.entries()].map(([k, n]) => <Tag key={k} className="num"><span className="wf-tg"><LiveGlyph status={k} /></span>{n} {stLabel(k).toLowerCase()}</Tag>)}</div>
      <h2>{g.title} <span className="wf-x">× {ms.length}</span></h2>
      <Props rows={[
        ['Requests', fmtN(ms.reduce((s, a) => s + a.requestsUsed, 0))],
        ['Facts', fmtN(fa)],
        ['Started', <>{fmtRel(Math.min(...ms.map(a => a.createdAt)), model.base)} → {fmtRel(Math.max(...ms.map(a => a.createdAt)), model.base)}</>],
        ...(lin ? [['Lineage', <>{lin.up.size} upstream · {[...lin.down].filter(x => x !== 'report').length} downstream</>] as [ReactNode, ReactNode]] : []),
      ]} />
      <Section title="Objective template"><p>{ms[0]?.objective}</p></Section>
      {fs.length > 0 && <Section title="Findings" right={fs.length}><FindingRows list={fs} max={8} /></Section>}
      <Section title="Workers" right={ms.length}>
        {ms.map(a => {
          const nf = (model.workerFindings.get(a.id) ?? []).length
          return <LinkRow key={a.id} glyph={<LiveGlyph status={a.status} />} trailing={null}
            right={<span className="num">{fmtN(a.requestsUsed)} req{nf ? ' · ' + plural(nf, 'finding') : ''}</span>}
            onClick={() => nav.select({ kind: 'worker', id: a.id }, { push: true })}>{a.title.split(' · ').slice(1).join(' · ') || a.title}</LinkRow>
        })}
      </Section>
    </div></PaneBody>
  </>
}

// ---------------------------------------------------------------- queued steps + single step

export function StepsInspector() {
  const model = useRunModel()
  const nav = useNav()
  const steps = useMemo(() => queuedSteps(model), [model])
  const canceled = model.detail.chainSteps.filter(s => s.status === 'canceled').length
  const byStatus = new Map<string, number>()
  steps.forEach(s => byStatus.set(s.status, (byStatus.get(s.status) ?? 0) + 1))
  return <>
    <PaneHeader title="Queued steps" sub={steps.length}
      extra={<button type="button" className="icon-btn" title="Center in graph" aria-label="Center in graph" onClick={() => requestCamera({ type: 'center', id: QUEUE_ID })}><Icon name="fit" /></button>} />
    <PaneBody><div className="d">
      <div className="d-meta">{[...byStatus.entries()].map(([k, n]) => <Tag key={k} className="num"><StatusGlyph status={k} />{n} {stLabel(k).toLowerCase()}</Tag>)}
        {canceled > 0 && <Tag className="num"><StatusGlyph status="canceled" />{canceled} canceled</Tag>}</div>
      <h2>Planned chain steps, not yet dispatched</h2>
      <p className="wf-lead">The coordinator queued these steps; each becomes a worker when its dependencies are met and the run is running. Open one to review its hypothesis or cancel it.</p>
      {steps.length ? <Section title="Steps" right={steps.length}>
        {steps.map(s => <LinkRow key={s.id} glyph={<StatusGlyph status={s.status} />} sub={prettyCat(s.category)} trailing="chevR"
          right={<span className="num">#{s.seq} · P{s.priority}</span>} onClick={() => nav.select({ kind: 'step', id: s.id }, { push: true })}>{s.title}</LinkRow>)}
      </Section> : <p className="wf-none">Every planned step has been dispatched.</p>}
    </div></PaneBody>
  </>
}

export function StepInspector({ sel }: InspectorProps) {
  const model = useRunModel()
  const nav = useNav()
  const s = model.stepById.get(sel.id)
  if (!s) return <><PaneHeader title="Step" /><PaneBody><EmptyState icon="node" title="Step not found" /></PaneBody></>
  const worker = s.assignedWorkerId ? model.workerById.get(s.assignedWorkerId) : undefined
  const deps = s.dependsOnStepIds.map(id => model.stepById.get(id)).filter((x): x is ChainStep => !!x)
  const factDeps = s.dependsOnFactIds.map(id => model.factById.get(id)).filter((x): x is Fact => !!x)
  return <>
    <PaneHeader title="Step" sub={'#' + s.seq} />
    <PaneBody><div className="d">
      <div className="d-meta"><Tag><StatusGlyph status={s.status} />{stLabel(s.status)}</Tag><Tag className="num">Step #{s.seq} · P{s.priority}</Tag><Tag>{prettyCat(s.category)}</Tag>
        {s.specialistProfile && <Tag>{s.specialistProfile}</Tag>}</div>
      <h2>{s.title}</h2>
      <Props rows={[
        ['Planned', <>{fmtDate(s.createdAt)} <span className="wf-dim mono">{fmtRel(s.createdAt, model.base)}</span></>],
        ...(s.sourceOrigins.length ? [['Origins', <span className="mono wf-origins">{s.sourceOrigins.slice(0, 6).map(host).join(', ')}</span>] as [ReactNode, ReactNode]] : []),
        ['Scope', 'Revision ' + s.scopeRevision],
      ]} />
      <Section title="Hypothesis"><p>{s.hypothesis}</p>{s.skills.length > 0 && <div className="chip-row">{s.skills.map(k => <Tag key={k} mono>{k}</Tag>)}</div>}</Section>
      {worker && <Section title="Worker"><LinkRow glyph={<LiveGlyph status={worker.status} />} trailing={null} onClick={() => nav.select({ kind: 'worker', id: worker.id }, { push: true })}>{worker.title}</LinkRow></Section>}
      {deps.length > 0 && <Section title="Depends on steps" right={deps.length}>
        {deps.map(d => <LinkRow key={d.id} glyph={<StatusGlyph status={d.status} />} right={<span className="num">#{d.seq}</span>} trailing={null}
          onClick={() => nav.select(d.assignedWorkerId ? { kind: 'worker', id: d.assignedWorkerId } : { kind: 'step', id: d.id }, { push: true })}>{d.title}</LinkRow>)}
      </Section>}
      {factDeps.length > 0 && <Section title="Depends on facts" right={factDeps.length}><div className="ctx">{factDeps.map(f => <FactItem key={f.id} f={f} />)}</div></Section>}
    </div></PaneBody>
    <CancelFooter step={s} />
  </>
}

// ---------------------------------------------------------------- graph digest

type DigestLoad = Awaited<ReturnType<typeof readGraphDigest>>
export function DigestInspector({ sel }: InspectorProps) {
  const { detail } = useRun()
  const model = useRunModel()
  const nav = useNav()
  const d = detail.digests.find(x => x.id === sel.id)
  const [load, setLoad] = useState<{ state: 'idle' | 'loading' | 'error' } | { state: 'done'; data: DigestLoad }>({ state: 'idle' })
  useEffect(() => { setLoad({ state: 'idle' }) }, [sel.id])
  if (!d) return <><PaneHeader title="Digest" /><PaneBody><EmptyState icon="archive" title="Digest not found" /></PaneBody></>
  const workers = d.coveredAssignmentIds.map(id => model.workerById.get(id)).filter((a): a is Assignment => !!a)
  const fetchFacts = () => {
    setLoad({ state: 'loading' })
    readGraphDigest({ data: { runId: detail.run.id, digestId: d.id } })
      .then(data => setLoad({ state: 'done', data }), () => setLoad({ state: 'error' }))
  }
  return <>
    <PaneHeader title="Graph digest" sub={'Round ' + d.roundNo} />
    <PaneBody><div className="d">
      <div className="d-meta"><Tag>{d.level === 'major' ? 'Major' : 'Minor'} compaction</Tag><Tag tone={d.active ? undefined : 'warn'}>{d.active ? 'Active' : 'Superseded'}</Tag></div>
      <h2>Cold-graph digest · round {d.roundNo}</h2>
      <Props rows={[
        ['Facts', fmtN(d.coveredFactIds.length)],
        ['Workers', fmtN(d.coveredAssignmentIds.length)],
        ['Compacted', <>{fmtDate(d.createdAt)} <span className="wf-dim mono">{fmtRel(d.createdAt, model.base)}</span></>],
        ['Signature', <span className="mono">{d.signatureHash.slice(0, 16)}</span>],
      ]} />
      <Section title="Summary"><p className="lead">{d.summary}</p></Section>
      <Section title="Covered facts" right={d.coveredFactIds.length}>
        {load.state === 'idle' && <button type="button" className="btn" onClick={fetchFacts}><Icon name="download" />Load covered facts</button>}
        {load.state === 'loading' && <div className="wf-load"><span className="wf-spin" />Loading facts…</div>}
        {load.state === 'error' && <p>Could not load the digest’s facts. <button type="button" className="linkbtn" onClick={fetchFacts}>Retry</button></p>}
        {load.state === 'done' && (load.data.facts.length
          ? <div className="ctx">{load.data.facts.map(f => <div key={f.id} className="ctx-item"><span className="ci"><Icon name="fact" /></span>
            <div style={{ minWidth: 0 }}><div className="ct"><b>{f.kind}</b> · <span className="mono">{host(f.origin)}</span></div><div className="cb">{f.summary}</div></div></div>)}</div>
          : <p className="wf-none">No untainted facts remain under this digest.</p>)}
      </Section>
      {workers.length > 0 && <Section title="Covered workers" right={workers.length}>
        {workers.slice(0, 30).map(a => <LinkRow key={a.id} glyph={<LiveGlyph status={a.status} />} right={PHASE_LABEL[a.phase] ?? a.phase} trailing={null}
          onClick={() => nav.select({ kind: 'worker', id: a.id }, { push: true })}>{a.title}</LinkRow>)}
        {workers.length > 30 && <p className="wf-more">+{workers.length - 30} more</p>}
      </Section>}
    </div></PaneBody>
  </>
}
