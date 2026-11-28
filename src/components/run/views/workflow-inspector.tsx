// Workflow inspectors (Agent W): worker (summary · transcript · evidence),
// stack, queued steps, single chain step, and memory summary digest.
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { readGraphDigest, readWorkerSessionAction } from '../../../actions.ts'
import type { WorkerSessionData } from '../../../server/worker-session-reader.ts'
import { useRun, useRunModel } from '../data.tsx'
import { Disclosure, EmptyState, FindingTitle, HostLabel, InlineError, LinkRow, Props, Section, Tag } from '../display.tsx'
import {
  deriveRound0PipelineState,
  fmtAgo,
  fmtDate,
  fmtFullDateTime,
  fmtN,
  fmtRel,
  fmtTimeS,
  host,
  isRound0ThreatModelWorker,
  plural,
  sharedApex,
} from '../format.ts'
import type { Round0HostSignal, Round0PipelineState, Round0PipelineStep, Round0StageKey, Round0StepStatus } from '../format.ts'
import { LiveGlyph, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { normFStatus, PHASE_LABEL, prettyCat, stLabel } from '../meta.ts'
import { aggStatus } from '../model.ts'
import type { Assignment, ChainStep, Fact, FindingRow } from '../model.ts'
import { Meter } from '../motion.tsx'
import { useLinks, useNav, useViewState } from '../nav.tsx'
import { ExchangeLink, PaneBody, PaneFooter, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, runIconBtn, RW } from '../tw.ts'
import { isLive, nodeLineage, QUEUE_ID, queuedSteps, requestCamera, setExpanded, useExpanded, useWorkflowLayout } from './workflow-layout.ts'
import type { WfLayout } from './workflow-layout.ts'

const OPEN_STEP = ['pending', 'ready', 'running', 'blocked']
const runEnded = (s: string) => s === 'complete' || s === 'stopped' || s === 'failed'

const WF_H2 = 'm-0 mb-3 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg'
const WF_META = 'mb-2.5 flex flex-wrap gap-1.5'
const WF_CHIP = 'inline-flex h-5 cursor-pointer items-center gap-[3px] rounded-[5px] border-0 bg-transparent px-1.5 font-sans text-[11px] font-normal text-fg-subtle shadow-[inset_0_0_0_1px_var(--line-2)] transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg'
const WF_SPIN = 'size-3 flex-none rounded-full border-[1.5px] border-line-strong border-t-fg-muted animate-spin'
const WF_LOAD = 'my-3.5 flex items-center gap-2 text-[12.5px] text-fg-subtle'
const WF_NONE = 'my-3 text-[12.5px] text-fg-subtle'
const WF_MORE = 'my-1 mb-2! text-[12px]! text-fg-subtle!'
const WF_PRE_JSON = cn(RW.pre, 'my-1.5 mb-1 max-h-[260px] text-[11.5px] leading-[17px]')
const WF_ORIGINS = 'rw-wrap min-w-0 font-mono text-[11.5px] whitespace-normal [overflow-wrap:anywhere]'

/** Comma-joined origin hosts that wrap between hosts, never inside one; an over-long host ellipsizes. */
function OriginList({ origins, max = 6, title }: { origins: readonly string[]; max?: number; title?: string }) {
  const shown = origins.slice(0, max)
  return <span className={WF_ORIGINS} title={title}>
    {shown.map((o, i) => <span key={o + i}>
      <span className="inline-block max-w-full truncate whitespace-nowrap align-bottom" title={o}>{host(o)}</span>
      {i < shown.length - 1 ? ', ' : ''}
    </span>)}
    {origins.length > max && <span className="whitespace-nowrap text-fg-subtle">{' +' + fmtN(origins.length - max)}</span>}
  </span>
}

/** Failed worker reason, surfaced under the title (clamped, expandable). */
function FailureCallout({ text }: { text: string }) {
  const [full, setFull] = useState(false)
  const long = text.length > 220 || text.split('\n').length > 3
  return <div
    role="alert"
    data-worker-failure=""
    className="mb-3 rounded-[7px] bg-danger-soft px-2.5 py-2 text-[12.5px] leading-[19px] text-fg shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--danger)_35%,transparent)]"
  >
    <p className={cn('m-0 whitespace-pre-wrap [overflow-wrap:anywhere]', !full && 'line-clamp-3')}>{text}</p>
    {long && <button type="button" className={cn(runBtn({ variant: 'link' }), 'mt-1 text-[12px]')} aria-expanded={full} onClick={() => setFull(f => !f)}>
      {full ? 'Show less' : 'Show full error'}
    </button>}
  </div>
}
const WF_TG = 'inline-flex size-3.5 items-center justify-center'
const WF_CTX = 'flex flex-col divide-y divide-dashed divide-line'
const WF_CTX_ITEM = 'grid grid-cols-[18px_minmax(0,1fr)] gap-2 py-[7px] text-[12px] leading-[18px]'

function FindingRows({ list, max = 10 }: { list: readonly FindingRow[]; max?: number }) {
  const links = useLinks()
  return <>
    {list.slice(0, max).map(f => <LinkRow key={f.id} glyph={<span className="inline-flex gap-1.5"><SevGlyph sev={f.severity} /><StatusGlyph status={normFStatus(f.status)} /></span>}
      right={f.origin ? <span className="font-mono text-[12px]" title={f.origin}><HostLabel host={host(f.origin)} quiet max={28} /></span> : null} trailing={null} onClick={() => links.finding(f.id)}><FindingTitle title={f.title} /></LinkRow>)}
    {list.length > max && <p className={WF_MORE}>+{list.length - max} more</p>}
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
  const model = useRunModel()
  const links = useLinks()
  const [open, setOpen] = useState(false)
  return <div className={WF_CTX_ITEM}>
    <span className="pt-0.5 text-fg-subtle"><Icon name="fact" /></span>
    <div className="min-w-0">
      <div className="text-[11.5px] text-fg-subtle">
        <b className="font-medium text-fg-muted">{f.kind}</b> · <span className="font-mono text-[11.5px]">{host(f.origin)}</span>
        {f.tainted && <Tag className="ml-1.5 h-4 text-danger">tainted</Tag>}
      </div>
      <div className="line-clamp-3 text-fg-muted">{f.summary}</div>
      <div className="mt-[5px] flex flex-wrap gap-1">
        {f.exchangeIds.slice(0, 6).map(x => {
          const ex = model.exchangeById.get(x)
          const label = ex ? `${ex.method} ${ex.pathAndQuery.length > 28 ? ex.pathAndQuery.slice(0, 27) + '…' : ex.pathAndQuery} · ${ex.status}` : 'HTTP exchange'
          const tip = ex ? `${ex.method} ${ex.origin}${ex.pathAndQuery} (${ex.status}) · ID ${x}` : `Open HTTP exchange · ID ${x}`
          return <button key={x} type="button" className={WF_CHIP} onClick={() => links.exchange(x)} title={tip}>{label}<Icon name="arrowR" size={10} /></button>
        })}
        {f.evidenceIds.slice(0, 6).map(x => {
          const ev = model.evidenceById.get(x)
          const rawTitle = ev?.title ?? 'Evidence record'
          const label = rawTitle.length > 30 ? rawTitle.slice(0, 29) + '…' : rawTitle
          const tip = ev ? `${ev.title} (${ev.kind}) · ID ${x}` : `Open evidence · ID ${x}`
          return <button key={x} type="button" className={WF_CHIP} onClick={() => links.evidence(x)} title={tip}>{label}<Icon name="ext" size={10} /></button>
        })}
        <button type="button" className={WF_CHIP} onClick={() => setOpen(o => !o)} aria-expanded={open}>{open ? 'Hide data' : 'Data'}<Icon name={open ? 'chevU' : 'chevD'} size={10} /></button>
      </div>
      {open && <pre className={WF_PRE_JSON}>{JSON.stringify(f.data, null, 2)}</pre>}
    </div>
  </div>
}

// ---------------------------------------------------------------- worker session (transcript)

type SessionState = { data?: WorkerSessionData; loading: boolean; error?: boolean; retry?: () => void }
function useWorkerSession(runId: string, a: Assignment | undefined): SessionState {
  const [s, setS] = useState<SessionState>({ loading: true })
  const [reload, setReload] = useState(0)
  useEffect(() => {
    if (!a) return
    let live = true
    setS(prev => ({ data: prev.data?.workerId === a.id ? prev.data : undefined, loading: true }))
    readWorkerSessionAction({ data: { runId, workerId: a.id } })
      .then(data => { if (live) setS({ data, loading: false }) }, () => { if (live) setS({ loading: false, error: true }) })
    return () => { live = false }
    // re-read as a live worker takes turns
  }, [runId, a?.id, a?.turnsUsed, a?.status, reload])
  return { ...s, retry: () => setReload(n => n + 1) }
}

function Transcript({ a, s }: { a: Assignment; s: SessionState }) {
  const model = useRunModel()
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const turns = s.data?.turns ?? []
  if (s.loading && !turns.length) return <div className={WF_LOAD}><span className={WF_SPIN} />Loading the durable session…</div>
  if (!turns.length) {
    const msgs = model.detail.messages.filter(m => m.threadId === a.id && m.content.trim() !== (a.outcome ?? '').trim())
    if (msgs.length) {
      return <div className="flex flex-col pt-1">{s.error && <InlineError className="mt-2" title="The session transcript could not be read." onRetry={s.retry} />}{msgs.map(m => <div key={m.id} className="border-b border-line pb-2.5 pt-3 last:border-b-0">
        <div className="mb-1.5 flex items-center gap-2 text-[11.5px] text-fg-subtle">
          <span className="font-semibold capitalize text-fg-muted">{m.role}</span>
          <span className="flex-1" />
          <span className="font-mono text-[11.5px]">{fmtTimeS(m.createdAt)}</span>
        </div>
        <p className="m-0 mb-2 whitespace-pre-wrap break-words text-[12.5px] leading-[19px] text-fg">{m.content}</p>
      </div>)}</div>
    }
    if (s.error) return <InlineError className="my-3" title="The session transcript could not be read." onRetry={s.retry} />
    return <p className={WF_NONE}>{a.status === 'queued'
      ? 'This worker has not taken a turn yet.'
      : a.turnsUsed > 0
        ? `${plural(a.turnsUsed, 'turn')} ran, but no durable transcript was recorded.`
        : 'No durable session transcript was recorded for this worker.'}</p>
  }
  return <div className="flex flex-col pt-1">
    {turns.map(t => <div key={t.turn} className="border-b border-line pb-2.5 pt-3 last:border-b-0">
      <div className="mb-1.5 flex items-center gap-2 text-[11.5px] text-fg-subtle">
        <span className="font-semibold capitalize text-fg-muted">Turn {t.turn}</span>
        {t.durationMs != null && <span className="tabular-nums">{(t.durationMs / 1000).toFixed(1)}s</span>}
        <span className="flex-1" />
        {t.timestamp != null && <span className="font-mono text-[11.5px]">{fmtRel(t.timestamp, model.base)}</span>}
      </div>
      {t.thinking && <p className="m-0 mb-2 whitespace-pre-wrap break-words border-l-2 border-line-2 pl-2.5 text-[12px] leading-[18px] text-fg-subtle">{t.thinking}</p>}
      {t.text && t.text !== a.outcome && <p className="m-0 mb-2 whitespace-pre-wrap break-words text-[12.5px] leading-[19px] text-fg">{t.text}</p>}
      {t.tools.map(tc => {
        const k = t.turn + ':' + tc.id
        return <div
          key={tc.id}
          className={cn(
            'mt-1.5 rounded-[7px] px-[9px] pb-2 pt-[7px]',
            tc.status === 'finding'
              ? 'bg-panel shadow-[inset_0_0_0_1px_var(--line-strong)]'
              : tc.status === 'error'
                ? 'bg-sunk shadow-[inset_0_0_0_1px_var(--bad-line,var(--line-strong))]'
                : 'bg-sunk shadow-[inset_0_0_0_1px_var(--line)]',
          )}
        >
          <div className="flex min-w-0 items-center gap-1.5 text-[11.5px] text-fg-subtle" data-tool-head="">
            <Icon name={tc.status === 'finding' ? 'findings' : tc.status === 'error' ? 'alert' : 'node'} size={12} className="flex-none" />
            <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] font-medium text-fg" title={tc.name}>{tc.name}</span>
            <span className={cn(
              'flex-none text-[11px]',
              tc.status === 'error' ? 'text-danger' : tc.status === 'finding' ? 'font-medium text-fg' : tc.status === 'pending' ? 'text-warn' : 'text-fg-subtle',
            )}>{tc.status}</span>
            {tc.durationMs != null && <span className="flex-none tabular-nums">{fmtN(tc.durationMs)} ms</span>}
          </div>
          {tc.argsPreview && <div className="my-1 mb-0.5 line-clamp-3 break-all font-mono text-[11px] leading-4 text-fg-muted">{tc.argsPreview}</div>}
          {tc.resultPreview && <>
            <button type="button" className={cn(WF_CHIP, 'mt-[5px]')} onClick={() => setOpen(o => ({ ...o, [k]: !o[k] }))} aria-expanded={!!open[k]}>
              {open[k] ? 'Hide result' : 'Show result'}<Icon name={open[k] ? 'chevU' : 'chevD'} size={10} />
            </button>
            {open[k] && <pre className={WF_PRE_JSON}>{tc.resultPreview}</pre>}
          </>}
        </div>
      })}
    </div>)}
    {s.loading && <div className={WF_LOAD}><span className={WF_SPIN} />Refreshing…</div>}
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
      return <div key={art.id} className="mb-1.5 overflow-hidden rounded-[7px] shadow-[inset_0_0_0_1px_var(--line)]">
        <button
          type="button"
          className="flex min-h-8 w-full cursor-pointer items-center gap-2 rounded-none border-0 bg-transparent px-[9px] text-left font-sans text-fg-subtle shadow-none transition-colors duration-[var(--d1)] hover:bg-hover"
          onClick={() => setOpen(o => ({ ...o, [art.id]: !isOpen }))}
          aria-expanded={isOpen}
        >
          {shell
            ? <span className={cn('inline-flex h-[18px] flex-none items-center rounded-[9px] bg-sunk px-1.5 font-mono text-[10.5px] shadow-[inset_0_0_0_1px_var(--line-2)]', art.exitStatus ? 'text-danger' : 'text-fg-muted')}>exit {art.exitStatus ?? 0}</span>
            : <Tag>{art.kind}</Tag>}
          <code className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-fg">{shell ? art.command : art.title}</code>
          <Icon name={isOpen ? 'chevU' : 'chevD'} size={12} />
        </button>
        {isOpen && <div className="border-t border-line px-[9px] pb-2">
          <div className="flex items-center justify-between gap-2 pt-1.5 text-[11.5px] text-fg-subtle">
            <span>{art.title} · {fmtTimeS(art.createdAt)}</span>
            <button type="button" className={runBtn({ variant: 'ghost', size: 'xs' })} onClick={() => links.evidence(art.id)}>Open<Icon name="ext" /></button>
          </div>
          {shell ? <>
            {art.stdout && <pre className={WF_PRE_JSON}>{art.stdout}</pre>}
            {art.stderr && <pre className={cn(WF_PRE_JSON, 'text-danger')}>{art.stderr}</pre>}
            {!art.stdout && !art.stderr && <p className={WF_NONE}>No stdout or stderr.</p>}
          </> : <pre className={WF_PRE_JSON}>{art.preview || '(empty artifact)'}</pre>}
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
    void send({ action: 'cancel_step', stepId: step.id }).then(
      () => toast.show('Step #' + step.seq + ' canceled', { sub: step.title, icon: 'stop' }),
      (e: unknown) => {
        setPending(null)
        toast.show(e instanceof Error ? e.message : 'Could not cancel step.', { tone: 'error' })
      },
    )
  }
  return { can, cancel, pending: !!step && pending === step.id }
}

function CancelFooter({ step, label }: { step: ChainStep; label?: ReactNode }) {
  const c = useCancelStep(step)
  if (!c.can && !c.pending) return null
  return <PaneFooter stamped={c.pending ? <><Icon name="stop" />Canceling step #{step.seq}…</> : undefined}>
    <span className="min-w-0 truncate text-[12px] text-fg-subtle">{label ?? <>Step #{step.seq} · {stLabel(step.status)}</>}</span>
    <span className="flex-1" />
    <button type="button" className={runBtn()} onClick={c.cancel} title="Cancel this chain step (the worker stops and the step is not retried)"><Icon name="stop" />Cancel step</button>
  </PaneFooter>
}

// ---------------------------------------------------------------- Round-0 recon pipeline summary

export { deriveRound0PipelineState, isRound0ThreatModelWorker }
export type { Round0HostSignal, Round0PipelineState, Round0PipelineStep, Round0StageKey, Round0StepStatus }

const ROUND0_HOST_PREVIEW = 6

function Round0StepIcon({ step }: { step: Round0PipelineStep }) {
  if (step.status === 'done') {
    return (
      <span
        className="inline-flex size-4 flex-none items-center justify-center rounded-full bg-ok-soft text-ok"
        aria-label="Done"
      >
        <Icon name="check" size={10} />
      </span>
    )
  }
  if (step.status === 'active') {
    return (
      <span
        className="inline-flex size-4 flex-none items-center justify-center"
        aria-label="In progress"
      >
        <span className="size-3.5 rounded-full border-[1.5px] border-accent/30 border-t-accent animate-spin motion-reduce:animate-none" />
      </span>
    )
  }
  return (
    <span
      className="inline-flex size-4 flex-none items-center justify-center rounded-full border border-line-2 text-[9.5px] font-medium text-fg-faint tabular-nums"
      aria-label="Pending"
    >
      {step.index}
    </span>
  )
}

function Round0PipelineSummary({
  state,
  exchanges,
  requestsUsed,
}: {
  state: Round0PipelineState
  exchanges: readonly { id: string }[]
  requestsUsed: number
}) {
  const [showAllHosts, setShowAllHosts] = useState(false)
  const [networkOpen, setNetworkOpen] = useState(false)
  const apex = useMemo(() => sharedApex(state.hosts.map(h => h.host)), [state.hosts])
  const visibleHosts = showAllHosts ? state.hosts : state.hosts.slice(0, ROUND0_HOST_PREVIEW)
  const hiddenHostCount = Math.max(0, state.hosts.length - ROUND0_HOST_PREVIEW)
  const totalRequests = Math.max(requestsUsed, state.counts.requests, exchanges.length)

  return <>
    <Section
      title="Recon pipeline"
      right={<span className="tabular-nums">{state.doneSteps}/5 complete</span>}
    >
      <ol
        className="m-0 mb-2 flex list-none flex-col gap-1 p-0"
        data-testid="round0-stage-stepper"
      >
        {state.steps.map(step => {
          const active = step.status === 'active'
          return (
            <li
              key={step.id}
              data-testid={`round0-stage-${step.id}`}
              data-stage-status={step.status}
              className={cn(
                'flex items-center gap-2 rounded-[7px] px-2 py-1.5 text-[12px] leading-[17px]',
                active
                  ? 'bg-accent-soft/60 text-fg shadow-[inset_0_0_0_1px_var(--accent-line)]'
                  : 'bg-transparent text-fg-muted',
              )}
            >
              <Round0StepIcon step={step} />
              <span
                className={cn(
                  'min-w-0 flex-1 truncate',
                  active ? 'font-medium text-fg' : step.status === 'done' ? 'text-fg-muted' : 'text-fg-subtle',
                )}
              >
                {step.index}. {step.label}
              </span>
              {step.metric && (
                <span
                  className={cn(
                    'flex-none font-mono text-[10.5px] tabular-nums whitespace-nowrap',
                    active ? 'text-accent font-medium' : 'text-fg-subtle',
                  )}
                >
                  {step.metric}
                </span>
              )}
            </li>
          )
        })}
      </ol>
      {state.activeDetail && (
        <p className="mb-2! truncate font-mono text-[11px]! text-fg-subtle!" title={state.activeDetail}>
          {state.activeDetail}
        </p>
      )}
    </Section>

    <Section title="Discovered so far">
      <div
        className="mb-2 grid grid-cols-2 gap-1.5 sm:grid-cols-3"
        data-testid="round0-discovery-counters"
      >
        {[
          { label: 'Endpoints', value: fmtN(state.counts.endpoints) },
          {
            label: 'Active hosts',
            value: state.counts.totalHosts > 0
              ? `${fmtN(state.counts.mappedHosts)} / ${fmtN(state.counts.totalHosts)}`
              : fmtN(state.counts.mappedHosts),
          },
          { label: 'Auth-gated', value: fmtN(state.counts.authGated), hint: '401/403' },
          { label: 'Privileged', value: fmtN(state.counts.privileged) },
          { label: 'Requests', value: fmtN(totalRequests) },
          { label: 'Parameters', value: fmtN(state.counts.params) },
        ].map(stat => (
          <div
            key={stat.label}
            className="min-w-0 rounded-[7px] bg-sunk px-2.5 py-1.5 shadow-[inset_0_0_0_1px_var(--line)]"
          >
            <div className="truncate text-[11px] leading-4 text-fg-subtle" data-round0-stat-label="">
              {stat.label}
            </div>
            <div className="mt-0.5 flex items-baseline gap-1.5 truncate text-[13.5px] font-semibold leading-[18px] text-fg tabular-nums">
              <span className="truncate">{stat.value}</span>
              {stat.hint && <span className="flex-none font-mono text-[10px] font-normal text-fg-faint">{stat.hint}</span>}
            </div>
          </div>
        ))}
      </div>
      {state.frameworks.length > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-1" data-testid="round0-frameworks">
          <span className="mr-0.5 text-[11px] text-fg-subtle">Frameworks</span>
          {state.frameworks.map(fw => <Tag key={fw} tone="solid" mono>{fw}</Tag>)}
        </div>
      )}
    </Section>

    <Section
      title="Top hosts by signal"
      right={<span className="tabular-nums">{fmtN(state.hosts.length)}</span>}
    >
      {state.hosts.length === 0 ? (
        <p className={WF_NONE}>Waiting for host probes…</p>
      ) : (
        <div className="mb-2" data-testid="round0-top-hosts">
          <div className="divide-y divide-line overflow-hidden rounded-[7px] border border-line bg-panel">
            {visibleHosts.map(h => (
              <div
                key={h.origin}
                data-testid="round0-host-row"
                className="flex min-h-[30px] items-center gap-2 px-2.5 py-1 text-[11.5px]"
              >
                <span className="min-w-0 flex-1 font-mono text-[11.5px]">
                  <HostLabel host={h.host} apex={apex} max={24} />
                </span>
                <span className="flex-none font-mono text-[11px] text-fg-muted tabular-nums">
                  {fmtN(h.endpoints)} ep
                </span>
                <span className="flex-none font-mono text-[11px] text-fg-subtle tabular-nums">
                  {fmtN(h.requests)} req
                </span>
                {(h.status401 > 0 || h.status403 > 0 || h.status5xx > 0 || h.privileged > 0) && (
                  <span className="flex flex-none items-center gap-1">
                    {h.status401 > 0 && (
                      <span className="rounded bg-sunk px-1 py-px font-mono text-[10px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)] tabular-nums" title={`${h.status401} HTTP 401 responses`}>
                        401·{h.status401}
                      </span>
                    )}
                    {h.status403 > 0 && (
                      <span className="rounded bg-warn-soft px-1 py-px font-mono text-[10px] text-warn shadow-[inset_0_0_0_1px_var(--warn-line)] tabular-nums" title={`${h.status403} HTTP 403 responses`}>
                        403·{h.status403}
                      </span>
                    )}
                    {h.status5xx > 0 && (
                      <span className="rounded bg-danger-soft px-1 py-px font-mono text-[10px] text-danger tabular-nums" title={`${h.status5xx} HTTP 5xx responses`}>
                        5xx·{h.status5xx}
                      </span>
                    )}
                    {h.privileged > 0 && h.status401 === 0 && h.status403 === 0 && (
                      <span className="rounded bg-accent-soft px-1 py-px font-mono text-[10px] text-accent tabular-nums" title={`${h.privileged} privileged routes`}>
                        priv·{h.privileged}
                      </span>
                    )}
                  </span>
                )}
              </div>
            ))}
          </div>
          {hiddenHostCount > 0 && (
            <button
              type="button"
              data-testid="round0-hosts-toggle"
              className="mt-1.5 flex h-auto w-full cursor-pointer items-center justify-center gap-1 whitespace-normal rounded-[6px] border-0 bg-sunk px-2.5 py-1.5 text-[11.5px] font-medium text-fg-muted shadow-none transition-colors duration-[var(--d1)] hover:bg-hover hover:text-fg"
              onClick={() => setShowAllHosts(v => !v)}
              aria-expanded={showAllHosts}
            >
              {showAllHosts ? `Show top ${ROUND0_HOST_PREVIEW} hosts` : `Show all ${fmtN(state.hosts.length)} hosts`}
              <Icon name={showAllHosts ? 'chevU' : 'chevD'} size={11} />
            </button>
          )}
        </div>
      )}
    </Section>

    <div className="mt-1 border-t border-line" data-testid="round0-network-drawer">
      <button
        type="button"
        data-testid="round0-network-log-toggle"
        className="flex h-auto min-h-[34px] w-full cursor-pointer items-center gap-1.5 whitespace-normal rounded-none border-0 bg-transparent px-0 py-1.5 text-left text-[12px] font-medium text-fg-muted shadow-none transition-colors duration-[var(--d1)] hover:bg-transparent hover:text-fg"
        onClick={() => setNetworkOpen(o => !o)}
        aria-expanded={networkOpen}
      >
        <Icon
          name="chev"
          className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', !networkOpen && '-rotate-90')}
        />
        <span>Network log ({plural(totalRequests, 'request')})</span>
        {exchanges.length > 0 && exchanges.length < totalRequests && (
          <span className="ml-auto text-[11px] font-normal text-fg-subtle tabular-nums">
            {fmtN(exchanges.length)} loaded
          </span>
        )}
      </button>
      {networkOpen && (
        <div className="pb-2 pt-0.5" data-testid="round0-network-log-panel">
          {exchanges.length > 0
            ? <ExchangeRows list={exchanges} />
            : <p className={WF_NONE}>No HTTP requests recorded in the loaded window yet.</p>}
        </div>
      )}
    </div>
  </>
}

// ---------------------------------------------------------------- worker

type ITab = 'summary' | 'transcript' | 'evidence'

export function WorkerInspector({ sel }: InspectorProps) {
  const { detail, events } = useRun()
  const model = useRunModel()
  const L = useWorkflowLayout()
  const expanded = useExpanded(detail.run.id)
  const [tab, setTab] = useViewState<ITab>('wf.itab', 'summary')
  const a = model.workerById.get(sel.id)
  const session = useWorkerSession(detail.run.id, a)
  const round0 = useMemo(
    () => (a && isRound0ThreatModelWorker(a) ? deriveRound0PipelineState({ assignment: a, detail, events }) : null),
    [a, detail, events],
  )
  if (!a) {
    return <><PaneHeader title="Worker" sub={<span title={`Worker ${sel.id}`}>Not found</span>} />
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
  const nTurns = session.data ? session.data.turns.length : null
  const failure = a.status === 'failed' && a.outcome ? a.outcome : null
  const nArts = session.data?.artifacts.length ?? 0
  const reqCount = round0 ? round0.counts.requests : a.requestsUsed
  return <>
    <PaneHeader
      title="Worker"
      sub={<span title={`Worker ${a.id} · Started ${fmtFullDateTime(a.createdAt)}`} suppressHydrationWarning>{PHASE_LABEL[a.phase] ?? a.phase} · {fmtAgo(a.createdAt)}</span>}
      extra={<button type="button" className={runIconBtn()} title="Center in graph (↵)" aria-label="Center in graph" onClick={() => requestCamera({ type: 'center', id: rid })}><Icon name="fit" /></button>}
    />
    <PaneBody><div className={RW.detail}>
      <div className={WF_META}>
        <Tag><span className={WF_TG}><LiveGlyph status={a.status} dotClassName="size-[7px]" /></span>{stLabel(a.status)}</Tag>
        <Tag>{PHASE_LABEL[a.phase] ?? a.phase}</Tag>
        {step && <Tag className="tabular-nums">Step #{step.seq} · P{step.priority}</Tag>}
        {step?.category && <Tag>{prettyCat(step.category)}</Tag>}
        {a.attempt > 0 && <Tag>Attempt {a.attempt + 1}</Tag>}
        {hist && <Tag tone="warn">{hist}</Tag>}
      </div>
      <h2 className={WF_H2}>{a.title}</h2>
      {failure && <FailureCallout text={failure} />}
      <Props rows={[
        round0
          ? ['Stage', <span className="inline-flex min-w-0 items-center gap-1.5">
              <Tag tone={isLive(a) ? 'accent' : 'solid'} className="tabular-nums">{round0.stageBadge}</Tag>
              {round0.counts.totalHosts > 0 && <span className="text-[11.5px] text-fg-subtle tabular-nums">{round0.counts.mappedHosts}/{round0.counts.totalHosts} hosts</span>}
            </span>]
          : ['Turns', <><Meter id={'wf.turns.' + a.id} value={pct} warn={isLive(a) && pct > 0.8} /><span className="tabular-nums">{fmtN(a.turnsUsed)} of {fmtN(a.maxTurns)}</span></>],
        ['Requests', <>{fmtN(reqCount)}{exs.length > 0 && <span className="text-fg-subtle">· {exs.length} in the loaded window</span>}</>],
        ...(a.sourceOrigins.length ? [[
          'Origins',
          round0 && a.sourceOrigins.length > 1
            ? <span className="truncate font-mono text-[11.5px]" title={a.sourceOrigins.join('\n')}>
                {host(a.sourceOrigins[0])} <span className="text-fg-subtle">+{a.sourceOrigins.length - 1} more</span>
              </span>
            : <OriginList origins={a.sourceOrigins} title={a.sourceOrigins.join('\n')} />,
        ] as [ReactNode, ReactNode]] : []),
        ['Started', <>{fmtDate(a.createdAt)} <span className="font-mono text-[12px] text-fg-subtle">{fmtRel(a.createdAt, model.base)}</span></>],
        ['Lineage', <>{lin.up.size} upstream · {[...lin.down].filter(x => x !== 'report').length} downstream</>],
      ]} />
      {g && <div className="mb-3 flex items-center gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]">
        <Icon name="workflow" />
        <span>Part of the stack <b className="font-medium text-fg">{g.title}</b> × {g.members.length}</span>
        <button
          type="button"
          className={cn(runBtn({ variant: 'ghost', size: 'sm' }), 'ml-auto')}
          onClick={() => setExpanded(detail.run.id, g.id, !expanded.has(g.id))}
        >
          {expanded.has(g.id) ? 'Collapse' : 'Expand'}
        </button>
      </div>}

      <div
        className="sticky top-0 z-[2] -mx-[18px] mt-1 flex gap-0.5 overflow-visible border-b border-line bg-panel px-[18px] py-2 [&+.rw-sec]:border-t-0"
        role="tablist"
        aria-label="Worker sections"
      >
        {([
          ['summary', 'Summary', null],
          ['transcript', 'Transcript', nTurns ?? '—'],
          ['evidence', 'Evidence', facts.length + exs.length + nArts],
        ] as const).map(([k, label, ct]) => {
          const on = tab === k
          return <button
            key={k}
            type="button"
            role="tab"
            aria-selected={on}
            className={cn(
              'inline-flex h-6 flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 px-[9px] font-sans text-[12.5px] font-medium shadow-none transition-[background-color,color] duration-[var(--d1)]',
              on ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-muted hover:bg-hover hover:text-fg',
            )}
            onClick={() => setTab(k)}
          >
            {label}
            {ct !== null && <span className={cn('font-normal tabular-nums', ct === '—' ? 'text-fg-faint' : 'text-fg-subtle')}>{typeof ct === 'number' ? fmtN(ct) : ct}</span>}
          </button>
        })}
      </div>

      {tab === 'summary' && <>
        {round0 && <Round0PipelineSummary state={round0} exchanges={exs} requestsUsed={a.requestsUsed} />}
        {a.objective && <Section title="Objective"><p>{a.objective}</p></Section>}
        {step?.hypothesis && step.hypothesis !== a.objective && <Section title="Hypothesis"><p>{step.hypothesis}</p>
          {step.skills.length > 0 && <div className="mb-2.5 flex flex-wrap gap-[5px]">{step.skills.map(s => <Tag key={s} mono>{s}</Tag>)}</div>}</Section>}
        {a.outcome && !failure && <Section title="Outcome"><p className="text-fg!">{a.outcome}</p></Section>}
        {ups.length > 0 && <Section title="Upstream" right={ups.length}>{ups.slice(0, 8).map(w => <LineageRow key={w} L={L} id={rid} other={w} />)}</Section>}
        {downs.length > 0 && <Section title="Downstream" right={downs.length}>{downs.slice(0, 8).map(w => <LineageRow key={w} L={L} id={rid} other={w} />)}</Section>}
        {fs.length > 0 && <Section title="Findings" right={fs.length}><FindingRows list={fs} /></Section>}
        {msgs.length > 0 && <Section title="Worker report">{msgs.map(m => <pre key={m.id} className={cn(RW.pre, 'break-words font-sans text-[12.5px] leading-[19px]')}>{m.content}</pre>)}</Section>}
        {!round0 && !a.objective && !a.outcome && !ups.length && !downs.length && !fs.length && !msgs.length && <p className={WF_NONE}>Nothing recorded yet.</p>}
      </>}
      {tab === 'transcript' && <Transcript a={a} s={session} />}
      {tab === 'evidence' && <>
        {facts.length > 0 && <Section title="Facts" right={facts.length}><div className={WF_CTX}>{facts.map(f => <FactItem key={f.id} f={f} />)}</div></Section>}
        <Artifacts s={session} />
        {exs.length > 0 && (
          round0 && exs.length > 20
            ? <Disclosure
                title="Exchanges"
                right={exs.length < reqCount ? `${fmtN(exs.length)} of ${fmtN(reqCount)}` : fmtN(exs.length)}
                defaultOpen={false}
              >
                <ExchangeRows list={exs} />
              </Disclosure>
            : <Section title="Exchanges" right={exs.length < reqCount ? exs.length + ' of ' + fmtN(reqCount) : exs.length}>
                <ExchangeRows list={exs} />
              </Section>
        )}
        {!facts.length && !exs.length && !nArts && <p className={WF_NONE}>{session.loading ? 'Loading…' : 'No facts, artifacts or exchanges recorded by this worker.'}</p>}
      </>}
    </div></PaneBody>
    {step && <CancelFooter step={step} label={<>Step #{step.seq} · {isLive(a) ? stLabel(a.status) : stLabel(step.status)}</>} />}
  </>
}

function ExchangeRows({ list }: { list: readonly { id: string }[] }) {
  return <>{list.slice(0, 40).map(e => <ExchangeLink key={e.id} id={e.id} />)}{list.length > 40 && <p className={WF_MORE}>+{list.length - 40} more in Exchanges</p>}</>
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
    <PaneHeader
      title="Stack"
      sub={PHASE_LABEL[g.phase] ?? g.phase}
      extra={<button type="button" className={runBtn({ variant: 'ghost', size: 'sm' })} onClick={() => setExpanded(detail.run.id, g.id, !exp)}><Icon name={exp ? 'minus' : 'plus'} />{exp ? 'Collapse' : 'Expand'}</button>}
    />
    <PaneBody><div className={RW.detail}>
      <div className={WF_META}>{[...st.entries()].map(([k, n]) => <Tag key={k} className="tabular-nums"><span className={WF_TG}><LiveGlyph status={k} dotClassName="size-[7px]" /></span>{n} {stLabel(k).toLowerCase()}</Tag>)}</div>
      <h2 className={WF_H2}>{g.title} <span className="font-normal text-fg-subtle">× {ms.length}</span></h2>
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
            right={<span className="tabular-nums">{fmtN(a.requestsUsed)} req{nf ? ' · ' + plural(nf, 'finding') : ''}</span>}
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
    <PaneHeader
      title="Queued steps"
      sub={steps.length}
      extra={<button type="button" className={runIconBtn()} title="Center in graph" aria-label="Center in graph" onClick={() => requestCamera({ type: 'center', id: QUEUE_ID })}><Icon name="fit" /></button>}
    />
    <PaneBody><div className={RW.detail}>
      <div className={WF_META}>{[...byStatus.entries()].map(([k, n]) => <Tag key={k} className="tabular-nums"><StatusGlyph status={k} />{n} {stLabel(k).toLowerCase()}</Tag>)}
        {canceled > 0 && <Tag className="tabular-nums"><StatusGlyph status="canceled" />{canceled} canceled</Tag>}</div>
      <h2 className={WF_H2}>Planned chain steps, not yet dispatched</h2>
      <p className="-mt-1 mb-3.5 text-[12.5px] leading-[19px] text-fg-muted">The coordinator queued these steps; each becomes a worker when its dependencies are met and the run is running. Open one to review its hypothesis or cancel it.</p>
      {steps.length ? <Section title="Steps" right={steps.length}>
        {steps.map(s => <LinkRow key={s.id} glyph={<StatusGlyph status={s.status} />} sub={prettyCat(s.category)} trailing="chevR"
          right={<span className="tabular-nums">#{s.seq} · P{s.priority}</span>} onClick={() => nav.select({ kind: 'step', id: s.id }, { push: true })}>{s.title}</LinkRow>)}
      </Section> : <p className={WF_NONE}>Every planned step has been dispatched.</p>}
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
    <PaneBody><div className={RW.detail}>
      <div className={WF_META}>
        <Tag><StatusGlyph status={s.status} />{stLabel(s.status)}</Tag>
        <Tag className="tabular-nums">Step #{s.seq} · P{s.priority}</Tag>
        <Tag>{prettyCat(s.category)}</Tag>
        {s.specialistProfile && <Tag>{s.specialistProfile}</Tag>}
      </div>
      <h2 className={WF_H2}>{s.title}</h2>
      <Props rows={[
        ['Planned', <>{fmtDate(s.createdAt)} <span className="font-mono text-[12px] text-fg-subtle">{fmtRel(s.createdAt, model.base)}</span></>],
        ...(s.sourceOrigins.length ? [['Origins', <OriginList origins={s.sourceOrigins} />] as [ReactNode, ReactNode]] : []),
        ['Scope', 'Revision ' + s.scopeRevision],
      ]} />
      <Section title="Hypothesis"><p>{s.hypothesis}</p>{s.skills.length > 0 && <div className="mb-2.5 flex flex-wrap gap-[5px]">{s.skills.map(k => <Tag key={k} mono>{k}</Tag>)}</div>}</Section>
      {worker && <Section title="Worker"><LinkRow glyph={<LiveGlyph status={worker.status} />} trailing={null} onClick={() => nav.select({ kind: 'worker', id: worker.id }, { push: true })}>{worker.title}</LinkRow></Section>}
      {deps.length > 0 && <Section title="Depends on steps" right={deps.length}>
        {deps.map(d => <LinkRow key={d.id} glyph={<StatusGlyph status={d.status} />} right={<span className="tabular-nums">#{d.seq}</span>} trailing={null}
          onClick={() => nav.select(d.assignedWorkerId ? { kind: 'worker', id: d.assignedWorkerId } : { kind: 'step', id: d.id }, { push: true })}>{d.title}</LinkRow>)}
      </Section>}
      {factDeps.length > 0 && <Section title="Depends on facts" right={factDeps.length}><div className={WF_CTX}>{factDeps.map(f => <FactItem key={f.id} f={f} />)}</div></Section>}
    </div></PaneBody>
    <CancelFooter step={s} />
  </>
}

// ---------------------------------------------------------------- memory summary digest

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
    <PaneHeader title="Memory summary" sub={<span title={`Saved workspace snapshot digest ${d.id}`}>Round {d.roundNo}</span>} />
    <PaneBody><div className={RW.detail}>
      <div className={WF_META}>
        <Tag title="Storage history level">{d.level === 'major' ? 'Major' : 'Minor'} compaction</Tag>
        <Tag tone={d.active ? undefined : 'warn'}>{d.active ? 'Active' : 'Superseded'}</Tag>
      </div>
      <h2 className={WF_H2} title="Saved workspace snapshot digest: compacted summary of older facts">Memory summary · round {d.roundNo}</h2>
      <Props rows={[
        ['Facts', fmtN(d.coveredFactIds.length)],
        ['Workers', fmtN(d.coveredAssignmentIds.length)],
        ['Compacted', <>{fmtDate(d.createdAt)} <span className="font-mono text-[12px] text-fg-subtle">{fmtRel(d.createdAt, model.base)}</span></>],
        ['Signature', <span className="font-mono text-[12px]">{d.signatureHash.slice(0, 16)}</span>],
      ]} />
      <Section title="Summary"><p className="text-fg!">{d.summary}</p></Section>
      <Section title="Covered facts" right={d.coveredFactIds.length}>
        {load.state === 'idle' && <button type="button" className={runBtn()} onClick={fetchFacts}><Icon name="download" />Load covered facts</button>}
        {load.state === 'loading' && <div className={WF_LOAD}><span className={WF_SPIN} />Loading facts…</div>}
        {load.state === 'error' && <p>Could not load the digest’s facts. <button type="button" className={runBtn({ variant: 'link', size: 'none' })} onClick={fetchFacts}>Retry</button></p>}
        {load.state === 'done' && (load.data.facts.length
          ? <div className={WF_CTX}>{load.data.facts.map(f => <div key={f.id} className={WF_CTX_ITEM}>
            <span className="pt-0.5 text-fg-subtle"><Icon name="fact" /></span>
            <div className="min-w-0">
              <div className="text-[11.5px] text-fg-subtle"><b className="font-medium text-fg-muted">{f.kind}</b> · <span className="font-mono text-[11.5px]">{host(f.origin)}</span></div>
              <div className="line-clamp-3 text-fg-muted">{f.summary}</div>
            </div>
          </div>)}</div>
          : <p className={WF_NONE}>No untainted facts remain under this digest.</p>)}
      </Section>
      {workers.length > 0 && <Section title="Covered workers" right={workers.length}>
        {workers.slice(0, 30).map(a => <LinkRow key={a.id} glyph={<LiveGlyph status={a.status} />} right={PHASE_LABEL[a.phase] ?? a.phase} trailing={null}
          onClick={() => nav.select({ kind: 'worker', id: a.id }, { push: true })}>{a.title}</LinkRow>)}
        {workers.length > 30 && <p className={WF_MORE}>+{workers.length - 30} more</p>}
      </Section>}
    </div></PaneBody>
  </>
}
