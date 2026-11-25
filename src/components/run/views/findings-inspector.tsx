// Finding inspector (owned by Agent Q). Opened from Findings, and by every
// cross-link to a finding (Surface, Workflow, Exchanges, palette…).
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { useRun, useRunModel } from '../data.tsx'
import { ACTIONS, useDecisions } from '../decisions.tsx'
import type { DecisionAct } from '../decisions.tsx'
import { Disclosure, EmptyState, LinkRow, Props, Section, Tag } from '../display.tsx'
import { cap, fmtDate, fmtTimeS, host, plural } from '../format.ts'
import { SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { IconName } from '../icons.tsx'
import { covCat, normFStatus, prettyCat, SEV_LABEL, stLabel } from '../meta.ts'
import type { FindingRow } from '../model.ts'
import { useLinks } from '../nav.tsx'
import { ExchangeLink, PaneBody, PaneFooter, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, RW } from '../tw.ts'
import { CodeLocations, CopyCurlButton, FoundBy, OnSurface } from './queue-read.tsx'

/** finding id → the queue item key that carries it (bundles map every member). */
export function useFindingQueueKey() {
  const model = useRunModel()
  const map = useMemo(() => {
    const m = new Map<string, string>()
    for (const it of model.queueItem.values()) if (it.kind === 'finding') for (const f of it.list) m.set(f.id, it.key)
    return m
  }, [model])
  return (id: string) => map.get(id) ?? null
}

const TIER_L: Record<string, string> = { runtime_confirmed: 'Runtime confirmed', static_verified: 'Statically verified', baseline_confirmed: 'Baseline confirmed' }
const RETEST_L: Record<string, string> = { reproduced: 'Still reproducible', fixed: 'Verified fixed', inconclusive: 'Inconclusive' }
const RETEST_ST: Record<string, string> = { reproduced: 'failed', fixed: 'confirmed', inconclusive: 'inconclusive' }

const text = (v: unknown) => v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v)

/** Primary action row inside Beat 3 ("How to fix & verify"): Copy as cURL + Verify fix + retest history. */
function FixVerifyActions({ f, primaryExchangeId }: { f: FindingRow; primaryExchangeId?: string }) {
  const { detail, send, pending } = useRun()
  const toast = useToast()
  const [asked, setAsked] = useState(false)
  const replay = detail.replaySpecs.find(r => (f.replaySpecId && r.id === f.replaySpecId) || r.findingId === f.id)
  const retests = detail.retestRuns.filter(r => r.findingId === f.id).slice().sort((a, b) => b.createdAt - a.createdAt)
  const active = detail.assignments.some(a => a.phase === 'retest' && (a.status === 'queued' || a.status === 'running') && (a.stepId === f.id || a.objective.includes(f.id) || (replay && a.objective.includes(replay.id))))
  const can = normFStatus(f.status) === 'confirmed' && Boolean(f.replaySpecId || replay)
  useEffect(() => { if (active) setAsked(false) }, [active])
  if (!primaryExchangeId && !can && !retests.length) return null
  const run = () => {
    setAsked(true)
    toast.undoable({
      message: 'Verify fix queued', sub: 'Replays the check against the live origin when this closes', icon: 'replay',
      undo: () => setAsked(false),
      commit: async () => { try { await send({ action: 'retest_finding', findingId: f.id }) } catch (e) { setAsked(false); throw e } },
    })
  }
  return <>
    {(primaryExchangeId || can) && <div className="mb-2.5 mt-2 flex flex-wrap items-center gap-2">
      <CopyCurlButton exchangeId={primaryExchangeId} />
      {can && <button type="button" className={runBtn()} disabled={active || asked || pending > 0} onClick={run} title="Re-run automated replay after shipping a fix">
        <Icon name="replay" />{active ? 'Verifying fix…' : asked ? 'Queued' : 'Verify fix'}
      </button>}
    </div>}
    {retests.length > 0 && <div className="divide-y divide-dashed divide-line">
      {retests.map(r => <div key={r.id} className="grid grid-cols-[14px_minmax(0,1fr)] gap-2 py-1.5 text-[12px] leading-[18px] text-fg-muted">
        <StatusGlyph status={RETEST_ST[r.verdict] ?? r.verdict} />
        <div className="min-w-0">
          <b className="font-medium text-fg">{RETEST_L[r.verdict] ?? cap(r.verdict)}</b>{' '}
          <span className="text-fg-subtle">· {fmtDate(r.createdAt)}</span>
          <div className="text-fg-subtle">{r.summary}</div>
        </div>
      </div>)}
    </div>}
  </>
}

const TRIAGE_BTNS: [DecisionAct, string, IconName][] = [
  ['accept', 'Accept', 'check'],
  ['dismiss', 'Dismiss', 'archive'],
  ['fp', 'False positive', 'slash'],
]

export function FindingInspector({ sel }: InspectorProps) {
  const model = useRunModel()
  const links = useLinks()
  const q = useDecisions()
  const keyOf = useFindingQueueKey()
  const f = model.findingById.get(sel.id)
  if (!f) {
    return <>
      <PaneHeader title="Finding" sub={<span title={`Finding ${sel.id}`}>Not found</span>} />
      <PaneBody><EmptyState icon="findings" title="Finding not found">It may have been superseded since the run refreshed.</EmptyState></PaneBody>
    </>
  }
  const st = normFStatus(f.status)
  const cat = covCat(f.category)
  const chain = f.findingKind === 'multi_step_chain'
  const replay = model.detail.replaySpecs.find(r => (f.replaySpecId && r.id === f.replaySpecId) || r.findingId === f.id)
  const spans = replay?.sourceOrigins ?? []
  const exIds = f.exchangeIds ?? []
  const primaryExchangeId = exIds[0] ?? (model.exchangesByOrigin.get(f.origin)?.find(e => e.pathAndQuery === '/' && e.method === 'GET') ?? model.exchangesByOrigin.get(f.origin)?.[0])?.id
  const evs = f.evidenceIds.map(id => model.evidenceById.get(id)).filter(Boolean)
  const workers = model.findingWorkers.get(f.id) ?? []
  const qkey = keyOf(f.id)
  const dec = qkey ? q.get(qkey) : undefined
  const superseded = f.supersededByFindingId ? model.findingById.get(f.supersededByFindingId) : undefined
  const obs = f.check?.observed
  const codeLocs = f.codeLocations ?? []
  const diff = replay?.lastVerificationDiff as unknown
  const canTriage = Boolean(qkey && !dec && (st === 'pending' || st === 'inconclusive') && q.sectionOf(qkey) !== 'done')

  const hasTechnicalDetails = Boolean(
    f.verification || replay || diff != null || f.counterevidence
    || f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap
    || workers.length || cat || exIds.length || evs.length,
  )
  const techSummary = [
    exIds.length ? plural(exIds.length, 'exchange') : '',
    evs.length ? plural(evs.length, 'record') : '',
  ].filter(Boolean).join(' · ')

  const bannerCls = 'mb-3 flex items-center gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]'

  return <>
    <PaneHeader title="Finding" sub={<span title={`Finding ${f.id}`}>{SEV_LABEL[f.severity] ?? f.severity} · {host(f.origin)}</span>} />
    <div className="flex min-h-0 flex-1 flex-col">
      <PaneBody><div className={cn(RW.detail, 'pb-6')}>
        {dec && <div className={bannerCls}><Icon name={ACTIONS[dec.act].icon} />
          <span>{ACTIONS[dec.act].label} · {fmtTimeS(dec.at)} · Saved locally in this browser</span>
          <button type="button" className={cn(runBtn({ variant: 'ghost' }), 'ml-auto')} onClick={() => q.reopen(qkey!)}><Icon name="undo" />Move back</button>
        </div>}
        {superseded && <div className={bannerCls}><Icon name="alert" /><span>Superseded by a newer finding.</span>
          <button type="button" className={cn(runBtn({ variant: 'ghost' }), 'ml-auto')} onClick={() => links.finding(superseded.id)}>Open<Icon name="arrowR" /></button></div>}
        <div className="mb-2.5 flex flex-wrap gap-1.5">
          <Tag><SevGlyph sev={f.severity} />{SEV_LABEL[f.severity] ?? f.severity}</Tag>
          <Tag tone={st === 'confirmed' ? 'accent' : undefined}><StatusGlyph status={st} />{stLabel(f.status === 'static_verified' ? 'static_verified' : st)}</Tag>
        </div>
        <h2 className="m-0 mb-3 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg">{f.title}</h2>
        <Props rows={[
          ['Origin', <span className="font-mono text-[12px]">{host(f.origin)}</span>, () => links.host(f.origin)],
          ['Category', <span>{prettyCat(f.category)}</span>, cat ? () => links.cell(f.origin, cat) : undefined],
          ...(f.cwe ? [['Weakness', <span className="font-mono text-[12px]">{f.cwe}</span>] as [string, ReactNode]] : []),
          ...(f.verificationTier ? [['Verified', TIER_L[f.verificationTier] ?? cap(f.verificationTier)] as [string, ReactNode]] : []),
          ...(spans.length > 1 ? [['Spans', <span className="rw-wrap break-all whitespace-normal font-mono text-[11.5px]">{spans.map(host).join(', ')}</span>] as [string, ReactNode]] : []),
          ...(qkey && (dec || q.sectionOf(qkey) !== 'done') ? [['Queue', <span>{dec ? ACTIONS[dec.act].label : 'Open for review'}</span>, () => links.queueItem(qkey)] as [string, ReactNode, () => void]] : []),
        ]} />

        {(f.reason || (f.check && (f.check.expected || obs !== undefined))) && <Section title="What happened">
          {f.reason && <p className="text-fg!">{f.reason}</p>}
          {f.check && (f.check.expected || obs !== undefined) && <div className={cn(RW.cmp, 'divide-y divide-line')}>
            <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
              <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Expected</span>
              <span className="min-w-0 px-2.5 py-[7px] text-fg-muted">{f.check.expected || '—'}</span>
            </div>
            <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
              <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Observed</span>
              <span className="min-w-0 break-words px-2.5 py-[7px] font-mono text-[12px] text-fg">
                {obs == null ? <span className="font-sans text-fg-subtle">No observation</span> : text(obs)}
              </span>
            </div>
          </div>}
        </Section>}

        {f.impact && <Section title="Why it matters">
          <p>{f.impact}</p>
        </Section>}

        {(f.remediation || f.recheck || codeLocs.length > 0 || primaryExchangeId || replay) && <Section title="How to fix & verify">
          {f.remediation && <p>{f.remediation}</p>}
          {f.recheck && <p><b className="font-medium text-fg">Recheck.</b> {f.recheck}</p>}
          <CodeLocations codeLocs={codeLocs} />
          <FixVerifyActions f={f} primaryExchangeId={primaryExchangeId} />
        </Section>}

        {hasTechnicalDetails && <Disclosure title="Technical details & raw evidence" right={techSummary || undefined}>
          <Props rows={[
            ['Kind', <>{chain ? <><Icon name="chain" />Multi-step chain</> : 'Baseline check'}{f.check?.id && !chain && <span className="font-mono text-[12px] text-fg-subtle">{f.check.id}</span>}</>],
            ...(f.confidence ? [['Confidence', cap(f.confidence)] as [string, ReactNode]] : []),
          ]} />
          {f.verification && <Section title="Verification"><p>{f.verification}</p></Section>}
          {replay && <Section title="Automated replay" right={replay.verifiedInline ? 'Verified inline' : plural(replay.attemptCount, 'attempt')}>
            <p title={`Replay spec ${replay.id}`}>Automated replay over {replay.sourceOrigins.map(host).join(', ')}. Re-sends the recorded HTTP requests directly and compares control vs. variant responses.</p>
            {diff != null && <pre className={RW.pre}>{text(diff)}</pre>}
          </Section>}
          {f.counterevidence && <Section title="Counterevidence"><p>{f.counterevidence}</p></Section>}
          {(f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap) && <Section title="Confidence & proof">
            {f.confidenceRationale && <p>{f.confidenceRationale}</p>}
            {f.severityChangeConditions && <p><b className="font-medium text-fg">Severity would change if</b> {f.severityChangeConditions}</p>}
            {f.runtimeProofGap && <p><b className="font-medium text-fg">Runtime proof gap.</b> {f.runtimeProofGap}</p>}
          </Section>}
          <FoundBy workers={workers} />
          {cat && <OnSurface origin={f.origin} category={cat} />}
          {exIds.length > 0 && <Section title="Exchanges" right={<span className="tabular-nums">{exIds.length}</span>}>
            {exIds.slice(0, 12).map(id => <ExchangeLink key={id} id={id} />)}
            {exIds.length > 12 && <p className="mb-1.5! mt-0.5! text-[12px]! text-fg-subtle!">+{exIds.length - 12} more cited exchanges</p>}
          </Section>}
          {evs.length > 0 && <Section title="Evidence records" right={<span className="tabular-nums">{evs.length}</span>}>
            {evs.slice(0, 8).map(e => <LinkRow key={e!.id} icon="fact" right={e!.kind} trailing={null} onClick={() => links.evidence(e!.id)}>{e!.title}</LinkRow>)}
          </Section>}
        </Disclosure>}
      </div></PaneBody>
      {canTriage && <PaneFooter>
        {TRIAGE_BTNS.map(([act, label, ico], idx) => <button
          key={act}
          type="button"
          className={runBtn({ variant: idx === 0 ? 'default' : 'ghost' })}
          title="Saved locally in this browser"
          onClick={() => q.decide(qkey!, act, { sub: 'Saved locally in this browser' })}
        >
          <Icon name={ico} />{label}
        </button>)}
        <span className="flex-1" />
        <span className="text-[11.5px] text-fg-subtle">Local triage</span>
      </PaneFooter>}
    </div>
  </>
}
