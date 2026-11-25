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
import { CopyCurlButton, FoundBy, OnSurface } from './queue-read.tsx'

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
    {(primaryExchangeId || can) && <div className="fverify">
      <CopyCurlButton exchangeId={primaryExchangeId} />
      {can && <button type="button" className="btn" disabled={active || asked || pending > 0} onClick={run} title="Re-run automated replay after shipping a fix">
        <Icon name="replay" />{active ? 'Verifying fix…' : asked ? 'Queued' : 'Verify fix'}
      </button>}
    </div>}
    {retests.map(r => <div key={r.id} className="fretest">
      <StatusGlyph status={RETEST_ST[r.verdict] ?? r.verdict} />
      <div style={{ minWidth: 0 }}><b>{RETEST_L[r.verdict] ?? cap(r.verdict)}</b> <span className="muted">· {fmtDate(r.createdAt)}</span><div className="muted">{r.summary}</div></div>
    </div>)}
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

  return <>
    <PaneHeader title="Finding" sub={<span title={`Finding ${f.id}`}>{SEV_LABEL[f.severity] ?? f.severity} · {host(f.origin)}</span>} />
    <div className="read">
      <PaneBody><div className="d">
        {dec && <div className="banner"><Icon name={ACTIONS[dec.act].icon} />
          <span>{ACTIONS[dec.act].label} · {fmtTimeS(dec.at)} · Saved locally in this browser</span>
          <button type="button" className="btn ghost" onClick={() => q.reopen(qkey!)}><Icon name="undo" />Move back</button>
        </div>}
        {superseded && <div className="banner"><Icon name="alert" /><span>Superseded by a newer finding.</span>
          <button type="button" className="btn ghost" onClick={() => links.finding(superseded.id)}>Open<Icon name="arrowR" /></button></div>}
        <div className="d-meta">
          <Tag><SevGlyph sev={f.severity} />{SEV_LABEL[f.severity] ?? f.severity}</Tag>
          <Tag tone={st === 'confirmed' ? 'accent' : undefined}><StatusGlyph status={st} />{stLabel(f.status === 'static_verified' ? 'static_verified' : st)}</Tag>
        </div>
        <h2>{f.title}</h2>
        <Props rows={[
          ['Origin', <span className="mono">{host(f.origin)}</span>, () => links.host(f.origin)],
          ['Category', <span>{prettyCat(f.category)}</span>, cat ? () => links.cell(f.origin, cat) : undefined],
          ...(f.cwe ? [['Weakness', <span className="mono">{f.cwe}</span>] as [string, ReactNode]] : []),
          ...(f.verificationTier ? [['Verified', TIER_L[f.verificationTier] ?? cap(f.verificationTier)] as [string, ReactNode]] : []),
          ...(spans.length > 1 ? [['Spans', <span className="mono fspans">{spans.map(host).join(', ')}</span>] as [string, ReactNode]] : []),
          ...(qkey && (dec || q.sectionOf(qkey) !== 'done') ? [['Queue', <span>{dec ? ACTIONS[dec.act].label : 'Open for review'}</span>, () => links.queueItem(qkey)] as [string, ReactNode, () => void]] : []),
        ]} />

        {(f.reason || (f.check && (f.check.expected || obs !== undefined))) && <Section title="What happened">
          {f.reason && <p className="lead">{f.reason}</p>}
          {f.check && (f.check.expected || obs !== undefined) && <div className="cmp">
            <div><span>Expected</span><span>{f.check.expected || '—'}</span></div>
            <div><span>Observed</span><span className="obs mono">{obs == null ? <span className="fnoobs">No observation</span> : text(obs)}</span></div>
          </div>}
        </Section>}

        {f.impact && <Section title="Why it matters">
          <p>{f.impact}</p>
        </Section>}

        {(f.remediation || f.recheck || codeLocs.length > 0 || primaryExchangeId || replay) && <Section title="How to fix & verify">
          {f.remediation && <p>{f.remediation}</p>}
          {f.recheck && <p><b className="ctx-strong">Recheck.</b> {f.recheck}</p>}
          {codeLocs.length > 0 && <div className="floc-list">
            {codeLocs.map((c, i) => <div key={i} className="floc">
              <div className="floc-h mono"><Icon name="node" /><span className="p">{c.repo}/{c.file}</span><span className="r num">L{c.startLine}{c.endLine !== c.startLine ? '–' + c.endLine : ''}</span></div>
              {c.label && <div className="floc-l">{c.label}</div>}
              {c.snippet && <pre className="block mono">{c.snippet}</pre>}
            </div>)}
          </div>}
          <FixVerifyActions f={f} primaryExchangeId={primaryExchangeId} />
        </Section>}

        {hasTechnicalDetails && <Disclosure title="Technical details & raw evidence" right={techSummary || undefined}>
          <Props rows={[
            ['Kind', <>{chain ? <><Icon name="chain" />Multi-step chain</> : 'Baseline check'}{f.check?.id && !chain && <span className="mono" style={{ color: 'var(--fg-3)' }}>{f.check.id}</span>}</>],
            ...(f.confidence ? [['Confidence', cap(f.confidence)] as [string, ReactNode]] : []),
          ]} />
          {f.verification && <Section title="Verification"><p>{f.verification}</p></Section>}
          {replay && <Section title="Automated replay" right={replay.verifiedInline ? 'Verified inline' : plural(replay.attemptCount, 'attempt')}>
            <p title={`Replay spec ${replay.id}`}>Automated replay over {replay.sourceOrigins.map(host).join(', ')}. Re-sends the recorded HTTP requests directly and compares control vs. variant responses.</p>
            {diff != null && <pre className="block mono">{text(diff)}</pre>}
          </Section>}
          {f.counterevidence && <Section title="Counterevidence"><p>{f.counterevidence}</p></Section>}
          {(f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap) && <Section title="Confidence & proof">
            {f.confidenceRationale && <p>{f.confidenceRationale}</p>}
            {f.severityChangeConditions && <p><b className="ctx-strong">Severity would change if</b> {f.severityChangeConditions}</p>}
            {f.runtimeProofGap && <p><b className="ctx-strong">Runtime proof gap.</b> {f.runtimeProofGap}</p>}
          </Section>}
          <FoundBy workers={workers} />
          {cat && <OnSurface origin={f.origin} category={cat} />}
          {exIds.length > 0 && <Section title="Exchanges" right={<span className="num">{exIds.length}</span>}>
            {exIds.slice(0, 12).map(id => <ExchangeLink key={id} id={id} />)}
            {exIds.length > 12 && <p className="qf-note">+{exIds.length - 12} more cited exchanges</p>}
          </Section>}
          {evs.length > 0 && <Section title="Evidence records" right={<span className="num">{evs.length}</span>}>
            {evs.slice(0, 8).map(e => <LinkRow key={e!.id} icon="fact" right={e!.kind} trailing={null} onClick={() => links.evidence(e!.id)}>{e!.title}</LinkRow>)}
          </Section>}
        </Disclosure>}
      </div></PaneBody>
      {canTriage && <PaneFooter>
        {TRIAGE_BTNS.map(([act, label, ico], idx) => <button key={act} type="button" className={idx === 0 ? 'btn' : 'btn ghost'}
          title="Saved locally in this browser"
          onClick={() => q.decide(qkey!, act, { sub: 'Saved locally in this browser' })}>
          <Icon name={ico} />{label}
        </button>)}
        <span className="sp" />
        <span className="muted" style={{ fontSize: 11.5 }}>Local triage</span>
      </PaneFooter>}
    </div>
  </>
}
