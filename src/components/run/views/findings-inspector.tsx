// Finding inspector (owned by Agent Q). Opened from Findings, and by every
// cross-link to a finding (Surface, Workflow, Exchanges, palette…).
import { useEffect, useMemo, useState } from 'react'

import { useRun, useRunModel } from '../data.tsx'
import { ACTIONS, useDecisions } from '../decisions.tsx'
import { EmptyState, LinkRow, Props, Section, Tag } from '../display.tsx'
import { cap, fmtDate, fmtTimeS, host, plural } from '../format.ts'
import { SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { covCat, normFStatus, prettyCat, SEV_LABEL, stLabel } from '../meta.ts'
import type { FindingRow } from '../model.ts'
import { useLinks } from '../nav.tsx'
import { ExchangeLink, PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { FoundBy, OnSurface } from './queue-read.tsx'

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

function VerifyFix({ f }: { f: FindingRow }) {
  const { detail, send, pending } = useRun()
  const toast = useToast()
  const [asked, setAsked] = useState(false)
  const replay = detail.replaySpecs.find(r => (f.replaySpecId && r.id === f.replaySpecId) || r.findingId === f.id)
  const retests = detail.retestRuns.filter(r => r.findingId === f.id).slice().sort((a, b) => b.createdAt - a.createdAt)
  const active = detail.assignments.some(a => a.phase === 'retest' && (a.status === 'queued' || a.status === 'running') && (a.stepId === f.id || a.objective.includes(f.id) || (replay && a.objective.includes(replay.id))))
  const can = normFStatus(f.status) === 'confirmed' && Boolean(f.replaySpecId || replay)
  useEffect(() => { if (active) setAsked(false) }, [active])
  if (!replay && !retests.length) return null
  const run = () => {
    setAsked(true)
    toast.undoable({
      message: 'Verify fix queued', sub: 'Replays the spec against the live origin when this closes', icon: 'replay',
      undo: () => setAsked(false),
      commit: async () => { try { await send({ action: 'retest_finding', findingId: f.id }) } catch (e) { setAsked(false); throw e } },
    })
  }
  const diff = replay?.lastVerificationDiff as unknown
  return <Section title="Replay" right={replay ? (replay.verifiedInline ? 'Verified inline' : plural(replay.attemptCount, 'attempt')) : undefined}>
    {replay && <p title={`Replay spec ${replay.id}`}>Automated verification replay over {replay.sourceOrigins.map(host).join(', ')}. Re-sends the recorded HTTP requests directly and checks the response — no AI model involved.</p>}
    {diff != null && <p className="qf-note">Last verification: <span className="mono">{text(diff).slice(0, 240)}</span></p>}
    {retests.map(r => <div key={r.id} className="fretest">
      <StatusGlyph status={RETEST_ST[r.verdict] ?? r.verdict} />
      <div style={{ minWidth: 0 }}><b>{RETEST_L[r.verdict] ?? cap(r.verdict)}</b> <span className="muted">· {fmtDate(r.createdAt)}</span><div className="muted">{r.summary}</div></div>
    </div>)}
    {can && <div className="fverify">
      <button type="button" className="btn" disabled={active || asked || pending > 0} onClick={run}>
        <Icon name="replay" />{active ? 'Verifying fix…' : asked ? 'Queued' : 'Verify fix'}
      </button>
      <span className="muted">Re-runs the replay after you ship a fix.</span>
    </div>}
  </Section>
}

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
  const evs = f.evidenceIds.map(id => model.evidenceById.get(id)).filter(Boolean)
  const qkey = keyOf(f.id)
  const dec = qkey ? q.get(qkey) : undefined
  const superseded = f.supersededByFindingId ? model.findingById.get(f.supersededByFindingId) : undefined
  const obs = f.check?.observed
  const codeLocs = f.codeLocations ?? []
  return <>
    <PaneHeader title="Finding" sub={<span title={`Finding ${f.id}`}>{SEV_LABEL[f.severity] ?? f.severity} · {host(f.origin)}</span>} />
    <PaneBody><div className="d">
      {dec && <div className="banner"><Icon name={ACTIONS[dec.act].icon} />
        <span>{ACTIONS[dec.act].label} by you · {fmtTimeS(dec.at)} · local triage, saved in this browser only</span>
        <button type="button" className="btn ghost" onClick={() => q.reopen(qkey!)}><Icon name="undo" />Move back</button>
      </div>}
      {superseded && <div className="banner"><Icon name="alert" /><span>Superseded by a newer finding.</span>
        <button type="button" className="btn ghost" onClick={() => links.finding(superseded.id)}>Open<Icon name="arrowR" /></button></div>}
      <div className="d-meta">
        <Tag><SevGlyph sev={f.severity} />{SEV_LABEL[f.severity] ?? f.severity}</Tag>
        <Tag tone={st === 'confirmed' ? 'accent' : undefined}><StatusGlyph status={st} />{stLabel(f.status === 'static_verified' ? 'static_verified' : st)}</Tag>
        {f.confidence && <Tag>Confidence {f.confidence}</Tag>}
      </div>
      <h2>{f.title}</h2>
      <Props rows={[
        ['Origin', <span className="mono">{host(f.origin)}</span>, () => links.host(f.origin)],
        ['Category', <span>{prettyCat(f.category)}</span>, cat ? () => links.cell(f.origin, cat) : undefined],
        ['Weakness', <span className="mono">{f.cwe || '—'}</span>],
        ['Kind', <>{chain ? <><Icon name="chain" />Multi-step chain</> : 'Baseline check'}{f.check?.id && !chain && <span className="mono" style={{ color: 'var(--fg-3)' }}>{f.check.id}</span>}</>],
        ...(spans.length > 1 ? [['Spans', <span className="mono fspans">{spans.map(host).join(', ')}</span>] as [string, React.ReactNode]] : []),
        ...(f.verificationTier ? [['Verified', TIER_L[f.verificationTier] ?? cap(f.verificationTier)] as [string, React.ReactNode]] : []),
        ['Evidence', <span className="num">{plural(f.evidenceIds.length, 'record')}{exIds.length ? ' · ' + plural(exIds.length, 'exchange') : ''}</span>],
        ...(qkey && (dec || q.sectionOf(qkey) !== 'done') ? [['Queue', <span>{dec ? ACTIONS[dec.act].label : q.sectionOf(qkey) === 'done' ? 'Done' : 'Open for review'}</span>, () => links.queueItem(qkey)] as [string, React.ReactNode, () => void]] : []),
      ]} />
      {f.check && (f.check.expected || obs !== undefined) && <Section title="Check" right="Expected vs observed">
        <div className="cmp">
          <div><span>Expected</span><span>{f.check.expected || '—'}</span></div>
          <div><span>Observed</span><span className="obs mono">{obs == null ? <span className="fnoobs">No observation</span> : text(obs)}</span></div>
        </div>
      </Section>}
      {f.reason && <Section title={st === 'confirmed' ? 'Observation' : 'Reason'}><p>{f.reason}</p></Section>}
      {f.impact && <Section title="Impact"><p>{f.impact}</p></Section>}
      {f.remediation && <Section title="Remediation"><p>{f.remediation}</p>{f.recheck && <p><b className="ctx-strong">Recheck.</b> {f.recheck}</p>}</Section>}
      {f.verification && <Section title="Verification"><p>{f.verification}</p></Section>}
      <VerifyFix f={f} />
      {f.counterevidence && <Section title="Counterevidence"><p>{f.counterevidence}</p></Section>}
      {(f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap) && <Section title="Confidence">
        {f.confidenceRationale && <p>{f.confidenceRationale}</p>}
        {f.severityChangeConditions && <p><b className="ctx-strong">Severity would change if</b> {f.severityChangeConditions}</p>}
        {f.runtimeProofGap && <p><b className="ctx-strong">Runtime proof gap.</b> {f.runtimeProofGap}</p>}
      </Section>}
      {codeLocs.length > 0 && <Section title="Code locations" right={<span className="num">{codeLocs.length}</span>}>
        {codeLocs.map((c, i) => <div key={i} className="floc">
          <div className="floc-h mono"><Icon name="node" /><span className="p">{c.repo}/{c.file}</span><span className="r num">L{c.startLine}{c.endLine !== c.startLine ? '–' + c.endLine : ''}</span></div>
          {c.label && <div className="floc-l">{c.label}</div>}
          {c.snippet && <pre className="block mono">{c.snippet}</pre>}
        </div>)}
      </Section>}
      <FoundBy workers={model.findingWorkers.get(f.id) ?? []} />
      {cat && <OnSurface origin={f.origin} category={cat} />}
      {exIds.length > 0 && <Section title="Exchanges" right={<span className="num">{exIds.length}</span>}>
        {exIds.slice(0, 12).map(id => <ExchangeLink key={id} id={id} />)}
        {exIds.length > 12 && <p className="qf-note">+{exIds.length - 12} more cited exchanges</p>}
      </Section>}
      {evs.length > 0 && <Section title="Evidence records" right={<span className="num">{evs.length}</span>}>
        {evs.slice(0, 8).map(e => <LinkRow key={e!.id} icon="fact" right={e!.kind} trailing={null} onClick={() => links.evidence(e!.id)}>{e!.title}</LinkRow>)}
      </Section>}
    </div></PaneBody>
  </>
}
