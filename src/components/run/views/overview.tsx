// Overview (B's written verdict at A's density). Waiting runs render the consent sheet.
import { useMemo, useState } from 'react'
import type { CSSProperties } from 'react'
import { capabilityTierMeta } from '../../run-state.ts'
import { useRun, useRunModel, useVerdict } from '../data.tsx'
import { useDecisions } from '../decisions.tsx'
import { HostLabel } from '../display.tsx'
import { fmtDate, fmtN, fmtTime, fmtTok, host, plural } from '../format.ts'
import { CovSwatch, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { PHASE_LABEL, SEV, SEV_COL, SEV_LABEL } from '../meta.ts'
import type { ViewId } from '../meta.ts'
import { bySeriousness, coverageCounts, trafficHistogram } from '../model.ts'
import { AnimatedNumber, Meter } from '../motion.tsx'
import { useLinks, useNav } from '../nav.tsx'
import { ConsentView } from './consent.tsx'
import { LabPanel } from './lab.tsx'

export function OverviewView() {
  const { detail } = useRun()
  // Keyed so the scope draft restarts when discovery consent turns into scope review.
  if (detail.run.status === 'waiting') return <ConsentView key={detail.run.phase + ':' + detail.run.scopeRevision} />
  return <RunOverview />
}

function Go({ to, children }: { to: ViewId; children: string }) {
  const nav = useNav()
  return <button type="button" className="go" onClick={() => nav.setView(to)}>{children}<Icon name="arrowR" /></button>
}

function RunOverview() {
  const { detail, counts, events } = useRun()
  const model = useRunModel()
  const v = useVerdict()
  const q = useDecisions()
  const nav = useNav()
  const links = useLinks()
  const r = detail.run
  const n = v.n
  const rep = model.report
  const [goalOpen, setGoalOpen] = useState(false)
  const live = r.status !== 'complete'

  const tally = SEV.map(s => [s, n[s] ?? 0] as const)
  const maxT = Math.max(1, ...tally.map(t => t[1]))
  const segT = v.conf.seg.reduce((a, s) => a + s[0], 0) || 1
  const worst = v.worst
  const goal = r.goal || ''
  const long = goal.length > 260
  const done = detail.assignments.filter(a => a.status === 'complete').length
  const runningWorkers = useMemo(() => detail.assignments.filter(a => a.status === 'running'), [detail.assignments])
  const top = useMemo(() => model.findings.filter(f => f.status !== 'dismissed').slice().sort(bySeriousness).slice(0, 7), [model])
  const hist = useMemo(() => trafficHistogram(model, events), [model, events])
  const cov = coverageCounts(detail.coverageEntries)
  const s = q.sections
  const needsAny = s.decide.length + s.review.length + s.follow.length > 0

  const openQueue = (sec: 'decide' | 'review' | 'follow') => {
    const first = s[sec][0] ?? s.decide[0] ?? s.review[0] ?? s.follow[0]
    if (first) nav.open('queue', { kind: 'queue', id: first.key }, { push: false })
    else nav.setView('queue')
  }

  const phases = model.workflow.phases
  const maxP = Math.max(1, ...phases.map(p => model.workflow.byPhase.get(p)?.length ?? 0))
  const liveSummary = runningWorkers.length > 0
    ? runningWorkers.slice(0, 2).map(w => w.title).join(' · ') + (runningWorkers.length > 2 ? ` +${runningWorkers.length - 2} more` : '')
    : `${PHASE_LABEL[r.phase] ?? r.phase} · Round ${r.roundNo}`

  return <div className="ov"><div className="ov-in">
    {r.status === 'running' && <div className="live-bar" role="status" aria-live="polite">
      <span className="live" aria-hidden="true" />
      <span className="live-k">What Kovo Hunter is doing now</span>
      <span className="live-v" title={liveSummary}>
        {runningWorkers.length > 0 && <b className="num">{plural(runningWorkers.length, 'active worker')} · </b>}
        {liveSummary}
      </span>
      <button type="button" className="linkbtn live-go" onClick={() => runningWorkers[0] ? links.worker(runningWorkers[0].id) : nav.setView('workflow')}>
        {runningWorkers.length > 0 ? 'Inspect' : 'Workflow'}<Icon name="arrowR" />
      </button>
    </div>}
    <div className="ov-eyebrow num">
      <span style={{ color: 'var(--fg-2)', fontWeight: 500 }}>{r.status === 'complete' ? 'Run summary' : 'Provisional summary'}</span>
      <span className="sep">·</span>
      <span>{rep && !live ? `Report v${rep.version} · ${fmtDate(rep.createdAt)}` : `As of ${fmtDate(model.end)}`}</span>
      <span className="sep">·</span>
      <span title={`Tier ${r.capabilityTier} · ${capabilityTierMeta[r.capabilityTier].name}`}>{capabilityTierMeta[r.capabilityTier].short}</span>
    </div>
    <h1 className="hed">{v.hed}</h1>
    {worst && <p className="dek">
      <span className="k">{live ? 'Most severe so far' : 'Most serious'}</span>
      <SevGlyph sev={worst.severity} />
      <a role="link" tabIndex={0} title={worst.title} onClick={() => links.finding(worst.id)} onKeyDown={e => { if (e.key === 'Enter') links.finding(worst.id) }}>{worst.title.replace(/\.$/, '')}</a>
      <span className="h mono">{host(worst.origin)}</span>
    </p>}
    {v.dek && <p className="dek" style={{ marginTop: 4 }}><span style={{ color: 'var(--fg-2)' }}>{v.dek}</span></p>}

    <div className="trio">
      <div>
        <h3>What was asked</h3>
        <p className={'ask' + (!long || goalOpen ? ' open' : '')}>{goal}</p>
        {long && <button type="button" className="linkbtn" onClick={() => setGoalOpen(!goalOpen)}>{goalOpen ? 'Show less' : 'Show full goal'}</button>}
      </div>
      <div>
        <h3>What Kovo Hunter found</h3>
        <div className="tally num">
          {tally.map(([sev, k]) => [
            <span key={sev + 'l'} className={'l' + (k ? '' : ' z')}><SevGlyph sev={sev} />{SEV_LABEL[sev]}</span>,
            <span key={sev + 'b'} className="bar"><TallyBar id={'ov.t.' + sev} value={k / maxT} color={SEV_COL[sev] === 'var(--fg-4)' ? 'var(--fg-3)' : SEV_COL[sev]} /></span>,
            <span key={sev + 'n'} className={'n' + (k ? '' : ' z')}>{k}</span>,
          ])}
        </div>
      </div>
      <div>
        <h3>How confident</h3>
        <div className="confw">{v.conf.word}</div>
        {v.conf.seg.length > 0 && <div className="cmeter" title={v.conf.seg.filter(x => x[0]).map(x => x[2] + ' ' + x[0]).join(' · ')}>
          {v.conf.seg.filter(x => x[0]).map(x => <b key={x[2]} style={{ flex: x[0] / segT, background: x[1] }} />)}
        </div>}
        <p>{v.conf.text}</p>
      </div>
    </div>

    <div className="stats stats-3 num">
      <div><div className="k">Tokens</div><div className="v"><AnimatedNumber id="ov.tok" value={r.spentTokens} format={x => fmtTok(Math.round(x))} /><small>{fmtN(r.turnsUsed)} turns</small></div></div>
      <div><div className="k">Workers</div><div className="v"><AnimatedNumber id="ov.wk" value={detail.assignments.length} /><small>{runningWorkers.length ? `${fmtN(runningWorkers.length)} running · ` : ''}{fmtN(done)} complete</small></div></div>
      <div><div className="k">Facts · evidence</div><div className="v"><AnimatedNumber id="ov.fa" value={detail.facts.length} /><small>· {fmtN(detail.evidence.length)}</small></div></div>
    </div>

    <div className="ov-grid">
      <div>
        <div className="ov-sec">
          <h4>Needs you<Go to="queue">Open queue</Go></h4>
          {needsAny
            ? <div className="needs">
              {([['decide', 'Decide', 'To approve or deny'], ['review', 'Review', 'Unverified findings'], ['follow', 'Follow up', 'Flagged coverage']] as const).map(([k, l, sub]) => {
                const hot = k === 'decide' && s.decide.length > 0
                return <button key={k} type="button" className={hot ? 'hot' : ''} onClick={() => openQueue(k)}>
                  <span className="n num">{hot && <StatusGlyph status="paused" />}<AnimatedNumber id={'ov.q.' + k} value={s[k].length} /><span style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--fg-2)' }}>{l}</span></span>
                  <span className="l">{sub}</span>
                </button>
              })}
            </div>
            : <div className="needs done"><StatusGlyph status="complete" />Nothing needs you. Every finding is decided or verified.</div>}
        </div>
        <div className="ov-sec">
          <h4>Most serious findings<span className="ct num">{top.length} of {model.findings.length}</span><Go to="findings">All findings</Go></h4>
          <div className="ov-list">
            {top.map(f => <div key={f.id} className="row" role="button" tabIndex={0} onClick={() => links.finding(f.id)} onKeyDown={e => { if (e.key === 'Enter') links.finding(f.id) }}>
              <span className="g"><SevGlyph sev={f.severity} /></span>
              <span className="g" title={f.status}><StatusGlyph status={f.status === 'static_verified' ? 'confirmed' : f.status} /></span>
              <span className="title">{f.title}</span>
              <span className="c-host mono" style={{ width: 130 }}><HostLabel host={host(f.origin)} quiet max={22} /></span>
            </div>)}
            {!top.length && <p style={{ color: 'var(--fg-3)', fontSize: 12.5, margin: '8px 0' }}>{live ? 'No findings drafted yet.' : 'No findings.'}</p>}
          </div>
        </div>
      </div>
      <div>
        <LabPanel />
        <div className="ov-sec">
          <h4>Workflow<span className="ct num">{fmtN(detail.assignments.length)} workers</span><Go to="workflow">Graph</Go></h4>
          <div className="flow" role="button" tabIndex={0} title="Open the workflow graph" onClick={() => nav.setView('workflow')} onKeyDown={e => { if (e.key === 'Enter') nav.setView('workflow') }}>
            {phases.map((p, i) => {
              const ws = model.workflow.byPhase.get(p) ?? []
              if (!ws.length && p === 'retest') return null
              const dn = ws.filter(a => a.status === 'complete').length
              const pz = ws.filter(a => a.status === 'paused' || a.status === 'waiting_approval').length
              const run = ws.filter(a => a.status === 'running').length
              const fl = ws.filter(a => a.status === 'failed').length
              return <div key={p} className="fr">
                <span className="k">{PHASE_LABEL[p] ?? p}</span>
                <span className="bar"><i style={{ width: `${ws.length / maxP * 100}%`, animationDelay: `${i * 60}ms` }} />{pz > 0 && <i className="pz" style={{ width: `${pz / maxP * 100}%`, animationDelay: `${i * 60}ms` }} />}</span>
                <span className="v num">{ws.length}</span>
                <span className="s num">{ws.length ? (pz ? pz + ' paused' : run ? run + ' running' : fl ? fl + ' failed' : dn === ws.length ? 'done' : dn + ' done') : '—'}</span>
              </div>
            })}
            {rep && <div className="fr"><span className="k">Report</span><span className="bar"><i style={{ width: '4%', background: 'var(--fg)' }} /></span><span className="v num">v{rep.version}</span><span className="s">{rep.partial ? 'partial' : 'ready'}</span></div>}
          </div>
        </div>
        <div className="ov-sec">
          <h4>Traffic<span className="ct num">{fmtN(counts.exchanges)} exchanges</span><Go to="exchanges">Exchanges</Go></h4>
          <div className="hist" title="HTTP exchanges over time; red marks requests blocked by scope or rate limits">
            {hist.bins.map((b, i) => <i key={i} style={{ height: Math.max(1.5, (b[0] + b[1]) / hist.max * 40).toFixed(1) + 'px', animationDelay: `${i * 8}ms` }} title={`${b[0]} exchanges${b[1] ? ', ' + b[1] + ' denied' : ''}`}>
              {b[1] > 0 && <em style={{ height: Math.max(2, b[1] / (b[0] + b[1]) * 100) + '%' }} />}
            </i>)}
          </div>
          <div className="hist-ax num"><span>{fmtTime(hist.t0)}</span><span>{fmtTime(hist.t0 + (hist.t1 - hist.t0) / 2)}</span><span>{fmtTime(hist.t1)}</span></div>
        </div>
        <div className="ov-sec">
          <h4>Coverage<span className="ct num">{fmtN(detail.coverageEntries.length)} cells</span><Go to="surface">Surface</Go></h4>
          {cov.length
            ? <>
              <div className="stack" style={{ width: '100%', height: 6, margin: '2px 0 8px' }}>{cov.map(c => <i key={c.status} className={'bg-' + c.status} style={{ flex: c.count }} title={`${c.label} ${c.count}`} />)}</div>
              <div className="legend num" style={{ fontSize: 12, color: 'var(--fg-2)', gap: '6px 14px' }}>
                {cov.map(c => <span key={c.status}><CovSwatch status={c.status} size={[14, 11]} />{c.label} <span style={{ color: 'var(--fg-3)' }}>{c.count}</span></span>)}
              </div>
            </>
            : <p style={{ color: 'var(--fg-3)', fontSize: 12.5, margin: 0 }}>No coverage recorded yet.</p>}
        </div>
      </div>
    </div>
  </div></div>
}

/** Tally bar that grows from its previous value (keyed per severity so it animates on run switch). */
function TallyBar({ id, value, color }: { id: string; value: number; color: string }) {
  return <Meter id={id} value={value} warn={false} wide className="tally-m" style={{ '--bar': color } as CSSProperties} />
}
