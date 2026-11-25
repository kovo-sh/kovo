// Overview: written verdict, severity tally, confidence meter, key stats,
// queue summary, top findings, workflow summary, traffic histogram, coverage.
// Waiting runs render the consent sheet.
import { useMemo, useState } from 'react'
import { capabilityTierMeta } from '../../run-state.ts'
import { useRun, useRunModel, useVerdict } from '../data.tsx'
import { useDecisions } from '../decisions.tsx'
import { HostLabel } from '../display.tsx'
import { fmtDate, fmtN, fmtTime, fmtTok, host, plural } from '../format.ts'
import { CovSwatch, LiveDot, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { PHASE_LABEL, SEV, SEV_COL, SEV_LABEL } from '../meta.ts'
import type { ViewId } from '../meta.ts'
import { bySeriousness, coverageCounts, trafficHistogram } from '../model.ts'
import { AnimatedNumber, Meter } from '../motion.tsx'
import { useLinks, useNav } from '../nav.tsx'
import { cn, covBarBgClass, runBtn } from '../tw.ts'
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
  return <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'ml-auto')} onClick={() => nav.setView(to)}>
    {children}<Icon name="arrowR" />
  </button>
}

/** Compute the live-strip status line, surfacing login-persona auth before threat-model workers spawn. */
export function liveOverviewSummary(input: {
  phase: string
  roundNo: number
  runningWorkers: readonly { title: string }[]
  approvedPersonaIds: readonly string[]
  personas: readonly { id: string; handle: string; authKind: string }[]
  events: readonly { id: number; kind: string; detail?: Record<string, unknown> | null }[]
  hasThreatModel: boolean
}): string {
  if (input.runningWorkers.length > 0) {
    return input.runningWorkers.slice(0, 2).map(w => w.title).join(' · ')
      + (input.runningWorkers.length > 2 ? ` +${input.runningWorkers.length - 2} more` : '')
  }
  if (input.phase === 'threat_model' && !input.hasThreatModel && input.approvedPersonaIds.length > 0) {
    const approvedSet = new Set(input.approvedPersonaIds)
    const loginPersonas = input.personas.filter(p => approvedSet.has(p.id) && p.authKind === 'login')
    if (loginPersonas.length > 0) {
      const latestScopeEventId = input.events.reduce(
        (max, ev) => (ev.kind === 'scope.approved' ? Math.max(max, ev.id) : max),
        0,
      )
      const authedPersonaIds = new Set<string>()
      for (const ev of input.events) {
        if (ev.id < latestScopeEventId) continue
        if (ev.kind === 'persona.authenticated') {
          const pid = typeof ev.detail?.personaId === 'string' ? ev.detail.personaId : null
          if (pid) authedPersonaIds.add(pid)
        }
      }
      const pending = loginPersonas.filter(p => !authedPersonaIds.has(p.id))
      if (pending.length > 0) {
        return `Authenticating test accounts… (${pending.map(p => p.handle).join(', ')})`
      }
    }
  }
  return `${PHASE_LABEL[input.phase] ?? input.phase} · Round ${input.roundNo}`
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
  const liveSummary = liveOverviewSummary({
    phase: r.phase,
    roundNo: r.roundNo,
    runningWorkers,
    approvedPersonaIds: r.approvedPersonaIds,
    personas: detail.personas,
    events,
    hasThreatModel: Boolean(detail.threatModel),
  })

  return <div className="min-h-0 flex-1 overflow-auto">
    <div className="max-w-[980px] px-6 pb-14 pt-[22px]">
      {r.status === 'running' && <div className="mb-3.5 flex min-h-9 min-w-0 items-center gap-2.5 rounded-lg bg-accent-soft px-3 py-1.5 text-[12.5px] shadow-[inset_0_0_0_1px_var(--accent-line)]" role="status" aria-live="polite">
        <LiveDot />
        <span className="flex-none whitespace-nowrap font-medium text-fg">What Kovo Hunter is doing now</span>
        <span className="min-w-0 flex-1 truncate text-fg-muted" title={liveSummary}>
          {runningWorkers.length > 0 && <b className="num font-medium text-fg">{plural(runningWorkers.length, 'active worker')} · </b>}
          {liveSummary}
        </span>
        <button
          type="button"
          className={cn(runBtn({ variant: 'link', size: 'none' }), 'flex-none font-medium text-accent hover:text-fg')}
          onClick={() => runningWorkers[0] ? links.worker(runningWorkers[0].id) : nav.setView('workflow')}
        >
          {runningWorkers.length > 0 ? 'Inspect' : 'Workflow'}<Icon name="arrowR" />
        </button>
      </div>}

      <div className="num mb-2 flex items-center gap-2 overflow-hidden whitespace-nowrap text-[12px] text-fg-subtle">
        <span className="font-medium text-fg-muted">{r.status === 'complete' ? 'Run summary' : 'Provisional summary'}</span>
        <span className="text-fg-faint">·</span>
        <span>{rep && !live ? `Report v${rep.version} · ${fmtDate(rep.createdAt)}` : `As of ${fmtDate(model.end)}`}</span>
        <span className="text-fg-faint">·</span>
        <span title={capabilityTierMeta[r.capabilityTier].name}>{capabilityTierMeta[r.capabilityTier].short}</span>
      </div>

      <h1 className="m-0 max-w-[820px] text-pretty text-[18px] font-semibold leading-[26px] tracking-[-0.017em] text-fg">{v.hed}</h1>
      {worst && <p className="m-0 mt-1.5 flex min-w-0 items-center gap-2 text-[13px] leading-5 text-fg-muted">
        <span className="flex-none text-fg-subtle">{live ? 'Most severe so far' : 'Most serious'}</span>
        <SevGlyph sev={worst.severity} />
        <a
          className="min-w-0 cursor-pointer truncate border-b border-line-strong text-fg no-underline hover:border-fg-muted"
          role="link"
          tabIndex={0}
          title={worst.title}
          onClick={() => links.finding(worst.id)}
          onKeyDown={e => { if (e.key === 'Enter') links.finding(worst.id) }}
        >
          {worst.title.replace(/\.$/, '')}
        </a>
        <span className="flex-none font-mono text-[12px] text-fg-subtle">{host(worst.origin)}</span>
      </p>}
      {v.dek && <p className="m-0 mt-1 flex min-w-0 items-center gap-2 text-[13px] leading-5 text-fg-muted"><span>{v.dek}</span></p>}

      <div className="mt-[18px] grid grid-cols-[1.15fr_1fr_1fr] border-y border-line max-[1180px]:grid-cols-2">
        <div className="min-w-0 pb-3.5 pr-[18px] pt-3 max-[1180px]:col-span-full max-[1180px]:border-b max-[1180px]:border-line max-[1180px]:pr-0">
          <h3 className="m-0 mb-1.5 text-[11.5px] font-medium text-fg-subtle">What was asked</h3>
          <p className={cn('m-0 text-[12.5px] leading-[19px] text-fg-muted', long && !goalOpen && 'line-clamp-4')}>{goal}</p>
          {long && <button type="button" className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1')} onClick={() => setGoalOpen(!goalOpen)}>{goalOpen ? 'Show less' : 'Show full goal'}</button>}
        </div>
        <div className="min-w-0 border-l border-line px-[18px] pb-3.5 pt-3 max-[1180px]:border-l-0 max-[1180px]:pl-0">
          <h3 className="m-0 mb-1.5 text-[11.5px] font-medium text-fg-subtle">What Kovo Hunter found</h3>
          <div className="num grid grid-cols-[62px_1fr_26px] items-center gap-x-2 gap-y-[3px] text-[12px]">
            {tally.map(([sev, k]) => [
              <span key={sev + 'l'} className={cn('flex items-center gap-1.5', k ? 'text-fg-muted' : 'text-fg-faint')}><SevGlyph sev={sev} />{SEV_LABEL[sev]}</span>,
              <span key={sev + 'b'} className="block h-1 overflow-hidden rounded-[3px] bg-line">
                <TallyBar id={'ov.t.' + sev} value={k / maxT} color={SEV_COL[sev] === 'var(--fg-4)' ? 'var(--fg-3)' : SEV_COL[sev]} />
              </span>,
              <span key={sev + 'n'} className={cn('text-right', k ? 'text-fg-muted' : 'text-fg-faint')}>{k}</span>,
            ])}
          </div>
        </div>
        <div className="min-w-0 border-l border-line pb-3.5 pl-[18px] pt-3">
          <h3 className="m-0 mb-1.5 text-[11.5px] font-medium text-fg-subtle">How confident</h3>
          <div className="mb-1.5 flex items-center gap-2 text-[15px] font-semibold tracking-[-0.01em] text-fg">{v.conf.word}</div>
          {v.conf.seg.length > 0 && <div className="mb-2 flex h-[5px] gap-0.5 overflow-hidden rounded-[4px] bg-line" title={v.conf.seg.filter(x => x[0]).map(x => x[2] + ' ' + x[0]).join(' · ')}>
            {v.conf.seg.filter(x => x[0]).map(x => <b key={x[2]} className="block h-full" style={{ flex: x[0] / segT, background: x[1] }} />)}
          </div>}
          <p className="m-0 text-[12.5px] leading-[19px] text-fg-muted">{v.conf.text}</p>
        </div>
      </div>

      <div className="num grid grid-cols-3 border-b border-line">
        <div className="min-w-0 pb-[11px] pr-3.5 pt-2.5">
          <div className="flex items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle">Tokens</div>
          <div className="whitespace-nowrap text-[15px] font-medium leading-[22px] tracking-[-0.01em] text-fg">
            <AnimatedNumber id="ov.tok" value={r.spentTokens} format={x => fmtTok(Math.round(x))} />
            <small className="ml-[3px] text-[12px] font-normal text-fg-subtle">{fmtN(r.turnsUsed)} turns</small>
          </div>
        </div>
        <div className="min-w-0 border-l border-line px-3.5 pb-[11px] pt-2.5">
          <div className="flex items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle">Workers</div>
          <div className="whitespace-nowrap text-[15px] font-medium leading-[22px] tracking-[-0.01em] text-fg">
            <AnimatedNumber id="ov.wk" value={detail.assignments.length} />
            <small className="ml-[3px] text-[12px] font-normal text-fg-subtle">{runningWorkers.length ? `${fmtN(runningWorkers.length)} running · ` : ''}{fmtN(done)} complete</small>
          </div>
        </div>
        <div className="min-w-0 border-l border-line pb-[11px] pl-3.5 pt-2.5">
          <div className="flex items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle">Facts · evidence</div>
          <div className="whitespace-nowrap text-[15px] font-medium leading-[22px] tracking-[-0.01em] text-fg">
            <AnimatedNumber id="ov.fa" value={detail.facts.length} />
            <small className="ml-[3px] text-[12px] font-normal text-fg-subtle">· {fmtN(detail.evidence.length)}</small>
          </div>
        </div>
      </div>

      <div className="mt-1.5 grid grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)] gap-x-7 max-[1180px]:grid-cols-1">
        <div>
          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Needs you<Go to="queue">Open queue</Go>
            </h4>
            {needsAny
              ? <div className="grid grid-cols-3 overflow-hidden rounded-lg border border-line">
                {([['decide', 'Decide', 'To approve or deny'], ['review', 'Review', 'Unverified findings'], ['follow', 'Follow up', 'Flagged coverage']] as const).map(([k, l, sub], idx) => {
                  const hot = k === 'decide' && s.decide.length > 0
                  return <button
                    key={k}
                    type="button"
                    className={cn(
                      'flex h-auto cursor-pointer flex-col items-start gap-px whitespace-normal rounded-none border-0 bg-transparent px-3 py-[9px] text-left font-sans shadow-none transition-colors duration-[var(--d1)] hover:bg-hover',
                      idx > 0 && 'border-l border-line',
                    )}
                    onClick={() => openQueue(k)}
                  >
                    <span className={cn('num flex items-center gap-[7px] text-[15px] font-medium leading-[22px]', hot ? 'text-warn' : 'text-fg')}>
                      {hot && <StatusGlyph status="paused" />}
                      <AnimatedNumber id={'ov.q.' + k} value={s[k].length} />
                      <span className="text-[12.5px] font-medium text-fg-muted">{l}</span>
                    </span>
                    <span className="text-[11.5px] font-normal text-fg-subtle">{sub}</span>
                  </button>
                })}
              </div>
              : <div className="flex items-center gap-2.5 rounded-lg border border-line px-3 py-2.5 text-[12.5px] text-fg-muted">
                <StatusGlyph status="complete" />Nothing needs you. Every finding is decided or verified.
              </div>}
          </div>

          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Most serious findings
              <span className="num font-normal text-fg-subtle">{top.length} of {model.findings.length}</span>
              <Go to="findings">All findings</Go>
            </h4>
            <div className="border-t border-line">
              {top.map(f => <div
                key={f.id}
                className="flex h-[34px] cursor-pointer items-center gap-2.5 border-b border-line pl-0.5 pr-1 transition-colors duration-[var(--d1)] hover:bg-hover"
                role="button"
                tabIndex={0}
                onClick={() => links.finding(f.id)}
                onKeyDown={e => { if (e.key === 'Enter') links.finding(f.id) }}
              >
                <span className="inline-flex size-3.5 flex-none items-center justify-center"><SevGlyph sev={f.severity} /></span>
                <span className="inline-flex size-3.5 flex-none items-center justify-center" title={f.status}><StatusGlyph status={f.status === 'static_verified' ? 'confirmed' : f.status} /></span>
                <span className="min-w-0 flex-1 truncate text-fg">{f.title}</span>
                <span className="w-[130px] flex-none truncate text-right font-mono text-[12px] text-fg-subtle max-[1180px]:hidden">
                  <HostLabel host={host(f.origin)} quiet max={22} />
                </span>
              </div>)}
              {!top.length && <p className="my-2 text-[12.5px] text-fg-subtle">{live ? 'No findings drafted yet.' : 'No findings.'}</p>}
            </div>
          </div>
        </div>

        <div>
          <LabPanel />
          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Workflow
              <span className="num font-normal text-fg-subtle">{fmtN(detail.assignments.length)} workers</span>
              <Go to="workflow">Graph</Go>
            </h4>
            <div
              className="cursor-pointer rounded-lg border border-line px-2.5 py-1 transition-colors duration-[var(--d1)] hover:border-line-strong"
              role="button"
              tabIndex={0}
              title="Open the workflow graph"
              onClick={() => nav.setView('workflow')}
              onKeyDown={e => { if (e.key === 'Enter') nav.setView('workflow') }}
            >
              {phases.map(p => {
                const ws = model.workflow.byPhase.get(p) ?? []
                if (!ws.length && p === 'retest') return null
                const dn = ws.filter(a => a.status === 'complete').length
                const pz = ws.filter(a => a.status === 'paused' || a.status === 'waiting_approval').length
                const run = ws.filter(a => a.status === 'running').length
                const fl = ws.filter(a => a.status === 'failed').length
                return <div key={p} className="grid h-6 grid-cols-[104px_1fr_30px_58px] items-center gap-2.5 text-[12px]">
                  <span className="truncate text-fg-muted">{PHASE_LABEL[p] ?? p}</span>
                  <span className="relative h-1 overflow-hidden rounded-[2px] bg-line">
                    <i className="absolute inset-y-0 left-0 block rounded-[2px] bg-fg-subtle" style={{ width: `${ws.length / maxP * 100}%` }} />
                    {pz > 0 && <i className="absolute inset-y-0 left-0 block rounded-[2px] bg-warn" style={{ width: `${pz / maxP * 100}%` }} />}
                  </span>
                  <span className="num text-right font-medium text-fg">{ws.length}</span>
                  <span className="num whitespace-nowrap text-[11.5px] text-fg-subtle">
                    {ws.length ? (pz ? pz + ' paused' : run ? run + ' running' : fl ? fl + ' failed' : dn === ws.length ? 'done' : dn + ' done') : '—'}
                  </span>
                </div>
              })}
              {rep && <div className="grid h-6 grid-cols-[104px_1fr_30px_58px] items-center gap-2.5 text-[12px]">
                <span className="truncate text-fg-muted">Report</span>
                <span className="relative h-1 overflow-hidden rounded-[2px] bg-line">
                  <i className="absolute inset-y-0 left-0 block rounded-[2px] bg-fg" style={{ width: '4%' }} />
                </span>
                <span className="num text-right font-medium text-fg">v{rep.version}</span>
                <span className="whitespace-nowrap text-[11.5px] text-fg-subtle">{rep.partial ? 'partial' : 'ready'}</span>
              </div>}
            </div>
          </div>

          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Traffic
              <span className="num font-normal text-fg-subtle">{fmtN(counts.exchanges)} exchanges</span>
              <Go to="exchanges">Exchanges</Go>
            </h4>
            <div className="flex h-11 items-end gap-0.5 overflow-hidden border-b border-line" title="HTTP exchanges over time; red marks requests blocked by scope or rate limits">
              {hist.bins.map((b, i) => <i
                key={i}
                className="relative min-h-px flex-1 overflow-hidden rounded-t-[1px] bg-fg-faint"
                style={{ height: Math.max(1.5, (b[0] + b[1]) / hist.max * 40).toFixed(1) + 'px' }}
                title={`${b[0]} exchanges${b[1] ? ', ' + b[1] + ' denied' : ''}`}
              >
                {b[1] > 0 && <em className="absolute inset-x-0 top-0 bg-danger" style={{ height: Math.max(2, b[1] / (b[0] + b[1]) * 100) + '%' }} />}
              </i>)}
            </div>
            <div className="num mt-[3px] flex justify-between text-[11px] text-fg-subtle">
              <span>{fmtTime(hist.t0)}</span>
              <span>{fmtTime(hist.t0 + (hist.t1 - hist.t0) / 2)}</span>
              <span>{fmtTime(hist.t1)}</span>
            </div>
          </div>

          <div className="pt-4">
            <h4 className="m-0 mb-1.5 flex items-center gap-2 text-[12px] font-medium text-fg-muted">
              Coverage
              <span className="num font-normal text-fg-subtle">{fmtN(detail.coverageEntries.length)} cells</span>
              <Go to="surface">Surface</Go>
            </h4>
            {cov.length
              ? <>
                <div className="mb-2 mt-0.5 flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full">
                  {cov.map(c => <i key={c.status} className={cn('block h-full', covBarBgClass(c.status))} style={{ flex: c.count }} title={`${c.label} ${c.count}`} />)}
                </div>
                <div className="num flex flex-wrap gap-x-3.5 gap-y-1.5 text-[12px] text-fg-muted">
                  {cov.map(c => <span key={c.status} className="inline-flex items-center gap-1.5">
                    <CovSwatch status={c.status} size={[14, 11]} />{c.label} <span className="text-fg-subtle">{c.count}</span>
                  </span>)}
                </div>
              </>
              : <p className="m-0 text-[12.5px] text-fg-subtle">No coverage recorded yet.</p>}
          </div>
        </div>
      </div>
    </div>
  </div>
}

/** Tally bar that grows from its previous value (keyed per severity so it animates on run switch). */
function TallyBar({ id, value, color }: { id: string; value: number; color: string }) {
  return <Meter id={id} value={value} warn={false} wide className="block h-full rounded-[3px] bg-transparent" barColor={color} />
}
