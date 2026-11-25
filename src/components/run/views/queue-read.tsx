// Reading-view building blocks shared by the Queue inspector and the Finding
// inspector (owned by Agent Q): exchange rows with the checked header,
// coordinator context, cross-link blocks, and the per-kind reading views.
import { useState } from 'react'
import type { ReactNode } from 'react'

import { approvalPolicyMeta, capabilityTierMeta } from '../../run-state.ts'
import { useFullExchange, useRun, useRunModel } from '../data.tsx'
import { LinkRow, Section } from '../display.tsx'
import { cap, capF, fmtDate, fmtN, fmtRel, fmtTime, fmtUsd, host, plural, prettyBody, words } from '../format.ts'
import { CovSwatch, SevGlyph, StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { IconName } from '../icons.tsx'
import { CHECK_HEADERS, COV_L, covCat, normFStatus, PHASE_LABEL, prettyCat, SEV_LABEL, stLabel } from '../meta.ts'
import type { Approval, Exchange, FindingRow, QueueItem, RunModel } from '../model.ts'
import { useLinks } from '../nav.tsx'

type FindingItem = Extract<QueueItem, { kind: 'finding' }>
type ApprovalItem = Extract<QueueItem, { kind: 'approval' }>
type FollowItem = Extract<QueueItem, { kind: 'follow' }>

/** Finding verification state, as E words it ("Unverified" while pending). */
export function VState({ status }: { status: string }) {
  const n = normFStatus(status)
  return <span className="vst"><StatusGlyph status={n} />{n === 'pending' ? 'Unverified' : stLabel(n)}</span>
}

/** Glyph for a queue item: shield (approval), flag (follow-up / consent), severity bars (finding). */
export function QGlyph({ it }: { it: QueueItem }) {
  if (it.kind === 'consent') return <span className="g" style={{ color: 'var(--fg-2)' }}><Icon name="flag" /></span>
  if (it.kind === 'approval') return <span className="g" style={{ color: 'var(--warn)' }}><Icon name="shield" /></span>
  if (it.kind === 'follow') return <span className="g" style={{ color: 'var(--warn)' }}><Icon name="flag" /></span>
  return <span className="g" title={SEV_LABEL[it.sev]}><SevGlyph sev={it.sev} /></span>
}

// ---------------------------------------------------------------- exchanges

const lower = (h: Record<string, string> | null | undefined) =>
  Object.fromEntries(Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]))

/**
 * One evidence exchange: method, status, URL and (for baseline checks) the
 * checked header's value or "absent". Expands to the full response headers
 * with the checked header highlighted. Exchanges outside the loaded window
 * are fetched by id (read-only GET).
 */
export function ExchangeRow({ id, summary, hl = [] }: { id: string; summary?: Exchange; hl?: readonly string[] }) {
  const links = useLinks()
  const [open, setOpen] = useState(false)
  const full = useFullExchange(id, open || hl.length > 0 || !summary)
  const x = summary ?? full
  if (!x) {
    return <div className="linkrow" aria-busy={full === undefined}>
      <span className="mono" style={{ width: 38, color: 'var(--fg-3)' }}>—</span>
      <span className="p" style={{ color: 'var(--fg-3)' }}>{full === null ? 'Exchange unavailable' : 'Loading exchange…'}</span>
    </div>
  }
  const H = full ? lower(full.respHeaders) : null
  const k = hl[0]
  let hv: ReactNode = null
  if (k && H) {
    hv = k in H
      ? <span className="r mono" title={`${k}: ${H[k]}`}>{k}: {H[k].slice(0, 24)}</span>
      : <span className="r mono" style={{ color: 'var(--bad)' }}>{k} absent</span>
  }
  const absent = H ? hl.filter(h => !(h in H)) : []
  return <>
    <div className="linkrow qx" role="button" tabIndex={0} aria-expanded={open} onClick={() => setOpen(o => !o)}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(o => !o) } }}>
      <span className="mono" style={{ width: 38, flex: 'none', color: 'var(--fg-3)' }}>{x.method}</span>
      <span className={'mono code-' + String(x.status)[0]} style={{ width: 28, flex: 'none' }}>{x.status}</span>
      <span className="p mono">{host(x.origin)}{x.pathAndQuery}</span>
      {hv}
      <span className={'qx-chev' + (open ? ' open' : '')}><Icon name="chev" /></span>
    </div>
    {open && <div className="qx-det">
      {!full ? <p style={{ fontSize: 12, color: 'var(--fg-3)' }}>{full === null ? 'Headers unavailable.' : 'Loading headers…'}</p>
        : <table className="hdrs mono">
          <tbody>
            {absent.map(h => <tr key={'a:' + h}><td style={{ color: 'var(--fg)' }}>{h}</td><td style={{ color: 'var(--bad)' }}>absent</td></tr>)}
            {Object.entries(H ?? {}).map(([h, v]) => <tr key={h} className={hl.includes(h) ? 'hl' : undefined}><td>{h}</td><td>{v}</td></tr>)}
          </tbody>
        </table>}
      <LinkRow icon="exchanges" onClick={() => links.exchange(id)}>Open in Exchanges</LinkRow>
    </div>}
  </>
}

// ---------------------------------------------------------------- coordinator context

interface CtxItem { icon: IconName; title: ReactNode; body: ReactNode; worker?: string | null; cell?: [string, string] }

/** "What the run knows": plan steps, chain facts, counterevidence, coverage and planner notes for these origins. */
export function CoordinatorContext({ origins, findings = [], category, excludeCoverageId, follow }: {
  origins: readonly string[]
  findings?: readonly FindingRow[]
  category?: string | null
  excludeCoverageId?: string
  follow?: boolean
}) {
  const { events } = useRun()
  const model = useRunModel()
  const links = useLinks()
  const d = model.detail
  const set = new Set(origins)
  const items: CtxItem[] = []
  d.chainSteps.filter(s => s.sourceOrigins.some(o => set.has(o)))
    .sort((a, b) => Number(b.status === 'complete') - Number(a.status === 'complete') || a.seq - b.seq).slice(0, 2)
    .forEach(s => items.push({ icon: 'workflow', title: <>Step {s.seq} · {cap(s.status)}</>, body: <><b className="ctx-strong">{s.title}</b> {s.hypothesis}</>, worker: s.assignedWorkerId }))
  const fids = findings.flatMap(f => f.chainFactIds ?? [])
  fids.map(id => model.factById.get(id)).filter(Boolean).slice(0, 2)
    .forEach(f => items.push({ icon: 'fact', title: <>Fact · {f!.kind}</>, body: f!.summary, worker: f!.assignmentId }))
  const ce = findings.find(f => f.counterevidence)?.counterevidence
  if (ce) items.push({ icon: 'alert', title: 'Counterevidence', body: ce })
  d.coverageEntries.filter(x => set.has(x.origin) && x.id !== excludeCoverageId)
    .sort((a, b) => Number(b.category === category) - Number(a.category === category)).slice(0, follow ? 3 : 2)
    .forEach(x => items.push({ icon: 'surface', title: <>Coverage · {host(x.origin)} · {prettyCat(x.category)} · <b>{COV_L[x.status]}</b></>, body: x.summary, cell: [x.origin, x.category] }))
  const hs = [...set].map(host)
  const pl = [...events].reverse().find(e => e.kind === 'planner.round' && typeof e.detail?.summary === 'string' && hs.some(h => (e.detail.summary as string).includes(h)))
  if (pl) items.push({ icon: 'node', title: <>Planner · round {String(pl.detail.roundNo ?? '')}</>, body: String(pl.detail.summary) })
  if (!items.length) return <p>The coordinator has no other notes on {hs.length > 1 ? 'these origins' : 'this origin'} yet.</p>
  return <div className="ctx">
    {items.slice(0, 5).map((c, i) => <div key={i} className="ctx-item">
      <span className="ci"><Icon name={c.icon} /></span>
      <div style={{ minWidth: 0 }}>
        <div className="ct">{c.title}
          {c.worker && model.workerById.has(c.worker) && <> · <button type="button" className="linkbtn ctx-a" onClick={() => links.worker(c.worker!)}>worker<Icon name="arrowR" /></button></>}
          {c.cell && <> · <button type="button" className="linkbtn ctx-a" onClick={() => links.cell(c.cell![0], c.cell![1])}>cell<Icon name="arrowR" /></button></>}
        </div>
        <div className="cb">{c.body}</div>
      </div>
    </div>)}
  </div>
}

// ---------------------------------------------------------------- cross-links

export function FoundBy({ workers, title = 'Found by' }: { workers: readonly string[]; title?: string }) {
  const model = useRunModel()
  const links = useLinks()
  const ws = workers.map(w => model.workerById.get(w)).filter(Boolean)
  if (!ws.length) return null
  return <Section title={title} right={<span className="num">{plural(ws.length, 'worker')}</span>}>
    {ws.slice(0, 6).map(a => <LinkRow key={a!.id} glyph={<StatusGlyph status={a!.status} />} right={PHASE_LABEL[a!.phase] ?? a!.phase} trailing="workflow"
      onClick={() => links.worker(a!.id)}>{a!.title}</LinkRow>)}
    {ws.length > 6 && <p className="qf-more">+{ws.length - 6} more</p>}
  </Section>
}

export function OnSurface({ origin, category }: { origin: string; category: string }) {
  const model = useRunModel()
  const links = useLinks()
  const cv = model.surface.cov[origin]?.[category]
  const st = cv?.status ?? 'untested'
  return <Section title="On the surface map">
    <LinkRow glyph={<CovSwatch status={st} size={[16, 12]} />} right={COV_L[st]} trailing="surface" onClick={() => links.cell(origin, category)}>
      <span className="mono">{host(origin)}</span> · {prettyCat(category)}
    </LinkRow>
  </Section>
}

// ---------------------------------------------------------------- reading views

/** Exchanges a queue finding cites; when none, the baseline responses for its origins (labelled as such). */
function evidenceFor(model: RunModel, it: FindingItem) {
  const ids = [...new Set(it.list.flatMap(f => f.exchangeIds ?? []))]
  if (ids.length) return { ids, inferred: false }
  const out: string[] = []
  for (const o of it.origins.slice(0, 6)) {
    const l = model.exchangesByOrigin.get(o) ?? []
    const x = l.find(e => e.pathAndQuery === '/' && e.method === 'GET') ?? l[0]
    if (x) out.push(x.id)
  }
  return { ids: out, inferred: true }
}

const obsText = (v: unknown) => v == null ? null : typeof v === 'string' ? v : JSON.stringify(v)

export function ReadFinding({ it }: { it: FindingItem }) {
  const model = useRunModel()
  const F = it.finding
  const chain = F.findingKind === 'multi_step_chain'
  const checkId = F.check?.id ?? ''
  const hl = CHECK_HEADERS[checkId] ?? []
  const ev = evidenceFor(model, it)
  const ws = [...new Set(it.list.flatMap(f => model.findingWorkers.get(f.id) ?? []))]
  const cat = covCat(F.category)
  let groups: [string, string[]][] = []
  if (it.bundle) {
    const g = new Map<string, string[]>()
    for (const f of it.list) {
      const v = obsText(f.check?.observed) ?? 'Not recorded'
      g.set(v, [...(g.get(v) ?? []), host(f.origin)])
    }
    groups = [...g]
  }
  const obs = obsText(F.check?.observed)
  return <>
    <div className="kicker">
      <span className="sevlab"><SevGlyph sev={it.sev} />{SEV_LABEL[it.sev]}</span><span>·</span><VState status={it.status} /><span>·</span>
      <span>{chain ? 'Multi-step chain' : 'Baseline check'}</span>
      {F.cwe && <><span>·</span><span className="mono">{F.cwe}</span></>}
      {F.confidence && <><span>·</span><span>{cap(F.confidence)} confidence</span></>}
    </div>
    <h2 className="rtitle">{F.title}</h2>
    <div className="rorigins">
      {it.origins.slice(0, 6).map(o => <span key={o} className="tag mono" style={{ fontSize: 11 }}>{host(o)}</span>)}
      {it.origins.length > 6 && <span className="tag">+{it.origins.length - 6} more</span>}
    </div>
    {(F.impact || F.reason || it.bundle) && <Section title="Narrative">
      {F.impact && <p className="lead">{F.impact}</p>}
      {F.reason && <p>{F.reason}</p>}
      {it.bundle && <p>The same baseline result was recorded on {it.origins.length} origins. A decision here applies to all of them.</p>}
    </Section>}
    {(F.check || F.verification) && <Section title="Check" right={chain ? 'Replay verdict' : 'Expected vs observed'}>
      {F.check && <div className="cmp">
        <div><span>Expected</span><span>{F.check.expected || '—'}</span></div>
        <div><span>Observed</span><span className={'obs' + (obs != null ? ' mono' : '')}>{obs ?? <span style={{ color: 'var(--fg-3)' }}>Not recorded</span>}</span></div>
      </div>}
      {it.bundle && <div className="olist">
        {groups.map(([v, hs]) => <div key={v} className="orow">
          <div style={{ minWidth: 0 }}><div className="ov mono" style={{ fontSize: 11.5 }}>{v}</div><div className="oh">{hs.join(' · ')}</div></div>
          <span className="num">{hs.length}</span>
        </div>)}
      </div>}
      {F.verification && <p>{F.verification}</p>}
    </Section>}
    <Section title="Evidence" right={<span className="num">{plural(ev.ids.length, 'exchange')}</span>}>
      {ev.inferred && ev.ids.length > 0 && <p className="qf-note">Not cited directly. Baseline responses for {ev.ids.length > 1 ? 'these origins' : 'this origin'}{hl.length ? <>, <span className="mono">{hl[0]}</span> highlighted</> : null}.</p>}
      {ev.ids.length
        ? ev.ids.slice(0, 8).map(id => <ExchangeRow key={id} id={id} summary={model.exchangeById.get(id)} hl={hl} />)
        : <p>No exchanges recorded for {it.origins.length > 1 ? 'these origins' : 'this origin'}.</p>}
      {ev.ids.length > 8 && <p className="qf-note">+{ev.ids.length - 8} more cited exchanges.</p>}
    </Section>
    {(F.remediation || F.recheck) && <Section title="Remediation">
      {F.remediation && <p>{F.remediation}</p>}
      {F.recheck && <p><b className="ctx-strong">Recheck.</b> {F.recheck}</p>}
    </Section>}
    <Section title="Coordinator context" right="What the run knows">
      <CoordinatorContext origins={it.origins} findings={it.list} category={cat} />
    </Section>
    <FoundBy workers={ws} />
    {it.origins.length === 1 && cat && <OnSurface origin={it.origins[0]} category={cat} />}
  </>
}

interface RequestPreview { method?: string; origin?: string; pathAndQuery?: string; headers?: Record<string, string>; bodyPreview?: unknown }
function parsePreview(a: Approval): RequestPreview {
  try { const v = JSON.parse(a.requestPreview) as unknown; return v && typeof v === 'object' ? v as RequestPreview : {} } catch { return {} }
}
export function ReadApproval({ it }: { it: ApprovalItem }) {
  const model = useRunModel()
  const links = useLinks()
  const a = it.ap
  const asg = model.workerById.get(a.assignmentId)
  const rp = parsePreview(a)
  const raw = !Object.keys(rp).length && a.requestPreview ? a.requestPreview : null
  const body = prettyBody(rp.bodyPreview)
  const win = a.expiresAt && a.createdAt ? Math.round((a.expiresAt - a.createdAt) / 60000) : null
  const persona = a.personaHandle && a.personaHandle !== 'None' ? a.personaHandle : null
  const policy = model.run.approvalPolicy
  return <>
    <div className="kicker">
      <span className="sevlab" style={{ color: 'var(--warn)' }} title="Tier 3 state-changing request"><Icon name="shield" />State-change approval</span><span>·</span>
      <span className="num">Requested {fmtRel(a.createdAt, model.base)}</span>
      {win != null && win > 0 && <><span>·</span><span>{win}-minute window</span></>}
      <span>·</span><span>Risk {a.riskLevel ? a.riskLevel : 'unrated'}</span>
    </div>
    <h2 className="rtitle url"><span className="m">{a.method}</span>{host(a.origin)}<span className="pq">{a.pathAndQuery}</span></h2>
    <div className="rorigins">
      <span className="tag">{persona ? <><Icon name="lock" />{persona}</> : 'Anonymous'}</span>
      {a.status === 'pending' ? <span className="tag num">Expires {fmtTime(a.expiresAt)}</span> : <span className="tag">{cap(a.status)}{a.decidedBy ? ' · ' + a.decidedBy : ''}</span>}
    </div>
    <Section title="Why">
      <p className="lead">{a.rationale}</p>
      <p>The approval policy is <b className="ctx-strong">{approvalPolicyMeta[policy ?? 'auto_review'].label}</b>. {a.policyNote ? a.policyNote + ' ' : 'The safety reviewer deferred this state-changing request to you. '}{a.status === 'pending' ? 'Nothing is sent until you approve.' : ''}</p>
    </Section>
    <Section title="Request" right="Exactly what will be sent">
      {raw != null ? <pre className="block mono">{raw}</pre> : <pre className="block mono"><span className="pm">{rp.method ?? a.method}</span> {rp.pathAndQuery ?? a.pathAndQuery}{'\n'}<span className="pk">Host:</span> {host(rp.origin ?? a.origin)}
        {Object.entries(rp.headers ?? {}).map(([k, v]) => <span key={k}>{'\n'}<span className="pk">{k}:</span> {String(v)}</span>)}
        {body ? '\n\n' + body : <>{'\n\n'}<span className="pk">(empty body)</span></>}</pre>}
    </Section>
    {asg && <Section title="Requested by">
      <LinkRow glyph={<StatusGlyph status={asg.status} />} onClick={() => links.worker(asg.id)}
        sub={<>{stLabel(asg.status)} · {asg.turnsUsed}/{asg.maxTurns} turns · {fmtN(asg.requestsUsed)} requests. {asg.objective}</>}>{asg.title}</LinkRow>
    </Section>}
    <Section title="Coordinator context" right="What the run knows">
      <CoordinatorContext origins={[a.origin]} />
    </Section>
  </>
}

export function ReadFollow({ it, local }: { it: FollowItem; local: boolean }) {
  const model = useRunModel()
  const links = useLinks()
  const x = it.cov
  const risk = model.risk.get(x.origin)?.riskTier
  const related = model.findings.filter(f => f.origin === x.origin)
  return <>
    <div className="kicker">
      <span className="sevlab" style={{ color: 'var(--warn)' }}><Icon name="flag" />Needs follow-up</span><span>·</span>
      <span>{prettyCat(x.category)}</span>
      {risk && <><span>·</span><span>{cap(risk)} risk surface</span></>}
    </div>
    <h2 className="rtitle">{it.title}</h2>
    <div className="rorigins"><span className="tag mono" style={{ fontSize: 11 }}>{host(x.origin)}</span></div>
    <Section title="Coverage note" right="From the worker handoff"><p className="lead">{x.summary}</p>
      {x.proofGapReason && <p><b className="ctx-strong">Proof gap.</b> {x.proofGapReason}</p>}
    </Section>
    {related.length > 0 && <Section title="Findings on this origin" right={<span className="num">{related.length}</span>}>
      {related.slice(0, 5).map(f => <LinkRow key={f.id} glyph={<SevGlyph sev={f.severity} />} right={<VState status={f.status} />} trailing={null} onClick={() => links.finding(f.id)}>{f.title}</LinkRow>)}
    </Section>}
    <Section title="If queued">
      {local
        ? <p>The run is complete, so nothing can be scheduled. Queuing records the follow-up locally for the next run on <span className="mono">{host(x.origin)}</span>.</p>
        : <p>Kovo Hunter sends the coordinator a steering hint for <span className="mono">{host(x.origin)}</span> · {prettyCat(x.category)}; it becomes a plan step in the next planner round. Requests requiring higher permissions come back here for approval.</p>}
    </Section>
    <Section title="Coordinator context"><CoordinatorContext origins={[x.origin]} category={x.category} excludeCoverageId={x.id} follow /></Section>
    <FoundBy workers={x.assignmentId && model.workerById.has(x.assignmentId) ? [x.assignmentId] : []} title="Recorded by" />
    <OnSurface origin={x.origin} category={x.category} />
  </>
}

export function ReadConsent() {
  const model = useRunModel()
  const r = model.run
  const seeds = model.detail.project.seeds
  const nw = (r.goal || '').split(/\s+/).filter(Boolean).length
  return <>
    <div className="kicker"><span className="sevlab"><Icon name="flag" />Consent</span><span>·</span><span>Created {fmtDate(r.createdAt)}</span></div>
    <h2 className="rtitle">{r.phase === 'review' ? 'Approve scope to start the run' : 'Approve discovery to start the run'}</h2>
    <div className="rorigins">
      <span className="tag num">{plural(seeds.length, 'host')}</span><span className="tag" title={`Tier ${r.capabilityTier}`}>{capabilityTierMeta[r.capabilityTier].short}</span>
      <span className="tag num">{fmtUsd(r.budgetUsd)} · {r.budgetRequests ? fmtN(r.budgetRequests) + ' req' : 'uncapped'}</span>
    </div>
    <Section title="Goal">
      <p className="lead">“{r.goal}”</p>
      {nw < 6 && <div className="callout"><Icon name="alert" /><div>{capF(words(nw))} word{nw === 1 ? '' : 's'} is broad. Sharpen it with the coordinator to focus the budget.</div></div>}
    </Section>
    <Section title="Hosts" right="Project seeds">
      <div className="qf-hosts mono">{seeds.map(s => <span key={s}>{host(s)}</span>)}</div>
    </Section>
  </>
}
