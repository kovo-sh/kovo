// Run model: pure derivations over the run detail, built once per detail
// snapshot (memoised in `useRunModel()`). Views read from here instead of
// re-deriving. Everything is real data; no links are invented.
import type { RunDetail } from '../run-state.ts'
import { capF, firstSentence, host, sharedApex, words } from './format.ts'
import { COV_L, covCat, FSTAT_ORDER, normFStatus, PHASE_ORDER, SEV, SEV_ORDER } from './meta.ts'
import type { RiskTier, Severity } from './meta.ts'

export type Detail = RunDetail
export type Run = RunDetail['run']
export type FindingRow = RunDetail['findings'][number]
export type Assignment = RunDetail['assignments'][number]
export type Exchange = RunDetail['exchangesSummary'][number]
export type Approval = RunDetail['approvals'][number]
export type Coverage = RunDetail['coverageEntries'][number]
export type Message = RunDetail['messages'][number]
export type Fact = RunDetail['facts'][number]
export type Evidence = RunDetail['evidence'][number]
export type ChainStep = RunDetail['chainSteps'][number]
export type Report = RunDetail['reports'][number]
export type ThreatEntry = NonNullable<RunDetail['threatModel']>['entries'][number]

/** A run event as streamed over SSE (`/api/runs/:id/events`). */
export interface RunEvent {
  id: number
  runId: string | null
  kind: string
  message: string
  detail: Record<string, unknown>
  createdAt: number
}

// ---------------------------------------------------------------- verdict

export interface Verdict {
  /** One-line headline (B): "Two medium-severity weaknesses confirmed across 30 hosts; nothing high or critical." */
  hed: string
  /** Second line, used while paused ("Six Tier 3 requests are waiting…"). */
  dek: string | null
  /** The most serious finding (confirmed when complete; worst drafted while paused). */
  worst: FindingRow | null
  conf: {
    /** High / Moderate / Limited / Provisional / Not yet assessed */
    word: string
    text: string
    /** [count, colour, label] segments for the confidence meter. */
    seg: [number, string, string][]
  }
  /** Counts by severity (excluding dismissed) and by raw status. */
  n: Record<string, number>
  hosts: number
  confirmed: number
  followups: number
  pendingApprovals: Approval[]
}

export function buildVerdict(d: Detail, findings: readonly FindingRow[], interrupted: boolean): Verdict {
  const r = d.run
  const n: Record<string, number> = { total: findings.length }
  for (const s of SEV) n[s] = findings.filter(f => f.severity === s && f.status !== 'dismissed').length
  for (const s of ['confirmed', 'static_verified', 'inconclusive', 'dismissed', 'pending']) n[s] = findings.filter(f => f.status === s).length
  const confirmed = findings.filter(f => normFStatus(f.status) === 'confirmed')
  const hosts = r.approved.length || new Set(d.coverageEntries.map(x => x.origin)).size
  const pendingApprovals = d.approvals.filter(a => a.status === 'pending')
  const followups = d.coverageEntries.filter(x => x.status === 'needs_follow_up').length
  const hostsW = words(hosts) + ' host' + (hosts === 1 ? '' : 's')
  let hed: string
  let dek: string | null = null
  let worst: FindingRow | null = null
  const bySev = (a: FindingRow, b: FindingRow) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  const live = r.status !== 'complete' && r.status !== 'stopped' && r.status !== 'failed'
  if (r.status === 'waiting') {
    hed = 'Awaiting your consent to begin. Nothing has been sent.'
  } else if (live && confirmed.length === 0) {
    const p = pendingApprovals.length
    const state = r.status === 'running' ? 'the investigation is running' : r.status === 'budget_paused' ? 'the run is paused at its budget' : 'the investigation is paused'
    hed = findings.length
      ? capF(words(findings.length)) + ' finding' + (findings.length === 1 ? '' : 's') + ' drafted, none yet verified; ' + state + '.'
      : 'No findings drafted yet; ' + state + '.'
    dek = (interrupted ? 'The application restarted mid-round. ' : '') + (p
      ? capF(words(p)) + ' approval-gated write request' + (p > 1 ? 's' : '') + ' waiting on your decision before work can resume.'
      : r.status === 'running' ? null : 'Resume to continue from saved evidence.')
    worst = findings.filter(f => f.status !== 'dismissed').slice().sort(bySev)[0] ?? null
  } else {
    const top = SEV.find(s => confirmed.some(f => f.severity === s))
    if (!top) {
      hed = 'No weakness could be confirmed across ' + hostsW + '.'
      const k = n.inconclusive
      dek = k ? capF(words(k)) + ' observation' + (k === 1 ? ' remains' : 's remain') + ' inconclusive.' : null
    } else {
      const k = confirmed.filter(f => f.severity === top).length
      const i = SEV.indexOf(top)
      const above = i === 2 ? '; nothing high or critical' : i > 2 ? '; nothing more severe' : ''
      hed = capF(words(k)) + ' ' + top + '-severity weakness' + (k > 1 ? 'es' : '') + ' confirmed across ' + hostsW + above + '.'
      worst = confirmed.filter(f => f.severity === top)
        .sort((a, b) => Number(b.findingKind === 'multi_step_chain') - Number(a.findingKind === 'multi_step_chain'))[0] ?? null
      if (live) dek = 'Provisional: the run is ' + (r.status === 'running' ? 'still running' : 'paused') + ', so more may follow.'
    }
  }
  let conf: Verdict['conf']
  if (r.status === 'waiting') {
    conf = { word: 'Not yet assessed', text: 'Confidence is earned by automated replay once work begins. Nothing has been observed.', seg: [] }
  } else {
    const standing = findings.length - n.dismissed
    const k = confirmed.length
    const ratio = standing ? k / standing : 0
    let word = ratio >= 0.6 ? 'High' : ratio >= 0.3 ? 'Moderate' : 'Limited'
    if (live) word = 'Provisional'
    const parts = [k + ' of ' + standing + ' standing findings confirmed by automated replay']
    if (n.dismissed) parts.push(n.dismissed + ' dismissed on replay')
    if (n.inconclusive) parts.push(n.inconclusive + ' inconclusive')
    if (n.pending) parts.push(n.pending + ' awaiting verification')
    let text = parts.join('; ') + '.'
    if (followups) text += ' ' + capF(words(followups)) + ' coverage area' + (followups > 1 ? 's need' : ' needs') + ' follow-up.'
    conf = {
      word, text,
      seg: [[k, 'var(--fg-2)', 'Confirmed'], [n.pending, 'var(--med)', 'Awaiting'], [n.inconclusive, 'var(--fg-4)', 'Inconclusive'], [n.dismissed, 'var(--line-strong)', 'Dismissed']],
    }
  }
  return { hed, dek, worst, conf, n, hosts, confirmed: confirmed.length, followups, pendingApprovals }
}

// ---------------------------------------------------------------- queue (E's triage)

export type QueueSection = 'decide' | 'review' | 'follow' | 'done'
export type QueueItem =
  | { key: string; kind: 'consent'; title: string; t: number }
  | { key: string; kind: 'approval'; ap: Approval; title: string; t: number }
  | {
    key: string; kind: 'finding'; bundle: boolean; list: FindingRow[]; finding: FindingRow
    sev: Severity; status: string; origins: string[]; title: string; t: number
  }
  | { key: string; kind: 'follow'; cov: Coverage; title: string; origins: string[]; t: number; risk: number }

export type QueueBase = Record<QueueSection, QueueItem[]>

/**
 * Queue key of the consent item. Discovery consent and the later scope approval are two
 * separate decisions, so the key carries the phase: approving discovery must not mark the
 * scope review (same run, phase `review`) as already decided.
 */
export const consentKey = (run: Pick<Run, 'phase'>) => 'consent:' + run.phase

/** True when a still-pending approval has passed its client-side expiry timestamp. */
export function isApprovalExpired(a: Pick<Approval, 'status' | 'expiresAt'>, now = Date.now()): boolean {
  return a.status === 'pending' && Number.isFinite(a.expiresAt) && a.expiresAt > 0 && now >= a.expiresAt
}

export const QSEC: [QueueSection, string, string][] = [
  ['decide', 'Decide', 'Needs your decision before work continues'],
  ['review', 'Review', 'Unverified findings, bundled by check'],
  ['follow', 'Follow up', 'Coverage the coordinator flagged'],
  ['done', 'Done', 'Server-side decisions and approval audit log'],
]

function buildQueue(d: Detail, _findings: readonly FindingRow[], risk: Map<string, ThreatEntry>, _evidenceById: Map<string, Evidence>, now = Date.now()): QueueBase {
  const run = d.run
  const riskRank = (o: string) => ({ critical: 0, high: 1, medium: 2, low: 3 } as Record<string, number>)[risk.get(o)?.riskTier ?? ''] ?? 4
  const base: QueueBase = { decide: [], review: [], follow: [], done: [] }
  if (run.status === 'waiting' && (run.phase === 'consent' || run.phase === 'review')) {
    base.decide.push({ key: consentKey(run), kind: 'consent', title: run.phase === 'review' ? 'Approve scope to start the run' : 'Approve discovery to start the run', t: run.createdAt })
  }
  for (const a of d.approvals.slice().sort((x, y) => x.createdAt - y.createdAt)) {
    const it: QueueItem = { key: 'ap:' + a.id, kind: 'approval', ap: a, title: a.method + ' ' + host(a.origin) + a.pathAndQuery, t: a.createdAt }
    ;(a.status === 'pending' && !isApprovalExpired(a, now) ? base.decide : base.done).push(it)
  }
  // Follow-ups send a real `inject_hint` command only while the run can still plan.
  const canScheduleFollowUp = run.phase !== 'complete' && !['complete', 'stopped', 'failed'].includes(run.status)
  if (canScheduleFollowUp) {
    for (const x of d.coverageEntries.filter(c => c.status === 'needs_follow_up')) {
      base.follow.push({ key: 'cv:' + x.id, kind: 'follow', cov: x, title: firstSentence(x.summary), origins: [x.origin], t: x.updatedAt || run.createdAt, risk: riskRank(x.origin) })
    }
    base.follow.sort((a, b) => a.kind === 'follow' && b.kind === 'follow' ? a.risk - b.risk || host(a.cov.origin).localeCompare(host(b.cov.origin)) : 0)
  }
  base.done.sort((a, b) => b.t - a.t)
  return base
}

// ---------------------------------------------------------------- surface (D's matrix)

export interface SurfaceOrigin {
  origin: string
  host: string
  tier: RiskTier
  tags: string[]
  rationale: string
  /** findings / exchanges (in the loaded window) / charted categories */
  nf: number
  nx: number
  ncov: number
}

export interface SurfaceModel {
  origins: SurfaceOrigin[]
  /** true when nothing is recorded yet and the rows are just the project seeds */
  ghost: boolean
  apex: string | null
  /** cov[origin][category] */
  cov: Record<string, Record<string, Coverage>>
  /** findings by origin, and by `origin|category` cell (sorted by severity, then status) */
  findingsByOrigin: Record<string, FindingRow[]>
  findingsByCell: Record<string, FindingRow[]>
  workersByOrigin: Record<string, Set<string>>
  approvalsByOrigin: Record<string, Approval[]>
  maxExchanges: number
}

export const cellKey = (origin: string, category: string) => origin + '|' + category
export const cellStatus = (m: SurfaceModel, origin: string, category: string) => m.cov[origin]?.[category]?.status ?? 'untested'

function buildSurface(d: Detail, findings: readonly FindingRow[], ix: Pick<RunModel, 'findingById' | 'workerById' | 'exchangesByOrigin' | 'risk'>): SurfaceModel {
  const set = new Map<string, true>()
  const add = (o: string | null | undefined) => { if (o && !set.has(o)) set.set(o, true) }
  d.run.candidates.forEach(c => add(c.origin))
  d.coverageEntries.forEach(x => add(x.origin))
  findings.forEach(f => add(f.origin))
  d.exchangesSummary.forEach(e => add(e.origin))
  let ghost = false
  if (!set.size) { d.project.seeds.forEach(s => add(/^https?:\/\//.test(s) ? s : 'https://' + s)); ghost = true }
  const apex = sharedApex([...set.keys()].map(host))
  const cov: SurfaceModel['cov'] = {}
  d.coverageEntries.forEach(x => { (cov[x.origin] ??= {})[x.category] = x })
  const fBy: Record<string, FindingRow[]> = {}
  const fCell: Record<string, FindingRow[]> = {}
  for (const f of findings) {
    (fBy[f.origin] ??= []).push(f)
    const cat = covCat(f.category)
    if (cat) (fCell[cellKey(f.origin, cat)] ??= []).push(f)
  }
  for (const cv of d.coverageEntries) {
    if (!cv.linkedFindingId) continue
    const f = ix.findingById.get(cv.linkedFindingId)
    const k = cellKey(cv.origin, cv.category)
    if (f && !(fCell[k] ?? []).includes(f)) (fCell[k] ??= []).push(f)
  }
  const fs = (a: FindingRow, b: FindingRow) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || ((FSTAT_ORDER[a.status] ?? 9) - (FSTAT_ORDER[b.status] ?? 9))
  Object.values(fBy).forEach(a => a.sort(fs))
  Object.values(fCell).forEach(a => a.sort(fs))
  const wBy: Record<string, Set<string>> = {}
  const addW = (o: string, wid: string | null | undefined) => { if (wid && ix.workerById.has(wid)) (wBy[o] ??= new Set()).add(wid) }
  d.assignments.forEach(a => { if (a.sourceOrigins.length <= 3) a.sourceOrigins.forEach(o => addW(o, a.id)) })
  d.exchangesSummary.forEach(e => addW(e.origin, e.assignmentId))
  d.coverageEntries.forEach(x => addW(x.origin, x.assignmentId))
  const apprBy: Record<string, Approval[]> = {}
  d.approvals.forEach(a => (apprBy[a.origin] ??= []).push(a))
  const origins: SurfaceOrigin[] = [...set.keys()].map(o => {
    const t = ix.risk.get(o)
    return {
      origin: o, host: host(o), tier: (t?.riskTier ?? 'unranked') as RiskTier, tags: t?.surfaceTags ?? [], rationale: t?.rationale ?? '',
      nf: (fBy[o] ?? []).length, nx: (ix.exchangesByOrigin.get(o) ?? []).length, ncov: Object.keys(cov[o] ?? {}).length,
    }
  })
  return { origins, ghost, apex, cov, findingsByOrigin: fBy, findingsByCell: fCell, workersByOrigin: wBy, approvalsByOrigin: apprBy, maxExchanges: Math.max(1, ...origins.map(o => o.nx)) }
}

// ---------------------------------------------------------------- workflow inputs

export interface WorkflowEdge { from: string; to: string; kind: 'handoff' | 'causal' }
export interface WorkflowModel {
  /** Phase columns in order: discovery, threat_model, investigation, verification, then any extra (retest). */
  phases: string[]
  byPhase: Map<string, Assignment[]>
  /** `input_assignment_id` handoffs (solid) and causal links via parent facts / step dependencies (dashed). */
  edges: WorkflowEdge[]
  upstream: Map<string, WorkflowEdge[]>
  downstream: Map<string, WorkflowEdge[]>
}

function buildWorkflow(d: Detail, ix: Pick<RunModel, 'workerById' | 'factById' | 'stepById'>): WorkflowModel {
  const base = ['discovery', 'threat_model', 'investigation', 'verification']
  const extra = [...new Set(d.assignments.map(a => a.phase))].filter(p => !base.includes(p)).sort((a, b) => (PHASE_ORDER[a] ?? 9) - (PHASE_ORDER[b] ?? 9))
  const phases = base.concat(extra)
  const byPhase = new Map<string, Assignment[]>(phases.map(p => [p, []]))
  d.assignments.forEach(a => byPhase.get(a.phase)?.push(a))
  const edges: WorkflowEdge[] = []
  const seen = new Set<string>()
  const push = (from: string | null | undefined, to: string, kind: WorkflowEdge['kind']) => {
    if (!from || from === to || !ix.workerById.has(from)) return
    const k = from + '>' + to
    if (seen.has(k)) return
    seen.add(k)
    edges.push({ from, to, kind })
  }
  for (const a of d.assignments) push(a.inputAssignmentId, a.id, 'handoff')
  for (const a of d.assignments) {
    for (const fid of a.parentFactIds) push(ix.factById.get(fid)?.assignmentId, a.id, 'causal')
    const step = a.stepId ? ix.stepById.get(a.stepId) : undefined
    if (step) {
      for (const sid of step.dependsOnStepIds) push(ix.stepById.get(sid)?.assignedWorkerId, a.id, 'causal')
      for (const fid of step.dependsOnFactIds) push(ix.factById.get(fid)?.assignmentId, a.id, 'causal')
    }
  }
  const upstream = new Map<string, WorkflowEdge[]>()
  const downstream = new Map<string, WorkflowEdge[]>()
  for (const e of edges) {
    upstream.set(e.to, [...(upstream.get(e.to) ?? []), e])
    downstream.set(e.from, [...(downstream.get(e.from) ?? []), e])
  }
  return { phases, byPhase, edges, upstream, downstream }
}

/** Full upstream and downstream lineage of a worker (transitive). */
export function lineage(w: WorkflowModel, id: string) {
  const walk = (start: string, next: Map<string, WorkflowEdge[]>, pick: (e: WorkflowEdge) => string) => {
    const out = new Set<string>()
    const stack = [start]
    while (stack.length) {
      for (const e of next.get(stack.pop()!) ?? []) {
        const n = pick(e)
        if (!out.has(n)) { out.add(n); stack.push(n) }
      }
    }
    return out
  }
  return { up: walk(id, w.upstream, e => e.from), down: walk(id, w.downstream, e => e.to) }
}

// ---------------------------------------------------------------- the model

export interface RunModel {
  detail: Detail
  run: Run
  /** Run start and the latest timestamp seen in the detail (end of the run, or "now" while live). */
  base: number
  end: number
  /** Current (non-superseded) findings. `allFindings` includes superseded rows. */
  findings: FindingRow[]
  allFindings: FindingRow[]
  findingById: Map<string, FindingRow>
  workerById: Map<string, Assignment>
  stepById: Map<string, ChainStep>
  stepByWorker: Map<string, ChainStep>
  exchangeById: Map<string, Exchange>
  evidenceById: Map<string, Evidence>
  factById: Map<string, Fact>
  approvalById: Map<string, Approval>
  factsByWorker: Map<string, Fact[]>
  evidenceByWorker: Map<string, Evidence[]>
  exchangesByWorker: Map<string, Exchange[]>
  exchangesByOrigin: Map<string, Exchange[]>
  /** finding ↔ worker: workers that recorded the finding's cited evidence or made its cited exchanges (no chain-fact authors, no invented links) */
  findingWorkers: Map<string, string[]>
  workerFindings: Map<string, FindingRow[]>
  /** exchange → findings that cite it; evidence → findings that cite it */
  exchangeFindings: Map<string, FindingRow[]>
  evidenceFindings: Map<string, FindingRow[]>
  risk: Map<string, ThreatEntry>
  /** Approved scope origins (falls back to project seeds before consent). */
  scopeOrigins: string[]
  queue: QueueBase
  /** queue item lookup by key, across all sections */
  queueItem: Map<string, QueueItem>
  surface: SurfaceModel
  workflow: WorkflowModel
  /** Latest report, if any. */
  report: Report | null
  /** Coordinator thread (operator, coordinator and kovo messages) and worker report messages. */
  coordinatorMessages: Message[]
  workerMessages: Message[]
  /** Model missing: scope approved and the run is in a model-driven phase without a usable model. */
  needsModel: boolean
}

const group = <T, K>(items: readonly T[], key: (t: T) => K | null | undefined) => {
  const m = new Map<K, T[]>()
  for (const it of items) {
    const k = key(it)
    if (k == null) continue
    const list = m.get(k)
    if (list) list.push(it)
    else m.set(k, [it])
  }
  return m
}

function pushTimestamp(times: number[], value: unknown) {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) times.push(value)
}

/**
 * Derive the latest known timestamp for a run without snapping backward when the run pauses
 * or finishes: incorporates `endedAt`/`updatedAt` on the run, assignments, chain steps,
 * coverage entries, board members, approvals (`decidedAt`), patch proposals, and endpoints.
 */
export function computeRunEnd(d: Detail): number {
  const times: number[] = []
  const runMeta = d.run as Detail['run'] & { endedAt?: number | null; updatedAt?: number | null }
  pushTimestamp(times, d.run.createdAt)
  pushTimestamp(times, runMeta.endedAt)
  pushTimestamp(times, runMeta.updatedAt)
  pushTimestamp(times, d.run.phase0CompletedAt)
  for (const e of d.exchangesSummary) {
    pushTimestamp(times, e.createdAt)
    if (typeof e.durationMs === 'number' && Number.isFinite(e.durationMs) && e.durationMs > 0) {
      pushTimestamp(times, e.createdAt + e.durationMs)
    }
  }
  for (const a of d.assignments) {
    const am = a as Assignment & { endedAt?: number | null; updatedAt?: number | null }
    pushTimestamp(times, a.createdAt)
    pushTimestamp(times, am.endedAt)
    pushTimestamp(times, am.updatedAt)
  }
  for (const s of d.chainSteps) {
    pushTimestamp(times, s.createdAt)
    pushTimestamp(times, s.updatedAt)
  }
  for (const c of d.coverageEntries) pushTimestamp(times, c.updatedAt)
  for (const a of d.approvals) {
    pushTimestamp(times, a.createdAt)
    pushTimestamp(times, a.decidedAt)
  }
  for (const b of d.boardMembers) {
    pushTimestamp(times, b.createdAt)
    pushTimestamp(times, b.updatedAt)
  }
  for (const b of d.boardMessages) pushTimestamp(times, b.createdAt)
  for (const f of d.facts) pushTimestamp(times, f.createdAt)
  for (const e of d.evidence) pushTimestamp(times, e.createdAt)
  for (const m of d.messages) pushTimestamp(times, m.createdAt)
  for (const r of d.reports) pushTimestamp(times, r.createdAt)
  for (const r of d.retestRuns) pushTimestamp(times, r.createdAt)
  for (const p of d.patchProposals ?? []) {
    pushTimestamp(times, p.createdAt)
    pushTimestamp(times, p.updatedAt)
  }
  for (const ep of d.endpoints ?? []) {
    pushTimestamp(times, ep.createdAt)
    pushTimestamp(times, ep.updatedAt)
  }
  return times.length ? Math.max(...times) : d.run.createdAt
}

export function buildRunModel(d: Detail, now = Date.now()): RunModel {
  const allFindings = d.findings
  const findings = allFindings.filter(f => !f.supersededByFindingId)
  const findingById = new Map(allFindings.map(f => [f.id, f]))
  const workerById = new Map(d.assignments.map(a => [a.id, a]))
  const stepById = new Map(d.chainSteps.map(s => [s.id, s]))
  const stepByWorker = new Map(d.chainSteps.filter(s => s.assignedWorkerId).map(s => [s.assignedWorkerId!, s]))
  const exchangeById = new Map(d.exchangesSummary.map(e => [e.id, e]))
  const evidenceById = new Map(d.evidence.map(e => [e.id, e]))
  const factById = new Map(d.facts.map(f => [f.id, f]))
  const approvalById = new Map(d.approvals.map(a => [a.id, a]))
  const factsByWorker = group(d.facts, f => f.assignmentId)
  const evidenceByWorker = group(d.evidence, e => e.assignmentId)
  const exchangesByWorker = group(d.exchangesSummary, e => e.assignmentId)
  const exchangesByOrigin = group(d.exchangesSummary, e => e.origin)

  const findingWorkers = new Map<string, string[]>()
  const workerFindings = new Map<string, FindingRow[]>()
  const exchangeFindings = new Map<string, FindingRow[]>()
  const evidenceFindings = new Map<string, FindingRow[]>()
  // A worker counts for a finding only if it produced or verified it: it recorded the
  // cited evidence, or it made a cited exchange. Chain facts are deliberately excluded:
  // they are upstream inputs another worker built on (the workflow lineage shows them),
  // so counting their authors inflated "Found by" and the "With findings" filter.
  for (const f of findings) {
    const w = new Set<string>()
    for (const e of f.evidenceIds) {
      const ev = evidenceById.get(e)
      if (ev?.assignmentId) w.add(ev.assignmentId)
      evidenceFindings.set(e, [...(evidenceFindings.get(e) ?? []), f])
    }
    for (const e of f.exchangeIds ?? []) {
      const ex = exchangeById.get(e)
      if (ex?.assignmentId) w.add(ex.assignmentId)
      exchangeFindings.set(e, [...(exchangeFindings.get(e) ?? []), f])
    }
    const ws = [...w].filter(a => workerById.has(a))
    findingWorkers.set(f.id, ws)
    for (const a of ws) workerFindings.set(a, [...(workerFindings.get(a) ?? []), f])
  }

  const end = computeRunEnd(d)

  const risk = new Map((d.threatModel?.entries ?? []).map(e => [e.origin, e]))
  const approved = new Set(d.run.approved)
  const scopeFromCandidates = d.run.candidates.filter(c => approved.has(c.id)).map(c => c.origin)
  const scopeOrigins = scopeFromCandidates.length ? scopeFromCandidates : d.project.seeds

  const queue = buildQueue(d, findings, risk, evidenceById, now)
  const queueItem = new Map<string, QueueItem>()
  for (const list of Object.values(queue)) for (const it of list) queueItem.set(it.key, it)

  const partial = { findingById, workerById, exchangesByOrigin, risk, factById, stepById }
  const surface = buildSurface(d, findings, partial)
  const workflow = buildWorkflow(d, partial)
  const report = d.reports.slice().sort((a, b) => b.version - a.version)[0] ?? null
  const coordinatorMessages = d.messages.filter(m => m.threadId === d.run.coordinatorId || m.role === 'operator' || m.role === 'kovo')
  const workerMessages = d.messages.filter(m => m.role === 'worker')
  const needsModel = !d.hasModel && d.run.approved.length > 0 && ['threat_model', 'investigation', 'verification'].includes(d.run.phase)
    && d.run.status !== 'complete' && d.run.status !== 'stopped'

  return {
    detail: d, run: d.run, base: d.run.createdAt, end,
    findings, allFindings, findingById, workerById, stepById, stepByWorker, exchangeById, evidenceById, factById, approvalById,
    factsByWorker, evidenceByWorker, exchangesByWorker, exchangesByOrigin,
    findingWorkers, workerFindings, exchangeFindings, evidenceFindings,
    risk, scopeOrigins, queue, queueItem, surface, workflow, report, coordinatorMessages, workerMessages, needsModel,
  }
}

// ---------------------------------------------------------------- small selectors

/** Findings sorted most serious first: severity, then confirmed before unverified, chains first. */
export function bySeriousness(a: FindingRow, b: FindingRow) {
  return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || ((FSTAT_ORDER[a.status] ?? 9) - (FSTAT_ORDER[b.status] ?? 9))
    || (Number(b.findingKind === 'multi_step_chain') - Number(a.findingKind === 'multi_step_chain'))
}

export function worstSeverity(list: readonly FindingRow[]): Severity {
  return list.reduce<Severity>((s, f) => (SEV_ORDER[f.severity] < SEV_ORDER[s] ? f.severity : s), 'informational')
}

/** Coverage counts by status, in display order. */
export function coverageCounts(cov: readonly Coverage[]) {
  const order = ['reported', 'needs_follow_up', 'no_issue_found', 'ruled_out', 'not_applicable'] as const
  const ct: Record<string, number> = {}
  for (const x of cov) ct[x.status] = (ct[x.status] ?? 0) + 1
  return order.filter(k => ct[k]).map(k => ({ status: k, label: COV_L[k], count: ct[k] }))
}

/** Exchange (and broker denial) histogram across the run's timeline. */
export function trafficHistogram(m: RunModel, events: readonly RunEvent[], bins = 36) {
  const t0 = m.base
  const tEnd = Math.max(m.end, events.length ? events[events.length - 1].createdAt : 0)
  const span = Math.max(1, tEnd - t0)
  const out = Array.from({ length: bins }, () => [0, 0] as [number, number])
  const put = (t: number, k: 0 | 1) => { out[Math.min(bins - 1, Math.max(0, Math.floor((t - t0) / span * bins)))][k]++ }
  const allowed = events.filter(e => e.kind === 'broker.allowed')
  // Prefer the event stream (complete); fall back to the loaded exchange window.
  if (allowed.length) allowed.forEach(e => put(e.createdAt, 0))
  else m.detail.exchangesSummary.forEach(e => put(e.createdAt, 0))
  events.filter(e => e.kind === 'broker.denied').forEach(e => put(e.createdAt, 1))
  return { bins: out, t0, t1: tEnd, max: Math.max(1, ...out.map(b => b[0] + b[1])) }
}
