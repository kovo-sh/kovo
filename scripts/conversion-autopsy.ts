// Read-only conversion autopsy for the agentic recall gap.
//
// Question: of the planted-but-unfound targets, how far did each planned investigation get?
// Buckets (exactly one per target row):
//   never_dispatched                  no agent request was ever made on the target route
//   route_hit_no_verify               target route requested, no verify tool/spec ever attempted
//   verify_called_but_oracle_rejected a verify verdict artifact exists and is non-confirming
//   probed_missed_bug                 probes + a spec attempt, but no verdict artifact (evidence
//                                     simply did not show the bug)
//
// Reads kept benchmark data dirs (sqlite + result JSON) and the app blueprints to resolve the
// per-seed route map. It never writes to the data dirs, never opens a worker, never runs a
// benchmark, and never prints response bodies, payloads or credentials.
//
// Usage:
//   node scripts/conversion-autopsy.ts [--json <path>]
//
// Env:
//   GUARDIAN_RB_HELDOUT_SALT  required for salted held-out seeds (or read from the owner-only
//                             file listed below). The value is never printed.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { join } from 'node:path'

import { blueprint as acme } from '../benchmarks/realistic-bench/apps/acme-saas/truth/blueprint.ts'
import { blueprint as opsportal } from '../benchmarks/realistic-bench/apps/opsportal/truth/blueprint.ts'
import { blueprint as shopflow } from '../benchmarks/realistic-bench/apps/shopflow/truth/blueprint.ts'
import { generateVariant } from '../benchmarks/realistic-bench/generator/variant.ts'
import type { AppBlueprint, VariantPlan } from '../benchmarks/realistic-bench/lib/types.ts'

const BLUEPRINTS: Record<string, AppBlueprint> = {
  'acme-saas': acme,
  opsportal,
  shopflow,
}

type Cell = {
  suite: 'dev' | 'heldout'
  root: string
  app: string
  seed: number
  slug: string
}

const CELLS: Cell[] = [
  { suite: 'dev', root: '/tmp/dev-final', app: 'acme-saas', seed: 1, slug: 'acme-saas-seed1-grey-box' },
  { suite: 'dev', root: '/tmp/dev-final', app: 'opsportal', seed: 1, slug: 'opsportal-seed1-grey-box' },
  { suite: 'dev', root: '/tmp/dev-final', app: 'shopflow', seed: 1, slug: 'shopflow-seed1-grey-box' },
  { suite: 'heldout', root: '/tmp/heldout-final', app: 'acme-saas', seed: 1000042, slug: 'acme-saas-seed1000042-grey-box' },
  { suite: 'heldout', root: '/tmp/heldout-final', app: 'opsportal', seed: 1000042, slug: 'opsportal-seed1000042-grey-box' },
  { suite: 'heldout', root: '/tmp/heldout-final', app: 'shopflow', seed: 1000042, slug: 'shopflow-seed1000042-grey-box' },
]

const HELDOUT_SALT_FILE = '/home/omarchy/.config/guardian-bench/heldout.salt'
const VERIFY_TOOLS = new Set(['guardian_verify', 'verify_replay_spec'])

type Bucket = 'never_dispatched' | 'route_hit_no_verify' | 'verify_called_but_oracle_rejected' | 'probed_missed_bug'

type Route = { method: string, path: string }

type ToolCall = { name: string, args: string }

function readSalt(): string | undefined {
  if (process.env.GUARDIAN_RB_HELDOUT_SALT) return process.env.GUARDIAN_RB_HELDOUT_SALT.trim()
  if (existsSync(HELDOUT_SALT_FILE)) return readFileSync(HELDOUT_SALT_FILE, 'utf8').trim()
  return undefined
}

function planFor(app: string, seed: number, salt: string | undefined): VariantPlan {
  const bp = BLUEPRINTS[app]
  if (!bp) throw new Error(`unknown app ${app}`)
  return generateVariant(bp, seed, seed >= 1_000_000 && salt ? { salt } : undefined)
}

function cleanPath(p: string): string {
  const q = p.indexOf('?')
  return q >= 0 ? p.slice(0, q) : p
}

function segs(p: string): string[] {
  return cleanPath(p).split('/').filter(Boolean)
}

/** Template segments (`:param`) match exactly one path segment. */
function routeMatches(template: Route, method: string, path: string): boolean {
  if (template.method.toUpperCase() !== method.toUpperCase()) return false
  const a = segs(template.path)
  const b = segs(path)
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    const t = a[i]!
    if (t.startsWith(':')) continue
    if (t !== b[i]) return false
  }
  return true
}

function toolCallsForSession(sessionPath: string): ToolCall[] {
  if (!existsSync(sessionPath)) return []
  const db = new DatabaseSync(sessionPath, { readOnly: true })
  const out: ToolCall[] = []
  try {
    for (const row of db.prepare('select record from entries order by id').all() as { record: string }[]) {
      let doc: any
      try { doc = JSON.parse(row.record) } catch { continue }
      for (const msg of doc.model ?? []) {
        const content = msg?.content
        if (!Array.isArray(content)) continue
        for (const part of content) {
          if (part && part.type === 'toolCall' && typeof part.name === 'string') {
            out.push({ name: part.name, args: typeof part.arguments === 'string' ? part.arguments : JSON.stringify(part.arguments ?? '') })
          }
        }
      }
    }
  } finally {
    db.close()
  }
  return out
}

type Rejection = {
  verdict: string
  endpoint: string
  failedStepId: string | null
  controlPassed: boolean | null
  reasonCode: string
  reason: string
}

function normalizeRejection(diffText: string | null): Rejection | null {
  if (!diffText) return null
  let d: any
  try { d = JSON.parse(diffText) } catch { return null }
  const reason: string = typeof d?.assertionSummary?.reason === 'string' ? d.assertionSummary.reason : ''
  return {
    verdict: String(d?.verdict ?? 'unknown'),
    endpoint: String(d?.verifiedEndpoint ?? ''),
    failedStepId: d?.failedStepId ?? null,
    controlPassed: typeof d?.controlPassed === 'boolean' ? d.controlPassed : null,
    reasonCode: reasonCodeFor(reason),
    reason: reason.length > 260 ? `${reason.slice(0, 257)}...` : reason,
  }
}

/** Collapse free-text oracle reasons to a small stable vocabulary (no payloads). */
function reasonCodeFor(reason: string): string {
  const r = reason.toLowerCase()
  if (!r) return 'no_reason'
  if (r.includes('not a json record') || r.includes('cannot be bound to an object-scoped attribute')) return 'unbindable_non_json_body'
  if (r.includes('no object-scoped attribute') || r.includes('identifier-binding non-public attribute')) return 'no_bound_object_attribute'
  if (r.includes('no privilege/ownership differential') || r.includes('not in the resource tenant')) return 'no_cross_actor_differential'
  if (r.includes('no successful mutating probe step')) return 'no_mutating_probe'
  if (r.includes('no separate post-mutation get readback')) return 'no_readback'
  if (r.includes('no genuine control-vs-probe differential')) return 'no_control_differential'
  if (r.includes('status-only') || r.includes('status equality')) return 'status_only'
  if (r.includes('csrf') && r.includes('not carry a csrf_state_change')) return 'csrf_no_impact_oracle'
  if (r.includes('csrf') && r.includes('same-origin')) return 'csrf_not_cross_site'
  if (r.includes('no positive semantic oracle')) return 'no_semantic_oracle'
  if (r.includes('requirecontrolnonerror') || r.includes('unexpected http 404')) return 'control_error_status'
  if (r.includes('publicly readable')) return 'publicly_readable'
  if (r.includes('readback is identical')) return 'no_persisted_impact'
  if (r.includes('proof-of-execution check did not pass')) return 'execution_marker_absent'
  if (r.includes('not served the resource')) return 'actor_not_served'
  return 'other'
}

function endReasonFor(a: any): string {
  if (!a) return 'never_assigned'
  const outcome = typeof a.outcome === 'string' ? a.outcome : ''
  if (a.status === 'canceled' && /provider stream stalled/i.test(outcome)) return 'provider_stall'
  if (a.status === 'canceled') return `canceled:${outcome.slice(0, 40) || 'unknown'}`
  if (a.status === 'paused') return 'wall_clock_pause'
  if (a.status === 'complete' && /reached maxturns/i.test(outcome)) return 'max_turns_no_complete_intent'
  if (a.status === 'complete') return 'completed'
  return a.status ?? 'unknown'
}

function pct(n: number, d: number): string {
  return d === 0 ? '0%' : `${Math.round((100 * n) / d)}%`
}

type Row = {
  suite: string
  app: string
  target: string
  vulnClass: string
  severity: string
  truthBucket: string
  autopsyBucket: Bucket
  subReason: string
  routes: string[]
  unit: 'dispatched' | 'planned_not_dispatched' | 'never_planned'
  stepSeq: number | null
  stepStatus: string | null
  assignmentId: string | null
  turns: string
  turnsUsed: number
  maxTurns: number
  endReason: string
  lastTools: string[]
  verifyCalls: number
  specAttempts: number
  proofGapCode: string
  rejection: Rejection | null
  observedRequests: number
}

function analyzeCell(cell: Cell, salt: string | undefined) {
  const dir = join(cell.root, 'data', cell.slug)
  const cellJson = JSON.parse(readFileSync(join(cell.root, `${cell.slug}.json`), 'utf8'))
  const meta = JSON.parse(readFileSync(join(cell.root, `${cell.slug}.meta.json`), 'utf8'))
  if (!existsSync(join(dir, 'guardian.sqlite'))) throw new Error(`missing db for ${cell.slug}`)

  const plan = planFor(cell.app, cell.seed, salt)
  const bp = BLUEPRINTS[cell.app]!
  const specById = new Map(bp.sites.map((s) => [s.id, s] as const))

  const db = new DatabaseSync(join(dir, 'guardian.sqlite'), { readOnly: true })
  const q = <T>(sql: string, ...params: any[]): T[] => db.prepare(sql).all(...params) as T[]

  const assignments = q<any>(`select id, step_id, status, turns_used, max_turns, requests_used, session_id, title, outcome
    from assignments where phase = 'investigation' order by created_at`)
  const steps = new Map<string, any>()
  for (const s of q<any>(`select id, seq, status, title, hypothesis, priority, trial_index, specialist_profile from chain_steps`)) {
    steps.set(s.id, s)
  }
  const exchanges = q<any>(`select assignment_id, method, path_and_query from broker_exchanges`)
  const coverage = q<any>(`select assignment_id, category, status, proof_gap_reason from coverage_entries`)
  const specs = q<any>(`select id, assignment_id, finding_id, verified_inline, last_verification_diff from replay_specs`)
  const findings = q<any>(`select id, provenance, verification_class, json_extract(finding,'$.status') as status,
    json_extract(finding,'$.title') as title from findings`)
  const events = q<any>(`select kind, detail from events where kind in
    ('worker.provider_stall','worker.stall_retry','worker.started','worker.complete','scheduler.dispatch','finding.proposed','finding.verified')`)
  db.close()

  const findingById = new Map(findings.map((f) => [f.id, f] as const))

  const traces = new Map<string, ToolCall[]>()
  for (const a of assignments) {
    traces.set(a.id, toolCallsForSession(join(dir, 'agent-sessions', `${a.session_id}.sqlite`)))
  }

  const isEngine = (a: any) => /deterministic differential engine/i.test(a.title)
  const agentAssignments = assignments.filter((a) => !isEngine(a))

  const exByAssignment = new Map<string, { method: string, path: string }[]>()
  for (const e of exchanges) {
    const list = exByAssignment.get(e.assignment_id) ?? []
    list.push({ method: e.method, path: cleanPath(e.path_and_query) })
    exByAssignment.set(e.assignment_id, list)
  }

  const routesFor = (siteId: string): Route[] => {
    const spec = specById.get(siteId)
    if (!spec) return []
    const keys = [...spec.routeKeys, ...(spec.triggerRouteKeys ?? [])]
    const seen = new Set<string>()
    const out: Route[] = []
    for (const k of keys) {
      const r = plan.routes[k]
      if (!r) continue
      const key = `${r.method} ${r.path}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push(r)
    }
    return out
  }

  /**
   * Blueprint route templates for plan-text matching. Planner prose quotes the blueprint nouns
   * (`/api/{noun:webhooks}/receive` -> `/api/webhooks/receive`) while the runtime instance uses the
   * seed's noun (`/api/event-hooks/charges`), so plan matching must accept both spellings.
   */
  const planRoutesFor = (siteId: string): Route[] => {
    const spec = specById.get(siteId)
    if (!spec) return []
    const out: Route[] = [...routesFor(siteId)]
    for (const key of [...spec.routeKeys, ...(spec.triggerRouteKeys ?? [])]) {
      const r = bp.routes[key]
      if (!r) continue
      out.push({ method: r.method, path: r.path.replace(/\{noun:([a-zA-Z0-9_-]+)\}/g, '$1') })
    }
    return out
  }

  /**
   * Route mention in plan text. Planner text uses blueprint param names (`:creditId`) while the
   * runtime route uses the seed's param name (`:cardId`), so params are wildcards on both sides.
   */
  const exactMention = (siteId: string, text: string): string | null => {
    const tokens = (text.match(/\/[a-zA-Z0-9._~/:{}-]+/g) ?? [])
      .map((t) => t.replace(/[.,;:]+$/, ''))
      .filter((t) => t.length >= 9 && t.startsWith('/api'))
    let best: string | null = null
    for (const r of planRoutesFor(siteId)) {
      const rSegs = segs(r.path)
      for (const tok of tokens) {
        const tSegs = segs(tok)
        if (tSegs.length < 2 || tSegs.length > rSegs.length) continue
        let ok = true
        for (let i = 0; i < tSegs.length; i++) {
          const a = tSegs[i]!
          const b = rSegs[i]!
          if (a.startsWith(':') || a.startsWith('{') || b.startsWith(':')) continue
          if (a.toLowerCase() !== b.toLowerCase()) { ok = false; break }
        }
        if (ok && (!best || tok.length > best.length)) best = tok
      }
    }
    return best
  }

  const verifyCallsOnTarget = (assignmentId: string, routes: Route[]): number => {
    const calls = traces.get(assignmentId) ?? []
    let n = 0
    for (const c of calls) {
      if (!VERIFY_TOOLS.has(c.name)) continue
      if (routes.some((r) => c.args.includes(r.path))) n++
    }
    return n
  }

  const specOnTarget = (assignmentId: string, routes: Route[]) => {
    const out: any[] = []
    for (const s of specs) {
      if (s.assignment_id !== assignmentId) continue
      const rej = normalizeRejection(s.last_verification_diff)
      const ep = rej?.endpoint ?? ''
      const sp = ep.indexOf(' ')
      const epMethod = sp >= 0 ? ep.slice(0, sp) : ''
      const epPath = sp >= 0 ? ep.slice(sp + 1) : ''
      const viaEndpoint = !!epPath && routes.some((r) => routeMatches(r, epMethod || 'GET', epPath))
      const findingTitle = findingById.get(s.finding_id)?.title ?? ''
      const viaTitle = routes.some((r) => findingTitle.includes(r.path))
      if (viaEndpoint || viaTitle) out.push({ ...s, rej })
    }
    return out
  }

  const assignedStepIds = new Set(assignments.map((a) => a.step_id).filter(Boolean))
  const unassignedSteps = [...steps.values()].filter((s) => !assignedStepIds.has(s.id))
  const targets = (cellJson.vulns ?? []).filter((v: any) => v.outcome !== 'confirmed')
  let touchedTargets = 0
  for (const v of targets) {
    const routes = routesFor(v.siteId)
    const hit = agentAssignments.some((a) => (exByAssignment.get(a.id) ?? []).some((e) => routes.some((r) => routeMatches(r, e.method, e.path))))
    if (hit) touchedTargets++
  }

  const rows: Row[] = []
  for (const v of targets) {
    const routes = routesFor(v.siteId)
    const observed = agentAssignments
      .map((a) => ({
        a,
        n: (exByAssignment.get(a.id) ?? []).filter((e) => routes.some((r) => routeMatches(r, e.method, e.path))).length,
      }))
      .filter((x) => x.n > 0)
      .sort((x, y) => y.n - x.n)

    const plannedExact = agentAssignments
      .map((a) => {
        const step = steps.get(a.step_id)
        const text = `${step?.title ?? a.title} ${step?.hypothesis ?? ''}`
        const frag = exactMention(v.siteId, text)
        return frag ? { a, frag } : null
      })
      .filter(Boolean) as { a: any, frag: string }[]

    const queuedSteps = unassignedSteps
      .map((s) => {
        const text = `${s.title} ${s.hypothesis ?? ''}`
        const frag = exactMention(v.siteId, text)
        return frag ? { step: s, frag } : null
      })
      .filter(Boolean) as { step: any, frag: string }[]

    let unit: Row['unit'] = 'never_planned'
    let evidence: any = null
    let step: any = null
    if (observed.length > 0) {
      unit = 'dispatched'
      evidence = observed[0]!.a
      step = steps.get(evidence.step_id)
    } else if (plannedExact.length > 0) {
      unit = 'dispatched'
      evidence = plannedExact[0]!.a
      step = steps.get(evidence.step_id)
    } else if (queuedSteps.length > 0) {
      unit = 'planned_not_dispatched'
      step = queuedSteps[0]!.step
    }

    let bucket: Bucket
    let rejection: Rejection | null = null
    let verifyCalls = 0
    let specAttempts = 0
    let subReason = ''
    if (observed.length === 0) {
      bucket = 'never_dispatched'
      if (unit === 'never_planned') subReason = 'no_planned_step_named_route'
      else if (unit === 'planned_not_dispatched') {
        const st = step?.status ?? 'unknown'
        subReason = `step_${st}_never_assigned`
      } else {
        subReason = 'assigned_but_route_untouched'
      }
    } else {
      const pool = observed.map((o) => o.a)
      const primary = pool[0]!
      const specHits = pool.flatMap((a) => specOnTarget(a.id, routes).map((s) => ({ a, s })))
      verifyCalls = Math.max(0, ...pool.map((a) => verifyCallsOnTarget(a.id, routes)))
      // Bucket 2 means no verify call *bound to this route*; an unbound verify somewhere else in a
      // broad sweep does not discharge this target's proof.
      const verifyAny = verifyCalls > 0
      specAttempts = specHits.length
      const rejected = specHits.find((x) => x.s.rej && x.s.rej.verdict !== 'confirmed')
      if (rejected) {
        bucket = 'verify_called_but_oracle_rejected'
        rejection = rejected.s.rej
        subReason = `verdict_${rejection!.verdict}:${rejection!.reasonCode}`
      } else if (specAttempts > 0 || verifyAny) {
        bucket = 'probed_missed_bug'
        subReason = specAttempts > 0 ? 'spec_without_verdict' : 'verify_without_target_verdict'
      } else {
        bucket = 'route_hit_no_verify'
        subReason = 'no_verify_tool_or_spec_on_route'
      }
    }

    const proofGapRaw = evidence
      ? coverage.find((c) => c.assignment_id === evidence.id && c.proof_gap_reason)?.proof_gap_reason ?? null
      : null
    const calls = evidence ? traces.get(evidence.id) ?? [] : []

    rows.push({
      suite: cell.suite,
      app: cell.app,
      target: v.siteId,
      vulnClass: v.vulnClass,
      severity: v.severity,
      truthBucket: v.failureBucket ?? 'confirmed',
      autopsyBucket: bucket,
      subReason,
      routes: routes.map((r) => `${r.method} ${r.path}`),
      unit,
      stepSeq: step?.seq ?? null,
      stepStatus: step?.status ?? null,
      assignmentId: evidence?.id ?? null,
      turns: evidence ? `${evidence.turns_used}/${evidence.max_turns}` : '0/0',
      turnsUsed: evidence?.turns_used ?? 0,
      maxTurns: evidence?.max_turns ?? 0,
      endReason: endReasonFor(evidence),
      lastTools: calls.slice(-3).map((c) => c.name),
      verifyCalls,
      specAttempts,
      proofGapCode: proofGapRaw ? proofGapRaw.split(':')[0]!.trim().slice(0, 48) : 'none',
      rejection,
      observedRequests: observed[0]?.n ?? 0,
    })
  }

  // Planned steps that never got an assignment and name an unfound target route.
  for (const s of unassignedSteps) {
    const text = `${s.title} ${s.hypothesis ?? ''}`
    for (const v of targets) {
      if (rows.some((r) => r.target === v.siteId)) continue
      const frag = exactMention(v.siteId, text)
      if (!frag) continue
      const routes = routesFor(v.siteId)
      rows.push({
        suite: cell.suite,
        app: cell.app,
        target: v.siteId,
        vulnClass: v.vulnClass,
        severity: v.severity,
        truthBucket: v.failureBucket ?? 'confirmed',
        autopsyBucket: 'never_dispatched',
        subReason: `step_${s.status}_never_assigned`,
        routes: routes.map((r) => `${r.method} ${r.path}`),
        unit: 'planned_not_dispatched',
        stepSeq: s.seq,
        stepStatus: s.status,
        assignmentId: null,
        turns: '0/0',
        turnsUsed: 0,
        maxTurns: 0,
        endReason: `step_${s.status}`,
        lastTools: [],
        verifyCalls: 0,
        specAttempts: 0,
        proofGapCode: 'none',
        rejection: null,
        observedRequests: 0,
      })
    }
  }

  const verifiedAssignments = agentAssignments.filter((a) => (traces.get(a.id) ?? []).some((c) => VERIFY_TOOLS.has(c.name)))
  const dispatched = agentAssignments.filter((a) => (traces.get(a.id) ?? []).length > 0 || (exByAssignment.get(a.id) ?? []).length > 0)
  const canceled = agentAssignments.filter((a) => a.status === 'canceled')
  const paused = agentAssignments.filter((a) => a.status === 'paused')

  // A target is floor-confirmed unless the only matched findings are agent-only.
  let agentIncrementalTargets = 0
  for (const v of cellJson.vulns ?? []) {
    if (v.outcome !== 'confirmed') continue
    const matched = (v.matchedFindingIds ?? []).map((id: string) => findingById.get(id)).filter(Boolean)
    if (matched.length > 0 && matched.every((f: any) => f.provenance === 'agent_only')) agentIncrementalTargets++
  }

  const summary = {
    suite: cell.suite,
    app: cell.app,
    seed: cell.seed,
    targets: cellJson.targets ?? cellJson.vulns.length,
    confirmed: cellJson.confirmed,
    recall: cellJson.recall,
    precision: cellJson.precision,
    missed: targets.length,
    agentIncrementalTargets,
    floorConfirmed: cellJson.confirmed - agentIncrementalTargets,
    funnel: cellJson.funnel,
    failureBuckets: cellJson.failureBuckets,
    maxDurationMs: meta.maxDurationMs,
    durationMs: meta.durationMs,
    timedOut: meta.timedOut,
    terminalStatus: meta.terminalStatus,
    terminalPhase: meta.terminalPhase,
    workerConcurrency: meta.workerConcurrency,
    requestBudgets: meta.requestBudgets,
    investigations: {
      totalRows: assignments.length,
      agentAssignments: agentAssignments.length,
      dispatched: dispatched.length,
      distinctStepsAssigned: assignedStepIds.size,
      completed: agentAssignments.filter((a) => a.status === 'complete').length,
      canceled: canceled.length,
      paused: paused.length,
      verified: verifiedAssignments.length,
      neverVerified: dispatched.length - verifiedAssignments.length,
      canceledTurns: canceled.reduce((n, a) => n + a.turns_used, 0),
      pausedTurns: paused.reduce((n, a) => n + a.turns_used, 0),
      settlementReachedNoVerify: dispatched.filter((a) => a.max_turns > 0 && a.turns_used >= a.max_turns * 0.85
        && !(traces.get(a.id) ?? []).some((c) => VERIFY_TOOLS.has(c.name))).length,
      totalTurns: agentAssignments.reduce((n, a) => n + a.turns_used, 0),
      trialRows: agentAssignments.filter((a) => (steps.get(a.step_id)?.trial_index ?? 0) > 0).length,
      trialTurns: agentAssignments.filter((a) => (steps.get(a.step_id)?.trial_index ?? 0) > 0).reduce((n, a) => n + a.turns_used, 0),
      verifyCallTotal: agentAssignments.reduce((n, a) => n + (traces.get(a.id) ?? []).filter((c) => VERIFY_TOOLS.has(c.name)).length, 0),
    },
    plannedSteps: {
      total: steps.size,
      assigned: steps.size - [...steps.values()].filter((s) => !assignedStepIds.has(s.id)).length,
      neverAssigned: [...steps.values()].filter((s) => !assignedStepIds.has(s.id)).length,
      byStatus: [...steps.values()].filter((s) => !assignedStepIds.has(s.id))
        .reduce((m: Record<string, number>, s: any) => { m[s.status] = (m[s.status] ?? 0) + 1; return m }, {}),
    },
    providerStalls: events.filter((e) => e.kind === 'worker.provider_stall').length,
    stallRetries: events.filter((e) => e.kind === 'worker.stall_retry').length,
    dispatchEvents: events.filter((e) => e.kind === 'scheduler.dispatch').length,
    agentProposals: findings.filter((f) => f.provenance === 'agent_only').length,
    agentProposalOutcomes: findings.filter((f) => f.provenance === 'agent_only').reduce((m: Record<string, number>, f: any) => {
      m[`${f.status}/${f.verification_class}`] = (m[`${f.status}/${f.verification_class}`] ?? 0) + 1
      return m
    }, {}),
    targetsNeverTouchedByAgent: targets.length - touchedTargets,
    targetsTouched: touchedTargets,
    rows,
  }
  return summary
}

function main() {
  const argIdx = process.argv.indexOf('--json')
  const jsonOut = argIdx >= 0 ? process.argv[argIdx + 1] : null
  const salt = readSalt()
  const results = CELLS.map((c) => analyzeCell(c, salt))

  const totals: Record<Bucket, number> = {
    never_dispatched: 0,
    route_hit_no_verify: 0,
    verify_called_but_oracle_rejected: 0,
    probed_missed_bug: 0,
  }
  for (const r of results) for (const row of r.rows) totals[row.autopsyBucket]++

  const grand = (k: string) => results.reduce((n, r) => n + (r as any)[k], 0)

  // Cross-tab: truth failure bucket -> autopsy bucket (pair level).
  const crossTab: Record<string, Record<string, number>> = {}
  for (const r of results) {
    for (const x of r.rows) {
      const t = x.truthBucket
      crossTab[t] ??= {}
      crossTab[t]![x.autopsyBucket] = (crossTab[t]![x.autopsyBucket] ?? 0) + 1
    }
  }

  // Investigation roll-up: one bucket per dispatched assignment (furthest progress on any row).
  const rank: Record<Bucket, number> = {
    never_dispatched: 0,
    route_hit_no_verify: 1,
    probed_missed_bug: 2,
    verify_called_but_oracle_rejected: 3,
  }
  const byInvestigation = new Map<string, { bucket: Bucket, app: string, suite: string, rows: number }>()
  for (const r of results) {
    for (const x of r.rows) {
      if (!x.assignmentId) continue
      const key = `${r.suite}/${r.app}/${x.assignmentId}`
      const prev = byInvestigation.get(key)
      if (!prev || rank[x.autopsyBucket] > rank[prev.bucket]) {
        byInvestigation.set(key, { bucket: x.autopsyBucket, app: r.app, suite: r.suite, rows: (prev?.rows ?? 0) + 1 })
      } else {
        prev.rows++
      }
    }
  }
  const investigationTotals: Record<Bucket, number> = {
    never_dispatched: 0, route_hit_no_verify: 0, verify_called_but_oracle_rejected: 0, probed_missed_bug: 0,
  }
  for (const v of byInvestigation.values()) investigationTotals[v.bucket]++
  const queuedOnly = results.flatMap((r) => r.rows).filter((x) => !x.assignmentId).length
  const endReasonsByBucket = results.flatMap((r) => r.rows).reduce((m: Record<string, Record<string, number>>, x) => {
    m[x.autopsyBucket] ??= {}
    m[x.autopsyBucket]![x.endReason] = (m[x.autopsyBucket]![x.endReason] ?? 0) + 1
    return m
  }, {})
  const toolsByBucket = results.flatMap((r) => r.rows).reduce((m: Record<string, Record<string, number>>, x) => {
    m[x.autopsyBucket] ??= {}
    for (const t of x.lastTools) m[x.autopsyBucket]![t] = (m[x.autopsyBucket]![t] ?? 0) + 1
    return m
  }, {})

  console.log('suite    app        tgt conf miss | inc | never nover rej  prob | planned/assigned | dispatched verify distSteps stalls paused')
  for (const r of results) {
    const c = (b: Bucket) => r.rows.filter((x) => x.autopsyBucket === b).length
    console.log(
      `${r.suite.padEnd(8)} ${r.app.padEnd(10)} ${String(r.targets).padStart(3)} ${String(r.confirmed).padStart(4)} ${String(r.missed).padStart(4)} | ` +
      `${String(r.agentIncrementalTargets).padStart(3)} | ` +
      `${String(c('never_dispatched')).padStart(5)} ${String(c('route_hit_no_verify')).padStart(5)} ${String(c('verify_called_but_oracle_rejected')).padStart(4)} ${String(c('probed_missed_bug')).padStart(4)} | ` +
      `${String(r.plannedSteps.assigned).padStart(3)}/${String(r.plannedSteps.total).padStart(3)}          | ` +
      `${String(r.investigations.dispatched).padStart(3)} ${String(r.investigations.verified).padStart(4)} ${String(r.investigations.distinctStepsAssigned).padStart(4)} ` +
      `${String(r.providerStalls).padStart(6)} ${String(r.investigations.paused).padStart(6)}`,
    )
  }
  console.log('\nrows by bucket:', JSON.stringify(totals))
  console.log('investigations by furthest bucket:', JSON.stringify(investigationTotals), `(+${queuedOnly} planned units with no assignment)`)
  console.log(`totals: targets ${grand('targets')} confirmed ${grand('confirmed')} missed ${grand('missed')} agent-incremental ${grand('agentIncrementalTargets')}`)
  console.log(`totals: dispatched ${results.reduce((n, r) => n + r.investigations.dispatched, 0)} verified ${results.reduce((n, r) => n + r.investigations.verified, 0)} planned ${results.reduce((n, r) => n + r.plannedSteps.total, 0)} assigned ${results.reduce((n, r) => n + r.plannedSteps.assigned, 0)}`)
  console.log(`totals: stalls ${grand('providerStalls')} canceledTurns ${results.reduce((n, r) => n + r.investigations.canceledTurns, 0)} pausedTurns ${results.reduce((n, r) => n + r.investigations.pausedTurns, 0)} settlementNoVerify ${results.reduce((n, r) => n + r.investigations.settlementReachedNoVerify, 0)}`)
  console.log('cross-tab truth->autopsy:', JSON.stringify(crossTab))
  console.log('end reasons by bucket:', JSON.stringify(endReasonsByBucket))
  console.log('last-3 tools by bucket:', JSON.stringify(toolsByBucket))
  console.log(`rows by truth bucket: ${JSON.stringify(results.reduce((m: Record<string, number>, r) => {
    for (const x of r.rows) m[x.truthBucket] = (m[x.truthBucket] ?? 0) + 1
    return m
  }, {}))}`)

  if (jsonOut) {
    writeFileSync(jsonOut, JSON.stringify({
      generatedAt: new Date().toISOString(),
      totals,
      investigationTotals,
      queuedOnly,
      crossTab,
      endReasonsByBucket,
      toolsByBucket,
      results,
    }, null, 2))
    console.log(`wrote ${jsonOut}`)
  }
}

main()
