/**
 * v6 graphwire: Program-Graph code→runtime leads for the deterministic lane.
 *
 * Hypotheses already carry severity/confidence/probeClass; this module only maps the code
 * hypothesis family onto the engine `det_lead` probe namespace and builds the fact payload.
 * Dedupe, caps and step creation stay in the lane (`queueDetLeadUpgradeSteps`).
 */
import type { CodeToRuntimeHypothesis } from './program-graph.ts'
import type { Assignment, Run } from './store.ts'

/** Map a Program-Graph code→runtime hypothesis onto the engine det_lead probe namespace. */
export function codeHypothesisProbeClass(hypothesis: CodeToRuntimeHypothesis): string | null {
  switch (hypothesis.probeClass) {
    case 'bola_bfla':
    case 'auth_bypass':
      return 'authz_matrix'
    case 'injection':
      return 'sqli_boolean'
    case 'ssrf':
      return 'ssrf_canary'
    case 'code_review': {
      const sink = (hypothesis.sinkKind ?? '').toLowerCase()
      if (/sql/.test(sink)) return 'sqli_boolean'
      if (/ssrf|http/.test(sink)) return 'ssrf_canary'
      if (/xss|html/.test(sink)) return 'xss_context'
      if (/command|exec|shell/.test(sink)) return 'command_injection'
      if (/path|file/.test(sink)) return 'path_traversal_benign'
      return 'authz_matrix'
    }
    default:
      return null
  }
}

export interface CodeToRuntimeLead {
  /** `METHOD /path` when the hypothesis has a runtime binding, else null. */
  runtime: { method: string; path: string } | null
  probeClass: string | null
  summary: string
  data: Record<string, unknown>
}

/** Build the `det_lead` fact payload for one hypothesis (null when it has no runtime binding). */
export function codeToRuntimeLead(hypothesis: CodeToRuntimeHypothesis): CodeToRuntimeLead {
  const path = typeof hypothesis.path === 'string' ? hypothesis.path : ''
  const method = typeof hypothesis.method === 'string' ? hypothesis.method.toUpperCase() : ''
  const runtime = method && path.startsWith('/') ? { method, path } : null
  return {
    runtime,
    probeClass: runtime ? codeHypothesisProbeClass(hypothesis) : null,
    summary: `Program-graph ${hypothesis.kind} (${hypothesis.severity}, ${Math.round(hypothesis.confidence * 100)}%): ${method} ${path}${hypothesis.sinkKind ? ` → ${hypothesis.sinkKind}` : ''}`,
    data: {
      kind: 'det_lead',
      source: 'program_graph',
      probeClass: codeHypothesisProbeClass(hypothesis),
      endpoint: path,
      method,
      reason: hypothesis.rationale.slice(0, 240),
      hypothesisId: hypothesis.id,
      file: hypothesis.file,
      line: hypothesis.line,
      severity: hypothesis.severity,
      confidence: hypothesis.confidence,
    },
  }
}

export interface LeadStore {
  addFact(run: Run, assignment: Assignment, input: {
    kind: 'note'
    origin: string
    summary: string
    data: Record<string, unknown>
  }): unknown
  event(runId: string, kind: string, message: string, detail?: Record<string, unknown>): unknown
}

/**
 * Forward Program-Graph code→runtime hypotheses into the lane as prioritized `det_lead` facts.
 * Idempotent per (run, hypothesis); fact persistence is additive and never blocks Phase-0.
 */
export function seedCodeToRuntimeLeads(
  storage: LeadStore,
  run: Run,
  assignment: Assignment,
  hypotheses: readonly CodeToRuntimeHypothesis[],
  seeded: Set<string>,
  fallbackOrigin: string,
): number {
  if (!hypotheses.length || !fallbackOrigin) return 0
  let created = 0
  for (const hypothesis of hypotheses.slice(0, 40)) {
    const key = `${run.id}\0${hypothesis.id}`
    if (seeded.has(key)) continue
    const lead = codeToRuntimeLead(hypothesis)
    if (!lead.runtime || !lead.probeClass) continue
    try {
      storage.addFact(run, assignment, {
        kind: 'note',
        origin: fallbackOrigin,
        summary: lead.summary,
        data: lead.data,
      })
      seeded.add(key)
      created += 1
    } catch { /* fact persistence is additive */ }
  }
  if (created > 0) {
    try {
      storage.event(
        run.id,
        'phase0.code_leads',
        `Forwarded ${created} Program-Graph code→runtime lead(s) into the deterministic lane.`,
        { count: created, total: hypotheses.length },
      )
    } catch { /* run may be gone */ }
  }
  return created
}

const SEVERITY_RISK: Record<string, number> = { critical: 98, high: 92, medium: 84, low: 70 }

export interface GraphLeadTarget {
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  source: string
  params: Array<{ name: string; location: string }>
}

/**
 * Turn persisted Program-Graph `det_lead` facts into high-priority engine targets. The floor lane
 * probes these first (severity-ranked) without changing endpoint dedupe or engine invariants.
 */
export function graphLeadTargets(
  facts: readonly { origin: string; data?: Record<string, unknown> }[],
): GraphLeadTarget[] {
  const targets: GraphLeadTarget[] = []
  const seen = new Set<string>()
  for (const fact of facts) {
    if (fact.data?.kind !== 'det_lead' || fact.data.source !== 'program_graph') continue
    const method = typeof fact.data.method === 'string' ? fact.data.method.toUpperCase() : ''
    const path = typeof fact.data.endpoint === 'string' ? fact.data.endpoint : ''
    if (!method || !path.startsWith('/')) continue
    const key = `${fact.origin}|${method}|${path}`
    if (seen.has(key)) continue
    seen.add(key)
    const severity = typeof fact.data.severity === 'string' ? fact.data.severity : 'medium'
    targets.push({
      origin: fact.origin,
      method,
      pathTemplate: path,
      riskScore: SEVERITY_RISK[severity] ?? 84,
      source: 'program_graph',
      params: [],
    })
  }
  // Facts are listed in store row order (ties broken by random row ids); severity-ranked probes
  // must not inherit that order. Severity first, then a total identity order.
  return targets.sort((a, b) =>
    b.riskScore - a.riskScore ||
    a.origin.localeCompare(b.origin) ||
    a.method.localeCompare(b.method) ||
    a.pathTemplate.localeCompare(b.pathTemplate))
}
