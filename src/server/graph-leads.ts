/**
 * v6 graphwire: Program-Graph code→runtime leads for the deterministic lane.
 *
 * Hypotheses already carry severity/confidence/probeClass; this module only maps the code
 * hypothesis family onto the engine `det_lead` probe namespace and builds the fact payload.
 * Dedupe, caps and step creation stay in the lane (`queueDetLeadUpgradeSteps`).
 */
import { renderCodeDataflowSlice } from './program-graph.ts'
import type {
  CodeDataflowSlice,
  CodeSliceGuardDiff,
  CodeToRuntimeHypothesis,
} from './program-graph.ts'
import type { Assignment, Run } from './store.ts'

/**
 * v7 whitebox hop: a det_lead fact carries the bounded code dataflow slice for its route so the
 * agentic brief can render exact file:line evidence without a second graph walk. The persisted
 * slice (plus its deduped `guardDiff` mirror) never exceeds this budget.
 */
export const DET_LEAD_CODE_SLICE_MAX_BYTES = 600

/** Hypothesis shape produced by phase0-recon: the v7 slice rides on the hypothesis payload. */
export type CodeSliceHypothesis = CodeToRuntimeHypothesis & { codeSlice?: CodeDataflowSlice }

function dedupeGuardDiffs(diffs: readonly CodeSliceGuardDiff[] | undefined, limit = 2): CodeSliceGuardDiff[] {
  const seen = new Set<string>()
  const out: CodeSliceGuardDiff[] = []
  for (const diff of diffs ?? []) {
    const key = `${diff.kind}\u0000${diff.guard}\u0000${diff.symbol}\u0000${diff.sibling}\u0000${diff.at}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ ...diff })
    if (out.length >= limit) break
  }
  return out
}

/**
 * Build the additive fact-data fields for a hypothesis code slice.
 *
 * The slice is re-fitted through the deterministic byte ladder (never a blind JSON slice) and
 * `guardDiff` is mirrored as a deduped top-level field so the upgrade queue/brief can read the
 * sibling-guard contrast without walking the slice. The combined payload stays <= `maxBytes`.
 */
export function detLeadCodeSliceFactFields(
  slice: CodeDataflowSlice | null | undefined,
  maxBytes = DET_LEAD_CODE_SLICE_MAX_BYTES,
): Record<string, unknown> {
  if (!slice || typeof slice !== 'object') return {}
  const cap = Math.max(64, Math.floor(maxBytes))
  // The slice itself is the source of truth and is fitted at the full budget; the `guardDiff`
  // mirror is added only when the combined payload still fits, never at the cost of evidence.
  // Guard diffs are deduped before fitting so a repeated sibling contrast cannot crowd out hops.
  const base: CodeDataflowSlice = slice.guardDiff?.length
    ? { ...slice, guardDiff: dedupeGuardDiffs(slice.guardDiff, 3) }
    : slice
  const rendered = renderCodeDataflowSlice(base, cap)
  const mirror = dedupeGuardDiffs(rendered.slice.guardDiff ?? [])
  let fields: Record<string, unknown> = {
    codeSlice: rendered.slice,
    codeSliceBytes: rendered.bytes,
    ...(mirror.length ? { guardDiff: mirror } : {}),
  }
  if (Buffer.byteLength(JSON.stringify(fields), 'utf8') > cap) {
    // The mirror is redundant evidence (it also lives inside `codeSlice`); drop it before
    // touching the slice so route/hops/sink remain intact.
    fields = { codeSlice: rendered.slice, codeSliceBytes: rendered.bytes }
  }
  return fields
}

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
export function codeToRuntimeLead(hypothesis: CodeSliceHypothesis): CodeToRuntimeLead {
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
      ...detLeadCodeSliceFactFields(hypothesis.codeSlice),
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
  hypotheses: readonly CodeSliceHypothesis[],
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

/**
 * Evidence fields a promoted deterministic lead must carry into its `det_lead` fact so the dispatcher
 * can prioritize (and brief) the upgrade without re-probing blindly. Structurally typed to avoid a
 * runtime import cycle with `deterministic-engine.ts`. Adoption at the fact-persistence site is:
 *   data: { ...existing, ...detLeadEvidenceFactFields(lead.evidence) }
 */
export interface DetLeadEvidenceFacts {
  kind?: string
  verifyFailureReason?: string | null
  verifyFailureCode?: string | null
  controlOutcome?: string
  evidenceExchangeIds?: readonly string[]
  candidateProbeClass?: string
  detail?: string
}

export const detLeadEvidenceFieldKeys = [
  'leadEvidenceKind',
  'verifyFailureReason',
  'verifyFailureCode',
  'controlOutcome',
  'evidenceExchangeIds',
  'candidateProbeClass',
  'leadEvidenceDetail',
] as const

/** Build the additive fact-data fields for a promoted lead (empty object when no evidence). */
export function detLeadEvidenceFactFields(
  evidence?: DetLeadEvidenceFacts | null,
): Record<string, unknown> {
  if (!evidence) return {}
  const fields: Record<string, unknown> = {}
  if (evidence.kind) fields.leadEvidenceKind = evidence.kind
  if (evidence.verifyFailureReason) fields.verifyFailureReason = evidence.verifyFailureReason
  if (evidence.verifyFailureCode) fields.verifyFailureCode = evidence.verifyFailureCode
  if (evidence.controlOutcome) fields.controlOutcome = evidence.controlOutcome
  if (evidence.candidateProbeClass) fields.candidateProbeClass = evidence.candidateProbeClass
  if (evidence.detail) fields.leadEvidenceDetail = evidence.detail
  const exchangeIds = [...new Set((evidence.evidenceExchangeIds ?? []).filter(id => typeof id === 'string' && id))]
  if (exchangeIds.length > 0) fields.evidenceExchangeIds = exchangeIds.slice(0, 6)
  return fields
}

/** Severity bonus for a fact that already carries promotion evidence (dispatcher ranking input). */
export function leadEvidenceRiskBonus(data?: Record<string, unknown>): number {
  switch (data?.leadEvidenceKind) {
    case 'near_miss': return 12
    case 'denied_control': return 8
    case 'data_delta': return 4
    default: return 0
  }
}

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
      riskScore: (SEVERITY_RISK[severity] ?? 84) + leadEvidenceRiskBonus(fact.data),
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
