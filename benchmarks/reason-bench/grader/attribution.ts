// Oracle-event attribution, funnel computation, and failure-taxonomy classification.
// Pure, no I/O. See CONTRACTS.md "Grading".
import type { BenchmarkFunnel, FailureTaxonomyBucket, GroundTruthEntry, OracleEvent } from '../lib/types.ts'

/** An event is attributed to an entry iff its kind and routeKey are both listed in the entry oracle. */
export function attributeEvent(event: OracleEvent, entry: Pick<GroundTruthEntry, 'oracle'>): boolean {
  if (!entry.oracle.kinds.includes(event.kind)) return false
  if (event.routeKey == null) return false
  return entry.oracle.routeKeys.includes(event.routeKey)
}

export interface FunnelStage {
  surfaceDiscovered: boolean
  hypothesisFormed: boolean
  signalObserved: boolean
  specSubmitted: boolean
  confirmed: boolean
}

/** Build the 6-stage monotonic funnel: each stage counts only vulns that passed the previous stage. */
export function computeFunnel(stages: FunnelStage[]): BenchmarkFunnel {
  const f: BenchmarkFunnel = {
    targetVulns: stages.length,
    surfaceDiscovered: 0,
    hypothesisFormed: 0,
    signalObserved: 0,
    specSubmitted: 0,
    zeroLlmConfirmed: 0,
  }
  // A later stage logically implies every earlier one (a confirmed vuln was surfaced, hypothesized,
  // observed and submitted — even if, say, a BOLA exploit carried no "suspicious" payload to set the
  // hypothesis flag directly). Back-fill so the funnel stays monotonic and never shows a confirmed
  // vuln dropping at an earlier stage.
  for (const s of stages) {
    const confirmed = s.confirmed
    const spec = s.specSubmitted || confirmed
    const signal = s.signalObserved || spec
    const hypothesis = s.hypothesisFormed || signal
    const surface = s.surfaceDiscovered || hypothesis
    if (surface) f.surfaceDiscovered++
    if (hypothesis) f.hypothesisFormed++
    if (signal) f.signalObserved++
    if (spec) f.specSubmitted++
    if (confirmed) f.zeroLlmConfirmed++
  }
  return f
}

export interface FailureContext {
  surfaceDiscovered: boolean
  hypothesisFormed: boolean
  signalObserved: boolean
  hasMatchingFinding: boolean
  confirmed: boolean
  telemetryExhausted: boolean
  tierBlocked: boolean
  csrfBlocked: boolean
  formEncodingMissing: boolean
  contextReset: boolean
  triggerMiss: boolean
  assertionFailure: boolean
}

/** First applicable failure bucket for a non-confirmed vuln (documented ordered rules). */
export function classifyFailure(ctx: FailureContext): FailureTaxonomyBucket {
  if (ctx.telemetryExhausted && !ctx.hasMatchingFinding && !ctx.surfaceDiscovered) return 'budget_exhausted'
  if (!ctx.surfaceDiscovered) return 'surface_miss'
  if (ctx.tierBlocked) return 'tier_blocked'
  if (ctx.csrfBlocked) return 'csrf_blocked'
  if (ctx.formEncodingMissing) return 'form_encoding_missing'
  if (ctx.contextReset) return 'context_reset'
  if (!ctx.hypothesisFormed) return 'hypothesis_miss'
  if (ctx.triggerMiss) return 'trigger_miss'
  if (ctx.signalObserved) return 'replay_spec_miss'
  if (ctx.assertionFailure) return 'jq_assertion_bug'
  return 'replay_spec_miss'
}
