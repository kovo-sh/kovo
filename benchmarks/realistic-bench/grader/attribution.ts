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

// ---------------------------------------------------------------------------------------------
// CQ-5 product-event attribution funnel buckets (never_dispatched, route_hit_no_verify,
// verify_rejected, capped_out, and typed terminal step outcomes).
// ---------------------------------------------------------------------------------------------

export const productAttributionBuckets = [
  'proved',
  'gap_coded',
  'capped_out',
  'infra_failed',
  'model_failure',
  'turn_capped',
  'nudged_out',
  'rotated_partial',
  'never_dispatched',
  'route_hit_no_verify',
  'verify_rejected',
] as const
export type ProductAttributionBucket = typeof productAttributionBuckets[number]

export type ExtendedFailureBucket =
  | FailureTaxonomyBucket
  | 'never_dispatched'
  | 'route_hit_no_verify'
  | 'verify_rejected'
  | 'capped_out'
  | 'infra_failed'
  | 'model_failure'
  | 'turn_capped'
  | 'nudged_out'
  | 'rotated_partial'

export interface ProductEventRecord {
  kind: string
  detail?: Record<string, unknown>
  ts?: number
}

export interface ProductAttributionTarget {
  vulnClass: string
  endpoints: ReadonlyArray<{ method?: string; path: string }>
}

export interface ProductEventSignals {
  dispatched: boolean
  cappedOut: boolean
  verifyAttempted: boolean
  verifyRejected: boolean
  gapCoded: boolean
  terminalStepStatus: 'complete' | 'infra_failed' | 'model_failure' | 'turn_capped' | 'nudged_out' | 'rotated_partial' | null
}

function normalizeAttributionPath(raw: string): string {
  const base = raw.split(/[?#]/, 1)[0] ?? raw
  return base
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/:id')
    .replace(/\/[a-z]{2,8}_[0-9a-f]{4,}(?=\/|$)/gi, '/:id')
    .replace(/\/\d+(?=\/|$)/g, '/:id')
    .replace(/\/\{[^}]+\}/g, '/:id')
    .replace(/\/:[A-Za-z0-9_]+/g, '/:id')
    .replace(/\/+$/, '') || '/'
}

function normalizeAttributionClass(raw: string): string {
  const lower = raw.trim().toLowerCase()
  if (!lower) return ''
  if (/sqli|sql/.test(lower)) return 'sqli'
  if (/idor|bola|bfla|authz|access[\s_-]?control/.test(lower)) return 'authz'
  if (/xss/.test(lower)) return 'xss'
  if (/ssrf/.test(lower)) return 'ssrf'
  if (/xxe/.test(lower)) return 'xxe'
  if (/traversal|path_escape/.test(lower)) return 'traversal'
  if (/ssti|template/.test(lower)) return 'ssti'
  if (/command|cmdi/.test(lower)) return 'command_injection'
  if (/race/.test(lower)) return 'race'
  if (/csrf/.test(lower)) return 'csrf'
  if (/redirect/.test(lower)) return 'redirect'
  if (/cache/.test(lower)) return 'cache'
  if (/workflow|business|invariant/.test(lower)) return 'workflow'
  if (/secret|info_disclosure/.test(lower)) return 'secret_disclosure'
  if (/auth_bypass|jwt|oauth|auth_protocol/.test(lower)) return 'auth_protocol'
  if (/mass_assignment/.test(lower)) return 'mass_assignment'
  if (/webhook/.test(lower)) return 'webhook'
  return lower
}

function pathMatchesTarget(candidatePath: unknown, targetPaths: ReadonlySet<string>): boolean {
  if (typeof candidatePath !== 'string' || !candidatePath.trim()) return false
  return targetPaths.has(normalizeAttributionPath(candidatePath.trim()))
}

function classMatchesTarget(candidateClass: unknown, targetClassFamily: string): boolean {
  if (typeof candidateClass !== 'string' || !candidateClass.trim()) return false
  return normalizeAttributionClass(candidateClass) === targetClassFamily
}

/** Extract dispatch, verify, gap, capped-out, and typed terminal signals for a target from product events. */
export function extractProductSignalsForTarget(
  events: readonly ProductEventRecord[],
  target: ProductAttributionTarget,
): ProductEventSignals {
  const targetPaths = new Set(target.endpoints.map(ep => normalizeAttributionPath(ep.path)))
  const targetFamily = normalizeAttributionClass(target.vulnClass)
  const signals: ProductEventSignals = {
    dispatched: false,
    cappedOut: false,
    verifyAttempted: false,
    verifyRejected: false,
    gapCoded: false,
    terminalStepStatus: null,
  }

  for (const ev of events) {
    const d = ev.detail ?? {}
    if (ev.kind === 'deterministic_engine.summary' || ev.kind === 'deterministic_engine.capped_out') {
      const byClassUnprobed = d.byClassUnprobed as Record<string, unknown> | undefined
      if (byClassUnprobed && typeof byClassUnprobed === 'object') {
        for (const [cls, count] of Object.entries(byClassUnprobed)) {
          if (typeof count === 'number' && count > 0 && classMatchesTarget(cls, targetFamily)) {
            signals.cappedOut = true
          }
        }
      }
      const cappedOut = Array.isArray(d.cappedOut) ? d.cappedOut : []
      for (const item of cappedOut) {
        if (!item || typeof item !== 'object') continue
        const rec = item as Record<string, unknown>
        if (typeof rec.dropped === 'number' && rec.dropped > 0 && classMatchesTarget(rec.class, targetFamily)) {
          signals.cappedOut = true
        }
      }
      continue
    }

    if (ev.kind === 'worker.step_terminal') {
      const targets = Array.isArray(d.targets) ? d.targets : []
      const matchesTarget = targets.some(item => {
        if (!item || typeof item !== 'object') return false
        const rec = item as Record<string, unknown>
        return pathMatchesTarget(rec.route, targetPaths)
          && (!rec.vulnClass || classMatchesTarget(rec.vulnClass, targetFamily))
      }) || (pathMatchesTarget(d.route ?? d.endpoint, targetPaths) && (!d.category || classMatchesTarget(d.category, targetFamily)))
      if (matchesTarget) {
        signals.dispatched = true
        if (d.gapCoded === true) signals.gapCoded = true
        const st = typeof d.stepStatus === 'string' ? d.stepStatus : null
        if (
          st === 'complete'
          || st === 'infra_failed'
          || st === 'model_failure'
          || st === 'turn_capped'
          || st === 'nudged_out'
          || st === 'rotated_partial'
        ) {
          signals.terminalStepStatus = st
        }
      }
      continue
    }

    if (
      ev.kind === 'chain_step.created'
      || ev.kind === 'deterministic_lane.tier_a_seeded'
      || ev.kind === 'deterministic_lane.lead_consumed'
    ) {
      if (pathMatchesTarget(d.endpoint ?? d.route, targetPaths)) {
        signals.dispatched = true
      }
      continue
    }

    if (
      ev.kind === 'agent.script_proof_rejected'
      || ev.kind === 'verify.rejected'
      || ev.kind === 'replay_spec.rejected'
      || ev.kind === 'deterministic_engine.spec_rejected'
    ) {
      if (pathMatchesTarget(d.endpoint ?? d.route ?? d.path, targetPaths) || classMatchesTarget(d.vulnClass ?? d.probeClass, targetFamily)) {
        signals.dispatched = true
        signals.verifyAttempted = true
        signals.verifyRejected = true
      }
      continue
    }

    if (ev.kind === 'agent.script_proof_confirmed' || ev.kind === 'deterministic_engine.confirmed') {
      if (pathMatchesTarget(d.endpoint ?? d.route ?? d.path, targetPaths)) {
        signals.dispatched = true
        signals.verifyAttempted = true
      }
      continue
    }

    if (ev.kind === 'agent.gap_validation' && typeof d.accepted === 'number' && d.accepted > 0) {
      if (pathMatchesTarget(d.endpoint ?? d.route, targetPaths)) {
        signals.dispatched = true
        signals.gapCoded = true
      }
    }
  }

  return signals
}

export interface ProductTargetAttributionInput {
  confirmed: boolean
  routeHit: boolean
  target: ProductAttributionTarget
  events?: readonly ProductEventRecord[]
  signals?: Partial<ProductEventSignals>
}

/**
 * Classify a single target into the CQ-5 product-event attribution funnel so targets are itemized
 * cleanly into `proved`, `gap_coded`, `capped_out`, typed terminal failures, `verify_rejected`,
 * `route_hit_no_verify`, or `never_dispatched` instead of falling through into `replay_spec_miss`.
 */
export function classifyProductAttribution(input: ProductTargetAttributionInput): ProductAttributionBucket {
  if (input.confirmed) return 'proved'
  const extracted = input.events ? extractProductSignalsForTarget(input.events, input.target) : {
    dispatched: false,
    cappedOut: false,
    verifyAttempted: false,
    verifyRejected: false,
    gapCoded: false,
    terminalStepStatus: null,
  }
  const signals: ProductEventSignals = { ...extracted, ...input.signals }

  if (signals.gapCoded) return 'gap_coded'
  if (signals.verifyRejected) return 'verify_rejected'
  if (
    signals.terminalStepStatus === 'infra_failed'
    || signals.terminalStepStatus === 'model_failure'
    || signals.terminalStepStatus === 'turn_capped'
    || signals.terminalStepStatus === 'nudged_out'
    || signals.terminalStepStatus === 'rotated_partial'
  ) {
    return signals.terminalStepStatus
  }
  if (signals.cappedOut && !signals.dispatched && !input.routeHit) return 'capped_out'
  if (input.routeHit && !signals.verifyAttempted) return 'route_hit_no_verify'
  if (signals.cappedOut && !signals.verifyAttempted) return 'capped_out'
  if (!signals.dispatched && !input.routeHit) return 'never_dispatched'
  return signals.verifyAttempted ? 'verify_rejected' : 'route_hit_no_verify'
}

export interface ExtendedFailureContext extends FailureContext {
  dispatched?: boolean
  routeHit?: boolean
  verifyAttempted?: boolean
  verifyRejected?: boolean
  cappedOut?: boolean
  terminalStepStatus?: ProductEventSignals['terminalStepStatus']
}

/**
 * Extended failure classifier that surfaces CQ-5 dispatch/verify/cap buckets (`never_dispatched`,
 * `route_hit_no_verify`, `verify_rejected`, `capped_out`, and typed terminal statuses) before
 * falling back to `replay_spec_miss`.
 */
export function classifyExtendedFailure(ctx: ExtendedFailureContext): ExtendedFailureBucket {
  if (ctx.telemetryExhausted && !ctx.hasMatchingFinding && !ctx.surfaceDiscovered) return 'budget_exhausted'
  if (ctx.cappedOut && !ctx.dispatched && !ctx.verifyAttempted) return 'capped_out'
  if (!ctx.surfaceDiscovered) {
    return ctx.dispatched === false ? 'never_dispatched' : 'surface_miss'
  }
  if (ctx.tierBlocked) return 'tier_blocked'
  if (ctx.csrfBlocked) return 'csrf_blocked'
  if (ctx.formEncodingMissing) return 'form_encoding_missing'
  if (ctx.contextReset) return 'context_reset'
  if (ctx.terminalStepStatus && ctx.terminalStepStatus !== 'complete') return ctx.terminalStepStatus
  if (ctx.verifyRejected) return 'verify_rejected'
  if (ctx.dispatched === false && !ctx.hypothesisFormed && !ctx.verifyAttempted) return 'never_dispatched'
  if (!ctx.hypothesisFormed) {
    return ctx.routeHit || ctx.surfaceDiscovered ? 'route_hit_no_verify' : 'hypothesis_miss'
  }
  if (ctx.triggerMiss) return 'trigger_miss'
  if (ctx.assertionFailure) return 'jq_assertion_bug'
  if (ctx.verifyAttempted === false && (ctx.routeHit || ctx.surfaceDiscovered)) return 'route_hit_no_verify'
  if (ctx.hasMatchingFinding || ctx.verifyAttempted) return 'verify_rejected'
  return ctx.signalObserved ? 'route_hit_no_verify' : 'never_dispatched'
}
