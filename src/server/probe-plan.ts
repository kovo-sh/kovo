/**
 * v6 graphwire probe-plan selection.
 *
 * Phase-0 persists every AST/declared route in the endpoint store (lossless) and reports a ranked,
 * clustered probe plan. Consumers use this module to bound *probe breadth* to that plan without
 * ever trimming the store. Extracted from `execution.ts` to keep the orchestrator shrinking.
 */
import type { CodeToRuntimeHypothesis } from './program-graph.ts'

/** Compact Phase-0 ranked probe plan emitted by the Program-Graph recon. */
export interface Phase0ProbePlanSummary {
  totalRoutes?: number
  priority?: number
  schemaTyped?: number
  longTail?: number
  clusters?: number
  representatives?: number
  probeSubset?: number
  sample?: readonly string[]
}

/** Extra Phase-0 result fields emitted by the Program-Graph recon (graphwire). */
export interface Phase0GraphwireExtras {
  probePlan?: Phase0ProbePlanSummary
  codeToRuntimeHypotheses?: readonly CodeToRuntimeHypothesis[]
}

/**
 * Bound the engine's probe targets to the Phase-0 ranked subset.
 *
 * Routes named by `probePlan.sample` are probed first, in recon rank order. The remaining breadth
 * is filled by the risk-ranked store up to `cap`, so a bounded ranked plan (which transports only
 * a sample of a much larger clustered subset) never starves recall. With `planOnly`, execution
 * probes only the reported sample. The store itself is never trimmed or rewritten.
 */
export function selectRankedProbeTargets<T extends {
  origin: string
  method: string
  pathTemplate: string
  riskScore?: number
}>(
  endpoints: readonly T[],
  probePlan: Phase0ProbePlanSummary | null | undefined,
  options: { cap: number; planOnly?: boolean },
): { targets: T[]; usedPlan: boolean; probed: number; skippedStored: number } {
  const cap = Math.max(1, Math.round(options.cap))
  // The store already returns a deterministic risk/coverage order; preserve it exactly so the
  // bounded probe set is identical to the pre-graphwire floor (no tie-break drift).
  const fallback = () => ({
    targets: endpoints.slice(0, cap),
    usedPlan: false,
    probed: Math.min(cap, endpoints.length),
    skippedStored: Math.max(0, endpoints.length - cap),
  })
  const sample = probePlan?.sample?.filter(key => typeof key === 'string' && key.trim().length > 0) ?? []
  if (!sample.length) return fallback()
  const byKey = new Map<string, T>()
  for (const endpoint of endpoints) {
    byKey.set(`${endpoint.method.toUpperCase()} ${endpoint.pathTemplate}`.toLowerCase(), endpoint)
  }
  const targets: T[] = []
  const seen = new Set<string>()
  for (const key of sample) {
    if (targets.length >= cap) break
    const normalized = key.trim().toLowerCase()
    if (seen.has(normalized)) continue
    seen.add(normalized)
    const endpoint = byKey.get(normalized)
    if (endpoint) targets.push(endpoint)
  }
  // Sample keys may be normalized differently (AST vs regex extraction); fail open to risk order
  // rather than probing nothing.
  if (!targets.length) return fallback()
  if (!options.planOnly) {
    const chosen = new Set(targets)
    for (const endpoint of endpoints) {
      if (targets.length >= cap) break
      if (chosen.has(endpoint)) continue
      chosen.add(endpoint)
      targets.push(endpoint)
    }
  }
  return {
    targets,
    usedPlan: true,
    probed: targets.length,
    skippedStored: Math.max(0, endpoints.length - targets.length),
  }
}

/** Per-run Phase-0 plan cache. The plan only orders probing; it never rewrites the endpoint store. */
export class ProbePlanRegistry {
  private readonly plans = new Map<string, Phase0ProbePlanSummary>()

  record(events: { event: (...args: any[]) => unknown }, runId: string, plan: Phase0ProbePlanSummary | undefined): void {
    if (!plan) return
    this.plans.set(runId, plan)
    try {
      events.event(
        runId,
        'deterministic_engine.probe_plan_ready',
        `Ranked probe plan ready: ${plan.probeSubset ?? plan.sample?.length ?? 0}/${plan.totalRoutes ?? '?'} routes prioritized (full store retained).`,
        {
          totalRoutes: plan.totalRoutes ?? null,
          priority: plan.priority ?? null,
          schemaTyped: plan.schemaTyped ?? null,
          clusters: plan.clusters ?? null,
          probeSubset: plan.probeSubset ?? plan.sample?.length ?? null,
        },
      )
    } catch { /* run may be gone */ }
  }

  /** Latest known ranked plan: in-memory after Phase-0, else the event log (resumed runs). */
  get(events: { eventsAfter: (...args: any[]) => Array<{ kind: string; detail: unknown }> }, runId: string): Phase0ProbePlanSummary | null {
    const cached = this.plans.get(runId)
    if (cached) return cached
    try {
      const event = events.eventsAfter(runId, 0).filter(e => e.kind === 'phase0.probe_plan').at(-1)
      const detail = event?.detail as Phase0ProbePlanSummary | undefined
      if (detail && Array.isArray(detail.sample) && detail.sample.length) {
        this.plans.set(runId, detail)
        return detail
      }
    } catch { /* store unavailable */ }
    return null
  }
}
