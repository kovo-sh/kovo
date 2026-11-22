// Per-seed ground truth, instantiated OUTSIDE the materialized tree (the app never imports it).
// Splits sites into vulns vs decoys by the plan's assigned mode and groups chains.
import type {
  AppBlueprint,
  Endpoint,
  GroundTruth,
  GroundTruthEntry,
  Severity,
  SiteSpec,
  VariantPlan,
} from '../lib/types.ts'

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 }

function endpointsFor(plan: VariantPlan, routeKeys: readonly string[]): Endpoint[] {
  return routeKeys.map((rk) => {
    const r = plan.routes[rk]
    if (!r) throw new Error(`ground truth: route "${rk}" missing from plan`)
    return { method: r.method, path: r.path, routeKey: rk }
  })
}

function entryFor(plan: VariantPlan, site: SiteSpec): GroundTruthEntry {
  const triggerKeys = site.triggerRouteKeys ?? site.routeKeys
  return {
    siteId: site.id,
    title: site.title,
    vulnClass: site.vulnClass,
    cwe: site.cwe,
    severity: site.severity,
    endpoints: endpointsFor(plan, site.routeKeys),
    triggerEndpoints: endpointsFor(plan, triggerKeys),
    params: site.params.map((p) => plan.params[p] ?? p),
    oracle: { kinds: [...site.oracle.kinds], routeKeys: [...site.oracle.routeKeys] },
    rootCause: { ...site.rootCause },
    chain: site.chain ? { ...site.chain } : undefined,
    formEncoding: site.formEncoding,
    requiresCsrf: site.requiresCsrf,
    secondOrder: site.secondOrder,
    lure: site.lure,
  }
}

/** Instantiate runtime ground truth for a materialized variant. */
export function buildGroundTruth(bp: AppBlueprint, plan: VariantPlan): GroundTruth {
  const vulns: GroundTruthEntry[] = []
  const decoys: GroundTruthEntry[] = []
  for (const site of bp.sites) {
    const entry = entryFor(plan, site)
    if (plan.sites[site.id] === 'vulnerable') vulns.push(entry)
    else decoys.push(entry)
  }

  const chainMap = new Map<string, { id: string; siteIds: string[]; severity: Severity }>()
  for (const site of bp.sites) {
    if (!site.chain) continue
    const c = chainMap.get(site.chain.id) ?? { id: site.chain.id, siteIds: [], severity: 'low' }
    c.siteIds.push(site.id)
    if (SEVERITY_RANK[site.severity] > SEVERITY_RANK[c.severity]) c.severity = site.severity
    chainMap.set(site.chain.id, c)
  }

  return {
    schemaVersion: 1,
    app: bp.app,
    seed: plan.seed,
    seedSet: plan.seedSet,
    vulns,
    decoys,
    chains: [...chainMap.values()],
  }
}
