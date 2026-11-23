// Blueprint validator: aggregates every structural problem into one error so authoring a new app
// surfaces all mistakes at once rather than one tsc/runtime failure at a time. Extended for
// reason-bench: families, causal chains and reason-specific oracle kinds.
import type { AppBlueprint, RouteTemplate } from '../lib/types.ts'
import { allOracleEventKinds } from '../lib/types.ts'
import { groupUnits, feasibleDecoyTargets } from './subset.ts'

const ROOTCAUSE_FILE = /^[a-z0-9-]+\/[a-z0-9-]+\.ts$/
const NOUN_REF = /\{noun:([a-zA-Z0-9_-]+)\}/g
const ALL_KINDS = new Set<string>(allOracleEventKinds)

function pathParams(tmpl: RouteTemplate): string[] {
  return tmpl.path
    .split('/')
    .filter((seg) => seg.startsWith(':'))
    .map((seg) => seg.slice(1))
}

function nounRefs(tmpl: RouteTemplate): string[] {
  const out: string[] = []
  for (const m of tmpl.path.matchAll(NOUN_REF)) out.push(m[1]!)
  return out
}

function validateChains(bp: AppBlueprint, problems: string[]): void {
  const chainIds = new Set<string>()
  const routeKeys = new Set(Object.keys(bp.routes))
  for (const chain of bp.chains ?? []) {
    if (chainIds.has(chain.id)) problems.push(`duplicate causal chain id: ${chain.id}`)
    chainIds.add(chain.id)
    if (chain.hops.length === 0) problems.push(`causal chain ${chain.id}: no hops`)
    const hopIds = new Set<string>()
    for (const hop of chain.hops) {
      if (hopIds.has(hop.hopId)) problems.push(`causal chain ${chain.id}: duplicate hop id ${hop.hopId}`)
      hopIds.add(hop.hopId)
      if (!routeKeys.has(hop.routeKey)) problems.push(`causal chain ${chain.id}: hop routeKey "${hop.routeKey}" is not in routes`)
      if (!ALL_KINDS.has(hop.kind)) problems.push(`causal chain ${chain.id}: unknown hop kind ${hop.kind}`)
      for (const prior of hop.requiresPrior ?? []) {
        if (!hopIds.has(prior)) problems.push(`causal chain ${chain.id}: hop ${hop.hopId} requires unknown/non-prior hop ${prior}`)
      }
    }
    if (!routeKeys.has(chain.finalRouteKey)) problems.push(`causal chain ${chain.id}: finalRouteKey "${chain.finalRouteKey}" is not in routes`)
    if (!ALL_KINDS.has(chain.finalImpactKind)) problems.push(`causal chain ${chain.id}: unknown final kind ${chain.finalImpactKind}`)
  }
  for (const site of bp.sites) {
    if (site.causalChainId && !chainIds.has(site.causalChainId)) {
      problems.push(`site ${site.id}: causalChainId "${site.causalChainId}" has no chain spec`)
    }
  }
}

/** Validate a blueprint, throwing an aggregated error listing every problem. Returns bp on success. */
export function validateBlueprint(bp: AppBlueprint): AppBlueprint {
  const problems: string[] = []
  const routeKeys = new Set(Object.keys(bp.routes))

  // Unique site ids.
  const seenIds = new Set<string>()
  for (const s of bp.sites) {
    if (seenIds.has(s.id)) problems.push(`duplicate site id: ${s.id}`)
    seenIds.add(s.id)
  }

  // Entry routeKeys must be unique across sites: every site is mounted simultaneously, and the HTTP
  // router is first-match-wins, so two sites owning the same entry route would shadow one another.
  const entryOwner = new Map<string, string>()
  for (const s of bp.sites) {
    for (const rk of s.routeKeys) {
      if (entryOwner.has(rk)) problems.push(`entry routeKey "${rk}" is claimed by two sites: ${entryOwner.get(rk)} & ${s.id}`)
      else entryOwner.set(rk, s.id)
    }
  }

  // Vocab keys referenced by route templates must exist.
  for (const [key, tmpl] of Object.entries(bp.routes)) {
    for (const noun of nounRefs(tmpl)) {
      if (!bp.vocab[noun]) problems.push(`route ${key}: {noun:${noun}} has no vocab entry`)
    }
  }

  // (kind, routeKey) attribution pairs must be globally unique + rootCause files unique + valid.
  const pairSeen = new Map<string, string>()
  const fileSeen = new Map<string, string>()
  for (const s of bp.sites) {
    const refKeys = [...s.routeKeys, ...(s.triggerRouteKeys ?? []), ...s.oracle.routeKeys]
    for (const rk of refKeys) {
      if (!routeKeys.has(rk)) problems.push(`site ${s.id}: routeKey "${rk}" is not in bp.routes`)
    }
    for (const p of s.params) {
      const isPathParam = s.routeKeys.some((rk) => bp.routes[rk] && pathParams(bp.routes[rk]!).includes(p))
      if (!bp.paramVocab[p] && !isPathParam) {
        problems.push(`site ${s.id}: param "${p}" is neither in paramVocab nor a path param of its routes`)
      }
    }
    for (const kind of s.oracle.kinds) {
      if (!ALL_KINDS.has(kind)) problems.push(`site ${s.id}: unknown oracle kind ${kind}`)
      for (const rk of s.oracle.routeKeys) {
        const pair = `${kind}@${rk}`
        if (pairSeen.has(pair)) problems.push(`duplicate (kind,routeKey) pair ${pair}: ${pairSeen.get(pair)} & ${s.id}`)
        else pairSeen.set(pair, s.id)
      }
    }
    if (!ROOTCAUSE_FILE.test(s.rootCause.file)) {
      problems.push(`site ${s.id}: rootCause.file "${s.rootCause.file}" must match <subdir>/<name>.ts`)
    }
    if (fileSeen.has(s.rootCause.file)) {
      problems.push(`duplicate rootCause.file ${s.rootCause.file}: ${fileSeen.get(s.rootCause.file)} & ${s.id}`)
    } else fileSeen.set(s.rootCause.file, s.id)
  }

  validateChains(bp, problems)

  // Decoy count must be feasible given decoyable units and chain grouping.
  const { min, max } = bp.decoyCount
  if (min < 0 || max < min) problems.push(`decoyCount range invalid: min=${min} max=${max}`)
  else if (feasibleDecoyTargets(groupUnits(bp.sites), min, max).length === 0) {
    problems.push(`decoyCount [${min},${max}] is infeasible given decoyable sites and chain grouping`)
  }

  if (problems.length) throw new Error(`invalid blueprint "${bp.app}":\n  - ${problems.join('\n  - ')}`)
  return bp
}
