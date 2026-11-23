// Static probe-family registry.
//
// The differential probe engine used to dispatch every class through one monolithic switch in
// surface-engine.ts. Families now live in their own modules so classes can be developed and run
// independently (per-class parallelism), while the registry remains a static, typed table with
// exactly one owner per class.

import type { CanaryBroker } from '../canary-broker.ts'
import type { Grant } from '../broker.ts'
import type { DifferentialProbeClass, DiffContext, DiffOutcome } from './context.ts'

import { authzProbe } from './authz.ts'
import { cacheProbe } from './cache.ts'
import { csrfProbe } from './csrf.ts'
import { graphqlProbe } from './graphql.ts'
import { injectionProbe } from './injection.ts'
import { jwtProbe } from './jwt.ts'
import { massAssignmentProbe } from './mass-assignment.ts'
import { openRedirectProbe } from './open-redirect.ts'
import { ssrfProbe } from './ssrf.ts'
import { traversalProbe } from './traversal.ts'
import { webhookProbe } from './webhook.ts'
import { workflowProbe } from './workflow.ts'
import { xssProbe } from './xss.ts'
import { xxeProbe } from './xxe.ts'

export type ProbeFamily =
  | 'authz'
  | 'injection'
  | 'ssrf'
  | 'xxe'
  | 'workflow'
  | 'jwt'
  | 'cache'
  | 'csrf'
  | 'webhook'
  | 'xss'
  | 'graphql'
  | 'traversal'
  | 'mass_assignment'
  | 'open_redirect'

/** Runtime services a probe family may need, supplied by the engine (never constructed by modules). */
export interface ProbeDeps {
  grant: Grant
  canaryBroker?: CanaryBroker
  signal: AbortSignal
}

export interface ProbeModule {
  readonly family: ProbeFamily
  /** Probe classes owned by this module. Ownership is exclusive; the registry enforces it. */
  readonly classes: readonly DifferentialProbeClass[]
  run(ctx: DiffContext, deps: ProbeDeps): Promise<DiffOutcome>
}

export const probeModules: readonly ProbeModule[] = [
  authzProbe,
  injectionProbe,
  ssrfProbe,
  xxeProbe,
  workflowProbe,
  jwtProbe,
  cacheProbe,
  csrfProbe,
  webhookProbe,
  xssProbe,
  graphqlProbe,
  traversalProbe,
  massAssignmentProbe,
  openRedirectProbe,
]

const owners = new Map<DifferentialProbeClass, ProbeModule>()
for (const mod of probeModules) {
  for (const cls of mod.classes) {
    const existing = owners.get(cls)
    if (existing) throw new Error(`Probe class ${cls} is owned by both ${existing.family} and ${mod.family}.`)
    owners.set(cls, mod)
  }
}

export function probeModuleFor(probeClass: DifferentialProbeClass): ProbeModule | undefined {
  return owners.get(probeClass)
}

export function probeFamilyFor(probeClass: DifferentialProbeClass): ProbeFamily | undefined {
  return owners.get(probeClass)?.family
}

/** Every probe class with a static owner (used by registry-completeness tests). */
export function ownedProbeClasses(): DifferentialProbeClass[] {
  return [...owners.keys()]
}
