/**
 * Barrel export for R3-12 parametric synthetic benign-archetype generators.
 */
import {
  deletingSanitizerArchetype,
  honestAccumulatorArchetype,
  publicEndpointArchetype,
  validator4xxArchetype,
} from './core-archetypes.ts'
import {
  benignShareLinkArchetype,
  cacheHitAndPaginationArchetype,
  honestRbacArchetype,
  integerCoercionArchetype,
} from './extended-archetypes.ts'
import {
  BENIGN_ARCHETYPE_IDS,
  type BenignArchetypeDefinition,
  type BenignArchetypeId,
} from './types.ts'

export {
  BENIGN_ARCHETYPE_IDS,
  MATRIX_ACTORS,
  MATRIX_ORIGIN,
  MATRIX_SIGNING_KEY,
  createBenignSession,
  headerCI,
  parseQueryParams,
  pathnameOf,
  sha256Hex,
  type BenignArchetypeDefinition,
  type BenignArchetypeId,
  type BenignTargetSession,
  type SyntheticActor,
  type SyntheticTargetRequest,
  type SyntheticTargetResponse,
} from './types.ts'

export {
  publicEndpointArchetype,
  validator4xxArchetype,
  deletingSanitizerArchetype,
  honestAccumulatorArchetype,
} from './core-archetypes.ts'

export {
  benignShareLinkArchetype,
  integerCoercionArchetype,
  honestRbacArchetype,
  cacheHitAndPaginationArchetype,
} from './extended-archetypes.ts'

export const BENIGN_ARCHETYPES: readonly BenignArchetypeDefinition[] = [
  publicEndpointArchetype,
  validator4xxArchetype,
  deletingSanitizerArchetype,
  honestAccumulatorArchetype,
  benignShareLinkArchetype,
  integerCoercionArchetype,
  honestRbacArchetype,
  cacheHitAndPaginationArchetype,
]

const BY_ID = new Map<BenignArchetypeId, BenignArchetypeDefinition>(
  BENIGN_ARCHETYPES.map(a => [a.id, a]),
)

export function getBenignArchetype(id: BenignArchetypeId): BenignArchetypeDefinition {
  const def = BY_ID.get(id)
  if (!def) throw new Error(`Unknown benign archetype "${id}" (known: ${BENIGN_ARCHETYPE_IDS.join(', ')})`)
  return def
}
