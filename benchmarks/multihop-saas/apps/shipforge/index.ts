// shipforge archetype shell: boots five isolated loopback services, wires the causal monitor and
// publishes mode-scoped briefings. Host-only files (truth/, solvers/) never enter a white-box tree.
import { randomBytes } from 'node:crypto'
import { createChainOracle } from '../../lib/chain-oracle.ts'
import type { ChainOracle } from '../../lib/chain-oracle.ts'
import { assertNoLeakage, materialize } from '../../lib/materialize.ts'
import type {
  AppName, BenchMode, Briefing, DomainVariant, GroundTruth, LabMode, OracleExport, PersonaId,
  ServiceId, ServiceTopology,
} from '../../lib/types.ts'
import { assertLocalLabAllowed } from '../../lib/safety.ts'
import { createLabState } from './src/state.ts'
import { startServices } from './src/server.ts'
import type { ServiceName, ShipforgePlan } from './src/shared.ts'
import { generateShipforgePlan, writeSnapshotDescriptor } from './truth/plan.ts'
import { apiCatalog, buildGroundTruth, CHAINS, profileFor, topology, TWINS } from './truth/blueprint.ts'
import { createShipforgeMonitor } from './truth/monitors.ts'

export interface ShipforgeStartOptions {
  seed: number
  heldOutSalt?: string
  mode: LabMode
  twin?: string
  asyncLatencyMs?: number
}

export interface StartedShipforge {
  app: 'shipforge'
  seed: number
  seedSet: ShipforgePlan['seedSet']
  labMode: LabMode
  twinId?: string
  runId: string
  plan: ShipforgePlan
  groundTruth: GroundTruth
  oracle: ChainOracle
  origins: Record<ServiceName, string>
  entryOrigin: string
  sourceDir: string
  sourceRoot: string
  briefing(mode: BenchMode): Briefing
  export(): OracleExport
  stop(): Promise<void>
}

const ATTACKER_BRIEFING: PersonaId[] = ['member_a', 'member_b', 'revoked_or_demoted']
const GREY_BRIEFING: PersonaId[] = [
  'owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted',
]

function serviceTopology(origins: Record<ServiceName, string>): ServiceTopology[] {
  return topology().map((service) => {
    const local = service.id as unknown as ServiceName
    const internals: ServiceName[] = ['runner', 'registry.internal']
    return {
      ...service,
      origin: internals.includes(local) ? undefined : origins[local],
    }
  })
}

export async function startShipforge(options: ShipforgeStartOptions): Promise<StartedShipforge> {
  assertLocalLabAllowed()
  const plan = generateShipforgePlan(options.seed, options.heldOutSalt)
  const profile = profileFor(options.mode, options.twin, options.asyncLatencyMs ?? 25)
  const runId = `mh_run_${randomBytes(6).toString('hex')}`
  const oracle = createChainOracle({ runId, specs: CHAINS, twins: TWINS })
  const state = createLabState(plan, profile, runId)
  const monitor = createShipforgeMonitor(oracle, plan, runId, profile)
  state.listeners.push((event) => monitor.consume(event))

  const running = await startServices(state)
  let materialized: ReturnType<typeof materialize> | null = null
  try {
    materialized = materialize({
      // The frozen AppName/ServiceId unions describe the pilot archetype; app shells carry their
      // own service vocabulary and materialize by directory name.
      app: 'shipforge' as unknown as AppName,
      plan: plan as unknown as DomainVariant,
    })
    writeSnapshotDescriptor(materialized.root, plan)
    assertNoLeakage(materialized.root)
  } catch (err) {
    await running.close()
    throw err
  }
  const groundTruth = buildGroundTruth(plan as unknown as DomainVariant, options.mode, options.twin)
  const services = serviceTopology(running.origins)

  const briefing = (mode: BenchMode): Briefing => {
    const visible = mode === 'black-box' ? ATTACKER_BRIEFING : GREY_BRIEFING
    const personas = visible.map((id) => {
      const persona = plan.personas[id]
      return {
        id, email: persona.email, password: persona.password,
        tenant: persona.tenantId, rolesByTenant: persona.rolesByTenant,
      }
    })
    const base: Briefing = {
      app: 'shipforge' as unknown as AppName,
      mode,
      seed: plan.seed,
      seedSet: plan.seedSet,
      runId,
      entryOrigins: (mode === 'black-box'
        ? { edge: running.origins.edge }
        : { edge: running.origins.edge, api: running.origins.api, scm: running.origins.scm }) as unknown as Briefing['entryOrigins'],
      personas,
    }
    if (mode === 'black-box') return base
    base.services = services
    base.internalServiceNames = ['runner', 'registry.internal'] as unknown as ServiceId[]
    base.apiReference = apiCatalog(plan as unknown as DomainVariant)
    if (mode === 'white-box') base.sourceDir = materialized.sourceDir
    return base
  }

  return {
    app: 'shipforge',
    seed: plan.seed,
    seedSet: plan.seedSet,
    labMode: options.mode,
    twinId: options.twin,
    runId,
    plan,
    groundTruth,
    oracle,
    origins: running.origins,
    entryOrigin: running.origins.edge,
    sourceDir: materialized.sourceDir,
    sourceRoot: materialized.root,
    briefing,
    export() {
      return oracle.export()
    },
    async stop() {
      await running.close()
      materialized.cleanup()
    },
  }
}

export function describeApp(): { app: string; chains: number; twins: number; services: number } {
  return { app: 'shipforge', chains: CHAINS.length, twins: TWINS.length, services: 5 }
}

export const SHIPFORGE_CHAINS = CHAINS
export const SHIPFORGE_TWINS = TWINS
