// paygrid archetype shell: boots five isolated loopback services, wires the causal monitor and
// publishes mode-scoped briefings. Host-only files (truth/, solvers/) never enter a white-box tree.
import { randomBytes } from 'node:crypto'
import { createChainOracle } from '../../lib/chain-oracle.ts'
import type { ChainOracle } from '../../lib/chain-oracle.ts'
import { generateDomainVariant } from '../../lib/domain-variant.ts'
import { materialize } from '../../lib/materialize.ts'
import type {
  AppName, BenchMode, Briefing, DomainVariant, GroundTruth, LabMode, OracleExport, PersonaId,
  ServiceTopology,
} from '../../lib/types.ts'
import { assertLocalLabAllowed } from '../../lib/safety.ts'
import { createLabState } from './src/state.ts'
import { startServices } from './src/server.ts'
import { apiCatalog, buildGroundTruth, CHAINS, profileFor, TWINS } from './truth/blueprint.ts'
import { createPaygridMonitor } from './truth/monitors.ts'

export interface PaygridStartOptions {
  seed: number
  heldOutSalt?: string
  mode: LabMode
  twin?: string
  asyncLatencyMs?: number
}

export interface StartedPaygrid {
  app: AppName
  seed: number
  seedSet: DomainVariant['seedSet']
  labMode: LabMode
  twinId?: string
  runId: string
  plan: DomainVariant
  groundTruth: GroundTruth
  oracle: ChainOracle
  origins: Record<string, string>
  entryOrigin: string
  sourceDir: string
  briefing(mode: BenchMode): Briefing
  export(): OracleExport
  stop(): Promise<void>
}

const ATTACKER_BRIEFING: PersonaId[] = ['member_a', 'member_b', 'revoked_or_demoted']
const GREY_BRIEFING: PersonaId[] = [
  'owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted',
]

function topology(origins: Record<string, string>): ServiceTopology[] {
  return [
    { id: 'edge', role: 'public entry / cdn', internal: false, origin: origins.edge },
    { id: 'api', role: 'tenant REST + GraphQL', internal: false, origin: origins.api },
    { id: 'idp', role: 'oidc sessions and invitations', internal: false, origin: origins.idp },
    { id: 'worker', role: 'async pdf / export runner', internal: true },
    { id: 'vault.internal', role: 'signing custody', internal: true },
  ]
}

export async function startPaygrid(options: PaygridStartOptions): Promise<StartedPaygrid> {
  assertLocalLabAllowed()
  const plan = generateDomainVariant('paygrid', options.seed, options.heldOutSalt)
  const profile = profileFor(options.mode, options.twin, options.asyncLatencyMs ?? 25)
  const runId = `mh_run_${randomBytes(6).toString('hex')}`
  const oracle = createChainOracle({ runId, specs: CHAINS, twins: TWINS })
  const state = createLabState(plan, profile, runId)
  const monitor = createPaygridMonitor(oracle, plan, runId)
  state.listeners.push((event) => monitor.consume(event))

  const running = await startServices(state)
  let materialized: ReturnType<typeof materialize> | null = null
  try {
    materialized = materialize({ app: 'paygrid', plan })
  } catch (err) {
    await running.close()
    throw err
  }
  const groundTruth = buildGroundTruth(plan, options.mode, options.twin)
  const services = topology(running.origins)

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
      app: 'paygrid',
      mode,
      seed: plan.seed,
      seedSet: plan.seedSet,
      runId,
      entryOrigins: mode === 'black-box'
        ? { edge: running.origins.edge }
        : { edge: running.origins.edge, api: running.origins.api, idp: running.origins.idp },
      personas,
    }
    if (mode === 'black-box') return base
    base.services = services
    base.internalServiceNames = ['worker', 'vault.internal']
    base.apiReference = apiCatalog(plan)
    if (mode === 'white-box') base.sourceDir = materialized.sourceDir
    return base
  }

  return {
    app: 'paygrid',
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

export function describeApp(): { app: AppName; chains: number; twins: number; services: number } {
  return { app: 'paygrid', chains: CHAINS.length, twins: TWINS.length, services: 5 }
}

export const PAYGRID_CHAINS = CHAINS
export const PAYGRID_TWINS = TWINS
