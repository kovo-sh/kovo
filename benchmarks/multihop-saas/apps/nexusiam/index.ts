// nexusiam archetype shell: boots five isolated loopback services, wires the causal monitor and
// publishes mode-scoped briefings. Host-only files (truth/, solvers/) never enter a white-box tree.
import { createHash, randomBytes } from 'node:crypto'
import { createChainOracle } from '../../lib/chain-oracle.ts'
import type { ChainOracle } from '../../lib/chain-oracle.ts'
import { generateDomainVariant } from '../../lib/domain-variant.ts'
import { assertLocalLabAllowed } from '../../lib/safety.ts'
import type {
  AppName, BenchMode, Briefing, DomainVariant, GroundTruth, LabMode, OracleExport, PersonaId,
  ServiceId, ServiceTopology,
} from '../../lib/types.ts'
import { createLabState } from './src/state.ts'
import { startServices } from './src/server.ts'
import type { NexusIds, NexusPlan, ServiceName } from './src/shared.ts'
import { apiCatalog, buildGroundTruth, CHAINS, profileFor, TWINS } from './truth/blueprint.ts'
import { createNexusiamMonitor } from './truth/monitors.ts'
import { materializeNexusiam } from './host/materialize.ts'

export const NEXUS_APP = 'nexusiam' as unknown as AppName

export interface NexusiamStartOptions {
  seed: number
  heldOutSalt?: string
  mode: LabMode
  twin?: string
  asyncLatencyMs?: number
}

export interface StartedNexusiam {
  app: AppName
  seed: number
  seedSet: DomainVariant['seedSet']
  labMode: LabMode
  twinId?: string
  runId: string
  plan: NexusPlan
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

const FOLDER_CANDIDATES = ['roadmap', 'board-minutes', 'customer-escrow', 'hiring-plan', 'incident-review']

function token(label: string, variant: DomainVariant, prefix: string): string {
  const value = createHash('sha256').update(`${variant.seed}:${variant.seedSet}:${label}`).digest('hex')
  return `${prefix}${value.slice(0, 24)}`
}

function buildNexusIds(variant: DomainVariant): NexusIds {
  const index = parseInt(createHash('sha256')
    .update(`${variant.seed}:${variant.seedSet}:folder-index`).digest('hex').slice(0, 2), 16) %
    FOLDER_CANDIDATES.length
  return {
    privateFolderName: FOLDER_CANDIDATES[index]!,
    folderCandidates: FOLDER_CANDIDATES.slice(),
    privateDocId: token('private-doc', variant, 'mh_doc_'),
    privateDocTitle: 'Workspace planning notes',
    shareLinkId: token('share-link', variant, 'mh_share_'),
    profileSlug: variant.tenants.a.slug,
    staleInviteId: token('stale-invite', variant, 'mh_inv_'),
    staleInviteToken: token('stale-invite-token', variant, 'mh_fake_invite_'),
    exportJobId: token('export-job', variant, 'mh_job_export_'),
    exportHandle: token('export-handle', variant, 'mh_fake_handle_'),
    canary: variant.economics.treasuryCanary,
  }
}

function toNexusPlan(variant: DomainVariant): NexusPlan {
  return {
    seed: variant.seed,
    seedSet: variant.seedSet,
    routePrefix: variant.routePrefix,
    tenants: variant.tenants,
    personas: variant.personas,
    secrets: variant.secrets,
    economics: variant.economics,
    ids: variant.ids,
    nexus: buildNexusIds(variant),
  }
}

function sid(name: ServiceName): ServiceId {
  return name as unknown as ServiceId
}

function topology(origins: Record<ServiceName, string>): ServiceTopology[] {
  return [
    { id: sid('cdn'), role: 'public static and profile cache edge', internal: false, origin: origins.cdn },
    { id: sid('app'), role: 'collaboration SPA and moderation worker', internal: false, origin: origins.app },
    { id: sid('api'), role: 'IAM, SCIM, documents, search and audit surfaces', internal: false, origin: origins.api },
    { id: sid('idp'), role: 'oidc sessions and invitations', internal: false, origin: origins.idp },
    { id: sid('docs-worker'), role: 'async document export runner', internal: true },
  ]
}

export async function startNexusiam(options: NexusiamStartOptions): Promise<StartedNexusiam> {
  assertLocalLabAllowed()
  const variant = generateDomainVariant('nexusiam' as AppName, options.seed, options.heldOutSalt)
  const plan = toNexusPlan(variant)
  const profile = profileFor(options.mode, options.twin, options.asyncLatencyMs ?? 25)
  const runId = `mh_run_${randomBytes(6).toString('hex')}`
  const oracle = createChainOracle({ runId, specs: CHAINS, twins: TWINS })
  const state = createLabState(plan, profile, runId)
  const monitor = createNexusiamMonitor(oracle, plan, runId)
  state.listeners.push((event) => monitor.consume(event))

  const running = await startServices(state)
  let materialized: ReturnType<typeof materializeNexusiam> | null = null
  try {
    materialized = materializeNexusiam(plan)
  } catch (err) {
    await running.close()
    throw err
  }
  const groundTruth = buildGroundTruth({ ...plan, app: NEXUS_APP }, options.mode, options.twin)
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
    const entryOrigins: Partial<Record<ServiceId, string>> = {}
    if (mode === 'black-box') {
      entryOrigins[sid('cdn')] = running.origins.cdn
    } else {
      entryOrigins[sid('cdn')] = running.origins.cdn
      entryOrigins[sid('app')] = running.origins.app
      entryOrigins[sid('api')] = running.origins.api
      entryOrigins[sid('idp')] = running.origins.idp
    }
    const base: Briefing = {
      app: NEXUS_APP,
      mode,
      seed: plan.seed,
      seedSet: plan.seedSet,
      runId,
      entryOrigins,
      personas,
    }
    if (mode === 'black-box') return base
    base.services = services
    base.internalServiceNames = [sid('docs-worker')]
    base.apiReference = apiCatalog(plan)
    if (mode === 'white-box') base.sourceDir = materialized.sourceDir
    return base
  }

  return {
    app: NEXUS_APP,
    seed: plan.seed,
    seedSet: plan.seedSet,
    labMode: options.mode,
    twinId: options.twin,
    runId,
    plan,
    groundTruth,
    oracle,
    origins: running.origins,
    entryOrigin: running.origins.cdn,
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

export function describeNexusiam(): { app: AppName; chains: number; twins: number; services: number } {
  return { app: NEXUS_APP, chains: CHAINS.length, twins: TWINS.length, services: 5 }
}

export const NEXUSIAM_CHAINS = CHAINS
export const NEXUSIAM_TWINS = TWINS
