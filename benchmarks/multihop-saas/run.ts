// multihop-saas entrypoint: programmatic API + CLI + Kovo v8 product-runner bridge.
//   startPaygrid({ seed, mode, twin?, asyncLatencyMs? }) -> StartedPaygrid
//   startMultihopApp({ app, seed, mode?, variant?, fastLab?, heldOutSalt? }) -> StartedMultihopApp
//   briefingFor(started, mode?) -> MultihopProductBriefing
//   runReferenceSolvers(lab, chainIds?) -> Finding[]
//   gradeRun(input) / renderScorecard(card, format) / listSeeds(...)
// CLI: list | seeds | serve | grade | selftest | anti-heuristic-check
//
// The suite is standalone: only node:* built-ins, native type stripping, loopback-only listeners.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type {
  ApiRef, AppName, BenchMode, Briefing, ChainSpec, Finding, GradeInput, GroundTruth,
  LabMode, OracleExport, SeedSet, SelftestResult, SelftestRow, ServiceTopology, TwinSpec,
} from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { listSeeds as libListSeeds } from './lib/domain-variant.ts'
import {
  ANTI_HEURISTIC_FLOOR_MAX,
  gradeRun as libGradeRun,
  renderScorecard as libRenderScorecard,
} from './lib/grader.ts'
import type { Scorecard } from './lib/types.ts'
import type { ChainOracle } from './lib/chain-oracle.ts'
import { startPaygrid, describeApp, PAYGRID_CHAINS, PAYGRID_TWINS } from './apps/paygrid/index.ts'
import type { StartedPaygrid } from './apps/paygrid/index.ts'
import { runReferenceSolvers } from './apps/paygrid/solvers/index.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
export const BENCH_ROOT = HERE

export const KNOWN_APPS = ['paygrid', 'shipforge', 'nexusiam', 'connecthub'] as const
export type MultihopKnownApp = typeof KNOWN_APPS[number]

export { startPaygrid, runReferenceSolvers, ANTI_HEURISTIC_FLOOR_MAX }
export type { StartedPaygrid, Scorecard, Finding, GradeInput, OracleExport }

// ---------------------------------------------------------------------------------------------
// Dynamic multi-app discovery (paygrid, shipforge, nexusiam, and connecthub when present)
// ---------------------------------------------------------------------------------------------

export interface StartedLabBase {
  app: string
  seed: number
  seedSet: SeedSet
  labMode: LabMode
  twinId?: string
  runId: string
  plan: { seedSet: SeedSet } & Record<string, unknown>
  groundTruth: GroundTruth
  oracle: ChainOracle
  origins: Record<string, string>
  entryOrigin: string
  sourceDir: string
  briefing(mode: BenchMode): Briefing
  export(): OracleExport
  stop(): Promise<void>
}

interface AppStartOptions {
  seed: number
  heldOutSalt?: string
  mode: LabMode
  twin?: string
  asyncLatencyMs?: number
}

interface LoadedAppModule {
  name: string
  services: number
  chains: readonly ChainSpec[]
  twins: readonly TwinSpec[]
  start(options: AppStartOptions): Promise<StartedLabBase>
  runSolvers?: (lab: StartedLabBase, chainIds?: readonly string[]) => Promise<Finding[]>
}

const loadedApps = new Map<string, Promise<LoadedAppModule>>()
const loadedAppsSync = new Map<string, LoadedAppModule>()

/**
 * Blueprint hop/terminal routeKeys mapped to one or more canonical + public-relay entries in
 * apiCatalog(). `resolveRouteKeyRefs()` always checks the raw routeKey first and then all listed
 * aliases, so both internal and public-relay endpoints are resolved with seed-varied prefixes.
 */
const HOP_ROUTE_KEY_ALIASES: Record<string, string | readonly string[]> = {
  // paygrid
  'api.permissionsPrime': 'api.orgPermissions',
  'api.exportCreate': 'api.orgExports',
  'api.exportSignedUrl': 'api.exportUrl',
  'file.treasuryDownload': 'edge.fileExport',
  'worker.jobRender': 'api.invoiceRender',
  'worker.jobTrace': 'api.jobTrace',
  'worker.jobPoll': ['api.exportGet', 'api.jobPoll'],
  'vault.settlementWebhook': 'api.settlementWebhook',
  // shipforge
  'api.productionRelease': 'api.deploymentRelease',
  'runner.sseStream': ['runner.streamShared', 'api.runnerSharedEvents'],
  'runner.sseArtifactEvent': ['runner.artifact', 'api.runnerSharedEvents'],
  'scm.webhookCreate': 'api.projectWebhooks',
  'scm.deliveryLog': 'api.deliveryLog',
  'registry.internalSync': 'api.registrySync',
  // nexusiam
  'app.moderationRender': ['app.moderationQueue', 'app.inbox'],
  'api.scimTokenMint': 'api.scimTokenCreate',
  'api.auditVaultRead': 'api.auditVault',
  'app.shareLinkCapture': 'app.sharePreview',
  'cdn.profileCacheRead': 'cdn.profileCss',
  'api.docsWorkspaceFallback': 'api.docsList',
  'api.docPrivateOpen': 'api.docGet',
  'api.docContentRead': 'api.docContent',
  'docsWorker.jobPoll': 'api.exportStatus',
  'docsWorker.jobResult': 'api.exportResult',
}

loadedAppsSync.set('paygrid', {
  name: 'paygrid',
  services: describeApp().services,
  chains: PAYGRID_CHAINS,
  twins: PAYGRID_TWINS,
  start: (options) => startPaygrid(options) as unknown as Promise<StartedLabBase>,
  runSolvers: (lab, chainIds) => runReferenceSolvers(lab as unknown as StartedPaygrid, chainIds),
})

function pascalCase(name: string): string {
  return name.replace(/(^|[-_])([a-z])/g, (_, __, ch: string) => ch.toUpperCase())
}

function appEntryPath(app: string): string {
  return join(HERE, 'apps', app, 'index.ts')
}

function appSolversPath(app: string): string {
  return join(HERE, 'apps', app, 'solvers', 'index.ts')
}

/** Return the ordered list of benchmark apps whose `apps/<app>/index.ts` is present on disk. */
export function discoverApps(): string[] {
  return KNOWN_APPS.filter((app) => existsSync(appEntryPath(app)))
}

function findExportFunction<T extends (...args: never[]) => unknown>(
  mod: Record<string, unknown>,
  preferredNames: readonly string[],
  fallbackPattern: RegExp,
): T | undefined {
  for (const name of preferredNames) {
    if (typeof mod[name] === 'function') return mod[name] as T
  }
  for (const [key, value] of Object.entries(mod)) {
    if (typeof value === 'function' && fallbackPattern.test(key)) return value as T
  }
  return undefined
}

async function loadAppModule(app: string): Promise<LoadedAppModule> {
  const cached = loadedApps.get(app)
  if (cached) return cached

  const loader = (async (): Promise<LoadedAppModule> => {
    const entry = appEntryPath(app)
    if (!existsSync(entry)) {
      const available = discoverApps()
      throw new Error(
        `app '${app}' is not installed (missing apps/${app}/index.ts); available apps: ${available.join(', ') || 'none'}`,
      )
    }
    const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>
    const pascal = pascalCase(app)
    const upper = app.toUpperCase()

    const start = findExportFunction<(options: AppStartOptions) => Promise<StartedLabBase>>(
      mod,
      ['startApp', `start${pascal}`],
      /^start[A-Z]/,
    )
    if (!start) {
      throw new Error(`apps/${app}/index.ts does not export start${pascal}() or startApp()`)
    }

    const describe = findExportFunction<() => { app: string; chains: number; twins: number; services: number }>(
      mod,
      ['describeApp', `describe${pascal}`],
      /^describe[A-Z]/,
    )
    const info = describe ? describe() : { app, chains: 0, twins: 0, services: 5 }

    const chains = (
      Array.isArray(mod[`${upper}_CHAINS`]) ? mod[`${upper}_CHAINS`]
        : Array.isArray(mod.CHAINS) ? mod.CHAINS
          : []
    ) as readonly ChainSpec[]
    const twins = (
      Array.isArray(mod[`${upper}_TWINS`]) ? mod[`${upper}_TWINS`]
        : Array.isArray(mod.TWINS) ? mod.TWINS
          : []
    ) as readonly TwinSpec[]

    let runSolvers: LoadedAppModule['runSolvers']
    const solversEntry = appSolversPath(app)
    if (existsSync(solversEntry)) {
      const solverMod = (await import(pathToFileURL(solversEntry).href)) as Record<string, unknown>
      runSolvers = findExportFunction<(lab: StartedLabBase, chainIds?: readonly string[]) => Promise<Finding[]>>(
        solverMod,
        ['runReferenceSolvers', `run${pascal}Solvers`],
        /^run.*Solvers$/,
      )
    }

    const loaded: LoadedAppModule = {
      name: app,
      services: info.services,
      chains,
      twins,
      start,
      runSolvers,
    }
    loadedAppsSync.set(app, loaded)
    return loaded
  })()

  loadedApps.set(app, loader)
  try {
    return await loader
  } catch (err) {
    loadedApps.delete(app)
    throw err
  }
}

export interface LabCatalogue {
  apps: Array<{
    name: string
    services: number
    chains: Array<{ id: string; hops: number; vulnClass: string; terminalKind: string }>
    twins: Array<{ id: string; baseChainId: string; decoyHopIds: string[]; enforcedAtHopId: string }>
  }>
}

/** Synchronous catalogue for existing callers (reports the statically loaded pilot app). */
export function catalog(): LabCatalogue {
  const info = describeApp()
  return {
    apps: [{
      name: info.app,
      services: info.services,
      chains: PAYGRID_CHAINS.map((chain) => ({
        id: chain.id,
        hops: chain.hops.length,
        vulnClass: chain.vulnClass,
        terminalKind: chain.terminal.kind,
      })),
      twins: PAYGRID_TWINS.map((twin) => ({
        id: twin.id,
        baseChainId: twin.baseChainId,
        decoyHopIds: twin.decoyHopIds,
        enforcedAtHopId: twin.enforcedAtHopId,
      })),
    }],
  }
}

/** Async catalogue discovering all installed apps (paygrid, shipforge, nexusiam, connecthub). */
export async function loadCatalog(): Promise<LabCatalogue> {
  const apps: LabCatalogue['apps'] = []
  for (const name of discoverApps()) {
    const mod = await loadAppModule(name)
    apps.push({
      name: mod.name,
      services: mod.services,
      chains: mod.chains.map((chain) => ({
        id: chain.id,
        hops: chain.hops.length,
        vulnClass: chain.vulnClass,
        terminalKind: chain.terminal.kind,
      })),
      twins: mod.twins.map((twin) => ({
        id: twin.id,
        baseChainId: twin.baseChainId,
        decoyHopIds: twin.decoyHopIds,
        enforcedAtHopId: twin.enforcedAtHopId,
      })),
    })
  }
  return { apps }
}

export async function runLab(
  options: { app?: string; seed: number; heldOutSalt?: string; mode: LabMode; twin?: string; asyncLatencyMs?: number },
): Promise<StartedPaygrid> {
  assertLocalLabAllowed()
  const app = options.app ?? 'paygrid'
  if (app === 'paygrid') {
    return startPaygrid({
      seed: options.seed,
      heldOutSalt: options.heldOutSalt,
      mode: options.mode,
      twin: options.twin,
      asyncLatencyMs: options.asyncLatencyMs,
    })
  }
  if (!(KNOWN_APPS as readonly string[]).includes(app)) {
    throw new Error(`unknown app '${app}': known apps are ${discoverApps().join(', ')}`)
  }
  const mod = await loadAppModule(app)
  const started = await mod.start({
    seed: options.seed,
    heldOutSalt: options.heldOutSalt,
    mode: options.mode,
    twin: options.twin,
    asyncLatencyMs: options.asyncLatencyMs,
  })
  return started as unknown as StartedPaygrid
}

export function gradeLab(lab: StartedPaygrid | StartedLabBase, findings: Finding[]): Scorecard {
  return libGradeRun({ groundTruth: lab.groundTruth, findings, oracle: lab.export() })
}

// ---------------------------------------------------------------------------------------------
// Kovo v8 product-runner bridge (`scripts/benchmark-multihop.ts`)
// ---------------------------------------------------------------------------------------------

export interface StartMultihopAppOptions {
  app?: string
  seed?: number
  heldOutSalt?: string
  mode?: LabMode | BenchMode
  variant?: string
  twin?: string
  fastLab?: boolean
  asyncLatencyMs?: number
  oobCallbackPorts?: number[]
}

export interface MultihopProductPersona {
  id: string
  email: string
  password: string
  tenant: string
  tenantId: string
  orgSlug?: string
  role: string
  rolesByTenant: Record<string, string>
}

export interface HardenedTwinEndpoint {
  method: string
  path: string
  routeKey: string
  hopId: string
  service: string
  role: 'decoy_hop' | 'enforced_hop'
}

export interface ProductTwinDecoy {
  twinId: string
  chainId: string
  baseChainId: string
  vulnClass: string
  benignHopIds: string[]
  enforcedAtHopId: string
  note: string
  endpoints: HardenedTwinEndpoint[]
  postEnforcementEndpoints?: Array<{ method: string; path: string; routeKey: string; hopId: string }>
}

export interface MultihopProductBriefing {
  app: string
  mode: BenchMode
  seed: number
  seedSet: SeedSet
  runId: string
  origin: string
  primaryOrigin: string
  publicOrigins: string[]
  origins: Record<string, string>
  entryOrigins: Record<string, string>
  personas: MultihopProductPersona[]
  services?: ServiceTopology[]
  internalServiceNames?: string[]
  apiReference?: ApiRef[]
  sourceDir?: string
}

export interface StartedMultihopApp {
  app: string
  seed: number
  seedSet: SeedSet
  labMode: LabMode
  twinId?: string
  runId: string
  origin: string
  primaryOrigin: string
  entryOrigin: string
  origins: Record<string, string>
  plan: { seedSet: SeedSet } & Record<string, unknown>
  groundTruth: GroundTruth
  sourceDir: string
  briefing(mode?: BenchMode): Briefing
  export(): OracleExport
  collectArtifacts(): {
    groundTruth: GroundTruth
    oracle: OracleExport
    events: unknown[]
    requests: unknown[]
    egress: unknown[]
  }
  oracle: {
    events(): unknown[]
    requests(): unknown[]
    egress(): unknown[]
    chainStates(): unknown[]
    export(): OracleExport
    reset(): void
  }
  rawOracle: ChainOracle
  stop(): Promise<void>
}

export interface ProductSubmittedFinding {
  id?: string
  findingId?: string
  title?: string
  chainId?: string
  twinId?: string
  terminalVulnClass?: string
  vulnClass?: string
  cwe?: string
  hopIds?: string[]
  method?: string
  path?: string
  endpoints?: Array<{ method?: string; path: string }>
  param?: string
  params?: string[]
  severity?: string
  status?: string
  supersededByFindingId?: string | null
  evidenceSummary?: string
}

export interface ProductSubmittedCompositeProof {
  findingId?: string
  chainId: string
  terminalVulnClass: string
  hopCount: number
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript'
  confirmed: boolean
  attackerProvenanceValid: boolean
  modeBVerified?: boolean
  receipt?: {
    hops?: Array<{
      hopId: string
      target?: { method?: string; pathAndQuery?: string }
    }>
    causalEdges?: Array<{ kind?: string }>
    terminalImpact?: { terminalHopId?: string }
  }
  verification?: {
    terminalEndpoint?: string | null
    terminalOracleFamily?: string | null
  }
}

export interface ProductGradeInput {
  groundTruth: GroundTruth
  findings: ProductSubmittedFinding[]
  compositeReceipts?: ProductSubmittedCompositeProof[]
  oracleEvents: unknown[]
  requestLog?: unknown[]
  egressLog?: unknown[]
  oracleExport?: OracleExport
  telemetry?: {
    startedAtMs?: number
    endedAtMs?: number
    durationMs?: number
    totalCostUsd?: number
    budgetUsd?: number
    budgetExhausted?: boolean
  }
  mode?: BenchMode
}

type ProductDropReason =
  | 'capability_not_extracted'
  | 'pivot_not_discovered'
  | 'edge_binding_rejected'
  | 'replay_failed'
  | 'budget_exhausted'
  | 'persona_shortcut_rejected'
  | 'other'

export interface ProductChainVerdict {
  chainId: string
  expectedHops: number
  maxHopReached: number
  oracleObserved: boolean
  forbiddenShortcutViolation: boolean
  compositeReceiptConfirmed: boolean
  twoSideConfirmed: boolean
  replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
  dropReason: ProductDropReason | null
  failureReason: string | null
  missingHopIds: string[]
  matchedFindingIds: string[]
  oracleEventSeqs: number[]
  terminalVulnClass: string
}

export interface ProductTwinVerdict {
  twinId: string
  baseChainId?: string
  vulnClass?: string
  falsePositive: boolean
  matchedFindingIds: string[]
  reason?: string
}

export interface ProductHopDepthFunnel {
  totalChains: number
  H1: number
  H2: number
  H3: number
  H4Plus: number
  FinalOracle: number
  CompositeReceiptConfirmed: number
  dropReasons: Record<ProductDropReason, number>
}

export interface ProductScorecard {
  app: string
  seed: number
  seedSet: SeedSet
  mode: string
  chainsTotal: number
  chainsOracleObserved: number
  chainsCompositeConfirmed: number
  chainsConfirmed: number
  recall: number
  precision: number
  hardenedTwinsTotal: number
  hardenedTwinDecoyFps: number
  decoys: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  totalCostUsd: number
  hopFunnel: ProductHopDepthFunnel
  chains: ProductChainVerdict[]
  hardenedTwins: ProductTwinVerdict[]
}

interface ChainEndpointTemplate {
  method: string
  path: string
  routeKey: string
  hopId?: string
}

interface ResolvedChainMatchSpec {
  chainId: string
  vulnClass: string
  terminalEndpoints: ChainEndpointTemplate[]
  upstreamHopEndpoints: ChainEndpointTemplate[]
  edgeKinds: string[]
}

const groundTruthOracleMap = new WeakMap<object, () => OracleExport>()
const groundTruthTwinsMap = new WeakMap<object, ProductTwinDecoy[]>()
const groundTruthChainsMap = new WeakMap<object, ResolvedChainMatchSpec[]>()
const startedDefaultBriefingMode = new WeakMap<object, BenchMode>()

function resolveRouteKeyRefs(routeKey: string, byRouteKey: ReadonlyMap<string, ApiRef>): ApiRef[] {
  const out: ApiRef[] = []
  const seen = new Set<string>()
  const addKey = (key: string): void => {
    const ref = byRouteKey.get(key)
    if (!ref) return
    const dedupeKey = `${ref.method.toUpperCase()} ${ref.path}`
    if (seen.has(dedupeKey)) return
    seen.add(dedupeKey)
    out.push(ref)
  }
  addKey(routeKey)
  const alias = HOP_ROUTE_KEY_ALIASES[routeKey]
  if (typeof alias === 'string') {
    addKey(alias)
  } else if (Array.isArray(alias)) {
    for (const key of alias) addKey(key)
  }
  return out
}

function buildResolvedChainMatchSpecs(
  chains: readonly ChainSpec[],
  apiReference?: readonly ApiRef[],
): ResolvedChainMatchSpec[] {
  if (!chains.length || !apiReference?.length) return []
  const byRouteKey = new Map<string, ApiRef>()
  for (const ref of apiReference) byRouteKey.set(ref.routeKey, ref)

  return chains.map((chain) => {
    const terminalEndpoints: ChainEndpointTemplate[] = []
    const terminalSeen = new Set<string>()
    const addTerminal = (routeKey: string, hopId?: string): void => {
      for (const ref of resolveRouteKeyRefs(routeKey, byRouteKey)) {
        const method = ref.method.toUpperCase()
        const dedupeKey = `${method} ${ref.path}`
        if (terminalSeen.has(dedupeKey)) continue
        terminalSeen.add(dedupeKey)
        terminalEndpoints.push({ method, path: ref.path, routeKey, ...(hopId ? { hopId } : {}) })
      }
    }

    const lastHop = chain.hops[chain.hops.length - 1]
    addTerminal(chain.terminal.routeKey, lastHop?.hopId)
    if (lastHop && lastHop.routeKey !== chain.terminal.routeKey) {
      addTerminal(lastHop.routeKey, lastHop.hopId)
    }

    const upstreamHopEndpoints: ChainEndpointTemplate[] = []
    const upstreamSeen = new Set<string>()
    const upstreamHops = chain.hops.length > 1 ? chain.hops.slice(0, -1) : []
    for (const hop of upstreamHops) {
      for (const ref of resolveRouteKeyRefs(hop.routeKey, byRouteKey)) {
        const method = ref.method.toUpperCase()
        const dedupeKey = `${method} ${ref.path}`
        if (upstreamSeen.has(dedupeKey)) continue
        upstreamSeen.add(dedupeKey)
        upstreamHopEndpoints.push({ method, path: ref.path, routeKey: hop.routeKey, hopId: hop.hopId })
      }
    }

    const edgeKinds = chain.hops.flatMap((hop) => (hop.edgeFromPrevious ? [hop.edgeFromPrevious] : []))
    return {
      chainId: chain.id,
      vulnClass: chain.vulnClass,
      terminalEndpoints,
      upstreamHopEndpoints,
      edgeKinds,
    }
  })
}

function resolveTwinEndpoints(
  twin: TwinSpec,
  chain: ChainSpec | undefined,
  apiReference: readonly ApiRef[] | undefined,
): HardenedTwinEndpoint[] {
  if (!chain || !apiReference?.length) return []
  const byRouteKey = new Map<string, ApiRef>()
  for (const ref of apiReference) byRouteKey.set(ref.routeKey, ref)
  const out: HardenedTwinEndpoint[] = []
  const seen = new Set<string>()
  const addHop = (hopId: string, role: HardenedTwinEndpoint['role']): void => {
    const hop = chain.hops.find((h) => h.hopId === hopId)
    if (!hop) return
    for (const ref of resolveRouteKeyRefs(hop.routeKey, byRouteKey)) {
      const dedupeKey = `${ref.method.toUpperCase()} ${ref.path} ${hopId}`
      if (seen.has(dedupeKey)) continue
      seen.add(dedupeKey)
      out.push({
        method: ref.method.toUpperCase(),
        path: ref.path,
        routeKey: hop.routeKey,
        hopId,
        service: String(hop.service),
        role,
      })
    }
  }
  for (const hopId of twin.decoyHopIds) addHop(hopId, 'decoy_hop')
  if (twin.enforcedAtHopId) addHop(twin.enforcedAtHopId, 'enforced_hop')
  return out
}

function resolveTwinPostEnforcementEndpoints(
  twin: TwinSpec,
  chain: ChainSpec | undefined,
  apiReference: readonly ApiRef[] | undefined,
  decoyEndpoints: readonly HardenedTwinEndpoint[],
): Array<{ method: string; path: string; routeKey: string; hopId: string }> {
  if (!chain || !apiReference?.length) return []
  const enforcedIdx = chain.hops.findIndex((h) => h.hopId === twin.enforcedAtHopId)
  if (enforcedIdx < 0) return []
  const byRouteKey = new Map<string, ApiRef>()
  for (const ref of apiReference) byRouteKey.set(ref.routeKey, ref)
  const decoyKeys = new Set(
    decoyEndpoints.map((ep) => `${ep.method.toUpperCase()} ${normalizeEndpointPath(ep.path)}`),
  )
  const out: Array<{ method: string; path: string; routeKey: string; hopId: string }> = []
  const seen = new Set<string>()
  const addRouteKey = (routeKey: string, hopId: string): void => {
    for (const ref of resolveRouteKeyRefs(routeKey, byRouteKey)) {
      const method = ref.method.toUpperCase()
      const key = `${method} ${normalizeEndpointPath(ref.path)}`
      if (decoyKeys.has(key) || seen.has(key)) continue
      seen.add(key)
      out.push({ method, path: ref.path, routeKey, hopId })
    }
  }
  const postHops = chain.hops.slice(enforcedIdx + 1)
  for (const hop of postHops) addRouteKey(hop.routeKey, hop.hopId)
  const lastHop = postHops[postHops.length - 1]
  if (chain.terminal.routeKey && (!lastHop || chain.terminal.routeKey !== lastHop.routeKey)) {
    addRouteKey(chain.terminal.routeKey, lastHop?.hopId ?? chain.id)
  }
  return out
}

function buildProductTwinDecoys(
  twins: readonly TwinSpec[],
  chains: readonly ChainSpec[],
  apiReference?: readonly ApiRef[],
  selectedTwinId?: string,
): ProductTwinDecoy[] {
  const chosen = selectedTwinId ? twins.filter((t) => t.id === selectedTwinId) : twins
  return chosen.map((twin) => {
    const baseChain = chains.find((c) => c.id === twin.baseChainId)
    const endpoints = resolveTwinEndpoints(twin, baseChain, apiReference)
    const postEnforcementEndpoints = resolveTwinPostEnforcementEndpoints(twin, baseChain, apiReference, endpoints)
    return {
      twinId: twin.id,
      chainId: twin.baseChainId,
      baseChainId: twin.baseChainId,
      vulnClass: baseChain?.vulnClass ?? '',
      benignHopIds: [...twin.decoyHopIds],
      enforcedAtHopId: twin.enforcedAtHopId,
      note: twin.note,
      endpoints,
      postEnforcementEndpoints,
    }
  })
}

function normalizeEndpointPath(raw: string): string {
  let path = raw.trim()
  if (/^https?:\/\//i.test(path)) {
    try {
      path = new URL(path).pathname
    } catch { /* fall through to string normalization */ }
  }
  const hashIdx = path.indexOf('#')
  if (hashIdx >= 0) path = path.slice(0, hashIdx)
  const queryIdx = path.indexOf('?')
  if (queryIdx >= 0) path = path.slice(0, queryIdx)
  path = path.replace(/\/{2,}/g, '/')
  if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1)
  return path.startsWith('/') ? path : `/${path}`
}

function escapeRegexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function templateSegmentToRegex(segment: string): string {
  if (/^:[A-Za-z0-9_-]+$/.test(segment) || /^\{[A-Za-z0-9_-]+\}$/.test(segment)) {
    return '[^/]+'
  }
  const tokenRe = /:[A-Za-z0-9_-]+|\{[A-Za-z0-9_-]+\}/g
  let out = ''
  let lastIndex = 0
  for (const match of segment.matchAll(tokenRe)) {
    const idx = match.index ?? 0
    out += escapeRegexLiteral(segment.slice(lastIndex, idx))
    out += '[^/]+'
    lastIndex = idx + match[0].length
  }
  out += escapeRegexLiteral(segment.slice(lastIndex))
  return out
}

function pathMatchesTemplate(actualRaw: string, templateRaw: string): boolean {
  const actual = normalizeEndpointPath(actualRaw)
  const template = normalizeEndpointPath(templateRaw)
  if (actual === template) return true
  const actualSegs = actual.split('/')
  const templateSegs = template.split('/')
  if (actualSegs.length !== templateSegs.length) return false
  for (let i = 0; i < templateSegs.length; i++) {
    const tSeg = templateSegs[i]!
    const aSeg = actualSegs[i]!
    if (tSeg === aSeg) continue
    const re = new RegExp(`^${templateSegmentToRegex(tSeg)}$`)
    if (!re.test(aSeg)) return false
  }
  return true
}

function findingEndpoints(finding: ProductSubmittedFinding): Array<{ method?: string; path: string }> {
  const out: Array<{ method?: string; path: string }> = []
  if (Array.isArray(finding.endpoints)) {
    for (const ep of finding.endpoints) {
      if (ep && typeof ep.path === 'string' && ep.path.trim()) {
        out.push({ ...(ep.method ? { method: ep.method } : {}), path: ep.path })
      }
    }
  }
  if (typeof finding.path === 'string' && finding.path.trim()) {
    out.push({ ...(finding.method ? { method: finding.method } : {}), path: finding.path })
  }
  return out
}

function endpointMatchesTwin(
  ep: { method?: string; path: string },
  twin: ProductTwinDecoy,
): boolean {
  const epMethod = ep.method?.trim().toUpperCase()
  for (const twinEp of twin.endpoints) {
    if (epMethod && twinEp.method && epMethod !== twinEp.method.toUpperCase()) continue
    if (pathMatchesTemplate(ep.path, twinEp.path)) return true
  }
  return false
}

function findingMatchesTwin(
  finding: ProductSubmittedFinding,
  twin: ProductTwinDecoy,
  options: { isTwinMode: boolean; baseChainConfirmed: boolean },
): boolean {
  if (finding.twinId === twin.twinId || finding.chainId === twin.twinId) return true
  if ((finding.hopIds ?? []).some((hopId) => twin.benignHopIds.includes(hopId) || hopId === twin.enforcedAtHopId)) {
    return true
  }
  const eps = findingEndpoints(finding)
  if (eps.some((ep) => endpointMatchesTwin(ep, twin))) return true

  const claimedVuln = (finding.terminalVulnClass ?? finding.vulnClass ?? '').trim().toLowerCase()
  const twinVuln = twin.vulnClass.trim().toLowerCase()
  const vulnMatches = Boolean(twinVuln && claimedVuln && claimedVuln === twinVuln)
  const baseChainMatches = finding.chainId === twin.baseChainId

  if (options.isTwinMode && (baseChainMatches || vulnMatches)) return true
  return false
}

function resolveProductTwins(gt: GroundTruth): ProductTwinDecoy[] {
  const mapped = groundTruthTwinsMap.get(gt)
  if (mapped && mapped.length > 0) return mapped

  const mod = loadedAppsSync.get(String(gt.app))
  if (gt.twinDecoys.length > 0) {
    return gt.twinDecoys.map((raw) => {
      const ext = raw as Partial<ProductTwinDecoy>
      const catalogTwin = mod?.twins.find((t) =>
        (ext.twinId && t.id === ext.twinId)
        || (gt.twinId && t.id === gt.twinId)
        || (t.baseChainId === raw.chainId && t.enforcedAtHopId === raw.enforcedAtHopId),
      )
      const baseChainId = ext.baseChainId ?? catalogTwin?.baseChainId ?? raw.chainId
      const baseChain = mod?.chains.find((c) => c.id === baseChainId)
      return {
        twinId: ext.twinId ?? catalogTwin?.id ?? gt.twinId ?? raw.chainId,
        chainId: raw.chainId,
        baseChainId,
        vulnClass: ext.vulnClass ?? baseChain?.vulnClass ?? '',
        benignHopIds: [...raw.benignHopIds],
        enforcedAtHopId: raw.enforcedAtHopId,
        note: raw.note,
        endpoints: Array.isArray(ext.endpoints) ? ext.endpoints : [],
      }
    })
  }

  if (mod && mod.twins.length > 0) {
    return buildProductTwinDecoys(mod.twins, mod.chains, undefined, gt.twinId)
  }
  return []
}

function flattenOracleEvents(exported: OracleExport): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = []
  for (const hop of exported.events.hops) out.push({ eventKind: 'hop', ...hop })
  for (const edge of exported.events.edges) out.push({ eventKind: 'edge', ...edge })
  for (const control of exported.events.controls) out.push({ eventKind: 'control', ...control })
  for (const terminal of exported.events.terminals) out.push({ eventKind: 'terminal', ...terminal })
  out.sort((a, b) => Number(a.seq ?? 0) - Number(b.seq ?? 0) || Number(a.ts ?? 0) - Number(b.ts ?? 0))
  return out
}

function resolveLabAndBriefingModes(mode: LabMode | BenchMode | undefined): {
  labMode: LabMode
  defaultBriefingMode: BenchMode
} {
  if (mode === 'hardened') return { labMode: 'hardened', defaultBriefingMode: 'grey-box' }
  if (mode === 'black-box' || mode === 'grey-box' || mode === 'white-box') {
    return { labMode: 'vulnerable', defaultBriefingMode: mode }
  }
  return { labMode: 'vulnerable', defaultBriefingMode: 'grey-box' }
}

/**
 * Start any installed multihop-saas archetype (`paygrid`, `shipforge`, `nexusiam`, or `connecthub`)
 * and wrap it with the exact `MultihopStartedApp` contract consumed by `scripts/benchmark-multihop.ts`.
 */
export async function startMultihopApp(opts: StartMultihopAppOptions = {}): Promise<StartedMultihopApp> {
  assertLocalLabAllowed()
  const app = opts.app ?? 'paygrid'
  if (!(KNOWN_APPS as readonly string[]).includes(app)) {
    throw new Error(`unknown app '${app}': known apps are ${discoverApps().join(', ')}`)
  }
  const seed = opts.seed ?? 1
  const { labMode, defaultBriefingMode } = resolveLabAndBriefingModes(opts.mode)
  const twin = opts.twin ?? opts.variant
  const asyncLatencyMs = opts.asyncLatencyMs ?? (opts.fastLab ? 5 : undefined)

  const mod = await loadAppModule(app)
  const lab = await mod.start({
    seed,
    heldOutSalt: opts.heldOutSalt,
    mode: labMode,
    twin,
    asyncLatencyMs,
  })

  const greyApiRef = lab.briefing('grey-box').apiReference
  const resolvedTwins = buildProductTwinDecoys(mod.twins, mod.chains, greyApiRef, lab.twinId)
  const resolvedChains = buildResolvedChainMatchSpecs(mod.chains, greyApiRef)
  const productGroundTruth: GroundTruth = {
    ...lab.groundTruth,
    twinDecoys: resolvedTwins,
  }
  groundTruthOracleMap.set(lab.groundTruth, () => lab.export())
  groundTruthOracleMap.set(productGroundTruth, () => lab.export())
  groundTruthTwinsMap.set(lab.groundTruth, resolvedTwins)
  groundTruthTwinsMap.set(productGroundTruth, resolvedTwins)
  groundTruthChainsMap.set(lab.groundTruth, resolvedChains)
  groundTruthChainsMap.set(productGroundTruth, resolvedChains)

  let stopPromise: Promise<void> | undefined
  const stop = (): Promise<void> => {
    stopPromise ??= lab.stop()
    return stopPromise
  }

  const started: StartedMultihopApp = {
    app: String(lab.app),
    seed: lab.seed,
    seedSet: lab.seedSet,
    labMode: lab.labMode,
    ...(lab.twinId !== undefined ? { twinId: lab.twinId } : {}),
    runId: lab.runId,
    origin: lab.entryOrigin,
    primaryOrigin: lab.entryOrigin,
    entryOrigin: lab.entryOrigin,
    origins: { ...lab.origins },
    plan: lab.plan,
    groundTruth: productGroundTruth,
    sourceDir: lab.sourceDir,
    briefing(mode?: BenchMode): Briefing {
      return lab.briefing(mode ?? defaultBriefingMode)
    },
    export(): OracleExport {
      return lab.export()
    },
    collectArtifacts() {
      const exported = lab.export()
      return {
        groundTruth: productGroundTruth,
        oracle: exported,
        events: flattenOracleEvents(exported),
        requests: [],
        egress: [],
      }
    },
    oracle: {
      events(): unknown[] {
        return flattenOracleEvents(lab.export())
      },
      requests(): unknown[] {
        return []
      },
      egress(): unknown[] {
        return []
      },
      chainStates(): unknown[] {
        return lab.export().evaluations
      },
      export(): OracleExport {
        return lab.export()
      },
      reset(): void {
        // ChainOracle instances are immutable per run; fresh runs create fresh instances.
      },
    },
    rawOracle: lab.oracle,
    stop,
  }
  startedDefaultBriefingMode.set(started, defaultBriefingMode)
  return started
}

export const startApp = startMultihopApp

/**
 * Produce the mode-scoped briefing expected by `scripts/benchmark-multihop.ts`.
 * Never leaks ground truth, victim bot credentials, internal origins, or out-of-mode artifacts.
 */
export function briefingFor(
  started: StartedMultihopApp | StartedLabBase | StartedPaygrid,
  mode?: BenchMode,
): MultihopProductBriefing {
  const resolvedMode = mode ?? startedDefaultBriefingMode.get(started) ?? 'grey-box'
  const raw = started.briefing(resolvedMode)
  const entryOrigins: Record<string, string> = {}
  for (const [service, origin] of Object.entries(raw.entryOrigins as Record<string, string | undefined>)) {
    if (origin) entryOrigins[service] = origin
  }
  const primaryOrigin = ('origin' in started && typeof started.origin === 'string' && started.origin)
    ? started.origin
    : started.entryOrigin || Object.values(entryOrigins)[0] || ''

  const publicOrigins: string[] = []
  const seen = new Set<string>()
  const pushOrigin = (origin: string | undefined): void => {
    if (!origin || seen.has(origin)) return
    seen.add(origin)
    publicOrigins.push(origin)
  }
  pushOrigin(primaryOrigin)
  for (const origin of Object.values(entryOrigins)) pushOrigin(origin)

  // Never leak admin_bot or its org_c tenant slug into the briefing.
  const nonBotPersonas = raw.personas.filter((persona) => String(persona.id) !== 'admin_bot')
  const exposedTenantIds = new Set(nonBotPersonas.map((persona) => String(persona.tenant)))
  const slugByTenantId = new Map<string, string>()
  const planTenants = (started.plan as { tenants?: Record<string, { id?: string; slug?: string }> } | undefined)?.tenants
  if (planTenants && typeof planTenants === 'object') {
    for (const entry of Object.values(planTenants)) {
      if (entry && typeof entry.id === 'string' && typeof entry.slug === 'string' && exposedTenantIds.has(entry.id)) {
        slugByTenantId.set(entry.id, entry.slug)
      }
    }
  }

  const personas: MultihopProductPersona[] = nonBotPersonas.map((persona) => {
    const rolesByTenant: Record<string, string> = {}
    for (const [tenant, role] of Object.entries(persona.rolesByTenant)) {
      if (role) rolesByTenant[tenant] = role
    }
    const primaryRole = rolesByTenant[persona.tenant] ?? Object.values(rolesByTenant)[0] ?? 'member'
    const tenantId = String(persona.tenant)
    const orgSlug = slugByTenantId.get(tenantId)
    return {
      id: persona.id,
      email: persona.email,
      password: persona.password,
      tenant: tenantId,
      tenantId,
      ...(orgSlug ? { orgSlug } : {}),
      role: primaryRole,
      rolesByTenant,
    }
  })

  const out: MultihopProductBriefing = {
    app: String(raw.app),
    mode: resolvedMode,
    seed: raw.seed,
    seedSet: raw.seedSet,
    runId: raw.runId,
    origin: primaryOrigin,
    primaryOrigin,
    publicOrigins,
    origins: { ...entryOrigins },
    entryOrigins,
    personas,
  }
  if (resolvedMode !== 'black-box') {
    if (raw.services) out.services = raw.services
    if (raw.internalServiceNames) out.internalServiceNames = raw.internalServiceNames.map(String)
    if (raw.apiReference) out.apiReference = raw.apiReference
  }
  if (resolvedMode === 'white-box' && raw.sourceDir) {
    out.sourceDir = raw.sourceDir
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Overloaded listSeeds, gradeRun, renderScorecard (standalone + product runner)
// ---------------------------------------------------------------------------------------------

export interface SeedCatalogue {
  apps: string[]
  dev: number[]
  heldOutAvailable: boolean
  heldOut?: number[]
}

export function listSeeds(): SeedCatalogue
export function listSeeds(set: SeedSet, n?: number, salt?: string): number[]
export function listSeeds(set?: SeedSet, n = 5, salt?: string): number[] | SeedCatalogue {
  if (set !== undefined) return libListSeeds(set, n, salt)
  const resolvedSalt = salt ?? process.env.KOVO_RB_HELDOUT_SALT
  const heldOutAvailable = Boolean(resolvedSalt && resolvedSalt.length >= 16)
  return {
    apps: discoverApps(),
    dev: libListSeeds('dev', n),
    heldOutAvailable,
    ...(heldOutAvailable ? { heldOut: libListSeeds('held-out', n, resolvedSalt) } : {}),
  }
}

function emptyProductDropReasons(): Record<ProductDropReason, number> {
  return {
    capability_not_extracted: 0,
    pivot_not_discovered: 0,
    edge_binding_rejected: 0,
    replay_failed: 0,
    budget_exhausted: 0,
    persona_shortcut_rejected: 0,
    other: 0,
  }
}

function mapProductDropReason(raw: string | undefined | null): ProductDropReason | null {
  if (!raw) return null
  switch (raw) {
    case 'capability_not_extracted':
    case 'pivot_not_discovered':
    case 'edge_binding_rejected':
    case 'replay_failed':
    case 'budget_exhausted':
    case 'persona_shortcut_rejected':
    case 'other':
      return raw
    case 'terminal_not_observed':
      return 'pivot_not_discovered'
    default:
      return 'other'
  }
}

function isStandaloneGradeInput(input: GradeInput | ProductGradeInput): input is GradeInput {
  return 'oracle' in input && input.oracle !== undefined
}

interface ParsedEndpointCandidate {
  method?: string
  path: string
}

function parseEndpointCandidate(
  rawPath: string | null | undefined,
  explicitMethod?: string | null,
): ParsedEndpointCandidate | null {
  if (typeof rawPath !== 'string') return null
  const trimmed = rawPath.trim()
  if (!trimmed) return null
  const methodMatch = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$/i.exec(trimmed)
  const method = (methodMatch?.[1] ?? explicitMethod ?? '').trim().toUpperCase() || undefined
  const pathPart = methodMatch?.[2] ?? trimmed
  const path = normalizeEndpointPath(pathPart)
  if (!path) return null
  return { ...(method ? { method } : {}), path }
}

function endpointMatchesTemplate(
  candidate: ParsedEndpointCandidate,
  template: ChainEndpointTemplate,
): boolean {
  if (candidate.method && template.method && candidate.method !== template.method.toUpperCase()) {
    return false
  }
  return pathMatchesTemplate(candidate.path, template.path)
}

function receiptPriority(receipt: ProductSubmittedCompositeProof): number {
  const modeAConfirmed = receipt.confirmed
    && receipt.attackerProvenanceValid
    && receipt.replayMode === 'fresh_clean_replay'
  if (modeAConfirmed) return 3
  if (receipt.confirmed) return 2
  if (receipt.replayMode === 'fresh_clean_replay') return 1
  return 0
}

function resolveReceiptChainId(
  receipt: ProductSubmittedCompositeProof,
  candidateChainIds: ReadonlySet<string>,
  chainSpecs: readonly ResolvedChainMatchSpec[],
  oracleObservedByChain: ReadonlyMap<string, boolean>,
): string | null {
  // Step A: exact benchmark chainId match (preserves all existing unit/synthetic tests).
  if (receipt.chainId && candidateChainIds.has(receipt.chainId)) {
    return receipt.chainId
  }

  // Step B: endpoint + causal-topology matching for real Kovo runs (anti-contamination generic chainIds).
  if (!chainSpecs.length || candidateChainIds.size === 0) return null
  const hops = receipt.receipt?.hops
  if (receipt.hopCount < 2 || (hops !== undefined && hops.length < 2)) {
    return null
  }

  const terminalHopId = receipt.receipt?.terminalImpact?.terminalHopId
  const terminalHop = hops?.length
    ? ((terminalHopId ? hops.find((h) => h.hopId === terminalHopId) : undefined) ?? hops[hops.length - 1])
    : undefined

  const terminalCandidates: ParsedEndpointCandidate[] = []
  const seenTerm = new Set<string>()
  const addTerminalCandidate = (rawPath: string | null | undefined, explicitMethod?: string | null): void => {
    const parsed = parseEndpointCandidate(rawPath, explicitMethod)
    if (!parsed) return
    const key = `${parsed.method ?? '*'} ${parsed.path}`
    if (seenTerm.has(key)) return
    seenTerm.add(key)
    terminalCandidates.push(parsed)
  }
  addTerminalCandidate(receipt.verification?.terminalEndpoint, terminalHop?.target?.method)
  addTerminalCandidate(terminalHop?.target?.pathAndQuery, terminalHop?.target?.method)
  if (!terminalCandidates.length) return null

  const matchSpecsForCandidates = (candidates: readonly ParsedEndpointCandidate[]): ResolvedChainMatchSpec[] =>
    chainSpecs.filter((spec) =>
      candidateChainIds.has(spec.chainId)
      && candidates.some((cand) =>
        spec.terminalEndpoints.some((tmpl) => endpointMatchesTemplate(cand, tmpl)),
      ),
    )

  let effectiveTerminalHop = terminalHop
  let readbackTailHop: NonNullable<typeof hops>[number] | undefined
  let matchingSpecs = matchSpecsForCandidates(terminalCandidates)

  // Post-mutation readback fallback: if the final hop is a read-only GET verification/readback
  // (e.g. GET /me, GET /orgs/..., GET /profile) that matched no chain terminal, allow resolving
  // against the penultimate hop while requiring >= 3 hops so at least one upstream hop remains.
  if (!matchingSpecs.length && hops && hops.length >= 3) {
    const lastHop = hops[hops.length - 1]!
    const penultimateHop = hops[hops.length - 2]!
    const lastParsed = parseEndpointCandidate(lastHop.target?.pathAndQuery, lastHop.target?.method)
    const penultimateCand = parseEndpointCandidate(penultimateHop.target?.pathAndQuery, penultimateHop.target?.method)
    if (lastParsed?.method === 'GET' && penultimateCand) {
      const penultimateMatches = matchSpecsForCandidates([penultimateCand])
      if (penultimateMatches.length > 0) {
        matchingSpecs = penultimateMatches
        effectiveTerminalHop = penultimateHop
        readbackTailHop = lastHop
      }
    }
  }

  if (!matchingSpecs.length) return null
  if (matchingSpecs.length === 1) return matchingSpecs[0]!.chainId

  const upstreamCandidates: ParsedEndpointCandidate[] = []
  const seenUp = new Set<string>()
  for (const hop of hops ?? []) {
    if (hop === effectiveTerminalHop || hop === readbackTailHop) continue
    const parsed = parseEndpointCandidate(hop.target?.pathAndQuery, hop.target?.method)
    if (!parsed) continue
    const key = `${parsed.method ?? '*'} ${parsed.path}`
    if (seenUp.has(key)) continue
    seenUp.add(key)
    upstreamCandidates.push(parsed)
  }
  const receiptEdgeKinds = new Set(
    (receipt.receipt?.causalEdges ?? [])
      .map((edge) => edge?.kind?.trim())
      .filter((kind): kind is string => Boolean(kind)),
  )

  let bestChainId = matchingSpecs[0]!.chainId
  let bestScore = -1
  for (const spec of matchingSpecs) {
    let upstreamOverlap = 0
    for (const up of upstreamCandidates) {
      if (spec.upstreamHopEndpoints.some((tmpl) => endpointMatchesTemplate(up, tmpl))) {
        upstreamOverlap += 1
      }
    }
    const specEdgeSet = new Set(spec.edgeKinds)
    let edgeOverlap = 0
    for (const kind of receiptEdgeKinds) {
      if (specEdgeSet.has(kind)) edgeOverlap += 1
    }
    const oracleBonus = oracleObservedByChain.get(spec.chainId) ? 1 : 0
    const score = (upstreamOverlap * 10) + (edgeOverlap * 2) + oracleBonus
    if (score > bestScore) {
      bestScore = score
      bestChainId = spec.chainId
    }
  }
  return bestChainId
}

function receiptReachesPostEnforcement(
  receipt: ProductSubmittedCompositeProof,
  decoy: ProductTwinDecoy,
): boolean {
  const postTemplates = decoy.postEnforcementEndpoints
  if (!postTemplates?.length) return false
  if (!receipt.confirmed || !receipt.attackerProvenanceValid || receipt.replayMode !== 'fresh_clean_replay') {
    return false
  }
  const hops = receipt.receipt?.hops
  if (receipt.hopCount < 2 || (hops !== undefined && hops.length < 2)) {
    return false
  }
  const terminalHopId = receipt.receipt?.terminalImpact?.terminalHopId
  const terminalHop = hops?.length
    ? ((terminalHopId ? hops.find((h) => h.hopId === terminalHopId) : undefined) ?? hops[hops.length - 1])
    : undefined

  const terminalCandidates: ParsedEndpointCandidate[] = []
  const seen = new Set<string>()
  const addCandidate = (rawPath: string | null | undefined, explicitMethod?: string | null): void => {
    const parsed = parseEndpointCandidate(rawPath, explicitMethod)
    if (!parsed) return
    const key = `${parsed.method ?? '*'} ${parsed.path}`
    if (seen.has(key)) return
    seen.add(key)
    terminalCandidates.push(parsed)
  }
  addCandidate(receipt.verification?.terminalEndpoint, terminalHop?.target?.method)
  addCandidate(terminalHop?.target?.pathAndQuery, terminalHop?.target?.method)

  const matchesPost = (candidates: readonly ParsedEndpointCandidate[]): boolean =>
    candidates.some((cand) => postTemplates.some((tmpl) => endpointMatchesTemplate(cand, tmpl)))

  if (matchesPost(terminalCandidates)) return true

  // Post-mutation GET readback tail (e.g. NX-C1 h1-h4 ending in PATCH /v1/scim/users/:id -> GET /v1/me):
  // require >= 3 hops so at least one upstream hop remains before the penultimate mutation hop.
  if (hops && hops.length >= 3) {
    const lastHop = hops[hops.length - 1]!
    const penultimateHop = hops[hops.length - 2]!
    const lastParsed = parseEndpointCandidate(lastHop.target?.pathAndQuery, lastHop.target?.method)
    const penultimateCand = parseEndpointCandidate(penultimateHop.target?.pathAndQuery, penultimateHop.target?.method)
    if (lastParsed?.method === 'GET' && penultimateCand && matchesPost([penultimateCand])) {
      return true
    }
  }
  return false
}

function gradeProductRun(input: ProductGradeInput): ProductScorecard {
  const gt = input.groundTruth
  const oracleExport = input.oracleExport ?? groundTruthOracleMap.get(gt)?.()
  const evalByChain = new Map((oracleExport?.evaluations ?? []).map((ev) => [ev.chainId, ev]))
  const rawReceipts = input.compositeReceipts ?? []
  const rawFindings = input.findings ?? []
  const chainSpecs = groundTruthChainsMap.get(gt) ?? []
  const isHardenedOrTwinRun = gt.labMode === 'hardened' || Boolean(gt.twinId)

  const oracleEventsByChain = new Map<string, Array<{ seq: number; eventKind?: string; hopId?: string }>>()
  for (const raw of input.oracleEvents ?? []) {
    if (!raw || typeof raw !== 'object') continue
    const ev = raw as Record<string, unknown>
    if (typeof ev.chainId !== 'string') continue
    const list = oracleEventsByChain.get(ev.chainId) ?? []
    list.push({
      seq: typeof ev.seq === 'number' ? ev.seq : 0,
      ...(typeof ev.eventKind === 'string' ? { eventKind: ev.eventKind } : {}),
      ...(typeof ev.hopId === 'string' ? { hopId: ev.hopId } : {}),
    })
    oracleEventsByChain.set(ev.chainId, list)
  }

  const expectedChainIds = new Set<string>()
  const oracleObservedByChain = new Map<string, boolean>()
  for (const expected of gt.expectedChains) {
    expectedChainIds.add(expected.chainId)
    const evaluation = evalByChain.get(expected.chainId)
    const chainEvents = oracleEventsByChain.get(expected.chainId) ?? []
    const observedHopIds = new Set(
      chainEvents.filter((e) => e.eventKind === 'hop' && e.hopId).map((e) => e.hopId!),
    )
    const maxHopReached = evaluation ? evaluation.hopsObserved : observedHopIds.size
    const forbiddenShortcutViolation = evaluation?.dropReason === 'persona_shortcut_rejected'
    const oracleObserved = evaluation
      ? evaluation.completed && evaluation.terminalObserved && !forbiddenShortcutViolation
      : chainEvents.some((e) => e.eventKind === 'terminal') && maxHopReached >= expected.hopIds.length
    oracleObservedByChain.set(expected.chainId, oracleObserved)
  }

  const allSpecChainIds = new Set(chainSpecs.map((spec) => spec.chainId))
  const chainSpecById = new Map(chainSpecs.map((spec) => [spec.chainId, spec]))
  const rawSupersededFindingIds = new Set<string>()
  for (const f of rawFindings) {
    if (typeof f.supersededByFindingId === 'string' && f.supersededByFindingId.trim()) {
      if (f.id) rawSupersededFindingIds.add(f.id)
      if (f.findingId) rawSupersededFindingIds.add(f.findingId)
    }
  }

  const receiptByChain = new Map<string, ProductSubmittedCompositeProof>()
  const resolvedChainByReceipt = new Map<ProductSubmittedCompositeProof, string>()
  const resolvedChainsByFindingId = new Map<string, Set<string>>()
  const confirmedReceiptChainsByFindingId = new Map<string, Set<string>>()
  for (const receipt of rawReceipts) {
    const resolvedExpected = resolveReceiptChainId(receipt, expectedChainIds, chainSpecs, oracleObservedByChain)
    const resolvedAny = resolvedExpected
      ?? resolveReceiptChainId(receipt, allSpecChainIds, chainSpecs, oracleObservedByChain)
    if (resolvedAny && receipt.findingId) {
      const set = resolvedChainsByFindingId.get(receipt.findingId) ?? new Set<string>()
      set.add(resolvedAny)
      resolvedChainsByFindingId.set(receipt.findingId, set)
      if (receipt.confirmed && receipt.attackerProvenanceValid && receipt.replayMode === 'fresh_clean_replay') {
        const cset = confirmedReceiptChainsByFindingId.get(receipt.findingId) ?? new Set<string>()
        cset.add(resolvedAny)
        confirmedReceiptChainsByFindingId.set(receipt.findingId, cset)
      }
    }
    if (!resolvedExpected) continue
    resolvedChainByReceipt.set(receipt, resolvedExpected)
    const existing = receiptByChain.get(resolvedExpected)
    const incomingSuperseded = !isHardenedOrTwinRun && Boolean(receipt.findingId && rawSupersededFindingIds.has(receipt.findingId))
    const existingSuperseded = !isHardenedOrTwinRun && Boolean(existing?.findingId && rawSupersededFindingIds.has(existing.findingId))
    if (
      !existing
      || (existingSuperseded && !incomingSuperseded)
      || (existingSuperseded === incomingSuperseded && receiptPriority(receipt) > receiptPriority(existing))
    ) {
      receiptByChain.set(resolvedExpected, receipt)
    }
  }

  const confirmedFindingIds = new Set<string>()
  const confirmedChainByFindingId = new Map<string, string>()
  const chains: ProductChainVerdict[] = gt.expectedChains.map((expected) => {
    const evaluation = evalByChain.get(expected.chainId)
    const chainEvents = oracleEventsByChain.get(expected.chainId) ?? []
    const observedHopIds = new Set(
      chainEvents.filter((e) => e.eventKind === 'hop' && e.hopId).map((e) => e.hopId!),
    )
    const maxHopReached = evaluation ? evaluation.hopsObserved : observedHopIds.size
    const forbiddenShortcutViolation = evaluation?.dropReason === 'persona_shortcut_rejected'
    const oracleObserved = oracleObservedByChain.get(expected.chainId) ?? false

    const matchedReceipt = receiptByChain.get(expected.chainId)
    const replayMode = matchedReceipt?.replayMode ?? 'fresh_clean_replay'
    const compositeReceiptConfirmed = Boolean(
      matchedReceipt
      && matchedReceipt.confirmed
      && matchedReceipt.attackerProvenanceValid
      && matchedReceipt.replayMode === 'fresh_clean_replay',
    )
    const twoSideConfirmed = oracleObserved && compositeReceiptConfirmed && !forbiddenShortcutViolation

    const matchedFindingIds: string[] = []
    if (matchedReceipt?.findingId) {
      matchedFindingIds.push(matchedReceipt.findingId)
      if (twoSideConfirmed) {
        confirmedFindingIds.add(matchedReceipt.findingId)
        confirmedChainByFindingId.set(matchedReceipt.findingId, expected.chainId)
      }
    }

    let dropReason: ProductDropReason | null = null
    if (!twoSideConfirmed) {
      if (forbiddenShortcutViolation) dropReason = 'persona_shortcut_rejected'
      else if (matchedReceipt && matchedReceipt.replayMode === 'one_shot_transcript') dropReason = 'replay_failed'
      else if (oracleObserved && !compositeReceiptConfirmed) dropReason = 'edge_binding_rejected'
      else {
        dropReason = mapProductDropReason(evaluation?.dropReason)
          ?? (maxHopReached === 0 ? 'capability_not_extracted' : 'pivot_not_discovered')
      }
    }

    const failureReason: string | null = twoSideConfirmed
      ? null
      : (typeof evaluation?.failureReason === 'string' && evaluation.failureReason.trim()
          ? evaluation.failureReason
          : null)
    const missingHopIds: string[] = Array.isArray(evaluation?.missingHopIds)
      ? [...evaluation.missingHopIds]
      : expected.hopIds.filter((hopId) => !observedHopIds.has(hopId))

    return {
      chainId: expected.chainId,
      expectedHops: evaluation?.hopsTotal ?? expected.hopIds.length,
      maxHopReached,
      oracleObserved,
      forbiddenShortcutViolation,
      compositeReceiptConfirmed,
      twoSideConfirmed,
      replayMode,
      dropReason,
      failureReason,
      missingHopIds,
      matchedFindingIds,
      oracleEventSeqs: chainEvents.map((e) => e.seq),
      terminalVulnClass: expected.vulnClass,
    }
  })

  // Filter findings marked `supersededByFindingId` ONLY in vulnerable mode (NEVER in hardened/twin mode),
  // and ONLY when:
  //  - the superseding winner is present with explicit `status === 'confirmed'`,
  //  - the winner is an actual two-side confirmed non-decoy TP (`confirmedFindingIds`), AND
  //  - the superseded loser is genuinely related to the winner (shares winner's resolved chainId OR
  //    matches winner's terminal/chain endpoint templates).
  const ignoredSupersededIds = new Set<string>()
  let findings = rawFindings
  let receipts = rawReceipts
  if (!isHardenedOrTwinRun) {
    const explicitConfirmedWinnerById = new Map<string, ProductSubmittedFinding>()
    for (const f of rawFindings) {
      if (f.supersededByFindingId || f.twinId) continue
      if (f.status !== 'confirmed') continue
      const fIds = [f.findingId, f.id].filter((x): x is string => Boolean(x))
      if (!fIds.some((fid) => confirmedFindingIds.has(fid))) continue
      for (const fid of fIds) explicitConfirmedWinnerById.set(fid, f)
    }

    const loserRelatedToWinner = (loser: ProductSubmittedFinding, winner: ProductSubmittedFinding, supId: string): boolean => {
      const winnerChainId = confirmedChainByFindingId.get(supId)
        ?? (winner.findingId ? confirmedChainByFindingId.get(winner.findingId) : undefined)
        ?? (winner.id ? confirmedChainByFindingId.get(winner.id) : undefined)
      const loserIds = [loser.findingId, loser.id].filter((x): x is string => Boolean(x))
      if (winnerChainId && loserIds.some((lid) => resolvedChainsByFindingId.get(lid)?.has(winnerChainId))) {
        return true
      }
      const loserEps = findingEndpoints(loser)
        .map((ep) => parseEndpointCandidate(ep.path, ep.method))
        .filter((p): p is ParsedEndpointCandidate => Boolean(p))
      if (!loserEps.length) return false
      const winnerSpec = winnerChainId ? chainSpecById.get(winnerChainId) : undefined
      if (winnerSpec) {
        const specTemplates = [...winnerSpec.terminalEndpoints, ...winnerSpec.upstreamHopEndpoints]
        if (loserEps.some((lep) => specTemplates.some((tmpl) => endpointMatchesTemplate(lep, tmpl)))) {
          return true
        }
      }
      const winnerEps = findingEndpoints(winner)
        .map((ep) => parseEndpointCandidate(ep.path, ep.method))
        .filter((p): p is ParsedEndpointCandidate => Boolean(p))
      return loserEps.some((lep) => winnerEps.some((wep) =>
        (!lep.method || !wep.method || lep.method === wep.method)
        && pathMatchesTemplate(lep.path, wep.path),
      ))
    }

    findings = rawFindings.filter((f) => {
      const supId = typeof f.supersededByFindingId === 'string' ? f.supersededByFindingId.trim() : ''
      if (!supId) return true
      const ownIds = [f.findingId, f.id].filter((x): x is string => Boolean(x))
      if (ownIds.includes(supId)) return true
      const winner = explicitConfirmedWinnerById.get(supId)
      if (!winner || !loserRelatedToWinner(f, winner, supId)) return true
      for (const oid of ownIds) ignoredSupersededIds.add(oid)
      return false
    })
    receipts = rawReceipts.filter((r) => !(r.findingId && ignoredSupersededIds.has(r.findingId)))
  }

  const confirmedChainIds = new Set(chains.filter((c) => c.twoSideConfirmed).map((c) => c.chainId))
  const shortcutViolationChainIds = new Set(
    chains.filter((c) => c.forbiddenShortcutViolation).map((c) => c.chainId),
  )
  const shortcutFindingIds = new Set<string>()
  const shortcutReceiptFallbackIds = new Set<string>()
  if (gt.labMode === 'vulnerable' && shortcutViolationChainIds.size > 0) {
    for (const chain of chains) {
      if (!chain.forbiddenShortcutViolation) continue
      for (const fid of chain.matchedFindingIds) shortcutFindingIds.add(fid)
    }
    for (const receipt of receipts) {
      const resolvedChain = resolvedChainByReceipt.get(receipt)
      const matchedChainId = (receipt.chainId && shortcutViolationChainIds.has(receipt.chainId))
        ? receipt.chainId
        : (resolvedChain && shortcutViolationChainIds.has(resolvedChain) ? resolvedChain : null)
      if (!matchedChainId) continue
      if (receipt.findingId) shortcutFindingIds.add(receipt.findingId)
      else shortcutReceiptFallbackIds.add(`receipt:${receipt.chainId}`)
    }
  }

  const confirmedModeAReceiptsByFindingId = new Map<string, ProductSubmittedCompositeProof[]>()
  for (const receipt of receipts) {
    if (
      receipt.findingId
      && receipt.confirmed
      && receipt.attackerProvenanceValid
      && receipt.replayMode === 'fresh_clean_replay'
    ) {
      const list = confirmedModeAReceiptsByFindingId.get(receipt.findingId) ?? []
      list.push(receipt)
      confirmedModeAReceiptsByFindingId.set(receipt.findingId, list)
    }
  }

  const resolvedTwins = resolveProductTwins(gt)
  const twinClaimFindingIds = new Set<string>()
  const hardenedTwins: ProductTwinVerdict[] = resolvedTwins.map((decoy) => {
    const matchedIds: string[] = []
    const isTwinMode = gt.labMode === 'hardened' || gt.twinId === decoy.twinId
    const baseChainConfirmed = confirmedChainIds.has(decoy.baseChainId)
    const isVulnerableShortcutBase =
      gt.labMode === 'vulnerable' && !isTwinMode && shortcutViolationChainIds.has(decoy.baseChainId)
    const baseChainSpec = chainSpecById.get(decoy.baseChainId)

    for (const receipt of receipts) {
      const receiptId = receipt.findingId ?? `receipt:${receipt.chainId}`
      if (receipt.findingId && confirmedFindingIds.has(receipt.findingId) && !isTwinMode) continue
      const resolvedChainForReceipt = resolvedChainByReceipt.get(receipt)
        ?? resolveReceiptChainId(receipt, allSpecChainIds, chainSpecs, oracleObservedByChain)
      const matchedBaseChain = resolvedChainForReceipt === decoy.baseChainId
      if (isVulnerableShortcutBase && (receipt.chainId === decoy.baseChainId || matchedBaseChain)) {
        // Vulnerable-mode shortcut on the base chain is a strict precision/shortcut FP, not a hardened twin hit.
        continue
      }
      // In vulnerable mode, hardened twin profiles are NOT active; only attribute a receipt to a twin
      // when the twin profile is actually running (`isTwinMode`) or the receipt explicitly claims `decoy.twinId`.
      // Unconfirmed base-chain receipts in vulnerable mode stay strict unmatched FPs (precision penalty preserved).
      const receiptMatchesTwin = receipt.chainId === decoy.twinId
        || ((receipt.chainId === decoy.baseChainId || matchedBaseChain) && isTwinMode)
      if (receiptMatchesTwin) {
        if (!matchedIds.includes(receiptId)) matchedIds.push(receiptId)
        twinClaimFindingIds.add(receiptId)
        if (receipt.findingId) twinClaimFindingIds.add(receipt.findingId)
      }
    }

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i]!
      const id = f.findingId ?? f.id ?? `finding:${i}`
      if (!isTwinMode && confirmedFindingIds.has(id)) continue
      if (matchedIds.includes(id)) continue
      if (
        gt.labMode === 'vulnerable'
        && !isTwinMode
        && f.twinId !== decoy.twinId
        && f.chainId !== decoy.twinId
      ) {
        // Vulnerable mode (twin profile is NOT active): exempt ONLY findings backed by a verified
        // Mode-A composite receipt that genuinely proves either:
        //  (a) a duplicate of an already two-side confirmed base chain (`decoy.baseChainId`), OR
        //  (b) a post-enforcement vulnerable hop of `decoy.baseChainId` (strictly past `enforcedAtHopId`,
        //      unreachable when the hardened twin profile is running — e.g. NX-C1 h4 PATCH /scim/users/:id
        //      or PG-C3 h5 export download).
        // Self-declared / unverified findings and decoy-hop-only findings are NEVER exempted, and exempted
        // findings remain strict `unmatchedFalsePositives` so precision is never weakened.
        const receiptConfirmedBase = baseChainConfirmed && Boolean(
          confirmedReceiptChainsByFindingId.get(id)?.has(decoy.baseChainId)
          || (f.id && confirmedReceiptChainsByFindingId.get(f.id)?.has(decoy.baseChainId))
          || (f.findingId && confirmedReceiptChainsByFindingId.get(f.findingId)?.has(decoy.baseChainId)),
        )
        const findingModeAReceipts = [
          ...(confirmedModeAReceiptsByFindingId.get(id) ?? []),
          ...(f.id && f.id !== id ? (confirmedModeAReceiptsByFindingId.get(f.id) ?? []) : []),
          ...(f.findingId && f.findingId !== id && f.findingId !== f.id
            ? (confirmedModeAReceiptsByFindingId.get(f.findingId) ?? [])
            : []),
        ]
        const receiptProvesPostEnforcementBaseHop = findingModeAReceipts.some(
          (r) => receiptReachesPostEnforcement(r, decoy),
        )
        if (receiptConfirmedBase || receiptProvesPostEnforcementBaseHop) {
          const eps = findingEndpoints(f)
          const baseSpecTemplates = baseChainSpec
            ? [...baseChainSpec.terminalEndpoints, ...baseChainSpec.upstreamHopEndpoints]
            : []
          const hitsDecoyOutsideBase = decoy.endpoints.some((twinEp) => {
            const twinParsed = parseEndpointCandidate(twinEp.path, twinEp.method)
            const inBaseSpec = Boolean(
              twinParsed && baseSpecTemplates.some((tmpl) => endpointMatchesTemplate(twinParsed, tmpl)),
            )
            if (inBaseSpec) return false
            return eps.some((ep) => {
              const epMethod = ep.method?.trim().toUpperCase()
              if (epMethod && twinEp.method && epMethod !== twinEp.method.toUpperCase()) return false
              return pathMatchesTemplate(ep.path, twinEp.path)
            })
          })
          if (!hitsDecoyOutsideBase) {
            continue
          }
        }
      }
      if (isVulnerableShortcutBase) {
        const eps = findingEndpoints(f)
        const hitsBaseTerminal = Boolean(
          baseChainSpec
          && eps.some((ep) => {
            const parsed = parseEndpointCandidate(ep.path, ep.method)
            return parsed
              ? baseChainSpec.terminalEndpoints.some((tmpl) => endpointMatchesTemplate(parsed, tmpl))
              : false
          }),
        )
        if (
          shortcutFindingIds.has(id)
          || f.chainId === decoy.baseChainId
          || hitsBaseTerminal
          || eps.length === 0
        ) {
          continue
        }
      }
      if (findingMatchesTwin(f, decoy, { isTwinMode, baseChainConfirmed })) {
        matchedIds.push(id)
        twinClaimFindingIds.add(id)
      }
    }

    return {
      twinId: decoy.twinId,
      baseChainId: decoy.baseChainId,
      ...(decoy.vulnClass ? { vulnClass: decoy.vulnClass } : {}),
      falsePositive: matchedIds.length > 0,
      matchedFindingIds: matchedIds,
      ...(matchedIds.length > 0 ? { reason: decoy.note } : {}),
    }
  })

  let hardenedTwinDecoyFps = Math.max(
    twinClaimFindingIds.size,
    hardenedTwins.filter((t) => t.falsePositive).length,
  )
  let unmatchedFalsePositives = 0
  const countedFindingIds = new Set<string>()
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]!
    const id = f.findingId ?? f.id ?? `finding:${i}`
    countedFindingIds.add(id)
    if (f.id) countedFindingIds.add(f.id)
    if (f.findingId) countedFindingIds.add(f.findingId)
    if (gt.labMode === 'hardened') {
      if (!twinClaimFindingIds.has(id)) hardenedTwinDecoyFps += 1
      continue
    }
    if (confirmedFindingIds.has(id) || twinClaimFindingIds.has(id)) continue
    unmatchedFalsePositives += 1
  }
  if (gt.labMode === 'vulnerable') {
    for (const id of shortcutFindingIds) {
      if (!countedFindingIds.has(id) && !confirmedFindingIds.has(id) && !twinClaimFindingIds.has(id)) {
        countedFindingIds.add(id)
        unmatchedFalsePositives += 1
      }
    }
    for (const id of shortcutReceiptFallbackIds) {
      if (!countedFindingIds.has(id) && !twinClaimFindingIds.has(id)) {
        countedFindingIds.add(id)
        unmatchedFalsePositives += 1
      }
    }
    for (const receipt of receipts) {
      if (!receipt.confirmed) continue
      const id = receipt.findingId ?? `receipt:${receipt.chainId}`
      if (countedFindingIds.has(id) || confirmedFindingIds.has(id) || twinClaimFindingIds.has(id)) continue
      countedFindingIds.add(id)
      unmatchedFalsePositives += 1
    }
  }

  const dropReasons = emptyProductDropReasons()
  let H1 = 0
  let H2 = 0
  let H3 = 0
  let H4Plus = 0
  let FinalOracle = 0
  let CompositeReceiptConfirmed = 0
  for (const chain of chains) {
    if (chain.maxHopReached >= 1) H1 += 1
    if (chain.maxHopReached >= 2) H2 += 1
    if (chain.maxHopReached >= 3) H3 += 1
    if (chain.maxHopReached >= 4) H4Plus += 1
    if (chain.oracleObserved && !chain.forbiddenShortcutViolation) FinalOracle += 1
    if (chain.twoSideConfirmed) CompositeReceiptConfirmed += 1
    else if (chain.dropReason) dropReasons[chain.dropReason] += 1
  }

  const chainsTotal = chains.length
  const chainsOracleObserved = FinalOracle
  const chainsCompositeConfirmed = chains.filter((c) => c.compositeReceiptConfirmed).length
  const chainsConfirmed = CompositeReceiptConfirmed
  const totalFps = hardenedTwinDecoyFps + unmatchedFalsePositives
  const precision = chainsConfirmed + totalFps > 0 ? chainsConfirmed / (chainsConfirmed + totalFps) : 1
  const recall = chainsTotal > 0 ? chainsConfirmed / chainsTotal : 0
  const hardenedTwinsTotal = hardenedTwins.length

  return {
    app: String(gt.app),
    seed: gt.seed,
    seedSet: gt.seedSet,
    mode: input.mode ?? gt.labMode,
    chainsTotal,
    chainsOracleObserved,
    chainsCompositeConfirmed,
    chainsConfirmed,
    recall,
    precision,
    hardenedTwinsTotal,
    hardenedTwinDecoyFps,
    decoys: hardenedTwinsTotal,
    decoyFalsePositives: hardenedTwinDecoyFps,
    unmatchedFalsePositives,
    totalCostUsd: input.telemetry?.totalCostUsd ?? 0,
    hopFunnel: {
      totalChains: chainsTotal,
      H1,
      H2,
      H3,
      H4Plus,
      FinalOracle,
      CompositeReceiptConfirmed,
      dropReasons,
    },
    chains,
    hardenedTwins,
  }
}

export function gradeRun(input: GradeInput): Scorecard
export function gradeRun(input: ProductGradeInput): ProductScorecard
export function gradeRun(input: GradeInput | ProductGradeInput): Scorecard | ProductScorecard {
  if (isStandaloneGradeInput(input)) return libGradeRun(input)
  return gradeProductRun(input)
}

function isStandaloneScorecard(card: Scorecard | ProductScorecard | ProductScorecard[]): card is Scorecard {
  return !Array.isArray(card) && 'gate' in card && 'fpByCategory' in card
}

function renderProductScorecardMd(card: ProductScorecard): string {
  const pct = (value: number): string => `${(value * 100).toFixed(1)}%`
  const f = card.hopFunnel
  const lines = [
    `# multihop-saas scorecard — ${card.app}`,
    '',
    `- seed: ${card.seed} (${card.seedSet})`,
    `- mode: ${card.mode}`,
    `- two-side confirmed chains: ${card.chainsConfirmed}/${card.chainsTotal} (${pct(card.recall)})`,
    `- oracle observed / composite confirmed: ${card.chainsOracleObserved}/${card.chainsCompositeConfirmed}`,
    `- precision: ${pct(card.precision)}`,
    `- hardened-twin decoy FPs: ${card.hardenedTwinDecoyFps}/${card.hardenedTwinsTotal}`,
    `- unmatched FPs: ${card.unmatchedFalsePositives}`,
    `- cost: $${card.totalCostUsd.toFixed(4)}`,
    '',
    '## Hop-Depth Funnel',
    '',
    '| Total | H1 | H2 | H3 | H4+ | FinalOracle | CompositeReceiptConfirmed |',
    '|---:|---:|---:|---:|---:|---:|---:|',
    `| ${f.totalChains} | ${f.H1} | ${f.H2} | ${f.H3} | ${f.H4Plus} | ${f.FinalOracle} | ${f.CompositeReceiptConfirmed} |`,
    '',
    '## Chains',
    '',
    '| chain | hops | maxHop | oracle | receipt | confirmed | dropReason |',
    '|---|---:|---:|---|---|---|---|',
    ...card.chains.map((c) =>
      `| ${c.chainId} | ${c.expectedHops} | ${c.maxHopReached} | ${c.oracleObserved ? 'yes' : 'no'} | ${c.compositeReceiptConfirmed ? 'yes' : 'no'} | ${c.twoSideConfirmed ? 'yes' : 'no'} | ${c.dropReason ?? 'none'} |`),
    '',
    ...(card.hardenedTwins.length > 0
      ? [
          '## Hardened Twins',
          '',
          '| twin | baseChain | vulnClass | decoyFP | matchedFindings |',
          '|---|---|---|---|---|',
          ...card.hardenedTwins.map((t) =>
            `| ${t.twinId} | ${t.baseChainId ?? '-'} | ${t.vulnClass ?? '-'} | ${t.falsePositive ? 'YES (FP)' : 'no'} | ${t.matchedFindingIds.join(', ') || 'none'} |`),
          '',
        ]
      : []),
  ]
  return lines.join('\n')
}

export function renderScorecard(
  card: Scorecard | ProductScorecard | ProductScorecard[],
  format: 'json' | 'md',
): string {
  if (isStandaloneScorecard(card)) return libRenderScorecard(card, format)
  if (format === 'json') return `${JSON.stringify(card, null, 2)}\n`
  if (Array.isArray(card)) return card.map(renderProductScorecardMd).join('\n---\n\n')
  return renderProductScorecardMd(card)
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) continue
    const key = arg.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) out[key] = true
    else {
      out[key] = next
      i++
    }
  }
  return out
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(isAbsolute(path) ? path : resolve(process.cwd(), path), 'utf8')) as T
}

function asMode(value: unknown): LabMode {
  if (value === undefined) return 'vulnerable'
  if (value === 'vulnerable' || value === 'hardened') return value
  throw new Error(`--mode must be vulnerable or hardened, got '${String(value)}'`)
}

function asBriefingMode(value: unknown): BenchMode {
  if (value === undefined) return 'grey-box'
  if (value === 'black-box' || value === 'grey-box' || value === 'white-box') return value
  throw new Error(`--briefing must be black-box, grey-box or white-box`)
}

function outDirFor(a: Record<string, string | boolean>): string {
  return a['out-dir'] ? resolve(process.cwd(), String(a['out-dir'])) : join(HERE, 'out')
}

function writeArtifacts(
  lab: StartedPaygrid | StartedLabBase, findings: Finding[], card: Scorecard, briefingMode: BenchMode,
  outDir = outDirFor({}),
): string {
  mkdirSync(outDir, { recursive: true })
  const base = join(outDir, `${lab.app}-${lab.seed}-${lab.labMode}${lab.twinId ? `-${lab.twinId}` : ''}`)
  writeFileSync(`${base}.groundtruth.json`, `${JSON.stringify(lab.groundTruth, null, 2)}\n`)
  writeFileSync(`${base}.oracle.json`, `${JSON.stringify(lab.export(), null, 2)}\n`)
  writeFileSync(`${base}.findings.json`, `${JSON.stringify(findings, null, 2)}\n`)
  writeFileSync(`${base}.briefing.json`, `${JSON.stringify(lab.briefing(briefingMode), null, 2)}\n`)
  writeFileSync(`${base}.scorecard.json`, renderScorecard(card, 'json'))
  writeFileSync(`${base}.scorecard.md`, renderScorecard(card, 'md'))
  return base
}

async function cmdList(a: Record<string, string | boolean>): Promise<void> {
  const data = await loadCatalog()
  if (a.json) {
    process.stdout.write(`${JSON.stringify(data, null, 2)}\n`)
    return
  }
  for (const app of data.apps) {
    process.stdout.write(`${app.name}: ${app.services} services, ${app.chains.length} chains, ${app.twins.length} twins\n`)
    for (const chain of app.chains) {
      process.stdout.write(`  ${chain.id} (${chain.hops} hops) ${chain.vulnClass} -> ${chain.terminalKind}\n`)
    }
    for (const twin of app.twins) {
      process.stdout.write(`  ${twin.id} (base ${twin.baseChainId}, decoy hops ${twin.decoyHopIds.join(',')}, enforced ${twin.enforcedAtHopId})\n`)
    }
  }
}

function cmdSeeds(a: Record<string, string | boolean>): void {
  const set = (a.set ? String(a.set) : 'dev') as SeedSet
  if (set !== 'dev' && set !== 'held-out') throw new Error('--set must be dev or held-out')
  if (a.salt !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set KOVO_RB_HELDOUT_SALT instead')
  }
  const n = Number(a.n ?? 5)
  process.stdout.write(`${JSON.stringify(listSeeds(set, n))}\n`)
}

async function cmdServe(a: Record<string, string | boolean>): Promise<void> {
  assertLocalLabAllowed()
  if (a['held-out-salt'] !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set KOVO_RB_HELDOUT_SALT instead')
  }
  const app = a.app ? String(a.app) : 'paygrid'
  const mode = asMode(a.mode)
  const briefingMode = asBriefingMode(a.briefing)
  const mod = await loadAppModule(app)
  const lab = await mod.start({
    seed: Number(a.seed ?? 1),
    mode,
    twin: a.twin ? String(a.twin) : undefined,
    asyncLatencyMs: a['async-latency-ms'] !== undefined ? Number(a['async-latency-ms']) : undefined,
  })
  process.stdout.write(`${JSON.stringify(lab.briefing(briefingMode), null, 2)}\n`)

  if (a.once) {
    const findings = mod.runSolvers ? await mod.runSolvers(lab) : []
    const card = gradeLab(lab, findings)
    const base = writeArtifacts(lab, findings, card, briefingMode, outDirFor(a))
    process.stderr.write(`[multihop-saas] artifacts -> ${base}.{groundtruth,oracle,findings,scorecard}.*\n`)
    process.stdout.write(renderScorecard(card, 'json'))
    await lab.stop()
    if (!card.gate.pass) process.exit(2)
    return
  }

  process.stderr.write(
    `[multihop-saas] ${lab.app} seed=${lab.seed} (${lab.seedSet}) ${lab.labMode}` +
      `${lab.twinId ? ` twin=${lab.twinId}` : ''} entry=${lab.entryOrigin} — Ctrl-C to stop\n`,
  )
  const shutdown = async (): Promise<void> => {
    const findings = mod.runSolvers ? await mod.runSolvers(lab).catch(() => []) : []
    const card = gradeLab(lab, findings)
    const base = writeArtifacts(lab, findings, card, briefingMode, outDirFor(a))
    process.stderr.write(`[multihop-saas] artifacts -> ${base}.*\n`)
    await lab.stop()
    process.exit(0)
  }
  process.on('SIGINT', () => void shutdown())
  process.on('SIGTERM', () => void shutdown())
}

function gradeInputFromArgs(a: Record<string, string | boolean>): GradeInput {
  return {
    groundTruth: readJson(String(a.truth)),
    findings: readJson(String(a.findings)),
    oracle: readJson(String(a.oracle)),
  }
}

function cmdGrade(a: Record<string, string | boolean>): void {
  if (!a.truth || !a.findings || !a.oracle) {
    throw new Error('grade requires --truth <file> --findings <file> --oracle <file>')
  }
  const card = gradeRun(gradeInputFromArgs(a))
  if (a.json) writeFileSync(resolve(process.cwd(), String(a.json)), renderScorecard(card, 'json'))
  if (a.md) writeFileSync(resolve(process.cwd(), String(a.md)), renderScorecard(card, 'md'))
  process.stdout.write(renderScorecard(card, a.md || a.json ? 'json' : 'md'))
}

async function cmdSelftest(a: Record<string, string | boolean>): Promise<void> {
  assertLocalLabAllowed()
  if (a['held-out-salt'] !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set KOVO_RB_HELDOUT_SALT instead')
  }
  const seeds = String(a.seeds ?? '1,2,3').split(',').map((value) => Number(value.trim()))
    .filter((value) => Number.isFinite(value))
  if (seeds.length === 0) throw new Error('--seeds must list at least one seed')
  const latency = a['async-latency-ms'] !== undefined ? Number(a['async-latency-ms']) : 10
  const requestedApp = a.app ? String(a.app) : 'all'
  const apps = requestedApp === 'all'
    ? discoverApps()
    : requestedApp.split(',').map((s) => s.trim()).filter(Boolean)
  if (apps.length === 0) throw new Error('no multihop-saas apps discovered')

  const rows: SelftestRow[] = []

  for (const appName of apps) {
    const mod = await loadAppModule(appName)
    const expectedCount = mod.chains.length
    for (const seed of seeds) {
      const lab = await mod.start({ seed, mode: 'vulnerable', asyncLatencyMs: latency })
      try {
        const findings = mod.runSolvers ? await mod.runSolvers(lab) : []
        const card = gradeLab(lab, findings)
        const ok = findings.length === expectedCount && card.gate.pass && card.tp === expectedCount
          && card.precision === 1 && card.recall === 1
        rows.push({
          scope: `${appName}:vulnerable`,
          seed,
          ok,
          detail: `findings=${findings.length}/${expectedCount} tp=${card.tp} precision=${card.precision}`,
        })
      } finally {
        await lab.stop()
      }

      const hardened = await mod.start({ seed, mode: 'hardened', asyncLatencyMs: latency })
      try {
        const findings = mod.runSolvers ? await mod.runSolvers(hardened) : []
        const events = hardened.export().events
        const total = events.hops.length + events.edges.length + events.controls.length + events.terminals.length
        rows.push({
          scope: `${appName}:hardened`,
          seed,
          ok: findings.length === 0 && total === 0,
          detail: `findings=${findings.length} events=${total}`,
        })
      } finally {
        await hardened.stop()
      }

      for (const twin of mod.twins) {
        const labTwin = await mod.start({ seed, mode: 'vulnerable', twin: twin.id, asyncLatencyMs: latency })
        try {
          const findings = mod.runSolvers ? await mod.runSolvers(labTwin, [twin.baseChainId]) : []
          const evaluation = labTwin.oracle.evaluate(twin.baseChainId)
          const terminals = labTwin.export().events.terminals.length
          rows.push({
            scope: `${appName}:${twin.id}`,
            seed,
            ok: findings.length === 0 && terminals === 0 && evaluation.hopsObserved >= 2 && !evaluation.confirmed,
            detail: `hops=${evaluation.hopsObserved} terminals=${terminals} findings=${findings.length} drop=${evaluation.dropReason ?? 'none'}`,
          })
        } finally {
          await labTwin.stop()
        }
      }
    }
  }

  const failures = rows.filter((row) => !row.ok)
  const result: SelftestResult = {
    summary: `${rows.length - failures.length}/${rows.length} selftest checks pass`,
    rows,
  }
  for (const row of rows) {
    process.stdout.write(`${row.ok ? 'PASS' : 'FAIL'} ${row.scope} seed=${row.seed} ${row.detail}\n`)
  }
  process.stdout.write(`${result.summary}\n`)
  if (failures.length > 0) process.exit(2)
}

function cmdAntiHeuristicCheck(a: Record<string, string | boolean>): void {
  const maxRecall = a['max-recall'] !== undefined ? Number(a['max-recall']) : ANTI_HEURISTIC_FLOOR_MAX
  let card: Scorecard
  if (a.scorecard) {
    card = readJson<Scorecard>(String(a.scorecard))
  } else {
    card = gradeRun(gradeInputFromArgs(a))
  }
  const pass = card.recall <= maxRecall
  process.stdout.write(`${JSON.stringify({
    app: card.app, seed: card.seed, seedSet: card.seedSet, mode: card.mode, twin: card.twin,
    heuristicFloor: card.recall, maxRecall, pass,
  }, null, 2)}\n`)
  if (!pass) process.exit(2)
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2)
  const a = parseArgs(rest)
  switch (command) {
    case 'list':
      return cmdList(a)
    case 'seeds':
      return cmdSeeds(a)
    case 'serve':
      return cmdServe(a)
    case 'grade':
      return cmdGrade(a)
    case 'selftest':
      return cmdSelftest(a)
    case 'anti-heuristic-check':
      return cmdAntiHeuristicCheck(a)
    default:
      process.stderr.write(
        'usage: run.ts <list|seeds|serve|grade|selftest|anti-heuristic-check> [--flags]\n',
      )
      process.exit(1)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err) => {
    process.stderr.write(`error: ${(err as Error).message}\n`)
    process.exit(1)
  })
}

export type { AppName }
