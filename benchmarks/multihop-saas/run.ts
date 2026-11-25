// multihop-saas entrypoint: programmatic API + CLI + Guardian v8 product-runner bridge.
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

    return {
      name: app,
      services: info.services,
      chains,
      twins,
      start,
      runSolvers,
    }
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
// Guardian v8 product-runner bridge (`scripts/benchmark-multihop.ts`)
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
  role: string
  rolesByTenant: Record<string, string>
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
  findingId?: string
  chainId?: string
  terminalVulnClass?: string
  vulnClass?: string
  hopIds?: string[]
  method?: string
  path?: string
  param?: string
  severity?: string
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
  matchedFindingIds: string[]
  oracleEventSeqs: number[]
  terminalVulnClass: string
}

export interface ProductTwinVerdict {
  twinId: string
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

const groundTruthOracleMap = new WeakMap<object, () => OracleExport>()
const startedDefaultBriefingMode = new WeakMap<object, BenchMode>()

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

  groundTruthOracleMap.set(lab.groundTruth, () => lab.export())

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
    groundTruth: lab.groundTruth,
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
        groundTruth: lab.groundTruth,
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

  const personas: MultihopProductPersona[] = raw.personas.map((persona) => {
    const rolesByTenant: Record<string, string> = {}
    for (const [tenant, role] of Object.entries(persona.rolesByTenant)) {
      if (role) rolesByTenant[tenant] = role
    }
    const primaryRole = rolesByTenant[persona.tenant] ?? Object.values(rolesByTenant)[0] ?? 'member'
    return {
      id: persona.id,
      email: persona.email,
      password: persona.password,
      tenant: persona.tenant,
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
  const resolvedSalt = salt ?? process.env.GUARDIAN_RB_HELDOUT_SALT
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

function gradeProductRun(input: ProductGradeInput): ProductScorecard {
  const gt = input.groundTruth
  const oracleExport = input.oracleExport ?? groundTruthOracleMap.get(gt)?.()
  const evalByChain = new Map((oracleExport?.evaluations ?? []).map((ev) => [ev.chainId, ev]))
  const receipts = input.compositeReceipts ?? []
  const findings = input.findings ?? []

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

  const receiptByChain = new Map<string, ProductSubmittedCompositeProof>()
  for (const receipt of receipts) {
    if (receipt.chainId && !receiptByChain.has(receipt.chainId)) {
      receiptByChain.set(receipt.chainId, receipt)
    }
  }

  const confirmedFindingIds = new Set<string>()
  const chains: ProductChainVerdict[] = gt.expectedChains.map((expected) => {
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
      if (twoSideConfirmed) confirmedFindingIds.add(matchedReceipt.findingId)
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
      matchedFindingIds,
      oracleEventSeqs: chainEvents.map((e) => e.seq),
      terminalVulnClass: expected.vulnClass,
    }
  })

  const twinClaimFindingIds = new Set<string>()
  const hardenedTwins: ProductTwinVerdict[] = gt.twinDecoys.map((decoy) => {
    const matchedIds: string[] = []
    for (const receipt of receipts) {
      if (receipt.chainId === decoy.chainId) {
        const id = receipt.findingId ?? `receipt:${receipt.chainId}`
        matchedIds.push(id)
        if (receipt.findingId) twinClaimFindingIds.add(receipt.findingId)
      }
    }
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i]!
      const id = f.findingId ?? `finding:${i}`
      if (matchedIds.includes(id)) continue
      const touchesDecoy = f.chainId === decoy.chainId
        || (f.hopIds ?? []).some((hopId) => decoy.benignHopIds.includes(hopId))
      if (touchesDecoy) {
        matchedIds.push(id)
        twinClaimFindingIds.add(id)
      }
    }
    return {
      twinId: gt.twinId ?? decoy.chainId,
      falsePositive: matchedIds.length > 0,
      matchedFindingIds: matchedIds,
      ...(matchedIds.length > 0 ? { reason: decoy.note } : {}),
    }
  })

  let hardenedTwinDecoyFps = hardenedTwins.filter((t) => t.falsePositive).length
  let unmatchedFalsePositives = 0
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i]!
    const id = f.findingId ?? `finding:${i}`
    if (gt.labMode === 'hardened') {
      hardenedTwinDecoyFps += 1
      continue
    }
    if (confirmedFindingIds.has(id) || twinClaimFindingIds.has(id)) continue
    unmatchedFalsePositives += 1
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
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
  }
  const n = Number(a.n ?? 5)
  process.stdout.write(`${JSON.stringify(listSeeds(set, n))}\n`)
}

async function cmdServe(a: Record<string, string | boolean>): Promise<void> {
  assertLocalLabAllowed()
  if (a['held-out-salt'] !== undefined) {
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
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
    throw new Error('never pass the held-out salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead')
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
