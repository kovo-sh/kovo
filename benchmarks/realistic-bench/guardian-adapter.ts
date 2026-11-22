// Integration layer between realistic-bench (pane 3) and Guardian's live engines.
//
// realistic-bench owns materialization, the impact oracle and grading. Guardian owns discovery,
// hypothesis probing and Zero-LLM replay verification. This adapter joins them without either
// side reading the other's answer key:
//   * input:  a materialized app tree + its live origin (per-seed variant.json routes only)
//   * output: findings in grader/schema.ts' SubmittedFinding shape + run telemetry
//
// Truth discipline: the app's groundTruth (and plan.sites) is never touched. The started-app
// type below deliberately omits them, so truth is not even reachable from this module. Routes,
// params, personas and the login flow all come from variant.json / the briefing.
//
// Guardian's engine is loaded from ../../scripts/*.ts through non-literal dynamic imports: the
// benchmark tsconfig stays self-contained (no tsc coupling to scripts/ + src/), while runtime
// still executes the real engine modules.
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type {
  AppName, BenchMode, Briefing, RunTelemetry, Severity, SubmittedFinding, VulnClass,
} from './lib/types.ts'
import { appNames } from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { briefingFor, startRealisticApp } from './run.ts'
import { loginPersonas, pickLoginPath, type LoginPersona, type PersonaAuth } from './guardian-login.ts'

export type ProfileMode = 'v3-baseline' | 'v4-full'
export type VerifierChoice = 'auto' | 'docker' | 'local-jq'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEFAULT_REPO_ROOT = resolve(HERE, '../..')

// ---------------------------------------------------------------------------------------------
// Materialized surface (variant.json: routes/params only, no site modes, no truth)
// ---------------------------------------------------------------------------------------------
export interface SurfaceRoute { routeKey: string; method: string; path: string; params: string[] }
export interface MaterializedSurface {
  app: string
  apiPrefix: string
  idFormat: string
  routes: SurfaceRoute[]
  params: Record<string, string>
}

const PATH_PARAM = /:([a-zA-Z0-9_]+)/g

function pathParams(path: string): string[] {
  return (path.match(PATH_PARAM) ?? []).map(s => s.slice(1))
}

export function readMaterializedSurface(treeDir: string): MaterializedSurface {
  const dir = resolve(treeDir)
  const variantPath = resolve(dir, 'variant.json')
  if (!existsSync(variantPath)) {
    throw new Error(`materialized tree has no variant.json at ${variantPath} (run.ts materialization incomplete?)`)
  }
  const raw = JSON.parse(readFileSync(variantPath, 'utf8')) as Record<string, unknown>
  const routesRaw = raw.routes
  if (!routesRaw || typeof routesRaw !== 'object') throw new Error(`${variantPath}: routes must be an object`)
  const routes: SurfaceRoute[] = []
  for (const [routeKey, value] of Object.entries(routesRaw as Record<string, unknown>)) {
    const rec = value as Record<string, unknown> | null
    if (!rec || typeof rec.method !== 'string' || typeof rec.path !== 'string') {
      throw new Error(`${variantPath}: route ${routeKey} must be { method, path }`)
    }
    routes.push({ routeKey, method: rec.method.toUpperCase(), path: rec.path, params: pathParams(rec.path) })
  }
  if (routes.length === 0) throw new Error(`${variantPath}: no routes (materialization incomplete)`)
  const params = (raw.params && typeof raw.params === 'object' ? raw.params : {}) as Record<string, string>
  return {
    app: typeof raw.app === 'string' ? raw.app : '',
    apiPrefix: typeof raw.apiPrefix === 'string' ? raw.apiPrefix : '',
    idFormat: typeof raw.idFormat === 'string' ? raw.idFormat : '',
    routes,
    params,
  }
}

// ---------------------------------------------------------------------------------------------
// Started-app view: intentionally no groundTruth / plan.sites
// ---------------------------------------------------------------------------------------------
export interface MaterializedPersona { id: string; email: string; password: string; tenant: string; role: string }

export interface MaterializedAppLike {
  app: string
  origin: string
  sourceDir: string
  plan: {
    seed: number
    routes: Record<string, { method: string; path: string }>
    params: Record<string, string>
    personas: Record<string, MaterializedPersona>
  }
  stop(): Promise<void>
}

export interface BriefingLike {
  origin: string
  mode: BenchMode
  personas: Array<LoginPersona & { tenant?: string }>
  apiReference?: Array<{ routeKey: string; method: string; path: string; params: string[] }>
  sourceDir?: string
}

// ---------------------------------------------------------------------------------------------
// Guardian engine surface (loaded dynamically; structural so tsc never follows scripts/)
// ---------------------------------------------------------------------------------------------
export interface DiscoveredParamLike { name: string; location: string; isObjectId: boolean; isCsrf: boolean }
export interface DiscoveredEndpointLike { method: string; path: string; params: DiscoveredParamLike[]; source: string }
export interface HypothesisLike {
  key: string
  endpoint: DiscoveredEndpointLike
  probeClass: string
  param?: DiscoveredParamLike
  location?: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
}
export interface HypothesisOutcomeLike {
  hyp: HypothesisLike
  verdict: 'signal' | 'no_signal' | 'inconclusive' | 'error'
  anomalies: Array<Record<string, unknown>>
  csrfRejected: boolean
  contextReset: boolean
  tierBlocked: boolean
}
export interface SynthesizedSpecLike { kind: string; spec: Record<string, unknown> }
export interface ProfileCapsLike { mode: string; tier: number; inlineRetries: number }
export interface EngineEnvLike {
  probeEnv: Record<string, unknown>
  controller?: { signal: AbortSignal }
  requestsUsed?: () => number
  cleanup: () => Promise<void>
}
export interface EngineHandleLike {
  origin: string
  port: number
  personas: Record<string, PersonaAuth & { userId?: string }>
  close: () => Promise<void>
  resetState?: () => void
}
export type ExchangeHook = (exchange: unknown) => void

export interface EngineModuleLike {
  profileCaps(mode: ProfileMode): ProfileCapsLike
  createEngineEnv(handle: EngineHandleLike, caps: ProfileCapsLike, label: string): Promise<EngineEnvLike>
  discoverEndpoints(env: EngineEnvLike, caps: ProfileCapsLike, onExchange: ExchangeHook): Promise<DiscoveredEndpointLike[]>
  formHypotheses(endpoints: DiscoveredEndpointLike[], caps: ProfileCapsLike): { hypotheses: HypothesisLike[]; encodingSkips: unknown[] }
  runHypothesis(hyp: HypothesisLike, probeEnv: Record<string, unknown>, onExchange: ExchangeHook): Promise<HypothesisOutcomeLike>
  synthesizeSpec(outcome: HypothesisOutcomeLike, probeEnv: Record<string, unknown>): SynthesizedSpecLike | null
  synthesizeSpecs?(outcome: HypothesisOutcomeLike, probeEnv: Record<string, unknown>): SynthesizedSpecLike[]
  selectVerifierBackend(choice: VerifierChoice): Promise<{ kind: string; backend: unknown }>
  verifyReplaySpec(params: Record<string, unknown>): Promise<{ verdict: string }>
  verifyReplaySpecInline?(params: Record<string, unknown>): Promise<{ replay: { verdict: string }; feedback?: { jqError?: boolean } }>
  runLivePipeline?(params: Record<string, unknown>): Promise<{ traces: unknown[]; totalCostUsd: number; verifierBackend: string | null; notes: string[] }>
}

async function importRepoModule(repoRootDir: string, rel: string): Promise<Record<string, unknown>> {
  const file = resolve(repoRootDir, rel)
  if (!existsSync(file)) throw new Error(`Guardian engine module missing: ${file}`)
  // Non-literal specifier: deliberately opaque to tsc so this tsconfig stays standalone.
  return await import(pathToFileURL(file).href) as Record<string, unknown>
}

export async function loadGuardianEngine(repoRootDir = DEFAULT_REPO_ROOT): Promise<EngineModuleLike> {
  const [envMod, probeMod, specMod, backendMod, verifierMod, liveMod] = await Promise.all([
    importRepoModule(repoRootDir, 'scripts/benchmark-env.ts'),
    importRepoModule(repoRootDir, 'scripts/benchmark-probes.ts'),
    importRepoModule(repoRootDir, 'scripts/benchmark-specs.ts'),
    importRepoModule(repoRootDir, 'scripts/benchmark-backend.ts'),
    importRepoModule(repoRootDir, 'src/server/replay-verifier.ts'),
    importRepoModule(repoRootDir, 'scripts/benchmark-live.ts'),
  ])
  const need = (mod: Record<string, unknown>, name: string, where: string): unknown => {
    const fn = mod[name]
    if (!fn) throw new Error(`${where} does not export ${name} (Guardian engine API drift)`)
    return fn
  }
  return {
    profileCaps: need(probeMod, 'profileCaps', 'scripts/benchmark-probes.ts') as EngineModuleLike['profileCaps'],
    createEngineEnv: need(envMod, 'createEngineEnv', 'scripts/benchmark-env.ts') as EngineModuleLike['createEngineEnv'],
    discoverEndpoints: need(envMod, 'discoverEndpoints', 'scripts/benchmark-env.ts') as EngineModuleLike['discoverEndpoints'],
    formHypotheses: need(probeMod, 'formHypotheses', 'scripts/benchmark-probes.ts') as EngineModuleLike['formHypotheses'],
    runHypothesis: need(probeMod, 'runHypothesis', 'scripts/benchmark-probes.ts') as EngineModuleLike['runHypothesis'],
    synthesizeSpec: need(specMod, 'synthesizeSpec', 'scripts/benchmark-specs.ts') as EngineModuleLike['synthesizeSpec'],
    ...(specMod.synthesizeSpecs ? { synthesizeSpecs: specMod.synthesizeSpecs as EngineModuleLike['synthesizeSpecs'] } : {}),
    selectVerifierBackend: need(backendMod, 'selectVerifierBackend', 'scripts/benchmark-backend.ts') as EngineModuleLike['selectVerifierBackend'],
    verifyReplaySpec: need(verifierMod, 'verifyReplaySpec', 'src/server/replay-verifier.ts') as EngineModuleLike['verifyReplaySpec'],
    ...(verifierMod.verifyReplaySpecInline ? { verifyReplaySpecInline: verifierMod.verifyReplaySpecInline as EngineModuleLike['verifyReplaySpecInline'] } : {}),
    ...(liveMod.runLivePipeline ? { runLivePipeline: liveMod.runLivePipeline as EngineModuleLike['runLivePipeline'] } : {}),
  }
}

// ---------------------------------------------------------------------------------------------
// Adapter options / result
// ---------------------------------------------------------------------------------------------
export interface GuardianAdapterDeps {
  startApp?: (opts: { app: AppName; seed: number; heldOutSalt?: string; oobCallbackPorts?: number[] }) => Promise<MaterializedAppLike>
  briefing?: (app: MaterializedAppLike, mode: BenchMode) => BriefingLike
  loadEngine?: (repoRootDir: string) => Promise<EngineModuleLike>
  fetchImpl?: typeof fetch
  now?: () => number
}

export interface RunGuardianOptions {
  treeDir: string
  seed: number
  app: AppName | string
  profileMode: ProfileMode | 'full' | 'baseline'
  verifierBackend: VerifierChoice
  benchMode?: BenchMode
  heldOutSalt?: string
  /** Reuse an already-started app (CLI path). When omitted the adapter starts and stops it. */
  started?: MaterializedAppLike
  maxRequests?: number
  deadlineMs?: number
  /** Default false: only confirmed/static-verified findings are submitted (like the live pipeline). */
  emitUnconfirmedFindings?: boolean
  repoRootDir?: string
}

export interface GuardianRunResult {
  app: string
  seed: number
  findings: SubmittedFinding[]
  telemetry: RunTelemetry
  surface: MaterializedSurface
  verifierBackend: string | null
  endpointsDiscovered: number
  hypothesesFormed: number
  signalsObserved: number
  proofGaps: number
  duplicateSignals: number
  notes: string[]
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
const AUTHZ_CWES = new Set([284, 285, 566, 639, 862, 863])

function normalizeProfileMode(mode: RunGuardianOptions['profileMode']): ProfileMode {
  if (mode === 'full' || mode === 'v4-full') return 'v4-full'
  if (mode === 'baseline' || mode === 'v3-baseline') return 'v3-baseline'
  throw new Error(`unknown profile mode '${String(mode)}' (use v4-full | v3-baseline)`)
}

function cweNumber(cwe: string | undefined): number | null {
  const m = cwe ? /(\d+)/.exec(cwe) : null
  return m ? Number(m[1]) : null
}

/** Map the engine's CWE/category labels onto realistic-bench's vuln taxonomy. */
export function vulnClassForFinding(cwe: string | undefined, category: string | undefined): VulnClass | undefined {
  const n = cweNumber(cwe)
  if (n === 89 || n === 564 || n === 943) return 'sqli'
  if (n != null && AUTHZ_CWES.has(n)) return 'idor'
  if (n === 79 || n === 80) return 'xss_reflected'
  if (n === 918) return 'ssrf'
  if (n === 611 || n === 776) return 'xxe'
  if (n === 22 || n === 23 || n === 73) return 'path_traversal'
  if (n === 78 || n === 77) return 'command_injection'
  if (n === 352) return 'csrf'
  if (n === 601) return 'open_redirect'
  if (n === 915) return 'mass_assignment'
  if (n === 1336 || n === 94 || n === 95) return 'ssti'
  if (n === 524 || n === 525) return 'cache_poisoning'
  if (n === 200 || n === 359) return 'info_disclosure'
  if (n === 307) return 'rate_limit_bypass'
  if (n === 345 || n === 347 || n === 327) return 'jwt'
  switch (category) {
    case 'injection-input': return 'sqli'
    case 'broken-access-control': return 'idor'
    case 'mass-assignment': return 'mass_assignment'
    default: return undefined
  }
}

function findingFromSpec(
  id: string, hyp: HypothesisLike, synth: SynthesizedSpecLike, status: SubmittedFinding['status'], now: number,
): SubmittedFinding {
  const spec = synth.spec
  const title = typeof spec.title === 'string' && spec.title ? spec.title : `Confirmed ${synth.kind} finding`
  const cwe = typeof spec.cwe === 'string' ? spec.cwe : undefined
  const vulnClass = vulnClassForFinding(cwe, typeof spec.category === 'string' ? spec.category : undefined)
  const severity = SEVERITIES.find(s => s === spec.severity)
  const path = hyp.endpoint.path.startsWith('/') ? hyp.endpoint.path : `/${hyp.endpoint.path}`
  const finding: SubmittedFinding = {
    id,
    title,
    endpoints: [{ method: hyp.method, path }],
    status,
    submittedAtMs: now,
    costUsdAtSubmit: 0,
  }
  if (cwe) finding.cwe = cwe
  if (vulnClass) finding.vulnClass = vulnClass
  if (severity) finding.severity = severity
  if (hyp.param?.name) finding.params = [hyp.param.name]
  return finding
}

function loginRoute(surface: MaterializedSurface, briefing: BriefingLike): string | null {
  const fromSurface = surface.routes
  const fromBriefing = (briefing.apiReference ?? []).map(r => ({ routeKey: r.routeKey, method: r.method, path: r.path }))
  return pickLoginPath([...fromSurface, ...fromBriefing])
}

/** Add briefing/surface routes the recon pass missed (params: path placeholders only). */
function mergeSurfaceEndpoints(
  discovered: DiscoveredEndpointLike[], surface: MaterializedSurface, briefing: BriefingLike,
): DiscoveredEndpointLike[] {
  const seen = new Set(discovered.map(e => `${e.method.toUpperCase()} ${e.path}`))
  const extra: DiscoveredEndpointLike[] = []
  const candidates = [
    ...surface.routes.map(r => ({ method: r.method, path: r.path, params: r.params })),
    ...(briefing.apiReference ?? []).map(r => ({ method: r.method, path: r.path, params: r.params.filter(p => r.path.includes(`:${p}`)) })),
  ]
  for (const c of candidates) {
    const key = `${c.method.toUpperCase()} ${c.path}`
    if (seen.has(key)) continue
    seen.add(key)
    extra.push({
      method: c.method.toUpperCase(), path: c.path, source: 'materialized-surface',
      params: c.params.map(name => ({ name, location: 'path', isObjectId: true, isCsrf: false })),
    })
  }
  return [...discovered, ...extra]
}

async function verifyWithRetries(
  engine: EngineModuleLike, env: EngineEnvLike, verifier: { backend: unknown }, spec: Record<string, unknown>,
  attempts: number, signal: AbortSignal,
): Promise<{ verdict: string; jqError: boolean; spaCatchall: boolean; reason: string }> {
  const rec = env as unknown as { broker?: unknown; canaryBroker?: unknown; grant?: unknown; storage?: unknown; runId?: string }
  const base: Record<string, unknown> = {
    spec, broker: rec.broker, canaryBroker: rec.canaryBroker, backend: verifier.backend,
    grant: rec.grant, storage: rec.storage, runId: rec.runId, signal, onExchange: () => undefined,
  }
  if (attempts > 0 && engine.verifyReplaySpecInline) {
    let last: { verdict: string; jqError: boolean; spaCatchall: boolean; reason: string } = { verdict: 'inconclusive', jqError: false, spaCatchall: false, reason: '' }
    for (let attempt = 1; attempt <= 1 + attempts; attempt += 1) {
      const res = await engine.verifyReplaySpecInline({ ...base, attemptCount: attempt, maxRetries: attempts })
      const outcome = (res.replay as unknown as { outcome?: { reason?: string } }).outcome
      last = {
        verdict: res.replay.verdict,
        jqError: Boolean(res.feedback?.jqError),
        spaCatchall: Boolean((res.feedback as unknown as { spaCatchallMatched?: boolean } | undefined)?.spaCatchallMatched),
        reason: String(outcome?.reason ?? ''),
      }
      if (last.verdict === 'confirmed' || last.verdict === 'dismissed') break
    }
    return last
  }
  const res = await engine.verifyReplaySpec(base)
  const outcome = (res as unknown as { outcome?: { reason?: string } }).outcome
  return { verdict: res.verdict, jqError: false, spaCatchall: false, reason: String(outcome?.reason ?? '') }
}

// ---------------------------------------------------------------------------------------------
// Main entrypoint
// ---------------------------------------------------------------------------------------------
export async function runGuardianAgainstMaterialized(
  opts: RunGuardianOptions, deps: GuardianAdapterDeps = {},
): Promise<GuardianRunResult> {
  assertLocalLabAllowed()
  if (!(appNames as readonly string[]).includes(String(opts.app))) {
    throw new Error(`unknown app '${String(opts.app)}' (known: ${appNames.join(', ')})`)
  }
  const app = opts.app as AppName
  const profileMode = normalizeProfileMode(opts.profileMode)
  const mode: BenchMode = opts.benchMode ?? 'grey-box'
  const repoRootDir = opts.repoRootDir ?? DEFAULT_REPO_ROOT
  const now = deps.now ?? (() => Date.now())
  const startedAtMs = now()

  const surface = readMaterializedSurface(opts.treeDir)
  if (surface.app && surface.app !== app) {
    throw new Error(`materialized tree is '${surface.app}' but --app is '${app}'`)
  }

  let started = opts.started
  let ownsApp = false
  if (!started) {
    const start = deps.startApp ?? (o => startRealisticApp(o))
    started = await start({ app, seed: opts.seed, ...(opts.heldOutSalt ? { heldOutSalt: opts.heldOutSalt } : {}) })
    ownsApp = true
  }
  if (realpathSync(resolve(opts.treeDir)) !== realpathSync(resolve(started.sourceDir))) {
    throw new Error(`treeDir (${opts.treeDir}) is not the app's materialized sourceDir (${started.sourceDir}); refusing to probe a different tree`)
  }

  const notes: string[] = []
  const engine = deps.loadEngine ? await deps.loadEngine(repoRootDir) : await loadGuardianEngine(repoRootDir)
  const caps = engine.profileCaps(profileMode)
  const briefing = (deps.briefing ?? ((a, m) => briefingFor(a as unknown as Parameters<typeof briefingFor>[0], m)))(started, mode)

  const loginPath = loginRoute(surface, briefing)
  const login = await loginPersonas(briefing.origin, loginPath, briefing.personas, deps.fetchImpl ?? fetch)
  notes.push(...login.notes)
  if (!loginPath) notes.push('login route missing; auth-required sites will surface as context_reset/surface_miss')

  const handle: EngineHandleLike = {
    origin: new URL(briefing.origin).origin,
    port: Number(new URL(briefing.origin).port || 80),
    personas: login.personas,
    close: async () => undefined,
  }

  const findings: SubmittedFinding[] = []
  const seenSignals = new Set<string>()
  let duplicates = 0
  let endpoints: DiscoveredEndpointLike[] = []
  let hypotheses: HypothesisLike[] = []
  let signals = 0
  let proofGaps = 0
  let verifierKind: string | null = null
  let budgetExhausted = false
  const tierBlocked: Array<{ method: string; path: string }> = []
  const assertionFailures: Array<{ findingId?: string; path?: string }> = []

  const env = await engine.createEngineEnv(handle, caps, `realistic-${app}-${opts.seed}`)
  try {
    const discovered = await engine.discoverEndpoints(env, caps, () => undefined)
    endpoints = mergeSurfaceEndpoints(discovered, surface, briefing)
    notes.push(`recon found ${discovered.length} endpoint(s); surface merge -> ${endpoints.length}`)
    const plan = engine.formHypotheses(endpoints, caps)
    hypotheses = plan.hypotheses
    notes.push(`formed ${hypotheses.length} hypothesis(es) (${plan.encodingSkips.length} encoding skips)`)

    const verifier = await engine.selectVerifierBackend(opts.verifierBackend)
    verifierKind = verifier.kind
    const deadlineMs = opts.deadlineMs ?? Number(process.env.GUARDIAN_BENCH_DEADLINE_MS ?? 8 * 60_000)
    const maxRequests = opts.maxRequests ?? 3800
    const deadline = now() + deadlineMs
    const probeEnv = env.probeEnv
    const controllerSignal = env.controller?.signal ?? AbortSignal.timeout(deadlineMs + 60_000)

    for (const hyp of hypotheses) {
      if (now() > deadline || (env.requestsUsed?.() ?? 0) > maxRequests) { budgetExhausted = true; break }
      if (hyp.probeClass === 'sqli_time_diff') {
        const left = Number(probeEnv.slowProbesLeft ?? 0)
        if (left <= 0) continue
        probeEnv.slowProbesLeft = left - 1
      }
      const outcome = await engine.runHypothesis(hyp, probeEnv, () => undefined).catch((err: unknown) => {
        notes.push(`probe error on ${hyp.endpoint.path} (${hyp.probeClass}): ${(err as Error).message.slice(0, 140)}`)
        return null
      })
      if (!outcome) continue
      if (outcome.tierBlocked) tierBlocked.push({ method: hyp.method, path: hyp.endpoint.path })
      if (outcome.verdict !== 'signal') continue
      signals += 1
      // v4.1 engine exposes synthesizeSpecs (several specs per signal); older engines expose one.
      const synthList: SynthesizedSpecLike[] = engine.synthesizeSpecs
        ? engine.synthesizeSpecs(outcome, probeEnv)
        : (() => { const one = engine.synthesizeSpec(outcome, probeEnv); return one ? [one] : [] })()
      if (synthList.length === 0) {
        proofGaps += 1
        notes.push(`signal without replay spec: ${hyp.probeClass} ${hyp.method} ${hyp.endpoint.path} ${hyp.param?.name ?? ''}`)
        continue
      }

      for (const synth of synthList) {
        let verdict = 'inconclusive'
        let jqError = false
        let reason = ''
        try {
          const res = await verifyWithRetries(engine, env, verifier, synth.spec, caps.inlineRetries, controllerSignal)
          verdict = res.verdict; jqError = res.jqError; reason = res.reason
        } catch (err) {
          notes.push(`verify error on ${hyp.endpoint.path} (${hyp.probeClass}): ${(err as Error).message.slice(0, 140)}`)
        }
        if (verdict !== 'confirmed') {
          // `static_verified` without a codeLocation cannot be attributed to a root cause by the
          // grader (it would land as an unmatched FP), so treat it as a proof gap here.
          proofGaps += 1
          notes.push(`unconfirmed ${synth.kind} ${hyp.method} ${hyp.endpoint.path} ${hyp.param?.name ?? ''}: ${verdict}${reason ? ` (${reason.slice(0, 100)})` : ''}`)
          if (jqError) assertionFailures.push({ path: hyp.endpoint.path })
          if (/tier 3/i.test(reason)) tierBlocked.push({ method: hyp.method, path: hyp.endpoint.path })
          if (opts.emitUnconfirmedFindings) {
            findings.push(findingFromSpec(`rb-${app}-${opts.seed}-g${findings.length + 1}`, hyp, synth, 'open_proof_gap', now()))
          }
          continue
        }
        const dedupeKey = `${hyp.endpoint.path}|${hyp.param?.name ?? ''}|${String(synth.spec.cwe ?? synth.kind)}`
        if (seenSignals.has(dedupeKey)) { duplicates += 1; continue }
        seenSignals.add(dedupeKey)
        findings.push(findingFromSpec(
          `rb-${app}-${opts.seed}-f${findings.length + 1}`, hyp, synth, 'runtime_confirmed', now(),
        ))
      }
    }
  } finally {
    await env.cleanup()
    if (ownsApp && started) await started.stop()
  }

  const endedAtMs = now()
  if (findings.length === 0) notes.push('no findings reached a confirmed/static-verified verdict')
  const telemetry: RunTelemetry = {
    startedAtMs,
    endedAtMs,
    totalCostUsd: 0,
    budgetUsd: 25,
    ...(budgetExhausted ? { budgetExhausted: true } : {}),
    hypotheses: hypotheses.map(h => ({ path: h.endpoint.path, method: h.method })),
    ...(tierBlocked.length ? { tierBlocked } : {}),
    ...(assertionFailures.length ? { assertionFailures } : {}),
  }

  return {
    app, seed: opts.seed, findings, telemetry, surface,
    verifierBackend: verifierKind,
    endpointsDiscovered: endpoints.length,
    hypothesesFormed: hypotheses.length,
    signalsObserved: signals,
    proofGaps,
    duplicateSignals: duplicates,
    notes,
  }
}

/**
 * Diagnostic path for callers that DO own a manifest (dev parity with the xben-25 runner):
 * runs `runLivePipeline` against this materialized app through the shared launcher contract.
 * Never used by the truth-free adapter path above.
 */
export async function runGuardianLivePipelineAgainstMaterialized(
  opts: {
    started: MaterializedAppLike
    treeDir: string
    manifest: unknown
    profileMode: ProfileMode | 'full' | 'baseline'
    verifierBackend: VerifierChoice
    repoRootDir?: string
    fetchImpl?: typeof fetch
  },
  deps: GuardianAdapterDeps = {},
): Promise<{ traces: unknown[]; totalCostUsd: number; verifierBackend: string | null; notes: string[] }> {
  assertLocalLabAllowed()
  if (!statSync(opts.treeDir).isDirectory()) throw new Error(`treeDir is not a directory: ${opts.treeDir}`)
  const repoRootDir = opts.repoRootDir ?? DEFAULT_REPO_ROOT
  const engine = deps.loadEngine ? await deps.loadEngine(repoRootDir) : await loadGuardianEngine(repoRootDir)
  if (!engine.runLivePipeline) throw new Error('scripts/benchmark-live.ts does not export runLivePipeline')
  const surface = readMaterializedSurface(opts.treeDir)
  const briefing = (deps.briefing ?? ((a, m) => briefingFor(a as unknown as Parameters<typeof briefingFor>[0], m)))(opts.started, 'grey-box')
  const login = await loginPersonas(briefing.origin, loginRoute(surface, briefing), briefing.personas, opts.fetchImpl ?? fetch)
  const handle: EngineHandleLike = {
    origin: new URL(briefing.origin).origin,
    port: Number(new URL(briefing.origin).port || 80),
    personas: login.personas,
    close: async () => undefined,
  }
  return await engine.runLivePipeline({
    suite: 'xben-25', manifest: opts.manifest, profileMode: normalizeProfileMode(opts.profileMode),
    launcher: async () => handle, verifierBackend: opts.verifierBackend, repoRootDir,
  })
}
