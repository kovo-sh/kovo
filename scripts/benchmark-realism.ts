#!/usr/bin/env node
// Guardian v6 — realism exit-gate harness.
//
// Boots one `benchmarks/realism-suite` fixture, hands its briefing to the REAL
// `Execution` product pipeline (black/grey/white-box, `--no-llm` and agentic), then
// extracts the persisted findings and grades them against the fixture's offline
// `truth.json`. Every number in the artifact comes from a real run; a fixture that
// `Execution` cannot reach is recorded with its exact failure stage, never as a pass.
//
// Usage:
//   GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
//     --fixture enterprise-spa --no-llm --out-dir /tmp/realism-gate
//   GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
//     --fixture all --mode grey-box --no-llm --json --md
//
// Agentic runs additionally need a Guardian data dir with an enabled model profile
// (`--data-dir` or GUARDIAN_DATA_DIR) and a worker-session-capable verifier (docker):
//   GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/path/to/data \
//     newgrp docker -c 'node scripts/benchmark-realism.ts --fixture all --verifier docker'
//
// Safety: only the loopback realism fixtures are used; `GUARDIAN_ALLOW_LOCAL_LAB=1`
// is mandatory. Fixture credentials are synthetic. Artifacts are written 0600 in a
// 0700 directory and are scanned for known secrets, the held-out salt and generic
// credential shapes before the process reports success.

import { execFile, execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'

import type { BenchMode } from '../benchmarks/realistic-bench/lib/types.ts'
import type {
  FixtureStartOptions,
  GradeResult,
  Persona,
  RouteRef,
  StartedFixture,
  SubmittedFinding,
} from '../benchmarks/realism-suite/lib/types.ts'
import { endpointMatches, gradeFindings, loadTruth } from '../benchmarks/realism-suite/lib/grade.ts'
import { assertLocalLabAllowed } from '../benchmarks/realism-suite/lib/safety.ts'
import { FIXTURES, briefingFor, startFixture } from '../benchmarks/realism-suite/run.ts'
import type { Finding } from '../src/domain.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { Execution } from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { privateModelProfiles } from '../src/server/model-settings.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { redact, redactJsonValue } from '../src/server/redact.ts'
import { tenantTagForRun } from '../src/server/scope-policy.ts'
import type { EnvironmentMode, OriginRole } from '../src/server/scope-policy.ts'
import { Store } from '../src/server/store.ts'
import type { EndpointRow } from '../src/server/store.ts'
import { selectVerifierBackend } from './benchmark-backend.ts'
import type { VerifierBackendKind } from './benchmark-backend.ts'
import {
  DEFAULT_BUDGET_USD,
  DEFAULT_MAX_DURATION_MS,
  PreflightError,
  assertAgenticPreflight,
  describeModelMode,
  detectWorkerSessions,
  endpointsFromReplaySpec,
  openCellStore,
  prepareIsolatedDataDir,
  stopEngine,
} from './benchmark-realistic.ts'
import type { ModelInfo } from './benchmark-realistic.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

export const DEFAULT_REALISM_SEED = 42
export const DEFAULT_CALLBACK_DELAY_MS: [number, number] = [15_000, 30_000]

export interface RealismArgs {
  fixtures: string[]
  mode: BenchMode
  noLlm: boolean
  verifier: 'auto' | 'docker' | 'local-jq'
  budgetUsd: number
  maxDurationMs: number
  outDir: string
  dataDir?: string
  isolateDataDir: boolean
  keepDataDirs: boolean
  seed: number
  callbackDelayMs: [number, number]
  targetOrigin?: string
  json: boolean
  md: boolean
  failOnGate: boolean
  keepSource: boolean
  help: boolean
}

const usage = `Guardian realism exit gates (real Execution loop)

Usage:
  GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- [flags]

Flags:
  --fixture <name|all>      enterprise-spa | wan-oob | staging-concurrency |
                            monorepo-whitebox | all (default: all)
  --mode <m>                black-box | grey-box | white-box (default: grey-box)
  --no-llm                  force the deterministic/Zero-LLM path in an isolated
                            data dir; never loads a model profile
  --verifier <kind>         auto | docker | local-jq (default: auto)
  --budget-usd <n>          per-run USD budget (default: ${DEFAULT_BUDGET_USD})
  --max-duration-ms <n>     wall-clock cap per fixture (default: ${DEFAULT_MAX_DURATION_MS})
  --out-dir <path>          artifact directory (default: .guardian/realism-bench)
  --data-dir <path>         Guardian data dir with an enabled model profile
                            (default: $GUARDIAN_DATA_DIR). Agentic cells always run
                            from an isolated copy under <out-dir>/data/<cell>.
  --isolate-data-dir        accepted for parity; agentic cells are always isolated
                            from the source data dir (profiles copied, credentials
                            symlinked, key never copied)
  --keep-data-dirs          keep isolated per-cell data dirs after the run
  --target-origin <label>   override the primary target origin label (e.g. api)
  --realism-seed <n>        fixture seed (default: ${DEFAULT_REALISM_SEED})
  --callback-delay-ms <a,b> WAN fixture async callback delay (default: 15000,30000;
                            shrink only for smoke runs, not for gate evidence)
  --json                    print the JSON summary to stdout
  --md                      print the Markdown summary to stdout
  --fail-on-gate            exit 3 when a fixture gate is not met (default:
                            measurement-only exit 0 for a completed run)
  --keep-source             keep the materialized white-box source tree
  --help                    show this help

Environment:
  GUARDIAN_ALLOW_LOCAL_LAB=1   required to boot loopback fixtures
  GUARDIAN_DATA_DIR            default Guardian data dir (model profile source)
  GUARDIAN_RB_HELDOUT_SALT     scanned in artifacts when set (never printed)

Artifacts per fixture:
  <out-dir>/<fixture>-<mode>[-no-llm].json         grade + gate metrics + meta
  <out-dir>/<fixture>-<mode>[-no-llm].md           rendered gate report
  <out-dir>/<fixture>-<mode>[-no-llm].meta.json    run/model/budget/shutdown meta
  <out-dir>/<fixture>-<mode>[-no-llm].findings.json  submitted findings (re-gradeable)
  <out-dir>/summary.{json,md}                      aggregate over fixtures
`

function fail(message: string): never {
  throw new Error(message)
}

function stringFlag(a: Record<string, string | boolean>, key: string): string | undefined {
  const value = a[key]
  return typeof value === 'string' ? value : undefined
}

function positiveInt(raw: string | undefined, flag: string, fallback: number): number {
  if (raw === undefined) return fallback
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) fail(`${flag} must be a positive integer (got '${raw}')`)
  return n
}

function parsePair(raw: string | undefined, flag: string, fallback: [number, number]): [number, number] {
  if (raw === undefined) return fallback
  const parts = raw.split(',').map(part => Number(part.trim()))
  if (parts.length !== 2 || parts.some(n => !Number.isFinite(n) || n < 0)) {
    fail(`${flag} must be "min,max" non-negative milliseconds (got '${raw}')`)
  }
  if (parts[0] > parts[1]) fail(`${flag} min must be <= max`)
  return [parts[0], parts[1]]
}

export function parseRealismArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): RealismArgs {
  const raw: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const key = arg.slice(2)
    if (!key) fail('empty flag')
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) raw[key] = true
    else { raw[key] = next; i += 1 }
  }
  const known = new Set([
    'fixture', 'mode', 'no-llm', 'verifier', 'budget-usd', 'max-duration-ms', 'out-dir',
    'data-dir', 'isolate-data-dir', 'keep-data-dirs', 'target-origin', 'realism-seed',
    'callback-delay-ms', 'json', 'md', 'fail-on-gate', 'keep-source', 'help',
  ])
  for (const key of Object.keys(raw)) if (!known.has(key)) fail(`unknown flag --${key}`)

  const modeRaw = stringFlag(raw, 'mode') ?? 'grey-box'
  if (!['black-box', 'grey-box', 'white-box'].includes(modeRaw)) {
    fail(`--mode must be black-box, grey-box or white-box (got '${modeRaw}')`)
  }
  const verifierRaw = stringFlag(raw, 'verifier') ?? 'auto'
  if (!['auto', 'docker', 'local-jq'].includes(verifierRaw)) {
    fail(`--verifier must be auto, docker or local-jq (got '${verifierRaw}')`)
  }
  const fixtureRaw = stringFlag(raw, 'fixture') ?? 'all'
  const fixtures = fixtureRaw === 'all'
    ? Object.keys(FIXTURES)
    : fixtureRaw.split(',').map(name => name.trim()).filter(Boolean)
  if (!fixtures.length) fail('--fixture requires at least one fixture name or all')
  for (const name of fixtures) {
    if (!FIXTURES[name]) fail(`unknown realism fixture '${name}' (have: ${Object.keys(FIXTURES).join(', ')})`)
  }
  const budgetUsd = raw['budget-usd'] === undefined ? DEFAULT_BUDGET_USD : Number(stringFlag(raw, 'budget-usd'))
  if (!Number.isFinite(budgetUsd) || budgetUsd < 0.1 || budgetUsd > 500) {
    fail(`--budget-usd must be a number between 0.1 and 500 (got '${String(raw['budget-usd'])}')`)
  }
  const outDirRaw = stringFlag(raw, 'out-dir') ?? '.guardian/realism-bench'
  const dataDirRaw = stringFlag(raw, 'data-dir') ?? env.GUARDIAN_DATA_DIR
  const seed = positiveInt(stringFlag(raw, 'realism-seed'), '--realism-seed', DEFAULT_REALISM_SEED)
  const targetOrigin = stringFlag(raw, 'target-origin')
  return {
    fixtures,
    mode: modeRaw as BenchMode,
    noLlm: raw['no-llm'] === true,
    verifier: verifierRaw as RealismArgs['verifier'],
    budgetUsd,
    maxDurationMs: positiveInt(stringFlag(raw, 'max-duration-ms'), '--max-duration-ms', DEFAULT_MAX_DURATION_MS),
    outDir: isAbsolute(outDirRaw) ? outDirRaw : resolve(outDirRaw),
    ...(dataDirRaw ? { dataDir: isAbsolute(dataDirRaw) ? dataDirRaw : resolve(dataDirRaw) } : {}),
    isolateDataDir: raw['isolate-data-dir'] === true || fixtures.length > 1,
    keepDataDirs: raw['keep-data-dirs'] === true,
    seed,
    callbackDelayMs: parsePair(stringFlag(raw, 'callback-delay-ms'), '--callback-delay-ms', DEFAULT_CALLBACK_DELAY_MS),
    ...(targetOrigin ? { targetOrigin } : {}),
    json: raw.json === true,
    md: raw.md === true,
    failOnGate: raw['fail-on-gate'] === true,
    keepSource: raw['keep-source'] === true,
    help: raw.help === true,
  }
}

// ---------------------------------------------------------------------------------------------
// Fixture scope map — which fixture origins are targets vs benign auth/asset infrastructure.
// Mirrors the three-tier policy (`targetOrigins` / `authOrigins` / `assetOrigins`).
// ---------------------------------------------------------------------------------------------

const FIXTURE_SCOPE: Record<string, Record<string, OriginRole>> = {
  'enterprise-spa': { app: 'target', api: 'target', idp: 'auth', assets: 'asset' },
  'wan-oob': { proxy: 'target', backend: 'auth', collector: 'auth' },
  'staging-concurrency': { app: 'target', h2: 'target' },
  'monorepo-whitebox': { app: 'target' },
}

const PRIMARY_ORIGIN: Record<string, string> = {
  'enterprise-spa': 'app',
  'wan-oob': 'proxy',
  'staging-concurrency': 'app',
  'monorepo-whitebox': 'app',
}

const ENTERPRISE_ROUTES = new Set(['enterprise-spa'])
const STAGING_FIXTURES = new Set(['staging-concurrency'])

function scopeFor(fixture: string, origins: Record<string, string>): Record<string, OriginRole> {
  const declared = FIXTURE_SCOPE[fixture]
  if (declared) return declared
  const roles: Record<string, OriginRole> = {}
  for (const label of Object.keys(origins)) roles[label] = 'auth'
  return roles
}

function primaryLabel(fixture: string, origins: Record<string, string>, override?: string): string {
  if (override) {
    if (!origins[override]) fail(`--target-origin '${override}' is not a fixture origin (have: ${Object.keys(origins).join(', ')})`)
    return override
  }
  const preferred = PRIMARY_ORIGIN[fixture]
  if (preferred && origins[preferred]) return preferred
  const first = Object.keys(origins)[0]
  if (!first) fail(`fixture ${fixture} exposes no origins`)
  return first
}

function normalizeOrigin(value: string): string {
  try { return new URL(value).origin } catch { return value.replace(/\/+$/, '') }
}

function originLabelMap(origins: Record<string, string>): Map<string, string> {
  const map = new Map<string, string>()
  for (const [label, url] of Object.entries(origins)) map.set(normalizeOrigin(url), label)
  return map
}

// ---------------------------------------------------------------------------------------------
// Briefing -> real Project/Run configuration (briefing only; truth is never imported)
// ---------------------------------------------------------------------------------------------

function safeHandle(id: string): string {
  const cleaned = id.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '')
  return cleaned.length ? cleaned.slice(0, 48) : 'persona'
}

function specPath(raw: string): string | null {
  const path = raw.split('?')[0]
  if (!path.startsWith('/')) return null
  return path
    .replace(/<([^>]+)>/g, '{$1}')
    .replace(/:([A-Za-z0-9_]+)/g, '{$1}')
}

export interface OpenApiDoc {
  openapi: string
  info: { title: string; version: string }
  paths: Record<string, Record<string, { parameters: Array<{ name: string; in: string; required: boolean }> }>>
}

/** Build a per-origin OpenAPI document from the fixture's published API reference. */
export function briefingToOpenApi(input: {
  fixture: string
  originLabel: string
  api: ReadonlyArray<{ origin: string; method: string; path: string }>
}): OpenApiDoc | null {
  const paths: OpenApiDoc['paths'] = {}
  for (const entry of input.api) {
    if (entry.origin !== input.originLabel) continue
    const path = specPath(entry.path)
    if (!path) continue
    const names = [...path.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map(match => match[1]!)
    paths[path] ??= {}
    paths[path][entry.method.toLowerCase()] = {
      parameters: names.map(name => ({ name, in: 'path', required: true })),
    }
  }
  if (Object.keys(paths).length === 0) return null
  return {
    openapi: '3.1.0',
    info: { title: `realism ${input.fixture} ${input.originLabel} API reference`, version: '1.0.0' },
    paths,
  }
}

interface PlannedPersona {
  handle: string
  roleLabel: string
  authKind: 'bearer' | 'cookie'
  secret: string
  canaryMarkers: string[]
}

interface CellPlan {
  mission: string
  primaryLabel: string
  primaryOrigin: string
  scopes: Record<string, OriginRole>
  origins: Record<string, string>
  personas: PlannedPersona[]
  capabilityTier: 3
}

interface BrowserCookieSource {
  browserCookie?: (personaId: string) => string
}

/** Mode -> briefing interpretation; the only configuration source. */
export function planCell(input: {
  fixture: string
  briefing: { origins: Record<string, string>; api: Array<{ origin: string; method: string; path: string; notes?: string }>; personas: Persona[]; sourceDir?: string }
  mode: BenchMode
  targetOrigin?: string
  browserCookie?: (personaId: string) => string
}): CellPlan {
  const { briefing, mode } = input
  if (mode === 'white-box' && !briefing.sourceDir) {
    throw new PreflightError(`realism fixture '${input.fixture}' has no source tree; white-box mode is unavailable (use grey-box)`)
  }
  const primary = primaryLabel(input.fixture, briefing.origins, input.targetOrigin)
  const scopes = scopeFor(input.fixture, briefing.origins)
  const originAllowlist = Object.values(briefing.origins).map(normalizeOrigin)
  const personas: PlannedPersona[] = []
  const handles = new Set<string>()
  const uniqueHandle = (base: string): string => {
    let handle = safeHandle(base)
    for (let n = 2; handles.has(handle); n += 1) handle = `${safeHandle(base)}-${n}`
    handles.add(handle)
    return handle
  }
  for (const persona of briefing.personas) {
    if (persona.token) {
      personas.push({
        handle: uniqueHandle(persona.id),
        roleLabel: `${persona.role} (${persona.tenant})`,
        authKind: 'bearer',
        secret: persona.token.replace(/^Bearer\s+/i, ''),
        canaryMarkers: [],
      })
    }
    if (input.browserCookie && (persona.role === 'admin' || persona.role === 'member')) {
      try {
        personas.push({
          handle: uniqueHandle(`${persona.id}-browser`),
          roleLabel: `${persona.role} (${persona.tenant}) browser session`,
          authKind: 'cookie',
          secret: input.browserCookie(persona.id),
          canaryMarkers: [],
        })
      } catch {
        // The fixture may not expose a browser session for every persona; skip it.
      }
    }
  }
  if (mode !== 'black-box' && !briefing.api.length) {
    throw new PreflightError(`realism fixture '${input.fixture}' published no API reference for grey-box mode`)
  }
  const mission = [
    `Defensive verification of the authorized local realism fixture ${input.fixture} (${briefing.origins[primary]}).`,
    'Map the reachable surface across the declared origins, form hypotheses from observed behaviour, and submit only',
    'findings whose impact is proven by deterministic replay verification. Do not fabricate findings and do not leave',
    'the approved fixture origins.',
    ...(mode === 'white-box' && briefing.sourceDir ? ['A read-only copy of the repository source is mounted for review.'] : []),
  ].join(' ')
  return {
    mission,
    primaryLabel: primary,
    primaryOrigin: briefing.origins[primary]!,
    scopes,
    origins: briefing.origins,
    personas,
    capabilityTier: 3,
  }
}

// ---------------------------------------------------------------------------------------------
// Persisted findings -> realism `SubmittedFinding`
// ---------------------------------------------------------------------------------------------

interface ReplaySpecLike {
  id: string
  findingId: string
  spec: unknown
  createdAt: number
}

interface ExchangeLike {
  id: string
  method: string
  pathAndQuery: string
}

export interface TranslatedFindings {
  findings: SubmittedFinding[]
  /** findingId -> number of concrete endpoints extracted for it (used for SAST->live linking). */
  endpointCounts: Map<string, number>
}

const IGNORED_FINDING_STATUSES = new Set(['dismissed'])

function submitStatus(status: string): string {
  if (status === 'confirmed') return 'runtime_confirmed'
  if (status === 'static_verified') return 'static_verified'
  if (status === 'pending') return 'proposed'
  return 'open_proof_gap'
}

/** Translate persisted Guardian findings into the realism-suite grading schema. */
export function translateFindings(input: {
  findings: Finding[]
  replaySpecs: ReplaySpecLike[]
  exchanges: ExchangeLike[]
  origins: Record<string, string>
  secrets: readonly NamedSecret[]
}): TranslatedFindings {
  const labels = originLabelMap(input.origins)
  const specsByFinding = new Map<string, ReplaySpecLike[]>()
  for (const spec of input.replaySpecs) {
    const list = specsByFinding.get(spec.findingId) ?? []
    list.push(spec)
    specsByFinding.set(spec.findingId, list)
  }
  for (const list of specsByFinding.values()) list.sort((a, b) => b.createdAt - a.createdAt)
  const exchangeById = new Map(input.exchanges.map(exchange => [exchange.id, exchange]))
  const findings: SubmittedFinding[] = []
  const endpointCounts = new Map<string, number>()

  for (const finding of input.findings) {
    if (finding.findingKind === 'baseline_check') continue
    if (IGNORED_FINDING_STATUSES.has(finding.status)) continue
    if (finding.supersededByFindingId) continue
    const endpoints: Array<{ method?: string; path: string }> = []
    for (const spec of (specsByFinding.get(finding.id) ?? []).slice(0, 3)) {
      endpoints.push(...endpointsFromReplaySpec(spec.spec))
    }
    if (!endpoints.length) {
      for (const id of finding.exchangeIds ?? []) {
        const exchange = exchangeById.get(id)
        if (exchange) endpoints.push({ method: exchange.method.toUpperCase(), path: exchange.pathAndQuery })
      }
    }
    const unique = new Map<string, { method?: string; path: string }>()
    for (const endpoint of endpoints) unique.set(`${endpoint.method ?? '*'}:${endpoint.path}`, endpoint)
    const clean = [...unique.values()]
    if (!clean.length) {
      // A finding with no executable endpoint cannot be graded against per-route truth.
      continue
    }
    endpointCounts.set(finding.id, clean.length)
    const originLabel = labels.get(normalizeOrigin(finding.origin))
    const evidence = [finding.reason, finding.verification, finding.counterevidence]
      .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
      .map(value => redact(value, input.secrets).replace(/\s+/g, ' ').trim().slice(0, 400))
      .slice(0, 3)
    for (const endpoint of clean) {
      findings.push({
        title: redact(finding.title, input.secrets).slice(0, 200),
        ...(finding.category ? { vulnClass: finding.category } : {}),
        ...(finding.cwe ? { cwe: finding.cwe } : {}),
        ...(originLabel ? { origin: originLabel } : {}),
        ...(endpoint.method ? { method: endpoint.method } : {}),
        endpoint: endpoint.path,
        status: submitStatus(finding.status),
        ...(evidence.length ? { evidence } : {}),
      })
    }
    if (clean.length > 1) endpointCounts.set(finding.id, clean.length)
  }
  return { findings, endpointCounts }
}

// ---------------------------------------------------------------------------------------------
// Exit-gate metrics
// ---------------------------------------------------------------------------------------------

export type FailureStage =
  | 'passed'
  | 'gate_incomplete'
  | 'fixture_start'
  | 'execution_preflight'
  | 'execution_failed'
  | 'timeout'
  | 'discovery'
  | 'investigation'
  | 'verification_or_attribution'
  | 'interrupted'

export interface GateCriterion {
  id: string
  label: string
  required: boolean
  met: boolean
  observed: string
}

export interface RouteDiscovery {
  discovered: number
  total: number
  pct: number
  missing: string[]
}

export interface ChainSummary {
  id: string
  total: number
  covered: number
  complete: boolean
}

export interface RealismMetrics {
  routeDiscovery: RouteDiscovery | null
  crossOriginAuthzConfirmed: boolean
  storedXssConfirmed: boolean
  browserExecutedStoredXss: boolean
  oob: {
    blindSqliConfirmed: boolean
    asyncSsrfConfirmed: boolean
    asyncXxeConfirmed: boolean
    webhookForgeryConfirmed: boolean
    falseNegativeRate: number | null
    fixtureCallbacks: Record<string, boolean>
  } | null
  staging: {
    writeBolaConfirmed: boolean
    raceConfirmed: boolean
    checkoutConfirmed: boolean
    leakedEntities: number
    taggedOrphansBeforeCleanup: string[]
    cleanup: { removed: number; restored: number } | null
  } | null
  monorepo: {
    sastLinkRate: number | null
    sastLinked: number
    sastSuspects: number
    routeScale: { declared: number; persisted: number; retrieved: number; truncated: boolean }
    fourHopConfirmations: number
  } | null
  grade: {
    submitted: number
    truePositives: number
    falsePositives: number
    precision: number
    recall: number
    chains: ChainSummary[]
  } | null
  criteria: GateCriterion[]
}

const ASYNC_TRUTH_IDS = ['wan-blind-sqli', 'wan-ssrf-async', 'wan-xxe-async'] as const
const MONO_4HOP_IDS = ['mono-billing-bola', 'mono-report-sqli', 'mono-admin-bfla'] as const

function truePositiveIds(grade: GradeResult | null): Set<string> {
  const ids = new Set<string>()
  if (!grade) return ids
  for (const claim of grade.claims) {
    if (claim.kind === 'true_positive' && claim.matched) ids.add(claim.matched.id)
  }
  return ids
}

function routeCandidatePaths(path: string): string[] {
  const candidates = [path]
  if (path.startsWith('/idp/')) candidates.push(path.slice('/idp'.length))
  if (path.startsWith('/assets/')) candidates.push(path.slice('/assets'.length))
  return candidates
}

function routeDiscovered(route: RouteRef, endpoints: EndpointRow[]): boolean {
  const method = route.method?.toUpperCase()
  return endpoints.some(endpoint => {
    if (method && method !== 'ANY' && endpoint.method.toUpperCase() !== method) return false
    return routeCandidatePaths(route.path).some(path =>
      endpointMatches(path, endpoint.pathTemplate) || endpointMatches(endpoint.pathTemplate, path),
    )
  })
}

export function computeRouteDiscovery(routes: RouteRef[], endpoints: EndpointRow[]): RouteDiscovery {
  // Framework internals are not product routes: liveness probes, CORS preflight, catch-all
  // handlers and fixture-only test hooks would otherwise depress (or inflate) discovery.
  const declared = routes.filter(route => isGateRoute(route))
  let discovered = 0
  const missing: string[] = []
  for (const route of declared) {
    if (routeDiscovered(route, endpoints)) discovered += 1
    else missing.push(`${route.method} ${route.path}`)
  }
  return {
    discovered,
    total: declared.length,
    pct: declared.length === 0 ? 1 : discovered / declared.length,
    missing: missing.slice(0, 50),
  }
}

function isGateRoute(route: RouteRef): boolean {
  const path = route.path
  const method = route.method?.toUpperCase() ?? 'GET'
  if (!path || !path.startsWith('/') || path === '*') return false
  if (method === 'OPTIONS' || method === 'ANY') return false
  if (path.startsWith('/__realism__') || path.startsWith('/__collector__') || path.startsWith('/__staging__')) return false
  if (/\/health\/?$/.test(path)) return false
  return true
}

function stagingOrphans(fixture: StartedFixture): string[] {
  const extras = fixture as unknown as { orphans?: (runId?: string) => string[] }
  try { return extras.orphans?.() ?? [] } catch { return [] }
}

function wanCallbacks(fixture: StartedFixture): Record<string, boolean> {
  const extras = fixture as unknown as {
    collector?: { events: () => Array<{ kind: string }> }
  }
  try {
    const events = extras.collector?.events() ?? []
    const kinds = new Set(events.map(event => event.kind))
    return Object.fromEntries(['sqli', 'ssrf', 'xxe', 'webhook'].map(kind => [kind, kinds.has(kind)]))
  } catch {
    return {}
  }
}

function persistedEndpointCount(storage: Store, runId: string): number {
  try {
    const row = storage.client.prepare('select count(*) as c from endpoints where run_id = ?').get(runId) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  } catch {
    return 0
  }
}

export function computeMetrics(input: {
  fixture: string
  started: StartedFixture
  routes: RouteRef[]
  endpoints: EndpointRow[]
  findings: Finding[]
  endpointCounts: Map<string, number>
  submitted: SubmittedFinding[]
  grade: GradeResult | null
  storage: Store
  runId: string
}): RealismMetrics {
  const tp = truePositiveIds(input.grade)
  const chains: ChainSummary[] = (input.grade?.chains ?? []).map(chain => ({
    id: chain.id, total: chain.total, covered: chain.covered, complete: chain.complete,
  }))
  const grade = input.grade
    ? {
        submitted: input.grade.submitted,
        truePositives: input.grade.truePositives,
        falsePositives: input.grade.falsePositives,
        precision: input.grade.precision,
        recall: input.grade.recall,
        chains,
      }
    : null

  const metrics: RealismMetrics = {
    routeDiscovery: null,
    crossOriginAuthzConfirmed: false,
    storedXssConfirmed: false,
    browserExecutedStoredXss: false,
    oob: null,
    staging: null,
    monorepo: null,
    grade,
    criteria: [],
  }

  if (ENTERPRISE_ROUTES.has(input.fixture)) {
    metrics.routeDiscovery = computeRouteDiscovery(input.routes, input.endpoints)
    metrics.crossOriginAuthzConfirmed = tp.has('spa-graphql-bola') || tp.has('spa-admin-export-bfla')
    metrics.storedXssConfirmed = tp.has('spa-stored-xss-admin')
    const xssClaim = input.grade?.claims.find(claim => claim.kind === 'true_positive' && claim.matched?.id === 'spa-stored-xss-admin')
    const proofText = [xssClaim?.finding.title, ...(xssClaim?.finding.evidence ?? [])].join(' ')
    metrics.browserExecutedStoredXss = metrics.storedXssConfirmed
      && /browser|dom|playwright|rendered|script|session theft/i.test(proofText)
  }

  if (input.fixture === 'wan-oob') {
    const missedAsync = ASYNC_TRUTH_IDS.filter(id => !tp.has(id)).length
    metrics.oob = {
      blindSqliConfirmed: tp.has('wan-blind-sqli'),
      asyncSsrfConfirmed: tp.has('wan-ssrf-async'),
      asyncXxeConfirmed: tp.has('wan-xxe-async'),
      webhookForgeryConfirmed: tp.has('wan-webhook-forgery'),
      falseNegativeRate: missedAsync / ASYNC_TRUTH_IDS.length,
      fixtureCallbacks: wanCallbacks(input.started),
    }
  }

  if (STAGING_FIXTURES.has(input.fixture)) {
    metrics.staging = {
      writeBolaConfirmed: tp.has('stg-write-bola'),
      raceConfirmed: tp.has('stg-race-double-spend'),
      checkoutConfirmed: tp.has('stg-price-tampering'),
      // Filled after teardown/cleanup so the number is a post-cleanup observation.
      leakedEntities: -1,
      taggedOrphansBeforeCleanup: stagingOrphans(input.started).slice(0, 50),
      cleanup: null,
    }
  }

  if (input.fixture === 'monorepo-whitebox') {
    const suspects = input.findings.filter(finding => (finding.codeLocations?.length ?? 0) > 0)
    const linked = suspects.filter(finding => (input.endpointCounts.get(finding.id) ?? 0) > 0)
    const persisted = persistedEndpointCount(input.storage, input.runId)
    metrics.monorepo = {
      sastLinkRate: suspects.length === 0 ? null : linked.length / suspects.length,
      sastLinked: linked.length,
      sastSuspects: suspects.length,
      routeScale: {
        declared: input.routes.length,
        persisted,
        retrieved: input.endpoints.length,
        truncated: persisted > input.endpoints.length,
      },
      fourHopConfirmations: MONO_4HOP_IDS.filter(id => tp.has(id)).length,
    }
  }

  metrics.criteria = evaluateGate(input.fixture, metrics)
  return metrics
}

export function evaluateGate(fixture: string, metrics: RealismMetrics): GateCriterion[] {
  const chainComplete = (id: string): boolean =>
    metrics.grade?.chains.some(chain => chain.id === id && chain.complete) ?? false
  const criteria: GateCriterion[] = []

  if (ENTERPRISE_ROUTES.has(fixture)) {
    const discovery = metrics.routeDiscovery
    criteria.push({
      id: 'route-discovery-80',
      label: 'Route discovery >= 80% of declared fixture routes',
      required: true,
      met: (discovery?.pct ?? 0) >= 0.8,
      observed: discovery ? `${discovery.discovered}/${discovery.total} (${(discovery.pct * 100).toFixed(1)}%)` : 'not measured',
    })
    criteria.push({
      id: 'cross-origin-authz',
      label: 'Cross-origin/tenant authz confirmed',
      required: true,
      met: metrics.crossOriginAuthzConfirmed,
      observed: metrics.crossOriginAuthzConfirmed ? 'confirmed' : 'not confirmed',
    })
    criteria.push({
      id: 'stored-xss-browser',
      label: 'Browser-executed stored XSS confirmed',
      required: true,
      met: metrics.browserExecutedStoredXss,
      observed: metrics.storedXssConfirmed
        ? (metrics.browserExecutedStoredXss ? 'confirmed with browser evidence' : 'stored XSS matched but no browser execution evidence')
        : 'not confirmed',
    })
    criteria.push({
      id: 'chain-spa-admin-compromise',
      label: 'Chain spa-admin-compromise complete',
      required: true,
      met: chainComplete('spa-admin-compromise'),
      observed: metrics.grade?.chains.find(chain => chain.id === 'spa-admin-compromise')
        ? `${metrics.grade.chains.find(chain => chain.id === 'spa-admin-compromise')!.covered}/${metrics.grade.chains.find(chain => chain.id === 'spa-admin-compromise')!.total}`
        : 'not measured',
    })
  }

  if (fixture === 'wan-oob') {
    const oob = metrics.oob
    criteria.push(
      { id: 'blind-sqli', label: 'Blind SQLi confirmed', required: true, met: Boolean(oob?.blindSqliConfirmed), observed: String(Boolean(oob?.blindSqliConfirmed)) },
      { id: 'async-ssrf', label: 'Async SSRF confirmed', required: true, met: Boolean(oob?.asyncSsrfConfirmed), observed: String(Boolean(oob?.asyncSsrfConfirmed)) },
      { id: 'async-xxe', label: 'Async XXE confirmed', required: true, met: Boolean(oob?.asyncXxeConfirmed), observed: String(Boolean(oob?.asyncXxeConfirmed)) },
      {
        id: 'async-false-negative-rate',
        label: 'Async false-negative rate < 5%',
        required: true,
        met: oob?.falseNegativeRate !== null && oob?.falseNegativeRate !== undefined && oob.falseNegativeRate < 0.05,
        observed: oob?.falseNegativeRate === null || oob?.falseNegativeRate === undefined ? 'not measured' : `${(oob.falseNegativeRate * 100).toFixed(1)}%`,
      },
      {
        id: 'chain-wan-oob-exfil',
        label: 'Chain wan-oob-exfil complete',
        required: true,
        met: chainComplete('wan-oob-exfil'),
        observed: metrics.grade?.chains.find(chain => chain.id === 'wan-oob-exfil')
          ? `${metrics.grade.chains.find(chain => chain.id === 'wan-oob-exfil')!.covered}/${metrics.grade.chains.find(chain => chain.id === 'wan-oob-exfil')!.total}`
          : 'not measured',
      },
    )
  }

  if (STAGING_FIXTURES.has(fixture)) {
    const staging = metrics.staging
    criteria.push(
      { id: 'write-bola', label: 'Write-BOLA confirmed', required: true, met: Boolean(staging?.writeBolaConfirmed), observed: String(Boolean(staging?.writeBolaConfirmed)) },
      { id: 'h2-race', label: 'HTTP/2 double-spend race confirmed', required: true, met: Boolean(staging?.raceConfirmed), observed: String(Boolean(staging?.raceConfirmed)) },
      { id: 'checkout-tampering', label: 'Checkout price tampering confirmed', required: true, met: Boolean(staging?.checkoutConfirmed), observed: String(Boolean(staging?.checkoutConfirmed)) },
      {
        id: 'zero-leaked-entities',
        label: 'Zero leaked guardian-qa- entities after cleanup',
        required: true,
        met: staging?.leakedEntities === 0,
        observed: staging?.leakedEntities === -1 ? 'cleanup not measured' : `${staging?.leakedEntities ?? '?'} leaked`,
      },
      {
        id: 'chain-stg-tenant-takeover',
        label: 'Chain stg-tenant-takeover complete (informational; the explicit staging gate above is authoritative)',
        required: false,
        met: chainComplete('stg-tenant-takeover'),
        observed: metrics.grade?.chains.find(chain => chain.id === 'stg-tenant-takeover')
          ? `${metrics.grade.chains.find(chain => chain.id === 'stg-tenant-takeover')!.covered}/${metrics.grade.chains.find(chain => chain.id === 'stg-tenant-takeover')!.total}`
          : 'not measured',
      },
    )
  }

  if (fixture === 'monorepo-whitebox') {
    const mono = metrics.monorepo
    criteria.push(
      {
        id: 'sast-live-link-85',
        label: 'SAST-suspect -> live-endpoint link >= 85%',
        required: true,
        met: mono?.sastLinkRate !== null && mono?.sastLinkRate !== undefined && mono.sastLinkRate >= 0.85,
        observed: mono?.sastLinkRate === null || mono?.sastLinkRate === undefined
          ? `no SAST suspects (${mono?.sastSuspects ?? 0})`
          : `${(mono.sastLinkRate * 100).toFixed(1)}% (${mono.sastLinked}/${mono.sastSuspects})`,
      },
      {
        id: 'route-scale-no-truncation',
        label: '2,500-route scale ingested without endpoint truncation',
        required: true,
        met: Boolean(mono && !mono.routeScale.truncated && mono.routeScale.declared >= 2_500 && mono.routeScale.persisted >= 2_500),
        observed: mono ? `${mono.routeScale.persisted} persisted / ${mono.routeScale.retrieved} retrieved / ${mono.routeScale.declared} declared${mono.routeScale.truncated ? ' (TRUNCATED)' : ''}${mono.routeScale.persisted < 2_500 ? ' (UNDER 2,500)' : ''}` : 'not measured',
      },
      {
        id: 'four-hop-confirmations',
        label: 'At least two 4-hop sinks confirmed',
        required: true,
        met: (mono?.fourHopConfirmations ?? 0) >= 2,
        observed: `${mono?.fourHopConfirmations ?? 0}/3`,
      },
      {
        id: 'chain-mono-tenant-takeover',
        label: 'Chain mono-tenant-takeover complete',
        required: true,
        met: chainComplete('mono-tenant-takeover'),
        observed: metrics.grade?.chains.find(chain => chain.id === 'mono-tenant-takeover')
          ? `${metrics.grade.chains.find(chain => chain.id === 'mono-tenant-takeover')!.covered}/${metrics.grade.chains.find(chain => chain.id === 'mono-tenant-takeover')!.total}`
          : 'not measured',
      },
    )
  }

  return criteria
}

export function gatePassed(metrics: RealismMetrics): boolean {
  return metrics.criteria.filter(criterion => criterion.required).every(criterion => criterion.met)
}

export function classifyFailureStage(input: {
  terminalStatus: string
  timedOut: boolean
  interrupted: boolean
  endpoints: number
  findings: number
  vulnerabilityFindings: number
  submitted: number
  truePositives: number
  metrics: RealismMetrics
}): { stage: FailureStage; detail: string } {
  if (input.interrupted) return { stage: 'interrupted', detail: 'run interrupted by SIGINT/SIGTERM' }
  if (input.timedOut) return { stage: 'timeout', detail: 'wall-clock cap reached; run stopped' }
  if (input.terminalStatus === 'failed') return { stage: 'execution_failed', detail: 'Execution reported terminal status failed' }
  if (input.endpoints === 0) return { stage: 'discovery', detail: 'Execution persisted zero endpoints' }
  if (input.vulnerabilityFindings === 0) {
    return { stage: 'investigation', detail: `Execution persisted zero vulnerability findings (${input.findings} baseline/auxiliary rows)` }
  }
  if (input.submitted === 0) return { stage: 'verification_or_attribution', detail: 'findings persisted but none carried a concrete endpoint for grading' }
  if (input.truePositives === 0) return { stage: 'verification_or_attribution', detail: 'submitted findings matched no ground-truth endpoint' }
  if (!gatePassed(input.metrics)) {
    const unmet = input.metrics.criteria.filter(criterion => criterion.required && !criterion.met).map(criterion => criterion.id)
    return { stage: 'gate_incomplete', detail: `gate criteria unmet: ${unmet.join(', ')}` }
  }
  return { stage: 'passed', detail: 'all required gate criteria met' }
}

// ---------------------------------------------------------------------------------------------
// Run metadata / cell results
// ---------------------------------------------------------------------------------------------

// Known secret values observed this process, used only for the artifact scan (never written).
const OBSERVED_SECRETS: NamedSecret[] = []

export interface ShutdownState {
  engineBusy: number
  fixtureStopped: boolean
  canaryStopped: boolean
  stagingCleanup: { removed: number; restored: number } | null
  stagingOrphansAfterCleanup: string[]
  workspaceContainers: number | null
  dataDirRemoved: boolean
}

export interface SecretScanResult {
  clean: boolean
  files: string[]
  matches: Array<{ file: string; kind: string }>
}

export interface RealismMeta {
  fixture: string
  mode: BenchMode
  noLlm: boolean
  model: ModelInfo
  verifierBackend: VerifierBackendKind
  workerSessions: boolean
  workerSessionsDetail: string
  seed: number
  targetOrigin: string
  origins: Record<string, string>
  hosts: Record<string, string>
  personaCount: number
  gitSha: string
  budgetUsd: number
  maxDurationMs: number
  dataDirIsolated: boolean
  dataDirSource: string | null
  startedAt: number
  endedAt: number
  durationMs: number
  timedOut: boolean
  interrupted: boolean
  terminalStatus: string
  terminalPhase: string
  runId: string
  projectId: string
  endpointsDiscovered: number
  declaredRoutes: number
  findingsPersisted: number
  vulnerabilityFindings: number
  findingsSubmitted: number
  facts: number
  brokerExchanges: number
  tenantTag: string
  notes: string[]
  shutdown: ShutdownState
  failureStage: FailureStage
  failureDetail: string
  gatePassed: boolean
}

export interface RealismCellResult {
  fixture: string
  mode: BenchMode
  noLlm: boolean
  passed: boolean
  failureStage: FailureStage
  failureDetail: string
  grade: GradeResult | null
  metrics: RealismMetrics
  meta: RealismMeta
  findingsFile: string | null
  error: string | null
}

export interface RealismSummary {
  suite: 'guardian-realism-gates'
  generatedAt: number
  gitSha: string
  mode: BenchMode
  noLlm: boolean
  cells: RealismCellResult[]
  passed: number
  failed: number
  secretScan: SecretScanResult
}

function resolveGitSha(): string {
  try {
    return process.env.GUARDIAN_GIT_SHA
      ?? execFileSyncText('git', ['rev-parse', 'HEAD']).trim().slice(0, 40)
  } catch {
    return 'unknown'
  }
}

function execFileSyncText(file: string, args: string[]): string {
  // Synchronous only for tiny, local, non-secret commands (git rev-parse).
  return execFileSync(file, args, { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] })
}

function emptyMetrics(): RealismMetrics {
  return {
    routeDiscovery: null,
    crossOriginAuthzConfirmed: false,
    storedXssConfirmed: false,
    browserExecutedStoredXss: false,
    oob: null,
    staging: null,
    monorepo: null,
    grade: null,
    criteria: [],
  }
}

function cellSlug(args: RealismArgs, fixture: string): string {
  return `${fixture}-${args.mode}${args.noLlm ? '-no-llm' : ''}`
}

// ---------------------------------------------------------------------------------------------
// Cell execution
// ---------------------------------------------------------------------------------------------

interface CellContext {
  args: RealismArgs
  fixture: string
  slug: string
  startedAt: number
  storage?: Store
  started?: StartedFixture
  engine?: Execution
  backend?: WorkerBackend
  backendKind: VerifierBackendKind
  model: ModelInfo
  workerSessions: boolean
  workerSessionsDetail: string
  canary?: CanaryBroker
  canaryStopped: boolean
  dataDir: string
  dataDirIsolated: boolean
  dataDirSource: string | null
  whiteBoxRoot?: string
  projectId: string
  runId: string
  personaCount: number
  secrets: NamedSecret[]
  notes: string[]
}

async function waitForTerminal(input: {
  storage: Store
  runId: string
  deadlineAt: number
  signal: AbortSignal
  onTick: (status: string, phase: string) => void
}): Promise<{ timedOut: boolean; interrupted: boolean; status: string; phase: string }> {
  const terminal = new Set(['complete', 'failed', 'stopped', 'paused', 'budget_paused'])
  let last = 0
  while (true) {
    const run = input.storage.run(input.runId)
    if (terminal.has(run.status)) {
      return { timedOut: false, interrupted: input.signal.aborted, status: run.status, phase: run.phase }
    }
    if (input.signal.aborted) {
      try { input.storage.command({ requestId: randomUUID(), runId: input.runId, action: 'stop' }) } catch { /* terminal */ }
      return { timedOut: false, interrupted: true, status: input.storage.run(input.runId).status, phase: input.storage.run(input.runId).phase }
    }
    if (Date.now() >= input.deadlineAt) {
      try { input.storage.command({ requestId: randomUUID(), runId: input.runId, action: 'stop' }) } catch { /* terminal */ }
      const after = input.storage.run(input.runId)
      return { timedOut: true, interrupted: false, status: after.status, phase: after.phase }
    }
    if (Date.now() - last > 5_000) {
      last = Date.now()
      input.onTick(run.status, run.phase)
    }
    await delay(200)
  }
}

function lockDown(dir: string): void {
  for (const entry of readdirSync(dir)) {
    const child = join(dir, entry)
    try {
      if (lstatSync(child).isDirectory()) lockDown(child)
      else chmodSync(child, 0o444)
    } catch { /* best-effort */ }
  }
  chmodSync(dir, 0o555)
}

function unlockAndRemove(dir: string): void {
  try {
    chmodSync(dir, 0o700)
    for (const entry of readdirSync(dir)) {
      const child = join(dir, entry)
      if (lstatSync(child).isDirectory()) unlockAndRemove(child)
    }
  } catch { /* best-effort */ }
  rmSync(dir, { recursive: true, force: true })
}

async function workspaceContainers(cell: string | undefined): Promise<number | null> {
  if (!cell || process.env.GUARDIAN_REALISM_SKIP_DOCKER_ORPHAN_CHECK === '1') return null
  return new Promise(resolvePromise => {
    execFile('docker', ['ps', '-q', '--filter', `label=dev.guardian.cell=${cell}`], { timeout: 8_000 }, (error, stdout) => {
      if (error) { resolvePromise(null); return }
      resolvePromise(String(stdout).split('\n').filter(Boolean).length)
    })
  })
}

async function tearDown(ctx: CellContext, signal: AbortSignal): Promise<ShutdownState> {
  let engineBusy = -1
  let fixtureStopped = false
  let canaryStopped = false
  let stagingCleanup: { removed: number; restored: number } | null = null
  let stagingOrphansAfterCleanup: string[] = []
  let dataDirRemoved = false

  if (ctx.engine) {
    try { engineBusy = await stopEngine(ctx.engine) } catch { engineBusy = -1 }
    // Execution.stop() aborts lanes but does not close the Playwright pool; leaving it open
    // keeps chrome-headless-shell alive and the Node event loop spinning after artifacts.
    try { await ctx.engine.browser.close() } catch { /* pool already closed */ }
  }
  // Staging cleanup happens after Execution is stopped (no in-flight writes) and before
  // the fixture tears down its own store, so the orphan check observes post-cleanup state.
  if (ctx.fixture === 'staging-concurrency' && ctx.started && ctx.runId) {
    const extras = ctx.started as unknown as {
      cleanup?: (runId: string) => { removed: number; restored: number }
      orphans?: (runId?: string) => string[]
    }
    try {
      stagingCleanup = extras.cleanup?.(ctx.runId) ?? null
    } catch (error) {
      ctx.notes.push(`staging cleanup failed: ${redact((error as Error).message).slice(0, 160)}`)
    }
    try { stagingOrphansAfterCleanup = extras.orphans?.() ?? [] } catch { stagingOrphansAfterCleanup = [] }
  }
  if (ctx.backend instanceof LinuxWorkerBackend) {
    try { await ctx.backend.reclaimInactive() } catch { /* best-effort */ }
  }
  if (ctx.canary) {
    try { await ctx.canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
  }
  if (ctx.started) {
    try { await ctx.started.stop(); fixtureStopped = true } catch { fixtureStopped = false }
  }
  if (ctx.whiteBoxRoot) {
    try { unlockAndRemove(ctx.whiteBoxRoot) } catch { /* best-effort */ }
  }
  if (ctx.storage) {
    try { ctx.storage.close() } catch { /* already closed */ }
  }
  if (ctx.dataDirIsolated && !ctx.args.keepDataDirs) {
    try { unlockAndRemove(ctx.dataDir); dataDirRemoved = true } catch { /* best-effort */ }
  }
  if (signal.aborted) ctx.notes.push('teardown after interrupt: engine, canary and fixture stopped')
  const containers = ctx.backendKind === 'docker' ? await workspaceContainers(ctx.slug) : 0
  return {
    engineBusy,
    fixtureStopped: !ctx.started || fixtureStopped,
    canaryStopped: !ctx.canary || canaryStopped,
    stagingCleanup,
    stagingOrphansAfterCleanup,
    workspaceContainers: containers,
    dataDirRemoved,
  }
}

export async function runCell(args: RealismArgs, fixtureName: string, signal: AbortSignal, log: (line: string) => void): Promise<RealismCellResult> {
  const startedAt = Date.now()
  const slug = cellSlug(args, fixtureName)
  const notes: string[] = []
  const secrets: NamedSecret[] = []
  const ctx: CellContext = {
    args, fixture: fixtureName, slug, startedAt,
    backendKind: 'local-jq', model: { mode: 'deterministic-no-llm', profiles: [] },
    workerSessions: false, workerSessionsDetail: 'not probed', canaryStopped: false,
    dataDir: '', dataDirIsolated: false, dataDirSource: null,
    projectId: '', runId: '', personaCount: 0, secrets, notes,
  }
  let detailEndpoints: EndpointRow[] = []
  let detailFindings: Finding[] = []
  let submitted: SubmittedFinding[] = []
  let grade: GradeResult | null = null
  let metrics: RealismMetrics = emptyMetrics()
  let terminalStatus = 'not_started'
  let terminalPhase = 'unknown'
  let timedOut = false
  let interrupted = false
  let endpointCounts = new Map<string, number>()
  let vulnerabilityFindings = 0
  let engineSummaryText = ''
  let stageReached: 'preflight' | 'fixture' | 'execution' | 'grading' = 'preflight'
  let failure: unknown
  let routes: RouteRef[] = []
  let facts = 0
  let exchanges = 0
  let capturedOrigins: Record<string, string> = {}
  let capturedHosts: Record<string, string> = {}
  let targetOriginLabel = ''

  try {
    // --- Data dir (--no-llm never inherits a model-enabled directory) -----------------------
    const sourceDataDir = args.noLlm ? undefined : args.dataDir
    let dataDir = join(args.outDir, 'data', slug)
    let isolated = false
    const isolate = Boolean(sourceDataDir)
    if (sourceDataDir && isolate) {
      const prepared = prepareIsolatedDataDir({ sourceDataDir, targetDir: dataDir })
      isolated = true
      notes.push(`isolated data dir from ${prepared.source}; profile(s): ${prepared.profileNames.join(', ')}; credentials symlinked (key not copied)`)
    } else if (sourceDataDir) {
      dataDir = args.fixtures.length === 1 ? sourceDataDir : join(sourceDataDir, slug)
    }
    ctx.dataDir = dataDir
    ctx.dataDirIsolated = isolated
    ctx.dataDirSource = isolated ? sourceDataDir ?? null : null
    mkdirSync(dataDir, { recursive: true, mode: 0o700 })
    mkdirSync(args.outDir, { recursive: true, mode: 0o700 })
    const storage = openCellStore(dataDir)
    ctx.storage = storage

    // --- Preflight: model mode, verifier backend, worker-session capability -----------------
    let profiles: ReturnType<typeof privateModelProfiles> = []
    try { profiles = privateModelProfiles(storage) } catch (error) {
      notes.push(`model profile lookup failed: ${redact((error as Error).message).slice(0, 160)}`)
    }
    if (args.noLlm) notes.push('--no-llm: model profiles ignored; isolated deterministic data dir')
    const model = describeModelMode(args.noLlm ? [] : profiles)
    ctx.model = model
    notes.push(model.mode === 'agentic'
      ? `agentic model profile(s): ${model.profiles.map(profile => profile.model).join(', ')}`
      : 'no model profile configured: deterministic Zero-LLM path')

    const selected = await selectVerifierBackend(args.verifier)
    ctx.backendKind = selected.kind
    ctx.backend = selected.kind === 'docker'
      ? new LinuxWorkerBackend({ workspace: { id: storage.workspace.id, directory: storage.directory }, cell: slug })
      : selected.backend
    const capability = model.mode === 'agentic'
      ? await detectWorkerSessions(ctx.backend)
      : { supported: false, detail: 'not required for --no-llm' }
    ctx.workerSessions = capability.supported
    ctx.workerSessionsDetail = capability.detail
    assertAgenticPreflight({
      hasProfiles: model.mode === 'agentic',
      noLlm: args.noLlm,
      allowInertWorkers: false,
      backendKind: ctx.backendKind,
      workerSessions: capability.supported,
      workerSessionsDetail: capability.detail,
    })
    notes.push(`verifier backend ${ctx.backendKind}; workerSessions=${capability.supported}${capability.supported ? '' : ` (${capability.detail})`}`)

    const canary = new CanaryBroker({ storage })
    ctx.canary = canary
    await canary.startListener({ host: '127.0.0.1', port: 0 })

    // --- Boot the fixture ------------------------------------------------------------------
    const startOptions: FixtureStartOptions = { seed: args.seed }
    if (fixtureName === 'wan-oob') startOptions.callbackDelayMs = args.callbackDelayMs
    if (fixtureName === 'monorepo-whitebox' && args.keepSource) startOptions.keepSource = true
    stageReached = 'fixture'
    ctx.started = await startFixture(fixtureName, startOptions)
    const started = ctx.started
    routes = started.routes ?? []
    capturedOrigins = started.origins
    capturedHosts = started.hosts
    const briefing = briefingFor(started)
    for (const persona of briefing.personas) {
      if (persona.password.length >= 4) {
        secrets.push({ value: persona.password, placeholder: '[[persona-password]]' })
        OBSERVED_SECRETS.push({ value: persona.password, placeholder: '[[persona-password]]' })
      }
      if (persona.token && persona.token.length >= 8) {
        secrets.push({ value: persona.token, placeholder: '[[persona-token]]' })
        OBSERVED_SECRETS.push({ value: persona.token, placeholder: '[[persona-token]]' })
      }
    }
    log(`[${slug}] fixture up: ${Object.entries(started.origins).map(([label, url]) => `${label}=${url}`).join(' ')}`)

    const browserCookie = (started as unknown as BrowserCookieSource).browserCookie
      ? (started as unknown as { browserCookie: (id: string) => string }).browserCookie.bind(started)
      : undefined
    const plan = planCell({
      fixture: fixtureName,
      briefing: { origins: briefing.origins, api: briefing.api, personas: briefing.personas, ...(started.sourceDir ? { sourceDir: started.sourceDir } : {}) },
      mode: args.mode,
      ...(args.targetOrigin ? { targetOrigin: args.targetOrigin } : {}),
      ...(browserCookie ? { browserCookie } : {}),
    })
    ctx.personaCount = plan.personas.length
    targetOriginLabel = plan.primaryLabel
    notes.push(`scope: ${Object.entries(plan.scopes).map(([label, role]) => `${label}=${role}`).join(', ')}; primary=${plan.primaryLabel}`)

    // --- Project, specs, personas, run -----------------------------------------------------
    const project = storage.createProject({
      requestId: randomUUID(),
      name: `realism ${fixtureName} seed ${args.seed} (${args.mode})`,
      seeds: [...new Set(Object.values(briefing.origins).map(normalizeOrigin))],
      environment: 'local-lab',
    })
    ctx.projectId = project.id

    if (args.mode !== 'black-box') {
      for (const label of Object.keys(briefing.origins)) {
        const doc = briefingToOpenApi({ fixture: fixtureName, originLabel: label, api: briefing.api })
        if (!doc) continue
        storage.importProjectSpec({
          requestId: randomUUID(),
          projectId: project.id,
          name: `realism-${fixtureName}-${label}.json`,
          kind: 'openapi',
          origin: briefing.origins[label]!,
          content: JSON.stringify(doc, null, 2),
        })
      }
    }

    if (args.mode === 'white-box' && started.sourceDir) {
      const repoRoot = join(projectReposDir(dataDir, project.id), 'bench', fixtureName)
      mkdirSync(join(repoRoot, '..'), { recursive: true, mode: 0o700 })
      if (existsSync(repoRoot)) unlockAndRemove(repoRoot)
      cpSync(started.sourceDir, repoRoot, { recursive: true })
      lockDown(repoRoot)
      ctx.whiteBoxRoot = repoRoot
      notes.push(`white-box read-only source mount: /repos/bench/${fixtureName}`)
    }

    const personaIds: string[] = []
    for (const planned of plan.personas) {
      try {
        const created = createProjectPersona(storage, {
          requestId: randomUUID(),
          projectId: project.id,
          handle: planned.handle,
          roleLabel: planned.roleLabel,
          originAllowlist: Object.values(briefing.origins).map(normalizeOrigin),
          authKind: planned.authKind,
          secret: planned.secret,
          canaryMarkers: planned.canaryMarkers,
        })
        personaIds.push(created.id)
        secrets.push({ value: planned.secret, placeholder: planned.authKind === 'cookie' ? '[[persona-cookie]]' : '[[persona-token]]' })
        OBSERVED_SECRETS.push({ value: planned.secret, placeholder: planned.authKind === 'cookie' ? '[[persona-cookie]]' : '[[persona-token]]' })
      } catch (error) {
        notes.push(`persona ${planned.handle} skipped: ${redact((error as Error).message).slice(0, 120)}`)
      }
    }
    notes.push(`personas: ${personaIds.length}/${plan.personas.length} created`)

    const createdRun = storage.createRun({
      requestId: randomUUID(),
      projectId: project.id,
      goal: plan.mission,
      sourceMode: 'public',
      capabilityTier: plan.capabilityTier,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: personaIds,
      budgetUsd: args.budgetUsd,
      budgetRequests: 2_000,
      maxRpsPerOrigin: 10,
      workerConcurrency: 2,
      workerMaxTurns: 30,
      multiTrialEnabled: true,
    })
    ctx.runId = createdRun.id
    const environmentMode: EnvironmentMode = STAGING_FIXTURES.has(fixtureName) ? 'staging_isolated' : 'ephemeral_lab'
    storage.setEnvironmentMode(storage.run(createdRun.id), environmentMode)
    notes.push(`environmentMode=${environmentMode}; tenantTag=${tenantTagForRun(createdRun.id)}`)

    storage.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
    const candidates = storage.run(createdRun.id).candidates
    if (!candidates.length) fail('discovery produced no candidate assets for the fixture origins')
    const targetOrigins = new Set(
      Object.entries(plan.scopes)
        .filter(([, role]) => role === 'target')
        .map(([label]) => normalizeOrigin(briefing.origins[label]!)),
    )
    const assetIds = candidates.filter(candidate => targetOrigins.has(normalizeOrigin(candidate.origin))).map(candidate => candidate.id)
    if (!assetIds.length) fail(`no discovered candidate matched the target origins (${[...targetOrigins].join(', ')})`)
    storage.command({
      requestId: randomUUID(),
      runId: createdRun.id,
      action: 'scope',
      expectedScopeRevision: 0,
      assetIds,
      consent: true,
      capabilityTier: plan.capabilityTier,
      approvedPersonaIds: personaIds,
      budgetUsd: args.budgetUsd,
      budgetRequests: 2_000,
      maxRpsPerOrigin: 10,
    })
    for (const [label, role] of Object.entries(plan.scopes)) {
      if (role === 'target') continue
      try {
        storage.setOriginRole(storage.run(createdRun.id), normalizeOrigin(briefing.origins[label]!), role)
      } catch (error) {
        notes.push(`scope role ${label}=${role} failed: ${redact((error as Error).message).slice(0, 140)}`)
      }
    }

    // --- Real Execution --------------------------------------------------------------------
    const engine = new Execution(storage, {
      canaryBroker: canary,
      ...(ctx.backend ? { backend: ctx.backend } : {}),
      deterministicOnly: args.noLlm,
    })
    ctx.engine = engine
    engine.start()
    engine.wake()
    stageReached = 'execution'

    const waited = await waitForTerminal({
      storage,
      runId: createdRun.id,
      deadlineAt: startedAt + args.maxDurationMs,
      signal,
      onTick: (status, phase) => log(`[${slug}] ${status}/${phase}`),
    })
    terminalStatus = waited.status
    terminalPhase = waited.phase
    timedOut = waited.timedOut
    interrupted = waited.interrupted
    stageReached = 'grading'
    if (timedOut) notes.push(`wall-clock cap reached after ${args.maxDurationMs}ms; run stopped`)
    if (interrupted) notes.push('interrupted by signal; run stopped')

    const detail = storage.runDetail(createdRun.id)
    detailEndpoints = detail.endpoints
    detailFindings = detail.findings
    vulnerabilityFindings = detail.findings.filter(finding => finding.findingKind !== 'baseline_check' && finding.status !== 'dismissed').length
    facts = detail.facts.length
    exchanges = detail.exchangesSummary.length
    const deterministicSummary = (() => {
      try {
        return storage.client.prepare(
          "select message from events where run_id = ? and kind = 'deterministic_engine.summary' order by id desc limit 1",
        ).get(createdRun.id) as { message?: string } | undefined
      } catch {
        return undefined
      }
    })()
    if (deterministicSummary?.message) {
      engineSummaryText = redact(deterministicSummary.message, secrets).slice(0, 240)
      notes.push(engineSummaryText)
    }
    const finalRun = storage.run(createdRun.id)
    const translated = translateFindings({
      findings: detail.findings,
      replaySpecs: detail.replaySpecs.map(spec => ({ id: spec.id, findingId: spec.findingId, spec: spec.spec, createdAt: spec.createdAt })),
      exchanges: detail.exchangesSummary.map(exchange => ({ id: exchange.id, method: exchange.method, pathAndQuery: exchange.pathAndQuery })),
      origins: briefing.origins,
      secrets,
    })
    submitted = translated.findings
    endpointCounts = translated.endpointCounts
    grade = gradeFindings(loadTruth(fixtureName), submitted)
    metrics = computeMetrics({
      fixture: fixtureName,
      started,
      routes,
      endpoints: detailEndpoints,
      findings: detailFindings,
      endpointCounts,
      submitted,
      grade,
      storage,
      runId: createdRun.id,
    })
    log(`[${slug}] ${terminalStatus}/${terminalPhase}: ${detailEndpoints.length} endpoints, ${detailFindings.length} findings, `
      + `${grade.truePositives} TP / ${grade.falsePositives} FP`)
    if (!['complete', 'stopped'].includes(terminalStatus)) notes.push(`terminal status ${terminalStatus}/${terminalPhase}`)
  } catch (error) {
    failure = error
    ctx.notes.push(`run failed at harness stage: ${redact(error instanceof Error ? error.message : String(error)).slice(0, 240)}`)
  } finally {
    const shutdown = await tearDown(ctx, signal)
    ctx.storage = undefined
    ctx.started = undefined
    ctx.engine = undefined
    ctx.backend = undefined
    ctx.canary = undefined
    ctx.whiteBoxRoot = undefined

    if (ctx.fixture === 'staging-concurrency') {
      if (!metrics.staging) metrics.staging = {
        writeBolaConfirmed: false, raceConfirmed: false, checkoutConfirmed: false,
        leakedEntities: -1, taggedOrphansBeforeCleanup: [], cleanup: null,
      }
      // Cleanup ran before fixture.stop(); `tearDown` captured both the cleanup result and
      // the post-cleanup orphan scan. Anything left is a real staging-safety regression.
      metrics.staging.cleanup = shutdown.stagingCleanup
      metrics.staging.leakedEntities = shutdown.stagingOrphansAfterCleanup.length
      if (shutdown.stagingCleanup) {
        ctx.notes.push(`staging cleanup: ${shutdown.stagingCleanup.removed} removed, ${shutdown.stagingCleanup.restored} restored`)
      }
      if (shutdown.stagingOrphansAfterCleanup.length > 0) {
        ctx.notes.push(`staging orphan check: ${shutdown.stagingOrphansAfterCleanup.length} guardian-qa- record(s) remain`)
      }
    }
    metrics.criteria = evaluateGate(ctx.fixture, metrics)
    if (shutdown.engineBusy > 0) ctx.notes.push(`warning: ${shutdown.engineBusy} execution task(s) still active after stop`)
    if (!shutdown.fixtureStopped) ctx.notes.push('warning: fixture did not report a clean stop')
    if (shutdown.workspaceContainers && shutdown.workspaceContainers > 0) {
      ctx.notes.push(`warning: ${shutdown.workspaceContainers} worker container(s) remain for cell ${slug}`)
    }

    const classified = classifyFailureStage({
      terminalStatus, timedOut, interrupted,
      endpoints: detailEndpoints.length,
      findings: detailFindings.length,
      vulnerabilityFindings,
      submitted: submitted.length,
      truePositives: grade?.truePositives ?? 0,
      metrics,
    })
    const failureStage: FailureStage = failure
      ? (stageReached === 'preflight'
          ? 'execution_preflight'
          : stageReached === 'fixture'
            ? 'fixture_start'
            : stageReached === 'grading'
              ? 'verification_or_attribution'
              : 'execution_failed')
      : classified.stage
    const detailText = failure
      ? redact(failure instanceof Error ? failure.message : String(failure), secrets).slice(0, 300)
      : (engineSummaryText && classified.stage !== 'passed'
          ? `${classified.detail}; ${engineSummaryText}`
          : classified.detail)
    const passed = !failure && gatePassed(metrics)
    const endedAt = Date.now()
    const meta: RealismMeta = {
      fixture: fixtureName,
      mode: args.mode,
      noLlm: args.noLlm,
      model: ctx.model,
      verifierBackend: ctx.backendKind,
      workerSessions: ctx.workerSessions,
      workerSessionsDetail: ctx.workerSessionsDetail,
      seed: args.seed,
      targetOrigin: targetOriginLabel,
      origins: capturedOrigins,
      hosts: capturedHosts,
      personaCount: ctx.personaCount,
      gitSha: resolveGitSha(),
      budgetUsd: args.budgetUsd,
      maxDurationMs: args.maxDurationMs,
      dataDirIsolated: ctx.dataDirIsolated,
      dataDirSource: ctx.dataDirSource,
      startedAt,
      endedAt,
      durationMs: endedAt - startedAt,
      timedOut,
      interrupted,
      terminalStatus,
      terminalPhase,
      runId: ctx.runId,
      projectId: ctx.projectId,
      endpointsDiscovered: detailEndpoints.length,
      declaredRoutes: routes.length,
      findingsPersisted: detailFindings.length,
      vulnerabilityFindings,
      findingsSubmitted: submitted.length,
      facts,
      brokerExchanges: exchanges,
      tenantTag: ctx.runId ? tenantTagForRun(ctx.runId) : '',
      notes: ctx.notes,
      shutdown,
      failureStage,
      failureDetail: detailText,
      gatePassed: passed,
    }

    // Artifacts are written from a redacted copy; the raw secret list never leaves memory.
    const safeFindings = redactJsonValue(submitted, secrets)
    const findingsFile = join(args.outDir, `${slug}.findings.json`)
    const result: RealismCellResult = {
      fixture: fixtureName,
      mode: args.mode,
      noLlm: args.noLlm,
      passed,
      failureStage,
      failureDetail: detailText,
      grade: grade ? redactJsonValue(grade, secrets) : null,
      metrics,
      meta,
      findingsFile,
      error: failure ? detailText : null,
    }
    writeFileSync(findingsFile, `${JSON.stringify(safeFindings, null, 2)}\n`, { mode: 0o600 })
    writeFileSync(join(args.outDir, `${slug}.meta.json`), `${JSON.stringify(redactJsonValue(meta, secrets), null, 2)}\n`, { mode: 0o600 })
    writeFileSync(join(args.outDir, `${slug}.json`), `${JSON.stringify(redactJsonValue(result, secrets), null, 2)}\n`, { mode: 0o600 })
    writeFileSync(join(args.outDir, `${slug}.md`), `${renderCellMarkdown(redactJsonValue(result, secrets))}\n`, { mode: 0o600 })
    metrics.criteria = evaluateGate(fixtureName, metrics)
    return redactJsonValue(result, secrets)
  }
}

// ---------------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------------

function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

function chainLine(id: string, chains: ChainSummary[]): string {
  const chain = chains.find(entry => entry.id === id)
  return chain ? `${chain.covered}/${chain.total}${chain.complete ? ' complete' : ''}` : 'n/a'
}

export function renderCellMarkdown(result: RealismCellResult): string {
  const lines: string[] = []
  const chains = result.metrics.grade?.chains ?? []
  lines.push(`# Realism gate — ${result.fixture}`)
  lines.push('')
  lines.push(`- mode: \`${result.mode}\`${result.noLlm ? ' (`--no-llm` deterministic floor)' : ' (agentic)'}`)
  lines.push(`- result: **${result.passed ? 'PASS' : 'FAIL'}** — failure stage \`${result.failureStage}\``)
  lines.push(`- detail: ${result.failureDetail}`)
  lines.push(`- terminal: ${result.meta.terminalStatus}/${result.meta.terminalPhase}; duration ${(result.meta.durationMs / 1000).toFixed(1)}s`)
  lines.push(`- endpoints: ${result.meta.endpointsDiscovered}; facts: ${result.meta.facts}; broker exchanges: ${result.meta.brokerExchanges}`)
  lines.push(`- findings: ${result.meta.findingsPersisted} persisted (${result.meta.vulnerabilityFindings} vulnerability) / ${result.meta.findingsSubmitted} submitted`)
  lines.push('')
  lines.push('## Gate criteria')
  lines.push('')
  lines.push('| criterion | required | met | observed |')
  lines.push('| --- | --- | --- | --- |')
  for (const criterion of result.metrics.criteria) {
    lines.push(`| ${criterion.label} | ${criterion.required ? 'yes' : 'no'} | ${criterion.met ? 'yes' : 'no'} | ${criterion.observed} |`)
  }
  if (result.metrics.routeDiscovery) {
    const discovery = result.metrics.routeDiscovery
    lines.push('')
    lines.push(`## Route discovery — ${discovery.discovered}/${discovery.total} (${(discovery.pct * 100).toFixed(1)}%)`)
    if (discovery.missing.length) {
      lines.push('')
      lines.push('Missing (first 50):')
      for (const route of discovery.missing) lines.push(`- \`${route}\``)
    }
  }
  if (result.metrics.oob) {
    const oob = result.metrics.oob
    lines.push('')
    lines.push('## WAN / async OOB')
    lines.push('')
    lines.push(`- blind SQLi: ${oob.blindSqliConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- async SSRF: ${oob.asyncSsrfConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- async XXE: ${oob.asyncXxeConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- webhook forgery: ${oob.webhookForgeryConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- async false-negative rate: ${pct(oob.falseNegativeRate)}`)
    lines.push(`- fixture-side callbacks observed: ${Object.entries(oob.fixtureCallbacks).filter(([, hit]) => hit).map(([kind]) => kind).join(', ') || 'none'}`)
  }
  if (result.metrics.staging) {
    const staging = result.metrics.staging
    lines.push('')
    lines.push('## Staging safety')
    lines.push('')
    lines.push(`- write-BOLA: ${staging.writeBolaConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- HTTP/2 race: ${staging.raceConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- checkout tampering: ${staging.checkoutConfirmed ? 'confirmed' : 'not confirmed'}`)
    lines.push(`- leaked \`guardian-qa-\` entities after cleanup: ${staging.leakedEntities}`)
    lines.push(`- cleanup: ${staging.cleanup ? `${staging.cleanup.removed} removed, ${staging.cleanup.restored} restored` : 'not run'}`)
  }
  if (result.metrics.monorepo) {
    const mono = result.metrics.monorepo
    lines.push('')
    lines.push('## Monorepo white-box')
    lines.push('')
    lines.push(`- SAST suspects: ${mono.sastSuspects}; linked to live endpoints: ${mono.sastLinked} (${pct(mono.sastLinkRate)})`)
    lines.push(`- route scale: declared ${mono.routeScale.declared}; persisted ${mono.routeScale.persisted}; retrieved ${mono.routeScale.retrieved}; truncated=${mono.routeScale.truncated}`)
    lines.push(`- 4-hop confirmations: ${mono.fourHopConfirmations}/3`)
  }
  if (result.grade) {
    lines.push('')
    lines.push('## Grading')
    lines.push('')
    lines.push(`submitted=${result.grade.submitted} tp=${result.grade.truePositives} fp=${result.grade.falsePositives} precision=${pct(result.grade.submitted ? result.grade.precision : null)} recall=${pct(result.grade.recall)}`)
    if (result.grade.claims.length) {
      lines.push('')
      lines.push('| claim | endpoint | matched | reason |')
      lines.push('| --- | --- | --- | --- |')
      for (const claim of result.grade.claims) {
        lines.push(`| ${claim.kind} | \`${claim.finding.method ?? 'ANY'} ${claim.finding.endpoint}\` | ${claim.matched?.id ?? '—'} | ${claim.reason} |`)
      }
    }
    if (result.grade.missed.length) {
      lines.push('')
      lines.push('Missed truth findings:')
      for (const missed of result.grade.missed) lines.push(`- \`${missed.id}\` ${missed.method ?? 'ANY'} ${missed.endpoint}`)
    }
    if (chains.length) {
      lines.push('')
      lines.push('Chains:')
      for (const chain of chains) lines.push(`- \`${chain.id}\`: ${chain.covered}/${chain.total}${chain.complete ? ' complete' : ''}`)
    }
  }
  lines.push('')
  lines.push('## Shutdown / orphans')
  lines.push('')
  lines.push(`- engine tasks remaining: ${result.meta.shutdown.engineBusy}`)
  lines.push(`- fixture stopped cleanly: ${result.meta.shutdown.fixtureStopped}`)
  lines.push(`- canary stopped cleanly: ${result.meta.shutdown.canaryStopped}`)
  lines.push(`- staging orphans after cleanup: ${result.meta.shutdown.stagingOrphansAfterCleanup.length}`)
  lines.push(`- worker containers remaining: ${result.meta.shutdown.workspaceContainers ?? 'not probed'}`)
  lines.push('')
  lines.push('## Notes')
  lines.push('')
  for (const note of result.meta.notes) lines.push(`- ${note}`)
  return lines.join('\n')
}

function renderSummaryMarkdown(summary: RealismSummary): string {
  const lines: string[] = []
  lines.push('# Realism exit gates')
  lines.push('')
  lines.push(`- mode: \`${summary.mode}\`${summary.noLlm ? ' (`--no-llm`)' : ' (agentic)'}`)
  lines.push(`- git: \`${summary.gitSha}\`; generated: ${new Date(summary.generatedAt).toISOString()}`)
  lines.push(`- fixtures: ${summary.passed} gate pass / ${summary.failed} not passing`)
  lines.push(`- artifact secret scan: ${summary.secretScan.clean ? 'clean' : 'FAILED'}`)
  lines.push('')
  lines.push('| fixture | gate | stage | TP | FP | precision | recall | chains |')
  lines.push('| --- | --- | --- | --- | --- | --- | --- | --- |')
  for (const cell of summary.cells) {
    const grade = cell.metrics.grade
    const chains = grade ? grade.chains.filter(chain => chain.complete).length : 0
    const chainTotal = grade?.chains.length ?? 0
    lines.push(`| ${cell.fixture} | ${cell.passed ? 'PASS' : 'FAIL'} | \`${cell.failureStage}\` | ${grade?.truePositives ?? 'n/a'} | ${grade?.falsePositives ?? 'n/a'} | ${pct(grade && grade.submitted ? grade.precision : null)} | ${pct(grade?.recall)} | ${chains}/${chainTotal} |`)
  }
  lines.push('')
  for (const cell of summary.cells) {
    lines.push(`## ${cell.fixture}`)
    lines.push('')
    lines.push(`Failure stage: \`${cell.failureStage}\` — ${cell.failureDetail}`)
    lines.push('')
    for (const criterion of cell.metrics.criteria) {
      lines.push(`- [${criterion.met ? 'x' : ' '}] ${criterion.label}: ${criterion.observed}`)
    }
    lines.push('')
  }
  return lines.join('\n')
}

// ---------------------------------------------------------------------------------------------
// Artifact secret / salt scanning
// ---------------------------------------------------------------------------------------------

const GENERIC_SECRET_PATTERNS: Array<{ kind: string; pattern: RegExp }> = [
  { kind: 'private_key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { kind: 'provider_key', pattern: /\bsk-[A-Za-z0-9_-]{20,}/ },
  { kind: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { kind: 'aws_key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
]

export function scanArtifacts(input: {
  files: string[]
  secrets: readonly NamedSecret[]
  salt?: string
}): SecretScanResult {
  const matches: Array<{ file: string; kind: string }> = []
  const scanned: string[] = []
  for (const file of input.files) {
    let text = ''
    try { text = readFileSync(file, 'utf8') } catch { continue }
    scanned.push(file)
    const kinds = new Set<string>()
    for (const secret of input.secrets) {
      if (secret.value.length >= 8 && text.includes(secret.value)) kinds.add('known_secret')
    }
    if (input.salt && input.salt.length >= 8 && text.includes(input.salt)) kinds.add('heldout_salt')
    for (const { kind, pattern } of GENERIC_SECRET_PATTERNS) if (pattern.test(text)) kinds.add(kind)
    for (const kind of kinds) matches.push({ file, kind })
  }
  return { clean: matches.length === 0, files: scanned, matches }
}

// ---------------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------------

function finishProcess(code: number): void {
  process.exitCode = code
  // Flush piped stdout/stderr, then exit deterministically: a RUN can leave browser sockets
  // or library timers alive after a clean engine/fixture teardown, and a benchmark must not
  // hang after its artifacts are written.
  const done = (): void => { process.exit(code) }
  if (process.stdout.writableLength === 0 && process.stderr.writableLength === 0) {
    setTimeout(done, 10)
    return
  }
  process.stdout.write('', () => process.stderr.write('', done))
}

async function main(): Promise<void> {
  const args = parseRealismArgs(process.argv.slice(2))
  if (args.help) {
    process.stdout.write(usage)
    return
  }
  assertLocalLabAllowed()
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })

  const controller = new AbortController()
  const onSignal = (): void => controller.abort()
  process.once('SIGINT', onSignal)
  process.once('SIGTERM', onSignal)

  const progress = (line: string): void => {
    const stream = args.json || args.md ? process.stderr : process.stdout
    stream.write(line)
  }
  progress(
    `[realism] ${args.fixtures.length} fixture(s): ${args.fixtures.join(', ')} mode=${args.mode}`
    + `${args.noLlm ? ' no-llm' : ' agentic'} budget=$${args.budgetUsd} seed=${args.seed}\n`,
  )

  const cells: RealismCellResult[] = []
  try {
    for (const fixture of args.fixtures) {
      if (controller.signal.aborted) break
      progress(`[realism] starting ${fixture}\n`)
      const result = await runCell(args, fixture, controller.signal, line => progress(`${line}\n`))
      cells.push(result)
      progress(
        `[realism] finished ${fixture}: ${result.passed ? 'PASS' : 'FAIL'} stage=${result.failureStage} `
        + `tp=${result.grade?.truePositives ?? 'n/a'} fp=${result.grade?.falsePositives ?? 'n/a'} `
        + `${result.meta.durationMs}ms\n`,
      )
    }
  } finally {
    process.removeListener('SIGINT', onSignal)
    process.removeListener('SIGTERM', onSignal)
  }

  // Scan every artifact produced by this invocation (including summaries after they are written).
  const baseFiles: string[] = []
  for (const cell of cells) {
    const slug = `${cell.fixture}-${cell.mode}${cell.noLlm ? '-no-llm' : ''}`
    for (const suffix of ['.json', '.md', '.meta.json', '.findings.json']) {
      const file = join(args.outDir, `${slug}${suffix}`)
      if (existsSync(file)) baseFiles.push(file)
    }
  }
  const salt = process.env.GUARDIAN_RB_HELDOUT_SALT
  const summary: RealismSummary = {
    suite: 'guardian-realism-gates',
    generatedAt: Date.now(),
    gitSha: resolveGitSha(),
    mode: args.mode,
    noLlm: args.noLlm,
    cells,
    passed: cells.filter(cell => cell.passed).length,
    failed: cells.filter(cell => !cell.passed).length,
    secretScan: { clean: true, files: [], matches: [] },
  }
  const summaryJson = join(args.outDir, 'summary.json')
  const summaryMd = join(args.outDir, 'summary.md')
  writeFileSync(summaryJson, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 })
  writeFileSync(summaryMd, `${renderSummaryMarkdown(summary)}\n`, { mode: 0o600 })
  const allFiles = [...baseFiles, summaryJson, summaryMd]
  const scan = scanArtifacts({ files: allFiles, secrets: OBSERVED_SECRETS, ...(salt ? { salt } : {}) })
  summary.secretScan = scan
  writeFileSync(summaryJson, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 })

  if (args.json) process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`)
  if (args.md) process.stdout.write(`${renderSummaryMarkdown(summary)}\n`)
  if (!args.json && !args.md) {
    process.stdout.write('\n')
    process.stdout.write(renderSummaryMarkdown(summary))
    process.stdout.write('\n')
  }

  if (!scan.clean) {
    const detail = scan.matches.map(match => `${match.file.split('/').pop()}:${match.kind}`).join(', ')
    process.stderr.write(`error: artifact secret/salt scan failed (${detail})\n`)
    finishProcess(4)
    return
  }
  const errors = cells.filter(cell => cell.error && cell.failureStage !== 'gate_incomplete')
  if (cells.some(cell => cell.failureStage === 'interrupted') || (controller.signal.aborted && cells.length === 0)) {
    finishProcess(130)
    return
  }
  if (errors.length) {
    for (const cell of errors) process.stderr.write(`error: ${cell.fixture}: ${cell.error}\n`)
    finishProcess(1)
    return
  }
  finishProcess(args.failOnGate && cells.some(cell => !cell.passed) ? 3 : 0)
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  main().catch(error => {
    process.stderr.write(`error: ${(error as Error).message}\n`)
    finishProcess(Number((error as { exitCode?: number }).exitCode ?? 1))
  })
}
