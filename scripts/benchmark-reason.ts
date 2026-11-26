/**
 * Kovo Hunter reason-bench product harness (M4).
 *
 * Drives the *real* `Execution` loop (the same engine the product runs) against the
 * `benchmarks/reason-bench/` loopback labs and reports the reasoning metrics defined in
 * `plans/reason-bench.md` §5:
 *
 *   - confirmed recall, precision / decoy FP
 *   - per-family A–F breakdown
 *   - strict causal-chain completion
 *   - `Execution --no-llm` deterministic floor
 *   - ΔReasoning = agentic recall − floor recall
 *   - $ per additive confirmed site
 *   - assignments per cell
 *   - budget × duration curve ($2/$5/$20 × 10m/30m/45m/60m)
 *
 * It intentionally reuses the M0 runtime patterns from `scripts/benchmark-realistic.ts`
 * (data-dir isolation, loopback app start, DB → findings translation, store/run setup,
 * teardown) and never forks grading: site outcomes come from `gradeRun()` in
 * `benchmarks/reason-bench/run.ts`.
 *
 * Anti-Heuristic Gate (`--no-llm`): runs the deterministic floor and exits non-zero when the
 * overall floor recall exceeds 10%, printing per-site confirmed/missed rows (structured only —
 * no payload strings).
 *
 * Safety: loopback local-lab only (`assertLocalLabAllowed`), per-cell data dirs, 0-orphan
 * teardown on exit/SIGINT, owner-only artifacts, and the salted held-out salt is never written
 * to any artifact (artifacts are scanned before they hit disk).
 *
 * The reason-bench runtime lands in a parallel stream; this harness therefore loads it through
 * a thin local interface and fails fast with an actionable message when it is absent.
 */
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'

import type { BenchmarkFunnel, FailureTaxonomyBucket, SubmittedFinding, RunTelemetry } from '../benchmarks/realistic-bench/lib/types.ts'
import { assertLocalLabAllowed } from '../benchmarks/realistic-bench/lib/safety.ts'
import type { Finding, PersonaPrivilege } from '../src/domain.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { Execution } from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { privateModelProfiles } from '../src/server/model-settings.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { normalizeRole } from '../src/server/oracle-invariants.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { redact, redactJsonValue } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'
import {
  applyRunSnapshot,
  assertSnapshotUsable,
  captureRunSnapshot,
  copySnapshotDatabase,
  readRunSnapshot,
  SnapshotError,
} from '../src/server/run-snapshot.ts'
import type { SnapshotCheckpoint } from '../src/server/run-snapshot.ts'
import { resolveOobCallbackPorts } from './benchmark-env.ts'
import { selectVerifierBackend } from './benchmark-backend.ts'
import type { VerifierBackendKind } from './benchmark-backend.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import {
  PreflightError,
  assertAgenticPreflight,
  buildTelemetry,
  describeModelMode,
  detectWorkerSessions,
  emptySnapshotMeta,
  isInertAgenticRun,
  linkSnapshotModelCredentials,
  openCellStore,
  prepareIsolatedDataDir,
  shouldIsolateDataDir,
  stopEngine,
  summarizeAssignments,
  translateFindings,
} from './benchmark-realistic.ts'
import type {
  AssignmentDiagnostics,
  IsolatedDataDirResult,
  ModelInfo,
  SnapshotRunMeta,
} from './benchmark-realistic.ts'

// ---------------------------------------------------------------------------------------------
// Contract with benchmarks/reason-bench/run.ts (documented API only)
// ---------------------------------------------------------------------------------------------

export const reasonAppNames = ['ledgerflow', 'forgecloud'] as const
export type ReasonAppName = typeof reasonAppNames[number]
export type ReasonMode = 'black-box' | 'grey-box' | 'white-box'
export type LlmMode = 'agentic' | 'deterministic-no-llm'

export interface ReasonApiRef {
  routeKey: string
  method: string
  path: string
  params: string[]
}

export interface ReasonPersona {
  id: string
  email: string
  password: string
  tenant: string
  role: string
}

/** What the scanner is allowed to see per mode. Never carries ground truth. */
export interface ReasonBriefing {
  app: ReasonAppName | string
  mode: ReasonMode
  origin: string
  personas: ReasonPersona[]
  apiReference?: ReasonApiRef[]
  sourceDir?: string
}

export interface ReasonStartedApp {
  app: ReasonAppName | string
  origin: string
  plan?: { seedSet?: 'dev' | 'held-out' }
  groundTruth: unknown
  sourceDir?: string
  oracle: {
    events(): unknown[]
    requests(): unknown[]
    egress?(): unknown[]
    reset?(): void
  }
  stop(): Promise<void>
}

export interface ReasonGradeInput {
  groundTruth: unknown
  findings: SubmittedFinding[]
  oracleEvents: unknown[]
  requestLog: unknown[]
  egressLog: unknown[]
  telemetry: RunTelemetry
  mode: ReasonMode
}

export interface ReasonSiteVerdict {
  siteId: string
  family?: string
  vulnClass?: string
  severity?: string
  outcome: string
  matchedFindingIds?: string[]
  oracleEventSeqs?: number[]
}

export interface ReasonChainVerdict {
  chainId: string
  siteId?: string
  completed: boolean
  hops?: number
  missingHops?: string[]
}

/** Reason-bench scorecard: realistic-bench accounting plus reasoning-specific output. */
export interface ReasonScorecard {
  app: string
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: string
  targets: number
  confirmed: number
  recall?: number
  precision: number
  decoys: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  duplicateFindings?: number
  chainsTotal: number
  chainsCompleted: number
  totalCostUsd: number
  funnel?: Partial<BenchmarkFunnel>
  failureBuckets?: Partial<Record<FailureTaxonomyBucket, number>>
  recallByClass?: Record<string, { targets: number; confirmed: number }>
  recallByFamily?: Record<string, { targets: number; confirmed: number }>
  vulns?: ReasonSiteVerdict[]
  chainResults?: ReasonChainVerdict[]
}

/**
 * The five documented exports of `benchmarks/reason-bench/run.ts`. Everything the harness needs
 * is expressed here so the harness type-checks before the apps land; the module is loaded by
 * path at runtime (never a bare specifier) and validated.
 */
export interface ReasonRuntime {
  startReasonApp(opts: {
    app: ReasonAppName
    seed: number
    heldOutSalt?: string
    oobCallbackPorts?: number[]
  }): Promise<ReasonStartedApp>
  briefingFor(app: ReasonStartedApp, mode: ReasonMode): ReasonBriefing
  gradeRun(input: ReasonGradeInput): ReasonScorecard
  renderScorecard(card: ReasonScorecard | ReasonScorecard[], format: 'json' | 'md'): string
  listSeeds(): unknown
}

const REASON_RUNTIME_RELATIVE = 'benchmarks/reason-bench/run.ts'
const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

export function reasonRuntimePath(root: string = REPO_ROOT): string {
  return join(root, REASON_RUNTIME_RELATIVE)
}

let cachedRuntime: ReasonRuntime | undefined

/** Load and validate the reason-bench runtime. Fails closed with an actionable message. */
export async function loadReasonRuntime(path: string = reasonRuntimePath()): Promise<ReasonRuntime> {
  if (cachedRuntime) return cachedRuntime
  if (!existsSync(path)) {
    throw new PreflightError(
      `reason-bench runtime is not available yet (missing ${path}). `
      + 'Land benchmarks/reason-bench/run.ts exporting startReasonApp, gradeRun, renderScorecard, '
      + 'briefingFor and listSeeds, then re-run.',
    )
  }
  const mod: unknown = await import(pathToFileURL(path).href)
  const runtime = mod as Partial<ReasonRuntime>
  const required = ['startReasonApp', 'gradeRun', 'renderScorecard', 'briefingFor', 'listSeeds'] as const
  for (const name of required) {
    if (typeof runtime[name] !== 'function') {
      throw new PreflightError(`${path} does not export ${name}() as documented in plans/reason-bench.md §6`)
    }
  }
  cachedRuntime = runtime as ReasonRuntime
  return cachedRuntime
}

// ---------------------------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------------------------

export const DEFAULT_BUDGET_USD = 5
export const DEFAULT_MAX_DURATION_MS = 15 * 60_000
export const DEFAULT_CONCURRENCY = 1
export const DEFAULT_SNAPSHOT_MAX_AGE_MS = 24 * 60 * 60_000
export const ANTI_HEURISTIC_CEILING = 0.10

export interface ReasonArgs {
  apps: ReasonAppName[]
  seeds: number[]
  mode: ReasonMode
  heldOut: boolean
  budgetUsd: number
  maxDurationMs: number
  outDir: string
  concurrency: number
  dataDir?: string
  noLlm: boolean
  isolateDataDir: boolean
  keepDataDirs: boolean
  allowInertWorkers: boolean
  verifier: 'auto' | 'docker' | 'local-jq'
  snapshotAfterFloorDir?: string
  resumeSnapshotDir?: string
  snapshotMaxAgeMs: number
  snapshotRefresh: boolean
  allowHeldoutSnapshot: boolean
  /** Extra artifact directories supplying floor (`--no-llm`) cells for ΔReasoning. */
  floorFrom: string[]
  /** Extra artifact directories feeding the budget × duration curve. */
  curveFrom: string[]
  jsonPath?: string
  mdPath?: string
  listSeeds: boolean
  help: boolean
}

const usage = `Kovo Hunter reason-bench (real Execution loop, plans/reason-bench.md §5–§6)

Usage:
  KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:reason -- [flags]

Flags:
  --app <name|all>          ledgerflow | forgecloud | all (default: all)
  --seed <n>                single dev seed (1..9999)
  --seeds <a,b,c>           comma-separated seeds
  --held-out                seeds are held-out (>= 1000000); needs KOVO_RB_HELDOUT_SALT
                            (the salt is never printed, stored or committed)
  --mode <m>                black-box | grey-box | white-box (default: grey-box)
  --no-llm                  deterministic floor run AND the Anti-Heuristic Gate:
                            exits non-zero (3) when overall recall > ${Math.round(ANTI_HEURISTIC_CEILING * 100)}%
  --verifier <kind>         auto | docker | local-jq (default: auto)
  --isolate-data-dir        per-cell data dir copied from --data-dir (credentials symlinked,
                            key never copied); on by default when --concurrency > 1
  --concurrency <n>         parallel app/seed cells (default: ${DEFAULT_CONCURRENCY})
  --budget-usd <n>          per-cell USD budget (default: ${DEFAULT_BUDGET_USD})
  --max-duration-ms <n|10m|30m|45m|60m>
                            wall-clock cap per cell (default: ${Math.round(DEFAULT_MAX_DURATION_MS / 60_000)}m)
  --data-dir <path>         Kovo Hunter data dir; single cell uses it verbatim, matrices use it
                            as the per-cell isolation source
                            (default: $KOVO_DATA_DIR)
  --keep-data-dirs          keep isolated per-cell data dirs after grading
  --allow-inert-workers     allow an agentic run when the verifier backend cannot open worker
                            sessions (records an inert run; still exits 2 by default)
  --snapshot-after-floor <dir>
                            capture a post-floor checkpoint (and each planner round) so the
                            live-model loop can resume without paying Phase-0/floor again
  --resume-snapshot <dir>   resume from a checkpoint (fresh app boot, rebound origins,
                            re-authenticated personas; Phase-0/floor are not re-run)
  --snapshot-max-age-ms <n> refuse checkpoints older than n ms (default 24 h)
  --snapshot-refresh        recapture an existing checkpoint
  --allow-heldout-snapshot  explicitly allow reusing a salted held-out checkpoint
  --floor-from <dir[,dir]>  additional artifact dirs holding --no-llm cells (ΔReasoning)
  --curve-from <dir[,dir]>  additional artifact dirs feeding the budget × duration curve
  --out-dir <path>          artifact directory (default: .kovo/reason-bench)
  --json <path>             write the structured reasoning report here
  --md <path>               write the markdown reasoning report here
  --list-seeds              print the reason-bench seed catalogue as JSON and exit
  --help                    show this help

Artifacts per cell (owner-only):
  <out-dir>/<app>-seed<seed>-<mode>.json        scorecard (reason-bench grader schema)
  <out-dir>/<app>-seed<seed>-<mode>.md          rendered scorecard
  <out-dir>/<app>-seed<seed>-<mode>.meta.json   metrics + model/backend/budget metadata
  <out-dir>/reason-report.{json,md}             aggregate reasoning metrics, gate, curve

Exit codes:
  0  success (agentic run, or floor <= ceiling)
  1  cell failure
  2  preflight / inert agentic run
  3  Anti-Heuristic Gate violation (--no-llm recall > ${Math.round(ANTI_HEURISTIC_CEILING * 100)}%)

Agentic runs need a worker-session-capable verifier:
  model profile + --verifier local-jq  -> exit 2 (inert workers) unless --no-llm
  model profile + --verifier docker    -> run under newgrp docker -c '<command>'
`

function fail(message: string): never {
  throw new Error(message)
}

function stringFlag(a: Record<string, string | boolean>, key: string): string | undefined {
  const v = a[key]
  return typeof v === 'string' ? v : undefined
}

function parsePositiveInt(raw: string, flag: string): number {
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) fail(`${flag} must be a positive integer (got '${raw}')`)
  return n
}

/** Accept `600000`, `90s`, `10m`, `1h`; reason-bench calibration uses 10m/30m/45m/60m. */
export function parseDurationMs(raw: string, flag = '--max-duration-ms'): number {
  const text = raw.trim()
  const match = /^(\d+(?:\.\d+)?)\s*([smh])$/i.exec(text)
  if (!match) {
    if (!/^\d+$/.test(text)) fail(`${flag} must be milliseconds or a duration like 10m/30m/45m/60m (got '${raw}')`)
    const ms = Number(text)
    if (ms <= 0) fail(`${flag} must be positive (got '${raw}')`)
    return ms
  }
  const value = Number(match[1])
  const unit = match[2]!.toLowerCase()
  const ms = Math.round(value * (unit === 's' ? 1_000 : unit === 'm' ? 60_000 : 3_600_000))
  if (ms < 60_000 || ms > 6 * 3_600_000) fail(`${flag} must be between 1m and 6h (got '${raw}')`)
  return ms
}

function parseAppList(raw: string | undefined): ReasonAppName[] {
  if (!raw || raw === 'all') return [...reasonAppNames]
  if (!(reasonAppNames as readonly string[]).includes(raw)) {
    fail(`--app must be one of ${reasonAppNames.join(', ')}, or all (got '${raw}')`)
  }
  return [raw as ReasonAppName]
}

function parseDirList(raw: string | undefined, flag: string): string[] {
  if (!raw) return []
  return raw
    .split(',')
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => (isAbsolute(part) ? part : resolve(part)))
}

function parseSeeds(a: Record<string, string | boolean>, heldOut: boolean): number[] {
  const rawSeeds = stringFlag(a, 'seeds')
  const rawSeed = stringFlag(a, 'seed')
  if (rawSeeds && rawSeed) fail('use either --seed or --seeds, not both')
  if (rawSeeds === '') fail('--seeds requires at least one seed')
  const source = rawSeeds ?? rawSeed ?? (heldOut ? '1000000' : '1')
  const seeds = source.split(',').map(s => s.trim()).filter(Boolean).map(s => {
    const n = Number(s)
    if (!Number.isInteger(n) || n <= 0) fail(`seed '${s}' must be a positive integer`)
    return n
  })
  if (!seeds.length) fail('at least one seed is required')
  return [...new Set(seeds)]
}

export function parseReasonArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): ReasonArgs {
  const a: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const key = arg.slice(2)
    if (!key) fail('empty flag')
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) a[key] = true
    else { a[key] = next; i += 1 }
  }

  const known = new Set([
    'app', 'seed', 'seeds', 'held-out', 'mode', 'no-llm', 'verifier', 'isolate-data-dir',
    'concurrency', 'budget-usd', 'max-duration-ms', 'data-dir', 'keep-data-dirs',
    'allow-inert-workers', 'snapshot-after-floor', 'resume-snapshot', 'snapshot-max-age-ms',
    'snapshot-refresh', 'allow-heldout-snapshot', 'floor-from', 'curve-from', 'out-dir',
    'json', 'md', 'list-seeds', 'help',
  ])
  for (const key of Object.keys(a)) {
    if (!known.has(key)) {
      if (/salt/i.test(key)) fail(`never pass a salt on the command line; set KOVO_RB_HELDOUT_SALT instead (got --${key})`)
      fail(`unknown flag --${key}`)
    }
  }

  if (a.help === true) {
    return {
      apps: [...reasonAppNames], seeds: [1], mode: 'grey-box', heldOut: false,
      budgetUsd: DEFAULT_BUDGET_USD, maxDurationMs: DEFAULT_MAX_DURATION_MS,
      outDir: resolve('.kovo/reason-bench'), concurrency: DEFAULT_CONCURRENCY,
      noLlm: false, isolateDataDir: false, keepDataDirs: false, allowInertWorkers: false,
      verifier: 'auto', snapshotMaxAgeMs: DEFAULT_SNAPSHOT_MAX_AGE_MS, snapshotRefresh: false,
      allowHeldoutSnapshot: false, floorFrom: [], curveFrom: [],
      listSeeds: false, help: true,
    }
  }

  const modeRaw = stringFlag(a, 'mode') ?? 'grey-box'
  if (modeRaw !== 'black-box' && modeRaw !== 'grey-box' && modeRaw !== 'white-box') {
    fail(`--mode must be black-box, grey-box or white-box (got '${modeRaw}')`)
  }

  const verifierRaw = stringFlag(a, 'verifier') ?? 'auto'
  if (verifierRaw !== 'auto' && verifierRaw !== 'docker' && verifierRaw !== 'local-jq') {
    fail(`--verifier must be auto, docker or local-jq (got '${verifierRaw}')`)
  }

  const heldOut = a['held-out'] === true
  const seeds = parseSeeds(a, heldOut)
  const salt = env.KOVO_RB_HELDOUT_SALT ?? ''
  if (heldOut) {
    if (salt.length < 16) fail('--held-out requires KOVO_RB_HELDOUT_SALT (>= 16 chars; never printed)')
    for (const seed of seeds) if (seed < 1_000_000) fail(`held-out seeds are >= 1000000 (got ${seed})`)
  } else {
    for (const seed of seeds) {
      if (seed >= 1_000_000) fail(`dev seeds are 1..9999 (got ${seed}); add --held-out`)
    }
  }

  const budgetUsd = a['budget-usd'] === undefined ? DEFAULT_BUDGET_USD : Number(stringFlag(a, 'budget-usd'))
  if (!Number.isFinite(budgetUsd) || budgetUsd < 0.1 || budgetUsd > 500) {
    fail(`--budget-usd must be a number between 0.1 and 500 (got '${String(a['budget-usd'])}')`)
  }
  const maxDurationMs = a['max-duration-ms'] === undefined
    ? DEFAULT_MAX_DURATION_MS
    : parseDurationMs(stringFlag(a, 'max-duration-ms') ?? '', '--max-duration-ms')
  const concurrency = a.concurrency === undefined
    ? DEFAULT_CONCURRENCY
    : parsePositiveInt(stringFlag(a, 'concurrency') ?? '', '--concurrency')
  if (concurrency > 16) fail('--concurrency must be <= 16')

  const snapshotAfterFloorRaw = stringFlag(a, 'snapshot-after-floor')
  if (a['snapshot-after-floor'] === true) fail('--snapshot-after-floor requires a directory argument')
  const resumeSnapshotRaw = stringFlag(a, 'resume-snapshot')
  if (a['resume-snapshot'] === true) fail('--resume-snapshot requires a directory argument')
  if (snapshotAfterFloorRaw && resumeSnapshotRaw) {
    fail('use either --snapshot-after-floor or --resume-snapshot, not both')
  }
  const snapshotRefresh = a['snapshot-refresh'] === true
  if (snapshotRefresh && !snapshotAfterFloorRaw) fail('--snapshot-refresh requires --snapshot-after-floor <dir>')
  const snapshotMaxAgeMs = a['snapshot-max-age-ms'] === undefined
    ? DEFAULT_SNAPSHOT_MAX_AGE_MS
    : parsePositiveInt(stringFlag(a, 'snapshot-max-age-ms') ?? '', '--snapshot-max-age-ms')

  const noLlm = a['no-llm'] === true
  if (resumeSnapshotRaw && noLlm) fail('--resume-snapshot requires the live agentic model; drop --no-llm')

  const outDirRaw = stringFlag(a, 'out-dir') ?? '.kovo/reason-bench'
  const dataDirRaw = stringFlag(a, 'data-dir') ?? env.KOVO_DATA_DIR

  return {
    apps: parseAppList(stringFlag(a, 'app')),
    seeds,
    mode: modeRaw,
    heldOut,
    budgetUsd,
    maxDurationMs,
    outDir: isAbsolute(outDirRaw) ? outDirRaw : resolve(outDirRaw),
    concurrency,
    ...(dataDirRaw ? { dataDir: isAbsolute(dataDirRaw) ? dataDirRaw : resolve(dataDirRaw) } : {}),
    noLlm,
    isolateDataDir: a['isolate-data-dir'] === true,
    keepDataDirs: a['keep-data-dirs'] === true,
    allowInertWorkers: a['allow-inert-workers'] === true,
    verifier: verifierRaw,
    ...(snapshotAfterFloorRaw
      ? { snapshotAfterFloorDir: isAbsolute(snapshotAfterFloorRaw) ? snapshotAfterFloorRaw : resolve(snapshotAfterFloorRaw) }
      : {}),
    ...(resumeSnapshotRaw
      ? { resumeSnapshotDir: isAbsolute(resumeSnapshotRaw) ? resumeSnapshotRaw : resolve(resumeSnapshotRaw) }
      : {}),
    snapshotMaxAgeMs,
    snapshotRefresh,
    allowHeldoutSnapshot: a['allow-heldout-snapshot'] === true,
    floorFrom: parseDirList(stringFlag(a, 'floor-from'), '--floor-from'),
    curveFrom: parseDirList(stringFlag(a, 'curve-from'), '--curve-from'),
    ...(stringFlag(a, 'json') ? { jsonPath: resolve(stringFlag(a, 'json')!) } : {}),
    ...(stringFlag(a, 'md') ? { mdPath: resolve(stringFlag(a, 'md')!) } : {}),
    listSeeds: a['list-seeds'] === true,
    help: false,
  }
}

// ---------------------------------------------------------------------------------------------
// Mode plan (briefing only; never ground truth)
// ---------------------------------------------------------------------------------------------

export interface ReasonCellPlan {
  briefing: ReasonBriefing
  loginPath: string | null
  openApi: { openapi: string; info: { title: string; version: string }; paths: Record<string, unknown> } | null
  personas: Array<{ handle: string; roleLabel: string; tenantRef: string | null; privilege: PersonaPrivilege | null; email: string; password: string; canaryMarkers: string[] }>
  capabilityTier: 3
  mission: string
}

function safeHandle(id: string): string {
  const cleaned = id.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '')
  return cleaned.length ? cleaned.slice(0, 48) : 'persona'
}

/** Black-box bootstrap: try conventional JSON login routes with the supplied credentials. */
export async function probeLoginPath(origin: string, personas: ReadonlyArray<Pick<ReasonPersona, 'email' | 'password'>>): Promise<string | null> {
  const first = personas[0]
  if (!first) return null
  const candidates = ['/login', '/api/auth/login', '/api/v1/login', '/auth/login', '/api/login', '/session']
  for (const path of candidates) {
    try {
      const res = await fetch(new URL(path, origin), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: first.email, password: first.password }),
        signal: AbortSignal.timeout(3_000),
      })
      const setCookie = res.headers.get('set-cookie') ?? ''
      const text = await res.text().catch(() => '')
      const token = /"(?:access_token|accessToken|token|jwt|id_token)"\s*:\s*"[^"]{8,}"/.test(text)
      if (res.ok && (setCookie.length > 0 || token)) return path
    } catch { /* try the next conventional path */ }
  }
  return null
}

/** Pick a login route from the grey/white-box API reference; black-box probes conventions. */
export function pickLoginPath(briefing: Pick<ReasonBriefing, 'apiReference'>): string | null {
  const routes = briefing.apiReference ?? []
  const named = routes.filter(r => /login|signin|sign-in|session/i.test(`${r.routeKey} ${r.path}`))
  const posts = named.filter(r => r.method.toUpperCase() === 'POST')
  const ranked = (posts.length ? posts : named).slice().sort((a, b) => {
    const legacy = (r: ReasonApiRef) => (/legacy|v1\//i.test(r.routeKey) ? 1 : 0)
    const exact = (r: ReasonApiRef) => (/^(login|signin|session)$/i.test(r.routeKey) ? 0 : 1)
    return exact(a) - exact(b) || legacy(a) - legacy(b)
  })
  return ranked[0]?.path ?? null
}

export function briefingToOpenApi(briefing: Pick<ReasonBriefing, 'app' | 'apiReference'>): NonNullable<ReasonCellPlan['openApi']> {
  const paths: Record<string, Record<string, { parameters: Array<{ name: string; in: string; required: boolean }> }>> = {}
  for (const route of briefing.apiReference ?? []) {
    const params = route.params.map(name => ({
      name,
      in: route.path.includes(`:${name}`) || route.path.includes(`{${name}}`) ? 'path' : 'query',
      required: route.path.includes(`:${name}`) || route.path.includes(`{${name}}`),
    }))
    paths[route.path] ??= {}
    paths[route.path]![route.method.toLowerCase()] = { parameters: params }
  }
  return {
    openapi: '3.1.0',
    info: { title: `reason-bench ${String(briefing.app)} API reference`, version: '1.0.0' },
    paths,
  }
}

/** Mode → briefing interpretation; this is the only configuration source. */
export function planCell(briefing: ReasonBriefing, loginPath: string | null): ReasonCellPlan {
  if (briefing.mode === 'black-box' && briefing.apiReference) {
    fail('black-box briefings must not include an API reference')
  }
  if (briefing.mode === 'grey-box' && !briefing.apiReference) fail('grey-box briefings require an API reference')
  if (briefing.mode === 'white-box' && !briefing.sourceDir) fail('white-box briefings require a source directory')

  const handles = new Set<string>()
  const personas = briefing.personas.map(p => {
    let handle = safeHandle(p.id)
    for (let n = 2; handles.has(handle); n += 1) handle = `${safeHandle(p.id)}-${n}`
    handles.add(handle)
    return {
      handle,
      roleLabel: `${p.role} (${p.tenant})`,
      tenantRef: p.tenant.trim() || null,
      privilege: normalizeRole(p.role),
      email: p.email,
      password: p.password,
      canaryMarkers: [] as string[],
    }
  })
  // Black-box exposes at most the three peer personas (plans/reason-bench.md §3.3).
  if (briefing.mode === 'black-box' && personas.length > 3) {
    fail('black-box briefings may expose at most member_a, member_b and dual_member')
  }

  const mission = [
    `Defensive verification of the authorized local-lab target ${briefing.origin} (${String(briefing.app)}).`,
    'The application enforces schema, auth and status-code correctness on every route; the defects are',
    'implicit domain, economic, temporal or cross-tenant authorization invariants that require multi-step',
    'causal sequences and cross-surface reasoning. Map the reachable surface, form hypotheses, prove impact',
    'with deterministic replay, and ignore hardened look-alike decoys. Do not fabricate findings and do not',
    'leave the approved origin.',
  ].join(' ')

  return {
    briefing,
    loginPath,
    openApi: briefing.apiReference ? briefingToOpenApi(briefing) : null,
    personas,
    // Chain and state-mutation proofs need Tier 3; local-lab approvals are auto-reviewed.
    capabilityTier: 3,
    mission,
  }
}

// ---------------------------------------------------------------------------------------------
// Cell metadata + result
// ---------------------------------------------------------------------------------------------

export interface ReasonFamilyRow {
  targets: number
  confirmed: number
  recall: number
}

export interface ReasonSiteRow {
  siteId: string
  family: string
  vulnClass: string | null
  severity: string | null
  outcome: string
  confirmed: boolean
}

export interface ReasonCellMeta {
  schemaVersion: 1
  app: ReasonAppName
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: ReasonMode
  cell: string
  llm: LlmMode
  origin: string
  loginPath: string | null
  gitSha: string
  model: ModelInfo
  verifierBackend: VerifierBackendKind
  workerSessions: boolean
  workerSessionsDetail: string
  dataDirIsolated: boolean
  dataDirSource: string | null
  isolatedProfileNames: string[]
  dataDirKept: boolean
  budgetUsd: number
  maxDurationMs: number
  startedAt: number
  endedAt: number
  durationMs: number | null
  timedOut: boolean
  terminalStatus: string
  terminalPhase: string
  runId: string | null
  projectId: string | null
  targets: number
  confirmed: number
  recall: number
  precision: number
  decoys: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  chainsCompleted: number
  chainsTotal: number
  costUsd: number
  assignmentsCompleted: number
  assignmentsTotal: number
  investigationCompleted: number
  facts: number
  findingsPersisted: number
  findingsSubmitted: number
  baselineChecksExcluded: number
  endpointsDiscovered: number
  requestCount: number
  oracleEventCount: number
  families: Record<string, ReasonFamilyRow>
  sites: ReasonSiteRow[]
  inert: boolean
  snapshot: SnapshotRunMeta
  resumedFrom: string | null
  snapshotSkippedMs: number
  notes: string[]
  shutdown: { engineBusy: number; appStopped: boolean; canaryStopped: boolean }
}

export interface ReasonCellResult {
  meta: ReasonCellMeta
  scorecard: ReasonScorecard
  jsonPath: string
  mdPath: string
  metaPath: string
}

export function cellSlug(app: ReasonAppName, seed: number, mode: ReasonMode): string {
  return `${app}-seed${seed}-${mode}`
}

function snapshotDirectoryFor(base: string, cells: number, slug: string): string {
  return cells > 1 ? join(base, slug) : base
}

function resolveResumeSnapshotDirectory(base: string, slug: string): string {
  if (existsSync(join(base, 'snapshot.json'))) return base
  const child = join(base, slug)
  if (existsSync(join(child, 'snapshot.json'))) return child
  return base
}

function resolveGitSha(): string {
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || 'unknown'
  } catch {
    return 'unknown'
  }
}

function nowMs(): number { return Date.now() }

function num(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0
}

// ---------------------------------------------------------------------------------------------
// Family attribution (reporting only; gradeRun owns site outcomes)
// ---------------------------------------------------------------------------------------------

const FAMILY_BY_SITE: Record<string, 'A' | 'B' | 'C' | 'D' | 'E' | 'F'> = {
  // plans/reason-bench.md §4
  'lf-01': 'A', 'lf-02': 'A', 'lf-03': 'A', 'lf-04': 'A', 'lf-05': 'A', 'lf-06': 'A',
  'lf-07': 'B', 'lf-08': 'B', 'lf-09': 'B', 'lf-10': 'B',
  'lf-11': 'D', 'lf-12': 'D',
  'lf-13': 'E', 'lf-14': 'E',
  'fc-01': 'B',
  'fc-02': 'C', 'fc-03': 'C', 'fc-04': 'C', 'fc-05': 'C', 'fc-06': 'C',
  'fc-07': 'D', 'fc-08': 'D', 'fc-09': 'D',
  'fc-10': 'E', 'fc-11': 'E',
  'fc-12': 'F', 'fc-13': 'F', 'fc-14': 'F',
}

export const reasonFamilies = ['A', 'B', 'C', 'D', 'E', 'F'] as const
export type ReasonFamily = typeof reasonFamilies[number]

export function normalizeFamily(raw: string | undefined, siteId: string): ReasonFamily | 'unknown' {
  if (raw) {
    const match = /(?:family\s*)?([A-F])\b/i.exec(raw)
    if (match) return match[1]!.toUpperCase() as ReasonFamily
  }
  const mapped = FAMILY_BY_SITE[siteId]
  return mapped ?? 'unknown'
}

export function emptyFamilyTable(): Record<string, ReasonFamilyRow> {
  const table: Record<string, ReasonFamilyRow> = {}
  for (const family of reasonFamilies) table[family] = { targets: 0, confirmed: 0, recall: 0 }
  return table
}

function finalizeFamilyTable(table: Record<string, ReasonFamilyRow>): Record<string, ReasonFamilyRow> {
  for (const row of Object.values(table)) row.recall = ratio(row.confirmed, row.targets)
  return table
}

/** Derive per-site rows from the grader scorecard (no grading logic is re-implemented). */
export function deriveSites(card: ReasonScorecard): ReasonSiteRow[] {
  const vulns = card.vulns ?? []
  return vulns.map(v => {
    const family = normalizeFamily(v.family, v.siteId)
    return {
      siteId: v.siteId,
      family,
      vulnClass: v.vulnClass ?? null,
      severity: v.severity ?? null,
      outcome: v.outcome,
      confirmed: v.outcome === 'confirmed',
    }
  })
}

export function deriveFamilies(sites: ReasonSiteRow[], card?: ReasonScorecard): Record<string, ReasonFamilyRow> {
  const table = emptyFamilyTable()
  if (sites.length) {
    for (const site of sites) {
      const row = table[site.family] ?? (table[site.family] = { targets: 0, confirmed: 0, recall: 0 })
      row.targets += 1
      if (site.confirmed) row.confirmed += 1
    }
    return finalizeFamilyTable(table)
  }
  // Fallback: the grader's own family aggregation when it reports one.
  for (const [raw, value] of Object.entries(card?.recallByFamily ?? {})) {
    const family = normalizeFamily(raw, raw)
    table[family] = {
      targets: num(value.targets),
      confirmed: num(value.confirmed),
      recall: ratio(num(value.confirmed), num(value.targets)),
    }
  }
  return finalizeFamilyTable(table)
}

// ---------------------------------------------------------------------------------------------
// Cell execution
// ---------------------------------------------------------------------------------------------

async function makeWhiteBoxMount(sourceDir: string, app: string, dataDir: string, projectId: string): Promise<string[]> {
  const repoRoot = join(projectReposDir(dataDir, projectId), 'bench', app)
  mkdirSync(join(repoRoot, '..'), { recursive: true, mode: 0o700 })
  if (existsSync(repoRoot)) unlockAndRemove(repoRoot)
  cpSync(sourceDir, repoRoot, { recursive: true })
  const lockDown = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const child = join(dir, entry)
      try {
        if (lstatSync(child).isDirectory()) lockDown(child)
        else chmodSync(child, 0o444)
      } catch { /* best-effort */ }
    }
    chmodSync(dir, 0o555)
  }
  lockDown(repoRoot)
  return [`/repos/bench/${app}`]
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

async function waitForTerminal(input: {
  storage: Store
  runId: string
  deadlineAt: number
  onTick?: (status: string, phase: string) => void
}): Promise<{ timedOut: boolean; status: string; phase: string }> {
  const terminal = new Set(['complete', 'failed', 'stopped', 'paused', 'budget_paused'])
  let last = 0
  while (true) {
    const run = input.storage.run(input.runId)
    if (terminal.has(run.status)) return { timedOut: false, status: run.status, phase: run.phase }
    if (nowMs() >= input.deadlineAt) {
      try {
        input.storage.command({ requestId: randomUUID(), runId: input.runId, action: 'stop' })
      } catch { /* run already terminal */ }
      const after = input.storage.run(input.runId)
      return { timedOut: true, status: after.status, phase: after.phase }
    }
    if (nowMs() - last > 5_000) {
      last = nowMs()
      input.onTick?.(run.status, run.phase)
    }
    await delay(200)
  }
}

/** Structured, payload-free per-site lines for the Anti-Heuristic Gate. */
export function formatGateSiteLines(meta: ReasonCellMeta, sites: ReasonSiteRow[]): string[] {
  return sites.map(site =>
    `[gate] ${meta.app} seed=${meta.seed} site=${site.siteId} family=${site.family} `
    + `class=${site.vulnClass ?? 'n/a'} outcome=${site.confirmed ? 'confirmed' : 'missed'}`)
}

/**
 * Accumulating guard for artifact writes only. Persona secrets themselves live in a per-cell
 * array, so concurrent cells never redact or scan each other's credentials.
 */
const artifactSecretGuard: NamedSecret[] = []
let activeSalt = ''

function assertNoSecrets(text: string, label: string): void {
  if (activeSalt && text.includes(activeSalt)) {
    throw new Error(`refusing to write ${label}: held-out salt appeared in the artifact`)
  }
  for (const secret of artifactSecretGuard) {
    if (secret.value.length >= 8 && text.includes(secret.value)) {
      throw new Error(`refusing to write ${label}: a persona secret appeared in the artifact`)
    }
  }
}

function writeOwnerOnly(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  assertNoSecrets(text, path)
  writeFileSync(path, text, { mode: 0o600 })
  chmodSync(path, 0o600)
}

export interface CleanupRegistry {
  add(fn: () => Promise<void>): () => void
  runAll(): Promise<void>
}

export function createCleanupRegistry(onError?: (error: unknown) => void): CleanupRegistry {
  const fns = new Set<() => Promise<void>>()
  return {
    add(fn) {
      fns.add(fn)
      return () => { fns.delete(fn) }
    },
    async runAll() {
      for (const fn of [...fns].reverse()) {
        fns.delete(fn)
        try { await fn() } catch (error) { onError?.(error) }
      }
    },
  }
}

export async function runCell(
  args: ReasonArgs,
  app: ReasonAppName,
  seed: number,
  runtime: ReasonRuntime,
  log: (line: string) => void,
  cleanup: CleanupRegistry,
): Promise<ReasonCellResult> {
  const startedAt = nowMs()
  const slug = cellSlug(app, seed, args.mode)
  const cells = cellKeys(args)
  const cellCount = cells.length
  const notes: string[] = []
  const llmMode: LlmMode = args.noLlm ? 'deterministic-no-llm' : 'agentic'
  const sourceDataDir = args.noLlm ? undefined : args.dataDir
  const isolate = shouldIsolateDataDir(args)
  const resumeRequested = Boolean(args.resumeSnapshotDir)
  const snapshotMeta = emptySnapshotMeta()
  snapshotMeta.resume.requested = resumeRequested
  snapshotMeta.resume.heldOutOverride = args.allowHeldoutSnapshot
  snapshotMeta.capture.requested = Boolean(args.snapshotAfterFloorDir)
  const captureBaseDir = args.snapshotAfterFloorDir
    ? snapshotDirectoryFor(args.snapshotAfterFloorDir, cellCount, slug)
    : undefined
  snapshotMeta.capture.directory = captureBaseDir ?? null
  if (captureBaseDir && args.snapshotRefresh) rmSync(captureBaseDir, { recursive: true, force: true })

  let dataDir = join(args.outDir, 'data', slug)
  let isolated: IsolatedDataDirResult | undefined
  let loadedSnapshot: ReturnType<typeof readRunSnapshot> | undefined
  if (resumeRequested) {
    const resumeDir = resolveResumeSnapshotDirectory(args.resumeSnapshotDir!, slug)
    snapshotMeta.resume.directory = resumeDir
    loadedSnapshot = readRunSnapshot(resumeDir)
    const targetApp = loadedSnapshot.target
    if (targetApp.app !== app || targetApp.seed !== seed || targetApp.mode !== args.mode) {
      throw new PreflightError(
        `snapshot ${resumeDir} is for ${targetApp.app} seed ${targetApp.seed} ${targetApp.mode}, `
        + `not ${app} seed ${seed} ${args.mode}`,
      )
    }
    const usable = assertSnapshotUsable(loadedSnapshot, {
      heldOut: args.heldOut,
      allowHeldOut: args.allowHeldoutSnapshot,
      maxAgeMs: args.snapshotMaxAgeMs,
    })
    snapshotMeta.resume.loaded = true
    snapshotMeta.resume.capturedAt = targetApp.capturedAt
    snapshotMeta.resume.ageMs = usable.ageMs
    snapshotMeta.resume.skippedMs = usable.skippedMs
    snapshotMeta.resume.schemaVersion = loadedSnapshot.snapshot.versions.snapshotSchemaVersion
    snapshotMeta.resume.gitSha = loadedSnapshot.snapshot.versions.gitSha
    snapshotMeta.resume.seedSet = targetApp.seedSet
    snapshotMeta.resume.phase0Skipped = Boolean(loadedSnapshot.snapshot.coordinator.phase0CompletedAt)
    dataDir = join(args.outDir, 'data', `${slug}-resume`)
    copySnapshotDatabase({ snapshotDir: resumeDir, targetDir: dataDir })
    const linked = linkSnapshotModelCredentials({
      snapshotDb: join(dataDir, 'kovo.sqlite'),
      ...(sourceDataDir ? { sourceDataDir } : {}),
      targetDataDir: dataDir,
    })
    notes.push(
      `resume snapshot loaded from ${resumeDir} (captured ${new Date(targetApp.capturedAt).toISOString()}, `
      + `age ${Math.round(usable.ageMs / 1000)}s, checkpoint skipped ${Math.round(usable.skippedMs / 1000)}s of cold work); `
      + `${linked.linked} model credential link(s)`,
    )
  } else if (isolate && sourceDataDir) {
    isolated = prepareIsolatedDataDir({ sourceDataDir, targetDir: dataDir })
  } else if (sourceDataDir) {
    dataDir = cellCount === 1 ? sourceDataDir : join(sourceDataDir, slug)
  }
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })

  const storage = (() => {
    try {
      return openCellStore(dataDir)
    } catch (error) {
      if (isolated) { try { unlockAndRemove(dataDir) } catch { /* best-effort */ } }
      throw error
    }
  })()
  const canary = new CanaryBroker({ storage })
  let started: ReasonStartedApp | undefined
  let engine: Execution | undefined
  let backend: WorkerBackend | undefined
  let backendKind: VerifierBackendKind = 'local-jq'
  let appStopped = false
  let canaryStopped = false
  let whiteBoxRoot: string | undefined
  let engineBusy = -1

  if (args.isolateDataDir && !sourceDataDir && !args.noLlm) {
    notes.push('--isolate-data-dir had no --data-dir/KOVO_DATA_DIR source; using a fresh cell data dir')
  }
  if (isolated) {
    notes.push(
      `isolated data dir from ${isolated.source}; profile(s): ${isolated.profileNames.join(', ')}; `
      + 'credentials symlinked (key not copied)',
    )
  }

  const cellSecrets: NamedSecret[] = []
  let runId = ''
  let projectId = ''
  let runStartedAt = startedAt
  let loginPath: string | null = null
  let gitSha = 'unknown'
  let model: ModelInfo = { mode: 'deterministic-no-llm', profiles: [] }

  const unregisterCleanup = cleanup.add(async () => {
    if (engine) { try { engineBusy = await stopEngine(engine) } catch { engineBusy = -1 } }
    if (backend instanceof LinuxWorkerBackend) { try { await backend.reclaimInactive() } catch { /* best-effort */ } }
    try { await canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
    if (started) { try { await started.stop(); appStopped = true } catch { appStopped = false } }
  })

  try {
    // --- Preflight (before booting the app): model mode + real worker-session capability ---
    let profiles: ResolvedModelProfile[] = []
    try {
      profiles = privateModelProfiles(storage)
    } catch (error) {
      notes.push(`model profile lookup failed: ${redact((error as Error).message).slice(0, 160)}`)
    }
    if (args.noLlm) notes.push('--no-llm: model profiles ignored; isolated deterministic data dir')
    model = describeModelMode(args.noLlm ? [] : profiles)
    notes.push(model.mode === 'agentic'
      ? `agentic model profile(s): ${model.profiles.map(p => p.model).join(', ')}`
      : 'no model profile configured: deterministic Zero-LLM path (threat model -> verification)')

    const selected = await (async () => {
      try {
        return await selectVerifierBackend(args.verifier)
      } catch (error) {
        const detail = redact(error instanceof Error ? error.message : String(error)).slice(0, 240)
        if (args.verifier === 'docker') {
          throw new PreflightError(
            `--verifier docker is not usable from this process: ${detail}. Docker worker sessions need `
            + 'socket access; re-run under `newgrp docker -c \'<command>\'` and make sure kovo-worker:v4 is built.',
          )
        }
        throw error
      }
    })()
    backendKind = selected.kind
    backend = selected.kind === 'docker'
      ? new LinuxWorkerBackend({ workspace: { id: storage.workspace.id, directory: storage.directory } })
      : selected.backend

    const capability = await detectWorkerSessions(backend)
    assertAgenticPreflight({
      hasProfiles: model.mode === 'agentic',
      noLlm: args.noLlm,
      allowInertWorkers: args.allowInertWorkers,
      backendKind,
      workerSessions: capability.supported,
      workerSessionsDetail: capability.detail,
    })
    notes.push(
      `verifier backend ${backendKind}; workerSessions=${capability.supported}`
      + `${capability.supported ? '' : ` (${capability.detail})`}`,
    )

    const listener = await canary.startListener({ host: '127.0.0.1', port: 0 })
    const oobPort = listener.port
    if (!oobPort) fail('canary listener did not bind a loopback port')
    const oobCallbackPorts = resolveOobCallbackPorts(canary, [oobPort])
    const canaryBaseUrl = listener.localBaseUrl ?? listener.effectiveBaseUrl ?? null

    started = await runtime.startReasonApp({
      app,
      seed,
      ...(args.heldOut ? { heldOutSalt: process.env.KOVO_RB_HELDOUT_SALT } : {}),
      oobCallbackPorts,
    })
    const briefing = runtime.briefingFor(started, args.mode)
    for (const p of briefing.personas) {
      const secret: NamedSecret = { value: p.password, placeholder: '[[persona-password]]' }
      cellSecrets.push(secret)
      artifactSecretGuard.push(secret)
    }

    loginPath = resumeRequested && loadedSnapshot?.target.loginPath
      ? loadedSnapshot.target.loginPath
      : pickLoginPath(briefing)
    if (!loginPath && args.mode === 'black-box' && !resumeRequested) {
      loginPath = await probeLoginPath(briefing.origin, briefing.personas)
      if (loginPath) notes.push(`black-box login route discovered by convention probe: ${loginPath}`)
      else notes.push('black-box login route not discovered; personas are not registered')
    }
    const plan = planCell(briefing, loginPath)
    gitSha = resolveGitSha()
    const seedSet: 'dev' | 'held-out' = started.plan?.seedSet ?? (args.heldOut ? 'held-out' : 'dev')

    let mountedRepos: string[] = []
    let personaIds: string[] = []
    if (resumeRequested && loadedSnapshot) {
      projectId = loadedSnapshot.target.projectId
      runId = loadedSnapshot.target.runId
      const run = storage.run(runId)
      personaIds = [...run.approvedPersonaIds]
      if (args.mode === 'white-box' && briefing.sourceDir) {
        mountedRepos = await makeWhiteBoxMount(briefing.sourceDir, String(briefing.app), dataDir, projectId)
        if (mountedRepos.length) {
          whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', String(briefing.app))
          notes.push(`white-box read-only source mount (resumed): ${mountedRepos.join(', ')}`)
        }
      }
      const applied = applyRunSnapshot({
        storage,
        snapshot: loadedSnapshot.snapshot,
        target: loadedSnapshot.target,
        newOrigin: briefing.origin,
        ...(canaryBaseUrl ? { newCanaryBaseUrls: [canaryBaseUrl] } : {}),
        personaCredentials: plan.personas.map(p => ({
          handle: p.handle, email: p.email, password: p.password,
        })),
      })
      snapshotMeta.resume.originsRebound = applied.origins.rowsUpdated
      snapshotMeta.resume.personaSessionsRebound = applied.personaSessionsRebound
      snapshotMeta.resume.phase0Skipped = applied.phase0Skipped
      snapshotMeta.resume.skippedMs = applied.skippedMs
      notes.push(
        `snapshot resumed at ${applied.runId}: phase0Skipped=${applied.phase0Skipped}, `
        + `origins rebound (${applied.origins.rowsUpdated} rows), `
        + `${applied.personaSessionsRebound} persona credential(s) re-created for fresh sessions, `
        + `${applied.assignmentsCanceled} in-flight assignment(s) discarded`,
      )
    } else {
      const project = storage.createProject({
        requestId: randomUUID(),
        name: `reason-bench ${app} seed ${seed} (${args.mode})`,
        seeds: [briefing.origin],
        environment: 'local-lab',
      })
      projectId = project.id

      if (plan.openApi) {
        storage.importProjectSpec({
          requestId: randomUUID(),
          projectId,
          name: `reason-bench-${app}-api.json`,
          kind: 'openapi',
          origin: briefing.origin,
          content: JSON.stringify(plan.openApi, null, 2),
        })
      }

      mountedRepos = args.mode === 'white-box' && briefing.sourceDir
        ? await makeWhiteBoxMount(briefing.sourceDir, String(briefing.app), dataDir, projectId)
        : []
      if (mountedRepos.length) {
        whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', String(briefing.app))
        notes.push(`white-box read-only source mount: ${mountedRepos.join(', ')}`)
      }

      if (loginPath) {
        for (const p of plan.personas) {
          const created = createProjectPersona(storage, {
            requestId: randomUUID(),
            projectId,
            handle: p.handle,
            roleLabel: p.roleLabel,
            tenantRef: p.tenantRef,
            privilege: p.privilege,
            originAllowlist: [briefing.origin],
            authKind: 'login',
            loginConfig: {
              adapter: 'json',
              email: p.email,
              loginUrl: new URL(loginPath, briefing.origin).toString(),
            },
            secret: p.password,
            canaryMarkers: p.canaryMarkers,
          })
          personaIds.push(created.id)
        }
      }

      const createdRun = storage.createRun({
        requestId: randomUUID(),
        projectId,
        goal: plan.mission,
        sourceMode: 'public',
        capabilityTier: plan.capabilityTier,
        approvalPolicy: 'auto_review',
        approvedPersonaIds: personaIds,
        budgetUsd: args.budgetUsd,
        budgetRequests: 2_000,
        maxRpsPerOrigin: 10,
        workerConcurrency: Math.min(4, Math.max(1, args.concurrency)),
        workerMaxTurns: 30,
        multiTrialEnabled: true,
      })
      runId = createdRun.id

      storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
      const assetIds = storage.run(runId).candidates.map(c => c.id)
      if (!assetIds.length) fail('discovery produced no candidate assets for the briefing origin')
      storage.command({
        requestId: randomUUID(),
        runId,
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
    }

    // --- Snapshot capture at post-floor / planner-round boundaries -----------------------------
    const capturedKeys = new Set<string>()
    const captureCheckpoint = (checkpoint: SnapshotCheckpoint): void => {
      if (resumeRequested || !captureBaseDir || !runId) return
      try {
        const latest = storage.run(runId)
        const key = checkpoint === 'planner-round' ? `${checkpoint}:${latest.roundNo}` : checkpoint
        if (capturedKeys.has(key)) return
        const dir = checkpoint === 'planner-round'
          ? join(captureBaseDir, `planner-round-${latest.roundNo}`)
          : checkpoint === 'phase0'
            ? join(captureBaseDir, 'phase0')
            : captureBaseDir
        if (!args.snapshotRefresh && existsSync(join(dir, 'snapshot.json'))) {
          capturedKeys.add(key)
          snapshotMeta.capture.reason = `checkpoint ${key} already present`
          return
        }
        const result = captureRunSnapshot({
          storage,
          snapshotDir: dir,
          checkpoint,
          target: {
            app,
            seed,
            seedSet,
            mode: args.mode,
            origin: briefing.origin,
            loginPath,
            canaryBaseUrls: canaryBaseUrl ? [canaryBaseUrl] : [],
            projectId,
            runId,
          },
          gitSha,
          secrets: cellSecrets,
        })
        capturedKeys.add(key)
        snapshotMeta.capture.captured = true
        snapshotMeta.capture.reason = null
        snapshotMeta.capture.checkpoints.push(checkpoint)
        if (dir === captureBaseDir) {
          snapshotMeta.capture.primary = {
            path: result.snapshotDir,
            capturedAt: result.snapshot.capturedAt,
            skippedMs: result.snapshot.coordinator.virtualElapsedMs,
            checkpoint,
            counts: result.counts,
          }
        }
        notes.push(
          `snapshot checkpoint '${checkpoint}' written to ${result.snapshotDir}: `
          + `${result.counts.endpoints} endpoints, ${result.counts.facts} facts, `
          + `${result.counts.findings} findings, ${result.counts.replaySpecs} replay specs; `
          + `cold work skipped on resume ~${Math.round(result.snapshot.coordinator.virtualElapsedMs / 1000)}s`,
        )
        log(`[${slug}] checkpoint ${checkpoint} captured (${Math.round(result.snapshot.coordinator.virtualElapsedMs / 1000)}s state)`)
      } catch (error) {
        const message = error instanceof SnapshotError ? error.message : (error instanceof Error ? error.message : String(error))
        snapshotMeta.capture.reason = `capture failed: ${redact(message).slice(0, 200)}`
        notes.push(`snapshot checkpoint '${checkpoint}' skipped: ${snapshotMeta.capture.reason}`)
      }
    }

    engine = new Execution(storage, {
      canaryBroker: canary,
      ...(backend ? { backend } : {}),
      deterministicOnly: args.noLlm,
      onCheckpoint: event => captureCheckpoint(event.checkpoint),
    })
    engine.start()
    engine.wake()
    runStartedAt = nowMs()

    const wait = await waitForTerminal({
      storage,
      runId,
      deadlineAt: startedAt + args.maxDurationMs,
      onTick: (status, phase) => log(`[${slug}] ${status}/${phase}`),
    })
    if (wait.timedOut) notes.push(`wall-clock cap reached after ${args.maxDurationMs}ms; run stopped`)
    if (wait.status !== 'complete') {
      const recent = storage.eventsAfter(runId, 0, 200)
      const last = recent[recent.length - 1]
      notes.push(`terminal status ${wait.status}/${wait.phase}${last ? ` (last event: ${last.kind})` : ''}`)
    }

    const finalRun = storage.run(runId)
    const detail = storage.runDetail(runId)

    const submitted = translateFindings({
      findings: detail.findings as Finding[],
      replaySpecs: detail.replaySpecs.map(row => ({
        id: row.id, findingId: row.findingId, spec: row.spec, createdAt: row.createdAt,
      })),
      endpoints: detail.endpoints,
      endpointParams: detail.endpointParams,
      exchanges: detail.exchangesSummary.map(ex => ({
        id: ex.id, method: ex.method, pathAndQuery: ex.pathAndQuery,
      })),
      spentUsd: finalRun.spentUsd,
      secrets: cellSecrets,
    })

    const telemetry = buildTelemetry({
      runStartedAt,
      runEndedAt: nowMs(),
      spentUsd: finalRun.spentUsd,
      budgetUsd: args.budgetUsd,
      budgetExhausted: wait.timedOut || finalRun.status === 'budget_paused',
    })

    const gradeInput: ReasonGradeInput = {
      groundTruth: started.groundTruth,
      findings: submitted,
      oracleEvents: started.oracle.events(),
      requestLog: started.oracle.requests(),
      egressLog: started.oracle.egress?.() ?? [],
      telemetry,
      mode: args.mode,
    }
    const card = runtime.gradeRun(gradeInput)
    const endedAt = nowMs()

    const targets = num(card.targets)
    const confirmed = num(card.confirmed)
    const sites = deriveSites(card)
    const families = deriveFamilies(sites, card)

    const failureEvents = storage.eventsAfter(runId, 0, 500)
      .filter(event => event.kind === 'worker.failed' || event.kind === 'worker.canceled')
      .map(event => event.message)
    const assignmentDiagnostics: AssignmentDiagnostics = summarizeAssignments(
      detail.assignments, failureEvents, cellSecrets,
    )
    const factsCount = detail.facts.length
    const inert = isInertAgenticRun({
      agentic: model.mode === 'agentic',
      submittedFindings: submitted.length,
      facts: factsCount,
      investigationCompleted: assignmentDiagnostics.investigationCompleted,
    })
    if (inert) {
      notes.push(
        'INERT RUN: agentic mode produced no facts, no submitted findings and no completed '
        + 'investigation assignment; the scorecard is not evidence of an investigation.',
      )
    }
    if (!sites.length) {
      notes.push('scorecard reported no per-site verdicts; family breakdown falls back to recallByFamily when present')
    }

    const meta: ReasonCellMeta = {
      schemaVersion: 1,
      app,
      seed,
      seedSet,
      mode: args.mode,
      cell: slug,
      llm: llmMode,
      origin: briefing.origin,
      loginPath,
      gitSha,
      model,
      verifierBackend: backendKind,
      workerSessions: capability.supported,
      workerSessionsDetail: capability.detail,
      dataDirIsolated: Boolean(isolated),
      dataDirSource: isolated?.source ?? null,
      isolatedProfileNames: isolated?.profileNames ?? [],
      dataDirKept: Boolean(isolated) && args.keepDataDirs,
      budgetUsd: args.budgetUsd,
      maxDurationMs: args.maxDurationMs,
      startedAt,
      endedAt,
      durationMs: endedAt - startedAt,
      timedOut: wait.timedOut,
      terminalStatus: wait.status,
      terminalPhase: wait.phase,
      runId,
      projectId,
      targets,
      confirmed,
      recall: num(card.recall, ratio(confirmed, targets)),
      precision: num(card.precision),
      decoys: num(card.decoys),
      decoyFalsePositives: num(card.decoyFalsePositives),
      unmatchedFalsePositives: num(card.unmatchedFalsePositives),
      chainsCompleted: num(card.chainsCompleted),
      chainsTotal: num(card.chainsTotal),
      costUsd: num(card.totalCostUsd, finalRun.spentUsd),
      assignmentsCompleted: assignmentDiagnostics.completed,
      assignmentsTotal: assignmentDiagnostics.total,
      investigationCompleted: assignmentDiagnostics.investigationCompleted,
      facts: factsCount,
      findingsPersisted: detail.findings.length,
      findingsSubmitted: submitted.length,
      baselineChecksExcluded: detail.findings.filter(f => f.findingKind === 'baseline_check').length,
      endpointsDiscovered: detail.endpoints.length,
      requestCount: gradeInput.requestLog.length,
      oracleEventCount: gradeInput.oracleEvents.length,
      families,
      sites,
      inert,
      snapshot: snapshotMeta,
      resumedFrom: snapshotMeta.resume.loaded ? snapshotMeta.resume.directory : null,
      snapshotSkippedMs: snapshotMeta.resume.loaded ? snapshotMeta.resume.skippedMs : 0,
      notes,
      shutdown: { engineBusy: -1, appStopped: false, canaryStopped: false },
    }

    const failureBuckets = (card.failureBuckets ?? {}) as Record<FailureTaxonomyBucket, number>
    const funnel: BenchmarkFunnel = {
      targetVulns: num(card.funnel?.targetVulns, targets),
      surfaceDiscovered: num(card.funnel?.surfaceDiscovered, detail.endpoints.length),
      hypothesisFormed: num(card.funnel?.hypothesisFormed),
      signalObserved: num(card.funnel?.signalObserved),
      specSubmitted: num(card.funnel?.specSubmitted, submitted.length),
      zeroLlmConfirmed: num(card.funnel?.zeroLlmConfirmed, llmMode === 'deterministic-no-llm' ? confirmed : 0),
    }
    storage.insertBenchmarkRun({
      suite: `reason:${app}:${args.mode}`,
      gitSha,
      modelRoutingConfig: {
        mode: args.mode,
        seed,
        seedSet,
        llm: llmMode,
        profiles: model.profiles,
        verifierBackend: backendKind,
        budgetUsd: args.budgetUsd,
        maxDurationMs: args.maxDurationMs,
        timedOut: wait.timedOut,
        snapshot: snapshotMeta.capture.requested
          ? { directory: snapshotMeta.capture.directory, captured: snapshotMeta.capture.captured, checkpoints: snapshotMeta.capture.checkpoints }
          : null,
        resumedFrom: snapshotMeta.resume.loaded ? snapshotMeta.resume.directory : null,
      },
      targetsTotal: targets,
      confirmedCount: confirmed,
      falsePositiveCount: num(card.decoyFalsePositives) + num(card.unmatchedFalsePositives),
      funnelCounts: funnel,
      failureTaxonomy: failureBuckets,
      totalCostUsd: meta.costUsd,
      durationMs: meta.durationMs ?? 0,
    })

    const jsonPath = join(args.outDir, `${slug}.json`)
    const mdPath = join(args.outDir, `${slug}.md`)
    const metaPath = join(args.outDir, `${slug}.meta.json`)
    writeOwnerOnly(jsonPath, `${runtime.renderScorecard(card, 'json')}\n`)
    writeOwnerOnly(mdPath, `${runtime.renderScorecard(card, 'md')}\n`)

    const result: ReasonCellResult = { meta, scorecard: card, jsonPath, mdPath, metaPath }

    // Teardown before publishing shutdown state (same ordering contract as the M0 harness).
    if (engine) { try { engineBusy = await stopEngine(engine) } catch { engineBusy = -1 } }
    if (backend instanceof LinuxWorkerBackend) { try { await backend.reclaimInactive() } catch { /* best-effort */ } }
    try { await canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
    if (started) { try { await started.stop(); appStopped = true } catch { appStopped = false } }
    engine = undefined
    started = undefined
    if (whiteBoxRoot) { try { unlockAndRemove(whiteBoxRoot) } catch { /* best-effort */ } }
    try { storage.close() } catch { /* already closed */ }
    if (isolated && !args.keepDataDirs) { try { unlockAndRemove(dataDir) } catch { /* best-effort */ } }
    unregisterCleanup()

    meta.shutdown = { engineBusy, appStopped, canaryStopped }
    if (engineBusy > 0) process.stderr.write(`warning: ${engineBusy} execution task(s) still active after stop for ${slug}\n`)
    if (!appStopped) process.stderr.write(`warning: reason-bench app for ${slug} did not report a clean stop\n`)
    writeOwnerOnly(metaPath, `${JSON.stringify(redactJsonValue(meta, []), null, 2)}\n`)
    return result
  } finally {
    // Failure path teardown: the registry closure is idempotent and stays registered until the
    // success path removes it.
    if (engine || started) {
      try { await cleanup.runAll() } catch { /* best-effort */ }
    }
    if (whiteBoxRoot) { try { unlockAndRemove(whiteBoxRoot) } catch { /* best-effort */ } }
    try { storage.close() } catch { /* already closed */ }
    if (isolated && !args.keepDataDirs) { try { unlockAndRemove(dataDir) } catch { /* best-effort */ } }
  }
}

// ---------------------------------------------------------------------------------------------
// Aggregation: floor, ΔReasoning, $/additive confirmed, budget × duration curve
// ---------------------------------------------------------------------------------------------

export interface ReasonAggregate {
  cells: number
  targets: number
  confirmed: number
  recall: number
  precision: number
  decoys: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  chainsCompleted: number
  chainsTotal: number
  families: Record<string, ReasonFamilyRow>
  sites: ReasonSiteRow[]
  costUsd: number
  durationMs: number
  assignmentsCompleted: number
  assignmentsTotal: number
}

export function aggregateCells(cells: ReasonCellMeta[]): ReasonAggregate {
  const families = emptyFamilyTable()
  const sites: ReasonSiteRow[] = []
  let targets = 0
  let confirmed = 0
  let decoys = 0
  let decoyFP = 0
  let unmatchedFP = 0
  let chainsCompleted = 0
  let chainsTotal = 0
  let costUsd = 0
  let durationMs = 0
  let assignmentsCompleted = 0
  let assignmentsTotal = 0
  for (const cell of cells) {
    targets += cell.targets
    confirmed += cell.confirmed
    decoys += cell.decoys
    decoyFP += cell.decoyFalsePositives
    unmatchedFP += cell.unmatchedFalsePositives
    chainsCompleted += cell.chainsCompleted
    chainsTotal += cell.chainsTotal
    costUsd += cell.costUsd
    durationMs += cell.durationMs ?? 0
    assignmentsCompleted += cell.assignmentsCompleted
    assignmentsTotal += cell.assignmentsTotal
    for (const site of cell.sites) sites.push(site)
    for (const [family, row] of Object.entries(cell.families)) {
      const bucket = families[family] ?? (families[family] = { targets: 0, confirmed: 0, recall: 0 })
      bucket.targets += row.targets
      bucket.confirmed += row.confirmed
    }
  }
  finalizeFamilyTable(families)
  return {
    cells: cells.length,
    targets,
    confirmed,
    recall: ratio(confirmed, targets),
    // Aggregate precision: confirmed targets are the true positives; FP are the noise.
    precision: ratio(confirmed, confirmed + decoyFP + unmatchedFP),
    decoys,
    decoyFalsePositives: decoyFP,
    unmatchedFalsePositives: unmatchedFP,
    chainsCompleted,
    chainsTotal,
    families,
    sites,
    costUsd,
    durationMs,
    assignmentsCompleted,
    assignmentsTotal,
  }
}

function readMetaArtifacts(dirs: string[]): ReasonCellMeta[] {
  const out = new Map<string, ReasonCellMeta>()
  for (const dir of dirs) {
    if (!existsSync(dir)) continue
    let entries: string[]
    try { entries = readdirSync(dir) } catch { continue }
    for (const entry of entries) {
      if (!entry.endsWith('.meta.json')) continue
      const path = join(dir, entry)
      try {
        const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<ReasonCellMeta>
        if (parsed.schemaVersion !== 1) continue
        if (typeof parsed.app !== 'string' || typeof parsed.seed !== 'number' || typeof parsed.mode !== 'string') continue
        if (typeof parsed.targets !== 'number' || typeof parsed.confirmed !== 'number') continue
        if (parsed.llm !== 'agentic' && parsed.llm !== 'deterministic-no-llm') continue
        const key = `${parsed.app}:${parsed.seed}:${parsed.mode}:${parsed.llm}`
        // Current-run cells win over older artifacts for the same key.
        if (!out.has(key)) out.set(key, parsed as ReasonCellMeta)
      } catch { /* ignore unreadable artifacts */ }
    }
  }
  return [...out.values()]
}

export interface FloorBaseline {
  recall: number
  confirmed: number
  targets: number
  cells: number
  byApp: Record<string, { recall: number; confirmed: number; targets: number; cells: number }>
}

export function floorBaseline(cells: ReasonCellMeta[]): FloorBaseline | null {
  const floorCells = cells.filter(cell => cell.llm === 'deterministic-no-llm')
  if (!floorCells.length) return null
  const byApp: FloorBaseline['byApp'] = {}
  for (const cell of floorCells) {
    const row = byApp[cell.app] ?? (byApp[cell.app] = { recall: 0, confirmed: 0, targets: 0, cells: 0 })
    row.confirmed += cell.confirmed
    row.targets += cell.targets
    row.cells += 1
  }
  for (const row of Object.values(byApp)) row.recall = ratio(row.confirmed, row.targets)
  const confirmed = floorCells.reduce((n, cell) => n + cell.confirmed, 0)
  const targets = floorCells.reduce((n, cell) => n + cell.targets, 0)
  return { recall: ratio(confirmed, targets), confirmed, targets, cells: floorCells.length, byApp }
}

/** Agentic lift over the deterministic floor, and the cost of each additive confirmed site. */
export function reasoningLift(agentic: ReasonCellMeta[], floor: FloorBaseline | null): {
  agenticRecall: number
  floorRecall: number | null
  deltaReasoning: number | null
  additiveConfirmed: number | null
  costPerAdditiveConfirmedUsd: number | null
  costUsd: number
} {
  const agg = aggregateCells(agentic)
  if (!floor || !agentic.length) {
    return {
      agenticRecall: agg.recall,
      floorRecall: floor ? floor.recall : null,
      deltaReasoning: null,
      additiveConfirmed: null,
      costPerAdditiveConfirmedUsd: null,
      costUsd: agg.costUsd,
    }
  }
  const floorExpected = floor.recall * agg.targets
  const additiveConfirmed = agg.confirmed - floorExpected
  return {
    agenticRecall: agg.recall,
    floorRecall: floor.recall,
    deltaReasoning: agg.recall - floor.recall,
    additiveConfirmed,
    costPerAdditiveConfirmedUsd: additiveConfirmed > 0 ? agg.costUsd / additiveConfirmed : null,
    costUsd: agg.costUsd,
  }
}

export interface CurveRow {
  budgetUsd: number
  maxDurationMs: number
  cells: number
  targets: number
  confirmed: number
  recall: number
  costUsd: number
  avgDurationMs: number
}

export function budgetDurationCurve(cells: ReasonCellMeta[]): CurveRow[] {
  const groups = new Map<string, ReasonCellMeta[]>()
  for (const cell of cells) {
    if (cell.llm !== 'agentic') continue
    const key = `${cell.budgetUsd}:${cell.maxDurationMs}`
    const list = groups.get(key) ?? []
    list.push(cell)
    groups.set(key, list)
  }
  return [...groups.values()]
    .map(group => {
      const targets = group.reduce((n, c) => n + c.targets, 0)
      const confirmed = group.reduce((n, c) => n + c.confirmed, 0)
      const costUsd = group.reduce((n, c) => n + c.costUsd, 0)
      const durations = group.map(c => c.durationMs ?? 0)
      return {
        budgetUsd: group[0]!.budgetUsd,
        maxDurationMs: group[0]!.maxDurationMs,
        cells: group.length,
        targets,
        confirmed,
        recall: ratio(confirmed, targets),
        costUsd,
        avgDurationMs: durations.length ? Math.round(durations.reduce((n, d) => n + d, 0) / durations.length) : 0,
      }
    })
    .sort((a, b) => a.budgetUsd - b.budgetUsd || a.maxDurationMs - b.maxDurationMs)
}

export interface AntiHeuristicGate {
  ceiling: number
  recall: number
  confirmed: number
  targets: number
  passed: boolean
  sites: Array<{ app: string; seed: number; siteId: string; family: string; outcome: string }>
}

export function evaluateAntiHeuristicGate(cells: ReasonCellMeta[], ceiling = ANTI_HEURISTIC_CEILING): AntiHeuristicGate {
  const agg = aggregateCells(cells)
  const sites = cells.flatMap(cell => cell.sites.map(site => ({
    app: cell.app,
    seed: cell.seed,
    siteId: site.siteId,
    family: site.family,
    outcome: site.confirmed ? 'confirmed' : 'missed',
  })))
  return {
    ceiling,
    recall: agg.recall,
    confirmed: agg.confirmed,
    targets: agg.targets,
    passed: agg.recall <= ceiling,
    sites,
  }
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------

export interface ReasonReport {
  schemaVersion: 1
  generatedAt: string
  gitSha: string
  cells: ReasonCellMeta[]
  byMode: Array<{ app: string; mode: string; llm: LlmMode; aggregate: ReasonAggregate }>
  agentic: ReasonAggregate
  floorRun: ReasonAggregate | null
  floor: FloorBaseline | null
  lift: ReturnType<typeof reasoningLift>
  curve: CurveRow[]
  gate: AntiHeuristicGate | null
  notes: string[]
}

export function buildReasonReport(cells: ReasonCellMeta[], floorCells: ReasonCellMeta[], gitSha: string): ReasonReport {
  const agenticCells = cells.filter(cell => cell.llm === 'agentic')
  const floorRunCells = cells.filter(cell => cell.llm === 'deterministic-no-llm')
  const allFloor = floorCells.length ? floorCells : floorRunCells
  const floor = floorBaseline(allFloor)
  const notes: string[] = []
  if (agenticCells.length && !floor) {
    notes.push('no --no-llm floor cells supplied: ΔReasoning is n/a (run --no-llm or pass --floor-from <dir>)')
  }
  if (agenticCells.length && floor) {
    const agenticApps = new Set(agenticCells.map(cell => cell.app))
    const floorApps = new Set(allFloor.map(cell => cell.app))
    if ([...agenticApps].some(app => !floorApps.has(app))) {
      notes.push('floor does not cover every agentic app; ΔReasoning extrapolates the floor recall across apps')
    }
    const agenticModes = new Set(agenticCells.map(cell => cell.mode))
    const floorModes = new Set(allFloor.map(cell => cell.mode))
    if ([...agenticModes].some(mode => !floorModes.has(mode))) {
      notes.push('floor was measured in a different mode than the agentic cells; ΔReasoning mixes modes')
    }
  }
  if (new Set(cells.map(cell => cell.mode)).size > 1) {
    notes.push('cells span multiple modes; headline metrics aggregate across them (see per-mode table)')
  }
  if (cells.some(cell => cell.seedSet === 'held-out')) {
    notes.push('held-out cells use salted seeds; the salt is never persisted in any artifact')
  }

  const byModeMap = new Map<string, ReasonCellMeta[]>()
  for (const cell of cells) {
    const key = `${cell.app}:${cell.mode}:${cell.llm}`
    const list = byModeMap.get(key) ?? []
    list.push(cell)
    byModeMap.set(key, list)
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    gitSha,
    cells,
    byMode: [...byModeMap.values()].map(group => ({
      app: group[0]!.app,
      mode: group[0]!.mode,
      llm: group[0]!.llm,
      aggregate: aggregateCells(group),
    })),
    agentic: aggregateCells(agenticCells),
    floorRun: floorRunCells.length ? aggregateCells(floorRunCells) : null,
    floor,
    lift: reasoningLift(agenticCells, floor),
    curve: budgetDurationCurve(allFloor.concat(agenticCells)),
    gate: floorRunCells.length ? evaluateAntiHeuristicGate(floorRunCells) : null,
    notes,
  }
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`

function mdTable(headers: string[], rows: string[][]): string {
  const lines = [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`]
  for (const row of rows) lines.push(`| ${row.join(' | ')} |`)
  return lines.join('\n')
}

export function renderReasonReport(report: ReasonReport, format: 'json' | 'md'): string {
  if (format === 'json') return JSON.stringify(report, null, 2)

  const lines: string[] = []
  lines.push('# reason-bench reasoning scorecard')
  lines.push('')
  lines.push(`Generated ${report.generatedAt} · git ${report.gitSha}`)
  lines.push('')
  lines.push('## Headline')
  lines.push('')
  const agentic = report.agentic
  const lift = report.lift
  lines.push(mdTable(
    ['metric', 'value'],
    [
      ['agentic cells', String(agentic.cells)],
      ['confirmed recall', `${agentic.confirmed}/${agentic.targets} (${pct(agentic.recall)})`],
      ['precision (confirmed TP / TP+FP)', pct(agentic.precision)],
      ['decoy false positives', String(agentic.decoyFalsePositives)],
      ['unmatched false positives', String(agentic.unmatchedFalsePositives)],
      ['strict causal chains', `${agentic.chainsCompleted}/${agentic.chainsTotal}`],
      ['assignments completed / cell', agentic.cells ? (agentic.assignmentsCompleted / agentic.cells).toFixed(2) : '0'],
      ['cost', `$${agentic.costUsd.toFixed(4)}`],
      [
        '`Execution --no-llm` floor',
        lift.floorRecall === null ? 'n/a (no floor run)' : pct(lift.floorRecall),
      ],
      ['ΔReasoning (agentic − floor)', lift.deltaReasoning === null ? 'n/a' : `${(lift.deltaReasoning * 100).toFixed(1)}pp`],
      [
        '$ / additive confirmed',
        lift.costPerAdditiveConfirmedUsd === null ? 'n/a' : `$${lift.costPerAdditiveConfirmedUsd.toFixed(4)}`,
      ],
    ],
  ))
  lines.push('')

  lines.push('## Per cell')
  lines.push('')
  lines.push(mdTable(
    ['cell', 'llm', 'confirmed', 'recall', 'precision', 'decoyFP', 'chains', 'cost', 'duration'],
    report.cells.map(cell => [
      cell.cell,
      cell.llm === 'agentic' ? 'agentic' : 'floor',
      `${cell.confirmed}/${cell.targets}`,
      pct(cell.recall),
      pct(cell.precision),
      String(cell.decoyFalsePositives),
      `${cell.chainsCompleted}/${cell.chainsTotal}`,
      `$${cell.costUsd.toFixed(4)}`,
      `${Math.round((cell.durationMs ?? 0) / 1000)}s`,
    ]),
  ))
  lines.push('')

  lines.push('## Per family (A–F)')
  lines.push('')
  for (const group of report.byMode) {
    lines.push(`### ${group.app} · ${group.mode} · ${group.llm === 'agentic' ? 'agentic' : 'floor'}`)
    lines.push('')
    lines.push(mdTable(
      ['family', 'targets', 'confirmed', 'recall'],
      reasonFamilies.map(family => {
        const row = group.aggregate.families[family] ?? { targets: 0, confirmed: 0, recall: 0 }
        return [family, String(row.targets), String(row.confirmed), pct(row.recall)]
      }),
    ))
    lines.push('')
  }

  if (report.gate) {
    lines.push('## Anti-Heuristic Gate (`--no-llm`)')
    lines.push('')
    lines.push(`Floor recall **${pct(report.gate.recall)}** (${report.gate.confirmed}/${report.gate.targets}) `
      + `against a ${pct(report.gate.ceiling)} ceiling → **${report.gate.passed ? 'PASS' : 'FAIL'}**`)
    lines.push('')
    lines.push(mdTable(
      ['app', 'seed', 'site', 'family', 'outcome'],
      report.gate.sites.map(site => [
        site.app, String(site.seed), site.siteId, site.family, site.outcome,
      ]),
    ))
    lines.push('')
  }

  lines.push('## Budget × duration curve')
  lines.push('')
  lines.push(mdTable(
    ['budget', 'duration', 'cells', 'confirmed', 'recall', 'cost', 'avg wall clock'],
    report.curve.map(row => [
      `$${row.budgetUsd}`,
      `${Math.round(row.maxDurationMs / 60_000)}m`,
      String(row.cells),
      `${row.confirmed}/${row.targets}`,
      pct(row.recall),
      `$${row.costUsd.toFixed(4)}`,
      `${Math.round(row.avgDurationMs / 1000)}s`,
    ]),
  ))
  lines.push('')
  lines.push('Legend: recall = confirmed / targets from `gradeRun`; precision = confirmed / (confirmed + decoyFP + unmatchedFP); '
    + 'ΔReasoning = agentic recall − `--no-llm` floor recall; $/additive confirmed = agentic cost / '
    + '(agentic confirmed − floor recall × targets).')
  if (report.notes.length) {
    lines.push('')
    lines.push('## Notes')
    lines.push('')
    for (const note of report.notes) lines.push(`- ${note}`)
  }
  lines.push('')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------------

export function cellKeys(args: Pick<ReasonArgs, 'apps' | 'seeds'>): Array<{ app: ReasonAppName; seed: number }> {
  const cells: Array<{ app: ReasonAppName; seed: number }> = []
  for (const app of args.apps) for (const seed of args.seeds) cells.push({ app, seed })
  return cells
}

async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<Array<R | { error: Error; item: T }>> {
  const results: Array<R | { error: Error; item: T }> = new Array(items.length)
  let next = 0
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const index = next++
      if (index >= items.length) return
      try {
        results[index] = await worker(items[index]!, index)
      } catch (error) {
        results[index] = { error: error as Error, item: items[index]! }
      }
    }
  })
  await Promise.all(runners)
  return results
}

function printCellSummary(result: ReasonCellResult): void {
  const meta = result.meta
  process.stdout.write(
    `[reason-bench] finished ${meta.cell}: ${meta.confirmed}/${meta.targets} confirmed `
    + `(${pct(meta.recall)}), precision ${pct(meta.precision)}, decoyFP ${meta.decoyFalsePositives}, `
    + `chains ${meta.chainsCompleted}/${meta.chainsTotal}, $${meta.costUsd.toFixed(4)}, `
    + `${meta.assignmentsCompleted} assignment(s)${meta.inert ? ' [INERT]' : ''}`
    + `${meta.resumedFrom ? ` resumed=${meta.snapshotSkippedMs}ms-skipped` : ''}`
    + `${meta.snapshot.capture.requested ? ` snapshot=${meta.snapshot.capture.captured ? meta.snapshot.capture.checkpoints.join('+') : 'not-captured'}` : ''}\n`,
  )
}

function printReasoningSummary(report: ReasonReport): void {
  const lines: string[] = ['']
  lines.push('cell                             llm      confirmed  recall    precision decoyFP chains  cost')
  lines.push('-'.repeat(100))
  for (const cell of report.cells) {
    lines.push(
      `${cell.cell.padEnd(32)} ${(cell.llm === 'agentic' ? 'agentic' : 'floor').padEnd(8)} `
      + `${`${cell.confirmed}/${cell.targets}`.padEnd(10)} ${pct(cell.recall).padEnd(9)} `
      + `${pct(cell.precision).padEnd(9)} ${String(cell.decoyFalsePositives).padEnd(7)} `
      + `${`${cell.chainsCompleted}/${cell.chainsTotal}`.padEnd(7)} $${cell.costUsd.toFixed(4)}`,
    )
  }
  lines.push('-'.repeat(100))
  const lift = report.lift
  if (!report.agentic.cells) {
    lines.push(
      `FLOOR-ONLY run: ${report.floorRun?.confirmed ?? 0}/${report.floorRun?.targets ?? 0} confirmed `
      + `(${pct(report.floorRun?.recall ?? 0)}); no agentic cells in this invocation`,
    )
    process.stdout.write(`${lines.join('\n')}\n`)
    return
  }
  lines.push(
    `AGENTIC recall ${pct(report.agentic.recall)} (${report.agentic.confirmed}/${report.agentic.targets})`
    + ` · floor ${lift.floorRecall === null ? 'n/a' : pct(lift.floorRecall)}`
    + ` · ΔReasoning ${lift.deltaReasoning === null ? 'n/a' : `${(lift.deltaReasoning * 100).toFixed(1)}pp`}`
    + ` · precision ${pct(report.agentic.precision)}`
    + ` · chains ${report.agentic.chainsCompleted}/${report.agentic.chainsTotal}`
    + ` · $/additive ${lift.costPerAdditiveConfirmedUsd === null ? 'n/a' : `$${lift.costPerAdditiveConfirmedUsd.toFixed(4)}`}`,
  )
  process.stdout.write(`${lines.join('\n')}\n`)
}

async function listSeedsAndExit(runtime: ReasonRuntime): Promise<void> {
  const seeds = await runtime.listSeeds()
  process.stdout.write(`${JSON.stringify({ apps: [...reasonAppNames], seeds }, null, 2)}\n`)
}

function mergeFloorArtifacts(current: ReasonCellMeta[], dirs: string[]): ReasonCellMeta[] {
  if (!dirs.length) return []
  const artifacts = readMetaArtifacts(dirs).filter(cell => cell.llm === 'deterministic-no-llm')
  const currentKeys = new Set(current
    .filter(cell => cell.llm === 'deterministic-no-llm')
    .map(cell => `${cell.app}:${cell.seed}:${cell.mode}`))
  return artifacts.filter(cell => !currentKeys.has(`${cell.app}:${cell.seed}:${cell.mode}`))
}

function mergeCurveArtifacts(current: ReasonCellMeta[], dirs: string[]): ReasonCellMeta[] {
  if (!dirs.length) return []
  const artifacts = readMetaArtifacts(dirs)
  const currentKeys = new Set(current.map(cell => cell.cell))
  return artifacts.filter(cell => !currentKeys.has(cell.cell))
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const args = parseReasonArgs(argv)
  if (args.help) {
    process.stdout.write(usage)
    return 0
  }

  // Safety: loopback local-lab only, before any runtime or app boot.
  assertLocalLabAllowed()
  activeSalt = args.heldOut ? (process.env.KOVO_RB_HELDOUT_SALT ?? '') : ''
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })

  const runtime = await loadReasonRuntime()
  if (args.listSeeds) {
    await listSeedsAndExit(runtime)
    return 0
  }

  const cleanup = createCleanupRegistry(error =>
    process.stderr.write(`warning: cleanup step failed: ${redact(String((error as Error)?.message ?? error)).slice(0, 200)}\n`))
  let aborted = false
  const emergency = (code: number) => {
    if (aborted) return
    aborted = true
    process.stderr.write(`[reason-bench] signal received; stopping cells and reclaiming workers\n`)
    void cleanup.runAll().finally(() => process.exit(code))
  }
  process.once('SIGINT', () => emergency(130))
  process.once('SIGTERM', () => emergency(143))

  const cells = cellKeys(args)
  const llmLabel = args.noLlm ? 'deterministic-no-llm' : 'agentic'
  process.stdout.write(
    `[reason-bench] ${cells.length} cell(s): ${cells.map(c => `${c.app}@${c.seed}`).join(', ')} `
    + `mode=${args.mode} llm=${llmLabel} budget=$${args.budgetUsd} duration=${Math.round(args.maxDurationMs / 60_000)}m\n`,
  )
  if (args.noLlm) {
    process.stdout.write(`[reason-bench] Anti-Heuristic Gate active: exit 3 when floor recall > ${pct(ANTI_HEURISTIC_CEILING)}\n`)
  }

  const results = await runWithConcurrency(cells, args.concurrency, async ({ app, seed }) => {
    if (aborted) throw new PreflightError('aborted by signal')
    process.stdout.write(`[reason-bench] starting ${app} seed=${seed} ${args.mode}\n`)
    const result = await runCell(args, app, seed, runtime, line => process.stdout.write(`${line}\n`), cleanup)
    printCellSummary(result)
    return result
  })

  const failures = results.filter((r): r is { error: Error; item: { app: ReasonAppName; seed: number } } => 'error' in r)
  const ok = results.filter((r): r is ReasonCellResult => !('error' in r))
  let exitCode = 0

  if (ok.length) {
    const currentMeta = ok.map(result => result.meta)
    const floorExtra = mergeFloorArtifacts(currentMeta, args.floorFrom)
    const curveExtra = mergeCurveArtifacts(currentMeta, args.curveFrom)
    const report = buildReasonReport(
      currentMeta,
      currentMeta.filter(cell => cell.llm === 'deterministic-no-llm').concat(floorExtra),
      resolveGitSha(),
    )
    if (curveExtra.length) report.curve = budgetDurationCurve(currentMeta.concat(curveExtra))

    const jsonPath = args.jsonPath ?? join(args.outDir, 'reason-report.json')
    const mdPath = args.mdPath ?? join(args.outDir, 'reason-report.md')
    writeOwnerOnly(jsonPath, `${renderReasonReport(report, 'json')}\n`)
    writeOwnerOnly(mdPath, `${renderReasonReport(report, 'md')}\n`)
    printReasoningSummary(report)
    process.stdout.write(`\nwrote ${jsonPath}\nwrote ${mdPath}\n`)

    if (report.gate) {
      process.stdout.write(`\nANTI-HEURISTIC GATE: overall --no-llm recall ${pct(report.gate.recall)} `
        + `(${report.gate.confirmed}/${report.gate.targets}) vs ceiling ${pct(report.gate.ceiling)}\n`)
      for (const meta of currentMeta) {
        for (const line of formatGateSiteLines(meta, meta.sites)) process.stdout.write(`${line}\n`)
      }
      if (!report.gate.passed) {
        process.stderr.write(
          `error: Anti-Heuristic Gate FAILED: deterministic floor recalls ${pct(report.gate.recall)} `
          + `(> ${pct(report.gate.ceiling)}); a deterministic heuristic solves reason-bench sites\n`,
        )
        exitCode = Math.max(exitCode, 3)
      }
    } else if (!args.noLlm) {
      process.stdout.write('\n(no --no-llm floor cells in this run; pass --floor-from <dir> for ΔReasoning)\n')
    }
  }

  for (const failure of failures) {
    process.stderr.write(`error: ${failure.item.app} seed=${failure.item.seed}: ${failure.error.message}\n`)
    exitCode = Math.max(exitCode, Number((failure.error as { exitCode?: number }).exitCode ?? 1))
  }

  const inert = ok.filter(result => result.meta.inert)
  if (inert.length) {
    process.stderr.write(
      `error: ${inert.length} agentic cell(s) were inert (no facts, no findings, no completed investigation); `
      + 'their scorecards are not investigation evidence\n',
    )
    exitCode = Math.max(exitCode, 2)
  }

  return exitCode
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  main()
    .then(code => {
      process.exitCode = code
      // Deterministic CLI teardown: engine timers/sockets can outlive a completed run.
      // Artifacts are written synchronously, so exit once the current turn drains.
      setImmediate(() => process.exit(code))
    })
    .catch(error => {
      process.stderr.write(`error: ${(error as Error).message}\n`)
      process.exit(Number((error as { exitCode?: number }).exitCode ?? 1))
    })
}
