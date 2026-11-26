#!/usr/bin/env node
/**
 * Kovo Hunter v8 Multi-Hop SaaS Product Benchmark Runner (plans/v8.md §Evaluation).
 *
 * Drives the *real* `Execution` loop (deterministic `--no-llm` floor OR agentic `--verifier docker`)
 * against `benchmarks/multihop-saas/` multi-service loopback SaaS archetypes and computes:
 *
 *   - Two-Side Confirmation: `ChainOracle v2` (ordered causal DAG from an attacker persona, zero
 *     shortcut violations) AND host-verified Kovo Hunter `CompositeProofReceipt` (Mode A clean replay)
 *   - Hop-Depth Funnel: `H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed`
 *     plus per-hop drop reasons and 3–4 hop vs 5–6 hop depth-tier recall
 *   - Efficiency metrics: `TP/$` and `TP/10m`
 *   - Hardened-twin decoy FP count (`must be 0`, 100% worst-run precision gate)
 *   - Anti-Heuristic Gate (`--no-llm <= 5%` overall chain recall, exit 3 on violation)
 *   - Fail-fast preflight guard refusing model profile + `local-jq` (inert run -> exit 2)
 *   - ΔReasoning against `--floor-from` `--no-llm` cells and budget × duration scaling matrix
 *
 * `benchmarks/multihop-saas/run.ts` is loaded strictly via lazy dynamic import so `tsc --noEmit`
 * and `--help` succeed cleanly even before the benchmark track merges.
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
import { DatabaseSync } from 'node:sqlite'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'

import type {
  BenchmarkFunnel,
  FailureTaxonomyBucket,
  RunTelemetry,
  SubmittedFinding,
} from '../benchmarks/realistic-bench/lib/types.ts'
import { assertLocalLabAllowed } from '../benchmarks/realistic-bench/lib/safety.ts'
import { maxWorkerConcurrency } from '../src/domain.ts'
import type { Finding } from '../src/domain.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { CompositeProofReceipt, CompositeReceiptVerification } from '../src/server/composite-receipt.ts'
import { Execution } from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { inspectModelProfileLoad } from '../src/server/model-settings.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { redact, redactJsonValue } from '../src/server/redact.ts'
import {
  applyRunSnapshot,
  assertSnapshotUsable,
  captureRunSnapshot,
  copySnapshotDatabase,
  readRunSnapshot,
  SnapshotError,
} from '../src/server/run-snapshot.ts'
import type { SnapshotCheckpoint } from '../src/server/run-snapshot.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import type { VerifierBackendKind } from './benchmark-backend.ts'
import { selectVerifierBackend } from './benchmark-backend.ts'
import { resolveOobCallbackPorts } from './benchmark-env.ts'
import {
  PreflightError,
  acquireCredentialsDirEnv,
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
// Lazy runtime contract with benchmarks/multihop-saas/run.ts
// ---------------------------------------------------------------------------------------------

export const multihopDevAppNames = ['paygrid', 'shipforge', 'nexusiam'] as const
export const multihopSealedAppNames = ['connecthub'] as const
export const multihopAppNames = ['paygrid', 'shipforge', 'nexusiam', 'connecthub'] as const

export type MultihopDevAppName = typeof multihopDevAppNames[number]
export type MultihopSealedAppName = typeof multihopSealedAppNames[number]
export type MultihopAppName = typeof multihopAppNames[number]
export type MultihopMode = 'black-box' | 'grey-box' | 'white-box'
export type MultihopLlmMode = 'agentic' | 'deterministic-no-llm'

export interface MultihopApiRef {
  routeKey: string
  service?: string
  method: string
  path: string
  params: string[]
}

export interface MultihopPersona {
  id: string
  email: string
  password: string
  tenant: string
  tenantId?: string
  orgSlug?: string
  role: string
  rolesByTenant?: Record<string, string>
}

/** Mode-scoped briefing exposed to Kovo Hunter (never ground truth, never victim bot creds). */
export interface MultihopBriefing {
  app: MultihopAppName | string
  mode: MultihopMode
  origin: string
  /** Additional public entry origins for multi-service archetypes (edge/app/api/idp). */
  publicOrigins?: string[]
  origins?: Record<string, string>
  personas: MultihopPersona[]
  apiReference?: MultihopApiRef[]
  sourceDir?: string
}

export interface MultihopStartedApp {
  app: MultihopAppName | string
  origin: string
  primaryOrigin?: string
  origins?: Record<string, string>
  plan?: { seedSet?: 'dev' | 'held-out' }
  groundTruth: unknown
  sourceDir?: string
  oracle: {
    events(): unknown[]
    requests(): unknown[]
    egress?(): unknown[]
    chainStates?(): unknown[]
    export?(): unknown
    reset?(): void
  }
  stop(): Promise<void>
}

export interface SubmittedCompositeProof {
  findingId?: string
  chainId: string
  terminalVulnClass: string
  hopCount: number
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript'
  confirmed: boolean
  attackerProvenanceValid: boolean
  modeBVerified?: boolean
  receipt?: CompositeProofReceipt
  verification?: CompositeReceiptVerification
}

export interface MultihopGradeInput {
  groundTruth: unknown
  findings: SubmittedFinding[]
  compositeReceipts?: SubmittedCompositeProof[]
  oracleEvents: unknown[]
  requestLog: unknown[]
  egressLog: unknown[]
  oracleExport?: unknown
  telemetry: RunTelemetry
  mode: MultihopMode
}

export const HOP_DROP_REASONS = [
  'capability_not_extracted',
  'pivot_not_discovered',
  'edge_binding_rejected',
  'replay_failed',
  'budget_exhausted',
  'persona_shortcut_rejected',
  'other',
] as const
export type HopDropReason = typeof HOP_DROP_REASONS[number]

export interface MultihopChainVerdict {
  chainId: string
  expectedHops: number
  /** Highest hop reached cleanly according to ChainOracle v2 (0..expectedHops). */
  maxHopReached: number
  /** Side 1: ChainOracle v2 observed the complete ordered causal DAG. */
  oracleObserved: boolean
  /** Side 1 anti-shortcut invariant: true if any forbidden privileged persona was used. */
  forbiddenShortcutViolation?: boolean
  /** Side 2: Kovo Hunter emitted a host-verified Mode-A CompositeProofReceipt for this chain. */
  compositeReceiptConfirmed: boolean
  /** True iff Side 1 (no shortcut) AND Side 2 both pass. */
  twoSideConfirmed: boolean
  /** Optional replay mode recorded by Kovo Hunter's receipt. */
  replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
  /** Diagnostic reason when the chain did not reach two-side confirmation. */
  dropReason?: HopDropReason | null
  matchedFindingIds?: string[]
  oracleEventSeqs?: number[]
  terminalVulnClass?: string | null
}

export interface MultihopTwinVerdict {
  twinId: string
  baseChainId?: string
  vulnClass?: string
  falsePositive: boolean
  matchedFindingIds?: string[]
  reason?: string
}

export interface HopDepthFunnel {
  totalChains: number
  H1: number
  H2: number
  H3: number
  H4Plus: number
  FinalOracle: number
  CompositeReceiptConfirmed: number
  dropReasons: Record<HopDropReason, number>
}

export interface MultihopScorecard {
  app: string
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: string
  chainsTotal: number
  chainsOracleObserved?: number
  chainsCompositeConfirmed?: number
  chainsConfirmed: number
  recall?: number
  precision: number
  hardenedTwinsTotal?: number
  hardenedTwinDecoyFps?: number
  decoys?: number
  decoyFalsePositives?: number
  unmatchedFalsePositives: number
  duplicateFindings?: number
  totalCostUsd: number
  hopFunnel?: Partial<HopDepthFunnel>
  funnel?: Partial<BenchmarkFunnel>
  failureBuckets?: Partial<Record<FailureTaxonomyBucket, number>>
  chains?: MultihopChainVerdict[]
  hardenedTwins?: MultihopTwinVerdict[]
}

export interface MultihopRuntime {
  startMultihopApp(opts: {
    app: MultihopAppName
    seed: number
    heldOutSalt?: string
    oobCallbackPorts?: number[]
  }): Promise<MultihopStartedApp>
  briefingFor(app: MultihopStartedApp, mode: MultihopMode): MultihopBriefing
  gradeRun(input: MultihopGradeInput): MultihopScorecard
  renderScorecard(card: MultihopScorecard | MultihopScorecard[], format: 'json' | 'md'): string
  listSeeds(): unknown
}

const MULTIHOP_RUNTIME_RELATIVE = 'benchmarks/multihop-saas/run.ts'
const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

export function multihopRuntimePath(root: string = REPO_ROOT): string {
  return join(root, MULTIHOP_RUNTIME_RELATIVE)
}

let cachedRuntime: MultihopRuntime | undefined

/**
 * Dynamically load and validate `benchmarks/multihop-saas/run.ts` at runtime.
 * Fails closed with `PreflightError` (exit 2) when the benchmark runtime has not landed yet.
 */
export async function loadMultihopRuntime(path: string = multihopRuntimePath()): Promise<MultihopRuntime> {
  if (cachedRuntime) return cachedRuntime
  if (!existsSync(path)) {
    throw new PreflightError(
      `multihop-saas runtime is not available yet (missing ${path}). `
      + 'Land benchmarks/multihop-saas/run.ts exporting startMultihopApp (or startApp), briefingFor, '
      + 'gradeRun, renderScorecard, and listSeeds, then re-run.',
    )
  }
  const mod = (await import(pathToFileURL(path).href)) as Record<string, unknown>
  const starter = typeof mod.startMultihopApp === 'function'
    ? mod.startMultihopApp
    : typeof mod.startApp === 'function'
      ? mod.startApp
      : undefined
  if (!starter) {
    throw new PreflightError(`${path} does not export startMultihopApp() or startApp()`)
  }
  const required = ['briefingFor', 'gradeRun', 'renderScorecard', 'listSeeds'] as const
  for (const name of required) {
    if (typeof mod[name] !== 'function') {
      throw new PreflightError(`${path} does not export ${name}() as required by plans/v8.md`)
    }
  }
  cachedRuntime = {
    startMultihopApp: starter as MultihopRuntime['startMultihopApp'],
    briefingFor: mod.briefingFor as MultihopRuntime['briefingFor'],
    gradeRun: mod.gradeRun as MultihopRuntime['gradeRun'],
    renderScorecard: mod.renderScorecard as MultihopRuntime['renderScorecard'],
    listSeeds: mod.listSeeds as MultihopRuntime['listSeeds'],
  }
  return cachedRuntime
}

// ---------------------------------------------------------------------------------------------
// CLI arguments & constants
// ---------------------------------------------------------------------------------------------

export const DEFAULT_BUDGET_USD = 5
export const DEFAULT_MAX_DURATION_MS = 30 * 60_000
export const DEFAULT_CONCURRENCY = 1
export const DEFAULT_SNAPSHOT_MAX_AGE_MS = 24 * 60 * 60_000
/** v8 Anti-Heuristic ceiling: Execution --no-llm MUST score <= 5% (target 0/16). */
export const ANTI_HEURISTIC_CEILING = 0.05

export interface MultihopArgs {
  apps: MultihopAppName[]
  seeds: number[]
  mode: MultihopMode
  heldOut: boolean
  budgetUsd: number
  maxDurationMs: number
  outDir: string
  concurrency: number
  /** Explicit in-run Execution worker slot override (1..16); omitted lets Execution dynamic AIMD scale. */
  workerConcurrency?: number
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
  floorFrom: string[]
  curveFrom: string[]
  jsonPath?: string
  mdPath?: string
  listSeeds: boolean
  help: boolean
}

export const usage = `Kovo Hunter v8 multihop-saas Product Benchmark Runner (real Execution loop, plans/v8.md §Evaluation)

Usage:
  KOVO_ALLOW_LOCAL_LAB=1 node scripts/benchmark-multihop.ts [flags]

Flags:
  --app <name|dev|all>      paygrid | shipforge | nexusiam | connecthub | dev | all
                            (default: dev = paygrid,shipforge,nexusiam; connecthub is SEALED for M4)
  --seed <n>                single dev seed (1..9999)
  --seeds <a,b,c>           comma-separated seeds
  --held-out                seeds are salted held-out (>= 1000000); requires KOVO_RB_HELDOUT_SALT
                            (the salt is never printed, stored, or committed)
  --mode <m>                black-box | grey-box | white-box (default: grey-box)
  --no-llm                  deterministic floor run AND Anti-Heuristic Gate:
                            exits 3 when overall chain recall > ${Math.round(ANTI_HEURISTIC_CEILING * 100)}%
  --verifier <kind>         auto | docker | local-jq (default: auto)
  --budget-usd <n>          per-cell USD budget (default: ${DEFAULT_BUDGET_USD})
  --max-duration-ms <n|10m|30m|60m>
                            wall-clock cap per cell (default: ${Math.round(DEFAULT_MAX_DURATION_MS / 60_000)}m)
  --duration-min <n>        alias for --max-duration-ms <n * 60000> (minutes, 1..360)
  --concurrency <n>         parallel app/seed cells (default: ${DEFAULT_CONCURRENCY})
  --worker-concurrency <n>  override in-run Execution worker slots (1..${maxWorkerConcurrency}; omitted = dynamic AIMD)
  --data-dir <path>         Kovo Hunter data dir (default: $KOVO_DATA_DIR)
  --isolate-data-dir        per-cell isolated data dir (default ON for --verifier docker;
                            host credentials read via KOVO_CREDENTIALS_DIR, no symlink, key never copied)
  --no-isolate-data-dir     disable default per-cell data-dir isolation for --verifier docker
  --keep-data-dirs          keep isolated per-cell data dirs after grading
  --allow-inert-workers     override fail-fast guard for model profile + local-jq (still exits 2)
  --snapshot-after-floor <dir>
                            capture a post-floor checkpoint for resume runs
  --resume-snapshot <dir>   resume an agentic run from a captured checkpoint
  --snapshot-max-age-ms <n> refuse checkpoints older than n ms (default 24h)
  --snapshot-refresh        recapture an existing checkpoint
  --allow-heldout-snapshot  allow reusing a salted held-out checkpoint
  --floor-from <dir[,dir]>  additional artifact dirs holding --no-llm floor cells (ΔReasoning)
  --curve-from <dir[,dir]>  additional artifact dirs feeding the budget × duration scaling matrix
  --out-dir <path>          artifact directory (default: .kovo/multihop-saas)
  --json <path>             write aggregate structured JSON report here
  --md <path>               write aggregate Markdown report here
  --list-seeds              print the multihop-saas seed catalogue as JSON and exit
  --help                    show this help

Metrics & Hard Gates:
  - Two-Side Confirmation:  ChainOracle v2 DAG (no shortcut personas) AND CompositeProofReceipt (Mode A)
  - Hop-Depth Funnel:       H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed
  - Efficiency:             TP/$ (M4 >= 0.50 at $5) and TP/10m (M4 >= 1.0 at 30m)
  - Hardened-Twin Decoys:   hardenedTwinDecoyFps MUST be 0 (100% worst-run precision)
  - Anti-Heuristic Floor:   --no-llm overall recall MUST be <= ${Math.round(ANTI_HEURISTIC_CEILING * 100)}%

Exit codes:
  0  PASS
  1  cell execution failure
  2  preflight error / inert agentic run (e.g., model profile + --verifier local-jq) / missing runtime
  3  Anti-Heuristic Gate violation (--no-llm recall > ${Math.round(ANTI_HEURISTIC_CEILING * 100)}%)
  4  Hardened-Twin Decoy FP / precision gate violation (hardenedTwinDecoyFps > 0)

Agentic runs require Docker workers:
  model profile + --verifier local-jq  -> FAIL FAST (exit 2) unless --no-llm
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

export function parseDurationMs(raw: string, flag = '--max-duration-ms'): number {
  const text = raw.trim()
  const match = /^(\d+(?:\.\d+)?)\s*([smh])$/i.exec(text)
  if (!match) {
    if (!/^\d+$/.test(text)) fail(`${flag} must be milliseconds or a duration like 10m/30m/60m (got '${raw}')`)
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

function parseAppList(raw: string | undefined): MultihopAppName[] {
  if (!raw || raw === 'dev') return [...multihopDevAppNames]
  if (raw === 'all') return [...multihopAppNames]
  const parts = raw.split(',').map(s => s.trim()).filter(Boolean)
  if (!parts.length) fail(`--app must be one of ${multihopAppNames.join(', ')}, dev, or all`)
  const resolved: MultihopAppName[] = []
  for (const part of parts) {
    if (part === 'dev') {
      for (const app of multihopDevAppNames) if (!resolved.includes(app)) resolved.push(app)
      continue
    }
    if (part === 'all') {
      for (const app of multihopAppNames) if (!resolved.includes(app)) resolved.push(app)
      continue
    }
    if (!(multihopAppNames as readonly string[]).includes(part)) {
      fail(`--app must be one of ${multihopAppNames.join(', ')}, dev, or all (got '${part}')`)
    }
    if (!resolved.includes(part as MultihopAppName)) resolved.push(part as MultihopAppName)
  }
  return resolved
}

function parseDirList(raw: string | undefined): string[] {
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

export function parseMultihopArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): MultihopArgs {
  const a: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '-h') {
      a.help = true
      continue
    }
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const eq = arg.indexOf('=')
    if (eq > 2) {
      a[arg.slice(2, eq)] = arg.slice(eq + 1)
      continue
    }
    const key = arg.slice(2)
    if (!key) fail('empty flag')
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) a[key] = true
    else { a[key] = next; i += 1 }
  }

  const known = new Set([
    'app', 'seed', 'seeds', 'held-out', 'mode', 'no-llm', 'verifier',
    'isolate-data-dir', 'no-isolate-data-dir',
    'concurrency', 'worker-concurrency', 'budget-usd', 'max-duration-ms', 'duration-min',
    'data-dir', 'keep-data-dirs',
    'allow-inert-workers', 'snapshot-after-floor', 'resume-snapshot', 'snapshot-max-age-ms',
    'snapshot-refresh', 'allow-heldout-snapshot', 'floor-from', 'curve-from', 'out-dir',
    'json', 'md', 'list-seeds', 'help',
  ])
  for (const key of Object.keys(a)) {
    if (!known.has(key)) {
      if (/salt/i.test(key)) {
        fail(`never pass a salt on the command line; set KOVO_RB_HELDOUT_SALT instead (got --${key})`)
      }
      fail(`unknown flag --${key}`)
    }
  }

  if (a.help === true) {
    return {
      apps: [...multihopDevAppNames],
      seeds: [1],
      mode: 'grey-box',
      heldOut: false,
      budgetUsd: DEFAULT_BUDGET_USD,
      maxDurationMs: DEFAULT_MAX_DURATION_MS,
      outDir: resolve('.kovo/multihop-saas'),
      concurrency: DEFAULT_CONCURRENCY,
      noLlm: false,
      isolateDataDir: false,
      keepDataDirs: false,
      allowInertWorkers: false,
      verifier: 'auto',
      snapshotMaxAgeMs: DEFAULT_SNAPSHOT_MAX_AGE_MS,
      snapshotRefresh: false,
      allowHeldoutSnapshot: false,
      floorFrom: [],
      curveFrom: [],
      listSeeds: false,
      help: true,
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
  if (a['max-duration-ms'] !== undefined && a['duration-min'] !== undefined) {
    fail('use either --max-duration-ms or --duration-min, not both')
  }
  let maxDurationMs = DEFAULT_MAX_DURATION_MS
  if (a['max-duration-ms'] !== undefined) {
    maxDurationMs = parseDurationMs(stringFlag(a, 'max-duration-ms') ?? '', '--max-duration-ms')
  } else if (a['duration-min'] !== undefined) {
    const rawMin = stringFlag(a, 'duration-min')
    if (rawMin === undefined) fail('--duration-min requires a positive number of minutes')
    const minutes = Number(rawMin.trim())
    if (!Number.isFinite(minutes) || minutes <= 0) {
      fail(`--duration-min must be a positive number of minutes (got '${rawMin}')`)
    }
    const ms = Math.round(minutes * 60_000)
    if (ms < 60_000 || ms > 6 * 3_600_000) {
      fail(`--duration-min must be between 1 and 360 minutes (got '${rawMin}')`)
    }
    maxDurationMs = ms
  }
  const concurrency = a.concurrency === undefined
    ? DEFAULT_CONCURRENCY
    : parsePositiveInt(stringFlag(a, 'concurrency') ?? '', '--concurrency')
  if (concurrency > 16) fail('--concurrency must be <= 16')

  let workerConcurrency: number | undefined
  if (a['worker-concurrency'] !== undefined) {
    const rawWorkerConc = stringFlag(a, 'worker-concurrency')
    if (rawWorkerConc === undefined) {
      fail(`--worker-concurrency requires an integer between 1 and ${maxWorkerConcurrency}`)
    }
    const parsedWorkerConc = Number(rawWorkerConc.trim())
    if (!Number.isInteger(parsedWorkerConc) || parsedWorkerConc < 1 || parsedWorkerConc > maxWorkerConcurrency) {
      fail(`--worker-concurrency must be an integer between 1 and ${maxWorkerConcurrency} (got '${rawWorkerConc}')`)
    }
    workerConcurrency = parsedWorkerConc
  }

  if (a['isolate-data-dir'] === true && a['no-isolate-data-dir'] === true) {
    fail('use either --isolate-data-dir or --no-isolate-data-dir, not both')
  }
  const isolateDataDir = a['isolate-data-dir'] === true
    ? true
    : a['no-isolate-data-dir'] === true
      ? false
      : verifierRaw === 'docker'

  const snapshotAfterFloorRaw = stringFlag(a, 'snapshot-after-floor')?.trim()
  if (a['snapshot-after-floor'] !== undefined && !snapshotAfterFloorRaw) {
    fail('--snapshot-after-floor requires a directory argument')
  }
  const resumeSnapshotRaw = stringFlag(a, 'resume-snapshot')?.trim()
  if (a['resume-snapshot'] !== undefined && !resumeSnapshotRaw) {
    fail('--resume-snapshot requires a directory argument')
  }
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

  const outDirRaw = stringFlag(a, 'out-dir') ?? '.kovo/multihop-saas'
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
    ...(workerConcurrency !== undefined ? { workerConcurrency } : {}),
    ...(dataDirRaw ? { dataDir: isAbsolute(dataDirRaw) ? dataDirRaw : resolve(dataDirRaw) } : {}),
    noLlm,
    isolateDataDir,
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
    floorFrom: parseDirList(stringFlag(a, 'floor-from')),
    curveFrom: parseDirList(stringFlag(a, 'curve-from')),
    ...(stringFlag(a, 'json') ? { jsonPath: resolve(stringFlag(a, 'json')!) } : {}),
    ...(stringFlag(a, 'md') ? { mdPath: resolve(stringFlag(a, 'md')!) } : {}),
    listSeeds: a['list-seeds'] === true,
    help: false,
  }
}

// ---------------------------------------------------------------------------------------------
// Preflight guard (model profile + local-jq MUST fail fast)
// ---------------------------------------------------------------------------------------------

export interface MultihopPreflightInput {
  hasProfiles: boolean
  noLlm: boolean
  allowInertWorkers: boolean
  backendKind: VerifierBackendKind
  workerSessions: boolean
  workerSessionsDetail: string
  profileLoadError?: string
}

/**
 * Enforces AGENTS.md fail-fast invariants:
 * 1) Agentic runs (`--no-llm` NOT set) MUST NEVER silently fall back to `deterministic-no-llm`
 *    when 0 usable model profiles are loaded (e.g. missing --data-dir, bad KOVO_CREDENTIALS_DIR,
 *    symlinked credentials, permission/pin failure).
 * 2) Agentic runs with a model profile + `local-jq` (or any backend incapable of opening worker
 *    sessions) fail immediately with exit code 2.
 */
export function assertMultihopPreflight(input: MultihopPreflightInput): void {
  if (!input.noLlm && !input.hasProfiles) {
    const detail = input.profileLoadError ? ` (${input.profileLoadError})` : ''
    throw new PreflightError(
      `refusing silent fallback to deterministic-no-llm: agentic mode was requested (--no-llm not set), `
      + `but 0 enabled model profiles loaded${detail}. `
      + 'Set --data-dir / KOVO_DATA_DIR (and ensure host credentials are non-symlink owner-only 0700/0600 files), '
      + 'or pass --no-llm for the deterministic floor.',
    )
  }
  if (!input.noLlm && input.hasProfiles && input.backendKind === 'local-jq' && !input.allowInertWorkers) {
    throw new PreflightError(
      'refusing inert agentic run: a model profile is enabled with --verifier local-jq '
      + '(local-jq is replay-only and cannot run Execution specialist workers). '
      + 'Re-run under `newgrp docker -c \'<command> --verifier docker\'` or pass --no-llm for the deterministic floor.',
    )
  }
  assertAgenticPreflight(input)
}

// ---------------------------------------------------------------------------------------------
// Two-Side Confirmation, Hop-Depth Funnel & Efficiency Metrics (pure, unit-testable)
// ---------------------------------------------------------------------------------------------

export interface TwoSideConfirmationSummary {
  chainsTotal: number
  oracleObserved: number
  compositeReceiptConfirmed: number
  twoSideConfirmed: number
  oracleOnlyCount: number
  receiptOnlyCount: number
  shortcutViolations: number
  modeBViolations: number
  verdicts: MultihopChainVerdict[]
}

export function normalizeDropReason(raw: unknown): HopDropReason | null {
  if (typeof raw !== 'string' || !raw.trim()) return null
  const value = raw.trim() as HopDropReason
  return (HOP_DROP_REASONS as readonly string[]).includes(value) ? value : 'other'
}

/**
 * Computes strict Two-Side Confirmation per plans/v8.md §ChainOracle v2:
 *   TP iff BOTH ChainOracle v2 observed the full ordered DAG from an attacker-eligible persona
 *   (no forbiddenShortcutViolation) AND Kovo Hunter emitted a host-verified Mode-A
 *   `CompositeProofReceipt` (`replayMode === 'fresh_clean_replay'`).
 */
export function evaluateTwoSideConfirmation(
  rawVerdicts: readonly MultihopChainVerdict[],
  compositeReceipts: readonly SubmittedCompositeProof[] = [],
): TwoSideConfirmationSummary {
  const receiptRank = (r: SubmittedCompositeProof): number => {
    if (r.confirmed && r.attackerProvenanceValid && r.replayMode === 'fresh_clean_replay') return 3
    if (r.confirmed) return 2
    if (r.replayMode === 'fresh_clean_replay') return 1
    return 0
  }
  const receiptByChainId = new Map<string, SubmittedCompositeProof>()
  const receiptByFindingId = new Map<string, SubmittedCompositeProof>()
  for (const r of compositeReceipts) {
    if (r.chainId) {
      const prev = receiptByChainId.get(r.chainId)
      if (!prev || receiptRank(r) > receiptRank(prev)) receiptByChainId.set(r.chainId, r)
    }
    if (r.findingId) {
      const prev = receiptByFindingId.get(r.findingId)
      if (!prev || receiptRank(r) > receiptRank(prev)) receiptByFindingId.set(r.findingId, r)
    }
  }

  let oracleObserved = 0
  let compositeReceiptConfirmed = 0
  let twoSideConfirmed = 0
  let oracleOnlyCount = 0
  let receiptOnlyCount = 0
  let shortcutViolations = 0
  let modeBViolations = 0

  const verdicts: MultihopChainVerdict[] = rawVerdicts.map(raw => {
    const matchedReceipt = receiptByChainId.get(raw.chainId)
      ?? (raw.matchedFindingIds ?? []).map(id => receiptByFindingId.get(id)).find(Boolean)

    const shortcutViolated = Boolean(raw.forbiddenShortcutViolation)
      || (matchedReceipt ? !matchedReceipt.attackerProvenanceValid : false)
    if (shortcutViolated) shortcutViolations += 1

    const replayMode = matchedReceipt?.replayMode ?? raw.replayMode ?? 'fresh_clean_replay'
    const modeBViolation = replayMode === 'one_shot_transcript'
    if (modeBViolation) modeBViolations += 1

    const side1Ok = Boolean(raw.oracleObserved) && !shortcutViolated
    const side2Ok = (
      matchedReceipt
        ? matchedReceipt.confirmed && matchedReceipt.attackerProvenanceValid && !modeBViolation
        : Boolean(raw.compositeReceiptConfirmed) && !shortcutViolated && !modeBViolation
    )
    const confirmed = side1Ok && side2Ok

    if (side1Ok) oracleObserved += 1
    if (side2Ok) compositeReceiptConfirmed += 1
    if (confirmed) twoSideConfirmed += 1
    else if (side1Ok && !side2Ok) oracleOnlyCount += 1
    else if (!side1Ok && side2Ok) receiptOnlyCount += 1

    let dropReason: HopDropReason | null = null
    if (!confirmed) {
      if (shortcutViolated) dropReason = 'persona_shortcut_rejected'
      else if (modeBViolation) dropReason = 'replay_failed'
      else dropReason = normalizeDropReason(raw.dropReason)
        ?? (side1Ok ? 'edge_binding_rejected' : raw.maxHopReached === 0 ? 'capability_not_extracted' : 'pivot_not_discovered')
    }

    return {
      ...raw,
      oracleObserved: side1Ok,
      forbiddenShortcutViolation: shortcutViolated,
      compositeReceiptConfirmed: side2Ok,
      twoSideConfirmed: confirmed,
      replayMode,
      dropReason,
    }
  })

  return {
    chainsTotal: verdicts.length,
    oracleObserved,
    compositeReceiptConfirmed,
    twoSideConfirmed,
    oracleOnlyCount,
    receiptOnlyCount,
    shortcutViolations,
    modeBViolations,
    verdicts,
  }
}

export function emptyDropReasons(): Record<HopDropReason, number> {
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

export function buildHopDepthFunnel(verdicts: readonly MultihopChainVerdict[]): HopDepthFunnel {
  const dropReasons = emptyDropReasons()
  let H1 = 0
  let H2 = 0
  let H3 = 0
  let H4Plus = 0
  let FinalOracle = 0
  let CompositeReceiptConfirmed = 0

  for (const v of verdicts) {
    const hop = Math.max(0, Math.floor(v.maxHopReached))
    if (hop >= 1) H1 += 1
    if (hop >= 2) H2 += 1
    if (hop >= 3) H3 += 1
    if (hop >= 4) H4Plus += 1
    if (v.oracleObserved && !v.forbiddenShortcutViolation) FinalOracle += 1
    if (v.twoSideConfirmed) CompositeReceiptConfirmed += 1
    else if (v.dropReason) {
      const bucket = normalizeDropReason(v.dropReason) ?? 'other'
      dropReasons[bucket] += 1
    }
  }

  return {
    totalChains: verdicts.length,
    H1,
    H2,
    H3,
    H4Plus,
    FinalOracle,
    CompositeReceiptConfirmed,
    dropReasons,
  }
}

export function aggregateHopDepthFunnels(funnels: readonly HopDepthFunnel[]): HopDepthFunnel {
  const dropReasons = emptyDropReasons()
  let totalChains = 0
  let H1 = 0
  let H2 = 0
  let H3 = 0
  let H4Plus = 0
  let FinalOracle = 0
  let CompositeReceiptConfirmed = 0

  for (const f of funnels) {
    totalChains += f.totalChains
    H1 += f.H1
    H2 += f.H2
    H3 += f.H3
    H4Plus += f.H4Plus
    FinalOracle += f.FinalOracle
    CompositeReceiptConfirmed += f.CompositeReceiptConfirmed
    for (const reason of HOP_DROP_REASONS) {
      dropReasons[reason] += f.dropReasons[reason] ?? 0
    }
  }

  return { totalChains, H1, H2, H3, H4Plus, FinalOracle, CompositeReceiptConfirmed, dropReasons }
}

export interface DepthTierBreakdown {
  hops3to4: { targets: number; confirmed: number; recall: number }
  hops5to6: { targets: number; confirmed: number; recall: number }
}

export function computeDepthTierBreakdown(verdicts: readonly MultihopChainVerdict[]): DepthTierBreakdown {
  let t34 = 0
  let c34 = 0
  let t56 = 0
  let c56 = 0
  for (const v of verdicts) {
    if (v.expectedHops >= 5) {
      t56 += 1
      if (v.twoSideConfirmed) c56 += 1
    } else {
      t34 += 1
      if (v.twoSideConfirmed) c34 += 1
    }
  }
  return {
    hops3to4: { targets: t34, confirmed: c34, recall: ratio(c34, t34) },
    hops5to6: { targets: t56, confirmed: c56, recall: ratio(c56, t56) },
  }
}

export interface EfficiencyMetrics {
  tpPerDollar: number | null
  tpPer10m: number | null
}

/** Compute TP/$ and TP/10m per plans/v8.md §M4 Efficiency Floor. */
export function computeEfficiencyMetrics(input: {
  confirmedChains: number
  costUsd: number
  durationMs: number
}): EfficiencyMetrics {
  const tpPerDollar = input.costUsd > 0 ? input.confirmedChains / input.costUsd : null
  const tpPer10m = input.durationMs > 0 ? input.confirmedChains / (input.durationMs / 600_000) : null
  return { tpPerDollar, tpPer10m }
}

// ---------------------------------------------------------------------------------------------
// Briefing / mode planning & CompositeProofReceipt extraction
// ---------------------------------------------------------------------------------------------

export interface MultihopCellPlan {
  briefing: MultihopBriefing
  publicOrigins: string[]
  loginPath: string | null
  openApi: { openapi: string; info: { title: string; version: string }; paths: Record<string, unknown> } | null
  personas: Array<{
    handle: string
    roleLabel: string
    role: string
    tenantId: string
    orgSlug?: string
    rolesByTenant?: Record<string, string>
    email: string
    password: string
    canaryMarkers: string[]
  }>
  capabilityTier: 3
  mission: string
}

/**
 * Format a briefing persona's role/tenant/orgSlug into the Kovo Hunter `roleLabel` contract
 * (`<role> [slug=<orgSlug>; memberships=<role>:<tenant>,...] (<tenantId>)`) so Execution's
 * tenant-scope parsers (`/\(([^()]+)\)\s*$/` and `parseRoleLabel`) extract both privilege and
 * primary tenantId cleanly while preserving orgSlug and secondary memberships for agentic reasoning.
 */
export function formatMultihopPersonaRoleLabel(persona: MultihopPersona): string {
  const tenantId = (persona.tenantId ?? persona.tenant ?? '').trim()
  const primaryRole = (
    persona.role?.trim()
    || (tenantId && persona.rolesByTenant?.[tenantId]?.trim())
    || Object.values(persona.rolesByTenant ?? {}).find(v => typeof v === 'string' && v.trim())?.trim()
    || 'member'
  )
  const membershipEntries = Object.entries(persona.rolesByTenant ?? {})
    .filter(([, r]) => Boolean(r?.trim()))
    .map(([t, r]) => `${r.trim()}:${t}`)
  const hasSecondaryScope = Object.keys(persona.rolesByTenant ?? {}).some(t => t !== tenantId)
  const metaParts: string[] = []
  const orgSlug = persona.orgSlug?.trim()
  if (orgSlug && orgSlug !== tenantId) metaParts.push(`slug=${orgSlug}`)
  if (hasSecondaryScope && membershipEntries.length) metaParts.push(`memberships=${membershipEntries.join(',')}`)

  const suffix = tenantId ? ` (${tenantId})` : ''
  const base = metaParts.length ? `${primaryRole} [${metaParts.join('; ')}]` : primaryRole
  const maxBaseLen = Math.max(1, 160 - suffix.length)
  return `${base.slice(0, maxBaseLen)}${suffix}`
}

function safeHandle(id: string): string {
  const cleaned = id.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '')
  return cleaned.length ? cleaned.slice(0, 48) : 'persona'
}

export function collectBriefingOrigins(briefing: MultihopBriefing): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  const push = (origin: string | undefined): void => {
    if (!origin) return
    const trimmed = origin.trim()
    if (!trimmed || seen.has(trimmed)) return
    seen.add(trimmed)
    out.push(trimmed)
  }
  push(briefing.origin)
  for (const origin of briefing.publicOrigins ?? []) push(origin)
  if (briefing.origins) {
    for (const [service, origin] of Object.entries(briefing.origins)) {
      if (service.endsWith('.internal') || service === 'internal') continue
      push(origin)
    }
  }
  return out
}

export async function probeLoginPath(
  origin: string,
  personas: ReadonlyArray<Pick<MultihopPersona, 'email' | 'password'>>,
): Promise<string | null> {
  const first = personas[0]
  if (!first) return null
  const candidates = [
    '/login',
    '/v1/auth/login',
    '/api/v1/auth/login',
    '/api/auth/login',
    '/api/v1/login',
    '/auth/login',
    '/api/login',
    '/session',
  ]
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
    } catch { /* try next conventional path */ }
  }
  return null
}

function selectLoginRoute(briefing: Pick<MultihopBriefing, 'apiReference'>): MultihopApiRef | null {
  const routes = briefing.apiReference ?? []
  const named = routes.filter(r => /login|signin|sign-in|session/i.test(`${r.routeKey} ${r.path}`))
  const posts = named.filter(r => r.method.toUpperCase() === 'POST')
  const ranked = (posts.length ? posts : named).slice().sort((a, b) => {
    const legacy = (r: MultihopApiRef) => (/legacy|v1\//i.test(r.routeKey) ? 1 : 0)
    const exact = (r: MultihopApiRef) => (/^(?:login|signin|session|(?:idp|scm|auth)\.login)$/i.test(r.routeKey) ? 0 : 1)
    return exact(a) - exact(b) || legacy(a) - legacy(b)
  })
  return ranked[0] ?? null
}

export function pickLoginPath(briefing: Pick<MultihopBriefing, 'apiReference'>): string | null {
  return selectLoginRoute(briefing)?.path ?? null
}

export function pickLoginUrl(
  briefing: Pick<MultihopBriefing, 'origin' | 'origins' | 'apiReference'>,
  loginPath: string | null,
): string | null {
  if (!loginPath) return null
  if (/^https?:\/\//i.test(loginPath)) return loginPath
  const routes = briefing.apiReference ?? []
  const matched = routes.find(r => r.path === loginPath && r.method.toUpperCase() === 'POST')
    ?? routes.find(r => r.path === loginPath)
  const serviceOrigin = matched?.service && briefing.origins?.[matched.service]
    ? briefing.origins[matched.service]!
    : briefing.origin
  return new URL(loginPath, serviceOrigin).toString()
}

export function briefingToOpenApiByOrigin(
  briefing: Pick<MultihopBriefing, 'app' | 'origin' | 'origins' | 'apiReference'>,
): Array<{ service: string; origin: string; spec: NonNullable<MultihopCellPlan['openApi']> }> {
  const routes = briefing.apiReference ?? []
  if (!routes.length) return []
  const hasOriginMap = Boolean(briefing.origins && Object.keys(briefing.origins).length > 0)
  const grouped = new Map<string, { service: string; origin: string; routes: MultihopApiRef[] }>()
  for (const route of routes) {
    let service = route.service ?? 'default'
    let origin: string | undefined
    if (route.service && hasOriginMap) {
      origin = briefing.origins![route.service]
      if (!origin) continue // skip internal-only services whose origins are not public
    } else {
      origin = briefing.origin
      service = 'default'
    }
    const existing = grouped.get(origin)
    if (existing) existing.routes.push(route)
    else grouped.set(origin, { service, origin, routes: [route] })
  }
  return [...grouped.values()].map(group => ({
    service: group.service,
    origin: group.origin,
    spec: briefingToOpenApi({ app: `${String(briefing.app)}-${group.service}`, apiReference: group.routes }),
  }))
}

export function briefingToOpenApi(
  briefing: Pick<MultihopBriefing, 'app' | 'apiReference'>,
): NonNullable<MultihopCellPlan['openApi']> {
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
    info: { title: `multihop-saas ${String(briefing.app)} API reference`, version: '1.0.0' },
    paths,
  }
}

export function planCell(briefing: MultihopBriefing, loginPath: string | null): MultihopCellPlan {
  if (briefing.mode === 'black-box' && briefing.apiReference) {
    fail('black-box briefings must not include an API reference')
  }
  if (briefing.mode === 'grey-box' && !briefing.apiReference) fail('grey-box briefings require an API reference')
  if (briefing.mode === 'white-box' && !briefing.sourceDir) fail('white-box briefings require a source directory')

  const handles = new Set<string>()
  const personas = briefing.personas.map(p => {
    const normalizedId = p.id.trim().toLowerCase()
    const normalizedRole = (p.role ?? '').trim().toLowerCase()
    if (normalizedId === 'admin_bot' || normalizedRole === 'bot') {
      fail(`refusing to register forbidden victim bot persona '${p.id}'`)
    }
    let handle = safeHandle(p.id)
    for (let n = 2; handles.has(handle); n += 1) handle = `${safeHandle(p.id)}-${n}`
    handles.add(handle)
    const tenantId = (p.tenantId ?? p.tenant ?? '').trim()
    const role = (
      p.role?.trim()
      || (tenantId && p.rolesByTenant?.[tenantId]?.trim())
      || 'member'
    )
    const roleLabel = formatMultihopPersonaRoleLabel({ ...p, role, tenant: tenantId, tenantId })
    return {
      handle,
      roleLabel,
      role,
      tenantId,
      ...(p.orgSlug?.trim() ? { orgSlug: p.orgSlug.trim() } : {}),
      ...(p.rolesByTenant ? { rolesByTenant: { ...p.rolesByTenant } } : {}),
      email: p.email,
      password: p.password,
      canaryMarkers: [] as string[],
    }
  })

  if (briefing.mode === 'black-box' && personas.length > 3) {
    fail('black-box briefings may expose at most 3 low-privilege attacker personas')
  }

  const publicOrigins = collectBriefingOrigins(briefing)
  const mission = [
    `Defensive multi-hop verification of the authorized local-lab target ${briefing.origin} (${String(briefing.app)}).`,
    'Map cross-service trust boundaries, entity lifecycles, and guard asymmetries across HTTP, GraphQL, SSE, async workers,',
    'IdP/OAuth, and edge/CDN layers. Compose verified intermediate capabilities into deterministic Mode-A clean-session',
    'multi-hop causal proofs starting strictly from attacker-eligible personas. Never report low-impact intermediate',
    'capabilities or hardened-twin decoys as standalone findings. Stay strictly within approved origins.',
  ].join(' ')

  return {
    briefing,
    publicOrigins,
    loginPath,
    openApi: briefing.apiReference ? briefingToOpenApi(briefing) : null,
    personas,
    capabilityTier: 3,
    mission,
  }
}

/**
 * Extract host-verified `CompositeProofReceipt` records attached to persisted findings/replaySpecs.
 * Pure helper; returns [] when findings carry only legacy single-hop specs.
 */
export function extractCompositeReceipts(input: {
  findings: readonly Finding[]
  replaySpecs: ReadonlyArray<{ id: string; findingId: string | null; spec: unknown; proofReceipt?: unknown }>
}): SubmittedCompositeProof[] {
  const out: SubmittedCompositeProof[] = []
  const indexByKey = new Map<string, number>()
  const skippedFindingIds = new Set<string>()
  for (const finding of input.findings) {
    if (finding.status === 'dismissed' || finding.supersededByFindingId) {
      if (finding.id) skippedFindingIds.add(finding.id)
    }
  }

  const candidateScore = (item: SubmittedCompositeProof): number => {
    const modeAConfirmed = item.confirmed && item.attackerProvenanceValid && item.replayMode === 'fresh_clean_replay'
    return (modeAConfirmed ? 8 : item.confirmed ? 4 : 0)
      + (item.verification ? 2 : 0)
      + (item.verification?.terminalEndpoint ? 1 : 0)
  }

  const inspectRecord = (findingId: string | undefined, raw: unknown): void => {
    if (findingId && skippedFindingIds.has(findingId)) return
    if (!raw || typeof raw !== 'object') return
    const obj = raw as Record<string, unknown>
    const candidate = (obj.compositeReceipt ?? obj.compositeProofReceipt ?? obj) as Record<string, unknown>
    const verification = (obj.compositeVerification ?? obj.verification) as Partial<CompositeReceiptVerification> | undefined
    if (
      typeof candidate.chainId === 'string'
      && typeof candidate.terminalVulnClass === 'string'
      && Array.isArray(candidate.hops)
      && candidate.hops.length >= 1
    ) {
      const replayMode = candidate.replayMode === 'one_shot_transcript' ? 'one_shot_transcript' : 'fresh_clean_replay'
      const confirmed = verification ? Boolean(verification.confirmed) : false
      const attackerProvenanceValid = verification
        ? verification.failedStage !== 'attacker_provenance'
        : false
      const entry: SubmittedCompositeProof = {
        ...(findingId ? { findingId } : {}),
        chainId: candidate.chainId,
        terminalVulnClass: candidate.terminalVulnClass,
        hopCount: candidate.hops.length,
        replayMode,
        confirmed,
        attackerProvenanceValid,
        ...(verification?.modeBVerified !== undefined ? { modeBVerified: verification.modeBVerified } : {}),
        receipt: candidate as unknown as CompositeProofReceipt,
        ...(verification ? { verification: verification as CompositeReceiptVerification } : {}),
      }
      const key = `${candidate.chainId}:${findingId ?? ''}`
      const existingIdx = indexByKey.get(key)
      if (existingIdx !== undefined) {
        if (candidateScore(entry) > candidateScore(out[existingIdx]!)) {
          out[existingIdx] = entry
        }
        return
      }
      indexByKey.set(key, out.length)
      out.push(entry)
    }
  }

  for (const row of input.replaySpecs) {
    const findingId = row.findingId ?? undefined
    if (findingId && skippedFindingIds.has(findingId)) continue
    inspectRecord(findingId, row.spec)
    if (row.proofReceipt !== undefined && row.proofReceipt !== null) {
      inspectRecord(findingId, row.proofReceipt)
    }
  }
  for (const finding of input.findings) {
    if (finding.status === 'dismissed' || finding.supersededByFindingId) continue
    inspectRecord(finding.id, (finding as unknown as { evidence?: unknown }).evidence)
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Structured Run Telemetry Extraction (Phase timing, Scheduler/Waste, CapabilityLedger, v8 SDK)
// ---------------------------------------------------------------------------------------------

export interface MultihopPhaseTimingTelemetry {
  codeAuditMs: number | null
  floorMs: number | null
  phaseBStartMs: number | null
  firstChainDispatchMs: number | null
  totalWallMs: number
}

export interface MultihopSchedulerTelemetry {
  maxEffectiveConcurrency: number
  workersStarted: number
  workersCompleted: number
  wallClockRotations: number
  maxWorkerWallMs: number | null
  totalPhaseBAssignments: number
  deadEndReprobes: number
  deadEndWastePct: number
}

export interface MultihopCapabilityLedgerTelemetry {
  nodesTotal: number
  capabilityOnlyCount: number
  sealedHandlesCount: number
  causalEdgesCount: number
  negativeEdgesPrunedCount: number
  compositeReceiptsCount: number
}

export interface MultihopRejectDetail {
  reason: string
  signature: string
  count: number
}

export interface MultihopV8SdkAdoptionTelemetry {
  kovoVerifyCalls: number
  sealCapabilityCalls: number
  hmacSignCalls: number
  jwtSignCalls: number
  awaitAsyncCalls: number
  proveCompositeCalls: number
  compositeConfirmed: number
  topRejectReasons: Array<{ reason: string; count: number }>
  topRejectDetails?: MultihopRejectDetail[]
}

export interface MultihopRunTelemetry {
  phaseTiming: MultihopPhaseTimingTelemetry
  scheduler: MultihopSchedulerTelemetry
  capabilityLedger: MultihopCapabilityLedgerTelemetry
  v8SdkAdoption: MultihopV8SdkAdoptionTelemetry
}

export interface MultihopFrontierWasteSnapshot {
  deadEndReprobeCount: number
  totalAssignmentsDispatched: number
  phaseBAssignments: number
  deadEndReprobeWasteRate: number
}

export interface ExtractMultihopRunTelemetryOptions {
  /** Override run wall-clock start timestamp (epoch ms). */
  runStartedAtMs?: number
  /** Override run wall-clock end timestamp (epoch ms). */
  runEndedAtMs?: number
  /** Optional Kovo Hunter data dir containing read-only `agent-sessions/*.sqlite` for SDK call counts. */
  dataDir?: string
  /** Optional live FrontierWaveController telemetry snapshot from Execution. */
  frontierTelemetry?: {
    totalAssignmentsDispatched?: number
    deadEndReprobeCount?: number
    deadEndReprobeWasteRate?: number
    prunedEdgeCount?: number
  } | null
  /** Optional pre-extracted composite receipt count from run grading. */
  compositeReceiptsExtracted?: number
}

type SqliteRow = Record<string, unknown>

function resolveSqliteHandle(
  db: DatabaseSync | Pick<Store, 'client' | 'directory'>,
): { client: DatabaseSync; directory?: string } {
  if ('client' in db && db.client && typeof db.client.prepare === 'function') {
    return { client: db.client, directory: db.directory }
  }
  return { client: db as DatabaseSync }
}

function listExistingTables(db: DatabaseSync): Set<string> {
  const rows = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as SqliteRow[]
  const out = new Set<string>()
  for (const row of rows) {
    if (typeof row.name === 'string') out.add(row.name)
  }
  return out
}

function listTableColumns(db: DatabaseSync, table: string): Set<string> {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as SqliteRow[]
  const out = new Set<string>()
  for (const row of rows) {
    if (typeof row.name === 'string') out.add(row.name)
  }
  return out
}

function safeJsonParse(raw: unknown): unknown {
  if (raw === null || raw === undefined) return null
  if (typeof raw === 'object') return raw
  if (typeof raw !== 'string' || !raw.trim()) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function finiteNonNeg(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

function finitePos(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null
}

function normalizeRejectReason(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const cleaned = redact(raw).replace(/\s+/g, ' ').trim()
  if (!cleaned) return null
  return cleaned.slice(0, 80)
}

function bumpRejectReason(map: Map<string, number>, raw: unknown, delta = 1): void {
  const normalized = normalizeRejectReason(raw)
  if (!normalized || delta <= 0) return
  map.set(normalized, (map.get(normalized) ?? 0) + delta)
}

/**
 * Sanitize a rejection error message into a compact, secret-free failure signature (<= 140 chars).
 * Normalizes UUIDs, gx-IDs, capability handles, runtime IDs, IP/ports, and numbers to `<id>`,
 * and strips inline secrets and raw HTTP/HTML/JSON bodies.
 */
export function sanitizeRejectSignature(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const pemScrubbed = raw.replace(/-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g, '[redacted]')
  const lines = pemScrubbed
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean)
  if (!lines.length) return null
  let picked = lines[0]!
  if (/^Traceback \(most recent call last\):/i.test(picked)) {
    picked = lines[lines.length - 1]!
  } else if (lines.length > 1) {
    const errLine = lines.find(l => /\b(?:[A-Z][A-Za-z0-9]*Error|Exception|ERR_[A-Z0-9_]+|AssertionError)\b/.test(l))
    if (errLine) picked = errLine
  }
  // Strip raw HTTP/HTML/JSON bodies BEFORE heuristic `redact()` so `Authorization: ...` patterns
  // cannot swallow the `body={` marker and leave trailing JSON fields exposed.
  const bodyStripped = picked
    .replace(/^CompositeProofReceipt rejected at stage ['"][^'"]+['"]:\s*/i, '')
    .replace(/\b(body|responseBody|response|payload)\s*[:=]\s*(?:[\[{<]|["'][\[{<]).*$/i, '$1=<redacted>')
    .replace(/<!DOCTYPE[^>]*>.*$/i, '<html>')
    .replace(/<(?:html|head|body)\b[^>]*>.*$/i, '<html>')
    .replace(/\bHTTP\/\d(?:\.\d)?\s+\d{3}\b.*$/i, '<http>')
  let s = redact(bodyStripped)
    .replace(/\b(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id)\s*[:=]\s*(?:Bearer\s+|Basic\s+)?[^\s,;}"']+/gi, '$1=<redacted>')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]+/g, '<redacted>')
    .replace(/\{[^{}]{32,}\}/g, '<json>')
    .replace(/\{[^{}]{32,}\}/g, '<json>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<id>')
    .replace(/\bcap:[A-Za-z0-9._:-]+/g, '<id>')
    .replace(/\bgx[-_][A-Za-z0-9_-]+/gi, '<id>')
    .replace(/\b(?:ex|chain|job|run|sess|req|resp|oob|poll|spec|finding|worker|assign|gv)[-_](?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]+/gi, '<id>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<id>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b/g, '<id>:<id>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<id>')
    .replace(/:(\d{2,5})(?=[/\s"'`),;]|$)/g, ':<id>')
    .replace(/\bport\s+\d{2,5}\b/gi, 'port <id>')
    .replace(/(?<=\b[a-z]+_)\d+\b/gi, '<id>')
    .replace(/#\d+\b/g, '#<id>')
    .replace(/\b\d+\b/g, '<id>')
    .replace(/<id>(?:,\s*<id>)+/g, '<id>')
    .replace(/\s+/g, ' ')
    .trim()
  if (!s) return null
  if (s.length > 140) s = s.slice(0, 140).trimEnd()
  return s || null
}

function pickRejectSignature(
  primary: Record<string, unknown> | null | undefined,
  secondary?: Record<string, unknown> | null,
  reasonHint?: unknown,
): unknown {
  const nonEmptyStr = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)
  const firstMeaningful = (list: unknown): string | null => {
    if (!Array.isArray(list)) return null
    let fallback: string | null = null
    for (const item of list) {
      const t = nonEmptyStr(item)
      if (!t) continue
      if (!fallback) fallback = t
      if (!/^(?:rejected-by|missing-evidence):/i.test(t)) return t
    }
    return fallback
  }
  const hint = typeof reasonHint === 'string' ? reasonHint.trim().toLowerCase() : ''
  const detailStr = nonEmptyStr(secondary?.reason) ?? nonEmptyStr(secondary?.detail) ?? nonEmptyStr(primary?.detail)
  const stderrStr = nonEmptyStr(primary?.stderrPreview) ?? nonEmptyStr(primary?.stderr)
  const isExecGeneric = hint === 'execution' || hint === 'execution_failed'
    || (detailStr !== null && /^(?:script exited|execution failed|worker exited)/i.test(detailStr))
  if (stderrStr && (isExecGeneric || !detailStr)) return stderrStr
  if (detailStr) return detailStr
  const errStr = nonEmptyStr(primary?.error) ?? nonEmptyStr(primary?.message) ?? firstMeaningful(primary?.failures)
  if (errStr) return errStr
  if (Array.isArray(primary?.attempts)) {
    for (const att of primary.attempts) {
      if (!att || typeof att !== 'object') continue
      const a = att as Record<string, unknown>
      const attSig = nonEmptyStr(a.stderrPreview) ?? nonEmptyStr(a.stderr) ?? firstMeaningful(a.failures) ?? nonEmptyStr(a.error)
      if (attSig) return attSig
    }
  }
  return nonEmptyStr(primary?.reason)
    ?? firstMeaningful(primary?.missingEvidence)
    ?? nonEmptyStr(primary?.rejectedBy)
    ?? nonEmptyStr(secondary?.failedStage)
    ?? nonEmptyStr(primary?.failedStage)
    ?? nonEmptyStr(primary?.errorCode)
    ?? null
}

function bumpRejectDetail(
  map: Map<string, MultihopRejectDetail>,
  rawReason: unknown,
  rawSignature: unknown,
  delta = 1,
): void {
  const reason = normalizeRejectReason(rawReason)
  if (!reason || delta <= 0) return
  const signature = sanitizeRejectSignature(rawSignature) ?? sanitizeRejectSignature(reason) ?? reason
  const key = `${reason}\0${signature}`
  const prev = map.get(key)
  if (prev) prev.count += delta
  else map.set(key, { reason, signature, count: delta })
}

function isChainStepRow(row: {
  category?: unknown
  skills?: unknown
  depends_on_step_ids?: unknown
  depends_on_fact_ids?: unknown
  title?: unknown
}): boolean {
  const cat = typeof row.category === 'string' ? row.category.toLowerCase() : ''
  if (cat === 'chain' || cat === 'chain_step' || cat === 'multihop_chain') return true
  const skills = safeJsonParse(row.skills)
  if (Array.isArray(skills)) {
    for (const s of skills) {
      if (typeof s === 'string' && (s.startsWith('chain:') || s === 'chain-primitives' || s === 'multihop-chains')) {
        return true
      }
    }
  }
  const depSteps = safeJsonParse(row.depends_on_step_ids)
  if (Array.isArray(depSteps) && depSteps.length > 0) return true
  const title = typeof row.title === 'string' ? row.title.toLowerCase() : ''
  if (/\b(?:chain|multi-?hop|pivot)\b/.test(title)) return true
  return false
}

function countPatternMatches(text: string, re: RegExp): number {
  let count = 0
  re.lastIndex = 0
  while (re.exec(text) !== null) count += 1
  return count
}

function roundPct(rate: number): number {
  return Math.round(Math.max(0, rate) * 10_000) / 100
}

/**
 * Extract structured Phase-timing, Scheduler/Dead-End-Waste, CapabilityLedger, and v8-SDK-Adoption
 * telemetry from a Kovo Hunter run's SQLite database.
 *
 * Strictly queries structured metadata columns only (`runs`, `events`, `assignments`/`workers`,
 * `chain_steps`, `capability_nodes`, `capability_causal_edges`/`capability_edges`,
 * `capability_negative_edges`, `replay_specs`, `findings`) — never raw HTTP bodies or secrets.
 */
export function extractMultihopRunTelemetry(
  db: DatabaseSync | Pick<Store, 'client' | 'directory'>,
  runId: string,
  options: ExtractMultihopRunTelemetryOptions = {},
): MultihopRunTelemetry {
  const { client, directory } = resolveSqliteHandle(db)
  const tables = listExistingTables(client)
  const dataDir = options.dataDir ?? directory

  // ---- 1. Run anchor timestamp ----
  let runCreatedAt: number | null = null
  if (tables.has('runs')) {
    const cols = listTableColumns(client, 'runs')
    if (cols.has('id') && cols.has('created_at')) {
      const row = client.prepare('SELECT created_at FROM runs WHERE id = ?').get(runId) as SqliteRow | undefined
      runCreatedAt = finitePos(row?.created_at)
    }
  }

  // ---- 2. Chain steps lookup (to identify chain dispatches cleanly) ----
  const chainStepIds = new Set<string>()
  if (tables.has('chain_steps')) {
    const cols = listTableColumns(client, 'chain_steps')
    if (cols.has('id') && cols.has('run_id')) {
      const selectCols = ['id']
      for (const c of ['category', 'skills', 'depends_on_step_ids', 'depends_on_fact_ids', 'title']) {
        if (cols.has(c)) selectCols.push(c)
      }
      const rows = client.prepare(`SELECT ${selectCols.join(', ')} FROM chain_steps WHERE run_id = ?`).all(runId) as SqliteRow[]
      for (const row of rows) {
        if (typeof row.id === 'string' && isChainStepRow(row)) chainStepIds.add(row.id)
      }
    }
  }

  // ---- 3. Assignments / Workers table ----
  const assignmentTable = tables.has('assignments') ? 'assignments' : tables.has('workers') ? 'workers' : null
  const investigationAssignmentIds = new Set<string>()
  const allKnownAssignmentPhases = new Map<string, string>()
  const sessionIds = new Set<string>()
  let dbPhaseBAssignments = 0
  let dbPhaseBCompleted = 0
  let earliestPhaseBAssignmentAt: number | null = null
  let assignmentFlagDeadEndReprobes = 0
  let maxAssignmentTableWallMs: number | null = null
  let earliestAssignmentCreatedAt: number | null = null
  let latestAssignmentTs: number | null = null

  if (assignmentTable) {
    const cols = listTableColumns(client, assignmentTable)
    if (cols.has('run_id')) {
      const want = [
        'id', 'phase', 'status', 'session_id', 'created_at',
        'started_at', 'completed_at', 'ended_at', 'wall_ms', 'dead_end_reprobe',
      ].filter(c => cols.has(c))
      if (want.length > 0) {
        const rows = client.prepare(`SELECT ${want.join(', ')} FROM ${assignmentTable} WHERE run_id = ?`).all(runId) as SqliteRow[]
        for (const row of rows) {
          const id = typeof row.id === 'string' ? row.id : null
          const phase = typeof row.phase === 'string' ? row.phase : null
          const status = typeof row.status === 'string' ? row.status : null
          const createdAt = finitePos(row.created_at)
          const startedAt = finitePos(row.started_at)
          const endedAt = finitePos(row.completed_at) ?? finitePos(row.ended_at)
          const wallMs = finiteNonNeg(row.wall_ms)

          if (typeof row.session_id === 'string' && row.session_id.trim()) sessionIds.add(row.session_id.trim())
          if (createdAt !== null) {
            earliestAssignmentCreatedAt = earliestAssignmentCreatedAt === null ? createdAt : Math.min(earliestAssignmentCreatedAt, createdAt)
            latestAssignmentTs = latestAssignmentTs === null ? createdAt : Math.max(latestAssignmentTs, createdAt)
          }
          if (endedAt !== null) {
            latestAssignmentTs = latestAssignmentTs === null ? endedAt : Math.max(latestAssignmentTs, endedAt)
          }
          if (id && phase) allKnownAssignmentPhases.set(id, phase)

          const isPhaseB = phase === null || phase === 'investigation'
          if (isPhaseB) {
            dbPhaseBAssignments += 1
            if (id) investigationAssignmentIds.add(id)
            if (status === 'complete' || status === 'completed') dbPhaseBCompleted += 1
            const ts = startedAt ?? createdAt
            if (ts !== null) {
              earliestPhaseBAssignmentAt = earliestPhaseBAssignmentAt === null ? ts : Math.min(earliestPhaseBAssignmentAt, ts)
            }
            const measuredWall = wallMs ?? (startedAt !== null && endedAt !== null && endedAt >= startedAt
              ? endedAt - startedAt
              : createdAt !== null && endedAt !== null && endedAt >= createdAt
                ? endedAt - createdAt
                : null)
            if (measuredWall !== null) {
              maxAssignmentTableWallMs = maxAssignmentTableWallMs === null
                ? measuredWall
                : Math.max(maxAssignmentTableWallMs, measuredWall)
            }
          }
          if (row.dead_end_reprobe === 1 || row.dead_end_reprobe === true) {
            assignmentFlagDeadEndReprobes += 1
          }
        }
      }
    }
  }

  // ---- 4. Events scan (structured fields only) ----
  let earliestEventAt: number | null = null
  let latestEventAt: number | null = null
  let codeAuditStartAt: number | null = null
  let codeAuditEndAt: number | null = null
  let codeAuditElapsedOverride: number | null = null
  let floorStartAt: number | null = null
  let floorEndAt: number | null = null
  let floorMsReported: number | null = null
  let phaseBStartEventAt: number | null = null
  let firstChainDispatchEventAt: number | null = null
  let firstChainRoundDispatchAt: number | null = null

  let maxEffectiveConcurrency = 0
  let eventWorkersStarted = 0
  let eventWorkersCompleted = 0
  let eventWorkersCompletedAll = 0
  let eventWallClockRotations = 0
  let metricsWallClockRotations = 0
  let metricsPhaseBAssignments = 0
  let frontierSummaryDispatched = 0
  let frontierSummaryDeadEndReprobes = 0
  let explicitDeadEndReprobeEvents = 0
  let negativeEdgePrunedEvents = 0
  let maxEventWorkerWallMs: number | null = null
  const workerStartById = new Map<string, number>()
  const workerIntervals: Array<{ start: number; end: number }> = []

  let eventKovoVerifyCalls = 0
  const seenKovoVerifyCallIds = new Set<string>()
  let eventSealCapabilityCalls = 0
  let eventHmacSignCalls = 0
  let eventJwtSignCalls = 0
  let eventAwaitAsyncCalls = 0
  let eventProveCompositeCalls = 0
  let eventCompositeRejected = 0
  const confirmedCompositeChainIds = new Set<string>()
  let anonymousCompositeConfirmed = 0
  const rejectReasons = new Map<string, number>()
  const rejectDetails = new Map<string, MultihopRejectDetail>()

  const bumpSdkOp = (op: unknown, count = 1): void => {
    if (typeof op !== 'string' || count <= 0) return
    const key = op.trim()
    if (key === 'capability.seal' || key === 'seal_capability' || key === 'sealCapabilityCalls') eventSealCapabilityCalls += count
    else if (key === 'crypto.hmacSign' || key === 'hmac_sign' || key === 'hmacSignCalls') eventHmacSignCalls += count
    else if (key === 'crypto.jwtSign' || key === 'jwt_sign' || key === 'jwtSignCalls') eventJwtSignCalls += count
    else if (key === 'async.awaitResult' || key === 'await_async' || key === 'awaitAsyncCalls') eventAwaitAsyncCalls += count
    else if (key === 'composite.verify' || key === 'prove_composite' || key === 'proveCompositeCalls') eventProveCompositeCalls += count
  }

  const recordPhaseBStart = (ts: number | null): void => {
    if (ts === null) return
    phaseBStartEventAt = phaseBStartEventAt === null ? ts : Math.min(phaseBStartEventAt, ts)
  }

  const recordFirstChainDispatch = (ts: number | null): void => {
    if (ts === null) return
    firstChainDispatchEventAt = firstChainDispatchEventAt === null ? ts : Math.min(firstChainDispatchEventAt, ts)
  }

  if (tables.has('events')) {
    const cols = listTableColumns(client, 'events')
    if (cols.has('run_id') && cols.has('kind')) {
      const selectCols = ['kind']
      if (cols.has('detail')) selectCols.push('detail')
      if (cols.has('created_at')) selectCols.push('created_at')
      const orderBy = cols.has('created_at')
        ? (cols.has('id') ? 'ORDER BY created_at ASC, id ASC' : 'ORDER BY created_at ASC')
        : (cols.has('id') ? 'ORDER BY id ASC' : '')
      const rows = client.prepare(`SELECT ${selectCols.join(', ')} FROM events WHERE run_id = ? ${orderBy}`).all(runId) as SqliteRow[]

      for (const row of rows) {
        const kind = typeof row.kind === 'string' ? row.kind : ''
        const createdAt = finitePos(row.created_at)
        const parsedDetail = safeJsonParse(row.detail)
        const detail = (parsedDetail && typeof parsedDetail === 'object' && !Array.isArray(parsedDetail))
          ? parsedDetail as Record<string, unknown>
          : {}

        if (createdAt !== null) {
          earliestEventAt = earliestEventAt === null ? createdAt : Math.min(earliestEventAt, createdAt)
          latestEventAt = latestEventAt === null ? createdAt : Math.max(latestEventAt, createdAt)
        }

        // --- Phase Timing events ---
        if (kind === 'code_audit.started') {
          if (createdAt !== null) codeAuditStartAt = codeAuditStartAt === null ? createdAt : Math.min(codeAuditStartAt, createdAt)
        } else if (kind === 'code_audit.complete' || kind === 'code_audit.wall_clock_rotated') {
          if (createdAt !== null) codeAuditEndAt = codeAuditEndAt === null ? createdAt : Math.max(codeAuditEndAt, createdAt)
          const elapsed = finiteNonNeg(detail.elapsedMs) ?? finiteNonNeg(detail.durationMs)
          if (elapsed !== null) {
            codeAuditElapsedOverride = codeAuditElapsedOverride === null ? elapsed : Math.max(codeAuditElapsedOverride, elapsed)
          }
        } else if (kind === 'deterministic_lane.started' || kind === 'floor.started') {
          if (createdAt !== null) floorStartAt = floorStartAt === null ? createdAt : Math.min(floorStartAt, createdAt)
        } else if (kind === 'deterministic_floor.summary' || kind === 'deterministic_lane.metrics' || kind === 'deterministic_engine.summary') {
          if (createdAt !== null) floorEndAt = floorEndAt === null ? createdAt : Math.max(floorEndAt, createdAt)
          const pt = (detail.phaseTimings && typeof detail.phaseTimings === 'object')
            ? detail.phaseTimings as Record<string, unknown>
            : null
          const fm = finiteNonNeg(pt?.floorMs) ?? finiteNonNeg(detail.laneWallMs) ?? finiteNonNeg(detail.durationMs)
          if (fm !== null) floorMsReported = fm
          recordPhaseBStart(finitePos(pt?.agentDispatchAt))
        } else if (kind === 'investigation.started') {
          recordPhaseBStart(createdAt)
        } else if (kind === 'scheduler.dispatch') {
          recordPhaseBStart(createdAt)
          const effConc = finiteNonNeg(detail.effectiveConcurrency) ?? finiteNonNeg(detail.slots)
          if (effConc !== null) maxEffectiveConcurrency = Math.max(maxEffectiveConcurrency, Math.floor(effConc))
          const byLane = (detail.selectedByLane && typeof detail.selectedByLane === 'object')
            ? detail.selectedByLane as Record<string, unknown>
            : null
          const chainSelected = finiteNonNeg(byLane?.chain) ?? 0
          const activeChains = finiteNonNeg(detail.activeChainCount) ?? 0
          const readyChains = finiteNonNeg(detail.readyChainSteps) ?? 0
          const dispatched = finiteNonNeg(detail.dispatched) ?? 0
          if (chainSelected > 0 || activeChains > 0 || (readyChains > 0 && dispatched > 0 && byLane === null)) {
            recordFirstChainDispatch(createdAt)
          }
        } else if (kind === 'chain.round') {
          const dispatched = finiteNonNeg(detail.dispatched) ?? 0
          if (dispatched > 0 && createdAt !== null) {
            firstChainRoundDispatchAt = firstChainRoundDispatchAt === null ? createdAt : Math.min(firstChainRoundDispatchAt, createdAt)
          }
        }

        // --- Worker lifecycle & scheduler metrics ---
        if (kind === 'worker.started') {
          eventWorkersStarted += 1
          recordPhaseBStart(createdAt)
          const aid = typeof detail.assignmentId === 'string' ? detail.assignmentId : null
          if (aid && createdAt !== null) workerStartById.set(aid, createdAt)
          const stepId = typeof detail.stepId === 'string' ? detail.stepId : null
          if (
            detail.lane === 'chain'
            || detail.isChain === true
            || (stepId && chainStepIds.has(stepId))
          ) {
            recordFirstChainDispatch(createdAt)
          }
        } else if (kind === 'worker.complete') {
          eventWorkersCompletedAll += 1
          const aid = typeof detail.assignmentId === 'string' ? detail.assignmentId : null
          const knownPhase = aid ? allKnownAssignmentPhases.get(aid) : undefined
          if (!knownPhase || knownPhase === 'investigation') {
            eventWorkersCompleted += 1
          }
          const explicitWall = finiteNonNeg(detail.elapsedMs) ?? finiteNonNeg(detail.wallMs)
          if (explicitWall !== null) {
            maxEventWorkerWallMs = maxEventWorkerWallMs === null ? explicitWall : Math.max(maxEventWorkerWallMs, explicitWall)
          }
          if (aid && createdAt !== null) {
            const st = workerStartById.get(aid)
            if (st !== undefined && createdAt >= st) {
              const dur = createdAt - st
              maxEventWorkerWallMs = maxEventWorkerWallMs === null ? dur : Math.max(maxEventWorkerWallMs, dur)
              workerIntervals.push({ start: st, end: createdAt })
            }
          }
        } else if (kind === 'worker.wall_clock_rotated') {
          eventWallClockRotations += 1
          const aid = typeof detail.assignmentId === 'string' ? detail.assignmentId : null
          const explicitWall = finiteNonNeg(detail.elapsedMs) ?? finiteNonNeg(detail.wallClockMs)
          if (explicitWall !== null) {
            maxEventWorkerWallMs = maxEventWorkerWallMs === null ? explicitWall : Math.max(maxEventWorkerWallMs, explicitWall)
          }
          if (aid && createdAt !== null) {
            const st = workerStartById.get(aid)
            if (st !== undefined && createdAt >= st) {
              const dur = createdAt - st
              maxEventWorkerWallMs = maxEventWorkerWallMs === null ? dur : Math.max(maxEventWorkerWallMs, dur)
              workerIntervals.push({ start: st, end: createdAt })
            }
          }
        } else if (kind === 'worker.failed' || kind === 'worker.canceled' || kind === 'worker.stall_failed') {
          const aid = typeof detail.assignmentId === 'string' ? detail.assignmentId : null
          if (aid && createdAt !== null) {
            const st = workerStartById.get(aid)
            if (st !== undefined && createdAt >= st) {
              const dur = createdAt - st
              maxEventWorkerWallMs = maxEventWorkerWallMs === null ? dur : Math.max(maxEventWorkerWallMs, dur)
              workerIntervals.push({ start: st, end: createdAt })
            }
          }
        } else if (kind === 'agentic.assignment_metrics') {
          const rot = finiteNonNeg(detail.wallClockRotations)
          if (rot !== null) metricsWallClockRotations = Math.max(metricsWallClockRotations, Math.floor(rot))
          const obs = finiteNonNeg(detail.assignmentsObserved)
          if (obs !== null) metricsPhaseBAssignments = Math.max(metricsPhaseBAssignments, Math.floor(obs))
          const mw = finiteNonNeg(detail.maxWorkerWallMs)
          if (mw !== null) {
            maxEventWorkerWallMs = maxEventWorkerWallMs === null ? mw : Math.max(maxEventWorkerWallMs, mw)
          }
        }

        // --- Frontier / Dead-end reprobe events ---
        if (kind === 'frontier.negative_edge') {
          if (detail.pruned === true) negativeEdgePrunedEvents += 1
          const attemptCount = finiteNonNeg(detail.attemptCount) ?? 0
          if (detail.wasDeadEndReprobe === true || detail.reprobe === true || (detail.pruned === true && attemptCount > 2)) {
            explicitDeadEndReprobeEvents += 1
          }
        } else if (kind === 'frontier.dead_end_reprobe' || kind === 'scheduler.dead_end_reprobe') {
          explicitDeadEndReprobeEvents += 1
        } else if (
          kind === 'frontier.summary'
          || kind === 'frontier.wave_summary'
          || kind === 'frontier.metrics'
          || kind === 'scheduler.frontier_summary'
        ) {
          const dispatched = finiteNonNeg(detail.totalAssignmentsDispatched) ?? finiteNonNeg(detail.phaseBAssignments)
          if (dispatched !== null) frontierSummaryDispatched = Math.max(frontierSummaryDispatched, Math.floor(dispatched))
          const reprobes = finiteNonNeg(detail.deadEndReprobeCount) ?? finiteNonNeg(detail.deadEndReprobes)
          if (reprobes !== null) frontierSummaryDeadEndReprobes = Math.max(frontierSummaryDeadEndReprobes, Math.floor(reprobes))
        }

        // --- v8 SDK Adoption & Verify RPC events ---
        const callId = typeof detail.callId === 'string' && detail.callId.trim() ? detail.callId.trim() : null
        if (
          kind === 'kovo_verify.called'
          || kind === 'kovo_verify.complete'
          || kind === 'kovo_verify.rejected'
          || kind === 'kovo_verify.failed'
          || ((kind === 'tool.call' || kind === 'tool.result') && (detail.tool === 'kovo_verify' || detail.name === 'kovo_verify'))
        ) {
          if (callId) {
            if (!seenKovoVerifyCallIds.has(callId)) {
              seenKovoVerifyCallIds.add(callId)
              eventKovoVerifyCalls += 1
            }
          } else {
            eventKovoVerifyCalls += 1
          }
        } else if (kind === 'agent.script_proof_confirmed' || kind === 'agent.script_proof_rejected') {
          if (!callId || !seenKovoVerifyCallIds.has(callId)) {
            if (callId) seenKovoVerifyCallIds.add(callId)
            eventKovoVerifyCalls += 1
          }
        }

        // Single-op or aggregate SDK RPC counters
        if (kind === 'verify_rpc.call' || kind === 'verify_rpc.op' || kind === 'kovo_verify.rpc') {
          bumpSdkOp(detail.op ?? detail.method ?? detail.rpcOp, 1)
          if ((detail.op === 'composite.verify' || detail.method === 'composite.verify') && detail.confirmed === true) {
            if (typeof detail.chainId === 'string' && detail.chainId.trim()) confirmedCompositeChainIds.add(detail.chainId.trim())
            else anonymousCompositeConfirmed += 1
          } else if (detail.ok === false || detail.confirmed === false) {
            if (detail.op === 'composite.verify' || detail.method === 'composite.verify') eventCompositeRejected += 1
            const r = detail.rejectReason ?? detail.failedStage ?? detail.rejectedBy ?? detail.reason ?? detail.errorCode
            bumpRejectReason(rejectReasons, r)
            bumpRejectDetail(rejectDetails, r, pickRejectSignature(detail, null, r))
          }
        } else if (kind === 'capability.seal' || kind === 'capability.sealed' || kind === 'verify_rpc.capability_seal') {
          eventSealCapabilityCalls += 1
        } else if (kind === 'crypto.hmacSign' || kind === 'crypto.hmac_sign' || kind === 'verify_rpc.hmac_sign') {
          eventHmacSignCalls += 1
        } else if (kind === 'crypto.jwtSign' || kind === 'crypto.jwt_sign' || kind === 'verify_rpc.jwt_sign') {
          eventJwtSignCalls += 1
        } else if (kind === 'async.awaitResult' || kind === 'async.await_result' || kind === 'verify_rpc.await_async') {
          eventAwaitAsyncCalls += 1
        } else if (kind === 'composite.verify' || kind === 'composite.verified' || kind === 'verify_rpc.composite_verify') {
          eventProveCompositeCalls += 1
          if (kind === 'composite.verified' || detail.confirmed === true) {
            if (typeof detail.chainId === 'string' && detail.chainId.trim()) confirmedCompositeChainIds.add(detail.chainId.trim())
            else anonymousCompositeConfirmed += 1
          } else if (detail.confirmed === false) {
            eventCompositeRejected += 1
            const r = detail.failedStage ?? detail.rejectReason ?? detail.rejectedBy ?? detail.reason
            bumpRejectReason(rejectReasons, r)
            bumpRejectDetail(rejectDetails, r, pickRejectSignature(detail, null, r))
          }
        } else if (kind === 'composite.rejected') {
          eventProveCompositeCalls += 1
          eventCompositeRejected += 1
          const r = detail.failedStage ?? detail.rejectReason ?? detail.rejectedBy ?? detail.reason
          bumpRejectReason(rejectReasons, r)
          bumpRejectDetail(rejectDetails, r, pickRejectSignature(detail, null, r))
        } else if (kind === 'agent.script_proof_confirmed') {
          const rule = typeof detail.receiptRule === 'string' ? detail.receiptRule : ''
          const chainId = typeof detail.chainId === 'string' && detail.chainId.trim() ? detail.chainId.trim() : null
          if (rule.startsWith('composite:') || chainId) {
            if (chainId) confirmedCompositeChainIds.add(chainId)
            else anonymousCompositeConfirmed += 1
          }
        } else if (
          kind === 'proof_receipt.shadow_reject'
          || kind === 'oob.receipt_rejected'
          || kind === 'kovo_verify.rejected'
          || kind === 'kovo_verify.failed'
          || kind === 'agent.script_proof_rejected'
          || kind === 'verify_rpc.rejected'
          || kind === 'verify_rpc.error'
        ) {
          const r = detail.failedStage ?? detail.rejectReason ?? detail.rejectedBy ?? detail.reason ?? detail.errorCode ?? detail.rule
          bumpRejectReason(rejectReasons, r)
          bumpRejectDetail(rejectDetails, r, pickRejectSignature(detail, null, r))
        }

        const rpcBag = (detail.rpcCounts && typeof detail.rpcCounts === 'object')
          ? detail.rpcCounts as Record<string, unknown>
          : (detail.sdkCalls && typeof detail.sdkCalls === 'object')
            ? detail.sdkCalls as Record<string, unknown>
            : null
        if (rpcBag) {
          for (const [opKey, rawCount] of Object.entries(rpcBag)) {
            const c = finiteNonNeg(rawCount)
            if (c !== null) bumpSdkOp(opKey, Math.floor(c))
          }
        }
      }
    }
  }

  // Fallback concurrency from overlapping worker intervals if no scheduler.dispatch events
  if (maxEffectiveConcurrency === 0 && workerIntervals.length > 0) {
    const pts: Array<{ ts: number; delta: number }> = []
    for (const iv of workerIntervals) {
      pts.push({ ts: iv.start, delta: 1 }, { ts: iv.end, delta: -1 })
    }
    pts.sort((a, b) => a.ts - b.ts || a.delta - b.delta)
    let cur = 0
    for (const p of pts) {
      cur += p.delta
      if (cur > maxEffectiveConcurrency) maxEffectiveConcurrency = cur
    }
  } else if (maxEffectiveConcurrency === 0 && (eventWorkersStarted > 0 || dbPhaseBAssignments > 0)) {
    maxEffectiveConcurrency = 1
  }

  // ---- 5. CapabilityLedger tables ----
  let nodesTotal = 0
  let capabilityOnlyCount = 0
  let sealedHandlesCount = 0
  let causalEdgesCount = 0
  let negativeEdgesPrunedCount = 0
  let negEdgeTableExtraReprobes = 0

  if (tables.has('capability_nodes')) {
    const cols = listTableColumns(client, 'capability_nodes')
    if (cols.has('run_id')) {
      const sel = ['cap_id', 'promotion_status'].filter(c => cols.has(c))
      const rows = client.prepare(
        sel.length ? `SELECT ${sel.join(', ')} FROM capability_nodes WHERE run_id = ?` : 'SELECT 1 FROM capability_nodes WHERE run_id = ?',
      ).all(runId) as SqliteRow[]
      nodesTotal = rows.length
      for (const row of rows) {
        if (row.promotion_status === 'capability_only') capabilityOnlyCount += 1
        if (typeof row.cap_id === 'string' && row.cap_id.startsWith('cap:')) sealedHandlesCount += 1
      }
    }
  }

  if (tables.has('capability_causal_edges')) {
    const cols = listTableColumns(client, 'capability_causal_edges')
    if (cols.has('run_id')) {
      const row = client.prepare('SELECT COUNT(*) AS c FROM capability_causal_edges WHERE run_id = ?').get(runId) as SqliteRow | undefined
      causalEdgesCount = finiteNonNeg(Number(row?.c)) ?? 0
    }
  } else if (tables.has('capability_edges')) {
    const cols = listTableColumns(client, 'capability_edges')
    if (cols.has('run_id')) {
      const sel = ['kind', 'edge_kind', 'pruned', 'is_negative', 'attempt_count'].filter(c => cols.has(c))
      const rows = client.prepare(
        sel.length ? `SELECT ${sel.join(', ')} FROM capability_edges WHERE run_id = ?` : 'SELECT 1 FROM capability_edges WHERE run_id = ?',
      ).all(runId) as SqliteRow[]
      for (const row of rows) {
        const edgeKind = String(row.kind ?? row.edge_kind ?? '').toLowerCase()
        const isNeg = row.is_negative === 1 || row.is_negative === true || edgeKind === 'negative' || edgeKind === 'negative_edge'
        if (isNeg) {
          if (row.pruned === 1 || row.pruned === true) {
            negativeEdgesPrunedCount += 1
            const attempts = finiteNonNeg(Number(row.attempt_count)) ?? 0
            if (attempts > 2) negEdgeTableExtraReprobes += Math.floor(attempts - 2)
          }
        } else {
          causalEdgesCount += 1
        }
      }
    }
  }

  if (tables.has('capability_negative_edges')) {
    const cols = listTableColumns(client, 'capability_negative_edges')
    if (cols.has('run_id')) {
      const sel = ['pruned', 'attempt_count'].filter(c => cols.has(c))
      const rows = client.prepare(
        sel.length ? `SELECT ${sel.join(', ')} FROM capability_negative_edges WHERE run_id = ?` : 'SELECT 1 FROM capability_negative_edges WHERE run_id = ?',
      ).all(runId) as SqliteRow[]
      for (const row of rows) {
        if (row.pruned === 1 || row.pruned === true) {
          negativeEdgesPrunedCount += 1
          const attempts = finiteNonNeg(Number(row.attempt_count)) ?? 0
          if (attempts > 2) negEdgeTableExtraReprobes += Math.floor(attempts - 2)
        }
      }
    }
  } else if (negativeEdgesPrunedCount === 0 && negativeEdgePrunedEvents > 0) {
    negativeEdgesPrunedCount = negativeEdgePrunedEvents
  }
  if (options.frontierTelemetry?.prunedEdgeCount !== undefined) {
    negativeEdgesPrunedCount = Math.max(negativeEdgesPrunedCount, Math.floor(options.frontierTelemetry.prunedEdgeCount))
  }

  // ---- 6. Replay specs & Findings (structured receipt / rejection metadata only) ----
  const compositeReceiptKeys = new Set<string>()
  let agentScriptSpecCount = 0

  const inspectCompositeCandidate = (raw: unknown, fallbackKey: string): void => {
    if (!raw || typeof raw !== 'object') return
    const obj = raw as Record<string, unknown>
    const receipt = (obj.compositeReceipt ?? obj.compositeProofReceipt ?? null) as Record<string, unknown> | null
    const verification = (obj.compositeVerification ?? obj.verification ?? null) as Record<string, unknown> | null
    if (receipt && typeof receipt.chainId === 'string' && Array.isArray(receipt.hops) && receipt.hops.length > 0) {
      compositeReceiptKeys.add(receipt.chainId)
      if (verification) {
        if (verification.confirmed === true) {
          confirmedCompositeChainIds.add(receipt.chainId)
        } else if (verification.confirmed === false) {
          const r = verification.failedStage ?? verification.reason
          bumpRejectReason(rejectReasons, r)
          bumpRejectDetail(rejectDetails, r, pickRejectSignature(verification, null, r))
        }
      }
    } else if (typeof obj.chainId === 'string' && Array.isArray(obj.hops) && obj.hops.length > 0) {
      compositeReceiptKeys.add(obj.chainId || fallbackKey)
      if (verification?.confirmed === true) confirmedCompositeChainIds.add(obj.chainId)
    }
  }

  if (tables.has('replay_specs')) {
    const cols = listTableColumns(client, 'replay_specs')
    if (cols.has('run_id')) {
      const sel = ['id', 'proof_kind', 'proof_verdict', 'spec', 'proof_receipt', 'last_verification_diff'].filter(c => cols.has(c))
      if (sel.length > 0) {
        const rows = client.prepare(`SELECT ${sel.join(', ')} FROM replay_specs WHERE run_id = ?`).all(runId) as SqliteRow[]
        for (const row of rows) {
          const rowId = typeof row.id === 'string' ? row.id : 'spec'
          if (row.proof_kind === 'agent_script') agentScriptSpecCount += 1
          const specObj = safeJsonParse(row.spec)
          const proofReceiptObj = safeJsonParse(row.proof_receipt)
          const diffObj = safeJsonParse(row.last_verification_diff)
          inspectCompositeCandidate(specObj, rowId)
          inspectCompositeCandidate(proofReceiptObj, rowId)
          if (diffObj && typeof diffObj === 'object') {
            const d = diffObj as Record<string, unknown>
            if (d.verdict && d.verdict !== 'confirmed') {
              const summary = (d.assertionSummary && typeof d.assertionSummary === 'object')
                ? d.assertionSummary as Record<string, unknown>
                : null
              bumpRejectReason(rejectReasons, summary?.reason ?? d.reason)
            }
          }
          if (row.proof_verdict === 'dismissed' || row.proof_verdict === 'inconclusive') {
            if (proofReceiptObj && typeof proofReceiptObj === 'object') {
              const pr = proofReceiptObj as Record<string, unknown>
              const ver = (pr.verification && typeof pr.verification === 'object') ? pr.verification as Record<string, unknown> : null
              bumpRejectReason(rejectReasons, ver?.reason ?? row.proof_verdict)
            }
          }
        }
      }
    }
  }

  if (tables.has('findings')) {
    const cols = listTableColumns(client, 'findings')
    if (cols.has('run_id') && cols.has('finding')) {
      const sel = ['id', 'finding'].filter(c => cols.has(c))
      const rows = client.prepare(`SELECT ${sel.join(', ')} FROM findings WHERE run_id = ?`).all(runId) as SqliteRow[]
      for (const row of rows) {
        const parsed = safeJsonParse(row.finding)
        if (parsed && typeof parsed === 'object') {
          const f = parsed as Record<string, unknown>
          inspectCompositeCandidate(f.evidence, typeof row.id === 'string' ? row.id : 'finding')
        }
      }
    }
  }

  // ---- 7. Optional read-only agent-sessions tool-call histogram (counts & reject codes only) ----
  let sessionKovoVerifyCalls = 0
  let sessionSealCalls = 0
  let sessionHmacCalls = 0
  let sessionJwtCalls = 0
  let sessionAwaitCalls = 0
  let sessionCompositeCalls = 0
  if (dataDir && sessionIds.size > 0) {
    const sessionsDir = join(dataDir, 'agent-sessions')
    if (existsSync(sessionsDir)) {
      const reSeal = /\b(?:seal_capability|sealCapability)\s*\(|['"]capability\.seal['"]/g
      const reHmac = /\b(?:hmac_sign|hmacSign)\s*\(|['"]crypto\.hmacSign['"]/g
      const reJwt = /\b(?:jwt_sign|jwtSign)\s*\(|['"]crypto\.jwtSign['"]/g
      const reAwait = /\b(?:await_async|awaitAsync)\s*\(|['"]async\.awaitResult['"]/g
      const reComposite = /\b(?:prove_composite|proveComposite)\s*\(|['"]composite\.verify['"]/g

      for (const sessionId of sessionIds) {
        const sessionPath = join(sessionsDir, `${sessionId}.sqlite`)
        if (!existsSync(sessionPath)) continue
        let sessionDb: DatabaseSync | undefined
        try {
          sessionDb = new DatabaseSync(sessionPath, { readOnly: true })
          const rows = sessionDb.prepare('SELECT record FROM entries ORDER BY commit_seq ASC').all() as Array<{ record?: unknown }>
          const gvCallIds = new Set<string>()
          for (const row of rows) {
            const parsed = safeJsonParse(row.record) as { model?: Array<Record<string, unknown>> } | null
            const models = Array.isArray(parsed?.model) ? parsed.model : []
            for (const msg of models) {
              if (msg.role === 'assistant' && Array.isArray(msg.content)) {
                for (const block of msg.content as Array<Record<string, unknown>>) {
                  if (block.type === 'toolCall' && block.name === 'kovo_verify') {
                    sessionKovoVerifyCalls += 1
                    if (typeof block.id === 'string') gvCallIds.add(block.id)
                    const argsObj = (block.arguments && typeof block.arguments === 'object')
                      ? block.arguments as Record<string, unknown>
                      : null
                    const scriptText = typeof argsObj?.script === 'string' ? argsObj.script : ''
                    if (scriptText) {
                      sessionSealCalls += countPatternMatches(scriptText, reSeal)
                      sessionHmacCalls += countPatternMatches(scriptText, reHmac)
                      sessionJwtCalls += countPatternMatches(scriptText, reJwt)
                      sessionAwaitCalls += countPatternMatches(scriptText, reAwait)
                      sessionCompositeCalls += countPatternMatches(scriptText, reComposite)
                    }
                  }
                }
              } else if (msg.role === 'toolResult' && typeof msg.toolCallId === 'string' && gvCallIds.has(msg.toolCallId)) {
                const rawText = typeof msg.content === 'string'
                  ? msg.content
                  : Array.isArray(msg.content)
                    ? (msg.content as Array<{ text?: unknown }>).map(p => (typeof p?.text === 'string' ? p.text : '')).join('\n')
                    : ''
                const resultObj = safeJsonParse(rawText)
                if (resultObj && typeof resultObj === 'object' && !Array.isArray(resultObj)) {
                  const rec = resultObj as Record<string, unknown>
                  const cr = (rec.compositeReceipt && typeof rec.compositeReceipt === 'object')
                    ? rec.compositeReceipt as Record<string, unknown>
                    : null
                  if (cr?.confirmed === true) {
                    if (typeof cr.chainId === 'string' && cr.chainId.trim()) confirmedCompositeChainIds.add(cr.chainId.trim())
                    else anonymousCompositeConfirmed += 1
                  }
                  if (rec.confirmed === false || rec.ok === false || cr?.confirmed === false) {
                    const r = cr?.failedStage ?? rec.rejectedBy ?? rec.reason ?? rec.errorCode
                    bumpRejectReason(rejectReasons, r)
                    bumpRejectDetail(rejectDetails, r, pickRejectSignature(rec, cr, r))
                  }
                }
              }
            }
          }
        } catch {
          // Best-effort: ignore locked/unreadable session SQLite files.
        } finally {
          try { sessionDb?.close() } catch { /* ignore */ }
        }
      }
    }
  }

  // ---- 8. Assemble all 4 telemetry sections ----
  const runAnchorMs = finitePos(options.runStartedAtMs)
    ?? runCreatedAt
    ?? earliestEventAt
    ?? earliestAssignmentCreatedAt
    ?? 0
  const runEndMs = finitePos(options.runEndedAtMs)
    ?? latestEventAt
    ?? latestAssignmentTs
    ?? runAnchorMs
  const totalWallMs = Math.max(0, runEndMs - runAnchorMs)

  const codeAuditMs = codeAuditStartAt !== null && codeAuditEndAt !== null && codeAuditEndAt >= codeAuditStartAt
    ? codeAuditEndAt - codeAuditStartAt
    : codeAuditElapsedOverride
  const floorMs = floorMsReported !== null
    ? floorMsReported
    : floorStartAt !== null && floorEndAt !== null && floorEndAt >= floorStartAt
      ? floorEndAt - floorStartAt
      : null

  const effectivePhaseBStartAt = phaseBStartEventAt ?? earliestPhaseBAssignmentAt
  const phaseBStartMs = effectivePhaseBStartAt !== null
    ? Math.max(0, effectivePhaseBStartAt - runAnchorMs)
    : null
  const effectiveFirstChainAt = firstChainDispatchEventAt ?? firstChainRoundDispatchAt
  const firstChainDispatchMs = effectiveFirstChainAt !== null
    ? Math.max(0, effectiveFirstChainAt - runAnchorMs)
    : null

  const workersStarted = eventWorkersStarted > 0 ? eventWorkersStarted : dbPhaseBAssignments
  const workersCompleted = eventWorkersCompleted > 0
    ? eventWorkersCompleted
    : dbPhaseBCompleted > 0
      ? dbPhaseBCompleted
      : eventWorkersCompletedAll
  const wallClockRotations = Math.max(eventWallClockRotations, metricsWallClockRotations)
  const maxWorkerWallMs = maxEventWorkerWallMs !== null && maxAssignmentTableWallMs !== null
    ? Math.max(maxEventWorkerWallMs, maxAssignmentTableWallMs)
    : (maxEventWorkerWallMs ?? maxAssignmentTableWallMs)
  const totalPhaseBAssignments = Math.max(
    dbPhaseBAssignments,
    workersStarted,
    metricsPhaseBAssignments,
    frontierSummaryDispatched,
    Math.floor(finiteNonNeg(options.frontierTelemetry?.totalAssignmentsDispatched) ?? 0),
  )
  const deadEndReprobes = Math.max(
    explicitDeadEndReprobeEvents,
    frontierSummaryDeadEndReprobes,
    negEdgeTableExtraReprobes,
    assignmentFlagDeadEndReprobes,
    Math.floor(finiteNonNeg(options.frontierTelemetry?.deadEndReprobeCount) ?? 0),
  )
  const wasteRate = totalPhaseBAssignments > 0
    ? deadEndReprobes / totalPhaseBAssignments
    : (finiteNonNeg(options.frontierTelemetry?.deadEndReprobeWasteRate) ?? 0)
  const deadEndWastePct = roundPct(wasteRate)

  const compositeReceiptsCount = Math.max(
    compositeReceiptKeys.size,
    confirmedCompositeChainIds.size + anonymousCompositeConfirmed,
    Math.floor(finiteNonNeg(options.compositeReceiptsExtracted) ?? 0),
  )
  const compositeConfirmed = confirmedCompositeChainIds.size + anonymousCompositeConfirmed

  const kovoVerifyCalls = Math.max(eventKovoVerifyCalls, sessionKovoVerifyCalls, agentScriptSpecCount)
  const sealCapabilityCalls = Math.max(eventSealCapabilityCalls, sessionSealCalls)
  const hmacSignCalls = Math.max(eventHmacSignCalls, sessionHmacCalls)
  const jwtSignCalls = Math.max(eventJwtSignCalls, sessionJwtCalls)
  const awaitAsyncCalls = Math.max(eventAwaitAsyncCalls, sessionAwaitCalls)
  const proveCompositeCalls = Math.max(
    eventProveCompositeCalls,
    sessionCompositeCalls,
    compositeConfirmed + eventCompositeRejected,
  )

  const topRejectReasons = [...rejectReasons.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, 10)
    .map(([reason, count]) => ({ reason, count }))
  const topRejectDetails = [...rejectDetails.values()]
    .sort((a, b) => b.count - a.count || (a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0))
    .slice(0, 12)

  return {
    phaseTiming: {
      codeAuditMs,
      floorMs,
      phaseBStartMs,
      firstChainDispatchMs,
      totalWallMs,
    },
    scheduler: {
      maxEffectiveConcurrency,
      workersStarted,
      workersCompleted,
      wallClockRotations,
      maxWorkerWallMs,
      totalPhaseBAssignments,
      deadEndReprobes,
      deadEndWastePct,
    },
    capabilityLedger: {
      nodesTotal,
      capabilityOnlyCount,
      sealedHandlesCount,
      causalEdgesCount,
      negativeEdgesPrunedCount,
      compositeReceiptsCount,
    },
    v8SdkAdoption: {
      kovoVerifyCalls,
      sealCapabilityCalls,
      hmacSignCalls,
      jwtSignCalls,
      awaitAsyncCalls,
      proveCompositeCalls,
      compositeConfirmed,
      topRejectReasons,
      topRejectDetails,
    },
  }
}

function avgNullable(values: ReadonlyArray<number | null>): number | null {
  const valid = values.filter((v): v is number => typeof v === 'number' && Number.isFinite(v))
  if (!valid.length) return null
  return Math.round(valid.reduce((acc, v) => acc + v, 0) / valid.length)
}

function maxNullable(values: ReadonlyArray<number | null>): number | null {
  const valid = values.filter((v): v is number => typeof v === 'number' && Number.isFinite(v))
  if (!valid.length) return null
  return Math.max(...valid)
}

/** Aggregate structured telemetry across multiple cells cleanly (returns null if none carry telemetry). */
export function aggregateMultihopTelemetry(
  cells: readonly Pick<MultihopCellMeta, 'telemetry'>[],
): MultihopRunTelemetry | null {
  const items = cells
    .map(c => c.telemetry)
    .filter((t): t is MultihopRunTelemetry => Boolean(t))
  if (!items.length) return null

  const totalPhaseBAssignments = items.reduce((n, t) => n + t.scheduler.totalPhaseBAssignments, 0)
  const deadEndReprobes = items.reduce((n, t) => n + t.scheduler.deadEndReprobes, 0)
  const deadEndWastePct = totalPhaseBAssignments > 0
    ? roundPct(deadEndReprobes / totalPhaseBAssignments)
    : roundPct(items.reduce((n, t) => n + t.scheduler.deadEndWastePct, 0) / (items.length * 100))

  const rejectMap = new Map<string, number>()
  const rejectDetailMap = new Map<string, MultihopRejectDetail>()
  const hasAnyRejectDetails = items.some(t => t.v8SdkAdoption.topRejectDetails !== undefined)
  for (const t of items) {
    for (const entry of t.v8SdkAdoption.topRejectReasons) {
      bumpRejectReason(rejectMap, entry.reason, entry.count)
    }
    for (const detailEntry of t.v8SdkAdoption.topRejectDetails ?? []) {
      bumpRejectDetail(rejectDetailMap, detailEntry.reason, detailEntry.signature, detailEntry.count)
    }
  }
  const topRejectReasons = [...rejectMap.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, 10)
    .map(([reason, count]) => ({ reason, count }))
  const topRejectDetails = [...rejectDetailMap.values()]
    .sort((a, b) => b.count - a.count || (a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0))
    .slice(0, 12)

  return {
    phaseTiming: {
      codeAuditMs: avgNullable(items.map(t => t.phaseTiming.codeAuditMs)),
      floorMs: avgNullable(items.map(t => t.phaseTiming.floorMs)),
      phaseBStartMs: avgNullable(items.map(t => t.phaseTiming.phaseBStartMs)),
      firstChainDispatchMs: avgNullable(items.map(t => t.phaseTiming.firstChainDispatchMs)),
      totalWallMs: items.reduce((n, t) => n + t.phaseTiming.totalWallMs, 0),
    },
    scheduler: {
      maxEffectiveConcurrency: Math.max(...items.map(t => t.scheduler.maxEffectiveConcurrency)),
      workersStarted: items.reduce((n, t) => n + t.scheduler.workersStarted, 0),
      workersCompleted: items.reduce((n, t) => n + t.scheduler.workersCompleted, 0),
      wallClockRotations: items.reduce((n, t) => n + t.scheduler.wallClockRotations, 0),
      maxWorkerWallMs: maxNullable(items.map(t => t.scheduler.maxWorkerWallMs)),
      totalPhaseBAssignments,
      deadEndReprobes,
      deadEndWastePct,
    },
    capabilityLedger: {
      nodesTotal: items.reduce((n, t) => n + t.capabilityLedger.nodesTotal, 0),
      capabilityOnlyCount: items.reduce((n, t) => n + t.capabilityLedger.capabilityOnlyCount, 0),
      sealedHandlesCount: items.reduce((n, t) => n + t.capabilityLedger.sealedHandlesCount, 0),
      causalEdgesCount: items.reduce((n, t) => n + t.capabilityLedger.causalEdgesCount, 0),
      negativeEdgesPrunedCount: items.reduce((n, t) => n + t.capabilityLedger.negativeEdgesPrunedCount, 0),
      compositeReceiptsCount: items.reduce((n, t) => n + t.capabilityLedger.compositeReceiptsCount, 0),
    },
    v8SdkAdoption: {
      kovoVerifyCalls: items.reduce((n, t) => n + t.v8SdkAdoption.kovoVerifyCalls, 0),
      sealCapabilityCalls: items.reduce((n, t) => n + t.v8SdkAdoption.sealCapabilityCalls, 0),
      hmacSignCalls: items.reduce((n, t) => n + t.v8SdkAdoption.hmacSignCalls, 0),
      jwtSignCalls: items.reduce((n, t) => n + t.v8SdkAdoption.jwtSignCalls, 0),
      awaitAsyncCalls: items.reduce((n, t) => n + t.v8SdkAdoption.awaitAsyncCalls, 0),
      proveCompositeCalls: items.reduce((n, t) => n + t.v8SdkAdoption.proveCompositeCalls, 0),
      compositeConfirmed: items.reduce((n, t) => n + t.v8SdkAdoption.compositeConfirmed, 0),
      topRejectReasons,
      ...(hasAnyRejectDetails ? { topRejectDetails } : {}),
    },
  }
}

// ---------------------------------------------------------------------------------------------
// Cell metadata, artifacts & execution
// ---------------------------------------------------------------------------------------------

export interface MultihopCellMeta {
  schemaVersion: 1
  app: MultihopAppName
  sealed: boolean
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: MultihopMode
  cell: string
  llm: MultihopLlmMode
  origin: string
  publicOrigins: string[]
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
  durationMs: number
  timedOut: boolean
  terminalStatus: string
  terminalPhase: string
  runId: string | null
  projectId: string | null
  chainsTotal: number
  chainsOracleObserved: number
  chainsCompositeConfirmed: number
  chainsConfirmed: number
  oracleOnlyCount: number
  receiptOnlyCount: number
  shortcutViolations: number
  modeBViolations: number
  recall: number
  precision: number
  hardenedTwinsTotal: number
  hardenedTwinDecoyFps: number
  unmatchedFalsePositives: number
  costUsd: number
  tpPerDollar: number | null
  tpPer10m: number | null
  hopFunnel: HopDepthFunnel
  depthBreakdown: DepthTierBreakdown
  chains: MultihopChainVerdict[]
  hardenedTwins: MultihopTwinVerdict[]
  assignmentsCompleted: number
  assignmentsTotal: number
  investigationCompleted: number
  phaseBAssignments?: number
  deadEndReprobeCount?: number
  deadEndReprobeWasteRate?: number
  deadEndWastePct?: number
  frontier?: MultihopFrontierWasteSnapshot
  telemetry?: MultihopRunTelemetry
  facts: number
  findingsPersisted: number
  findingsSubmitted: number
  compositeReceiptsExtracted: number
  endpointsDiscovered: number
  requestCount: number
  oracleEventCount: number
  inert: boolean
  snapshot: SnapshotRunMeta
  resumedFrom: string | null
  snapshotSkippedMs: number
  notes: string[]
  shutdown: { engineBusy: number; appStopped: boolean; canaryStopped: boolean }
}

export type MultihopCellReport = MultihopCellMeta

export interface MultihopCellResult {
  meta: MultihopCellMeta
  scorecard: MultihopScorecard
  jsonPath: string
  mdPath: string
  metaPath: string
}

export function cellSlug(app: MultihopAppName, seed: number, mode: MultihopMode): string {
  return `${app}-seed${seed}-${mode}`
}

export function isSealedApp(app: MultihopAppName): boolean {
  return (multihopSealedAppNames as readonly string[]).includes(app)
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
      } catch { /* already terminal */ }
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

/**
 * Resolve the optional in-run `workerConcurrency` override passed into `Store.createRun`.
 * Returning `undefined` omits the override so `Execution`'s dynamic AIMD Phase-B controller
 * auto-scales worker slots instead of clamping single-app runs to cell `--concurrency`.
 */
export function resolveMultihopWorkerConcurrency(
  args: Pick<MultihopArgs, 'workerConcurrency'>,
): number | undefined {
  if (args.workerConcurrency === undefined || !Number.isFinite(args.workerConcurrency)) return undefined
  return Math.max(1, Math.min(maxWorkerConcurrency, Math.trunc(args.workerConcurrency)))
}

export function cellKeys(args: Pick<MultihopArgs, 'apps' | 'seeds'>): Array<{ app: MultihopAppName; seed: number }> {
  const cells: Array<{ app: MultihopAppName; seed: number }> = []
  for (const app of args.apps) for (const seed of args.seeds) cells.push({ app, seed })
  return cells
}

export async function runCell(
  args: MultihopArgs,
  app: MultihopAppName,
  seed: number,
  runtime: MultihopRuntime,
  log: (line: string) => void,
  cleanup: CleanupRegistry,
): Promise<MultihopCellResult> {
  const startedAt = nowMs()
  const slug = cellSlug(app, seed, args.mode)
  const cellCount = cellKeys(args).length
  const notes: string[] = []
  const sealed = isSealedApp(app)
  if (sealed) notes.push('SEALED benchmark archetype (M4 certification gate only; do not hill-climb)')
  const llmMode: MultihopLlmMode = args.noLlm ? 'deterministic-no-llm' : 'agentic'
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
  let releaseCredentialsDir: (() => void) | undefined
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
    if (linked.credentialsDir) {
      releaseCredentialsDir = acquireCredentialsDirEnv(linked.credentialsDir)
    }
  } else if (isolate && sourceDataDir) {
    isolated = prepareIsolatedDataDir({ sourceDataDir, targetDir: dataDir })
    releaseCredentialsDir = acquireCredentialsDirEnv(isolated.credentialsDir)
  } else if (sourceDataDir) {
    dataDir = cellCount === 1 ? sourceDataDir : join(sourceDataDir, slug)
  }
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })

  const storage = (() => {
    try {
      return openCellStore(dataDir)
    } catch (error) {
      releaseCredentialsDir?.()
      if (isolated) { try { unlockAndRemove(dataDir) } catch { /* best-effort */ } }
      throw error
    }
  })()
  const canary = new CanaryBroker({ storage })
  let started: MultihopStartedApp | undefined
  let engine: Execution | undefined
  let backend: WorkerBackend | undefined
  let backendKind: VerifierBackendKind = 'local-jq'
  let appStopped = false
  let canaryStopped = false
  let whiteBoxRoot: string | undefined
  let engineBusy = -1

  const cellSecrets: NamedSecret[] = []
  let runId = ''
  let projectId = ''
  let runStartedAt = startedAt
  let loginPath: string | null = null
  let gitSha = 'unknown'
  let model: ModelInfo = { mode: 'deterministic-no-llm', profiles: [] }

  const stopStartedApp = async (target: MultihopStartedApp): Promise<boolean> => {
    try {
      const outcome = await Promise.race([
        target.stop().then(() => 'stopped' as const),
        delay(10_000).then(() => 'timeout' as const),
      ])
      return outcome === 'stopped'
    } catch {
      return false
    }
  }

  const unregisterCleanup = cleanup.add(async () => {
    if (engine) { try { engineBusy = await stopEngine(engine) } catch { engineBusy = -1 } }
    if (backend instanceof LinuxWorkerBackend) { try { await backend.reclaimInactive() } catch { /* best-effort */ } }
    try { await canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
    if (started) { appStopped = await stopStartedApp(started) }
  })

  try {
    // --- Preflight (before booting any lab service): fail fast on missing model profile or local-jq ---
    let profiles: ResolvedModelProfile[] = []
    let profileLoadError: string | undefined
    if (!args.noLlm) {
      try {
        const load = inspectModelProfileLoad(storage)
        profiles = load.profiles
        if (load.errors.length) {
          profileLoadError = redact(load.errors.join('; ')).slice(0, 240)
          notes.push(`model profile lookup diagnostic: ${profileLoadError}`)
        } else if (load.profiles.length === 0) {
          profileLoadError = load.enabledRows === 0
            ? `no enabled model_profiles rows in ${dataDir}`
            : `${load.enabledRows} enabled profile row(s) in SQLite failed credential/pin validation`
        }
      } catch (error) {
        profileLoadError = redact((error as Error).message).slice(0, 240)
        notes.push(`model profile lookup failed: ${profileLoadError}`)
      }
      if (profiles.length === 0) {
        assertMultihopPreflight({
          hasProfiles: false,
          noLlm: false,
          allowInertWorkers: args.allowInertWorkers,
          backendKind: args.verifier === 'docker' ? 'docker' : 'local-jq',
          workerSessions: false,
          workerSessionsDetail: 'skipped after missing model profile',
          ...(profileLoadError ? { profileLoadError } : {}),
        })
      }
    } else {
      notes.push('--no-llm: deterministic floor mode (model profiles ignored)')
    }
    model = describeModelMode(args.noLlm ? [] : profiles)

    const selected = await (async () => {
      try {
        return await selectVerifierBackend(args.verifier)
      } catch (error) {
        const detail = redact(error instanceof Error ? error.message : String(error)).slice(0, 240)
        if (args.verifier === 'docker') {
          throw new PreflightError(
            `--verifier docker is not usable from this process: ${detail}. `
            + 'Re-run under `newgrp docker -c \'<command>\'` and ensure kovo-worker:v4 is built.',
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
    assertMultihopPreflight({
      hasProfiles: model.mode === 'agentic',
      noLlm: args.noLlm,
      allowInertWorkers: args.allowInertWorkers,
      backendKind,
      workerSessions: capability.supported,
      workerSessionsDetail: capability.detail,
    })
    notes.push(`verifier backend ${backendKind}; workerSessions=${capability.supported}`)

    const listener = await canary.startListener({ host: '127.0.0.1', port: 0 })
    const oobPort = listener.port
    if (!oobPort) fail('canary listener did not bind a loopback port')
    const oobCallbackPorts = resolveOobCallbackPorts(canary, [oobPort])
    const canaryBaseUrl = listener.localBaseUrl ?? listener.effectiveBaseUrl ?? null

    started = await runtime.startMultihopApp({
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
    }
    const plan = planCell(briefing, loginPath)
    gitSha = resolveGitSha()
    const seedSet: 'dev' | 'held-out' = started.plan?.seedSet ?? (args.heldOut ? 'held-out' : 'dev')

    const workerConcurrency = resolveMultihopWorkerConcurrency(args)
    let personaIds: string[] = []
    if (resumeRequested && loadedSnapshot) {
      projectId = loadedSnapshot.target.projectId
      runId = loadedSnapshot.target.runId
      const run = storage.run(runId)
      personaIds = [...run.approvedPersonaIds]
      if (args.mode === 'white-box' && briefing.sourceDir) {
        const mounted = await makeWhiteBoxMount(briefing.sourceDir, String(briefing.app), dataDir, projectId)
        if (mounted.length) whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', String(briefing.app))
      }
      const applied = applyRunSnapshot({
        storage,
        snapshot: loadedSnapshot.snapshot,
        target: loadedSnapshot.target,
        newOrigin: briefing.origin,
        ...(canaryBaseUrl ? { newCanaryBaseUrls: [canaryBaseUrl] } : {}),
        personaCredentials: plan.personas.map(p => ({ handle: p.handle, email: p.email, password: p.password })),
      })
      if (workerConcurrency !== undefined) {
        storage.updateRun(runId, { workerConcurrency })
      }
      snapshotMeta.resume.originsRebound = applied.origins.rowsUpdated
      snapshotMeta.resume.personaSessionsRebound = applied.personaSessionsRebound
      snapshotMeta.resume.phase0Skipped = applied.phase0Skipped
      snapshotMeta.resume.skippedMs = applied.skippedMs
    } else {
      const project = storage.createProject({
        requestId: randomUUID(),
        name: `multihop-saas ${app} seed ${seed} (${args.mode})`,
        seeds: plan.publicOrigins,
        environment: 'local-lab',
      })
      projectId = project.id

      if (plan.openApi) {
        const perOriginSpecs = briefingToOpenApiByOrigin(briefing)
        if (perOriginSpecs.length) {
          for (const entry of perOriginSpecs) {
            storage.importProjectSpec({
              requestId: randomUUID(),
              projectId,
              name: `multihop-saas-${app}-${entry.service}-api.json`,
              kind: 'openapi',
              origin: entry.origin,
              content: JSON.stringify(entry.spec, null, 2),
            })
          }
        } else {
          storage.importProjectSpec({
            requestId: randomUUID(),
            projectId,
            name: `multihop-saas-${app}-api.json`,
            kind: 'openapi',
            origin: briefing.origin,
            content: JSON.stringify(plan.openApi, null, 2),
          })
        }
      }

      if (args.mode === 'white-box' && briefing.sourceDir) {
        const mounted = await makeWhiteBoxMount(briefing.sourceDir, String(briefing.app), dataDir, projectId)
        if (mounted.length) {
          whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', String(briefing.app))
          notes.push(`white-box read-only source mount: ${mounted.join(', ')}`)
        }
      }

      const resolvedLoginUrl = pickLoginUrl(briefing, loginPath)
      if (resolvedLoginUrl) {
        for (const p of plan.personas) {
          const created = createProjectPersona(storage, {
            requestId: randomUUID(),
            projectId,
            handle: p.handle,
            roleLabel: p.roleLabel,
            originAllowlist: plan.publicOrigins,
            authKind: 'login',
            loginConfig: {
              adapter: 'json',
              email: p.email,
              loginUrl: resolvedLoginUrl,
            },
            secret: p.password,
            canaryMarkers: p.canaryMarkers,
          })
          personaIds.push(created.id)
        }
      }

      const createRunInput: Omit<Parameters<Store['createRun']>[0], 'workerConcurrency'> & {
        workerConcurrency?: number
      } = {
        requestId: randomUUID(),
        projectId,
        goal: plan.mission,
        sourceMode: 'public',
        capabilityTier: plan.capabilityTier,
        approvalPolicy: 'auto_review',
        approvedPersonaIds: personaIds,
        budgetUsd: args.budgetUsd,
        budgetRequests: 5_000,
        maxRpsPerOrigin: 15,
        ...(workerConcurrency !== undefined ? { workerConcurrency } : {}),
        workerMaxTurns: 40,
        multiTrialEnabled: true,
      }
      const createdRun = storage.createRun(createRunInput as Parameters<Store['createRun']>[0])
      runId = createdRun.id

      storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
      const assetIds = storage.run(runId).candidates.map(c => c.id)
      if (!assetIds.length) fail('discovery produced no candidate assets for the briefing origins')
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
        budgetRequests: 5_000,
        maxRpsPerOrigin: 15,
      })
    }

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
      } catch (error) {
        const message = error instanceof SnapshotError ? error.message : (error instanceof Error ? error.message : String(error))
        snapshotMeta.capture.reason = `capture failed: ${redact(message).slice(0, 200)}`
      }
    }

    engine = new Execution(storage, {
      canaryBroker: canary,
      ...(backend ? { backend } : {}),
      deterministicOnly: args.noLlm,
      maxDurationMs: args.maxDurationMs,
      ...(workerConcurrency !== undefined ? { workerConcurrencyOverride: workerConcurrency } : {}),
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
    const compositeReceipts = extractCompositeReceipts({
      findings: detail.findings as Finding[],
      replaySpecs: detail.replaySpecs.map(row => ({
        id: row.id, findingId: row.findingId, spec: row.spec, proofReceipt: row.proofReceipt,
      })),
    })

    const telemetry = buildTelemetry({
      runStartedAt,
      runEndedAt: nowMs(),
      spentUsd: finalRun.spentUsd,
      budgetUsd: args.budgetUsd,
      budgetExhausted: wait.timedOut || finalRun.status === 'budget_paused',
    })

    const gradeInput: MultihopGradeInput = {
      groundTruth: started.groundTruth,
      findings: submitted,
      compositeReceipts,
      oracleEvents: started.oracle.events(),
      requestLog: started.oracle.requests(),
      egressLog: started.oracle.egress?.() ?? [],
      ...(started.oracle.export ? { oracleExport: started.oracle.export() } : {}),
      telemetry,
      mode: args.mode,
    }
    const card = runtime.gradeRun(gradeInput)
    const endedAt = nowMs()
    const durationMs = Math.max(1, endedAt - startedAt)

    const twoSide = evaluateTwoSideConfirmation(card.chains ?? [], compositeReceipts)
    const chainsTotal = twoSide.chainsTotal || num(card.chainsTotal)
    const chainsConfirmed = twoSide.chainsTotal > 0 ? twoSide.twoSideConfirmed : num(card.chainsConfirmed)
    const chainsOracleObserved = twoSide.chainsTotal > 0 ? twoSide.oracleObserved : num(card.chainsOracleObserved)
    const chainsCompositeConfirmed = twoSide.chainsTotal > 0
      ? twoSide.compositeReceiptConfirmed
      : num(card.chainsCompositeConfirmed, chainsConfirmed)
    const hopFunnel = twoSide.chainsTotal > 0
      ? buildHopDepthFunnel(twoSide.verdicts)
      : {
          totalChains: chainsTotal,
          H1: num(card.hopFunnel?.H1),
          H2: num(card.hopFunnel?.H2),
          H3: num(card.hopFunnel?.H3),
          H4Plus: num(card.hopFunnel?.H4Plus),
          FinalOracle: num(card.hopFunnel?.FinalOracle, chainsOracleObserved),
          CompositeReceiptConfirmed: num(card.hopFunnel?.CompositeReceiptConfirmed, chainsConfirmed),
          dropReasons: { ...emptyDropReasons(), ...(card.hopFunnel?.dropReasons ?? {}) },
        }
    const depthBreakdown = computeDepthTierBreakdown(twoSide.verdicts)

    const hardenedTwins = card.hardenedTwins ?? []
    const rawTwinsTotal = num(card.hardenedTwinsTotal, num(card.decoys, hardenedTwins.length))
    const hardenedTwinsTotal = rawTwinsTotal > 0 ? rawTwinsTotal : hardenedTwins.length
    const hardenedTwinDecoyFps = num(
      card.hardenedTwinDecoyFps,
      num(card.decoyFalsePositives, hardenedTwins.filter(t => t.falsePositive).length),
    )
    const unmatchedFalsePositives = num(card.unmatchedFalsePositives)
    const totalFps = hardenedTwinDecoyFps + unmatchedFalsePositives
    const precision = chainsConfirmed + totalFps > 0 ? ratio(chainsConfirmed, chainsConfirmed + totalFps) : 1
    const costUsd = num(card.totalCostUsd, finalRun.spentUsd)
    const efficiency = computeEfficiencyMetrics({ confirmedChains: chainsConfirmed, costUsd, durationMs })

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

    let frontierTelemetry: ExtractMultihopRunTelemetryOptions['frontierTelemetry'] = null
    try {
      frontierTelemetry = engine.frontierControllerFor(runId).getTelemetry()
    } catch { /* best-effort */ }
    const runTelemetry = extractMultihopRunTelemetry(storage, runId, {
      runStartedAtMs: startedAt,
      runEndedAtMs: endedAt,
      dataDir,
      frontierTelemetry,
      compositeReceiptsExtracted: compositeReceipts.length,
    })
    const deadEndReprobeWasteRate = runTelemetry.scheduler.totalPhaseBAssignments > 0
      ? runTelemetry.scheduler.deadEndReprobes / runTelemetry.scheduler.totalPhaseBAssignments
      : 0

    const meta: MultihopCellMeta = {
      schemaVersion: 1,
      app,
      sealed,
      seed,
      seedSet,
      mode: args.mode,
      cell: slug,
      llm: llmMode,
      origin: briefing.origin,
      publicOrigins: plan.publicOrigins,
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
      durationMs,
      timedOut: wait.timedOut,
      terminalStatus: wait.status,
      terminalPhase: wait.phase,
      runId,
      projectId,
      chainsTotal,
      chainsOracleObserved,
      chainsCompositeConfirmed,
      chainsConfirmed,
      oracleOnlyCount: twoSide.oracleOnlyCount,
      receiptOnlyCount: twoSide.receiptOnlyCount,
      shortcutViolations: twoSide.shortcutViolations,
      modeBViolations: twoSide.modeBViolations,
      recall: ratio(chainsConfirmed, chainsTotal),
      precision,
      hardenedTwinsTotal,
      hardenedTwinDecoyFps,
      unmatchedFalsePositives,
      costUsd,
      tpPerDollar: efficiency.tpPerDollar,
      tpPer10m: efficiency.tpPer10m,
      hopFunnel,
      depthBreakdown,
      chains: twoSide.verdicts,
      hardenedTwins,
      assignmentsCompleted: assignmentDiagnostics.completed,
      assignmentsTotal: assignmentDiagnostics.total,
      investigationCompleted: assignmentDiagnostics.investigationCompleted,
      phaseBAssignments: runTelemetry.scheduler.totalPhaseBAssignments,
      deadEndReprobeCount: runTelemetry.scheduler.deadEndReprobes,
      deadEndReprobeWasteRate,
      deadEndWastePct: runTelemetry.scheduler.deadEndWastePct,
      frontier: {
        deadEndReprobeCount: runTelemetry.scheduler.deadEndReprobes,
        totalAssignmentsDispatched: runTelemetry.scheduler.totalPhaseBAssignments,
        phaseBAssignments: runTelemetry.scheduler.totalPhaseBAssignments,
        deadEndReprobeWasteRate,
      },
      telemetry: runTelemetry,
      facts: factsCount,
      findingsPersisted: detail.findings.length,
      findingsSubmitted: submitted.length,
      compositeReceiptsExtracted: compositeReceipts.length,
      endpointsDiscovered: detail.endpoints.length,
      requestCount: gradeInput.requestLog.length,
      oracleEventCount: gradeInput.oracleEvents.length,
      inert,
      snapshot: snapshotMeta,
      resumedFrom: snapshotMeta.resume.loaded ? snapshotMeta.resume.directory : null,
      snapshotSkippedMs: snapshotMeta.resume.loaded ? snapshotMeta.resume.skippedMs : 0,
      notes,
      shutdown: { engineBusy: -1, appStopped: false, canaryStopped: false },
    }

    const failureBuckets = (card.failureBuckets ?? {}) as Record<FailureTaxonomyBucket, number>
    const funnel: BenchmarkFunnel = {
      targetVulns: num(card.funnel?.targetVulns, chainsTotal),
      surfaceDiscovered: num(card.funnel?.surfaceDiscovered, detail.endpoints.length),
      hypothesisFormed: num(card.funnel?.hypothesisFormed),
      signalObserved: num(card.funnel?.signalObserved, hopFunnel.H1),
      specSubmitted: num(card.funnel?.specSubmitted, submitted.length),
      zeroLlmConfirmed: num(card.funnel?.zeroLlmConfirmed, llmMode === 'deterministic-no-llm' ? chainsConfirmed : 0),
    }
    storage.insertBenchmarkRun({
      suite: `multihop:${app}:${args.mode}`,
      gitSha,
      modelRoutingConfig: {
        mode: args.mode,
        seed,
        seedSet,
        sealed,
        llm: llmMode,
        profiles: model.profiles,
        verifierBackend: backendKind,
        budgetUsd: args.budgetUsd,
        maxDurationMs: args.maxDurationMs,
        timedOut: wait.timedOut,
      },
      targetsTotal: chainsTotal,
      confirmedCount: chainsConfirmed,
      falsePositiveCount: totalFps,
      funnelCounts: funnel,
      failureTaxonomy: failureBuckets,
      totalCostUsd: costUsd,
      durationMs,
    })

    const jsonPath = join(args.outDir, `${slug}.json`)
    const mdPath = join(args.outDir, `${slug}.md`)
    const metaPath = join(args.outDir, `${slug}.meta.json`)
    writeOwnerOnly(jsonPath, `${runtime.renderScorecard(card, 'json')}\n`)
    writeOwnerOnly(mdPath, `${runtime.renderScorecard(card, 'md')}\n`)

    if (engine) { try { engineBusy = await stopEngine(engine) } catch { engineBusy = -1 } }
    if (backend instanceof LinuxWorkerBackend) { try { await backend.reclaimInactive() } catch { /* best-effort */ } }
    try { await canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
    if (started) { appStopped = await stopStartedApp(started) }
    engine = undefined
    started = undefined
    if (whiteBoxRoot) { try { unlockAndRemove(whiteBoxRoot) } catch { /* best-effort */ } }
    try { storage.close() } catch { /* already closed */ }
    if (isolated && !args.keepDataDirs) { try { unlockAndRemove(dataDir) } catch { /* best-effort */ } }
    unregisterCleanup()

    meta.shutdown = { engineBusy, appStopped, canaryStopped }
    writeOwnerOnly(metaPath, `${JSON.stringify(redactJsonValue(meta, []), null, 2)}\n`)
    return { meta, scorecard: card, jsonPath, mdPath, metaPath }
  } finally {
    if (engine || started) {
      try { await cleanup.runAll() } catch { /* best-effort */ }
    }
    if (whiteBoxRoot) { try { unlockAndRemove(whiteBoxRoot) } catch { /* best-effort */ } }
    try { storage.close() } catch { /* already closed */ }
    releaseCredentialsDir?.()
    if (isolated && !args.keepDataDirs) { try { unlockAndRemove(dataDir) } catch { /* best-effort */ } }
  }
}

// ---------------------------------------------------------------------------------------------
// Aggregation, Anti-Heuristic Gate (<= 5%), Hardened-Twin FP Gate (= 0), and Report
// ---------------------------------------------------------------------------------------------

export interface MultihopAggregate {
  cells: number
  chainsTotal: number
  chainsOracleObserved: number
  chainsCompositeConfirmed: number
  chainsConfirmed: number
  oracleOnlyCount: number
  receiptOnlyCount: number
  shortcutViolations: number
  modeBViolations: number
  recall: number
  precision: number
  worstRunPrecision: number
  hardenedTwinsTotal: number
  hardenedTwinDecoyFps: number
  unmatchedFalsePositives: number
  hardenedTwinGatePassed: boolean
  costUsd: number
  durationMs: number
  tpPerDollar: number | null
  tpPer10m: number | null
  hopFunnel: HopDepthFunnel
  depthBreakdown: DepthTierBreakdown
  assignmentsCompleted: number
  assignmentsTotal: number
}

export function aggregateMultihopCells(cells: readonly MultihopCellMeta[]): MultihopAggregate {
  let chainsTotal = 0
  let chainsOracleObserved = 0
  let chainsCompositeConfirmed = 0
  let chainsConfirmed = 0
  let oracleOnlyCount = 0
  let receiptOnlyCount = 0
  let shortcutViolations = 0
  let modeBViolations = 0
  let hardenedTwinsTotal = 0
  let hardenedTwinDecoyFps = 0
  let unmatchedFalsePositives = 0
  let costUsd = 0
  let durationMs = 0
  let assignmentsCompleted = 0
  let assignmentsTotal = 0
  let worstRunPrecision = 1
  const allChains: MultihopChainVerdict[] = []
  const funnels: HopDepthFunnel[] = []

  for (const cell of cells) {
    chainsTotal += cell.chainsTotal
    chainsOracleObserved += cell.chainsOracleObserved
    chainsCompositeConfirmed += cell.chainsCompositeConfirmed
    chainsConfirmed += cell.chainsConfirmed
    oracleOnlyCount += cell.oracleOnlyCount
    receiptOnlyCount += cell.receiptOnlyCount
    shortcutViolations += cell.shortcutViolations
    modeBViolations += cell.modeBViolations
    hardenedTwinsTotal += cell.hardenedTwinsTotal
    hardenedTwinDecoyFps += cell.hardenedTwinDecoyFps
    unmatchedFalsePositives += cell.unmatchedFalsePositives
    costUsd += cell.costUsd
    durationMs += cell.durationMs
    assignmentsCompleted += cell.assignmentsCompleted
    assignmentsTotal += cell.assignmentsTotal
    worstRunPrecision = Math.min(worstRunPrecision, cell.precision)
    funnels.push(cell.hopFunnel)
    for (const chain of cell.chains) allChains.push(chain)
  }

  const totalFps = hardenedTwinDecoyFps + unmatchedFalsePositives
  const precision = chainsConfirmed + totalFps > 0 ? ratio(chainsConfirmed, chainsConfirmed + totalFps) : 1
  const eff = computeEfficiencyMetrics({ confirmedChains: chainsConfirmed, costUsd, durationMs })
  return {
    cells: cells.length,
    chainsTotal,
    chainsOracleObserved,
    chainsCompositeConfirmed,
    chainsConfirmed,
    oracleOnlyCount,
    receiptOnlyCount,
    shortcutViolations,
    modeBViolations,
    recall: ratio(chainsConfirmed, chainsTotal),
    precision,
    worstRunPrecision: cells.length ? worstRunPrecision : 1,
    hardenedTwinsTotal,
    hardenedTwinDecoyFps,
    unmatchedFalsePositives,
    hardenedTwinGatePassed: hardenedTwinDecoyFps === 0 && unmatchedFalsePositives === 0 && worstRunPrecision >= 1,
    costUsd,
    durationMs,
    tpPerDollar: eff.tpPerDollar,
    tpPer10m: eff.tpPer10m,
    hopFunnel: aggregateHopDepthFunnels(funnels),
    depthBreakdown: computeDepthTierBreakdown(allChains),
    assignmentsCompleted,
    assignmentsTotal,
  }
}

export interface MultihopAntiHeuristicGate {
  ceiling: number
  recall: number
  confirmed: number
  targets: number
  passed: boolean
  chains: Array<{
    app: string
    seed: number
    chainId: string
    expectedHops: number
    maxHopReached: number
    twoSideConfirmed: boolean
  }>
}

export function evaluateAntiHeuristicGate(
  cells: readonly MultihopCellMeta[],
  ceiling: number = ANTI_HEURISTIC_CEILING,
): MultihopAntiHeuristicGate {
  const agg = aggregateMultihopCells(cells)
  const chains = cells.flatMap(cell => cell.chains.map(ch => ({
    app: cell.app,
    seed: cell.seed,
    chainId: ch.chainId,
    expectedHops: ch.expectedHops,
    maxHopReached: ch.maxHopReached,
    twoSideConfirmed: ch.twoSideConfirmed,
  })))
  return {
    ceiling,
    recall: agg.recall,
    confirmed: agg.chainsConfirmed,
    targets: agg.chainsTotal,
    passed: agg.recall <= ceiling,
    chains,
  }
}

export interface MultihopFloorBaseline {
  recall: number
  confirmed: number
  targets: number
  cells: number
}

export function floorBaseline(cells: readonly MultihopCellMeta[]): MultihopFloorBaseline | null {
  const floorCells = cells.filter(cell => cell.llm === 'deterministic-no-llm')
  if (!floorCells.length) return null
  const confirmed = floorCells.reduce((n, c) => n + c.chainsConfirmed, 0)
  const targets = floorCells.reduce((n, c) => n + c.chainsTotal, 0)
  return { recall: ratio(confirmed, targets), confirmed, targets, cells: floorCells.length }
}

export interface MultihopLift {
  agenticRecall: number
  floorRecall: number | null
  deltaReasoning: number | null
  costUsd: number
  tpPerDollar: number | null
  tpPer10m: number | null
}

export function computeMultihopLift(
  agentic: readonly MultihopCellMeta[],
  floor: MultihopFloorBaseline | null,
): MultihopLift {
  const agg = aggregateMultihopCells(agentic)
  return {
    agenticRecall: agg.recall,
    floorRecall: floor ? floor.recall : null,
    deltaReasoning: floor && agentic.length ? agg.recall - floor.recall : null,
    costUsd: agg.costUsd,
    tpPerDollar: agg.tpPerDollar,
    tpPer10m: agg.tpPer10m,
  }
}

export interface MultihopCurveRow {
  budgetUsd: number
  maxDurationMs: number
  cells: number
  chainsTotal: number
  chainsConfirmed: number
  recall: number
  hardenedTwinDecoyFps: number
  costUsd: number
  tpPerDollar: number | null
  tpPer10m: number | null
}

export function budgetDurationCurve(cells: readonly MultihopCellMeta[]): MultihopCurveRow[] {
  const groups = new Map<string, MultihopCellMeta[]>()
  for (const cell of cells) {
    if (cell.llm !== 'agentic') continue
    const key = `${cell.budgetUsd}:${cell.maxDurationMs}`
    const list = groups.get(key) ?? []
    list.push(cell)
    groups.set(key, list)
  }
  return [...groups.values()]
    .map(group => {
      const agg = aggregateMultihopCells(group)
      return {
        budgetUsd: group[0]!.budgetUsd,
        maxDurationMs: group[0]!.maxDurationMs,
        cells: group.length,
        chainsTotal: agg.chainsTotal,
        chainsConfirmed: agg.chainsConfirmed,
        recall: agg.recall,
        hardenedTwinDecoyFps: agg.hardenedTwinDecoyFps,
        costUsd: agg.costUsd,
        tpPerDollar: agg.tpPerDollar,
        tpPer10m: agg.tpPer10m,
      }
    })
    .sort((a, b) => a.budgetUsd - b.budgetUsd || a.maxDurationMs - b.maxDurationMs)
}

export interface MultihopReport {
  schemaVersion: 1
  generatedAt: string
  gitSha: string
  cells: MultihopCellMeta[]
  agentic: MultihopAggregate
  floorRun: MultihopAggregate | null
  floor: MultihopFloorBaseline | null
  lift: MultihopLift
  curve: MultihopCurveRow[]
  antiHeuristicGate: MultihopAntiHeuristicGate | null
  hardenedTwinGatePassed: boolean
  telemetry?: MultihopRunTelemetry | null
  notes: string[]
}

export function buildMultihopReport(
  cells: MultihopCellMeta[],
  floorCells: MultihopCellMeta[],
  gitSha: string,
): MultihopReport {
  const agenticCells = cells.filter(c => c.llm === 'agentic')
  const floorRunCells = cells.filter(c => c.llm === 'deterministic-no-llm')
  const allFloor = floorCells.length ? floorCells : floorRunCells
  const floor = floorBaseline(allFloor)
  const agentic = aggregateMultihopCells(agenticCells)
  const floorRun = floorRunCells.length ? aggregateMultihopCells(floorRunCells) : null
  const allAgg = aggregateMultihopCells(cells)
  const telemetry = aggregateMultihopTelemetry(agenticCells.length ? agenticCells : cells)

  const notes: string[] = []
  if (agenticCells.length && !floor) {
    notes.push('no --no-llm floor cells supplied: ΔReasoning is n/a (pass --floor-from <dir> or run --no-llm)')
  }
  if (cells.some(c => c.sealed)) {
    notes.push('includes SEALED connecthub cells (M4 certification only)')
  }
  if (cells.some(c => c.seedSet === 'held-out')) {
    notes.push('held-out cells use salted seeds; KOVO_RB_HELDOUT_SALT is never persisted in any artifact')
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    gitSha,
    cells,
    agentic,
    floorRun,
    floor,
    lift: computeMultihopLift(agenticCells, floor),
    curve: budgetDurationCurve(allFloor.concat(agenticCells)),
    antiHeuristicGate: floorRunCells.length ? evaluateAntiHeuristicGate(floorRunCells) : null,
    hardenedTwinGatePassed: allAgg.hardenedTwinGatePassed,
    telemetry,
    notes,
  }
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`
const fmtMs = (ms: number | null): string => (ms === null ? 'n/a' : `${(ms / 1000).toFixed(1)}s (${ms}ms)`)

function mdTable(headers: string[], rows: string[][]): string {
  const lines = [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`]
  for (const row of rows) lines.push(`| ${row.join(' | ')} |`)
  return lines.join('\n')
}

export function renderMultihopReport(report: MultihopReport, format: 'json' | 'md'): string {
  if (format === 'json') return JSON.stringify(report, null, 2)

  const lines: string[] = []
  lines.push('# Kovo Hunter v8 multihop-saas scorecard')
  lines.push('')
  lines.push(`Generated ${report.generatedAt} · git ${report.gitSha}`)
  lines.push('')
  const a = report.agentic
  const f = a.hopFunnel
  lines.push('## Headline (Two-Side Confirmation)')
  lines.push('')
  lines.push(mdTable(
    ['metric', 'value'],
    [
      ['agentic cells', String(a.cells)],
      ['two-side confirmed chains', `${a.chainsConfirmed}/${a.chainsTotal} (${pct(a.recall)})`],
      ['worst-run precision', pct(a.worstRunPrecision)],
      ['hardened-twin decoy FPs (must be 0)', `${a.hardenedTwinDecoyFps}/${a.hardenedTwinsTotal}`],
      ['unmatched FPs', String(a.unmatchedFalsePositives)],
      ['3–4 hop recall', `${a.depthBreakdown.hops3to4.confirmed}/${a.depthBreakdown.hops3to4.targets} (${pct(a.depthBreakdown.hops3to4.recall)})`],
      ['5–6 hop recall', `${a.depthBreakdown.hops5to6.confirmed}/${a.depthBreakdown.hops5to6.targets} (${pct(a.depthBreakdown.hops5to6.recall)})`],
      ['TP/$', a.tpPerDollar === null ? 'n/a' : a.tpPerDollar.toFixed(2)],
      ['TP/10m', a.tpPer10m === null ? 'n/a' : a.tpPer10m.toFixed(2)],
      ['`--no-llm` floor recall', report.lift.floorRecall === null ? 'n/a' : pct(report.lift.floorRecall)],
      ['ΔReasoning (agentic − floor)', report.lift.deltaReasoning === null ? 'n/a' : `${(report.lift.deltaReasoning * 100).toFixed(1)}pp`],
    ],
  ))
  lines.push('')
  lines.push('## Hop-Depth Funnel')
  lines.push('')
  lines.push(mdTable(
    ['stage', 'chains'],
    [
      ['Total', String(f.totalChains)],
      ['H1', String(f.H1)],
      ['H2', String(f.H2)],
      ['H3', String(f.H3)],
      ['H4+', String(f.H4Plus)],
      ['FinalOracle (ChainOracle v2)', String(f.FinalOracle)],
      ['CompositeReceiptConfirmed (Two-Side TP)', String(f.CompositeReceiptConfirmed)],
    ],
  ))
  lines.push('')
  if (report.antiHeuristicGate) {
    const g = report.antiHeuristicGate
    lines.push('## Anti-Heuristic Gate (`--no-llm <= 5%`)')
    lines.push('')
    lines.push(`Floor chain recall **${pct(g.recall)}** (${g.confirmed}/${g.targets}) vs ceiling **${pct(g.ceiling)}** -> **${g.passed ? 'PASS' : 'FAIL'}**`)
    lines.push('')
  }
  const tel = report.telemetry ?? aggregateMultihopTelemetry(report.cells)
  if (tel) {
    const pt = tel.phaseTiming
    const sc = tel.scheduler
    const cl = tel.capabilityLedger
    const sdk = tel.v8SdkAdoption
    const rejectSummary = sdk.topRejectReasons.length
      ? sdk.topRejectReasons.slice(0, 5).map(r => `\`${r.reason}\` (${r.count})`).join(', ')
      : 'none'
    lines.push('## Telemetry Summary')
    lines.push('')
    lines.push(mdTable(
      ['section', 'metrics'],
      [
        [
          'Phase Timing',
          `codeAudit=${fmtMs(pt.codeAuditMs)}, floor=${fmtMs(pt.floorMs)}, phaseBStart=${fmtMs(pt.phaseBStartMs)}, firstChainDispatch=${fmtMs(pt.firstChainDispatchMs)}, totalWall=${fmtMs(pt.totalWallMs)}`,
        ],
        [
          'Scheduler & Waste',
          `maxConc=${sc.maxEffectiveConcurrency}, workers=${sc.workersCompleted}/${sc.workersStarted}, rotations=${sc.wallClockRotations}, maxWorkerWall=${fmtMs(sc.maxWorkerWallMs)}, phaseBAssignments=${sc.totalPhaseBAssignments}, deadEndReprobes=${sc.deadEndReprobes} (${sc.deadEndWastePct.toFixed(2)}%)`,
        ],
        [
          'CapabilityLedger',
          `nodes=${cl.nodesTotal} (capOnly=${cl.capabilityOnlyCount}, sealed=${cl.sealedHandlesCount}), causalEdges=${cl.causalEdgesCount}, negEdgesPruned=${cl.negativeEdgesPrunedCount}, compositeReceipts=${cl.compositeReceiptsCount}`,
        ],
        [
          'v8 SDK Adoption',
          `kovo_verify=${sdk.kovoVerifyCalls}, seal=${sdk.sealCapabilityCalls}, hmac=${sdk.hmacSignCalls}, jwt=${sdk.jwtSignCalls}, awaitAsync=${sdk.awaitAsyncCalls}, proveComposite=${sdk.proveCompositeCalls} (confirmed=${sdk.compositeConfirmed}), topRejects=${rejectSummary}`,
        ],
        ...(sdk.topRejectDetails?.length
          ? [[
              'Top Reject Details',
              sdk.topRejectDetails.slice(0, 5).map(d => `\`${d.reason}\`: ${d.signature.replace(/\|/g, '/')} (${d.count})`).join('; '),
            ]]
          : []),
      ],
    ))
    lines.push('')
  }
  lines.push('## Per Cell')
  lines.push('')
  lines.push(mdTable(
    ['cell', 'llm', 'confirmed', 'recall', 'precision', 'twinFP', 'TP/$', 'TP/10m', 'cost'],
    report.cells.map(c => [
      c.cell,
      c.llm === 'agentic' ? 'agentic' : 'floor',
      `${c.chainsConfirmed}/${c.chainsTotal}`,
      pct(c.recall),
      pct(c.precision),
      `${c.hardenedTwinDecoyFps}/${c.hardenedTwinsTotal}`,
      c.tpPerDollar === null ? 'n/a' : c.tpPerDollar.toFixed(2),
      c.tpPer10m === null ? 'n/a' : c.tpPer10m.toFixed(2),
      `$${c.costUsd.toFixed(4)}`,
    ]),
  ))
  lines.push('')
  return lines.join('\n')
}

function readMetaArtifacts(dirs: string[]): MultihopCellMeta[] {
  const out = new Map<string, MultihopCellMeta>()
  for (const dir of dirs) {
    if (!existsSync(dir)) continue
    let entries: string[]
    try { entries = readdirSync(dir) } catch { continue }
    for (const entry of entries) {
      if (!entry.endsWith('.meta.json')) continue
      try {
        const parsed = JSON.parse(readFileSync(join(dir, entry), 'utf8')) as Partial<MultihopCellMeta>
        if (parsed.schemaVersion !== 1) continue
        if (typeof parsed.app !== 'string' || typeof parsed.seed !== 'number' || typeof parsed.mode !== 'string') continue
        if (typeof parsed.chainsTotal !== 'number' || typeof parsed.chainsConfirmed !== 'number') continue
        if (parsed.llm !== 'agentic' && parsed.llm !== 'deterministic-no-llm') continue
        const key = `${parsed.app}:${parsed.seed}:${parsed.mode}:${parsed.llm}`
        if (!out.has(key)) out.set(key, parsed as MultihopCellMeta)
      } catch { /* ignore unreadable artifacts */ }
    }
  }
  return [...out.values()]
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

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const args = parseMultihopArgs(argv)
  if (args.help) {
    process.stdout.write(usage)
    return 0
  }

  assertLocalLabAllowed()
  activeSalt = args.heldOut ? (process.env.KOVO_RB_HELDOUT_SALT ?? '') : ''
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })

  const runtime = await loadMultihopRuntime()
  if (args.listSeeds) {
    const seeds = await runtime.listSeeds()
    process.stdout.write(`${JSON.stringify({ apps: [...multihopAppNames], devApps: [...multihopDevAppNames], sealedApps: [...multihopSealedAppNames], seeds }, null, 2)}\n`)
    return 0
  }

  const cleanup = createCleanupRegistry(error =>
    process.stderr.write(`warning: cleanup step failed: ${redact(String((error as Error)?.message ?? error)).slice(0, 200)}\n`))
  let aborted = false
  const emergency = (code: number) => {
    if (aborted) return
    aborted = true
    process.stderr.write('[multihop-saas] signal received; stopping cells and reclaiming workers\n')
    void cleanup.runAll().finally(() => process.exit(code))
  }
  process.once('SIGINT', () => emergency(130))
  process.once('SIGTERM', () => emergency(143))

  const cells = cellKeys(args)
  process.stdout.write(
    `[multihop-saas] ${cells.length} cell(s): ${cells.map(c => `${c.app}@${c.seed}`).join(', ')} `
    + `mode=${args.mode} llm=${args.noLlm ? 'deterministic-no-llm' : 'agentic'} `
    + `budget=$${args.budgetUsd} duration=${Math.round(args.maxDurationMs / 60_000)}m\n`,
  )

  const results = await runWithConcurrency(cells, args.concurrency, async ({ app, seed }) => {
    if (aborted) throw new PreflightError('aborted by signal')
    return runCell(args, app, seed, runtime, line => process.stdout.write(`${line}\n`), cleanup)
  })

  const failures = results.filter((r): r is { error: Error; item: { app: MultihopAppName; seed: number } } => 'error' in r)
  const ok = results.filter((r): r is MultihopCellResult => !('error' in r))
  let exitCode = 0

  if (ok.length) {
    const currentMeta = ok.map(r => r.meta)
    const floorExtra = readMetaArtifacts(args.floorFrom).filter(c => c.llm === 'deterministic-no-llm')
    const curveExtra = readMetaArtifacts(args.curveFrom)
    const report = buildMultihopReport(
      currentMeta,
      currentMeta.filter(c => c.llm === 'deterministic-no-llm').concat(floorExtra),
      resolveGitSha(),
    )
    if (curveExtra.length) report.curve = budgetDurationCurve(currentMeta.concat(curveExtra))

    const jsonPath = args.jsonPath ?? join(args.outDir, 'multihop-report.json')
    const mdPath = args.mdPath ?? join(args.outDir, 'multihop-report.md')
    writeOwnerOnly(jsonPath, `${renderMultihopReport(report, 'json')}\n`)
    writeOwnerOnly(mdPath, `${renderMultihopReport(report, 'md')}\n`)
    process.stdout.write(`\nwrote ${jsonPath}\nwrote ${mdPath}\n`)

    if (report.antiHeuristicGate && !report.antiHeuristicGate.passed) {
      process.stderr.write(
        `error: Anti-Heuristic Gate FAILED: --no-llm chain recall ${pct(report.antiHeuristicGate.recall)} `
        + `exceeds ${pct(report.antiHeuristicGate.ceiling)} ceiling\n`,
      )
      exitCode = Math.max(exitCode, 3)
    }

    if (!report.hardenedTwinGatePassed) {
      const agg = aggregateMultihopCells(currentMeta)
      process.stderr.write(
        `error: Hardened-Twin / Precision Gate FAILED: hardenedTwinDecoyFps=${agg.hardenedTwinDecoyFps}, `
        + `unmatchedFalsePositives=${agg.unmatchedFalsePositives}, worstRunPrecision=${pct(agg.worstRunPrecision)}\n`,
      )
      exitCode = Math.max(exitCode, 4)
    }
  }

  for (const failure of failures) {
    process.stderr.write(`error: ${failure.item.app} seed=${failure.item.seed}: ${failure.error.message}\n`)
    exitCode = Math.max(exitCode, Number((failure.error as { exitCode?: number }).exitCode ?? 1))
  }

  const inert = ok.filter(r => r.meta.inert)
  if (inert.length) {
    process.stderr.write(`error: ${inert.length} agentic cell(s) were inert\n`)
    exitCode = Math.max(exitCode, 2)
  }

  return exitCode
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  main()
    .then(code => {
      process.exitCode = code
      setImmediate(() => process.exit(code))
    })
    .catch(error => {
      process.stderr.write(`error: ${(error as Error).message}\n`)
      process.exit(Number((error as { exitCode?: number }).exitCode ?? 1))
    })
}
