#!/usr/bin/env node
/**
 * Guardian v8 Multi-Hop SaaS Product Benchmark Runner (plans/v8.md §Evaluation).
 *
 * Drives the *real* `Execution` loop (deterministic `--no-llm` floor OR agentic `--verifier docker`)
 * against `benchmarks/multihop-saas/` multi-service loopback SaaS archetypes and computes:
 *
 *   - Two-Side Confirmation: `ChainOracle v2` (ordered causal DAG from an attacker persona, zero
 *     shortcut violations) AND host-verified Guardian `CompositeProofReceipt` (Mode A clean replay)
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
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'

import type {
  BenchmarkFunnel,
  FailureTaxonomyBucket,
  RunTelemetry,
  SubmittedFinding,
} from '../benchmarks/realistic-bench/lib/types.ts'
import { assertLocalLabAllowed } from '../benchmarks/realistic-bench/lib/safety.ts'
import type { Finding } from '../src/domain.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { CompositeProofReceipt, CompositeReceiptVerification } from '../src/server/composite-receipt.ts'
import { Execution } from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { privateModelProfiles } from '../src/server/model-settings.ts'
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
  role: string
  rolesByTenant?: Record<string, string>
}

/** Mode-scoped briefing exposed to Guardian (never ground truth, never victim bot creds). */
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
  origins?: Record<string, string>
  plan?: { seedSet?: 'dev' | 'held-out' }
  groundTruth: unknown
  sourceDir?: string
  oracle: {
    events(): unknown[]
    requests(): unknown[]
    egress?(): unknown[]
    chainStates?(): unknown[]
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
  /** Side 2: Guardian emitted a host-verified Mode-A CompositeProofReceipt for this chain. */
  compositeReceiptConfirmed: boolean
  /** True iff Side 1 (no shortcut) AND Side 2 both pass. */
  twoSideConfirmed: boolean
  /** Optional replay mode recorded by Guardian's receipt. */
  replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
  /** Diagnostic reason when the chain did not reach two-side confirmation. */
  dropReason?: HopDropReason | null
  matchedFindingIds?: string[]
  oracleEventSeqs?: number[]
  terminalVulnClass?: string | null
}

export interface MultihopTwinVerdict {
  twinId: string
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

export const usage = `Guardian v8 multihop-saas Product Benchmark Runner (real Execution loop, plans/v8.md §Evaluation)

Usage:
  GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-multihop.ts [flags]

Flags:
  --app <name|dev|all>      paygrid | shipforge | nexusiam | connecthub | dev | all
                            (default: dev = paygrid,shipforge,nexusiam; connecthub is SEALED for M4)
  --seed <n>                single dev seed (1..9999)
  --seeds <a,b,c>           comma-separated seeds
  --held-out                seeds are salted held-out (>= 1000000); requires GUARDIAN_RB_HELDOUT_SALT
                            (the salt is never printed, stored, or committed)
  --mode <m>                black-box | grey-box | white-box (default: grey-box)
  --no-llm                  deterministic floor run AND Anti-Heuristic Gate:
                            exits 3 when overall chain recall > ${Math.round(ANTI_HEURISTIC_CEILING * 100)}%
  --verifier <kind>         auto | docker | local-jq (default: auto)
  --budget-usd <n>          per-cell USD budget (default: ${DEFAULT_BUDGET_USD})
  --max-duration-ms <n|10m|30m|60m>
                            wall-clock cap per cell (default: ${Math.round(DEFAULT_MAX_DURATION_MS / 60_000)}m)
  --concurrency <n>         parallel app/seed cells (default: ${DEFAULT_CONCURRENCY})
  --data-dir <path>         Guardian data dir (default: $GUARDIAN_DATA_DIR)
  --isolate-data-dir        per-cell isolated data dir (credentials symlinked, key never copied)
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
  --out-dir <path>          artifact directory (default: .guardian/multihop-saas)
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
      if (/salt/i.test(key)) {
        fail(`never pass a salt on the command line; set GUARDIAN_RB_HELDOUT_SALT instead (got --${key})`)
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
      outDir: resolve('.guardian/multihop-saas'),
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
  const salt = env.GUARDIAN_RB_HELDOUT_SALT ?? ''
  if (heldOut) {
    if (salt.length < 16) fail('--held-out requires GUARDIAN_RB_HELDOUT_SALT (>= 16 chars; never printed)')
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

  const outDirRaw = stringFlag(a, 'out-dir') ?? '.guardian/multihop-saas'
  const dataDirRaw = stringFlag(a, 'data-dir') ?? env.GUARDIAN_DATA_DIR

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
}

/**
 * Enforces AGENTS.md fail-fast invariant: agentic runs with a model profile + `local-jq`
 * (or any backend incapable of opening worker sessions) fail immediately with exit code 2.
 */
export function assertMultihopPreflight(input: MultihopPreflightInput): void {
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
 *   (no forbiddenShortcutViolation) AND Guardian emitted a host-verified Mode-A
 *   `CompositeProofReceipt` (`replayMode === 'fresh_clean_replay'`).
 */
export function evaluateTwoSideConfirmation(
  rawVerdicts: readonly MultihopChainVerdict[],
  compositeReceipts: readonly SubmittedCompositeProof[] = [],
): TwoSideConfirmationSummary {
  const receiptByChainId = new Map<string, SubmittedCompositeProof>()
  const receiptByFindingId = new Map<string, SubmittedCompositeProof>()
  for (const r of compositeReceipts) {
    if (r.chainId) receiptByChainId.set(r.chainId, r)
    if (r.findingId) receiptByFindingId.set(r.findingId, r)
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
  personas: Array<{ handle: string; roleLabel: string; email: string; password: string; canaryMarkers: string[] }>
  capabilityTier: 3
  mission: string
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
    } catch { /* try next conventional path */ }
  }
  return null
}

export function pickLoginPath(briefing: Pick<MultihopBriefing, 'apiReference'>): string | null {
  const routes = briefing.apiReference ?? []
  const named = routes.filter(r => /login|signin|sign-in|session/i.test(`${r.routeKey} ${r.path}`))
  const posts = named.filter(r => r.method.toUpperCase() === 'POST')
  const ranked = (posts.length ? posts : named).slice().sort((a, b) => {
    const legacy = (r: MultihopApiRef) => (/legacy|v1\//i.test(r.routeKey) ? 1 : 0)
    const exact = (r: MultihopApiRef) => (/^(login|signin|session)$/i.test(r.routeKey) ? 0 : 1)
    return exact(a) - exact(b) || legacy(a) - legacy(b)
  })
  return ranked[0]?.path ?? null
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
    let handle = safeHandle(p.id)
    for (let n = 2; handles.has(handle); n += 1) handle = `${safeHandle(p.id)}-${n}`
    handles.add(handle)
    const roleLabel = p.rolesByTenant
      ? Object.entries(p.rolesByTenant).map(([t, r]) => `${r}@${t}`).join(', ')
      : `${p.role} (${p.tenant})`
    return {
      handle,
      roleLabel,
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
  replaySpecs: ReadonlyArray<{ id: string; findingId: string | null; spec: unknown }>
}): SubmittedCompositeProof[] {
  const out: SubmittedCompositeProof[] = []
  const seen = new Set<string>()

  const inspectRecord = (findingId: string | undefined, raw: unknown): void => {
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
      const key = `${candidate.chainId}:${findingId ?? ''}`
      if (seen.has(key)) return
      seen.add(key)
      const replayMode = candidate.replayMode === 'one_shot_transcript' ? 'one_shot_transcript' : 'fresh_clean_replay'
      const confirmed = verification ? Boolean(verification.confirmed) : false
      const attackerProvenanceValid = verification
        ? verification.failedStage !== 'attacker_provenance'
        : false
      out.push({
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
      })
    }
  }

  for (const row of input.replaySpecs) {
    inspectRecord(row.findingId ?? undefined, row.spec)
  }
  for (const finding of input.findings) {
    inspectRecord(finding.id, (finding as unknown as { evidence?: unknown }).evidence)
  }
  return out
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
    linkSnapshotModelCredentials({
      snapshotDb: join(dataDir, 'guardian.sqlite'),
      ...(sourceDataDir ? { sourceDataDir } : {}),
      targetDataDir: dataDir,
    })
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

  const unregisterCleanup = cleanup.add(async () => {
    if (engine) { try { engineBusy = await stopEngine(engine) } catch { engineBusy = -1 } }
    if (backend instanceof LinuxWorkerBackend) { try { await backend.reclaimInactive() } catch { /* best-effort */ } }
    try { await canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
    if (started) { try { await started.stop(); appStopped = true } catch { appStopped = false } }
  })

  try {
    // --- Preflight (before booting any lab service): fail fast on model profile + local-jq ---
    let profiles: ResolvedModelProfile[] = []
    try {
      profiles = privateModelProfiles(storage)
    } catch (error) {
      notes.push(`model profile lookup failed: ${redact((error as Error).message).slice(0, 160)}`)
    }
    if (args.noLlm) notes.push('--no-llm: deterministic floor mode (model profiles ignored)')
    model = describeModelMode(args.noLlm ? [] : profiles)

    const selected = await (async () => {
      try {
        return await selectVerifierBackend(args.verifier)
      } catch (error) {
        const detail = redact(error instanceof Error ? error.message : String(error)).slice(0, 240)
        if (args.verifier === 'docker') {
          throw new PreflightError(
            `--verifier docker is not usable from this process: ${detail}. `
            + 'Re-run under `newgrp docker -c \'<command>\'` and ensure guardian-worker:v4 is built.',
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
      ...(args.heldOut ? { heldOutSalt: process.env.GUARDIAN_RB_HELDOUT_SALT } : {}),
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
        storage.importProjectSpec({
          requestId: randomUUID(),
          projectId,
          name: `multihop-saas-${app}-api.json`,
          kind: 'openapi',
          origin: briefing.origin,
          content: JSON.stringify(plan.openApi, null, 2),
        })
      }

      if (args.mode === 'white-box' && briefing.sourceDir) {
        const mounted = await makeWhiteBoxMount(briefing.sourceDir, String(briefing.app), dataDir, projectId)
        if (mounted.length) {
          whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', String(briefing.app))
          notes.push(`white-box read-only source mount: ${mounted.join(', ')}`)
        }
      }

      if (loginPath) {
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
        budgetRequests: 5_000,
        maxRpsPerOrigin: 15,
        workerConcurrency: Math.min(4, Math.max(1, args.concurrency)),
        workerMaxTurns: 40,
        multiTrialEnabled: true,
      })
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
        id: row.id, findingId: row.findingId, spec: row.spec,
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
    const hardenedTwinsTotal = num(card.hardenedTwinsTotal, num(card.decoys, hardenedTwins.length))
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
    if (started) { try { await started.stop(); appStopped = true } catch { appStopped = false } }
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

  const notes: string[] = []
  if (agenticCells.length && !floor) {
    notes.push('no --no-llm floor cells supplied: ΔReasoning is n/a (pass --floor-from <dir> or run --no-llm)')
  }
  if (cells.some(c => c.sealed)) {
    notes.push('includes SEALED connecthub cells (M4 certification only)')
  }
  if (cells.some(c => c.seedSet === 'held-out')) {
    notes.push('held-out cells use salted seeds; GUARDIAN_RB_HELDOUT_SALT is never persisted in any artifact')
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
    notes,
  }
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`

function mdTable(headers: string[], rows: string[][]): string {
  const lines = [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`]
  for (const row of rows) lines.push(`| ${row.join(' | ')} |`)
  return lines.join('\n')
}

export function renderMultihopReport(report: MultihopReport, format: 'json' | 'md'): string {
  if (format === 'json') return JSON.stringify(report, null, 2)

  const lines: string[] = []
  lines.push('# Guardian v8 multihop-saas scorecard')
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
      String(c.hardenedTwinDecoyFps),
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
  activeSalt = args.heldOut ? (process.env.GUARDIAN_RB_HELDOUT_SALT ?? '') : ''
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
