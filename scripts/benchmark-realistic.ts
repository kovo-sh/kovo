#!/usr/bin/env node
// Kovo Hunter v5 M0 — true end-to-end `realistic-bench` harness.
//
// Drives Kovo Hunter's REAL `Execution` orchestrator (Phase-0 recon → threat model →
// investigation → Zero-LLM replay verification) against a materialized
// `benchmarks/realistic-bench` app, then grades the persisted findings with the
// benchmark's immutable grader.
//
// It deliberately does NOT touch `scripts/benchmark-probes.ts`,
// `scripts/benchmark-specs*.ts` or `benchmarks/realistic-bench/kovo-adapter.ts`
// (the procedural pipeline). The only benchmark inputs are `startRealisticApp`,
// `briefingFor`, `gradeRun` and `renderScorecard`.
//
// Usage:
//   KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- \
//     --app acme-saas --seed 1 --mode grey-box --budget-usd 5 \
//     --out-dir /tmp/rb-v4-base
//
// Held-out seeds (>= 1_000_000) additionally require KOVO_RB_HELDOUT_SALT
// (>= 16 chars). The salt is read from the environment only and is never written
// to an artifact.
//
// Model usage: a fresh per-cell data directory has no provider profile, so the
// run is deterministic/Zero-LLM (`Execution` stops after threat model because it
// has no investigator). Point `--data-dir` at a Kovo Hunter data directory that has
// an enabled model profile to run the full agentic loop. `--no-llm` refuses to
// run when such a profile is present. The selected model mode is always recorded
// in the artifact metadata; results are never simulated.

import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync,
  writeFileSync,
} from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'

import type {
  AppName, BenchMode, Briefing, GradeInput, OracleEvent, RequestLogEntry,
  RunTelemetry, Scorecard, StartedApp, SubmittedFinding,
} from '../benchmarks/realistic-bench/lib/types.ts'
import { appNames } from '../benchmarks/realistic-bench/lib/types.ts'
import { startRealisticApp, briefingFor, gradeRun, renderScorecard } from '../benchmarks/realistic-bench/run.ts'
import { assertLocalLabAllowed } from '../benchmarks/realistic-bench/lib/safety.ts'
import { endpointMatches } from '../benchmarks/realistic-bench/grader/match.ts'
import { isLocalModelEnvEnabled, maxRpsPerOriginCeiling } from '../src/domain.ts'
import type { EndpointSource, Finding, ParamLocation, PersonaPrivilege } from '../src/domain.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { resolveOobCallbackPorts, defaultWorkerConcurrency, resolveWorkerConcurrency, MAX_RUN_WORKER_CONCURRENCY } from './benchmark-env.ts'
import {
  DEFAULT_AGENT_REQUEST_BUDGET,
  DEFAULT_FLOOR_REQUEST_BUDGET,
  Execution,
} from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { inspectModelProfileLoad, privateModelProfiles } from '../src/server/model-settings.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  getPersonaIdentityFallbackCount,
  normalizeRole,
  resetPersonaIdentityFallbackCount,
} from '../src/server/oracle-invariants.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { redact, redactJsonValue } from '../src/server/redact.ts'
import { normalizeEndpointTemplate } from '../src/server/dedupe.ts'
import { Store } from '../src/server/store.ts'
import type { EndpointRow } from '../src/server/store.ts'
import {
  DEFAULT_SNAPSHOT_MAX_AGE_MS,
  SnapshotError,
  applyRunSnapshot,
  assertSnapshotUsable,
  captureRunSnapshot,
  copySnapshotDatabase,
  readRunSnapshot,
} from '../src/server/run-snapshot.ts'
import type {
  CaptureRunSnapshotResult,
  LoadedRunSnapshot,
  SnapshotCheckpoint,
  SnapshotCounts,
} from '../src/server/run-snapshot.ts'
import { resolveWorkerImageRef, selectVerifierBackend } from './benchmark-backend.ts'
import type { VerifierBackendKind, WorkerImageIdentity } from './benchmark-backend.ts'
import { VERIFY_RPC_SDK_VERSION } from '../src/server/verify-rpc.ts'
import {
  DEFAULT_LEDGER_PATH,
  appendPerRunLedgerRow,
  computeBenchmarkVersion,
  computeEffectiveConfig,
  extractObservedEffectiveConfig,
  promoteLedgerRows,
  resolveGitState,
  type EffectiveConfigSnapshot,
  type LedgerRow,
  type ObservedEffectiveConfig,
} from './bench-ledger.ts'
import { buildLedgerRow } from './score-primitives.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

export const DEFAULT_BUDGET_USD = 5
export const DEFAULT_MAX_DURATION_MS = 15 * 60_000
/** How many app/seed cells run in parallel. Scheduling only; never the in-run worker count. */
export const DEFAULT_CONCURRENCY = 1
/** Lab per-origin rate cap (hard cap; WAF/429 backoff still applies). 25k/600 s needs ~42 RPS. */
export const DEFAULT_MAX_RPS = 50

/**
 * v6 budget split. The 2,000-request constant was a stale floor-era value: at K=6 it was spent by
 * Phase A alone, leaving ~10-25 requests per agentic assignment. These allowances are **caps, not
 * targets** — a run still stops on wall clock, USD or completion, and never spends a request just
 * to reach the allowance.
 *
 * Calibrated anchors (linear between them, capped at the 45-minute values):
 *   600 s  → floor  6,000 / agent  25,000 / total  31,000
 *   45 min → floor 12,000 / agent 100,000 / total 112,000
 */
export const REQUEST_BUDGET_ANCHOR_MS = 600_000
export const FLOOR_BUDGET_ANCHOR = 6_000
export const AGENT_BUDGET_ANCHOR = 25_000
export const FLOOR_BUDGET_CEILING = 12_000
export const AGENT_BUDGET_CEILING = 100_000
export { DEFAULT_AGENT_REQUEST_BUDGET, DEFAULT_FLOOR_REQUEST_BUDGET }

const roundToHundred = (value: number): number => Math.max(100, Math.round(value / 100) * 100)

/** Duration-scaled split allowances. Explicit flags/env always override this. */
export function defaultRequestBudgets(maxDurationMs: number): {
  floor: number
  agent: number
  total: number
} {
  const duration = Number.isFinite(maxDurationMs) && maxDurationMs > 0 ? maxDurationMs : REQUEST_BUDGET_ANCHOR_MS
  const scale = duration / REQUEST_BUDGET_ANCHOR_MS
  const floor = Math.min(FLOOR_BUDGET_CEILING, roundToHundred(FLOOR_BUDGET_ANCHOR * scale))
  const agent = Math.min(AGENT_BUDGET_CEILING, roundToHundred(AGENT_BUDGET_ANCHOR * scale))
  return { floor, agent, total: floor + agent }
}

/** Duration-scaled USD cap: $5 at 600 s, $10 at 45 min (linear between). */
export function defaultBudgetUsd(maxDurationMs: number): number {
  const duration = Number.isFinite(maxDurationMs) && maxDurationMs > 0 ? maxDurationMs : REQUEST_BUDGET_ANCHOR_MS
  if (duration <= REQUEST_BUDGET_ANCHOR_MS) return DEFAULT_BUDGET_USD
  const span = 2_700_000 - REQUEST_BUDGET_ANCHOR_MS
  const extra = Math.min(5, Math.round((5 * (duration - REQUEST_BUDGET_ANCHOR_MS)) / span))
  return DEFAULT_BUDGET_USD + Math.max(0, extra)
}

export const DEFAULT_TOTAL_REQUEST_BUDGET = defaultRequestBudgets(REQUEST_BUDGET_ANCHOR_MS).total

export interface RealisticArgs {
  apps: AppName[]
  seeds: number[]
  mode: BenchMode
  heldOut: boolean
  budgetUsd: number
  maxDurationMs: number
  /** Phase-A (deterministic floor) request allowance. Never borrowed by Phase B. */
  floorRequestBudget: number
  /** Phase-B (agentic investigation) request allowance. Never borrowed by Phase A. */
  agentRequestBudget: number
  /** Hard run-total request cap (`runs.budget_requests`). Defaults to floor + agent. */
  totalRequestBudget: number
  /** Hard per-origin requests/second cap written to the run (default 50 for lab runs). */
  maxRps: number
  outDir: string
  /** Parallel app/seed cells. */
  concurrency: number
  /**
   * In-run investigation worker slots handed to `Execution` (`runs.worker_concurrency`).
   * Independent of `concurrency`: a cell may run one at a time and still use 6 workers.
   */
  workerConcurrency: number
  dataDir?: string
  noLlm: boolean
  /** Conventional noun/action route wordlists (local-lab opt-in only; non-reportable when ON). Default OFF. */
  conventionalWordlist: boolean
  isolateDataDir: boolean
  keepDataDirs: boolean
  allowInertWorkers: boolean
  verifier: 'auto' | 'docker' | 'local-jq'
  /** Reuse a Phase-0 recon snapshot from this directory (v5.1 inner loop). */
  reuseReconDir?: string
  /** Ignore any existing snapshot and recapture it after a fresh Phase-0 pass. */
  refreshRecon: boolean
  /** Capture a post-floor/planner-round checkpoint into this directory (v5.1 inner loop). */
  snapshotAfterFloorDir?: string
  /** Resume the product harness from a checkpoint instead of paying Phase-0/floor again. */
  resumeSnapshotDir?: string
  /** Reject checkpoints older than this (default 24 h). */
  snapshotMaxAgeMs: number
  /** Ignore an existing checkpoint and recapture it. */
  snapshotRefresh: boolean
  /** Explicitly allow reusing a salted held-out checkpoint (refused by default). */
  allowHeldoutSnapshot: boolean
  /** Optional target ledger path to promote validated per-run rows into (`--ledger [path]` / `--promote-ledger [path]`). */
  ledgerPath?: string
  /** Escape hatch for ad-hoc scratch/dry-runs: disable default per-run ledger emission. */
  noLedger?: boolean
  /** R3-19: Use opaque UI-style role labels ('Account 1', 'Account 2', ...) alongside typed tenantRef & privilege. */
  opaqueLabels: boolean
  help: boolean
}

const usage = `Kovo Hunter realistic-bench (real Execution loop)

Usage:
  KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- [flags]

Flags:
  --app <name|all>        acme-saas | shopflow | opsportal | all (default: all)
  --seed <n>              single dev seed (1..9999)
  --seeds <a,b,c>         comma-separated seeds
  --held-out              seeds are held-out (>= 1000000) and need KOVO_RB_HELDOUT_SALT
  --mode <m>              black-box | grey-box | white-box (default: grey-box)
  --budget-usd <n>        per-run USD budget (default: $${DEFAULT_BUDGET_USD} at 600 s,
                          $10 at 45 min; linear between)
  --max-duration-ms <n>   wall-clock cap per cell (default: ${DEFAULT_MAX_DURATION_MS})
  --budget-requests <n>   hard run-total request cap written to runs.budget_requests
                          (default: floor + agent; --total-request-budget is an alias)
  --floor-request-budget <n>
                          Phase-A deterministic-floor request allowance (default scales
                          with --max-duration-ms: 6,000 at 600 s, 12,000 at 45 min).
                          Phase B never borrows it.
  --agent-request-budget <n>
                          Phase-B agentic-investigation request allowance (default scales
                          with --max-duration-ms: 25,000 at 600 s, 100,000 at 45 min).
                          Phase A never borrows it.
  --max-rps <n>           hard per-origin rate cap (default ${DEFAULT_MAX_RPS}; WAF/429
                          backoff still applies). KOVO_MAX_RPS is the env equivalent.
  These are caps, not targets: wall/USD/completion still end the run.
  --out-dir <path>        artifact directory (default: .kovo/realistic-bench)
  --concurrency <n>       parallel app/seed cells (default: ${DEFAULT_CONCURRENCY})
  --worker-concurrency <n>
                          in-run investigation worker slots handed to Execution
                          (default: 6 agentic, 1 with --no-llm). Independent of
                          --concurrency: it changes how many assignments one cell
                          runs at once, never how many cells run at once.
  --data-dir <path>       Kovo Hunter data dir (single cell: used verbatim, so an
                          existing model profile is picked up; multi-cell: base
                          directory, one isolated child dir per cell)
                          (default: $KOVO_DATA_DIR or <out-dir>/data/<cell>)
  --no-llm                force the deterministic/Zero-LLM path; the run uses an
                          isolated data dir and never loads a model profile
  --conventional-wordlist
                          opt-in local-lab convenience: enable the conventional noun/action
                          route wordlist (default OFF). Stamps scorecard wordlistOn=true
                          and reportable=false.
  --no-conventional-wordlist
                          explicitly keep the conventional noun/action route wordlist OFF
                          (the default). Only target-discovered/declared surface is probed.
  --isolate-data-dir      per-cell data dir initialized from --data-dir: copies only
                          enabled model_profiles rows and reads host credentials via
                          KOVO_CREDENTIALS_DIR (read-only, no symlink, key not copied)
                          (default: on when --concurrency > 1)
  --keep-data-dirs        keep per-cell isolated data dirs after grading (default:
                          remove them)
  --allow-inert-workers   allow an agentic run even when the verifier backend
                          cannot open worker sessions (records an inert run;
                          diagnostics still show zero completed assignments)
  --verifier <kind>       auto | docker | local-jq (default: auto)
  --reuse-recon <dir>     reuse Phase-0 discovery snapshots (endpoints, params,
                          dependencies, redacted resource samples and persona
                          session handles) from <dir>; misses run fresh Phase-0
                          and write a snapshot back. Probing/verification are
                          never skipped and scorecards always come from real probes.
  --refresh-recon         ignore any existing snapshot and recapture it after a
                          fresh Phase-0 pass (requires --reuse-recon)
  --snapshot-after-floor <dir>
                          capture a run checkpoint at the post-floor boundary (and
                          each planner round) so the live-model iteration can resume
                          in seconds. Directory/file modes are 0700/0600.
  --resume-snapshot <dir>
                          resume from a checkpoint: boot the seeded app fresh,
                          rebind origins/ports, re-authenticate personas, and start
                          agentic investigation directly (no Phase-0, no floor).
  --snapshot-max-age-ms <n>
                          refuse checkpoints older than n ms (default 24 h)
  --snapshot-refresh      ignore an existing checkpoint and recapture it
  --allow-heldout-snapshot
                          explicitly allow reusing a salted held-out checkpoint
                          (refused by default)
  --ledger [path]         promote validated per-run ledger rows into committed ledger
                          (default: ${DEFAULT_LEDGER_PATH}; per-run rows are emitted by default)
  --promote-ledger [path] alias for --ledger [path]
  --no-ledger             disable default per-run ledger emission (ad-hoc scratch/dry-runs only)
  --opaque-labels         use opaque UI-style role labels ('Account 1', 'Account 2', ...) with
                          typed tenantRef & privilege (R3-19 realism ablation cell)
  --help                  show this help

Environment:
  KOVO_ALLOW_LOCAL_LAB=1   required to boot loopback lab origins
  KOVO_RB_HELDOUT_SALT     required for --held-out (never logged/committed)
  KOVO_DATA_DIR            default Kovo Hunter data dir (model profile source)
  KOVO_FLOOR_REQUEST_BUDGET / KOVO_AGENT_REQUEST_BUDGET / KOVO_TOTAL_REQUEST_BUDGET
                               defaults for the split request budgets
  KOVO_MAX_RPS             hard per-origin rate cap (default 50)

Parallel agentic matrix:
  --concurrency 3 --isolate-data-dir  gives each cell its own Store under
  <out-dir>/data/<cell>/ with copied profile metadata and reads the real host
  credentials directory via KOVO_CREDENTIALS_DIR (no symlink, key never copied),
  so cells never contend for the source data-dir lock.
  --worker-concurrency controls worker slots *inside* each cell and is unrelated
  to how many cells run in parallel.

Agentic runs need a worker-session-capable verifier:
  model profile + --verifier local-jq  -> exit 2 (inert workers) unless --no-llm
  model profile + --verifier docker    -> requires Docker socket access; run under
                                          newgrp docker -c '<command>'

Recon cache (v5.1 inner loop):
  --reuse-recon <dir> snapshots Phase-0 discovery keyed by (app, seed, split, mode,
  briefing variantHash). A hit seeds the run's Store with endpoints, endpoint_params,
  api_dependencies, engine-redacted resource samples and persona session handles, then
  lets the engine skip Phase-0 (its own phase0CompletedAt gate). Probing and verification
  always run for real; nothing about findings/facts/replay specs is cached. Cache hits
  replay the cached Phase-0 GET paths as benign requests so the discovery funnel stays
  honest. Snapshot files are owner-only (0600) and contain no cookies, bearer tokens,
  passwords or session values; a key mismatch/corrupt file falls back to fresh discovery.
  --refresh-recon ignores an existing snapshot and recaptures it after a fresh Phase-0.

Snapshot resume (v5.1 primary inner loop):
  --snapshot-after-floor <dir> captures <dir>/kovo.sqlite (VACUUM INTO),
  snapshot.json (coordinator state + version stamps) and target.json (app/seed/mode +
  mutating replay log) at the post-floor boundary and at each planner round (round
  snapshots go to <dir>/planner-round-<n>/). --resume-snapshot <dir> copies that DB
  into a fresh data dir, rebinds loopback origins/ports to the freshly booted app and
  canary listener, recreates persona login credentials for fresh sessions, and starts
  the normal agentic loop at 'investigation'. Phase-0 and the deterministic floor are
  never re-run; meta.record has resumedFrom + snapshotSkippedMs. Checkpoints expire
  after --snapshot-max-age-ms (24 h) and salted held-out checkpoints are refused unless
  --allow-heldout-snapshot is passed. The resumed scorecard only counts oracle evidence
  produced by requests in the resumed process; persisted engine evidence (findings,
  facts, specs) is preserved exactly, and nothing is faked.

Artifacts per cell:
  <out-dir>/<app>-seed<seed>-<mode>.json      Scorecard (benchmark grader schema)
  <out-dir>/<app>-seed<seed>-<mode>.md        rendered scorecard
  <out-dir>/<app>-seed<seed>-<mode>.meta.json run/model/budget metadata (redacted)
  <out-dir>/summary.{json,md}                 aggregate over all cells
  benchmark_runs row in the cell data dir      suite = realistic:<app>:<mode>
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

/** flag > env > default, positive integers only. */
function requestBudgetValue(
  flagValue: string | undefined,
  envValue: string | undefined,
  fallback: number,
  flag: string,
): number {
  if (flagValue !== undefined) return parsePositiveInt(flagValue, flag)
  const fromEnv = envValue?.trim()
  if (fromEnv) return parsePositiveInt(fromEnv, flag)
  return fallback
}

/** In-run worker slots: engine ceiling is 16, and 0 would make the run inert. */
export function parseWorkerConcurrency(raw: string): number {
  const n = parsePositiveInt(raw, '--worker-concurrency')
  if (n > MAX_RUN_WORKER_CONCURRENCY) {
    fail(`--worker-concurrency must be between 1 and ${MAX_RUN_WORKER_CONCURRENCY} (got '${raw}')`)
  }
  return n
}

function parseAppList(raw: string | undefined): AppName[] {
  if (!raw || raw === 'all') return [...appNames]
  if (!(appNames as readonly string[]).includes(raw)) {
    fail(`--app must be one of ${appNames.join(', ')}, or all (got '${raw}')`)
  }
  return [raw as AppName]
}

function parseSeeds(a: Record<string, string | boolean>): number[] {
  const rawSeeds = stringFlag(a, 'seeds')
  const rawSeed = stringFlag(a, 'seed')
  if (rawSeeds && rawSeed) fail('use either --seed or --seeds, not both')
  const source = rawSeeds ?? rawSeed ?? '1'
  const seeds = source.split(',').map(s => s.trim()).filter(Boolean).map(s => {
    const n = Number(s)
    if (!Number.isInteger(n) || n <= 0) fail(`seed '${s}' must be a positive integer`)
    return n
  })
  if (!seeds.length) fail('at least one seed is required')
  return [...new Set(seeds)]
}

export function parseRealisticArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): RealisticArgs {
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
    'app', 'seed', 'seeds', 'held-out', 'mode', 'budget-usd', 'max-duration-ms',
    'budget-requests', 'floor-request-budget', 'agent-request-budget', 'total-request-budget',
    'max-rps',
    'out-dir', 'concurrency', 'worker-concurrency', 'data-dir', 'no-llm',
    'conventional-wordlist', 'no-conventional-wordlist', 'isolate-data-dir', 'keep-data-dirs',
    'allow-inert-workers', 'verifier', 'reuse-recon', 'refresh-recon', 'help',
    'snapshot-after-floor', 'resume-snapshot', 'snapshot-max-age-ms', 'snapshot-refresh',
    'allow-heldout-snapshot', 'ledger', 'promote-ledger', 'no-ledger', 'opaque-labels',
  ])
  for (const key of Object.keys(a)) {
    if (!known.has(key)) fail(`unknown flag --${key}`)
  }
  if (a['conventional-wordlist'] === true && a['no-conventional-wordlist'] === true) {
    fail('use either --conventional-wordlist or --no-conventional-wordlist, not both')
  }
  if (a['no-ledger'] === true && (a.ledger !== undefined || a['promote-ledger'] !== undefined)) {
    fail('--no-ledger cannot be combined with --ledger or --promote-ledger')
  }

  if (a.help === true) {
    const defaults = defaultRequestBudgets(DEFAULT_MAX_DURATION_MS)
    return {
      apps: [...appNames], seeds: [1], mode: 'grey-box', heldOut: false,
      budgetUsd: defaultBudgetUsd(DEFAULT_MAX_DURATION_MS), maxDurationMs: DEFAULT_MAX_DURATION_MS,
      floorRequestBudget: defaults.floor,
      agentRequestBudget: defaults.agent,
      totalRequestBudget: defaults.total,
      maxRps: DEFAULT_MAX_RPS,
      outDir: resolve('.kovo/realistic-bench'), concurrency: DEFAULT_CONCURRENCY,
      workerConcurrency: defaultWorkerConcurrency(Boolean(a['no-llm'])),
      noLlm: Boolean(a['no-llm']), isolateDataDir: Boolean(a['isolate-data-dir']),
      conventionalWordlist: a['conventional-wordlist'] === true,
      keepDataDirs: Boolean(a['keep-data-dirs']),
      allowInertWorkers: Boolean(a['allow-inert-workers']),
      verifier: 'auto', refreshRecon: a['refresh-recon'] === true, help: true,
      snapshotMaxAgeMs: DEFAULT_SNAPSHOT_MAX_AGE_MS,
      snapshotRefresh: false, allowHeldoutSnapshot: false,
      opaqueLabels: a['opaque-labels'] === true,
    }
  }

  const reuseReconRaw = stringFlag(a, 'reuse-recon')
  if (a['reuse-recon'] === true) fail('--reuse-recon requires a directory argument')
  const refreshRecon = a['refresh-recon'] === true
  if (refreshRecon && !reuseReconRaw) fail('--refresh-recon requires --reuse-recon <dir> (the snapshot directory to rewrite)')

  const snapshotAfterFloorRaw = stringFlag(a, 'snapshot-after-floor')
  if (a['snapshot-after-floor'] === true) fail('--snapshot-after-floor requires a directory argument')
  const resumeSnapshotRaw = stringFlag(a, 'resume-snapshot')
  if (a['resume-snapshot'] === true) fail('--resume-snapshot requires a directory argument')
  if (snapshotAfterFloorRaw && resumeSnapshotRaw) {
    fail('use either --snapshot-after-floor or --resume-snapshot, not both')
  }
  if (resumeSnapshotRaw && reuseReconRaw) fail('--resume-snapshot already carries Phase-0 state; drop --reuse-recon')
  const snapshotRefresh = a['snapshot-refresh'] === true
  if (snapshotRefresh && !snapshotAfterFloorRaw) {
    fail('--snapshot-refresh requires --snapshot-after-floor <dir>')
  }
  const snapshotMaxAgeMs = a['snapshot-max-age-ms'] === undefined
    ? DEFAULT_SNAPSHOT_MAX_AGE_MS
    : parsePositiveInt(stringFlag(a, 'snapshot-max-age-ms') ?? '', '--snapshot-max-age-ms')

  const modeRaw = stringFlag(a, 'mode') ?? 'grey-box'
  if (modeRaw !== 'black-box' && modeRaw !== 'grey-box' && modeRaw !== 'white-box') {
    fail(`--mode must be black-box, grey-box or white-box (got '${modeRaw}')`)
  }

  const verifierRaw = stringFlag(a, 'verifier') ?? 'auto'
  if (verifierRaw !== 'auto' && verifierRaw !== 'docker' && verifierRaw !== 'local-jq') {
    fail(`--verifier must be auto, docker or local-jq (got '${verifierRaw}')`)
  }

  const heldOut = a['held-out'] === true
  const seeds = parseSeeds(a)
  const salt = env.KOVO_RB_HELDOUT_SALT ?? ''
  if (heldOut) {
    if (salt.length < 16) fail('--held-out requires KOVO_RB_HELDOUT_SALT (>= 16 chars)')
    for (const seed of seeds) if (seed < 1_000_000) fail(`held-out seeds are >= 1000000 (got ${seed})`)
  } else {
    for (const seed of seeds) {
      if (seed >= 1_000_000) fail(`dev seeds are 1..9999 (got ${seed}); add --held-out`)
    }
  }

  const maxDurationMs = a['max-duration-ms'] === undefined
    ? DEFAULT_MAX_DURATION_MS
    : parsePositiveInt(stringFlag(a, 'max-duration-ms') ?? '', '--max-duration-ms')
  // Duration-scaled defaults: $5/6k/25k at 600 s, $10/12k/100k at 45 min.
  const scaledBudgets = defaultRequestBudgets(maxDurationMs)
  // $5 default is preserved for the implicit 15-minute invocation; an explicit duration scales it
  // ($5 at 600 s, $10 at 45 min) unless --budget-usd overrides.
  const budgetUsd = a['budget-usd'] === undefined
    ? (a['max-duration-ms'] === undefined ? DEFAULT_BUDGET_USD : defaultBudgetUsd(maxDurationMs))
    : Number(stringFlag(a, 'budget-usd'))
  if (!Number.isFinite(budgetUsd) || budgetUsd < 0.1 || budgetUsd > 500) {
    fail(`--budget-usd must be a number between 0.1 and 500 (got '${String(a['budget-usd'])}')`)
  }
  // Split request budgets: flag > env > duration-scaled default. Phase A/B never borrow each other.
  const floorRequestBudget = requestBudgetValue(
    stringFlag(a, 'floor-request-budget'), env.KOVO_FLOOR_REQUEST_BUDGET,
    scaledBudgets.floor, '--floor-request-budget',
  )
  const agentRequestBudget = requestBudgetValue(
    stringFlag(a, 'agent-request-budget'), env.KOVO_AGENT_REQUEST_BUDGET,
    scaledBudgets.agent, '--agent-request-budget',
  )
  if (stringFlag(a, 'budget-requests') !== undefined && stringFlag(a, 'total-request-budget') !== undefined) {
    fail('use either --budget-requests or --total-request-budget, not both')
  }
  const totalRequestBudget = requestBudgetValue(
    stringFlag(a, 'budget-requests') ?? stringFlag(a, 'total-request-budget'),
    env.KOVO_TOTAL_REQUEST_BUDGET,
    floorRequestBudget + agentRequestBudget,
    '--budget-requests',
  )
  const maxRps = requestBudgetValue(
    stringFlag(a, 'max-rps'), env.KOVO_MAX_RPS,
    DEFAULT_MAX_RPS,
    '--max-rps',
  )
  if (maxRps > maxRpsPerOriginCeiling) {
    fail(`--max-rps must be between 1 and ${maxRpsPerOriginCeiling} (got '${maxRps}')`)
  }
  const concurrency = a.concurrency === undefined
    ? DEFAULT_CONCURRENCY
    : parsePositiveInt(stringFlag(a, 'concurrency') ?? '', '--concurrency')
  const noLlm = a['no-llm'] === true
  // Cell concurrency (--concurrency) never sets the in-run worker count: an agentic cell needs
  // several investigation slots even when it is the only cell running.
  const workerConcurrency = a['worker-concurrency'] === undefined
    ? defaultWorkerConcurrency(noLlm)
    : parseWorkerConcurrency(stringFlag(a, 'worker-concurrency') ?? '')
  const outDirRaw = stringFlag(a, 'out-dir') ?? '.kovo/realistic-bench'
  const dataDirRaw = stringFlag(a, 'data-dir') ?? env.KOVO_DATA_DIR
  if (resumeSnapshotRaw && noLlm) {
    fail('--resume-snapshot requires the live agentic model; drop --no-llm')
  }

  return {
    apps: parseAppList(stringFlag(a, 'app')),
    seeds,
    mode: modeRaw,
    heldOut,
    budgetUsd,
    maxDurationMs,
    floorRequestBudget,
    agentRequestBudget,
    totalRequestBudget,
    maxRps,
    outDir: isAbsolute(outDirRaw) ? outDirRaw : resolve(outDirRaw),
    concurrency,
    workerConcurrency,
    ...(dataDirRaw ? { dataDir: isAbsolute(dataDirRaw) ? dataDirRaw : resolve(dataDirRaw) } : {}),
    noLlm,
    conventionalWordlist: a['conventional-wordlist'] === true,
    isolateDataDir: a['isolate-data-dir'] === true,
    keepDataDirs: a['keep-data-dirs'] === true,
    allowInertWorkers: a['allow-inert-workers'] === true,
    verifier: verifierRaw,
    ...(reuseReconRaw
      ? { reuseReconDir: isAbsolute(reuseReconRaw) ? reuseReconRaw : resolve(reuseReconRaw) }
      : {}),
    refreshRecon,
    ...(snapshotAfterFloorRaw
      ? { snapshotAfterFloorDir: isAbsolute(snapshotAfterFloorRaw) ? snapshotAfterFloorRaw : resolve(snapshotAfterFloorRaw) }
      : {}),
    ...(resumeSnapshotRaw
      ? { resumeSnapshotDir: isAbsolute(resumeSnapshotRaw) ? resumeSnapshotRaw : resolve(resumeSnapshotRaw) }
      : {}),
    snapshotMaxAgeMs,
    snapshotRefresh,
    allowHeldoutSnapshot: a['allow-heldout-snapshot'] === true,
    ...(a.ledger === true || a['promote-ledger'] === true
      ? { ledgerPath: DEFAULT_LEDGER_PATH }
      : typeof a['promote-ledger'] === 'string'
        ? { ledgerPath: a['promote-ledger'] }
        : typeof a.ledger === 'string'
          ? { ledgerPath: a.ledger }
          : {}),
    ...(a['no-ledger'] === true ? { noLedger: true } : {}),
    opaqueLabels: a['opaque-labels'] === true,
    help: false,
  }
}

// ---------------------------------------------------------------------------------------------
// Briefing -> real Project/Run configuration (briefing only; never ground truth)
// ---------------------------------------------------------------------------------------------

/** Pick a login route from the grey/white-box API reference; black-box falls back to probing. */
export function pickLoginPath(briefing: Pick<Briefing, 'apiReference'>): string | null {
  const routes = briefing.apiReference ?? []
  const named = routes.filter(r => /login|signin|sign-in|session/i.test(`${r.routeKey} ${r.path}`))
  const posts = named.filter(r => r.method.toUpperCase() === 'POST')
  const ranked = (posts.length ? posts : named).slice().sort((a, b) => {
    const legacy = (r: { routeKey: string }) => (/legacy|v1\//i.test(r.routeKey) ? 1 : 0)
    const exact = (r: { routeKey: string }) => (/^(login|signin|session)$/i.test(r.routeKey) ? 0 : 1)
    return exact(a) - exact(b) || legacy(a) - legacy(b)
  })
  return ranked[0]?.path ?? null
}

/** Black-box bootstrap: try conventional JSON login routes with the supplied credentials. */
export async function probeLoginPath(origin: string, personas: Briefing['personas']): Promise<string | null> {
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

export interface OpenApiDoc {
  openapi: string
  info: { title: string; version: string }
  paths: Record<string, Record<string, { parameters: Array<{ name: string; in: string; required: boolean }> }>>
}

/** Build an OpenAPI 3.1 document from the briefing's API reference (grey/white-box). */
export function briefingToOpenApi(briefing: Pick<Briefing, 'app' | 'apiReference'>): OpenApiDoc {
  const paths: OpenApiDoc['paths'] = {}
  for (const route of briefing.apiReference ?? []) {
    const params = route.params.map(name => ({
      name,
      in: route.path.includes(`:${name}`) || route.path.includes(`{${name}}`) ? 'path' : 'query',
      required: route.path.includes(`:${name}`) || route.path.includes(`{${name}}`),
    }))
    paths[route.path] ??= {}
    paths[route.path][route.method.toLowerCase()] = { parameters: params }
  }
  return {
    openapi: '3.1.0',
    info: { title: `realistic-bench ${briefing.app} API reference`, version: '1.0.0' },
    paths,
  }
}

export interface CellPlan {
  briefing: Briefing
  loginPath: string | null
  openApi: OpenApiDoc | null
  personas: Array<{
    handle: string
    roleLabel: string
    tenantRef: string | null
    privilege: PersonaPrivilege | null
    email: string
    password: string
    canaryMarkers: string[]
  }>
  capabilityTier: 2 | 3
  mission: string
}

function safeHandle(id: string): string {
  const cleaned = id.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '')
  return cleaned.length ? cleaned.slice(0, 48) : 'persona'
}

/** Mode -> briefing interpretation; this is the only configuration source. */
export function planCell(
  briefing: Briefing,
  loginPath: string | null,
  options?: { opaqueLabels?: boolean },
): CellPlan {
  if (briefing.mode === 'black-box' && briefing.apiReference) {
    fail('black-box briefings must not include an API reference')
  }
  if (briefing.mode === 'grey-box' && !briefing.apiReference) fail('grey-box briefings require an API reference')
  if (briefing.mode === 'white-box' && !briefing.sourceDir) fail('white-box briefings require a source directory')

  const opaqueLabels = options?.opaqueLabels === true
  const handles = new Set<string>()
  const personas = briefing.personas.map((p, index) => {
    let handle = safeHandle(p.id)
    for (let n = 2; handles.has(handle); n += 1) handle = `${safeHandle(p.id)}-${n}`
    handles.add(handle)
    return {
      handle,
      roleLabel: opaqueLabels ? `Account ${index + 1}` : `${p.role} (${p.tenant})`,
      tenantRef: p.tenant.trim() || null,
      privilege: normalizeRole(p.role),
      email: p.email,
      password: p.password,
      canaryMarkers: [] as string[],
    }
  })
  if (briefing.mode === 'black-box' && personas.length > 2) {
    fail('black-box briefings may expose at most persona_a and persona_b')
  }

  const mission = [
    `Defensive verification of the authorized local-lab target ${briefing.origin} (${briefing.app}).`,
    'Map the reachable surface, form hypotheses from observed behaviour, and submit only findings whose impact',
    'is proven by deterministic replay verification. Do not fabricate findings and do not leave the approved origin.',
  ].join(' ')

  return {
    briefing,
    loginPath,
    openApi: briefing.apiReference ? briefingToOpenApi(briefing) : null,
    personas,
    // This harness only runs local labs (assertLocalLabAllowed). Tier 3 is required for the
    // state-changing probes (PATCH/PUT/DELETE, race, benign RCE proofs); local-lab approvals are
    // auto-reviewed, while public-target Tier-3 HITL rules remain untouched.
    capabilityTier: 3,
    mission,
  }
}

// ---------------------------------------------------------------------------------------------
// Finding translation
// ---------------------------------------------------------------------------------------------

export interface ReplaySpecLike {
  id: string
  findingId: string
  spec: unknown
  createdAt: number
  verifiedInline?: boolean
  lastVerificationDiff?: { verdict?: string } | null
  proofReceipt?: unknown
}

export interface EndpointLike {
  id: string
  method: string
  pathTemplate: string
}

export interface EndpointParamLike {
  endpointId: string
  name: string
}

export interface ExchangeLike {
  id: string
  method: string
  pathAndQuery: string
}

export interface TranslateInput {
  findings: Finding[]
  replaySpecs: ReplaySpecLike[]
  endpoints?: EndpointLike[]
  endpointParams?: EndpointParamLike[]
  exchanges?: ExchangeLike[]
  spentUsd?: number
  now?: number
  secrets?: readonly NamedSecret[]
}

// ---------------------------------------------------------------------------
// False-positive proof capture (durable, redacted)
// ---------------------------------------------------------------------------

export interface FalsePositiveExchangeSummary {
  stepId: string
  method: string
  status: number | null
  rejectedBy: string | null
}

export interface FalsePositiveProofSummary {
  findingId: string
  vulnClass: string
  cwe: string | null
  category: string | null
  route: { method: string; pathTemplate: string }
  verificationClass: string
  provenance: string
  oracleRulePassed: boolean
  claimedDeltaSummary: string
  exchangeSummaries: FalsePositiveExchangeSummary[]
}

interface FalsePositiveFindingLike {
  id: string
  category?: string | null
  cwe?: string | null
  title?: string | null
  reason?: string | null
  exchangeIds?: readonly string[] | null
  verificationStatus?: string | null
  provenance?: string | null
}

interface FalsePositiveSpecLike {
  findingId: string
  spec: unknown
  lastVerificationDiff?: {
    verdict?: string
    failedStepId?: string
    jqError?: string
    stepStatuses?: ReadonlyArray<{ id: string; role?: string; status: number | null }>
    assertionSummary?: { observed?: string; expected?: string; reason?: string }
  } | null
}

interface FalsePositiveExchangeLike {
  id: string
  method: string
  pathAndQuery: string
  status: number
}

function specStepsWithIds(spec: unknown, out: Array<{ stepId: string; method: string; path: string }> = []): Array<{ stepId: string; method: string; path: string }> {
  const seen = new Set<unknown>()
  const visit = (value: unknown, depth: number) => {
    if (out.length >= 24 || depth > 9 || !value || typeof value !== 'object' || seen.has(value)) return
    seen.add(value)
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1)
      return
    }
    const rec = value as Record<string, unknown>
    const request = rec.request && typeof rec.request === 'object' && !Array.isArray(rec.request)
      ? rec.request as Record<string, unknown>
      : rec
    const path = typeof request.pathAndQuery === 'string' ? request.pathAndQuery
      : typeof request.path === 'string' ? request.path : null
    const method = typeof request.method === 'string' ? request.method : null
    if (path && method) {
      const stepId = typeof rec.id === 'string' ? rec.id : `step-${out.length + 1}`
      out.push({ stepId, method: method.toUpperCase(), path: path.split(/[?#]/, 1)[0] ?? '/' })
    }
    for (const child of Object.values(rec)) if (child !== request) visit(child, depth + 1)
  }
  visit(spec, 0)
  return out
}

/**
 * Build a redacted, structured proof summary for every unmatched/misclassified finding, so an FP
 * can still be autopsied after the temp data dir is removed. Never includes bodies, headers,
 * tokens, or free-form probe strings — only ids, route templates, statuses and oracle codes.
 */
export function buildFalsePositiveEvidence(
  input: {
    findingIds: readonly string[]
    findings: readonly FalsePositiveFindingLike[]
    replaySpecs: readonly FalsePositiveSpecLike[]
    exchanges?: readonly FalsePositiveExchangeLike[]
  },
  secrets: readonly NamedSecret[] = [],
): FalsePositiveProofSummary[] {
  const wanted = [...new Set(input.findingIds.filter(id => typeof id === 'string' && id.length > 0))]
  const out: FalsePositiveProofSummary[] = []
  const exchangeById = new Map((input.exchanges ?? []).map(ex => [ex.id, ex]))
  for (const findingId of wanted) {
    const finding = input.findings.find(row => row.id === findingId)
    if (!finding) continue
    // A finding may carry several specs (failed repair attempts plus the confirming anchor). The
    // proof that backed a confirmed claim is the confirming one; prefer it so the autopsy never
    // attributes an inconclusive retry to a finding whose oracle actually passed.
    const spec = input.replaySpecs.find(row => row.findingId === findingId && row.lastVerificationDiff?.verdict === 'confirmed')
      ?? input.replaySpecs.find(row => row.findingId === findingId)
    const diff = spec?.lastVerificationDiff ?? null
    const steps = spec ? specStepsWithIds(spec.spec) : []
    const findingExchanges = (finding.exchangeIds ?? [])
      .map(id => exchangeById.get(id))
      .filter((ex): ex is FalsePositiveExchangeLike => Boolean(ex))
    const primary = steps[0] ?? (findingExchanges[0]
      ? { stepId: 'exchange-1', method: findingExchanges[0].method, path: findingExchanges[0].pathAndQuery.split(/[?#]/, 1)[0] ?? '/' }
      : null)
    const statusById = new Map((diff?.stepStatuses ?? []).map(step => [step.id, step.status]))
    const rejectedBy = diff?.failedStepId
      ? redact(diff.jqError ?? diff.assertionSummary?.reason ?? 'oracle_rejected', secrets).slice(0, 160)
      : null
    const exchangeSummaries: FalsePositiveExchangeSummary[] = steps.length
      ? steps.map(step => ({
          stepId: step.stepId,
          method: step.method,
          status: statusById.get(step.stepId) ?? null,
          rejectedBy: diff?.failedStepId === step.stepId ? rejectedBy : null,
        }))
      : findingExchanges.slice(0, 8).map((ex, index) => ({
          stepId: `exchange-${index + 1}`,
          method: ex.method.toUpperCase(),
          status: ex.status,
          rejectedBy: index === 0 ? rejectedBy : null,
        }))
    const assertion = diff?.assertionSummary
    const delta = assertion
      ? [assertion.observed, assertion.expected, assertion.reason].filter(Boolean).join(' | ')
      : (finding.reason ?? finding.title ?? '')
    out.push({
      findingId,
      vulnClass: finding.category ?? 'unknown',
      cwe: finding.cwe ?? null,
      category: spec ? (typeof (spec.spec as { category?: unknown })?.category === 'string' ? (spec.spec as { category: string }).category : null) : null,
      route: primary
        ? { method: primary.method.toUpperCase(), pathTemplate: normalizeEndpointTemplate(primary.path) }
        : { method: '*', pathTemplate: '/unknown' },
      verificationClass: finding.verificationStatus ?? 'runtime_confirmed',
      provenance: finding.provenance ?? 'unknown',
      oracleRulePassed: diff?.verdict === 'confirmed',
      claimedDeltaSummary: redact(String(delta ?? ''), secrets).replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 240),
      exchangeSummaries,
    })
  }
  return out
}

/** Attach the evidence block only when non-empty, so a 0-FP artifact stays byte-identical. */
export function withFalsePositiveEvidence<T extends Record<string, unknown>>(
  artifact: T,
  evidence: readonly FalsePositiveProofSummary[],
): T | (T & { falsePositiveEvidence: FalsePositiveProofSummary[] }) {
  return evidence.length ? { ...artifact, falsePositiveEvidence: [...evidence] } : artifact
}

/** Stamp scorecard reportability: any run with conventional wordlist ON is non-reportable. */
export function withScorecardReportability<T extends Record<string, unknown>>(
  artifact: T,
  conventionalWordlist: boolean,
): T & { wordlistOn: boolean; reportable: boolean } {
  const wordlistOn = Boolean(conventionalWordlist)
  return { ...artifact, wordlistOn, reportable: !wordlistOn }
}

/** Stamp benchmarkVersion & effectiveConfigHash onto a scorecard or summary artifact. */
export function withScorecardVersion<T extends Record<string, unknown>>(
  artifact: T,
  stamp: { benchmarkVersion: string; effectiveConfigHash: string },
): T & { benchmarkVersion: string; effectiveConfigHash: string } {
  return {
    ...artifact,
    benchmarkVersion: stamp.benchmarkVersion,
    effectiveConfigHash: stamp.effectiveConfigHash,
  }
}

interface ExtractedEndpoint { method?: string; path: string }

function pathOf(value: unknown): string | null {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : null
}

/** Recursively collect concrete probe/control paths from any DeclarativeReplaySpec shape. */
export function endpointsFromReplaySpec(spec: unknown): ExtractedEndpoint[] {
  const out: ExtractedEndpoint[] = []
  const seen = new Set<string>()
  const add = (path: string | null, method?: unknown) => {
    if (!path) return
    const m = typeof method === 'string' ? method.toUpperCase() : undefined
    const key = `${m ?? '*'}:${path}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ ...(m ? { method: m } : {}), path })
  }
  const visit = (node: unknown, depth: number): void => {
    if (!node || typeof node !== 'object' || depth > 8) return
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1)
      return
    }
    const rec = node as Record<string, unknown>
    const method = rec.method ?? (rec.request && typeof rec.request === 'object'
      ? (rec.request as Record<string, unknown>).method : undefined)
    for (const key of ['pathAndQuery', 'controlPath', 'probePath', 'verifyPath', 'path']) {
      add(pathOf(rec[key]) ? String(rec[key]) : null, method)
    }
    for (const [key, value] of Object.entries(rec)) {
      if (key === 'request' || typeof value === 'object') visit(value, depth + 1)
    }
  }
  visit(spec, 0)
  return out
}

const CANONICAL_VULN_CLASSES = new Set([
  'idor', 'bola', 'bfla', 'graphql_bola', 'mass_assignment', 'auth_bypass', 'jwt', 'oauth',
  'csrf', 'sqli', 'ssti', 'ssrf', 'xxe', 'xss_stored', 'xss_reflected', 'path_traversal',
  'command_injection', 'cache_poisoning', 'cache_deception', 'race_condition', 'business_logic',
  'workflow_bypass', 'open_redirect', 'webhook_forgery', 'info_disclosure', 'rate_limit_bypass',
])

const PROBE_CLASS_TO_VULN_CLASS: Record<string, string> = {
  sqli_boolean: 'sqli',
  sqli_time_diff: 'sqli',
  sql_boolean_diff: 'sqli',
  sql_time_diff: 'sqli',
  sql_injection: 'sqli',
  authz_matrix: 'bola',
  authorization: 'bola',
  access_boundary: 'bola',
  cross_tenant_read: 'bola',
  cross_tenant_write: 'bola',
  dual_tenant_abac: 'bola',
  privilege_escalation: 'bfla',
  ssti_math: 'ssti',
  template_injection: 'ssti',
  ssrf_canary: 'ssrf',
  ssrf_oob: 'ssrf',
  xxe_canary: 'xxe',
  xxe_oob: 'xxe',
  xss_context: 'xss_reflected',
  dom_xss: 'xss_reflected',
  browser_dom: 'xss_reflected',
  xss: 'xss_reflected',
  path_traversal_benign: 'path_traversal',
  directory_traversal: 'path_traversal',
  lfi: 'path_traversal',
  path_escape: 'path_traversal',
  cache_poison_deception: 'cache_poisoning',
  cache_differential: 'cache_poisoning',
  cache_poison: 'cache_poisoning',
  race_burst: 'race_condition',
  race_double_spend: 'race_condition',
  race: 'race_condition',
  workflow_invariant: 'business_logic',
  workflow_skip: 'workflow_bypass',
  price_tampering: 'business_logic',
  invariant_violation: 'business_logic',
  conserved_balance: 'business_logic',
  auth_protocol_audit: 'jwt',
  token_forgery: 'jwt',
  graphql_audit: 'graphql_bola',
  graphql_authz: 'graphql_bola',
  rce_proof: 'command_injection',
  rce: 'command_injection',
  os_command: 'command_injection',
  secret_disclosed: 'info_disclosure',
  disclosure: 'info_disclosure',
  redirect: 'open_redirect',
  csrf_state_change: 'csrf',
}

/** Map a verifier/spec probe class or receipt class to a realistic-bench `vulnClass` key. */
export function probeClassToVulnClass(raw: string | null | undefined): string | undefined {
  if (typeof raw !== 'string') return undefined
  const key = raw.trim().toLowerCase()
  if (!key || key === 'unknown') return undefined
  if (CANONICAL_VULN_CLASSES.has(key)) return key
  return PROBE_CLASS_TO_VULN_CLASS[key]
}

/** Derive the canonical `vulnClass` from the verifying spec's probe class / recipe / receipt. */
export function vulnClassFromSpec(spec: unknown, proofReceipt?: unknown): string | undefined {
  const rec = spec && typeof spec === 'object' && !Array.isArray(spec)
    ? spec as Record<string, unknown>
    : null
  const receiptObj = proofReceipt && typeof proofReceipt === 'object' && !Array.isArray(proofReceipt)
    ? proofReceipt as Record<string, unknown>
    : null
  const receiptInner = receiptObj?.receipt && typeof receiptObj.receipt === 'object' && !Array.isArray(receiptObj.receipt)
    ? receiptObj.receipt as Record<string, unknown>
    : null
  const receiptVer = receiptObj?.verification && typeof receiptObj.verification === 'object' && !Array.isArray(receiptObj.verification)
    ? receiptObj.verification as Record<string, unknown>
    : null
  const agentScript = rec?.agentScript && typeof rec.agentScript === 'object' && !Array.isArray(rec.agentScript)
    ? rec.agentScript as Record<string, unknown>
    : null
  const recipe = rec?.recipe && typeof rec.recipe === 'object' && !Array.isArray(rec.recipe)
    ? rec.recipe as Record<string, unknown>
    : null
  const recipeArgs = recipe?.args && typeof recipe.args === 'object' && !Array.isArray(recipe.args)
    ? recipe.args as Record<string, unknown>
    : null

  const explicitCandidates = [
    rec?.probeClass,
    rec?.vulnClass,
    agentScript?.vulnClass,
    recipeArgs?.vulnClass,
    recipeArgs?.probeClass,
    receiptInner?.vulnClass,
    receiptVer?.vulnClass,
    receiptInner?.terminalVulnClass,
    receiptVer?.terminalVulnClass,
  ]
  for (const candidate of explicitCandidates) {
    if (typeof candidate === 'string') {
      const mapped = probeClassToVulnClass(candidate)
      if (mapped) return mapped
    }
  }

  const kind = typeof rec?.kind === 'string' ? rec.kind : ''
  if (kind === 'sql_boolean_diff' || kind === 'sql_time_diff') return 'sqli'
  if (kind === 'cache_differential') return rec?.mode === 'deception' ? 'cache_deception' : 'cache_poisoning'
  if (kind === 'browser_chain' || kind === 'browser_dom') return 'xss_reflected'
  if (kind === 'auth_protocol_proof') {
    const protocol = typeof rec?.protocol === 'string' ? rec.protocol : 'jwt'
    return protocol === 'oauth' || protocol === 'oidc' ? 'oauth' : 'jwt'
  }
  if (kind === 'race_burst') return 'race_condition'
  if (kind === 'rce_proof') return 'command_injection'

  const recipeId = typeof recipe?.recipeId === 'string' ? recipe.recipeId : ''
  if (recipeId) {
    const mapped = probeClassToVulnClass(recipeId)
    if (mapped) return mapped
    if (recipeId === 'boolean_or_timing') return 'sqli'
    if (recipeId === 'browser_sink') return 'xss_reflected'
  }
  return undefined
}

const VALID_PARAM_NAME = /^[A-Za-z0-9_.\-[\]]{1,128}$/

function queryParamMap(pathAndQuery: unknown): Map<string, string> {
  const out = new Map<string, string>()
  if (typeof pathAndQuery !== 'string') return out
  const qIndex = pathAndQuery.indexOf('?')
  if (qIndex < 0) return out
  try {
    const params = new URLSearchParams(pathAndQuery.slice(qIndex + 1).split('#', 1)[0])
    for (const [k, v] of params.entries()) {
      if (k === '_gcb') continue
      out.set(k, v)
    }
  } catch { /* ignore malformed query */ }
  return out
}

function bodyFieldMap(request: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>()
  for (const key of ['jsonBody', 'formFields', 'variables', 'params']) {
    const value = request[key]
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out.set(k, JSON.stringify(v))
      }
    }
  }
  return out
}

function requestOfStep(step: unknown): Record<string, unknown> | null {
  if (!step || typeof step !== 'object' || Array.isArray(step)) return null
  const rec = step as Record<string, unknown>
  if (rec.request && typeof rec.request === 'object' && !Array.isArray(rec.request)) {
    return rec.request as Record<string, unknown>
  }
  return rec
}

/** Extract ONLY the mutated parameter names carried by a replay spec (never endpoint inventory). */
export function specMutatedParams(spec: unknown): string[] {
  const names = new Set<string>()
  const add = (value: unknown) => {
    if (typeof value === 'string' && VALID_PARAM_NAME.test(value)) names.add(value)
  }
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return []
  const rec = spec as Record<string, unknown>

  // 1. Explicit mutated-input declarations take precedence (never widen to unrelated body fields).
  add(rec.paramName)
  if (Array.isArray(rec.mutatedParams)) {
    for (const item of rec.mutatedParams) add(item)
  }
  const recipe = rec.recipe && typeof rec.recipe === 'object' && !Array.isArray(rec.recipe)
    ? rec.recipe as Record<string, unknown>
    : null
  const recipeArgs = recipe?.args && typeof recipe.args === 'object' && !Array.isArray(recipe.args)
    ? recipe.args as Record<string, unknown>
    : null
  if (recipeArgs) {
    for (const key of ['paramName', 'param', 'fieldName', 'field']) add(recipeArgs[key])
    if (Array.isArray(recipeArgs.mutatedParams)) {
      for (const item of recipeArgs.mutatedParams) add(item)
    }
  }
  const uploadStep = rec.uploadStep && typeof rec.uploadStep === 'object' && !Array.isArray(rec.uploadStep)
    ? rec.uploadStep as Record<string, unknown>
    : null
  if (uploadStep) add(uploadStep.fieldName)
  if (names.size > 0) return [...names].slice(0, 24)

  // 2. Step-based specs: collect query/body params introduced or mutated in probe steps vs control.
  const controlReqs: Record<string, unknown>[] = []
  const probeReqs: Record<string, unknown>[] = []
  if (Array.isArray(rec.steps)) {
    for (const step of rec.steps) {
      if (!step || typeof step !== 'object' || Array.isArray(step)) continue
      const role = (step as Record<string, unknown>).role
      const req = requestOfStep(step)
      if (!req) continue
      if (role === 'control') controlReqs.push(req)
      else if (role === 'probe') probeReqs.push(req)
    }
  }
  const ctrlStepReq = requestOfStep(rec.controlStep)
  if (ctrlStepReq) controlReqs.push(ctrlStepReq)
  const probeStepReq = requestOfStep(rec.probeStep)
  if (probeStepReq) probeReqs.push(probeStepReq)
  if (Array.isArray(rec.burst)) {
    for (const item of rec.burst) {
      const req = requestOfStep(item)
      if (req) probeReqs.push(req)
    }
  }

  if (probeReqs.length > 0) {
    const controlQuery = new Map<string, Set<string>>()
    const controlBody = new Map<string, Set<string>>()
    for (const req of controlReqs) {
      for (const [k, v] of queryParamMap(req.pathAndQuery ?? req.path)) {
        const set = controlQuery.get(k) ?? new Set<string>()
        set.add(v)
        controlQuery.set(k, set)
      }
      for (const [k, v] of bodyFieldMap(req)) {
        const set = controlBody.get(k) ?? new Set<string>()
        set.add(v)
        controlBody.set(k, set)
      }
    }
    for (const req of probeReqs) {
      for (const [k, v] of queryParamMap(req.pathAndQuery ?? req.path)) {
        const baseline = controlQuery.get(k)
        if (!baseline || !baseline.has(v)) add(k)
      }
      for (const [k, v] of bodyFieldMap(req)) {
        const baseline = controlBody.get(k)
        if (!baseline || !baseline.has(v)) add(k)
      }
    }
    return [...names].slice(0, 24)
  }

  // 3. Flat spec without steps: query/body keys on the spec itself.
  for (const key of ['probePath', 'pathAndQuery', 'path']) {
    for (const k of queryParamMap(rec[key]).keys()) add(k)
  }
  for (const k of bodyFieldMap(rec).keys()) add(k)
  return [...names].slice(0, 24)
}

/**
 * Translate persisted Kovo Hunter findings into the benchmark grader schema.
 * Confirmed -> runtime_confirmed, static_verified -> static_verified; pending /
 * inconclusive claims are preserved as proposed/open_proof_gap so the precision
 * denominator reflects what was actually submitted. Dismissed and superseded
 * rows are dropped (the grader treats those as ruled_out).
 *
 * Fail-closed invariants:
 *  - `vulnClass` comes from the verifying spec's probe class (never wildcard-matched).
 *  - `params` come ONLY from the verifying spec's mutated inputs (never widened to endpoint inventory).
 *  - Findings with neither a CWE nor a class are stamped `vulnClass: 'unmatched_classless'`.
 */
export function translateFindings(input: TranslateInput): SubmittedFinding[] {
  const now = input.now ?? Date.now()
  const spent = input.spentUsd ?? 0
  const specsByFinding = new Map<string, ReplaySpecLike[]>()
  for (const spec of input.replaySpecs) {
    const list = specsByFinding.get(spec.findingId) ?? []
    list.push(spec)
    specsByFinding.set(spec.findingId, list)
  }
  for (const list of specsByFinding.values()) list.sort((a, b) => b.createdAt - a.createdAt)
  const exchangeById = new Map((input.exchanges ?? []).map(ex => [ex.id, ex]))

  const out: SubmittedFinding[] = []
  for (const finding of input.findings) {
    // Baseline hygiene checks (HSTS/CSP/XFO/...) are not vulnerability claims and have no
    // realistic-bench ground-truth counterpart; submitting them would be pure FP noise.
    if (finding.findingKind === 'baseline_check') continue
    if (finding.status === 'dismissed') continue
    if (finding.supersededByFindingId) continue
    const specs = specsByFinding.get(finding.id) ?? []
    const verifyingSpec = specs.find(s => s.lastVerificationDiff?.verdict === 'confirmed')
      ?? specs.find(s => s.verifiedInline)
      ?? specs[0]
    const endpoints: ExtractedEndpoint[] = []
    const params = new Set<string>()
    for (const spec of specs.slice(0, 3)) {
      for (const ep of endpointsFromReplaySpec(spec.spec)) endpoints.push(ep)
    }
    if (verifyingSpec) {
      for (const name of specMutatedParams(verifyingSpec.spec)) params.add(name)
    }
    // Fallback: exchanges persisted with the finding (when no replay spec survived).
    if (!endpoints.length) {
      for (const id of finding.exchangeIds ?? []) {
        const ex = exchangeById.get(id)
        if (ex) endpoints.push({ method: ex.method.toUpperCase(), path: ex.pathAndQuery })
      }
    }
    const unique = new Map<string, ExtractedEndpoint>()
    for (const ep of endpoints) unique.set(`${ep.method ?? '*'}:${ep.path}`, ep)
    const clean = [...unique.values()]

    const specVulnClass = verifyingSpec
      ? vulnClassFromSpec(verifyingSpec.spec, verifyingSpec.proofReceipt)
      : undefined
    const findingClass = probeClassToVulnClass(finding.category)
    const resolvedVulnClass = specVulnClass ?? findingClass
    const cwe = finding.cwe?.trim() || undefined
    const vulnClass = resolvedVulnClass ?? (cwe ? undefined : 'unmatched_classless')

    const status: SubmittedFinding['status'] = finding.status === 'confirmed'
      ? 'runtime_confirmed'
      : finding.status === 'static_verified'
        ? 'static_verified'
        : finding.status === 'pending'
          ? 'proposed'
          : 'open_proof_gap'

    const submittedAtMs = verifyingSpec?.createdAt ?? specs[0]?.createdAt ?? now
    const severity = finding.severity === 'informational' ? 'low' : finding.severity
    out.push({
      id: finding.id,
      title: redact(finding.title, input.secrets ?? []).slice(0, 200),
      ...(cwe ? { cwe } : {}),
      ...(vulnClass ? { vulnClass } : {}),
      severity,
      endpoints: clean,
      ...(params.size ? { params: [...params] } : {}),
      status,
      submittedAtMs,
      costUsdAtSubmit: spent,
      ...(finding.codeLocations?.length
        ? { codeLocations: finding.codeLocations.map(c => ({ ...c })) }
        : {}),
    })
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------------------------

export function buildTelemetry(input: {
  runStartedAt: number
  runEndedAt: number
  spentUsd: number
  budgetUsd: number
  budgetExhausted: boolean
}): RunTelemetry {
  // Kovo Hunter does not persist a chain-step -> concrete path mapping, so the harness
  // deliberately reports no synthesized hypotheses rather than guessing paths. The
  // grader still derives hypothesis formation from the recorded request log.
  return {
    startedAtMs: input.runStartedAt,
    endedAtMs: input.runEndedAt,
    totalCostUsd: input.spentUsd,
    budgetUsd: input.budgetUsd,
    budgetExhausted: input.budgetExhausted,
    hypotheses: [],
    tierBlocked: [],
  }
}

// ---------------------------------------------------------------------------------------------
// Cell execution
// ---------------------------------------------------------------------------------------------

export interface ModelInfo {
  mode: 'agentic' | 'deterministic-no-llm'
  profiles: Array<{ name: string; model: string; protocol: string }>
}

export function describeModelMode(profiles: ResolvedModelProfile[]): ModelInfo {
  return {
    mode: profiles.length ? 'agentic' : 'deterministic-no-llm',
    profiles: profiles.map(p => ({ name: p.name, model: p.model, protocol: p.protocol })),
  }
}

// ---------------------------------------------------------------------------------------------
// Backend capability + agentic preflight
// ---------------------------------------------------------------------------------------------

/** A configuration error that must terminate the harness with exit code 2. */
export class PreflightError extends Error {
  readonly exitCode = 2
  constructor(message: string) {
    super(message)
    this.name = 'PreflightError'
  }
}

export interface WorkerSessionCapability {
  supported: boolean
  detail: string
}

/**
 * Prove worker-session support by actually opening (and closing) a session. This is
 * deliberately not a name check: LocalJqBackend throws, and Docker fails here when the
 * daemon/socket/image is unavailable.
 */
export async function detectWorkerSessions(
  backend: Pick<WorkerBackend, 'openSession'>,
  timeoutMs = 20_000,
): Promise<WorkerSessionCapability> {
  let session: Awaited<ReturnType<WorkerBackend['openSession']>> | undefined
  try {
    session = await backend.openSession(randomUUID(), AbortSignal.timeout(timeoutMs))
    return { supported: true, detail: 'worker session opened and closed' }
  } catch (error) {
    const detail = redact(error instanceof Error ? error.message : String(error)).slice(0, 240)
    return { supported: false, detail: detail || 'worker session could not be opened' }
  } finally {
    if (session) await session.close().catch(() => undefined)
  }
}

export interface AgenticPreflightInput {
  hasProfiles: boolean
  noLlm: boolean
  allowInertWorkers: boolean
  backendKind: VerifierBackendKind
  workerSessions: boolean
  workerSessionsDetail?: string
  profileEndpoints?: readonly string[]
  localModelEnabled?: boolean
}

function findBlockedLoopbackModelOrigin(endpoints: readonly string[] | undefined): string | null {
  if (!endpoints?.length) return null
  for (const raw of endpoints) {
    try {
      const url = new URL(raw)
      const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
      if (url.protocol === 'http:' && (host === '127.0.0.1' || host === 'localhost' || host === '::1')) {
        return url.origin
      }
    } catch {
      // Invalid URLs are rejected by profile schema validation.
    }
  }
  return null
}

/**
 * Fail fast instead of producing an inert run: a model profile will send work to
 * specialist workers, and only a worker-session-capable backend (docker) can run them.
 * Loopback HTTP model profiles (such as the matrix ModelGate) also require
 * `KOVO_ALLOW_LOCAL_MODEL=1` or `EgressGateway` will reject every turn before egress.
 */
export function assertAgenticPreflight(input: AgenticPreflightInput): void {
  if (!input.hasProfiles || input.noLlm || input.allowInertWorkers) return
  const blockedLoopback = findBlockedLoopbackModelOrigin(input.profileEndpoints)
  if (blockedLoopback && !(input.localModelEnabled ?? isLocalModelEnvEnabled())) {
    throw new PreflightError(
      `agentic model profile points to loopback HTTP endpoint (${blockedLoopback}) without KOVO_ALLOW_LOCAL_MODEL=1; `
      + 'EgressGateway will block all model requests (peak=0). Set KOVO_ALLOW_LOCAL_MODEL=1 for loopback ModelGate/fixtures '
      + 'or pass --no-model-gate to dial HTTPS provider endpoints directly.',
    )
  }
  if (input.workerSessions) return
  const detail = input.workerSessionsDetail ? ` (${input.workerSessionsDetail})` : ''
  if (input.backendKind === 'docker') {
    throw new PreflightError(
      `agentic Execution requires a worker-session-capable verifier backend; --verifier docker could not open a worker session${detail}. `
      + 'Docker worker sessions need socket access: re-run under `newgrp docker -c \'<command>\'` and verify '
      + '`docker images` contains kovo-worker:v4.',
    )
  }
  throw new PreflightError(
    'agentic Execution requires a worker-session-capable verifier backend (docker); '
    + 'use --verifier docker or --no-llm'
    + (input.allowInertWorkers ? '' : ' (or --allow-inert-workers to explicitly record an inert run)')
    + ` — ${input.backendKind} cannot run worker sessions${detail}.`,
  )
}

export interface AssignmentDiagnosticInput {
  status: string
  outcome?: string | null
  title?: string
  phase?: string
}

export interface AssignmentDiagnostics {
  total: number
  completed: number
  failed: number
  canceled: number
  investigationTotal: number
  investigationCompleted: number
  investigationFailed: number
  topFailureReasons: string[]
}

/**
 * Corrected det_lead funnel. `floorLeadsConsumed` used to increment when a lead was *queued*, so
 * "emitted > 0 => consumed > 0" could pass with zero investigation. `investigated` counts leads
 * whose bound upgrade step reached a completed assignment (a verdict); `dispatched` additionally
 * counts leads whose step reached any assignment, and `queued` preserves the queue-time count.
 */
export interface LeadFunnelMetrics {
  emitted: number
  queued: number
  dispatched: number
  investigated: number
  source: 'events'
}

export function summarizeLeadFunnel(input: {
  events: ReadonlyArray<{ kind: string; detail?: Record<string, unknown> | null }>
  assignments: ReadonlyArray<{ stepId?: string | null; status: string }>
  /** Chain steps, used to follow a lead fact into a re-queued/multi-trial upgrade step. */
  steps?: ReadonlyArray<{ id: string; title?: string | null; dependsOnFactIds?: readonly string[] | null }>
}): LeadFunnelMetrics {
  let emitted = 0
  const queued = new Map<string, { factId: string | null; stepId: string | null }>()
  for (const event of input.events) {
    if (event.kind === 'deterministic_engine.lead') {
      emitted += 1
      continue
    }
    if (event.kind !== 'deterministic_lane.lead_consumed') continue
    const detail = event.detail ?? {}
    const factId = typeof detail.factId === 'string' ? detail.factId : null
    const stepId = typeof detail.stepId === 'string' ? detail.stepId : null
    const key = factId ?? stepId
    if (key) queued.set(key, { factId, stepId })
  }
  // A lead may be re-bound to a multi-trial (`[trial 2]`) upgrade step instead of the step that
  // was queued, so follow the fact into det_lead upgrade steps only (never broad planner steps,
  // which would count an unrelated verdict as lead investigation).
  const upgradeStepsByFact = new Map<string, string[]>()
  for (const step of input.steps ?? []) {
    if (!step.title?.startsWith('det_lead upgrade')) continue
    for (const factId of step.dependsOnFactIds ?? []) {
      const list = upgradeStepsByFact.get(factId) ?? []
      list.push(step.id)
      upgradeStepsByFact.set(factId, list)
    }
  }
  const statusesByStep = new Map<string, string[]>()
  for (const assignment of input.assignments) {
    if (!assignment.stepId) continue
    const statuses = statusesByStep.get(assignment.stepId) ?? []
    statuses.push(assignment.status)
    statusesByStep.set(assignment.stepId, statuses)
  }
  let dispatched = 0
  let investigated = 0
  for (const entry of queued.values()) {
    const candidateSteps = new Set<string>()
    if (entry.stepId) candidateSteps.add(entry.stepId)
    if (entry.factId) for (const stepId of upgradeStepsByFact.get(entry.factId) ?? []) candidateSteps.add(stepId)
    if (!candidateSteps.size) continue
    const statuses = [...candidateSteps].flatMap(stepId => statusesByStep.get(stepId) ?? [])
    if (!statuses.length) continue
    dispatched += 1
    // A verdict requires the assignment to close normally; killed/canceled/failed work did not
    // investigate the lead to an outcome (partial closure is reported separately by the engine).
    if (statuses.includes('complete')) investigated += 1
  }
  return { emitted, queued: queued.size, dispatched, investigated, source: 'events' }
}

/**
 * Split request-budget telemetry ingested from the run's own phase events. Meta is written before
 * `engine.stop()` finalizes the run, so it must not rely on the final `deterministic_floor.summary`
 * alone: `request_budget.floor_settled` / `request_budget.phase_ended` / `request_budget.agent_exhausted`
 * are emitted exactly at the phase boundaries and are the authoritative source here.
 */
export interface RequestBudgetMeta {
  mode: 'split' | 'single'
  floorRequestBudget: number | null
  agentRequestBudget: number | null
  totalRequestBudget: number | null
  floorRequests: number | null
  agentRequests: number | null
  totalRequests: number
  floorBudgetExhausted: boolean
  agentBudgetExhausted: boolean
  /** Honest phase termination: `agent_budget_exhausted` when ready steps were left unfunded. */
  terminationReason: string | null
}

export function summarizeRequestBudgets(input: {
  events: ReadonlyArray<{ kind: string; detail?: Record<string, unknown> | null }>
  spentRequests: number
  floorRequestBudget?: number | null
  agentRequestBudget?: number | null
  totalRequestBudget?: number | null
}): RequestBudgetMeta {
  const num = (value: unknown): number | null =>
    typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
  let floorRequests: number | null = null
  let floorExhausted = false
  let agentRequests: number | null = null
  let spentAtFloorSettle: number | null = null
  let agentExhausted = false
  let terminationReason: string | null = null
  let engineReportedFloor = 0
  let sawEngineSummary = false
  for (const event of input.events) {
    const detail = event.detail ?? {}
    if (event.kind === 'deterministic_engine.summary') {
      const used = num(detail.requestsUsed)
      if (used !== null) {
        engineReportedFloor += used
        sawEngineSummary = true
      }
    } else if (event.kind === 'request_budget.floor_settled') {
      floorRequests = num(detail.floorRequests)
      spentAtFloorSettle = num(detail.spentRequestsAtSettle)
      if (detail.floorBudgetExhausted === true) floorExhausted = true
    } else if (event.kind === 'request_budget.floor_exhausted') {
      floorExhausted = true
    } else if (event.kind === 'request_budget.phase_ended') {
      const used = num(detail.agentRequests)
      if (used !== null) agentRequests = used
      if (detail.agentBudgetExhausted === true) agentExhausted = true
      if (typeof detail.terminationReason === 'string') terminationReason = detail.terminationReason
    } else if (event.kind === 'request_budget.agent_exhausted') {
      agentExhausted = true
      if (typeof detail.reason === 'string') terminationReason = detail.reason
      const used = num(detail.agentRequests)
      if (used !== null) agentRequests = used
    }
  }
  if (floorRequests === null && sawEngineSummary) floorRequests = engineReportedFloor
  // A wall stop mid-Phase-B never reaches `request_budget.phase_ended`; the settle event still
  // gives an honest consumption delta (verification has not run yet).
  if (agentRequests === null && spentAtFloorSettle !== null) {
    agentRequests = Math.max(0, input.spentRequests - spentAtFloorSettle)
  }
  const split = input.floorRequestBudget != null || input.agentRequestBudget != null
  return {
    mode: split ? 'split' : 'single',
    floorRequestBudget: input.floorRequestBudget ?? null,
    agentRequestBudget: input.agentRequestBudget ?? null,
    totalRequestBudget: input.totalRequestBudget ?? null,
    floorRequests,
    agentRequests,
    totalRequests: input.spentRequests,
    floorBudgetExhausted: floorExhausted,
    agentBudgetExhausted: agentExhausted,
    terminationReason,
  }
}

/** An agentic run that never completed an investigation assignment is inert, not a result. */
export function isInertAgenticRun(input: {
  agentic: boolean
  submittedFindings: number
  facts: number
  investigationCompleted: number
}): boolean {
  return input.agentic
    && input.submittedFindings === 0
    && input.facts === 0
    && input.investigationCompleted === 0
}

/** Summarize assignment outcomes without leaking secrets or raw payload strings. */
export function summarizeAssignments(
  assignments: readonly AssignmentDiagnosticInput[],
  fallbackReasons: readonly string[] = [],
  secrets: readonly NamedSecret[] = [],
): AssignmentDiagnostics {
  let completed = 0
  let failed = 0
  let canceled = 0
  let investigationTotal = 0
  let investigationCompleted = 0
  let investigationFailed = 0
  const reasons = new Map<string, number>()
  const addReason = (raw: string | null | undefined) => {
    if (!raw) return
    const clean = redact(String(raw), secrets).replace(/\s+/g, ' ').trim().slice(0, 240)
    if (!clean) return
    reasons.set(clean, (reasons.get(clean) ?? 0) + 1)
  }
  for (const assignment of assignments) {
    const investigation = assignment.phase === 'investigation'
    if (investigation) investigationTotal += 1
    if (assignment.status === 'complete') {
      completed += 1
      if (investigation) investigationCompleted += 1
    } else if (assignment.status === 'failed') {
      failed += 1
      if (investigation) investigationFailed += 1
      addReason(assignment.outcome)
    } else if (assignment.status === 'canceled') {
      canceled += 1
      if (investigation) investigationFailed += 1
      addReason(assignment.outcome)
    }
  }
  if (failed + canceled > 0 && reasons.size === 0) {
    for (const reason of fallbackReasons) addReason(reason)
  }
  const topFailureReasons = [...reasons.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([reason]) => reason)
  return {
    total: assignments.length,
    completed,
    failed,
    canceled,
    investigationTotal,
    investigationCompleted,
    investigationFailed,
    topFailureReasons,
  }
}

/** Paginate every event for a run (a deep floor emits >3k rows; a single page truncates). */
function collectRunEvents(
  storage: Store,
  runId: string,
): Array<{ kind: string; detail?: Record<string, unknown> | null }> {
  const out: Array<{ kind: string; detail?: Record<string, unknown> | null }> = []
  let after = 0
  for (;;) {
    const page = storage.eventsAfter(runId, after, 1_000)
    if (!page.length) break
    for (const event of page) {
      out.push({
        kind: event.kind,
        detail: (event.detail ?? null) as Record<string, unknown> | null,
      })
    }
    after = page[page.length - 1]!.id
    if (page.length < 1_000) break
  }
  return out
}

function countTableRows(storage: Store, table: string): number {  try {
    const row = storage.client.prepare(`select count(*) as c from ${table}`).get() as { c?: number } | undefined
    return Number(row?.c ?? 0)
  } catch {
    return 0
  }
}

/** Open a cell Store; turn the source-data-dir lock into an actionable preflight error. */
export function openCellStore(directory: string): Store {
  try {
    return new Store(directory)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (/Another Kovo Hunter server is using this data directory/.test(message)) {
      throw new PreflightError(
        `${message} Parallel cells need isolated stores: add --isolate-data-dir `
        + '(it is on by default when --concurrency > 1) or use a distinct --data-dir per cell.',
      )
    }
    throw error
  }
}

/**
 * Effective in-run worker slots for this invocation. `--concurrency` (parallel cells) must never
 * leak into this: the benchmark used to pass cell concurrency into `runs.worker_concurrency`,
 * leaving an agentic cell with one slot for 20+ ready steps.
 */
export function runWorkerConcurrency(args: Pick<RealisticArgs, 'workerConcurrency' | 'noLlm'>): number {
  return resolveWorkerConcurrency(args.workerConcurrency, { noLlm: args.noLlm })
}

/** The two concurrency values recorded in cell meta, kept separate by construction. */
export function concurrencyMeta(
  args: Pick<RealisticArgs, 'concurrency' | 'workerConcurrency' | 'noLlm'>,
): { cellConcurrency: number; workerConcurrency: number } {
  return {
    cellConcurrency: Math.max(1, Math.trunc(args.concurrency)),
    workerConcurrency: runWorkerConcurrency(args),
  }
}

export interface IsolatedDataDirResult {
  directory: string
  source: string
  credentialsDir: string
  profileNames: string[]
}

let credentialsDirScopeCount = 0
let credentialsDirScopePrev: string | undefined
let credentialsDirScopeOwned = false

/**
 * Ref-counted helper that binds `KOVO_CREDENTIALS_DIR` to the real host credentials directory
 * while one or more isolated benchmark cells run concurrently in this process.
 * Respects any pre-existing explicit `KOVO_CREDENTIALS_DIR` set by the caller.
 */
export function acquireCredentialsDirEnv(credentialsDir: string): () => void {
  const resolved = resolve(credentialsDir)
  if (credentialsDirScopeCount === 0) {
    credentialsDirScopePrev = process.env.KOVO_CREDENTIALS_DIR
    if (!credentialsDirScopePrev?.trim()) {
      process.env.KOVO_CREDENTIALS_DIR = resolved
      credentialsDirScopeOwned = true
    } else {
      credentialsDirScopeOwned = false
    }
  } else if (credentialsDirScopeOwned) {
    process.env.KOVO_CREDENTIALS_DIR = resolved
  }
  credentialsDirScopeCount += 1
  let released = false
  return () => {
    if (released) return
    released = true
    credentialsDirScopeCount = Math.max(0, credentialsDirScopeCount - 1)
    if (credentialsDirScopeCount === 0) {
      if (credentialsDirScopeOwned) {
        if (credentialsDirScopePrev === undefined) delete process.env.KOVO_CREDENTIALS_DIR
        else process.env.KOVO_CREDENTIALS_DIR = credentialsDirScopePrev
      }
      credentialsDirScopePrev = undefined
      credentialsDirScopeOwned = false
    }
  }
}

/** Per-cell isolation is explicit, or implicit for a parallel matrix with a source data dir. */
export function shouldIsolateDataDir(args: Pick<RealisticArgs, 'isolateDataDir' | 'concurrency' | 'dataDir' | 'noLlm'>): boolean {
  return Boolean(!args.noLlm && args.dataDir && (args.isolateDataDir || args.concurrency > 1))
}

function assertValidSourceCredentialsDir(sourceCredentials: string, label: string): void {
  let dirInfo
  try {
    dirInfo = lstatSync(sourceCredentials)
  } catch {
    throw new PreflightError(`${label} has no credentials dir: ${sourceCredentials}`)
  }
  if (dirInfo.isSymbolicLink()) {
    throw new PreflightError(`${label} credentials dir must not be a symbolic link: ${sourceCredentials}`)
  }
  if (!dirInfo.isDirectory()) {
    throw new PreflightError(`${label} credentials path is not a directory: ${sourceCredentials}`)
  }
  const modeBits = dirInfo.mode & 0o7777
  if (modeBits !== 0o700 && modeBits !== 0o500) {
    throw new PreflightError(`${label} credentials dir must be owner-only (mode 0700 or 0500): ${sourceCredentials}`)
  }
}

function lstatIfPresent(path: string): ReturnType<typeof lstatSync> | null {
  try {
    return lstatSync(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return null
    throw error
  }
}

function assertValidCredentialFile(credentialPath: string, profileLabel: string, dirLabel?: string): void {
  let info
  try {
    info = lstatSync(credentialPath)
  } catch {
    throw new PreflightError(
      dirLabel
        ? `profile '${profileLabel}' has no readable credential file in ${dirLabel}`
        : `profile '${profileLabel}' has no readable credential file in the source data dir`,
    )
  }
  if (info.isSymbolicLink()) {
    throw new PreflightError(`profile '${profileLabel}' credential must not be a symbolic link`)
  }
  if (!info.isFile()) {
    throw new PreflightError(
      dirLabel
        ? `profile '${profileLabel}' has no readable credential file in ${dirLabel}`
        : `profile '${profileLabel}' has no readable credential file in the source data dir`,
    )
  }
  if ((info.mode & 0o077) !== 0) {
    throw new PreflightError(`profile '${profileLabel}' credential must be owner-only (mode 600)`)
  }
}

/**
 * Create a per-cell Kovo Hunter Store from a source data dir without copying or symlinking keys:
 * only enabled model_profiles rows + the workspace identity are copied into the isolated SQLite DB;
 * callers reference the real host `credentialsDir` via `KOVO_CREDENTIALS_DIR` (read-only),
 * keeping M-15 anti-symlink hardening intact and giving each cell its own `credentials/` for
 * persona secrets and receipt keys.
 *
 * Supports nested isolation (e.g. `benchmark-agentic-matrix.ts` model-gate data dirs): when a
 * gated/already-isolated source dir has an empty `credentials/` directory and `KOVO_CREDENTIALS_DIR`
 * (or `input.sourceCredentialsDir`) points at the real host credentials directory, credential files
 * are validated there without ever copying or symlinking keys.
 */
export function prepareIsolatedDataDir(input: {
  sourceDataDir: string
  targetDir: string
  sourceCredentialsDir?: string
}): IsolatedDataDirResult {
  const source = resolve(input.sourceDataDir)
  const target = resolve(input.targetDir)
  const sourceDb = join(source, 'kovo.sqlite')
  const localCredentials = join(source, 'credentials')
  const explicitCredentials = input.sourceCredentialsDir?.trim()
    ? resolve(input.sourceCredentialsDir.trim())
    : null
  const envCredentials = process.env.KOVO_CREDENTIALS_DIR?.trim()
    ? resolve(process.env.KOVO_CREDENTIALS_DIR.trim())
    : null

  if (!existsSync(sourceDb)) throw new PreflightError(`--isolate-data-dir source has no kovo.sqlite: ${source}`)
  if (explicitCredentials) {
    assertValidSourceCredentialsDir(explicitCredentials, '--isolate-data-dir source')
  } else if (lstatIfPresent(localCredentials)) {
    // Always enforce anti-symlink / owner-only checks on source/credentials when it exists.
    assertValidSourceCredentialsDir(localCredentials, '--isolate-data-dir source')
  } else if (envCredentials) {
    assertValidSourceCredentialsDir(envCredentials, '--isolate-data-dir source KOVO_CREDENTIALS_DIR')
  } else {
    assertValidSourceCredentialsDir(localCredentials, '--isolate-data-dir source')
  }

  unlockAndRemove(target)
  mkdirSync(target, { recursive: true, mode: 0o700 })

  const sourceClient = new DatabaseSync(sourceDb, { readOnly: true })
  let storage: Store | undefined
  try {
    const sourceWorkspace = sourceClient.prepare(
      'select id, name, actor_id, created_at from workspaces order by created_at asc limit 1',
    ).get() as { id?: string; name?: string; actor_id?: string; created_at?: number } | undefined
    if (!sourceWorkspace?.id) throw new PreflightError(`--isolate-data-dir source has no workspace row: ${source}`)
    const rows = sourceClient.prepare(
      'select name, endpoint, model, protocol, credential_id, priority, context_window, max_tokens, '
      + 'thinking_level, role_affinity, input_cost_per_mtok, cached_input_cost_per_mtok, output_cost_per_mtok '
      + 'from model_profiles where enabled = 1 order by priority desc, updated_at desc',
    ).all() as Array<Record<string, string | number>>
    if (!rows.length) throw new PreflightError(`--isolate-data-dir source has no enabled model profile: ${source}`)

    let sourceCredentials = explicitCredentials ?? localCredentials
    if (!explicitCredentials && envCredentials) {
      const localDirPresent = Boolean(lstatIfPresent(localCredentials))
      const anyMissingLocally = !localDirPresent || rows.some(
        row => lstatIfPresent(join(localCredentials, String(row.credential_id))) === null,
      )
      if (anyMissingLocally) {
        assertValidSourceCredentialsDir(envCredentials, '--isolate-data-dir source KOVO_CREDENTIALS_DIR')
        sourceCredentials = envCredentials
      }
    }

    for (const row of rows) {
      assertValidCredentialFile(join(sourceCredentials, String(row.credential_id)), String(row.name))
    }

    storage = new Store(target)
    storage.close()
    storage = undefined

    // Replace the auto-created workspace with the source workspace row, then bind the
    // copied profile rows to it. Only workspace identity + profile metadata move; keys do not.
    const targetClient = new DatabaseSync(join(target, 'kovo.sqlite'))
    try {
      targetClient.exec('PRAGMA foreign_keys = OFF')
      targetClient.prepare('delete from workspaces').run()
      targetClient.prepare('insert into workspaces (id, name, actor_id, created_at) values (?, ?, ?, ?)')
        .run(String(sourceWorkspace.id), String(sourceWorkspace.name), String(sourceWorkspace.actor_id), Number(sourceWorkspace.created_at ?? Date.now()))
      const insert = targetClient.prepare(
        'insert into model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, '
        + 'enabled, context_window, max_tokens, thinking_level, role_affinity, input_cost_per_mtok, '
        + 'cached_input_cost_per_mtok, output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at) '
        + 'values (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, null, null, ?)',
      )
      for (const row of rows) {
        insert.run(
          randomUUID(), String(sourceWorkspace.id), String(row.name), String(row.endpoint), String(row.model),
          String(row.protocol), String(row.credential_id), Number(row.priority), Number(row.context_window),
          Number(row.max_tokens), String(row.thinking_level), String(row.role_affinity),
          Number(row.input_cost_per_mtok), Number(row.cached_input_cost_per_mtok),
          Number(row.output_cost_per_mtok), 'closed', Date.now(),
        )
      }
    } finally {
      targetClient.close()
    }

    // Never copy or symlink model keys: keep target/credentials as a real owner-only dir
    // for per-cell persona credentials and receipt keys, and read model credentials from
    // `sourceCredentials` via KOVO_CREDENTIALS_DIR.
    const targetCredentials = join(target, 'credentials')
    rmSync(targetCredentials, { recursive: true, force: true })
    mkdirSync(targetCredentials, { recursive: true, mode: 0o700 })
    chmodSync(targetCredentials, 0o700)

    const profileNames = rows.map(row => String(row.name))
    return { directory: target, source, credentialsDir: sourceCredentials, profileNames }
  } catch (error) {
    try { storage?.close() } catch { /* already closed */ }
    try { unlockAndRemove(target) } catch { /* best-effort */ }
    throw error
  } finally {
    sourceClient.close()
  }
}

// ---------------------------------------------------------------------------------------------
// Phase-0 recon cache (v5.1 inner loop): reuse discovery snapshots, never probe results
// ---------------------------------------------------------------------------------------------
//
// A hill-climb iteration re-runs the same (app, seed, split, mode) cell many times. Phase-0
// discovery (surface crawl, auth passes, route-map/JS harvesting) is deterministic for a fixed
// briefing, so this cache snapshots ONLY the artefacts Phase-0 persists:
//   * endpoints / endpoint_params / api_dependencies
//   * resource samples, which the engine itself documents as "redacted non-secret sample
//     identifiers" (store.recordResourceSample re-validates them on load)
//   * persona session *handles* (header type/name + adapter + an opaque digest). Session values,
//     cookies, bearer tokens and passwords are never written.
//
// It never caches probing or verification state: findings, facts, replay specs, exchanges and
// coverage outcomes are absent, so every scorecard still comes from real probes and real
// Zero-LLM/agentic verification. A hit only flips the engine's own `run.phase0CompletedAt` gate
// and rehydrates the surface rows exactly as Phase-0 had persisted them.

export const RECON_CACHE_FORMAT = 1

export interface ReconCacheKeyInputs {
  app: AppName
  seed: number
  split: 'dev' | 'held-out'
  mode: BenchMode
  variantHash: string
}

export interface CachedEndpoint {
  ref: string
  /** Phase-0 insertion order (rowid). Warm rehydration preserves it so equal-risk ties rank identically. */
  seq: number
  origin: string
  method: string
  pathTemplate: string
  source: EndpointSource
  framework: string | null
  authRequirement: string | null
  ownershipGuard: string | null
  sinkKinds: string[]
  testedClasses: string[]
  coveragePct: number | null
  riskScore: number
  codeLocation: EndpointRow['codeLocation']
  createdAt: number
}

export interface CachedEndpointParam {
  endpointRef: string
  name: string
  location: ParamLocation
  inferredType: string | null
  isCsrf: boolean
  isObjectId: boolean
  source: string
  createdAt: number
}

export interface CachedApiDependency {
  producerRef: string
  consumerRef: string
  resourceKey: string
  sampleResourceIdHash: string | null
  personaHandle: string | null
  observedTransitions: string[]
  testedBola: boolean
  createdAt: number
}

export interface CachedResourceSample {
  ownerPersona: string
  resourceKey: string
  resourceId: string
  origin: string
  endpoint: string
  method: string
  mediaType: string | null
  authenticated: boolean
  createdAt: number
}

/**
 * Session metadata only. `sessionHandle` is a non-reversible digest used to confirm the warm run
 * authenticated the same persona surface; the minted cookie/bearer value stays in the cell's
 * owner-only credentials directory and is never serialized here.
 */
export interface CachedPersonaSessionHandle {
  handle: string
  roleLabel: string
  authKind: string
  headerType: 'cookie' | 'bearer' | 'header' | 'unknown'
  headerName: string | null
  adapter: string | null
  loginPath: string | null
  expiresAt: number | null
  sessionHandle: string
}

export interface ReconCacheFile {
  format: number
  key: string
  keyInputs: ReconCacheKeyInputs
  capturedAt: number
  gitSha: string
  sourceOrigin: string
  phase0: { completedAt: number; observedDurationMs: number | null }
  surface: {
    endpoints: CachedEndpoint[]
    endpointParams: CachedEndpointParam[]
    apiDependencies: CachedApiDependency[]
    resourceSamples: CachedResourceSample[]
    /** Plain GET paths Phase-0 requested, replayed unauthenticated on a hit (surface affirmation). */
    surfacePaths: string[]
  }
  auth: CachedPersonaSessionHandle[]
  security: { secretsIncluded: false; sessionValuesIncluded: false; note: string }
  checksum: string
}

export interface ReconCacheMeta {
  requested: boolean
  directory: string | null
  key: string | null
  keyInputs: ReconCacheKeyInputs | null
  hit: boolean
  refresh: boolean
  path: string | null
  reason: string | null
  loadMs: number
  applyMs: number
  phase0Skipped: boolean
  phase0ObservedMs: number | null
  reconTimeSavedMs: number
  captured: boolean
  capturedAt: number | null
  surface: {
    endpoints: number
    endpointParams: number
    apiDependencies: number
    resourceSamples: number
    personaSessionHandles: number
  }
  /** Cached surface paths replayed as benign GETs so the benchmark's discovery funnel is not
   *  penalised for skipping the crawler (real requests; no probe results are reused). */
  surfaceAffirmation: { attempted: number; completed: number; failed: number }
}

export function emptyReconCacheMeta(refresh = false): ReconCacheMeta {
  return {
    requested: false,
    directory: null,
    key: null,
    keyInputs: null,
    hit: false,
    refresh,
    path: null,
    reason: null,
    loadMs: 0,
    applyMs: 0,
    phase0Skipped: false,
    phase0ObservedMs: null,
    reconTimeSavedMs: 0,
    captured: false,
    capturedAt: null,
    surface: { endpoints: 0, endpointParams: 0, apiDependencies: 0, resourceSamples: 0, personaSessionHandles: 0 },
    surfaceAffirmation: { attempted: 0, completed: 0, failed: 0 },
  }
}

/**
 * `variantHash` invalidates snapshots when the discovery inputs change: the briefing surface
 * (routes/params), persona handles, login route and cache format. It deliberately excludes the
 * app's ephemeral loopback origin/port and the model/verifier configuration, because neither
 * changes what Phase-0 discovers.
 */
export function reconVariantHash(input: {
  app: AppName
  mode: BenchMode
  loginPath: string | null
  apiReference: Briefing['apiReference']
  personaHandles: readonly string[]
  opaqueLabels?: boolean
}): string {
  const routes = (input.apiReference ?? [])
    .map(route => `${route.method.toUpperCase()} ${route.path} ${[...route.params].sort().join(',')}`)
    .sort()
  return createHash('sha256').update(JSON.stringify({
    format: RECON_CACHE_FORMAT,
    app: input.app,
    mode: input.mode,
    loginPath: input.loginPath,
    routes,
    personaHandles: [...input.personaHandles].sort(),
    ...(input.opaqueLabels ? { opaqueLabels: true } : {}),
  })).digest('hex').slice(0, 16)
}

export function reconCacheKey(keyInputs: ReconCacheKeyInputs): string {
  return createHash('sha256').update(JSON.stringify({
    format: RECON_CACHE_FORMAT,
    app: keyInputs.app,
    seed: keyInputs.seed,
    split: keyInputs.split,
    mode: keyInputs.mode,
    variantHash: keyInputs.variantHash,
  })).digest('hex').slice(0, 32)
}

export function reconCachePath(directory: string, keyInputs: ReconCacheKeyInputs): string {
  const name = `${keyInputs.app}-seed${keyInputs.seed}-${keyInputs.split}-${keyInputs.mode}-${keyInputs.variantHash}.json`
  return join(resolve(directory), name)
}

function endpointRef(method: string, pathTemplate: string): string {
  return `${method.toUpperCase()} ${pathTemplate}`
}

function reconCacheChecksum(doc: Omit<ReconCacheFile, 'checksum'>): string {
  const material = JSON.stringify({
    format: doc.format,
    key: doc.key,
    keyInputs: doc.keyInputs,
    capturedAt: doc.capturedAt,
    gitSha: doc.gitSha,
    sourceOrigin: doc.sourceOrigin,
    phase0: doc.phase0,
    surface: doc.surface,
    auth: doc.auth,
    security: doc.security,
  })
  return createHash('sha256').update(material).digest('hex')
}

function sameKeyInputs(a: ReconCacheKeyInputs, b: ReconCacheKeyInputs): boolean {
  return a.app === b.app && a.seed === b.seed && a.split === b.split
    && a.mode === b.mode && a.variantHash === b.variantHash
}

function isBoundedString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length <= max
}

function isBoundedStringArray(value: unknown, maxItems: number, maxLen: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every(item => isBoundedString(item, maxLen))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

/** Structural validation; any failure is a cache miss (never a crash). */
export function validateReconCacheFile(raw: unknown, expected: ReconCacheKeyInputs): string | null {
  if (!isRecord(raw)) return 'snapshot is not an object'
  if (raw.format !== RECON_CACHE_FORMAT) return `format ${String(raw.format)} != ${RECON_CACHE_FORMAT}`
  if (!isRecord(raw.keyInputs) || !sameKeyInputs(raw.keyInputs as unknown as ReconCacheKeyInputs, expected)) {
    return 'key inputs changed (app/seed/split/mode/variant)'
  }
  const key = reconCacheKey(expected)
  if (raw.key !== key) return 'cache key mismatch'
  if (!isBoundedString(raw.sourceOrigin, 2048)) return 'missing source origin'
  if (!isBoundedString(raw.gitSha, 64)) return 'missing git sha'
  if (!isRecord(raw.phase0) || typeof raw.phase0.completedAt !== 'number') return 'missing phase-0 marker'
  if (!isRecord(raw.surface)) return 'missing surface'
  const surface = raw.surface
  if (!Array.isArray(surface.endpoints) || surface.endpoints.length > 5_000) return 'invalid endpoints'
  for (const ep of surface.endpoints as unknown[]) {
    if (!isRecord(ep)
      || !isBoundedString(ep.ref, 4096) || typeof ep.seq !== 'number' || !isBoundedString(ep.origin, 2048)
      || !isBoundedString(ep.method, 16) || !isBoundedString(ep.pathTemplate, 4096)
      || !isBoundedString(ep.source, 64)
      || !isBoundedStringArray(ep.sinkKinds, 64, 128)
      || !isBoundedStringArray(ep.testedClasses, 64, 128)) return 'invalid endpoint row'
  }
  const refs = new Set((surface.endpoints as CachedEndpoint[]).map(ep => ep.ref))
  if (!Array.isArray(surface.endpointParams) || surface.endpointParams.length > 20_000) return 'invalid endpoint params'
  for (const param of surface.endpointParams as unknown[]) {
    if (!isRecord(param) || !isBoundedString(param.endpointRef, 4096) || !refs.has(param.endpointRef)
      || !isBoundedString(param.name, 256) || !isBoundedString(param.location, 32)
      || !isBoundedString(param.source, 64)) return 'invalid endpoint param row'
  }
  if (!Array.isArray(surface.apiDependencies) || surface.apiDependencies.length > 20_000) return 'invalid dependencies'
  for (const dep of surface.apiDependencies as unknown[]) {
    if (!isRecord(dep) || !isBoundedString(dep.producerRef, 4096) || !isBoundedString(dep.consumerRef, 4096)
      || !refs.has(dep.producerRef) || !refs.has(dep.consumerRef)
      || !isBoundedString(dep.resourceKey, 256)) return 'invalid dependency row'
  }
  if (!Array.isArray(surface.resourceSamples) || surface.resourceSamples.length > 20_000) return 'invalid resource samples'
  for (const sample of surface.resourceSamples as unknown[]) {
    if (!isRecord(sample) || !isBoundedString(sample.ownerPersona, 256) || !isBoundedString(sample.resourceKey, 256)
      || !isBoundedString(sample.resourceId, 128) || !isBoundedString(sample.origin, 2048)
      || !isBoundedString(sample.endpoint, 2048) || !isBoundedString(sample.method, 16)) return 'invalid resource sample row'
  }
  if (!Array.isArray(surface.surfacePaths) || surface.surfacePaths.length > 300
    || !surface.surfacePaths.every(path => isBoundedString(path, 512) && path.startsWith('/'))) {
    return 'invalid surface paths'
  }
  if (!Array.isArray(raw.auth) || raw.auth.length > 64) return 'invalid persona auth handles'
  for (const auth of raw.auth as unknown[]) {
    if (!isRecord(auth) || !isBoundedString(auth.handle, 128) || !isBoundedString(auth.sessionHandle, 64)) {
      return 'invalid persona auth handle'
    }
    if ('value' in auth || 'cookie' in auth || 'token' in auth || 'password' in auth) {
      return 'persona auth handle contains secret material'
    }
  }
  if (!isRecord(raw.security) || raw.security.secretsIncluded !== false || raw.security.sessionValuesIncluded !== false) {
    return 'snapshot security contract missing'
  }
  if (!isBoundedString(raw.checksum, 128)) return 'missing checksum'
  const { checksum, ...rest } = raw as unknown as ReconCacheFile
  if (reconCacheChecksum(rest) !== checksum) return 'checksum mismatch (snapshot modified or corrupt)'
  return null
}

export interface ReconCacheLoad {
  hit: boolean
  reason: string
  path: string
  loadMs: number
  snapshot?: ReconCacheFile
}

/** Read + validate a snapshot. Any problem is a clean miss so the caller falls back to Phase-0. */
export function readReconCache(directory: string, keyInputs: ReconCacheKeyInputs): ReconCacheLoad {
  const startedAt = nowMs()
  const path = reconCachePath(directory, keyInputs)
  const done = (hit: boolean, reason: string, snapshot?: ReconCacheFile): ReconCacheLoad => ({
    hit, reason, path, loadMs: nowMs() - startedAt, ...(snapshot ? { snapshot } : {}),
  })
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? 'read failed'
    return done(false, code === 'ENOENT' ? 'no snapshot for this key' : `snapshot unreadable (${code})`)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return done(false, 'snapshot is not valid JSON')
  }
  const invalid = validateReconCacheFile(parsed, keyInputs)
  if (invalid) return done(false, invalid)
  return done(true, 'snapshot loaded', parsed as ReconCacheFile)
}

/**
 * A Phase-0 request path may be replayed on a warm hit only when it is a plain, query-free path
 * that cannot carry a probe payload, canary marker or redacted secret.
 */
export function surfaceReplayPath(pathAndQuery: string): string | null {
  const path = pathAndQuery.split('?')[0] ?? ''
  if (!path.startsWith('/') || path.startsWith('//')) return null
  if (path.length > 512) return null
  if (path.includes('.kovo-cal-')) return null // soft-404 calibration tokens
  if (path.includes('[[') || path.includes('{{')) return null // redacted secret placeholders
  if (!/^[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(path)) return null
  return path
}

/** Unique GET paths the engine's Phase-0 actually requested before completion. */
export function collectPhase0SurfacePaths(storage: Store, runId: string, boundary: number): string[] {
  let rows: Array<{ p: string }> = []
  try {
    rows = storage.client.prepare(
      "select path_and_query as p from broker_exchanges where run_id = ? and method = 'GET' and created_at <= ? order by created_at asc",
    ).all(runId, boundary) as Array<{ p: string }>
  } catch {
    return []
  }
  const paths = new Set<string>()
  for (const row of rows) {
    const path = surfaceReplayPath(row.p)
    if (path) paths.add(path)
    if (paths.size >= 300) break
  }
  return [...paths]
}

export interface SurfaceReplayResult {
  attempted: number
  completed: number
  failed: number
}

/**
 * Warm-hit surface affirmation: replay the cached Phase-0 GET paths as plain, unauthenticated
 * requests. These are real in-scope requests (the same routes the crawler already fetched), so
 * the benchmark's "entry route was touched" funnel stage stays meaningful. No probe payloads,
 * findings or verification state are replayed.
 */
export async function replayReconSurface(input: {
  origin: string
  paths: readonly string[]
  concurrency?: number
  timeoutMs?: number
}): Promise<SurfaceReplayResult> {
  const paths = [...new Set(input.paths)]
    .map(path => surfaceReplayPath(path))
    .filter((path): path is string => Boolean(path))
    .slice(0, 300)
  let completed = 0
  let failed = 0
  let cursor = 0
  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++
      if (index >= paths.length) return
      try {
        const res = await fetch(new URL(paths[index]!, input.origin), {
          method: 'GET',
          headers: { accept: '*/*' },
          signal: AbortSignal.timeout(input.timeoutMs ?? 4_000),
        })
        await res.arrayBuffer().catch(() => undefined)
        completed += 1
      } catch {
        failed += 1
      }
    }
  }
  const concurrency = Math.max(1, Math.min(input.concurrency ?? 4, paths.length || 1))
  await Promise.all(Array.from({ length: concurrency }, () => worker()))
  return { attempted: paths.length, completed, failed }
}

export interface ReconCaptureInput {
  storage: Store
  runId: string
  keyInputs: ReconCacheKeyInputs
  sourceOrigin: string
  phase0CompletedAt: number
  observedDurationMs: number | null
  personaSessions: readonly CachedPersonaSessionHandle[]
  secrets: readonly NamedSecret[]
  gitSha: string
}

export interface ReconCaptureResult {
  snapshot: ReconCacheFile
  counts: ReconCacheMeta['surface']
}

/**
 * Snapshot the persisted Phase-0 surface. Rows created after Phase-0 completion (investigation,
 * verification) are excluded via `createdAt <= phase0CompletedAt`, so a warm run starts from the
 * exact surface a cold run had at the same boundary.
 */
export function captureReconSnapshot(input: ReconCaptureInput): ReconCaptureResult {
  const boundary = input.phase0CompletedAt
  const included = (createdAt: number) => createdAt <= boundary + 1
  const endpointRows = input.storage.listEndpoints(input.runId, { limit: 2_000 })
    .filter(row => included(row.createdAt))
  // SQLite rowid gives the exact Phase-0 insertion order; ties in risk rank by it.
  const insertionOrder = new Map<string, number>()
  try {
    const rows = input.storage.client.prepare(
      'select id from endpoints where run_id = ? order by rowid asc',
    ).all(input.runId) as Array<{ id: string }>
    rows.forEach((row, index) => insertionOrder.set(row.id, index))
  } catch { /* ordering is optimisation only; fall back to 0 */ }
  const endpoints: CachedEndpoint[] = endpointRows
    .slice()
    .sort((a, b) => (insertionOrder.get(a.id) ?? 0) - (insertionOrder.get(b.id) ?? 0)
      || a.createdAt - b.createdAt
      || endpointRef(a.method, a.pathTemplate).localeCompare(endpointRef(b.method, b.pathTemplate)))
    .map((row, index) => {
      const ref = endpointRef(row.method, row.pathTemplate)
      const cached: CachedEndpoint = {
        ref,
        seq: insertionOrder.get(row.id) ?? index,
        origin: row.origin,
        method: row.method,
        pathTemplate: row.pathTemplate,
        source: row.source,
        framework: row.framework ?? null,
        authRequirement: row.authRequirement ?? null,
        ownershipGuard: row.ownershipGuard ?? null,
        sinkKinds: [...row.sinkKinds],
        testedClasses: [...row.testedClasses],
        coveragePct: row.coveragePct ?? null,
        riskScore: row.riskScore,
        codeLocation: row.codeLocation ?? null,
        createdAt: row.createdAt,
      }
      return cached
    })
  const endpointById = new Map(endpointRows.map(row => [row.id, row]))
  const endpointParams: CachedEndpointParam[] = []
  for (const param of input.storage.listEndpointParams(input.runId)) {
    if (!included(param.createdAt)) continue
    const endpoint = endpointById.get(param.endpointId)
    if (!endpoint) continue
    endpointParams.push({
      endpointRef: endpointRef(endpoint.method, endpoint.pathTemplate),
      name: param.name,
      location: param.location,
      inferredType: param.inferredType ?? null,
      isCsrf: Boolean(param.isCsrf),
      isObjectId: Boolean(param.isObjectId),
      source: param.source,
      createdAt: param.createdAt,
    })
  }
  const idToRef = new Map(endpointRows.map(row => [row.id, endpointRef(row.method, row.pathTemplate)]))
  const apiDependencies: CachedApiDependency[] = []
  for (const dep of input.storage.listApiDependencies(input.runId)) {
    if (!included(dep.createdAt)) continue
    const producerRef = idToRef.get(dep.producerEndpointId)
    const consumerRef = idToRef.get(dep.consumerEndpointId)
    if (!producerRef || !consumerRef) continue
    apiDependencies.push({
      producerRef,
      consumerRef,
      resourceKey: dep.resourceKey,
      sampleResourceIdHash: dep.sampleResourceIdHash ?? null,
      personaHandle: dep.personaHandle ?? null,
      observedTransitions: [...dep.observedTransitions],
      testedBola: Boolean(dep.testedBola),
      createdAt: dep.createdAt,
    })
  }
  const resourceSamples: CachedResourceSample[] = []
  for (const sample of input.storage.listResourceSamples(input.runId)) {
    if (!included(sample.createdAt)) continue
    resourceSamples.push({
      ownerPersona: sample.ownerPersona,
      resourceKey: sample.resourceKey,
      resourceId: sample.resourceId,
      origin: sample.origin,
      endpoint: sample.endpoint,
      method: sample.method,
      mediaType: sample.mediaType ?? null,
      authenticated: Boolean(sample.authenticated),
      createdAt: sample.createdAt,
    })
  }

  const surfacePaths = collectPhase0SurfacePaths(input.storage, input.runId, boundary)
  const base = {
    format: RECON_CACHE_FORMAT,
    key: reconCacheKey(input.keyInputs),
    keyInputs: input.keyInputs,
    capturedAt: nowMs(),
    gitSha: input.gitSha,
    sourceOrigin: input.sourceOrigin,
    phase0: { completedAt: boundary, observedDurationMs: input.observedDurationMs },
    surface: { endpoints, endpointParams, apiDependencies, resourceSamples, surfacePaths },
    auth: input.personaSessions.map(session => ({ ...session })),
    security: {
      secretsIncluded: false as const,
      sessionValuesIncluded: false as const,
      note: 'Phase-0 surface + redacted resource samples + persona session handles only; '
        + 'no cookies, bearer tokens, passwords, exchanges, findings or verification state.',
    },
  }
  const redacted = redactJsonValue(base, input.secrets)
  const snapshot: ReconCacheFile = { ...redacted, checksum: reconCacheChecksum(redacted) }
  const serialized = JSON.stringify(snapshot)
  for (const secret of input.secrets) {
    if (secret.value && secret.value.length >= 4 && serialized.includes(secret.value)) {
      throw new Error('recon cache would contain a registered secret; refusing to write it')
    }
  }
  return {
    snapshot,
    counts: {
      endpoints: endpoints.length,
      endpointParams: endpointParams.length,
      apiDependencies: apiDependencies.length,
      resourceSamples: resourceSamples.length,
      personaSessionHandles: snapshot.auth.length,
    },
  }
}

/** Owner-only atomic write; the directory holds only redacted discovery artefacts. */
export function writeReconCache(directory: string, keyInputs: ReconCacheKeyInputs, snapshot: ReconCacheFile): string {
  const dir = resolve(directory)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const path = reconCachePath(dir, keyInputs)
  const tmp = `${path}.tmp-${randomUUID()}`
  writeFileSync(tmp, `${JSON.stringify(snapshot, null, 2)}\n`, { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, path)
  return path
}

export interface ApplyReconInput {
  storage: Store
  runId: string
  origin: string
  snapshot: ReconCacheFile
  completedAt?: number
}

export interface ApplyReconResult {
  endpoints: number
  endpointParams: number
  apiDependencies: number
  resourceSamples: number
  phase0CompletedAt: number
}

/**
 * Rehydrate the snapshot into a fresh run's Store and close the engine's Phase-0 gate. Only
 * discovery rows are seeded; probing/verification state stays empty, so the run still has to
 * earn every finding with real requests.
 */
export function applyReconSnapshot(input: ApplyReconInput): ApplyReconResult {
  const mapOrigin = (origin: string): string => origin === input.snapshot.sourceOrigin ? input.origin : origin
  const ids = new Map<string, string>()
  const orderedEndpoints = input.snapshot.surface.endpoints
    .slice()
    .sort((a, b) => a.seq - b.seq || a.createdAt - b.createdAt || a.ref.localeCompare(b.ref))
  for (const endpoint of orderedEndpoints) {
    const row = input.storage.upsertEndpoint({
      runId: input.runId,
      origin: mapOrigin(endpoint.origin),
      method: endpoint.method,
      pathTemplate: endpoint.pathTemplate,
      source: endpoint.source,
      framework: endpoint.framework,
      authRequirement: endpoint.authRequirement,
      ownershipGuard: endpoint.ownershipGuard,
      sinkKinds: endpoint.sinkKinds,
      testedClasses: endpoint.testedClasses,
      coveragePct: endpoint.coveragePct,
      riskScore: endpoint.riskScore,
      codeLocation: endpoint.codeLocation,
    })
    ids.set(endpoint.ref, row.id)
  }
  let endpointParams = 0
  for (const param of input.snapshot.surface.endpointParams) {
    const endpointId = ids.get(param.endpointRef)
    if (!endpointId) continue
    input.storage.upsertEndpointParam({
      runId: input.runId,
      endpointId,
      name: param.name,
      location: param.location,
      inferredType: param.inferredType,
      isCsrf: param.isCsrf,
      isObjectId: param.isObjectId,
      source: param.source,
    })
    endpointParams += 1
  }
  let apiDependencies = 0
  for (const dep of input.snapshot.surface.apiDependencies) {
    const producerEndpointId = ids.get(dep.producerRef)
    const consumerEndpointId = ids.get(dep.consumerRef)
    if (!producerEndpointId || !consumerEndpointId) continue
    input.storage.recordApiDependency({
      runId: input.runId,
      producerEndpointId,
      consumerEndpointId,
      resourceKey: dep.resourceKey,
      sampleResourceIdHash: dep.sampleResourceIdHash,
      personaHandle: dep.personaHandle,
      observedTransitions: dep.observedTransitions,
      testedBola: dep.testedBola,
    })
    apiDependencies += 1
  }
  let resourceSamples = 0
  for (const sample of input.snapshot.surface.resourceSamples) {
    const saved = input.storage.recordResourceSample({
      runId: input.runId,
      ownerPersona: sample.ownerPersona,
      resourceKey: sample.resourceKey,
      resourceId: sample.resourceId,
      origin: mapOrigin(sample.origin),
      endpoint: sample.endpoint,
      method: sample.method,
      mediaType: sample.mediaType,
      authenticated: sample.authenticated,
    })
    if (saved) resourceSamples += 1
  }
  const phase0CompletedAt = input.completedAt ?? nowMs()
  input.storage.updateRunPhase0Completed(input.runId, phase0CompletedAt)
  return {
    endpoints: ids.size,
    endpointParams,
    apiDependencies,
    resourceSamples,
    phase0CompletedAt,
  }
}

// ---------------------------------------------------------------------------------------------
// Snapshot resume metadata + rehydration helpers (v5.1 primary inner loop)
// ---------------------------------------------------------------------------------------------

export interface SnapshotCaptureMeta {
  requested: boolean
  directory: string | null
  captured: boolean
  reason: string | null
  checkpoints: string[]
  primary: {
    path: string
    capturedAt: number
    skippedMs: number
    checkpoint: string
    counts: SnapshotCounts
  } | null
}

export interface SnapshotResumeMeta {
  requested: boolean
  loaded: boolean
  directory: string | null
  capturedAt: number | null
  ageMs: number | null
  skippedMs: number
  phase0Skipped: boolean
  originsRebound: number
  personaSessionsRebound: number
  schemaVersion: number | null
  gitSha: string | null
  seedSet: string | null
  heldOutOverride: boolean
  incompatibleReason: string | null
}

export interface SnapshotRunMeta {
  capture: SnapshotCaptureMeta
  resume: SnapshotResumeMeta
}

export function emptySnapshotMeta(): SnapshotRunMeta {
  return {
    capture: {
      requested: false,
      directory: null,
      captured: false,
      reason: null,
      checkpoints: [],
      primary: null,
    },
    resume: {
      requested: false,
      loaded: false,
      directory: null,
      capturedAt: null,
      ageMs: null,
      skippedMs: 0,
      phase0Skipped: false,
      originsRebound: 0,
      personaSessionsRebound: 0,
      schemaVersion: null,
      gitSha: null,
      seedSet: null,
      heldOutOverride: false,
      incompatibleReason: null,
    },
  }
}

/** One cell writes verbatim; a matrix gets a per-cell subdirectory. */
export function snapshotDirectoryFor(
  base: string,
  app: AppName,
  seed: number,
  mode: BenchMode,
  cellCount: number,
): string {
  return cellCount > 1 ? join(base, cellSlug(app, seed, mode)) : base
}

/** Accept either a checkpoint root or a matrix root that contains one per-cell child. */
export function resolveResumeSnapshotDirectory(
  base: string,
  app: AppName,
  seed: number,
  mode: BenchMode,
): string {
  if (existsSync(join(base, 'snapshot.json'))) return base
  const child = join(base, cellSlug(app, seed, mode))
  if (existsSync(join(child, 'snapshot.json'))) return child
  return base
}

/**
 * Validate and bind the snapshot's model profile credentials against the real host source
 * credentials directory without copying or symlinking keys. Callers reference the returned
 * `credentialsDir` via `KOVO_CREDENTIALS_DIR` (read-only), keeping M-15 anti-symlink hardening
 * intact. Persona credentials are written separately into `targetDataDir/credentials`.
 */
export function linkSnapshotModelCredentials(input: {
  snapshotDb: string
  sourceDataDir?: string
  targetDataDir: string
}): { profiles: number; linked: number; credentialsDir?: string } {
  const snapshot = new DatabaseSync(input.snapshotDb)
  let rows: Array<{ id?: string; credential_id?: string; name?: string; model?: string }> = []
  try {
    rows = snapshot.prepare(
      'select id, credential_id, name, model from model_profiles where enabled = 1 order by priority desc, updated_at desc',
    ).all() as Array<{ id?: string; credential_id?: string; name?: string; model?: string }>
  } catch {
    rows = []
  }
  if (!rows.length) {
    snapshot.close()
    return { profiles: 0, linked: 0 }
  }
  if (!input.sourceDataDir) {
    snapshot.close()
    throw new PreflightError(
      '--resume-snapshot needs --data-dir (or KOVO_DATA_DIR) pointing at the enabled model '
      + 'profile whose key the resumed run must use',
    )
  }
  const localSourceCredentials = join(resolve(input.sourceDataDir), 'credentials')
  const envCredentials = process.env.KOVO_CREDENTIALS_DIR?.trim()
    ? resolve(process.env.KOVO_CREDENTIALS_DIR.trim())
    : null
  try {
    if (lstatIfPresent(localSourceCredentials)) {
      assertValidSourceCredentialsDir(localSourceCredentials, '--resume-snapshot source')
    } else if (envCredentials) {
      assertValidSourceCredentialsDir(envCredentials, '--resume-snapshot source KOVO_CREDENTIALS_DIR')
    } else {
      assertValidSourceCredentialsDir(localSourceCredentials, '--resume-snapshot source')
    }
    const targetCredentials = join(resolve(input.targetDataDir), 'credentials')
    mkdirSync(targetCredentials, { recursive: true, mode: 0o700 })
    chmodSync(targetCredentials, 0o700)

    // Fall back to matching the profile by name/model when the source credential id differs
    // (e.g. the checkpoint came from a different isolated copy of the same profile).
    let sourceRows: Array<{ credential_id?: string; name?: string; model?: string }> = []
    const sourceDb = join(resolve(input.sourceDataDir), 'kovo.sqlite')
    if (existsSync(sourceDb)) {
      const source = new DatabaseSync(sourceDb, { readOnly: true })
      try {
        sourceRows = source.prepare(
          'select credential_id, name, model from model_profiles where enabled = 1',
        ).all() as Array<{ credential_id?: string; name?: string; model?: string }>
      } catch {
        sourceRows = []
      } finally {
        source.close()
      }
    }

    let sourceCredentials = localSourceCredentials
    if (envCredentials) {
      const localDirPresent = Boolean(lstatIfPresent(localSourceCredentials))
      const anyMissingLocally = !localDirPresent || rows.some(row => {
        const id = row.credential_id ? String(row.credential_id) : ''
        if (!id) return false
        if (lstatIfPresent(join(localSourceCredentials, id)) !== null) return false
        const match = sourceRows.find(candidate =>
          candidate.credential_id && candidate.name === row.name && candidate.model === row.model)
        return !(match?.credential_id && lstatIfPresent(join(localSourceCredentials, String(match.credential_id))) !== null)
      })
      if (anyMissingLocally) {
        assertValidSourceCredentialsDir(envCredentials, '--resume-snapshot source KOVO_CREDENTIALS_DIR')
        sourceCredentials = envCredentials
      }
    }

    let linked = 0
    for (const row of rows) {
      const id = row.credential_id ? String(row.credential_id) : ''
      if (!id) continue
      let effectiveCredId = id
      let sourcePath = join(sourceCredentials, effectiveCredId)
      if (!existsSync(sourcePath)) {
        const match = sourceRows.find(candidate =>
          candidate.credential_id && candidate.name === row.name && candidate.model === row.model)
        if (match?.credential_id) {
          effectiveCredId = String(match.credential_id)
          sourcePath = join(sourceCredentials, effectiveCredId)
        }
      }
      let info
      try {
        info = lstatSync(sourcePath)
      } catch {
        throw new PreflightError(
          `profile '${String(row.name ?? id)}' has no credential file in ${sourceCredentials}; `
          + 'resume needs the same --data-dir source that captured the checkpoint',
        )
      }
      if (info.isSymbolicLink()) {
        throw new PreflightError(`profile '${String(row.name ?? id)}' credential must not be a symbolic link`)
      }
      if (!info.isFile()) {
        throw new PreflightError(
          `profile '${String(row.name ?? id)}' has no readable credential file in ${sourceCredentials}`,
        )
      }
      if ((info.mode & 0o077) !== 0) {
        throw new PreflightError(`profile '${String(row.name ?? id)}' credential must be owner-only (mode 600)`)
      }
      if (effectiveCredId !== id && row.id) {
        snapshot.prepare('update model_profiles set credential_id = ? where id = ?').run(effectiveCredId, String(row.id))
      }
      linked += 1
    }
    return { profiles: rows.length, linked, credentialsDir: sourceCredentials }
  } finally {
    snapshot.close()
  }
}

export interface CellMeta {
  runtimeConfirmed?: number
  advisories?: number
  /** Redacted proof summaries for unmatched/misclassified findings (survives temp-dir cleanup). */
  falsePositiveEvidence?: FalsePositiveProofSummary[]
  app: AppName
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: BenchMode
  /** Effective conventional noun/action route wordlist switch for the deterministic engine. */
  conventionalWordlist: boolean
  /** True when the conventional noun/action route wordlist was opted in. */
  wordlistOn: boolean
  /** False whenever wordlistOn is true (non-reportable). */
  reportable: boolean
  /** R3-19: True when personas were provisioned with opaque UI-style role labels + typed tenantRef/privilege. */
  opaqueLabels?: boolean
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
  /** Parallel app/seed cells in this invocation (scheduling only, never worker slots). */
  cellConcurrency: number
  /** In-run investigation worker slots handed to `Execution` (`runs.worker_concurrency`). */
  workerConcurrency: number
  /** Hard per-origin rate cap written to the run. */
  maxRpsPerOrigin: number
  /** Corrected det_lead funnel (queued vs. investigated to a verdict). */
  leadFunnel: LeadFunnelMetrics
  /** Split Phase-A/Phase-B request budgets and their measured consumption. */
  requestBudgets: RequestBudgetMeta
  reconCache: ReconCacheMeta
  snapshot: SnapshotRunMeta
  /** Checkpoint directory this run resumed from (null for a cold run). */
  resumedFrom: string | null
  /** Wall-clock of cold work the checkpoint skipped. */
  snapshotSkippedMs: number
  startedAt: number
  endedAt: number
  durationMs: number
  timedOut: boolean
  terminalStatus: string
  terminalPhase: string
  runId: string
  projectId: string
  findingsPersisted: number
  findingsSubmitted: number
  baselineChecksExcluded: number
  endpointsDiscovered: number
  endpointParamsDiscovered: number
  brokerExchanges: number
  requestsOnDiscoveredRoutes: number
  assignments: AssignmentDiagnostics
  facts: number
  boardMessages: number
  inert: boolean
  requestCount: number
  oracleEventCount: number
  notes: string[]
  shutdown: { engineBusy: number; appStopped: boolean; canaryStopped: boolean }
}

export interface CellResult {
  meta: CellMeta
  scorecard: Scorecard
  jsonPath: string
  mdPath: string
  metaPath: string
}

function cellSlug(app: AppName, seed: number, mode: BenchMode): string {
  return `${app}-seed${seed}-${mode}`
}

function resolveGitSha(): string {
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
      cwd: resolve(fileURLToPath(new URL('..', import.meta.url))),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || 'unknown'
  } catch {
    return 'unknown'
  }
}

async function makeWhiteBoxMount(briefing: Briefing, dataDir: string, projectId: string): Promise<string[]> {
  if (!briefing.sourceDir) return []
  const repoRoot = join(projectReposDir(dataDir, projectId), 'bench', briefing.app)
  mkdirSync(join(repoRoot, '..'), { recursive: true, mode: 0o700 })
  // A prior run with the same --data-dir may have left a read-only mount behind.
  if (existsSync(repoRoot)) unlockAndRemove(repoRoot)
  cpSync(briefing.sourceDir, repoRoot, { recursive: true })
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
  return [`/repos/bench/${briefing.app}`]
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

function nowMs(): number { return Date.now() }

/** Sentinel hash stamped on INVALID rows when an Execution-backed run emitted no `run.effective_config` event. */
export const MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH = createHash('sha256')
  .update('kovo-effective-config:missing-observed')
  .digest('hex')

/**
 * Resolve effective config strictly from an engine-emitted `run.effective_config` event.
 * Never fabricates `effectiveConfig` from caller flags when `observed` is absent.
 */
export function resolveObservedEffectiveConfigForRunner(input: {
  observed: ObservedEffectiveConfig | null | undefined
  deterministicOnly: boolean
  environment?: string
  approvalPolicy?: string
  wordlistOn?: boolean
  verifierBackend: string
  mode: string
  workerImageId?: string | null
  workerSourceHash?: string | null
  sdkVersion?: string | null
  opaqueLabels?: boolean
  env?: NodeJS.ProcessEnv
  extra?: Record<string, string | number | boolean | null | undefined>
}): { observed: boolean; effectiveConfigHash: string; effectiveConfig?: EffectiveConfigSnapshot } {
  if (!input.observed) {
    return {
      observed: false,
      effectiveConfigHash: MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH,
      effectiveConfig: undefined,
    }
  }
  const mergedExtra = {
    ...(input.opaqueLabels ? { opaqueLabels: true } : {}),
    ...(input.extra ?? {}),
  }
  const { effectiveConfigHash, effectiveConfig } = computeEffectiveConfig({
    ...(input.env ? { env: input.env } : {}),
    observed: input.observed,
    deterministicOnly: input.deterministicOnly,
    environment: input.environment ?? 'local-lab',
    approvalPolicy: input.approvalPolicy ?? 'auto_review',
    ...(input.wordlistOn !== undefined ? { wordlistOn: input.wordlistOn } : {}),
    verifierBackend: input.verifierBackend,
    mode: input.mode,
    ...(input.workerImageId ? { workerImageId: input.workerImageId } : {}),
    ...(input.workerSourceHash ? { workerSourceHash: input.workerSourceHash } : {}),
    sdkVersion: input.sdkVersion ?? VERIFY_RPC_SDK_VERSION,
    ...(Object.keys(mergedExtra).length > 0 ? { extra: mergedExtra } : {}),
  })
  return { observed: true, effectiveConfigHash, effectiveConfig }
}

/**
 * Emit one realistic-bench cell ledger row to the gitignored per-run ledger by default
 * (`KOVO_LEDGER_ROOT` / `benchmarks/results/runs/<run-id>.jsonl`), optionally promoting to
 * `promoteLedgerPath`. Marks the row `INVALID` when observed `effectiveConfig` is missing.
 */
export function writeRealisticCellLedgerRow(input: {
  scorecard: Scorecard
  app: AppName
  split: 'dev' | 'held-out' | 'sealed'
  mode: BenchMode
  llm: 'agentic' | 'deterministic-no-llm'
  seed: number
  recordedAt: string
  gitSha: string
  dirty: boolean
  benchmarkVersion: string
  effectiveConfigHash: string
  effectiveConfig?: EffectiveConfigSnapshot
  observedEffectiveConfig: boolean
  inert: boolean
  conventionalWordlist: boolean
  durationMs: number
  workerImageId?: string | null
  workerSourceHash?: string | null
  sdkVersion?: string | null
  opaqueLabels?: boolean
  noLedger?: boolean
  promoteLedgerPath?: string
  runId?: string
  runsDir?: string
  repoRoot?: string
}): { perRunPath: string | null; row: LedgerRow | null } {
  if (input.noLedger) return { perRunPath: null, row: null }
  const card = input.scorecard
  const graded = card as typeof card & { validUnplantedCount?: number }
  const siteOutcomes: Record<string, string> = {}
  for (const v of card.vulns) siteOutcomes[v.siteId] = v.outcome
  const missingObserved = !input.observedEffectiveConfig || !input.effectiveConfig
  const notes: string[] = []
  if (missingObserved) notes.push('missing_observed_effective_config')
  if (input.opaqueLabels) notes.push('opaque_labels')
  const row = buildLedgerRow({
    cell: card as unknown as Record<string, unknown>,
    readMeta: {
      failed: missingObserved,
      inert: input.inert,
      app: input.app,
      seed: input.seed,
      split: input.split,
      mode: input.mode,
      llm: input.llm,
      durationMs: input.durationMs,
      ...(missingObserved ? { error: 'missing_observed_effective_config' } : {}),
    },
    suite: 'realistic-bench',
    recordedAt: input.recordedAt,
    gitSha: input.gitSha,
    dirty: input.dirty,
    benchmarkVersion: input.benchmarkVersion,
    effectiveConfigHash: input.effectiveConfigHash,
    ...(input.effectiveConfig ? { effectiveConfig: input.effectiveConfig } : {}),
    app: input.app,
    split: input.split,
    mode: input.mode,
    llm: input.llm,
    seed: input.seed,
    repeat: 1,
    certifying: false,
    reportable: !input.conventionalWordlist && !input.inert && !missingObserved,
    validUnplantedCount: graded.validUnplantedCount ?? 0,
    costUsd: card.totalCostUsd,
    durationMs: input.durationMs,
    siteOutcomes,
    notes,
  })
  const stampedRow: LedgerRow & { opaqueLabels?: boolean } = {
    ...row,
    workerImageId: input.workerImageId ?? input.effectiveConfig?.workerImageId ?? null,
    workerSourceHash: input.workerSourceHash ?? input.effectiveConfig?.workerSourceHash ?? null,
    sdkVersion: input.sdkVersion ?? input.effectiveConfig?.sdkVersion ?? VERIFY_RPC_SDK_VERSION,
    ...(input.opaqueLabels ? { opaqueLabels: true } : {}),
  }
  const runStem = input.runId ?? `realistic-${input.app}-seed${input.seed}-${input.mode}-${input.recordedAt.replace(/[:.]/g, '-')}-${process.pid}`
  const appended = appendPerRunLedgerRow(stampedRow, {
    runId: runStem,
    runsDir: input.runsDir,
    repoRoot: input.repoRoot,
  })
  if (input.promoteLedgerPath) {
    promoteLedgerRows(appended.path, {
      targetLedgerPath: input.promoteLedgerPath,
      repoRoot: input.repoRoot,
    })
  }
  return { perRunPath: appended.path, row: appended.row }
}

export async function waitForTerminal(input: {
  storage: Store
  runId: string
  deadlineAt: number
  onTick?: (status: string, phase: string) => void
  /** Fired once, on the first poll that observes the engine's Phase-0 completion marker. */
  onPhase0Complete?: (completedAt: number) => void
  isEngineStopped?: () => boolean
}): Promise<{ timedOut: boolean; status: string; phase: string }> {
  const terminal = new Set(['complete', 'failed', 'stopped', 'paused', 'budget_paused'])
  let last = 0
  let phase0Seen = false
  while (true) {
    const run = input.storage.run(input.runId)
    if (!phase0Seen && run.phase0CompletedAt) {
      phase0Seen = true
      try {
        input.onPhase0Complete?.(run.phase0CompletedAt)
      } catch { /* cache capture is best-effort; never block the run */ }
    }
    if (terminal.has(run.status)) return { timedOut: false, status: run.status, phase: run.phase }
    if (input.isEngineStopped?.()) {
      const latest = input.storage.run(input.runId)
      if (terminal.has(latest.status)) return { timedOut: false, status: latest.status, phase: latest.phase }
      throw new Error(`Execution engine stopped unexpectedly while run ${input.runId} was ${latest.status}/${latest.phase}`)
    }
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

export async function stopEngine(engine: Execution): Promise<number> {
  await engine.stop()
  const deadline = nowMs() + 5_000
  while (nowMs() < deadline) {
    const busy = (engine as unknown as { active: Map<string, unknown> }).active.size +
      (engine as unknown as { coordinator: Map<string, unknown> }).coordinator.size +
      (engine as unknown as { threatModeling: Map<string, unknown> }).threatModeling.size +
      (engine as unknown as { plannerTasks: Map<string, unknown> }).plannerTasks.size +
      (engine as unknown as { runAuthInFlight: Map<string, unknown> }).runAuthInFlight.size
    if (busy === 0) return 0
    await delay(50)
  }
  const left = (engine as unknown as { active: Map<string, unknown> }).active.size +
    (engine as unknown as { coordinator: Map<string, unknown> }).coordinator.size +
    (engine as unknown as { threatModeling: Map<string, unknown> }).threatModeling.size +
    (engine as unknown as { plannerTasks: Map<string, unknown> }).plannerTasks.size +
    (engine as unknown as { runAuthInFlight: Map<string, unknown> }).runAuthInFlight.size
  return left
}

export async function runCell(args: RealisticArgs, app: AppName, seed: number, log: (line: string) => void): Promise<CellResult> {
  const startedAt = nowMs()
  const slug = cellSlug(app, seed, args.mode)
  // The deterministic engine reads the switch from the environment (same mechanism as
  // KOVO_DETERMINISTIC_ENGINE). Record the effective value in cell meta and scorecard JSON.
  if (args.conventionalWordlist) process.env.KOVO_CONVENTIONAL_WORDLIST = '1'
  else process.env.KOVO_CONVENTIONAL_WORDLIST = '0'
  // The product surface benefits from response-driven object siblings; the procedural capability
  // harness keeps its historical corpus (the flag is opt-in in phase0-recon).
  process.env.KOVO_RECON_SIBLINGS = '1'
  const cellCount = cellKeys(args).length
  // --no-llm must never inherit a model-enabled data dir: use an isolated deterministic store.
  const sourceDataDir = args.noLlm ? undefined : args.dataDir
  const isolate = shouldIsolateDataDir(args)
  const resumeRequested = Boolean(args.resumeSnapshotDir)
  const notes: string[] = []
  const snapshotMeta = emptySnapshotMeta()
  snapshotMeta.resume.requested = resumeRequested
  snapshotMeta.resume.heldOutOverride = args.allowHeldoutSnapshot
  snapshotMeta.capture.requested = Boolean(args.snapshotAfterFloorDir)
  const captureBaseDir = args.snapshotAfterFloorDir
    ? snapshotDirectoryFor(args.snapshotAfterFloorDir, app, seed, args.mode, cellCount)
    : undefined
  snapshotMeta.capture.directory = captureBaseDir ?? null
  if (captureBaseDir && args.snapshotRefresh) {
    rmSync(captureBaseDir, { recursive: true, force: true })
  }

  let dataDir = join(args.outDir, 'data', slug)
  let isolated: IsolatedDataDirResult | undefined
  let releaseCredentialsDir: (() => void) | undefined
  let loadedSnapshot: LoadedRunSnapshot | undefined
  if (resumeRequested) {
    const resumeDir = resolveResumeSnapshotDirectory(args.resumeSnapshotDir!, app, seed, args.mode)
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
    // Resume always uses a fresh data dir; --data-dir is only the credential/profile source.
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
    notes.push(
      `resume snapshot loaded from ${resumeDir} (captured ${new Date(targetApp.capturedAt).toISOString()}, `
      + `age ${Math.round(usable.ageMs / 1000)}s, checkpoint skipped ${Math.round(usable.skippedMs / 1000)}s of cold work); `
      + `${linked.linked} model credential binding(s) via KOVO_CREDENTIALS_DIR`,
    )
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
  let started: StartedApp | undefined
  let engine: Execution | undefined
  let backend: WorkerBackend | undefined
  let backendKind: VerifierBackendKind = 'local-jq'
  let appStopped = false
  let canaryStopped = false
  let whiteBoxRoot: string | undefined
  if (args.isolateDataDir && !sourceDataDir && !args.noLlm) {
    notes.push('--isolate-data-dir had no --data-dir/KOVO_DATA_DIR source; using a fresh cell data dir')
  }
  if (isolated) {
    notes.push(
      `isolated data dir from ${isolated.source}; profile(s): ${isolated.profileNames.join(', ')}; credentials referenced via KOVO_CREDENTIALS_DIR (read-only, no symlink, key not copied)`,
    )
  }

  const secrets: NamedSecret[] = []
  let runId = ''
  let projectId = ''
  let runStartedAt = startedAt

  try {
    // --- Preflight (before booting the app): model mode + real worker-session capability ---
    let profiles: ResolvedModelProfile[] = []
    let profileLoadErrors: string[] = []
    if (!args.noLlm) {
      try {
        const load = inspectModelProfileLoad(storage)
        profiles = load.profiles
        profileLoadErrors = load.errors.map(msg => redact(msg).slice(0, 160))
        if (profileLoadErrors.length) {
          notes.push(`model profile lookup diagnostic: ${profileLoadErrors.join('; ')}`)
        }
      } catch (error) {
        const detail = redact((error as Error).message).slice(0, 160)
        profileLoadErrors.push(detail)
        notes.push(`model profile lookup failed: ${detail}`)
      }
      if (isolated && profiles.length === 0) {
        const detail = profileLoadErrors.length ? ` (${profileLoadErrors.join('; ')})` : ''
        throw new PreflightError(
          `isolated agentic data dir prepared from ${isolated.source} loaded 0 usable model profiles${detail}. `
          + 'Verify KOVO_CREDENTIALS_DIR and source credentials are non-symlink owner-only files/dirs.',
        )
      }
    }
    if (args.noLlm) notes.push('--no-llm: model profiles ignored; isolated deterministic data dir')
    const model = describeModelMode(args.noLlm ? [] : profiles)
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
            `--verifier docker is not usable from this process: ${detail}. Docker worker sessions need socket access; `
            + 're-run under `newgrp docker -c \'<command>\'` and make sure kovo-worker:v4 is built.',
          )
        }
        throw error
      }
    })()
    backendKind = selected.kind
    const workerImage: WorkerImageIdentity | null = selected.workerImage
    backend = selected.kind === 'docker'
      // Tag containers with this workspace so a crashed run can be reclaimed, and so the
      // harness leaves zero orphan containers after stop.
      ? new LinuxWorkerBackend({
          image: workerImage?.imageRef ?? resolveWorkerImageRef(),
          imageId: workerImage?.imageId ?? null,
          sourceHash: workerImage?.sourceHash ?? null,
          workspace: { id: storage.workspace.id, directory: storage.directory },
        })
      : selected.backend

    const capability = await detectWorkerSessions(backend)
    assertAgenticPreflight({
      hasProfiles: model.mode === 'agentic',
      noLlm: args.noLlm,
      allowInertWorkers: args.allowInertWorkers,
      backendKind,
      workerSessions: capability.supported,
      workerSessionsDetail: capability.detail,
      profileEndpoints: profiles.map(p => p.endpoint),
    })
    notes.push(`verifier backend ${backendKind}; workerSessions=${capability.supported}${capability.supported ? '' : ` (${capability.detail})`}`)

    const listener = await canary.startListener({ host: '127.0.0.1', port: 0 })
    const oobPort = listener.port
    if (!oobPort) fail('canary listener did not bind a loopback port')
    // Same invariant as the procedural harness: the app may call back only to this exact port,
    // and Execution must use this same broker for SSRF/XXE verification.
    const oobCallbackPorts = resolveOobCallbackPorts(canary, [oobPort])

    started = await startRealisticApp({
      app,
      seed,
      ...(args.heldOut ? { heldOutSalt: process.env.KOVO_RB_HELDOUT_SALT } : {}),
      oobCallbackPorts,
    })
    const briefing = briefingFor(started, args.mode)
    for (const p of briefing.personas) secrets.push({ value: p.password, placeholder: '[[persona-password]]' })

    let loginPath = resumeRequested && loadedSnapshot?.target.loginPath
      ? loadedSnapshot.target.loginPath
      : pickLoginPath(briefing)
    if (!loginPath && args.mode === 'black-box' && !resumeRequested) {
      loginPath = await probeLoginPath(briefing.origin, briefing.personas)
      if (loginPath) notes.push(`black-box login route discovered by convention probe: ${loginPath}`)
      else notes.push('black-box login route not discovered; personas are not registered')
    }
    const plan = planCell(briefing, loginPath, { opaqueLabels: args.opaqueLabels })
    if (args.opaqueLabels) notes.push('--opaque-labels: UI-style opaque role labels with typed tenantRef & privilege')
    const gitSha = resolveGitSha()
    const canaryBaseUrl = listener.localBaseUrl ?? listener.effectiveBaseUrl ?? null

    // Recon-cache key: (app, seed, split, mode, variantHash). The variant hash covers only the
    // discovery inputs (briefing surface + persona handles + login route), never the port.
    const recon = emptyReconCacheMeta(args.refreshRecon)
    if (args.reuseReconDir && !resumeRequested) {
      const keyInputs: ReconCacheKeyInputs = {
        app,
        seed,
        split: args.heldOut ? 'held-out' : 'dev',
        mode: args.mode,
        variantHash: reconVariantHash({
          app,
          mode: args.mode,
          loginPath,
          apiReference: briefing.apiReference,
          personaHandles: plan.personas.map(p => p.handle),
          opaqueLabels: args.opaqueLabels,
        }),
      }
      recon.requested = true
      recon.directory = args.reuseReconDir
      recon.keyInputs = keyInputs
      recon.key = reconCacheKey(keyInputs)
      recon.path = reconCachePath(args.reuseReconDir, keyInputs)
    }

    let mountedRepos: string[] = []
    let personaIds: string[] = []
    if (resumeRequested && loadedSnapshot) {
      // Resume: the checkpoint already carries project/persona/run/scope state. Only the
      // benchmark's white-box source mount is recreated under the new data dir.
      projectId = loadedSnapshot.target.projectId
      runId = loadedSnapshot.target.runId
      const run = storage.run(runId)
      personaIds = [...run.approvedPersonaIds]
      if (args.mode === 'white-box') {
        mountedRepos = await makeWhiteBoxMount(briefing, dataDir, projectId)
        if (mountedRepos.length) {
          whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', briefing.app)
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
        name: `realistic-bench ${app} seed ${seed} (${args.mode})`,
        seeds: [briefing.origin],
        environment: 'local-lab',
      })
      projectId = project.id

      if (plan.openApi) {
        storage.importProjectSpec({
          requestId: randomUUID(),
          projectId,
          name: `realistic-bench-${app}-api.json`,
          kind: 'openapi',
          origin: briefing.origin,
          content: JSON.stringify(plan.openApi, null, 2),
        })
      }

      mountedRepos = args.mode === 'white-box'
        ? await makeWhiteBoxMount(briefing, dataDir, projectId)
        : []
      if (mountedRepos.length) {
        whiteBoxRoot = join(projectReposDir(dataDir, projectId), 'bench', briefing.app)
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
        // Hard run-total cap. Phase allowances are enforced inside Execution (floor/agent split).
        budgetRequests: args.totalRequestBudget,
        maxRpsPerOrigin: args.maxRps,
        workerConcurrency: runWorkerConcurrency(args),
        workerMaxTurns: 30,
        multiTrialEnabled: true,
        allowWebSearch: false,
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
        budgetRequests: args.totalRequestBudget,
        maxRpsPerOrigin: args.maxRps,
      })
    }

    // Recon cache (v5.1): seed the run's Store from a prior Phase-0 snapshot and let the engine's
    // own `phase0CompletedAt` gate skip discovery. Probing/verification still run in full.
    if (!resumeRequested && recon.requested && recon.directory && recon.keyInputs) {
      if (args.refreshRecon) {
        recon.reason = 'refresh requested; a fresh Phase-0 pass will recapture the snapshot'
        notes.push('recon cache refresh requested: existing snapshot ignored')
      } else {
        const loaded = readReconCache(recon.directory, recon.keyInputs)
        recon.loadMs = loaded.loadMs
        recon.path = loaded.path
        if (loaded.hit && loaded.snapshot) {
          try {
            const applyStartedAt = nowMs()
            const applied = applyReconSnapshot({
              storage,
              runId,
              origin: briefing.origin,
              snapshot: loaded.snapshot,
            })
            recon.applyMs = nowMs() - applyStartedAt
            recon.hit = true
            recon.phase0Skipped = true
            recon.phase0ObservedMs = loaded.snapshot.phase0.observedDurationMs
            recon.reconTimeSavedMs = Math.max(0, loaded.snapshot.phase0.observedDurationMs ?? 0)
            recon.capturedAt = loaded.snapshot.capturedAt
            recon.surface = {
              endpoints: applied.endpoints,
              endpointParams: applied.endpointParams,
              apiDependencies: applied.apiDependencies,
              resourceSamples: applied.resourceSamples,
              personaSessionHandles: loaded.snapshot.auth.length,
            }
            notes.push(
              `recon cache hit (${recon.key?.slice(0, 12)}): seeded ${applied.endpoints} endpoints, `
              + `${applied.endpointParams} params, ${applied.apiDependencies} dependencies, `
              + `${applied.resourceSamples} resource samples; Phase-0 discovery skipped in ${recon.applyMs}ms`,
            )
            // Real, benign GET replay of the cached discovery routes keeps the benchmark's
            // "entry route touched" funnel stage honest without re-running the crawler.
            recon.surfaceAffirmation = await replayReconSurface({
              origin: briefing.origin,
              paths: loaded.snapshot.surface.surfacePaths,
            })
            notes.push(
              `recon surface affirmation: ${recon.surfaceAffirmation.completed}/${recon.surfaceAffirmation.attempted} `
              + 'cached Phase-0 GET paths replayed (real requests; probing/verification untouched)',
            )
          } catch (error) {
            // A snapshot that validates but cannot be applied must not abort the cell: reopen the
            // Phase-0 gate and fall back to a fresh discovery pass.
            recon.hit = false
            recon.phase0Skipped = false
            recon.reconTimeSavedMs = 0
            recon.reason = `snapshot apply failed: ${redact(error instanceof Error ? error.message : String(error)).slice(0, 160)}`
            notes.push(`recon cache apply failed (${recon.reason}); falling back to fresh Phase-0 discovery`)
            try {
              if (storage.run(runId).phase0CompletedAt) {
                storage.updateRun(runId, { phase0CompletedAt: null })
              }
            } catch { /* best-effort: engine reruns discovery when the gate is open */ }
          }
        } else {
          recon.reason = loaded.reason
          notes.push(`recon cache miss: ${loaded.reason}; running fresh Phase-0 discovery`)
        }
      }
    }

    // --- Snapshot checkpoints (v5.1 primary inner loop) -------------------------------------
    const capturedCheckpointKeys = new Set<string>()
    const captureCheckpoint = (checkpoint: SnapshotCheckpoint): void => {
      if (resumeRequested || !captureBaseDir || !runId) return
      try {
        const latest = storage.run(runId)
        const round = latest.roundNo
        const key = checkpoint === 'planner-round' ? `${checkpoint}:${round}` : checkpoint
        if (capturedCheckpointKeys.has(key)) return
        const dir = checkpoint === 'planner-round'
          ? join(captureBaseDir, `planner-round-${round}`)
          : checkpoint === 'phase0'
            ? join(captureBaseDir, 'phase0')
            : captureBaseDir
        if (!args.snapshotRefresh && existsSync(join(dir, 'snapshot.json'))) {
          if (checkpoint === 'planner-round' || checkpoint === 'phase0') {
            capturedCheckpointKeys.add(key)
            snapshotMeta.capture.reason = `checkpoint ${key} already present`
            return
          }
          try {
            const existing = readRunSnapshot(dir)
            if (existing.snapshot.coordinator.checkpoint !== 'phase0') {
              capturedCheckpointKeys.add(key)
              snapshotMeta.capture.reason = 'fresh checkpoint already present; pass --snapshot-refresh to recapture'
              return
            }
          } catch { /* corrupt existing checkpoint: overwrite it */ }
        }
        const result: CaptureRunSnapshotResult = captureRunSnapshot({
          storage,
          snapshotDir: dir,
          checkpoint,
          target: {
            app,
            seed,
            seedSet: started?.plan.seedSet ?? (args.heldOut ? 'held-out' : 'dev'),
            mode: args.mode,
            origin: briefing.origin,
            loginPath,
            canaryBaseUrls: canaryBaseUrl ? [canaryBaseUrl] : [],
            projectId,
            runId,
          },
          gitSha,
          secrets,
        })
        capturedCheckpointKeys.add(key)
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
          + `${result.counts.endpoints} endpoints, ${result.counts.facts} facts `
          + `(${result.counts.detLeads} det_lead), ${result.counts.findings} findings, `
          + `${result.counts.replaySpecs} replay specs; cold work skipped on resume `
          + `~${Math.round(result.snapshot.coordinator.virtualElapsedMs / 1000)}s`,
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
      floorRequestBudget: args.floorRequestBudget,
      agentRequestBudget: args.agentRequestBudget,
      onCheckpoint: event => captureCheckpoint(event.checkpoint as SnapshotCheckpoint),
    })
    engine.start()
    engine.wake()
    runStartedAt = nowMs()

    const captureRecon = (completedAt: number): void => {
      if (resumeRequested) return
      if (!recon.requested || recon.captured || recon.hit || !recon.keyInputs || !recon.directory) return
      try {
        const resolved = resolveRunPersonas(storage, projectId, personaIds)
        const personaSessions: CachedPersonaSessionHandle[] = plan.personas.map(p => {
          const session = resolved.get(p.handle)?.session
          const headerType = session?.headerType ?? 'unknown'
          return {
            handle: p.handle,
            roleLabel: p.roleLabel,
            authKind: 'login',
            headerType,
            headerName: session?.headerName ?? null,
            adapter: session?.adapterUsed ?? null,
            loginPath: loginPath ? new URL(loginPath, briefing.origin).pathname : null,
            expiresAt: typeof session?.expiresAt === 'number' ? session.expiresAt : null,
            // Non-reversible handle only; the minted session value stays in the cell credentials dir.
            sessionHandle: createHash('sha256').update(`${recon.key}:${p.handle}:${headerType}`).digest('hex').slice(0, 24),
          }
        })
        const { snapshot, counts } = captureReconSnapshot({
          storage,
          runId,
          keyInputs: recon.keyInputs,
          sourceOrigin: briefing.origin,
          phase0CompletedAt: completedAt,
          observedDurationMs: Math.max(0, completedAt - runStartedAt),
          personaSessions,
          secrets,
          gitSha,
        })
        recon.path = writeReconCache(recon.directory, recon.keyInputs, snapshot)
        recon.captured = true
        recon.capturedAt = snapshot.capturedAt
        recon.phase0ObservedMs = snapshot.phase0.observedDurationMs
        recon.surface = counts
        notes.push(
          `recon cache snapshot written: ${counts.endpoints} endpoints, ${counts.endpointParams} params, `
          + `${counts.apiDependencies} dependencies, ${counts.resourceSamples} redacted resource samples, `
          + `${counts.personaSessionHandles} persona session handles (no secret values)`,
        )
      } catch (error) {
        recon.reason = `capture failed: ${redact(error instanceof Error ? error.message : String(error)).slice(0, 160)}`
        notes.push(`recon cache capture skipped: ${recon.reason}`)
      }
    }

    resetPersonaIdentityFallbackCount()
    const wait = await waitForTerminal({
      storage,
      runId,
      deadlineAt: startedAt + args.maxDurationMs,
      onTick: (status, phase) => log(`[${slug}] ${status}/${phase}`),
      onPhase0Complete: captureRecon,
      isEngineStopped: () => engine?.isStopped === true,
    })
    notes.push(`personaIdentityFallbacks=${getPersonaIdentityFallbackCount()}`)
    if (recon.requested && !recon.captured && !recon.hit) {
      // The poll can miss a very fast phase transition; recapture from the same boundary.
      // createdAt filters keep investigation/verification rows out either way.
      const completedAt = storage.run(runId).phase0CompletedAt
      if (completedAt) captureRecon(completedAt)
      else notes.push('recon cache not written: Phase-0 never reported completion')
    }
    if (wait.timedOut) notes.push(`wall-clock cap reached after ${args.maxDurationMs}ms; run stopped`)
    if (wait.status !== 'complete') {
      const recent = storage.eventsAfter(runId, 0, 200)
      const last = recent[recent.length - 1]
      notes.push(`terminal status ${wait.status}/${wait.phase}${last ? ` (last event: ${last.kind})` : ''}`)
    }

    const finalRun = storage.run(runId)
    const detail = storage.runDetail(runId)
    const runEvents = collectRunEvents(storage, runId)
    const leadFunnel = summarizeLeadFunnel({
      events: runEvents,
      assignments: detail.assignments,
      steps: detail.chainSteps,
    })
    const requestBudgets = summarizeRequestBudgets({
      events: runEvents,
      spentRequests: finalRun.spentRequests,
      floorRequestBudget: args.floorRequestBudget,
      agentRequestBudget: args.agentRequestBudget,
      totalRequestBudget: finalRun.budgetRequests > 0 ? finalRun.budgetRequests : args.totalRequestBudget,
    })

    // Product contract: only runtime_confirmed findings are submittable evidence. Static,
    // pending-OOB, open-proof-gap and dismissed rows are advisories and must never be graded
    // as confirmed findings (or charged as false positives).
    const verificationClassOf = (f: unknown): string => {
      const v = (f as { verificationStatus?: unknown }).verificationStatus
      return typeof v === 'string' ? v : 'runtime_confirmed'
    }
    const runtimeFindings = detail.findings.filter(f => verificationClassOf(f) === 'runtime_confirmed')
    const advisories = detail.findings.filter(f => verificationClassOf(f) !== 'runtime_confirmed')

    const submitted = translateFindings({
      findings: runtimeFindings,
      replaySpecs: detail.replaySpecs.map(row => ({
        id: row.id,
        findingId: row.findingId,
        spec: row.spec,
        createdAt: row.createdAt,
        verifiedInline: row.verifiedInline,
        lastVerificationDiff: row.lastVerificationDiff,
        proofReceipt: row.proofReceipt,
      })),
      endpoints: detail.endpoints,
      endpointParams: detail.endpointParams,
      exchanges: detail.exchangesSummary.map(ex => ({
        id: ex.id, method: ex.method, pathAndQuery: ex.pathAndQuery,
      })),
      spentUsd: finalRun.spentUsd,
      secrets,
    })

    const telemetry = buildTelemetry({
      runStartedAt,
      runEndedAt: nowMs(),
      spentUsd: finalRun.spentUsd,
      budgetUsd: args.budgetUsd,
      budgetExhausted: wait.timedOut || finalRun.status === 'budget_paused',
    })

    const gradeInput: GradeInput = {
      groundTruth: started.groundTruth,
      findings: submitted,
      oracleEvents: started.oracle.events() as OracleEvent[],
      requestLog: started.oracle.requests() as RequestLogEntry[],
      egressLog: started.oracle.egress(),
      telemetry,
      mode: args.mode,
    }
    const card = gradeRun(gradeInput)
    const endedAt = nowMs()
    // FP evidence must be captured while the store is still open: temp data dirs are removed below.
    const falsePositiveEvidence = buildFalsePositiveEvidence({
      findingIds: [...card.unmatchedFindingIds, ...(card.misclassifiedFindingIds ?? [])],
      findings: detail.findings as unknown as FalsePositiveFindingLike[],
      replaySpecs: detail.replaySpecs as unknown as FalsePositiveSpecLike[],
      exchanges: detail.exchangesSummary,
    }, secrets)
    const requestsOnDiscoveredRoutes = gradeInput.requestLog.filter(req =>
      detail.endpoints.some(ep => endpointMatches(
        { method: req.method, path: req.path },
        { method: ep.method, path: ep.pathTemplate },
      )),
    ).length
    if (model.mode === 'deterministic-no-llm' && requestsOnDiscoveredRoutes === 0) {
      notes.push(
        'deterministic path requested none of the discovered endpoint templates '
        + '(driveInvestigation returns without an LLM profile; Phase-0 only probes its fixed seed list)',
      )
    }

    const failureEvents = storage.eventsAfter(runId, 0, 500)
      .filter(event => event.kind === 'worker.failed' || event.kind === 'worker.canceled')
      .map(event => event.message)
    const assignmentDiagnostics = summarizeAssignments(detail.assignments, failureEvents, secrets)
    const factsCount = detail.facts.length
    const boardMessages = countTableRows(storage, 'board_messages')
    const inert = isInertAgenticRun({
      agentic: model.mode === 'agentic',
      submittedFindings: submitted.length,
      facts: factsCount,
      investigationCompleted: assignmentDiagnostics.investigationCompleted,
    })
    if (inert) {
      notes.push(
        'INERT RUN: agentic mode produced no facts, no submitted findings and no completed investigation assignment; '
        + 'the scorecard below is not evidence of an investigation.',
      )
    }

    const meta: CellMeta = {
      ...(falsePositiveEvidence.length ? { falsePositiveEvidence } : {}),
      app,
      seed,
      seedSet: started.plan.seedSet,
      mode: args.mode,
      origin: briefing.origin,
      loginPath,
      gitSha,
      conventionalWordlist: args.conventionalWordlist,
      wordlistOn: args.conventionalWordlist,
      reportable: !args.conventionalWordlist,
      ...(args.opaqueLabels ? { opaqueLabels: true } : {}),
      model,
      verifierBackend: backendKind,
      ...concurrencyMeta(args),
      maxRpsPerOrigin: args.maxRps,
      leadFunnel,
      requestBudgets,
      workerSessions: capability.supported,
      workerSessionsDetail: capability.detail,
      dataDirIsolated: Boolean(isolated),
      dataDirSource: isolated?.source ?? null,
      isolatedProfileNames: isolated?.profileNames ?? [],
      dataDirKept: Boolean(isolated) && args.keepDataDirs,
      budgetUsd: args.budgetUsd,
      maxDurationMs: args.maxDurationMs,
      reconCache: recon,
      snapshot: snapshotMeta,
      resumedFrom: snapshotMeta.resume.loaded ? snapshotMeta.resume.directory : null,
      snapshotSkippedMs: snapshotMeta.resume.loaded ? snapshotMeta.resume.skippedMs : 0,
      startedAt,
      endedAt,
      durationMs: endedAt - startedAt,
      timedOut: wait.timedOut,
      terminalStatus: wait.status,
      terminalPhase: wait.phase,
      runId,
      projectId,
      findingsPersisted: detail.findings.length,
      runtimeConfirmed: runtimeFindings.length,
      advisories: advisories.length,
      findingsSubmitted: submitted.length,
      baselineChecksExcluded: detail.findings.filter(f => f.findingKind === 'baseline_check').length,
      endpointsDiscovered: detail.endpoints.length,
      endpointParamsDiscovered: detail.endpointParams.length,
      brokerExchanges: detail.exchangesSummary.length,
      requestsOnDiscoveredRoutes,
      assignments: assignmentDiagnostics,
      facts: factsCount,
      boardMessages,
      inert,
      requestCount: gradeInput.requestLog.length,
      oracleEventCount: gradeInput.oracleEvents.length,
      notes,
      shutdown: { engineBusy: -1, appStopped: false, canaryStopped: false },
    }

    storage.insertBenchmarkRun({
      suite: `realistic:${app}:${args.mode}`,
      gitSha,
      modelRoutingConfig: {
        mode: args.mode,
        seed,
        seedSet: started.plan.seedSet,
        llm: model.mode,
        profiles: model.profiles,
        verifierBackend: backendKind,
        cellConcurrency: args.concurrency,
        workerConcurrency: runWorkerConcurrency(args),
        maxRpsPerOrigin: args.maxRps,
        budgetUsd: args.budgetUsd,
        opaqueLabels: args.opaqueLabels,
        requestBudgets,
        timedOut: wait.timedOut,
        reconCache: recon.requested
          ? { key: recon.key, hit: recon.hit, refreshed: args.refreshRecon, phase0Skipped: recon.phase0Skipped }
          : null,
        snapshot: {
          capture: snapshotMeta.capture.requested
            ? {
                directory: snapshotMeta.capture.directory,
                captured: snapshotMeta.capture.captured,
                checkpoints: snapshotMeta.capture.checkpoints,
              }
            : null,
          resume: snapshotMeta.resume.requested
            ? {
                loaded: snapshotMeta.resume.loaded,
                directory: snapshotMeta.resume.directory,
                capturedAt: snapshotMeta.resume.capturedAt,
                ageMs: snapshotMeta.resume.ageMs,
                skippedMs: snapshotMeta.resume.skippedMs,
                phase0Skipped: snapshotMeta.resume.phase0Skipped,
                heldOut: snapshotMeta.resume.seedSet === 'held-out',
              }
            : null,
        },
      },
      targetsTotal: card.targets,
      confirmedCount: card.confirmed,
      falsePositiveCount: card.decoyFalsePositives + card.unmatchedFalsePositives,
      funnelCounts: card.funnel,
      failureTaxonomy: card.failureBuckets,
      totalCostUsd: card.totalCostUsd,
      durationMs: endedAt - startedAt,
    })

    const { benchmarkVersion } = computeBenchmarkVersion('realistic-bench')
    const observedEffectiveConfig = extractObservedEffectiveConfig(runEvents)
    const cfgResolved = resolveObservedEffectiveConfigForRunner({
      observed: observedEffectiveConfig,
      deterministicOnly: args.noLlm,
      environment: 'local-lab',
      approvalPolicy: 'auto_review',
      wordlistOn: args.conventionalWordlist,
      verifierBackend: backendKind,
      mode: args.mode,
      workerImageId: workerImage?.imageId ?? null,
      workerSourceHash: workerImage?.sourceHash ?? null,
      sdkVersion: VERIFY_RPC_SDK_VERSION,
      opaqueLabels: args.opaqueLabels,
    })
    if (!cfgResolved.observed) {
      notes.push('missing observed run.effective_config event (Execution-backed scorer requires observed config)')
    }
    const { effectiveConfigHash, effectiveConfig } = cfgResolved
    const versionStamp = { benchmarkVersion, effectiveConfigHash }
    const metaRec = meta as unknown as Record<string, unknown>
    metaRec.benchmarkVersion = benchmarkVersion
    metaRec.effectiveConfigHash = effectiveConfigHash
    metaRec.effectiveConfigObserved = cfgResolved.observed
    if (effectiveConfig) metaRec.effectiveConfig = effectiveConfig
    metaRec.workerImageId = workerImage?.imageId ?? effectiveConfig?.workerImageId ?? null
    metaRec.workerSourceHash = workerImage?.sourceHash ?? effectiveConfig?.workerSourceHash ?? null
    metaRec.sdkVersion = effectiveConfig?.sdkVersion ?? VERIFY_RPC_SDK_VERSION
    metaRec.status = meta.inert || !cfgResolved.observed ? 'INVALID' : 'VALID'
    metaRec.reportable = !args.conventionalWordlist && !meta.inert && cfgResolved.observed

    const jsonPath = join(args.outDir, `${slug}.json`)
    const mdPath = join(args.outDir, `${slug}.md`)
    const metaPath = join(args.outDir, `${slug}.meta.json`)
    writeFileSync(jsonPath, `${JSON.stringify(withScorecardVersion(
      withScorecardReportability(
        withFalsePositiveEvidence(
          card as unknown as Record<string, unknown>,
          falsePositiveEvidence,
        ),
        args.conventionalWordlist,
      ),
      versionStamp,
    ), null, 2)}\n`, { mode: 0o600 })
    writeFileSync(mdPath, `${renderScorecard(card, 'md')}\n`, { mode: 0o600 })
    if (!args.noLedger) {
      const gitState = resolveGitState()
      writeRealisticCellLedgerRow({
        scorecard: card,
        app,
        split: started.plan.seedSet,
        mode: args.mode,
        llm: model.mode === 'agentic' ? 'agentic' : 'deterministic-no-llm',
        seed,
        recordedAt: new Date(endedAt).toISOString(),
        gitSha: gitState.gitSha,
        dirty: gitState.dirty,
        benchmarkVersion,
        effectiveConfigHash,
        effectiveConfig,
        observedEffectiveConfig: cfgResolved.observed,
        inert: meta.inert,
        conventionalWordlist: args.conventionalWordlist,
        durationMs: endedAt - startedAt,
        workerImageId: workerImage?.imageId ?? effectiveConfig?.workerImageId ?? null,
        workerSourceHash: workerImage?.sourceHash ?? effectiveConfig?.workerSourceHash ?? null,
        sdkVersion: effectiveConfig?.sdkVersion ?? VERIFY_RPC_SDK_VERSION,
        opaqueLabels: args.opaqueLabels,
        promoteLedgerPath: args.ledgerPath,
      })
    }

    return { meta, scorecard: card, jsonPath, mdPath, metaPath }
  } finally {
    // Always tear down: engine first (aborts workers + canary), then the app, then the store.
    let engineBusy = -1
    if (engine) {
      try { engineBusy = await stopEngine(engine) } catch { engineBusy = -1 }
    }
    if (backend instanceof LinuxWorkerBackend) {
      try { await backend.reclaimInactive() } catch { /* best-effort */ }
    }
    try { await canary.stopListener(); canaryStopped = true } catch { canaryStopped = false }
    if (started) {
      try { await started.stop(); appStopped = true } catch { appStopped = false }
    }
    if (whiteBoxRoot) {
      try { unlockAndRemove(whiteBoxRoot) } catch { /* best-effort */ }
    }
    try { storage.close() } catch { /* already closed */ }
    releaseCredentialsDir?.()
    if (isolated && !args.keepDataDirs) {
      try { unlockAndRemove(dataDir) } catch { /* best-effort */ }
    }
    if (engineBusy > 0) process.stderr.write(`warning: ${engineBusy} execution task(s) still active after stop for ${slug}\n`)
    if (!appStopped && started) process.stderr.write(`warning: realistic app for ${slug} did not report a clean stop\n`)
    // runCell builds meta before teardown, so publish the shutdown result for finalizeCellResult.
    shutdownState.set(slug, { engineBusy, appStopped, canaryStopped })
    secrets.length = 0
  }
}

// `runCell` computes meta before teardown, so the caller patches shutdown info in.
const shutdownState = new Map<string, { engineBusy: number; appStopped: boolean; canaryStopped: boolean }>()

export function finalizeCellResult(result: CellResult): CellResult {
  const state = shutdownState.get(cellSlug(result.meta.app, result.meta.seed, result.meta.mode))
  if (state) result.meta.shutdown = state
  const safe = redactJsonValue(result.meta, [])
  writeFileSync(result.metaPath, `${JSON.stringify(safe, null, 2)}\n`, { mode: 0o600 })
  return result
}

// ---------------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------------

export function cellKeys(args: RealisticArgs): Array<{ app: AppName; seed: number }> {
  const cells: Array<{ app: AppName; seed: number }> = []
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

function writeSummary(outDir: string, results: CellResult[]): void {
  const cards = results.map(r => r.scorecard)
  const wordlistOn = results.some(r => r.meta.wordlistOn)
  const firstMeta = results[0]?.meta as unknown as Record<string, unknown> | undefined
  const benchmarkVersion = typeof firstMeta?.benchmarkVersion === 'string'
    ? firstMeta.benchmarkVersion
    : computeBenchmarkVersion('realistic-bench').benchmarkVersion
  const effectiveConfigHash = typeof firstMeta?.effectiveConfigHash === 'string'
    ? firstMeta.effectiveConfigHash
    : MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH
  const rendered = renderScorecard(cards, 'json')
  try {
    const parsed = JSON.parse(rendered) as unknown
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      writeFileSync(
        join(outDir, 'summary.json'),
        `${JSON.stringify(withScorecardVersion(
          withScorecardReportability(parsed as Record<string, unknown>, wordlistOn),
          { benchmarkVersion, effectiveConfigHash },
        ), null, 2)}\n`,
        { mode: 0o600 },
      )
    } else {
      writeFileSync(join(outDir, 'summary.json'), `${rendered}\n`, { mode: 0o600 })
    }
  } catch {
    writeFileSync(join(outDir, 'summary.json'), `${rendered}\n`, { mode: 0o600 })
  }
  writeFileSync(join(outDir, 'summary.md'), `${renderScorecard(cards, 'md')}\n`, { mode: 0o600 })
}

function printSummary(results: CellResult[]): void {
  const pct = (n: number | null) => (n === null ? 'n/a' : `${(n * 100).toFixed(1)}%`)
  const lines = ['', 'cell                             recall     precision  decoyFP  unmatchedFP  chain   budget', '-'.repeat(100)]
  for (const r of results) {
    const c = r.scorecard
    const label = cellSlug(r.meta.app, r.meta.seed, r.meta.mode).padEnd(32)
    lines.push(
      `${label} ${`${c.confirmed}/${c.targets}`.padEnd(9)} ${pct(c.precision).padEnd(10)} ${String(c.decoyFalsePositives).padEnd(8)} ${String(c.unmatchedFalsePositives).padEnd(12)} ${`${c.chainsCompleted}/${c.chainsTotal}`.padEnd(7)} $${c.totalCostUsd.toFixed(4)}`,
    )
  }
  const totalTargets = results.reduce((n, r) => n + r.scorecard.targets, 0)
  const totalConfirmed = results.reduce((n, r) => n + r.scorecard.confirmed, 0)
  lines.push('-'.repeat(100))
  lines.push(`TOTAL confirmed ${totalConfirmed}/${totalTargets} (${pct(totalTargets ? totalConfirmed / totalTargets : 0)}) over ${results.length} cell(s)`)
  process.stdout.write(`${lines.join('\n')}\n`)
}

async function main(): Promise<void> {
  const args = parseRealisticArgs(process.argv.slice(2))
  if (args.help) {
    process.stdout.write(usage)
    return
  }
  assertLocalLabAllowed()
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })

  const cells = cellKeys(args)
  process.stdout.write(`[realistic-bench] ${cells.length} cell(s): ${cells.map(c => `${c.app}@${c.seed}`).join(', ')} mode=${args.mode} budget=$${args.budgetUsd} cells-in-parallel=${args.concurrency} workers-per-cell=${runWorkerConcurrency(args)}\n`)

  const results = await runWithConcurrency(cells, args.concurrency, async ({ app, seed }) => {
    process.stdout.write(`[realistic-bench] starting ${app} seed=${seed} ${args.mode}\n`)
    const result = finalizeCellResult(await runCell(args, app, seed, line => process.stdout.write(`${line}\n`)))
    const c = result.scorecard
    const precText = c.precision === null ? 'n/a' : `${(c.precision * 100).toFixed(1)}%`
    process.stdout.write(`[realistic-bench] finished ${app} seed=${seed}: ${c.confirmed}/${c.targets} confirmed, precision ${precText}, ${result.meta.durationMs}ms${result.meta.inert ? ' [INERT]' : ''}${result.meta.reconCache.requested ? ` recon=${result.meta.reconCache.hit ? 'hit' : 'miss'} saved=${result.meta.reconCache.reconTimeSavedMs}ms` : ''}${result.meta.resumedFrom ? ` resumed=yes skipped=${result.meta.snapshotSkippedMs}ms` : ''}${result.meta.snapshot.capture.requested ? ` snapshot=${result.meta.snapshot.capture.captured ? result.meta.snapshot.capture.checkpoints.join('+') : 'not-captured'}` : ''}\n`)
    return result
  })

  const failed = results.filter((r): r is { error: Error; item: { app: AppName; seed: number } } => 'error' in r)
  const ok = results.filter((r): r is CellResult => !('error' in r))
  if (ok.length) {
    writeSummary(args.outDir, ok)
    printSummary(ok)
    process.stdout.write(`\nwrote ${join(args.outDir, 'summary.json')}\n`)
  }
  let exitCode = 0
  for (const failure of failed) {
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
  if (exitCode) process.exitCode = exitCode
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  main()
    .then(() => {
      // The engine can leave timers/server handles open after a completed cell; artifacts are
      // already flushed, so exit deterministically instead of lingering as an orphan run.
      setImmediate(() => process.exit(process.exitCode ?? 0))
    })
    .catch((error) => {
      process.stderr.write(`error: ${(error as Error).message}\n`)
      process.exit(Number((error as { exitCode?: number }).exitCode ?? 1))
    })
}
