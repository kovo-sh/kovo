#!/usr/bin/env node
// Guardian v5 M0 — true end-to-end `realistic-bench` harness.
//
// Drives Guardian's REAL `Execution` orchestrator (Phase-0 recon → threat model →
// investigation → Zero-LLM replay verification) against a materialized
// `benchmarks/realistic-bench` app, then grades the persisted findings with the
// benchmark's immutable grader.
//
// It deliberately does NOT touch `scripts/benchmark-probes.ts`,
// `scripts/benchmark-specs*.ts` or `benchmarks/realistic-bench/guardian-adapter.ts`
// (the procedural pipeline). The only benchmark inputs are `startRealisticApp`,
// `briefingFor`, `gradeRun` and `renderScorecard`.
//
// Usage:
//   GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- \
//     --app acme-saas --seed 1 --mode grey-box --budget-usd 5 \
//     --out-dir /tmp/rb-v4-base
//
// Held-out seeds (>= 1_000_000) additionally require GUARDIAN_RB_HELDOUT_SALT
// (>= 16 chars). The salt is read from the environment only and is never written
// to an artifact.
//
// Model usage: a fresh per-cell data directory has no provider profile, so the
// run is deterministic/Zero-LLM (`Execution` stops after threat model because it
// has no investigator). Point `--data-dir` at a Guardian data directory that has
// an enabled model profile to run the full agentic loop. `--no-llm` refuses to
// run when such a profile is present. The selected model mode is always recorded
// in the artifact metadata; results are never simulated.

import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync,
  symlinkSync, writeFileSync,
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
import type { EndpointSource, Finding, ParamLocation } from '../src/domain.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { resolveOobCallbackPorts } from './benchmark-env.ts'
import { Execution } from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { privateModelProfiles } from '../src/server/model-settings.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import type { NamedSecret } from '../src/server/redact.ts'
import { redact, redactJsonValue } from '../src/server/redact.ts'
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
import { selectVerifierBackend } from './benchmark-backend.ts'
import type { VerifierBackendKind } from './benchmark-backend.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

export const DEFAULT_BUDGET_USD = 5
export const DEFAULT_MAX_DURATION_MS = 15 * 60_000
export const DEFAULT_CONCURRENCY = 1

export interface RealisticArgs {
  apps: AppName[]
  seeds: number[]
  mode: BenchMode
  heldOut: boolean
  budgetUsd: number
  maxDurationMs: number
  outDir: string
  concurrency: number
  dataDir?: string
  noLlm: boolean
  /** Conventional noun/action route wordlists (local-lab convenience). Default ON. */
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
  help: boolean
}

const usage = `Guardian realistic-bench (real Execution loop)

Usage:
  GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- [flags]

Flags:
  --app <name|all>        acme-saas | shopflow | opsportal | all (default: all)
  --seed <n>              single dev seed (1..9999)
  --seeds <a,b,c>         comma-separated seeds
  --held-out              seeds are held-out (>= 1000000) and need GUARDIAN_RB_HELDOUT_SALT
  --mode <m>              black-box | grey-box | white-box (default: grey-box)
  --budget-usd <n>        per-run USD budget (default: ${DEFAULT_BUDGET_USD})
  --max-duration-ms <n>   wall-clock cap per cell (default: ${DEFAULT_MAX_DURATION_MS})
  --out-dir <path>        artifact directory (default: .guardian/realistic-bench)
  --concurrency <n>       parallel app/seed cells (default: ${DEFAULT_CONCURRENCY})
  --data-dir <path>       Guardian data dir (single cell: used verbatim, so an
                          existing model profile is picked up; multi-cell: base
                          directory, one isolated child dir per cell)
                          (default: $GUARDIAN_DATA_DIR or <out-dir>/data/<cell>)
  --no-llm                force the deterministic/Zero-LLM path; the run uses an
                          isolated data dir and never loads a model profile
  --no-conventional-wordlist
                          run the deterministic engine without the conventional
                          noun/action route wordlist (local-lab convenience). Only
                          target-discovered/declared surface is probed.
  --isolate-data-dir      per-cell data dir initialized from --data-dir: copies only
                          enabled model_profiles rows and symlinks credentials/
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
  --help                  show this help

Environment:
  GUARDIAN_ALLOW_LOCAL_LAB=1   required to boot loopback lab origins
  GUARDIAN_RB_HELDOUT_SALT     required for --held-out (never logged/committed)
  GUARDIAN_DATA_DIR            default Guardian data dir (model profile source)

Parallel agentic matrix:
  --concurrency 3 --isolate-data-dir  gives each cell its own Store under
  <out-dir>/data/<cell>/ with copied profile metadata and a credentials symlink,
  so cells never contend for the source data-dir lock. The key is never copied.

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
  --snapshot-after-floor <dir> captures <dir>/guardian.sqlite (VACUUM INTO),
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
    'out-dir', 'concurrency', 'data-dir', 'no-llm', 'no-conventional-wordlist', 'isolate-data-dir', 'keep-data-dirs',
    'allow-inert-workers', 'verifier', 'reuse-recon', 'refresh-recon', 'help',
    'snapshot-after-floor', 'resume-snapshot', 'snapshot-max-age-ms', 'snapshot-refresh',
    'allow-heldout-snapshot',
  ])
  for (const key of Object.keys(a)) {
    if (!known.has(key)) fail(`unknown flag --${key}`)
  }

  if (a.help === true) {
    return {
      apps: [...appNames], seeds: [1], mode: 'grey-box', heldOut: false,
      budgetUsd: DEFAULT_BUDGET_USD, maxDurationMs: DEFAULT_MAX_DURATION_MS,
      outDir: resolve('.guardian/realistic-bench'), concurrency: DEFAULT_CONCURRENCY,
      noLlm: Boolean(a['no-llm']), isolateDataDir: Boolean(a['isolate-data-dir']),
      conventionalWordlist: a['no-conventional-wordlist'] !== true,
      keepDataDirs: Boolean(a['keep-data-dirs']),
      allowInertWorkers: Boolean(a['allow-inert-workers']),
      verifier: 'auto', refreshRecon: a['refresh-recon'] === true, help: true,
      snapshotMaxAgeMs: DEFAULT_SNAPSHOT_MAX_AGE_MS,
      snapshotRefresh: false, allowHeldoutSnapshot: false,
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
  const salt = env.GUARDIAN_RB_HELDOUT_SALT ?? ''
  if (heldOut) {
    if (salt.length < 16) fail('--held-out requires GUARDIAN_RB_HELDOUT_SALT (>= 16 chars)')
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
    : parsePositiveInt(stringFlag(a, 'max-duration-ms') ?? '', '--max-duration-ms')
  const concurrency = a.concurrency === undefined
    ? DEFAULT_CONCURRENCY
    : parsePositiveInt(stringFlag(a, 'concurrency') ?? '', '--concurrency')
  const outDirRaw = stringFlag(a, 'out-dir') ?? '.guardian/realistic-bench'
  const dataDirRaw = stringFlag(a, 'data-dir') ?? env.GUARDIAN_DATA_DIR
  const noLlm = a['no-llm'] === true
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
    outDir: isAbsolute(outDirRaw) ? outDirRaw : resolve(outDirRaw),
    concurrency,
    ...(dataDirRaw ? { dataDir: isAbsolute(dataDirRaw) ? dataDirRaw : resolve(dataDirRaw) } : {}),
    noLlm,
    conventionalWordlist: a['no-conventional-wordlist'] !== true,
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
export function planCell(briefing: Briefing, loginPath: string | null): CellPlan {
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

function specParams(spec: unknown): string[] {
  const names = new Set<string>()
  const visit = (node: unknown, depth: number): void => {
    if (!node || typeof node !== 'object' || depth > 8) return
    if (Array.isArray(node)) { for (const item of node) visit(item, depth + 1); return }
    const rec = node as Record<string, unknown>
    if (typeof rec.paramName === 'string') names.add(rec.paramName)
    for (const key of ['params', 'jsonBody', 'formFields', 'variables']) {
      const value = rec[key]
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        for (const name of Object.keys(value as Record<string, unknown>)) names.add(name)
      }
    }
    for (const value of Object.values(rec)) if (value && typeof value === 'object') visit(value, depth + 1)
  }
  visit(spec, 0)
  return [...names].filter(n => /^[A-Za-z0-9_.\-[\]]{1,128}$/.test(n)).slice(0, 24)
}

/**
 * Translate persisted Guardian findings into the benchmark grader schema.
 * Confirmed -> runtime_confirmed, static_verified -> static_verified; pending /
 * inconclusive claims are preserved as proposed/open_proof_gap so the precision
 * denominator reflects what was actually submitted. Dismissed and superseded
 * rows are dropped (the grader treats those as ruled_out).
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
  const paramsByEndpoint = new Map<string, string[]>()
  for (const p of input.endpointParams ?? []) {
    const list = paramsByEndpoint.get(p.endpointId) ?? []
    list.push(p.name)
    paramsByEndpoint.set(p.endpointId, list)
  }

  const out: SubmittedFinding[] = []
  for (const finding of input.findings) {
    // Baseline hygiene checks (HSTS/CSP/XFO/...) are not vulnerability claims and have no
    // realistic-bench ground-truth counterpart; submitting them would be pure FP noise.
    if (finding.findingKind === 'baseline_check') continue
    if (finding.status === 'dismissed') continue
    if (finding.supersededByFindingId) continue
    const specs = specsByFinding.get(finding.id) ?? []
    const endpoints: ExtractedEndpoint[] = []
    const params = new Set<string>()
    for (const spec of specs.slice(0, 3)) {
      for (const ep of endpointsFromReplaySpec(spec.spec)) endpoints.push(ep)
      for (const name of specParams(spec.spec)) params.add(name)
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
    for (const ep of clean) {
      for (const row of input.endpoints ?? []) {
        if (!endpointMatches(ep, { method: row.method, path: row.pathTemplate })) continue
        for (const name of paramsByEndpoint.get(row.id) ?? []) params.add(name)
      }
    }

    const status: SubmittedFinding['status'] = finding.status === 'confirmed'
      ? 'runtime_confirmed'
      : finding.status === 'static_verified'
        ? 'static_verified'
        : finding.status === 'pending'
          ? 'proposed'
          : 'open_proof_gap'

    const submittedAtMs = specs[0]?.createdAt ?? now
    const severity = finding.severity === 'informational' ? 'low' : finding.severity
    out.push({
      id: finding.id,
      title: redact(finding.title, input.secrets ?? []).slice(0, 200),
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
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
  // Guardian does not persist a chain-step -> concrete path mapping, so the harness
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
}

/**
 * Fail fast instead of producing an inert run: a model profile will send work to
 * specialist workers, and only a worker-session-capable backend (docker) can run them.
 */
export function assertAgenticPreflight(input: AgenticPreflightInput): void {
  if (!input.hasProfiles || input.noLlm || input.allowInertWorkers) return
  if (input.workerSessions) return
  const detail = input.workerSessionsDetail ? ` (${input.workerSessionsDetail})` : ''
  if (input.backendKind === 'docker') {
    throw new PreflightError(
      `agentic Execution requires a worker-session-capable verifier backend; --verifier docker could not open a worker session${detail}. `
      + 'Docker worker sessions need socket access: re-run under `newgrp docker -c \'<command>\'` and verify '
      + '`docker images` contains guardian-worker:v4.',
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

function countTableRows(storage: Store, table: string): number {
  try {
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
    if (/Another Guardian server is using this data directory/.test(message)) {
      throw new PreflightError(
        `${message} Parallel cells need isolated stores: add --isolate-data-dir `
        + '(it is on by default when --concurrency > 1) or use a distinct --data-dir per cell.',
      )
    }
    throw error
  }
}

export interface IsolatedDataDirResult {
  directory: string
  source: string
  profileNames: string[]
}

/** Per-cell isolation is explicit, or implicit for a parallel matrix with a source data dir. */
export function shouldIsolateDataDir(args: Pick<RealisticArgs, 'isolateDataDir' | 'concurrency' | 'dataDir' | 'noLlm'>): boolean {
  return Boolean(!args.noLlm && args.dataDir && (args.isolateDataDir || args.concurrency > 1))
}

/**
 * Create a per-cell Guardian Store from a source data dir without copying the key:
 * only enabled model_profiles rows + the workspace identity are copied; credentials/
 * becomes a symlink to the source credentials dir.
 */
export function prepareIsolatedDataDir(input: { sourceDataDir: string; targetDir: string }): IsolatedDataDirResult {
  const source = resolve(input.sourceDataDir)
  const target = resolve(input.targetDir)
  const sourceDb = join(source, 'guardian.sqlite')
  const sourceCredentials = join(source, 'credentials')
  if (!existsSync(sourceDb)) throw new PreflightError(`--isolate-data-dir source has no guardian.sqlite: ${source}`)
  if (!existsSync(sourceCredentials)) throw new PreflightError(`--isolate-data-dir source has no credentials dir: ${source}`)

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

    for (const row of rows) {
      const credentialPath = join(sourceCredentials, String(row.credential_id))
      let mode: number
      try {
        const info = statSync(credentialPath)
        if (!info.isFile()) throw new Error('not a file')
        mode = info.mode
      } catch {
        throw new PreflightError(`profile '${String(row.name)}' has no readable credential file in the source data dir`)
      }
      if ((mode & 0o077) !== 0) {
        throw new PreflightError(`profile '${String(row.name)}' credential must be owner-only (mode 600)`)
      }
    }

    storage = new Store(target)
    storage.close()
    storage = undefined

    // Replace the auto-created workspace with the source workspace row, then bind the
    // copied profile rows to it. Only workspace identity + profile metadata move; keys do not.
    const targetClient = new DatabaseSync(join(target, 'guardian.sqlite'))
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

    // Never copy keys: make the isolated credentials dir a symlink to the source dir.
    rmSync(join(target, 'credentials'), { recursive: true, force: true })
    symlinkSync(sourceCredentials, join(target, 'credentials'), 'dir')

    const profileNames = rows.map(row => String(row.name))
    return { directory: target, source, profileNames }
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
  if (path.includes('.guardian-cal-')) return null // soft-404 calibration tokens
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
 * Link the snapshot's model profile credential files from the source data dir into the fresh
 * resume data dir. The provider key is never copied; only an owner-only symlink is created, the
 * same invariant `prepareIsolatedDataDir` uses. Persona credentials are written separately.
 */
export function linkSnapshotModelCredentials(input: {
  snapshotDb: string
  sourceDataDir?: string
  targetDataDir: string
}): { profiles: number; linked: number } {
  const snapshot = new DatabaseSync(input.snapshotDb, { readOnly: true })
  let rows: Array<{ credential_id?: string; name?: string; model?: string }> = []
  try {
    rows = snapshot.prepare(
      'select credential_id, name, model from model_profiles where enabled = 1 order by priority desc, updated_at desc',
    ).all() as Array<{ credential_id?: string; name?: string; model?: string }>
  } catch {
    rows = []
  } finally {
    snapshot.close()
  }
  if (!rows.length) return { profiles: 0, linked: 0 }
  if (!input.sourceDataDir) {
    throw new PreflightError(
      '--resume-snapshot needs --data-dir (or GUARDIAN_DATA_DIR) pointing at the enabled model '
      + 'profile whose key the resumed run must use',
    )
  }
  const sourceCredentials = join(resolve(input.sourceDataDir), 'credentials')
  const targetCredentials = join(resolve(input.targetDataDir), 'credentials')
  mkdirSync(targetCredentials, { recursive: true, mode: 0o700 })

  // Fall back to matching the profile by name/model when the source credential id differs
  // (e.g. the checkpoint came from a different isolated copy of the same profile).
  let sourceRows: Array<{ credential_id?: string; name?: string; model?: string }> = []
  const sourceDb = join(resolve(input.sourceDataDir), 'guardian.sqlite')
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

  let linked = 0
  for (const row of rows) {
    const id = row.credential_id ? String(row.credential_id) : ''
    if (!id) continue
    let sourcePath = join(sourceCredentials, id)
    if (!existsSync(sourcePath)) {
      const match = sourceRows.find(candidate =>
        candidate.credential_id && candidate.name === row.name && candidate.model === row.model)
      if (match?.credential_id) sourcePath = join(sourceCredentials, String(match.credential_id))
    }
    if (!existsSync(sourcePath)) {
      throw new PreflightError(
        `profile '${String(row.name ?? id)}' has no credential file in ${sourceCredentials}; `
        + 'resume needs the same --data-dir source that captured the checkpoint',
      )
    }
    const mode = statSync(sourcePath).mode
    if ((mode & 0o077) !== 0) {
      throw new PreflightError(`profile '${String(row.name ?? id)}' credential must be owner-only (mode 600)`)
    }
    const targetPath = join(targetCredentials, id)
    if (!existsSync(targetPath)) {
      symlinkSync(sourcePath, targetPath)
      linked += 1
    }
  }
  return { profiles: rows.length, linked }
}

export interface CellMeta {
  app: AppName
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: BenchMode
  /** Effective conventional noun/action route wordlist switch for the deterministic engine. */
  conventionalWordlist: boolean
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

async function waitForTerminal(input: {
  storage: Store
  runId: string
  deadlineAt: number
  onTick?: (status: string, phase: string) => void
  /** Fired once, on the first poll that observes the engine's Phase-0 completion marker. */
  onPhase0Complete?: (completedAt: number) => void
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
  // GUARDIAN_DETERMINISTIC_ENGINE). Record the effective value in cell meta as well.
  if (args.conventionalWordlist) delete process.env.GUARDIAN_CONVENTIONAL_WORDLIST
  else process.env.GUARDIAN_CONVENTIONAL_WORDLIST = '0'
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
      snapshotDb: join(dataDir, 'guardian.sqlite'),
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
  let started: StartedApp | undefined
  let engine: Execution | undefined
  let backend: WorkerBackend | undefined
  let backendKind: VerifierBackendKind = 'local-jq'
  let appStopped = false
  let canaryStopped = false
  let whiteBoxRoot: string | undefined
  if (args.isolateDataDir && !sourceDataDir && !args.noLlm) {
    notes.push('--isolate-data-dir had no --data-dir/GUARDIAN_DATA_DIR source; using a fresh cell data dir')
  }
  if (isolated) {
    notes.push(
      `isolated data dir from ${isolated.source}; profile(s): ${isolated.profileNames.join(', ')}; credentials symlinked (key not copied)`,
    )
  }

  const secrets: NamedSecret[] = []
  let runId = ''
  let projectId = ''
  let runStartedAt = startedAt

  try {
    // --- Preflight (before booting the app): model mode + real worker-session capability ---
    let profiles: ResolvedModelProfile[] = []
    try {
      profiles = privateModelProfiles(storage)
    } catch (error) {
      notes.push(`model profile lookup failed: ${redact((error as Error).message).slice(0, 160)}`)
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
            + 're-run under `newgrp docker -c \'<command>\'` and make sure guardian-worker:v4 is built.',
          )
        }
        throw error
      }
    })()
    backendKind = selected.kind
    backend = selected.kind === 'docker'
      // Tag containers with this workspace so a crashed run can be reclaimed, and so the
      // harness leaves zero orphan containers after stop.
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
      ...(args.heldOut ? { heldOutSalt: process.env.GUARDIAN_RB_HELDOUT_SALT } : {}),
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
    const plan = planCell(briefing, loginPath)
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

    const wait = await waitForTerminal({
      storage,
      runId,
      deadlineAt: startedAt + args.maxDurationMs,
      onTick: (status, phase) => log(`[${slug}] ${status}/${phase}`),
      onPhase0Complete: captureRecon,
    })
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

    const submitted = translateFindings({
      findings: detail.findings,
      replaySpecs: detail.replaySpecs.map(row => ({
        id: row.id, findingId: row.findingId, spec: row.spec, createdAt: row.createdAt,
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
      app,
      seed,
      seedSet: started.plan.seedSet,
      mode: args.mode,
      origin: briefing.origin,
      loginPath,
      gitSha,
      conventionalWordlist: args.conventionalWordlist,
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
        budgetUsd: args.budgetUsd,
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

    const jsonPath = join(args.outDir, `${slug}.json`)
    const mdPath = join(args.outDir, `${slug}.md`)
    const metaPath = join(args.outDir, `${slug}.meta.json`)
    writeFileSync(jsonPath, `${renderScorecard(card, 'json')}\n`, { mode: 0o600 })
    writeFileSync(mdPath, `${renderScorecard(card, 'md')}\n`, { mode: 0o600 })

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
  writeFileSync(join(outDir, 'summary.json'), `${renderScorecard(cards, 'json')}\n`, { mode: 0o600 })
  writeFileSync(join(outDir, 'summary.md'), `${renderScorecard(cards, 'md')}\n`, { mode: 0o600 })
}

function printSummary(results: CellResult[]): void {
  const pct = (n: number) => `${(n * 100).toFixed(1)}%`
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
  process.stdout.write(`[realistic-bench] ${cells.length} cell(s): ${cells.map(c => `${c.app}@${c.seed}`).join(', ')} mode=${args.mode} budget=$${args.budgetUsd}\n`)

  const results = await runWithConcurrency(cells, args.concurrency, async ({ app, seed }) => {
    process.stdout.write(`[realistic-bench] starting ${app} seed=${seed} ${args.mode}\n`)
    const result = finalizeCellResult(await runCell(args, app, seed, line => process.stdout.write(`${line}\n`)))
    const c = result.scorecard
    process.stdout.write(`[realistic-bench] finished ${app} seed=${seed}: ${c.confirmed}/${c.targets} confirmed, precision ${(c.precision * 100).toFixed(1)}%, ${result.meta.durationMs}ms${result.meta.inert ? ' [INERT]' : ''}${result.meta.reconCache.requested ? ` recon=${result.meta.reconCache.hit ? 'hit' : 'miss'} saved=${result.meta.reconCache.reconTimeSavedMs}ms` : ''}${result.meta.resumedFrom ? ` resumed=yes skipped=${result.meta.snapshotSkippedMs}ms` : ''}${result.meta.snapshot.capture.requested ? ` snapshot=${result.meta.snapshot.capture.captured ? result.meta.snapshot.capture.checkpoints.join('+') : 'not-captured'}` : ''}\n`)
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
  main().catch((error) => {
    process.stderr.write(`error: ${(error as Error).message}\n`)
    process.exit(Number((error as { exitCode?: number }).exitCode ?? 1))
  })
}
