// v5.1 snapshot/resume checkpointing for the *product* harness.
//
// A hill-climb iteration pays ~240 s of recon + deterministic floor before the first agentic
// assignment. This module captures a phase/assignment/planner-round boundary as:
//
//   <snapshot-dir>/kovo.sqlite   VACUUM INTO copy of the run DB (WAL-safe, consistent)
//   <snapshot-dir>/snapshot.json     typed coordinator state + version stamps (redacted)
//   <snapshot-dir>/target.json       rehydration spec (app/seed/mode/mutating log, redacted)
//
// Resume copies the DB into a fresh data dir, rebinds loopback origins/ports to the freshly
// booted app + canary listener, recreates persona login credentials (fresh sessions), and lets
// the normal scheduler start at the phase boundary. Nothing about verification is faked: the
// resumed run keeps the recorded findings/facts/specs and still has to earn any new one.
//
// Security: the directory is 0700, every file is 0600, and snapshot.json/target.json never
// contain cookies, bearer tokens, passwords, canaries or provider keys. The DB copy only holds
// rows the engine already redacted; persona credentials stay in owner-only credential files.

import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { isTerminalStepStatus } from '../step-status.ts'
import { redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'

export const SNAPSHOT_SCHEMA_VERSION = 1
export const SNAPSHOT_ARTIFACT_REGISTRY_VERSION = 1
export const SNAPSHOT_TOOL_CONTRACT_VERSION = 'v5.1'
export const SNAPSHOT_PROMPT_CONTRACT_VERSION = 'v5.1'
export const DEFAULT_SNAPSHOT_MAX_AGE_MS = 24 * 60 * 60_000

export type SnapshotErrorCode =
  | 'SNAPSHOT_NOT_FOUND'
  | 'SNAPSHOT_CORRUPT'
  | 'SNAPSHOT_INCOMPATIBLE'
  | 'SNAPSHOT_EXPIRED'
  | 'SNAPSHOT_HELDOUT_REFUSED'
  | 'SNAPSHOT_CAPTURE_FAILED'

export class SnapshotError extends Error {
  readonly code: SnapshotErrorCode
  constructor(code: SnapshotErrorCode, message: string) {
    super(`${code}: ${message}`)
    this.name = 'SnapshotError'
    this.code = code
  }
}

export type SnapshotCheckpoint = 'phase0' | 'deterministic-lane' | 'post-floor' | 'planner-round' | 'manual'

export interface SnapshotVersions {
  snapshotSchemaVersion: number
  dbMigrationVersion: string
  artifactRegistryVersion: number
  toolContractVersion: string
  gitSha: string
  promptContractVersion?: string
}

export interface MutatingReplayEntry {
  method: string
  pathAndQuery: string
  personaHandle: string | null
  status: number
  /** Redacted, bounded request body preview; never a credential. */
  bodyPreview: string
}

export interface SnapshotTarget {
  app: string
  seed: number
  seedSet: 'dev' | 'held-out'
  mode: string
  /** App origin when the checkpoint was taken; rebound to the fresh boot origin on resume. */
  origin: string
  loginPath: string | null
  /** Canary listener base URLs when the checkpoint was taken; rebound to fresh loopback ports. */
  canaryBaseUrls: string[]
  /** Safe/idempotent mutating requests observed during the run (POST/PUT/PATCH, 2xx only). */
  mutatingReplayLog: MutatingReplayEntry[]
  projectId: string
  runId: string
  capturedAt: number
}

export interface SnapshotArtifactRef {
  id: string
  kind: string
  title: string
}

export interface SnapshotCoordinatorState {
  /**
   * The engine has no persistent artifact registry yet; the field is present so additive
   * registry implementations can populate it without a schema break.
   */
  artifactRegistry: SnapshotArtifactRef[]
  plannerRoundIdx: number
  k6DryStreak: number
  dynamicStepBudget: number | null
  scopeRevision: number
  goalRevision: number
  virtualElapsedMs: number
  spendUsd: number
  deterministicLaneCompleted: boolean
  phase: string
  status: string
  phase0CompletedAt: number | null
  checkpoint: SnapshotCheckpoint
}

export interface SnapshotCounts {
  runs: number
  endpoints: number
  endpointParams: number
  apiDependencies: number
  facts: number
  detLeads: number
  findings: number
  runtimeConfirmed: number
  staticVerified: number
  chainSteps: number
  replaySpecs: number
  boardMembers: number
  boardMessages: number
  secondOrderCanaries: number
  coverageEntries: number
  brokerExchanges: number
}

export interface RunSnapshot {
  versions: SnapshotVersions
  coordinator: SnapshotCoordinatorState
  counts: SnapshotCounts
  security: {
    secretsIncluded: false
    sessionValuesIncluded: false
    note: string
  }
  capturedAt: number
  checksum: string
}

export interface CaptureRunSnapshotInput {
  storage: Store
  snapshotDir: string
  checkpoint: SnapshotCheckpoint
  target: Pick<SnapshotTarget, 'app' | 'seed' | 'seedSet' | 'mode' | 'origin' | 'loginPath' | 'canaryBaseUrls' | 'projectId' | 'runId'>
  gitSha: string
  /** Boundary for the mutating replay log (defaults to the capture instant). */
  mutatingBoundary?: number
  secrets?: readonly NamedSecret[]
  now?: number
}

export interface CaptureRunSnapshotResult {
  snapshotDir: string
  databasePath: string
  snapshotPath: string
  targetPath: string
  snapshot: RunSnapshot
  target: SnapshotTarget
  counts: SnapshotCounts
}

/** Latest applied Drizzle migration name. Used as the DB migration stamp. */
export function currentDbMigrationVersion(): string {
  const folder = resolve('drizzle')
  try {
    const names = readdirSync(folder, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && existsSync(join(folder, entry.name, 'migration.sql')))
      .map(entry => entry.name)
      .sort()
    return names[names.length - 1] ?? 'unknown'
  } catch {
    return 'unknown'
  }
}

function sqlString(value: string): string {
  return `'${value.replaceAll("'", "''")}'`
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex')
}

function writeOwnerOnly(path: string, body: string): void {
  const tmp = `${path}.tmp-${randomUUID()}`
  writeFileSync(tmp, body, { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, path)
}

function tableCount(storage: Store, table: string, where = '', params: unknown[] = []): number {
  try {
    const row = storage.client
      .prepare(`select count(*) as c from ${table}${where ? ` where ${where}` : ''}`)
      .get(...(params as never[])) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  } catch {
    return 0
  }
}

export function collectMutatingReplayLog(
  storage: Store,
  runId: string,
  boundary: number,
): MutatingReplayEntry[] {
  try {
    const rows = storage.client.prepare(
      "select method, path_and_query as pathAndQuery, persona_handle as personaHandle, status, body_preview as bodyPreview "
      + "from broker_exchanges where run_id = ? and method in ('POST', 'PUT', 'PATCH') "
      + 'and status >= 200 and status < 300 and created_at <= ? order by created_at asc limit 100',
    ).all(runId, boundary) as Array<{
      method?: string
      pathAndQuery?: string
      personaHandle?: string | null
      status?: number
      bodyPreview?: string
    }>
    return rows
      .filter(row => typeof row.method === 'string' && typeof row.pathAndQuery === 'string'
        && row.pathAndQuery.startsWith('/') && !row.pathAndQuery.startsWith('//'))
      .slice(0, 100)
      .map(row => ({
        method: String(row.method),
        pathAndQuery: String(row.pathAndQuery).slice(0, 512),
        personaHandle: row.personaHandle ?? null,
        status: Number(row.status ?? 0),
        bodyPreview: String(row.bodyPreview ?? '').slice(0, 2_048),
      }))
  } catch {
    return []
  }
}

function readCounts(storage: Store, runId: string): SnapshotCounts {
  const factsWhere = 'run_id = ?'
  return {
    runs: tableCount(storage, 'runs', 'id = ?', [runId]),
    endpoints: tableCount(storage, 'endpoints', 'run_id = ?', [runId]),
    endpointParams: tableCount(storage, 'endpoint_params', 'run_id = ?', [runId]),
    apiDependencies: tableCount(storage, 'api_dependencies', 'run_id = ?', [runId]),
    facts: tableCount(storage, 'facts', factsWhere, [runId]),
    detLeads: tableCount(storage, 'facts', 'run_id = ? and kind = ?', [runId, 'det_lead']),
    findings: tableCount(storage, 'findings', 'run_id = ?', [runId]),
    runtimeConfirmed: tableCount(storage, 'findings', "run_id = ? and verification_tier = 'runtime_confirmed'", [runId]),
    staticVerified: tableCount(storage, 'findings', "run_id = ? and verification_tier = 'static_verified'", [runId]),
    chainSteps: tableCount(storage, 'chain_steps', 'run_id = ?', [runId]),
    replaySpecs: tableCount(storage, 'replay_specs', 'run_id = ?', [runId]),
    boardMembers: tableCount(storage, 'board_members', 'run_id = ?', [runId]),
    boardMessages: tableCount(storage, 'board_messages', 'run_id = ?', [runId]),
    secondOrderCanaries: tableCount(storage, 'second_order_canaries', 'run_id = ?', [runId]),
    coverageEntries: tableCount(storage, 'coverage_entries', 'run_id = ?', [runId]),
    brokerExchanges: tableCount(storage, 'broker_exchanges', 'run_id = ?', [runId]),
  }
}

function snapshotChecksum(snapshot: Omit<RunSnapshot, 'checksum'>): string {
  return sha256(JSON.stringify(snapshot))
}

/**
 * Capture a checkpoint. Must be called at a phase/planner-round boundary (never mid-turn), and
 * outside an open SQLite transaction (VACUUM INTO cannot run inside one).
 */
export function captureRunSnapshot(input: CaptureRunSnapshotInput): CaptureRunSnapshotResult {
  const now = input.now ?? Date.now()
  // v6 batched writes: flush the exchange queue so VACUUM INTO captures every recorded exchange.
  input.storage.flushNow()
  const run = input.storage.run(input.target.runId)
  const dir = resolve(input.snapshotDir)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)

  const databasePath = join(dir, 'kovo.sqlite')
  const tmpDb = `${databasePath}.tmp-${randomUUID()}`
  try {
    rmSync(tmpDb, { force: true })
    input.storage.client.exec(`VACUUM INTO ${sqlString(tmpDb)}`)
    chmodSync(tmpDb, 0o600)
    renameSync(tmpDb, databasePath)
  } catch (error) {
    try { rmSync(tmpDb, { force: true }) } catch { /* best-effort */ }
    throw new SnapshotError(
      'SNAPSHOT_CAPTURE_FAILED',
      `VACUUM INTO failed: ${(error instanceof Error ? error.message : String(error)).slice(0, 240)}`,
    )
  }

  const counts = readCounts(input.storage, input.target.runId)
  const target: SnapshotTarget = {
    ...input.target,
    canaryBaseUrls: [...input.target.canaryBaseUrls],
    mutatingReplayLog: collectMutatingReplayLog(
      input.storage,
      input.target.runId,
      input.mutatingBoundary ?? now,
    ),
    capturedAt: now,
  }
  const coordinator: SnapshotCoordinatorState = {
    artifactRegistry: [],
    plannerRoundIdx: run.roundNo,
    k6DryStreak: countDrySteps(input.storage, input.target.runId),
    dynamicStepBudget: run.dynamicStepBudget ?? null,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    virtualElapsedMs: Math.max(0, now - run.createdAt),
    spendUsd: run.spentUsd,
    deterministicLaneCompleted: input.checkpoint !== 'phase0',
    phase: run.phase,
    status: run.status,
    phase0CompletedAt: run.phase0CompletedAt ?? null,
    checkpoint: input.checkpoint,
  }
  const versions: SnapshotVersions = {
    snapshotSchemaVersion: SNAPSHOT_SCHEMA_VERSION,
    dbMigrationVersion: currentDbMigrationVersion(),
    artifactRegistryVersion: SNAPSHOT_ARTIFACT_REGISTRY_VERSION,
    toolContractVersion: SNAPSHOT_TOOL_CONTRACT_VERSION,
    gitSha: input.gitSha,
    promptContractVersion: SNAPSHOT_PROMPT_CONTRACT_VERSION,
  }
  const base: Omit<RunSnapshot, 'checksum'> = {
    versions,
    coordinator,
    counts,
    security: {
      secretsIncluded: false,
      sessionValuesIncluded: false,
      note: 'Checkpoint state only: the DB copy holds rows the engine already redacted; snapshot.json/'
        + 'target.json hold coordinator counters and the app/seed/mode rehydration spec. No cookies, '
        + 'session values, bearer tokens, passwords or provider keys are written to either JSON file.',
    },
    capturedAt: now,
  }
  const redactedSnapshot = redactJsonValue(base, input.secrets ?? [])
  const snapshot: RunSnapshot = { ...redactedSnapshot, checksum: snapshotChecksum(redactedSnapshot) }
  const redactedTarget = redactJsonValue(target, input.secrets ?? [])

  const serialized = `${JSON.stringify(snapshot, null, 2)}\n${JSON.stringify(redactedTarget, null, 2)}`
  for (const secret of input.secrets ?? []) {
    if (secret.value && secret.value.length >= 4 && serialized.includes(secret.value)) {
      throw new SnapshotError('SNAPSHOT_CAPTURE_FAILED', 'refusing to write a snapshot containing a registered secret')
    }
  }

  const snapshotPath = join(dir, 'snapshot.json')
  const targetPath = join(dir, 'target.json')
  writeOwnerOnly(snapshotPath, `${JSON.stringify(snapshot, null, 2)}\n`)
  writeOwnerOnly(targetPath, `${JSON.stringify(redactedTarget, null, 2)}\n`)
  chmodSync(databasePath, 0o600)

  return { snapshotDir: dir, databasePath, snapshotPath, targetPath, snapshot, target: redactedTarget, counts }
}

function countDrySteps(storage: Store, runId: string): number {
  try {
    const rows = storage.client.prepare(
      'select status from chain_steps where run_id = ? order by seq desc limit 12',
    ).all(runId) as Array<{ status?: string }>
    let streak = 0
    for (const row of rows) {
      if (isTerminalStepStatus(row.status)) streak += 1
      else break
    }
    return streak
  } catch {
    return 0
  }
}

export interface LoadedRunSnapshot {
  directory: string
  snapshotPath: string
  targetPath: string
  databasePath: string
  snapshot: RunSnapshot
  target: SnapshotTarget
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function readRunSnapshot(directory: string): LoadedRunSnapshot {
  const dir = resolve(directory)
  const snapshotPath = join(dir, 'snapshot.json')
  const targetPath = join(dir, 'target.json')
  const databasePath = join(dir, 'kovo.sqlite')
  if (!existsSync(snapshotPath) || !existsSync(targetPath)) {
    throw new SnapshotError('SNAPSHOT_NOT_FOUND', `no snapshot.json/target.json in ${dir}`)
  }
  if (!existsSync(databasePath)) {
    throw new SnapshotError('SNAPSHOT_NOT_FOUND', `no kovo.sqlite in ${dir}`)
  }
  let snapshotRaw: unknown
  let targetRaw: unknown
  try {
    snapshotRaw = JSON.parse(readFileSync(snapshotPath, 'utf8'))
    targetRaw = JSON.parse(readFileSync(targetPath, 'utf8'))
  } catch (error) {
    throw new SnapshotError('SNAPSHOT_CORRUPT', `unreadable snapshot JSON: ${(error as Error).message.slice(0, 160)}`)
  }
  if (!isRecord(snapshotRaw) || !isRecord(snapshotRaw.versions) || !isRecord(snapshotRaw.coordinator)
    || !isRecord(snapshotRaw.counts) || typeof snapshotRaw.checksum !== 'string') {
    throw new SnapshotError('SNAPSHOT_CORRUPT', 'snapshot.json is missing required fields')
  }
  const snapshot = snapshotRaw as unknown as RunSnapshot
  const { checksum, ...rest } = snapshot
  if (checksum !== snapshotChecksum(rest as Omit<RunSnapshot, 'checksum'>)) {
    throw new SnapshotError('SNAPSHOT_CORRUPT', 'snapshot.json checksum mismatch')
  }
  if (!isRecord(targetRaw) || typeof targetRaw.app !== 'string' || typeof targetRaw.origin !== 'string'
    || typeof targetRaw.runId !== 'string' || typeof targetRaw.projectId !== 'string') {
    throw new SnapshotError('SNAPSHOT_CORRUPT', 'target.json is missing required fields')
  }
  return {
    directory: dir,
    snapshotPath,
    targetPath,
    databasePath,
    snapshot,
    target: targetRaw as unknown as SnapshotTarget,
  }
}

export interface SnapshotUseOptions {
  heldOut: boolean
  allowHeldOut: boolean
  maxAgeMs?: number
  now?: number
}

export interface SnapshotUseResult {
  ageMs: number
  /** Wall-clock the cold run had already spent at the checkpoint. */
  skippedMs: number
}

/**
 * Fail fast on breaking mismatches, expiry and salted held-out reuse. Additive fields/registry
 * versions are ignored; schema/tool-contract changes and unknown migrations are not.
 */
export function assertSnapshotUsable(loaded: LoadedRunSnapshot, options: SnapshotUseOptions): SnapshotUseResult {
  const now = options.now ?? Date.now()
  const versions = loaded.snapshot.versions
  const mismatch = (what: string): never => {
    throw new SnapshotError('SNAPSHOT_INCOMPATIBLE', `${what} changed since capture`)
  }
  if (versions.snapshotSchemaVersion !== SNAPSHOT_SCHEMA_VERSION) mismatch('snapshot schema version')
  if (versions.artifactRegistryVersion !== SNAPSHOT_ARTIFACT_REGISTRY_VERSION) mismatch('artifact registry version')
  if (versions.toolContractVersion !== SNAPSHOT_TOOL_CONTRACT_VERSION) mismatch('tool contract version')
  if (versions.promptContractVersion && versions.promptContractVersion !== SNAPSHOT_PROMPT_CONTRACT_VERSION) {
    mismatch('prompt contract version')
  }
  const currentMigration = currentDbMigrationVersion()
  if (versions.dbMigrationVersion !== currentMigration) {
    // Allow an older snapshot when its migration is still a known migration (additive schema):
    // opening the Store applies the newer migrations before the boundary is resumed.
    if (!knownMigrations().includes(versions.dbMigrationVersion)) mismatch('database migration version')
  }
  const ageMs = Math.max(0, now - loaded.target.capturedAt)
  const maxAgeMs = options.maxAgeMs ?? DEFAULT_SNAPSHOT_MAX_AGE_MS
  if (maxAgeMs > 0 && ageMs > maxAgeMs) {
    throw new SnapshotError('SNAPSHOT_EXPIRED', `snapshot is ${Math.round(ageMs / 1000)}s old (max ${Math.round(maxAgeMs / 1000)}s)`)
  }
  if (loaded.target.seedSet === 'held-out' && !options.allowHeldOut) {
    throw new SnapshotError(
      'SNAPSHOT_HELDOUT_REFUSED',
      'salted held-out checkpoints are not reusable without the explicit operator flag',
    )
  }
  if (options.heldOut !== (loaded.target.seedSet === 'held-out')) {
    throw new SnapshotError(
      'SNAPSHOT_INCOMPATIBLE',
      `snapshot seed set '${loaded.target.seedSet}' does not match this run's seed set`,
    )
  }
  return { ageMs, skippedMs: Math.max(0, loaded.snapshot.coordinator.virtualElapsedMs) }
}

function knownMigrations(): string[] {
  const folder = resolve('drizzle')
  try {
    return readdirSync(folder, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && existsSync(join(folder, entry.name, 'migration.sql')))
      .map(entry => entry.name)
      .sort()
  } catch {
    return []
  }
}

/** Copy the snapshot DB into a fresh data dir (call before opening the Store). */
export function copySnapshotDatabase(input: {
  snapshotDir: string
  targetDir: string
}): { directory: string; databasePath: string } {
  const target = resolve(input.targetDir)
  rmSync(target, { recursive: true, force: true })
  mkdirSync(target, { recursive: true, mode: 0o700 })
  mkdirSync(join(target, 'credentials'), { recursive: true, mode: 0o700 })
  const source = join(resolve(input.snapshotDir), 'kovo.sqlite')
  if (!existsSync(source)) throw new SnapshotError('SNAPSHOT_NOT_FOUND', `no kovo.sqlite in ${input.snapshotDir}`)
  const databasePath = join(target, 'kovo.sqlite')
  copyFileSync(source, databasePath)
  chmodSync(databasePath, 0o600)
  return { directory: target, databasePath }
}

interface OriginRewrite {
  table: string
  column: string
}

/**
 * Columns whose text can contain the app origin or canary base URL. JSON arrays/objects store the
 * same literal origin string, so the same REPLACE works for both. History tables (events,
 * messages) are intentionally left untouched: resume must not rewrite what was recorded.
 */
const originRewriteColumns: readonly OriginRewrite[] = [
  { table: 'projects', column: 'seeds' },
  { table: 'project_assets', column: 'origin' },
  { table: 'project_specs', column: 'origin' },
  { table: 'project_specs', column: 'content' },
  { table: 'personas', column: 'origin_allowlist' },
  { table: 'personas', column: 'login_config' },
  { table: 'runs', column: 'candidates' },
  { table: 'endpoints', column: 'origin' },
  { table: 'resource_samples', column: 'origin' },
  { table: 'threat_models', column: 'entries' },
  { table: 'chain_steps', column: 'source_origins' },
  { table: 'assignments', column: 'source_origins' },
  { table: 'facts', column: 'origin' },
  { table: 'facts', column: 'source_origins' },
  { table: 'facts', column: 'summary' },
  { table: 'facts', column: 'data' },
  { table: 'findings', column: 'source_origins' },
  { table: 'findings', column: 'finding' },
  { table: 'broker_exchanges', column: 'origin' },
  { table: 'broker_exchanges', column: 'final_origin' },
  { table: 'broker_exchanges', column: 'redirect_origins' },
  { table: 'broker_exchanges', column: 'req_headers' },
  { table: 'broker_exchanges', column: 'resp_headers' },
  { table: 'replay_specs', column: 'source_origins' },
  { table: 'replay_specs', column: 'spec' },
  { table: 'coverage_entries', column: 'origin' },
  { table: 'approval_requests', column: 'origin' },
  { table: 'second_order_canaries', column: 'injected_origin' },
  { table: 'second_order_canaries', column: 'surfaced_origin' },
  { table: 'second_order_canaries', column: 'injected_endpoint' },
  { table: 'second_order_canaries', column: 'surfaced_endpoint' },
  { table: 'board_members', column: 'source_origins' },
  { table: 'board_messages', column: 'source_origins' },
]

/**
 * Header/body columns that carry a bare `host:port` (HTTP Host header, Location, previews) rather
 * than a full origin. Rebound alongside the origin pass so replay headers match the fresh app.
 */
const hostRewriteColumns: readonly OriginRewrite[] = [
  { table: 'broker_exchanges', column: 'req_headers' },
  { table: 'broker_exchanges', column: 'resp_headers' },
]

export interface RebindOriginsResult {
  appOrigin: { from: string; to: string }
  canaryOrigins: Array<{ from: string; to: string }>
  rowsUpdated: number
}

/** Rebind every recorded origin/port to the freshly booted app and canary listener. */
export function rebindSnapshotOrigins(input: {
  storage: Store
  target: SnapshotTarget
  newOrigin: string
  newCanaryBaseUrls?: readonly string[]
}): RebindOriginsResult {
  const pairs: Array<{ from: string; to: string }> = []
  if (input.target.origin && input.target.origin !== input.newOrigin) {
    pairs.push({ from: input.target.origin, to: input.newOrigin })
  }
  for (let i = 0; i < input.target.canaryBaseUrls.length; i += 1) {
    const from = input.target.canaryBaseUrls[i]
    const to = input.newCanaryBaseUrls?.[i]
    if (from && to && from !== to) pairs.push({ from, to })
  }
  let rowsUpdated = 0
  if (pairs.length) {
    const hostPairs: Array<{ from: string; to: string }> = []
    for (const pair of pairs) {
      try {
        const fromHost = new URL(pair.from).host
        const toHost = new URL(pair.to).host
        if (fromHost && toHost && fromHost !== toHost) hostPairs.push({ from: fromHost, to: toHost })
      } catch { /* non-URL target: origin pass is enough */ }
    }
    input.storage.transaction(() => {
      for (const { table, column } of originRewriteColumns) {
        for (const pair of pairs) {
          const result = input.storage.client.prepare(
            `update ${table} set ${column} = replace(${column}, ?, ?) where ${column} like ?`,
          ).run(pair.from, pair.to, `%${pair.from}%`) as { changes?: number }
          rowsUpdated += Number(result.changes ?? 0)
        }
      }
      for (const { table, column } of hostRewriteColumns) {
        for (const pair of hostPairs) {
          const result = input.storage.client.prepare(
            `update ${table} set ${column} = replace(${column}, ?, ?) where ${column} like ?`,
          ).run(pair.from, pair.to, `%${pair.from}%`) as { changes?: number }
          rowsUpdated += Number(result.changes ?? 0)
        }
      }
    }, { behavior: 'immediate' })
  }
  return {
    appOrigin: { from: input.target.origin, to: input.newOrigin },
    canaryOrigins: pairs.filter(pair => pair.from !== input.target.origin),
    rowsUpdated,
  }
}

export interface PersonaCredentialInput {
  handle: string
  email: string
  password: string
}

export interface ApplyRunSnapshotInput {
  storage: Store
  snapshot: RunSnapshot
  target: SnapshotTarget
  newOrigin: string
  newCanaryBaseUrls?: readonly string[]
  personaCredentials: readonly PersonaCredentialInput[]
  now?: number
}

export interface ApplyRunSnapshotResult {
  runId: string
  projectId: string
  phase0Skipped: boolean
  skippedMs: number
  origins: RebindOriginsResult
  personaSessionsRebound: number
  assignmentsCanceled: number
  stepsRequeued: number
}

/** Recreate owner-only login credential files so the engine re-authenticates from scratch. */
export function rebindPersonaCredentials(
  storage: Store,
  personaRows: ReadonlyArray<{ handle: string; credentialId: string }>,
  credentials: readonly PersonaCredentialInput[],
): number {
  const byHandle = new Map(credentials.map(entry => [entry.handle, entry]))
  let written = 0
  for (const row of personaRows) {
    const credential = byHandle.get(row.handle)
    if (!credential) continue
    const path = join(storage.directory, 'credentials', row.credentialId)
    // A stale session file would be trusted on resume; remove it so login really re-runs.
    rmSync(`${path}.session`, { force: true })
    writeFileSync(path, JSON.stringify({ v: 1, email: credential.email, password: credential.password }), { mode: 0o600 })
    chmodSync(path, 0o600)
    written += 1
  }
  return written
}

/**
 * Apply a checkpoint to a freshly opened Store: rebind origins, recreate persona credentials,
 * discard in-flight assignments (checkpoints are boundary-only), and re-open the run at
 * `investigation` so Phase-0/threat-model are never re-run.
 */
export function applyRunSnapshot(input: ApplyRunSnapshotInput): ApplyRunSnapshotResult {
  const run = input.storage.run(input.target.runId)
  if (run.projectId !== input.target.projectId) {
    throw new SnapshotError('SNAPSHOT_INCOMPATIBLE', 'snapshot run/project binding does not match the database')
  }
  const origins = rebindSnapshotOrigins({
    storage: input.storage,
    target: input.target,
    newOrigin: input.newOrigin,
    ...(input.newCanaryBaseUrls ? { newCanaryBaseUrls: input.newCanaryBaseUrls } : {}),
  })

  const personaRows = input.storage.client.prepare(
    'select handle, credential_id as credentialId, project_id as projectId from personas where project_id = ?',
  ).all(input.target.projectId) as Array<{ handle: string; credentialId: string; projectId: string }>
  const personaSessionsRebound = rebindPersonaCredentials(
    input.storage,
    personaRows,
    input.personaCredentials,
  )

  const now = input.now ?? Date.now()
  let assignmentsCanceled = 0
  let stepsRequeued = 0
  input.storage.transaction(() => {
    // Store.recover() pauses interrupted runs on open; the checkpoint is an explicit resume, so
    // restore the boundary phase without touching spend/round/coverage counters.
    input.storage.updateRun(input.target.runId, { status: 'running', phase: 'investigation' })
    const canceled = input.storage.client.prepare(
      "update assignments set status = 'canceled', lease = null, lease_expires_at = null, "
      + "outcome = coalesce(outcome, 'Resumed from snapshot; in-flight assignment discarded.') "
      + "where run_id = ? and status in ('queued', 'running', 'waiting_approval', 'paused')",
    ).run(input.target.runId) as { changes?: number }
    assignmentsCanceled = Number(canceled.changes ?? 0)
    const requeued = input.storage.client.prepare(
      "update chain_steps set status = 'ready', assigned_worker_id = null, updated_at = ? "
      + "where run_id = ? and status = 'running'",
    ).run(now, input.target.runId) as { changes?: number }
    stepsRequeued = Number(requeued.changes ?? 0)
    input.storage.client.prepare(
      "update board_members set state = 'waiting', active_assignment_id = null, updated_at = ? "
      + "where run_id = ? and state = 'working'",
    ).run(now, input.target.runId)
    input.storage.event(
      input.target.runId,
      'snapshot.resumed',
      `Resumed from checkpoint captured ${new Date(input.target.capturedAt).toISOString()} `
        + `(${input.snapshot.coordinator.checkpoint}); Phase-0 and the deterministic floor were skipped.`,
      {
        snapshotAt: input.target.capturedAt,
        checkpoint: input.snapshot.coordinator.checkpoint,
        skippedMs: input.snapshot.coordinator.virtualElapsedMs,
        schemaVersion: input.snapshot.versions.snapshotSchemaVersion,
        gitSha: input.snapshot.versions.gitSha,
        originsRebound: origins.rowsUpdated,
        personaSessionsRebound,
      },
    )
  }, { behavior: 'immediate' })

  return {
    runId: input.target.runId,
    projectId: input.target.projectId,
    phase0Skipped: Boolean(run.phase0CompletedAt),
    skippedMs: Math.max(0, input.snapshot.coordinator.virtualElapsedMs),
    origins,
    personaSessionsRebound,
    assignmentsCanceled,
    stepsRequeued,
  }
}

/** Read-only helper for tests/operators: owner-only snapshot file modes. */
export function snapshotFileModes(directory: string): Record<string, number> {
  const dir = resolve(directory)
  const out: Record<string, number> = { '.': statSync(dir).mode & 0o777 }
  for (const name of ['kovo.sqlite', 'snapshot.json', 'target.json']) {
    const path = join(dir, name)
    if (existsSync(path)) out[name] = statSync(path).mode & 0o777
  }
  return out
}

/** Escape hatch for tests that need to open the snapshot DB without a Store. */
export function readSnapshotDatabase<T>(databasePath: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return fn(db)
  } finally {
    db.close()
  }
}
