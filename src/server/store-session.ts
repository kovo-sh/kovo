/**
 * Shared SQLite `DbSession` infrastructure, domain row types, pagination/retry/JSON helpers,
 * disk artifact layout helpers, and cascade-aware run cleanup primitives shared across
 * `store-projects.ts`, `store-runs.ts`, `store-findings.ts`, and the `Store` facade.
 *
 * Strictly leaf-level within the store layer: never imports `store.ts` or any domain repository.
 */
import { createHash, randomUUID } from 'node:crypto'
import type { EventEmitter } from 'node:events'
import {
  chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, rmdirSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { and, eq } from 'drizzle-orm'
import type { drizzle } from 'drizzle-orm/node-sqlite'
import type {
  Candidate,
  CheckCoverage,
  EvidenceSummary,
  Finding,
  PublicPersona,
  SelectedChecks,
} from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import { suppliedResponseLabel } from '../report-summary.ts'
import type {
  FindingProvenance,
  FindingVerificationClass,
} from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { isSafeMetadataPath, redact, secretMatchKinds } from './redact.ts'
import type { NamedSecret, SecretMatch } from './redact.ts'
import { responseReview } from './response-checks.ts'
import type { ReplayProofReceiptRow } from './schema.ts'
import * as tables from './schema.ts'

/** Local SQLite schema stamp (`PRAGMA user_version`), independent of Drizzle migrations. */
export const STORE_SCHEMA_VERSION = 9

const PENDING_OOB_RE = /pending[_\s-]?oob|awaiting[_\s-]?(?:oob|callback)/i

/**
 * Hard verification invariant: a persisted finding may only be `confirmed` when its
 * verification class is `runtime_confirmed`. Static-only proof belongs in the advisory bucket.
 */
export function assertConfirmedVerificationClass(
  status: Finding['status'],
  verificationClass: FindingVerificationClass,
): void {
  if (status === 'confirmed' && verificationClass !== 'runtime_confirmed') {
    throw new Error(
      `Invariant: confirmed findings require verification_class='runtime_confirmed' (got '${verificationClass}').`,
    )
  }
}

/** Derive the persisted verification class from a finding status + optional pending-OOB signal. */
export function verificationClassForFinding(
  finding: Pick<Finding, 'status'> & Pick<Partial<Finding>, 'runtimeProofGap' | 'verification' | 'reason' | 'verificationTier'>,
  requested?: FindingVerificationClass,
): FindingVerificationClass {
  if (finding.status === 'confirmed') {
    if (requested !== undefined && requested !== 'runtime_confirmed') {
      assertConfirmedVerificationClass(finding.status, requested)
    }
    if (finding.verificationTier === 'static_verified') {
      throw new Error(
        "Invariant: a static_verified finding must persist with status='static_verified' and verification_class='static_advisory', never as confirmed.",
      )
    }
    return 'runtime_confirmed'
  }
  if (finding.status === 'static_verified') return 'static_advisory'
  if (finding.status === 'dismissed') return 'dismissed'
  if (requested === 'pending_oob') return 'pending_oob'
  const signal = `${finding.runtimeProofGap ?? ''} ${finding.verification ?? ''} ${finding.reason ?? ''}`
  if (PENDING_OOB_RE.test(signal)) return 'pending_oob'
  return requested === 'open_proof_gap' || requested === undefined ? 'open_proof_gap' : requested
}

/**
 * Typed precision-integrity failure. Thrown when a write would persist a `confirmed` finding
 * without persisted evidence that satisfies the oracle (a confirming replay diff or ProofReceipt).
 */
export class InvariantError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'InvariantError'
    this.code = code
  }
}

/**
 * A persisted replay verdict that satisfies a runtime oracle. Zero-LLM `confirmed` is the only
 * runtime-confirming verdict: `static_verified` belongs to the advisory tier and must never back a
 * `runtime_confirmed` claim.
 */
export function replayVerdictConfirmsRuntime(verdict: string | null | undefined): boolean {
  return verdict === 'confirmed'
}

/** Where a runtime_confirmed finding's persisted proof currently lives. */
export interface ConfirmationEvidence {
  /** True only when the persisted evidence satisfies the oracle for the claimed class. */
  backed: boolean
  /** True when a persisted spec verdict explicitly contradicts the confirmed claim. */
  contradicted: boolean
  kind: 'spec' | 'receipt' | 'baseline' | 'floor_artifact' | 'none'
  verdict: string | null
  replaySpecId: string | null
}

export interface FindingProvenanceOptions {
  /** Explicit attribution. `floor` is reserved for the deterministic floor's own confirmations. */
  provenance?: FindingProvenance
  /** Findings/primitives this chain was derived from; enables `chain_from_floor` attribution. */
  parentFindingIds?: readonly string[]
  /** Explicit verification class; confirmed + non-runtime is rejected by the store. */
  verificationClass?: FindingVerificationClass
}

/**
 * Full-body FTS5 indexing modes (v6.2):
 * - `off`     — no FTS rows are written; `searchExchanges` uses the bounded LIKE fallback.
 * - `preview` — default. Index the stored redacted preview (<= 8 KiB/column) and cap the indexed
 *               body text at `ftsMaxBodyBytes`, preserving pre-v6 search behaviour.
 * - `full`    — index the whole redacted body up to `ftsMaxBodyBytes` (operator opt-in; refused
 *               above `maxFullFtsDbBytes` unless explicitly forced).
 */
export type FtsMode = 'off' | 'preview' | 'full'

export const ftsModes: readonly FtsMode[] = ['off', 'preview', 'full']
export const DEFAULT_FTS_MODE: FtsMode = 'preview'
/** Hard per-exchange cap on the bytes of body text handed to the FTS index (default 8 KiB). */
export const DEFAULT_FTS_MAX_BODY_BYTES = 8 * 1024
export const MIN_FTS_MAX_BODY_BYTES = 512
export const MAX_FTS_MAX_BODY_BYTES = 1024 * 1024
/** A `full` index is refused above this DB size unless `forceFullFts` is set (default 512 MiB). */
export const DEFAULT_MAX_FULL_FTS_DB_BYTES = 512 * 1024 * 1024
/** Default exchange retention window applied by `Store.prune()`. */
export const DEFAULT_EXCHANGE_RETENTION_DAYS = 14

export interface StoreOptions {
  /** FTS indexing mode; defaults to `preview` (pre-v6 behaviour, bounded by `ftsMaxBodyBytes`). */
  ftsMode?: FtsMode
  /** Per-exchange cap on the body text indexed by FTS. Default 8 KiB. */
  ftsMaxBodyBytes?: number
  /** Refuse `ftsMode: 'full'` when the main DB file is larger than this. Default 512 MiB. */
  maxFullFtsDbBytes?: number
  /** Explicit operator override for the `full` size guard. */
  forceFullFts?: boolean
}

/** Thrown when `ftsMode: 'full'` is refused by the DB size guard. */
export class FtsModeRefusedError extends Error {
  readonly code = 'FTS_FULL_REFUSED'
  readonly dbBytes: number
  readonly maxFullFtsDbBytes: number
  constructor(dbBytes: number, maxFullFtsDbBytes: number) {
    super(
      `ftsMode 'full' refused: database is ${dbBytes} bytes (cap ${maxFullFtsDbBytes}). `
      + 'Pass { forceFullFts: true } or raise maxFullFtsDbBytes to opt in.',
    )
    this.name = 'FtsModeRefusedError'
    this.dbBytes = dbBytes
    this.maxFullFtsDbBytes = maxFullFtsDbBytes
  }
}

export interface PruneExchangesOptions {
  runId: string
  /** Delete exchanges older than this many milliseconds (relative to `now`). */
  olderThanMs?: number
  /** Always keep the newest N exchanges of the run, regardless of age. */
  keepLatest?: number
  /** Rows deleted per IMMEDIATE transaction batch. Default 500 (max 5,000). */
  batchSize?: number
  now?: number
  /** Emit the structured `retention.pruned` note (default true; `prune()` aggregates instead). */
  emitEvent?: boolean
}

export interface PruneExchangesResult {
  runId: string
  /** Exchange rows deleted. */
  exchanges: number
  /** FTS5 rows deleted (0 when the index was never created). */
  ftsRows: number
  /** Content-addressed blob files deleted (unreferenced after the row delete). */
  blobs: number
  /** Bytes reclaimed from deleted blob files. */
  blobBytes: number
  /** Number of bounded delete batches committed. */
  batches: number
  /** Created-at cutoff actually applied (`now - olderThanMs`), or null when age was unbounded. */
  cutoff: number | null
  keepLatest: number
}

export interface PruneOptions {
  /** Age window in days applied per run. Default 14; `<= 0` disables pruning. */
  retentionDays?: number
  /** Always keep the newest N exchanges of every run. Default 0. */
  keepLatest?: number
  /** Restrict pruning to one run (default: every run). */
  runId?: string
  /** Skip runs that are actively executing (default true). */
  skipActiveRuns?: boolean
  batchSize?: number
  now?: number
}

export interface PruneResult {
  runs: number
  exchanges: number
  ftsRows: number
  blobs: number
  blobBytes: number
  batches: number
  retentionDays: number
  keepLatest: number
  perRun: Array<{ runId: string; exchanges: number; ftsRows: number; blobs: number; blobBytes: number }>
}

export interface StoreFootprint {
  directory: string
  /** `kovo.sqlite` main file size. */
  mainDbBytes: number
  walBytes: number
  shmBytes: number
  /** main + WAL + SHM. */
  dbBytes: number
  /** Every file under `artifacts/` (evidence + exchange blobs). */
  artifactBytes: number
  /** Content-addressed exchange body blobs only. */
  blobBytes: number
  ftsRows: number
  exchangeRows: number
  ftsMode: FtsMode
  ftsMaxBodyBytes: number
  maxFullFtsDbBytes: number
}

export type WorkspaceRow = typeof tables.workspaces.$inferSelect
export type Run = typeof tables.runs.$inferSelect
export type Assignment = typeof tables.assignments.$inferSelect
export type Project = typeof tables.projects.$inferSelect
export type ProjectSpec = typeof tables.projectSpecs.$inferSelect
export type Evidence = typeof tables.evidence.$inferSelect
export type ThreatModel = typeof tables.threatModels.$inferSelect
export type ChainStep = typeof tables.chainSteps.$inferSelect
export type Fact = typeof tables.facts.$inferSelect
export type GraphEdge = typeof tables.graphEdges.$inferSelect
export type GraphDigest = typeof tables.graphDigests.$inferSelect
export type BrokerExchange = typeof tables.brokerExchanges.$inferSelect
export type ApprovalRequest = typeof tables.approvalRequests.$inferSelect
export type ApprovalLeaseRow = typeof tables.approvalLeases.$inferSelect
export type ReplaySpecRow = typeof tables.replaySpecs.$inferSelect

/**
 * Persisted agent-script proof (v7 M5). The receipt is the confirmation primitive: `verifyReceipt()`
 * re-derives the claim from the cited host exchanges, so a re-validation never trusts this row.
 */
export interface AgentScriptProofRecord {
  replaySpecId: string
  findingId: string
  verdict: 'confirmed' | 'dismissed' | 'inconclusive'
  runtime: 'ts' | 'python'
  scriptSha256: string
  artifactId?: string | null
  /** `{ receipt, verification }` exactly as validated at confirmation time. */
  receipt?: ReplayProofReceiptRow | null
  createdAt: number
}

/** Columns written for an agent-script proof (kept in one place so accessors cannot drift). */
export function proofColumns(proof: AgentScriptProofRecord | null | undefined) {
  if (!proof) {
    return {
      proofKind: null, proofVerdict: null, proofRuntime: null,
      proofScriptSha256: null, proofArtifactId: null, proofReceipt: null,
    }
  }
  return {
    proofKind: 'agent_script' as const,
    proofVerdict: proof.verdict,
    proofRuntime: proof.runtime,
    proofScriptSha256: proof.scriptSha256,
    proofArtifactId: proof.artifactId ?? null,
    proofReceipt: proof.receipt ?? null,
  }
}

export function proofRecordOf(row: ReplaySpecRow): AgentScriptProofRecord | null {
  if (row.proofKind !== 'agent_script' || !row.proofVerdict || !row.proofRuntime || !row.proofScriptSha256) return null
  return {
    replaySpecId: row.id,
    findingId: row.findingId,
    verdict: row.proofVerdict,
    runtime: row.proofRuntime,
    scriptSha256: row.proofScriptSha256,
    artifactId: row.proofArtifactId ?? null,
    receipt: row.proofReceipt ?? null,
    createdAt: row.createdAt,
  }
}

export type RetestRun = typeof tables.retestRuns.$inferSelect
export type CoverageEntry = typeof tables.coverageEntries.$inferSelect
export type CanaryRow = typeof tables.canaries.$inferSelect
export type SastRun = typeof tables.sastRuns.$inferSelect
export type SurfaceProbe = typeof tables.surfaceProbes.$inferSelect
export type PatchProposal = typeof tables.patchProposals.$inferSelect
export type ReportRow = typeof tables.reports.$inferSelect
export type MessageRow = typeof tables.messages.$inferSelect
export type BoardMemberRow = typeof tables.boardMembers.$inferSelect
export type BoardMessageRow = typeof tables.boardMessages.$inferSelect
export type EndpointRow = typeof tables.endpoints.$inferSelect
export type EndpointParamRow = typeof tables.endpointParams.$inferSelect
export type ApiDependencyRow = typeof tables.apiDependencies.$inferSelect
export type SecondOrderCanaryRow = typeof tables.secondOrderCanaries.$inferSelect
export type LabTelemetryRow = typeof tables.labTelemetry.$inferSelect
export type LabContainerRow = typeof tables.labContainers.$inferSelect
export type ResourceSampleTableRow = typeof tables.resourceSamples.$inferSelect
export type BenchmarkRunRow = typeof tables.benchmarkRuns.$inferSelect

export type FactKind =
  | Fact['kind']
  | 'tech_fingerprint'
  | 'cve_hypothesis'
  | 'code_audit_suspect'
  | 'persona_resource'

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }
export type SerializableFact = Omit<Fact, 'data'> & { data: Record<string, JsonValue> }
export type SerializableReplaySpecRow = Omit<ReplaySpecRow, 'spec'> & {
  spec: {
    version: 1
    kind: DeclarativeReplaySpec['kind']
    origin: string
    title: string
    category: string
    cwe: string
    severity: Finding['severity']
    severityRationale: string
    impact: string
    remediation: string
    recheckInstructions: string
    assertionsJq: string
    [key: string]: JsonValue
  }
}

export interface ExchangeSummary {
  id: string
  assignmentId: string
  scopeRevision: number
  origin: string
  finalOrigin: string
  redirectOrigins: string[]
  method: string
  pathAndQuery: string
  personaHandle: string | null
  status: number
  mediaType: string
  bodyPreview: string
  bodyArtifactId: string | null
  bodySha256: string
  durationMs: number
  createdAt: number
}

export interface ProjectSpecSummary {
  id: string
  projectId: string
  name: string
  kind: ProjectSpec['kind']
  origin: string | null
  bytes: number
  preview: string
  createdAt: number
}

export interface WorkspaceProjectLatestRun {
  id: string
  goal: string
  status: string
  phase: string
  startedAt: number
  confirmedCount: number
  findingCount: number
}

export interface WorkspaceProjectSummary extends Project {
  runCount: number
  hostCount: number
  latestRun: WorkspaceProjectLatestRun | null
}

export interface WorkspaceRecentRunSummary {
  id: string
  projectId: string
  projectName: string
  goal: string
  status: string
  phase: string
  startedAt: number
  confirmedCount: number
  findings: number
}

export interface WorkspaceSummary {
  workspace: { id: string; name: string }
  projects: WorkspaceProjectSummary[]
  recentRuns: WorkspaceRecentRunSummary[]
}

export interface RunShellIndexEntry {
  id: string
  goal: string
  status: string
  phase: string
  createdAt: number
  projectId: string
  projectName: string
  findings: number
}

export interface RunShellSummary {
  runs: RunShellIndexEntry[]
  counts: {
    exchanges: number
    events: number
  }
}

/** v6 pagination contract: `limit` is explicit (never silently capped); offset is stable. */
export interface PaginationOptions {
  limit?: number
  offset?: number
}

export interface RunDetailOptions extends PaginationOptions {
  /** Per-collection overrides; omitted collections inherit `limit`/`offset`. */
  facts?: PaginationOptions
  endpoints?: PaginationOptions
  endpointParams?: PaginationOptions
  exchanges?: PaginationOptions
  evidence?: PaginationOptions
  messages?: PaginationOptions
  boardMessages?: PaginationOptions
  /** Include exact SQL COUNT(*) totals for paginated collections (default: true when paging). */
  includeTotals?: boolean
}

/** Summary returned by `Store.recover()`; persisted so startup recovery is idempotent. */
export interface RecoveryReport {
  pausedRuns: number
  requeuedAssignments: number
  resetBoardMembers: number
  expiredApprovals: number
  reclaimedContainers: Array<{ runId: string; containerName: string }>
  changed: boolean
}

export interface RunEventPayload {
  id: number
  kind: string
  message: string
  detail: Record<string, unknown>
  createdAt: number
}

export type TenantAuditOutcome = 'allowed' | 'denied' | 'tripped' | 'purged' | 'exported'

export interface AppendTenantAuditLogInput {
  tenantId: string
  runId?: string | null
  actor: string
  action: string
  resourceKind: string
  resourceId?: string | null
  outcome: TenantAuditOutcome
  detail?: Record<string, unknown>
  now?: number
}

export interface TenantAuditLogEntry {
  seq: number
  id: string
  tenantId: string
  runId: string | null
  actor: string
  action: string
  resourceKind: string
  resourceId: string | null
  outcome: TenantAuditOutcome
  detail: Record<string, unknown>
  prevHash: string
  entryHash: string
  createdAt: number
}

export interface RawTenantAuditRow {
  seq: number
  id: string
  tenant_id: string
  run_id: string | null
  actor: string
  action: string
  resource_kind: string
  resource_id: string | null
  outcome: string
  detail: string
  prev_hash: string
  entry_hash: string
  created_at: number
}

export class TenantIsolationError extends Error {
  readonly code = 'TENANT_ISOLATION_DENIED'
  readonly requestedTenant: string
  readonly resourceTenant: string
  readonly resourceId: string

  constructor(requestedTenant: string, resourceTenant: string, resourceId: string) {
    super(`Tenant "${requestedTenant}" is not authorized to access resource "${resourceId}".`)
    this.name = 'TenantIsolationError'
    this.requestedTenant = requestedTenant
    this.resourceTenant = resourceTenant
    this.resourceId = resourceId
  }
}

export function computeTenantAuditHash(fields: {
  id: string
  tenantId: string
  runId: string | null
  actor: string
  action: string
  resourceKind: string
  resourceId: string | null
  outcome: string
  detailJson: string
  prevHash: string
  createdAt: number
}): string {
  return createHash('sha256')
    .update(
      [
        'kovo.tenant-audit.v1',
        fields.prevHash,
        fields.id,
        fields.tenantId,
        fields.runId ?? '',
        fields.actor,
        fields.action,
        fields.resourceKind,
        fields.resourceId ?? '',
        fields.outcome,
        fields.detailJson,
        String(fields.createdAt),
      ].join('\0'),
      'utf8',
    )
    .digest('hex')
}

export function normalizeTenantId(tenantId: string): string {
  const trimmed = tenantId.trim()
  if (!trimmed || trimmed.length > 128 || /[\r\n\0]/.test(trimmed)) {
    throw new Error('Invalid tenantId: must be a non-empty identifier <= 128 characters.')
  }
  return trimmed
}

export const inventoryTitle = 'Supplied asset inventory'
export const reportAccessOperation = 'report-access:'
export const untestedReason = 'Verification had no saved result when this report was created.'

export function evidenceTitle(run: Run, kind: EvidenceSummary['kind'], title: string) {
  return run.sourceMode === 'prepared' && kind === 'observation' && title === 'Observed public response'
    ? suppliedResponseLabel : title
}

export const dataDirectory = () => resolve(process.env.KOVO_DATA_DIR ?? '.kovo')

/** Explicit limits are honored (never silently capped); non-finite input falls back. */
export function resolvePageLimit(value: number | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.max(1, Math.round(value))
}

export function resolvePageOffset(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return 0
  return Math.round(value)
}

export function assessmentAssignments(assignments: readonly Assignment[], assetId: string, goalRevision: number) {
  const ordered = assignments.filter(worker => worker.assetId === assetId && worker.goalRevision === goalRevision)
    .sort((a, b) => b.scopeRevision - a.scopeRevision || b.createdAt - a.createdAt)
  const analysis = ordered.find(worker => worker.phase === 'threat_model' || worker.phase === 'investigation')
  const verification = ordered.find(worker => worker.phase === 'verification' && worker.status !== 'canceled' &&
    worker.scopeRevision >= (analysis?.scopeRevision ?? 0))
  return { analysis, verification }
}

export function untestedCoverage(asset: Candidate, selection: SelectedChecks): CheckCoverage[] {
  const reviews = responseReview(null, undefined, selection.checks.filter(id => id !== 'access-policy'))
  if (selection.checks.includes('access-policy')) {
    reviews.push(...accessPolicyReviews(asset.accessPolicy?.origin === asset.origin ? asset.accessPolicy : undefined))
  }
  return reviews.map(({ coverage }) => ({
    ...coverage, observed: null, status: 'untested',
    reason: untestedReason,
  }))
}

export function inconclusiveReasons(checks: readonly CheckCoverage[]) {
  return new Set(checks.filter(check => check.status === 'inconclusive').map(check => check.reason))
}

export function normalizeFactKind(kind: FactKind): Fact['kind'] {
  if (kind === 'tech_fingerprint') return 'config'
  if (kind === 'cve_hypothesis') return 'note'
  if (kind === 'code_audit_suspect') return 'policy_gap'
  if (kind === 'persona_resource') return 'object_ref'
  return kind
}

export function toSpecSummary(spec: ProjectSpec): ProjectSpecSummary {
  return {
    id: spec.id,
    projectId: spec.projectId,
    name: spec.name,
    kind: spec.kind,
    origin: spec.origin,
    bytes: Buffer.byteLength(spec.content, 'utf8'),
    preview: spec.content.slice(0, 400),
    createdAt: spec.createdAt,
  }
}

const secretMatchKindSet: ReadonlySet<string> = new Set(secretMatchKinds)

/**
 * Whitelist-projects caller-supplied secret metadata before persistence. This is the last line of
 * defense: even if a caller mistakenly populates an extra field, only `kind`, `sha256Prefix`,
 * `fieldPath`, and `count` can reach the database, so raw tokens cannot be smuggled into storage.
 */
export function sanitizeSecretMatches(
  matches: readonly SecretMatch[] | undefined,
  secrets: readonly NamedSecret[],
): SecretMatch[] {
  if (!matches?.length) return []
  const out: SecretMatch[] = []
  for (const match of matches.slice(0, 64)) {
    if (!match || typeof match !== 'object') continue
    if (!secretMatchKindSet.has(match.kind)) continue
    const sha256Prefix = typeof match.sha256Prefix === 'string' ? match.sha256Prefix : ''
    if (!/^[0-9a-f]{12}$/.test(sha256Prefix)) continue
    let fieldPath = typeof match.fieldPath === 'string'
      ? match.fieldPath.replace(/[^\x20-\x7e]/g, '').slice(0, 256)
      : ''
    // Field paths are attacker-influenced. Drop the path rather than persist a secret-shaped key.
    if (fieldPath && !isSafeMetadataPath(fieldPath, secrets)) fieldPath = ''
    const count = Number.isFinite(match.count) ? Math.max(1, Math.min(1_000, Math.round(match.count))) : 1
    out.push({
      kind: match.kind,
      sha256Prefix,
      ...(fieldPath ? { fieldPath } : {}),
      count,
    })
  }
  return out
}

/** One queued exchange write; `row` is fully redacted and safe to persist at flush time. */
export interface PendingExchangeWrite {
  row: typeof tables.brokerExchanges.$inferInsert
  /** Bounded body text for the FTS row (`preview` body or capped full body); null when FTS is off. */
  ftsBody: string | null
  eventMessage: string
  eventDetail: Record<string, unknown>
}

/** Best-effort file size (0 when absent). */
export function safeFileSize(path: string): number {
  try {
    const info = lstatSync(path)
    return info.isFile() ? info.size : 0
  } catch {
    return 0
  }
}

export function clampInteger(value: number, min: number, max: number): number {
  const numeric = Number.isFinite(value) ? value : min
  return Math.round(Math.min(max, Math.max(min, numeric)))
}

/** Cap a string at `maxBytes` of UTF-8 without splitting a code point mid-sequence. */
export function capUtf8Bytes(text: string, maxBytes: number): string {
  if (text.length === 0) return text
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text
  return Buffer.from(text, 'utf8').subarray(0, Math.max(0, maxBytes)).toString('utf8')
}

/** Safe JSON parse helper that returns `fallback` on malformed payloads. */
export function safeJsonParse<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

/** Default SQLite `busy_timeout` (ms) enforced across all Store and auxiliary SQLite connections. */
export const SQLITE_DEFAULT_BUSY_TIMEOUT_MS = 5_000
/** Default SQLite `journal_size_limit` (64 MiB) capping WAL file growth after checkpoints. */
export const SQLITE_JOURNAL_SIZE_LIMIT_BYTES = 64 * 1024 * 1024
/** Minimum SQLite `busy_timeout` (ms) enforced when high-concurrency Phase-B workers run. */
export const HIGH_CONCURRENCY_SQLITE_BUSY_TIMEOUT_MS = 15_000

const busyRetrySleepBuffer = new Int32Array(new SharedArrayBuffer(4))

/** Bounded synchronous retry wrapper for transient SQLite BUSY/LOCKED errors. */
export function withBusyRetry<T>(fn: () => T, maxAttempts = 6, baseBackoffMs = 5): T {
  const attempts = Math.max(1, Math.floor(maxAttempts))
  let attempt = 0
  for (;;) {
    try {
      return fn()
    } catch (error) {
      attempt += 1
      const message = error instanceof Error ? error.message : String(error)
      const isBusy = /SQLITE_BUSY|database is locked/i.test(message)
      if (!isBusy || attempt >= attempts) throw error
      if (baseBackoffMs > 0) {
        const delayMs = Math.min(100, Math.max(1, Math.floor(baseBackoffMs * attempt)))
        try { Atomics.wait(busyRetrySleepBuffer, 0, 0, delayMs) } catch { /* ignore on restricted runtimes */ }
      }
    }
  }
}

export interface OpenSqliteDatabaseOptions {
  busyTimeoutMs?: number
  journalSizeLimitBytes?: number
  foreignKeys?: boolean
  readOnly?: boolean
  createOwnerOnlyFile?: boolean
}

/**
 * Unified SQLite connection factory enforcing WAL mode, `synchronous = NORMAL`,
 * `busy_timeout = 5000`, `journal_size_limit = 64 MiB`, and `foreign_keys = ON`.
 */
export function openSqliteDatabase(
  path: string,
  options: OpenSqliteDatabaseOptions = {},
): DatabaseSync {
  const isMemory = path === ':memory:'
  const readOnly = Boolean(options.readOnly)
  const busyTimeoutMs = clampInteger(options.busyTimeoutMs ?? SQLITE_DEFAULT_BUSY_TIMEOUT_MS, 500, 60_000)
  const journalSizeLimitBytes = Math.max(0, Math.trunc(options.journalSizeLimitBytes ?? SQLITE_JOURNAL_SIZE_LIMIT_BYTES))

  if (!isMemory && !readOnly) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    if (options.createOwnerOnlyFile !== false && !existsSync(path)) {
      try {
        writeFileSync(path, '', { flag: 'wx', mode: 0o600 })
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
    }
  }

  const client = new DatabaseSync(path, {
    timeout: busyTimeoutMs,
    ...(readOnly ? { readOnly: true } : {}),
  })
  try {
    if (!isMemory && !readOnly && options.createOwnerOnlyFile !== false) {
      try { chmodSync(path, 0o600) } catch { /* best-effort owner-only permissions */ }
    }
    if (readOnly) {
      withBusyRetry(() => client.exec(`PRAGMA busy_timeout = ${busyTimeoutMs};`))
    } else {
      const pragmas: string[] = []
      if (!isMemory) pragmas.push('PRAGMA journal_mode = WAL;')
      pragmas.push('PRAGMA synchronous = NORMAL;')
      pragmas.push(`PRAGMA busy_timeout = ${busyTimeoutMs};`)
      if (!isMemory) pragmas.push(`PRAGMA journal_size_limit = ${journalSizeLimitBytes};`)
      if (options.foreignKeys !== false) pragmas.push('PRAGMA foreign_keys = ON;')
      withBusyRetry(() => client.exec(pragmas.join(' ')))
    }
    return client
  } catch (error) {
    try { client.close() } catch { /* ignore */ }
    throw error
  }
}

/** Safe single filesystem segment for a tenant's partitioned blob namespace. */
export function tenantBlobSegment(tenantId: string): string {
  const normalized = normalizeTenantId(tenantId)
  if (/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(normalized) && !normalized.includes('..')) {
    return normalized
  }
  return `t_${createHash('sha256').update(normalized, 'utf8').digest('hex').slice(0, 32)}`
}

/** Partitioned content-addressed blob path: `artifacts/<tenantId>/blobs/<bucket>/<blobId>.txt`. */
export function tenantBlobFile(directory: string, tenantId: string, blobId: string): string {
  return join(directory, 'artifacts', tenantBlobSegment(tenantId), 'blobs', artifactBucket(blobId), blobId + '.txt')
}

/** True when a single path segment contains no traversal or separator characters. */
export function isSafePathSegment(segment: string): boolean {
  return Boolean(segment) && !segment.includes('..') && !/[\\/\0]/.test(segment)
}

/** Deterministic 2-hex shard for artifact paths: `artifacts/<runId>/<bucket>/<id>.txt`. */
export function artifactBucket(id: string): string {
  return createHash('sha256').update(id).digest('hex').slice(0, 2)
}

export function artifactShardFile(directory: string, runId: string, id: string, group?: string): string {
  const parts = [directory, 'artifacts', runId]
  if (group) parts.push(group)
  parts.push(artifactBucket(id), id + '.txt')
  return join(...parts)
}

export function writeArtifactFileOnDisk(
  directory: string,
  runId: string,
  id: string,
  content: string,
  group?: string,
  durable = true,
): void {
  const file = artifactShardFile(directory, runId, id, group)
  mkdirSync(join(file, '..'), { recursive: true, mode: 0o700 })
  try {
    writeFileSync(file, content, { flag: 'wx', mode: 0o600, flush: durable })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
}

/** Read a sharded artifact, falling back to the legacy flat `artifacts/<id>.txt` layout. */
export function readArtifactFileOnDisk(
  directory: string,
  runId: string,
  id: string,
  group?: string,
): string | null {
  const flat = join(directory, 'artifacts', id + '.txt')
  if (existsSync(flat)) return readFileSync(flat, 'utf8')
  const direct = artifactShardFile(directory, runId, id, group)
  if (existsSync(direct)) return readFileSync(direct, 'utf8')
  const runDir = join(directory, 'artifacts', runId)
  const buckets = [artifactBucket(id)]
  try {
    for (const entry of readdirSync(runDir, { withFileTypes: true })) {
      if (entry.isDirectory() && entry.name !== buckets[0]) buckets.push(entry.name)
    }
  } catch { /* no sharded artifacts yet */ }
  for (const bucket of buckets) {
    for (const prefix of group ? [group] : []) {
      const candidate = join(runDir, prefix, bucket, id + '.txt')
      if (existsSync(candidate)) return readFileSync(candidate, 'utf8')
    }
    const candidate = join(runDir, bucket, id + '.txt')
    if (existsSync(candidate)) return readFileSync(candidate, 'utf8')
  }
  return null
}

/** Directory names directly under `artifacts/` (sharded run dirs), bounded and symlink-free. */
export function uniqueArtifactRunDirs(directory: string): string[] {
  const out: string[] = []
  try {
    for (const entry of readdirSync(join(directory, 'artifacts'), { withFileTypes: true })) {
      if (!entry.isDirectory() || out.length >= 500) continue
      out.push(entry.name)
    }
  } catch { /* empty artifacts dir */ }
  return out
}

/** Bounded recursive size of `artifacts/`, split into all files vs content-addressed blobs. */
export function boundedArtifactSize(root: string): { total: number; blobs: number } {
  const maxEntries = 50_000
  let total = 0
  let blobs = 0
  let seen = 0
  const stack: Array<{ path: string; relative: string }> = [{ path: root, relative: '' }]
  while (stack.length > 0 && seen < maxEntries) {
    const current = stack.pop()!
    let entries
    try {
      entries = readdirSync(current.path, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      seen += 1
      if (seen >= maxEntries) break
      const full = join(current.path, entry.name)
      const relative = current.relative ? `${current.relative}/${entry.name}` : entry.name
      try {
        const info = lstatSync(full)
        if (info.isSymbolicLink()) continue
        if (info.isDirectory()) {
          stack.push({ path: full, relative })
        } else if (info.isFile()) {
          total += info.size
          if (relative.includes('/blobs/') || entry.name.startsWith('blob-')) blobs += info.size
        }
      } catch {
        // Best-effort accounting.
      }
    }
  }
  return { total, blobs }
}

/**
 * Identify SQLite foreign-key / deleted-run errors raised when a run (or its assignment) is
 * deleted concurrently while queued exchange writes are flushing. Genuine I/O or corruption
 * errors return false so they are never silently dropped.
 */
export function isDeadRunFkError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const err = error as { message?: unknown; code?: unknown; errstr?: unknown; errcode?: unknown; cause?: unknown }
  const message = typeof err.message === 'string' ? err.message : ''
  const errstr = typeof err.errstr === 'string' ? err.errstr : ''
  const code = typeof err.code === 'string' ? err.code : ''
  const errcode = typeof err.errcode === 'number' ? err.errcode : undefined
  if (code === 'SQLITE_CONSTRAINT_FOREIGNKEY' || errcode === 787) return true
  if (/FOREIGN KEY constraint failed/i.test(message) || /FOREIGN KEY constraint failed/i.test(errstr)) return true
  if (/\brun not found\b/i.test(message)) return true
  if (err.cause && err.cause !== error) return isDeadRunFkError(err.cause)
  return false
}

export function cleanupRunFilesOnDisk(
  directory: string,
  runId: string,
  sessionIds: readonly string[],
  flatArtifactIds: readonly string[],
  tenantBlobFiles: readonly string[] = [],
): void {
  if (isSafePathSegment(runId)) {
    for (const dir of [
      join(directory, 'artifacts', runId),
      join(directory, 'runs', runId),
      join(directory, 'agent-sessions', runId),
    ]) {
      try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
    }
    const safeVaultRunId = /^[A-Za-z0-9._-]{1,128}$/.test(runId)
      ? runId
      : runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
    for (const vaultFile of new Set([`${runId}.json`, `${safeVaultRunId}.json`])) {
      if (!isSafePathSegment(vaultFile)) continue
      try { unlinkSync(join(directory, 'capability-vaults', vaultFile)) } catch { /* ignore */ }
    }
  }
  for (const sessionId of sessionIds) {
    if (!isSafePathSegment(sessionId)) continue
    const base = join(directory, 'agent-sessions', `${sessionId}.sqlite`)
    for (const file of [base, `${base}-wal`, `${base}-shm`]) {
      try { unlinkSync(file) } catch { /* ignore */ }
    }
  }
  for (const artifactId of flatArtifactIds) {
    if (!isSafePathSegment(artifactId)) continue
    try { unlinkSync(join(directory, 'artifacts', `${artifactId}.txt`)) } catch { /* ignore */ }
  }
  for (const blobPath of tenantBlobFiles) {
    try {
      unlinkSync(blobPath)
      try { rmdirSync(dirname(blobPath)) } catch { /* non-empty */ }
    } catch { /* missing or already removed */ }
  }
}

export type StoreDb = ReturnType<typeof drizzle>

/**
 * Shared persistence session passed to every domain repository (`ProjectsRepository`,
 * `RunsRepository`, `FindingsRepository`). Owns SQLite transaction nesting, queued exchange
 * flushing, event emission, workspace-scoped lookups, artifact I/O, and cascade-aware cleanup.
 */
export interface DbSession {
  readonly db: StoreDb
  readonly client: DatabaseSync
  readonly workspace: WorkspaceRow
  readonly directory: string
  readonly ftsMode: FtsMode
  readonly ftsMaxBodyBytes: number
  readonly maxFullFtsDbBytes: number
  readonly ftsAvailable: boolean
  readonly ftsTableExists: boolean
  readonly txDepth: number
  readonly isFlushing: boolean
  /** Optional tenant boundary enforced on every project/run/blob read and write when set. */
  readonly tenantId?: string
  transaction<T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T
  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result
  ensureHighConcurrencyPragmas(minBusyTimeoutMs?: number): { journalMode: string; busyTimeoutMs: number }
  flushNow(): void
  enqueueExchange(item: PendingExchangeWrite): void
  tableExists(table: string): boolean
  hasCascadeSchema(): boolean
  countRunRows(table: string, runId: string): number
  effectiveRunTenant(runId: string): string | null
  requireProject(projectId: string): Project
  requireRun(runId: string): Run
  listProjectPersonas(projectId: string): PublicPersona[]
  event(
    runId: string | null,
    kind: string,
    message: string,
    detail?: Record<string, unknown>,
  ): typeof tables.events.$inferSelect
  message(
    runId: string,
    threadId: string,
    role: typeof tables.messages.$inferSelect.role,
    content: string,
    replyTo?: string,
    evidenceIds?: string[],
    secrets?: readonly NamedSecret[],
  ): string
  onRunEvent(runId: string, fn: (event: RunEventPayload) => void): () => void
  onWake(fn: () => void): () => void
  emitWake(): void
  writeArtifactFile(runId: string, id: string, content: string, group?: string, durable?: boolean): void
  readArtifactFile(runId: string, id: string, group?: string): string | null
  writeBlob(
    content: string,
    secrets?: readonly NamedSecret[],
    runId?: string,
    durable?: boolean,
    tenantId?: string,
  ): { id: string; sha256: string }
  readBlob(blobId: string, runId?: string, tenantId?: string): string
  collectRunCleanupFiles(runId: string): { sessionIds: string[]; artifactIds: Set<string> }
  filterUnreferencedFlatArtifacts(artifactIds: ReadonlySet<string>): string[]
  filterUnreferencedTenantBlobs(tenantId: string, artifactIds: ReadonlySet<string>): string[]
  deleteRunRowsInTx(runId: string, cascade?: boolean): {
    sessionIds: string[]
    flatArtifactIds: string[]
    tenantBlobFiles: string[]
  }
  cleanupRunFilesOnDisk(
    runId: string,
    sessionIds: readonly string[],
    flatArtifactIds: readonly string[],
    tenantBlobFiles?: readonly string[],
  ): void
}

export interface StoreSessionConfig {
  db: StoreDb
  client: DatabaseSync
  /** Optional unwrapped SQLite handle for internal non-exchange lookups that must not flush queued exchanges. */
  rawClient?: DatabaseSync
  workspace: WorkspaceRow
  directory: string
  emitter: EventEmitter
  ftsMode: FtsMode
  ftsMaxBodyBytes: number
  maxFullFtsDbBytes: number
  ftsAvailable: boolean
  ftsTableExists: boolean
  listProjectPersonas: (projectId: string) => PublicPersona[]
}

/** Concrete `DbSession` implementation backing a single `Store` instance. */
export class StoreSession implements DbSession {
  readonly db: StoreDb
  readonly client: DatabaseSync
  private readonly rawClient: DatabaseSync
  readonly workspace: WorkspaceRow
  readonly directory: string
  readonly ftsMode: FtsMode
  readonly ftsMaxBodyBytes: number
  readonly maxFullFtsDbBytes: number
  readonly ftsAvailable: boolean
  readonly ftsTableExists: boolean
  private readonly emitter: EventEmitter
  private readonly listPersonasFn: (projectId: string) => PublicPersona[]
  private _txDepth = 0
  /** Deferred emitter callbacks per transaction nesting frame (flushed on outermost COMMIT, dropped on ROLLBACK). */
  private deferredEmitStack: Array<Array<() => void>> = []
  /** Bounded async write queue for broker exchanges (flushed by microtask/size boundary). */
  private pendingExchanges: PendingExchangeWrite[] = []
  private readonly exchangeAttempts = new WeakMap<PendingExchangeWrite, number>()
  private readonly deadLetterExchanges: Array<{ item: PendingExchangeWrite; error: string; at: number }> = []
  private flushScheduled = false
  private _flushing = false
  private flushError: unknown = null
  private static readonly maxPendingExchanges = 128
  private static readonly maxPoisonItemAttempts = 2
  private static readonly maxDeadLetterExchanges = 256

  constructor(config: StoreSessionConfig) {
    this.db = config.db
    this.client = config.client
    this.rawClient = config.rawClient ?? config.client
    this.workspace = config.workspace
    this.directory = config.directory
    this.emitter = config.emitter
    this.ftsMode = config.ftsMode
    this.ftsMaxBodyBytes = config.ftsMaxBodyBytes
    this.maxFullFtsDbBytes = config.maxFullFtsDbBytes
    this.ftsAvailable = config.ftsAvailable
    this.ftsTableExists = config.ftsTableExists
    this.listPersonasFn = config.listProjectPersonas
  }

  get txDepth(): number {
    return this._txDepth
  }

  get isFlushing(): boolean {
    return this._flushing
  }

  listProjectPersonas(projectId: string): PublicPersona[] {
    return this.listPersonasFn(projectId)
  }

  tableExists(table: string): boolean {
    const row = this.client.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
    ).get(table) as { name?: string } | undefined
    return Boolean(row?.name)
  }

  /**
   * Returns true when every child FK referencing `projects`, `runs`, `assignments`,
   * `replay_specs`, or `endpoints` in the opened SQLite DB declares `ON DELETE CASCADE`
   * (and the non-FK cascade triggers are installed). Legacy pre-cascade DBs return false and
   * automatically use the explicit topological child-before-parent delete fallback.
   */
  hasCascadeSchema(): boolean {
    const fkParents = new Set(['projects', 'runs', 'assignments', 'replay_specs', 'endpoints'])
    const childTables = [
      'project_assets', 'project_specs', 'personas', 'runs', 'threat_models', 'chain_steps',
      'assignments', 'facts', 'graph_edges', 'graph_digests', 'broker_exchanges',
      'approval_requests', 'approval_leases', 'replay_specs', 'retest_runs', 'coverage_entries',
      'canaries', 'evidence', 'findings', 'sast_runs', 'surface_probes', 'patch_proposals',
      'reports', 'messages', 'events', 'endpoints', 'endpoint_params', 'api_dependencies',
      'second_order_canaries', 'lab_telemetry', 'board_members', 'board_messages',
      'resource_samples', 'lab_containers',
    ] as const
    for (const table of childTables) {
      if (!this.tableExists(table)) continue
      const fks = this.client.prepare(`PRAGMA foreign_key_list(${table})`).all() as Array<{
        table: string
        on_delete: string
      }>
      const relevant = fks.filter(fk => fkParents.has(fk.table))
      if (!relevant.length || relevant.some(fk => fk.on_delete.toUpperCase() !== 'CASCADE')) {
        return false
      }
    }
    const triggerNames = new Set(
      (this.client.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all() as Array<{ name: string }>)
        .map(row => row.name),
    )
    if (!triggerNames.has('runs_after_delete_capability_ledger')) return false
    if (this.ftsTableExists && !triggerNames.has('runs_after_delete_fts')) return false
    return true
  }

  /** Exact pagination totals (indexed run_id COUNT); used by `runDetail` instead of hydration. */
  countRunRows(table: string, runId: string): number {
    const row = this.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE run_id = ?`).get(runId) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  }

  effectiveRunTenant(runId: string): string | null {
    const row = this.rawClient.prepare(
      `SELECT COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') AS effective_tenant
       FROM runs r
       LEFT JOIN projects p ON p.id = r.project_id
       WHERE r.id = ? AND r.workspace_id = ?`,
    ).get(runId, this.workspace.id) as { effective_tenant?: string | null } | undefined
    if (!row) return null
    return row.effective_tenant || 'default'
  }

  requireProject(projectId: string): Project {
    const project = this.db.select().from(tables.projects).where(and(
      eq(tables.projects.id, projectId), eq(tables.projects.workspaceId, this.workspace.id),
    )).get()
    if (!project) throw new Error('Project not found.')
    return project
  }

  requireRun(runId: string): Run {
    const run = this.db.select().from(tables.runs).where(and(
      eq(tables.runs.id, runId), eq(tables.runs.workspaceId, this.workspace.id),
    )).get()
    if (!run) throw new Error('Run not found.')
    return run
  }

  /**
   * Ensure SQLite WAL mode and a `busy_timeout >= minBusyTimeoutMs` (default 15s) are active
   * before high-concurrency Phase-B worker pools write events, facts, exchanges, and findings.
   */
  ensureHighConcurrencyPragmas(minBusyTimeoutMs = HIGH_CONCURRENCY_SQLITE_BUSY_TIMEOUT_MS): {
    journalMode: string
    busyTimeoutMs: number
  } {
    const targetTimeout = clampInteger(minBusyTimeoutMs, 10_000, 60_000)
    const journalRow = this.client.prepare('PRAGMA journal_mode').get() as { journal_mode?: string } | undefined
    let journalMode = String(journalRow?.journal_mode ?? '').toLowerCase()
    if (journalMode && journalMode !== 'wal' && journalMode !== 'memory') {
      withBusyRetry(() => this.client.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;'))
      const updated = this.client.prepare('PRAGMA journal_mode').get() as { journal_mode?: string } | undefined
      journalMode = String(updated?.journal_mode ?? journalMode).toLowerCase()
    }
    const busyRow = this.client.prepare('PRAGMA busy_timeout').get() as { timeout?: number } | undefined
    let busyTimeoutMs = Number(busyRow?.timeout ?? 0)
    if (!Number.isFinite(busyTimeoutMs) || busyTimeoutMs < targetTimeout) {
      withBusyRetry(() => this.client.exec(`PRAGMA busy_timeout = ${targetTimeout};`))
      const updatedBusy = this.client.prepare('PRAGMA busy_timeout').get() as { timeout?: number } | undefined
      busyTimeoutMs = Number(updatedBusy?.timeout ?? targetTimeout)
    }
    return { journalMode, busyTimeoutMs }
  }

  /** Inspect dead-lettered poison exchange writes (diagnostics & tests). */
  getDeadLetterExchanges(): ReadonlyArray<{ item: PendingExchangeWrite; error: string; at: number }> {
    return this.deadLetterExchanges
  }

  private recordDeadLetter(item: PendingExchangeWrite, error: unknown): void {
    const base = error instanceof Error ? error.message : String(error)
    const cause = error && typeof error === 'object' && 'cause' in error
      ? (error as { cause?: unknown }).cause
      : undefined
    const causeMsg = cause instanceof Error ? cause.message : typeof cause === 'string' ? cause : ''
    const message = causeMsg && !base.includes(causeMsg) ? `${base}: ${causeMsg}` : base
    this.deadLetterExchanges.push({ item, error: message, at: Date.now() })
    if (this.deadLetterExchanges.length > StoreSession.maxDeadLetterExchanges) {
      this.deadLetterExchanges.shift()
    }
  }

  private scheduleEmit(fn: () => void): void {
    if (this._txDepth > 0 && this.deferredEmitStack.length > 0) {
      this.deferredEmitStack[this.deferredEmitStack.length - 1]!.push(fn)
      return
    }
    queueMicrotask(fn)
  }

  /**
   * Durably flush every queued exchange write. Called by tests, teardown, snapshot capture and
   * every read-after-write path (`getExchange`, `runDetail`, `searchExchanges`, report authoring).
   * Safe to call repeatedly; a no-op when the queue is empty.
   */
  flushNow(): void {
    if (this._txDepth > 0) return
    if (this._flushing) return
    const priorError = this.flushError
    this.flushError = null
    if (!this.pendingExchanges.length) {
      if (priorError) throw priorError
      return
    }
    const batch = this.pendingExchanges.splice(0, this.pendingExchanges.length)
    this._flushing = true
    try {
      let begun = false
      try {
        withBusyRetry(() => this.client.exec('BEGIN IMMEDIATE'))
        begun = true
        const inserted = this.applyExchangeBatch(batch)
        withBusyRetry(() => this.client.exec('COMMIT'))
        // Successful flush recovers cleanly; clear any stale priorError.
        this.emitExchangeEvents(inserted)
      } catch (error) {
        if (begun) {
          try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
        } else {
          this.pendingExchanges.unshift(...batch)
          throw error
        }
        // M-16 & M1: isolate per item on BOTH dead-run FK errors and non-FK poison rows so one
        // bad row never head-of-line blocks healthy sibling writes or wedges unrelated readers.
        const requeuedItems: PendingExchangeWrite[] = []
        let firstError: unknown = null
        for (const item of batch) {
          let itemBegun = false
          try {
            withBusyRetry(() => this.client.exec('BEGIN IMMEDIATE'))
            itemBegun = true
            const inserted = this.applyExchangeBatch([item])
            withBusyRetry(() => this.client.exec('COMMIT'))
            this.emitExchangeEvents(inserted)
          } catch (itemError) {
            if (itemBegun) {
              try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
            }
            if (isDeadRunFkError(itemError)) {
              // Dead run / deleted assignment: drop this stale write cleanly.
              continue
            }
            const msg = itemError instanceof Error ? itemError.message : String(itemError)
            const isTransientLock = /SQLITE_BUSY|database is locked/i.test(msg)
            const attempts = (this.exchangeAttempts.get(item) ?? 0) + 1
            this.exchangeAttempts.set(item, attempts)
            if (isTransientLock || attempts < StoreSession.maxPoisonItemAttempts) {
              requeuedItems.push(item)
              firstError ??= itemError
            } else {
              // Repeated non-FK poison row: dead-letter it instead of infinite head-of-line blocking.
              this.recordDeadLetter(item, itemError)
            }
          }
        }
        if (requeuedItems.length > 0) {
          this.pendingExchanges.unshift(...requeuedItems)
          throw firstError ?? error
        }
      }
    } finally {
      this._flushing = false
    }
  }

  /** Queue one fully-redacted exchange row, flushing synchronously at the bounded size boundary. */
  enqueueExchange(item: PendingExchangeWrite): void {
    if (this._txDepth > 0) {
      const inserted = this.applyExchangeBatch([item])
      this.emitExchangeEvents(inserted)
      return
    }
    this.pendingExchanges.push(item)
    if (this.pendingExchanges.length >= StoreSession.maxPendingExchanges) {
      this.flushNow()
      return
    }
    this.scheduleFlush()
  }

  private scheduleFlush(): void {
    if (this.flushScheduled || this._flushing || this._txDepth > 0) return
    this.flushScheduled = true
    queueMicrotask(() => {
      this.flushScheduled = false
      if (!this.pendingExchanges.length || this._flushing || this._txDepth > 0) return
      try {
        this.flushNow()
      } catch (error) {
        this.flushError ??= error
      }
    })
  }

  private emitExchangeEvents(inserted: readonly (typeof tables.events.$inferSelect)[]): void {
    if (!inserted.length) return
    this.scheduleEmit(() => {
      for (const event of inserted) {
        this.emitter.emit('run:' + event.runId, {
          id: event.id,
          kind: event.kind,
          message: event.message,
          detail: event.detail,
          createdAt: event.createdAt,
        } satisfies RunEventPayload)
      }
      this.emitter.emit('wake')
    })
  }

  /**
   * Insert a batch of exchanges, their FTS rows, run/assignment request counters and audit events
   * inside one IMMEDIATE transaction. Bulk values keep a 128-exchange flush well under 50 ms.
   */
  private applyExchangeBatch(batch: readonly PendingExchangeWrite[]): (typeof tables.events.$inferSelect)[] {
    if (!batch.length) return []
    const rows = batch.map(item => item.row)
    this.db.insert(tables.brokerExchanges).values(rows as typeof tables.brokerExchanges.$inferInsert[]).run()
    if (this.ftsAvailable) {
      const fts = this.client.prepare(
        `INSERT INTO broker_exchanges_fts (exchange_id, run_id, origin, method, path_and_query, req_headers, resp_headers, body_preview)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      for (const [index, row] of rows.entries()) {
        // `ftsBody` is capped at `ftsMaxBodyBytes` by recordExchange(); a null means FTS is off.
        const ftsBody = batch[index]?.ftsBody
        if (ftsBody == null) continue
        fts.run(row.id, row.runId, row.origin, row.method, row.pathAndQuery,
          JSON.stringify(row.reqHeaders ?? {}), JSON.stringify(row.respHeaders ?? {}), ftsBody)
      }
    }
    const byRun = new Map<string, number>()
    const byAssignment = new Map<string, number>()
    for (const row of rows) {
      byRun.set(row.runId, (byRun.get(row.runId) ?? 0) + 1)
      byAssignment.set(row.assignmentId, (byAssignment.get(row.assignmentId) ?? 0) + 1)
    }
    const bumpRun = this.client.prepare('UPDATE runs SET spent_requests = spent_requests + ? WHERE id = ?')
    for (const [runId, count] of byRun) bumpRun.run(count, runId)
    const bumpAssignment = this.client.prepare('UPDATE assignments SET requests_used = requests_used + ? WHERE id = ?')
    for (const [assignmentId, count] of byAssignment) bumpAssignment.run(count, assignmentId)

    const eventRows = batch.map(item => ({
      workspaceId: this.workspace.id,
      runId: item.row.runId,
      kind: 'broker.exchange',
      message: redact(item.eventMessage),
      detail: item.eventDetail,
      createdAt: item.row.createdAt ?? Date.now(),
    }))
    return this.db.insert(tables.events).values(eventRows).returning().all()
  }

  transaction<T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T {
    if (this._txDepth === 0) {
      // Preserve write ordering: never open a transaction while exchange writes are pending.
      this.flushNow()
      this._txDepth += 1
      const beginSql = options?.behavior === 'exclusive'
        ? 'BEGIN EXCLUSIVE'
        : options?.behavior === 'deferred'
          ? 'BEGIN DEFERRED'
          : 'BEGIN IMMEDIATE'
      try {
        withBusyRetry(() => this.client.exec(beginSql))
      } catch (error) {
        this._txDepth -= 1
        throw error
      }
      const frame: Array<() => void> = []
      this.deferredEmitStack.push(frame)
      let committed = false
      try {
        const result = fn()
        withBusyRetry(() => this.client.exec('COMMIT'))
        committed = true
        return result
      } catch (error) {
        try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
        throw error
      } finally {
        this.deferredEmitStack.pop()
        this._txDepth -= 1
        if (committed && frame.length > 0) {
          queueMicrotask(() => {
            for (const cb of frame) cb()
          })
        }
      }
    }
    const sp = `sp_${++this._txDepth}`
    this.client.exec(`SAVEPOINT ${sp}`)
    const childFrame: Array<() => void> = []
    this.deferredEmitStack.push(childFrame)
    let released = false
    try {
      const result = fn()
      this.client.exec(`RELEASE SAVEPOINT ${sp}`)
      released = true
      return result
    } catch (error) {
      try {
        this.client.exec(`ROLLBACK TO SAVEPOINT ${sp}`)
        this.client.exec(`RELEASE SAVEPOINT ${sp}`)
      } catch { /* ignore */ }
      throw error
    } finally {
      this.deferredEmitStack.pop()
      this._txDepth -= 1
      if (released && childFrame.length > 0) {
        const parent = this.deferredEmitStack[this.deferredEmitStack.length - 1]
        if (parent) {
          parent.push(...childFrame)
        } else {
          queueMicrotask(() => {
            for (const cb of childFrame) cb()
          })
        }
      }
    }
  }

  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result {
    const fingerprint = createHash('sha256').update(JSON.stringify(input)).digest('hex')
    return this.transaction(() => {
      const existing = this.db.select().from(tables.operations).where(and(
        eq(tables.operations.id, input.requestId), eq(tables.operations.workspaceId, this.workspace.id),
      )).get()
      if (existing) {
        if (existing.fingerprint !== fingerprint) throw new Error('This action ID was already used.')
        return JSON.parse(existing.result) as Result
      }
      const result = apply()
      this.db.insert(tables.operations).values({
        id: input.requestId, workspaceId: this.workspace.id, fingerprint, result: JSON.stringify(result),
      }).run()
      return result
    }, { behavior: 'immediate' })
  }

  onRunEvent(runId: string, fn: (event: RunEventPayload) => void): () => void {
    const channel = 'run:' + runId
    this.emitter.on(channel, fn)
    return () => { this.emitter.off(channel, fn) }
  }

  onWake(fn: () => void): () => void {
    this.emitter.on('wake', fn)
    return () => { this.emitter.off('wake', fn) }
  }

  emitWake(): void {
    this.scheduleEmit(() => { this.emitter.emit('wake') })
  }

  event(runId: string | null, kind: string, message: string, detail: Record<string, unknown> = {}) {
    const inserted = withBusyRetry(() => this.db.insert(tables.events).values({
      workspaceId: this.workspace.id, runId, kind, message: redact(message), detail, createdAt: Date.now(),
    }).returning().get())
    const payload: RunEventPayload = {
      id: inserted.id,
      kind: inserted.kind,
      message: inserted.message,
      detail: inserted.detail,
      createdAt: inserted.createdAt,
    }
    this.scheduleEmit(() => {
      if (runId) this.emitter.emit('run:' + runId, payload)
      this.emitter.emit('wake')
    })
    return inserted
  }

  message(
    runId: string,
    threadId: string,
    role: typeof tables.messages.$inferSelect.role,
    content: string,
    replyTo?: string,
    evidenceIds?: string[],
    secrets: readonly NamedSecret[] = [],
  ): string {
    const id = randomUUID()
    this.db.insert(tables.messages).values({
      id, runId, threadId, role, content: redact(content, secrets), replyTo, evidenceIds, createdAt: Date.now(),
    }).onConflictDoNothing().run()
    this.scheduleEmit(() => {
      this.emitter.emit('run:' + runId, { id: 0, kind: 'message', message: '', detail: { threadId, role }, createdAt: Date.now() })
    })
    return id
  }

  writeArtifactFile(runId: string, id: string, content: string, group?: string, durable = true): void {
    writeArtifactFileOnDisk(this.directory, runId, id, content, group, durable)
  }

  readArtifactFile(runId: string, id: string, group?: string): string | null {
    return readArtifactFileOnDisk(this.directory, runId, id, group)
  }

  writeBlob(
    content: string,
    secrets: readonly NamedSecret[] = [],
    runId?: string,
    durable = true,
    tenantId?: string,
  ): { id: string; sha256: string } {
    const clean = redact(content, secrets)
    const sha256 = createHash('sha256').update(clean, 'utf8').digest('hex')
    const id = 'blob-' + sha256
    const resolvedTenant = tenantId !== undefined
      ? normalizeTenantId(tenantId)
      : (runId ? (this.effectiveRunTenant(runId) ?? 'default') : 'default')

    if (resolvedTenant !== 'default' || !runId) {
      const file = tenantBlobFile(this.directory, resolvedTenant, id)
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
      try {
        writeFileSync(file, clean, { flag: 'wx', mode: 0o600, flush: durable })
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
    } else {
      this.writeArtifactFile(runId, id, clean, 'blobs', durable)
    }
    return { id, sha256 }
  }

  readBlob(blobId: string, runId?: string, tenantId?: string): string {
    if (!/^blob-[a-f0-9]{64}$/.test(blobId)) throw new Error('Invalid blob ID.')
    let resolvedTenant: string
    if (tenantId !== undefined) {
      resolvedTenant = normalizeTenantId(tenantId)
      if (runId) {
        const runOwner = this.effectiveRunTenant(runId)
        if (runOwner !== null && runOwner !== resolvedTenant) {
          throw new TenantIsolationError(resolvedTenant, runOwner, runId)
        }
      }
    } else if (runId) {
      resolvedTenant = this.effectiveRunTenant(runId) ?? 'default'
    } else {
      resolvedTenant = 'default'
    }

    // 1. Tenant-partitioned content-addressed layout: artifacts/<tenantId>/blobs/<bucket>/<blobId>.txt
    const partitioned = tenantBlobFile(this.directory, resolvedTenant, blobId)
    if (existsSync(partitioned)) return readFileSync(partitioned, 'utf8')

    // 2. Run-sharded layout for the authorized run (default tenant or legacy pre-migration run).
    if (runId && isSafePathSegment(runId)) {
      const runScoped = artifactShardFile(this.directory, runId, blobId, 'blobs')
      if (existsSync(runScoped)) return readFileSync(runScoped, 'utf8')
    }

    // 3. DB-indexed same-tenant run lookup (never scans other tenants' directories via readdirSync).
    const sameTenantRuns = this.client.prepare(
      `SELECT DISTINCT e.run_id AS runId
       FROM broker_exchanges e
       JOIN runs r ON r.id = e.run_id
       LEFT JOIN projects p ON p.id = r.project_id
       WHERE e.body_artifact_id = ?
         AND r.workspace_id = ?
         AND COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?
       LIMIT 16`,
    ).all(blobId, this.workspace.id, resolvedTenant) as Array<{ runId: string }>
    for (const row of sameTenantRuns) {
      if (!isSafePathSegment(row.runId)) continue
      const candidate = artifactShardFile(this.directory, row.runId, blobId, 'blobs')
      if (existsSync(candidate)) return readFileSync(candidate, 'utf8')
    }

    // 4. Legacy flat path fallback during migration (only when owned by this tenant or unowned in default).
    const flat = join(this.directory, 'artifacts', blobId + '.txt')
    if (existsSync(flat)) {
      if (sameTenantRuns.length > 0) {
        return readFileSync(flat, 'utf8')
      }
      if (resolvedTenant === 'default') {
        const otherTenantRef = this.client.prepare(
          `SELECT 1 AS hit
           FROM broker_exchanges e
           JOIN runs r ON r.id = e.run_id
           LEFT JOIN projects p ON p.id = r.project_id
           WHERE e.body_artifact_id = ?
             AND r.workspace_id = ?
             AND COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') <> 'default'
           LIMIT 1`,
        ).get(blobId, this.workspace.id) as { hit?: number } | undefined
        if (!otherTenantRef?.hit) {
          return readFileSync(flat, 'utf8')
        }
      }
    }
    throw new Error('Artifact not found.')
  }

  collectRunCleanupFiles(runId: string): { sessionIds: string[]; artifactIds: Set<string> } {
    const assignmentSessions = this.client.prepare(
      `SELECT DISTINCT session_id AS sid FROM assignments WHERE run_id = ?`,
    ).all(runId) as { sid: string | null }[]
    const boardSessions = this.client.prepare(
      `SELECT DISTINCT session_id AS sid FROM board_members WHERE run_id = ?`,
    ).all(runId) as { sid: string | null }[]
    const sessionIds = [...new Set(
      [...assignmentSessions, ...boardSessions]
        .map(row => row.sid)
        .filter((sid): sid is string => typeof sid === 'string' && sid.length > 0),
    )]

    const artifactIds = new Set<string>()
    for (const row of this.client.prepare(`SELECT id FROM evidence WHERE run_id = ?`).all(runId) as { id: string }[]) {
      if (row.id) artifactIds.add(row.id)
    }
    for (const row of this.client.prepare(`SELECT body_artifact_id AS aid FROM broker_exchanges WHERE run_id = ? AND body_artifact_id IS NOT NULL`).all(runId) as { aid: string | null }[]) {
      if (row.aid) artifactIds.add(row.aid)
    }
    for (const row of this.client.prepare(`SELECT proof_artifact_id AS aid FROM replay_specs WHERE run_id = ? AND proof_artifact_id IS NOT NULL`).all(runId) as { aid: string | null }[]) {
      if (row.aid) artifactIds.add(row.aid)
    }
    for (const row of this.client.prepare(`SELECT raw_artifact_id AS aid FROM sast_runs WHERE run_id = ? AND raw_artifact_id IS NOT NULL`).all(runId) as { aid: string | null }[]) {
      if (row.aid) artifactIds.add(row.aid)
    }
    for (const row of this.client.prepare(`SELECT artifact_id AS aid FROM lab_telemetry WHERE run_id = ?`).all(runId) as { aid: string | null }[]) {
      if (row.aid) artifactIds.add(row.aid)
    }
    return { sessionIds, artifactIds }
  }

  /** Keep any legacy flat content-addressed blob still referenced by another surviving run. */
  filterUnreferencedFlatArtifacts(artifactIds: ReadonlySet<string>): string[] {
    if (artifactIds.size === 0) return []
    const checkShared = this.client.prepare(
      `SELECT 1 FROM broker_exchanges WHERE body_artifact_id = ? LIMIT 1`,
    )
    const flatArtifactIds: string[] = []
    for (const aid of artifactIds) {
      if (!checkShared.get(aid)) flatArtifactIds.push(aid)
    }
    return flatArtifactIds
  }

  /** Return tenant-partitioned blob paths no longer referenced by any surviving run of `tenantId`. */
  filterUnreferencedTenantBlobs(tenantId: string, artifactIds: ReadonlySet<string>): string[] {
    if (artifactIds.size === 0) return []
    const normalized = normalizeTenantId(tenantId)
    const checkTenantRef = this.client.prepare(
      `SELECT 1 AS hit
       FROM broker_exchanges e
       JOIN runs r ON r.id = e.run_id
       LEFT JOIN projects p ON p.id = r.project_id
       WHERE e.body_artifact_id = ?
         AND r.workspace_id = ?
         AND COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?
       LIMIT 1`,
    )
    const out: string[] = []
    for (const aid of artifactIds) {
      if (!/^blob-[a-f0-9]{64}$/.test(aid)) continue
      if (!checkTenantRef.get(aid, this.workspace.id, normalized)) {
        out.push(tenantBlobFile(this.directory, normalized, aid))
      }
    }
    return out
  }

  deleteRunRowsInTx(runId: string, cascade = this.hasCascadeSchema()): {
    sessionIds: string[]
    flatArtifactIds: string[]
    tenantBlobFiles: string[]
  } {
    const runTenant = this.effectiveRunTenant(runId) ?? 'default'
    const { sessionIds, artifactIds } = this.collectRunCleanupFiles(runId)

    // Note: tenant_audit_log is an append-only immutable audit table with a BEFORE DELETE trigger
    // and no FK to runs, so it is intentionally preserved on both cascade and legacy paths.
    if (!cascade) {
      // Legacy pre-cascade DB fallback: delete in strict child-before-parent order for PRAGMA foreign_keys = ON.
      if (this.ftsTableExists) {
        this.client.prepare(`DELETE FROM broker_exchanges_fts WHERE run_id = ?`).run(runId)
      }
      const orderedTables = [
        'retest_runs',
        'replay_specs',
        'facts',
        'broker_exchanges',
        'approval_requests',
        'evidence',
        'sast_runs',
        'surface_probes',
        'endpoint_params',
        'api_dependencies',
        'capability_causal_edges',
        'capability_negative_edges',
        'capability_nodes',
        'lab_containers',
        'lab_telemetry',
        'board_messages',
        'board_members',
        'resource_samples',
        'second_order_canaries',
        'approval_leases',
        'patch_proposals',
        'findings',
        'coverage_entries',
        'canaries',
        'graph_edges',
        'graph_digests',
        'threat_models',
        'chain_steps',
        'reports',
        'messages',
        'events',
        'endpoints',
        'assignments',
      ] as const
      for (const table of orderedTables) {
        this.client.prepare(`DELETE FROM ${table} WHERE run_id = ?`).run(runId)
      }
    }
    this.client.prepare(`DELETE FROM runs WHERE id = ? AND workspace_id = ?`).run(runId, this.workspace.id)
    return {
      sessionIds,
      flatArtifactIds: this.filterUnreferencedFlatArtifacts(artifactIds),
      tenantBlobFiles: this.filterUnreferencedTenantBlobs(runTenant, artifactIds),
    }
  }

  cleanupRunFilesOnDisk(
    runId: string,
    sessionIds: readonly string[],
    flatArtifactIds: readonly string[],
    tenantBlobFiles: readonly string[] = [],
  ): void {
    cleanupRunFilesOnDisk(this.directory, runId, sessionIds, flatArtifactIds, tenantBlobFiles)
  }
}

/**
 * Tenant-scoped `DbSession` wrapper enforcing strict tenant isolation across every
 * project, run, child-entity, and blob access while delegating transactions, exchange
 * batching, and events to the backing `StoreSession`.
 */
export class TenantScopedSession implements DbSession {
  private readonly inner: DbSession
  readonly tenantId: string

  constructor(inner: DbSession, tenantId: string) {
    this.inner = inner
    this.tenantId = normalizeTenantId(tenantId)
  }

  get db() { return this.inner.db }
  get client() { return this.inner.client }
  get workspace() { return this.inner.workspace }
  get directory() { return this.inner.directory }
  get ftsMode() { return this.inner.ftsMode }
  get ftsMaxBodyBytes() { return this.inner.ftsMaxBodyBytes }
  get maxFullFtsDbBytes() { return this.inner.maxFullFtsDbBytes }
  get ftsAvailable() { return this.inner.ftsAvailable }
  get ftsTableExists() { return this.inner.ftsTableExists }
  get txDepth() { return this.inner.txDepth }
  get isFlushing() { return this.inner.isFlushing }

  transaction<T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T {
    return this.inner.transaction(fn, options)
  }
  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result {
    return this.inner.operate(input, apply)
  }
  ensureHighConcurrencyPragmas(minBusyTimeoutMs?: number) {
    return this.inner.ensureHighConcurrencyPragmas(minBusyTimeoutMs)
  }
  flushNow() { return this.inner.flushNow() }
  enqueueExchange(item: PendingExchangeWrite) { return this.inner.enqueueExchange(item) }
  tableExists(table: string) { return this.inner.tableExists(table) }
  hasCascadeSchema() { return this.inner.hasCascadeSchema() }
  countRunRows(table: string, runId: string) {
    this.requireRun(runId)
    return this.inner.countRunRows(table, runId)
  }

  effectiveRunTenant(runId: string): string | null {
    return this.inner.effectiveRunTenant(runId)
  }

  requireProject(projectId: string): Project {
    const project = this.inner.requireProject(projectId)
    const owner = project.tenantId || 'default'
    if (owner !== this.tenantId) {
      throw new TenantIsolationError(this.tenantId, owner, projectId)
    }
    return project
  }

  requireRun(runId: string): Run {
    const run = this.inner.requireRun(runId)
    const owner = this.inner.effectiveRunTenant(runId) ?? 'default'
    if (owner !== this.tenantId) {
      throw new TenantIsolationError(this.tenantId, owner, runId)
    }
    return run
  }

  listProjectPersonas(projectId: string): PublicPersona[] {
    this.requireProject(projectId)
    return this.inner.listProjectPersonas(projectId)
  }

  event(runId: string | null, kind: string, message: string, detail?: Record<string, unknown>) {
    return this.inner.event(runId, kind, message, detail)
  }

  message(
    runId: string,
    threadId: string,
    role: typeof tables.messages.$inferSelect.role,
    content: string,
    replyTo?: string,
    evidenceIds?: string[],
    secrets?: readonly NamedSecret[],
  ): string {
    return this.inner.message(runId, threadId, role, content, replyTo, evidenceIds, secrets)
  }

  onRunEvent(runId: string, fn: (event: RunEventPayload) => void) {
    this.requireRun(runId)
    return this.inner.onRunEvent(runId, fn)
  }
  onWake(fn: () => void) { return this.inner.onWake(fn) }
  emitWake() { return this.inner.emitWake() }

  writeArtifactFile(runId: string, id: string, content: string, group?: string, durable?: boolean): void {
    this.requireRun(runId)
    this.inner.writeArtifactFile(runId, id, content, group, durable)
  }

  readArtifactFile(runId: string, id: string, group?: string): string | null {
    this.requireRun(runId)
    return this.inner.readArtifactFile(runId, id, group)
  }

  writeBlob(
    content: string,
    secrets: readonly NamedSecret[] = [],
    runId?: string,
    durable = true,
    tenantId?: string,
  ): { id: string; sha256: string } {
    if (tenantId !== undefined && normalizeTenantId(tenantId) !== this.tenantId) {
      throw new TenantIsolationError(this.tenantId, normalizeTenantId(tenantId), 'blob')
    }
    if (runId) this.requireRun(runId)
    return this.inner.writeBlob(content, secrets, runId, durable, this.tenantId)
  }

  readBlob(blobId: string, runId?: string, tenantId?: string): string {
    if (tenantId !== undefined && normalizeTenantId(tenantId) !== this.tenantId) {
      throw new TenantIsolationError(this.tenantId, normalizeTenantId(tenantId), blobId)
    }
    if (runId) this.requireRun(runId)
    return this.inner.readBlob(blobId, runId, this.tenantId)
  }

  collectRunCleanupFiles(runId: string) {
    this.requireRun(runId)
    return this.inner.collectRunCleanupFiles(runId)
  }
  filterUnreferencedFlatArtifacts(artifactIds: ReadonlySet<string>) {
    return this.inner.filterUnreferencedFlatArtifacts(artifactIds)
  }
  filterUnreferencedTenantBlobs(tenantId: string, artifactIds: ReadonlySet<string>) {
    return this.inner.filterUnreferencedTenantBlobs(tenantId, artifactIds)
  }
  deleteRunRowsInTx(runId: string, cascade?: boolean) {
    this.requireRun(runId)
    return this.inner.deleteRunRowsInTx(runId, cascade)
  }
  cleanupRunFilesOnDisk(
    runId: string,
    sessionIds: readonly string[],
    flatArtifactIds: readonly string[],
    tenantBlobFiles?: readonly string[],
  ) {
    this.inner.cleanupRunFilesOnDisk(runId, sessionIds, flatArtifactIds, tenantBlobFiles)
  }
}
