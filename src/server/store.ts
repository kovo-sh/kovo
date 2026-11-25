import { createHash, randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, rmdirSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { and, asc, desc, eq, gt, inArray, or, sql } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-sqlite'
import { migrate } from 'drizzle-orm/node-sqlite/migrator'
import type { z } from 'zod'
import type { importAccessPolicy } from '../access-policy.ts'
import {
  assessmentCheckTitles,
  assetOriginForEnvironment,
  boardHandlePattern,
  boardSystemHandles,
  canReviewScope,
  canonicalBoardHandles,
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultLabBudgetRequests,
  defaultMaxRpsPerOrigin,
  defaultPublicBudgetRequests,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
  isLocalLabEnvEnabled,
  maxBoardBodyLength,
  normalizeBoardHandle,
  parseBoardMentions,
  specialistProfiles,
  workerHistory,
} from '../domain.ts'
import type {
  ApprovalPolicy,
  ApprovedEndpointPattern,
  BenchmarkFunnel,
  BoardAuthorRole,
  BoardMemberRole,
  BoardMemberState,
  BoardMessageKind,
  CallerCompatibility,
  Candidate,
  CapabilityTier,
  CheckCoverage,
  CodeLocation,
  DnsSource,
  DynamicRetestVerdict,
  EndpointSource,
  EvidenceSummary,
  FailureTaxonomyBucket,
  Finding,
  InlineVerifyFeedback,
  LabConfig,
  OwaspCategory,
  ParamLocation,
  PatchProposalStatus,
  PatchProposalSummary,
  ReportBody,
  RunCommand,
  SecondOrderCanaryStatus,
  SelectedChecks,
  SpecialistProfile,
  ThreatModelSummary,
  VerificationTier,
  WorkerPhase,
  importDnsInventory,
  importProjectSpec,
  newProject,
  newRun,
  projectAsset,
} from '../domain.ts'
import { parseDnsInventory } from '../passive-dns.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import type { ReplayProofReceiptRow } from './schema.ts'
import {
  buildProvenanceReport,
  chainFindingDedupKey,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
  findingSeverityOrder,
  mergeChainFindings,
  suppliedResponseLabel,
} from '../report-summary.ts'
import type {
  FindingProvenance,
  FindingProvenanceFields,
  FindingVerificationClass,
  ReportProvenanceSurface,
} from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { matchesApprovedEndpointPattern, normalizeApprovalPathPattern } from './approval-judge.ts'
import {
  CapabilityLedger,
  initCapabilityLedgerSchema,
  type CapabilityLedgerOptions,
} from './capability-ledger.ts'
import { computeFindingFingerprint, isOriginWideCwe, normalizeEndpointTemplate } from './dedupe.ts'
import type { ApprovalDecidedBy, ApprovalRiskLevel } from './approval-judge.ts'
import { deletePersonaCredentialFiles, listProjectPersonas } from './persona-vault.ts'
import { isSafeMetadataPath, redact, redactHeaders, redactJsonValue, redactZdrJsonValue, secretMatchKinds } from './redact.ts'
import type { NamedSecret, SecretMatch } from './redact.ts'
import { purgeExpiredArtifacts } from './artifact-ttl.ts'
import type { ArtifactTtlPolicy, ArtifactTtlPurgeResult } from './artifact-ttl.ts'
import { responseCapture, restrictAccessVerification } from './report-evidence.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks } from './review-plan.ts'
import {
  defaultEnvironmentMode,
  environmentModes,
  isProvenanceOriginAllowed,
  normalizeScopeOrigin,
  originRoles,
  provenanceOriginsFor,
  routePatternForPath,
  tenantTagForRun,
} from './scope-policy.ts'
import type { EnvironmentMode, OriginRole, ScopePolicy } from './scope-policy.ts'
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
 * - `preview` — default. Index the stored redacted preview (≤ 8 KiB/column) and cap the indexed
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
  /** `guardian.sqlite` main file size. */
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
function proofColumns(proof: AgentScriptProofRecord | null | undefined) {
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

function proofRecordOf(row: ReplaySpecRow): AgentScriptProofRecord | null {
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

const inventoryTitle = 'Supplied asset inventory'
const reportAccessOperation = 'report-access:'
const untestedReason = 'Verification had no saved result when this report was created.'

function evidenceTitle(run: Run, kind: EvidenceSummary['kind'], title: string) {
  return run.sourceMode === 'prepared' && kind === 'observation' && title === 'Observed public response'
    ? suppliedResponseLabel : title
}

export const dataDirectory = () => resolve(process.env.GUARDIAN_DATA_DIR ?? '.guardian')

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

function untestedCoverage(asset: Candidate, selection: SelectedChecks): CheckCoverage[] {
  const reviews = responseReview(null, undefined, selection.checks.filter(id => id !== 'access-policy'))
  if (selection.checks.includes('access-policy')) {
    reviews.push(...accessPolicyReviews(asset.accessPolicy?.origin === asset.origin ? asset.accessPolicy : undefined))
  }
  return reviews.map(({ coverage }) => ({
    ...coverage, observed: null, status: 'untested',
    reason: untestedReason,
  }))
}

function inconclusiveReasons(checks: readonly CheckCoverage[]) {
  return new Set(checks.filter(check => check.status === 'inconclusive').map(check => check.reason))
}

function normalizeFactKind(kind: FactKind): Fact['kind'] {
  if (kind === 'tech_fingerprint') return 'config'
  if (kind === 'cve_hypothesis') return 'note'
  if (kind === 'code_audit_suspect') return 'policy_gap'
  if (kind === 'persona_resource') return 'object_ref'
  return kind
}

function toSpecSummary(spec: ProjectSpec): ProjectSpecSummary {
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

// --- Cross-persona object-ID harvesting (v5 M2.1) -------------------------------------------

export interface ExtractedResourceRef {
  /** Opaque object identifier observed in a path, JSON/GraphQL body, HTML link or redirect. */
  resourceId: string
  /** Concrete (or link) endpoint that exposed the identifier. */
  endpoint: string
  method: string
  /** Field/segment that carried the identifier, e.g. `invoiceId` or `path:invoices`. */
  field: string
}

export interface ResourceSampleRow {
  id: string
  runId: string
  ownerPersona: string
  resourceKey: string
  /** Collection the id belongs to (e.g. `/invoices`); absent on legacy rows (treated as `''`). */
  collectionPath?: string
  resourceId: string
  origin: string
  endpoint: string
  method: string
  mediaType: string | null
  authenticated: boolean
  createdAt: number
  updatedAt: number
}

export interface ResourceHarvestExchange {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  status: number
  mediaType: string
  body: string
  respHeaders?: Record<string, string> | null
}

const RESOURCE_STATIC_ASSET_RE = /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf)(?:\?|$)/i
const RESOURCE_ID_KEY_RE = /^(?:id|uuid|guid|ref|slug|[a-z][a-z0-9]*[-_]?id|[a-z][a-z0-9]*Id|[a-z][a-z0-9_]*_id)$/i
const RESOURCE_IGNORED_VALUES = new Set([
  'true', 'false', 'null', 'undefined', 'default', 'self', 'me', 'current', 'none', 'all', 'new',
  'list', 'index', 'health', 'status', 'public', 'latest', 'recent', 'summary', 'search', 'create',
])
const RESOURCE_SECRET_VALUE_RE = /(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|-----BEGIN [^-\n]*PRIVATE KEY-----|^Bearer\s)/i
const RESOURCE_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const RESOURCE_MONGO_RE = /^[0-9a-f]{24}$/i
const RESOURCE_ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/i
const RESOURCE_NANOID_RE = /^[A-Za-z0-9_-]{12,21}$/
const RESOURCE_HASHID_RE = /^(?=[A-Za-z0-9]{6,32}$)(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9]+$/
const RESOURCE_NUMERIC_RE = /^\d{1,18}$/
const RESOURCE_PREFIXED_RE = /^(?:usr|org|proj|acct|app|ord|inv|doc|file|chat|team|sub|cus|ws|res|msg|pay|txn|evt|job|run|repo|prj|tenant|user|order|invoice|customer)_[A-Za-z0-9_-]{2,64}$/i
const RESOURCE_GENERIC_PREFIXED_RE = /^(?=[a-z]{1,4}_[A-Za-z0-9]{2,64}$)(?=.*[0-9])[A-Za-z0-9_]+$/i

function decodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

/**
 * True when a string looks like an opaque object identifier (never a credential). Supports
 * 1-digit numeric ids, UUIDs, 24-hex Mongo ObjectIDs, ULIDs, NanoIDs, hashids and prefixed ids.
 */
export function isOpaqueResourceId(raw: string, opts?: { keyed?: boolean }): boolean {
  const value = raw.trim()
  if (!value || value.length > 64) return false
  if (/\s/.test(value) || /[/?#]/.test(value)) return false
  if (RESOURCE_IGNORED_VALUES.has(value.toLowerCase())) return false
  if (RESOURCE_SECRET_VALUE_RE.test(value)) return false
  if (RESOURCE_UUID_RE.test(value)) return true
  if (RESOURCE_MONGO_RE.test(value)) return true
  if (RESOURCE_ULID_RE.test(value)) return true
  if (RESOURCE_PREFIXED_RE.test(value)) return true
  if (RESOURCE_GENERIC_PREFIXED_RE.test(value)) return true
  if (RESOURCE_NUMERIC_RE.test(value)) return true
  if (RESOURCE_NANOID_RE.test(value)) {
    // Path segments that are ordinary words should not be mistaken for NanoIDs; mixed case, a digit
    // or an underscore/url-safe separator is a strong opaque-id signal.
    if (opts?.keyed || /[0-9_]/.test(value) || /[a-z][A-Z]/.test(value)) return true
  }
  if (RESOURCE_HASHID_RE.test(value)) return true
  return false
}

/**
 * Normalize the collection a harvested identifier belongs to. Trailing opaque id segments are
 * dropped so `/invoices/42` and `/invoices` share the `/invoices` collection, while `/orders`
 * and `/tickets` never collide on a shared `id` field name.
 */
export function collectionPathFor(endpoint: string): string {
  const bare = (endpoint.split('?')[0]?.split('#')[0] ?? '').trim()
  const segments = bare.split('/').filter(Boolean)
  while (segments.length) {
    const last = decodePathSegment(segments[segments.length - 1]!)
    if (!isOpaqueResourceId(last)) break
    segments.pop()
  }
  const normalized = ('/' + segments.join('/')).slice(0, 512)
  return normalized === '/' ? '' : normalized
}

function sameOriginPath(raw: string, origin: string): string | null {
  const candidate = raw.trim()
  if (!candidate || candidate.startsWith('#') || /^(?:javascript|data|mailto):/i.test(candidate)) return null
  try {
    const base = new URL(origin)
    const parsed = new URL(candidate, base)
    if (parsed.origin !== base.origin) return null
    return `${parsed.pathname}${parsed.search}`
  } catch {
    return null
  }
}

/**
 * Extract object identifiers from an HTTP exchange. Bounded and redaction-safe: static assets,
 * secrets and ignored sentinel values are never returned. Unauthenticated responses are included
 * because they can leak identifiers that later enable cross-persona BOLA chains.
 */
export function extractResourceRefsFromExchange(ex: ResourceHarvestExchange): ExtractedResourceRef[] {
  if (ex.status < 200 || ex.status >= 400) return []
  if (RESOURCE_STATIC_ASSET_RE.test(ex.pathAndQuery) || ex.pathAndQuery.startsWith('/_next/static/')) return []

  const found: ExtractedResourceRef[] = []
  const seen = new Set<string>()
  const push = (rawId: string, endpoint: string, field: string) => {
    const clean = rawId.trim()
    if (!clean || !isOpaqueResourceId(clean, { keyed: !field.startsWith('path:') && !field.startsWith('href:') && !field.startsWith('location:') })) return
    if (found.length >= 16) return
    const key = `${endpoint}|${clean}`
    if (seen.has(key)) return
    seen.add(key)
    found.push({ resourceId: clean, endpoint, method: ex.method.toUpperCase(), field })
  }
  const pushPath = (pathAndQuery: string, fieldPrefix: string) => {
    const bare = pathAndQuery.split('?')[0].split('#')[0] || '/'
    const segments = bare.split('/').filter(Boolean)
    for (let i = 1; i < segments.length; i += 1) {
      const value = decodePathSegment(segments[i])
      const previous = decodePathSegment(segments[i - 1])
      if (/^v\d+$/i.test(previous)) continue
      if (!/^[A-Za-z][A-Za-z0-9_-]{0,40}$/.test(previous)) continue
      if (!isOpaqueResourceId(value)) continue
      push(value, bare, `${fieldPrefix}${previous}`)
    }
  }

  pushPath(ex.pathAndQuery, 'path:')

  // Redirect / creation Location headers commonly reveal the canonical item URL and its id.
  const location = Object.entries(ex.respHeaders ?? {})
    .find(([name]) => name.toLowerCase() === 'location')?.[1]
  if (location && (ex.status === 201 || (ex.status >= 300 && ex.status < 400))) {
    const near = sameOriginPath(location, ex.origin)
    if (near) pushPath(near, 'location:')
  }

  if (ex.mediaType.toLowerCase().includes('json') && ex.body && ex.body.length <= 512 * 1024) {
    try {
      const parsed = JSON.parse(ex.body) as unknown
      const basePath = ex.pathAndQuery.split('?')[0] || '/'
      const graphql = /graphql/i.test(ex.pathAndQuery) ||
        Boolean(parsed && typeof parsed === 'object' && 'data' in (parsed as Record<string, unknown>) &&
          ('errors' in (parsed as Record<string, unknown>) || !Array.isArray(parsed)))
      const maxDepth = graphql ? 24 : 8
      const walk = (node: unknown, depth: number, parentKey: string) => {
        if (depth > maxDepth || found.length >= 16 || !node || typeof node !== 'object') return
        if (Array.isArray(node)) {
          for (const item of node.slice(0, graphql ? 12 : 5)) walk(item, depth + 1, parentKey)
          return
        }
        for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
          if (found.length >= 16) break
          if (RESOURCE_ID_KEY_RE.test(key)) {
            if (typeof val === 'string') push(val, basePath, key)
            else if (typeof val === 'number' && Number.isInteger(val) && val >= 0) push(String(val), basePath, key)
          } else if (val && typeof val === 'object') {
            // Objects keyed by id, e.g. {"invoices": {"<objectId>": {...}}}.
            if (isOpaqueResourceId(key, { keyed: true }) && !parentKey) push(key, basePath, `key:${parentKey || 'map'}`)
            walk(val, depth + 1, key)
          }
        }
      }
      walk(parsed, 1, '')
    } catch {
      // Non-JSON or truncated body: fall through to markup extraction.
    }
  }

  if (/html/i.test(ex.mediaType) || /<a\b[^>]+href=/i.test(ex.body)) {
    for (const match of ex.body.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
      if (found.length >= 16) break
      const href = match[1] ?? match[2] ?? ''
      const near = sameOriginPath(href, ex.origin)
      if (near) pushPath(near, 'href:')
    }
  }

  return found
}

const secretMatchKindSet: ReadonlySet<string> = new Set(secretMatchKinds)

/**
 * Whitelist-projects caller-supplied secret metadata before persistence. This is the last line of
 * defense: even if a caller mistakenly populates an extra field, only `kind`, `sha256Prefix`,
 * `fieldPath`, and `count` can reach the database, so raw tokens cannot be smuggled into storage.
 */
function sanitizeSecretMatches(matches: readonly SecretMatch[] | undefined, secrets: readonly NamedSecret[]): SecretMatch[] {
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
interface PendingExchangeWrite {
  row: typeof tables.brokerExchanges.$inferInsert
  /** Bounded body text for the FTS row (`preview` body or capped full body); null when FTS is off. */
  ftsBody: string | null
  eventMessage: string
  eventDetail: Record<string, unknown>
}

export class Store {
  readonly db
  readonly client: DatabaseSync
  readonly workspace
  readonly directory: string
  /** FTS indexing mode recorded in `store_settings` and honoured on every exchange write. */
  readonly ftsMode: FtsMode
  /** Bounded per-exchange body cap handed to FTS. */
  readonly ftsMaxBodyBytes: number
  /** DB size threshold above which `ftsMode: 'full'` is refused (unless forced). */
  readonly maxFullFtsDbBytes: number
  private readonly processLock: DatabaseSync
  private readonly emitter = new EventEmitter()
  private ftsAvailable = false
  /** True whenever the FTS5 virtual table exists, even if the active mode is `off`. */
  private ftsTableExists = false
  private txDepth = 0
  /** Bounded async write queue for broker exchanges (flushed by microtask/size boundary). */
  private pendingExchanges: PendingExchangeWrite[] = []
  private flushScheduled = false
  private flushing = false
  private flushError: unknown = null
  private static readonly maxPendingExchanges = 128

  constructor(directory: string, options: StoreOptions = {}) {
    this.directory = directory
    const requestedMode = options.ftsMode ?? DEFAULT_FTS_MODE
    if (!ftsModes.includes(requestedMode)) {
      throw new Error(`Invalid ftsMode '${String(requestedMode)}' (expected ${ftsModes.join('|')}).`)
    }
    this.ftsMode = requestedMode
    this.ftsMaxBodyBytes = Math.round(Math.min(
      MAX_FTS_MAX_BODY_BYTES,
      Math.max(MIN_FTS_MAX_BODY_BYTES, options.ftsMaxBodyBytes ?? DEFAULT_FTS_MAX_BODY_BYTES),
    ))
    this.maxFullFtsDbBytes = Math.max(0, options.maxFullFtsDbBytes ?? DEFAULT_MAX_FULL_FTS_DB_BYTES)
    this.emitter.setMaxListeners(256)
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    mkdirSync(join(directory, 'artifacts'), { recursive: true, mode: 0o700 })
    mkdirSync(join(directory, 'credentials'), { recursive: true, mode: 0o700 })
    this.processLock = new DatabaseSync(join(directory, 'process-lock.sqlite'))
    try {
      this.processLock.exec('BEGIN EXCLUSIVE')
    } catch {
      this.processLock.close()
      throw new Error('Another Guardian server is using this data directory.')
    }
    const path = join(directory, 'guardian.sqlite')
    if (!existsSync(path)) {
      try {
        writeFileSync(path, '', { flag: 'wx', mode: 0o600 })
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
    }
    const rawClient = new DatabaseSync(path, { timeout: 5000 })
    // v6 scale pragmas: WAL keeps readers non-blocking under the batched writer; NORMAL skips the
    // per-commit fsync (WAL still guarantees a consistent DB across process crashes), and the
    // busy timeout lets concurrent readers/snapshot copies wait instead of failing fast.
    rawClient.exec(
      'PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;',
    )
    // Transparent read-after-write safety: any direct `client.prepare/exec` (including engine code
    // and tests that bypass Store helpers) flushes queued exchanges first. Flush/transaction
    // internals are guarded, so this never recurses.
    this.client = new Proxy(rawClient, {
      get: (target, property) => {
        const value = Reflect.get(target, property, target)
        if (typeof value !== 'function') return value
        if (property === 'prepare' || property === 'exec') {
          return (...args: unknown[]) => {
            if (!this.flushing && this.txDepth === 0) this.flushNow()
            return (value as (...params: unknown[]) => unknown).apply(target, args)
          }
        }
        return value.bind(target)
      },
    }) as DatabaseSync
    this.db = drizzle({ client: this.client })
    const result = migrate(this.db, { migrationsFolder: resolve('drizzle') })
    if (result && 'exitCode' in result) throw new Error('Guardian database migration failed.')
    this.initV3Schema()
    this.initV4Schema()
    this.initV5Schema()
    this.initV6Schema()
    this.initV7Schema()
    this.initV8Schema()
    // v6.2 full-body FTS size guard: refuse to switch on an expensive index over a database that is
    // already large unless the operator explicitly forced it. Release the process lock so a
    // subsequent correctly-configured reopen can proceed.
    if (this.ftsMode === 'full' && !options.forceFullFts) {
      const dbBytes = safeFileSize(path)
      if (dbBytes > this.maxFullFtsDbBytes) {
        try { rawClient.close() } catch { /* teardown is best-effort */ }
        try { this.processLock.exec('ROLLBACK') } catch { /* ignore */ }
        try { this.processLock.close() } catch { /* ignore */ }
        throw new FtsModeRefusedError(dbBytes, this.maxFullFtsDbBytes)
      }
    }
    this.initFts()
    const current = this.db.select().from(tables.workspaces).limit(1).get()
    this.workspace = current ?? this.db.insert(tables.workspaces).values({
      id: randomUUID(),
      actorId: randomUUID(),
      name: 'Personal workspace',
      createdAt: Date.now(),
    }).returning().get()
    this.recordStoreSettings()
    this.recover()
  }

  private initV3Schema() {
    const existingColumns = (table: string): Set<string> => {
      const rows = this.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
      return new Set(rows.map(r => r.name))
    }
    const ensureColumn = (table: string, column: string, definition: string) => {
      if (!existingColumns(table).has(column)) {
        this.client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
      }
    }

    // model_profiles v3 columns
    ensureColumn('model_profiles', 'cached_input_cost_per_mtok', 'REAL NOT NULL DEFAULT 0.003')

    // projects v3 columns
    ensureColumn('projects', 'lab_config', 'TEXT')

    // personas v3 columns
    ensureColumn('personas', 'login_config', 'TEXT')

    // runs v3 Tier 3 approval policy columns
    ensureColumn('runs', 'approval_policy', "TEXT NOT NULL DEFAULT 'auto_review'")
    ensureColumn('runs', 'approved_endpoint_patterns', "TEXT NOT NULL DEFAULT '[]'")

    // approval_requests v3 audit trail columns
    ensureColumn('approval_requests', 'policy_note', 'TEXT')
    ensureColumn('approval_requests', 'risk_level', 'TEXT')

    // findings v3 columns
    ensureColumn('findings', 'verification_tier', 'TEXT')
    ensureColumn('findings', 'fingerprint_hash', 'TEXT')
    ensureColumn('findings', 'superseded_by_finding_id', 'TEXT')
    ensureColumn('findings', 'counterevidence', 'TEXT')
    ensureColumn('findings', 'confidence_rationale', 'TEXT')
    ensureColumn('findings', 'severity_change_conditions', 'TEXT')
    ensureColumn('findings', 'code_locations', 'TEXT')

    // coverage_entries v3 columns
    ensureColumn('coverage_entries', 'enforcing_control', 'TEXT')
    ensureColumn('coverage_entries', 'proof_gap_reason', 'TEXT')
    ensureColumn('coverage_entries', 'linked_finding_id', 'TEXT')

    // canaries v3 columns
    ensureColumn('canaries', 'protocol', `TEXT NOT NULL DEFAULT 'http'`)
    ensureColumn('canaries', 'dns_host', 'TEXT')
    ensureColumn('canaries', 'hit_count', 'INTEGER NOT NULL DEFAULT 0')

    // broker_exchanges v5 secret-disclosure metadata (redacted fingerprints; no raw values)
    ensureColumn('broker_exchanges', 'secret_matches', `TEXT NOT NULL DEFAULT '[]'`)

    // v3 tables & indexes
    this.client.exec(`
      CREATE INDEX IF NOT EXISTS findings_fingerprint ON findings (run_id, fingerprint_hash);

      CREATE TABLE IF NOT EXISTS sast_runs (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        assignment_id TEXT NOT NULL REFERENCES assignments(id),
        repo TEXT NOT NULL,
        engine TEXT NOT NULL,
        raw_artifact_id TEXT,
        finding_count INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sast_runs_run ON sast_runs (run_id);

      CREATE TABLE IF NOT EXISTS surface_probes (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        assignment_id TEXT NOT NULL REFERENCES assignments(id),
        scope_revision INTEGER NOT NULL,
        origin TEXT NOT NULL,
        probe_kind TEXT NOT NULL,
        requests_sent INTEGER NOT NULL DEFAULT 0,
        anomalies_found INTEGER NOT NULL DEFAULT 0,
        baseline_signature TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS surface_probes_run ON surface_probes (run_id, origin);

      CREATE TABLE IF NOT EXISTS patch_proposals (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        finding_id TEXT NOT NULL,
        repo TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        caller_compatibility TEXT NOT NULL DEFAULT 'attacker_only',
        diff TEXT NOT NULL,
        code_locations TEXT NOT NULL,
        review_notes TEXT NOT NULL DEFAULT '',
        dynamic_retest_verdict TEXT NOT NULL DEFAULT 'skipped',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS patch_proposals_run ON patch_proposals (run_id, finding_id);
    `)
  }

  private initV4Schema() {
    const existingColumns = (table: string): Set<string> => {
      const rows = this.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
      return new Set(rows.map(r => r.name))
    }
    const ensureColumn = (table: string, column: string, definition: string) => {
      if (!existingColumns(table).has(column)) {
        this.client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
      }
    }

    // model_profiles v4 columns
    ensureColumn('model_profiles', 'role_affinity', "TEXT NOT NULL DEFAULT 'any'")

    // projects v4 columns
    ensureColumn('projects', 'sandbox_write_allowlist', "TEXT NOT NULL DEFAULT '[]'")

    // runs v4 columns
    ensureColumn('runs', 'dynamic_step_budget', 'INTEGER')
    ensureColumn('runs', 'multi_trial_enabled', 'INTEGER NOT NULL DEFAULT 1')
    ensureColumn('runs', 'phase0_completed_at', 'INTEGER')

    // chain_steps v4 columns
    ensureColumn('chain_steps', 'specialist_profile', 'TEXT')
    ensureColumn('chain_steps', 'trial_group_id', 'TEXT')
    ensureColumn('chain_steps', 'trial_index', 'INTEGER NOT NULL DEFAULT 0')

    // replay_specs v4 columns
    ensureColumn('replay_specs', 'attempt_count', 'INTEGER NOT NULL DEFAULT 1')
    ensureColumn('replay_specs', 'verified_inline', 'INTEGER NOT NULL DEFAULT 0')
    ensureColumn('replay_specs', 'last_verification_diff', 'TEXT')

    // v4 tables & indexes
    this.client.exec(`
      CREATE TABLE IF NOT EXISTS endpoints (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        scope_revision INTEGER NOT NULL,
        origin TEXT NOT NULL,
        method TEXT NOT NULL,
        path_template TEXT NOT NULL,
        source TEXT NOT NULL,
        framework TEXT,
        auth_requirement TEXT,
        ownership_guard TEXT,
        sink_kinds TEXT NOT NULL DEFAULT '[]',
        tested_classes TEXT NOT NULL DEFAULT '[]',
        coverage_pct REAL,
        risk_score INTEGER NOT NULL DEFAULT 50,
        code_location TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS endpoints_run_route ON endpoints (run_id, origin, method, path_template);
      CREATE INDEX IF NOT EXISTS endpoints_run_risk ON endpoints (run_id, risk_score);

      CREATE TABLE IF NOT EXISTS endpoint_params (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        inferred_type TEXT,
        is_csrf INTEGER NOT NULL DEFAULT 0,
        is_object_id INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS endpoint_params_unique ON endpoint_params (endpoint_id, name, location);
      CREATE INDEX IF NOT EXISTS endpoint_params_run ON endpoint_params (run_id, endpoint_id);

      CREATE TABLE IF NOT EXISTS api_dependencies (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        producer_endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
        consumer_endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
        resource_key TEXT NOT NULL,
        sample_resource_id_hash TEXT,
        persona_handle TEXT,
        observed_transitions TEXT NOT NULL DEFAULT '[]',
        tested_bola INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS api_dependencies_edge ON api_dependencies (run_id, producer_endpoint_id, consumer_endpoint_id, resource_key);
      CREATE INDEX IF NOT EXISTS api_dependencies_run ON api_dependencies (run_id, tested_bola);

      CREATE TABLE IF NOT EXISTS second_order_canaries (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        assignment_id TEXT NOT NULL,
        marker TEXT NOT NULL UNIQUE,
        injected_origin TEXT NOT NULL,
        injected_endpoint TEXT NOT NULL,
        injected_param TEXT NOT NULL,
        injected_persona TEXT,
        surfaced_origin TEXT,
        surfaced_endpoint TEXT,
        surfaced_persona TEXT,
        surfaced_exchange_id TEXT,
        status TEXT NOT NULL DEFAULT 'planted',
        created_at INTEGER NOT NULL,
        surfaced_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS second_order_canaries_run ON second_order_canaries (run_id, status);

      CREATE TABLE IF NOT EXISTS lab_telemetry (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        exchange_id TEXT NOT NULL,
        trace_id TEXT NOT NULL,
        routes_hit TEXT NOT NULL DEFAULT '[]',
        new_lines_covered INTEGER NOT NULL DEFAULT 0,
        sink_events_count INTEGER NOT NULL DEFAULT 0,
        has_unhandled_exception INTEGER NOT NULL DEFAULT 0,
        artifact_id TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS lab_telemetry_run ON lab_telemetry (run_id, created_at);
      CREATE UNIQUE INDEX IF NOT EXISTS lab_telemetry_trace ON lab_telemetry (run_id, trace_id);

      CREATE TABLE IF NOT EXISTS benchmark_runs (
        id TEXT PRIMARY KEY NOT NULL,
        suite TEXT NOT NULL,
        git_sha TEXT NOT NULL,
        model_routing_config TEXT NOT NULL DEFAULT '{}',
        targets_total INTEGER NOT NULL,
        confirmed_count INTEGER NOT NULL,
        false_positive_count INTEGER NOT NULL,
        funnel_counts TEXT NOT NULL,
        failure_taxonomy TEXT NOT NULL,
        total_cost_usd REAL NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS benchmark_runs_suite ON benchmark_runs (suite, created_at);
    `)
  }

  /**
   * v5 Swarm Message Board tables. `CREATE TABLE IF NOT EXISTS` + defensive column backfill keeps
   * every v2–v4 SQLite database losslessly upgradable in place (no destructive rebuilds).
   */
  private initV5Schema() {
    this.client.exec(`
      CREATE TABLE IF NOT EXISTS board_members (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        handle TEXT NOT NULL,
        role TEXT NOT NULL,
        specialist_profile TEXT,
        session_id TEXT NOT NULL,
        active_assignment_id TEXT,
        state TEXT NOT NULL,
        role_affinity TEXT,
        last_read_seq INTEGER NOT NULL DEFAULT 0,
        turns_used INTEGER NOT NULL DEFAULT 0,
        posts_count INTEGER NOT NULL DEFAULT 0,
        peer_hops_used INTEGER NOT NULL DEFAULT 0,
        scope_revision INTEGER NOT NULL,
        goal_revision INTEGER NOT NULL,
        source_origins TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS board_members_run_handle ON board_members (run_id, handle);
      CREATE INDEX IF NOT EXISTS board_members_run_state ON board_members (run_id, state);

      CREATE TABLE IF NOT EXISTS board_messages (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        seq INTEGER NOT NULL,
        author_handle TEXT NOT NULL,
        author_role TEXT NOT NULL,
        kind TEXT NOT NULL,
        mentions TEXT NOT NULL,
        body TEXT NOT NULL,
        ref_fact_ids TEXT NOT NULL,
        ref_exchange_ids TEXT NOT NULL,
        ref_finding_ids TEXT NOT NULL,
        ref_step_id TEXT,
        ref_approval_id TEXT,
        reply_to_seq INTEGER,
        scope_revision INTEGER NOT NULL,
        goal_revision INTEGER NOT NULL,
        source_origins TEXT NOT NULL,
        tainted INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS board_messages_run_seq ON board_messages (run_id, seq);
      CREATE INDEX IF NOT EXISTS board_messages_run_tainted ON board_messages (run_id, tainted, seq);

      -- v5 M2.1: redacted non-secret sample identifiers harvested per (run, owner persona, collection, resource key).
      CREATE TABLE IF NOT EXISTS resource_samples (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        owner_persona TEXT NOT NULL,
        resource_key TEXT NOT NULL,
        collection_path TEXT NOT NULL DEFAULT '',
        resource_id TEXT NOT NULL,
        origin TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        media_type TEXT,
        authenticated INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS resource_samples_key ON resource_samples (run_id, owner_persona, origin, collection_path, resource_key);
      CREATE INDEX IF NOT EXISTS resource_samples_run ON resource_samples (run_id, resource_key);
    `)

    const existingColumns = (table: string): Set<string> => {
      const rows = this.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
      return new Set(rows.map(r => r.name))
    }
    const ensureColumn = (table: string, column: string, definition: string) => {
      if (!existingColumns(table).has(column)) {
        this.client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
      }
    }

    for (const [column, definition] of [
      ['role_affinity', 'TEXT'],
      ['last_read_seq', 'INTEGER NOT NULL DEFAULT 0'],
      ['turns_used', 'INTEGER NOT NULL DEFAULT 0'],
      ['posts_count', 'INTEGER NOT NULL DEFAULT 0'],
      ['peer_hops_used', 'INTEGER NOT NULL DEFAULT 0'],
      ['active_assignment_id', 'TEXT'],
      ['updated_at', 'INTEGER NOT NULL DEFAULT 0'],
    ] as const) {
      ensureColumn('board_members', column, definition)
    }
    for (const [column, definition] of [
      ['ref_fact_ids', "TEXT NOT NULL DEFAULT '[]'"],
      ['ref_exchange_ids', "TEXT NOT NULL DEFAULT '[]'"],
      ['ref_finding_ids', "TEXT NOT NULL DEFAULT '[]'"],
      ['ref_step_id', 'TEXT'],
      ['ref_approval_id', 'TEXT'],
      ['reply_to_seq', 'INTEGER'],
      ['tainted', 'INTEGER NOT NULL DEFAULT 0'],
    ] as const) {
      ensureColumn('board_messages', column, definition)
    }

    // Backfill the deterministic system roster for runs created before v5 so an upgraded
    // database renders a complete Board tab without mutating any existing evidence rows.
    this.client.exec(`
      INSERT OR IGNORE INTO board_members
        (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
      SELECT lower(hex(randomblob(16))), id, 'coordinator', 'coordinator', coordinator_id, 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
      INSERT OR IGNORE INTO board_members
        (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
      SELECT lower(hex(randomblob(16))), id, 'verifier', 'verifier', 'system:verifier', 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
      INSERT OR IGNORE INTO board_members
        (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
      SELECT lower(hex(randomblob(16))), id, 'broker', 'system', 'system:broker', 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
      INSERT OR IGNORE INTO board_members
        (id, run_id, handle, role, session_id, state, scope_revision, goal_revision, source_origins, created_at, updated_at)
      SELECT lower(hex(randomblob(16))), id, 'canary', 'system', 'system:canary', 'waiting', scope_revision, goal_revision, '[]', created_at, created_at FROM runs;
    `)
  }

  /**
   * v6 scale/data-integrity migration. Additive only:
   * - `resource_samples.collection_path` + a wider unique key (backfilled with `''`).
   * - `lab_containers` registry for crash recovery.
   * - pagination indexes so `runDetail`/`listEndpoints`/`listFacts` do not scan whole tables.
   * `PRAGMA user_version = STORE_SCHEMA_VERSION` stamps the upgrade.
   */
  private initV6Schema() {
    const existingColumns = (table: string): Set<string> => {
      const rows = this.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
      return new Set(rows.map(r => r.name))
    }
    const ensureColumn = (table: string, column: string, definition: string) => {
      if (!existingColumns(table).has(column)) {
        this.client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
        return true
      }
      return false
    }

    ensureColumn('resource_samples', 'collection_path', "TEXT NOT NULL DEFAULT ''")
    this.client.exec("UPDATE resource_samples SET collection_path = '' WHERE collection_path IS NULL")

    // v6 Phase 2 Layer-1 scope + environment contract (additive).
    // The legacy approved-candidate allowlist stays the target tier; auth/asset tiers are additive.
    const hadEnvironmentMode = existingColumns('runs').has('environment_mode')
    ensureColumn('runs', 'auth_origins', "TEXT NOT NULL DEFAULT '[]'")
    ensureColumn('runs', 'asset_origins', "TEXT NOT NULL DEFAULT '[]'")
    ensureColumn('runs', 'environment_mode', "TEXT NOT NULL DEFAULT 'prod_readonly'")
    ensureColumn('runs', 'route_denylist', "TEXT NOT NULL DEFAULT '[]'")
    ensureColumn('assignments', 'approval_parked_at', 'INTEGER')

    // v6 provenance / advisory contract (additive; safe on legacy databases).
    const previousVersion = Number(
      (this.client.prepare('PRAGMA user_version').get() as { user_version?: number } | undefined)?.user_version ?? 0,
    )
    const addedProvenance = ensureColumn(
      'findings', 'provenance',
      "TEXT NOT NULL DEFAULT 'agent_only' CHECK (provenance IN ('floor', 'agent_only', 'chain_from_floor'))",
    )
    const addedParents = ensureColumn('findings', 'parent_finding_ids', 'TEXT')
    const addedVerificationClass = ensureColumn(
      'findings', 'verification_class',
      "TEXT NOT NULL DEFAULT 'runtime_confirmed' CHECK (verification_class IN ('runtime_confirmed', 'pending_oob', 'static_advisory', 'open_proof_gap', 'dismissed')) "
      + "CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_class = 'runtime_confirmed') "
      + "CHECK (json_extract(finding, '$.status') <> 'confirmed' OR verification_tier IS NULL OR verification_tier <> 'static_verified')",
    )
    if (addedProvenance || addedParents || addedVerificationClass || previousVersion < STORE_SCHEMA_VERSION) {
      this.backfillFindingsProvenance()
    }
    this.client.exec(`
      CREATE INDEX IF NOT EXISTS findings_provenance ON findings (run_id, provenance);
    `)

    if (!hadEnvironmentMode) {
      // Existing local-lab runs keep autonomous testing; every other existing run starts read-only.
      this.client.exec(`
        UPDATE runs SET environment_mode = 'ephemeral_lab'
        WHERE project_id IN (SELECT id FROM projects WHERE environment = 'local-lab')
      `)
    }

    const desiredColumns = ['run_id', 'owner_persona', 'origin', 'collection_path', 'resource_key']
    const currentColumns = (this.client.prepare('PRAGMA index_info(resource_samples_key)').all() as Array<{ name: string }>)
      .map(row => row.name)
    if (currentColumns.join(',') !== desiredColumns.join(',')) {
      this.client.exec(`
        DROP INDEX IF EXISTS resource_samples_key;
        CREATE UNIQUE INDEX resource_samples_key ON resource_samples (run_id, owner_persona, origin, collection_path, resource_key);
      `)
    }

    this.client.exec(`
      CREATE TABLE IF NOT EXISTS lab_containers (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        assignment_id TEXT,
        container_name TEXT NOT NULL,
        image_name TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS lab_containers_name ON lab_containers (run_id, container_name);
      CREATE INDEX IF NOT EXISTS lab_containers_run ON lab_containers (run_id, status);

      CREATE TABLE IF NOT EXISTS approval_leases (
        id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(id),
        scope_revision INTEGER NOT NULL,
        origin TEXT NOT NULL,
        method TEXT NOT NULL,
        route_pattern TEXT NOT NULL,
        persona_handle TEXT,
        status TEXT NOT NULL,
        source_approval_id TEXT,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        uses INTEGER NOT NULL DEFAULT 0,
        last_used_at INTEGER
      );
      CREATE UNIQUE INDEX IF NOT EXISTS approval_leases_route
        ON approval_leases (run_id, origin, method, route_pattern, scope_revision);
      CREATE INDEX IF NOT EXISTS approval_leases_run ON approval_leases (run_id, status);

      CREATE INDEX IF NOT EXISTS broker_exchanges_run_created ON broker_exchanges (run_id, created_at);
      CREATE INDEX IF NOT EXISTS broker_exchanges_body_artifact ON broker_exchanges (body_artifact_id);
      CREATE INDEX IF NOT EXISTS facts_run_created ON facts (run_id, created_at);
      CREATE INDEX IF NOT EXISTS endpoints_run_updated ON endpoints (run_id, updated_at);
      CREATE INDEX IF NOT EXISTS evidence_run_created ON evidence (run_id, created_at);

      CREATE TABLE IF NOT EXISTS store_settings (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `)
    this.initConfirmationGuards()
  }

  /**
   * v7 M5 agent-script proof storage (additive, safe on legacy databases).
   *
   * A Layer-3 `guardian_verify` proof persists its oracle verdict, the receipt it was re-checked
   * with and the owner-only artifact holding script source + receipt. Declarative columns stay for
   * attribution; confirmation/retest are receipt-first. No backfill is needed: pre-migration rows
   * are simply not script proofs.
   */
  private initV7Schema() {
    const existingColumns = (table: string): Set<string> => {
      const rows = this.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
      return new Set(rows.map(r => r.name))
    }
    const ensureColumn = (table: string, column: string, definition: string) => {
      if (!existingColumns(table).has(column)) {
        this.client.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`)
      }
    }
    ensureColumn('replay_specs', 'proof_kind', 'TEXT')
    ensureColumn('replay_specs', 'proof_verdict', 'TEXT')
    ensureColumn('replay_specs', 'proof_runtime', 'TEXT')
    ensureColumn('replay_specs', 'proof_script_sha256', 'TEXT')
    ensureColumn('replay_specs', 'proof_artifact_id', 'TEXT')
    ensureColumn('replay_specs', 'proof_receipt', 'TEXT')
    ensureColumn('project_assets', 'include_subdomains', 'INTEGER NOT NULL DEFAULT 0')
    // v7 M4: per-tenant isolation & append-only tenant audit log (additive, safe on legacy DBs).
    ensureColumn('projects', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
    ensureColumn('runs', 'tenant_id', "TEXT NOT NULL DEFAULT 'default'")
    this.client.exec(`
      CREATE INDEX IF NOT EXISTS replay_specs_proof ON replay_specs (run_id, proof_kind);
      CREATE INDEX IF NOT EXISTS projects_tenant ON projects (tenant_id);
      CREATE INDEX IF NOT EXISTS runs_tenant ON runs (tenant_id);
      CREATE TABLE IF NOT EXISTS tenant_audit_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        tenant_id TEXT NOT NULL,
        run_id TEXT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_kind TEXT NOT NULL,
        resource_id TEXT,
        outcome TEXT NOT NULL,
        detail TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tenant_audit_log_tenant ON tenant_audit_log (tenant_id, seq);
      CREATE TRIGGER IF NOT EXISTS tenant_audit_log_no_update
        BEFORE UPDATE ON tenant_audit_log
        BEGIN
          SELECT RAISE(ABORT, 'invariant.audit_log_append_only');
        END;
      CREATE TRIGGER IF NOT EXISTS tenant_audit_log_no_delete
        BEFORE DELETE ON tenant_audit_log
        BEGIN
          SELECT RAISE(ABORT, 'invariant.audit_log_append_only');
        END;
    `)
    this.client.exec(`PRAGMA user_version = ${STORE_SCHEMA_VERSION}`)
  }

  /** v8 M0: idempotent CapabilityLedger tables & indexes on the shared WAL SQLite handle. */
  private initV8Schema() {
    initCapabilityLedgerSchema(this.client)
  }

  /**
   * Return a run-scoped v8 `CapabilityLedger` bound directly to this Store's shared WAL
   * `DatabaseSync` handle (zero extra SQLite connections; closing the returned view is a no-op).
   */
  capabilityLedger(runId: string, options: Omit<CapabilityLedgerOptions, 'runId'> = {}): CapabilityLedger {
    return new CapabilityLedger(this.client, { ...options, runId })
  }

  /**
   * Database-level confirmation guard (defence in depth for the store invariant).
   *
   * A row may only be `verification_class = 'runtime_confirmed'` + `status = 'confirmed'` while the
   * same database holds confirming evidence: the linked replay spec's persisted diff verdict is
   * `confirmed`, a verified OOB ProofReceipt, or a baseline review. Direct SQL writers (migrations,
   * ad-hoc scripts, future call sites) are aborted with `invariant.confirmation_evidence` instead of
   * persisting a confirmed claim contradicted by its own evidence.
   */
  private initConfirmationGuards() {
    if (!this.tableExists('findings') || !this.tableExists('replay_specs')) return
    const guard = (name: string, event: 'INSERT' | 'UPDATE OF verification_class, replay_spec_id, finding, verification_tier') => `
      CREATE TRIGGER IF NOT EXISTS ${name}
      BEFORE ${event} ON findings
      WHEN NEW.verification_class = 'runtime_confirmed'
        AND json_extract(NEW.finding, '$.status') = 'confirmed'
        AND coalesce(NEW.finding_kind, '') <> 'baseline_check'
        AND coalesce(NEW.verification_tier, json_extract(NEW.finding, '$.verificationTier'), '') <> 'baseline_confirmed'
        AND coalesce(json_extract(NEW.finding, '$.verification'), '') NOT LIKE 'ProofReceipt%'
        AND NOT EXISTS (
          SELECT 1 FROM replay_specs s
          WHERE s.id = NEW.replay_spec_id
            AND json_extract(s.last_verification_diff, '$.verdict') = 'confirmed'
        )
        ${this.tableExists('events') ? `AND NOT EXISTS (
          SELECT 1 FROM events e
          WHERE e.run_id = NEW.run_id
            AND e.kind = 'oob.receipt_confirmed'
            AND json_extract(e.detail, '$.findingId') = NEW.id
        )` : ''}
      BEGIN
        SELECT RAISE(ABORT, 'invariant.confirmation_evidence');
      END;
    `
    try {
      this.client.exec(guard('findings_confirmation_evidence_insert', 'INSERT'))
      this.client.exec(guard('findings_confirmation_evidence_update', 'UPDATE OF verification_class, replay_spec_id, finding, verification_tier'))
    } catch (error) {
      // Never block startup on an old SQLite build that lacks json_extract; the store-level
      // InvariantError remains authoritative.
      if (!/json_extract|syntax error/i.test((error as Error).message)) throw error
    }
  }

  /**
   * Additive backfill for pre-provenance databases:
   *  - static/open-proof-gap findings become advisories (never confirmed),
   *  - findings emitted by `deterministic_engine.confirmed` become `floor`.
   * Idempotent; the CHECK constraints guard every later write.
   */
  private backfillFindingsProvenance() {
    if (!this.tableExists('findings')) return
    this.client.exec(`
      -- A legacy "confirmed" row that was only static-verified is a static item, not a runtime
      -- confirmation. Correct the embedded status before class backfill so it can never leak
      -- into queryFindings()/report confirmed counts.
      UPDATE findings
      SET finding = json_set(finding, '$.status', 'static_verified')
      WHERE verification_tier = 'static_verified'
        AND json_extract(finding, '$.status') = 'confirmed';

      UPDATE findings
      SET verification_class = 'static_advisory'
      WHERE verification_class <> 'static_advisory'
        AND (json_extract(finding, '$.status') = 'static_verified' OR verification_tier = 'static_verified');

      UPDATE findings
      SET verification_class = 'dismissed'
      WHERE verification_class <> 'dismissed'
        AND json_extract(finding, '$.status') = 'dismissed';

      UPDATE findings
      SET verification_class = 'pending_oob'
      WHERE verification_class NOT IN ('pending_oob', 'dismissed')
        AND json_extract(finding, '$.status') IN ('pending', 'inconclusive')
        AND lower(coalesce(json_extract(finding, '$.runtimeProofGap'), '') || ' '
          || coalesce(json_extract(finding, '$.verification'), '') || ' '
          || coalesce(json_extract(finding, '$.reason'), '')) GLOB '*pending*oob*';

      UPDATE findings
      SET verification_class = 'open_proof_gap'
      WHERE verification_class = 'runtime_confirmed'
        AND json_extract(finding, '$.status') IN ('pending', 'inconclusive');
    `)
    if (this.tableExists('events')) {
      this.client.exec(`
        UPDATE findings
        SET provenance = 'floor'
        WHERE provenance = 'agent_only'
          AND EXISTS (
            SELECT 1 FROM events e
            WHERE e.run_id = findings.run_id
              AND e.kind = 'deterministic_engine.confirmed'
              AND json_extract(e.detail, '$.findingId') = findings.id
          );
      `)
    }
  }

  private tableExists(table: string): boolean {
    const row = this.client.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
    ).get(table) as { name?: string } | undefined
    return Boolean(row?.name)
  }

  /** Durably record the storage/FTS configuration this DB was opened with. */
  private recordStoreSettings() {
    const upsert = this.client.prepare(
      'INSERT INTO store_settings (key, value, updated_at) VALUES (?, ?, ?) '
      + 'ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
    )
    const now = Date.now()
    upsert.run('fts_mode', this.ftsMode, now)
    upsert.run('fts_max_body_bytes', String(this.ftsMaxBodyBytes), now)
  }

  private initFts() {
    // Mode `off`: do not create a new index and do not write/query FTS rows. A pre-existing table
    // (from an earlier `preview`/`full` process) is preserved so re-enabling search is lossless.
    if (this.ftsMode === 'off') {
      const existing = this.client.prepare(
        "SELECT count(*) AS c FROM sqlite_master WHERE type = 'table' AND name = 'broker_exchanges_fts'",
      ).get() as { c?: number } | undefined
      this.ftsTableExists = Number(existing?.c ?? 0) > 0
      this.ftsAvailable = false
      return
    }
    try {
      this.client.exec(`
        CREATE VIRTUAL TABLE IF NOT EXISTS broker_exchanges_fts USING fts5(
          exchange_id UNINDEXED,
          run_id UNINDEXED,
          origin,
          method,
          path_and_query,
          req_headers,
          resp_headers,
          body_preview,
          tokenize='trigram'
        );
      `)
      this.ftsAvailable = true
    } catch {
      try {
        this.client.exec(`
          CREATE VIRTUAL TABLE IF NOT EXISTS broker_exchanges_fts USING fts5(
            exchange_id UNINDEXED,
            run_id UNINDEXED,
            origin,
            method,
            path_and_query,
            req_headers,
            resp_headers,
            body_preview
          );
        `)
        this.ftsAvailable = true
      } catch {
        this.ftsAvailable = false
      }
    }
    this.ftsTableExists = this.ftsAvailable
  }

  close() {
    try { this.flushNow() } catch { /* teardown is best-effort */ }
    try { this.client.close() } catch { /* ignore */ }
    try { this.processLock.exec('ROLLBACK') } catch { /* ignore */ }
    try { this.processLock.close() } catch { /* ignore */ }
  }

  /**
   * Durably flush every queued exchange write. Called by tests, teardown, snapshot capture and
   * every read-after-write path (`getExchange`, `runDetail`, `searchExchanges`, report authoring).
   * Safe to call repeatedly; a no-op when the queue is empty.
   */
  flushNow(): void {
    if (this.txDepth > 0) return
    if (this.flushing) return
    const priorError = this.flushError
    this.flushError = null
    if (!this.pendingExchanges.length) {
      if (priorError) throw priorError
      return
    }
    const batch = this.pendingExchanges.splice(0, this.pendingExchanges.length)
    this.flushing = true
    try {
      this.client.exec('BEGIN IMMEDIATE')
      try {
        this.applyExchangeBatch(batch)
        this.client.exec('COMMIT')
      } catch (error) {
        try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
        this.pendingExchanges.unshift(...batch)
        throw error
      }
    } finally {
      this.flushing = false
    }
    if (priorError) throw priorError
  }

  /** Queue one fully-redacted exchange row, flushing synchronously at the bounded size boundary. */
  private enqueueExchange(item: PendingExchangeWrite) {
    if (this.txDepth > 0) {
      this.applyExchangeBatch([item])
      return
    }
    this.pendingExchanges.push(item)
    if (this.pendingExchanges.length >= Store.maxPendingExchanges) {
      this.flushNow()
      return
    }
    this.scheduleFlush()
  }

  private scheduleFlush() {
    if (this.flushScheduled || this.flushing || this.txDepth > 0) return
    this.flushScheduled = true
    queueMicrotask(() => {
      this.flushScheduled = false
      if (!this.pendingExchanges.length || this.flushing || this.txDepth > 0) return
      try {
        this.flushNow()
      } catch (error) {
        this.flushError ??= error
      }
    })
  }

  /**
   * Insert a batch of exchanges, their FTS rows, run/assignment request counters and audit events
   * inside one IMMEDIATE transaction. Bulk values keep a 128-exchange flush well under 50 ms.
   */
  private applyExchangeBatch(batch: readonly PendingExchangeWrite[]) {
    if (!batch.length) return
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
    const inserted = this.db.insert(tables.events).values(eventRows).returning().all()
    queueMicrotask(() => {
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

  transaction<T>(fn: () => T, _options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T {
    if (this.txDepth === 0) {
      // Preserve write ordering: never open a transaction while exchange writes are pending.
      this.flushNow()
      this.txDepth += 1
      this.client.exec('BEGIN IMMEDIATE')
      try {
        const result = fn()
        this.client.exec('COMMIT')
        return result
      } catch (error) {
        try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
        throw error
      } finally {
        this.txDepth -= 1
      }
    }
    const sp = `sp_${++this.txDepth}`
    this.client.exec(`SAVEPOINT ${sp}`)
    try {
      const result = fn()
      this.client.exec(`RELEASE SAVEPOINT ${sp}`)
      return result
    } catch (error) {
      try {
        this.client.exec(`ROLLBACK TO SAVEPOINT ${sp}`)
        this.client.exec(`RELEASE SAVEPOINT ${sp}`)
      } catch { /* ignore */ }
      throw error
    } finally {
      this.txDepth -= 1
    }
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

  emitWake() {
    queueMicrotask(() => { this.emitter.emit('wake') })
  }

  /**
   * Crash recovery (idempotent). Resets interrupted runs, stuck board members and stale
   * assignments, expires pending approval leases, and reclaims persisted LabRunner container rows.
   * Permanently `failed` assignments are never re-queued.
   */
  recover(now = Date.now()): RecoveryReport {
    if (this.txDepth > 0) throw new Error('recover() cannot run inside an open transaction.')
    this.flushNow()
    const report: RecoveryReport = {
      pausedRuns: 0,
      requeuedAssignments: 0,
      resetBoardMembers: 0,
      expiredApprovals: 0,
      reclaimedContainers: [],
      changed: false,
    }
    this.transaction(() => {
      const runRows = this.db.select({ id: tables.runs.id, status: tables.runs.status }).from(tables.runs)
        .where(and(
          eq(tables.runs.workspaceId, this.workspace.id),
          inArray(tables.runs.status, ['running', 'paused']),
        )).all()
      const runIds = runRows.map(row => row.id)
      const interrupted = runRows.filter(row => row.status === 'running')

      for (const row of interrupted) {
        const run = this.run(row.id)
        this.setStatus(run, 'paused')
        this.db.update(tables.chainSteps).set({ status: 'ready', assignedWorkerId: null, updatedAt: now })
          .where(and(eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.status, 'running'))).run()
        report.pausedRuns += 1
      }

      if (runIds.length) {
        const placeholders = runIds.map(() => '?').join(', ')
        const requeued = this.client.prepare(
          `UPDATE assignments SET status = 'queued', lease = NULL, lease_expires_at = NULL
           WHERE run_id IN (${placeholders}) AND (
             status IN ('running', 'paused')
             OR (status = 'waiting_approval' AND approval_parked_at IS NULL)
           )`,
        ).run(...runIds) as { changes?: number }
        report.requeuedAssignments = Number(requeued.changes ?? 0)

        const resetMembers = this.client.prepare(
          `UPDATE board_members SET state = 'waiting', active_assignment_id = NULL, updated_at = ?
           WHERE run_id IN (${placeholders}) AND state = 'working'`,
        ).run(now, ...runIds) as { changes?: number }
        report.resetBoardMembers = Number(resetMembers.changes ?? 0)
      }

      const expired = this.client.prepare(
        `UPDATE approval_requests SET status = 'expired', decided_at = ?,
           policy_note = coalesce(policy_note, 'Expired approval lease cleared during crash recovery.')
         WHERE status = 'pending' AND expires_at < ?
           AND run_id IN (SELECT id FROM runs WHERE workspace_id = ?)`,
      ).run(now, now, this.workspace.id) as { changes?: number }
      report.expiredApprovals = Number(expired.changes ?? 0)

      const orphanedRows = this.db.select().from(tables.labContainers)
        .where(eq(tables.labContainers.status, 'orphaned')).all()
      const liveRows = runIds.length
        ? this.db.select().from(tables.labContainers).where(and(
            eq(tables.labContainers.status, 'running'),
            inArray(tables.labContainers.runId, runIds),
          )).all()
        : []
      const containerRows = [...orphanedRows, ...liveRows]
      const uniqueContainers = new Map(containerRows.map(row => [row.id, row]))
      if (uniqueContainers.size) {
        const ids = [...uniqueContainers.keys()]
        const deleteStmt = this.client.prepare(`DELETE FROM lab_containers WHERE id IN (${ids.map(() => '?').join(', ')})`)
        deleteStmt.run(...ids)
        report.reclaimedContainers = [...uniqueContainers.values()]
          .map(row => ({ runId: row.runId, containerName: row.containerName }))
      }

      for (const row of interrupted) {
        this.event(row.id, 'interrupted', 'The application restarted. Resume to continue from saved evidence.')
      }

      report.changed = report.pausedRuns > 0 || report.requeuedAssignments > 0
        || report.resetBoardMembers > 0 || report.expiredApprovals > 0 || report.reclaimedContainers.length > 0

      if (report.reclaimedContainers.length || report.expiredApprovals) {
        this.event(null, 'recovery.completed', 'Crash recovery reclaimed runtime state.', {
          pausedRuns: report.pausedRuns,
          requeuedAssignments: report.requeuedAssignments,
          resetBoardMembers: report.resetBoardMembers,
          expiredApprovals: report.expiredApprovals,
          reclaimedContainers: report.reclaimedContainers.map(row => row.containerName).slice(0, 50),
        })
      }
    }, { behavior: 'immediate' })
    return report
  }

  // --- LabRunner container registry (v6 crash recovery) ------------------------------

  recordLabContainer(input: {
    runId: string
    assignmentId?: string | null
    containerName: string
    imageName?: string | null
    status?: LabContainerRow['status']
  }): LabContainerRow {
    const now = Date.now()
    const existing = this.db.select().from(tables.labContainers).where(and(
      eq(tables.labContainers.runId, input.runId),
      eq(tables.labContainers.containerName, input.containerName),
    )).get()
    if (existing) {
      return this.db.update(tables.labContainers).set({
        assignmentId: input.assignmentId !== undefined ? input.assignmentId : existing.assignmentId,
        imageName: input.imageName !== undefined ? input.imageName : existing.imageName,
        status: input.status ?? existing.status,
        updatedAt: now,
      }).where(eq(tables.labContainers.id, existing.id)).returning().get()!
    }
    return this.db.insert(tables.labContainers).values({
      id: randomUUID(),
      runId: input.runId,
      assignmentId: input.assignmentId ?? null,
      containerName: input.containerName,
      imageName: input.imageName ?? null,
      status: input.status ?? 'running',
      createdAt: now,
      updatedAt: now,
    }).returning().get()
  }

  markLabContainerOrphaned(runId: string, containerName: string) {
    this.db.update(tables.labContainers).set({ status: 'orphaned', updatedAt: Date.now() }).where(and(
      eq(tables.labContainers.runId, runId),
      eq(tables.labContainers.containerName, containerName),
    )).run()
  }

  listLabContainers(runId: string): LabContainerRow[] {
    return this.db.select().from(tables.labContainers).where(eq(tables.labContainers.runId, runId))
      .orderBy(asc(tables.labContainers.createdAt), asc(tables.labContainers.containerName)).all()
  }


  event(runId: string | null, kind: string, message: string, detail: Record<string, unknown> = {}) {
    const inserted = this.db.insert(tables.events).values({
      workspaceId: this.workspace.id, runId, kind, message: redact(message), detail, createdAt: Date.now(),
    }).returning().get()
    const payload: RunEventPayload = {
      id: inserted.id,
      kind: inserted.kind,
      message: inserted.message,
      detail: inserted.detail,
      createdAt: inserted.createdAt,
    }
    queueMicrotask(() => {
      if (runId) this.emitter.emit('run:' + runId, payload)
      this.emitter.emit('wake')
    })
    return inserted
  }

  message(runId: string, threadId: string, role: typeof tables.messages.$inferSelect.role, content: string,
    replyTo?: string, evidenceIds?: string[], secrets: readonly NamedSecret[] = []) {
    const id = randomUUID()
    this.db.insert(tables.messages).values({
      id, runId, threadId, role, content: redact(content, secrets), replyTo, evidenceIds, createdAt: Date.now(),
    }).onConflictDoNothing().run()
    queueMicrotask(() => {
      this.emitter.emit('run:' + runId, { id: 0, kind: 'message', message: '', detail: { threadId, role }, createdAt: Date.now() })
    })
    return id
  }

  // --- v5 Swarm Message Board ---

  private approvedOriginsFor(run: Run): Set<string> {
    const approved = new Set(run.approved)
    return new Set(run.candidates.filter(candidate => approved.has(candidate.id)).map(candidate => candidate.origin))
  }

  /**
   * v6 three-tier scope for a run. `targetOrigins` remains the legacy approved-candidate allowlist
   * (so every pre-v6 database upgrades without data loss); `authOrigins`/`assetOrigins` are
   * additive benign-infrastructure tiers.
   */
  scopePolicy(runOrId: Run | string): ScopePolicy {
    const run = typeof runOrId === 'string' ? this.run(runOrId) : runOrId
    return {
      mode: run.environmentMode ?? defaultEnvironmentMode(this.project(run.projectId).environment),
      targetOrigins: [...this.approvedOriginsFor(run)],
      authOrigins: [...(run.authOrigins ?? [])],
      assetOrigins: [...(run.assetOrigins ?? [])],
      routeDenylist: [...(run.routeDenylist ?? [])],
      tenantTag: tenantTagForRun(run.id),
      runId: run.id,
    }
  }

  /** Target + benign auth/asset origins, used for provenance and revocation decisions. */
  private provenanceOriginsFor(run: Run): Set<string> {
    return provenanceOriginsFor(this.scopePolicy(run))
  }

  setEnvironmentMode(run: Run, mode: EnvironmentMode): Run {
    if (!environmentModes.includes(mode)) throw new Error('Unknown environment mode.')
    if (['complete', 'stopped', 'failed'].includes(run.status)) {
      throw new Error('Cannot change the environment mode after a run has ended.')
    }
    const updated = this.updateRun(run.id, { environmentMode: mode })
    this.event(run.id, 'scope.environment_mode', `Environment contract set to ${mode}.`, {
      environmentMode: mode,
    })
    return updated
  }

  setRouteDenylist(run: Run, routes: readonly string[]): Run {
    const normalized: string[] = []
    for (const entry of routes) {
      const path = (entry ?? '').trim()
      if (!path) continue
      if (!path.startsWith('/')) throw new Error('Route denylist entries must start with "/".')
      if (/[\r\n\0]/.test(path)) throw new Error('Invalid route denylist entry.')
      normalized.push(path)
    }
    const updated = this.updateRun(run.id, { routeDenylist: [...new Set(normalized)] })
    this.event(run.id, 'scope.route_denylist', `Staging route denylist updated (${normalized.length} entries).`, {
      routeDenylist: updated.routeDenylist,
    })
    return updated
  }

  /**
   * Assign an origin to one of the three tiers. The legacy approved-candidate allowlist is the
   * target tier, so promoting/demoting is expressed as an edit to `approved` plus the role lists.
   */
  setOriginRole(run: Run, origin: string, role: OriginRole): Run {
    if (!originRoles.includes(role)) throw new Error('Unknown origin role.')
    const project = this.project(run.projectId)
    const validated = assetOriginForEnvironment(project.environment).parse(origin)
    const normalized = normalizeScopeOrigin(validated) ?? validated
    const candidate = run.candidates.find(item => normalizeScopeOrigin(item.origin) === normalized)
    const approved = new Set(run.approved)
    if (role === 'target') {
      if (!candidate) {
        throw new Error('Add the host to the run inventory before approving it as a target origin.')
      }
      approved.add(candidate.id)
    } else if (candidate) {
      approved.delete(candidate.id)
    }
    const without = (list: readonly string[] | undefined) =>
      [...(list ?? [])].filter(item => normalizeScopeOrigin(item) !== normalized)
    const updated = this.updateRun(run.id, {
      approved: [...approved],
      authOrigins: role === 'auth' ? [...new Set([...without(run.authOrigins), normalized])] : without(run.authOrigins),
      assetOrigins: role === 'asset' ? [...new Set([...without(run.assetOrigins), normalized])] : without(run.assetOrigins),
    })
    this.event(run.id, 'scope.origin_role', `Origin ${normalized} assigned the ${role} role.`, {
      origin: normalized, role,
    })
    return updated
  }

  boardMember(runId: string, handle: string): BoardMemberRow | undefined {
    const normalized = normalizeBoardHandle(handle)
    if (!normalized) return undefined
    return this.db.select().from(tables.boardMembers).where(and(
      eq(tables.boardMembers.runId, runId), eq(tables.boardMembers.handle, normalized),
    )).get()
  }

  listBoardMembers(runId: string): BoardMemberRow[] {
    return this.db.select().from(tables.boardMembers).where(eq(tables.boardMembers.runId, runId))
      .orderBy(asc(tables.boardMembers.createdAt), asc(tables.boardMembers.handle)).all()
  }

  upsertBoardMember(runOrId: Run | string, input: {
    handle: string
    role: BoardMemberRole
    specialistProfile?: SpecialistProfile | null
    sessionId?: string
    activeAssignmentId?: string | null
    state?: BoardMemberState
    roleAffinity?: BoardMemberRow['roleAffinity']
    lastReadSeq?: number
    turnsUsed?: number
    postsCount?: number
    peerHopsUsed?: number
    scopeRevision?: number
    goalRevision?: number
    sourceOrigins?: readonly string[]
  }): BoardMemberRow {
    const run = typeof runOrId === 'string' ? this.run(runOrId) : runOrId
    const handle = normalizeBoardHandle(input.handle)
    if (!handle || !boardHandlePattern.test(handle)) {
      throw new Error('Board handle must match ^[a-z][a-z0-9_-]{1,23}$.')
    }
    if (input.specialistProfile && !specialistProfiles.includes(input.specialistProfile)) {
      throw new Error('Unknown specialist profile.')
    }
    const now = Date.now()
    const existing = this.boardMember(run.id, handle)
    const values = {
      handle,
      role: input.role,
      specialistProfile: input.specialistProfile ?? existing?.specialistProfile ?? null,
      sessionId: input.sessionId ?? existing?.sessionId ?? randomUUID(),
      activeAssignmentId: input.activeAssignmentId !== undefined ? input.activeAssignmentId : existing?.activeAssignmentId ?? null,
      state: input.state ?? existing?.state ?? 'waiting',
      roleAffinity: input.roleAffinity !== undefined ? input.roleAffinity : existing?.roleAffinity ?? null,
      lastReadSeq: Math.max(0, Math.round(input.lastReadSeq ?? existing?.lastReadSeq ?? 0)),
      turnsUsed: Math.max(0, Math.round(input.turnsUsed ?? existing?.turnsUsed ?? 0)),
      postsCount: Math.max(0, Math.round(input.postsCount ?? existing?.postsCount ?? 0)),
      peerHopsUsed: Math.max(0, Math.round(input.peerHopsUsed ?? existing?.peerHopsUsed ?? 0)),
      scopeRevision: Math.max(0, Math.round(input.scopeRevision ?? existing?.scopeRevision ?? run.scopeRevision)),
      goalRevision: Math.max(0, Math.round(input.goalRevision ?? existing?.goalRevision ?? run.goalRevision)),
      sourceOrigins: [...new Set(input.sourceOrigins ?? existing?.sourceOrigins ?? [])],
    }
    if (existing) {
      return this.db.update(tables.boardMembers).set({ ...values, updatedAt: now })
        .where(eq(tables.boardMembers.id, existing.id)).returning().get()!
    }
    return this.db.insert(tables.boardMembers).values({
      id: randomUUID(), runId: run.id, ...values, createdAt: now, updatedAt: now,
    }).returning().get()
  }

  updateBoardMemberState(runId: string, handle: string, patch: {
    state?: BoardMemberState
    activeAssignmentId?: string | null
    lastReadSeq?: number
    turnsUsed?: number
    postsCount?: number
    peerHopsUsed?: number
    scopeRevision?: number
    goalRevision?: number
    roleAffinity?: BoardMemberRow['roleAffinity']
    sourceOrigins?: readonly string[]
    sessionId?: string
  }): BoardMemberRow {
    const existing = this.boardMember(runId, handle)
    if (!existing) throw new Error('Board member not found.')
    return this.upsertBoardMember(runId, {
      handle: existing.handle,
      role: existing.role,
      specialistProfile: existing.specialistProfile,
      sessionId: patch.sessionId ?? existing.sessionId,
      activeAssignmentId: patch.activeAssignmentId !== undefined ? patch.activeAssignmentId : existing.activeAssignmentId,
      state: patch.state ?? existing.state,
      roleAffinity: patch.roleAffinity !== undefined ? patch.roleAffinity : existing.roleAffinity,
      lastReadSeq: patch.lastReadSeq ?? existing.lastReadSeq,
      turnsUsed: patch.turnsUsed ?? existing.turnsUsed,
      postsCount: patch.postsCount ?? existing.postsCount,
      peerHopsUsed: patch.peerHopsUsed ?? existing.peerHopsUsed,
      scopeRevision: patch.scopeRevision ?? existing.scopeRevision,
      goalRevision: patch.goalRevision ?? existing.goalRevision,
      sourceOrigins: patch.sourceOrigins ?? existing.sourceOrigins,
    })
  }

  retireBoardMember(run: Run | string, handle: string, reason: string): BoardMemberRow {
    const resolved = typeof run === 'string' ? this.run(run) : run
    const member = this.updateBoardMemberState(resolved.id, handle, { state: 'retired' })
    this.event(resolved.id, 'board.member.retired', `@${member.handle} retired.`, {
      handle: member.handle, reason, assignmentId: member.activeAssignmentId, scopeRevision: resolved.scopeRevision,
    })
    return member
  }

  private boardHandleAllowList(runId: string): Set<string> {
    const handles = new Set<string>([...canonicalBoardHandles, ...boardSystemHandles])
    for (const member of this.listBoardMembers(runId)) {
      if (member.state === 'retired') handles.delete(member.handle)
      else handles.add(member.handle)
    }
    return handles
  }

  /** Redact + cap + reject prompt-injection carriers before a board body reaches SQLite or SSE. */
  private cleanBoardBody(body: string, secrets: readonly NamedSecret[]): string {
    const trimmed = body.trim()
    if (!trimmed) throw new Error('Board message body is required.')
    if (/<\s*\/?\s*(?:script|iframe|object|embed|style|img|svg|a|div|span|table|form|input|link|meta|html|body|br|p|h[1-6])\b[^>]*>/i.test(trimmed)) {
      throw new Error('Board messages cannot contain raw HTML or markup.')
    }
    const headerLines = trimmed.split('\n').filter(line =>
      /^(?:host|user-agent|authorization|cookie|set-cookie|content-type|content-length|accept|referer|origin|x-[a-z0-9-]+):\s*\S/i.test(line.trim()))
    if (headerLines.length >= 2) {
      throw new Error('Board messages cannot contain multi-line HTTP header dumps. Reference an exchange instead.')
    }
    const cleaned = redact(trimmed, secrets).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
    if (cleaned.length <= maxBoardBodyLength) return cleaned
    return cleaned.slice(0, maxBoardBodyLength - 1) + '…'
  }

  postBoardMessage(runOrId: Run | string, input: {
    authorHandle: string
    authorRole: BoardAuthorRole
    kind: BoardMessageKind
    body: string
    mentions?: readonly string[]
    refFactIds?: readonly string[]
    refExchangeIds?: readonly string[]
    refFindingIds?: readonly string[]
    refStepId?: string | null
    refApprovalId?: string | null
    replyToSeq?: number | null
    sourceOrigins?: readonly string[]
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow {
    const run = typeof runOrId === 'string' ? this.run(runOrId) : runOrId
    const authorHandle = normalizeBoardHandle(input.authorHandle)
    if (!authorHandle) throw new Error('Invalid board author handle.')
    const roleHandles: Record<Exclude<BoardAuthorRole, 'specialist'>, readonly string[]> = {
      operator: ['operator'],
      coordinator: ['coordinator'],
      verifier: ['verifier'],
      system: ['broker', 'canary', 'system'],
    }
    if (input.authorRole === 'specialist') {
      if (['operator', 'coordinator', 'verifier', 'broker', 'canary', 'system', 'all'].includes(authorHandle)) {
        throw new Error('A specialist cannot post under a system actor handle.')
      }
    } else if (!roleHandles[input.authorRole].includes(authorHandle)) {
      throw new Error(`@${authorHandle} cannot post with the ${input.authorRole} author role.`)
    }
    const allowed = this.boardHandleAllowList(run.id)
    if (input.authorRole === 'specialist' && !allowed.has(authorHandle)) {
      throw new Error(`Specialist @${authorHandle} is not on the active board roster.`)
    }
    const mentions = [...new Set((input.mentions ?? parseBoardMentions(input.body))
      .map(mention => normalizeBoardHandle(mention))
      .filter((h): h is string => Boolean(h)))]
    for (const mention of mentions) {
      if (mention === 'all') {
        if (!['operator', 'coordinator', 'system'].includes(input.authorRole)) {
          throw new Error('Only the operator, coordinator, or system actors may use @all.')
        }
        continue
      }
      if (!allowed.has(mention)) throw new Error(`Cannot mention unknown or retired board handle @${mention}.`)
    }
    const scopePolicy = this.scopePolicy(run)
    const approvedOrigins = this.approvedOriginsFor(run)
    // A board post may cite a benign IdP/CDN hop without being out of scope.
    const sourceOrigins = [...new Set(input.sourceOrigins ?? approvedOrigins)]
    if (sourceOrigins.some(origin => !isProvenanceOriginAllowed(scopePolicy, origin))) {
      throw new Error('Board message references an origin outside approved scope.')
    }
    const body = this.cleanBoardBody(input.body, secrets)
    if (input.replyToSeq !== undefined && input.replyToSeq !== null) {
      const exists = this.db.select({ id: tables.boardMessages.id }).from(tables.boardMessages).where(and(
        eq(tables.boardMessages.runId, run.id), eq(tables.boardMessages.seq, input.replyToSeq),
      )).get()
      if (!exists) throw new Error('Cannot reply to a board sequence that does not exist.')
    }
    const message = this.transaction(() => {
      const maxSeq = this.db.select({ value: sql<number>`COALESCE(MAX(${tables.boardMessages.seq}), 0)` })
        .from(tables.boardMessages).where(eq(tables.boardMessages.runId, run.id)).get()
      const seq = Number(maxSeq?.value ?? 0) + 1
      return this.db.insert(tables.boardMessages).values({
        id: randomUUID(),
        runId: run.id,
        seq,
        authorHandle,
        authorRole: input.authorRole,
        kind: input.kind,
        mentions,
        body,
        refFactIds: [...new Set(input.refFactIds ?? [])].slice(0, 50),
        refExchangeIds: [...new Set(input.refExchangeIds ?? [])].slice(0, 50),
        refFindingIds: [...new Set(input.refFindingIds ?? [])].slice(0, 50),
        refStepId: input.refStepId ?? null,
        refApprovalId: input.refApprovalId ?? null,
        replyToSeq: input.replyToSeq ?? null,
        scopeRevision: run.scopeRevision,
        goalRevision: run.goalRevision,
        sourceOrigins,
        tainted: false,
        createdAt: Date.now(),
      }).returning().get()
    }, { behavior: 'immediate' })
    const member = this.boardMember(run.id, authorHandle)
    if (member) {
      this.db.update(tables.boardMembers).set({ postsCount: member.postsCount + 1, updatedAt: Date.now() })
        .where(eq(tables.boardMembers.id, member.id)).run()
    }
    this.event(run.id, 'board.message', `@${authorHandle} posted a ${input.kind}.`, {
      boardMessageId: message.id, seq: message.seq, authorHandle, authorRole: input.authorRole,
      kind: input.kind, mentions, refApprovalId: message.refApprovalId, tainted: false,
    })
    return message
  }

  listBoardMessages(runId: string, opts: {
    sinceSeq?: number
    limit?: number
    includeTainted?: boolean
    authorHandle?: string
    kind?: BoardMessageKind
    mentionHandle?: string
    approvalId?: string
  } = {}): BoardMessageRow[] {
    const sinceSeq = Math.max(0, Math.round(opts.sinceSeq ?? 0))
    const limit = Math.min(Math.max(1, opts.limit ?? 200), 500)
    const authorHandle = opts.authorHandle ? normalizeBoardHandle(opts.authorHandle) : null
    const mentionHandle = opts.mentionHandle ? normalizeBoardHandle(opts.mentionHandle) : null
    return this.db.select().from(tables.boardMessages).where(and(
      eq(tables.boardMessages.runId, runId),
      gt(tables.boardMessages.seq, sinceSeq),
      ...(opts.includeTainted ? [] : [eq(tables.boardMessages.tainted, false)]),
      ...(opts.kind ? [eq(tables.boardMessages.kind, opts.kind)] : []),
      ...(authorHandle ? [eq(tables.boardMessages.authorHandle, authorHandle)] : []),
      ...(opts.approvalId ? [eq(tables.boardMessages.refApprovalId, opts.approvalId)] : []),
    )).orderBy(asc(tables.boardMessages.seq)).all()
      .filter(message => !mentionHandle || message.mentions.includes(mentionHandle))
      .slice(0, limit)
  }

  /**
   * Scope revocation: immediately taint board posts touching unapproved origins and retire the
   * affected roster members so revoked-origin text can never reach a later specialist wake.
   */
  taintBoardMessagesForRevokedOrigins(runId: string, approvedOrigins: ReadonlySet<string>): {
    taintedMessageIds: string[]
    retiredHandles: string[]
  } {
    // IdP/CDN hops are benign infrastructure: they must never taint a valid target finding.
    const policy = this.scopePolicy(runId)
    const allowed = (origin: string) =>
      approvedOrigins.has(origin) || isProvenanceOriginAllowed(policy, origin)
    const taintedMessageIds: string[] = []
    for (const message of this.db.select().from(tables.boardMessages).where(and(
      eq(tables.boardMessages.runId, runId), eq(tables.boardMessages.tainted, false),
    )).all()) {
      if (message.sourceOrigins.some(origin => !allowed(origin))) {
        taintedMessageIds.push(message.id)
      }
    }
    if (taintedMessageIds.length) {
      this.db.update(tables.boardMessages).set({ tainted: true }).where(and(
        eq(tables.boardMessages.runId, runId), inArray(tables.boardMessages.id, taintedMessageIds),
      )).run()
    }
    const retiredHandles: string[] = []
    for (const member of this.listBoardMembers(runId)) {
      if (member.state === 'retired') continue
      if (member.sourceOrigins.some(origin => !allowed(origin))) {
        this.updateBoardMemberState(runId, member.handle, { state: 'retired', activeAssignmentId: null })
        retiredHandles.push(member.handle)
      }
    }
    if (taintedMessageIds.length || retiredHandles.length) {
      this.event(runId, 'board.tainted', 'Scope revocation tainted board messages and retired affected members.', {
        taintedMessageIds, retiredHandles,
      })
    }
    return { taintedMessageIds, retiredHandles }
  }

  eventsAfter(runId: string, after: number, limit = 1000) {    return this.db.select({
      id: tables.events.id, kind: tables.events.kind, message: tables.events.message,
      detail: tables.events.detail, createdAt: tables.events.createdAt,
    }).from(tables.events).where(and(
      eq(tables.events.workspaceId, this.workspace.id), eq(tables.events.runId, runId), gt(tables.events.id, after),
    )).orderBy(asc(tables.events.id)).limit(limit).all()
  }

  project(projectId: string): Project {
    const project = this.db.select().from(tables.projects).where(and(
      eq(tables.projects.id, projectId), eq(tables.projects.workspaceId, this.workspace.id),
    )).get()
    if (!project) throw new Error('Project not found.')
    return project
  }

  run(runId: string): Run {
    const run = this.db.select().from(tables.runs).where(and(
      eq(tables.runs.id, runId), eq(tables.runs.workspaceId, this.workspace.id),
    )).get()
    if (!run) throw new Error('Run not found.')
    return run
  }

  listWorkspace() {
    return {
      workspace: { id: this.workspace.id, name: this.workspace.name },
      projects: this.db.select().from(tables.projects).where(eq(tables.projects.workspaceId, this.workspace.id))
        .orderBy(desc(tables.projects.createdAt)).all(),
    }
  }

  /** Typed workspace dashboard summary (projects with run/host/latest-run rollups + recent runs). */
  workspaceSummary(recentLimit = 15): WorkspaceSummary {
    const workspaceList = this.listWorkspace()
    const workspaceId = workspaceList.workspace.id
    const safeRecentLimit = resolvePageLimit(recentLimit, 15)

    const runCountRows = this.client.prepare(`
      select project_id as projectId, count(*) as runCount
      from runs
      where workspace_id = ?
      group by project_id
    `).all(workspaceId) as { projectId: string; runCount: number }[]
    const runCounts = new Map(runCountRows.map(r => [r.projectId, Number(r.runCount)]))

    const hostCountRows = this.client.prepare(`
      select a.project_id as projectId, count(*) as hostCount
      from project_assets a
      join projects p on p.id = a.project_id
      where p.workspace_id = ?
      group by a.project_id
    `).all(workspaceId) as { projectId: string; hostCount: number }[]
    const hostCounts = new Map(hostCountRows.map(r => [r.projectId, Number(r.hostCount)]))

    const latestRunRows = this.client.prepare(`
      select r.id as id, r.project_id as projectId, r.goal as goal, r.status as status, r.phase as phase,
        r.created_at as startedAt,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null
          and json_extract(f.finding, '$.status') in ('confirmed', 'verified', 'static_verified')) as confirmedCount,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findingCount
      from runs r
      where r.workspace_id = ?
        and r.id = (
          select r2.id from runs r2
          where r2.project_id = r.project_id and r2.workspace_id = r.workspace_id
          order by r2.created_at desc, r2.rowid desc
          limit 1
        )
    `).all(workspaceId) as unknown as (WorkspaceProjectLatestRun & { projectId: string })[]
    const latestRuns = new Map<string, WorkspaceProjectLatestRun>(latestRunRows.map(r => [r.projectId, {
      id: r.id,
      goal: r.goal,
      status: r.status,
      phase: r.phase,
      startedAt: Number(r.startedAt),
      confirmedCount: Number(r.confirmedCount),
      findingCount: Number(r.findingCount),
    }]))

    const recentRunRows = this.client.prepare(`
      select r.id as id, r.project_id as projectId, p.name as projectName, r.goal as goal,
        r.status as status, r.phase as phase, r.created_at as startedAt,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null
          and json_extract(f.finding, '$.status') in ('confirmed', 'verified', 'static_verified')) as confirmedCount,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findings
      from runs r
      join projects p on p.id = r.project_id
      where r.workspace_id = ?
      order by r.created_at desc, r.rowid desc
      limit ?
    `).all(workspaceId, safeRecentLimit) as unknown as WorkspaceRecentRunSummary[]

    return {
      workspace: workspaceList.workspace,
      projects: workspaceList.projects.map(project => ({
        ...project,
        runCount: runCounts.get(project.id) ?? 0,
        hostCount: hostCounts.get(project.id) ?? project.seeds.length,
        latestRun: latestRuns.get(project.id) ?? null,
      })),
      recentRuns: recentRunRows.map(r => ({
        ...r,
        startedAt: Number(r.startedAt),
        confirmedCount: Number(r.confirmedCount),
        findings: Number(r.findings),
      })),
    }
  }

  /** Run workspace shell summary: workspace run index (newest first) and exact totals for one run. */
  runShellSummary(runId: string, limit = 200): RunShellSummary {
    const run = this.run(runId)
    const safeLimit = resolvePageLimit(limit, 200)
    const runs = this.client.prepare(`
      select r.id as id, r.goal as goal, r.status as status, r.phase as phase,
        r.created_at as createdAt, r.project_id as projectId, p.name as projectName,
        (select count(*) from findings f where f.run_id = r.id and f.superseded_by_finding_id is null) as findings
      from runs r
      join projects p on p.id = r.project_id
      where r.workspace_id = ?
      order by r.created_at desc, r.rowid desc
      limit ?
    `).all(run.workspaceId, safeLimit) as unknown as RunShellIndexEntry[]
    const counts = this.client.prepare(`
      select
        (select count(*) from broker_exchanges where run_id = ?) as exchanges,
        (select count(*) from events where run_id = ?) as events
    `).get(run.id, run.id) as { exchanges: number; events: number }
    return {
      runs: runs.map(r => ({ ...r, createdAt: Number(r.createdAt), findings: Number(r.findings) })),
      counts: { exchanges: Number(counts.exchanges), events: Number(counts.events) },
    }
  }

  listProjectSpecs(projectId: string): ProjectSpecSummary[] {
    this.project(projectId)
    return this.db.select().from(tables.projectSpecs).where(eq(tables.projectSpecs.projectId, projectId))
      .orderBy(desc(tables.projectSpecs.createdAt)).all().map(toSpecSummary)
  }

  listProjectSpecsFull(projectId: string): ProjectSpec[] {
    this.project(projectId)
    return this.db.select().from(tables.projectSpecs).where(eq(tables.projectSpecs.projectId, projectId))
      .orderBy(desc(tables.projectSpecs.createdAt)).all()
  }

  getProjectSpec(projectId: string, specId: string): ProjectSpec {
    this.project(projectId)
    const spec = this.db.select().from(tables.projectSpecs).where(and(
      eq(tables.projectSpecs.projectId, projectId), eq(tables.projectSpecs.id, specId),
    )).get()
    if (!spec) throw new Error('Project spec not found.')
    return spec
  }

  importProjectSpec(input: z.output<typeof importProjectSpec>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const spec = this.upsertProjectSpecRaw(project.id, {
        name: input.name,
        kind: input.kind,
        origin: input.origin ?? null,
        content: input.content,
      })
      return { id: spec.id, name: spec.name, kind: spec.kind }
    })
  }

  upsertProjectSpecRaw(projectId: string, input: {
    name: string
    kind: ProjectSpec['kind']
    origin?: string | null
    content: string
  }): ProjectSpec {
    this.project(projectId)
    const cleanName = redact(input.name)
    const cleanContent = redact(input.content)
    const existing = this.db.select().from(tables.projectSpecs).where(and(
      eq(tables.projectSpecs.projectId, projectId), eq(tables.projectSpecs.name, cleanName),
    )).get()
    if (existing) {
      const updated = this.db.update(tables.projectSpecs).set({
        kind: input.kind,
        origin: input.origin ?? null,
        content: cleanContent,
        createdAt: Date.now(),
      }).where(eq(tables.projectSpecs.id, existing.id)).returning().get()!
      this.event(null, 'spec.updated', `Updated project spec ${cleanName}.`, { projectId, specId: updated.id, kind: updated.kind })
      return updated
    }
    const created = this.db.insert(tables.projectSpecs).values({
      id: randomUUID(),
      projectId,
      name: cleanName,
      kind: input.kind,
      origin: input.origin ?? null,
      content: cleanContent,
      createdAt: Date.now(),
    }).returning().get()
    this.event(null, 'spec.imported', `Imported project spec ${cleanName}.`, { projectId, specId: created.id, kind: created.kind })
    return created
  }

  deleteProjectSpec(input: { requestId: string; projectId: string; specId: string }) {
    return this.operate(input, () => {
      this.project(input.projectId)
      const existing = this.getProjectSpec(input.projectId, input.specId)
      this.db.delete(tables.projectSpecs).where(eq(tables.projectSpecs.id, existing.id)).run()
      this.event(null, 'spec.deleted', `Removed project spec ${existing.name}.`, { projectId: input.projectId, specId: existing.id })
      return { id: existing.id }
    })
  }

  projectDetail(projectId: string) {
    const project = this.project(projectId)
    const runRows = this.db.select({
      id: tables.runs.id,
      goal: tables.runs.goal,
      status: tables.runs.status,
      phase: tables.runs.phase,
      capabilityTier: tables.runs.capabilityTier,
      approvalPolicy: tables.runs.approvalPolicy,
      spentUsd: tables.runs.spentUsd,
      spentRequests: tables.runs.spentRequests,
      turnsUsed: tables.runs.turnsUsed,
      createdAt: tables.runs.createdAt,
    }).from(tables.runs).where(eq(tables.runs.projectId, projectId)).orderBy(desc(tables.runs.createdAt)).all()
    const findingCountRows = this.client.prepare(`
      SELECT r.id AS runId,
        (SELECT count(*) FROM findings f WHERE f.run_id = r.id AND f.superseded_by_finding_id IS NULL) AS findingCount,
        (SELECT count(*) FROM findings f WHERE f.run_id = r.id AND f.superseded_by_finding_id IS NULL
          AND json_extract(f.finding, '$.status') IN ('confirmed', 'verified', 'static_verified')) AS confirmedCount
      FROM runs r
      WHERE r.project_id = ? AND r.workspace_id = ?
    `).all(projectId, this.workspace.id) as { runId: string; findingCount: number; confirmedCount: number }[]
    const findingCounts = new Map(findingCountRows.map(r => [r.runId, {
      findingCount: Number(r.findingCount),
      confirmedCount: Number(r.confirmedCount),
    }]))
    return {
      project,
      assets: this.db.select().from(tables.projectAssets).where(eq(tables.projectAssets.projectId, projectId)).all(),
      personas: listProjectPersonas(this, projectId),
      specs: this.listProjectSpecs(projectId),
      runs: runRows.map(r => {
        const counts = findingCounts.get(r.id)
        return {
          ...r,
          findingCount: counts?.findingCount ?? 0,
          confirmedCount: counts?.confirmedCount ?? 0,
        }
      }),
    }
  }

  /** True when the run itself is in `running` status or still owns running workers/lab containers. */
  isRunActive(runId: string): boolean {
    const run = this.db.select({ id: tables.runs.id, status: tables.runs.status })
      .from(tables.runs)
      .where(and(eq(tables.runs.id, runId), eq(tables.runs.workspaceId, this.workspace.id)))
      .get()
    if (!run) return false
    if (run.status === 'running') return true
    const activeAssignments = this.client.prepare(
      `SELECT count(*) AS c FROM assignments WHERE run_id = ? AND status IN ('running', 'waiting_approval')`,
    ).get(runId) as { c?: number } | undefined
    if (Number(activeAssignments?.c ?? 0) > 0) return true
    const activeContainers = this.client.prepare(
      `SELECT count(*) AS c FROM lab_containers WHERE run_id = ? AND status = 'running'`,
    ).get(runId) as { c?: number } | undefined
    return Number(activeContainers?.c ?? 0) > 0
  }

  /** Return all run IDs belonging to a project that are currently active. */
  listActiveRunIdsForProject(projectId: string): string[] {
    const rows = this.db.select({ id: tables.runs.id })
      .from(tables.runs)
      .where(and(eq(tables.runs.projectId, projectId), eq(tables.runs.workspaceId, this.workspace.id)))
      .all()
    return rows.map(r => r.id).filter(runId => this.isRunActive(runId))
  }

  private deleteRunRowsInTx(runId: string): { sessionIds: string[]; flatArtifactIds: string[] } {
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

    // Delete in strict child-before-parent order to satisfy PRAGMA foreign_keys = ON.
    // Note: tenant_audit_log is an append-only immutable audit table with a BEFORE DELETE trigger
    // and no FK to runs, so it is intentionally preserved.
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
    this.client.prepare(`DELETE FROM runs WHERE id = ? AND workspace_id = ?`).run(runId, this.workspace.id)

    // Keep any legacy flat content-addressed blob still referenced by another run.
    const flatArtifactIds: string[] = []
    if (artifactIds.size > 0) {
      const checkShared = this.client.prepare(
        `SELECT 1 FROM broker_exchanges WHERE body_artifact_id = ? LIMIT 1`,
      )
      for (const aid of artifactIds) {
        if (!checkShared.get(aid)) flatArtifactIds.push(aid)
      }
    }
    return { sessionIds, flatArtifactIds }
  }

  private cleanupRunFilesOnDisk(
    runId: string,
    sessionIds: readonly string[],
    flatArtifactIds: readonly string[],
  ): void {
    const isSafeSegment = (seg: string) => Boolean(seg) && !seg.includes('..') && !/[\\/\0]/.test(seg)
    if (isSafeSegment(runId)) {
      for (const dir of [
        join(this.directory, 'artifacts', runId),
        join(this.directory, 'runs', runId),
        join(this.directory, 'agent-sessions', runId),
      ]) {
        try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
      }
    }
    for (const sessionId of sessionIds) {
      if (!isSafeSegment(sessionId)) continue
      const base = join(this.directory, 'agent-sessions', `${sessionId}.sqlite`)
      for (const file of [base, `${base}-wal`, `${base}-shm`]) {
        try { unlinkSync(file) } catch { /* ignore */ }
      }
    }
    for (const artifactId of flatArtifactIds) {
      if (!isSafeSegment(artifactId)) continue
      try { unlinkSync(join(this.directory, 'artifacts', `${artifactId}.txt`)) } catch { /* ignore */ }
    }
  }

  /**
   * Delete a single run and all of its child rows atomically in one SQLite transaction,
   * then remove on-disk run artifacts and worker session files.
   */
  deleteRun(runId: string): { deleted: boolean; projectId: string; runId: string } {
    this.flushNow()
    const committed = this.transaction(() => {
      const existing = this.db.select({ id: tables.runs.id, projectId: tables.runs.projectId })
        .from(tables.runs)
        .where(and(eq(tables.runs.id, runId), eq(tables.runs.workspaceId, this.workspace.id)))
        .get()
      if (!existing) return null
      const files = this.deleteRunRowsInTx(runId)
      this.event(null, 'run.deleted', `Deleted run ${runId}.`, {
        projectId: existing.projectId,
        runId,
      })
      return { projectId: existing.projectId, ...files }
    }, { behavior: 'immediate' })
    if (!committed) return { deleted: false, projectId: '', runId }
    this.cleanupRunFilesOnDisk(runId, committed.sessionIds, committed.flatArtifactIds)
    return { deleted: true, projectId: committed.projectId, runId }
  }

  /**
   * Delete a project, cascading all runs (and their child rows), specs, personas, assets,
   * on-disk run artifacts/sessions, local 0600 persona credentials, and synced repo cache dir.
   */
  deleteProject(projectId: string): { deleted: boolean; projectId: string; deletedRuns: number } {
    this.flushNow()
    const committed = this.transaction(() => {
      const existing = this.db.select({ id: tables.projects.id, name: tables.projects.name })
        .from(tables.projects)
        .where(and(eq(tables.projects.id, projectId), eq(tables.projects.workspaceId, this.workspace.id)))
        .get()
      if (!existing) return null
      const runRows = this.db.select({ id: tables.runs.id })
        .from(tables.runs)
        .where(and(eq(tables.runs.projectId, projectId), eq(tables.runs.workspaceId, this.workspace.id)))
        .all()
      const personaRows = this.db.select({ credentialId: tables.personas.credentialId })
        .from(tables.personas)
        .where(and(eq(tables.personas.projectId, projectId), eq(tables.personas.workspaceId, this.workspace.id)))
        .all()

      const runCleanups: Array<{ runId: string; sessionIds: string[]; flatArtifactIds: string[] }> = []
      for (const row of runRows) {
        const files = this.deleteRunRowsInTx(row.id)
        runCleanups.push({ runId: row.id, ...files })
      }
      this.client.prepare(`DELETE FROM retest_runs WHERE project_id = ?`).run(projectId)
      this.client.prepare(`DELETE FROM personas WHERE project_id = ? AND workspace_id = ?`).run(projectId, this.workspace.id)
      this.client.prepare(`DELETE FROM project_specs WHERE project_id = ?`).run(projectId)
      this.client.prepare(`DELETE FROM project_assets WHERE project_id = ?`).run(projectId)
      this.client.prepare(`DELETE FROM projects WHERE id = ? AND workspace_id = ?`).run(projectId, this.workspace.id)
      this.event(null, 'project.deleted', `Deleted project ${existing.name}.`, {
        projectId,
        projectName: existing.name,
        deletedRuns: runRows.length,
      })
      return {
        runCleanups,
        credentialIds: personaRows.map(p => p.credentialId),
        deletedRuns: runRows.length,
      }
    }, { behavior: 'immediate' })
    if (!committed) return { deleted: false, projectId, deletedRuns: 0 }

    for (const cleanup of committed.runCleanups) {
      this.cleanupRunFilesOnDisk(cleanup.runId, cleanup.sessionIds, cleanup.flatArtifactIds)
    }
    deletePersonaCredentialFiles(this.directory, committed.credentialIds)
    if (projectId && !projectId.includes('..') && !/[\\/\0]/.test(projectId)) {
      try {
        rmSync(join(this.directory, 'repos', projectId), { recursive: true, force: true })
      } catch {
        // Best-effort repo cache cleanup.
      }
    }
    return { deleted: true, projectId, deletedRuns: committed.deletedRuns }
  }

  runDetail(runId: string, options?: RunDetailOptions) {
    // A caller that just recorded an exchange must see it in the detail view.
    this.flushNow()
    const run = this.run(runId)
    const pageFor = (specific?: PaginationOptions): PaginationOptions => ({
      limit: specific?.limit ?? options?.limit,
      offset: specific?.offset ?? options?.offset,
    })
    const isPaged = (page: PaginationOptions) => page.limit !== undefined || page.offset !== undefined
    const evidencePage = pageFor(options?.evidence)
    const factsPage = pageFor(options?.facts)
    const exchangePage = pageFor(options?.exchanges)
    const endpointPage = pageFor(options?.endpoints)
    const messagePage = pageFor(options?.messages)
    const boardPage = pageFor(options?.boardMessages)

    const streamHead = this.db.select({ id: tables.events.id }).from(tables.events)
      .where(eq(tables.events.runId, run.id)).orderBy(desc(tables.events.id)).limit(1).get()

    const evidenceBase = this.db.select().from(tables.evidence).where(eq(tables.evidence.runId, runId))
      .orderBy(asc(tables.evidence.createdAt), asc(tables.evidence.id))
    const evidenceRows = isPaged(evidencePage)
      ? evidenceBase.limit(resolvePageLimit(evidencePage.limit, 1000)).offset(resolvePageOffset(evidencePage.offset)).all()
      : evidenceBase.all()

    const threatModel = this.latestThreatModel(runId, run.goalRevision)
    const chainSteps = this.listChainSteps(runId)

    const factsBase = this.db.select().from(tables.facts).where(eq(tables.facts.runId, runId))
      .orderBy(asc(tables.facts.createdAt), asc(tables.facts.id))
    const facts = isPaged(factsPage)
      ? factsBase.limit(resolvePageLimit(factsPage.limit, 100)).offset(resolvePageOffset(factsPage.offset)).all()
      : factsBase.all()

    const graphEdges = this.listGraphEdges(runId)
    const digests = this.listDigests(runId, false)
    const assignments = this.workerList(runId)
    const approvals = this.listApprovalRequests(runId)

    const exchangeColumns = {
      id: tables.brokerExchanges.id,
      assignmentId: tables.brokerExchanges.assignmentId,
      scopeRevision: tables.brokerExchanges.scopeRevision,
      origin: tables.brokerExchanges.origin,
      finalOrigin: tables.brokerExchanges.finalOrigin,
      redirectOrigins: tables.brokerExchanges.redirectOrigins,
      method: tables.brokerExchanges.method,
      pathAndQuery: tables.brokerExchanges.pathAndQuery,
      personaHandle: tables.brokerExchanges.personaHandle,
      status: tables.brokerExchanges.status,
      mediaType: tables.brokerExchanges.mediaType,
      bodyPreview: tables.brokerExchanges.bodyPreview,
      bodyArtifactId: tables.brokerExchanges.bodyArtifactId,
      bodySha256: tables.brokerExchanges.bodySha256,
      durationMs: tables.brokerExchanges.durationMs,
      createdAt: tables.brokerExchanges.createdAt,
    }
    const exchangeBase = this.db.select(exchangeColumns).from(tables.brokerExchanges)
      .where(eq(tables.brokerExchanges.runId, runId))
      .orderBy(desc(tables.brokerExchanges.createdAt), asc(tables.brokerExchanges.id))
    const exchangesSummary: ExchangeSummary[] = (isPaged(exchangePage)
      ? exchangeBase.limit(resolvePageLimit(exchangePage.limit, 500)).offset(resolvePageOffset(exchangePage.offset)).all()
      : exchangeBase.limit(500).all())
      .map(ex => ({ ...ex, bodyPreview: ex.bodyPreview.slice(0, 320) }))

    const coverageEntries = this.listCoverageEntries(runId)
    const endpoints = this.listEndpoints(runId, isPaged(endpointPage)
      ? { limit: resolvePageLimit(endpointPage.limit, 500), offset: resolvePageOffset(endpointPage.offset) }
      : undefined)
    const endpointParams = isPaged(endpointPage)
      ? (endpoints.length
          ? this.db.select().from(tables.endpointParams).where(and(
              eq(tables.endpointParams.runId, runId),
              inArray(tables.endpointParams.endpointId, endpoints.map(endpoint => endpoint.id)),
            )).orderBy(asc(tables.endpointParams.createdAt), asc(tables.endpointParams.id)).all()
          : [])
      : this.listEndpointParams(runId)
    const apiDependencies = this.listApiDependencies(runId)
    const labTelemetry = this.listLabTelemetry(runId)
    const openProofGaps = this.listOpenProofGaps(runId, run.goalRevision)
    const sastRuns = this.listSastRuns(runId)
    const surfaceProbes = this.listSurfaceProbes(runId)
    const patchProposals = this.listPatchProposals(runId)
    const replaySpecs = this.listReplaySpecs(runId)
    const retestRuns = this.db.select().from(tables.retestRuns).where(eq(tables.retestRuns.runId, runId))
      .orderBy(desc(tables.retestRuns.createdAt)).all()
    const findingsRows = this.db.select().from(tables.findings).where(eq(tables.findings.runId, runId)).all()
    const findings: Finding[] = findingsRows.map(row => ({
      ...row.finding,
      findingKind: row.findingKind,
      replaySpecId: row.replaySpecId ?? row.finding.replaySpecId,
      verificationTier: row.verificationTier ?? row.finding.verificationTier,
      fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash,
      supersededByFindingId: row.supersededByFindingId ?? row.finding.supersededByFindingId,
      counterevidence: row.counterevidence ?? row.finding.counterevidence,
      confidenceRationale: row.confidenceRationale ?? row.finding.confidenceRationale,
      severityChangeConditions: row.severityChangeConditions ?? row.finding.severityChangeConditions,
      ...(row.codeLocations?.length ? { codeLocations: row.codeLocations } : row.finding.codeLocations?.length ? { codeLocations: row.finding.codeLocations } : {}),
      // The DB row is authoritative for the v6 provenance/verification contract.
      provenance: row.provenance,
      ...(row.parentFindingIds?.length ? { parentFindingIds: row.parentFindingIds } : {}),
      verificationStatus: row.verificationClass,
    } as Finding & FindingProvenanceFields))
    const provenanceCounts = buildProvenanceReport(findings as (Finding & FindingProvenanceFields)[]).provenanceCounts

    const messageBase = this.db.select().from(tables.messages).where(eq(tables.messages.runId, runId))
      .orderBy(asc(tables.messages.createdAt), sql`${tables.messages}.rowid`)
    const messages = isPaged(messagePage)
      ? messageBase.limit(resolvePageLimit(messagePage.limit, 1000)).offset(resolvePageOffset(messagePage.offset)).all()
      : messageBase.all()
    const boardMessages = isPaged(boardPage)
      ? this.db.select().from(tables.boardMessages).where(eq(tables.boardMessages.runId, runId))
          .orderBy(asc(tables.boardMessages.seq))
          .limit(resolvePageLimit(boardPage.limit, 500)).offset(resolvePageOffset(boardPage.offset)).all()
      : this.listBoardMessages(runId, { includeTainted: true, limit: 500 })

    const paging = options
      ? {
          ...(options.includeTotals === false ? {} : {
            totals: {
              evidence: this.countRunRows('evidence', runId),
              facts: this.countRunRows('facts', runId),
              exchanges: this.countRunRows('broker_exchanges', runId),
              endpoints: this.countRunRows('endpoints', runId),
              endpointParams: this.countRunRows('endpoint_params', runId),
              messages: this.countRunRows('messages', runId),
              boardMessages: this.countRunRows('board_messages', runId),
            },
          }),
          limit: options.limit,
          offset: resolvePageOffset(options.offset),
        }
      : undefined

    return {
      run,
      project: this.project(run.projectId),
      personas: listProjectPersonas(this, run.projectId),
      specs: this.listProjectSpecs(run.projectId),
      threatModel,
      chainSteps,
      facts: facts as SerializableFact[],
      graphEdges,
      digests,
      assignments,
      approvals,
      exchangesSummary,
      coverageEntries,
      endpoints,
      endpointParams,
      apiDependencies,
      labTelemetry,
      openProofGaps,
      sastRuns,
      surfaceProbes,
      patchProposals,
      replaySpecs: replaySpecs as unknown as SerializableReplaySpecRow[],
      retestRuns,
      findings,
      provenanceCounts,
      messages,
      boardMembers: this.listBoardMembers(runId),
      boardMessages,
      evidence: evidenceRows.map(item => ({ ...item, title: evidenceTitle(run, item.kind, item.title) })),
      reports: this.db.select().from(tables.reports).where(eq(tables.reports.runId, runId))
        .orderBy(desc(tables.reports.version)).all(),
      cursor: streamHead?.id ?? 0,
      ...(paging ? { paging } : {}),
    }
  }

  /** Exact pagination totals (indexed run_id COUNT); used by `runDetail` instead of hydration. */
  private countRunRows(table: string, runId: string): number {
    const row = this.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE run_id = ?`).get(runId) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  }

  workerList(runId: string) {
    return this.db.select().from(tables.assignments).where(eq(tables.assignments.runId, runId))
      .orderBy(asc(tables.assignments.createdAt), asc(tables.assignments.title)).all()
  }

  runnable() {
    return this.db.select().from(tables.runs).where(and(
      eq(tables.runs.workspaceId, this.workspace.id), eq(tables.runs.status, 'running'),
    )).orderBy(asc(tables.runs.createdAt)).all()
  }

  runsWithPendingRetests() {
    const queuedRetests = this.db.select({ runId: tables.assignments.runId }).from(tables.assignments).where(and(
      eq(tables.assignments.phase, 'retest'), eq(tables.assignments.status, 'queued'),
    )).all()
    const ids = [...new Set(queuedRetests.map(r => r.runId))]
    if (!ids.length) return []
    return this.db.select().from(tables.runs).where(and(
      eq(tables.runs.workspaceId, this.workspace.id), inArray(tables.runs.id, ids),
    )).all()
  }

  worker(workerId: string) {
    const assignment = this.db.select().from(tables.assignments).where(eq(tables.assignments.id, workerId)).get()
    if (!assignment) throw new Error('Assignment not found.')
    this.run(assignment.runId)
    return assignment
  }

  assignmentEvidence(assignmentId: string, operationId: string) {
    return this.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.assignmentId, assignmentId), eq(tables.evidence.operationId, operationId),
    )).get()
  }

  assignmentObservation(assignmentId: string) {
    return this.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.assignmentId, assignmentId), eq(tables.evidence.kind, 'observation'),
    )).orderBy(desc(tables.evidence.scopeRevision), desc(tables.evidence.createdAt)).limit(1).get()
  }

  brokerOrigins(assignment: Assignment) {
    this.flushNow()
    const exchangeRows = this.db.select({
      origin: tables.brokerExchanges.origin,
      finalOrigin: tables.brokerExchanges.finalOrigin,
      redirectOrigins: tables.brokerExchanges.redirectOrigins,
    }).from(tables.brokerExchanges).where(eq(tables.brokerExchanges.assignmentId, assignment.id)).all()
    const origins = new Set<string>(assignment.sourceOrigins)
    for (const ex of exchangeRows) {
      origins.add(ex.origin)
      origins.add(ex.finalOrigin)
      for (const hop of ex.redirectOrigins) origins.add(hop)
    }
    const evs = this.db.select({ kind: tables.events.kind, detail: tables.events.detail })
      .from(tables.events).where(and(
        eq(tables.events.runId, assignment.runId), inArray(tables.events.kind, ['broker.allowed', 'evidence.reused']),
        sql`json_extract(${tables.events.detail}, '$.assignmentId') = ${assignment.id}`,
      )).all()
    for (const { kind, detail } of evs) {
      const list = kind === 'broker.allowed' ? [detail.origin] : detail.origins
      if (Array.isArray(list)) {
        for (const origin of list) {
          if (typeof origin === 'string' && origin) origins.add(origin)
        }
      }
    }
    return [...origins]
  }

  /** Deterministic 2-hex shard for artifact paths: `artifacts/<runId>/<bucket>/<id>.txt`. */
  private artifactBucket(id: string): string {
    return createHash('sha256').update(id).digest('hex').slice(0, 2)
  }

  private artifactShardFile(runId: string, id: string, group?: string): string {
    const parts = [this.directory, 'artifacts', runId]
    if (group) parts.push(group)
    parts.push(this.artifactBucket(id), id + '.txt')
    return join(...parts)
  }

  private writeArtifactFile(runId: string, id: string, content: string, group?: string, durable = true) {
    const file = this.artifactShardFile(runId, id, group)
    mkdirSync(join(file, '..'), { recursive: true, mode: 0o700 })
    try {
      writeFileSync(file, content, { flag: 'wx', mode: 0o600, flush: durable })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    }
  }

  /** Read a sharded artifact, falling back to the legacy flat `artifacts/<id>.txt` layout. */
  private readArtifactFile(runId: string, id: string, group?: string): string | null {
    const flat = join(this.directory, 'artifacts', id + '.txt')
    if (existsSync(flat)) return readFileSync(flat, 'utf8')
    const direct = this.artifactShardFile(runId, id, group)
    if (existsSync(direct)) return readFileSync(direct, 'utf8')
    const runDir = join(this.directory, 'artifacts', runId)
    const buckets = [this.artifactBucket(id)]
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

  writeBlob(content: string, secrets: readonly NamedSecret[] = [], runId?: string, durable = true): { id: string; sha256: string } {
    const clean = redact(content, secrets)
    const sha256 = createHash('sha256').update(clean, 'utf8').digest('hex')
    const id = 'blob-' + sha256
    if (runId) {
      this.writeArtifactFile(runId, id, clean, 'blobs', durable)
    } else {
      const file = join(this.directory, 'artifacts', id + '.txt')
      if (!existsSync(file)) {
        try {
          writeFileSync(file, clean, { flag: 'wx', mode: 0o600, flush: durable })
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
        }
      }
    }
    return { id, sha256 }
  }

  readBlob(blobId: string, runId?: string): string {
    if (!/^blob-[a-f0-9]{64}$/.test(blobId)) throw new Error('Invalid blob ID.')
    if (runId) {
      const scoped = this.readArtifactFile(runId, blobId, 'blobs')
      if (scoped !== null) return scoped
    }
    const flat = join(this.directory, 'artifacts', blobId + '.txt')
    if (existsSync(flat)) return readFileSync(flat, 'utf8')
    // Content-addressed blobs may have been first written under another run.
    let dirs: string[] = []
    try {
      dirs = readdirSync(join(this.directory, 'artifacts'), { withFileTypes: true })
        .filter(entry => entry.isDirectory()).map(entry => entry.name)
    } catch { /* empty artifacts dir */ }
    for (const dir of dirs) {
      const found = this.readArtifactFile(dir, blobId, 'blobs')
      if (found !== null) return found
    }
    throw new Error('Artifact not found.')
  }

  artifact(runId: string, artifactId: string) {
    const run = this.run(runId)
    const item = this.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.id, artifactId), eq(tables.evidence.runId, runId),
    )).get()
    if (!item) throw new Error('Evidence not found.')
    const content = this.readArtifactFile(runId, item.id)
    if (content === null) throw new Error('Artifact not found.')
    return {
      ...item,
      title: evidenceTitle(run, item.kind, item.title),
      content,
    }
  }

  addArtifact(
    run: Run,
    assignment: Assignment,
    kind: typeof tables.evidence.$inferSelect.kind,
    title: string,
    content: string,
    operationId?: string,
    secrets: readonly NamedSecret[] = [],
  ) {
    if (operationId) {
      const existing = this.assignmentEvidence(assignment.id, operationId)
      if (existing) return existing
    }
    const id = randomUUID()
    this.writeArtifactFile(run.id, id, redact(content, secrets))
    return this.db.insert(tables.evidence).values({
      id, runId: run.id, assignmentId: assignment.id, scopeRevision: run.scopeRevision,
      goalRevision: assignment.goalRevision, title: redact(title, secrets), kind, operationId, createdAt: Date.now(),
    }).returning().get()
  }

  // --- Broker Exchanges & FTS5 Search ---

  recordExchange(input: {
    runId: string
    assignmentId: string
    scopeRevision: number
    origin: string
    finalOrigin: string
    redirectOrigins: string[]
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    status: number
    mediaType: string
    reqHeaders: Record<string, string>
    respHeaders: Record<string, string>
    body: string
    durationMs: number
    secrets?: readonly NamedSecret[]
    /** Redacted structural evidence captured pre-scrub by the broker. Fingerprints only. */
    secretMatches?: readonly SecretMatch[]
  }): BrokerExchange {
    const secrets = input.secrets ?? []
    const cleanBody = redact(input.body, secrets)
    const cleanPath = redact(input.pathAndQuery, secrets)
    const cleanReqHeaders = redactHeaders(input.reqHeaders, secrets)
    const cleanRespHeaders = redactHeaders(input.respHeaders, secrets)
    const bodyPreview = cleanBody.slice(0, 8192)
    let bodyArtifactId: string | null = null
    let bodySha256: string
    if (cleanBody.length > 0) {
      // Hot path: write the content-addressed body without an fsync. WAL + the explicit flush
      // boundaries (snapshot/close/report) provide the same crash guarantee as `synchronous=NORMAL`.
      const blob = this.writeBlob(cleanBody, secrets, input.runId, false)
      bodyArtifactId = blob.id
      bodySha256 = blob.sha256
    } else {
      bodySha256 = createHash('sha256').update('').digest('hex')
    }

    const row: BrokerExchange = {
      id: randomUUID(),
      runId: input.runId,
      assignmentId: input.assignmentId,
      scopeRevision: input.scopeRevision,
      origin: input.origin,
      finalOrigin: input.finalOrigin,
      redirectOrigins: [...new Set([input.origin, input.finalOrigin, ...input.redirectOrigins])],
      method: input.method.toUpperCase(),
      pathAndQuery: cleanPath,
      personaHandle: input.personaHandle ?? null,
      status: input.status,
      mediaType: input.mediaType || 'application/octet-stream',
      reqHeaders: cleanReqHeaders,
      respHeaders: cleanRespHeaders,
      bodyPreview,
      bodyArtifactId,
      bodySha256,
      secretMatches: sanitizeSecretMatches(input.secretMatches, secrets),
      durationMs: Math.max(0, Math.round(input.durationMs)),
      createdAt: Date.now(),
    }

    this.enqueueExchange({
      row,
      ftsBody: this.ftsMode === 'off'
        ? null
        : capUtf8Bytes(this.ftsMode === 'full' ? cleanBody : bodyPreview, this.ftsMaxBodyBytes),
      eventMessage: `${row.method} ${row.origin}${row.pathAndQuery.slice(0, 80)} → ${row.status}`,
      eventDetail: {
        exchangeId: row.id,
        assignmentId: row.assignmentId,
        origin: row.origin,
        finalOrigin: row.finalOrigin,
        status: row.status,
        personaHandle: row.personaHandle,
      },
    })
    return row
  }

  getExchange(runId: string, exchangeId: string): (BrokerExchange & { body: string }) {
    this.flushNow()
    this.run(runId)
    const row = this.db.select().from(tables.brokerExchanges).where(and(
      eq(tables.brokerExchanges.runId, runId), eq(tables.brokerExchanges.id, exchangeId),
    )).get()
    if (!row) throw new Error('Broker exchange not found.')
    let body = row.bodyPreview
    if (row.bodyArtifactId) {
      try { body = this.readBlob(row.bodyArtifactId, runId) } catch { body = row.bodyPreview }
    }
    return { ...row, body }
  }

  searchExchanges(runId: string, query: string, opts: {
    approvedOrigins?: ReadonlySet<string>
    origin?: string
    limit?: number
  } = {}): BrokerExchange[] {
    this.flushNow()
    this.run(runId)
    const limit = Math.min(Math.max(1, opts.limit ?? 30), 100)
    const q = query.trim()
    let rows: BrokerExchange[]
    if (!q) {
      rows = this.db.select().from(tables.brokerExchanges)
        .where(opts.origin
          ? and(eq(tables.brokerExchanges.runId, runId), eq(tables.brokerExchanges.origin, opts.origin))
          : eq(tables.brokerExchanges.runId, runId))
        .orderBy(desc(tables.brokerExchanges.createdAt)).limit(limit * 2).all()
    } else if (this.ftsAvailable && q.length >= 3) {
      const escaped = '"' + q.replaceAll('"', '""') + '"'
      const ids = this.client.prepare(
        `SELECT exchange_id FROM broker_exchanges_fts WHERE run_id = ? AND broker_exchanges_fts MATCH ? LIMIT ?`,
      ).all(runId, escaped, limit * 3) as Array<{ exchange_id: string }>
      const matchIds = ids.map(r => r.exchange_id)
      rows = matchIds.length
        ? this.db.select().from(tables.brokerExchanges)
            .where(and(eq(tables.brokerExchanges.runId, runId), inArray(tables.brokerExchanges.id, matchIds)))
            .orderBy(desc(tables.brokerExchanges.createdAt)).all()
        : []
    } else {
      const likePattern = `%${q.toLowerCase()}%`
      rows = this.db.select().from(tables.brokerExchanges)
        .where(and(
          eq(tables.brokerExchanges.runId, runId),
          sql`(lower(${tables.brokerExchanges.pathAndQuery}) LIKE ${likePattern} OR lower(${tables.brokerExchanges.bodyPreview}) LIKE ${likePattern} OR lower(${tables.brokerExchanges.respHeaders}) LIKE ${likePattern})`,
        ))
        .orderBy(desc(tables.brokerExchanges.createdAt)).limit(limit * 2).all()
    }
    return rows.filter(ex => {
      if (opts.origin && ex.origin !== opts.origin) return false
      if (opts.approvedOrigins) {
        const origins = [ex.origin, ex.finalOrigin, ...ex.redirectOrigins]
        if (origins.some(o => !opts.approvedOrigins!.has(o))) return false
      }
      return true
    }).slice(0, limit)
  }

  // --- Retention GC & storage footprint (v6.2) ---

  /**
   * Delete aged exchanges (rows + FTS rows + unreferenced sharded body blobs) for one run in
   * bounded IMMEDIATE batches. `olderThanMs` bounds the age, `keepLatest` always preserves the
   * newest N exchanges. An unbounded delete (no cutoff and no keepLatest) is a no-op.
   */
  pruneExchanges(options: PruneExchangesOptions): PruneExchangesResult {
    const result = this.pruneExchangeRows(options)
    if (options.emitEvent !== false && result.exchanges > 0) {
      this.event(result.runId, 'retention.pruned',
        `Pruned ${result.exchanges} exchange row(s) from run ${result.runId}.`, {
          scope: 'run',
          runId: result.runId,
          exchanges: result.exchanges,
          ftsRows: result.ftsRows,
          blobs: result.blobs,
          blobBytes: result.blobBytes,
          batches: result.batches,
          cutoff: result.cutoff,
          keepLatest: result.keepLatest,
        })
    }
    return result
  }

  /**
   * Apply per-run exchange retention (`retentionDays`, default 14) across the workspace, or one
   * run. Skips actively running runs by default so a live scan keeps its verification evidence,
   * and emits a single aggregated `retention.pruned` note with counts.
   */
  prune(options: PruneOptions = {}): PruneResult {
    this.flushNow()
    const retentionDays = options.retentionDays ?? DEFAULT_EXCHANGE_RETENTION_DAYS
    const keepLatest = Math.max(0, Math.trunc(options.keepLatest ?? 0))
    const now = options.now ?? Date.now()
    const result: PruneResult = {
      runs: 0, exchanges: 0, ftsRows: 0, blobs: 0, blobBytes: 0, batches: 0,
      retentionDays, keepLatest, perRun: [],
    }
    if (!(retentionDays > 0)) return result
    let runIds: string[]
    if (options.runId) {
      runIds = [this.run(options.runId).id]
    } else {
      const rows = this.client.prepare('SELECT id, status FROM runs').all() as Array<{ id: string; status: string }>
      runIds = rows
        .filter(row => !(options.skipActiveRuns ?? true) || row.status !== 'running')
        .map(row => row.id)
    }
    for (const runId of runIds) {
      const pruned = this.pruneExchangeRows({
        runId,
        olderThanMs: retentionDays * 24 * 60 * 60_000,
        keepLatest,
        batchSize: options.batchSize,
        now,
        emitEvent: false,
      })
      if (pruned.exchanges === 0) continue
      result.runs += 1
      result.exchanges += pruned.exchanges
      result.ftsRows += pruned.ftsRows
      result.blobs += pruned.blobs
      result.blobBytes += pruned.blobBytes
      result.batches += pruned.batches
      result.perRun.push({
        runId, exchanges: pruned.exchanges, ftsRows: pruned.ftsRows, blobs: pruned.blobs, blobBytes: pruned.blobBytes,
      })
    }
    if (result.exchanges > 0) {
      this.event(options.runId ?? null, 'retention.pruned',
        `Pruned ${result.exchanges} exchange row(s) across ${result.runs} run(s) `
        + `(retention ${retentionDays}d, keepLatest ${keepLatest}).`, {
          scope: options.runId ? 'run' : 'workspace',
          retentionDays,
          keepLatest,
          runs: result.runs,
          exchanges: result.exchanges,
          ftsRows: result.ftsRows,
          blobs: result.blobs,
          blobBytes: result.blobBytes,
          batches: result.batches,
          perRun: result.perRun.slice(0, 20),
        })
    }
    return result
  }

  /** Current on-disk DB/WAL/artifact sizes plus FTS/exchange row counts. */
  storeFootprint(): StoreFootprint {
    this.flushNow()
    const mainDbBytes = safeFileSize(join(this.directory, 'guardian.sqlite'))
    const walBytes = safeFileSize(join(this.directory, 'guardian.sqlite-wal'))
    const shmBytes = safeFileSize(join(this.directory, 'guardian.sqlite-shm'))
    const { total: artifactBytes, blobs: blobBytes } = boundedArtifactSize(join(this.directory, 'artifacts'))
    let ftsRows = 0
    if (this.ftsTableExists) {
      try {
        const row = this.client.prepare('SELECT count(*) AS c FROM broker_exchanges_fts').get() as { c?: number } | undefined
        ftsRows = Number(row?.c ?? 0)
      } catch { ftsRows = 0 }
    }
    const exchangeRow = this.client.prepare('SELECT count(*) AS c FROM broker_exchanges').get() as { c?: number } | undefined
    return {
      directory: this.directory,
      mainDbBytes,
      walBytes,
      shmBytes,
      dbBytes: mainDbBytes + walBytes + shmBytes,
      artifactBytes,
      blobBytes,
      ftsRows,
      exchangeRows: Number(exchangeRow?.c ?? 0),
      ftsMode: this.ftsMode,
      ftsMaxBodyBytes: this.ftsMaxBodyBytes,
      maxFullFtsDbBytes: this.maxFullFtsDbBytes,
    }
  }

  /** Rowid of the oldest exchange that must be kept by `keepLatest` (null when the run is short). */
  private keepBoundaryRowid(runId: string, keepLatest: number): number | null {
    const row = this.client.prepare(
      'SELECT rowid AS r FROM broker_exchanges WHERE run_id = ? ORDER BY rowid DESC LIMIT 1 OFFSET ?',
    ).get(runId, Math.max(0, keepLatest - 1)) as { r?: number } | undefined
    return row?.r === undefined ? null : Number(row.r)
  }

  private pruneExchangeRows(options: PruneExchangesOptions): PruneExchangesResult {
    this.flushNow()
    const run = this.run(options.runId)
    const batchSize = clampInteger(options.batchSize ?? 500, 1, 5000)
    const now = options.now ?? Date.now()
    const keepLatest = Math.max(0, Math.trunc(options.keepLatest ?? 0))
    const cutoff = options.olderThanMs === undefined ? null : now - Math.max(0, options.olderThanMs)
    const result: PruneExchangesResult = {
      runId: run.id, exchanges: 0, ftsRows: 0, blobs: 0, blobBytes: 0, batches: 0, cutoff, keepLatest,
    }
    // Safety: never delete a whole run's history without an age bound or a keepLatest floor.
    if (cutoff === null && keepLatest === 0) return result
    const keepRowid = keepLatest > 0 ? this.keepBoundaryRowid(run.id, keepLatest) : null
    if (keepLatest > 0 && keepRowid === null) return result
    const blobIds = new Set<string>()
    let cursor = 0
    for (;;) {
      const batch = this.pruneExchangeBatch(run.id, { cursor, cutoff, keepRowid, batchSize })
      if (!batch) break
      result.exchanges += batch.rows
      result.ftsRows += batch.ftsRows
      result.batches += 1
      cursor = batch.lastRowid
      for (const id of batch.blobIds) blobIds.add(id)
      if (batch.rows < batchSize) break
    }
    const runDirs = uniqueArtifactRunDirs(this.directory)
    for (const blobId of blobIds) {
      const removed = this.deleteBlobIfUnreferenced(run.id, blobId, runDirs)
      if (removed.deleted) {
        result.blobs += 1
        result.blobBytes += removed.bytes
      }
    }
    return result
  }

  private pruneExchangeBatch(
    runId: string,
    state: { cursor: number; cutoff: number | null; keepRowid: number | null; batchSize: number },
  ): { rows: number; ftsRows: number; lastRowid: number; blobIds: string[] } | null {
    const conditions = ['run_id = ?']
    const params: Array<string | number> = [runId]
    if (state.cursor > 0) {
      conditions.push('rowid > ?')
      params.push(state.cursor)
    }
    if (state.keepRowid !== null) {
      conditions.push('rowid < ?')
      params.push(state.keepRowid)
    }
    if (state.cutoff !== null) {
      conditions.push('created_at < ?')
      params.push(state.cutoff)
    }
    const rows = this.client.prepare(
      `SELECT rowid AS rowid, id, body_artifact_id FROM broker_exchanges
       WHERE ${conditions.join(' AND ')} ORDER BY rowid ASC LIMIT ?`,
    ).all(...params, state.batchSize) as Array<{ rowid: number; id: string; body_artifact_id: string | null }>
    if (!rows.length) return null
    const ids = rows.map(row => row.id)
    const placeholders = ids.map(() => '?').join(', ')
    let ftsRows = 0
    this.transaction(() => {
      if (this.ftsTableExists) {
        const info = this.client.prepare(
          `DELETE FROM broker_exchanges_fts WHERE exchange_id IN (${placeholders})`,
        ).run(...ids)
        ftsRows = Number(info.changes ?? 0)
      }
      this.client.prepare(
        `DELETE FROM broker_exchanges WHERE run_id = ? AND id IN (${placeholders})`,
      ).run(runId, ...ids)
    })
    return {
      rows: rows.length,
      ftsRows,
      lastRowid: Number(rows[rows.length - 1]!.rowid),
      blobIds: rows.map(row => row.body_artifact_id).filter((id): id is string => typeof id === 'string' && id.length > 0),
    }
  }

  /**
   * Remove a content-addressed exchange body blob once no exchange row anywhere references it.
   * Blobs are shared by hash across runs, so every shard copy is scanned before deletion.
   */
  private deleteBlobIfUnreferenced(
    runId: string,
    blobId: string,
    artifactRunDirs: readonly string[] = uniqueArtifactRunDirs(this.directory),
  ): { deleted: boolean; bytes: number } {
    const referenced = this.client.prepare(
      'SELECT 1 AS hit FROM broker_exchanges WHERE body_artifact_id = ? LIMIT 1',
    ).get(blobId) as { hit?: number } | undefined
    if (referenced?.hit) return { deleted: false, bytes: 0 }
    const candidates = new Set<string>([join(this.directory, 'artifacts', blobId + '.txt')])
    const bucket = this.artifactBucket(blobId)
    const runDirs = new Set<string>([runId, ...artifactRunDirs])
    for (const dir of runDirs) {
      candidates.add(join(this.directory, 'artifacts', dir, 'blobs', bucket, blobId + '.txt'))
    }
    let bytes = 0
    let deleted = false
    for (const file of candidates) {
      try {
        const info = lstatSync(file)
        if (!info.isFile()) continue
        bytes += info.size
        unlinkSync(file)
        deleted = true
      } catch { /* missing or already removed */ }
    }
    if (deleted) {
      try { rmdirSync(join(this.directory, 'artifacts', runId, 'blobs', bucket)) } catch { /* non-empty */ }
    }
    return { deleted, bytes }
  }

  // --- Threat Models, Chain Steps, Facts, Graph Edges, Digests ---

  saveThreatModel(run: Run, entries: ThreatModelSummary[], summary: string): ThreatModel {
    const row = this.db.insert(tables.threatModels).values({
      id: randomUUID(),
      runId: run.id,
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      entries,
      summary: redact(summary),
      createdAt: Date.now(),
    }).returning().get()
    this.event(run.id, 'threat_model.saved', `Threat model ranked ${entries.length} approved hosts.`, {
      threatModelId: row.id, scopeRevision: run.scopeRevision, hosts: entries.length,
    })
    return row
  }

  latestThreatModel(runId: string, goalRevision?: number): ThreatModel | null {
    const where = goalRevision !== undefined
      ? and(eq(tables.threatModels.runId, runId), eq(tables.threatModels.goalRevision, goalRevision))
      : eq(tables.threatModels.runId, runId)
    return this.db.select().from(tables.threatModels).where(where)
      .orderBy(desc(tables.threatModels.createdAt)).limit(1).get() ?? null
  }

  listChainSteps(runId: string, goalRevision?: number): ChainStep[] {
    const where = goalRevision !== undefined
      ? and(eq(tables.chainSteps.runId, runId), eq(tables.chainSteps.goalRevision, goalRevision))
      : eq(tables.chainSteps.runId, runId)
    return this.db.select().from(tables.chainSteps).where(where)
      .orderBy(asc(tables.chainSteps.seq), desc(tables.chainSteps.priority)).all()
  }

  addChainStep(run: Run, input: {
    title: string
    hypothesis: string
    category?: OwaspCategory | string
    priority?: number
    targetAssetIds: string[]
    skills?: string[]
    dependsOnFactIds?: string[]
    dependsOnStepIds?: string[]
    sourceOrigins?: string[]
    specialistProfile?: SpecialistProfile | null
    trialGroupId?: string | null
    trialIndex?: number
  }): ChainStep {
    if (
      input.specialistProfile !== undefined &&
      input.specialistProfile !== null &&
      !(specialistProfiles as readonly string[]).includes(input.specialistProfile)
    ) {
      throw new Error(`Invalid specialistProfile "${String(input.specialistProfile)}": expected one of ${specialistProfiles.join(', ')}.`)
    }
    const existingSteps = this.listChainSteps(run.id)
    const nextSeq = (existingSteps.at(-1)?.seq ?? 0) + 1
    const depFactIds = [...new Set(input.dependsOnFactIds ?? [])]
    const depStepIds = [...new Set(input.dependsOnStepIds ?? [])]
    const origins = new Set<string>(input.sourceOrigins ?? [])
    for (const assetId of input.targetAssetIds) {
      const asset = run.candidates.find(c => c.id === assetId)
      if (asset) origins.add(asset.origin)
    }
    if (depFactIds.length) {
      const depFacts = this.db.select().from(tables.facts).where(and(
        eq(tables.facts.runId, run.id), inArray(tables.facts.id, depFactIds),
      )).all()
      for (const f of depFacts) {
        origins.add(f.origin)
        for (const o of f.sourceOrigins) origins.add(o)
      }
    }
    const allDepStepsComplete = depStepIds.every(sid => existingSteps.find(s => s.id === sid)?.status === 'complete')
    const now = Date.now()
    const step = this.transaction(() => {
      const created = this.db.insert(tables.chainSteps).values({
        id: randomUUID(),
        runId: run.id,
        goalRevision: run.goalRevision,
        scopeRevision: run.scopeRevision,
        seq: nextSeq,
        title: redact(input.title.slice(0, 200)),
        hypothesis: redact(input.hypothesis.slice(0, 1200)),
        category: input.category ?? 'misconfig-exposure',
        priority: Math.max(0, Math.min(100, Math.round(input.priority ?? 50))),
        targetAssetIds: [...new Set(input.targetAssetIds)],
        skills: [...new Set(input.skills ?? [])],
        dependsOnFactIds: depFactIds,
        dependsOnStepIds: depStepIds,
        status: allDepStepsComplete ? 'ready' : 'pending',
        assignedWorkerId: null,
        specialistProfile: input.specialistProfile ?? null,
        trialGroupId: input.trialGroupId ?? null,
        trialIndex: Math.max(0, Math.round(input.trialIndex ?? 0)),
        sourceOrigins: [...origins],
        createdAt: now,
        updatedAt: now,
      }).returning().get()
      for (const fId of depFactIds) {
        this.addGraphEdge(run.id, { fromKind: 'step', fromId: created.id, toKind: 'fact', toId: fId, edgeKind: 'depends_on' })
      }
      for (const sId of depStepIds) {
        this.addGraphEdge(run.id, { fromKind: 'step', fromId: created.id, toKind: 'step', toId: sId, edgeKind: 'depends_on' })
      }
      return created
    }, { behavior: 'immediate' })
    this.event(run.id, 'chain_step.created', `Planned step #${step.seq}: ${step.title}`, {
      stepId: step.id, seq: step.seq, priority: step.priority, category: step.category,
    })
    return step
  }

  updateChainStep(stepId: string, patch: Partial<ChainStep>): ChainStep {
    const existing = this.db.select().from(tables.chainSteps).where(eq(tables.chainSteps.id, stepId)).get()
    if (!existing) throw new Error('Chain step not found.')
    // `canceled` is terminal: a sibling trial's worker can finish after early-stop and must not
    // resurrect its step as complete/running.
    if (existing.status === 'canceled' && patch.status && patch.status !== 'canceled') {
      return existing as unknown as ChainStep
    }
    const updated = this.db.update(tables.chainSteps).set({ ...patch, updatedAt: Date.now() })
      .where(eq(tables.chainSteps.id, stepId)).returning().get()
    if (!updated) throw new Error('Chain step not found.')
    return updated
  }

  refreshReadyChainSteps(runId: string, goalRevision: number) {
    const steps = this.listChainSteps(runId, goalRevision)
    const stepById = new Map(steps.map(s => [s.id, s]))
    const runFacts = new Map(
      this.db.select({ id: tables.facts.id, tainted: tables.facts.tainted }).from(tables.facts)
        .where(eq(tables.facts.runId, runId)).all().map(f => [f.id, f]),
    )
    for (const step of steps) {
      if (step.status !== 'pending') continue
      const taintedDep = step.dependsOnStepIds.some(sid => {
        const s = stepById.get(sid)
        return s && (s.status === 'tainted' || s.status === 'canceled')
      }) || step.dependsOnFactIds.some(fid => runFacts.get(fid)?.tainted)
      if (taintedDep) {
        this.updateChainStep(step.id, { status: 'tainted' })
        continue
      }
      const ready = step.dependsOnStepIds.every(sid => stepById.get(sid)?.status === 'complete') &&
        step.dependsOnFactIds.every(fid => {
          const f = runFacts.get(fid)
          return f && !f.tainted
        })
      if (ready) this.updateChainStep(step.id, { status: 'ready' })
    }
  }

  addFact(run: Run, assignment: Assignment, input: {
    kind: FactKind
    origin: string
    summary: string
    data?: Record<string, unknown>
    evidenceIds?: string[]
    exchangeIds?: string[]
    sourceOrigins?: string[]
    secrets?: readonly NamedSecret[]
  }): Fact {
    const secrets = input.secrets ?? []
    const origins = new Set<string>([input.origin, ...assignment.sourceOrigins, ...(input.sourceOrigins ?? [])])
    const exIds = [...new Set(input.exchangeIds ?? [])]
    if (exIds.length) {
      const exRows = this.db.select({
        origin: tables.brokerExchanges.origin,
        finalOrigin: tables.brokerExchanges.finalOrigin,
        redirectOrigins: tables.brokerExchanges.redirectOrigins,
      }).from(tables.brokerExchanges).where(and(
        eq(tables.brokerExchanges.runId, run.id), inArray(tables.brokerExchanges.id, exIds),
      )).all()
      for (const ex of exRows) {
        origins.add(ex.origin)
        origins.add(ex.finalOrigin)
        for (const hop of ex.redirectOrigins) origins.add(hop)
      }
    }
    const rawData = input.data ?? {}
    const isSubkind = input.kind === 'tech_fingerprint' || input.kind === 'cve_hypothesis' ||
      input.kind === 'code_audit_suspect' || input.kind === 'persona_resource'
    const enrichedData: Record<string, unknown> = isSubkind
      ? { subkind: input.kind, ...rawData }
      : rawData
    const cleanData = JSON.parse(redact(JSON.stringify(enrichedData), secrets)) as Record<string, unknown>
    const fact = this.transaction(() => {
      const inserted = this.db.insert(tables.facts).values({
        id: randomUUID(),
        runId: run.id,
        assignmentId: assignment.id,
        scopeRevision: run.scopeRevision,
        goalRevision: assignment.goalRevision,
        kind: normalizeFactKind(input.kind),
        origin: input.origin,
        summary: redact(input.summary.slice(0, 600), secrets),
        data: cleanData,
        sourceOrigins: [...origins],
        evidenceIds: [...new Set(input.evidenceIds ?? [])],
        exchangeIds: exIds,
        tainted: false,
        coldSinceRound: null,
        digestId: null,
        createdAt: Date.now(),
      }).returning().get()
      this.addGraphEdge(run.id, {
        fromKind: 'assignment', fromId: assignment.id, toKind: 'fact', toId: inserted.id, edgeKind: 'yields',
      })
      return inserted
    }, { behavior: 'immediate' })
    this.event(run.id, 'fact.recorded', `[${input.kind}] ${fact.origin}: ${fact.summary.slice(0, 120)}`, {
      factId: fact.id, kind: input.kind, origin: fact.origin, assignmentId: assignment.id,
    })
    return fact
  }

  listFacts(runId: string, opts: {
    includeTainted?: boolean
    origin?: string
    kind?: string
    query?: string
    limit?: number
    offset?: number
  } = {}): Fact[] {
    const conditions = [eq(tables.facts.runId, runId)]
    if (!opts.includeTainted) conditions.push(eq(tables.facts.tainted, false))
    if (opts.origin) conditions.push(eq(tables.facts.origin, opts.origin))
    if (opts.kind) {
      conditions.push(or(
        eq(tables.facts.kind, opts.kind as Fact['kind']),
        sql`json_extract(${tables.facts.data}, '$.subkind') = ${opts.kind}`,
      )!)
    }
    const q = opts.query?.trim().toLowerCase()
    if (q) {
      const pattern = `%${q}%`
      conditions.push(sql`lower(
        ${tables.facts.origin} || ' ' || ${tables.facts.kind} || ' ' || ${tables.facts.summary} || ' ' || ${tables.facts.data}
      ) LIKE ${pattern}`)
    }
    const limit = resolvePageLimit(opts.limit, 100)
    const offset = resolvePageOffset(opts.offset)
    return this.db.select().from(tables.facts).where(and(...conditions))
      .orderBy(desc(tables.facts.createdAt), asc(tables.facts.id))
      .limit(limit).offset(offset).all()
  }

  addGraphEdge(runId: string, edge: {
    fromKind: GraphEdge['fromKind']
    fromId: string
    toKind: GraphEdge['toKind']
    toId: string
    edgeKind: GraphEdge['edgeKind']
  }): GraphEdge {
    return this.db.insert(tables.graphEdges).values({
      id: randomUUID(), runId, ...edge, createdAt: Date.now(),
    }).returning().get()
  }

  listGraphEdges(runId: string): GraphEdge[] {
    return this.db.select().from(tables.graphEdges).where(eq(tables.graphEdges.runId, runId))
      .orderBy(asc(tables.graphEdges.createdAt)).all()
  }

  listDigests(runId: string, activeOnly = true): GraphDigest[] {
    const where = activeOnly
      ? and(eq(tables.graphDigests.runId, runId), eq(tables.graphDigests.active, true))
      : eq(tables.graphDigests.runId, runId)
    return this.db.select().from(tables.graphDigests).where(where)
      .orderBy(desc(tables.graphDigests.createdAt)).all()
  }

  getDigest(runId: string, digestId: string) {
    this.run(runId)
    const digest = this.db.select().from(tables.graphDigests).where(and(
      eq(tables.graphDigests.runId, runId), eq(tables.graphDigests.id, digestId),
    )).get()
    if (!digest) throw new Error('Graph digest not found.')
    const coveredFacts = digest.coveredFactIds.length
      ? this.db.select().from(tables.facts).where(and(
          eq(tables.facts.runId, runId),
          eq(tables.facts.tainted, false),
          inArray(tables.facts.id, digest.coveredFactIds),
        )).all()
      : []
    return { digest, facts: coveredFacts as SerializableFact[] }
  }

  saveDigest(runId: string, input: {
    roundNo: number
    level: 'minor' | 'major'
    signatureHash: string
    summary: string
    coveredFactIds: string[]
    coveredAssignmentIds: string[]
    supersedeDigestIds?: string[]
  }): GraphDigest {
    const digest = this.transaction(() => {
      const created = this.db.insert(tables.graphDigests).values({
        id: randomUUID(),
        runId,
        roundNo: input.roundNo,
        level: input.level,
        signatureHash: input.signatureHash,
        summary: redact(input.summary),
        coveredFactIds: [...new Set(input.coveredFactIds)],
        coveredAssignmentIds: [...new Set(input.coveredAssignmentIds)],
        active: true,
        createdAt: Date.now(),
      }).returning().get()
      if (created.coveredFactIds.length) {
        this.db.update(tables.facts).set({ digestId: created.id }).where(and(
          eq(tables.facts.runId, runId), inArray(tables.facts.id, created.coveredFactIds),
        )).run()
        for (const fId of created.coveredFactIds) {
          this.addGraphEdge(runId, { fromKind: 'digest', fromId: created.id, toKind: 'fact', toId: fId, edgeKind: 'covers' })
        }
      }
      if (input.supersedeDigestIds?.length) {
        this.db.update(tables.graphDigests).set({ active: false }).where(and(
          eq(tables.graphDigests.runId, runId), inArray(tables.graphDigests.id, input.supersedeDigestIds),
        )).run()
      }
      return created
    }, { behavior: 'immediate' })
    this.event(runId, 'graph.compacted', `Created ${digest.level} digest covering ${digest.coveredFactIds.length} facts.`, {
      digestId: digest.id, level: digest.level, roundNo: digest.roundNo,
    })
    return digest
  }

  // --- Tier 3 Approval Requests ---

  createApprovalRequest(run: Run, assignment: Assignment, input: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    rationale: string
    requestPreview: string
    policyNote?: string | null
    riskLevel?: ApprovalRiskLevel | null
    expiresInMs?: number
    secrets?: readonly NamedSecret[]
  }): ApprovalRequest {
    const secrets = input.secrets ?? []
    const now = Date.now()
    const row = this.db.insert(tables.approvalRequests).values({
      id: randomUUID(),
      runId: run.id,
      assignmentId: assignment.id,
      scopeRevision: run.scopeRevision,
      origin: input.origin,
      method: input.method.toUpperCase(),
      pathAndQuery: redact(input.pathAndQuery, secrets),
      personaHandle: input.personaHandle ?? null,
      rationale: redact(input.rationale, secrets),
      requestPreview: redact(input.requestPreview, secrets),
      status: 'pending',
      decidedBy: null,
      decidedAt: null,
      policyNote: input.policyNote ? redact(input.policyNote, secrets) : null,
      riskLevel: input.riskLevel ?? null,
      expiresAt: now + (input.expiresInMs ?? 15 * 60_000),
      createdAt: now,
    }).returning().get()
    this.updateWorker(assignment.id, { status: 'waiting_approval' })
    this.event(run.id, 'approval.requested', `Tier 3 approval requested for ${row.method} ${row.origin}${row.pathAndQuery.slice(0, 80)}.`, {
      approvalId: row.id, assignmentId: assignment.id, origin: row.origin, method: row.method,
      riskLevel: row.riskLevel, policyNote: row.policyNote,
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Tier 3 approval required: ${row.method} ${row.origin}${row.pathAndQuery}\nRationale: ${row.rationale}`)
    return row
  }

  /**
   * Append an audit row for an automatic Tier-3 decision. These rows are deliberately NOT an
   * authorization source: the broker fast path only accepts an exact, single-use fingerprint from
   * the Execution ledger (see approval-judge.authorizeStateChange). `expiresAt` here only bounds
   * how long the audit row is considered recent for operator review; it never grants a later probe.
   */
  recordAutoApprovalDecision(run: Run, assignment: Assignment, input: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    rationale: string
    requestPreview: string
    decision: 'approved' | 'denied'
    decidedBy: Exclude<ApprovalDecidedBy, 'operator'>
    riskLevel: ApprovalRiskLevel
    policyNote: string
    expiresInMs?: number
    secrets?: readonly NamedSecret[]
  }): ApprovalRequest {
    const secrets = input.secrets ?? []
    const now = Date.now()
    const row = this.db.insert(tables.approvalRequests).values({
      id: randomUUID(),
      runId: run.id,
      assignmentId: assignment.id,
      scopeRevision: run.scopeRevision,
      origin: input.origin,
      method: input.method.toUpperCase(),
      pathAndQuery: redact(input.pathAndQuery, secrets),
      personaHandle: input.personaHandle ?? null,
      rationale: redact(input.rationale, secrets),
      requestPreview: redact(input.requestPreview, secrets),
      status: input.decision,
      decidedBy: input.decidedBy,
      decidedAt: now,
      policyNote: redact(input.policyNote, secrets),
      riskLevel: input.riskLevel,
      expiresAt: now + (input.expiresInMs ?? 15 * 60_000),
      createdAt: now,
    }).returning().get()
    const kind = input.decision === 'approved' ? 'approval.auto_approved' : 'approval.auto_denied'
    const verb = input.decision === 'approved' ? 'auto-approved' : 'auto-denied'
    this.event(run.id, kind, `Tier 3 probe ${verb} (${input.decidedBy}) for ${row.method} ${row.origin}${row.pathAndQuery.slice(0, 80)}.`, {
      approvalId: row.id,
      assignmentId: assignment.id,
      origin: row.origin,
      method: row.method,
      decidedBy: row.decidedBy,
      riskLevel: row.riskLevel,
      policyNote: row.policyNote,
    })
    return row
  }

  getApprovalRequest(runId: string, approvalId: string): ApprovalRequest {
    const row = this.db.select().from(tables.approvalRequests).where(and(
      eq(tables.approvalRequests.runId, runId), eq(tables.approvalRequests.id, approvalId),
    )).get()
    if (!row) throw new Error('Approval request not found.')
    return row
  }

  listApprovalRequests(runId: string, status?: ApprovalRequest['status']): ApprovalRequest[] {
    const where = status
      ? and(eq(tables.approvalRequests.runId, runId), eq(tables.approvalRequests.status, status))
      : eq(tables.approvalRequests.runId, runId)
    return this.db.select().from(tables.approvalRequests).where(where)
      .orderBy(desc(tables.approvalRequests.createdAt)).all()
  }

  // --- v6 durable route-scoped approval leases ---

  /**
   * Grant (or refresh) a durable, route-scoped lease. Unlike the single-use 60 s body-hash
   * fingerprint, a lease authorizes every probe iteration and independent replay on the normalized
   * route, until the run's scope revision changes or the origin leaves scope.
   */
  grantApprovalLease(run: Run, input: {
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    sourceApprovalId?: string | null
    createdBy?: string
    expiresInMs?: number | null
  }): ApprovalLeaseRow {
    const origin = normalizeScopeOrigin(input.origin)
    if (!origin) throw new Error('Approval lease origin is malformed.')
    const method = input.method.trim().toUpperCase()
    if (!method) throw new Error('Approval lease method is required.')
    const routePattern = routePatternForPath(input.pathAndQuery)
    const now = Date.now()
    const row = this.db.insert(tables.approvalLeases).values({
      id: randomUUID(),
      runId: run.id,
      scopeRevision: run.scopeRevision,
      origin,
      method,
      routePattern,
      personaHandle: input.personaHandle ?? null,
      status: 'active',
      sourceApprovalId: input.sourceApprovalId ?? null,
      createdBy: input.createdBy ?? 'operator',
      createdAt: now,
      updatedAt: now,
      expiresAt: input.expiresInMs === null || input.expiresInMs === undefined ? null : now + input.expiresInMs,
      uses: 0,
      lastUsedAt: null,
    }).onConflictDoUpdate({
      target: [
        tables.approvalLeases.runId, tables.approvalLeases.origin, tables.approvalLeases.method,
        tables.approvalLeases.routePattern, tables.approvalLeases.scopeRevision,
      ],
      set: {
        status: 'active',
        updatedAt: now,
        personaHandle: input.personaHandle ?? null,
        sourceApprovalId: input.sourceApprovalId ?? null,
        expiresAt: input.expiresInMs == null ? null : now + input.expiresInMs,
      },
    }).returning().get()
    this.event(run.id, 'approval.lease_granted', `Durable route lease for ${method} ${origin}${routePattern}.`, {
      leaseId: row.id, origin, method, routePattern, sourceApprovalId: row.sourceApprovalId,
    })
    return row
  }

  listApprovalLeases(runId: string, status?: ApprovalLeaseRow['status']): ApprovalLeaseRow[] {
    const where = status
      ? and(eq(tables.approvalLeases.runId, runId), eq(tables.approvalLeases.status, status))
      : eq(tables.approvalLeases.runId, runId)
    return this.db.select().from(tables.approvalLeases).where(where)
      .orderBy(desc(tables.approvalLeases.createdAt)).all()
  }

  revokeApprovalLease(run: Run, leaseId: string, reason = 'Revoked by operator.'): ApprovalLeaseRow {
    const updated = this.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() })
      .where(and(eq(tables.approvalLeases.runId, run.id), eq(tables.approvalLeases.id, leaseId)))
      .returning().get()
    if (!updated) throw new Error('Approval lease not found.')
    this.event(run.id, 'approval.lease_revoked', `Durable route lease revoked: ${updated.method} ${updated.origin}${updated.routePattern}.`, {
      leaseId: updated.id, origin: updated.origin, method: updated.method, reason,
    })
    return updated
  }

  revokeApprovalLeasesForOrigin(run: Run, origin: string): number {
    const normalized = normalizeScopeOrigin(origin)
    if (!normalized) return 0
    const revoked = this.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() })
      .where(and(
        eq(tables.approvalLeases.runId, run.id),
        eq(tables.approvalLeases.status, 'active'),
        eq(tables.approvalLeases.origin, normalized),
      )).returning({ id: tables.approvalLeases.id }).all()
    if (revoked.length) {
      this.event(run.id, 'approval.lease_revoked', `${revoked.length} durable lease(s) revoked for ${normalized}.`, {
        origin: normalized, leases: revoked.map(row => row.id),
      })
    }
    return revoked.length
  }

  /**
   * Broker-side lease check. A match authorizes the normalized route without a per-request
   * approval; the lease must belong to the run's current scope revision and be unexpired.
   */
  leaseAuthorizes(runId: string, origin: string, method: string, pathAndQuery: string): boolean {
    const normalized = normalizeScopeOrigin(origin)
    if (!normalized) return false
    let run: Run
    try {
      run = this.run(runId)
    } catch {
      return false
    }
    const routePattern = routePatternForPath(pathAndQuery)
    const row = this.db.select().from(tables.approvalLeases).where(and(
      eq(tables.approvalLeases.runId, runId),
      eq(tables.approvalLeases.origin, normalized),
      eq(tables.approvalLeases.method, method.trim().toUpperCase()),
      eq(tables.approvalLeases.routePattern, routePattern),
      eq(tables.approvalLeases.status, 'active'),
      eq(tables.approvalLeases.scopeRevision, run.scopeRevision),
    )).get()
    if (!row) return false
    if (row.expiresAt !== null && row.expiresAt <= Date.now()) {
      this.db.update(tables.approvalLeases).set({ status: 'expired', updatedAt: Date.now() })
        .where(eq(tables.approvalLeases.id, row.id)).run()
      return false
    }
    this.db.update(tables.approvalLeases).set({
      uses: row.uses + 1, lastUsedAt: Date.now(), updatedAt: Date.now(),
    }).where(eq(tables.approvalLeases.id, row.id)).run()
    return true
  }

  /** Ready-to-wire broker grant hook: `approvalLeases: storage.approvalLeaseAuthorizer(runId)`. */
  approvalLeaseAuthorizer(runId: string): (origin: string, method: string, pathAndQuery: string) => boolean {
    return (origin, method, pathAndQuery) => this.leaseAuthorizes(runId, origin, method, pathAndQuery)
  }

  /**
   * Park an assignment in `awaiting_approval` with its worker slot released. The caller persists
   * the approval request separately; this is the non-blocking half of the operator opt-in flow.
   */
  parkWorkerForApproval(run: Run, assignmentId: string): Assignment {
    const existing = this.worker(assignmentId)
    if (existing.runId !== run.id) throw new Error('Assignment does not belong to this run.')
    if (!['queued', 'running', 'waiting_approval'].includes(existing.status)) {
      throw new Error(`Cannot park an assignment in state ${existing.status}.`)
    }
    const updated = this.updateWorker(assignmentId, {
      status: 'waiting_approval',
      approvalParkedAt: Date.now(),
      lease: null,
      leaseExpiresAt: null,
    })!
    this.event(run.id, 'approval.worker_parked', `Worker parked awaiting approval; slot released.`, {
      assignmentId,
    })
    return updated
  }

  /** Resume a parked assignment with a fresh worker lease (caller re-enters the scheduler). */
  resumeParkedWorker(run: Run, assignmentId: string): Assignment {
    const existing = this.worker(assignmentId)
    if (existing.runId !== run.id) throw new Error('Assignment does not belong to this run.')
    if (existing.status !== 'waiting_approval') {
      throw new Error(`Assignment is not awaiting approval (state ${existing.status}).`)
    }
    const updated = this.updateWorker(assignmentId, {
      status: 'running',
      approvalParkedAt: null,
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    this.event(run.id, 'approval.worker_resumed', `Worker resumed with a fresh slot lease.`, {
      assignmentId, leaseExpiresAt: updated.leaseExpiresAt,
    })
    return updated
  }

  parkedWorkerCount(runId: string): number {
    const row = this.client.prepare(
      `SELECT count(*) AS c FROM assignments WHERE run_id = ? AND status = 'waiting_approval' AND approval_parked_at IS NOT NULL AND lease IS NULL`,
    ).get(runId) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  }

  decideApproval(run: Run, approvalId: string, decision: 'approved' | 'denied'): ApprovalRequest {
    const existing = this.getApprovalRequest(run.id, approvalId)
    if (existing.status !== 'pending') throw new Error(`Approval request is already ${existing.status}.`)
    if (existing.scopeRevision !== run.scopeRevision) {
      this.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: Date.now() })
        .where(eq(tables.approvalRequests.id, approvalId)).run()
      throw new Error('Scope changed before this approval could be decided.')
    }
    const updated = this.db.update(tables.approvalRequests).set({
      status: decision,
      decidedBy: 'operator',
      decidedAt: Date.now(),
    }).where(eq(tables.approvalRequests.id, approvalId)).returning().get()!
    this.event(run.id, 'approval.decided', `Tier 3 request ${decision} for ${updated.method} ${updated.origin}.`, {
      approvalId: updated.id, assignmentId: updated.assignmentId, decision, decidedBy: 'operator',
    })
    if (decision === 'approved') {
      // Operator opt-in grants a durable route-scoped lease, not a 60 s single-use body-hash token.
      this.grantApprovalLease(run, {
        origin: updated.origin,
        method: updated.method,
        pathAndQuery: updated.pathAndQuery,
        personaHandle: updated.personaHandle,
        sourceApprovalId: updated.id,
        createdBy: 'operator',
      })
    }
    this.message(run.id, run.coordinatorId, 'guardian',
      `Tier 3 request ${decision}: ${updated.method} ${updated.origin}${updated.pathAndQuery}`)
    return updated
  }

  setApprovalPolicy(run: Run, approvalPolicy: ApprovalPolicy) {
    if (['complete', 'stopped', 'failed'].includes(run.status)) {
      throw new Error('Cannot change approval policy after a run has ended.')
    }
    const previous = run.approvalPolicy ?? 'auto_review'
    this.updateRun(run.id, { approvalPolicy })
    let autoApprovedCount = 0
    if (approvalPolicy === 'yolo') {
      const now = Date.now()
      const pending = this.listApprovalRequests(run.id, 'pending')
      for (const req of pending) {
        if (req.scopeRevision !== run.scopeRevision) {
          this.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: now })
            .where(eq(tables.approvalRequests.id, req.id)).run()
          continue
        }
        this.db.update(tables.approvalRequests).set({
          status: 'approved',
          decidedBy: 'auto-yolo',
          decidedAt: now,
          riskLevel: 'low',
          policyNote: 'Auto-approved when operator switched Tier 3 policy to YOLO autonomous mode.',
        }).where(eq(tables.approvalRequests.id, req.id)).run()
        autoApprovedCount += 1
        this.event(run.id, 'approval.auto_approved', `Auto-approved ${req.method} ${req.origin}${req.pathAndQuery.slice(0, 80)} via YOLO policy switch.`, {
          approvalId: req.id, assignmentId: req.assignmentId, decidedBy: 'auto-yolo',
        })
      }
    }
    this.event(run.id, 'approval.policy_changed', `Tier 3 approval policy switched from ${previous} to ${approvalPolicy}.`, {
      previous, approvalPolicy, autoApprovedCount,
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Tier 3 approval policy updated to ${approvalPolicy}${autoApprovedCount > 0 ? ` (${autoApprovedCount} pending ${autoApprovedCount === 1 ? 'request' : 'requests'} auto-approved)` : ''}.`)
  }

  approveSimilarEndpoint(run: Run, approvalId: string) {
    const existing = this.getApprovalRequest(run.id, approvalId)
    const now = Date.now()
    if (existing.status === 'pending') {
      if (existing.scopeRevision !== run.scopeRevision) {
        this.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: now })
          .where(eq(tables.approvalRequests.id, approvalId)).run()
        throw new Error('Scope changed before this approval could be decided.')
      }
      this.db.update(tables.approvalRequests).set({
        status: 'approved',
        decidedBy: 'operator',
        decidedAt: now,
        policyNote: 'Approved by operator with similar endpoint pattern.',
      }).where(eq(tables.approvalRequests.id, approvalId)).run()
    } else if (existing.status !== 'approved') {
      throw new Error(`Approval request is already ${existing.status}.`)
    }

    const pathPattern = normalizeApprovalPathPattern(existing.pathAndQuery)
    const newPattern: ApprovedEndpointPattern = {
      origin: existing.origin,
      method: existing.method.toUpperCase(),
      pathPattern,
      scopeRevision: run.scopeRevision,
      createdAt: now,
    }
    const currentPatterns = run.approvedEndpointPatterns ?? []
    const alreadyStored = currentPatterns.some(p =>
      p.origin === newPattern.origin &&
      p.method.toUpperCase() === newPattern.method &&
      p.pathPattern === newPattern.pathPattern &&
      p.scopeRevision === newPattern.scopeRevision,
    )
    const nextPatterns = alreadyStored ? currentPatterns : [...currentPatterns, newPattern]
    if (!alreadyStored) {
      this.updateRun(run.id, { approvedEndpointPatterns: nextPatterns })
    }

    // Also approve any other pending requests matching this exact newly approved pattern
    let matchedPendingCount = 0
    for (const req of this.listApprovalRequests(run.id, 'pending')) {
      if (req.id === approvalId || req.scopeRevision !== run.scopeRevision) continue
      if (matchesApprovedEndpointPattern({ origin: req.origin, method: req.method, pathAndQuery: req.pathAndQuery }, [newPattern])) {
        this.db.update(tables.approvalRequests).set({
          status: 'approved',
          decidedBy: 'auto-review:rule',
          decidedAt: now,
          riskLevel: 'low',
          policyNote: `Auto-approved via operator-approved pattern ${newPattern.method} ${newPattern.pathPattern}.`,
        }).where(eq(tables.approvalRequests.id, req.id)).run()
        matchedPendingCount += 1
      }
    }

    this.event(run.id, 'approval.pattern_approved', `Approved similar probes matching ${newPattern.method} ${newPattern.origin}${newPattern.pathPattern}.`, {
      approvalId: existing.id,
      origin: newPattern.origin,
      method: newPattern.method,
      pathPattern: newPattern.pathPattern,
      matchedPendingCount,
    })
    this.grantApprovalLease(run, {
      origin: newPattern.origin,
      method: newPattern.method,
      pathAndQuery: newPattern.pathPattern,
      personaHandle: existing.personaHandle,
      sourceApprovalId: existing.id,
      createdBy: 'operator',
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Approved ${existing.method} ${existing.origin}${existing.pathAndQuery} and future probes matching ${newPattern.method} ${newPattern.pathPattern}.`)
  }

  approveAllPending(run: Run): number {
    const now = Date.now()
    const pending = this.listApprovalRequests(run.id, 'pending')
    let approvedCount = 0
    for (const req of pending) {
      if (req.scopeRevision !== run.scopeRevision) {
        this.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: now })
          .where(eq(tables.approvalRequests.id, req.id)).run()
        continue
      }
      this.db.update(tables.approvalRequests).set({
        status: 'approved',
        decidedBy: 'operator',
        decidedAt: now,
        policyNote: 'Batch-approved by operator (Approve all pending).',
      }).where(eq(tables.approvalRequests.id, req.id)).run()
      this.grantApprovalLease(run, {
        origin: req.origin,
        method: req.method,
        pathAndQuery: req.pathAndQuery,
        personaHandle: req.personaHandle,
        sourceApprovalId: req.id,
        createdBy: 'operator',
      })
      approvedCount += 1
    }
    this.event(run.id, 'approval.batch_approved', `Operator batch-approved ${approvedCount} pending Tier 3 ${approvedCount === 1 ? 'request' : 'requests'}.`, {
      approvedCount,
    })
    if (approvedCount > 0) {
      this.message(run.id, run.coordinatorId, 'guardian',
        `Batch-approved ${approvedCount} pending Tier 3 ${approvedCount === 1 ? 'probe' : 'probes'}.`)
    }
    return approvedCount
  }

  // --- Replay Specs, Retests, Coverage, Findings ---

  createReplaySpec(
    run: Run,
    assignment: Assignment,
    findingId: string,
    spec: DeclarativeReplaySpec,
    sourceOrigins: string[],
    options?: {
      initialAttemptCount?: number
      verifiedInline?: boolean
      lastVerificationDiff?: InlineVerifyFeedback | null
      proof?: AgentScriptProofRecord | null
    },
  ): ReplaySpecRow {
    const specSha256 = createHash('sha256').update(JSON.stringify(spec)).digest('hex')
    return this.db.insert(tables.replaySpecs).values({
      id: randomUUID(),
      runId: run.id,
      findingId,
      assignmentId: assignment.id,
      scopeRevision: run.scopeRevision,
      goalRevision: assignment.goalRevision,
      spec,
      specSha256,
      sourceOrigins: [...new Set(sourceOrigins)],
      attemptCount: options?.initialAttemptCount ?? 1,
      verifiedInline: options?.verifiedInline ?? false,
      lastVerificationDiff: options?.lastVerificationDiff ?? null,
      ...proofColumns(options?.proof),
      createdAt: Date.now(),
    }).returning().get()
  }

  /** Persist (or replace) the agent-script proof attached to a replay spec row. */
  setReplaySpecProof(runId: string, replaySpecId: string, proof: AgentScriptProofRecord): ReplaySpecRow {
    const row = this.db.update(tables.replaySpecs)
      .set(proofColumns(proof))
      .where(and(eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId)))
      .returning().get()
    if (!row) throw new Error('Replay spec not found.')
    return row
  }

  /** Proof columns for a row (or null when the row is not a script proof). */
  replaySpecProof(runId: string, replaySpecId: string): AgentScriptProofRecord | null {
    const row = this.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
    )).get()
    return row ? proofRecordOf(row) : null
  }

  /** Latest script proof attached to any spec row of a finding (null when none). */
  agentProofForFinding(runId: string, findingId: string): AgentScriptProofRecord | null {
    const rows = this.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.findingId, findingId),
    )).orderBy(desc(tables.replaySpecs.createdAt)).all()
    for (const row of rows) {
      const proof = proofRecordOf(row)
      if (proof) return proof
    }
    return null
  }

  getReplaySpec(runId: string, replaySpecId: string): ReplaySpecRow {
    const row = this.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
    )).get()
    if (!row) throw new Error('Replay spec not found.')
    return row
  }

  listReplaySpecs(runId: string): ReplaySpecRow[] {
    return this.db.select().from(tables.replaySpecs).where(eq(tables.replaySpecs.runId, runId))
      .orderBy(desc(tables.replaySpecs.createdAt)).all()
  }

  listReplaySpecsForFinding(runId: string, findingId: string): ReplaySpecRow[] {
    return this.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.findingId, findingId),
    )).orderBy(desc(tables.replaySpecs.createdAt)).all()
  }

  /** How many confirmed claims this run demoted after their persisted evidence stopped confirming. */
  confirmationConflictCount(runId: string): number {
    const row = this.db.select({ count: sql<number>`count(*)` }).from(tables.events).where(and(
      eq(tables.events.runId, runId), eq(tables.events.kind, 'finding.confirmation_conflict'),
    )).get()
    return Number(row?.count ?? 0)
  }

  /**
   * Resolve the persisted proof that backs a runtime claim. A `confirmed` finding is only valid when
   * one of these holds: its linked replay spec's persisted diff verdict is `confirmed`; a verified
   * OOB ProofReceipt promoted it; or (legacy floor rows only, before spec diffs were persisted) the
   * deterministic-engine confirmation event exists and no later spec verdict contradicts it.
   * Baseline checks are evidenced by their coverage review, not a replay spec.
   */
  private confirmationEvidenceFor(runId: string, input: {
    findingId: string
    replaySpecId?: string | null
    verification?: string
    findingKind?: Finding['findingKind']
    verificationTier?: VerificationTier | null
    provenance?: FindingProvenance | null
  }): ConfirmationEvidence {
    const replaySpecId = input.replaySpecId ?? null
    if (input.findingKind === 'baseline_check' || input.verificationTier === 'baseline_confirmed') {
      return { backed: true, contradicted: false, kind: 'baseline', verdict: 'baseline_confirmed', replaySpecId }
    }
    const spec = replaySpecId
      ? this.db.select().from(tables.replaySpecs).where(and(
          eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
        )).get()
      : undefined
    const verdict = spec?.lastVerificationDiff?.verdict ?? null
    if (replayVerdictConfirmsRuntime(verdict)) {
      return { backed: true, contradicted: false, kind: 'spec', verdict, replaySpecId }
    }
    const receipt = typeof input.verification === 'string' && input.verification.startsWith('ProofReceipt')
      ? true
      : Boolean(this.db.select({ id: tables.events.id }).from(tables.events).where(and(
          eq(tables.events.runId, runId),
          eq(tables.events.kind, 'oob.receipt_confirmed'),
          sql`json_extract(${tables.events.detail}, '$.findingId') = ${input.findingId}`,
        )).get())
    if (receipt) return { backed: true, contradicted: false, kind: 'receipt', verdict, replaySpecId }
    // Legacy floor confirmations predate persisted spec diffs: their deterministic-engine event (or
    // the floor's own in-flight confirmation write) is the anchor. An explicit non-confirming diff
    // still wins (it is the later, contradicting write).
    if (verdict === null) {
      if (input.provenance === 'floor') {
        return { backed: true, contradicted: false, kind: 'floor_artifact', verdict: null, replaySpecId }
      }
      const floorEvent = this.db.select({ id: tables.events.id }).from(tables.events).where(and(
        eq(tables.events.runId, runId),
        eq(tables.events.kind, 'deterministic_engine.confirmed'),
        sql`json_extract(${tables.events.detail}, '$.findingId') = ${input.findingId}`,
      )).get()
      if (floorEvent) return { backed: true, contradicted: false, kind: 'floor_artifact', verdict: null, replaySpecId }
    }
    // An explicit non-confirming verdict is a contradiction. A missing verdict/spec is unknown
    // (legacy rows and fixtures), not a conflict: there is nothing to contradict.
    return { backed: false, contradicted: verdict !== null, kind: 'none', verdict, replaySpecId }
  }

  /**
   * Hard write gate: a confirmed finding may only be persisted when its own persisted evidence is
   * confirming (linked spec diff `confirmed`, a verified ProofReceipt, or a baseline review).
   * Throws `InvariantError('invariant.confirmation_evidence')` otherwise, so an inconclusive result
   * can never structurally persist as confirmed.
   */
  assertConfirmationEvidence(runId: string, input: {
    findingId: string
    replaySpecId?: string | null
    verification?: string
    findingKind?: Finding['findingKind']
    verificationTier?: VerificationTier | null
    provenance?: FindingProvenance | null
  }): ConfirmationEvidence {
    const evidence = this.confirmationEvidenceFor(runId, input)
    if (!evidence.backed) {
      throw new InvariantError(
        'invariant.confirmation_evidence',
        `Invariant: a confirmed finding requires confirming persisted evidence `
          + `(linked spec diff 'confirmed' or a verified ProofReceipt); got `
          + `${evidence.kind} verdict '${evidence.verdict ?? 'none'}' for ${input.findingId}.`,
      )
    }
    return evidence
  }

  /**
   * Precision-integrity invariant: a finding may only be persisted `runtime_confirmed` while its
   * own persisted evidence satisfies the oracle. When a later verdict downgrades that evidence the
   * finding is demoted to `open_proof_gap`/`inconclusive`, a loud `finding.confirmation_conflict`
   * event is emitted, and the per-run conflict counter is incremented. Never leaves a confirmed
   * claim whose persisted diff says otherwise.
   */
  enforceConfirmationEvidence(runId: string, findingId: string, cause: string): boolean {
    const row = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, runId), eq(tables.findings.id, findingId),
    )).get()
    if (!row) return false
    if (row.verificationClass !== 'runtime_confirmed' || row.finding.status !== 'confirmed') return false
    const evidence = this.confirmationEvidenceFor(runId, {
      findingId: row.id,
      replaySpecId: row.replaySpecId,
      verification: row.finding.verification,
      findingKind: row.findingKind,
      verificationTier: row.finding.verificationTier ?? row.verificationTier,
      provenance: row.provenance,
    })
    if (evidence.backed || !evidence.contradicted) return false
    const conflicts = this.confirmationConflictCount(runId) + 1
    const demoted: Finding = {
      ...row.finding,
      status: 'inconclusive',
      verificationTier: undefined,
      confidence: 'low',
      reason: `Confirmation conflict: ${cause}; the persisted evidence no longer satisfies the `
        + `${row.finding.category ?? 'claimed'} oracle (${evidence.kind}: ${evidence.verdict ?? 'no verdict'}).`
        + (row.finding.reason ? ` Prior: ${row.finding.reason}` : ''),
    }
    this.transaction(() => {
      this.db.update(tables.findings).set({
        verificationClass: 'open_proof_gap',
        verificationTier: null,
        finding: demoted,
      }).where(and(eq(tables.findings.runId, runId), eq(tables.findings.id, findingId))).run()
      this.event(
        runId,
        'finding.confirmation_conflict',
        `Demoted confirmed finding "${row.finding.title.slice(0, 160)}" (${row.id}): ${cause}; `
          + `persisted evidence is ${evidence.kind} (${evidence.verdict ?? 'no verdict'}).`,
        {
          findingId: row.id,
          previousStatus: 'confirmed',
          previousVerificationClass: 'runtime_confirmed',
          replaySpecId: evidence.replaySpecId,
          evidenceKind: evidence.kind,
          evidenceVerdict: evidence.verdict,
          provenance: row.provenance,
          cause,
          conflictsForRun: conflicts,
        },
      )
    }, { behavior: 'immediate' })
    return true
  }

  incrementReplaySpecAttempt(
    id: string,
    feedback: InlineVerifyFeedback,
    updated?: {
      spec?: DeclarativeReplaySpec
      sourceOrigins?: string[]
      secrets?: readonly NamedSecret[]
    },
  ): ReplaySpecRow {
    const secrets = updated?.secrets ?? []
    const cleanFeedback = redactJsonValue(feedback, secrets)
    return this.transaction(() => {
      const existing = this.db.select().from(tables.replaySpecs).where(eq(tables.replaySpecs.id, id)).get()
      if (!existing) throw new Error('Replay spec not found.')
      const verified = existing.verifiedInline ||
        cleanFeedback.verdict === 'confirmed' ||
        cleanFeedback.verdict === 'static_verified'
      const specPatch = updated?.spec && !existing.verifiedInline
        ? {
            spec: updated.spec,
            specSha256: createHash('sha256').update(JSON.stringify(updated.spec)).digest('hex'),
            ...(updated.sourceOrigins ? { sourceOrigins: [...new Set(updated.sourceOrigins)] } : {}),
          }
        : {}
      const row = this.db.update(tables.replaySpecs).set({
        attemptCount: sql`${tables.replaySpecs.attemptCount} + 1`,
        verifiedInline: verified,
        lastVerificationDiff: cleanFeedback,
        ...specPatch,
      }).where(eq(tables.replaySpecs.id, id)).returning().get()!
      // A retry that no longer confirms must not leave the finding's confirmed claim backed by a
      // non-confirming diff. Demote (and count) instead of silently keeping the old status.
      if (cleanFeedback.verdict !== 'confirmed') {
        this.enforceConfirmationEvidence(
          existing.runId,
          existing.findingId,
          `replay spec attempt ${row.attemptCount} returned ${cleanFeedback.verdict}`,
        )
      }
      return row
    }, { behavior: 'immediate' })
  }

  /**
   * Persist a verification diff on an existing spec (Phase-3 retest path). Shares the confirmation
   * invariant with `incrementReplaySpecAttempt`: a non-confirming write demotes a confirmed claim.
   */
  recordReplaySpecVerification(
    runId: string,
    replaySpecId: string,
    feedback: InlineVerifyFeedback,
    cause: string,
  ): ReplaySpecRow {
    return this.transaction(() => {
      const row = this.db.update(tables.replaySpecs).set({ lastVerificationDiff: feedback }).where(and(
        eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
      )).returning().get()
      if (!row) throw new Error('Replay spec not found.')
      if (feedback.verdict !== 'confirmed') {
        this.enforceConfirmationEvidence(runId, row.findingId, cause)
      }
      return row
    }, { behavior: 'immediate' })
  }

  recordRetestRun(
    run: Run,
    findingId: string,
    replaySpecId: string,
    verdict: 'reproduced' | 'fixed' | 'inconclusive',
    summary: string,
    evidenceIds: string[],
    exchangeIds: string[],
  ): RetestRun {
    const row = this.db.insert(tables.retestRuns).values({
      id: randomUUID(),
      projectId: run.projectId,
      runId: run.id,
      findingId,
      replaySpecId,
      scopeRevision: run.scopeRevision,
      verdict,
      summary: redact(summary),
      evidenceIds: [...new Set(evidenceIds)],
      exchangeIds: [...new Set(exchangeIds)],
      createdAt: Date.now(),
    }).returning().get()
    this.event(run.id, 'retest.complete', `Verify Fix retest verdict: ${verdict}.`, {
      retestId: row.id, findingId, replaySpecId, verdict,
    })
    return row
  }

  // --- v3 SAST Runs, Surface Probes, Patch Proposals, Open Proof Gaps ---

  recordSastRun(input: {
    runId: string
    assignmentId: string
    repo: string
    engine: string
    rawArtifactId?: string | null
    findingCount: number
    durationMs: number
  }): SastRun {
    const row = this.db.insert(tables.sastRuns).values({
      id: randomUUID(),
      runId: input.runId,
      assignmentId: input.assignmentId,
      repo: redact(input.repo.slice(0, 200)),
      engine: input.engine.slice(0, 64),
      rawArtifactId: input.rawArtifactId ?? null,
      findingCount: Math.max(0, Math.round(input.findingCount)),
      durationMs: Math.max(0, Math.round(input.durationMs)),
      createdAt: Date.now(),
    }).returning().get()
    this.event(input.runId, 'sast.run', `SAST (${row.engine}) on ${row.repo}: ${row.findingCount} findings (${row.durationMs}ms).`, {
      sastRunId: row.id,
      assignmentId: row.assignmentId,
      repo: row.repo,
      engine: row.engine,
      findingCount: row.findingCount,
      rawArtifactId: row.rawArtifactId,
    })
    return row
  }

  listSastRuns(runId: string): SastRun[] {
    return this.db.select().from(tables.sastRuns).where(eq(tables.sastRuns.runId, runId))
      .orderBy(desc(tables.sastRuns.createdAt)).all()
  }

  recordSurfaceProbe(input: {
    runId: string
    assignmentId: string
    scopeRevision: number
    origin: string
    probeKind: string
    requestsSent: number
    anomaliesFound: number
    baselineSignature?: string | null
  }): SurfaceProbe {
    const row = this.db.insert(tables.surfaceProbes).values({
      id: randomUUID(),
      runId: input.runId,
      assignmentId: input.assignmentId,
      scopeRevision: input.scopeRevision,
      origin: input.origin,
      probeKind: input.probeKind.slice(0, 64),
      requestsSent: Math.max(0, Math.round(input.requestsSent)),
      anomaliesFound: Math.max(0, Math.round(input.anomaliesFound)),
      baselineSignature: input.baselineSignature ? redact(input.baselineSignature.slice(0, 500)) : null,
      createdAt: Date.now(),
    }).returning().get()
    this.event(input.runId, 'surface.probe', `Surface probe (${row.probeKind}) on ${row.origin}: ${row.requestsSent} reqs, ${row.anomaliesFound} anomalies.`, {
      surfaceProbeId: row.id,
      assignmentId: row.assignmentId,
      origin: row.origin,
      probeKind: row.probeKind,
      requestsSent: row.requestsSent,
      anomaliesFound: row.anomaliesFound,
    })
    return row
  }

  listSurfaceProbes(runId: string): SurfaceProbe[] {
    return this.db.select().from(tables.surfaceProbes).where(eq(tables.surfaceProbes.runId, runId))
      .orderBy(desc(tables.surfaceProbes.createdAt)).all()
  }

  savePatchProposal(input: {
    id?: string
    runId: string
    findingId: string
    repo: string
    status: PatchProposalStatus
    callerCompatibility: CallerCompatibility
    diff: string
    codeLocations: CodeLocation[]
    reviewNotes: string
    dynamicRetestVerdict?: DynamicRetestVerdict
    secrets?: readonly NamedSecret[]
  }): PatchProposal {
    const now = Date.now()
    const secrets = input.secrets ?? []
    const cleanDiff = redact(input.diff, secrets)
    const cleanNotes = redact(input.reviewNotes, secrets)
    const cleanLocations = input.codeLocations.map(loc => ({
      ...loc,
      ...(loc.snippet ? { snippet: redact(loc.snippet, secrets) } : {}),
      ...(loc.label ? { label: redact(loc.label, secrets) } : {}),
    }))

    const existing = input.id
      ? this.db.select().from(tables.patchProposals).where(and(
          eq(tables.patchProposals.runId, input.runId), eq(tables.patchProposals.id, input.id),
        )).get()
      : undefined

    const saved = existing
      ? this.db.update(tables.patchProposals).set({
          status: input.status,
          callerCompatibility: input.callerCompatibility,
          diff: cleanDiff,
          codeLocations: cleanLocations,
          reviewNotes: cleanNotes,
          dynamicRetestVerdict: input.dynamicRetestVerdict ?? existing.dynamicRetestVerdict,
          updatedAt: now,
        }).where(eq(tables.patchProposals.id, existing.id)).returning().get()!
      : this.db.insert(tables.patchProposals).values({
          id: input.id ?? randomUUID(),
          runId: input.runId,
          findingId: input.findingId,
          repo: redact(input.repo.slice(0, 200)),
          status: input.status,
          callerCompatibility: input.callerCompatibility,
          diff: cleanDiff,
          codeLocations: cleanLocations,
          reviewNotes: cleanNotes,
          dynamicRetestVerdict: input.dynamicRetestVerdict ?? 'skipped',
          createdAt: now,
          updatedAt: now,
        }).returning().get()

    this.event(input.runId, 'patch.saved', `Patch proposal [${saved.status}] for finding ${saved.findingId} (${saved.callerCompatibility}).`, {
      patchId: saved.id,
      findingId: saved.findingId,
      repo: saved.repo,
      status: saved.status,
      callerCompatibility: saved.callerCompatibility,
      dynamicRetestVerdict: saved.dynamicRetestVerdict,
    })
    return saved
  }

  listPatchProposals(runId: string, findingId?: string): PatchProposal[] {
    const where = findingId
      ? and(eq(tables.patchProposals.runId, runId), eq(tables.patchProposals.findingId, findingId))
      : eq(tables.patchProposals.runId, runId)
    return this.db.select().from(tables.patchProposals).where(where)
      .orderBy(desc(tables.patchProposals.updatedAt)).all()
  }

  getPatchProposal(runId: string, patchId: string): PatchProposal {
    const row = this.db.select().from(tables.patchProposals).where(and(
      eq(tables.patchProposals.runId, runId), eq(tables.patchProposals.id, patchId),
    )).get()
    if (!row) throw new Error('Patch proposal not found.')
    return row
  }

  listOpenProofGaps(runId: string, goalRevision?: number): CoverageEntry[] {
    const where = goalRevision !== undefined
      ? and(
          eq(tables.coverageEntries.runId, runId),
          eq(tables.coverageEntries.goalRevision, goalRevision),
          eq(tables.coverageEntries.status, 'needs_follow_up'),
        )
      : and(
          eq(tables.coverageEntries.runId, runId),
          eq(tables.coverageEntries.status, 'needs_follow_up'),
        )
    return this.db.select().from(tables.coverageEntries).where(where)
      .orderBy(asc(tables.coverageEntries.origin), asc(tables.coverageEntries.category)).all()
  }

  updateProposedFinding(
    run: Run,
    findingId: string,
    patch: {
      finding?: Partial<Finding>
      replaySpecId?: string
      sourceOrigins?: string[]
      verificationTier?: VerificationTier | null
      fingerprintHash?: string | null
      supersededByFindingId?: string | null
      counterevidence?: string | null
      confidenceRationale?: string | null
      severityChangeConditions?: string | null
      codeLocations?: CodeLocation[] | null
      parentFindingIds?: string[] | null
      verificationClass?: FindingVerificationClass
    },
  ): Finding {
    const existing = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, run.id), eq(tables.findings.id, findingId),
    )).get()
    if (!existing) throw new Error('Finding not found.')

    // Floor-confirmed rows are immutable: later agent passes may add evidence elsewhere but can
    // never overwrite, downgrade or reclassify the floor's own confirmation.
    if (existing.provenance === 'floor') {
      this.event(
        run.id,
        'finding.floor_preserved',
        `Rejected update of floor-confirmed finding "${existing.finding.title}" (${existing.id}); floor rows are immutable.`,
        { findingId: existing.id, provenance: 'floor' },
      )
      return existing.finding
    }

    const mergedFinding: Finding = {
      ...existing.finding,
      ...(patch.finding ?? {}),
      id: existing.id,
      ...(patch.replaySpecId !== undefined ? { replaySpecId: patch.replaySpecId } : {}),
      ...(patch.verificationTier !== undefined ? { verificationTier: patch.verificationTier ?? undefined } : {}),
      ...(patch.fingerprintHash !== undefined ? { fingerprintHash: patch.fingerprintHash } : {}),
      ...(patch.supersededByFindingId !== undefined ? { supersededByFindingId: patch.supersededByFindingId } : {}),
      ...(patch.counterevidence !== undefined ? { counterevidence: patch.counterevidence } : {}),
      ...(patch.confidenceRationale !== undefined ? { confidenceRationale: patch.confidenceRationale } : {}),
      ...(patch.severityChangeConditions !== undefined ? { severityChangeConditions: patch.severityChangeConditions } : {}),
      ...(patch.codeLocations !== undefined ? { codeLocations: patch.codeLocations ?? undefined } : {}),
      evidenceIds: [...new Set([...existing.finding.evidenceIds, ...(patch.finding?.evidenceIds ?? [])])],
      exchangeIds: [...new Set([...(existing.finding.exchangeIds ?? []), ...(patch.finding?.exchangeIds ?? [])])],
      chainFactIds: [...new Set([...(existing.finding.chainFactIds ?? []), ...(patch.finding?.chainFactIds ?? [])])],
      scopeRevision: Math.max(existing.finding.scopeRevision, run.scopeRevision),
    }

    const cleanOrigins = [...new Set([
      ...existing.sourceOrigins,
      ...(patch.sourceOrigins ?? []),
      ...(mergedFinding.origin ? [mergedFinding.origin] : []),
    ])]

    const parentFindingIds = patch.parentFindingIds !== undefined
      ? (patch.parentFindingIds ? [...new Set(patch.parentFindingIds)] : null)
      : existing.parentFindingIds
    if (mergedFinding.status === 'confirmed' && mergedFinding.verificationTier === 'static_verified') {
      mergedFinding.verificationTier = 'runtime_confirmed'
    }
    const verificationClass = verificationClassForFinding(mergedFinding, patch.verificationClass)
    assertConfirmedVerificationClass(mergedFinding.status, verificationClass)
    if (mergedFinding.status === 'confirmed') {
      this.assertConfirmationEvidence(run.id, {
        findingId: existing.id,
        replaySpecId: patch.replaySpecId ?? existing.replaySpecId,
        verification: mergedFinding.verification,
        findingKind: existing.findingKind,
        verificationTier: mergedFinding.verificationTier ?? existing.verificationTier,
        provenance: existing.provenance,
      })
    }
    const persistedFinding = {
      ...mergedFinding,
      provenance: existing.provenance,
      ...(parentFindingIds?.length ? { parentFindingIds } : {}),
      verificationStatus: verificationClass,
    } as Finding

    this.db.update(tables.findings).set({
      replaySpecId: patch.replaySpecId ?? existing.replaySpecId,
      sourceOrigins: cleanOrigins,
      verificationTier: patch.verificationTier !== undefined ? patch.verificationTier : (mergedFinding.verificationTier ?? existing.verificationTier),
      fingerprintHash: patch.fingerprintHash !== undefined ? patch.fingerprintHash : (mergedFinding.fingerprintHash ?? existing.fingerprintHash),
      supersededByFindingId: patch.supersededByFindingId !== undefined ? patch.supersededByFindingId : (mergedFinding.supersededByFindingId ?? existing.supersededByFindingId),
      counterevidence: patch.counterevidence !== undefined ? patch.counterevidence : (mergedFinding.counterevidence ?? existing.counterevidence),
      confidenceRationale: patch.confidenceRationale !== undefined ? patch.confidenceRationale : (mergedFinding.confidenceRationale ?? existing.confidenceRationale),
      severityChangeConditions: patch.severityChangeConditions !== undefined ? patch.severityChangeConditions : (mergedFinding.severityChangeConditions ?? existing.severityChangeConditions),
      codeLocations: patch.codeLocations !== undefined ? patch.codeLocations : (mergedFinding.codeLocations ?? existing.codeLocations),
      parentFindingIds: parentFindingIds?.length ? parentFindingIds : null,
      verificationClass,
      finding: persistedFinding,
    }).where(eq(tables.findings.id, existing.id)).run()

    this.event(run.id, 'finding.updated', `Updated finding "${mergedFinding.title}" (${mergedFinding.status}).`, {
      findingId: mergedFinding.id,
      status: mergedFinding.status,
      severity: mergedFinding.severity,
      verificationTier: mergedFinding.verificationTier ?? null,
      verificationClass,
    })
    return persistedFinding
  }

  upsertCoverageEntry(run: Run, assignmentId: string, input: {
    origin: string
    category: OwaspCategory
    status: CoverageEntry['status']
    summary: string
    enforcingControl?: string | null
    proofGapReason?: string | null
    linkedFindingId?: string | null
  }): CoverageEntry {
    const now = Date.now()
    const cleanControl = input.enforcingControl?.trim() ? redact(input.enforcingControl.trim().slice(0, 600)) : null
    const cleanGapReason = input.proofGapReason?.trim() ? redact(input.proofGapReason.trim().slice(0, 600)) : null
    const linkedFindingId = input.linkedFindingId?.trim() || null
    const existing = this.db.select().from(tables.coverageEntries).where(and(
      eq(tables.coverageEntries.runId, run.id),
      eq(tables.coverageEntries.goalRevision, run.goalRevision),
      eq(tables.coverageEntries.origin, input.origin),
      eq(tables.coverageEntries.category, input.category),
    )).get()
    if (existing) {
      return this.db.update(tables.coverageEntries).set({
        scopeRevision: run.scopeRevision,
        status: input.status,
        summary: redact(input.summary.slice(0, 600)),
        enforcingControl: cleanControl ?? (input.status === 'ruled_out' ? existing.enforcingControl : null),
        proofGapReason: cleanGapReason ?? (input.status === 'needs_follow_up' ? existing.proofGapReason : null),
        linkedFindingId: linkedFindingId ?? (input.status === 'reported' ? existing.linkedFindingId : null),
        assignmentId,
        updatedAt: now,
      }).where(eq(tables.coverageEntries.id, existing.id)).returning().get()!
    }
    return this.db.insert(tables.coverageEntries).values({
      id: randomUUID(),
      runId: run.id,
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      origin: input.origin,
      category: input.category,
      status: input.status,
      summary: redact(input.summary.slice(0, 600)),
      enforcingControl: cleanControl,
      proofGapReason: cleanGapReason,
      linkedFindingId,
      assignmentId,
      updatedAt: now,
    }).returning().get()
  }

  listCoverageEntries(runId: string, goalRevision?: number): CoverageEntry[] {
    const where = goalRevision !== undefined
      ? and(eq(tables.coverageEntries.runId, runId), eq(tables.coverageEntries.goalRevision, goalRevision))
      : eq(tables.coverageEntries.runId, runId)
    return this.db.select().from(tables.coverageEntries).where(where)
      .orderBy(asc(tables.coverageEntries.origin), asc(tables.coverageEntries.category)).all()
  }

  findDuplicateChainFinding(
    runId: string,
    goalRevision: number,
    candidate: Pick<Finding, 'origin' | 'cwe' | 'category' | 'title' | 'fingerprintHash'> & {
      endpoint?: string | null
      method?: string | null
      param?: string | null
      graphqlField?: string | null
    },
    excludeId?: string,
  ) {
    const originWide = isOriginWideCwe(candidate.cwe, candidate.category)
    const legacyKey = chainFindingDedupKey(candidate)
    // Prefer the structural fingerprint: (origin, endpoint, method, param/resolver, cwe). Two BOLA
    // routes, two verbs, two parameters or two GraphQL resolvers on one host stay distinct.
    const candidateHash = candidate.fingerprintHash ?? (candidate.endpoint
      ? computeFindingFingerprint({
          origin: candidate.origin,
          cwe: candidate.cwe,
          category: candidate.category,
          endpoint: candidate.endpoint,
          method: candidate.method,
          param: candidate.param,
          graphqlField: candidate.graphqlField,
        }).hash
      : null)
    const candidateOrigin = candidate.origin.trim().toLowerCase()
    const candidateCwe = (candidate.cwe ?? '').trim().toUpperCase()
    const rows = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, runId),
      eq(tables.findings.goalRevision, goalRevision),
      eq(tables.findings.findingKind, 'multi_step_chain'),
    )).all()
    const matches = rows.filter(row => {
      if (row.id === excludeId) return false
      // Origin-wide classes (CORS/CSP/HSTS/TLS/cookies) collapse per host even across routes.
      if (originWide) {
        const rowOrigin = row.finding.origin.trim().toLowerCase()
        const rowCwe = (row.finding.cwe ?? '').trim().toUpperCase()
        if (rowOrigin === candidateOrigin && rowCwe === candidateCwe) return true
      }
      const rowHash = row.fingerprintHash ?? row.finding.fingerprintHash ?? null
      if (candidateHash && rowHash) return candidateHash === rowHash
      // Legacy rows without a fingerprint may only collapse via the fingerprint-free key.
      return !candidateHash && !rowHash && chainFindingDedupKey(row.finding) === legacyKey
    })
    if (!matches.length) return undefined
    // Prefer confirmed duplicate first, then static_verified, then pending, then others
    const order: Record<Finding['status'], number> = {
      confirmed: 0, static_verified: 1, pending: 2, inconclusive: 3, dismissed: 4,
    }
    matches.sort((a, b) => order[a.finding.status] - order[b.finding.status])
    return matches[0]
  }

  /**
   * Resolve monotonic provenance for a persisted finding:
   *  - `floor` rows stay `floor`,
   *  - `chain_from_floor` requires >=1 confirmed floor parent AND a distinct dedupe key,
   *  - everything else is `agent_only`.
   */
  private resolveFindingProvenance(
    runId: string,
    finding: Finding,
    targetRow: typeof tables.findings.$inferSelect | undefined,
    requested: FindingProvenance | undefined,
    parentFindingIds: readonly string[] | null | undefined,
  ): FindingProvenance {
    if (targetRow?.provenance === 'floor') return 'floor'
    if (requested === 'floor') return 'floor'
    if (requested === 'chain_from_floor' || (parentFindingIds?.length ?? 0) > 0) {
      return this.chainFromFloorIsValid(runId, finding, parentFindingIds) ? 'chain_from_floor' : 'agent_only'
    }
    return 'agent_only'
  }

  private chainFromFloorIsValid(
    runId: string,
    finding: Finding,
    parentFindingIds: readonly string[] | null | undefined,
  ): boolean {
    const ids = [...new Set((parentFindingIds ?? []).filter(id => typeof id === 'string' && id.length > 0))]
    if (!ids.length) return false
    const rows = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, runId),
      inArray(tables.findings.id, ids),
    )).all()
    const floorParents = rows.filter(row =>
      row.provenance === 'floor'
      && row.verificationClass === 'runtime_confirmed'
      && row.finding.status === 'confirmed')
    if (!floorParents.length) return false
    // A chain must prove a distinct downstream target/privilege boundary: the dedupe key must
    // differ from every floor parent, otherwise it is the same finding re-discovered.
    const incomingKey = finding.fingerprintHash ?? chainFindingDedupKey(finding)
    return floorParents.some(parent => {
      const parentKey = parent.fingerprintHash ?? parent.finding.fingerprintHash ?? chainFindingDedupKey(parent.finding)
      return parentKey !== incomingKey
    })
  }

  upsertChainFinding(
    run: Run,
    assetId: string,
    finding: Finding,
    replaySpecId: string,
    sourceOrigins: string[],
    options: FindingProvenanceOptions = {},
  ) {
    const byId = this.db.select().from(tables.findings).where(eq(tables.findings.id, finding.id)).get()
    const dupRow = this.findDuplicateChainFinding(run.id, run.goalRevision, finding, byId?.id)

    // When a finding updates by ID and a separate duplicate row already exists for the same (origin, cwe),
    // merge into the canonical duplicate row (especially if confirmed) and remove the redundant row.
    const incoming: Finding = {
      ...finding,
      findingKind: 'multi_step_chain',
      replaySpecId,
    }

    const targetRow = (() => {
      if (byId && dupRow) {
        // Keep whichever row is confirmed first, otherwise keep dupRow as the canonical earlier record
        return byId.finding.status === 'confirmed' && dupRow.finding.status !== 'confirmed' ? byId : dupRow
      }
      return byId ?? dupRow
    })()

    const redundantRow = byId && dupRow
      ? (targetRow?.id === byId.id ? dupRow : byId)
      : undefined

    // Monotonicity: a floor-confirmed row is immutable. An agent re-discovery of the same
    // canonical dedupe key is suppressed as a no-op — never overwritten, never duplicated.
    const targetIsFloor = targetRow?.provenance === 'floor'
    if (targetIsFloor && options.provenance !== 'floor') {
      this.event(
        run.id,
        'finding.floor_preserved',
        `Ignored agent re-discovery of floor-confirmed finding "${targetRow.finding.title}" (${targetRow.id}); floor rows are immutable.`,
        { findingId: targetRow.id, suppressedFindingId: finding.id, provenance: 'floor' },
      )
      return targetRow.finding
    }

    const storedFinding: Finding = targetRow
      ? mergeChainFindings(targetRow.finding, incoming)
      : incoming

    const parentFindingIds = options.parentFindingIds
      ? [...new Set(options.parentFindingIds.filter(id => typeof id === 'string' && id.length > 0))]
      : (targetRow?.parentFindingIds ?? null)
    const provenance = this.resolveFindingProvenance(
      run.id, storedFinding, targetRow, options.provenance, parentFindingIds,
    )
    const canonicalSpecId = storedFinding.replaySpecId ?? replaySpecId
    const verificationClass = verificationClassForFinding(storedFinding, options.verificationClass)
    assertConfirmedVerificationClass(storedFinding.status, verificationClass)
    // Hard gate: never persist a confirmed claim whose own evidence is not confirming. This is the
    // chokepoint for every chain finding write (inline replay, floor, receipt promotion). It throws
    // a typed InvariantError so an inconclusive result structurally cannot become confirmed.
    if (storedFinding.status === 'confirmed') {
      this.assertConfirmationEvidence(run.id, {
        findingId: storedFinding.id,
        replaySpecId: canonicalSpecId,
        verification: storedFinding.verification,
        findingKind: storedFinding.findingKind,
        verificationTier: storedFinding.verificationTier,
        provenance: options.provenance ?? targetRow?.provenance ?? null,
      })
    }
    const persistedFinding = {
      ...storedFinding,
      provenance,
      ...(parentFindingIds?.length ? { parentFindingIds } : {}),
      verificationStatus: verificationClass,
    } as Finding

    const cleanOrigins = [...new Set([
      storedFinding.origin,
      ...(targetRow?.sourceOrigins ?? []),
      ...(redundantRow?.sourceOrigins ?? []),
      ...sourceOrigins,
    ])]

    const verificationTier: VerificationTier | null = storedFinding.verificationTier ??
        (storedFinding.status === 'static_verified'
          ? 'static_verified'
          : storedFinding.status === 'confirmed'
            ? 'runtime_confirmed'
            : targetRow?.verificationTier ?? null)

    if (verificationTier) storedFinding.verificationTier = verificationTier
    // A finding promoted to runtime-confirmed must not retain the static tier marker.
    if (storedFinding.status === 'confirmed' && storedFinding.verificationTier === 'static_verified') {
      storedFinding.verificationTier = 'runtime_confirmed'
    }

    this.transaction(() => {
      if (targetRow) {
        this.db.update(tables.findings).set({
          replaySpecId: canonicalSpecId,
          sourceOrigins: cleanOrigins,
          verificationTier,
          fingerprintHash: storedFinding.fingerprintHash ?? targetRow.fingerprintHash ?? null,
          supersededByFindingId: storedFinding.supersededByFindingId ?? targetRow.supersededByFindingId ?? null,
          counterevidence: storedFinding.counterevidence ?? targetRow.counterevidence ?? null,
          confidenceRationale: storedFinding.confidenceRationale ?? targetRow.confidenceRationale ?? null,
          severityChangeConditions: storedFinding.severityChangeConditions ?? targetRow.severityChangeConditions ?? null,
          codeLocations: storedFinding.codeLocations ?? targetRow.codeLocations ?? null,
          provenance,
          parentFindingIds: parentFindingIds?.length ? parentFindingIds : null,
          verificationClass,
          finding: persistedFinding,
        }).where(eq(tables.findings.id, targetRow.id)).run()
      } else {
        this.db.insert(tables.findings).values({
          id: storedFinding.id,
          runId: run.id,
          assetId,
          goalRevision: run.goalRevision,
          checkId: 'chain',
          caseId: storedFinding.id,
          findingKind: 'multi_step_chain',
          replaySpecId: canonicalSpecId,
          sourceOrigins: cleanOrigins,
          verificationTier,
          fingerprintHash: storedFinding.fingerprintHash ?? null,
          supersededByFindingId: storedFinding.supersededByFindingId ?? null,
          counterevidence: storedFinding.counterevidence ?? null,
          confidenceRationale: storedFinding.confidenceRationale ?? null,
          severityChangeConditions: storedFinding.severityChangeConditions ?? null,
          codeLocations: storedFinding.codeLocations ?? null,
          provenance,
          parentFindingIds: parentFindingIds?.length ? parentFindingIds : null,
          verificationClass,
          finding: persistedFinding,
        }).run()
      }
      if (targetRow) {
        if (finding.id !== targetRow.id) {
          this.db.update(tables.replaySpecs).set({ findingId: targetRow.id })
            .where(and(eq(tables.replaySpecs.runId, run.id), eq(tables.replaySpecs.findingId, finding.id))).run()
        }
        if (redundantRow && redundantRow.id !== targetRow.id) {
          this.db.update(tables.replaySpecs).set({ findingId: targetRow.id })
            .where(and(eq(tables.replaySpecs.runId, run.id), eq(tables.replaySpecs.findingId, redundantRow.id))).run()
        }
      }
      if (redundantRow && redundantRow.id !== targetRow?.id) {
        this.db.delete(tables.findings).where(eq(tables.findings.id, redundantRow.id)).run()
      }
    }, { behavior: 'immediate' })

    this.event(run.id, storedFinding.status === 'pending' ? 'finding.proposed' : 'finding.verified',
      `[${storedFinding.status}] ${storedFinding.severity.toUpperCase()} ${storedFinding.title} (${storedFinding.origin})`, {
        findingId: storedFinding.id,
        status: storedFinding.status,
        severity: storedFinding.severity,
        origin: storedFinding.origin,
        replaySpecId: canonicalSpecId,
        deduplicated: Boolean(dupRow),
        provenance,
        verificationClass,
      })
    return persistedFinding
  }

  // --- Budget & Spend Tracking ---

  recordLlmSpend(runId: string, delta: { usd?: number; tokens?: number; turns?: number }) {
    const usd = Math.max(0, delta.usd ?? 0)
    const tokens = Math.max(0, Math.round(delta.tokens ?? 0))
    const turns = Math.max(0, Math.round(delta.turns ?? 0))
    return this.db.update(tables.runs).set({
      spentUsd: sql`${tables.runs.spentUsd} + ${usd}`,
      spentTokens: sql`${tables.runs.spentTokens} + ${tokens}`,
      turnsUsed: sql`${tables.runs.turnsUsed} + ${turns}`,
    }).where(eq(tables.runs.id, runId)).returning().get()
  }

  checkBudgetExceeded(runId: string): boolean {
    const run = this.run(runId)
    const usdExceeded = run.spentUsd >= run.budgetUsd
    const reqExceeded = run.budgetRequests > 0 && run.spentRequests >= run.budgetRequests
    if (!usdExceeded && !reqExceeded) return false
    if (run.status === 'running') {
      this.transaction(() => {
        const current = this.run(runId)
        if (current.status !== 'running') return
        this.setStatus(current, 'budget_paused')
        const reason = usdExceeded
          ? `USD spend budget reached ($${current.spentUsd.toFixed(2)} / $${current.budgetUsd.toFixed(2)}).`
          : `Broker request budget reached (${current.spentRequests} / ${current.budgetRequests}).`
        this.event(runId, 'run.budget_paused', `${reason} Raise the budget and click Resume to continue.`, {
          spentUsd: current.spentUsd, budgetUsd: current.budgetUsd,
          spentRequests: current.spentRequests, budgetRequests: current.budgetRequests,
        })
        this.message(runId, current.coordinatorId, 'guardian',
          `Run paused: ${reason} A partial report has been saved. Raise the budget to resume.`)
        this.writeReport(this.run(runId), true)
      }, { behavior: 'immediate' })
    }
    return true
  }

  // --- Idempotent Operations ---

  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result
  operate(input: { requestId: string }, apply: () => { id: string }): { id: string } {
    const fingerprint = createHash('sha256').update(JSON.stringify(input)).digest('hex')
    return this.transaction(() => {
      const existing = this.db.select().from(tables.operations).where(and(
        eq(tables.operations.id, input.requestId), eq(tables.operations.workspaceId, this.workspace.id),
      )).get()
      if (existing) {
        if (existing.fingerprint !== fingerprint) throw new Error('This action ID was already used.')
        return JSON.parse(existing.result) as { id: string }
      }
      const result = apply()
      this.db.insert(tables.operations).values({
        id: input.requestId, workspaceId: this.workspace.id, fingerprint, result: JSON.stringify(result),
      }).run()
      return result
    }, { behavior: 'immediate' })
  }

  createProject(input: z.output<typeof newProject>) {
    return this.operate(input, () => {
      const environment = input.environment ?? 'public'
      const originValidator = assetOriginForEnvironment(environment)
      const validatedSeeds = [...new Set(input.seeds.map(seed => originValidator.parse(seed)))]
      const labConfig = environment === 'local-lab' && input.labConfig
        ? ((input.labConfig.enabled || input.labConfig.iastEnabled) && !isLocalLabEnvEnabled()
            ? (() => { throw new Error('Enabling local-lab execution requires GUARDIAN_ALLOW_LOCAL_LAB=1.') })()
            : input.labConfig)
        : (input.labConfig?.enabled || input.labConfig?.iastEnabled
            ? (() => { throw new Error('Local-lab execution and IAST telemetry are forbidden on public projects.') })()
            : null)
      const project = this.db.insert(tables.projects).values({
        id: randomUUID(),
        workspaceId: this.workspace.id,
        name: redact(input.name),
        environment,
        seeds: validatedSeeds,
        defaultScope: [],
        labConfig,
        sandboxWriteAllowlist: input.sandboxWriteAllowlist ?? [],
        createdAt: Date.now(),
      }).returning().get()
      const includeSubdomains = environment === 'public' && Boolean(input.includeSubdomains)
      this.db.insert(tables.projectAssets).values(project.seeds.map(origin => ({
        id: randomUUID(), projectId: project.id, origin, source: 'Project seed', thirdParty: false, includeSubdomains,
      }))).run()
      this.event(null, 'project.created', 'Project created.', { projectId: project.id, environment: project.environment })
      return { id: project.id }
    })
  }

  updateProjectLabConfig(input: { requestId: string; projectId: string; labConfig: LabConfig | null }) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      if (input.labConfig?.enabled || input.labConfig?.iastEnabled) {
        if (project.environment !== 'local-lab') {
          throw new Error('Local-lab app execution and IAST telemetry are forbidden on public projects.')
        }
        if (!isLocalLabEnvEnabled()) {
          throw new Error('Local-lab app execution and IAST telemetry require GUARDIAN_ALLOW_LOCAL_LAB=1 on the server.')
        }
      }
      const nextConfig = project.environment === 'local-lab' ? input.labConfig : null
      this.db.update(tables.projects).set({ labConfig: nextConfig }).where(eq(tables.projects.id, project.id)).run()
      this.event(null, 'project.lab_config_updated', 'Project lab configuration updated.', {
        projectId: project.id,
        enabled: Boolean(nextConfig?.enabled),
      })
      return { id: project.id, labConfig: nextConfig }
    })
  }

  updateProjectSandboxWriteAllowlist(input: {
    requestId: string
    projectId: string
    sandboxWriteAllowlist: ApprovedEndpointPattern[]
  }) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const originValidator = assetOriginForEnvironment(project.environment)
      const validated: ApprovedEndpointPattern[] = []
      for (const entry of input.sandboxWriteAllowlist) {
        const origin = originValidator.parse(entry.origin)
        const method = entry.method.trim().toUpperCase()
        const pathPattern = entry.pathPattern.trim()
        if (!pathPattern.startsWith('/')) {
          throw new Error('Allowlist path pattern must start with "/".')
        }
        validated.push({
          origin,
          method,
          pathPattern,
          ...(entry.scopeRevision !== undefined ? { scopeRevision: entry.scopeRevision } : {}),
          createdAt: entry.createdAt ?? Date.now(),
        })
      }
      this.db.update(tables.projects)
        .set({ sandboxWriteAllowlist: validated })
        .where(eq(tables.projects.id, project.id))
        .run()
      this.event(null, 'project.sandbox_allowlist_updated', 'Project sandbox write allowlist updated.', {
        projectId: project.id,
        count: validated.length,
      })
      return { id: project.id, sandboxWriteAllowlist: validated }
    })
  }

  createRun(input: Omit<z.output<typeof newRun>, 'approvalPolicy' | 'multiTrialEnabled'> & {
    approvalPolicy?: ApprovalPolicy
    multiTrialEnabled?: boolean
  }) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const goal = redact(input.goal)
      const capabilityTier: CapabilityTier = input.sourceMode === 'prepared' ? 0 : (input.capabilityTier ?? 1)
      const validPersonaIds = new Set(listProjectPersonas(this, project.id).map(p => p.id))
      const approvedPersonaIds = capabilityTier >= 2
        ? [...new Set((input.approvedPersonaIds ?? []).filter(pid => validPersonaIds.has(pid)))]
        : []
      const defaultReqs = project.environment === 'local-lab' ? defaultLabBudgetRequests : defaultPublicBudgetRequests
      const run = this.db.insert(tables.runs).values({
        id: randomUUID(),
        projectId: project.id,
        workspaceId: this.workspace.id,
        coordinatorId: randomUUID(),
        originalGoal: goal,
        goal,
        goalRevision: 0,
        scopeRevision: 0,
        phase: 'consent',
        status: 'waiting',
        sourceMode: input.sourceMode,
        capabilityTier,
        approvalPolicy: input.approvalPolicy ?? 'auto_review',
        approvedEndpointPatterns: [],
        approvedPersonaIds,
        roundNo: 0,
        budgetUsd: input.budgetUsd ?? defaultBudgetUsd,
        budgetRequests: input.budgetRequests ?? defaultReqs ?? defaultBudgetRequests,
        spentUsd: 0,
        spentTokens: 0,
        spentRequests: 0,
        turnsUsed: 0,
        maxRpsPerOrigin: input.maxRpsPerOrigin ?? defaultMaxRpsPerOrigin,
        workerConcurrency: input.workerConcurrency ?? defaultWorkerConcurrency,
        workerMaxTurns: input.workerMaxTurns ?? defaultWorkerMaxTurns,
        dynamicStepBudget: null,
        multiTrialEnabled: input.multiTrialEnabled ?? true,
        phase0CompletedAt: null,
        candidates: [],
        approved: [],
        authOrigins: [],
        assetOrigins: [],
        environmentMode: defaultEnvironmentMode(project.environment),
        routeDenylist: [],
        createdAt: Date.now(),
      }).returning().get()
      for (const [handle, role] of [
        ['coordinator', 'coordinator'],
        ['verifier', 'verifier'],
        ['broker', 'system'],
        ['canary', 'system'],
      ] as const) {
        this.upsertBoardMember(run, {
          handle,
          role,
          sessionId: handle === 'coordinator' ? run.coordinatorId : `system:${handle}`,
          state: 'waiting',
          sourceOrigins: [],
        })
      }
      this.event(run.id, 'run.created', 'Run created.', {
        capabilityTier,
        approvalPolicy: run.approvalPolicy,
        sourceMode: input.sourceMode,
      })
      const goalMessageId = this.message(run.id, run.coordinatorId, 'operator', goal)
      this.updateRun(run.id, { reviewPlan: { status: 'pending', goalMessageId } })
      return { id: run.id }
    })
  }

  addProjectAsset(input: z.output<typeof projectAsset>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const origin = assetOriginForEnvironment(project.environment).parse(input.origin)
      const includeSubdomains = project.environment === 'public' && !input.thirdParty && Boolean(input.includeSubdomains)
      const candidate = this.saveCandidate(project.id, { ...input, origin, includeSubdomains })
      return { id: candidate.id }
    })
  }

  updateProjectAssetScope(input: {
    requestId: string
    projectId: string
    assetId: string
    includeSubdomains?: boolean
    approveInDefaultScope?: boolean
  }) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const asset = this.db.select().from(tables.projectAssets)
        .where(and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.id, input.assetId)))
        .get()
      if (!asset) throw new Error('Project asset not found.')

      let nextIncludeSubdomains = Boolean(asset.includeSubdomains)
      if (input.includeSubdomains !== undefined) {
        nextIncludeSubdomains = project.environment === 'public' && !asset.thirdParty && Boolean(input.includeSubdomains)
        this.db.update(tables.projectAssets)
          .set({ includeSubdomains: nextIncludeSubdomains })
          .where(eq(tables.projectAssets.id, asset.id))
          .run()
      }

      let nextDefaultScope = [...project.defaultScope]
      if (input.approveInDefaultScope !== undefined) {
        if (input.approveInDefaultScope) {
          if (!nextDefaultScope.includes(asset.origin)) nextDefaultScope.push(asset.origin)
        } else {
          nextDefaultScope = nextDefaultScope.filter(origin => origin !== asset.origin)
        }
        this.db.update(tables.projects)
          .set({ defaultScope: nextDefaultScope })
          .where(eq(tables.projects.id, project.id))
          .run()
      }

      this.event(null, 'inventory.asset_scope_updated', `Updated scope settings for ${asset.origin}.`, {
        projectId: project.id,
        assetId: asset.id,
        origin: asset.origin,
        thirdParty: asset.thirdParty,
        includeSubdomains: nextIncludeSubdomains,
        approvedInDefaultScope: nextDefaultScope.includes(asset.origin),
      })
      return {
        id: asset.id,
        includeSubdomains: nextIncludeSubdomains,
        approvedInDefaultScope: nextDefaultScope.includes(asset.origin),
      }
    })
  }

  importProjectDns(input: z.output<typeof importDnsInventory>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const { zone, candidates } = parseDnsInventory(input.zone, input.document)
      let added = 0
      for (let offset = 0; offset < candidates.length; offset += 100) {
        const rows = candidates.slice(offset, offset + 100).map(candidate => ({
          ...candidate, id: randomUUID(), projectId: project.id,
        }))
        added += this.db.insert(tables.projectAssets).values(rows).onConflictDoNothing()
          .returning({ id: tables.projectAssets.id }).all().length
      }
      const existing = candidates.length - added
      this.event(null, 'inventory.dns_imported', 'Passive DNS inventory imported.', {
        projectId: project.id, actorId: this.workspace.actorId, zone, added, existing,
      })
      return { id: project.id, added, existing }
    })
  }

  importProjectAccessPolicy(input: z.output<typeof importAccessPolicy>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const snapshot = input.snapshot
      const json = JSON.stringify(snapshot)
      if (redact(json) !== json) throw new Error('Use case, role, and capability labels without credentials.')
      const target = and(eq(tables.projectAssets.projectId, project.id), eq(tables.projectAssets.origin, snapshot.origin))
      const asset = this.db.update(tables.projectAssets).set({ accessPolicy: snapshot }).where(target)
        .returning({ id: tables.projectAssets.id }).get()
      if (!asset) throw new Error('Select a file for an existing project host.')
      this.event(null, 'inventory.access_policy_imported', 'Access policy records imported.', {
        projectId: project.id, assetId: asset.id, actorId: this.workspace.actorId,
        recordedAt: snapshot.recordedAt, expected: snapshot.expected.length, observed: snapshot.observed.length,
      })
      return { id: asset.id, origin: snapshot.origin, cases: snapshot.expected.length }
    })
  }

  private saveCandidate(projectId: string, input: Omit<Candidate, 'id'>, replace = true) {
    const candidate = {
      id: randomUUID(), projectId, origin: input.origin, source: redact(input.source),
      thirdParty: input.thirdParty,
      includeSubdomains: !input.thirdParty && Boolean(input.includeSubdomains),
      prepared: input.prepared ?? null,
      dnsSource: input.dnsSource ?? null,
    }
    const insert = this.db.insert(tables.projectAssets).values(candidate)
    if (replace) return insert.onConflictDoUpdate({
      target: [tables.projectAssets.projectId, tables.projectAssets.origin],
      set: {
        source: candidate.source,
        thirdParty: candidate.thirdParty,
        ...(input.includeSubdomains === undefined ? {} : { includeSubdomains: candidate.includeSubdomains }),
        ...(input.prepared === undefined ? {} : { prepared: input.prepared }),
        ...(input.dnsSource === undefined ? {} : { dnsSource: input.dnsSource }),
      },
    }).returning().get()
    insert.onConflictDoNothing().run()
    return this.db.select().from(tables.projectAssets).where(and(
      eq(tables.projectAssets.projectId, projectId), eq(tables.projectAssets.origin, input.origin),
    )).get()!
  }

  suggestCandidateHost(run: Run, origin: string, source: string, thirdParty = false, dnsSource?: DnsSource | null) {
    if (run.candidates.some(candidate => candidate.origin === origin)) {
      return { added: false, origin }
    }
    const asset = this.saveCandidate(
      run.projectId,
      { origin, source: redact(source), thirdParty, ...(dnsSource !== undefined ? { dnsSource } : {}) },
      false,
    )
    const discovery = this.workerList(run.id).find(worker => worker.phase === 'discovery' && worker.assetId === null)
    const sourceEv = discovery && this.recordInventory(run, discovery, 'Candidate source', [asset])
    const candidate = sourceEv ? { ...asset, sourceEvidenceId: sourceEv.id } : asset
    this.updateRun(run.id, { candidates: [...run.candidates, candidate] })
    this.event(run.id, 'asset.candidate', `Worker suggested candidate host ${origin} (unapproved until scope approval).`, {
      id: asset.id, origin: asset.origin, source: redact(source), thirdParty, sourceEvidenceId: sourceEv?.id,
    })
    return { added: true, id: asset.id, origin: asset.origin }
  }

  makeWorker(
    run: Run,
    phase: WorkerPhase,
    candidate: Candidate | undefined,
    title: string,
    objective: string,
    opts: {
      input?: Assignment
      stepId?: string | null
      maxTurns?: number
      parentFactIds?: string[]
      sourceOrigins?: string[]
    } = {},
  ): Assignment {
    const sourceOrigins = [...new Set([
      ...(candidate ? [candidate.origin] : []),
      ...(opts.sourceOrigins ?? []),
    ])]
    const assignment = this.db.insert(tables.assignments).values({
      id: randomUUID(),
      runId: run.id,
      assetId: candidate?.id ?? null,
      stepId: opts.stepId ?? null,
      inputAssignmentId: opts.input?.id ?? null,
      phase,
      status: 'queued',
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      sessionId: randomUUID(),
      lease: null,
      leaseExpiresAt: null,
      attempt: 0,
      maxTurns: opts.maxTurns ?? run.workerMaxTurns ?? defaultWorkerMaxTurns,
      turnsUsed: 0,
      requestsUsed: 0,
      parentFactIds: [...new Set(opts.parentFactIds ?? [])],
      sourceOrigins,
      title: redact(title),
      objective: redact(objective),
      outcome: null,
      checks: null,
      createdAt: Date.now(),
    }).returning().get()
    const target = candidate?.origin ?? (sourceOrigins.join(', ') || 'Supplied project records')
    this.addArtifact(run, assignment, 'handoff', 'assignment.md',
      [
        '# Assignment', '', objective, '',
        'Phase: ' + phase,
        'Target: ' + target,
        ...(opts.stepId ? ['Chain step: ' + opts.stepId] : []),
        ...(opts.input ? ['Input assignment: ' + opts.input.id] : []),
        'Goal: ' + run.goal,
        'Goal revision: ' + run.goalRevision,
        'Scope revision: ' + run.scopeRevision,
      ].join('\n'), 'assignment')
    return assignment
  }

  commitReviewPlan(expected: Pick<Run, 'id' | 'goalRevision' | 'scopeRevision'>, selection: SelectedChecks) {
    this.transaction(() => {
      const run = this.run(expected.id)
      const plan = run.reviewPlan
      if (run.status !== 'running' || plan?.status !== 'pending' ||
        run.goalRevision !== expected.goalRevision || run.scopeRevision !== expected.scopeRevision) return
      this.updateRun(run.id, { reviewPlan: { status: 'ready', goalMessageId: plan.goalMessageId, ...selection } })
      const titles = selection.checks.map(id => assessmentCheckTitles[id]).join(', ')
      const planned = selection.source === 'coordinator'
      this.message(run.id, run.coordinatorId, planned ? 'coordinator' : 'guardian',
        (planned ? 'Baseline checks selected: ' : 'Standard baseline checks selected: ') + titles + '.', plan.goalMessageId)
      this.event(run.id, 'review.planned', 'Baseline check plan saved.', {
        goalRevision: run.goalRevision, scopeRevision: run.scopeRevision, ...selection,
      })
    }, { behavior: 'immediate' })
  }

  updateRun(runId: string, state: Partial<Run>) {
    const updated = this.db.update(tables.runs).set(state).where(eq(tables.runs.id, runId)).returning().get()
    if (!updated) throw new Error('Run not found.')
    return updated
  }

  updateWorker(assignmentId: string, state: Partial<Assignment>) {
    return this.db.update(tables.assignments).set(state).where(eq(tables.assignments.id, assignmentId)).returning().get()
  }

  setStatus(run: Run, status: Run['status']) {
    this.updateRun(run.id, { status })
    if (status === 'paused' || status === 'budget_paused' || status === 'stopped' || status === 'failed') {
      this.db.update(tables.assignments).set({ status: 'paused', lease: null, leaseExpiresAt: null }).where(and(
        eq(tables.assignments.runId, run.id),
        inArray(tables.assignments.status, ['queued', 'running', 'waiting_approval']),
        // Operator opt-in approvals that released their slot survive pause/recovery.
        sql`NOT (${tables.assignments.status} = 'waiting_approval' AND ${tables.assignments.approvalParkedAt} IS NOT NULL)`,
      )).run()
    }
    if (status === 'running') {
      this.db.update(tables.assignments).set({ status: 'queued', lease: null, leaseExpiresAt: null }).where(and(
        eq(tables.assignments.runId, run.id), inArray(tables.assignments.status, ['paused', 'failed']),
      )).run()
    }
  }

  private discover(run: Run) {
    if (run.phase !== 'consent' || run.status !== 'waiting') throw new Error('Discovery has already started.')
    const project = this.project(run.projectId)
    this.event(run.id, 'discovery.consented', 'Discovery consent recorded.', {
      actorId: this.workspace.actorId, seeds: project.seeds,
    })
    const inventory = this.db.select().from(tables.projectAssets).where(eq(tables.projectAssets.projectId, run.projectId)).all()
    this.updateRun(run.id, { phase: 'discovery', status: 'running' })
    const worker = this.makeWorker(run, 'discovery', undefined, 'Asset inventory', 'Review supplied project records and attribute the candidate origins.')
    const initial = this.recordInventory(run, worker, inventoryTitle, inventory)
    this.updateWorker(worker.id, { status: 'complete', outcome: 'Reviewed supplied project records.' })
    this.message(run.id, worker.id, 'worker', `Recorded ${inventory.length} candidates from supplied project records.`,
      undefined, [initial.id])
    this.updateRun(run.id, {
      phase: 'review', status: 'waiting',
      candidates: inventory.map(asset => ({ ...asset, sourceEvidenceId: initial.id })),
    })
    this.event(run.id, 'discovery.complete', 'Discovery complete. Review scope and capability tier to continue.')
    this.message(run.id, run.coordinatorId, 'guardian', 'Review the candidate hosts, capability tier, and personas before approving assessment.')
  }

  private recordInventory(run: Run, worker: Assignment, title: string, assets: readonly Candidate[]) {
    const records = assets.map(({ origin, thirdParty, source, dnsSource }) =>
      ({ origin, thirdParty, source, ...(dnsSource ? { dnsSource } : {}) }))
    return this.addArtifact(run, worker, 'inventory', title, JSON.stringify(records, null, 2))
  }

  // --- Transitive Scope Revocation ---

  private applyTransitiveRevocation(run: Run, approvedIds: readonly string[], approvedOrigins: ReadonlySet<string>, scopeRevision: number) {
    const approvedIdSet = new Set(approvedIds)
    // Benign auth/asset hops remain valid provenance after a target origin is revoked.
    const provenanceOrigins = this.provenanceOriginsFor(run)
    const provenanceAllowed = (origin: string) =>
      approvedOrigins.has(origin) || provenanceOrigins.has(normalizeScopeOrigin(origin) ?? origin)
    const allFacts = this.db.select().from(tables.facts).where(eq(tables.facts.runId, run.id)).all()
    const allSteps = this.db.select().from(tables.chainSteps).where(eq(tables.chainSteps.runId, run.id)).all()
    const allAssignments = this.workerList(run.id)
    const allEdges = this.listGraphEdges(run.id)

    // Build downstream propagation graph: upstream node key -> downstream node keys
    const downstream = new Map<string, Set<string>>()
    const addLink = (fromKey: string, toKey: string) => {
      let set = downstream.get(fromKey)
      if (!set) {
        set = new Set()
        downstream.set(fromKey, set)
      }
      set.add(toKey)
    }

    for (const edge of allEdges) {
      const fromKey = `${edge.fromKind}:${edge.fromId}`
      const toKey = `${edge.toKind}:${edge.toId}`
      if (edge.edgeKind === 'depends_on' || edge.edgeKind === 'derived_from') {
        // from depends on to -> taint flows from `to` to `from`
        addLink(toKey, fromKey)
      } else if (edge.edgeKind === 'yields' || edge.edgeKind === 'spawns' || edge.edgeKind === 'proves') {
        // from produces/spawns/proves to -> taint flows from `from` to `to`
        addLink(fromKey, toKey)
      }
    }

    // Also incorporate explicit foreign-key dependency links
    for (const step of allSteps) {
      const stepKey = `step:${step.id}`
      for (const fId of step.dependsOnFactIds) addLink(`fact:${fId}`, stepKey)
      for (const sId of step.dependsOnStepIds) addLink(`step:${sId}`, stepKey)
      if (step.assignedWorkerId) addLink(stepKey, `assignment:${step.assignedWorkerId}`)
    }
    for (const worker of allAssignments) {
      const wKey = `assignment:${worker.id}`
      for (const fId of worker.parentFactIds) addLink(`fact:${fId}`, wKey)
      if (worker.stepId) addLink(`step:${worker.stepId}`, wKey)
    }
    for (const fact of allFacts) {
      addLink(`assignment:${fact.assignmentId}`, `fact:${fact.id}`)
    }

    const taintedNodes = new Set<string>()
    const queue: string[] = []
    const enqueue = (key: string) => {
      if (taintedNodes.has(key)) return
      taintedNodes.add(key)
      queue.push(key)
    }

    // Seed with directly affected facts, steps, assignments
    for (const fact of allFacts) {
      if (!approvedOrigins.has(fact.origin) || fact.sourceOrigins.some(o => !provenanceAllowed(o))) {
        enqueue(`fact:${fact.id}`)
      }
    }
    for (const step of allSteps) {
      if (step.sourceOrigins.some(o => !provenanceAllowed(o)) ||
          step.targetAssetIds.some(aid => !approvedIdSet.has(aid))) {
        enqueue(`step:${step.id}`)
      }
    }
    for (const worker of allAssignments) {
      if (worker.phase === 'discovery') continue
      const touchesUnapproved =
        (worker.assetId !== null && !approvedIdSet.has(worker.assetId)) ||
        worker.sourceOrigins.some(o => !provenanceAllowed(o)) ||
        this.brokerOrigins(worker).some(o => !provenanceAllowed(o))
      if (touchesUnapproved) enqueue(`assignment:${worker.id}`)
    }

    // BFS transitive propagation
    while (queue.length) {
      const current = queue.shift()!
      const neighbors = downstream.get(current)
      if (!neighbors) continue
      for (const next of neighbors) enqueue(next)
    }

    const taintedFactIds: string[] = []
    const taintedStepIds: string[] = []
    const canceledAssignmentIds: string[] = []

    for (const key of taintedNodes) {
      const [kind, itemId] = key.split(':')
      if (kind === 'fact') taintedFactIds.push(itemId)
      else if (kind === 'step') taintedStepIds.push(itemId)
      else if (kind === 'assignment') canceledAssignmentIds.push(itemId)
    }

    if (taintedFactIds.length) {
      this.db.update(tables.facts).set({ tainted: true }).where(and(
        eq(tables.facts.runId, run.id), inArray(tables.facts.id, taintedFactIds),
      )).run()
      // Deactivate any digest covering a tainted fact
      const taintedSet = new Set(taintedFactIds)
      for (const digest of this.listDigests(run.id, true)) {
        if (digest.coveredFactIds.some(fid => taintedSet.has(fid))) {
          this.db.update(tables.graphDigests).set({ active: false }).where(eq(tables.graphDigests.id, digest.id)).run()
        }
      }
    }

    if (taintedStepIds.length) {
      this.db.update(tables.chainSteps).set({ status: 'tainted', assignedWorkerId: null, updatedAt: Date.now() }).where(and(
        eq(tables.chainSteps.runId, run.id),
        inArray(tables.chainSteps.id, taintedStepIds),
        sql`${tables.chainSteps.status} != 'canceled'`,
      )).run()
    }

    if (canceledAssignmentIds.length) {
      for (const worker of allAssignments) {
        if (canceledAssignmentIds.includes(worker.id) && !['complete', 'canceled'].includes(worker.status)) {
          this.updateWorker(worker.id, { status: 'canceled', outcome: 'Scope revoked.', lease: null, leaseExpiresAt: null })
        }
      }
    }

    // Cancel pending approvals referencing unapproved origins or canceled assignments
    const pendingApprovals = this.listApprovalRequests(run.id, 'pending')
    for (const req of pendingApprovals) {
      if (!approvedOrigins.has(req.origin) || canceledAssignmentIds.includes(req.assignmentId)) {
        this.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: Date.now() })
          .where(eq(tables.approvalRequests.id, req.id)).run()
      }
    }

    // Durable leases are scoped to the current scope revision; revoke any lease on a revoked origin.
    this.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() }).where(and(
      eq(tables.approvalLeases.runId, run.id),
      eq(tables.approvalLeases.status, 'active'),
      sql`${tables.approvalLeases.scopeRevision} != ${scopeRevision}`,
    )).run()
    for (const lease of this.listApprovalLeases(run.id, 'active')) {
      if (!approvedOrigins.has(lease.origin)) {
        this.db.update(tables.approvalLeases).set({ status: 'revoked', updatedAt: Date.now() })
          .where(eq(tables.approvalLeases.id, lease.id)).run()
      }
    }

    const boardTaint = this.taintBoardMessagesForRevokedOrigins(run.id, approvedOrigins)

    if (taintedFactIds.length || taintedStepIds.length || canceledAssignmentIds.length) {
      this.event(run.id, 'scope.revoked',
        `Scope revision ${scopeRevision} tainted ${taintedFactIds.length} facts, ${taintedStepIds.length} steps, ${boardTaint.taintedMessageIds.length} board posts, and canceled ${canceledAssignmentIds.length} assignments.`,
        { scopeRevision, taintedFactIds, taintedStepIds, canceledAssignmentIds, ...boardTaint })
    }
  }

  private setScope(run: Run, cmd: Extract<RunCommand, { action: 'scope' }>) {
    const { assetIds, expectedScopeRevision, saveProject } = cmd
    if (run.scopeRevision !== expectedScopeRevision) {
      throw new Error('Scope changed since you opened this review.')
    }
    if (!canReviewScope(run.phase, run.status)) {
      throw new Error('Scope changes are unavailable in this phase.')
    }
    const approved = [...new Set(assetIds)]
    if (approved.some(id => !run.candidates.some(asset => asset.id === id))) {
      throw new Error('Select assets from this run’s inventory.')
    }
    const project = this.project(run.projectId)
    const originValidator = assetOriginForEnvironment(project.environment)
    for (const id of approved) {
      const asset = run.candidates.find(c => c.id === id)
      if (asset) originValidator.parse(asset.origin)
    }
    if (run.phase === 'review' && approved.length === 0) {
      throw new Error('Approve at least one host to start assessment.')
    }

    const capabilityTier: CapabilityTier = cmd.capabilityTier ?? run.capabilityTier
    if (run.sourceMode === 'prepared' && capabilityTier > 0) {
      throw new Error('Prepared runs are restricted to Tier 0 (offline prepared).')
    }

    // Validate approved persona IDs belong to this project
    const approvedPersonaIds = cmd.approvedPersonaIds !== undefined
      ? [...new Set(cmd.approvedPersonaIds)]
      : run.approvedPersonaIds
    if (approvedPersonaIds.length) {
      if (capabilityTier < 2) {
        throw new Error('Persona credentials require Capability Tier 2 or Tier 3.')
      }
      const validIds = new Set(listProjectPersonas(this, run.projectId).map(p => p.id))
      if (approvedPersonaIds.some(pid => !validIds.has(pid))) {
        throw new Error('Select personas registered in this project.')
      }
    }

    const scopeRevision = run.scopeRevision + 1
    const removed = run.approved.filter(id => !approved.includes(id))
    const added = approved.filter(id => !run.approved.includes(id))
    const approvedOrigins = new Set(run.candidates.filter(a => approved.includes(a.id)).map(a => a.origin))
    const loweredTier = capabilityTier < run.capabilityTier

    const phase = run.phase === 'review'
      ? 'threat_model'
      : added.length && run.phase === 'verification'
        ? 'investigation'
        : run.phase
    const status = run.phase === 'review' ? 'running' : run.status

    const plan = run.reviewPlan
    let reviewPlan = plan
    if (plan?.status === 'ready' && added.length) {
      const priorAssets = run.candidates.filter(asset => run.approved.includes(asset.id))
      const priorChecks = priorAssets.length ? availableReviewChecks(priorAssets, run.sourceMode) : []
      const currentChecks = availableReviewChecks(run.candidates.filter(asset => approved.includes(asset.id)), run.sourceMode)
      if (currentChecks.some(check => !priorChecks.includes(check))) {
        reviewPlan = { status: 'pending', goalMessageId: plan.goalMessageId, previous: { checks: plan.checks, source: plan.source } }
      }
    }

    const updated = this.updateRun(run.id, {
      approved,
      scopeRevision,
      phase,
      status,
      reviewPlan,
      capabilityTier,
      approvedPersonaIds,
      ...(cmd.approvalPolicy !== undefined ? { approvalPolicy: cmd.approvalPolicy } : {}),
      ...(cmd.budgetUsd !== undefined ? { budgetUsd: cmd.budgetUsd } : {}),
      ...(cmd.budgetRequests !== undefined ? { budgetRequests: cmd.budgetRequests } : {}),
      ...(cmd.maxRpsPerOrigin !== undefined ? { maxRpsPerOrigin: cmd.maxRpsPerOrigin } : {}),
    })

    if (saveProject) {
      this.db.update(tables.projects).set({
        defaultScope: run.candidates.filter(asset => approved.includes(asset.id)).map(asset => asset.origin),
      }).where(eq(tables.projects.id, run.projectId)).run()
    }

    if (removed.length) {
      this.applyTransitiveRevocation(updated, approved, approvedOrigins, scopeRevision)
    }

    if (loweredTier && capabilityTier < 3) {
      this.db.update(tables.approvalRequests).set({ status: 'canceled', decidedAt: Date.now() }).where(and(
        eq(tables.approvalRequests.runId, run.id), eq(tables.approvalRequests.status, 'pending'),
      )).run()
    }

    this.event(run.id, 'scope.approved', `Recorded scope revision ${scopeRevision} (Tier ${capabilityTier}).`, {
      actorId: this.workspace.actorId,
      scopeRevision,
      capabilityTier,
      approvedPersonaIds,
      approved: updated.candidates.filter(asset => approved.includes(asset.id)).map(asset => asset.origin),
      excluded: updated.candidates.filter(asset => !approved.includes(asset.id)).map(asset => asset.origin),
      removed,
      added,
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Scope revision ${scopeRevision} approved for ${approved.length} ${approved.length === 1 ? 'host' : 'hosts'} at Tier ${capabilityTier}.`)
  }

  private revise(run: Run, input: string) {
    if (run.phase === 'complete') throw new Error('Create a new run to change a completed goal.')
    const goal = redact(input)
    const revision = run.goalRevision + 1
    const phase = ['investigation', 'verification'].includes(run.phase) ? 'threat_model' : run.phase
    if (run.reviewPlan?.status === 'pending') {
      this.message(run.id, run.coordinatorId, 'guardian', 'This goal was superseded by a revision.', run.reviewPlan.goalMessageId)
    }
    const goalMessageId = this.message(run.id, run.coordinatorId, 'operator', `Revised goal: ${goal}`)
    this.updateRun(run.id, { goal, goalRevision: revision, phase, reviewPlan: { status: 'pending', goalMessageId } })
    for (const assignment of this.workerList(run.id)) {
      if (assignment.goalRevision === run.goalRevision && assignment.phase !== 'discovery' &&
          !['complete', 'canceled'].includes(assignment.status)) {
        this.updateWorker(assignment.id, { status: 'canceled', outcome: 'Superseded by a goal revision.', lease: null, leaseExpiresAt: null })
      }
    }
    this.db.update(tables.chainSteps).set({ status: 'canceled', assignedWorkerId: null, updatedAt: Date.now() }).where(and(
      eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.goalRevision, run.goalRevision),
      inArray(tables.chainSteps.status, ['pending', 'ready', 'running', 'blocked']),
    )).run()
    this.event(run.id, 'goal.revised', `Goal revision ${revision} recorded.`, { actorId: this.workspace.actorId, revision, goal })
  }

  private retainAccessVerification(run: Run, origin: string, worker: Assignment, source: Evidence, receipt: Evidence) {
    if (source.goalRevision !== run.goalRevision || receipt.goalRevision !== run.goalRevision ||
      source.scopeRevision > receipt.scopeRevision || receipt.scopeRevision > run.scopeRevision ||
      source.createdAt > receipt.createdAt) return
    const restricted = (() => {
      try {
        return restrictAccessVerification(this.artifact(run.id, receipt.id).content, this.artifact(run.id, source.id), origin)
      } catch {
        return undefined
      }
    })()
    if (!restricted) return

    const operation = reportAccessOperation + run.scopeRevision
    const existing = this.assignmentEvidence(worker.id, operation)
    const evidence = existing ?? this.addArtifact(run, worker, 'verification', 'Access policy verification',
      JSON.stringify({ ...restricted.receipt, verifiedAt: new Date(receipt.createdAt).toISOString() }, null, 2), operation)
    if (!existing) this.event(run.id, 'evidence.restricted', 'Preserved the independent access verification for the current scope.', {
      assignmentId: worker.id, artifactId: evidence.id, sourceArtifactId: receipt.id, scopeRevision: run.scopeRevision,
    })
    return {
      sourceId: source.id, receiptId: receipt.id, evidenceId: evidence.id, origin,
      checks: restricted.receipt.checks, recordedAt: restricted.recordedAt,
    }
  }

  writeReport(run: Run, partial: boolean) {
    const snapshot = this.runDetail(run.id)
    const scope = run.candidates.filter(candidate => run.approved.includes(candidate.id))
    const approvedOrigins = new Set(scope.map(asset => asset.origin))
    // Provenance rule: IdP/auth and CDN/asset hops are benign infrastructure. They may appear in a
    // recorded redirect chain or source set without invalidating a valid targetOrigins finding.
    const provenancePolicy = this.scopePolicy(run)
    const provenanceOrigins = provenanceOriginsFor(provenancePolicy)
    const provenanceAllowed = (origin: string) =>
      approvedOrigins.has(origin) || provenanceOrigins.has(normalizeScopeOrigin(origin) ?? origin)
    const currentEvidence = new Set<string>()
    const retainedAccess = new Map<string, NonNullable<ReturnType<Store['retainAccessVerification']>>>()
    const gaps: string[] = []
    const plan = run.reviewPlan
    const selection = plan?.status === 'ready' ? { checks: plan.checks, source: plan.source } : plan?.previous
    if (plan?.status === 'pending' && plan.previous) gaps.push('A revised check plan was pending for this approval.')

    // Non-tainted facts set for transitive chain validation
    const taintedFactIds = new Set(snapshot.facts.filter(f => f.tainted).map(f => f.id))
    const validFactCount = snapshot.facts.filter(f => !f.tainted && approvedOrigins.has(f.origin)).length

    // Collect valid evidence from non-revoked assignments
    for (const item of snapshot.evidence) {
      if (item.goalRevision === run.goalRevision && item.scopeRevision <= run.scopeRevision) {
        currentEvidence.add(item.id)
      }
    }

    const coverage = scope.map(asset => {
      const { analysis, verification } = assessmentAssignments(snapshot.assignments, asset.id, run.goalRevision)
      const analyzed = analysis?.status === 'complete' ? analysis : undefined
      const verified = verification?.status === 'complete' ? verification : undefined
      const done = verified ?? analyzed
      const evList = snapshot.evidence.filter(item =>
        (item.assignmentId === analyzed?.id || item.assignmentId === verified?.id) &&
        !item.operationId?.startsWith(reportAccessOperation))
      const artifact = evList.findLast(item => item.assignmentId === done?.id &&
        (verified ? item.kind === 'verification' : ['observation', 'access-policy'].includes(item.kind)))
      const access = evList.findLast(item => item.assignmentId === analyzed?.id && item.kind === 'access-policy')

      if (analyzed && this.brokerOrigins(analyzed).some(origin => !provenanceAllowed(origin))) {
        const reason = 'A source in the recorded redirect chain is no longer approved.'
        const retained = verified?.inputAssignmentId === analyzed.id && access && artifact
          ? this.retainAccessVerification(run, asset.origin, verified, access, artifact) : undefined
        if (retained) retainedAccess.set(asset.id, retained)
        const checks: CheckCoverage[] = (verified?.checks ?? []).filter(check => check.id !== 'access-policy' || !retained).map(check => ({
          ...check, observed: null,
          status: check.status === 'untested' ? 'untested' : 'inconclusive',
          reason: check.status === 'untested' ? untestedReason : check.id === 'access-policy'
            ? 'The saved verification does not support a separate access policy result.' : reason,
        }))
        if (retained) checks.push(...retained.checks)
        if (selection) {
          for (const check of untestedCoverage(asset, selection)) {
            if (!checks.some(saved => saved.id === check.id && saved.caseId === check.caseId)) checks.push(check)
          }
        }
        const status = 'Inconclusive. ' + reason
        gaps.push(asset.origin + ' · ' + status)
        for (const r of inconclusiveReasons(retained?.checks ?? [])) gaps.push(asset.origin + ' · ' + r)
        return {
          origin: asset.origin,
          status: retained?.checks.some(check => check.status === 'met' || check.status === 'gap')
            ? 'Access policy reviewed. Response checks inconclusive.' : status,
          evidenceId: retained?.evidenceId ?? null,
          ...(retained ? { accessEvidence: { id: retained.sourceId, recordedAt: retained.recordedAt } } : {}),
          ...(checks.length ? { checks } : {}),
        }
      }

      const derived = evList.findLast(item => item.assignmentId === analyzed?.id && item.kind === 'analysis')
      const status = verified?.outcome ?? (analyzed ? 'Analysis complete. Verification pending.' : 'Pending review')
      const checks = verified ? verified.checks : selection && untestedCoverage(asset, selection)
      if (!verified || !artifact) {
        gaps.push(asset.origin + ' · ' + status)
      } else if (verified.checks) {
        for (const r of inconclusiveReasons(verified.checks)) gaps.push(asset.origin + ' · ' + r)
      } else if (status.startsWith('Inconclusive')) {
        gaps.push(asset.origin + ' · ' + status)
      }
      return {
        origin: asset.origin,
        status,
        evidenceId: artifact?.id ?? null,
        analysisEvidenceId: derived?.id,
        ...(access ? { accessEvidence: { id: access.id, recordedAt: asset.accessPolicy?.recordedAt } } : {}),
        ...(checks ? { checks } : {}),
      }
    })

    // Filter findings strictly by current approved scope & non-tainted provenance
    const results = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, run.id), eq(tables.findings.goalRevision, run.goalRevision),
    )).all().flatMap(row => {
      const { assetId, checkId, caseId, findingKind, sourceOrigins, replaySpecId } = row
      const finding: Finding & FindingProvenanceFields = {
        ...row.finding,
        verificationTier: row.verificationTier ?? row.finding.verificationTier,
        fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash,
        supersededByFindingId: row.supersededByFindingId ?? row.finding.supersededByFindingId,
        counterevidence: row.counterevidence ?? row.finding.counterevidence,
        confidenceRationale: row.confidenceRationale ?? row.finding.confidenceRationale,
        severityChangeConditions: row.severityChangeConditions ?? row.finding.severityChangeConditions,
        ...(row.codeLocations?.length ? { codeLocations: row.codeLocations } : row.finding.codeLocations?.length ? { codeLocations: row.finding.codeLocations } : {}),
        provenance: row.provenance,
        ...(row.parentFindingIds?.length ? { parentFindingIds: row.parentFindingIds } : {}),
        verificationStatus: row.verificationClass,
      }
      const isStaticVerified = finding.status === 'static_verified' || finding.verificationTier === 'static_verified'
      if (!isStaticVerified) {
        if (!run.approved.includes(assetId) || !approvedOrigins.has(finding.origin)) return []
        if (sourceOrigins.some(o => !provenanceAllowed(o))) return []
      } else {
        // Static-verified findings may reference approved origins or synthetic 'https://static-analysis.invalid'
        const nonSynthetic = sourceOrigins.filter(o => o !== 'https://static-analysis.invalid')
        if (nonSynthetic.some(o => !provenanceAllowed(o))) return []
      }
      if (finding.chainFactIds?.some(fid => taintedFactIds.has(fid))) return []
      if (!finding.evidenceIds.length && !(finding.exchangeIds?.length)) return []
      if (findingKind === 'multi_step_chain') {
        return [{ ...finding, findingKind, replaySpecId: replaySpecId ?? finding.replaySpecId }]
      }
      if (finding.evidenceIds.every(eid => currentEvidence.has(eid))) return [finding]
      const retained = retainedAccess.get(assetId)
      const check = finding.check
      if (!retained || checkId !== 'access-policy' || finding.status !== 'confirmed' || finding.origin !== retained.origin ||
        check?.id !== 'access-policy' || check.caseId !== caseId || finding.evidenceIds.length !== 2 ||
        !finding.evidenceIds.includes(retained.sourceId) || !finding.evidenceIds.includes(retained.receiptId)) return []
      const verified = retained.checks.find(item => item.caseId === caseId && item.status === 'gap')
      if (!verified || verified.observed !== check.observed || verified.expected !== check.expected) return []
      return [{ ...finding, evidenceIds: [retained.sourceId, retained.evidenceId] }]
    })

    const deduplicated = deduplicateChainFindings(results)
    const { findings: finalFindings } = collapseBaselineHeaderFindings(deduplicated)
    // v6 report contract: only runtime-confirmed items count; static/open-proof-gap items are
    // surfaced separately as advisories and can never become recall/precision TPs.
    const reportProvenance = buildProvenanceReport(finalFindings as (Finding & FindingProvenanceFields)[])

    const currentSteps = snapshot.chainSteps.filter(s => s.goalRevision === run.goalRevision)
    const chainStepsCompleted = currentSteps.filter(s => s.status === 'complete').length
    const chainStepsUntested = currentSteps.filter(s => ['pending', 'ready', 'running', 'blocked'].includes(s.status)).length
    const taintedSteps = currentSteps.filter(s => s.status === 'tainted')
    if (chainStepsUntested > 0) {
      gaps.push(`${chainStepsUntested} planned investigation ${chainStepsUntested === 1 ? 'step remained' : 'steps remained'} untested when this report was saved.`)
    }
    if (taintedSteps.length > 0) {
      gaps.push(`${taintedSteps.length} chain ${taintedSteps.length === 1 ? 'step was' : 'steps were'} omitted due to mid-run scope revocation.`)
    }
    if (!scope.length) gaps.push('No approved hosts in this report.')

    const threatModelEntries = snapshot.threatModel?.entries.filter(e => approvedOrigins.has(e.origin))
    const owaspCoverage = snapshot.coverageEntries
      .filter(c => c.goalRevision === run.goalRevision && approvedOrigins.has(c.origin))
      .map(c => ({
        origin: c.origin,
        category: c.category,
        status: c.status,
        summary: c.summary,
        ...(c.enforcingControl ? { enforcingControl: c.enforcingControl } : {}),
        ...(c.proofGapReason ? { proofGapReason: c.proofGapReason } : {}),
        ...(c.linkedFindingId ? { linkedFindingId: c.linkedFindingId } : {}),
      }))
    const openProofGaps = snapshot.openProofGaps
      .filter(c => approvedOrigins.has(c.origin))
      .map(c => ({
        origin: c.origin,
        category: c.category,
        summary: c.summary,
        proofGapReason: c.proofGapReason || c.summary,
      }))
    const includedFindingIds = new Set(finalFindings.map(f => f.id))
    const patchProposals: PatchProposalSummary[] = snapshot.patchProposals
      .filter(p => includedFindingIds.has(p.findingId))
      .map(p => ({
        id: p.id,
        findingId: p.findingId,
        repo: p.repo,
        status: p.status,
        callerCompatibility: p.callerCompatibility,
        diff: p.diff,
        codeLocations: p.codeLocations,
        reviewNotes: p.reviewNotes,
        dynamicRetestVerdict: p.dynamicRetestVerdict,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
      }))

    const body: ReportBody & ReportProvenanceSurface = {
      goal: run.goal,
      capabilityTier: run.capabilityTier,
      scope: scope.map(({ accessPolicy: _ap, ...asset }) => asset),
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      ...(selection ? { selectedChecks: selection } : {}),
      ...(threatModelEntries?.length ? { threatModel: threatModelEntries } : {}),
      ...(owaspCoverage.length ? { owaspCoverage } : {}),
      ...(openProofGaps.length ? { openProofGaps } : {}),
      ...(patchProposals.length ? { patchProposals } : {}),
      metrics: {
        turnsUsed: run.turnsUsed,
        requestsUsed: run.spentRequests,
        factsRecorded: validFactCount,
        chainStepsCompleted,
        chainStepsUntested,
        spentUsd: Number(run.spentUsd.toFixed(4)),
        spentTokens: run.spentTokens,
      },
      coverage,
      findings: finalFindings,
      provenanceCounts: reportProvenance.provenanceCounts,
      confirmedFindings: reportProvenance.confirmedFindings,
      advisories: reportProvenance.advisories,
      gaps,
    }

    const reportId = randomUUID()
    const version = (snapshot.reports[0]?.version ?? 0) + 1
    this.db.insert(tables.reports).values({ id: reportId, runId: run.id, partial, body, version, createdAt: Date.now() }).run()
    this.event(run.id, partial ? 'report.partial' : 'report.complete',
      partial ? 'Partial report created.' : 'Complete report created.',
      { reportId, version, phase: run.phase, status: run.status })
    return reportId
  }

  command(input: RunCommand, canUseModel = true) {
    return this.operate(input, () => {
      const run = this.run(input.runId)
      switch (input.action) {
        case 'discover':
          this.discover(run)
          break
        case 'scope':
          this.setScope(run, input)
          break
        case 'candidate': {
          if (run.phase === 'complete') throw new Error('Add the host to the project for the next run.')
          if (run.candidates.some(candidate => candidate.origin === input.candidate.origin)) {
            throw new Error('This host is already in the inventory.')
          }
          const asset = this.saveCandidate(run.projectId, input.candidate, false)
          const discovery = this.workerList(run.id).find(worker => worker.phase === 'discovery' && worker.assetId === null)
          const source = discovery && this.recordInventory(run, discovery, 'Candidate source', [asset])
          const candidate = source ? { ...asset, sourceEvidenceId: source.id } : asset
          this.updateRun(run.id, { candidates: [...run.candidates, candidate] })
          this.event(run.id, 'asset.candidate', 'Added a candidate host awaiting scope review.', {
            id: asset.id, origin: asset.origin, actorId: this.workspace.actorId, sourceEvidenceId: source?.id,
          })
          break
        }
        case 'revise':
          this.revise(run, input.goal)
          break
        case 'message': {
          // Mirror operator text onto the board (defaulting plain text to @coordinator) while
          // keeping the legacy coordinator thread fully functional for v2–v4 compatibility.
          try {
            const allowed = this.boardHandleAllowList(run.id)
            const parsed = parseBoardMentions(input.message).filter(handle => allowed.has(handle) || handle === 'all')
            const targets = parsed.length ? parsed : ['coordinator']
            this.postBoardMessage(run, {
              authorHandle: 'operator',
              authorRole: 'operator',
              kind: targets.length === 1 && targets[0] === 'coordinator' ? 'note' : 'handoff',
              body: input.message,
              mentions: targets,
            })
          } catch {
            // Board mirroring is advisory; legacy operator messaging must never regress.
          }
          const questionId = this.message(run.id, run.coordinatorId, 'operator', input.message)
          this.event(run.id, 'coordinator.message', 'Coordinator message received.')
          if (run.status !== 'running') {
            const workers = this.workerList(run.id)
            const history = workerHistory(run, workers)
            const count = workers.filter(worker => worker.status === 'complete' && !history.has(worker.id)).length
            const complete = count === 1 ? '1 assignment is complete.' : `${count} assignments are complete.`
            this.message(run.id, run.coordinatorId, 'guardian',
              `The run is ${run.status}. ${complete} See Workflow for the next available action.`, questionId)
          } else if (!canUseModel) {
            this.message(run.id, run.coordinatorId, 'guardian',
              'This run needs a configured model profile. Open Settings to add a model profile.', questionId)
          }
          break
        }
        case 'board_post': {
          const allowed = this.boardHandleAllowList(run.id)
          const parsed = [...new Set((input.mentions ?? parseBoardMentions(input.body))
            .map(handle => normalizeBoardHandle(handle))
            .filter((handle): handle is string => Boolean(handle)))]
          const mentions = parsed.filter(handle => allowed.has(handle) || handle === 'all')
          const rejected = parsed.filter(handle => !allowed.has(handle) && handle !== 'all')
          if (rejected.length) throw new Error(`Cannot mention unknown board handle @${rejected[0]}.`)
          this.postBoardMessage(run, {
            authorHandle: 'operator',
            authorRole: 'operator',
            kind: input.kind ?? (mentions.some(handle => handle !== 'coordinator') ? 'handoff' : 'note'),
            body: input.body,
            mentions,
            replyToSeq: input.replyToSeq ?? null,
          })
          break
        }
        case 'retire_member': {
          const member = this.boardMember(run.id, input.handle)
          if (!member) throw new Error('Board member not found.')
          if (member.role === 'coordinator') throw new Error('The coordinator cannot be retired.')
          this.retireBoardMember(run, member.handle, 'Retired by operator.')
          break
        }
        case 'inject_hint': {
          if (run.phase === 'complete') throw new Error('Cannot inject a hint into a completed run.')
          const cleanHint = redact(input.hint)
          const targetAsset = input.targetAssetId
            ? run.candidates.find(c => c.id === input.targetAssetId && run.approved.includes(c.id))
            : run.candidates.find(c => run.approved.includes(c.id))
          this.message(run.id, run.coordinatorId, 'operator', `Steering hint: ${cleanHint}`)
          if (targetAsset) {
            this.addChainStep(run, {
              title: `Operator hint · ${new URL(targetAsset.origin).hostname}`,
              hypothesis: cleanHint,
              category: 'misconfig-exposure',
              priority: 95,
              targetAssetIds: [targetAsset.id],
              sourceOrigins: [targetAsset.origin],
            })
          }
          this.event(run.id, 'hint.injected', 'Operator steering hint queued for the planner.', {
            hint: cleanHint, targetAssetId: targetAsset?.id ?? null,
          })
          break
        }
        case 'decide_approval':
          this.decideApproval(run, input.approvalId, input.decision)
          break
        case 'set_approval_policy':
          this.setApprovalPolicy(run, input.approvalPolicy)
          break
        case 'approve_similar_endpoint':
          this.approveSimilarEndpoint(run, input.approvalId)
          break
        case 'approve_all_pending':
          this.approveAllPending(run)
          break
        case 'cancel_step': {
          const step = this.db.select().from(tables.chainSteps).where(and(
            eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.id, input.stepId),
          )).get()
          if (!step) throw new Error('Chain step not found.')
          this.updateChainStep(step.id, { status: 'canceled', assignedWorkerId: null })
          if (step.assignedWorkerId) {
            this.updateWorker(step.assignedWorkerId, { status: 'canceled', outcome: 'Canceled by operator.', lease: null, leaseExpiresAt: null })
          }
          this.event(run.id, 'chain_step.canceled', `Canceled step #${step.seq}: ${step.title}`, { stepId: step.id })
          break
        }
        case 'raise_budget': {
          if (['complete', 'stopped', 'failed'].includes(run.status)) {
            throw new Error('Cannot revise budget after a run has ended.')
          }
          const patch: Partial<Run> = {}
          if (input.budgetUsd !== undefined) {
            if (input.budgetUsd <= run.spentUsd) throw new Error('New USD budget must exceed current spend.')
            patch.budgetUsd = input.budgetUsd
          }
          if (input.budgetRequests !== undefined) {
            if (input.budgetRequests !== 0 && input.budgetRequests <= run.spentRequests) {
              throw new Error('New request cap must be 0 (unlimited) or exceed current requests used.')
            }
            patch.budgetRequests = input.budgetRequests
          }
          if (input.maxRpsPerOrigin !== undefined) {
            patch.maxRpsPerOrigin = input.maxRpsPerOrigin
          }
          if (Object.keys(patch).length > 0) {
            this.updateRun(run.id, patch)
          }
          const updated = this.run(run.id)
          const stillExceeded = updated.spentUsd >= updated.budgetUsd ||
            (updated.budgetRequests > 0 && updated.spentRequests >= updated.budgetRequests)
          const resumed = Boolean(
            input.resume &&
            !stillExceeded &&
            (run.status === 'budget_paused' || run.status === 'paused'),
          )
          if (resumed) {
            this.setStatus(updated, 'running')
          }
          this.event(run.id, 'budget.raised', 'Run budget updated.', { ...patch, resumed })
          break
        }
        case 'retest_finding': {
          const row = this.db.select().from(tables.findings).where(and(
            eq(tables.findings.runId, run.id), eq(tables.findings.id, input.findingId),
          )).get()
          if (!row) throw new Error('Finding not found.')
          if (!row.replaySpecId) throw new Error('Only findings with a Declarative Replay Spec support one-click Verify Fix retest.')
          const specRow = this.getReplaySpec(run.id, row.replaySpecId)
          const approvedOrigins = new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
          const retestPolicy = this.scopePolicy(run)
          if (specRow.sourceOrigins.some(o =>
            !approvedOrigins.has(o) && !isProvenanceOriginAllowed(retestPolicy, o))) {
            throw new Error('Cannot retest because one or more origins in this replay spec are no longer in approved scope.')
          }
          const asset = run.candidates.find(c => c.id === row.assetId)
          const worker = this.makeWorker(run, 'retest', asset, `Verify Fix · ${row.finding.title.slice(0, 80)}`,
            `Re-run declarative replay spec ${specRow.id} to verify whether "${row.finding.title}" is fixed.`, {
              stepId: row.id,
              sourceOrigins: specRow.sourceOrigins,
            })
          this.event(run.id, 'retest.queued', `Queued Verify Fix retest for "${row.finding.title}".`, {
            findingId: row.id, replaySpecId: specRow.id, assignmentId: worker.id,
          })
          break
        }
        case 'pause':
          if (run.status !== 'running') throw new Error('Only running work can be paused.')
          this.setStatus(run, 'paused')
          this.event(run.id, 'run.paused', 'Run paused.')
          break
        case 'stop':
          if (['complete', 'stopped'].includes(run.status)) throw new Error('This run has already ended.')
          this.setStatus(run, 'stopped')
          this.writeReport(this.run(run.id), true)
          break
        case 'resume':
          if (!['paused', 'budget_paused', 'stopped', 'failed'].includes(run.status)) {
            throw new Error('This run is not paused or stopped.')
          }
          if (run.status === 'budget_paused' && (run.spentUsd >= run.budgetUsd || (run.budgetRequests > 0 && run.spentRequests >= run.budgetRequests))) {
            throw new Error('Raise the run budget before resuming a budget-paused run.')
          }
          this.setStatus(run, ['consent', 'review'].includes(run.phase) ? 'waiting' : 'running')
          this.event(run.id, 'run.resumed', 'Run resumed.')
          break
      }
      return { id: run.id }
    })
  }

  // --- v4 Application State Graph, Second-Order Canaries, Lab Telemetry & Benchmarks ---

  upsertEndpoint(input: {
    runId: string
    scopeRevision?: number
    origin: string
    method: string
    pathTemplate: string
    source: EndpointSource
    framework?: string | null
    authRequirement?: string | null
    ownershipGuard?: string | null
    sinkKinds?: readonly string[]
    testedClasses?: readonly string[]
    coveragePct?: number | null
    riskScore?: number
    codeLocation?: CodeLocation | null
  }): EndpointRow {
    const method = input.method.trim().toUpperCase()
    const pathTemplate = input.pathTemplate.trim()
    const now = Date.now()
    const clampRisk = (v: number) =>
      Number.isFinite(v)
        ? Math.max(0, Math.min(100, Math.round(v)))
        : v === Infinity ? 100 : v === -Infinity ? 0 : 50
    const clampCoverage = (v: number | null | undefined) =>
      typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(100, v)) : null

    return this.transaction(() => {
      const resolvedScopeRev = typeof input.scopeRevision === 'number' && Number.isFinite(input.scopeRevision)
        ? Math.max(0, Math.round(input.scopeRevision))
        : (this.db.select({ scopeRevision: tables.runs.scopeRevision }).from(tables.runs).where(eq(tables.runs.id, input.runId)).get()?.scopeRevision ?? 1)
      const existing = this.db.select().from(tables.endpoints).where(and(
        eq(tables.endpoints.runId, input.runId),
        eq(tables.endpoints.origin, input.origin),
        eq(tables.endpoints.method, method),
        eq(tables.endpoints.pathTemplate, pathTemplate),
      )).get()
      if (existing) {
        const nextSinks = [...new Set([...existing.sinkKinds, ...(input.sinkKinds ?? [])])]
        const nextTested = [...new Set([...existing.testedClasses, ...(input.testedClasses ?? [])])]
        const nextRisk = clampRisk(Math.max(existing.riskScore, input.riskScore ?? existing.riskScore))
        const nextCov = input.coveragePct !== undefined ? clampCoverage(input.coveragePct) : existing.coveragePct
        return this.db.update(tables.endpoints).set({
          scopeRevision: Math.max(existing.scopeRevision, resolvedScopeRev),
          framework: input.framework ?? existing.framework,
          authRequirement: input.authRequirement ?? existing.authRequirement,
          ownershipGuard: input.ownershipGuard ?? existing.ownershipGuard,
          sinkKinds: nextSinks,
          testedClasses: nextTested,
          coveragePct: nextCov,
          riskScore: nextRisk,
          codeLocation: input.codeLocation ?? existing.codeLocation,
          updatedAt: now,
        }).where(eq(tables.endpoints.id, existing.id)).returning().get()!
      }
      return this.db.insert(tables.endpoints).values({
        id: randomUUID(),
        runId: input.runId,
        scopeRevision: resolvedScopeRev,
        origin: input.origin,
        method,
        pathTemplate,
        source: input.source,
        framework: input.framework ?? null,
        authRequirement: input.authRequirement ?? null,
        ownershipGuard: input.ownershipGuard ?? null,
        sinkKinds: [...new Set(input.sinkKinds ?? [])],
        testedClasses: [...new Set(input.testedClasses ?? [])],
        coveragePct: clampCoverage(input.coveragePct),
        riskScore: clampRisk(input.riskScore ?? 50),
        codeLocation: input.codeLocation ?? null,
        createdAt: now,
        updatedAt: now,
      }).returning().get()
    }, { behavior: 'immediate' })
  }

  listEndpoints(runId: string, filter?: {
    origin?: string
    method?: string
    source?: EndpointSource
    untestedClass?: string
    minRiskScore?: number
    maxCoveragePct?: number
    orderBy?: 'risk' | 'coverage' | 'updated'
    limit?: number
    offset?: number
  }): EndpointRow[] {
    const conditions = [eq(tables.endpoints.runId, runId)]
    if (filter?.origin) conditions.push(eq(tables.endpoints.origin, filter.origin))
    if (filter?.method) conditions.push(eq(tables.endpoints.method, filter.method.trim().toUpperCase()))
    if (filter?.source) conditions.push(eq(tables.endpoints.source, filter.source))
    if (filter?.untestedClass) {
      conditions.push(sql`NOT EXISTS (
        SELECT 1 FROM json_each(${tables.endpoints.testedClasses}) WHERE json_each.value = ${filter.untestedClass}
      )`)
    }
    if (filter?.minRiskScore !== undefined) {
      conditions.push(sql`${tables.endpoints.riskScore} >= ${filter.minRiskScore}`)
    }
    if (filter?.maxCoveragePct !== undefined) {
      conditions.push(sql`coalesce(${tables.endpoints.coveragePct}, 0) <= ${filter.maxCoveragePct}`)
    }

    const orderBy = filter?.orderBy ?? 'risk'
    const order = orderBy === 'coverage'
      ? [sql`coalesce(${tables.endpoints.coveragePct}, -1) asc`, desc(tables.endpoints.riskScore), asc(tables.endpoints.id)]
      : orderBy === 'updated'
        ? [desc(tables.endpoints.updatedAt), asc(tables.endpoints.id)]
        : [desc(tables.endpoints.riskScore), sql`coalesce(${tables.endpoints.coveragePct}, 0) asc`, asc(tables.endpoints.id)]

    const limit = resolvePageLimit(filter?.limit, 500)
    const offset = resolvePageOffset(filter?.offset)
    return this.db.select().from(tables.endpoints).where(and(...conditions))
      .orderBy(...order).limit(limit).offset(offset).all()
  }

  updateEndpointCoverage(
    endpointId: string,
    coveragePct: number | null,
    testedClasses?: readonly string[],
  ): EndpointRow {
    const existing = this.db.select().from(tables.endpoints).where(eq(tables.endpoints.id, endpointId)).get()
    if (!existing) throw new Error('Endpoint not found.')
    const nextCov = typeof coveragePct === 'number' && Number.isFinite(coveragePct)
      ? Math.max(0, Math.min(100, coveragePct))
      : coveragePct === null ? null : existing.coveragePct
    const nextTested = testedClasses
      ? [...new Set([...existing.testedClasses, ...testedClasses])]
      : existing.testedClasses
    return this.db.update(tables.endpoints).set({
      coveragePct: nextCov,
      testedClasses: nextTested,
      updatedAt: Date.now(),
    }).where(eq(tables.endpoints.id, endpointId)).returning().get()!
  }

  upsertEndpointParam(input: {
    runId: string
    endpointId: string
    name: string
    location: ParamLocation
    inferredType?: string | null
    isCsrf?: boolean
    isObjectId?: boolean
    source: string
  }): EndpointParamRow {
    const now = Date.now()
    return this.transaction(() => {
      const existing = this.db.select().from(tables.endpointParams).where(and(
        eq(tables.endpointParams.endpointId, input.endpointId),
        eq(tables.endpointParams.name, input.name),
        eq(tables.endpointParams.location, input.location),
      )).get()
      if (existing) {
        return this.db.update(tables.endpointParams).set({
          inferredType: input.inferredType ?? existing.inferredType,
          isCsrf: existing.isCsrf || Boolean(input.isCsrf),
          isObjectId: existing.isObjectId || Boolean(input.isObjectId),
          source: input.source,
        }).where(eq(tables.endpointParams.id, existing.id)).returning().get()!
      }
      return this.db.insert(tables.endpointParams).values({
        id: randomUUID(),
        runId: input.runId,
        endpointId: input.endpointId,
        name: input.name,
        location: input.location,
        inferredType: input.inferredType ?? null,
        isCsrf: Boolean(input.isCsrf),
        isObjectId: Boolean(input.isObjectId),
        source: input.source,
        createdAt: now,
      }).returning().get()
    }, { behavior: 'immediate' })
  }

  listEndpointParams(runId: string, endpointId?: string): EndpointParamRow[] {
    const where = endpointId
      ? and(eq(tables.endpointParams.runId, runId), eq(tables.endpointParams.endpointId, endpointId))
      : eq(tables.endpointParams.runId, runId)
    return this.db.select().from(tables.endpointParams).where(where)
      .orderBy(asc(tables.endpointParams.createdAt)).all()
  }

  recordApiDependency(input: {
    runId: string
    producerEndpointId: string
    consumerEndpointId: string
    resourceKey: string
    sampleResourceIdHash?: string | null
    personaHandle?: string | null
    observedTransitions?: readonly string[]
    testedBola?: boolean
  }): ApiDependencyRow {
    const safeHash = input.sampleResourceIdHash ? redact(input.sampleResourceIdHash).slice(0, 64) : null
    const now = Date.now()
    return this.transaction(() => {
      const existing = this.db.select().from(tables.apiDependencies).where(and(
        eq(tables.apiDependencies.runId, input.runId),
        eq(tables.apiDependencies.producerEndpointId, input.producerEndpointId),
        eq(tables.apiDependencies.consumerEndpointId, input.consumerEndpointId),
        eq(tables.apiDependencies.resourceKey, input.resourceKey),
      )).get()
      if (existing) {
        const mergedTransitions = [...new Set([...existing.observedTransitions, ...(input.observedTransitions ?? [])])]
        return this.db.update(tables.apiDependencies).set({
          sampleResourceIdHash: safeHash ?? existing.sampleResourceIdHash,
          personaHandle: input.personaHandle ?? existing.personaHandle,
          observedTransitions: mergedTransitions,
          testedBola: existing.testedBola || Boolean(input.testedBola),
        }).where(eq(tables.apiDependencies.id, existing.id)).returning().get()!
      }
      return this.db.insert(tables.apiDependencies).values({
        id: randomUUID(),
        runId: input.runId,
        producerEndpointId: input.producerEndpointId,
        consumerEndpointId: input.consumerEndpointId,
        resourceKey: input.resourceKey,
        sampleResourceIdHash: safeHash,
        personaHandle: input.personaHandle ?? null,
        observedTransitions: [...new Set(input.observedTransitions ?? [])],
        testedBola: Boolean(input.testedBola),
        createdAt: now,
      }).returning().get()
    }, { behavior: 'immediate' })
  }

  listApiDependencies(runId: string): ApiDependencyRow[] {
    return this.db.select().from(tables.apiDependencies).where(eq(tables.apiDependencies.runId, runId))
      .orderBy(asc(tables.apiDependencies.createdAt)).all()
  }

  markApiDependencyTestedBola(id: string): ApiDependencyRow {
    const updated = this.db.update(tables.apiDependencies).set({ testedBola: true })
      .where(eq(tables.apiDependencies.id, id)).returning().get()
    if (!updated) throw new Error('API dependency not found.')
    return updated
  }

  recordResourceSample(input: {
    runId: string
    ownerPersona: string
    resourceKey: string
    resourceId: string
    origin: string
    endpoint: string
    method: string
    mediaType?: string | null
    authenticated?: boolean
    /**
     * Collection the identifier belongs to. Defaults to the endpoint's collection so
     * `/invoices` and `/orders` keep separate ids for the same `id` field name.
     */
    collectionPath?: string
  }): ResourceSampleRow | null {
    const rawId = input.resourceId.trim()
    if (!rawId || rawId.length > 128) return null
    const redacted = redact(rawId)
    // Never persist credentials or token-like values as BOLA replay samples.
    const sample = redacted === rawId && isOpaqueResourceId(rawId, { keyed: true }) ? rawId : '[redacted]'
    const resourceKey = input.resourceKey.trim().slice(0, 128) || 'id'
    const origin = input.origin.trim()
    const endpoint = redact(input.endpoint).slice(0, 2048)
    const method = input.method.trim().toUpperCase() || 'GET'
    const collectionRaw = (input.collectionPath ?? collectionPathFor(endpoint)).split('?')[0]!.split('#')[0]!.trim()
    const collectionPath = collectionRaw
      ? (collectionRaw.startsWith('/') ? collectionRaw : `/${collectionRaw}`).slice(0, 512)
      : ''
    const now = Date.now()
    return this.transaction(() => {
      const existing = this.client.prepare(
        `SELECT id, resource_id AS resourceId, collection_path AS collectionPath, endpoint, method,
           media_type AS mediaType, authenticated, created_at AS createdAt FROM resource_samples
         WHERE run_id = ? AND owner_persona = ? AND origin = ? AND collection_path = ? AND resource_key = ? LIMIT 1`,
      ).get(input.runId, input.ownerPersona, origin, collectionPath, resourceKey) as {
        id: string
        resourceId: string
        collectionPath: string
        endpoint: string
        method: string
        mediaType: string | null
        authenticated: number
        createdAt: number
      } | undefined
      if (existing) {
        if (sample === '[redacted]' && existing.resourceId !== '[redacted]') {
          return {
            id: existing.id,
            runId: input.runId,
            ownerPersona: input.ownerPersona,
            resourceKey,
            collectionPath,
            resourceId: existing.resourceId,
            origin,
            endpoint: existing.endpoint,
            method: existing.method,
            mediaType: existing.mediaType,
            authenticated: Boolean(existing.authenticated),
            createdAt: existing.createdAt,
            updatedAt: existing.createdAt,
          }
        }
        this.client.prepare(
          `UPDATE resource_samples SET resource_id = ?, endpoint = ?, method = ?, media_type = ?,
             authenticated = ?, updated_at = ? WHERE id = ?`,
        ).run(sample, endpoint, method, input.mediaType ?? null, input.authenticated ? 1 : 0, now, existing.id)
        return {
          id: existing.id,
          runId: input.runId,
          ownerPersona: input.ownerPersona,
          resourceKey,
          collectionPath,
          resourceId: sample,
          origin,
          endpoint,
          method,
          mediaType: input.mediaType ?? null,
          authenticated: Boolean(input.authenticated),
          createdAt: existing.createdAt,
          updatedAt: now,
        }
      }
      const id = randomUUID()
      this.client.prepare(
        `INSERT INTO resource_samples (
           id, run_id, owner_persona, resource_key, collection_path, resource_id, origin, endpoint, method,
           media_type, authenticated, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(id, input.runId, input.ownerPersona, resourceKey, collectionPath, sample, origin, endpoint, method,
        input.mediaType ?? null, input.authenticated ? 1 : 0, now, now)
      return {
        id,
        runId: input.runId,
        ownerPersona: input.ownerPersona,
        resourceKey,
        collectionPath,
        resourceId: sample,
        origin,
        endpoint,
        method,
        mediaType: input.mediaType ?? null,
        authenticated: Boolean(input.authenticated),
        createdAt: now,
        updatedAt: now,
      }
    }, { behavior: 'immediate' })
  }

  listResourceSamples(runId: string): ResourceSampleRow[] {
    const rows = this.client.prepare(
      `SELECT id, run_id AS runId, owner_persona AS ownerPersona, resource_key AS resourceKey,
         collection_path AS collectionPath, resource_id AS resourceId, origin, endpoint, method,
         media_type AS mediaType, authenticated, created_at AS createdAt, updated_at AS updatedAt
       FROM resource_samples WHERE run_id = ?
       ORDER BY collection_path ASC, resource_key ASC, created_at ASC`,
    ).all(runId) as Array<Omit<ResourceSampleRow, 'authenticated'> & { authenticated: number }>
    return rows.map(row => ({ ...row, authenticated: Boolean(row.authenticated) }))
  }

  /**
   * Persist harvested samples plus producer -> consumer `api_dependencies` edges for one exchange.
   * Called from Phase-0 HTTP recon, `crawlStateGraph` and worker exchanges (including unauth).
   */
  trackExchangeResources(input: {
    runId: string
    scopeRevision?: number
    exchange: ResourceHarvestExchange
    source?: EndpointSource
  }): ExtractedResourceRef[] {
    const ex = input.exchange
    const refs = extractResourceRefsFromExchange(ex)
    if (!refs.length) return []
    const ownerPersona = ex.personaHandle?.trim() || 'anonymous'
    const source = input.source ?? 'surface_probe'
    const origin = ex.origin
    const producerPath = normalizeEndpointTemplate(ex.pathAndQuery.split('?')[0] || '/')
    let producerEp: EndpointRow | null = null
    try {
      producerEp = this.upsertEndpoint({
        runId: input.runId,
        ...(typeof input.scopeRevision === 'number' ? { scopeRevision: input.scopeRevision } : {}),
        origin,
        method: ex.method.toUpperCase(),
        pathTemplate: producerPath,
        source,
      })
    } catch { /* best-effort graph edge inference */ }

    for (const ref of refs) {
      const resourceKey = ref.field.replace(/^(?:path|href|location|key):/, '') || 'id'
      try {
        this.recordResourceSample({
          runId: input.runId,
          ownerPersona,
          resourceKey,
          collectionPath: collectionPathFor(ref.endpoint),
          resourceId: ref.resourceId,
          origin,
          endpoint: ref.endpoint,
          method: ref.method,
          mediaType: ex.mediaType,
          authenticated: Boolean(ex.personaHandle),
        })
      } catch { /* sample persistence is additive/best-effort */ }
      if (!producerEp) continue
      try {
        const sampleHash = `sha256:${createHash('sha256').update(ref.resourceId).digest('hex').slice(0, 16)}`
        const originEndpoints = this.listEndpoints(input.runId, { origin })
        const basePrefix = producerPath.replace(/\/+$/, '')
        for (const cand of originEndpoints) {
          if (cand.id === producerEp.id) continue
          const tmpl = cand.pathTemplate
          const extendsBase = Boolean(basePrefix && basePrefix !== '/' &&
            tmpl.startsWith(`${basePrefix}/`) &&
            /(?::[a-zA-Z0-9_-]+|\{[a-zA-Z0-9_-]+\})/.test(tmpl.slice(basePrefix.length)))
          const matchesKey = Boolean(ref.field && !/^(?:path|href|location|key):/.test(ref.field) &&
            (tmpl.includes(`:${ref.field}`) || tmpl.includes(`{${ref.field}}`)))
          if (!extendsBase && !matchesKey) continue
          this.recordApiDependency({
            runId: input.runId,
            producerEndpointId: producerEp.id,
            consumerEndpointId: cand.id,
            resourceKey,
            sampleResourceIdHash: sampleHash,
            personaHandle: ex.personaHandle ?? null,
          })
        }
      } catch { /* best-effort dependency edge inference */ }
    }
    return refs
  }

  /**
   * Record one exercised request against its normalized route template and recompute real coverage.
   * Four distinct tested classes saturate an endpoint at 100%.
   */
  noteEndpointProbe(input: {
    runId: string
    scopeRevision?: number
    origin: string
    method: string
    pathAndQuery: string
    testedClass: string
    source?: EndpointSource
    riskScore?: number
  }): EndpointRow | null {
    if (RESOURCE_STATIC_ASSET_RE.test(input.pathAndQuery)) return null
    try {
      const pathTemplate = normalizeEndpointTemplate(input.pathAndQuery.split('?')[0] || '/')
      const ep = this.upsertEndpoint({
        runId: input.runId,
        ...(typeof input.scopeRevision === 'number' ? { scopeRevision: input.scopeRevision } : {}),
        origin: input.origin,
        method: input.method,
        pathTemplate,
        source: input.source ?? 'surface_probe',
        ...(typeof input.riskScore === 'number' ? { riskScore: input.riskScore } : {}),
      })
      const classes = [...new Set([...ep.testedClasses, input.testedClass])]
      const coveragePct = Math.min(100, classes.length * 25)
      return this.updateEndpointCoverage(ep.id, coveragePct, [input.testedClass])
    } catch {
      return null
    }
  }

  insertSecondOrderCanary(input: {
    runId: string
    assignmentId: string
    marker: string
    injectedOrigin: string
    injectedEndpoint: string
    injectedParam: string
    injectedPersona?: string | null
  }): SecondOrderCanaryRow {
    const existing = this.db.select().from(tables.secondOrderCanaries).where(
      eq(tables.secondOrderCanaries.marker, input.marker),
    ).get()
    if (existing) {
      if (existing.runId === input.runId) return existing
      throw new Error('Second-order canary marker collision across runs.')
    }
    return this.db.insert(tables.secondOrderCanaries).values({
      id: randomUUID(),
      runId: input.runId,
      assignmentId: input.assignmentId,
      marker: input.marker,
      injectedOrigin: input.injectedOrigin,
      injectedEndpoint: redact(input.injectedEndpoint),
      injectedParam: redact(input.injectedParam),
      injectedPersona: input.injectedPersona ?? null,
      surfacedOrigin: null,
      surfacedEndpoint: null,
      surfacedPersona: null,
      surfacedExchangeId: null,
      status: 'planted',
      createdAt: Date.now(),
      surfacedAt: null,
    }).returning().get()
  }

  markSecondOrderCanarySurfaced(
    id: string,
    details: {
      surfacedOrigin: string
      surfacedEndpoint: string
      surfacedPersona?: string | null
      surfacedExchangeId?: string | null
      status?: 'surfaced' | 'verified'
    },
  ): SecondOrderCanaryRow {
    const updated = this.db.update(tables.secondOrderCanaries).set({
      surfacedOrigin: details.surfacedOrigin,
      surfacedEndpoint: redact(details.surfacedEndpoint),
      surfacedPersona: details.surfacedPersona ?? null,
      surfacedExchangeId: details.surfacedExchangeId ?? null,
      status: details.status ?? 'surfaced',
      surfacedAt: Date.now(),
    }).where(eq(tables.secondOrderCanaries.id, id)).returning().get()
    if (!updated) throw new Error('Second-order canary not found.')
    this.event(updated.runId, 'second_order_canary.surfaced',
      `Second-order canary surfaced on ${updated.surfacedOrigin}${updated.surfacedEndpoint ?? ''}.`, {
        canaryId: updated.id,
        marker: updated.marker,
        injectedOrigin: updated.injectedOrigin,
        injectedEndpoint: updated.injectedEndpoint,
        surfacedOrigin: updated.surfacedOrigin,
        surfacedEndpoint: updated.surfacedEndpoint,
        surfacedPersona: updated.surfacedPersona,
        status: updated.status,
      })
    return updated
  }

  listSecondOrderCanaries(runId: string, status?: SecondOrderCanaryStatus): SecondOrderCanaryRow[] {
    const where = status
      ? and(eq(tables.secondOrderCanaries.runId, runId), eq(tables.secondOrderCanaries.status, status))
      : eq(tables.secondOrderCanaries.runId, runId)
    return this.db.select().from(tables.secondOrderCanaries).where(where)
      .orderBy(desc(tables.secondOrderCanaries.createdAt)).all()
  }

  insertLabTelemetry(input: {
    runId: string
    exchangeId: string
    traceId: string
    routesHit: readonly string[]
    newLinesCovered: number
    sinkEventsCount: number
    hasUnhandledException: boolean
    artifactId: string
  }): LabTelemetryRow {
    const cleanRoutes = [...new Set(input.routesHit.map(r => redact(r)))]
    const newLinesCovered = Number.isFinite(input.newLinesCovered) ? Math.max(0, Math.round(input.newLinesCovered)) : 0
    const sinkEventsCount = Number.isFinite(input.sinkEventsCount) ? Math.max(0, Math.round(input.sinkEventsCount)) : 0
    return this.db.insert(tables.labTelemetry).values({
      id: randomUUID(),
      runId: input.runId,
      exchangeId: input.exchangeId,
      traceId: input.traceId,
      routesHit: cleanRoutes,
      newLinesCovered,
      sinkEventsCount,
      hasUnhandledException: Boolean(input.hasUnhandledException),
      artifactId: input.artifactId,
      createdAt: Date.now(),
    }).onConflictDoUpdate({
      target: [tables.labTelemetry.runId, tables.labTelemetry.traceId],
      set: {
        exchangeId: input.exchangeId,
        routesHit: cleanRoutes,
        newLinesCovered,
        sinkEventsCount,
        hasUnhandledException: Boolean(input.hasUnhandledException),
        artifactId: input.artifactId,
      },
    }).returning().get()
  }

  listLabTelemetry(runId: string): LabTelemetryRow[] {
    return this.db.select().from(tables.labTelemetry).where(eq(tables.labTelemetry.runId, runId))
      .orderBy(desc(tables.labTelemetry.createdAt)).all()
  }

  insertBenchmarkRun(input: {
    id?: string
    suite: string
    gitSha: string
    modelRoutingConfig?: Record<string, unknown>
    targetsTotal: number
    confirmedCount: number
    falsePositiveCount: number
    funnelCounts: BenchmarkFunnel
    failureTaxonomy: Record<FailureTaxonomyBucket, number>
    totalCostUsd?: number
    durationMs?: number
  }): BenchmarkRunRow {
    const cleanRouting = input.modelRoutingConfig
      ? redactJsonValue(input.modelRoutingConfig)
      : {}
    const nonNegInt = (v: number | undefined) =>
      typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.round(v)) : 0
    const nonNegNum = (v: number | undefined) =>
      typeof v === 'number' && Number.isFinite(v) ? Math.max(0, v) : 0
    return this.db.insert(tables.benchmarkRuns).values({
      id: input.id ?? randomUUID(),
      suite: input.suite,
      gitSha: input.gitSha,
      modelRoutingConfig: cleanRouting,
      targetsTotal: nonNegInt(input.targetsTotal),
      confirmedCount: nonNegInt(input.confirmedCount),
      falsePositiveCount: nonNegInt(input.falsePositiveCount),
      funnelCounts: input.funnelCounts,
      failureTaxonomy: input.failureTaxonomy,
      totalCostUsd: nonNegNum(input.totalCostUsd),
      durationMs: nonNegInt(input.durationMs),
      createdAt: Date.now(),
    }).returning().get()
  }

  listBenchmarkRuns(suite?: string, limit = 50): BenchmarkRunRow[] {
    const capped = typeof limit === 'number' && Number.isFinite(limit)
      ? Math.min(Math.max(1, Math.round(limit)), 500)
      : 50
    const query = suite
      ? this.db.select().from(tables.benchmarkRuns).where(eq(tables.benchmarkRuns.suite, suite))
      : this.db.select().from(tables.benchmarkRuns)
    return query.orderBy(desc(tables.benchmarkRuns.createdAt)).limit(capped).all()
  }

  getLatestBenchmarkRun(suite: string): BenchmarkRunRow | null {
    return this.db.select().from(tables.benchmarkRuns).where(eq(tables.benchmarkRuns.suite, suite))
      .orderBy(desc(tables.benchmarkRuns.createdAt)).limit(1).get() ?? null
  }

  updateRunPhase0Completed(runId: string, ts = Date.now()): Run {
    const updated = this.updateRun(runId, { phase0CompletedAt: ts })
    this.event(runId, 'phase0.completed', 'Phase-0 deterministic surface mapping completed.', {
      phase0CompletedAt: ts,
    })
    return updated
  }

  updateRunDynamicStepBudget(runId: string, budget: number | null): Run {
    if (budget === null) return this.updateRun(runId, { dynamicStepBudget: null })
    if (!Number.isFinite(budget)) {
      if (budget === Infinity) return this.updateRun(runId, { dynamicStepBudget: 300 })
      if (budget === -Infinity) return this.updateRun(runId, { dynamicStepBudget: 1 })
      return this.run(runId)
    }
    const clamped = Math.max(1, Math.min(300, Math.round(budget)))
    return this.updateRun(runId, { dynamicStepBudget: clamped })
  }

  // --- v7 M4: Per-tenant isolation, append-only audit log, and TTL purge ---

  private normalizeTenantId(tenantId: string): string {
    const trimmed = tenantId.trim()
    if (!trimmed || trimmed.length > 128 || /[\r\n\0]/.test(trimmed)) {
      throw new Error('Invalid tenantId: must be a non-empty identifier <= 128 characters.')
    }
    return trimmed
  }

  /** Assign a project (and its existing runs) to a tenant namespace. */
  setProjectTenant(projectId: string, tenantId: string): void {
    const normalized = this.normalizeTenantId(tenantId)
    this.project(projectId)
    this.client.prepare('UPDATE projects SET tenant_id = ? WHERE id = ?').run(normalized, projectId)
    this.client.prepare('UPDATE runs SET tenant_id = ? WHERE project_id = ?').run(normalized, projectId)
  }

  getProjectTenant(projectId: string): string {
    const row = this.client.prepare('SELECT tenant_id FROM projects WHERE id = ?').get(projectId) as
      | { tenant_id: string }
      | undefined
    if (!row) throw new Error(`Unknown project ${projectId}`)
    return row.tenant_id || 'default'
  }

  /** Assign a specific run to a tenant namespace. */
  setRunTenant(runId: string, tenantId: string): void {
    const normalized = this.normalizeTenantId(tenantId)
    this.run(runId)
    this.client.prepare('UPDATE runs SET tenant_id = ? WHERE id = ?').run(normalized, runId)
  }

  /** Resolve a run's effective tenant (inheriting its parent project tenant if unset). */
  getRunTenant(runId: string): string {
    const row = this.client.prepare(
      'SELECT r.tenant_id AS run_tenant, p.tenant_id AS project_tenant FROM runs r LEFT JOIN projects p ON p.id = r.project_id WHERE r.id = ?',
    ).get(runId) as { run_tenant: string | null; project_tenant: string | null } | undefined
    if (!row) throw new Error(`Unknown run ${runId}`)
    if (row.run_tenant && row.run_tenant !== 'default') return row.run_tenant
    if (row.project_tenant && row.project_tenant !== 'default') return row.project_tenant
    return row.run_tenant || 'default'
  }

  /** Fail closed if `tenantId` does not own `runId`, recording a denied audit entry. */
  assertRunTenantAccess(runId: string, tenantId: string, actor = 'operator'): void {
    const requested = this.normalizeTenantId(tenantId)
    const owner = this.getRunTenant(runId)
    if (owner !== requested) {
      this.appendTenantAuditLog({
        tenantId: requested,
        runId,
        actor,
        action: 'tenant.access_denied',
        resourceKind: 'run',
        resourceId: runId,
        outcome: 'denied',
        detail: { reason: 'Cross-tenant run access rejected.' },
      })
      throw new TenantIsolationError(requested, owner, runId)
    }
  }

  /** List projects strictly belonging to `tenantId` (zero cross-tenant visibility). */
  listProjectsForTenant(tenantId: string): Project[] {
    const normalized = this.normalizeTenantId(tenantId)
    const rows = this.client.prepare(
      'SELECT id FROM projects WHERE tenant_id = ? ORDER BY created_at DESC',
    ).all(normalized) as Array<{ id: string }>
    return rows.map(r => this.project(r.id))
  }

  /** List runs strictly belonging to `tenantId` (zero cross-tenant visibility). */
  listRunsForTenant(tenantId: string): Run[] {
    const normalized = this.normalizeTenantId(tenantId)
    const rows = this.client.prepare(
      `SELECT r.id FROM runs r
       LEFT JOIN projects p ON p.id = r.project_id
       WHERE r.tenant_id = ?
          OR (r.tenant_id = 'default' AND p.tenant_id = ?)
       ORDER BY r.created_at DESC`,
    ).all(normalized, normalized) as Array<{ id: string }>
    return rows.map(r => this.run(r.id))
  }

  /** Append a hash-chained, PII/secret-scrubbed entry to the immutable `tenant_audit_log`. */
  appendTenantAuditLog(input: AppendTenantAuditLogInput): TenantAuditLogEntry {
    const tenantId = this.normalizeTenantId(input.tenantId)
    const now = input.now ?? Date.now()
    const id = randomUUID()
    const actor = (input.actor || 'system').trim().slice(0, 128)
    const action = (input.action || 'unknown').trim().slice(0, 128)
    const resourceKind = (input.resourceKind || 'system').trim().slice(0, 64)
    const resourceId = input.resourceId ?? null
    const runId = input.runId ?? null
    const scrubbedDetail = redactZdrJsonValue(input.detail ?? {}) as Record<string, unknown>
    const detailJson = JSON.stringify(scrubbedDetail)

    const prevRow = this.client.prepare(
      'SELECT entry_hash FROM tenant_audit_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1',
    ).get(tenantId) as { entry_hash: string } | undefined
    const prevHash = prevRow?.entry_hash ?? 'GENESIS'
    const entryHash = computeTenantAuditHash({
      id,
      tenantId,
      runId,
      actor,
      action,
      resourceKind,
      resourceId,
      outcome: input.outcome,
      detailJson,
      prevHash,
      createdAt: now,
    })

    const inserted = this.client.prepare(
      `INSERT INTO tenant_audit_log
       (id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, tenantId, runId, actor, action, resourceKind, resourceId, input.outcome, detailJson, prevHash, entryHash, now)

    return {
      seq: Number(inserted.lastInsertRowid),
      id,
      tenantId,
      runId,
      actor,
      action,
      resourceKind,
      resourceId,
      outcome: input.outcome,
      detail: scrubbedDetail,
      prevHash,
      entryHash,
      createdAt: now,
    }
  }

  /** Query append-only audit log entries strictly scoped to `tenantId`. */
  listTenantAuditLog(
    tenantId: string,
    options: { runId?: string; limit?: number } = {},
  ): TenantAuditLogEntry[] {
    const normalized = this.normalizeTenantId(tenantId)
    const limit = Math.max(1, Math.min(1000, Math.trunc(options.limit ?? 200)))
    const rows = options.runId
      ? (this.client.prepare(
          'SELECT seq, id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at FROM tenant_audit_log WHERE tenant_id = ? AND run_id = ? ORDER BY seq ASC LIMIT ?',
        ).all(normalized, options.runId, limit) as unknown as RawTenantAuditRow[])
      : (this.client.prepare(
          'SELECT seq, id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at FROM tenant_audit_log WHERE tenant_id = ? ORDER BY seq ASC LIMIT ?',
        ).all(normalized, limit) as unknown as RawTenantAuditRow[])
    return rows.map(row => ({
      seq: row.seq,
      id: row.id,
      tenantId: row.tenant_id,
      runId: row.run_id,
      actor: row.actor,
      action: row.action,
      resourceKind: row.resource_kind,
      resourceId: row.resource_id,
      outcome: row.outcome as TenantAuditOutcome,
      detail: JSON.parse(row.detail) as Record<string, unknown>,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
      createdAt: row.created_at,
    }))
  }

  /** Verify the cryptographic hash chain of all audit log entries for `tenantId`. */
  verifyTenantAuditLogChain(tenantId: string): { valid: boolean; count: number; brokenAtSeq?: number } {
    const normalized = this.normalizeTenantId(tenantId)
    const rows = this.client.prepare(
      'SELECT seq, id, tenant_id, run_id, actor, action, resource_kind, resource_id, outcome, detail, prev_hash, entry_hash, created_at FROM tenant_audit_log WHERE tenant_id = ? ORDER BY seq ASC',
    ).all(normalized) as unknown as RawTenantAuditRow[]
    let expectedPrev = 'GENESIS'
    for (const row of rows) {
      if (row.prev_hash !== expectedPrev) {
        return { valid: false, count: rows.length, brokenAtSeq: row.seq }
      }
      const recomputed = computeTenantAuditHash({
        id: row.id,
        tenantId: row.tenant_id,
        runId: row.run_id,
        actor: row.actor,
        action: row.action,
        resourceKind: row.resource_kind,
        resourceId: row.resource_id,
        outcome: row.outcome,
        detailJson: row.detail,
        prevHash: row.prev_hash,
        createdAt: row.created_at,
      })
      if (recomputed !== row.entry_hash) {
        return { valid: false, count: rows.length, brokenAtSeq: row.seq }
      }
      expectedPrev = row.entry_hash
    }
    return { valid: true, count: rows.length }
  }

  /** Deterministically purge expired exchanges, artifacts, and temp files according to `policy`. */
  purgeArtifactsByTtl(policy: ArtifactTtlPolicy): ArtifactTtlPurgeResult {
    return purgeExpiredArtifacts(this, policy)
  }
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

interface RawTenantAuditRow {
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

function computeTenantAuditHash(fields: {
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
        'guardian.tenant-audit.v1',
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

export type StoreRunDetail = ReturnType<Store['runDetail']>

/** Best-effort file size (0 when absent). */
function safeFileSize(path: string): number {
  try {
    const info = lstatSync(path)
    return info.isFile() ? info.size : 0
  } catch {
    return 0
  }
}

function clampInteger(value: number, min: number, max: number): number {
  const numeric = Number.isFinite(value) ? value : min
  return Math.round(Math.min(max, Math.max(min, numeric)))
}

/** Cap a string at `maxBytes` of UTF-8 without splitting a code point mid-sequence. */
function capUtf8Bytes(text: string, maxBytes: number): string {
  if (text.length === 0) return text
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text
  return Buffer.from(text, 'utf8').subarray(0, Math.max(0, maxBytes)).toString('utf8')
}

/** Directory names directly under `artifacts/` (sharded run dirs), bounded and symlink-free. */
function uniqueArtifactRunDirs(directory: string): string[] {
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
function boundedArtifactSize(root: string): { total: number; blobs: number } {
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

export interface DeleteExecutionControl {
  wake: () => void
  getLabTargetHandle: (runId: string) => unknown
}

export interface DeleteLabControl {
  getTarget: (runId: string) => unknown
  stopLabTarget: (runId: string) => Promise<unknown>
}

async function stopRunsBeforeDelete(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  runIds: readonly string[],
  waitTimeoutMs = 2_500,
): Promise<void> {
  for (const runId of runIds) {
    try {
      const current = db.run(runId)
      if (!['complete', 'stopped'].includes(current.status)) {
        db.command({ requestId: randomUUID(), runId, action: 'stop' })
      }
    } catch {
      // Run may already be stopped or absent.
    }
    await labRunner.stopLabTarget(runId).catch(() => undefined)
  }
  exec.wake()

  const deadline = Date.now() + Math.max(0, waitTimeoutMs)
  while (Date.now() < deadline) {
    const stillActive = runIds.some(runId =>
      db.isRunActive(runId) || Boolean(exec.getLabTargetHandle(runId)) || Boolean(labRunner.getTarget(runId)),
    )
    if (!stillActive) break
    await new Promise(resolve => setTimeout(resolve, 100))
    exec.wake()
  }
}

export async function deleteRunWithActiveGuard(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  input: { runId: string; stopActive?: boolean; waitTimeoutMs?: number },
): Promise<{ deleted: boolean; projectId: string; runId: string }> {
  const isActive = db.isRunActive(input.runId)
    || Boolean(exec.getLabTargetHandle(input.runId))
    || Boolean(labRunner.getTarget(input.runId))
  if (isActive && !input.stopActive) {
    throw new Error('This run is currently active. Stop the run first (or choose Stop & Delete) before deleting it.')
  }
  if (isActive && input.stopActive) {
    await stopRunsBeforeDelete(db, exec, labRunner, [input.runId], input.waitTimeoutMs)
  } else {
    await labRunner.stopLabTarget(input.runId).catch(() => undefined)
  }
  const result = db.deleteRun(input.runId)
  if (result.deleted) exec.wake()
  return result
}

export async function deleteProjectWithActiveGuard(
  db: Store,
  exec: DeleteExecutionControl,
  labRunner: DeleteLabControl,
  input: { projectId: string; stopActive?: boolean; waitTimeoutMs?: number },
): Promise<{ deleted: boolean; projectId: string; deletedRuns: number }> {
  let detail: ReturnType<Store['projectDetail']> | null = null
  try {
    detail = db.projectDetail(input.projectId)
  } catch {
    return { deleted: false, projectId: input.projectId, deletedRuns: 0 }
  }
  const allRunIds = detail.runs.map(r => r.id)
  const activeRunIds = allRunIds.filter(runId =>
    db.isRunActive(runId) || Boolean(exec.getLabTargetHandle(runId)) || Boolean(labRunner.getTarget(runId)),
  )
  if (activeRunIds.length > 0 && !input.stopActive) {
    throw new Error(
      `This project has ${activeRunIds.length} active ${activeRunIds.length === 1 ? 'run' : 'runs'}. Stop active runs first (or choose Stop & Delete) before deleting the project.`,
    )
  }
  if (activeRunIds.length > 0 && input.stopActive) {
    await stopRunsBeforeDelete(db, exec, labRunner, activeRunIds, input.waitTimeoutMs)
  } else {
    for (const runId of allRunIds) {
      await labRunner.stopLabTarget(runId).catch(() => undefined)
    }
  }
  const result = db.deleteProject(input.projectId)
  if (result.deleted) exec.wake()
  return result
}

let instance: Store | undefined
export function store() {
  return instance ??= new Store(dataDirectory())
}
