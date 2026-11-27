/**
 * Domain repository for findings, evidence/artifacts, facts, graph edges, coverage entries,
 * replay specs, retest runs, SAST runs, surface probes, patch proposals, broker exchanges
 * (plus FTS5 search, retention pruning, storage footprint), endpoints/params/API dependencies,
 * resource samples, second-order canaries, lab telemetry, and benchmark runs.
 *
 * Strictly depends only on `store-session.ts` and `resource-harvest.ts` (never imports
 * `store.ts`, `store-projects.ts`, or `store-runs.ts`).
 */
import { createHash, randomUUID } from 'node:crypto'
import { lstatSync, rmdirSync, unlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { DatabaseSync } from 'node:sqlite'
import { and, asc, desc, eq, inArray, or, sql } from 'drizzle-orm'
import type {
  BenchmarkFunnel,
  CallerCompatibility,
  CodeLocation,
  DynamicRetestVerdict,
  EndpointSource,
  FailureTaxonomyBucket,
  Finding,
  InlineVerifyFeedback,
  OwaspCategory,
  ParamLocation,
  PatchProposalStatus,
  SecondOrderCanaryStatus,
  VerificationTier,
} from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import { chainFindingDedupKey } from '../report-summary.ts'
import { classifyCompositeChainOverlap, compositeChainOriginsEquivalent, compositeChainRichnessScore, extractCompositeChainDedupSignature, extractRowCompositeSignature, isGenericSharedAuthOrUtilityEndpoint, matchSubstantialUpstreamCompositeOverlap, matchesSameClassCompositeDuplicateRow, mergeChainFindingWithCompositeUpgrade, sortChainDuplicateRows, type CompositeChainDedupSignature } from './composite-chain-dedup.ts'
export { classifyCompositeChainOverlap, compositeChainOriginsEquivalent, compositeChainRichnessScore, extractCompositeChainDedupSignature, extractRowCompositeSignature, isGenericSharedAuthOrUtilityEndpoint, matchSubstantialUpstreamCompositeOverlap, sortChainDuplicateRows, type CompositeChainDedupSignature }
import type { FindingProvenance, FindingVerificationClass } from '../report-summary.ts'
import { isTerminalRunStatus } from './run-status.ts'
import {
  RECORD_COVERAGE_CONTRACT,
  appendCoverageEvidenceMetadata,
  categoryToOwaspCoverageCategory,
  extractCoverageEvidenceMetadata,
  mergeRouteCoverageStatuses,
  normalizeOriginForCoverage,
  normalizeRouteForCoverage,
  validateRecordCoverageContractInput,
} from './coverage-category.ts'
import {
  FindingCodec,
  operatorSeverityOverrides,
  operatorTriageStatuses,
  type FindingQueryFilter,
  type OperatorSeverityOverride,
  type OperatorTriage,
  type OperatorTriageStatus,
  type RawFindingRow,
  type RunFindingRollup,
  type TriagedFinding,
} from './finding-codec.ts'
import { computeFindingFingerprint, isOriginWideCwe, normalizeEndpointTemplate } from './finding-fingerprint.ts'
import { redact, redactHeaders, redactJsonValue } from './redact.ts'
import type { NamedSecret, SecretMatch } from './redact.ts'
import {
  RESOURCE_STATIC_ASSET_RE,
  collectionPathFor,
  extractResourceRefsFromExchange,
  isOpaqueResourceId,
  type ExtractedResourceRef,
  type ResourceHarvestExchange,
  type ResourceSampleRow,
} from './resource-harvest.ts'
import * as tables from './schema.ts'
import {
  DEFAULT_EXCHANGE_RETENTION_DAYS,
  InvariantError,
  artifactBucket,
  artifactShardFile,
  assertConfirmedVerificationClass,
  boundedArtifactSize,
  capUtf8Bytes,
  clampInteger,
  evidenceTitle,
  normalizeFactKind,
  proofColumns,
  proofRecordOf,
  replayVerdictConfirmsRuntime,
  resolvePageLimit,
  resolvePageOffset,
  safeFileSize,
  sanitizeSecretMatches,
  tenantBlobFile,
  verificationClassForFinding,
  type AgentScriptProofRecord,
  type ApiDependencyRow,
  type Assignment,
  type BenchmarkRunRow,
  type BrokerExchange,
  type ConfirmationBackingKind,
  type ConfirmationEvidence,
  type CoverageEntry,
  type DbSession,
  type EndpointParamRow,
  type EndpointRow,
  type Fact,
  type FactKind,
  type FindingProvenanceOptions,
  type GraphEdge,
  type LabTelemetryRow,
  type PatchProposal,
  type PruneExchangesOptions,
  type PruneExchangesResult,
  type PruneOptions,
  type PruneResult,
  type ReplaySpecRow,
  type RetestRun,
  type Run,
  type SastRun,
  type SecondOrderCanaryRow,
  type StoreFootprint,
  type SurfaceProbe,
} from './store-session.ts'

export {
  operatorTriageStatuses,
  operatorSeverityOverrides,
  type OperatorTriageStatus,
  type OperatorSeverityOverride,
  type OperatorTriage,
  type TriagedFinding,
  type FindingQueryFilter,
  type RunFindingRollup,
}

export interface TriageFindingInput {
  status?: OperatorTriageStatus
  severityOverride?: OperatorSeverityOverride | null
  notes?: string
}

export const patchProposalReviewStatuses = ['approved', 'rejected', 'pending'] as const
export type PatchProposalReviewStatus = typeof patchProposalReviewStatuses[number]

export interface PatchProposalReviewInput {
  status: PatchProposalReviewStatus
  reviewNotes?: string
}

const operatorTriageStatusSet = new Set<string>(operatorTriageStatuses)
const operatorSeverityOverrideSet = new Set<string>(operatorSeverityOverrides)
const patchProposalReviewStatusSet = new Set<string>(patchProposalReviewStatuses)

/**
 * R3-H-14: Single authoritative predicate for confirmed deterministic-floor rows.
 * Immutability, `floor_artifact` backing, and `host_persisted` envelope trust apply ONLY to
 * rows that are both floor-attributed AND already `confirmed` (never pending proposals).
 */
export function isConfirmedFloorFinding(
  row: {
    provenance?: FindingProvenance | null
    status?: Finding['status'] | null
    finding?: Pick<Finding, 'status'> | null
  } | null | undefined,
): boolean {
  if (!row || row.provenance !== 'floor') return false
  const status = row.finding?.status ?? row.status ?? null
  return status === 'confirmed'
}

/** Derive replay/retest envelope trust strictly from confirmed floor rows (never pending proposals). */
export function floorEnvelopeTrustForFinding(
  row: {
    provenance?: FindingProvenance | null
    status?: Finding['status'] | null
    finding?: Pick<Finding, 'status'> | null
  } | null | undefined,
): 'host_persisted' | 'untrusted' {
  return isConfirmedFloorFinding(row) ? 'host_persisted' : 'untrusted'
}

export interface PruneExchangesWithProtectionOptions extends PruneExchangesOptions {
  /**
   * When true (default), automatically preserve every exchange cited by findings, replay specs /
   * proof receipts (single-hop and composite), retest runs, and facts for the run.
   * Pass `false` explicitly only for hard-wipe / ZDR sweeps that intend to discard cited transcripts.
   */
  preserveProtectedExchanges?: boolean
  /**
   * Alias aligned with `ArtifactTtlPolicy.preserveConfirmedEvidence` for Stream 15 (`artifact-ttl.ts`).
   * If either `preserveProtectedExchanges` or `preserveConfirmedEvidence` is `false`, built-in
   * protection is disabled (explicit `protectedExchangeIds`, if supplied, remain protected).
   */
  preserveConfirmedEvidence?: boolean
  /** Optional caller-supplied exchange IDs that must never be deleted during pruning. */
  protectedExchangeIds?: ReadonlySet<string>
}

const EXCHANGE_ID_KEY_RE = /(?:^|_)exchange_?ids?$|ExchangeIds?$/i
const MAX_EXCHANGE_JSON_WALK_DEPTH = 12

function addNonEmptyString(out: Set<string>, value: unknown): void {
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (trimmed.length > 0) out.add(trimmed)
  }
}

function addStringArray(out: Set<string>, value: unknown): void {
  if (!Array.isArray(value)) return
  for (const item of value) addNonEmptyString(out, item)
}

function collectExchangeIdsFromJson(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > MAX_EXCHANGE_JSON_WALK_DEPTH || value == null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const item of value) collectExchangeIdsFromJson(item, out, depth + 1)
    return
  }
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (entry == null) continue
    if (EXCHANGE_ID_KEY_RE.test(key)) {
      if (typeof entry === 'string') {
        addNonEmptyString(out, entry)
        continue
      }
      if (Array.isArray(entry)) {
        addStringArray(out, entry)
        continue
      }
    }
    if (typeof entry === 'object') {
      collectExchangeIdsFromJson(entry, out, depth + 1)
    }
  }
}

function parseJsonAndCollectExchangeIds(raw: unknown, out: Set<string>, topLevelArray = false): void {
  if (raw == null) return
  let parsed: unknown = raw
  if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (!trimmed) return
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      return
    }
  }
  if (topLevelArray && Array.isArray(parsed)) {
    addStringArray(out, parsed)
    return
  }
  collectExchangeIdsFromJson(parsed, out)
}

/**
 * R3-H-16: Collect every broker exchange ID cited by persisted run artifacts (`findings`,
 * `replay_specs` / `proof_receipt` / `compositeReceipt`, `retest_runs`, `facts`, and surfaced
 * `second_order_canaries`) so retention pruning never destroys evidence referenced by findings,
 * receipts, retests, or facts.
 */
export function listProtectedExchangeIdsForRun(
  client: Pick<DatabaseSync, 'prepare'>,
  runId: string,
): Set<string> {
  const protectedIds = new Set<string>()

  // 1. Findings (confirmed, static_verified, or any finding row's JSON exchangeIds / nested evidence/receipt refs).
  try {
    const findingRows = client.prepare(
      'SELECT finding FROM findings WHERE run_id = ?',
    ).all(runId) as Array<{ finding: string | null }>
    for (const row of findingRows) {
      parseJsonAndCollectExchangeIds(row.finding, protectedIds)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  // 2. Replay specs (proof_receipt single-hop + compositeReceipt hops/edges/terminal/control exchanges, spec, diff).
  try {
    const specRows = client.prepare(
      'SELECT spec, proof_receipt, last_verification_diff FROM replay_specs WHERE run_id = ?',
    ).all(runId) as Array<{
      spec: string | null
      proof_receipt: string | null
      last_verification_diff: string | null
    }>
    for (const row of specRows) {
      parseJsonAndCollectExchangeIds(row.proof_receipt, protectedIds)
      parseJsonAndCollectExchangeIds(row.spec, protectedIds)
      parseJsonAndCollectExchangeIds(row.last_verification_diff, protectedIds)
    }
  } catch {
    // Fallback for legacy schemas without proof_receipt / last_verification_diff columns.
    try {
      const specRows = client.prepare(
        'SELECT spec FROM replay_specs WHERE run_id = ?',
      ).all(runId) as Array<{ spec: string | null }>
      for (const row of specRows) {
        parseJsonAndCollectExchangeIds(row.spec, protectedIds)
      }
    } catch {
      // Table unavailable on minimal schema.
    }
  }

  // 3. Retest runs (cited exchange_ids).
  try {
    const retestRows = client.prepare(
      'SELECT exchange_ids FROM retest_runs WHERE run_id = ?',
    ).all(runId) as Array<{ exchange_ids: string | null }>
    for (const row of retestRows) {
      parseJsonAndCollectExchangeIds(row.exchange_ids, protectedIds, true)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  // 4. Facts (exchange_ids column + nested exchangeId/exchangeIds in fact data JSON).
  try {
    const factRows = client.prepare(
      'SELECT exchange_ids, data FROM facts WHERE run_id = ?',
    ).all(runId) as Array<{ exchange_ids: string | null; data: string | null }>
    for (const row of factRows) {
      parseJsonAndCollectExchangeIds(row.exchange_ids, protectedIds, true)
      parseJsonAndCollectExchangeIds(row.data, protectedIds)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  // 5. Surfaced second-order canaries citing a broker exchange.
  try {
    const canaryRows = client.prepare(
      'SELECT surfaced_exchange_id FROM second_order_canaries WHERE run_id = ? AND surfaced_exchange_id IS NOT NULL',
    ).all(runId) as Array<{ surfaced_exchange_id: string | null }>
    for (const row of canaryRows) {
      addNonEmptyString(protectedIds, row.surfaced_exchange_id)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  return protectedIds
}

export class FindingsRepository {
  private readonly session: DbSession

  constructor(session: DbSession) {
    this.session = session
  }

  private assertTenantRun(runId: string): void {
    if (this.session.tenantId) {
      this.session.requireRun(runId)
    }
  }

  // --- Evidence & Artifacts ---

  assignmentEvidence(assignmentId: string, operationId: string) {
    return this.session.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.assignmentId, assignmentId), eq(tables.evidence.operationId, operationId),
    )).get()
  }

  assignmentObservation(assignmentId: string) {
    return this.session.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.assignmentId, assignmentId), eq(tables.evidence.kind, 'observation'),
    )).orderBy(desc(tables.evidence.scopeRevision), desc(tables.evidence.createdAt)).limit(1).get()
  }

  brokerOrigins(assignment: Assignment) {
    this.session.flushNow()
    const exchangeRows = this.session.db.select({
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
    const evs = this.session.db.select({ kind: tables.events.kind, detail: tables.events.detail })
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

  artifact(runId: string, artifactId: string) {
    const run = this.session.requireRun(runId)
    const item = this.session.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.id, artifactId), eq(tables.evidence.runId, runId),
    )).get()
    if (!item) throw new Error('Evidence not found.')
    const content = this.session.readArtifactFile(runId, item.id)
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
    this.assertTenantRun(run.id)
    if (operationId) {
      const existing = this.assignmentEvidence(assignment.id, operationId)
      if (existing) return existing
    }
    const id = randomUUID()
    this.session.writeArtifactFile(run.id, id, redact(content, secrets))
    return this.session.db.insert(tables.evidence).values({
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
    this.assertTenantRun(input.runId)
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
      const blob = this.session.writeBlob(cleanBody, secrets, input.runId, false)
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

    this.session.enqueueExchange({
      row,
      ftsBody: this.session.ftsMode === 'off'
        ? null
        : capUtf8Bytes(this.session.ftsMode === 'full' ? cleanBody : bodyPreview, this.session.ftsMaxBodyBytes),
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
    this.session.flushNow()
    this.session.requireRun(runId)
    const row = this.session.db.select().from(tables.brokerExchanges).where(and(
      eq(tables.brokerExchanges.runId, runId), eq(tables.brokerExchanges.id, exchangeId),
    )).get()
    if (!row) throw new Error('Broker exchange not found.')
    let body = row.bodyPreview
    if (row.bodyArtifactId) {
      try { body = this.session.readBlob(row.bodyArtifactId, runId) } catch { body = row.bodyPreview }
    }
    return { ...row, body }
  }

  searchExchanges(runId: string, query: string, opts: {
    approvedOrigins?: ReadonlySet<string>
    origin?: string
    limit?: number
  } = {}): BrokerExchange[] {
    this.session.flushNow()
    this.session.requireRun(runId)
    const limit = Math.min(Math.max(1, opts.limit ?? 30), 100)
    const q = query.trim()
    let rows: BrokerExchange[]
    if (!q) {
      rows = this.session.db.select().from(tables.brokerExchanges)
        .where(opts.origin
          ? and(eq(tables.brokerExchanges.runId, runId), eq(tables.brokerExchanges.origin, opts.origin))
          : eq(tables.brokerExchanges.runId, runId))
        .orderBy(desc(tables.brokerExchanges.createdAt)).limit(limit * 2).all()
    } else if (this.session.ftsAvailable && q.length >= 3) {
      const escaped = '"' + q.replaceAll('"', '""') + '"'
      const ids = this.session.client.prepare(
        `SELECT exchange_id FROM broker_exchanges_fts WHERE run_id = ? AND broker_exchanges_fts MATCH ? LIMIT ?`,
      ).all(runId, escaped, limit * 3) as Array<{ exchange_id: string }>
      const matchIds = ids.map(r => r.exchange_id)
      rows = matchIds.length
        ? this.session.db.select().from(tables.brokerExchanges)
            .where(and(eq(tables.brokerExchanges.runId, runId), inArray(tables.brokerExchanges.id, matchIds)))
            .orderBy(desc(tables.brokerExchanges.createdAt)).all()
        : []
    } else {
      const likePattern = `%${q.toLowerCase()}%`
      rows = this.session.db.select().from(tables.brokerExchanges)
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
   * Collect every exchange ID cited by findings, replay specs / proof receipts, retest runs,
   * and facts for `runId` so retention pruning never deletes referenced evidence.
   */
  listProtectedExchangeIdsForRun(runId: string): Set<string> {
    this.session.flushNow()
    this.session.requireRun(runId)
    return listProtectedExchangeIdsForRun(this.session.client, runId)
  }

  /**
   * Delete aged exchanges (rows + FTS rows + unreferenced sharded body blobs) for one run in
   * bounded IMMEDIATE batches. `olderThanMs` bounds the age, `keepLatest` always preserves the
   * newest N exchanges, and exchanges cited by findings/receipts/retests/facts are preserved
   * automatically unless `preserveProtectedExchanges: false` or `preserveConfirmedEvidence: false`.
   * An unbounded delete (no cutoff and no keepLatest) is a no-op.
   */
  pruneExchanges(options: PruneExchangesWithProtectionOptions): PruneExchangesResult {
    const result = this.pruneExchangeRows(options)
    if (options.emitEvent !== false && result.exchanges > 0) {
      this.session.event(result.runId, 'retention.pruned',
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
    this.session.flushNow()
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
      runIds = [this.session.requireRun(options.runId).id]
    } else if (this.session.tenantId) {
      const rows = this.session.client.prepare(
        `SELECT r.id, r.status FROM runs r
         LEFT JOIN projects p ON p.id = r.project_id
         WHERE r.workspace_id = ?
           AND COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?`,
      ).all(this.session.workspace.id, this.session.tenantId) as Array<{ id: string; status: string }>
      runIds = rows
        .filter(row => !(options.skipActiveRuns ?? true) || isTerminalRunStatus(row.status))
        .map(row => row.id)
    } else {
      const rows = this.session.client.prepare(
        'SELECT id, status FROM runs WHERE workspace_id = ?',
      ).all(this.session.workspace.id) as Array<{ id: string; status: string }>
      runIds = rows
        .filter(row => !(options.skipActiveRuns ?? true) || isTerminalRunStatus(row.status))
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
      this.session.event(options.runId ?? null, 'retention.pruned',
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
    this.session.flushNow()
    const mainDbBytes = safeFileSize(join(this.session.directory, 'kovo.sqlite'))
    const walBytes = safeFileSize(join(this.session.directory, 'kovo.sqlite-wal'))
    const shmBytes = safeFileSize(join(this.session.directory, 'kovo.sqlite-shm'))
    const { total: artifactBytes, blobs: blobBytes } = boundedArtifactSize(join(this.session.directory, 'artifacts'))
    let ftsRows = 0
    if (this.session.ftsTableExists) {
      try {
        const row = this.session.client.prepare('SELECT count(*) AS c FROM broker_exchanges_fts').get() as { c?: number } | undefined
        ftsRows = Number(row?.c ?? 0)
      } catch { ftsRows = 0 }
    }
    const exchangeRow = this.session.client.prepare('SELECT count(*) AS c FROM broker_exchanges').get() as { c?: number } | undefined
    return {
      directory: this.session.directory,
      mainDbBytes,
      walBytes,
      shmBytes,
      dbBytes: mainDbBytes + walBytes + shmBytes,
      artifactBytes,
      blobBytes,
      ftsRows,
      exchangeRows: Number(exchangeRow?.c ?? 0),
      ftsMode: this.session.ftsMode,
      ftsMaxBodyBytes: this.session.ftsMaxBodyBytes,
      maxFullFtsDbBytes: this.session.maxFullFtsDbBytes,
    }
  }

  /** Rowid of the oldest exchange that must be kept by `keepLatest` (null when the run is short). */
  private keepBoundaryRowid(runId: string, keepLatest: number): number | null {
    const row = this.session.client.prepare(
      'SELECT rowid AS r FROM broker_exchanges WHERE run_id = ? ORDER BY rowid DESC LIMIT 1 OFFSET ?',
    ).get(runId, Math.max(0, keepLatest - 1)) as { r?: number } | undefined
    return row?.r === undefined ? null : Number(row.r)
  }

  private pruneExchangeRows(options: PruneExchangesWithProtectionOptions): PruneExchangesResult {
    this.session.flushNow()
    const run = this.session.requireRun(options.runId)
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

    const protectBuiltIn =
      options.preserveProtectedExchanges !== false
      && options.preserveConfirmedEvidence !== false
    const protectedIds = new Set<string>()
    if (protectBuiltIn) {
      for (const id of listProtectedExchangeIdsForRun(this.session.client, run.id)) {
        protectedIds.add(id)
      }
    }
    if (options.protectedExchangeIds) {
      for (const id of options.protectedExchangeIds) {
        addNonEmptyString(protectedIds, id)
      }
    }

    const blobIds = new Set<string>()
    let cursor = 0
    for (;;) {
      const batch = this.pruneExchangeBatch(run.id, { cursor, cutoff, keepRowid, batchSize, protectedIds })
      if (!batch) break
      if (batch.rows > 0) {
        result.exchanges += batch.rows
        result.ftsRows += batch.ftsRows
        result.batches += 1
      }
      cursor = batch.lastRowid
      for (const id of batch.blobIds) blobIds.add(id)
      if (batch.fetched < batchSize) break
    }
    if (blobIds.size > 0) {
      this.session.afterCommit(() => {
        for (const blobId of blobIds) {
          const removed = this.deleteBlobIfUnreferenced(run.id, blobId)
          if (removed.deleted) {
            result.blobs += 1
            result.blobBytes += removed.bytes
          }
        }
      })
    }
    return result
  }

  private pruneExchangeBatch(
    runId: string,
    state: {
      cursor: number
      cutoff: number | null
      keepRowid: number | null
      batchSize: number
      protectedIds: ReadonlySet<string>
    },
  ): { fetched: number; rows: number; ftsRows: number; lastRowid: number; blobIds: string[] } | null {
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
    const rows = this.session.client.prepare(
      `SELECT rowid AS rowid, id, body_artifact_id FROM broker_exchanges
       WHERE ${conditions.join(' AND ')} ORDER BY rowid ASC LIMIT ?`,
    ).all(...params, state.batchSize) as Array<{ rowid: number; id: string; body_artifact_id: string | null }>
    if (!rows.length) return null
    const lastRowid = Number(rows[rows.length - 1]!.rowid)
    const deletable = state.protectedIds.size > 0
      ? rows.filter(row => !state.protectedIds.has(row.id))
      : rows
    if (!deletable.length) {
      return { fetched: rows.length, rows: 0, ftsRows: 0, lastRowid, blobIds: [] }
    }
    const ids = deletable.map(row => row.id)
    const placeholders = ids.map(() => '?').join(', ')
    let ftsRows = 0
    this.session.transaction(() => {
      if (this.session.ftsTableExists) {
        const info = this.session.client.prepare(
          `DELETE FROM broker_exchanges_fts WHERE exchange_id IN (${placeholders})`,
        ).run(...ids)
        ftsRows = Number(info.changes ?? 0)
      }
      this.session.client.prepare(
        `DELETE FROM broker_exchanges WHERE run_id = ? AND id IN (${placeholders})`,
      ).run(runId, ...ids)
    })
    return {
      fetched: rows.length,
      rows: deletable.length,
      ftsRows,
      lastRowid,
      blobIds: deletable.map(row => row.body_artifact_id).filter((id): id is string => typeof id === 'string' && id.length > 0),
    }
  }

  /**
   * Remove a content-addressed exchange body blob once no exchange row in the run's tenant
   * references it. Strictly tenant-scoped: never scans other tenants' directories on disk.
   */
  private deleteBlobIfUnreferenced(
    runId: string,
    blobId: string,
  ): { deleted: boolean; bytes: number } {
    const tenantId = this.session.effectiveRunTenant(runId) ?? 'default'
    const tenantReferenced = this.session.client.prepare(
      `SELECT 1 AS hit
       FROM broker_exchanges e
       JOIN runs r ON r.id = e.run_id
       LEFT JOIN projects p ON p.id = r.project_id
       WHERE e.body_artifact_id = ?
         AND r.workspace_id = ?
         AND COALESCE(NULLIF(r.tenant_id, 'default'), p.tenant_id, 'default') = ?
       LIMIT 1`,
    ).get(blobId, this.session.workspace.id, tenantId) as { hit?: number } | undefined
    if (tenantReferenced?.hit) return { deleted: false, bytes: 0 }

    const bucket = artifactBucket(blobId)
    const tenantPath = tenantBlobFile(this.session.directory, tenantId, blobId)
    const runPath = artifactShardFile(this.session.directory, runId, blobId, 'blobs')
    const candidates = new Set<string>([tenantPath, runPath])

    const globallyReferenced = this.session.client.prepare(
      'SELECT 1 AS hit FROM broker_exchanges WHERE body_artifact_id = ? LIMIT 1',
    ).get(blobId) as { hit?: number } | undefined
    if (!globallyReferenced?.hit) {
      candidates.add(join(this.session.directory, 'artifacts', blobId + '.txt'))
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
      try { rmdirSync(dirname(tenantPath)) } catch { /* non-empty */ }
      try { rmdirSync(join(this.session.directory, 'artifacts', runId, 'blobs', bucket)) } catch { /* non-empty */ }
    }
    return { deleted, bytes }
  }

  // --- Facts & Graph Edges ---

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
    this.assertTenantRun(run.id)
    const secrets = input.secrets ?? []
    const origins = new Set<string>([input.origin, ...assignment.sourceOrigins, ...(input.sourceOrigins ?? [])])
    const exIds = [...new Set(input.exchangeIds ?? [])]
    if (exIds.length) {
      const exRows = this.session.db.select({
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
    const fact = this.session.transaction(() => {
      const inserted = this.session.db.insert(tables.facts).values({
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
    this.session.event(run.id, 'fact.recorded', `[${input.kind}] ${fact.origin}: ${fact.summary.slice(0, 120)}`, {
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
    this.assertTenantRun(runId)
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
    return this.session.db.select().from(tables.facts).where(and(...conditions))
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
    return this.session.db.insert(tables.graphEdges).values({
      id: randomUUID(), runId, ...edge, createdAt: Date.now(),
    }).returning().get()
  }

  listGraphEdges(runId: string): GraphEdge[] {
    this.assertTenantRun(runId)
    return this.session.db.select().from(tables.graphEdges).where(eq(tables.graphEdges.runId, runId))
      .orderBy(asc(tables.graphEdges.createdAt)).all()
  }

  // --- Replay Specs, Retests, Coverage, Findings ---

  private hasConfirmedProofReceipt(proof: AgentScriptProofRecord | null | undefined): boolean {
    const raw = proof?.receipt as unknown as Record<string, unknown> | null | undefined
    if (!raw || typeof raw !== 'object') return false
    const single = Boolean(
      raw.receipt
      && typeof raw.receipt === 'object'
      && (raw.verification as { confirmed?: unknown } | undefined)?.confirmed === true,
    )
    const composite = Boolean(
      raw.compositeReceipt
      && typeof raw.compositeReceipt === 'object'
      && (raw.compositeVerification as { confirmed?: unknown } | undefined)?.confirmed === true,
    )
    return single || composite
  }

  private isAuthorizedHostBackingKind(kind: ConfirmationBackingKind | undefined): boolean {
    return (
      kind === 'inline_verifier'
      || kind === 'floor_engine'
      || kind === 'oob_receipt'
      || kind === 'baseline'
      || kind === 'verifier_receipt'
    )
  }

  private isScriptHarnessCaller(stack: string | undefined = new Error().stack): boolean {
    if (!stack) return false
    const frames = stack.split('\n').slice(1)
    for (const frame of frames) {
      if (/[\\/]src[\\/]server[\\/]store(?:-[a-z]+)?\.ts/.test(frame)) continue
      if (/[\\/]scripts[\\/][^)]+\.(?:ts|js|mjs|cjs)/.test(frame)) return true
      if (/[\\/]src[\\/]server[\\/]/.test(frame)) return false
    }
    return false
  }

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
      backingKind?: ConfirmationBackingKind
      requireReceiptOrBackingKind?: boolean
    },
  ): ReplaySpecRow {
    this.assertTenantRun(run.id)
    if (options?.verifiedInline === true) {
      if (options.backingKind === 'harness_assisted') {
        throw new InvariantError(
          'invariant.harness_assisted_confirmation',
          `Invariant: harness_assisted proofs cannot persist verifiedInline=true for finding ${findingId}.`,
        )
      }
      const hasReceipt = this.hasConfirmedProofReceipt(options.proof)
      const hasAuthorizedBacking = this.isAuthorizedHostBackingKind(options.backingKind)
      const diffVerdict = options.lastVerificationDiff?.verdict
      const hasConfirmingDiff = diffVerdict === 'confirmed' || diffVerdict === 'static_verified'
      if (!hasReceipt && !hasAuthorizedBacking) {
        if (!hasConfirmingDiff || options.requireReceiptOrBackingKind === true || this.isScriptHarnessCaller()) {
          throw new InvariantError(
            'invariant.unbacked_verified_inline',
            `Invariant: createReplaySpec(verifiedInline=true) requires a verifier-issued ProofReceipt or an authorized host backingKind for finding ${findingId}.`,
          )
        }
      }
    }
    const specSha256 = createHash('sha256').update(JSON.stringify(spec)).digest('hex')
    return this.session.db.insert(tables.replaySpecs).values({
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
    this.assertTenantRun(runId)
    const row = this.session.db.update(tables.replaySpecs)
      .set(proofColumns(proof))
      .where(and(eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId)))
      .returning().get()
    if (!row) throw new Error('Replay spec not found.')
    return row
  }

  /** Proof columns for a row (or null when the row is not a script proof). */
  replaySpecProof(runId: string, replaySpecId: string): AgentScriptProofRecord | null {
    this.assertTenantRun(runId)
    const row = this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
    )).get()
    return row ? proofRecordOf(row) : null
  }

  /** Latest script proof attached to any spec row of a finding (null when none). */
  agentProofForFinding(runId: string, findingId: string): AgentScriptProofRecord | null {
    this.assertTenantRun(runId)
    const rows = this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.findingId, findingId),
    )).orderBy(desc(tables.replaySpecs.createdAt)).all()
    for (const row of rows) {
      const proof = proofRecordOf(row)
      if (proof) return proof
    }
    return null
  }

  getReplaySpec(runId: string, replaySpecId: string): ReplaySpecRow {
    this.assertTenantRun(runId)
    const row = this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
    )).get()
    if (!row) throw new Error('Replay spec not found.')
    return row
  }

  listReplaySpecs(runId: string): ReplaySpecRow[] {
    this.assertTenantRun(runId)
    return this.session.db.select().from(tables.replaySpecs).where(eq(tables.replaySpecs.runId, runId))
      .orderBy(desc(tables.replaySpecs.createdAt)).all()
  }

  listReplaySpecsForFinding(runId: string, findingId: string): ReplaySpecRow[] {
    this.assertTenantRun(runId)
    return this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.findingId, findingId),
    )).orderBy(desc(tables.replaySpecs.createdAt)).all()
  }

  /** Query findings for a run via indexed promoted columns (`status`, `severity`, `cwe`, `origin`, `triage_status`). */
  queryFindings(runId: string, filter: FindingQueryFilter = {}): TriagedFinding[] {
    this.assertTenantRun(runId)
    return FindingCodec.queryFindings(this.session.client, runId, filter)
  }

  /** Indexed count of runtime-confirmed, non-superseded findings for a single run. */
  confirmedFindingCount(runId: string): number {
    this.assertTenantRun(runId)
    return FindingCodec.countConfirmedForRun(this.session.client, runId)
  }

  /** Indexed `(findingCount, confirmedCount)` rollups across run IDs (zero `json_extract`). */
  rollupFindingCountsByRunIds(runIds: readonly string[]): Map<string, RunFindingRollup> {
    return FindingCodec.rollupCountsByRunIds(this.session.client, runIds)
  }

  /** How many confirmed claims this run demoted after their persisted evidence stopped confirming. */
  confirmationConflictCount(runId: string): number {
    const row = this.session.db.select({ count: sql<number>`count(*)` }).from(tables.events).where(and(
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
    status?: Finding['status'] | null
    requireReceiptOnly?: boolean
  }): ConfirmationEvidence {
    const replaySpecId = input.replaySpecId ?? null
    if (input.findingKind === 'baseline_check' || input.verificationTier === 'baseline_confirmed') {
      return { backed: true, contradicted: false, kind: 'baseline', verdict: 'baseline_confirmed', replaySpecId }
    }
    const spec = replaySpecId
      ? this.session.db.select().from(tables.replaySpecs).where(and(
          eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
        )).get()
      : undefined
    const verdict = spec?.lastVerificationDiff?.verdict ?? null
    if (!input.requireReceiptOnly && replayVerdictConfirmsRuntime(verdict)) {
      return { backed: true, contradicted: false, kind: 'spec', verdict, replaySpecId }
    }
    // An explicit non-confirming verdict on the linked replay spec always contradicts the claim
    // (including prior ProofReceipt / OOB confirmations) so contradicting retries demote cleanly.
    if (verdict !== null && !replayVerdictConfirmsRuntime(verdict)) {
      return { backed: false, contradicted: true, kind: 'spec', verdict, replaySpecId }
    }

    const rawProofReceipt = spec?.proofReceipt as unknown as Record<string, unknown> | null | undefined
    const singleReceiptConfirmed = Boolean(
      rawProofReceipt
      && typeof rawProofReceipt === 'object'
      && rawProofReceipt.receipt
      && typeof rawProofReceipt.receipt === 'object'
      && (rawProofReceipt.verification as { confirmed?: unknown } | undefined)?.confirmed === true,
    )
    const compositeReceiptConfirmed = Boolean(
      rawProofReceipt
      && typeof rawProofReceipt === 'object'
      && rawProofReceipt.compositeReceipt
      && typeof rawProofReceipt.compositeReceipt === 'object'
      && (rawProofReceipt.compositeVerification as { confirmed?: unknown } | undefined)?.confirmed === true,
    )
    const oobReceiptConfirmed = Boolean(this.session.db.select({ id: tables.events.id }).from(tables.events).where(and(
      eq(tables.events.runId, runId),
      eq(tables.events.kind, 'oob.receipt_confirmed'),
      sql`json_extract(${tables.events.detail}, '$.findingId') = ${input.findingId}`,
    )).get())
    if (singleReceiptConfirmed || compositeReceiptConfirmed || oobReceiptConfirmed) {
      return { backed: true, contradicted: false, kind: 'receipt', verdict, replaySpecId }
    }
    // Legacy floor confirmations predate persisted spec diffs: their deterministic-engine event (or
    // the floor's own in-flight confirmation write) is the anchor. An explicit non-confirming diff
    // still wins (it is the later, contradicting write).
    // R3-H-14: Scope `floor_artifact` backing strictly to confirmed floor rows — never pending proposals.
    if (input.provenance === 'floor' && (input.status === undefined || input.status === null || input.status === 'confirmed')) {
      const existingRow = this.session.db.select({ finding: tables.findings.finding }).from(tables.findings).where(and(
        eq(tables.findings.runId, runId), eq(tables.findings.id, input.findingId),
      )).get()
      const backedByConfirmedFloor = existingRow
        ? existingRow.finding.status === 'confirmed'
        : input.status === 'confirmed'
      if (backedByConfirmedFloor) {
        return { backed: true, contradicted: false, kind: 'floor_artifact', verdict: null, replaySpecId }
      }
    }
    const floorEvent = this.session.db.select({ id: tables.events.id }).from(tables.events).where(and(
      eq(tables.events.runId, runId),
      eq(tables.events.kind, 'deterministic_engine.confirmed'),
      sql`json_extract(${tables.events.detail}, '$.findingId') = ${input.findingId}`,
    )).get()
    if (floorEvent) return { backed: true, contradicted: false, kind: 'floor_artifact', verdict: null, replaySpecId }
    return { backed: false, contradicted: false, kind: 'none', verdict, replaySpecId }
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
    status?: Finding['status'] | null
    requireReceiptOnly?: boolean
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
    this.assertTenantRun(runId)
    return this.session.transaction(() => {
      const row = this.session.db.select().from(tables.findings).where(and(
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
        status: row.finding.status,
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
      const encoded = FindingCodec.toUpdateColumns({
        finding: demoted,
        verificationClass: 'open_proof_gap',
        verificationTier: null,
      })
      this.session.client.prepare(`
        UPDATE findings
        SET verification_class = ?, verification_tier = ?,
            status = ?, severity = ?, cwe = ?, origin = ?, triage_status = ?,
            finding = ?
        WHERE run_id = ? AND id = ?
      `).run(
        encoded.verification_class,
        encoded.verification_tier ?? null,
        encoded.status,
        encoded.severity,
        encoded.cwe,
        encoded.origin,
        encoded.triage_status,
        encoded.finding,
        runId,
        findingId,
      )
      this.session.event(
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
      return true
    }, { behavior: 'immediate' })
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
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.replaySpecs).where(eq(tables.replaySpecs.id, id)).get()
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
      const row = this.session.db.update(tables.replaySpecs).set({
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
    return this.session.transaction(() => {
      const row = this.session.db.update(tables.replaySpecs).set({ lastVerificationDiff: feedback }).where(and(
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
    const row = this.session.db.insert(tables.retestRuns).values({
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
    this.session.event(run.id, 'retest.complete', `Verify Fix retest verdict: ${verdict}.`, {
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
    const row = this.session.db.insert(tables.sastRuns).values({
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
    this.session.event(input.runId, 'sast.run', `SAST (${row.engine}) on ${row.repo}: ${row.findingCount} findings (${row.durationMs}ms).`, {
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
    return this.session.db.select().from(tables.sastRuns).where(eq(tables.sastRuns.runId, runId))
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
    const row = this.session.db.insert(tables.surfaceProbes).values({
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
    this.session.event(input.runId, 'surface.probe', `Surface probe (${row.probeKind}) on ${row.origin}: ${row.requestsSent} reqs, ${row.anomaliesFound} anomalies.`, {
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
    return this.session.db.select().from(tables.surfaceProbes).where(eq(tables.surfaceProbes.runId, runId))
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
    labRevision?: string | null
    compositeVerdict?: string | null
    patchBrokeHopId?: string | null
    secrets?: readonly NamedSecret[]
  }): PatchProposal {
    this.assertTenantRun(input.runId)
    const secrets = input.secrets ?? []
    const cleanDiff = redact(input.diff, secrets)
    const cleanNotes = redact(input.reviewNotes, secrets)
    const cleanLocations = input.codeLocations.map(loc => ({
      ...loc,
      ...(loc.snippet ? { snippet: redact(loc.snippet, secrets) } : {}),
      ...(loc.label ? { label: redact(loc.label, secrets) } : {}),
    }))

    return this.session.transaction(() => {
      const now = Date.now()
      const existing = input.id
        ? this.session.db.select().from(tables.patchProposals).where(and(
            eq(tables.patchProposals.runId, input.runId), eq(tables.patchProposals.id, input.id),
          )).get()
        : undefined

      const saved = existing
        ? this.session.db.update(tables.patchProposals).set({
            status: input.status,
            callerCompatibility: input.callerCompatibility,
            diff: cleanDiff,
            codeLocations: cleanLocations,
            reviewNotes: cleanNotes,
            dynamicRetestVerdict: input.dynamicRetestVerdict ?? existing.dynamicRetestVerdict,
            updatedAt: now,
          }).where(eq(tables.patchProposals.id, existing.id)).returning().get()!
        : this.session.db.insert(tables.patchProposals).values({
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

      this.session.event(input.runId, 'patch.saved', `Patch proposal [${saved.status}] for finding ${saved.findingId} (${saved.callerCompatibility}).`, {
        patchId: saved.id,
        findingId: saved.findingId,
        repo: saved.repo,
        status: saved.status,
        callerCompatibility: saved.callerCompatibility,
        dynamicRetestVerdict: saved.dynamicRetestVerdict,
        ...(input.labRevision ? { labRevision: redact(input.labRevision, secrets) } : {}),
        ...(input.compositeVerdict ? { compositeVerdict: input.compositeVerdict } : {}),
        ...(input.patchBrokeHopId !== undefined ? { patchBrokeHopId: input.patchBrokeHopId ? redact(input.patchBrokeHopId, secrets) : null } : {}),
      })
      return saved
    }, { behavior: 'immediate' })
  }

  listPatchProposals(runId: string, findingId?: string): PatchProposal[] {
    this.assertTenantRun(runId)
    const where = findingId
      ? and(eq(tables.patchProposals.runId, runId), eq(tables.patchProposals.findingId, findingId))
      : eq(tables.patchProposals.runId, runId)
    return this.session.db.select().from(tables.patchProposals).where(where)
      .orderBy(desc(tables.patchProposals.updatedAt)).all()
  }

  getPatchProposal(runId: string, patchId: string): PatchProposal {
    this.assertTenantRun(runId)
    const row = this.session.db.select().from(tables.patchProposals).where(and(
      eq(tables.patchProposals.runId, runId), eq(tables.patchProposals.id, patchId),
    )).get()
    if (!row) throw new Error('Patch proposal not found.')
    return row
  }

  /**
   * Persist operator approval/rejection and review notes on a patch proposal.
   * Maps `'pending'` to the domain `'draft'` status so report/UI status labels stay consistent.
   */
  updatePatchProposalReview(
    proposalId: string,
    input: PatchProposalReviewInput,
    options: { runId?: string } = {},
  ): PatchProposal {
    if (!patchProposalReviewStatusSet.has(input.status)) {
      throw new Error(`Invalid patch proposal review status "${String(input.status)}".`)
    }
    return this.session.transaction(() => {
      if (options.runId) this.session.requireRun(options.runId)
      const where = options.runId
        ? and(eq(tables.patchProposals.runId, options.runId), eq(tables.patchProposals.id, proposalId))
        : eq(tables.patchProposals.id, proposalId)
      const existing = this.session.db.select().from(tables.patchProposals).where(where).get()
      if (!existing) throw new Error('Patch proposal not found.')
      this.session.requireRun(existing.runId)

      const nextStatus: PatchProposalStatus = input.status === 'pending' ? 'draft' : input.status
      const nextNotes = input.reviewNotes !== undefined
        ? redact(input.reviewNotes.trim().slice(0, 4000))
        : existing.reviewNotes
      const now = Date.now()

      const updated = this.session.db.update(tables.patchProposals).set({
        status: nextStatus,
        reviewNotes: nextNotes,
        updatedAt: now,
      }).where(eq(tables.patchProposals.id, existing.id)).returning().get()!

      this.session.event(existing.runId, 'patch.reviewed', `Patch proposal [${updated.status}] reviewed by operator for finding ${updated.findingId}.`, {
        patchId: updated.id,
        findingId: updated.findingId,
        status: updated.status,
        hasReviewNotes: updated.reviewNotes.length > 0,
      })
      return updated
    }, { behavior: 'immediate' })
  }

  /**
   * Persist operator triage metadata alongside machine-verified finding state without mutating
   * H-4 / H-18 machine verdict, severity, category, or confirmation receipts.
   */
  triageFinding(
    findingId: string,
    input: TriageFindingInput,
    options: { runId?: string } = {},
  ): TriagedFinding {
    if (input.status !== undefined && !operatorTriageStatusSet.has(input.status)) {
      throw new Error(`Invalid operator triage status "${String(input.status)}".`)
    }
    if (
      input.severityOverride !== undefined
      && input.severityOverride !== null
      && !operatorSeverityOverrideSet.has(input.severityOverride)
    ) {
      throw new Error(`Invalid severity override "${String(input.severityOverride)}".`)
    }

    return this.session.transaction(() => {
      if (options.runId) this.session.requireRun(options.runId)

      const existingRaw = options.runId
        ? (this.session.client.prepare('SELECT * FROM findings WHERE run_id = ? AND id = ?').get(options.runId, findingId) as RawFindingRow | undefined)
        : (this.session.client.prepare('SELECT * FROM findings WHERE id = ?').get(findingId) as RawFindingRow | undefined)
      if (!existingRaw) throw new Error('Finding not found.')
      this.session.requireRun(existingRaw.run_id)

      const existingFinding = FindingCodec.fromRow(existingRaw)
      const prevTriage = existingFinding.operatorTriage ?? null
      const nextTriage: OperatorTriage = {
        status: input.status ?? prevTriage?.status ?? 'open',
        severityOverride: input.severityOverride !== undefined
          ? input.severityOverride
          : (prevTriage?.severityOverride ?? null),
        notes: input.notes !== undefined
          ? redact(input.notes.trim().slice(0, 4000))
          : (prevTriage?.notes ?? ''),
        updatedAt: Date.now(),
      }

      const nextFinding: TriagedFinding = {
        ...existingFinding,
        operatorTriage: nextTriage,
      }
      const encoded = FindingCodec.toUpdateColumns({
        finding: nextFinding,
        verificationClass: existingRaw.verification_class,
      })

      this.session.client.prepare(`
        UPDATE findings
        SET status = ?, severity = ?, cwe = ?, origin = ?, triage_status = ?, finding = ?
        WHERE id = ?
      `).run(
        encoded.status,
        encoded.severity,
        encoded.cwe,
        encoded.origin,
        encoded.triage_status,
        encoded.finding,
        existingRaw.id,
      )

      this.session.event(existingRaw.run_id, 'finding.triaged', `Operator triaged "${existingFinding.title}" (${nextTriage.status}).`, {
        findingId: existingRaw.id,
        triageStatus: nextTriage.status,
        severityOverride: nextTriage.severityOverride,
        hasNotes: nextTriage.notes.length > 0,
      })

      return encoded.canonical
    }, { behavior: 'immediate' })
  }

  listOpenProofGaps(runId: string, goalRevision?: number): CoverageEntry[] {
    this.assertTenantRun(runId)
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
    return this.session.db.select().from(tables.coverageEntries).where(where)
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
    this.assertTenantRun(run.id)
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.findings).where(and(
        eq(tables.findings.runId, run.id), eq(tables.findings.id, findingId),
      )).get()
      if (!existing) throw new Error('Finding not found.')

      // Floor-confirmed rows are immutable: later agent passes may add evidence elsewhere but can
      // never overwrite, downgrade or reclassify the floor's own runtime confirmation.
      // Pending or static_verified floor rows remain monotonically upgradable once runtime proof arrives.
      if (isConfirmedFloorFinding(existing)) {
        this.session.event(
          run.id,
          'finding.floor_preserved',
          `Rejected update of floor-confirmed finding "${existing.finding.title}" (${existing.id}); floor rows are immutable.`,
          { findingId: existing.id, provenance: 'floor' },
        )
        return existing.finding
      }

      const freshRun = this.session.db.select({ scopeRevision: tables.runs.scopeRevision })
        .from(tables.runs).where(eq(tables.runs.id, run.id)).get()
      const currentScopeRevision = Math.max(run.scopeRevision, freshRun?.scopeRevision ?? run.scopeRevision)

      const isExistingConfirmed = existing.finding.status === 'confirmed'
      const rawIncomingFinding: Partial<Finding> = patch.finding ? { ...patch.finding } : {}
      if (isExistingConfirmed && rawIncomingFinding.status === 'static_verified') {
        // Monotonicity: never downgrade a runtime-confirmed finding back to static_verified.
        delete rawIncomingFinding.status
      }
      const staysConfirmed = isExistingConfirmed
        && (rawIncomingFinding.status === undefined || rawIncomingFinding.status === 'confirmed')
      if (isExistingConfirmed) {
        // H-4 / H-18: Never allow post-confirmation updates to mutate confirmed finding identity/severity/category.
        delete rawIncomingFinding.cwe
        delete rawIncomingFinding.origin
        delete rawIncomingFinding.title
        delete rawIncomingFinding.category
        delete rawIncomingFinding.severity
        delete rawIncomingFinding.fingerprintHash
        if (staysConfirmed && existing.replaySpecId) {
          delete rawIncomingFinding.replaySpecId
        }
      }
      const effectiveReplaySpecId = staysConfirmed && existing.replaySpecId
        ? existing.replaySpecId
        : (patch.replaySpecId ?? existing.replaySpecId)
      const mergedFinding: Finding = {
        ...existing.finding,
        ...rawIncomingFinding,
        id: existing.id,
        ...(effectiveReplaySpecId !== undefined && effectiveReplaySpecId !== null ? { replaySpecId: effectiveReplaySpecId } : {}),
        ...(patch.verificationTier !== undefined ? { verificationTier: patch.verificationTier ?? undefined } : {}),
        ...(!isExistingConfirmed && patch.fingerprintHash !== undefined ? { fingerprintHash: patch.fingerprintHash } : {}),
        ...(patch.supersededByFindingId !== undefined ? { supersededByFindingId: patch.supersededByFindingId } : {}),
        ...(patch.counterevidence !== undefined ? { counterevidence: patch.counterevidence } : {}),
        ...(patch.confidenceRationale !== undefined ? { confidenceRationale: patch.confidenceRationale } : {}),
        ...(patch.severityChangeConditions !== undefined ? { severityChangeConditions: patch.severityChangeConditions } : {}),
        ...(patch.codeLocations !== undefined ? { codeLocations: patch.codeLocations ?? undefined } : {}),
        evidenceIds: [...new Set([...existing.finding.evidenceIds, ...(patch.finding?.evidenceIds ?? [])])],
        exchangeIds: [...new Set([...(existing.finding.exchangeIds ?? []), ...(patch.finding?.exchangeIds ?? [])])],
        chainFactIds: [...new Set([...(existing.finding.chainFactIds ?? []), ...(patch.finding?.chainFactIds ?? [])])],
        scopeRevision: Math.max(existing.finding.scopeRevision, currentScopeRevision),
      }

      const cleanOrigins = [...new Set([
        ...existing.sourceOrigins,
        ...(patch.sourceOrigins ?? []),
        ...(mergedFinding.origin ? [mergedFinding.origin] : []),
      ])]

      const parentFindingIds = patch.parentFindingIds !== undefined
        ? (patch.parentFindingIds ? [...new Set(patch.parentFindingIds)] : null)
        : existing.parentFindingIds
      if (mergedFinding.status === 'confirmed') {
        if (mergedFinding.verificationTier === 'static_verified' || mergedFinding.verificationTier === undefined) {
          mergedFinding.verificationTier = existing.findingKind === 'baseline_check' ? 'baseline_confirmed' : 'runtime_confirmed'
        }
        if (existing.finding.status === 'static_verified' && rawIncomingFinding.runtimeProofGap === undefined) {
          mergedFinding.runtimeProofGap = null
        }
      }
      const verificationClass = verificationClassForFinding(mergedFinding, patch.verificationClass)
      assertConfirmedVerificationClass(mergedFinding.status, verificationClass)
      if (mergedFinding.status === 'confirmed') {
        this.assertConfirmationEvidence(run.id, {
          findingId: existing.id,
          replaySpecId: effectiveReplaySpecId,
          verification: mergedFinding.verification,
          findingKind: existing.findingKind,
          verificationTier: mergedFinding.verificationTier ?? existing.verificationTier,
          provenance: isConfirmedFloorFinding(existing) ? 'floor' : null,
          status: existing.finding.status,
        })
      }
      const existingOperatorTriage = (existing.finding as TriagedFinding).operatorTriage
      const persistedFinding = {
        ...mergedFinding,
        ...(existingOperatorTriage !== undefined ? { operatorTriage: existingOperatorTriage } : {}),
        provenance: existing.provenance,
        ...(parentFindingIds?.length ? { parentFindingIds } : {}),
        verificationStatus: verificationClass,
      } as Finding

      const nextVerificationTier = mergedFinding.status === 'confirmed'
        ? (mergedFinding.verificationTier ?? 'runtime_confirmed')
        : (patch.verificationTier !== undefined
            ? patch.verificationTier
            : (mergedFinding.verificationTier ?? existing.verificationTier))
      const nextFingerprintHash = !isExistingConfirmed && patch.fingerprintHash !== undefined
        ? patch.fingerprintHash
        : (mergedFinding.fingerprintHash ?? existing.fingerprintHash)
      const nextSupersededBy = patch.supersededByFindingId !== undefined
        ? patch.supersededByFindingId
        : (mergedFinding.supersededByFindingId ?? existing.supersededByFindingId)
      const nextCounterevidence = patch.counterevidence !== undefined
        ? patch.counterevidence
        : (mergedFinding.counterevidence ?? existing.counterevidence)
      const nextConfidenceRationale = patch.confidenceRationale !== undefined
        ? patch.confidenceRationale
        : (mergedFinding.confidenceRationale ?? existing.confidenceRationale)
      const nextSeverityConditions = patch.severityChangeConditions !== undefined
        ? patch.severityChangeConditions
        : (mergedFinding.severityChangeConditions ?? existing.severityChangeConditions)
      const nextCodeLocations = patch.codeLocations !== undefined
        ? patch.codeLocations
        : (mergedFinding.codeLocations ?? existing.codeLocations)

      const encoded = FindingCodec.toUpdateColumns({
        finding: persistedFinding,
        replaySpecId: effectiveReplaySpecId ?? null,
        provenance: existing.provenance,
        parentFindingIds: parentFindingIds?.length ? parentFindingIds : null,
        verificationClass,
        sourceOrigins: cleanOrigins,
        verificationTier: nextVerificationTier,
        fingerprintHash: nextFingerprintHash,
        supersededByFindingId: nextSupersededBy,
        counterevidence: nextCounterevidence,
        confidenceRationale: nextConfidenceRationale,
        severityChangeConditions: nextSeverityConditions,
        codeLocations: nextCodeLocations,
      })

      this.session.client.prepare(`
        UPDATE findings
        SET replay_spec_id = ?, source_origins = ?, verification_tier = ?, fingerprint_hash = ?,
            superseded_by_finding_id = ?, counterevidence = ?, confidence_rationale = ?,
            severity_change_conditions = ?, code_locations = ?, parent_finding_ids = ?,
            verification_class = ?, status = ?, severity = ?, cwe = ?, origin = ?,
            triage_status = ?, finding = ?
        WHERE id = ?
      `).run(
        encoded.replay_spec_id ?? null,
        encoded.source_origins ?? JSON.stringify(cleanOrigins),
        encoded.verification_tier ?? null,
        encoded.fingerprint_hash ?? null,
        encoded.superseded_by_finding_id ?? null,
        encoded.counterevidence ?? null,
        encoded.confidence_rationale ?? null,
        encoded.severity_change_conditions ?? null,
        encoded.code_locations ?? null,
        encoded.parent_finding_ids ?? null,
        encoded.verification_class,
        encoded.status,
        encoded.severity,
        encoded.cwe,
        encoded.origin,
        encoded.triage_status,
        encoded.finding,
        existing.id,
      )

      this.session.event(run.id, 'finding.updated', `Updated finding "${mergedFinding.title}" (${mergedFinding.status}).`, {
        findingId: mergedFinding.id,
        status: encoded.status,
        severity: encoded.severity,
        verificationTier: encoded.verification_tier ?? null,
        verificationClass: encoded.verification_class,
      })
      return encoded.canonical
    }, { behavior: 'immediate' })
  }

  static inspectCoverageExchangeEvidence(
    db: DbSession['db'],
    runId: string,
    origins: string | readonly string[],
    candidateExchangeIds?: readonly string[],
    assignmentId?: string,
  ): {
    verifiedExchangeIds: string[]
    inferredRouteFromExchange: string | null
    distinctPersonas: string[]
    distinctExchanges: number
    statuses: number[]
    allDenial403Or404: boolean
  } {
    const targetOrigins = new Set((Array.isArray(origins) ? origins : [origins]).map(normalizeOriginForCoverage))
    const ids = [...new Set((candidateExchangeIds ?? []).map(id => id.trim()).filter(Boolean))]
    if (!ids.length && !assignmentId) {
      return { verifiedExchangeIds: [], inferredRouteFromExchange: null, distinctPersonas: [], distinctExchanges: 0, statuses: [], allDenial403Or404: false }
    }
    const matchedRows = db.select({
      id: tables.brokerExchanges.id,
      origin: tables.brokerExchanges.origin,
      method: tables.brokerExchanges.method,
      pathAndQuery: tables.brokerExchanges.pathAndQuery,
      personaHandle: tables.brokerExchanges.personaHandle,
      status: tables.brokerExchanges.status,
    })
      .from(tables.brokerExchanges)
      .where(and(
        eq(tables.brokerExchanges.runId, runId),
        ids.length > 0
          ? inArray(tables.brokerExchanges.id, ids)
          : eq(tables.brokerExchanges.assignmentId, assignmentId!),
      ))
      .all()
    const rowById = new Map(matchedRows.map(r => [r.id, r]))
    const orderedRows = ids.length > 0
      ? ids.map(id => rowById.get(id)).filter((r): r is NonNullable<typeof r> => Boolean(r))
      : matchedRows
    const verifiedExchangeIds: string[] = []
    const seenIds = new Set<string>()
    const personas = new Set<string>()
    const statuses: number[] = []
    let inferredRouteFromExchange: string | null = null
    for (const row of orderedRows) {
      if (!targetOrigins.has(normalizeOriginForCoverage(row.origin))) continue
      if (seenIds.has(row.id)) continue
      seenIds.add(row.id)
      verifiedExchangeIds.push(row.id)
      personas.add(row.personaHandle?.trim() || 'unauthenticated')
      statuses.push(row.status)
      if (!inferredRouteFromExchange) {
        const pathOnly = row.pathAndQuery.split('?')[0] || '/'
        inferredRouteFromExchange = `${row.method.toUpperCase()} ${pathOnly}`
      }
    }
    return {
      verifiedExchangeIds,
      inferredRouteFromExchange,
      distinctPersonas: [...personas],
      distinctExchanges: verifiedExchangeIds.length,
      statuses,
      allDenial403Or404: verifiedExchangeIds.length > 0 && statuses.every(s => s === 403 || s === 404),
    }
  }

  upsertCoverageEntry(run: Run, assignmentId: string, input: {
    origin: string
    category: OwaspCategory
    status: CoverageEntry['status']
    summary: string
    enforcingControl?: string | null
    proofGapReason?: string | null
    linkedFindingId?: string | null
    route?: string | null
    branchKey?: string | null
    exchangeIds?: readonly string[]
  }): CoverageEntry {
    this.assertTenantRun(run.id)
    const cleanControl = input.enforcingControl?.trim() ? redact(input.enforcingControl.trim().slice(0, 600)) : null
    const cleanGapReason = input.proofGapReason?.trim() ? redact(input.proofGapReason.trim().slice(0, 600)) : null
    const linkedFindingId = input.linkedFindingId?.trim() || null
    const cleanSummaryBase = redact(input.summary.slice(0, 600))
    const targetOrigin = normalizeOriginForCoverage(input.origin)

    const contractCheck = validateRecordCoverageContractInput(input, { allowImplicitLinkedFinding: true })
    if (!contractCheck.ok) {
      throw new InvariantError(contractCheck.code, contractCheck.error)
    }
    const statusRule = RECORD_COVERAGE_CONTRACT[input.status]
    const candidateExchangeIds = contractCheck.candidateExchangeIds

    const requiresExchangeEvidence = statusRule.requiresVerifiedExchange
    if (requiresExchangeEvidence || candidateExchangeIds.length > 0) {
      // Flush queued broker exchanges so newly recorded run exchanges are visible before verification.
      this.session.flushNow()
    }

    const exchangeEvidence = candidateExchangeIds.length > 0
      ? FindingsRepository.inspectCoverageExchangeEvidence(this.session.db, run.id, targetOrigin, candidateExchangeIds)
      : { verifiedExchangeIds: [], inferredRouteFromExchange: null, distinctPersonas: [], distinctExchanges: 0, statuses: [], allDenial403Or404: false }
    const verifiedExchangeIds = exchangeEvidence.verifiedExchangeIds
    const inferredRouteFromExchange = exchangeEvidence.inferredRouteFromExchange

    if (requiresExchangeEvidence && verifiedExchangeIds.length === 0) {
      const reason = `Coverage status "${input.status}" rejected: none of the supplied exchangeIds (${candidateExchangeIds.slice(0, 5).join(', ')}) belong to run ${run.id} for origin ${input.origin}.`
      throw new InvariantError('COVERAGE_EVIDENCE_REQUIRED', reason)
    }

    const cleanRoute = input.route?.trim()
      ? normalizeRouteForCoverage(redact(input.route.trim().slice(0, 200)))
      : (inferredRouteFromExchange ? normalizeRouteForCoverage(inferredRouteFromExchange) : null)
    const cleanBranchKey = input.branchKey?.trim() ? redact(input.branchKey.trim().slice(0, 160)) : null

    const isFindingSupersededOrDismissed = (row: {
      supersededByFindingId: string | null
      finding: Finding
    }): boolean => {
      if (row.supersededByFindingId || row.finding.supersededByFindingId) return true
      if (row.finding.status === 'dismissed') return true
      const triageStatus = (row.finding as Finding & { operatorTriage?: { status?: string } }).operatorTriage?.status
      if (triageStatus === 'false_positive') return true
      return false
    }

    return this.session.transaction(() => {
      const now = Date.now()
      const existing = this.session.db.select().from(tables.coverageEntries).where(and(
        eq(tables.coverageEntries.runId, run.id),
        eq(tables.coverageEntries.goalRevision, run.goalRevision),
        eq(tables.coverageEntries.origin, input.origin),
        eq(tables.coverageEntries.category, input.category),
      )).get()

      const runFindings = this.session.db.select({
        id: tables.findings.id,
        supersededByFindingId: tables.findings.supersededByFindingId,
        finding: tables.findings.finding,
      })
        .from(tables.findings)
        .where(and(
          eq(tables.findings.runId, run.id),
          eq(tables.findings.goalRevision, run.goalRevision),
        ))
        .all()

      const activeConfirmedForCell = runFindings.find(row =>
        !isFindingSupersededOrDismissed(row)
        && row.finding.status === 'confirmed'
        && normalizeOriginForCoverage(row.finding.origin) === targetOrigin
        && categoryToOwaspCoverageCategory(row.finding.category) === input.category,
      )

      const existingMeta = existing ? extractCoverageEvidenceMetadata(existing) : null
      const mergedRoutes = [...new Set([
        ...(existingMeta?.routes ?? []),
        ...(cleanRoute ? [cleanRoute] : []),
      ])]
      const mergedExchangeIds = [...new Set([
        ...(existingMeta?.exchangeIds ?? []),
        ...verifiedExchangeIds,
      ])]
      const mergedBranchKey = cleanBranchKey ?? existingMeta?.branchKey ?? null

      let effectiveStatus: CoverageEntry['status'] = input.status
      let effectiveLinkedFindingId: string | null = linkedFindingId
      let effectiveSummaryBase = cleanSummaryBase
      let allowDemotionFromReported = false
      let blockDemotion = false

      if (input.status !== 'reported') {
        let preservedFindingId: string | null = null

        if (existing?.status === 'reported') {
          if (existing.linkedFindingId) {
            const linkedRow = runFindings.find(r => r.id === existing.linkedFindingId)
              ?? this.session.db.select({
                id: tables.findings.id,
                supersededByFindingId: tables.findings.supersededByFindingId,
                finding: tables.findings.finding,
              })
                .from(tables.findings)
                .where(and(eq(tables.findings.runId, run.id), eq(tables.findings.id, existing.linkedFindingId)))
                .get()
            const linkedDemotable = linkedRow ? isFindingSupersededOrDismissed(linkedRow) : false
            if (linkedDemotable) {
              allowDemotionFromReported = true
            } else {
              blockDemotion = true
              preservedFindingId = existing.linkedFindingId
            }
          } else {
            // A reported cell with no linked finding id cannot prove its finding was superseded/dismissed.
            blockDemotion = true
          }
        }

        if (!blockDemotion && activeConfirmedForCell) {
          blockDemotion = true
          preservedFindingId = activeConfirmedForCell.id
        }

        if (blockDemotion) {
          effectiveStatus = 'reported'
          effectiveLinkedFindingId = preservedFindingId ?? existing?.linkedFindingId ?? null
          if (existing?.status === 'reported') {
            effectiveSummaryBase = existing.summary
          } else if (activeConfirmedForCell) {
            effectiveSummaryBase = redact(`Confirmed finding active: ${activeConfirmedForCell.finding.title}`.slice(0, 600))
          }
        } else {
          effectiveLinkedFindingId = null
        }
      } else {
        effectiveLinkedFindingId = linkedFindingId ?? existing?.linkedFindingId ?? activeConfirmedForCell?.id ?? null
      }

      const routeMerge = mergeRouteCoverageStatuses({
        existingStatus: existing?.status ?? null,
        existingRoutes: existingMeta?.routes ?? [],
        existingRouteStatuses: existingMeta?.routeStatuses ?? {},
        incomingRoute: cleanRoute,
        incomingStatus: input.status,
        allowDemotionFromReported,
      })

      if (!blockDemotion && input.status !== 'reported') {
        effectiveStatus = routeMerge.derivedStatus
        if (routeMerge.preservedExistingGap && existing) {
          effectiveSummaryBase = existing.summary
        }
      }

      const finalSummary = appendCoverageEvidenceMetadata(effectiveSummaryBase, {
        routes: mergedRoutes,
        routeStatuses: routeMerge.routeStatuses,
        branchKey: mergedBranchKey,
        exchangeIds: mergedExchangeIds,
      })

      if (existing) {
        return this.session.db.update(tables.coverageEntries).set({
          scopeRevision: run.scopeRevision,
          status: effectiveStatus,
          summary: finalSummary,
          enforcingControl: effectiveStatus === 'ruled_out'
            ? (cleanControl ?? existing.enforcingControl)
            : (effectiveStatus === 'reported' ? existing.enforcingControl : cleanControl),
          proofGapReason: effectiveStatus === 'needs_follow_up'
            ? (routeMerge.preservedExistingGap ? (existing.proofGapReason ?? cleanGapReason) : (cleanGapReason ?? existing.proofGapReason))
            : (effectiveStatus === 'reported' ? existing.proofGapReason : cleanGapReason),
          linkedFindingId: effectiveStatus === 'reported' ? effectiveLinkedFindingId : null,
          assignmentId: (effectiveStatus === 'reported' && input.status !== 'reported') || routeMerge.preservedExistingGap
            ? existing.assignmentId
            : assignmentId,
          updatedAt: now,
        }).where(eq(tables.coverageEntries.id, existing.id)).returning().get()!
      }
      return this.session.db.insert(tables.coverageEntries).values({
        id: randomUUID(),
        runId: run.id,
        scopeRevision: run.scopeRevision,
        goalRevision: run.goalRevision,
        origin: input.origin,
        category: input.category,
        status: effectiveStatus,
        summary: finalSummary,
        enforcingControl: effectiveStatus === 'ruled_out' ? cleanControl : null,
        proofGapReason: effectiveStatus === 'needs_follow_up' ? cleanGapReason : (cleanGapReason ?? null),
        linkedFindingId: effectiveStatus === 'reported' ? effectiveLinkedFindingId : null,
        assignmentId,
        updatedAt: now,
      }).returning().get()
    }, { behavior: 'immediate' })
  }

  listCoverageEntries(runId: string, goalRevision?: number): CoverageEntry[] {
    this.assertTenantRun(runId)
    const where = goalRevision !== undefined
      ? and(eq(tables.coverageEntries.runId, runId), eq(tables.coverageEntries.goalRevision, goalRevision))
      : eq(tables.coverageEntries.runId, runId)
    return this.session.db.select().from(tables.coverageEntries).where(where)
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
      evidence?: Record<string, unknown> | null
      compositeSignature?: CompositeChainDedupSignature | null
    },
    excludeId?: string,
  ) {
    const originWide = isOriginWideCwe(candidate.cwe, candidate.category)
    const legacyKey = chainFindingDedupKey(candidate)
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
    const candidateCompSig = candidate.compositeSignature ?? extractCompositeChainDedupSignature({ origin: candidate.origin, evidence: candidate.evidence })
    const rows = this.session.db.select().from(tables.findings).where(and(eq(tables.findings.runId, runId), eq(tables.findings.goalRevision, goalRevision), eq(tables.findings.findingKind, 'multi_step_chain'))).all()
    const rowCompSigById = new Map<string, CompositeChainDedupSignature | null>()
    const matches = rows.filter(row => {
      if (row.id === excludeId || row.supersededByFindingId || row.finding.supersededByFindingId) return false
      if (originWide && row.finding.origin.trim().toLowerCase() === candidateOrigin && (row.finding.cwe ?? '').trim().toUpperCase() === candidateCwe) return true
      const rowHash = row.fingerprintHash ?? row.finding.fingerprintHash ?? null
      if (candidateHash && rowHash && candidateHash === rowHash) return true
      const sameClass = Boolean(candidateCwe && (row.finding.cwe ?? '').trim().toUpperCase() === candidateCwe)
      if (candidateHash && rowHash && !sameClass) return false
      if (candidateCompSig && candidateCompSig.hopCount >= 2 && sameClass) {
        const res = matchesSameClassCompositeDuplicateRow(candidate.origin, candidateCompSig, row)
        rowCompSigById.set(row.id, res.rowSig)
        if (res.matched) return true
      }
      if (candidateHash && rowHash) return false
      return !candidateHash && !rowHash && chainFindingDedupKey(row.finding) === legacyKey
    })
    if (!matches.length) return undefined
    const order: Record<Finding['status'], number> = {
      confirmed: 0, static_verified: 1, pending: 2, inconclusive: 3, dismissed: 4,
    }
    return sortChainDuplicateRows(matches, order, r => rowCompSigById.get(r.id) ?? extractRowCompositeSignature(r))[0]
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
    if (isConfirmedFloorFinding(targetRow)) return 'floor'
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
    const rows = this.session.db.select().from(tables.findings).where(and(
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
    this.assertTenantRun(run.id)
    return this.session.transaction(() => {
      const byId = this.session.db.select().from(tables.findings).where(eq(tables.findings.id, finding.id)).get()
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
      // Pending or static_verified floor rows remain monotonically upgradable once runtime proof arrives.
      const targetIsFloorConfirmed = isConfirmedFloorFinding(targetRow)
      if (targetRow && targetIsFloorConfirmed && options.provenance !== 'floor') {
        this.session.event(
          run.id,
          'finding.floor_preserved',
          `Ignored agent re-discovery of floor-confirmed finding "${targetRow.finding.title}" (${targetRow.id}); floor rows are immutable.`,
          { findingId: targetRow.id, suppressedFindingId: finding.id, provenance: 'floor' },
        )
        return targetRow.finding
      }

      const rawStoredFinding: Finding = targetRow
        ? mergeChainFindingWithCompositeUpgrade(targetRow.finding, incoming)
        : incoming
      const targetIsConfirmed = Boolean(targetRow && targetRow.finding.status === 'confirmed')
      const preservesConfirmedIdentity = targetIsConfirmed && targetRow!.finding.status === rawStoredFinding.status
      const storedFinding: Finding = preservesConfirmedIdentity && targetRow
        ? {
            ...rawStoredFinding,
            cwe: targetRow.finding.cwe,
            origin: targetRow.finding.origin,
            title: targetRow.finding.title,
            category: targetRow.finding.category,
            severity: targetRow.finding.severity,
            ...(targetRow.finding.fingerprintHash !== undefined ? { fingerprintHash: targetRow.finding.fingerprintHash } : {}),
          }
        : rawStoredFinding

      if (storedFinding.status === 'confirmed') {
        if (storedFinding.verificationTier === 'static_verified') {
          storedFinding.verificationTier = 'runtime_confirmed'
        }
        if (targetRow?.finding.status === 'static_verified' && !incoming.runtimeProofGap) {
          storedFinding.runtimeProofGap = null
        }
      }

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
        if (options.backingKind === 'harness_assisted') {
          throw new InvariantError(
            'invariant.harness_assisted_confirmation',
            `Invariant: harness_assisted findings cannot persist as runtime_confirmed for ${storedFinding.id}.`,
          )
        }
        const hasAuthorizedBacking = this.isAuthorizedHostBackingKind(options.backingKind)
        const requireReceiptOnly =
          !hasAuthorizedBacking
          && (options.requireReceiptOrBackingKind === true || this.isScriptHarnessCaller())
        this.assertConfirmationEvidence(run.id, {
          findingId: storedFinding.id,
          replaySpecId: canonicalSpecId,
          verification: storedFinding.verification,
          findingKind: storedFinding.findingKind,
          verificationTier: storedFinding.verificationTier,
          provenance: options.provenance === 'floor'
            ? 'floor'
            : (targetIsFloorConfirmed ? 'floor' : null),
          status: options.provenance === 'floor'
            ? storedFinding.status
            : (targetRow?.finding.status ?? storedFinding.status),
          requireReceiptOnly,
        })
      }

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

      const existingOperatorTriage = targetRow ? (targetRow.finding as TriagedFinding).operatorTriage : undefined
      const persistedFinding = {
        ...storedFinding,
        ...(existingOperatorTriage !== undefined ? { operatorTriage: existingOperatorTriage } : {}),
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

      let finalCanonical: TriagedFinding
      if (targetRow) {
        const encoded = FindingCodec.toUpdateColumns({
          finding: persistedFinding,
          replaySpecId: canonicalSpecId,
          sourceOrigins: cleanOrigins,
          verificationTier: storedFinding.verificationTier ?? verificationTier,
          fingerprintHash: storedFinding.fingerprintHash ?? targetRow.fingerprintHash ?? null,
          supersededByFindingId: storedFinding.supersededByFindingId ?? targetRow.supersededByFindingId ?? null,
          counterevidence: storedFinding.counterevidence ?? targetRow.counterevidence ?? null,
          confidenceRationale: storedFinding.confidenceRationale ?? targetRow.confidenceRationale ?? null,
          severityChangeConditions: storedFinding.severityChangeConditions ?? targetRow.severityChangeConditions ?? null,
          codeLocations: storedFinding.codeLocations ?? targetRow.codeLocations ?? null,
          provenance,
          parentFindingIds: parentFindingIds?.length ? parentFindingIds : null,
          verificationClass,
        })
        this.session.client.prepare(`
          UPDATE findings
          SET replay_spec_id = ?, source_origins = ?, verification_tier = ?, fingerprint_hash = ?,
              superseded_by_finding_id = ?, counterevidence = ?, confidence_rationale = ?,
              severity_change_conditions = ?, code_locations = ?, provenance = ?,
              parent_finding_ids = ?, verification_class = ?, status = ?, severity = ?,
              cwe = ?, origin = ?, triage_status = ?, finding = ?
          WHERE id = ?
        `).run(
          encoded.replay_spec_id ?? null,
          encoded.source_origins ?? JSON.stringify(cleanOrigins),
          encoded.verification_tier ?? null,
          encoded.fingerprint_hash ?? null,
          encoded.superseded_by_finding_id ?? null,
          encoded.counterevidence ?? null,
          encoded.confidence_rationale ?? null,
          encoded.severity_change_conditions ?? null,
          encoded.code_locations ?? null,
          encoded.provenance ?? provenance,
          encoded.parent_finding_ids ?? null,
          encoded.verification_class,
          encoded.status,
          encoded.severity,
          encoded.cwe,
          encoded.origin,
          encoded.triage_status,
          encoded.finding,
          targetRow.id,
        )
        finalCanonical = encoded.canonical
      } else {
        const encoded = FindingCodec.toRow({
          id: storedFinding.id,
          runId: run.id,
          assetId,
          goalRevision: run.goalRevision,
          checkId: 'chain',
          caseId: storedFinding.id,
          findingKind: 'multi_step_chain',
          replaySpecId: canonicalSpecId,
          sourceOrigins: cleanOrigins,
          verificationTier: storedFinding.verificationTier ?? verificationTier,
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
        })
        this.session.client.prepare(`
          INSERT INTO findings (
            id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind,
            replay_spec_id, provenance, parent_finding_ids, verification_class,
            source_origins, verification_tier, fingerprint_hash, superseded_by_finding_id,
            counterevidence, confidence_rationale, severity_change_conditions, code_locations,
            status, severity, cwe, origin, triage_status, finding
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          encoded.id,
          encoded.run_id,
          encoded.asset_id,
          encoded.goal_revision,
          encoded.check_id,
          encoded.case_id,
          encoded.finding_kind,
          encoded.replay_spec_id,
          encoded.provenance,
          encoded.parent_finding_ids,
          encoded.verification_class,
          encoded.source_origins,
          encoded.verification_tier,
          encoded.fingerprint_hash,
          encoded.superseded_by_finding_id,
          encoded.counterevidence,
          encoded.confidence_rationale,
          encoded.severity_change_conditions,
          encoded.code_locations,
          encoded.status,
          encoded.severity,
          encoded.cwe,
          encoded.origin,
          encoded.triage_status,
          encoded.finding,
        )
        finalCanonical = encoded.canonical
      }
      if (targetRow) {
        if (finding.id !== targetRow.id) {
          this.session.db.update(tables.replaySpecs).set({ findingId: targetRow.id })
            .where(and(eq(tables.replaySpecs.runId, run.id), eq(tables.replaySpecs.findingId, finding.id))).run()
        }
        if (redundantRow && redundantRow.id !== targetRow.id) {
          this.session.db.update(tables.replaySpecs).set({ findingId: targetRow.id })
            .where(and(eq(tables.replaySpecs.runId, run.id), eq(tables.replaySpecs.findingId, redundantRow.id))).run()
        }
      }
      if (redundantRow && redundantRow.id !== targetRow?.id) {
        this.session.db.delete(tables.findings).where(eq(tables.findings.id, redundantRow.id)).run()
      }

      this.session.event(run.id, finalCanonical.status === 'pending' ? 'finding.proposed' : 'finding.verified',
        `[${finalCanonical.status}] ${finalCanonical.severity.toUpperCase()} ${finalCanonical.title} (${finalCanonical.origin})`, {
          findingId: finalCanonical.id,
          status: finalCanonical.status,
          severity: finalCanonical.severity,
          origin: finalCanonical.origin,
          replaySpecId: canonicalSpecId,
          deduplicated: Boolean(dupRow),
          provenance,
          verificationClass,
        })
      return finalCanonical
    }, { behavior: 'immediate' })
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
    this.assertTenantRun(input.runId)
    const method = input.method.trim().toUpperCase()
    const pathTemplate = input.pathTemplate.trim()
    const now = Date.now()
    const clampRisk = (v: number) =>
      Number.isFinite(v)
        ? Math.max(0, Math.min(100, Math.round(v)))
        : v === Infinity ? 100 : v === -Infinity ? 0 : 50
    const clampCoverage = (v: number | null | undefined) =>
      typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(100, v)) : null

    return this.session.transaction(() => {
      const resolvedScopeRev = typeof input.scopeRevision === 'number' && Number.isFinite(input.scopeRevision)
        ? Math.max(0, Math.round(input.scopeRevision))
        : (this.session.db.select({ scopeRevision: tables.runs.scopeRevision }).from(tables.runs).where(eq(tables.runs.id, input.runId)).get()?.scopeRevision ?? 1)
      const existing = this.session.db.select().from(tables.endpoints).where(and(
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
        return this.session.db.update(tables.endpoints).set({
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
      return this.session.db.insert(tables.endpoints).values({
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
    this.assertTenantRun(runId)
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
    return this.session.db.select().from(tables.endpoints).where(and(...conditions))
      .orderBy(...order).limit(limit).offset(offset).all()
  }

  updateEndpointCoverage(
    endpointId: string,
    coveragePct: number | null,
    testedClasses?: readonly string[],
  ): EndpointRow {
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.endpoints).where(eq(tables.endpoints.id, endpointId)).get()
      if (!existing) throw new Error('Endpoint not found.')
      this.session.requireRun(existing.runId)
      const nextCov = typeof coveragePct === 'number' && Number.isFinite(coveragePct)
        ? Math.max(0, Math.min(100, coveragePct))
        : coveragePct === null ? null : existing.coveragePct
      const nextTested = testedClasses
        ? [...new Set([...existing.testedClasses, ...testedClasses])]
        : existing.testedClasses
      return this.session.db.update(tables.endpoints).set({
        coveragePct: nextCov,
        testedClasses: nextTested,
        updatedAt: Date.now(),
      }).where(eq(tables.endpoints.id, endpointId)).returning().get()!
    }, { behavior: 'immediate' })
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
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.endpointParams).where(and(
        eq(tables.endpointParams.endpointId, input.endpointId),
        eq(tables.endpointParams.name, input.name),
        eq(tables.endpointParams.location, input.location),
      )).get()
      if (existing) {
        return this.session.db.update(tables.endpointParams).set({
          inferredType: input.inferredType ?? existing.inferredType,
          isCsrf: existing.isCsrf || Boolean(input.isCsrf),
          isObjectId: existing.isObjectId || Boolean(input.isObjectId),
          source: input.source,
        }).where(eq(tables.endpointParams.id, existing.id)).returning().get()!
      }
      return this.session.db.insert(tables.endpointParams).values({
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
    return this.session.db.select().from(tables.endpointParams).where(where)
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
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.apiDependencies).where(and(
        eq(tables.apiDependencies.runId, input.runId),
        eq(tables.apiDependencies.producerEndpointId, input.producerEndpointId),
        eq(tables.apiDependencies.consumerEndpointId, input.consumerEndpointId),
        eq(tables.apiDependencies.resourceKey, input.resourceKey),
      )).get()
      if (existing) {
        const mergedTransitions = [...new Set([...existing.observedTransitions, ...(input.observedTransitions ?? [])])]
        return this.session.db.update(tables.apiDependencies).set({
          sampleResourceIdHash: safeHash ?? existing.sampleResourceIdHash,
          personaHandle: input.personaHandle ?? existing.personaHandle,
          observedTransitions: mergedTransitions,
          testedBola: existing.testedBola || Boolean(input.testedBola),
        }).where(eq(tables.apiDependencies.id, existing.id)).returning().get()!
      }
      return this.session.db.insert(tables.apiDependencies).values({
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
    return this.session.db.select().from(tables.apiDependencies).where(eq(tables.apiDependencies.runId, runId))
      .orderBy(asc(tables.apiDependencies.createdAt)).all()
  }

  markApiDependencyTestedBola(id: string): ApiDependencyRow {
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.apiDependencies).where(eq(tables.apiDependencies.id, id)).get()
      if (!existing) throw new Error('API dependency not found.')
      this.session.requireRun(existing.runId)
      return this.session.db.update(tables.apiDependencies).set({ testedBola: true })
        .where(eq(tables.apiDependencies.id, id)).returning().get()!
    }, { behavior: 'immediate' })
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
    return this.session.transaction(() => {
      const existing = this.session.client.prepare(
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
        this.session.client.prepare(
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
      this.session.client.prepare(
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
    const rows = this.session.client.prepare(
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
    this.assertTenantRun(input.runId)
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.secondOrderCanaries).where(
        eq(tables.secondOrderCanaries.marker, input.marker),
      ).get()
      if (existing) {
        if (existing.runId === input.runId) return existing
        throw new Error('Second-order canary marker collision across runs.')
      }
      return this.session.db.insert(tables.secondOrderCanaries).values({
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
    }, { behavior: 'immediate' })
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
    return this.session.transaction(() => {
      const existing = this.session.db.select().from(tables.secondOrderCanaries)
        .where(eq(tables.secondOrderCanaries.id, id)).get()
      if (!existing) throw new Error('Second-order canary not found.')
      this.session.requireRun(existing.runId)
      const updated = this.session.db.update(tables.secondOrderCanaries).set({
        surfacedOrigin: details.surfacedOrigin,
        surfacedEndpoint: redact(details.surfacedEndpoint),
        surfacedPersona: details.surfacedPersona ?? null,
        surfacedExchangeId: details.surfacedExchangeId ?? null,
        status: details.status ?? 'surfaced',
        surfacedAt: Date.now(),
      }).where(eq(tables.secondOrderCanaries.id, id)).returning().get()!
      this.session.event(updated.runId, 'second_order_canary.surfaced',
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
    }, { behavior: 'immediate' })
  }

  listSecondOrderCanaries(runId: string, status?: SecondOrderCanaryStatus): SecondOrderCanaryRow[] {
    this.assertTenantRun(runId)
    const where = status
      ? and(eq(tables.secondOrderCanaries.runId, runId), eq(tables.secondOrderCanaries.status, status))
      : eq(tables.secondOrderCanaries.runId, runId)
    return this.session.db.select().from(tables.secondOrderCanaries).where(where)
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
    return this.session.db.insert(tables.labTelemetry).values({
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
    return this.session.db.select().from(tables.labTelemetry).where(eq(tables.labTelemetry.runId, runId))
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
    return this.session.db.insert(tables.benchmarkRuns).values({
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
      ? this.session.db.select().from(tables.benchmarkRuns).where(eq(tables.benchmarkRuns.suite, suite))
      : this.session.db.select().from(tables.benchmarkRuns)
    return query.orderBy(desc(tables.benchmarkRuns.createdAt)).limit(capped).all()
  }

  getLatestBenchmarkRun(suite: string): BenchmarkRunRow | null {
    return this.session.db.select().from(tables.benchmarkRuns).where(eq(tables.benchmarkRuns.suite, suite))
      .orderBy(desc(tables.benchmarkRuns.createdAt)).limit(1).get() ?? null
  }

  /**
   * Persist or update a baseline or OOB-confirmed finding through the repository boundary.
   * Enforces tenant isolation, confirmation-evidence invariants, `FindingCodec` promoted-column
   * sync, and an explicit `run_id` predicate on every UPDATE.
   */
  upsertFindingRecord(input: {
    runId: string
    assetId: string
    goalRevision: number
    findingId: string
    existingId?: string | null
    checkId: string
    caseId: string
    findingKind: 'baseline_check' | 'multi_step_chain'
    replaySpecId?: string | null
    sourceOrigins: string[]
    verificationTier: VerificationTier | null
    provenance?: FindingProvenance
    verificationClass: FindingVerificationClass
    finding: Finding
  }): TriagedFinding {
    this.assertTenantRun(input.runId)
    return this.session.transaction(() => {
      const provenance = input.provenance ?? 'agent_only'
      const verificationClass = verificationClassForFinding(input.finding, input.verificationClass)
      assertConfirmedVerificationClass(input.finding.status, verificationClass)
      if (input.finding.status === 'confirmed') {
        this.assertConfirmationEvidence(input.runId, {
          findingId: input.findingId,
          replaySpecId: input.replaySpecId ?? null,
          verification: input.finding.verification,
          findingKind: input.findingKind,
          verificationTier: input.verificationTier,
          provenance,
          status: input.finding.status,
        })
      }
      if (input.existingId) {
        const encoded = FindingCodec.toUpdateColumns({
          finding: input.finding,
          verificationTier: input.verificationTier,
          verificationClass,
        })
        this.session.client.prepare(`
          UPDATE findings
          SET verification_tier = ?, verification_class = ?,
              status = ?, severity = ?, cwe = ?, origin = ?, triage_status = ?,
              finding = ?
          WHERE run_id = ? AND id = ?
        `).run(
          encoded.verification_tier ?? null,
          encoded.verification_class,
          encoded.status,
          encoded.severity,
          encoded.cwe,
          encoded.origin,
          encoded.triage_status,
          encoded.finding,
          input.runId,
          input.existingId,
        )
        return encoded.canonical
      }
      const encoded = FindingCodec.toRow({
        id: input.findingId,
        runId: input.runId,
        assetId: input.assetId,
        goalRevision: input.goalRevision,
        checkId: input.checkId,
        caseId: input.caseId,
        findingKind: input.findingKind,
        replaySpecId: input.replaySpecId ?? null,
        provenance,
        parentFindingIds: null,
        verificationClass,
        sourceOrigins: input.sourceOrigins,
        verificationTier: input.verificationTier,
        fingerprintHash: null,
        supersededByFindingId: null,
        counterevidence: null,
        confidenceRationale: null,
        severityChangeConditions: null,
        codeLocations: null,
        finding: input.finding,
      })
      this.session.client.prepare(`
        INSERT INTO findings (
          id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind,
          replay_spec_id, provenance, parent_finding_ids, verification_class,
          source_origins, verification_tier, fingerprint_hash, superseded_by_finding_id,
          counterevidence, confidence_rationale, severity_change_conditions, code_locations,
          status, severity, cwe, origin, triage_status, finding
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        encoded.id,
        encoded.run_id,
        encoded.asset_id,
        encoded.goal_revision,
        encoded.check_id,
        encoded.case_id,
        encoded.finding_kind,
        encoded.replay_spec_id,
        encoded.provenance,
        encoded.parent_finding_ids,
        encoded.verification_class,
        encoded.source_origins,
        encoded.verification_tier,
        encoded.fingerprint_hash,
        encoded.superseded_by_finding_id,
        encoded.counterevidence,
        encoded.confidence_rationale,
        encoded.severity_change_conditions,
        encoded.code_locations,
        encoded.status,
        encoded.severity,
        encoded.cwe,
        encoded.origin,
        encoded.triage_status,
        encoded.finding,
      )
      return encoded.canonical
    }, { behavior: 'immediate' })
  }
}
