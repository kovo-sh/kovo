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
import { join } from 'node:path'
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
import {
  chainFindingDedupKey,
  mergeChainFindings,
} from '../report-summary.ts'
import type {
  FindingProvenance,
  FindingVerificationClass,
} from '../report-summary.ts'
import { computeFindingFingerprint, isOriginWideCwe, normalizeEndpointTemplate } from './dedupe.ts'
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
  uniqueArtifactRunDirs,
  verificationClassForFinding,
  type AgentScriptProofRecord,
  type ApiDependencyRow,
  type Assignment,
  type BenchmarkRunRow,
  type BrokerExchange,
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

export class FindingsRepository {
  private readonly session: DbSession

  constructor(session: DbSession) {
    this.session = session
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
   * Delete aged exchanges (rows + FTS rows + unreferenced sharded body blobs) for one run in
   * bounded IMMEDIATE batches. `olderThanMs` bounds the age, `keepLatest` always preserves the
   * newest N exchanges. An unbounded delete (no cutoff and no keepLatest) is a no-op.
   */
  pruneExchanges(options: PruneExchangesOptions): PruneExchangesResult {
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
    } else {
      const rows = this.session.client.prepare('SELECT id, status FROM runs').all() as Array<{ id: string; status: string }>
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
    const mainDbBytes = safeFileSize(join(this.session.directory, 'guardian.sqlite'))
    const walBytes = safeFileSize(join(this.session.directory, 'guardian.sqlite-wal'))
    const shmBytes = safeFileSize(join(this.session.directory, 'guardian.sqlite-shm'))
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

  private pruneExchangeRows(options: PruneExchangesOptions): PruneExchangesResult {
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
    const runDirs = uniqueArtifactRunDirs(this.session.directory)
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
    const rows = this.session.client.prepare(
      `SELECT rowid AS rowid, id, body_artifact_id FROM broker_exchanges
       WHERE ${conditions.join(' AND ')} ORDER BY rowid ASC LIMIT ?`,
    ).all(...params, state.batchSize) as Array<{ rowid: number; id: string; body_artifact_id: string | null }>
    if (!rows.length) return null
    const ids = rows.map(row => row.id)
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
    artifactRunDirs: readonly string[] = uniqueArtifactRunDirs(this.session.directory),
  ): { deleted: boolean; bytes: number } {
    const referenced = this.session.client.prepare(
      'SELECT 1 AS hit FROM broker_exchanges WHERE body_artifact_id = ? LIMIT 1',
    ).get(blobId) as { hit?: number } | undefined
    if (referenced?.hit) return { deleted: false, bytes: 0 }
    const candidates = new Set<string>([join(this.session.directory, 'artifacts', blobId + '.txt')])
    const bucket = artifactBucket(blobId)
    const runDirs = new Set<string>([runId, ...artifactRunDirs])
    for (const dir of runDirs) {
      candidates.add(join(this.session.directory, 'artifacts', dir, 'blobs', bucket, blobId + '.txt'))
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
    return this.session.db.select().from(tables.graphEdges).where(eq(tables.graphEdges.runId, runId))
      .orderBy(asc(tables.graphEdges.createdAt)).all()
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
    const row = this.session.db.update(tables.replaySpecs)
      .set(proofColumns(proof))
      .where(and(eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId)))
      .returning().get()
    if (!row) throw new Error('Replay spec not found.')
    return row
  }

  /** Proof columns for a row (or null when the row is not a script proof). */
  replaySpecProof(runId: string, replaySpecId: string): AgentScriptProofRecord | null {
    const row = this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
    )).get()
    return row ? proofRecordOf(row) : null
  }

  /** Latest script proof attached to any spec row of a finding (null when none). */
  agentProofForFinding(runId: string, findingId: string): AgentScriptProofRecord | null {
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
    const row = this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.id, replaySpecId),
    )).get()
    if (!row) throw new Error('Replay spec not found.')
    return row
  }

  listReplaySpecs(runId: string): ReplaySpecRow[] {
    return this.session.db.select().from(tables.replaySpecs).where(eq(tables.replaySpecs.runId, runId))
      .orderBy(desc(tables.replaySpecs.createdAt)).all()
  }

  listReplaySpecsForFinding(runId: string, findingId: string): ReplaySpecRow[] {
    return this.session.db.select().from(tables.replaySpecs).where(and(
      eq(tables.replaySpecs.runId, runId), eq(tables.replaySpecs.findingId, findingId),
    )).orderBy(desc(tables.replaySpecs.createdAt)).all()
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
    if (replayVerdictConfirmsRuntime(verdict)) {
      return { backed: true, contradicted: false, kind: 'spec', verdict, replaySpecId }
    }
    const receipt = typeof input.verification === 'string' && input.verification.startsWith('ProofReceipt')
      ? true
      : Boolean(this.session.db.select({ id: tables.events.id }).from(tables.events).where(and(
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
      const floorEvent = this.session.db.select({ id: tables.events.id }).from(tables.events).where(and(
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
    this.session.transaction(() => {
      this.session.db.update(tables.findings).set({
        verificationClass: 'open_proof_gap',
        verificationTier: null,
        finding: demoted,
      }).where(and(eq(tables.findings.runId, runId), eq(tables.findings.id, findingId))).run()
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
    })
    return saved
  }

  listPatchProposals(runId: string, findingId?: string): PatchProposal[] {
    const where = findingId
      ? and(eq(tables.patchProposals.runId, runId), eq(tables.patchProposals.findingId, findingId))
      : eq(tables.patchProposals.runId, runId)
    return this.session.db.select().from(tables.patchProposals).where(where)
      .orderBy(desc(tables.patchProposals.updatedAt)).all()
  }

  getPatchProposal(runId: string, patchId: string): PatchProposal {
    const row = this.session.db.select().from(tables.patchProposals).where(and(
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
    const existing = this.session.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, run.id), eq(tables.findings.id, findingId),
    )).get()
    if (!existing) throw new Error('Finding not found.')

    // Floor-confirmed rows are immutable: later agent passes may add evidence elsewhere but can
    // never overwrite, downgrade or reclassify the floor's own confirmation.
    if (existing.provenance === 'floor') {
      this.session.event(
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

    this.session.db.update(tables.findings).set({
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

    this.session.event(run.id, 'finding.updated', `Updated finding "${mergedFinding.title}" (${mergedFinding.status}).`, {
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
    const existing = this.session.db.select().from(tables.coverageEntries).where(and(
      eq(tables.coverageEntries.runId, run.id),
      eq(tables.coverageEntries.goalRevision, run.goalRevision),
      eq(tables.coverageEntries.origin, input.origin),
      eq(tables.coverageEntries.category, input.category),
    )).get()
    if (existing) {
      return this.session.db.update(tables.coverageEntries).set({
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
    return this.session.db.insert(tables.coverageEntries).values({
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
    const rows = this.session.db.select().from(tables.findings).where(and(
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
    const targetIsFloor = targetRow?.provenance === 'floor'
    if (targetIsFloor && options.provenance !== 'floor') {
      this.session.event(
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

    this.session.transaction(() => {
      if (targetRow) {
        this.session.db.update(tables.findings).set({
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
        this.session.db.insert(tables.findings).values({
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
    }, { behavior: 'immediate' })

    this.session.event(run.id, storedFinding.status === 'pending' ? 'finding.proposed' : 'finding.verified',
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
    const existing = this.session.db.select().from(tables.endpoints).where(eq(tables.endpoints.id, endpointId)).get()
    if (!existing) throw new Error('Endpoint not found.')
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
    const updated = this.session.db.update(tables.apiDependencies).set({ testedBola: true })
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
    const updated = this.session.db.update(tables.secondOrderCanaries).set({
      surfacedOrigin: details.surfacedOrigin,
      surfacedEndpoint: redact(details.surfacedEndpoint),
      surfacedPersona: details.surfacedPersona ?? null,
      surfacedExchangeId: details.surfacedExchangeId ?? null,
      status: details.status ?? 'surfaced',
      surfacedAt: Date.now(),
    }).where(eq(tables.secondOrderCanaries.id, id)).returning().get()
    if (!updated) throw new Error('Second-order canary not found.')
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
  }

  listSecondOrderCanaries(runId: string, status?: SecondOrderCanaryStatus): SecondOrderCanaryRow[] {
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
}
