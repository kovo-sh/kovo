import { createHash, randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { and, asc, desc, eq, gt, inArray, sql } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-sqlite'
import { migrate } from 'drizzle-orm/node-sqlite/migrator'
import type { z } from 'zod'
import type { importAccessPolicy } from '../access-policy.ts'
import {
  assessmentCheckTitles,
  assetOriginForEnvironment,
  canReviewScope,
  defaultBudgetRequests,
  defaultBudgetUsd,
  defaultLabBudgetRequests,
  defaultMaxRpsPerOrigin,
  defaultPublicBudgetRequests,
  defaultWorkerConcurrency,
  defaultWorkerMaxTurns,
  isLocalLabEnvEnabled,
  workerHistory,
} from '../domain.ts'
import type {
  CallerCompatibility,
  Candidate,
  CapabilityTier,
  CheckCoverage,
  CodeLocation,
  DynamicRetestVerdict,
  EvidenceSummary,
  Finding,
  LabConfig,
  OwaspCategory,
  PatchProposalStatus,
  PatchProposalSummary,
  ReportBody,
  RunCommand,
  SelectedChecks,
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
import {
  chainFindingDedupKey,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
  findingSeverityOrder,
  mergeChainFindings,
  suppliedResponseLabel,
} from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { listProjectPersonas } from './persona-vault.ts'
import { redact, redactHeaders } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { responseCapture, restrictAccessVerification } from './report-evidence.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks } from './review-plan.ts'
import * as tables from './schema.ts'

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
export type ReplaySpecRow = typeof tables.replaySpecs.$inferSelect
export type RetestRun = typeof tables.retestRuns.$inferSelect
export type CoverageEntry = typeof tables.coverageEntries.$inferSelect
export type CanaryRow = typeof tables.canaries.$inferSelect
export type SastRun = typeof tables.sastRuns.$inferSelect
export type SurfaceProbe = typeof tables.surfaceProbes.$inferSelect
export type PatchProposal = typeof tables.patchProposals.$inferSelect
export type ReportRow = typeof tables.reports.$inferSelect
export type MessageRow = typeof tables.messages.$inferSelect

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

export class Store {
  readonly db
  readonly client: DatabaseSync
  readonly workspace
  readonly directory: string
  private readonly processLock: DatabaseSync
  private readonly emitter = new EventEmitter()
  private ftsAvailable = false
  private txDepth = 0

  constructor(directory: string) {
    this.directory = directory
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
    this.client = new DatabaseSync(path, { timeout: 5000 })
    this.client.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;')
    this.db = drizzle({ client: this.client })
    const result = migrate(this.db, { migrationsFolder: resolve('drizzle') })
    if (result && 'exitCode' in result) throw new Error('Guardian database migration failed.')
    this.initV3Schema()
    this.initFts()
    const current = this.db.select().from(tables.workspaces).limit(1).get()
    this.workspace = current ?? this.db.insert(tables.workspaces).values({
      id: randomUUID(),
      actorId: randomUUID(),
      name: 'Personal workspace',
      createdAt: Date.now(),
    }).returning().get()
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

  private initFts() {
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
  }

  close() {
    try { this.client.close() } catch { /* ignore */ }
    try { this.processLock.exec('ROLLBACK') } catch { /* ignore */ }
    try { this.processLock.close() } catch { /* ignore */ }
  }

  transaction<T>(fn: () => T, _options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T {
    if (this.txDepth === 0) {
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

  private recover() {
    this.transaction(() => {
      const interrupted = this.db.select().from(tables.runs).where(and(
        eq(tables.runs.workspaceId, this.workspace.id), eq(tables.runs.status, 'running'),
      )).all()
      for (const run of interrupted) {
        this.setStatus(run, 'paused')
        this.db.update(tables.chainSteps).set({ status: 'ready', assignedWorkerId: null, updatedAt: Date.now() })
          .where(and(eq(tables.chainSteps.runId, run.id), eq(tables.chainSteps.status, 'running'))).run()
        this.event(run.id, 'interrupted', 'The application restarted. Resume to continue from saved evidence.')
      }
    }, { behavior: 'immediate' })
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

  eventsAfter(runId: string, after: number, limit = 1000) {
    return this.db.select({
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
    return {
      project,
      assets: this.db.select().from(tables.projectAssets).where(eq(tables.projectAssets.projectId, projectId)).all(),
      personas: listProjectPersonas(this, projectId),
      specs: this.listProjectSpecs(projectId),
      runs: this.db.select({
        id: tables.runs.id,
        goal: tables.runs.goal,
        status: tables.runs.status,
        phase: tables.runs.phase,
        capabilityTier: tables.runs.capabilityTier,
        spentUsd: tables.runs.spentUsd,
        spentRequests: tables.runs.spentRequests,
        turnsUsed: tables.runs.turnsUsed,
        createdAt: tables.runs.createdAt,
      }).from(tables.runs).where(eq(tables.runs.projectId, projectId)).orderBy(desc(tables.runs.createdAt)).all(),
    }
  }

  runDetail(runId: string) {
    const run = this.run(runId)
    const streamHead = this.db.select({ id: tables.events.id }).from(tables.events)
      .where(eq(tables.events.runId, run.id)).orderBy(desc(tables.events.id)).limit(1).get()
    const evidence = this.db.select().from(tables.evidence).where(eq(tables.evidence.runId, runId))
      .orderBy(asc(tables.evidence.createdAt)).all()
    const threatModel = this.latestThreatModel(runId, run.goalRevision)
    const chainSteps = this.listChainSteps(runId)
    const facts = this.db.select().from(tables.facts).where(eq(tables.facts.runId, runId))
      .orderBy(asc(tables.facts.createdAt)).all()
    const graphEdges = this.listGraphEdges(runId)
    const digests = this.listDigests(runId, false)
    const assignments = this.workerList(runId)
    const approvals = this.listApprovalRequests(runId)
    const exchangesSummary: ExchangeSummary[] = this.db.select({
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
    }).from(tables.brokerExchanges).where(eq(tables.brokerExchanges.runId, runId))
      .orderBy(desc(tables.brokerExchanges.createdAt)).limit(500).all()
      .map(ex => ({ ...ex, bodyPreview: ex.bodyPreview.slice(0, 320) }))
    const coverageEntries = this.listCoverageEntries(runId)
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
    }))
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
      openProofGaps,
      sastRuns,
      surfaceProbes,
      patchProposals,
      replaySpecs: replaySpecs as unknown as SerializableReplaySpecRow[],
      retestRuns,
      findings,
      messages: this.db.select().from(tables.messages).where(eq(tables.messages.runId, runId))
        .orderBy(asc(tables.messages.createdAt), sql`${tables.messages}.rowid`).all(),
      evidence: evidence.map(item => ({ ...item, title: evidenceTitle(run, item.kind, item.title) })),
      reports: this.db.select().from(tables.reports).where(eq(tables.reports.runId, runId))
        .orderBy(desc(tables.reports.version)).all(),
      cursor: streamHead?.id ?? 0,
    }
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

  writeBlob(content: string, secrets: readonly NamedSecret[] = []): { id: string; sha256: string } {
    const clean = redact(content, secrets)
    const sha256 = createHash('sha256').update(clean, 'utf8').digest('hex')
    const id = 'blob-' + sha256
    const file = join(this.directory, 'artifacts', id + '.txt')
    if (!existsSync(file)) {
      try {
        writeFileSync(file, clean, { flag: 'wx', mode: 0o600, flush: true })
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      }
    }
    return { id, sha256 }
  }

  readBlob(blobId: string): string {
    if (!/^blob-[a-f0-9]{64}$/.test(blobId)) throw new Error('Invalid blob ID.')
    return readFileSync(join(this.directory, 'artifacts', blobId + '.txt'), 'utf8')
  }

  artifact(runId: string, artifactId: string) {
    const run = this.run(runId)
    const item = this.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.id, artifactId), eq(tables.evidence.runId, runId),
    )).get()
    if (!item) throw new Error('Evidence not found.')
    return {
      ...item,
      title: evidenceTitle(run, item.kind, item.title),
      content: readFileSync(join(this.directory, 'artifacts', item.id + '.txt'), 'utf8'),
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
    writeFileSync(join(this.directory, 'artifacts', id + '.txt'), redact(content, secrets), { flag: 'wx', mode: 0o600, flush: true })
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
      const blob = this.writeBlob(cleanBody, secrets)
      bodyArtifactId = blob.id
      bodySha256 = blob.sha256
    } else {
      bodySha256 = createHash('sha256').update('').digest('hex')
    }

    const row: typeof tables.brokerExchanges.$inferInsert = {
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
      durationMs: Math.max(0, Math.round(input.durationMs)),
      createdAt: Date.now(),
    }

    const inserted = this.transaction(() => {
      const ex = this.db.insert(tables.brokerExchanges).values(row).returning().get()
      if (this.ftsAvailable) {
        this.client.prepare(
          `INSERT INTO broker_exchanges_fts (exchange_id, run_id, origin, method, path_and_query, req_headers, resp_headers, body_preview)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          ex.id, ex.runId, ex.origin, ex.method, ex.pathAndQuery,
          JSON.stringify(ex.reqHeaders), JSON.stringify(ex.respHeaders), ex.bodyPreview,
        )
      }
      this.db.update(tables.runs).set({ spentRequests: sql`${tables.runs.spentRequests} + 1` })
        .where(eq(tables.runs.id, input.runId)).run()
      this.db.update(tables.assignments).set({ requestsUsed: sql`${tables.assignments.requestsUsed} + 1` })
        .where(eq(tables.assignments.id, input.assignmentId)).run()
      return ex
    }, { behavior: 'immediate' })

    this.event(input.runId, 'broker.exchange', `${inserted.method} ${inserted.origin}${inserted.pathAndQuery.slice(0, 80)} → ${inserted.status}`, {
      exchangeId: inserted.id,
      assignmentId: inserted.assignmentId,
      origin: inserted.origin,
      finalOrigin: inserted.finalOrigin,
      status: inserted.status,
      personaHandle: inserted.personaHandle,
    })
    return inserted
  }

  getExchange(runId: string, exchangeId: string): (BrokerExchange & { body: string }) {
    this.run(runId)
    const row = this.db.select().from(tables.brokerExchanges).where(and(
      eq(tables.brokerExchanges.runId, runId), eq(tables.brokerExchanges.id, exchangeId),
    )).get()
    if (!row) throw new Error('Broker exchange not found.')
    let body = row.bodyPreview
    if (row.bodyArtifactId) {
      try { body = this.readBlob(row.bodyArtifactId) } catch { body = row.bodyPreview }
    }
    return { ...row, body }
  }

  searchExchanges(runId: string, query: string, opts: {
    approvedOrigins?: ReadonlySet<string>
    origin?: string
    limit?: number
  } = {}): BrokerExchange[] {
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
  }): ChainStep {
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
  } = {}): Fact[] {
    const all = this.db.select().from(tables.facts).where(eq(tables.facts.runId, runId))
      .orderBy(desc(tables.facts.createdAt)).all()
    const q = opts.query?.trim().toLowerCase()
    const filtered = all.filter(f => {
      if (!opts.includeTainted && f.tainted) return false
      if (opts.origin && f.origin !== opts.origin) return false
      if (opts.kind) {
        const subkind = typeof f.data?.subkind === 'string' ? f.data.subkind : ''
        if (f.kind !== opts.kind && subkind !== opts.kind) return false
      }
      if (q) {
        const hay = `${f.origin} ${f.kind} ${f.summary} ${JSON.stringify(f.data)}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
    return filtered.slice(0, Math.min(Math.max(1, opts.limit ?? 100), 500))
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
      expiresAt: now + (input.expiresInMs ?? 15 * 60_000),
      createdAt: now,
    }).returning().get()
    this.updateWorker(assignment.id, { status: 'waiting_approval' })
    this.event(run.id, 'approval.requested', `Tier 3 approval requested for ${row.method} ${row.origin}${row.pathAndQuery.slice(0, 80)}.`, {
      approvalId: row.id, assignmentId: assignment.id, origin: row.origin, method: row.method,
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Tier 3 approval required: ${row.method} ${row.origin}${row.pathAndQuery}\nRationale: ${row.rationale}`)
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
      decidedBy: this.workspace.actorId,
      decidedAt: Date.now(),
    }).where(eq(tables.approvalRequests.id, approvalId)).returning().get()!
    this.event(run.id, 'approval.decided', `Tier 3 request ${decision} for ${updated.method} ${updated.origin}.`, {
      approvalId: updated.id, assignmentId: updated.assignmentId, decision,
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Tier 3 request ${decision}: ${updated.method} ${updated.origin}${updated.pathAndQuery}`)
    return updated
  }

  // --- Replay Specs, Retests, Coverage, Findings ---

  createReplaySpec(
    run: Run,
    assignment: Assignment,
    findingId: string,
    spec: DeclarativeReplaySpec,
    sourceOrigins: string[],
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
      createdAt: Date.now(),
    }).returning().get()
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
    },
  ): Finding {
    const existing = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, run.id), eq(tables.findings.id, findingId),
    )).get()
    if (!existing) throw new Error('Finding not found.')

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
      finding: mergedFinding,
    }).where(eq(tables.findings.id, existing.id)).run()

    this.event(run.id, 'finding.updated', `Updated finding "${mergedFinding.title}" (${mergedFinding.status}).`, {
      findingId: mergedFinding.id,
      status: mergedFinding.status,
      severity: mergedFinding.severity,
      verificationTier: mergedFinding.verificationTier ?? null,
    })
    return mergedFinding
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
    candidate: Pick<Finding, 'origin' | 'cwe' | 'category' | 'title'>,
    excludeId?: string,
  ) {
    const key = chainFindingDedupKey(candidate)
    const rows = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, runId),
      eq(tables.findings.goalRevision, goalRevision),
      eq(tables.findings.findingKind, 'multi_step_chain'),
    )).all()
    const matches = rows.filter(row => row.id !== excludeId && chainFindingDedupKey(row.finding) === key)
    if (!matches.length) return undefined
    // Prefer confirmed duplicate first, then static_verified, then pending, then others
    const order: Record<Finding['status'], number> = {
      confirmed: 0, static_verified: 1, pending: 2, inconclusive: 3, dismissed: 4,
    }
    matches.sort((a, b) => order[a.finding.status] - order[b.finding.status])
    return matches[0]
  }

  upsertChainFinding(
    run: Run,
    assetId: string,
    finding: Finding,
    replaySpecId: string,
    sourceOrigins: string[],
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

    const storedFinding: Finding = targetRow
      ? mergeChainFindings(targetRow.finding, incoming)
      : incoming

    const canonicalSpecId = storedFinding.replaySpecId ?? replaySpecId
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
          finding: storedFinding,
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
          finding: storedFinding,
        }).run()
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
      })
    return storedFinding
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
        ? (input.labConfig.enabled && !isLocalLabEnvEnabled()
            ? (() => { throw new Error('Enabling local-lab execution requires GUARDIAN_ALLOW_LOCAL_LAB=1.') })()
            : input.labConfig)
        : null
      const project = this.db.insert(tables.projects).values({
        id: randomUUID(),
        workspaceId: this.workspace.id,
        name: redact(input.name),
        environment,
        seeds: validatedSeeds,
        defaultScope: [],
        labConfig,
        createdAt: Date.now(),
      }).returning().get()
      this.db.insert(tables.projectAssets).values(project.seeds.map(origin => ({
        id: randomUUID(), projectId: project.id, origin, source: 'Project seed', thirdParty: false,
      }))).run()
      this.event(null, 'project.created', 'Project created.', { projectId: project.id, environment: project.environment })
      return { id: project.id }
    })
  }

  updateProjectLabConfig(input: { requestId: string; projectId: string; labConfig: LabConfig | null }) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      if (input.labConfig?.enabled) {
        if (project.environment !== 'local-lab') {
          throw new Error('Local-lab app execution is forbidden on public projects.')
        }
        if (!isLocalLabEnvEnabled()) {
          throw new Error('Local-lab app execution requires GUARDIAN_ALLOW_LOCAL_LAB=1 on the server.')
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

  createRun(input: z.output<typeof newRun>) {
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
        candidates: [],
        approved: [],
        createdAt: Date.now(),
      }).returning().get()
      this.event(run.id, 'run.created', 'Run created.', { capabilityTier, sourceMode: input.sourceMode })
      const goalMessageId = this.message(run.id, run.coordinatorId, 'operator', goal)
      this.updateRun(run.id, { reviewPlan: { status: 'pending', goalMessageId } })
      return { id: run.id }
    })
  }

  addProjectAsset(input: z.output<typeof projectAsset>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const origin = assetOriginForEnvironment(project.environment).parse(input.origin)
      const candidate = this.saveCandidate(project.id, { ...input, origin })
      return { id: candidate.id }
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
      thirdParty: input.thirdParty, prepared: input.prepared ?? null,
    }
    const insert = this.db.insert(tables.projectAssets).values(candidate)
    if (replace) return insert.onConflictDoUpdate({
      target: [tables.projectAssets.projectId, tables.projectAssets.origin],
      set: { source: candidate.source, thirdParty: candidate.thirdParty, ...(input.prepared === undefined ? {} : { prepared: input.prepared }) },
    }).returning().get()
    insert.onConflictDoNothing().run()
    return this.db.select().from(tables.projectAssets).where(and(
      eq(tables.projectAssets.projectId, projectId), eq(tables.projectAssets.origin, input.origin),
    )).get()!
  }

  suggestCandidateHost(run: Run, origin: string, source: string, thirdParty = false) {
    if (run.candidates.some(candidate => candidate.origin === origin)) {
      return { added: false, origin }
    }
    const asset = this.saveCandidate(run.projectId, { origin, source: redact(source), thirdParty }, false)
    const discovery = this.workerList(run.id).find(worker => worker.phase === 'discovery' && worker.assetId === null)
    const sourceEv = discovery && this.recordInventory(run, discovery, 'Candidate source', [asset])
    const candidate = sourceEv ? { ...asset, sourceEvidenceId: sourceEv.id } : asset
    this.updateRun(run.id, { candidates: [...run.candidates, candidate] })
    this.event(run.id, 'asset.candidate', `Worker suggested candidate host ${origin} (unapproved until scope approval).`, {
      id: asset.id, origin: asset.origin, source: redact(source), sourceEvidenceId: sourceEv?.id,
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
        eq(tables.assignments.runId, run.id), inArray(tables.assignments.status, ['queued', 'running', 'waiting_approval']),
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
      if (!approvedOrigins.has(fact.origin) || fact.sourceOrigins.some(o => !approvedOrigins.has(o))) {
        enqueue(`fact:${fact.id}`)
      }
    }
    for (const step of allSteps) {
      if (step.sourceOrigins.some(o => !approvedOrigins.has(o)) ||
          step.targetAssetIds.some(aid => !approvedIdSet.has(aid))) {
        enqueue(`step:${step.id}`)
      }
    }
    for (const worker of allAssignments) {
      if (worker.phase === 'discovery') continue
      const touchesUnapproved =
        (worker.assetId !== null && !approvedIdSet.has(worker.assetId)) ||
        worker.sourceOrigins.some(o => !approvedOrigins.has(o)) ||
        this.brokerOrigins(worker).some(o => !approvedOrigins.has(o))
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

    if (taintedFactIds.length || taintedStepIds.length || canceledAssignmentIds.length) {
      this.event(run.id, 'scope.revoked',
        `Scope revision ${scopeRevision} tainted ${taintedFactIds.length} facts, ${taintedStepIds.length} steps, and canceled ${canceledAssignmentIds.length} assignments.`,
        { scopeRevision, taintedFactIds, taintedStepIds, canceledAssignmentIds })
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

      if (analyzed && this.brokerOrigins(analyzed).some(origin => !approvedOrigins.has(origin))) {
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
      const finding: Finding = {
        ...row.finding,
        verificationTier: row.verificationTier ?? row.finding.verificationTier,
        fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash,
        supersededByFindingId: row.supersededByFindingId ?? row.finding.supersededByFindingId,
        counterevidence: row.counterevidence ?? row.finding.counterevidence,
        confidenceRationale: row.confidenceRationale ?? row.finding.confidenceRationale,
        severityChangeConditions: row.severityChangeConditions ?? row.finding.severityChangeConditions,
        ...(row.codeLocations?.length ? { codeLocations: row.codeLocations } : row.finding.codeLocations?.length ? { codeLocations: row.finding.codeLocations } : {}),
      }
      const isStaticVerified = finding.status === 'static_verified' || finding.verificationTier === 'static_verified'
      if (!isStaticVerified) {
        if (!run.approved.includes(assetId) || !approvedOrigins.has(finding.origin)) return []
        if (sourceOrigins.some(o => !approvedOrigins.has(o))) return []
      } else {
        // Static-verified findings may reference approved origins or synthetic 'https://static-analysis.invalid'
        const nonSynthetic = sourceOrigins.filter(o => o !== 'https://static-analysis.invalid')
        if (nonSynthetic.some(o => !approvedOrigins.has(o))) return []
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

    const body: ReportBody = {
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
          if (specRow.sourceOrigins.some(o => !approvedOrigins.has(o))) {
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
}

export type StoreRunDetail = ReturnType<Store['runDetail']>

let instance: Store | undefined
export function store() {
  return instance ??= new Store(dataDirectory())
}
