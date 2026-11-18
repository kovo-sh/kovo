import { createHash, randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { and, asc, desc, eq, gt, inArray, sql } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-sqlite'
import { migrate } from 'drizzle-orm/node-sqlite/migrator'
import type { z } from 'zod'
import type { importAccessPolicy } from '../access-policy.ts'
import { assessmentCheckTitles } from '../domain.ts'
import type { Candidate, CheckCoverage, EvidenceSummary, ReportBody, RunCommand, SelectedChecks, WorkerPhase, importDnsInventory, newProject, newRun, projectAsset } from '../domain.ts'
import { parseDnsInventory } from '../passive-dns.ts'
import { findingSeverityOrder, suppliedResponseLabel } from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { responseReview } from './response-checks.ts'
import * as tables from './schema.ts'
import { redact } from './redact.ts'

export type Run = typeof tables.runs.$inferSelect
export type Assignment = typeof tables.assignments.$inferSelect
type Project = typeof tables.projects.$inferSelect
const inventoryTitle = 'Supplied asset inventory'

function evidenceTitle(run: Run, kind: EvidenceSummary['kind'], title: string) {
  return run.sourceMode === 'prepared' && kind === 'observation' && title === 'Observed public response'
    ? suppliedResponseLabel : title
}

export const dataDirectory = () => resolve(process.env.GUARDIAN_DATA_DIR ?? '.guardian')

export function assessmentAssignments(assignments: readonly Assignment[], assetId: string, goalRevision: number) {
  const ordered = assignments.filter(worker => worker.assetId === assetId && worker.goalRevision === goalRevision)
    .sort((a, b) => b.scopeRevision - a.scopeRevision || b.createdAt - a.createdAt)
  const analysis = ordered.find(worker => worker.phase === 'analysis')
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
    reason: 'Verification had no saved result when this report was created.',
  }))
}

export class Store {
  readonly db
  readonly workspace
  readonly directory: string
  private readonly processLock: DatabaseSync

  constructor(directory: string) {
    this.directory = directory
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    mkdirSync(join(directory, 'artifacts'), { recursive: true, mode: 0o700 })
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
    const client = new DatabaseSync(path, { timeout: 5000 })
    client.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;')
    this.db = drizzle({ client })
    const result = migrate(this.db, { migrationsFolder: resolve('drizzle') })
    if (result && 'exitCode' in result) throw new Error('Guardian database migration failed.')
    const current = this.db.select().from(tables.workspaces).limit(1).get()
    this.workspace = current ?? this.db.insert(tables.workspaces).values({
      id: randomUUID(),
      actorId: randomUUID(),
      name: 'Personal workspace',
      createdAt: Date.now(),
    }).returning().get()
    this.recover()
  }

  private recover() {
    this.db.transaction(() => {
      const interrupted = this.db.select().from(tables.runs).where(and(
        eq(tables.runs.workspaceId, this.workspace.id), eq(tables.runs.status, 'running'),
      )).all()
      for (const run of interrupted) {
        this.setStatus(run, 'paused')
        this.event(run.id, 'interrupted', 'The application restarted. Resume to continue from saved evidence.')
      }
    }, { behavior: 'immediate' })
  }

  event(runId: string | null, kind: string, message: string, detail: Record<string, unknown> = {}) {
    this.db.insert(tables.events).values({
      workspaceId: this.workspace.id, runId, kind, message: redact(message), detail, createdAt: Date.now(),
    }).run()
  }

  message(runId: string, threadId: string, role: typeof tables.messages.$inferSelect.role, content: string, replyTo?: string) {
    const id = randomUUID()
    this.db.insert(tables.messages).values({
      id, runId, threadId, role, content: redact(content), replyTo, createdAt: Date.now(),
    }).onConflictDoNothing().run()
    return id
  }

  eventsAfter(runId: string, after: number) {
    return this.db.select({
      id: tables.events.id, kind: tables.events.kind, message: tables.events.message, createdAt: tables.events.createdAt,
    }).from(tables.events).where(and(
      eq(tables.events.workspaceId, this.workspace.id), eq(tables.events.runId, runId), gt(tables.events.id, after),
    )).orderBy(asc(tables.events.id)).limit(250).all()
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

  projectDetail(projectId: string) {
    const project = this.project(projectId)
    return {
      project,
      assets: this.db.select().from(tables.projectAssets).where(eq(tables.projectAssets.projectId, projectId)).all(),
      runs: this.db.select({
        id: tables.runs.id, goal: tables.runs.goal, status: tables.runs.status,
        phase: tables.runs.phase, createdAt: tables.runs.createdAt,
      }).from(tables.runs).where(eq(tables.runs.projectId, projectId)).orderBy(desc(tables.runs.createdAt)).all(),
    }
  }

  runDetail(runId: string) {
    const run = this.run(runId)
    const streamHead = this.db.select({ id: tables.events.id }).from(tables.events)
      .where(eq(tables.events.runId, run.id)).orderBy(desc(tables.events.id)).limit(1).get()
    const evidence = this.db.select().from(tables.evidence).where(eq(tables.evidence.runId, runId))
      .orderBy(asc(tables.evidence.createdAt)).all()
    const initialInventory = evidence.find(item => item.kind === 'inventory' && item.title === inventoryTitle)
    return {
      run: { ...run, candidates: this.linkLegacySources(run, initialInventory?.id) },
      project: this.project(run.projectId),
      assignments: this.workerList(runId),
      messages: this.db.select().from(tables.messages).where(eq(tables.messages.runId, runId))
        .orderBy(asc(tables.messages.createdAt), asc(tables.messages.id)).all(),
      evidence: evidence.map(item => ({ ...item, title: evidenceTitle(run, item.kind, item.title) })),
      reports: this.db.select().from(tables.reports).where(eq(tables.reports.runId, runId))
        .orderBy(desc(tables.reports.version)).all(),
      cursor: streamHead?.id ?? 0,
    }
  }

  private linkLegacySources(run: Run, inventoryId: string | undefined) {
    if (!inventoryId || run.candidates.every(asset => asset.sourceEvidenceId)) return run.candidates
    try {
      const records: unknown = JSON.parse(this.artifact(run.id, inventoryId).content)
      if (!Array.isArray(records)) return run.candidates
      const origins = new Set(records.map(record => record?.origin))
      return run.candidates.map(asset => !asset.sourceEvidenceId && origins.has(asset.origin)
        ? { ...asset, sourceEvidenceId: inventoryId } : asset)
    } catch {
      return run.candidates
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
    return this.db.selectDistinct({ origin: sql<string>`json_extract(${tables.events.detail}, '$.origin')` })
      .from(tables.events).where(and(
        eq(tables.events.runId, assignment.runId), eq(tables.events.kind, 'broker.allowed'),
        sql`json_extract(${tables.events.detail}, '$.assignmentId') = ${assignment.id}`,
      )).all().map(row => row.origin)
  }

  artifact(runId: string, artifactId: string) {
    const run = this.run(runId)
    const item = this.db.select().from(tables.evidence).where(and(
      eq(tables.evidence.id, artifactId), eq(tables.evidence.runId, runId),
    )).get()
    if (!item) throw new Error('Evidence not found.')
    return { ...item, title: evidenceTitle(run, item.kind, item.title),
      content: readFileSync(join(this.directory, 'artifacts', item.id + '.txt'), 'utf8') }
  }

  addArtifact(run: Run, assignment: Assignment, kind: typeof tables.evidence.$inferSelect.kind, title: string, content: string, operationId?: string) {
    if (operationId) {
      const existing = this.assignmentEvidence(assignment.id, operationId)
      if (existing) return existing
    }
    const id = randomUUID()
    writeFileSync(join(this.directory, 'artifacts', id + '.txt'), redact(content), { flag: 'wx', mode: 0o600, flush: true })
    return this.db.insert(tables.evidence).values({
      id, runId: run.id, assignmentId: assignment.id, scopeRevision: run.scopeRevision,
      goalRevision: assignment.goalRevision, title: redact(title), kind, operationId, createdAt: Date.now(),
    }).returning().get()
  }

  operate<Result extends { id: string }>(input: { requestId: string }, apply: () => Result): Result
  operate(input: { requestId: string }, apply: () => { id: string }): { id: string } {
    const fingerprint = createHash('sha256').update(JSON.stringify(input)).digest('hex')
    return this.db.transaction(() => {
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
      const project = this.db.insert(tables.projects).values({
        id: randomUUID(), workspaceId: this.workspace.id, name: redact(input.name),
        seeds: [...new Set(input.seeds)], defaultScope: [], createdAt: Date.now(),
      }).returning().get()
      this.db.insert(tables.projectAssets).values(project.seeds.map(origin => ({
        id: randomUUID(), projectId: project.id, origin, source: 'Project seed', thirdParty: false,
      }))).run()
      this.event(null, 'project.created', 'Project created.')
      return { id: project.id }
    })
  }

  createRun(input: z.output<typeof newRun>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const goal = redact(input.goal)
      const run = this.db.insert(tables.runs).values({
        id: randomUUID(), projectId: project.id, workspaceId: this.workspace.id, coordinatorId: randomUUID(),
        originalGoal: goal, goal, goalRevision: 0, scopeRevision: 0, phase: 'consent', status: 'waiting',
        sourceMode: input.sourceMode,
        candidates: [], approved: [], createdAt: Date.now(),
      }).returning().get()
      this.event(run.id, 'run.created', 'Run created.')
      const goalMessageId = this.message(run.id, run.coordinatorId, 'operator', goal)
      this.updateRun(run.id, { reviewPlan: { status: 'pending', goalMessageId } })
      return { id: run.id }
    })
  }

  addProjectAsset(input: z.output<typeof projectAsset>) {
    return this.operate(input, () => {
      const project = this.project(input.projectId)
      const candidate = this.saveCandidate(project.id, input)
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

  makeWorker(run: Run, phase: WorkerPhase, candidate: Candidate | undefined, title: string, objective: string): Assignment {
    const assignment = this.db.insert(tables.assignments).values({
      id: randomUUID(), runId: run.id, assetId: candidate?.id ?? null, title, objective, phase, status: 'queued',
      scopeRevision: run.scopeRevision, goalRevision: run.goalRevision, sessionId: randomUUID(),
      outcome: null, createdAt: Date.now(),
    }).returning().get()
    const target = candidate?.origin ?? 'Supplied project records'
    const checks = run.reviewPlan?.status === 'ready' && phase !== 'discovery'
      ? ['Checks: ' + run.reviewPlan.checks.map(id => assessmentCheckTitles[id]).join(', ')] : []
    this.addArtifact(run, assignment, 'handoff', 'assignment.md',
      ['# Assignment', '', objective, '', 'Input: ' + target, 'Goal: ' + run.goal,
        'Goal revision: ' + run.goalRevision, 'Scope revision: ' + run.scopeRevision, ...checks].join('\n'), 'assignment')
    return assignment
  }

  private queueAnalysis(run: Run, assetIds: string[]) {
    for (const asset of run.candidates.filter(asset => assetIds.includes(asset.id))) {
      this.makeWorker(run, 'analysis', asset, `Review ${new URL(asset.origin).hostname}`,
        'Review the approved evidence and identify gaps in the planned checks.')
    }
  }

  commitReviewPlan(expected: Pick<Run, 'id' | 'goalRevision' | 'scopeRevision'>, selection: SelectedChecks) {
    this.db.transaction(() => {
      const run = this.run(expected.id)
      const plan = run.reviewPlan
      if (run.status !== 'running' || run.phase !== 'analysis' || plan?.status !== 'pending' ||
        run.goalRevision !== expected.goalRevision || run.scopeRevision !== expected.scopeRevision) return
      const updated = this.updateRun(run.id, { reviewPlan: { status: 'ready', goalMessageId: plan.goalMessageId, ...selection } })
      this.queueAnalysis(updated, updated.approved)
      const titles = selection.checks.map(id => assessmentCheckTitles[id]).join(', ')
      const planned = selection.source === 'coordinator'
      this.message(run.id, run.coordinatorId, planned ? 'coordinator' : 'guardian',
        (planned ? 'I’ll review ' : 'Standard checks selected for this run. Checks include ') + titles + '.', plan.goalMessageId)
      this.event(run.id, 'review.planned', 'Review plan saved.', {
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
    if (status === 'paused' || status === 'stopped' || status === 'failed') {
      this.db.update(tables.assignments).set({ status: 'paused', lease: null }).where(and(
        eq(tables.assignments.runId, run.id), inArray(tables.assignments.status, ['queued', 'running']),
      )).run()
    }
    if (status === 'running') {
      this.db.update(tables.assignments).set({ status: 'queued', lease: null }).where(and(
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
    this.message(run.id, worker.id, 'worker', `Recorded ${inventory.length} candidates from supplied project records.`)
    this.updateRun(run.id, {
      phase: 'review', status: 'waiting',
      candidates: inventory.map(asset => ({ ...asset, sourceEvidenceId: initial.id })),
    })
    this.event(run.id, 'discovery.complete', 'Discovery complete. Review scope to continue.')
    this.message(run.id, run.coordinatorId, 'guardian', 'Review the candidate hosts before approving analysis.')
  }

  private recordInventory(run: Run, worker: Assignment, title: string, assets: readonly Candidate[]) {
    const records = assets.map(({ origin, thirdParty, source, dnsSource }) =>
      ({ origin, thirdParty, source, ...(dnsSource ? { dnsSource } : {}) }))
    return this.addArtifact(run, worker, 'inventory', title, JSON.stringify(records, null, 2))
  }

  private setScope(run: Run, assetIds: string[], saveProject = false) {
    if (!['review', 'analysis', 'verification'].includes(run.phase) || ['complete', 'failed'].includes(run.status)) {
      throw new Error('Scope changes are unavailable in this phase.')
    }
    const approved = [...new Set(assetIds)]
    if (approved.some(id => !run.candidates.some(asset => asset.id === id))) throw new Error('Select assets from this run’s inventory.')
    if (run.phase === 'review' && approved.length === 0) throw new Error('Approve at least one host to start analysis.')
    const scopeRevision = run.scopeRevision + 1
    const removed = run.approved.filter(id => !approved.includes(id))
    const added = approved.filter(id => !run.approved.includes(id))
    const phase = added.length || run.phase === 'review' ? 'analysis' : run.phase
    const status = run.phase === 'review' ? 'running' : run.status
    const updated = this.updateRun(run.id, { approved, scopeRevision, phase, status })
    if (saveProject) {
      this.db.update(tables.projects).set({
        defaultScope: run.candidates.filter(asset => approved.includes(asset.id)).map(asset => asset.origin),
      }).where(eq(tables.projects.id, run.projectId)).run()
    }
    for (const assignment of this.workerList(run.id)) {
      if (assignment.assetId && removed.includes(assignment.assetId) && assignment.status !== 'complete') {
        this.updateWorker(assignment.id, { status: 'canceled', outcome: 'Scope revoked.', lease: null })
      }
    }
    if (updated.reviewPlan?.status !== 'pending') {
      this.queueAnalysis(updated, added)
    }
    this.event(run.id, 'scope.approved', `Recorded scope revision ${scopeRevision}.`, {
      actorId: this.workspace.actorId, scopeRevision,
      approved: updated.candidates.filter(asset => approved.includes(asset.id)).map(asset => asset.origin),
      excluded: updated.candidates.filter(asset => !approved.includes(asset.id)).map(asset => asset.origin),
      removed, added,
    })
    this.message(run.id, run.coordinatorId, 'guardian',
      `Scope revision ${scopeRevision} approved for ${approved.length} ${approved.length === 1 ? 'host' : 'hosts'}.`)
  }

  private revise(run: Run, input: string) {
    if (run.phase === 'complete') throw new Error('Create a new run to change a completed goal.')
    const goal = redact(input)
    const revision = run.goalRevision + 1
    const phase = run.phase === 'verification' ? 'analysis' : run.phase
    if (run.reviewPlan?.status === 'pending') {
      this.message(run.id, run.coordinatorId, 'guardian', 'This goal was superseded by a revision.', run.reviewPlan.goalMessageId)
    }
    const goalMessageId = this.message(run.id, run.coordinatorId, 'operator', `Revised goal: ${goal}`)
    this.updateRun(run.id, { goal, goalRevision: revision, phase, reviewPlan: { status: 'pending', goalMessageId } })
    if (phase === 'analysis') {
      for (const assignment of this.workerList(run.id)) {
        if (assignment.goalRevision === run.goalRevision && assignment.phase !== 'discovery' &&
            !['complete', 'canceled'].includes(assignment.status)) {
          this.updateWorker(assignment.id, { status: 'canceled', outcome: 'Superseded by a goal revision.', lease: null })
        }
      }
    }
    this.event(run.id, 'goal.revised', `Goal revision ${revision} recorded.`, { actorId: this.workspace.actorId, revision, goal })
  }

  writeReport(run: Run, partial: boolean) {
    const snapshot = this.runDetail(run.id)
    const scope = run.candidates.filter(candidate => run.approved.includes(candidate.id))
    const approvedOrigins = new Set(scope.map(asset => asset.origin))
    const currentEvidence = new Set<string>()
    const gaps: string[] = []
    const selection = run.reviewPlan?.status === 'ready'
      ? { checks: run.reviewPlan.checks, source: run.reviewPlan.source } : undefined
    const coverage = scope.map(asset => {
      const { analysis, verification } = assessmentAssignments(snapshot.assignments, asset.id, run.goalRevision)
      const analyzed = analysis?.status === 'complete' ? analysis : undefined
      const verified = verification?.status === 'complete' ? verification : undefined
      if (analyzed && this.brokerOrigins(analyzed).some(origin => !approvedOrigins.has(origin))) {
        const status = 'Inconclusive: a source in the recorded redirect chain is no longer approved.'
        gaps.push(asset.origin + ' · ' + status)
        return { origin: asset.origin, status, evidenceId: null }
      }
      const done = verified ?? analyzed
      const evidence = snapshot.evidence.filter(item => item.assignmentId === analyzed?.id || item.assignmentId === verified?.id)
      for (const item of evidence) currentEvidence.add(item.id)
      const artifact = evidence.findLast(item => item.assignmentId === done?.id &&
        (verified ? item.kind === 'verification' : ['observation', 'access-policy'].includes(item.kind)))
      const derived = evidence.findLast(item => item.assignmentId === analyzed?.id && item.kind === 'analysis')
      const access = evidence.findLast(item => item.assignmentId === analyzed?.id && item.kind === 'access-policy')
      const status = verified?.outcome ?? (analyzed ? 'Analysis complete. Verification pending.'
        : run.reviewPlan?.status === 'pending' ? 'Check plan pending' : 'Pending review')
      const checks = verified ? verified.checks : selection && untestedCoverage(asset, selection)
      if (!verified || !artifact) {
        gaps.push(asset.origin + ' · ' + status)
      } else if (verified.checks) {
        const reasons = new Set(verified.checks.filter(check => check.status === 'inconclusive').map(check => check.reason))
        for (const reason of reasons) gaps.push(asset.origin + ' · ' + reason)
      } else if (status.startsWith('Inconclusive')) {
        gaps.push(asset.origin + ' · ' + status)
      }
      return {
        origin: asset.origin, status,
        evidenceId: artifact?.id ?? null, analysisEvidenceId: derived?.id,
        ...(access ? { accessEvidence: { id: access.id, recordedAt: asset.accessPolicy?.recordedAt } } : {}),
        ...(checks ? { checks } : {}),
      }
    })
    const results = this.db.select().from(tables.findings).where(and(
      eq(tables.findings.runId, run.id), eq(tables.findings.goalRevision, run.goalRevision),
    )).all().filter(row => run.approved.includes(row.assetId) && row.finding.evidenceIds.length > 0 &&
      row.finding.evidenceIds.every(id => currentEvidence.has(id))).map(row => row.finding)
    const statusOrder = { confirmed: 0, pending: 1, inconclusive: 2, dismissed: 3 }
    results.sort((a, b) => statusOrder[a.status] - statusOrder[b.status] ||
      findingSeverityOrder[a.severity] - findingSeverityOrder[b.severity] ||
      a.origin.localeCompare(b.origin) || a.title.localeCompare(b.title))
    if (!scope.length) gaps.push('No approved hosts in this report.')
    const body: ReportBody = {
      goal: run.goal, scope: scope.map(({ accessPolicy, ...asset }) => asset),
      scopeRevision: run.scopeRevision, goalRevision: run.goalRevision, coverage, findings: results, gaps,
      ...(selection ? { selectedChecks: selection } : {}),
    }
    const reportId = randomUUID()
    const version = (snapshot.reports[0]?.version ?? 0) + 1
    this.db.insert(tables.reports).values({ id: reportId, runId: run.id, partial, body, version, createdAt: Date.now() }).run()
    this.event(run.id, partial ? 'report.partial' : 'report.complete',
      partial ? 'Partial report created.' : 'Complete report created.',
      { reportId, version, phase: run.phase, status: run.status })
  }

  command(input: RunCommand) {
    return this.operate(input, () => {
      const run = this.run(input.runId)
      switch (input.action) {
        case 'discover':
          this.discover(run)
          break
        case 'scope':
          this.setScope(run, input.assetIds, input.saveProject)
          break
        case 'candidate': {
          if (run.phase === 'complete') throw new Error('Add the host to the project for the next run.')
          if (run.candidates.some(candidate => candidate.origin === input.candidate.origin)) throw new Error('This host is already in the inventory.')
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
            const count = this.workerList(run.id).filter(worker => worker.status === 'complete').length
            this.message(run.id, run.coordinatorId, 'guardian',
              'The run is ' + run.status + '. ' + count + ' assignments are complete. See Workflow for the next available action.', questionId)
          }
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
          if (!['paused', 'stopped', 'failed'].includes(run.status)) throw new Error('This run is not paused or stopped.')
          this.setStatus(run, ['consent', 'review'].includes(run.phase) ? 'waiting' : 'running')
          this.event(run.id, 'run.resumed', 'Run resumed.')
          break
      }
      return { id: run.id }
    })
  }
}

let instance: Store | undefined
export function store() {
  return instance ??= new Store(dataDirectory())
}
