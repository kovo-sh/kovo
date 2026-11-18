import { index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import type { Candidate, EvidenceSummary, Finding, Phase, PreparedObservation, ReportBody, RunStatus, WorkerPhase, WorkerStatus } from '../domain.ts'

export const workspaces = sqliteTable('workspaces', {
  id: text('id').primaryKey().notNull(),
  name: text('name').notNull(),
  actorId: text('actor_id').notNull(),
  createdAt: integer('created_at').notNull(),
})

export const modelConfig = sqliteTable('model_config', {
  workspaceId: text('workspace_id').primaryKey().notNull().references(() => workspaces.id),
  endpoint: text('endpoint').notNull(),
  model: text('model').notNull(),
  protocol: text('protocol').$type<'responses' | 'messages'>().notNull(),
  credentialId: text('credential_id').notNull(),
  updatedAt: integer('updated_at').notNull(),
})

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey().notNull(),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  name: text('name').notNull(),
  seeds: text('seeds', { mode: 'json' }).$type<string[]>().notNull(),
  defaultScope: text('default_scope', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
})

export const projectAssets = sqliteTable('project_assets', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id),
  origin: text('origin').notNull(),
  source: text('source').notNull(),
  thirdParty: integer('third_party', { mode: 'boolean' }).notNull(),
  prepared: text('prepared', { mode: 'json' }).$type<PreparedObservation>(),
}, table => [uniqueIndex('project_assets_origin').on(table.projectId, table.origin)])

export const runs = sqliteTable('runs', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  originalGoal: text('original_goal').notNull(),
  goal: text('goal').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  coordinatorId: text('coordinator_id').notNull(),
  phase: text('phase').$type<Phase>().notNull(),
  status: text('status').$type<RunStatus>().notNull(),
  sourceMode: text('source_mode').$type<'prepared' | 'public'>().default('prepared').notNull(),
  candidates: text('candidates', { mode: 'json' }).$type<Candidate[]>().notNull(),
  approved: text('approved', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('runs_project').on(table.projectId)])

export const assignments = sqliteTable('assignments', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assetId: text('asset_id'),
  phase: text('phase').$type<WorkerPhase>().notNull(),
  status: text('status').$type<WorkerStatus>().notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  sessionId: text('session_id').notNull(),
  lease: text('lease'),
  attempt: integer('attempt').default(0).notNull(),
  title: text('title').notNull(),
  objective: text('objective').notNull(),
  outcome: text('outcome'),
  createdAt: integer('created_at').notNull(),
}, table => [index('assignments_run').on(table.runId)])

export const evidence = sqliteTable('evidence', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  title: text('title').notNull(),
  kind: text('kind').$type<EvidenceSummary['kind']>().notNull(),
  operationId: text('operation_id'),
  createdAt: integer('created_at').notNull(),
}, table => [index('evidence_run').on(table.runId), uniqueIndex('evidence_operation').on(table.assignmentId, table.operationId)])

export const findings = sqliteTable('findings', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assetId: text('asset_id').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  finding: text('finding', { mode: 'json' }).$type<Finding>().notNull(),
}, table => [index('findings_run').on(table.runId)])

export const reports = sqliteTable('reports', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  version: integer('version').notNull(),
  partial: integer('partial', { mode: 'boolean' }).notNull(),
  body: text('body', { mode: 'json' }).$type<ReportBody>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [uniqueIndex('report_version').on(table.runId, table.version)])

export const messages = sqliteTable('messages', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  threadId: text('thread_id').notNull(),
  role: text('role').$type<'operator' | 'coordinator' | 'worker' | 'guardian'>().notNull(),
  content: text('content').notNull(),
  replyTo: text('reply_to'),
  createdAt: integer('created_at').notNull(),
}, table => [index('thread_messages').on(table.runId, table.threadId), uniqueIndex('run_replies').on(table.runId, table.replyTo)])

export const events = sqliteTable('events', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  runId: text('run_id').references(() => runs.id),
  kind: text('kind').notNull(),
  message: text('message').notNull(),
  detail: text('detail', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('events_run').on(table.runId, table.id)])

export const operations = sqliteTable('operations', {
  id: text('id').primaryKey().notNull(),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  fingerprint: text('fingerprint').notNull(),
  result: text('result').notNull(),
})
