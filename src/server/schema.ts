import { index, integer, real, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import type {
  AssessmentCheckId, CallerCompatibility, Candidate, CapabilityTier, CheckCoverage,
  CodeLocation, DnsSource, DynamicRetestVerdict, EvidenceSummary, Finding, LabConfig,
  OwaspCategory, PatchProposalStatus, Phase, PreparedObservation, ReportBody, ReviewPlan,
  RunStatus, ThinkingLevel, ThreatModelSummary, VerificationTier, WorkerPhase, WorkerStatus,
} from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'

export const workspaces = sqliteTable('workspaces', {
  id: text('id').primaryKey().notNull(),
  name: text('name').notNull(),
  actorId: text('actor_id').notNull(),
  createdAt: integer('created_at').notNull(),
})

export const modelProfiles = sqliteTable('model_profiles', {
  id: text('id').primaryKey().notNull(),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  name: text('name').notNull(),
  endpoint: text('endpoint').notNull(),
  model: text('model').notNull(),
  protocol: text('protocol').$type<'responses' | 'messages'>().notNull(),
  credentialId: text('credential_id').notNull(),
  priority: integer('priority').default(100).notNull(),
  enabled: integer('enabled', { mode: 'boolean' }).default(true).notNull(),
  contextWindow: integer('context_window').default(131_072).notNull(),
  maxTokens: integer('max_tokens').default(16_384).notNull(),
  thinkingLevel: text('thinking_level').$type<ThinkingLevel>().default('medium').notNull(),
  inputCostPerMtok: real('input_cost_per_mtok').default(0.25).notNull(),
  outputCostPerMtok: real('output_cost_per_mtok').default(0.9).notNull(),
  healthState: text('health_state').$type<'closed' | 'open' | 'half_open'>().default('closed').notNull(),
  cooldownUntil: integer('cooldown_until'),
  lastError: text('last_error'),
  updatedAt: integer('updated_at').notNull(),
}, table => [index('model_profiles_workspace').on(table.workspaceId, table.priority)])

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey().notNull(),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  name: text('name').notNull(),
  environment: text('environment').$type<'public' | 'local-lab'>().default('public').notNull(),
  seeds: text('seeds', { mode: 'json' }).$type<string[]>().notNull(),
  defaultScope: text('default_scope', { mode: 'json' }).$type<string[]>().notNull(),
  labConfig: text('lab_config', { mode: 'json' }).$type<LabConfig | null>(),
  createdAt: integer('created_at').notNull(),
})

export const projectAssets = sqliteTable('project_assets', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id),
  origin: text('origin').notNull(),
  source: text('source').notNull(),
  thirdParty: integer('third_party', { mode: 'boolean' }).notNull(),
  prepared: text('prepared', { mode: 'json' }).$type<PreparedObservation>(),
  dnsSource: text('dns_source', { mode: 'json' }).$type<DnsSource>(),
  accessPolicy: text('access_policy', { mode: 'json' }).$type<AccessPolicySnapshot>(),
}, table => [uniqueIndex('project_assets_origin').on(table.projectId, table.origin)])

export const projectSpecs = sqliteTable('project_specs', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id),
  name: text('name').notNull(),
  kind: text('kind').$type<'openapi' | 'graphql' | 'routes' | 'notes'>().notNull(),
  origin: text('origin'),
  content: text('content').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('project_specs_project').on(table.projectId)])

export const personas = sqliteTable('personas', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  handle: text('handle').notNull(),
  roleLabel: text('role_label').notNull(),
  originAllowlist: text('origin_allowlist', { mode: 'json' }).$type<string[]>().notNull(),
  authKind: text('auth_kind').$type<'cookie' | 'bearer' | 'header'>().notNull(),
  headerName: text('header_name'),
  credentialId: text('credential_id').notNull(),
  canaryMarkers: text('canary_markers', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [uniqueIndex('personas_project_handle').on(table.projectId, table.handle)])

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
  sourceMode: text('source_mode').$type<'prepared' | 'public'>().default('public').notNull(),
  capabilityTier: integer('capability_tier').$type<CapabilityTier>().default(1).notNull(),
  approvedPersonaIds: text('approved_persona_ids', { mode: 'json' }).$type<string[]>().notNull(),
  roundNo: integer('round_no').default(0).notNull(),
  budgetUsd: real('budget_usd').default(25).notNull(),
  budgetRequests: integer('budget_requests').default(2500).notNull(),
  spentUsd: real('spent_usd').default(0).notNull(),
  spentTokens: integer('spent_tokens').default(0).notNull(),
  spentRequests: integer('spent_requests').default(0).notNull(),
  turnsUsed: integer('turns_used').default(0).notNull(),
  maxRpsPerOrigin: integer('max_rps_per_origin').default(5).notNull(),
  workerConcurrency: integer('worker_concurrency').default(6).notNull(),
  workerMaxTurns: integer('worker_max_turns').default(150).notNull(),
  reviewPlan: text('review_plan', { mode: 'json' }).$type<ReviewPlan>(),
  candidates: text('candidates', { mode: 'json' }).$type<Candidate[]>().notNull(),
  approved: text('approved', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('runs_project').on(table.projectId)])

export const threatModels = sqliteTable('threat_models', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  entries: text('entries', { mode: 'json' }).$type<ThreatModelSummary[]>().notNull(),
  summary: text('summary').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('threat_models_run').on(table.runId)])

export const chainSteps = sqliteTable('chain_steps', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  goalRevision: integer('goal_revision').notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  seq: integer('seq').notNull(),
  title: text('title').notNull(),
  hypothesis: text('hypothesis').notNull(),
  category: text('category').$type<OwaspCategory | string>().default('misconfig-exposure').notNull(),
  priority: integer('priority').default(50).notNull(),
  targetAssetIds: text('target_asset_ids', { mode: 'json' }).$type<string[]>().notNull(),
  skills: text('skills', { mode: 'json' }).$type<string[]>().notNull(),
  dependsOnFactIds: text('depends_on_fact_ids', { mode: 'json' }).$type<string[]>().notNull(),
  dependsOnStepIds: text('depends_on_step_ids', { mode: 'json' }).$type<string[]>().notNull(),
  status: text('status').$type<'pending' | 'ready' | 'running' | 'complete' | 'blocked' | 'tainted' | 'canceled'>().notNull(),
  assignedWorkerId: text('assigned_worker_id'),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [index('chain_steps_run').on(table.runId, table.status)])

export const assignments = sqliteTable('assignments', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assetId: text('asset_id'),
  stepId: text('step_id'),
  inputAssignmentId: text('input_assignment_id'),
  phase: text('phase').$type<WorkerPhase>().notNull(),
  status: text('status').$type<WorkerStatus>().notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  sessionId: text('session_id').notNull(),
  lease: text('lease'),
  leaseExpiresAt: integer('lease_expires_at'),
  attempt: integer('attempt').default(0).notNull(),
  maxTurns: integer('max_turns').default(150).notNull(),
  turnsUsed: integer('turns_used').default(0).notNull(),
  requestsUsed: integer('requests_used').default(0).notNull(),
  parentFactIds: text('parent_fact_ids', { mode: 'json' }).$type<string[]>().notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  title: text('title').notNull(),
  objective: text('objective').notNull(),
  outcome: text('outcome'),
  checks: text('checks', { mode: 'json' }).$type<CheckCoverage[]>(),
  createdAt: integer('created_at').notNull(),
}, table => [index('assignments_run').on(table.runId)])

export const facts = sqliteTable('facts', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  kind: text('kind').$type<'endpoint' | 'auth' | 'header' | 'cors' | 'cookie' | 'object_ref' | 'redirect' | 'policy_gap' | 'config' | 'dns' | 'tls' | 'secret' | 'dom' | 'note'>().notNull(),
  origin: text('origin').notNull(),
  summary: text('summary').notNull(),
  data: text('data', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  evidenceIds: text('evidence_ids', { mode: 'json' }).$type<string[]>().notNull(),
  exchangeIds: text('exchange_ids', { mode: 'json' }).$type<string[]>().notNull(),
  tainted: integer('tainted', { mode: 'boolean' }).default(false).notNull(),
  coldSinceRound: integer('cold_since_round'),
  digestId: text('digest_id'),
  createdAt: integer('created_at').notNull(),
}, table => [index('facts_run').on(table.runId, table.tainted)])

export const graphEdges = sqliteTable('graph_edges', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  fromKind: text('from_kind').$type<'assignment' | 'step' | 'fact' | 'finding' | 'digest'>().notNull(),
  fromId: text('from_id').notNull(),
  toKind: text('to_kind').$type<'assignment' | 'step' | 'fact' | 'finding' | 'digest'>().notNull(),
  toId: text('to_id').notNull(),
  edgeKind: text('edge_kind').$type<'spawns' | 'depends_on' | 'yields' | 'proves' | 'covers' | 'derived_from'>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('graph_edges_run').on(table.runId, table.fromId), index('graph_edges_to').on(table.runId, table.toId)])

export const graphDigests = sqliteTable('graph_digests', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  roundNo: integer('round_no').notNull(),
  level: text('level').$type<'minor' | 'major'>().notNull(),
  signatureHash: text('signature_hash').notNull(),
  summary: text('summary').notNull(),
  coveredFactIds: text('covered_fact_ids', { mode: 'json' }).$type<string[]>().notNull(),
  coveredAssignmentIds: text('covered_assignment_ids', { mode: 'json' }).$type<string[]>().notNull(),
  active: integer('active', { mode: 'boolean' }).default(true).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('graph_digests_run').on(table.runId, table.active)])

export const brokerExchanges = sqliteTable('broker_exchanges', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  scopeRevision: integer('scope_revision').notNull(),
  origin: text('origin').notNull(),
  finalOrigin: text('final_origin').notNull(),
  redirectOrigins: text('redirect_origins', { mode: 'json' }).$type<string[]>().notNull(),
  method: text('method').notNull(),
  pathAndQuery: text('path_and_query').notNull(),
  personaHandle: text('persona_handle'),
  status: integer('status').notNull(),
  mediaType: text('media_type').notNull(),
  reqHeaders: text('req_headers', { mode: 'json' }).$type<Record<string, string>>().notNull(),
  respHeaders: text('resp_headers', { mode: 'json' }).$type<Record<string, string>>().notNull(),
  bodyPreview: text('body_preview').notNull(),
  bodyArtifactId: text('body_artifact_id'),
  bodySha256: text('body_sha256').notNull(),
  durationMs: integer('duration_ms').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('broker_exchanges_run').on(table.runId, table.origin)])

export const approvalRequests = sqliteTable('approval_requests', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  scopeRevision: integer('scope_revision').notNull(),
  origin: text('origin').notNull(),
  method: text('method').notNull(),
  pathAndQuery: text('path_and_query').notNull(),
  personaHandle: text('persona_handle'),
  rationale: text('rationale').notNull(),
  requestPreview: text('request_preview').notNull(),
  status: text('status').$type<'pending' | 'approved' | 'denied' | 'expired' | 'canceled'>().notNull(),
  decidedBy: text('decided_by'),
  decidedAt: integer('decided_at'),
  expiresAt: integer('expires_at').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('approval_requests_run').on(table.runId, table.status)])

export const replaySpecs = sqliteTable('replay_specs', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  findingId: text('finding_id').notNull(),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  spec: text('spec', { mode: 'json' }).$type<DeclarativeReplaySpec>().notNull(),
  specSha256: text('spec_sha256').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('replay_specs_run').on(table.runId)])

export const retestRuns = sqliteTable('retest_runs', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id),
  runId: text('run_id').notNull().references(() => runs.id),
  findingId: text('finding_id').notNull(),
  replaySpecId: text('replay_spec_id').notNull().references(() => replaySpecs.id),
  scopeRevision: integer('scope_revision').notNull(),
  verdict: text('verdict').$type<'reproduced' | 'fixed' | 'inconclusive'>().notNull(),
  summary: text('summary').notNull(),
  evidenceIds: text('evidence_ids', { mode: 'json' }).$type<string[]>().notNull(),
  exchangeIds: text('exchange_ids', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('retest_runs_finding').on(table.findingId)])

export const coverageEntries = sqliteTable('coverage_entries', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  origin: text('origin').notNull(),
  category: text('category').$type<OwaspCategory>().notNull(),
  status: text('status').$type<'reported' | 'no_issue_found' | 'ruled_out' | 'not_applicable' | 'needs_follow_up'>().notNull(),
  summary: text('summary').notNull(),
  enforcingControl: text('enforcing_control'),
  proofGapReason: text('proof_gap_reason'),
  linkedFindingId: text('linked_finding_id'),
  assignmentId: text('assignment_id').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [uniqueIndex('coverage_origin_cat').on(table.runId, table.goalRevision, table.origin, table.category)])

export const canaries = sqliteTable('canaries', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull(),
  token: text('token').notNull().unique(),
  purpose: text('purpose').notNull(),
  protocol: text('protocol').$type<'http' | 'dns' | 'both'>().default('http').notNull(),
  dnsHost: text('dns_host'),
  hitCount: integer('hit_count').default(0).notNull(),
  triggered: integer('triggered', { mode: 'boolean' }).default(false).notNull(),
  triggerDetail: text('trigger_detail', { mode: 'json' }).$type<Record<string, unknown>>(),
  createdAt: integer('created_at').notNull(),
  triggeredAt: integer('triggered_at'),
}, table => [index('canaries_run').on(table.runId)])

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
  checkId: text('check_id').$type<AssessmentCheckId | 'chain'>().notNull().default('hsts'),
  caseId: text('case_id').notNull().default(''),
  findingKind: text('finding_kind').$type<'baseline_check' | 'multi_step_chain'>().default('baseline_check').notNull(),
  replaySpecId: text('replay_spec_id'),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  verificationTier: text('verification_tier').$type<VerificationTier | null>(),
  fingerprintHash: text('fingerprint_hash'),
  supersededByFindingId: text('superseded_by_finding_id'),
  counterevidence: text('counterevidence'),
  confidenceRationale: text('confidence_rationale'),
  severityChangeConditions: text('severity_change_conditions'),
  codeLocations: text('code_locations', { mode: 'json' }).$type<CodeLocation[] | null>(),
  finding: text('finding', { mode: 'json' }).$type<Finding>().notNull(),
}, table => [
  index('findings_run').on(table.runId),
  index('findings_fingerprint').on(table.runId, table.fingerprintHash),
  uniqueIndex('findings_check_case').on(table.runId, table.assetId, table.goalRevision, table.checkId, table.caseId),
])

export const sastRuns = sqliteTable('sast_runs', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  repo: text('repo').notNull(),
  engine: text('engine').notNull(),
  rawArtifactId: text('raw_artifact_id'),
  findingCount: integer('finding_count').default(0).notNull(),
  durationMs: integer('duration_ms').default(0).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('sast_runs_run').on(table.runId)])

export const surfaceProbes = sqliteTable('surface_probes', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id),
  scopeRevision: integer('scope_revision').notNull(),
  origin: text('origin').notNull(),
  probeKind: text('probe_kind').notNull(),
  requestsSent: integer('requests_sent').default(0).notNull(),
  anomaliesFound: integer('anomalies_found').default(0).notNull(),
  baselineSignature: text('baseline_signature'),
  createdAt: integer('created_at').notNull(),
}, table => [index('surface_probes_run').on(table.runId, table.origin)])

export const patchProposals = sqliteTable('patch_proposals', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id),
  findingId: text('finding_id').notNull(),
  repo: text('repo').notNull(),
  status: text('status').$type<PatchProposalStatus>().default('draft').notNull(),
  callerCompatibility: text('caller_compatibility').$type<CallerCompatibility>().default('attacker_only').notNull(),
  diff: text('diff').notNull(),
  codeLocations: text('code_locations', { mode: 'json' }).$type<CodeLocation[]>().notNull(),
  reviewNotes: text('review_notes').default('').notNull(),
  dynamicRetestVerdict: text('dynamic_retest_verdict').$type<DynamicRetestVerdict>().default('skipped').notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [index('patch_proposals_run').on(table.runId, table.findingId)])

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
  evidenceIds: text('evidence_ids', { mode: 'json' }).$type<string[]>(),
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
