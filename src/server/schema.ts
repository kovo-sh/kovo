import { index, integer, real, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import type {
  ApprovalLeaseScope, ApprovalPolicy, ApprovedEndpointPattern, AssessmentCheckId, BenchmarkFunnel, BoardAuthorRole, BoardMemberRole, BoardMemberState,
  BoardMessageKind, CallerCompatibility, Candidate, CapabilityTier, CheckCoverage,
  CodeLocation, DnsSource, DynamicRetestVerdict, EndpointSource, EvidenceSummary, FailureTaxonomyBucket, Finding, InlineVerifyFeedback, LabConfig,
  OwaspCategory, ParamLocation, PatchProposalStatus, PersonaAuthKind, PersonaLoginConfig, PersonaPrivilege, Phase,
  PreparedObservation, ProviderProtocol, ReportBody, ReviewPlan, RoleAffinity, RunStatus, SecondOrderCanaryStatus, SpecialistProfile, ThinkingLevel, ThreatModelSummary,
  VerificationTier, WorkerPhase, WorkerStatus,
} from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import type { SecretMatch } from './redact.ts'
import type { EnvironmentMode } from './scope-policy.ts'
import type { CompiledVerifyFixPredicate } from './verify-fix-predicate.ts'

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
  protocol: text('protocol').$type<ProviderProtocol>().notNull(),
  credentialId: text('credential_id').notNull(),
  priority: integer('priority').default(100).notNull(),
  enabled: integer('enabled', { mode: 'boolean' }).default(true).notNull(),
  contextWindow: integer('context_window').default(1_048_576).notNull(),
  maxTokens: integer('max_tokens').default(16_384).notNull(),
  thinkingLevel: text('thinking_level').$type<ThinkingLevel>().default('medium').notNull(),
  roleAffinity: text('role_affinity').$type<RoleAffinity>().default('any').notNull(),
  inputCostPerMtok: real('input_cost_per_mtok').default(0.15).notNull(),
  cachedInputCostPerMtok: real('cached_input_cost_per_mtok').default(0.003).notNull(),
  outputCostPerMtok: real('output_cost_per_mtok').default(0.6).notNull(),
  healthState: text('health_state').$type<'closed' | 'open' | 'half_open'>().default('closed').notNull(),
  cooldownUntil: integer('cooldown_until'),
  lastError: text('last_error'),
  updatedAt: integer('updated_at').notNull(),
}, table => [index('model_profiles_workspace').on(table.workspaceId, table.priority)])

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey().notNull(),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  tenantId: text('tenant_id').default('default').notNull(),
  name: text('name').notNull(),
  environment: text('environment').$type<'public' | 'local-lab'>().default('public').notNull(),
  seeds: text('seeds', { mode: 'json' }).$type<string[]>().notNull(),
  defaultScope: text('default_scope', { mode: 'json' }).$type<string[]>().notNull(),
  labConfig: text('lab_config', { mode: 'json' }).$type<LabConfig | null>(),
  sandboxWriteAllowlist: text('sandbox_write_allowlist', { mode: 'json' }).$type<ApprovedEndpointPattern[]>().default([]).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('projects_tenant').on(table.tenantId)])

export const projectAssets = sqliteTable('project_assets', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  origin: text('origin').notNull(),
  source: text('source').notNull(),
  thirdParty: integer('third_party', { mode: 'boolean' }).notNull(),
  includeSubdomains: integer('include_subdomains', { mode: 'boolean' }).default(false).notNull(),
  prepared: text('prepared', { mode: 'json' }).$type<PreparedObservation>(),
  dnsSource: text('dns_source', { mode: 'json' }).$type<DnsSource>(),
  accessPolicy: text('access_policy', { mode: 'json' }).$type<AccessPolicySnapshot>(),
}, table => [uniqueIndex('project_assets_origin').on(table.projectId, table.origin)])

export const projectSpecs = sqliteTable('project_specs', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  kind: text('kind').$type<'openapi' | 'graphql' | 'routes' | 'notes'>().notNull(),
  origin: text('origin'),
  content: text('content').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('project_specs_project').on(table.projectId)])

export const personas = sqliteTable('personas', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  handle: text('handle').notNull(),
  roleLabel: text('role_label').notNull(),
  tenantRef: text('tenant_ref'),
  privilege: text('privilege').$type<PersonaPrivilege | null>(),
  originAllowlist: text('origin_allowlist', { mode: 'json' }).$type<string[]>().notNull(),
  authKind: text('auth_kind').$type<PersonaAuthKind>().notNull(),
  headerName: text('header_name'),
  loginConfig: text('login_config', { mode: 'json' }).$type<PersonaLoginConfig | null>(),
  credentialId: text('credential_id').notNull(),
  canaryMarkers: text('canary_markers', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [uniqueIndex('personas_project_handle').on(table.projectId, table.handle)])

export const runs = sqliteTable('runs', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  tenantId: text('tenant_id').default('default').notNull(),
  originalGoal: text('original_goal').notNull(),
  goal: text('goal').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  coordinatorId: text('coordinator_id').notNull(),
  phase: text('phase').$type<Phase>().notNull(),
  status: text('status').$type<RunStatus>().notNull(),
  sourceMode: text('source_mode').$type<'prepared' | 'public'>().default('public').notNull(),
  capabilityTier: integer('capability_tier').$type<CapabilityTier>().default(1).notNull(),
  approvalPolicy: text('approval_policy').$type<ApprovalPolicy>().default('auto_review').notNull(),
  approvedEndpointPatterns: text('approved_endpoint_patterns', { mode: 'json' }).$type<ApprovedEndpointPattern[]>().default([]).notNull(),
  approvedPersonaIds: text('approved_persona_ids', { mode: 'json' }).$type<string[]>().notNull(),
  roundNo: integer('round_no').default(0).notNull(),
  budgetUsd: real('budget_usd').default(25).notNull(),
  budgetRequests: integer('budget_requests').default(0).notNull(),
  spentUsd: real('spent_usd').default(0).notNull(),
  spentTokens: integer('spent_tokens').default(0).notNull(),
  spentRequests: integer('spent_requests').default(0).notNull(),
  turnsUsed: integer('turns_used').default(0).notNull(),
  maxRpsPerOrigin: integer('max_rps_per_origin').default(5).notNull(),
  workerConcurrency: integer('worker_concurrency').default(6).notNull(),
  workerMaxTurns: integer('worker_max_turns').default(150).notNull(),
  dynamicStepBudget: integer('dynamic_step_budget'),
  multiTrialEnabled: integer('multi_trial_enabled', { mode: 'boolean' }).default(true).notNull(),
  allowWebSearch: integer('allow_web_search', { mode: 'boolean' }).default(true).notNull(),
  phase0CompletedAt: integer('phase0_completed_at'),
  reviewPlan: text('review_plan', { mode: 'json' }).$type<ReviewPlan>(),
  candidates: text('candidates', { mode: 'json' }).$type<Candidate[]>().notNull(),
  approved: text('approved', { mode: 'json' }).$type<string[]>().notNull(),
  // v6 Layer-1: the legacy approved-candidate allowlist remains `targetOrigins` for compatibility;
  // these additive role lists carry the two benign-infrastructure tiers.
  authOrigins: text('auth_origins', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  assetOrigins: text('asset_origins', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  environmentMode: text('environment_mode').$type<EnvironmentMode>().default('prod_readonly').notNull(),
  routeDenylist: text('route_denylist', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('runs_project').on(table.projectId),
  index('runs_tenant').on(table.tenantId),
])

export const threatModels = sqliteTable('threat_models', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  entries: text('entries', { mode: 'json' }).$type<ThreatModelSummary[]>().notNull(),
  summary: text('summary').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('threat_models_run').on(table.runId)])

import type { ChainStepStatus } from '../step-status.ts'
export {
  STEP_STATUS,
  chainStepActiveStatuses,
  chainStepContinuableStatuses,
  chainStepLostWorkStatuses,
  chainStepRetryableStatuses,
  chainStepStatuses,
  chainStepTerminalStatuses,
  type ChainStepActiveStatus,
  type ChainStepContinuableStatus,
  type ChainStepLostWorkStatus,
  type ChainStepRetryableStatus,
  type ChainStepStatus,
  type ChainStepTerminalStatus,
  type StepStatusMeta,
} from '../step-status.ts'

export const chainSteps = sqliteTable('chain_steps', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
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
  status: text('status').$type<ChainStepStatus>().notNull(),
  assignedWorkerId: text('assigned_worker_id'),
  specialistProfile: text('specialist_profile').$type<SpecialistProfile | null>(),
  trialGroupId: text('trial_group_id'),
  trialIndex: integer('trial_index').default(0).notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [index('chain_steps_run').on(table.runId, table.status)])

export const assignments = sqliteTable('assignments', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
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
  /** v6: set while the assignment is parked in awaiting_approval with its slot released. */
  approvalParkedAt: integer('approval_parked_at'),
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
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
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
}, table => [
  index('facts_run').on(table.runId, table.tainted),
  index('facts_run_created').on(table.runId, table.createdAt),
])

export const graphEdges = sqliteTable('graph_edges', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  fromKind: text('from_kind').$type<'assignment' | 'step' | 'fact' | 'finding' | 'digest'>().notNull(),
  fromId: text('from_id').notNull(),
  toKind: text('to_kind').$type<'assignment' | 'step' | 'fact' | 'finding' | 'digest'>().notNull(),
  toId: text('to_id').notNull(),
  edgeKind: text('edge_kind').$type<'spawns' | 'depends_on' | 'yields' | 'proves' | 'covers' | 'derived_from'>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('graph_edges_run').on(table.runId, table.fromId), index('graph_edges_to').on(table.runId, table.toId)])

export const graphDigests = sqliteTable('graph_digests', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
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
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
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
  /** Redacted structural evidence from the pre-scrub response (fingerprints only). */
  secretMatches: text('secret_matches', { mode: 'json' }).$type<SecretMatch[]>().default([]).notNull(),
  durationMs: integer('duration_ms').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('broker_exchanges_run').on(table.runId, table.origin),
  index('broker_exchanges_run_created').on(table.runId, table.createdAt),
  index('broker_exchanges_body_artifact').on(table.bodyArtifactId),
])

export const approvalRequests = sqliteTable('approval_requests', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
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
  policyNote: text('policy_note'),
  riskLevel: text('risk_level').$type<'low' | 'medium' | 'high'>(),
  expiresAt: integer('expires_at').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('approval_requests_run').on(table.runId, table.status)])

/**
 * v6 durable, route-scoped approval leases. An operator approval authorizes the whole normalized
 * route (`POST /api/items/*`) across probe iterations and independent replays, instead of a
 * single-use 60 s exact-body-hash fingerprint. Leases are scoped to the run's current revision and
 * are revoked when that origin leaves scope.
 */
export const approvalLeases = sqliteTable('approval_leases', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  scopeRevision: integer('scope_revision').notNull(),
  origin: text('origin').notNull(),
  method: text('method').notNull(),
  routePattern: text('route_pattern').notNull(),
  leaseScope: text('lease_scope').$type<ApprovalLeaseScope>().default('route').notNull(),
  personaHandle: text('persona_handle'),
  crossPersona: integer('cross_persona', { mode: 'boolean' }).default(false).notNull(),
  status: text('status').$type<'active' | 'revoked' | 'expired'>().notNull(),
  sourceApprovalId: text('source_approval_id'),
  createdBy: text('created_by').notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
  expiresAt: integer('expires_at'),
  uses: integer('uses').default(0).notNull(),
  maxUses: integer('max_uses'),
  lastUsedAt: integer('last_used_at'),
}, table => [
  index('approval_leases_run').on(table.runId, table.status),
  uniqueIndex('approval_leases_route').on(table.runId, table.origin, table.method, table.routePattern, table.scopeRevision),
])

/**
 * Persisted receipt for an agent-script proof. Concrete (serializable) fields only: it is returned
 * by the read API, and the verdict is re-derived by `verifyReceipt()`, never trusted from here.
 */
export interface ReplayProofReceiptRow {
  receipt: {
    vulnClass: string
    target: { origin: string; method?: string; pathAndQuery?: string; param?: string }
    exchangeIds: string[]
    oobEventIds: string[]
    browserTraceIds: string[]
    claimedDelta: string
    oracleEvents?: string[]
    requiredRole?: string
    resourceTenant?: string
    expectControlDenied?: boolean
    proofPatterns?: string[]
  }
  verification: {
    confirmed: boolean
    vulnClass: string
    rule: string
    reason: string
    observed: string
    expected: string
  }
  /** A3: 0-LLM Verify Fix predicate compiled at confirmation (stored in the `proof_receipt` JSON; no migration). */
  compiledPredicate?: CompiledVerifyFixPredicate | null
}

export const replaySpecs = sqliteTable('replay_specs', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  findingId: text('finding_id').notNull(),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  spec: text('spec', { mode: 'json' }).$type<DeclarativeReplaySpec>().notNull(),
  specSha256: text('spec_sha256').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  attemptCount: integer('attempt_count').default(1).notNull(),
  verifiedInline: integer('verified_inline', { mode: 'boolean' }).default(false).notNull(),
  lastVerificationDiff: text('last_verification_diff', { mode: 'json' }).$type<InlineVerifyFeedback | null>(),
  /**
   * v7 M5 agent-script proof columns. A `kovo_verify` script proof persists the oracle verdict,
   * the receipt it was re-checked with and the owner-only artifact holding the script source +
   * receipt. The declarative fields above stay for attribution; confirmation and retest are
   * receipt-first (`verifyReceipt()` over the cited exchanges), never a DSL re-interpretation.
   */
  proofKind: text('proof_kind').$type<'agent_script' | null>(),
  proofVerdict: text('proof_verdict').$type<'confirmed' | 'dismissed' | 'inconclusive' | 'needs_review' | null>(),
  proofRuntime: text('proof_runtime').$type<'ts' | 'python' | null>(),
  proofScriptSha256: text('proof_script_sha256'),
  proofArtifactId: text('proof_artifact_id'),
  proofReceipt: text('proof_receipt', { mode: 'json' }).$type<ReplayProofReceiptRow | null>(),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('replay_specs_run').on(table.runId),
  index('replay_specs_proof').on(table.runId, table.proofKind),
])

export const retestRuns = sqliteTable('retest_runs', {
  id: text('id').primaryKey().notNull(),
  projectId: text('project_id').notNull().references(() => projects.id, { onDelete: 'cascade' }),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  findingId: text('finding_id').notNull(),
  replaySpecId: text('replay_spec_id').notNull().references(() => replaySpecs.id, { onDelete: 'cascade' }),
  scopeRevision: integer('scope_revision').notNull(),
  verdict: text('verdict').$type<'reproduced' | 'fixed' | 'inconclusive'>().notNull(),
  summary: text('summary').notNull(),
  evidenceIds: text('evidence_ids', { mode: 'json' }).$type<string[]>().notNull(),
  exchangeIds: text('exchange_ids', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('retest_runs_finding').on(table.findingId)])

export const coverageEntries = sqliteTable('coverage_entries', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
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
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
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
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  title: text('title').notNull(),
  kind: text('kind').$type<EvidenceSummary['kind']>().notNull(),
  operationId: text('operation_id'),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('evidence_run').on(table.runId),
  index('evidence_run_created').on(table.runId, table.createdAt),
  uniqueIndex('evidence_operation').on(table.assignmentId, table.operationId),
])

/** v6 provenance contract: where a persisted finding came from. */
export const findingProvenances = ['floor', 'agent_only', 'chain_from_floor'] as const
export type FindingProvenance = typeof findingProvenances[number]

/**
 * v6 verification contract. `confirmed` findings must be `runtime_confirmed`; static-only and
 * open-proof-gap items are persisted as advisories and never counted as confirmed.
 */
export const findingVerificationClasses = [
  'runtime_confirmed', 'pending_oob', 'static_advisory', 'open_proof_gap', 'dismissed',
] as const
export type FindingVerificationClass = typeof findingVerificationClasses[number]

export const findings = sqliteTable('findings', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assetId: text('asset_id').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  checkId: text('check_id').$type<AssessmentCheckId | 'chain'>().notNull().default('hsts'),
  caseId: text('case_id').notNull().default(''),
  findingKind: text('finding_kind').$type<'baseline_check' | 'multi_step_chain'>().default('baseline_check').notNull(),
  replaySpecId: text('replay_spec_id'),
  provenance: text('provenance').$type<FindingProvenance>().default('agent_only').notNull(),
  parentFindingIds: text('parent_finding_ids', { mode: 'json' }).$type<string[] | null>(),
  verificationClass: text('verification_class').$type<FindingVerificationClass>().default('runtime_confirmed').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  verificationTier: text('verification_tier').$type<VerificationTier | null>(),
  fingerprintHash: text('fingerprint_hash'),
  supersededByFindingId: text('superseded_by_finding_id'),
  counterevidence: text('counterevidence'),
  confidenceRationale: text('confidence_rationale'),
  severityChangeConditions: text('severity_change_conditions'),
  codeLocations: text('code_locations', { mode: 'json' }).$type<CodeLocation[] | null>(),
  status: text('status').$type<Finding['status']>().default('pending').notNull(),
  severity: text('severity').$type<Finding['severity']>().default('medium').notNull(),
  cwe: text('cwe'),
  origin: text('origin').default('').notNull(),
  triageStatus: text('triage_status').$type<'open' | 'confirmed_by_operator' | 'accepted_risk' | 'false_positive' | 'fixed'>().default('open').notNull(),
  finding: text('finding', { mode: 'json' }).$type<Finding>().notNull(),
}, table => [
  index('findings_run').on(table.runId),
  index('findings_fingerprint').on(table.runId, table.fingerprintHash),
  index('findings_provenance').on(table.runId, table.provenance),
  index('findings_run_verified').on(table.runId, table.verificationClass, table.supersededByFindingId),
  index('findings_run_status_severity').on(table.runId, table.status, table.severity),
  index('findings_run_triage').on(table.runId, table.triageStatus),
  index('findings_run_origin_cwe').on(table.runId, table.origin, table.cwe),
  uniqueIndex('findings_check_case').on(table.runId, table.assetId, table.goalRevision, table.checkId, table.caseId),
])

export const sastRuns = sqliteTable('sast_runs', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
  repo: text('repo').notNull(),
  engine: text('engine').notNull(),
  rawArtifactId: text('raw_artifact_id'),
  findingCount: integer('finding_count').default(0).notNull(),
  durationMs: integer('duration_ms').default(0).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [index('sast_runs_run').on(table.runId)])

export const surfaceProbes = sqliteTable('surface_probes', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull().references(() => assignments.id, { onDelete: 'cascade' }),
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
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
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
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  version: integer('version').notNull(),
  partial: integer('partial', { mode: 'boolean' }).notNull(),
  body: text('body', { mode: 'json' }).$type<ReportBody>().notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [uniqueIndex('report_version').on(table.runId, table.version)])

export const messages = sqliteTable('messages', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  threadId: text('thread_id').notNull(),
  role: text('role').$type<'operator' | 'coordinator' | 'worker' | 'kovo'>().notNull(),
  content: text('content').notNull(),
  replyTo: text('reply_to'),
  evidenceIds: text('evidence_ids', { mode: 'json' }).$type<string[]>(),
  createdAt: integer('created_at').notNull(),
}, table => [index('thread_messages').on(table.runId, table.threadId), uniqueIndex('run_replies').on(table.runId, table.replyTo)])

export const events = sqliteTable('events', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  workspaceId: text('workspace_id').notNull().references(() => workspaces.id),
  runId: text('run_id').references(() => runs.id, { onDelete: 'cascade' }),
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
  createdAt: integer('created_at').default(0).notNull(),
}, table => [index('operations_created').on(table.createdAt)])

export const endpoints = sqliteTable('endpoints', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  scopeRevision: integer('scope_revision').notNull(),
  origin: text('origin').notNull(),
  method: text('method').notNull(),
  pathTemplate: text('path_template').notNull(),
  source: text('source').$type<EndpointSource>().notNull(),
  framework: text('framework'),
  authRequirement: text('auth_requirement'),
  ownershipGuard: text('ownership_guard'),
  sinkKinds: text('sink_kinds', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  testedClasses: text('tested_classes', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  coveragePct: real('coverage_pct'),
  riskScore: integer('risk_score').default(50).notNull(),
  codeLocation: text('code_location', { mode: 'json' }).$type<CodeLocation | null>(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [
  uniqueIndex('endpoints_run_route').on(table.runId, table.origin, table.method, table.pathTemplate),
  index('endpoints_run_risk').on(table.runId, table.riskScore),
  index('endpoints_run_updated').on(table.runId, table.updatedAt),
])

export const endpointParams = sqliteTable('endpoint_params', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  endpointId: text('endpoint_id').notNull().references(() => endpoints.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  location: text('location').$type<ParamLocation>().notNull(),
  inferredType: text('inferred_type'),
  isCsrf: integer('is_csrf', { mode: 'boolean' }).default(false).notNull(),
  isObjectId: integer('is_object_id', { mode: 'boolean' }).default(false).notNull(),
  source: text('source').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  uniqueIndex('endpoint_params_unique').on(table.endpointId, table.name, table.location),
  index('endpoint_params_run').on(table.runId, table.endpointId),
])

export const apiDependencies = sqliteTable('api_dependencies', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  producerEndpointId: text('producer_endpoint_id').notNull().references(() => endpoints.id, { onDelete: 'cascade' }),
  consumerEndpointId: text('consumer_endpoint_id').notNull().references(() => endpoints.id, { onDelete: 'cascade' }),
  resourceKey: text('resource_key').notNull(),
  sampleResourceIdHash: text('sample_resource_id_hash'),
  personaHandle: text('persona_handle'),
  observedTransitions: text('observed_transitions', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  testedBola: integer('tested_bola', { mode: 'boolean' }).default(false).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  uniqueIndex('api_dependencies_edge').on(table.runId, table.producerEndpointId, table.consumerEndpointId, table.resourceKey),
  index('api_dependencies_run').on(table.runId, table.testedBola),
])

export const secondOrderCanaries = sqliteTable('second_order_canaries', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id').notNull(),
  marker: text('marker').notNull().unique(),
  injectedOrigin: text('injected_origin').notNull(),
  injectedEndpoint: text('injected_endpoint').notNull(),
  injectedParam: text('injected_param').notNull(),
  injectedPersona: text('injected_persona'),
  surfacedOrigin: text('surfaced_origin'),
  surfacedEndpoint: text('surfaced_endpoint'),
  surfacedPersona: text('surfaced_persona'),
  surfacedExchangeId: text('surfaced_exchange_id'),
  status: text('status').$type<SecondOrderCanaryStatus>().default('planted').notNull(),
  createdAt: integer('created_at').notNull(),
  surfacedAt: integer('surfaced_at'),
}, table => [
  index('second_order_canaries_run').on(table.runId, table.status),
])

export const labTelemetry = sqliteTable('lab_telemetry', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  exchangeId: text('exchange_id').notNull(),
  traceId: text('trace_id').notNull(),
  routesHit: text('routes_hit', { mode: 'json' }).$type<string[]>().default([]).notNull(),
  newLinesCovered: integer('new_lines_covered').default(0).notNull(),
  sinkEventsCount: integer('sink_events_count').default(0).notNull(),
  hasUnhandledException: integer('has_unhandled_exception', { mode: 'boolean' }).default(false).notNull(),
  artifactId: text('artifact_id').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('lab_telemetry_run').on(table.runId, table.createdAt),
  uniqueIndex('lab_telemetry_trace').on(table.runId, table.traceId),
])

export const boardMembers = sqliteTable('board_members', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  handle: text('handle').notNull(), // e.g. 'coordinator', 'bola', 'auth', 'bola-2'
  role: text('role').$type<BoardMemberRole>().notNull(),
  specialistProfile: text('specialist_profile').$type<SpecialistProfile | null>(),
  sessionId: text('session_id').notNull(),
  activeAssignmentId: text('active_assignment_id'),
  state: text('state').$type<BoardMemberState>().notNull(),
  roleAffinity: text('role_affinity').$type<RoleAffinity | null>(),
  lastReadSeq: integer('last_read_seq').default(0).notNull(),
  turnsUsed: integer('turns_used').default(0).notNull(),
  postsCount: integer('posts_count').default(0).notNull(),
  peerHopsUsed: integer('peer_hops_used').default(0).notNull(),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [
  uniqueIndex('board_members_run_handle').on(table.runId, table.handle),
  index('board_members_run_state').on(table.runId, table.state),
])

export const boardMessages = sqliteTable('board_messages', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  seq: integer('seq').notNull(), // strictly monotonic per run (1, 2, 3, ...)
  authorHandle: text('author_handle').notNull(),
  authorRole: text('author_role').$type<BoardAuthorRole>().notNull(),
  kind: text('kind').$type<BoardMessageKind>().notNull(),
  mentions: text('mentions', { mode: 'json' }).$type<string[]>().notNull(),
  body: text('body').notNull(), // redacted, capped <= 1200 chars
  refFactIds: text('ref_fact_ids', { mode: 'json' }).$type<string[]>().notNull(),
  refExchangeIds: text('ref_exchange_ids', { mode: 'json' }).$type<string[]>().notNull(),
  refFindingIds: text('ref_finding_ids', { mode: 'json' }).$type<string[]>().notNull(),
  refStepId: text('ref_step_id'),
  refApprovalId: text('ref_approval_id'),
  replyToSeq: integer('reply_to_seq'),
  scopeRevision: integer('scope_revision').notNull(),
  goalRevision: integer('goal_revision').notNull(),
  sourceOrigins: text('source_origins', { mode: 'json' }).$type<string[]>().notNull(),
  tainted: integer('tainted', { mode: 'boolean' }).default(false).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  uniqueIndex('board_messages_run_seq').on(table.runId, table.seq),
  index('board_messages_run_tainted').on(table.runId, table.tainted, table.seq),
])

/**
 * v6 M2.1: redacted non-secret sample identifiers harvested per collection. The unique key
 * includes `collection_path` so `/invoices`, `/orders` and `/tickets` keep distinct ids instead
 * of clobbering each other on the same `id` field name.
 */
export const resourceSamples = sqliteTable('resource_samples', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  ownerPersona: text('owner_persona').notNull(),
  resourceKey: text('resource_key').notNull(),
  collectionPath: text('collection_path').default('').notNull(),
  resourceId: text('resource_id').notNull(),
  origin: text('origin').notNull(),
  endpoint: text('endpoint').notNull(),
  method: text('method').notNull(),
  mediaType: text('media_type'),
  authenticated: integer('authenticated', { mode: 'boolean' }).default(false).notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [
  uniqueIndex('resource_samples_key').on(
    table.runId, table.ownerPersona, table.origin, table.collectionPath, table.resourceKey,
  ),
  index('resource_samples_run').on(table.runId, table.resourceKey),
])

/**
 * v6.2 persistence settings: durable record of the storage configuration the DB was opened with
 * (e.g. `fts_mode`, `fts_max_body_bytes`) so a diagnostic can tell how the FTS index was built
 * without re-reading process arguments.
 */
export const storeSettings = sqliteTable('store_settings', {
  key: text('key').primaryKey().notNull(),
  value: text('value').notNull(),
  updatedAt: integer('updated_at').notNull(),
})

/** v6 crash recovery: persisted LabRunner container IDs so a restart can reclaim orphans. */
export const labContainers = sqliteTable('lab_containers', {
  id: text('id').primaryKey().notNull(),
  runId: text('run_id').notNull().references(() => runs.id, { onDelete: 'cascade' }),
  assignmentId: text('assignment_id'),
  containerName: text('container_name').notNull(),
  imageName: text('image_name'),
  status: text('status').$type<'running' | 'orphaned' | 'reclaimed'>().default('running').notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, table => [
  uniqueIndex('lab_containers_name').on(table.runId, table.containerName),
  index('lab_containers_run').on(table.runId, table.status),
])

export const benchmarkRuns = sqliteTable('benchmark_runs', {
  id: text('id').primaryKey().notNull(),
  suite: text('suite').notNull(),
  gitSha: text('git_sha').notNull(),
  modelRoutingConfig: text('model_routing_config', { mode: 'json' }).$type<Record<string, unknown>>().default({}).notNull(),
  targetsTotal: integer('targets_total').notNull(),
  confirmedCount: integer('confirmed_count').notNull(),
  falsePositiveCount: integer('false_positive_count').notNull(),
  funnelCounts: text('funnel_counts', { mode: 'json' }).$type<BenchmarkFunnel>().notNull(),
  failureTaxonomy: text('failure_taxonomy', { mode: 'json' }).$type<Record<FailureTaxonomyBucket, number>>().notNull(),
  totalCostUsd: real('total_cost_usd').default(0).notNull(),
  durationMs: integer('duration_ms').default(0).notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('benchmark_runs_suite').on(table.suite, table.createdAt),
])

/**
 * v7 M4: append-only hash-chained tenant audit log.
 * CRITICAL SAFETY INVARIANT: Intentionally has NO foreign key and NO `ON DELETE CASCADE` to
 * `runs` or `projects` (enforced further by SQLite `BEFORE UPDATE`/`BEFORE DELETE` abort triggers)
 * so audit records survive run and project deletion intact.
 */
export const tenantAuditLog = sqliteTable('tenant_audit_log', {
  seq: integer('seq').primaryKey({ autoIncrement: true }),
  id: text('id').notNull().unique(),
  tenantId: text('tenant_id').notNull(),
  runId: text('run_id'),
  actor: text('actor').notNull(),
  action: text('action').notNull(),
  resourceKind: text('resource_kind').notNull(),
  resourceId: text('resource_id'),
  outcome: text('outcome').notNull(),
  detail: text('detail', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
  prevHash: text('prev_hash').notNull(),
  entryHash: text('entry_hash').notNull(),
  createdAt: integer('created_at').notNull(),
}, table => [
  index('tenant_audit_log_tenant').on(table.tenantId, table.seq),
])
