import { z } from "zod";
import { writerPinned } from "./compatibility.js";
import { discoveryValidationRuleSchema } from "./discovery-validation.js";
import { decisionTraceSchema } from "./api/explain.js";
import {
  fixStatusSchema,
  ladderRungSchema,
  fixOutcomeReasonSchema,
  slotKindSchema,
} from "./enums/fixes.js";
import { fixTierSchema } from "./enums/advisories.js";
import { waitReasonSchema, nextActionSchema } from "./enums/waits.js";
import {
  provenanceObservationSchema,
  provenanceReportSchema,
  provenanceMissingCauseSchema,
} from "./evidence.js";
import { gateOutcomeSchema, mergeBlockReasonSchema } from "./enums/merge.js";
import { packageNameSchema } from "./npm.js";
import { accountIdSchema, repoIdSchema, jobIdSchema } from "./ids.js";
import { paginationQueryShape, pageSchema } from "./pagination.js";
import { utcDateTimeSchema } from "./time.js";

export const DIAGNOSTIC_QUERIES = [
  "repo_state",
  "consent_history",
  "approval_history",
  "workflow_steps_for_job",
  "self_repair_rounds",
  "enqueue_decisions",
  "recent_jobs",
  "explain",
  "fix_states",
  "fix_provenance",
] as const;
export const diagnosticQueryNameSchema = z.enum(DIAGNOSTIC_QUERIES);
export type DiagnosticQueryName = z.output<typeof diagnosticQueryNameSchema>;
const diagnosticAccountIdSchema = z.codec(z.uuid(), accountIdSchema, {
  decode: (value) => accountIdSchema.parse(value.toLowerCase()),
  encode: (value) => value,
});
const diagnosticRepoIdSchema = z.codec(z.uuid(), repoIdSchema, {
  decode: (value) => repoIdSchema.parse(value.toLowerCase()),
  encode: (value) => value,
});
const diagnosticJobIdSchema = z.codec(z.uuid(), jobIdSchema, {
  decode: (value) => jobIdSchema.parse(value.toLowerCase()),
  encode: (value) => value,
});
const diagnosticIdSchema = z.codec(z.uuid(), z.uuid(), {
  decode: (value) => value.toLowerCase(),
  encode: (value) => value,
});

export const diagnosticRequestedBySchema = z
  .string()
  .regex(/^(owner|agent:[a-z0-9][a-z0-9-]{0,62})$/);

export const diagnosticGrantRequestSchema = z.strictObject({
  account_id: diagnosticAccountIdSchema,
  repo_id: diagnosticRepoIdSchema.exactOptional(),
  requested_by: diagnosticRequestedBySchema,
  justification: z.string().trim().min(20).max(1000),
  duration_seconds: z.int().min(1).max(7200).default(7200),
});
export const diagnosticGrantSchema = z.strictObject({
  id: z.uuid(),
  account_id: accountIdSchema,
  repo_id: repoIdSchema.nullable(),
  operator_id: z.uuid(),
  justification: z.string().min(20).max(1000),
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
});
export const diagnosticQueryRequestSchema = z.strictObject({
  grant_id: diagnosticIdSchema,
  account_id: diagnosticAccountIdSchema,
  repo_id: diagnosticRepoIdSchema.exactOptional(),
  job_id: diagnosticJobIdSchema.exactOptional(),
  limit: z.int().min(1).max(100).default(50),
});
export type DiagnosticGrantRequest = z.output<typeof diagnosticGrantRequestSchema>;
export type DiagnosticGrant = z.output<typeof diagnosticGrantSchema>;
export type DiagnosticQueryRequest = z.output<typeof diagnosticQueryRequestSchema>;

// Closed projections: unknown fields fail validation rather than leaking a future content column.
export const MAX_DIAGNOSTIC_PROVENANCE_ITEMS = 100;
export const MAX_DIAGNOSTIC_PROVENANCE_BYTES = 256 * 1024;

const id = z.uuid();
const code = z.string().regex(/^[a-zA-Z][a-zA-Z0-9_.-]{0,99}$/);
const time = utcDateTimeSchema;
const nullableTime = time.nullable();
const diagnosticTraceSchema = decisionTraceSchema
  .pick({
    id: true,
    machine: true,
    transition: true,
    input_fingerprint: true,
    rule: true,
    reason_codes: true,
    actor_kind: true,
    job_id: true,
    created_at: true,
  })
  .extend({ repo_id: repoIdSchema });
const recentJobsReader = z.strictObject({
  id,
  repo_id: id.nullable(),
  kind: code,
  status: code,
  error_code: code.nullable(),
  discovery_validation_rule: discoveryValidationRuleSchema.nullable().exactOptional(),
  funding_wait: code.nullable(),
  created_at: time,
  started_at: nullableTime,
  finished_at: nullableTime,
});

export const DIAGNOSTIC_ROW_SCHEMAS = {
  repo_state: z.strictObject({
    id,
    account_id: id,
    desired_mode: code,
    mode: code,
    mode_reason: code.nullable(),
    activation_policy: code,
    activation_version: z.int(),
    active_recipe_version_id: id.nullable(),
    enabled_at: nullableTime,
    disabled_at: nullableTime,
    paused_at: nullableTime,
  }),
  consent_history: z.strictObject({
    id,
    repo_id: id,
    activation_version: z.int(),
    authorized_by: id,
    authorized_at: time,
    revoked_at: nullableTime,
  }),
  approval_history: z.strictObject({
    id,
    repo_id: id,
    version: z.int(),
    approval_status: code,
    calibration_status: code,
    approved_via: code.nullable(),
    approved_by: id.nullable(),
    approved_at: nullableTime,
    created_at: time,
  }),
  workflow_steps_for_job: z.strictObject({
    job_id: id,
    position: z.int().nonnegative(),
    step_name: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_.:-]{0,199}$/),
    status: z.enum(["succeeded", "failed"]),
  }),
  self_repair_rounds: z.strictObject({
    repo_id: id,
    recipe_version_id: id,
    round: z.int().nonnegative(),
    applied_version_id: id.nullable(),
    egress_processed: z.boolean(),
    stop_reason: code.nullable(),
    created_at: time,
  }),
  fix_provenance: z.strictObject({
    id,
    target_package: packageNameSchema,
    pr_number: z.int().positive().nullable(),
    evidence_id: id.nullable(),
    verified_at: nullableTime,
    expires_at: nullableTime,
    matches_published_head: z.boolean().nullable(),
    evaluated_at: nullableTime,
    records_available: z.boolean().nullable(),
    findings_source: z.enum(["merge_evaluation", "verification_evidence", "none"]),
    missing_records: provenanceReportSchema.shape.missing.max(MAX_DIAGNOSTIC_PROVENANCE_ITEMS),
    unmatched_records: provenanceReportSchema.shape.unmatched.max(MAX_DIAGNOSTIC_PROVENANCE_ITEMS),
    missing_causes: z.array(provenanceMissingCauseSchema).max(MAX_DIAGNOSTIC_PROVENANCE_ITEMS),
    truncated: z.boolean(),
    check_outcome: gateOutcomeSchema.nullable(),
    check_reasons: z.array(mergeBlockReasonSchema).max(20),
    findings: z.array(provenanceObservationSchema).max(MAX_DIAGNOSTIC_PROVENANCE_ITEMS),
  }),
  fix_states: z.strictObject({
    id,
    finding_ids: z.array(id),
    target_package: packageNameSchema,
    tier: fixTierSchema,
    status: fixStatusSchema,
    attempt: z.int().positive(),
    ladder_rung: ladderRungSchema.nullable(),
    wait_reason: waitReasonSchema.nullable(),
    next_action: nextActionSchema.nullable(),
    outcome_reason: fixOutcomeReasonSchema.nullable(),
    hold_until: nullableTime,
    merge_gates: decisionTraceSchema.shape.evaluation,
    merge_evaluated_at: nullableTime,
    merge_gate_outcomes: z
      .array(
        z.strictObject({
          rule: code,
          outcome: z.enum(["pass", "fail", "unknown"]),
        }),
      )
      .max(100),
    pr_number: z.int().positive().nullable(),
    pr_state: z.enum(["open", "closed", "merged", "unknown"]).nullable(),
    slot_kind: slotKindSchema.nullable(),
    slot_lease_expires_at: nullableTime,
    mode: z.enum(["pr_only", "shadow", "autopilot"]),
    fix_cap: z.int().positive().nullable(),
    p0_extra_cap: z.int().nonnegative(),
    slots_used: z.strictObject({ fix: z.int().nonnegative(), p0_extra: z.int().nonnegative() }),
    created_at: time,
    updated_at: time,
    terminal_at: nullableTime,
  }),
  enqueue_decisions: diagnosticTraceSchema,
  explain: diagnosticTraceSchema,
  // Tolerant reader first; diagnostic SQL starts emitting this after reader promotion.
  recent_jobs: writerPinned(
    recentJobsReader,
    recentJobsReader.omit({ discovery_validation_rule: true }),
  ),
} as const;
export const diagnosticQueryResponseSchema = z.strictObject({
  query: diagnosticQueryNameSchema,
  rows: z.array(z.union(Object.values(DIAGNOSTIC_ROW_SCHEMAS))).max(100),
});
export type DiagnosticQueryResponse = z.output<typeof diagnosticQueryResponseSchema>;

/** D3 is a separate read surface; D9's existing named-query enum stays unchanged. */
export const diagnosticTimelineRequestSchema = z.strictObject({
  grant_id: diagnosticIdSchema,
  account_id: diagnosticAccountIdSchema,
  since: utcDateTimeSchema.exactOptional(),
  ...paginationQueryShape,
});
const event = {
  id: z
    .string()
    .regex(/^[a-z_]+:[0-9a-f-]+(?::[0-9]+)?$/)
    .max(150),
  at: time,
};
export const diagnosticTimelineRowSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...event,
    kind: z.literal("audit"),
    data: z.strictObject({ action: code, actor_kind: code }),
  }),
  z.strictObject({
    ...event,
    kind: z.literal("job"),
    // Timeline exposure waits for its reader-compatible rollout in the writer slice.
    data: recentJobsReader.omit({ discovery_validation_rule: true }),
  }),
  z.strictObject({
    ...event,
    kind: z.literal("workflow_step"),
    data: DIAGNOSTIC_ROW_SCHEMAS.workflow_steps_for_job,
  }),
  z.strictObject({
    ...event,
    kind: z.literal("decision"),
    data: diagnosticTraceSchema.extend({ versions: decisionTraceSchema.shape.versions }),
  }),
  z.strictObject({
    ...event,
    kind: z.literal("consent"),
    data: DIAGNOSTIC_ROW_SCHEMAS.consent_history,
  }),
  z.strictObject({
    ...event,
    kind: z.literal("calibration"),
    data: DIAGNOSTIC_ROW_SCHEMAS.approval_history,
  }),
  z.strictObject({
    ...event,
    kind: z.literal("repair"),
    data: DIAGNOSTIC_ROW_SCHEMAS.self_repair_rounds,
  }),
  z.strictObject({
    ...event,
    kind: z.literal("notification"),
    data: z.strictObject({ id, kind: code, state: code, failure_code: code.nullable() }),
  }),
  z.strictObject({
    ...event,
    kind: z.literal("pr"),
    data: z.strictObject({
      number: z.int().positive(),
      state: z.enum(["open", "closed", "merged"]),
    }),
  }),
]);
export const diagnosticTimelineResponseSchema = pageSchema(diagnosticTimelineRowSchema);
export type DiagnosticTimelineRequest = z.output<typeof diagnosticTimelineRequestSchema>;
export type DiagnosticTimelineResponse = z.output<typeof diagnosticTimelineResponseSchema>;
