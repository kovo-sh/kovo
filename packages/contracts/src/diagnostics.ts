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
import { exactVersionSchema, packageNameSchema } from "./npm.js";
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
  // Served after their reader (#5537) was promoted to production (#5500).
  "fix_recipe_versions",
  "recent_job_links",
  // Served after its reader (#6473) was promoted to production (#5699).
  "fix_notifications",
  // Served after its reader (#6623) was promoted to production (#5699).
  "fix_kovo_side_fallbacks",
  // #7831: served in its own PR, reader and writer together; D-574 deploys stop the world before
  // launch, so no previous release reads this response beside it.
  "provider_events_stuck",
  // #8324: served in its own PR, reader and writer together, as #7831's was (D-574).
  "github_deliveries_stuck",
  // #8590: served in its own PR, reader and writer together, as #7831's was (D-574).
  "malware_unknown",
  // #8948: one package version's stored verdicts, metadata only, in its own PR (D-574).
  "malware_verdict",
] as const;
/**
 * Reader first (#5500, docs/decisions/schema-compatibility.md "Reader-first sequencing"): query
 * responses already accept these names and rows; the API serves them only in the writer PR,
 * after a release containing this reader is promoted to production.
 */
export const DIAGNOSTIC_READER_ONLY_QUERIES = ["job_sandbox_outcomes"] as const;
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
  // `malware_verdict` only (#8948): the public package name and exact version to look up.
  package: packageNameSchema.exactOptional(),
  version: exactVersionSchema.exactOptional(),
  limit: z.int().min(1).max(100).default(50),
});
export type DiagnosticGrantRequest = z.output<typeof diagnosticGrantRequestSchema>;
export type DiagnosticGrant = z.output<typeof diagnosticGrantSchema>;
export type DiagnosticQueryRequest = z.output<typeof diagnosticQueryRequestSchema>;

// Closed projections: unknown fields fail validation rather than leaking a future content column.
export const MAX_DIAGNOSTIC_PROVENANCE_ITEMS = 100;
export const MAX_DIAGNOSTIC_PROVENANCE_BYTES = 256 * 1024;

/**
 * The reasons the malware cache stores on an unknown verdict (#8590): the scanner's unknown
 * reasons, `integrity_unavailable` for an artifact with no bound integrity,
 * `integrity_registry_mismatch` for a sha1-only copy the registry's shasum contradicts (#8951),
 * `integrity_unavailable_bundled` for a bundled copy no byte verification ran for, the
 * `bundled_bytes_*` reasons for a bundled copy whose bytes did not verify against the registry
 * artifact (#8951), and the scanner's
 * resolved reasons (`no_signal`, `ai_suspicion`, `known_malware`), which stay unknown when the
 * batch carried no single verdict revision and are retried. The `malware_unknown` diagnostic
 * reads any other stored value as `unknown_legacy`.
 */
export const MALWARE_UNKNOWN_REASONS = [
  "quota_exhausted",
  "access_denied",
  "unavailable",
  "integrity_unavailable",
  "integrity_unavailable_bundled",
  "integrity_registry_mismatch",
  "bundled_bytes_mismatch",
  "bundled_bytes_over_cap",
  "bundled_bytes_registry_missing",
  "bundled_bytes_unavailable",
  "not_found",
  "pending_scan",
  "incomplete",
  "malformed_response",
  "no_signal",
  "ai_suspicion",
  "known_malware",
] as const;

/** Why a bundled copy's bytes were not shown to be the registry artifact's (#8951). */
export const MALWARE_BUNDLED_BYTES_REASONS = [
  "bundled_bytes_mismatch",
  "bundled_bytes_over_cap",
  "bundled_bytes_registry_missing",
  "bundled_bytes_unavailable",
] as const;
/** The empty-integrity marker reasons of a bundled copy: a ticket, never a page (#8951). */
export const MALWARE_BUNDLED_MARKER_REASONS = [
  "integrity_unavailable_bundled",
  ...MALWARE_BUNDLED_BYTES_REASONS,
] as const;
/**
 * Every reason an empty-integrity investigation marker can carry: never sent to Socket, and
 * removable through the D-763 operator tool.
 */
export const MALWARE_MARKER_REASONS = [
  "integrity_unavailable",
  "integrity_registry_mismatch",
  ...MALWARE_BUNDLED_MARKER_REASONS,
] as const;

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
  // #5500: IDs, codes and timestamps only. Appended last so the response reader keeps #5537's
  // union order. The recipe version a fix last recorded against its repository's active version.
  // Codes stay open so a newer status never fails a read.
  fix_recipe_versions: z.strictObject({
    id,
    status: code,
    recipe_version_id: id.nullable(),
    active_recipe_version_id: id.nullable(),
    matches_active: z.boolean().nullable(),
    created_at: time,
    updated_at: time,
  }),
  // A separate query, not new recent_jobs columns: recent_jobs is a strict reader persisted in
  // repro bundles, so widening it would need its own reader-first release.
  recent_job_links: z.strictObject({
    id,
    repo_id: id.nullable(),
    fix_id: id.nullable(),
    recipe_version_id: id.nullable(),
    kind: code,
    status: code,
    created_at: time,
  }),
  // The notification (email outbox) rows a repository's fixes produced (#5699, D-414 drill):
  // enough to count "exactly one email was enqueued or sent for this fix" without reading an
  // inbox. IDs, open codes, counts and timestamps only: never an address, name, subject, body or
  // template model. `fix_id` is the fix the notification concerns, null for a kind with none.
  // Served by the writer after #6473's reader was promoted; appended last to keep the union order.
  fix_notifications: z.strictObject({
    id,
    fix_id: id.nullable(),
    kind: code,
    state: code,
    failure_code: code.nullable(),
    attempts: z.int().nonnegative(),
    created_at: time,
    sent_at: nullableTime,
    delivered_at: nullableTime,
  }),
  // Each of a repository's fixes with its D-414 Kovo-side fallback marker (#5699, criterion 7):
  // whether the fix workflow recorded one, and its reason code, fallback revision and recorded
  // time. IDs, open codes, a revision number, a flag and timestamps only. `id` is the fix ID and
  // `status` its state; the marker fields are null when `fallback` is false. Served by the
  // writer after #6623's reader was promoted; appended last to keep the union order.
  fix_kovo_side_fallbacks: z.strictObject({
    id,
    status: code,
    fallback: z.boolean(),
    reason: code.nullable(),
    revision: z.int().positive().nullable(),
    recorded_at: nullableTime,
    created_at: time,
  }),
  // The account's GitHub deliveries the nightly redrive gave up on (#7831, the
  // `kovo.github.events_stuck` gauge's rows): past its seven-day window or eight attempts and
  // still unprocessed. IDs, codes, a count and timestamps only: never the kept sanitized event,
  // headers, a body or error text. `event_id` is the delivery GUID (null if it is not a plain
  // identifier); `repo_id` is the Kovo repository the kept event names, null when it names none or
  // was not kept. `last_error_code` is the stable reason the last failed attempt recorded, or
  // `unknown_legacy` for a stored value outside the code form. `last_attempt_at` is null for
  // attempts recorded before #7831, and then `given_up_at` too when the attempt bound stopped it.
  provider_events_stuck: z.strictObject({
    provider: z.literal("github"),
    event_id: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/)
      .nullable(),
    event_type: code,
    account_id: id,
    repo_id: id.nullable(),
    status: z.enum(["received", "processing", "failed"]),
    attempts: z.int().nonnegative(),
    last_error_code: code.nullable(),
    given_up_reason: z.enum(["max_attempts", "retry_window"]),
    received_at: time,
    last_attempt_at: nullableTime,
    given_up_at: nullableTime,
  }),
  // The grant account's given-up GitHub deliveries and those that belong to no account (#8324):
  // GitHub deliveries carry no account, so `provider_events_stuck` cannot see them; this one
  // resolves it, and never returns another account's delivery (D9). The same bounds, newest
  // first. IDs, enums, codes, a count and timestamps only: never the kept sanitized event, a
  // repository, organization or user name, headers, a body or error text.
  // `github_installation_id` is the GitHub installation the kept event names (decimal digits),
  // null when it names none (push, pull request and checks events) or was not kept.
  // `installation` is `linked` when Kovo has an installation row for it (live or deleted), or the
  // kept event names a Kovo repository (live or removed); `not_linked` when it names an
  // installation Kovo never linked; `unknown` otherwise. `account_id` is the grant's account when
  // the delivery resolves to it (the linked installation's account, else the live, else the most
  // recently removed repository's), else null (no tenant owns the delivery). `excluded_reason` is
  // null when `kovo.github.events_stuck` counts the delivery, else why it leaves it out:
  // `installation_not_linked` (an installation Kovo never linked), `installation_removed` (its
  // installation is deleted), `reconciled_since_given_up` (a fully successful nightly
  // reconciliation of its installation finished after the delivery's last arrival or attempt) or
  // `repo_checked_since_given_up` (a repository-state delivery whose repository's own nightly
  // check succeeded after it, #8819); or it is retired, counted by `kovo.github.events_retired`
  // instead: `repo_removed` (its repository is removed), `repo_archived` (archived) or
  // `permanent_failure` (its last failure was `not_found`, `permission_denied` or
  // `installation_suspended`).
  github_deliveries_stuck: z.strictObject({
    provider: z.literal("github"),
    event_id: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/)
      .nullable(),
    event_type: code,
    github_installation_id: z
      .string()
      .regex(/^[1-9][0-9]{0,17}$/)
      .nullable(),
    installation: z.enum(["linked", "not_linked", "unknown"]),
    account_id: id.nullable(),
    status: z.enum(["received", "processing", "failed"]),
    attempts: z.int().nonnegative(),
    last_error_code: code.nullable(),
    given_up_reason: z.enum(["max_attempts", "retry_window"]),
    excluded_reason: z
      .enum([
        "installation_not_linked",
        "installation_removed",
        "reconciled_since_given_up",
        "repo_checked_since_given_up",
        "repo_removed",
        "repo_archived",
        "permanent_failure",
      ])
      .nullable(),
    received_at: time,
    last_attempt_at: nullableTime,
    given_up_at: nullableTime,
  }),
  // The malware scanner's unknown verdicts (#8590), the rows behind `kovo.malware.unknown_escalated`:
  // escalated first, then oldest first. `malware_scans` is global public-artifact evidence with no
  // tenant identifiers, so this read is fleet-wide under an account-wide grant and never narrowed
  // to a repository or job. Public package name and exact version, whether an integrity is bound
  // (never the integrity value), the stored unknown reason, the escalation flag and timestamps.
  // Never the scanner namespace or organization, a revision, suspicion details or anything that
  // ties the artifact to a customer. `deadline_at` is `first_unknown_at` plus the two-hour
  // escalation bound. `reason_unknown_total` counts every unknown row with this row's reason (not
  // only the rows returned), and `scanner_next_lookup_at` is the scanner's next batch time (later
  // than usual when a vendor Retry-After deferred it), null before its first sweep. The store keeps
  // no attempt count.
  malware_unknown: z.strictObject({
    name: packageNameSchema,
    version: exactVersionSchema,
    integrity_present: z.boolean(),
    reason: z.enum([...MALWARE_UNKNOWN_REASONS, "unknown_legacy"]),
    escalated: z.boolean(),
    first_unknown_at: time,
    deadline_at: time,
    first_lookup_at: nullableTime,
    checked_at: nullableTime,
    next_attempt_at: time,
    reason_unknown_total: z.int().nonnegative(),
    scanner_next_lookup_at: nullableTime,
  }),
  // One package version's stored malware verdicts (#8948), newest first, at most 20: the resolved
  // evidence `malware_unknown` never lists. `malware_scans` is global public-artifact evidence, so
  // the read is fleet-wide under an account-wide grant. `verdict` is the stored enum (`no_signal`
  // is no signal, not proof of safety), `integrity_present` says whether an integrity is bound
  // (never its value), `decided_at` is when the scanner first answered (else its last check),
  // `provider` is the scanner's vendor (`socket`, else `other`; never the organization namespace)
  // and `reason` the stored reason (`unknown_legacy` outside the closed set). Never the integrity,
  // a revision, suspicion details, advisory text or any package content.
  malware_verdict: z.strictObject({
    verdict: z.enum(["unknown", "no_signal", "suspected", "confirmed"]),
    escalated: z.boolean(),
    integrity_present: z.boolean(),
    decided_at: nullableTime,
    provider: z.enum(["socket", "other"]),
    reason: z.enum([...MALWARE_UNKNOWN_REASONS, "unknown_legacy"]),
  }),
} as const;
/** Row readers for DIAGNOSTIC_READER_ONLY_QUERIES (#5500); IDs, codes and timestamps only. */
export const DIAGNOSTIC_READER_ONLY_ROW_SCHEMAS = {
  // Each recent job's sanitized sandbox outcome (#5500): the job's first sandbox failure, else its
  // latest clean end. Codes stay open here so a newer state, phase or failure code never fails a
  // read; the served writer narrows them to fixed enums.
  job_sandbox_outcomes: z.strictObject({
    id,
    repo_id: id.nullable(),
    kind: code,
    status: code,
    sandbox_state: code.nullable(),
    sandbox_phase: code.nullable(),
    sandbox_failure_code: code.nullable(),
    sandbox_outcome_at: nullableTime,
    sandbox_outcome_refusal: code.nullable(),
    created_at: time,
  }),
} as const satisfies Record<(typeof DIAGNOSTIC_READER_ONLY_QUERIES)[number], z.ZodType>;
// Reader first: responses accept the reader-only queries; the writer stays the served language.
export const diagnosticQueryResponseSchema = writerPinned(
  z.strictObject({
    query: z.enum([...DIAGNOSTIC_QUERIES, ...DIAGNOSTIC_READER_ONLY_QUERIES]),
    rows: z
      .array(
        z.union([
          ...Object.values(DIAGNOSTIC_ROW_SCHEMAS),
          ...Object.values(DIAGNOSTIC_READER_ONLY_ROW_SCHEMAS),
        ]),
      )
      .max(100),
  }),
  z.strictObject({
    query: diagnosticQueryNameSchema,
    rows: z.array(z.union(Object.values(DIAGNOSTIC_ROW_SCHEMAS))).max(100),
  }),
);
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
