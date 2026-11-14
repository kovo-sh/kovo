import { z } from "zod";
import { sandboxIdSchema } from "../ids.js";
import { nonNegativeMicroUsdWireSchema } from "../money.js";
import { supportBudgetLedgerSchema, supportBudgetMonthSchema } from "../support-budget.js";
import { SANDBOX_STATES, sandboxProviderKindSchema } from "../enums/operations.js";
import { runOperatorResearchBacktest } from "./research-watch.js";
import { containsCredential } from "../redaction/patterns.js";

import type { GlobalSettingKey } from "../enums/operations.js";
import { pageLimitSchema } from "../pagination.js";
import { whenValid } from "../primitives.js";
import { durableFailureReasonCodeSchema } from "../problem.js";
import { utcDateTimeSchema } from "../time.js";
import { pauseReasonCodeSchema } from "../enums/repos.js";
import { sandboxPhaseSchema } from "../enums/operations.js";
import { sha256HexSchema } from "../primitives.js";
import { failureCategoryNameSchema } from "../step-result.js";
import { WORKSPACE_LAYOUTS } from "../toolchain.js";
import { wellKnownPackageSchema } from "../well-known-packages.js";
import { packageManagerSchema } from "../enums/recipes.js";
import { diagnosticRequestedBySchema } from "../diagnostics.js";
import { exactVersionSchema, packageNameSchema } from "../npm.js";
import { ownerPlanGrantSchema } from "./billing.js";
import { defineEndpoint } from "./endpoint.js";

// Operator controls (SPEC: "Operator pause uses service identity plus explicit operator
// authorization, not a shared customer API key; log actor/reason and alert until cleared. Operator
// routes are not publicly usable through ordinary account sessions." "Separate operator controls
// can stop sandbox/model dispatch during an incident."). Only the `operator` actor may call these;
// the acting principal comes from the verified service identity, never from the request body.

/** Global switches: the merge pause and the sandbox/model dispatch stops. */
export const OPERATOR_CONTROLS = ["merge", "sandbox_dispatch", "model_dispatch"] as const;
export const operatorControlSchema = z.enum(OPERATOR_CONTROLS);
export type OperatorControl = z.infer<typeof operatorControlSchema>;

/** The `global_settings` key each control is stored under. */
export const OPERATOR_CONTROL_SETTING = {
  merge: "merge_pause",
  sandbox_dispatch: "sandbox_dispatch_pause",
  model_dispatch: "model_dispatch_pause",
} as const satisfies Record<OperatorControl, GlobalSettingKey>;

/** The verified operator principal (a service identity or operator account), as logged. */
export const operatorPrincipalSchema = z
  .string()
  .regex(/^[\x21-\x7e]{1,256}$/, { error: "must be a printable principal identifier" });

export const operatorControlStateSchema = z
  .strictObject({
    control: operatorControlSchema,
    paused: z.boolean(),
    /** The closed reason code given with the last change; a pause always has one. */
    reason: pauseReasonCodeSchema.nullable(),
    changed_by: operatorPrincipalSchema.nullable(),
    changed_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((state, ctx) => {
    const changed = state.changed_at !== null;
    if (changed !== (state.changed_by !== null) || changed !== (state.reason !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["changed_by"],
        message: "a change records its actor, time and reason together",
      });
    }
    if (state.paused && !changed) {
      ctx.addIssue({
        code: "custom",
        path: ["paused"],
        message: "a pause records who set it and why",
      });
    }
  }, whenValid);
export type OperatorControlState = z.output<typeof operatorControlStateSchema>;

const supportBudgetCountSchema = z.int().min(0);

/**
 * One support ledger month (owner D-136: $5 per case, $500 per UTC month; D-144: a separate $200
 * simulation month). Money is a decimal string of micro-USD. No case, account or content field.
 */
export const operatorSupportBudgetMonthSchema = z.strictObject({
  ledger: supportBudgetLedgerSchema,
  month: supportBudgetMonthSchema,
  budget_usd: nonNegativeMicroUsdWireSchema,
  held_usd: nonNegativeMicroUsdWireSchema,
  spent_usd: nonNegativeMicroUsdWireSchema,
  /** Whole percent of the budget held or spent, rounded down. */
  committed_percent: supportBudgetCountSchema,
  reservations: z.strictObject({
    held: supportBudgetCountSchema,
    uncertain: supportBudgetCountSchema,
    settled: supportBudgetCountSchema,
  }),
  cases: supportBudgetCountSchema,
  /** Refused reservations by which budget was spent (`support_case_budget_exhausted`, month). */
  refusals: z.strictObject({
    case_budget: supportBudgetCountSchema,
    month_budget: supportBudgetCountSchema,
  }),
});

export const operatorSupportBudgetSchema = z.strictObject({
  month: supportBudgetMonthSchema,
  case_budget_usd: nonNegativeMicroUsdWireSchema,
  items: z.array(operatorSupportBudgetMonthSchema).max(4),
});

/** An absent gate is open; an unreadable gate never becomes success evidence. */
export const operatorRestoreGateSchema = z.union([
  z.strictObject({ state: z.literal("open"), epoch: z.null() }),
  z.strictObject({ state: z.enum(["pending", "passed"]), epoch: z.int().positive() }),
]);

const OPERATOR_SPEC =
  "Operator pause uses service identity plus explicit operator authorization, not a shared customer API key; log actor/reason and alert until cleared. Operator routes are not publicly usable through ordinary account sessions.";

const DEAD_LETTER_SPEC =
  "Use a bounded dead-letter/reconciliation path for exhausted external retries, with visible action reasons.";

/**
 * A dead-lettered workflow as the operator view shows it: identifiers and codes only (never a
 * repository name, input or output). The kind is the outbox workflow kind of its fix or job.
 */
export const operatorDeadLetterSchema = z.strictObject({
  workflow_id: z.string().regex(/^[\x21-\x7e]{1,512}$/),
  kind: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
  account_id: z.uuid().nullable(),
  repo_id: z.uuid().nullable(),
  reason: durableFailureReasonCodeSchema,
  /**
   * The cause the dead letter recorded (D-267, #5659): the registered step that last failed and its
   * stable reason code (for example `query_canceled`). Null when none was recorded. Optional, so a
   * reader also accepts a response from a release that did not send it.
   */
  cause_step: z
    .string()
    .max(128)
    .regex(/^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)+$/)
    .nullable()
    .optional(),
  cause_code: z
    .string()
    .regex(/^[a-z][a-z0-9_]{0,63}$/)
    .nullable()
    .optional(),
  attempts: z.int().nonnegative(),
  dead_lettered_at: utcDateTimeSchema,
});
export type OperatorDeadLetter = z.output<typeof operatorDeadLetterSchema>;

/**
 * Why an operator re-drives a dead-lettered workflow: a closed code, never free text (the audit
 * event and the logs carry it; SPEC operator actions "log actor/reason").
 */
export const REDRIVE_REASON_CODES = [
  "incident_resolved",
  "provider_recovered",
  "defect_fixed",
  "capacity_restored",
  "other",
] as const;
export const redriveReasonCodeSchema = z.enum(REDRIVE_REASON_CODES);
export type RedriveReasonCode = z.infer<typeof redriveReasonCodeSchema>;

/**
 * What a re-drive did, by the dead letter's kind (docs/decisions/operations.md "Dead letters"):
 * - `fix_retried`: a fix attempt (or one of its runs) went through the fix retry: the attempt is
 *   retired and a successor with its own workflow passes the entitlement, slot and cost gates;
 * - `job_requested`: a failed job's work was requested again through its area (a new inventory
 *   run, or a recipe rediscovery that calibrates anew), never by resuming the cancelled workflow;
 * - `workflow_resumed`: any other workflow the reaper cancelled resumed on the queue it was on.
 */
export const REDRIVE_ACTIONS = ["fix_retried", "job_requested", "workflow_resumed"] as const;
export const redriveActionSchema = z.enum(REDRIVE_ACTIONS);
export type RedriveAction = z.infer<typeof redriveActionSchema>;

const deadLetterWorkflowIdSchema = z.string().regex(/^[\x21-\x7e]{1,512}$/);

export const operatorRedriveSchema = z.strictObject({
  workflow_id: deadLetterWorkflowIdSchema,
  kind: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
  action: redriveActionSchema,
  account_id: z.uuid().nullable(),
  repo_id: z.uuid().nullable(),
  /** The fix a `fix_retried` created (the retired attempt's successor); null otherwise. */
  fix_id: z.uuid().nullable(),
  /** The job a `job_requested` created or joined; null otherwise. */
  job_id: z.uuid().nullable(),
  /** The workflow that now does the work (the successor's, the new job's, or the resumed one). */
  started_workflow_id: deadLetterWorkflowIdSchema.nullable(),
  reason: redriveReasonCodeSchema,
  redriven_at: utcDateTimeSchema,
});
export type OperatorRedrive = z.output<typeof operatorRedriveSchema>;

// Stuck outbox rows (P0 release-deadlock prevention; docs/deploy/ALERT_RUNBOOKS.md "outbox-lag"):
// the metadata reader and the operator's abandon of exactly one row. Identifiers, codes, counts and
// times only: never a row's inputs, and of its correlation only the account ID.

/** Which outbox a row is in: a workflow start, or a wake of a started workflow. */
export const OUTBOX_ROW_OUTBOXES = ["start", "wake"] as const;
export const outboxRowOutboxSchema = z.enum(OUTBOX_ROW_OUTBOXES);
export type OutboxRowOutbox = z.infer<typeof outboxRowOutboxSchema>;

/** Why an operator abandons a stuck row: a closed code, never free text (audited and logged). */
export const OUTBOX_ABANDON_REASON_CODES = [
  "release_gate_blocked",
  "permanent_failure_confirmed",
  "superseded",
  "incident_resolved",
  "other",
] as const;
export const outboxAbandonReasonCodeSchema = z.enum(OUTBOX_ABANDON_REASON_CODES);
export type OutboxAbandonReasonCode = z.infer<typeof outboxAbandonReasonCodeSchema>;

/**
 * The stable code that leads the `detail` of a refused abandon (`<code>: …`); the problem's
 * `reason` is `forbidden_actor` for the first, `not_found` for the second and `conflict` for the
 * rest.
 */
export const OUTBOX_ABANDON_REFUSALS = [
  // Both outbox routes: the operator grant is not a verified human identity (agents are refused).
  "outbox_human_operator_required",
  // No row by that ID in that outbox, or its account is not the one named (wrong tenant).
  "outbox_row_not_found",
  "outbox_row_already_published",
  "outbox_row_already_abandoned",
  // A dispatcher holds the row's lock right now (it is being dispatched).
  "outbox_row_dispatching",
  // The workflow kind or wake reason is protected (`PROTECTED_OUTBOX_KINDS` in the control plane).
  "outbox_row_protected_kind",
  // A wake whose workflow's start row is gone: its kind cannot be checked, so it is refused.
  "outbox_row_kind_unknown",
] as const;
export type OutboxAbandonRefusal = (typeof OUTBOX_ABANDON_REFUSALS)[number];

const outboxCodeSchema = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);
const outboxErrorCodeSchema = z.string().regex(/^[a-z0-9_.]{1,64}$/);
const outboxWorkflowIdSchema = z.string().regex(/^[\x21-\x7e]{1,512}$/);

/** The least age (seconds) of a row the reader lists: 0 to 30 days. */
export const outboxMinAgeSchema = z.codec(
  z.string().regex(/^(?:0|[1-9]\d{0,6})$/, { error: "min_age_seconds must be an integer" }),
  z
    .int()
    .min(0)
    .max(30 * 86_400),
  { decode: (text) => Number(text), encode: (seconds) => String(seconds) },
);

/** An unpublished outbox row as the operator reader shows it: identifiers and codes only. */
export const operatorOutboxRowSchema = z.strictObject({
  row_id: z.uuid(),
  outbox: outboxRowOutboxSchema,
  workflow_id: outboxWorkflowIdSchema,
  /** The outbox workflow kind (a wake's is its start's); null when no route or start names it. */
  workflow_kind: outboxCodeSchema.nullable(),
  /** A wake's closed reason; null for a start. */
  wake_reason: outboxCodeSchema.nullable(),
  account_id: z.uuid().nullable(),
  attempts: z.int().nonnegative(),
  last_error_code: outboxErrorCodeSchema.nullable(),
  /** `abandoned`: left for an operator (automatically or by an operator's abandon). */
  state: z.enum(["pending", "abandoned"]),
  /** An operator abandon of this row is refused as `outbox_row_protected_kind`. */
  protected: z.boolean(),
  created_at: utcDateTimeSchema,
  age_seconds: z.int().nonnegative(),
});
export type OperatorOutboxRow = z.output<typeof operatorOutboxRowSchema>;

export const operatorOutboxAbandonSchema = z.strictObject({
  row_id: z.uuid(),
  outbox: outboxRowOutboxSchema,
  workflow_id: outboxWorkflowIdSchema,
  workflow_kind: outboxCodeSchema.nullable(),
  account_id: z.uuid().nullable(),
  attempts: z.int().nonnegative(),
  previous_error_code: outboxErrorCodeSchema.nullable(),
  reason: outboxAbandonReasonCodeSchema,
  created_at: utcDateTimeSchema,
  abandoned_at: utcDateTimeSchema,
});
export type OperatorOutboxAbandon = z.output<typeof operatorOutboxAbandonSchema>;

// Owner D-763 (docs/deploy/SOCKET.md "integrity_unavailable"): the reviewed removal of one repaired
// missing-integrity malware_scans investigation row. Only the operator CLI reaches it (the admin
// site's channel is refused outside `ADMIN_UI_PATHS`); agents are admitted, attributed by their
// self-declared label and audited under the operator grant.
const MALWARE_SCAN_REMOVE_SPEC =
  "Operators remove a repaired missing-integrity investigation through a reviewed operator tool";

/** Why the operator removes the investigation; closed codes, never free text (never-persist). */
export const MALWARE_SCAN_REMOVE_REASONS = [
  // The lockfile's exact SHA-512 binding was repaired and every affected waiting fix rechecked.
  "binding_repaired",
  // A bundled copy covered by its containing tarball's pinned evidence (no separate integrity).
  "bundled_copy_covered",
  // A Kovo writer bug queued the row; the writer is repaired and deployed.
  "writer_bug_repaired",
] as const;
export const malwareScanRemoveReasonSchema = z.enum(MALWARE_SCAN_REMOVE_REASONS);
export type MalwareScanRemoveReason = z.infer<typeof malwareScanRemoveReasonSchema>;

/**
 * The stable codes a refused removal leads its problem detail with (D-267); nothing is changed.
 * The removable predicate is SOCKET.md's: empty integrity, verdict `unknown`, a marker reason
 * (`integrity_unavailable`, and since #8951 `integrity_registry_mismatch`,
 * `integrity_unavailable_bundled` and the `bundled_bytes_*` reasons) and no suspicion.
 */
export const MALWARE_SCAN_REMOVE_REFUSALS = [
  // No malware_scans row has exactly this scanner namespace, package name and version.
  "malware_scan_not_found",
  // More than one row (several integrities) has this namespace, name and version.
  "malware_scan_ambiguous",
  // The row records a suspicion: only the U2 hold process resolves it.
  "malware_scan_suspicion_recorded",
  // The row has a verdict other than `unknown`.
  "malware_scan_verdict_recorded",
  // The row binds an integrity: it is scanner evidence, not a missing-binding investigation.
  "malware_scan_integrity_bound",
  // The row's reason is not an empty-integrity investigation marker's.
  "malware_scan_reason_mismatch",
] as const;
export type MalwareScanRemoveRefusal = (typeof MALWARE_SCAN_REMOVE_REFUSALS)[number];

/** A scanner namespace as the cache stores it (`socket:v0:<organization>`). */
export const malwareScanNamespaceSchema = z
  .string()
  .regex(/^socket:v0:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/, {
    error: "must be a scanner namespace such as socket:v0:kovo",
  });

/** The tracker issue a removal cites. */
const malwareScanRemoveIssueSchema = z.int().positive().max(1_000_000);

/** The removal's outcome: what a dry run found removable, or what was removed. */
export const operatorMalwareScanRemovalSchema = z.strictObject({
  namespace: malwareScanNamespaceSchema,
  name: packageNameSchema,
  version: exactVersionSchema,
  /** `removable`: a dry run that changed nothing; `removed`: the row was deleted. */
  outcome: z.enum(["removable", "removed"]),
  escalated: z.boolean(),
  first_unknown_at: utcDateTimeSchema,
  reason: malwareScanRemoveReasonSchema,
  issue: malwareScanRemoveIssueSchema,
  requested_by: diagnosticRequestedBySchema,
  /** When the row was removed (the audit time); null for a dry run. */
  removed_at: utcDateTimeSchema.nullable(),
});
export type OperatorMalwareScanRemoval = z.output<typeof operatorMalwareScanRemovalSchema>;

const STEP_FAILURE_SPEC =
  "Cloud Logging/Monitoring and OpenTelemetry carry account/repo/fix/workflow IDs, timing, reason codes and cost metadata.";

/** The most groups one step-failure listing returns (largest first). */
export const STEP_FAILURE_GROUPS_MAX = 200;

/**
 * A coarse toolchain signature for grouping failures across repositories: enums and major versions
 * only (the full fingerprint stays with each record), and its canonical SHA-256.
 */
export const operatorToolchainSignatureSchema = z.strictObject({
  sha256: sha256HexSchema,
  package_manager: packageManagerSchema,
  layout: z.enum(WORKSPACE_LAYOUTS),
  tools: z
    .array(z.strictObject({ name: wellKnownPackageSchema, major: z.int().nonnegative() }))
    .max(wellKnownPackageSchema.options.length),
  eslint_configured: z.boolean(),
});
export type OperatorToolchainSignature = z.output<typeof operatorToolchainSignatureSchema>;

/**
 * Failed steps of one phase and category under one toolchain signature (null: recorded before
 * fingerprints existed), counted over calibration baselines and controls and fix verifications:
 * IDs, enums and counts only, never a repository name, step name or output.
 */
export const operatorStepFailureGroupSchema = z.strictObject({
  source: z.enum(["calibration", "verification"]),
  phase: sandboxPhaseSchema,
  category: failureCategoryNameSchema,
  toolchain: operatorToolchainSignatureSchema.nullable(),
  failures: z.int().positive(),
  /** A few records to look at (recipe version or fix evidence IDs), newest first. */
  sample_ids: z.array(z.uuid()).min(1).max(3),
});
export type OperatorStepFailureGroup = z.output<typeof operatorStepFailureGroupSchema>;

/** Open key syntax: the service validates current registry membership before reading/writing. */
export const operatorFlagKeySchema = z.string().regex(/^[a-zA-Z][a-zA-Z0-9.]{0,127}$/);
export const operatorFlagQuerySchema = z
  .strictObject({
    scope: z.enum(["global", "account", "repo"]),
    account_id: z.uuid().exactOptional(),
    repo_id: z.uuid().exactOptional(),
  })
  .superRefine((target, ctx) => {
    if (
      (target.scope === "global" &&
        (target.account_id !== undefined || target.repo_id !== undefined)) ||
      (target.scope === "account" &&
        (target.account_id === undefined || target.repo_id !== undefined)) ||
      (target.scope === "repo" && (target.account_id === undefined || target.repo_id === undefined))
    )
      ctx.addIssue({ code: "custom", message: "scope requires its exact tenant identifiers" });
  });
export const operatorFlagTargetSchema = z.discriminatedUnion("scope", [
  z.strictObject({ scope: z.literal("global") }),
  z.strictObject({ scope: z.literal("account"), account_id: z.uuid() }),
  z.strictObject({ scope: z.literal("repo"), account_id: z.uuid(), repo_id: z.uuid() }),
]);
export type OperatorFlagTarget = z.output<typeof operatorFlagTargetSchema>;
export const operatorFlagReasonSchema = z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/);
export const operatorFlagJustificationSchema = z
  .string()
  .min(10)
  .max(500)
  .refine((value) => value.trim().length >= 10 && !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(value), {
    message: "justification must be a single line without control characters",
  })
  .refine((value) => !containsCredential(value), {
    message: "justification contains a credential",
  });
export const operatorFlagChangeSchema = z.strictObject({
  target: operatorFlagTargetSchema,
  reason: operatorFlagReasonSchema,
  justification: operatorFlagJustificationSchema,
  incident_issue: z.int().positive().max(2147483647).exactOptional(),
});
export const operatorFlagOffSchema = operatorFlagChangeSchema.extend({
  value: z.literal("off"),
  expires_at: utcDateTimeSchema,
});
export type OperatorFlagChange = z.output<typeof operatorFlagChangeSchema>;
export type OperatorFlagOff = z.output<typeof operatorFlagOffSchema>;
export const operatorFlagStateSchema = z.strictObject({
  flag: operatorFlagKeySchema,
  target: operatorFlagTargetSchema,
  override: z
    .strictObject({
      value: z.literal("off"),
      reason: operatorFlagReasonSchema,
      actor: z.uuid(),
      incident_issue: z.int().positive().nullable(),
      created_at: utcDateTimeSchema,
      expires_at: utcDateTimeSchema,
      active: z.boolean(),
    })
    .nullable(),
});
export type OperatorFlagState = z.output<typeof operatorFlagStateSchema>;
/** Most active OFF overrides one list returns; `total` still counts every active row. */
export const OPERATOR_FLAG_LIST_LIMIT = 200;
/**
 * One active OFF override, metadata only: the registry key, its target (tenant IDs exactly as
 * `getOperatorFlag` echoes them), the sanitized reason code, the operator grant ID and its live
 * agent/human classification, the optional incident issue and the UTC times. `registered` is
 * false for a key the deployed registry no longer has (the alert's `unknown` series).
 */
export const operatorFlagListItemSchema = z.strictObject({
  flag: operatorFlagKeySchema,
  registered: z.boolean(),
  target: operatorFlagTargetSchema,
  reason: operatorFlagReasonSchema,
  actor: z.uuid(),
  actor_type: z.enum(["agent", "human"]),
  incident_issue: z.int().positive().nullable(),
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
});
export type OperatorFlagListItem = z.output<typeof operatorFlagListItemSchema>;
export const operatorFlagListSchema = z.strictObject({
  items: z.array(operatorFlagListItemSchema).max(OPERATOR_FLAG_LIST_LIMIT),
  total: z.int().nonnegative(),
  truncated: z.boolean(),
});
export type OperatorFlagList = z.output<typeof operatorFlagListSchema>;

export const operatorFlagEmailSchema = z.strictObject({
  email_id: z.uuid(),
  audit_id: z.uuid(),
  flag: operatorFlagKeySchema,
  state: z.enum(["uncertain", "refused"]),
  created_at: utcDateTimeSchema,
});
export type OperatorFlagEmail = z.output<typeof operatorFlagEmailSchema>;
export const operatorFlagEmailAcknowledgmentSchema = z.strictObject({
  email_id: z.uuid(),
  acknowledged_at: utcDateTimeSchema,
});
export type OperatorFlagEmailAcknowledgment = z.output<
  typeof operatorFlagEmailAcknowledgmentSchema
>;
export const operatorFlagEmailAcknowledgeSchema = z.strictObject({
  justification: operatorFlagJustificationSchema,
});

export const supplyChainMeasurementSchema = z.strictObject({
  artifacts: z
    .array(
      z.strictObject({
        artifact_id: z.uuid(),
        package: z.string(),
        version: z.string(),
        integrity: z.string(),
        first_evaluated_at: utcDateTimeSchema,
        registry_published_at: utcDateTimeSchema.nullable(),
        signals: z.array(
          z.strictObject({
            source: z.string(),
            first_signalled_at: utcDateTimeSchema,
            age_seconds: z.number().nullable(),
          }),
        ),
        resolved_holds: z.array(
          z.strictObject({
            state: z.enum(["cleared", "retracted"]),
            false_report: z.boolean(),
            source: z.string(),
            resolved_at: utcDateTimeSchema.nullable(),
            resolution_seconds: z.number().nullable(),
          }),
        ),
        scanners: z.array(
          z.strictObject({
            source: z.string(),
            verdict: z.string(),
            reason: z.string(),
            first_lookup_at: utcDateTimeSchema.nullable(),
            first_resolved_at: utcDateTimeSchema.nullable(),
            unknown_seconds: z.number().nullable(),
            unknown_at_registry_publication: z.boolean().nullable(),
            unknown_at_first_evaluation: z.boolean().nullable(),
            unknown_at_p0_min_age: z.boolean().nullable(),
          }),
        ),
      }),
    )
    .max(100),
  evidence_truncated: z.boolean(),
  next_after: z.uuid().nullable(),
  scanner_coverage: z.strictObject({
    evaluated_artifacts: z.int().nonnegative(),
    with_scanner_lookup: z.int().nonnegative(),
    known_registry_publication: z.int().nonnegative(),
    unknown_at_registry_publication: z.int().nonnegative(),
    unknown_share: z.number().min(0).max(1).nullable(),
    unknown_at_first_evaluation: z.int().nonnegative(),
    unknown_at_first_evaluation_share: z.number().min(0).max(1).nullable(),
    p0_min_age_seconds: z.int().positive(),
    artifacts_at_p0_min_age: z.int().nonnegative(),
    unknown_at_p0_min_age: z.int().nonnegative(),
    unknown_at_p0_min_age_share: z.number().min(0).max(1).nullable(),
  }),
  publication_delays: z.strictObject({
    groups: z.array(
      z.strictObject({
        tier: z.enum(["P0", "P1"]),
        reason: z.enum([
          "p0_min_age",
          "malware_evidence_pending",
          "malware_suspected",
          "publish_time_unknown",
        ]),
        fix_count: z.int().nonnegative(),
        wait_count: z.int().nonnegative(),
        delay_seconds: z.number().nonnegative(),
      }),
    ),
    scanned_fixes: z.int().nonnegative(),
    truncated: z.boolean(),
    next_fix_offset: z.int().nonnegative().nullable(),
  }),
});
export type SupplyChainMeasurement = z.output<typeof supplyChainMeasurementSchema>;

export const OPERATOR_ENDPOINTS = {
  listOperatorSandboxOverdue: defineEndpoint({
    operationId: "listOperatorSandboxOverdue",
    area: "operator",
    method: "GET",
    path: "/v1/operator/sandbox-overdue",
    summary: "Read ID-keyed overdue sandbox observations and recent containment outcomes.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        items: z
          .array(
            z.strictObject({
              sandbox_id: sandboxIdSchema,
              provider: sandboxProviderKindSchema,
              state: z.enum(SANDBOX_STATES),
              created_at: utcDateTimeSchema,
              hard_expires_at: utcDateTimeSchema,
              last_state_change_at: utcDateTimeSchema.nullable(),
              account_kind: z.enum(["internal_test", "customer"]),
              provider_exists: z.enum(["yes", "no", "unknown"]),
              provider_checked_at: utcDateTimeSchema,
              containment_outcome: z.enum(["pending", "destroyed", "provider_gone"]),
              contained_at: utcDateTimeSchema.nullable(),
            }),
          )
          .max(200),
      }),
    },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listOperatorRetentionReconciliations: defineEndpoint({
    operationId: "listOperatorRetentionReconciliations",
    area: "operator",
    method: "GET",
    path: "/v1/operator/retention-reconciliations",
    summary: "Read aggregate retention reconciliation findings only.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        items: z
          .array(
            z.strictObject({
              check: z.enum([
                "patch_blobs",
                "failure_excerpts",
                "evidence",
                "inventory_history",
                "operational_runs",
                "email_and_analytics",
                "delivery_records",
                "auth",
                "audit",
                "financial",
                "account_deletion",
                "uninstall_cleanup",
                "sandbox_lifetime",
                "workflow_history",
                "other",
              ]),
              overdue: z.int().nonnegative(),
              oldest_due_at: utcDateTimeSchema.nullable(),
              reconciled_at: utcDateTimeSchema,
              trigger: z.enum(["nightly", "restore", "other"]),
              status: z.enum(["other"]),
            }),
          )
          .max(200),
      }),
    },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getOperatorRestoreGate: defineEndpoint({
    operationId: "getOperatorRestoreGate",
    area: "operator",
    method: "GET",
    path: "/v1/operator/restore-gate",
    summary: "Read restore gate state and epoch for an isolated restore drill.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: { 200: operatorRestoreGateSchema },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getOperatorSupportBudget: defineEndpoint({
    operationId: "getOperatorSupportBudget",
    area: "operator",
    method: "GET",
    path: "/v1/operator/support-budget",
    summary:
      "Read Kovo's own support and simulation budget totals for this UTC month and the last (owner D-136, D-144): amounts, counts and refusal counts only.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: { 200: operatorSupportBudgetSchema },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  runOperatorResearchBacktest,
  getOperatorSupplyChainMeasurement: defineEndpoint({
    operationId: "getOperatorSupplyChainMeasurement",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/supply-chain-measurement",
    summary: "Human-IAP operator malware incident measurement; tenant data appears only as counts.",
    auditStorage: "malware_hold_audit",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: z.strictObject({
      after: z.uuid().exactOptional(),
      fix_offset: z.coerce.number().int().nonnegative().max(2147483547).exactOptional(),
    }),
    body: null,
    responses: { 200: supplyChainMeasurementSchema },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listOperatorMalwareHolds: defineEndpoint({
    operationId: "listOperatorMalwareHolds",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/malware-holds",
    summary: "List malware holds for human operator triage.",
    auditStorage: "malware_hold_audit",
    source: { kind: "spec_implied", section: "Inventory, advisories, and tiering" },
    params: null,
    query: z.strictObject({
      after: z.uuid().exactOptional(),
      fix_after: z.uuid().exactOptional(),
      state: z.enum(["active", "cleared", "retracted"]).default("active"),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        blocks: z
          .array(
            z.strictObject({
              hold_id: z.uuid(),
              fix_id: z.uuid(),
              account_id: z.uuid(),
              repo_id: z.uuid(),
            }),
          )
          .max(100000),
        truncated: z.boolean(),
        next_after: z.uuid().nullable(),
        next_fix_after: z.uuid().nullable(),
        holds: z
          .array(
            z.strictObject({
              id: z.uuid(),
              package: z.string(),
              version: z.string().nullable(),
              tier: z.enum(["unknown", "suspected", "confirmed"]),
              state: z.enum(["active", "cleared", "retracted"]),
              source: z.string(),
              updated_at: utcDateTimeSchema,
            }),
          )
          .max(100),
      }),
    },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  changeOperatorMalwareHold: defineEndpoint({
    operationId: "changeOperatorMalwareHold",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/malware-holds/{id}",
    summary: "Human operator confirms, clears or retracts a malware hold.",
    source: { kind: "spec_implied", section: "Inventory, advisories, and tiering" },
    params: z.strictObject({ id: z.uuid() }),
    query: null,
    body: z.strictObject({
      action: z.enum(["confirm", "clear", "retract"]),
      reason: z.string().regex(/^[a-z][a-z0-9_.]{0,63}$/),
    }),
    responses: {
      200: z.strictObject({ id: z.uuid(), state: z.enum(["active", "cleared", "retracted"]) }),
    },
    auditStorage: "malware_hold_audit",
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "conflict"],
  }),
  listOperatorFlagEmails: defineEndpoint({
    operationId: "listOperatorFlagEmails",
    area: "operator",
    method: "GET",
    path: "/v1/operator/flag-emails",
    summary: "List at most 100 unacknowledged refused or uncertain flag FYIs, oldest first.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ items: z.array(operatorFlagEmailSchema).max(100) }) },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  acknowledgeOperatorFlagEmail: defineEndpoint({
    operationId: "acknowledgeOperatorFlagEmail",
    area: "operator",
    method: "POST",
    path: "/v1/operator/flag-emails/{email_id}/acknowledge",
    summary: "Audit acknowledgment of an undelivered FYI without sending or marking it sent.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: z.strictObject({ email_id: z.uuid() }),
    query: null,
    body: operatorFlagEmailAcknowledgeSchema,
    responses: { 200: operatorFlagEmailAcknowledgmentSchema },
    auditStorage: "flag_email_acknowledgments",
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "conflict", "validation_failed"],
  }),
  listOperatorFlags: defineEndpoint({
    operationId: "listOperatorFlags",
    area: "operator",
    method: "GET",
    path: "/v1/operator/flags",
    summary: "List every active OFF override as metadata, at most 200, with the active total.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: null,
    body: null,
    responses: { 200: operatorFlagListSchema },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getOperatorFlag: defineEndpoint({
    operationId: "getOperatorFlag",
    area: "operator",
    method: "GET",
    path: "/v1/operator/flags/{key}",
    summary: "Read one scoped OFF override, including expired metadata.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: z.strictObject({ key: operatorFlagKeySchema }),
    query: operatorFlagQuerySchema,
    body: null,
    responses: { 200: operatorFlagStateSchema },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  putOperatorFlag: defineEndpoint({
    operationId: "putOperatorFlag",
    area: "operator",
    method: "PUT",
    path: "/v1/operator/flags/{key}",
    summary: "Set an audited, expiring OFF override.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: z.strictObject({ key: operatorFlagKeySchema }),
    query: null,
    body: operatorFlagOffSchema,
    responses: { 200: operatorFlagStateSchema },
    auditStorage: "flag_override_audit",
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "validation_failed"],
  }),
  deleteOperatorFlag: defineEndpoint({
    operationId: "deleteOperatorFlag",
    area: "operator",
    method: "DELETE",
    path: "/v1/operator/flags/{key}",
    summary: "Clear an audited override; agents clear only their own.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: z.strictObject({ key: operatorFlagKeySchema }),
    query: null,
    body: operatorFlagChangeSchema,
    responses: { 200: operatorFlagStateSchema },
    auditStorage: "flag_override_audit",
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "validation_failed"],
  }),

  listOperatorPlanGrants: defineEndpoint({
    operationId: "listOperatorPlanGrants",
    area: "operator",
    method: "GET",
    path: "/v1/operator/billing/plan-grants",
    summary: "List owner-directed Plus grants and their authorization metadata.",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    params: null,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ grants: z.array(ownerPlanGrantSchema).max(200) }) },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listOperatorControls: defineEndpoint({
    operationId: "listOperatorControls",
    area: "operator",
    method: "GET",
    path: "/v1/operator/pauses",
    summary: "Read every global operator control.",
    source: { kind: "spec_implied", section: "Public API" },
    params: null,
    query: null,
    body: null,
    responses: {
      200: z
        .strictObject({ controls: z.array(operatorControlStateSchema) })
        .refine(
          (body) =>
            body.controls.length === OPERATOR_CONTROLS.length &&
            body.controls.every((state, index) => state.control === OPERATOR_CONTROLS[index]),
          { ...whenValid, error: "every control once, in order", path: ["controls"] },
        ),
    },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  setOperatorControl: defineEndpoint({
    operationId: "setOperatorControl",
    area: "operator",
    method: "PUT",
    path: "/v1/operator/pauses/{control}",
    summary:
      "Pause or clear a global control with a logged reason; an active pause alerts until cleared.",
    source: { kind: "spec_implied", section: "Public API" },
    auditActions: [
      "operator.global_paused",
      "operator.global_resumed",
      "operator.dispatch_paused",
      "operator.dispatch_resumed",
    ],
    params: z.strictObject({ control: operatorControlSchema }),
    query: null,
    body: z.strictObject({ paused: z.boolean(), reason: pauseReasonCodeSchema }),
    responses: { 200: z.strictObject({ control: operatorControlStateSchema }) },
    authorization: { spec: OPERATOR_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listOperatorDeadLetters: defineEndpoint({
    operationId: "listOperatorDeadLetters",
    area: "operator",
    method: "GET",
    path: "/v1/operator/dead-letters",
    summary: "Workflows dead-lettered since an instant, newest first, with their visible reasons.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: z.strictObject({ since: utcDateTimeSchema, limit: pageLimitSchema.default(50) }),
    body: null,
    responses: { 200: z.strictObject({ items: z.array(operatorDeadLetterSchema).max(100) }) },
    authorization: { spec: DEAD_LETTER_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listOperatorStepFailures: defineEndpoint({
    operationId: "listOperatorStepFailures",
    area: "operator",
    method: "GET",
    path: "/v1/operator/diagnostics/step-failures",
    summary:
      "Categorized failed steps recorded since an instant, by phase, category and toolchain signature.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: z.strictObject({
      since: utcDateTimeSchema,
      /** Only this category (`unclassified` lists what the classifier does not yet recognize). */
      category: failureCategoryNameSchema.exactOptional(),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        groups: z.array(operatorStepFailureGroupSchema).max(STEP_FAILURE_GROUPS_MAX),
        /** Records read; `truncated` when the window held more than one listing reads. */
        scanned: z.strictObject({
          calibrations: z.int().nonnegative(),
          verifications: z.int().nonnegative(),
          truncated: z.boolean(),
        }),
      }),
    },
    authorization: { spec: STEP_FAILURE_SPEC, actors: ["operator"], tenant: "none" },
  }),
  redriveOperatorDeadLetter: defineEndpoint({
    operationId: "redriveOperatorDeadLetter",
    area: "operator",
    method: "POST",
    // The workflow ID travels in the body: a fix's names its package, which may hold `/` and `@`.
    path: "/v1/operator/dead-letters/redrive",
    summary:
      "Re-drive one dead-lettered workflow through its area's path, with a logged actor and reason.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditActions: ["operator.dead_letter_redriven", "fix.retry_requested"],
    params: null,
    query: null,
    body: z.strictObject({
      workflow_id: deadLetterWorkflowIdSchema,
      reason: redriveReasonCodeSchema,
    }),
    responses: { 200: z.strictObject({ redrive: operatorRedriveSchema }) },
    authorization: { spec: DEAD_LETTER_SPEC, actors: ["operator"], tenant: "none" },
    // `not_found`: no dead letter by that ID; `conflict`: re-driven already, or not re-drivable in
    // its current state (its job still open, its workflow no longer cancelled); a fix the retry
    // refuses; a revert only its repository admin may request again; a repository out of service.
    problems: [
      "not_found",
      "conflict",
      "fix_not_retriable",
      "human_approval_required",
      "repo_not_enabled",
      "installation_suspended",
    ],
  }),
  listOperatorOutboxRows: defineEndpoint({
    operationId: "listOperatorOutboxRows",
    area: "operator",
    method: "GET",
    path: "/v1/operator/outbox/rows",
    summary:
      "Unpublished outbox starts and wakes at least an age old, oldest first: identifiers and codes only.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: null,
    query: z.strictObject({
      min_age_seconds: outboxMinAgeSchema.default(300),
      limit: pageLimitSchema.default(50),
    }),
    body: null,
    responses: { 200: z.strictObject({ items: z.array(operatorOutboxRowSchema).max(100) }) },
    authorization: { spec: DEAD_LETTER_SPEC, actors: ["operator"], tenant: "none" },
  }),
  abandonOperatorOutboxRow: defineEndpoint({
    operationId: "abandonOperatorOutboxRow",
    area: "operator",
    method: "POST",
    path: "/v1/operator/outbox/abandon",
    summary:
      "Abandon exactly one stuck outbox start or wake (kept, never deleted), with a logged actor and reason.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditActions: ["operator.outbox_row_abandoned"],
    params: null,
    query: null,
    body: z.strictObject({
      outbox: outboxRowOutboxSchema,
      row_id: z.uuid(),
      /** The row's account; null only for a row with none (operator-global). */
      account_id: z.uuid().nullable(),
      reason: outboxAbandonReasonCodeSchema,
    }),
    responses: { 200: z.strictObject({ abandon: operatorOutboxAbandonSchema }) },
    authorization: { spec: DEAD_LETTER_SPEC, actors: ["operator"], tenant: "none" },
    // `not_found`: `outbox_row_not_found` (also a row of another account); `conflict`: the
    // `OUTBOX_ABANDON_REFUSALS` code leading the detail.
    problems: ["not_found", "conflict"],
  }),
  removeOperatorMalwareScan: defineEndpoint({
    operationId: "removeOperatorMalwareScan",
    area: "operator",
    method: "POST",
    // Package names hold `/` and `@`: the exact identifiers travel in the body.
    path: "/v1/operator/malware-scans/remove",
    summary:
      "Remove one repaired integrity_unavailable malware scan investigation by exact name and version, or check it with a dry run.",
    source: { kind: "spec_implied", section: "Recipes and verification" },
    auditActions: ["operator.malware_scan_removed"],
    params: null,
    query: null,
    body: z.strictObject({
      namespace: malwareScanNamespaceSchema,
      name: packageNameSchema,
      version: exactVersionSchema,
      reason: malwareScanRemoveReasonSchema,
      /** The tracker issue the repair is recorded on. */
      issue: malwareScanRemoveIssueSchema,
      requested_by: diagnosticRequestedBySchema,
      /** True checks the predicate and changes nothing; false removes the row. */
      dry_run: z.boolean(),
    }),
    responses: { 200: z.strictObject({ removal: operatorMalwareScanRemovalSchema }) },
    authorization: { spec: MALWARE_SCAN_REMOVE_SPEC, actors: ["operator"], tenant: "none" },
    // `not_found`: `malware_scan_not_found`; `conflict`: another `MALWARE_SCAN_REMOVE_REFUSALS`
    // code leading the detail.
    problems: ["not_found", "conflict"],
  }),
} as const;
