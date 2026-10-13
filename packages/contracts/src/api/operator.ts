import { z } from "zod";
import { runOperatorResearchBacktest } from "./research-watch.js";
import { containsCredential } from "../redaction/index.js";

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
} as const;
