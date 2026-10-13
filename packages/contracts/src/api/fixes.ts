import { stepDiagnosticRecordSchema } from "../step-diagnostics.js";
import { z } from "zod";

import { fixTierSchema } from "../enums/advisories.js";
import {
  FIX_OUTCOME_STATUS,
  fixOutcomeReasonSchema,
  fixStatusSchema,
  isTerminalFixStatus,
  ladderRungSchema,
  mergedBySchema,
  verificationResultSchema,
  type FixStatus,
} from "../enums/fixes.js";
import { baseFreshnessSchema } from "../enums/repos.js";
import { fixWaitSchema, retryStrategySchema } from "../enums/waits.js";
import {
  changedFilesSchema,
  evidenceBindingSchema,
  evidenceRecipeSchema,
  fixEvidenceSchema,
  mergeDecisionSchema,
  policyChecksSchema,
  servedModelIdsSchema,
  servedProvidersSchema,
  stepResultsSchema,
  type FixEvidence,
} from "../evidence.js";
import {
  accountIdSchema,
  evidenceIdSchema,
  findingIdSchema,
  fixIdSchema,
  repoIdSchema,
} from "../ids.js";
import { exactVersionSchema, packageNameSchema, packageVersionSchema } from "../npm.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import {
  countSchema,
  gitShaSchema,
  imageDigestSchema,
  sha256HexSchema,
  whenValid,
} from "../primitives.js";
import { DURATIONS, utcDateTimeSchema } from "../time.js";
import { pullRequestRefSchema } from "../webhooks.js";
import { fixAttemptSchema } from "../workflow-ids.js";
import {
  emptyBodySchema,
  queryBooleanSchema,
  repoRefSchema,
  uniqueArraySchema,
  workSearchSchema,
} from "./common.js";
import { inventoryPublicationSchema } from "./jobs.js";
import { defineEndpoint } from "./endpoint.js";
import { JOB_RESULT_SCHEMAS, jobSchema } from "./jobs.js";
import { viewerPermissionSchema } from "./repos.js";

// `/v1/repos/{repo}/fixes`, `/v1/fixes/{id}/…`: fixes with their evidence summary, decideMerge
// record, PR link, wait reason and next action (SPEC "Workflows", "decideMerge", Public API rows
// 19–21). Evidence is sanitized metadata only: names, versions, paths, codes, counts and hashes.

// ---- Evidence summary ----

const REQUIRED_CHECK_COUNT_KEYS = ["success", "failure", "pending", "missing", "unknown"] as const;

/**
 * A fix's verification evidence as lists show it. The full record is on `GET /v1/fixes/{id}`.
 * "old verification evidence expires after 30 days and can never authorize a later merge".
 */
export const evidenceSummarySchema = z
  .strictObject({
    id: evidenceIdSchema,
    /** The `Kovo verification` outcome ("failed/unverified fixes must never publish a success"). */
    result: verificationResultSchema,
    verified_at: utcDateTimeSchema,
    expires_at: utcDateTimeSchema,
    /** What the evidence is bound to: "Record exact head/base/tree, recipe/config/image versions". */
    base_sha: gitShaSchema,
    /** The published head and tree the evidence authorizes; null until bound before publication. */
    binding: evidenceBindingSchema.nullable(),
    /** The recipe version and fingerprint verified with; null without an approved recipe. */
    recipe: evidenceRecipeSchema.nullable(),
    policy_version: z.int().positive(),
    base_freshness: baseFreshnessSchema,
    /**
     * True for `selective` freshness: the evidence covers the recorded base only, so it is not
     * proof of the final merged tree ("show that this is not proof of the final merged tree").
     */
    recorded_base_only: z.boolean(),
    /** The runtime the harness ran on; null when no sandbox step ran (unverified). */
    runtime: z
      .strictObject({
        image_digest: imageDigestSchema,
        node_version: exactVersionSchema,
        pm_version: exactVersionSchema,
      })
      .nullable(),
    /**
     * Every model ID and inference provider that served the agent's run (each a `, `-joined list,
     * usually of one); null for deterministic fixes.
     */
    model: z
      .strictObject({ model_id: servedModelIdsSchema, provider: servedProvidersSchema })
      .nullable(),
    dependency_changes: z.strictObject({
      total: countSchema,
      added: countSchema,
      removed: countSchema,
      upgraded: countSchema,
      downgraded: countSchema,
      major: countSchema,
      new_top_level: countSchema,
    }),
    changed_files: changedFilesSchema,
    steps: stepResultsSchema,
    policy_checks: policyChecksSchema,
    advisory_recheck: z.strictObject({
      targeted: countSchema,
      cleared: countSchema,
      introduced_severe: countSchema,
      existing_unrelated: countSchema,
    }),
    required_checks: z
      .strictObject({
        empty: z.boolean(),
        strict_up_to_date: z.boolean(),
        success: countSchema,
        failure: countSchema,
        pending: countSchema,
        missing: countSchema,
        unknown: countSchema,
      })
      .nullable(),
  })
  .superRefine((evidence, ctx) => {
    const lifetime = evidence.expires_at.getTime() - evidence.verified_at.getTime();
    if (lifetime <= 0 || lifetime > DURATIONS.evidenceMaxAge) {
      ctx.addIssue({
        code: "custom",
        path: ["expires_at"],
        message: "evidence expires after verification and within 30 days",
      });
    }
    const deps = evidence.dependency_changes;
    if (deps.total !== deps.added + deps.removed + deps.upgraded + deps.downgraded) {
      ctx.addIssue({
        code: "custom",
        path: ["dependency_changes", "total"],
        message: "total is the sum of the kinds",
      });
    }
    if (deps.major > deps.upgraded + deps.downgraded || deps.new_top_level > deps.added) {
      ctx.addIssue({
        code: "custom",
        path: ["dependency_changes"],
        message: "majors are version changes and new top-level dependencies are additions",
      });
    }
    const recheck = evidence.advisory_recheck;
    if (recheck.targeted === 0 || recheck.cleared > recheck.targeted) {
      ctx.addIssue({
        code: "custom",
        path: ["advisory_recheck"],
        message: "a fix targets at least one finding and clears at most all of them",
      });
    }
    const checks = evidence.required_checks;
    if (checks !== null) {
      const reported = REQUIRED_CHECK_COUNT_KEYS.reduce((sum, key) => sum + checks[key], 0);
      if (checks.empty !== (reported === 0)) {
        ctx.addIssue({
          code: "custom",
          path: ["required_checks", "empty"],
          message: "empty must match the counts",
        });
      }
    }
    const blocking = evidence.steps.some(
      (step) => step.status !== "passed" && step.status !== "skipped",
    );
    if (evidence.result === "passed" && (blocking || evidence.steps.length === 0)) {
      ctx.addIssue({
        code: "custom",
        path: ["result"],
        message: "passed verification ran steps and every step passed or was skipped",
      });
    }
    if (evidence.recorded_base_only !== (evidence.base_freshness === "selective")) {
      ctx.addIssue({
        code: "custom",
        path: ["recorded_base_only"],
        message: "selective evidence covers the recorded base only",
      });
    }
    if (evidence.result === "passed" && (evidence.recipe === null || evidence.runtime === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["recipe"],
        message: "passed verification ran an approved or calibrated recipe",
      });
    }
  }, whenValid);
export type EvidenceSummary = z.output<typeof evidenceSummarySchema>;

/** Derives the list summary from a full evidence record. */
export function summarizeEvidence(evidence: FixEvidence): EvidenceSummary {
  const changes = evidence.dependency_changes;
  const count = (kind: (typeof changes)[number]["change"]) =>
    changes.filter((change) => change.change === kind).length;
  const required = evidence.required_checks;
  const state = (value: string) =>
    required?.checks.filter((check) => check.state === value).length ?? 0;
  const targeted = evidence.advisory_recheck.targeted;
  const runtime =
    evidence.image_digest === null || evidence.node_version === null || evidence.pm_version === null
      ? null
      : {
          image_digest: evidence.image_digest,
          node_version: evidence.node_version,
          pm_version: evidence.pm_version,
        };
  const summary: EvidenceSummary = {
    id: evidence.id,
    result: evidence.result,
    verified_at: evidence.verified_at,
    expires_at: evidence.expires_at,
    base_sha: evidence.base_sha,
    binding: evidence.binding,
    recipe: evidence.recipe,
    policy_version: evidence.policy_version,
    base_freshness: evidence.base_freshness,
    recorded_base_only: evidence.base_freshness === "selective",
    runtime,
    model:
      evidence.model_id === null || evidence.provider === null
        ? null
        : { model_id: evidence.model_id, provider: evidence.provider },
    dependency_changes: {
      total: changes.length,
      added: count("added"),
      removed: count("removed"),
      upgraded: count("upgraded"),
      downgraded: count("downgraded"),
      major: changes.filter((change) => change.bump === "major").length,
      new_top_level: changes.filter((change) => change.change === "added" && change.is_direct)
        .length,
    },
    changed_files: evidence.changed_files,
    steps: evidence.step_results,
    policy_checks: evidence.policy_checks,
    advisory_recheck: {
      targeted: targeted.length,
      cleared: targeted.filter((finding) => finding.cleared).length,
      introduced_severe: evidence.advisory_recheck.introduced.filter(
        (finding) => finding.is_malicious || finding.tier !== "digest",
      ).length,
      existing_unrelated: evidence.advisory_recheck.existing_unrelated,
    },
    required_checks:
      required === null
        ? null
        : {
            empty: required.empty,
            strict_up_to_date: required.strict_up_to_date,
            success: state("success"),
            failure: state("failure"),
            pending: state("pending"),
            missing: state("missing"),
            unknown: state("unknown"),
          },
  };
  // Round-trips the wire form so the summary's invariants are checked on the domain value.
  return evidenceSummarySchema.decode(evidenceSummarySchema.encode(summary));
}

// ---- Fix ----

/** Statuses that always have a published PR. */
const PR_STATUSES: ReadonlySet<FixStatus> = new Set([
  "pr_open",
  "reverifying",
  "merging",
  "merged",
  "reverted",
]);

/**
 * The most finding IDs a `/v1` fix lists (`finding_ids`): the lowest IDs of the findings the attempt
 * targets. Every presenter of a fix bounds its list to it (docs/decisions/fix-orchestration.md
 * "Fixes API").
 */
export const FIX_FINDING_IDS_MAX = 500;

/**
 * A fix attempt: status, the wait reason and next action while it waits ("Every waiting state
 * carries a machine-readable reason and next action"), the PR, evidence and the rule-by-rule
 * decision.
 */
/** Capability negotiation preserves strict older clients during rolling updates. */
export const CRITICAL_AUTO_REVERT_ACCEPT = "application/json; kovo-critical-auto-revert=1";
export function acceptsCriticalAutoRevert(accept: string | undefined): boolean {
  return (
    accept
      ?.split(",")
      .some((media) =>
        /^\s*application\/json\s*;\s*kovo-critical-auto-revert=1\s*$/i.test(media),
      ) ?? false
  );
}

/** Additive read model; watch metadata never enters persisted evidence or decision JSON. */
export const criticalAutoRevertSchema = z.strictObject({
  state: z.enum(["armed", "watching", "regression", "revert_open", "reverted", "passed", "held"]),
  reason: z
    .string()
    .regex(/^[a-z][a-z0-9_]{0,95}$/)
    .nullable(),
  expires_at: utcDateTimeSchema.nullable(),
});
export type CriticalAutoRevert = z.output<typeof criticalAutoRevertSchema>;

export const fixSchema = z
  .strictObject({
    id: fixIdSchema,
    repo_id: repoIdSchema,
    target_package: packageNameSchema,
    attempt: fixAttemptSchema,
    tier: fixTierSchema,
    status: fixStatusSchema,
    ladder_rung: ladderRungSchema.nullable(),
    used_agent: z.boolean(),
    target_version: packageVersionSchema.nullable(),
    finding_ids: uniqueArraySchema(findingIdSchema, FIX_FINDING_IDS_MAX, 1),
    wait: fixWaitSchema.nullable(),
    needs_retarget: z.boolean(),
    pull_request: pullRequestRefSchema.nullable(),
    evidence: evidenceSummarySchema.nullable(),
    decision: mergeDecisionSchema.nullable(),
    merged_sha: gitShaSchema.nullable(),
    merged_by: mergedBySchema.nullable(),
    revert_pull_request: pullRequestRefSchema.nullable(),
    critical_auto_revert: criticalAutoRevertSchema.exactOptional(),
    /**
     * End of the seven-day package hold a merged revert placed ("place a seven-day package hold");
     * null once a newly actionable advisory cleared it early, and on every other fix.
     */
    hold_until: utcDateTimeSchema.nullable(),
    outcome_reason: fixOutcomeReasonSchema.nullable(),
    created_at: utcDateTimeSchema,
    terminal_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((fix, ctx) => {
    const terminal = isTerminalFixStatus(fix.status);
    if (terminal !== (fix.terminal_at !== null) || terminal !== (fix.outcome_reason !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["outcome_reason"],
        message: "exactly terminal fixes have terminal_at and an outcome reason",
      });
    }
    if (fix.outcome_reason !== null && FIX_OUTCOME_STATUS[fix.outcome_reason] !== fix.status) {
      ctx.addIssue({
        code: "custom",
        path: ["outcome_reason"],
        message: `${fix.outcome_reason} ends a fix as ${FIX_OUTCOME_STATUS[fix.outcome_reason]}`,
      });
    }
    if (terminal && fix.wait !== null) {
      ctx.addIssue({ code: "custom", path: ["wait"], message: "a terminal fix is not waiting" });
    }
    if (fix.status === "awaiting_human" && fix.wait === null) {
      ctx.addIssue({
        code: "custom",
        path: ["wait"],
        message: "awaiting_human carries a reason and next action",
      });
    }
    if (PR_STATUSES.has(fix.status) && fix.pull_request === null) {
      ctx.addIssue({
        code: "custom",
        path: ["pull_request"],
        message: `a ${fix.status} fix has a PR`,
      });
    }
    const merged = fix.status === "merged" || fix.status === "reverted";
    if (merged !== (fix.merged_sha !== null) || merged !== (fix.merged_by !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["merged_sha"],
        message: "exactly merged (and later reverted) fixes record the merge",
      });
    }
    if (fix.hold_until !== null && fix.status !== "reverted") {
      ctx.addIssue({
        code: "custom",
        path: ["hold_until"],
        message: "only a reverted fix holds its package",
      });
    }
    if (fix.status === "reverted" && fix.revert_pull_request === null) {
      ctx.addIssue({
        code: "custom",
        path: ["revert_pull_request"],
        message: "a reverted fix links its revert PR",
      });
    }
    if (fix.revert_pull_request !== null && !merged) {
      ctx.addIssue({
        code: "custom",
        path: ["revert_pull_request"],
        message: "only merged fixes are reverted",
      });
    }
    if (fix.decision?.merge != null && fix.merged_by !== "kovo") {
      ctx.addIssue({
        code: "custom",
        path: ["merged_by"],
        message: "an autopilot merge is merged by kovo",
      });
    }
    if (fix.decision !== null && fix.decision.tier !== fix.tier) {
      ctx.addIssue({
        code: "custom",
        path: ["decision"],
        message: "the decision is for the fix's tier",
      });
    }
    if (fix.terminal_at !== null && fix.terminal_at.getTime() < fix.created_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["terminal_at"],
        message: "a fix ends after it is created",
      });
    }
  }, whenValid);
export type Fix = z.output<typeof fixSchema>;

export const fixResponseSchema = z.strictObject({ fix: fixSchema });

/**
 * `POST /v1/fixes/{id}/retry`. `strategy` (default `default`) chooses how the successor runs:
 * `deterministic_only` skips the agent. SPEC: "Waiting for AI must not prevent an independent
 * deterministic retry": a fix waiting on AI availability or AI funding (`AI_FUNDING_WAIT_REASONS`)
 * allows `retry_fix`, and its successor runs `deterministic_only` whatever the request says,
 * because an agent attempt would only wait again.
 */
/** A durable retry intent has a fixed RFC9562 timestamp, enforced by the server Clock. */
export const retryIntentIdSchema = z
  .uuid()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
export const retryReceiptSelectorSchema = z.strictObject({
  retry_intent_id: retryIntentIdSchema,
  retry_key_sha256: sha256HexSchema,
  retry_request_sha256: sha256HexSchema,
});
export const retryReceiptSchema = z
  .strictObject({
    retry_intent_id: retryIntentIdSchema,
    original_fix_id: fixIdSchema,
    successor_fix_id: fixIdSchema,
    attempt: fixAttemptSchema,
    retry_key_sha256: sha256HexSchema,
    retry_request_sha256: sha256HexSchema,
    accepted_at: utcDateTimeSchema,
  })
  .refine(
    (receipt) => receipt.original_fix_id !== receipt.successor_fix_id && receipt.attempt >= 2,
    {
      ...whenValid,
      error: "a retry receipt names a distinct successor attempt",
    },
  );
export type RetryReceipt = z.output<typeof retryReceiptSchema>;
export type RetryReceiptSelector = z.output<typeof retryReceiptSelectorSchema>;
/** Stored revision identity of the actual evidence named by this completed job. */
export const jobVerificationEvidenceSchema = z.strictObject({
  id: evidenceIdSchema,
  revision: z.number().int().positive(),
  result: verificationResultSchema,
  base_sha: gitShaSchema,
  binding: evidenceBindingSchema.nullable(),
  patch_sha256: sha256HexSchema.nullable(),
  expires_at: utcDateTimeSchema,
});
export type JobVerificationEvidence = z.output<typeof jobVerificationEvidenceSchema>;
export const fixJobHistoryItemSchema = z
  .strictObject({
    job: jobSchema,
    verification_evidence: jobVerificationEvidenceSchema.nullable(),
  })
  .refine(
    (item) => {
      if (item.verification_evidence === null) return true;
      const result = JOB_RESULT_SCHEMAS.fix_verification.safeParse(item.job.result);
      return (
        item.job.kind === "fix_verification" &&
        item.job.status === "succeeded" &&
        result.success &&
        result.data.evidence_id === item.verification_evidence.id &&
        result.data.verification === item.verification_evidence.result
      );
    },
    { ...whenValid, error: "verification evidence matches the actual completed job result" },
  );

const fixRecoveryQuerySchema = z
  .strictObject({
    ...paginationQueryShape,
    include_jobs: queryBooleanSchema.exactOptional(),
    retry_intent_id: retryIntentIdSchema.exactOptional(),
    retry_key_sha256: sha256HexSchema.exactOptional(),
    retry_request_sha256: sha256HexSchema.exactOptional(),
  })
  .refine(
    (value) => {
      const present = [
        value.retry_intent_id,
        value.retry_key_sha256,
        value.retry_request_sha256,
      ].filter((part) => part !== undefined).length;
      return present === 0 || present === 3;
    },
    { ...whenValid, error: "an exact retry receipt selector requires all three fields" },
  )
  .refine((value) => value.cursor === undefined || value.include_jobs === true, {
    ...whenValid,
    error: "a job history cursor requires include_jobs=true",
  });

export const retryFixBodySchema = z.strictObject({
  retry_intent_id: retryIntentIdSchema.exactOptional(),
  /** Optional exact current publication precondition, checked under the repository lock. */
  expected_inventory: inventoryPublicationSchema.exactOptional(),
  strategy: retryStrategySchema.exactOptional(),
});

/**
 * A fix in the account-wide list: the fix as the repository's list shows it, the repository it is
 * in and the viewer's permission there (as `GET /v1/repos` reports it).
 */
export const accountFixSchema = z
  .strictObject({
    fix: fixSchema,
    repo: repoRefSchema,
    viewer_permission: viewerPermissionSchema,
  })
  .refine((item) => item.fix.repo_id === item.repo.id, {
    ...whenValid,
    error: "the fix is in the repository named",
    path: ["repo"],
  });
export type AccountFix = z.output<typeof accountFixSchema>;

/** Separate U5 read model; never extends the strict fix/evidence response. */
export const publishNowBindingSchema = z.strictObject({
  evidence_id: evidenceIdSchema,
  revision: z.int().positive(),
  candidate_identity: z.string().regex(/^(head:[0-9a-f]{40}|patch:[0-9a-f]{64})$/),
  artifacts_digest: sha256HexSchema,
});
export const publishNowAvailabilitySchema = z.strictObject({
  available: z.boolean(),
  reason: z.string().regex(/^[a-z][a-z0-9_]{0,95}$/),
  binding: publishNowBindingSchema.nullable(),
  versions: z
    .array(
      z.strictObject({
        name: packageNameSchema,
        version: packageVersionSchema,
        age_ms: z.number().finite().nonnegative().nullable(),
        npm_scan: z.enum(["complete", "pending"]),
        scanner_verdict: z.string().max(64),
        checks_passed: z.array(z.string().max(64)).max(16),
      }),
    )
    .max(5000),
  checks_passed: z.array(z.string().max(64)).max(16),
});
export type PublishNowAvailability = z.output<typeof publishNowAvailabilitySchema>;
export type PublishNowBinding = z.output<typeof publishNowBindingSchema>;

// ---- Endpoints ----

const READERS = ["human_session", "api_key_read", "api_key_write"] as const;
const fixParams = z.strictObject({ id: fixIdSchema });

export const FIX_ENDPOINTS = {
  listFixes: defineEndpoint({
    operationId: "listFixes",
    area: "fixes",
    method: "GET",
    path: "/v1/repos/{repo}/fixes",
    summary: "List a repository's fixes with evidence, decisions, PRs and action reasons.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/fixes" },
    params: z.strictObject({ repo: repoIdSchema }),
    query: z.strictObject({
      ...paginationQueryShape,
      status: fixStatusSchema.exactOptional(),
      package: packageNameSchema.exactOptional(),
      /** `true`: nonterminal fixes only; `false`: terminal fixes only. */
      active: queryBooleanSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(fixSchema) },
    authorization: {
      spec: "Scoped read; evidence, decisions, PR and action reasons",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
    paginated: true,
  }),
  listAccountFixes: defineEndpoint({
    operationId: "listAccountFixes",
    area: "fixes",
    method: "GET",
    path: "/v1/accounts/{account}/fixes",
    summary: "List the fixes of every repository of the account the caller can read, newest first.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: z.strictObject({ account: accountIdSchema }),
    query: z.strictObject({
      ...paginationQueryShape,
      repo_id: repoIdSchema.exactOptional(),
      status: fixStatusSchema.exactOptional(),
      tier: fixTierSchema.exactOptional(),
      package: packageNameSchema.exactOptional(),
      /** `true`: nonterminal fixes only; `false`: terminal fixes only. */
      active: queryBooleanSchema.exactOptional(),
      /** Part of the target package's name. */
      q: workSearchSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(accountFixSchema) },
    authorization: {
      spec: "Repository visibility always requires current GitHub read access.",
      actors: READERS,
      tenant: "path_account",
      repoAuthority: { level: "read", over: "listed_items" },
    },
    paginated: true,
  }),
  getFix: defineEndpoint({
    operationId: "getFix",
    area: "fixes",
    method: "GET",
    path: "/v1/fixes/{id}",
    summary: "Read one fix with its full sanitized evidence record.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: fixParams,
    query: fixRecoveryQuerySchema,
    body: null,
    responses: {
      200: z
        .strictObject({
          fix: fixSchema,
          evidence: fixEvidenceSchema.nullable(),
          step_diagnostics: z.array(stepDiagnosticRecordSchema).max(1000).exactOptional(),
          retry_receipt: retryReceiptSchema.nullable().exactOptional(),
          job_history: pageSchema(fixJobHistoryItemSchema)
            .extend({
              scope: z.literal("retained"),
            })
            .exactOptional(),
        })
        .refine(
          (body) =>
            body.job_history === undefined ||
            body.job_history.items.every(
              (item) =>
                "fix_id" in item.job &&
                item.job.fix_id === body.fix.id &&
                item.job.repo_id === body.fix.repo_id,
            ),
          { ...whenValid, error: "retained jobs belong to the requested fix and repository" },
        )
        .refine((body) => body.evidence === null || body.evidence.fix_id === body.fix.id, {
          ...whenValid,
          error: "the evidence belongs to the fix",
          path: ["evidence"],
        })
        .refine(
          (body) =>
            body.retry_receipt == null || body.retry_receipt.original_fix_id === body.fix.id,
          {
            ...whenValid,
            error: "the retry receipt belongs to the addressed original fix",
            path: ["retry_receipt"],
          },
        ),
    },
    authorization: {
      spec: "Repository visibility always requires current GitHub read access.",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "resource_repos" },
    },
    paginated: true,
    problems: ["idempotency_conflict", "conflict"],
  }),
  reevaluateFix: defineEndpoint({
    operationId: "reevaluateFix",
    area: "fixes",
    method: "POST",
    path: "/v1/fixes/{id}/reevaluate",
    summary: "Immediately screen and release an eligible held fix through the reconciliation path.",
    source: { kind: "spec_row", path: "/v1/fixes/{id}/reevaluate" },
    auditActions: ["fix.retry_requested"],
    params: fixParams,
    query: null,
    body: emptyBodySchema,
    responses: { 202: z.strictObject({ fix_id: fixIdSchema, status: z.literal("released") }) },
    authorization: {
      managementPermission: "retryFix",
      spec: "Human repo admin; immediate single-fix re-evaluation with all current gates",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "resource_repos" },
    },
    idempotency: "required",
    problems: ["not_reevaluable", "already_evaluated_at_version", "reevaluation_budget_exhausted"],
  }),
  retryFix: defineEndpoint({
    operationId: "retryFix",
    area: "fixes",
    method: "POST",
    path: "/v1/fixes/{id}/retry",
    summary:
      "Retry a fix: the prior attempt retires and its successor passes the same entitlement, slot and cost gates.",
    source: { kind: "spec_row", path: "/v1/fixes/{id}/retry" },
    auditActions: ["fix.retry_requested"],
    params: fixParams,
    query: null,
    body: retryFixBodySchema,
    responses: {
      202: fixResponseSchema.refine((body) => !isTerminalFixStatus(body.fix.status), {
        ...whenValid,
        error: "the retried fix is active",
      }),
    },
    authorization: {
      spec: "Scoped write; preserve entitlement, slot and cost gates",
      actors: ["human_session", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "write", over: "resource_repos" },
    },
    idempotency: "accepted",
    problems: [
      "fix_not_retriable",
      "repo_not_enabled",
      "installation_suspended",
      "precondition_failed",
      "conflict",
    ],
  }),
  getPublishNowAvailability: defineEndpoint({
    operationId: "getPublishNowAvailability",
    area: "fixes",
    method: "GET",
    path: "/v1/fixes/{id}/publish-now",
    summary: "Read exact-candidate publication override eligibility and confirmation facts.",
    source: { kind: "spec_row", path: "/v1/fixes/{id}/publish-now" },
    params: fixParams,
    query: null,
    body: null,
    responses: { 200: publishNowAvailabilitySchema },
    authorization: {
      spec: "Human repository admin only; separate exact-candidate availability, refusal code and confirmation facts",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "resource_repos" },
    },
  }),
  publishFixNow: defineEndpoint({
    operationId: "publishFixNow",
    area: "fixes",
    method: "POST",
    path: "/v1/fixes/{id}/publish-now",
    summary:
      "Authorize one exact P0 candidate to publish before its minimum age; merge age stays mandatory.",
    source: { kind: "spec_row", path: "/v1/fixes/{id}/publish-now" },
    auditActions: ["fix.publication_override_requested"],
    params: fixParams,
    query: null,
    body: publishNowBindingSchema,
    responses: { 202: z.strictObject({ fix_id: fixIdSchema, status: z.literal("recorded") }) },
    authorization: {
      spec: "Human repository admin only; required Idempotency-Key; echo exact evidence/revision, candidate identity and artifact digest; publication only",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "resource_repos" },
    },
    idempotency: "required",
    problems: ["conflict"],
  }),
  revertFix: defineEndpoint({
    operationId: "revertFix",
    area: "fixes",
    method: "POST",
    path: "/v1/fixes/{id}/revert",
    summary: "Open a reviewed revert PR for a merged fix; a revert is never auto-merged.",
    source: { kind: "spec_row", path: "/v1/fixes/{id}/revert" },
    auditActions: ["fix.revert_requested"],
    params: fixParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      202: z
        .strictObject({ fix: fixSchema, job: jobSchema })
        .refine((body) => body.fix.status === "merged" && body.job.kind === "revert", {
          ...whenValid,
          error: "a revert job for a merged fix",
        }),
    },
    authorization: {
      spec: "Human repo admin; merged fix only; opens reviewed PR",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "resource_repos" },
    },
    idempotency: "accepted",
    problems: ["fix_not_merged", "conflict", "installation_suspended"],
  }),
} as const;
