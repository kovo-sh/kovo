import { z } from "zod";
import { discoveryProvenanceReader } from "../discovery-validation.js";
import { stepDiagnosticRecordSchema } from "../step-diagnostics.js";
import { doctorOverrideSchema } from "../recipe-doctor.js";

import {
  approvalStatusSchema,
  approvedViaSchema,
  calibrationStatusSchema,
  recipeApprovalRefusalSchema,
  recipeStrengthDeltaSchema,
} from "../enums/recipes.js";
import { resourceVersionSchema } from "../http.js";
import { apiKeyIdSchema, recipeVersionIdSchema, repoIdSchema } from "../ids.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { activationScopeShape } from "../policy.js";
import {
  countSchema,
  egressHostSchema,
  envVarNameSchema,
  jsonPointerSchema,
  sha256HexSchema,
  whenValid,
} from "../primitives.js";
import {
  calibrationSchema,
  ciDeviationSchema,
  ciStepSchema,
  recipeOverrideSchema,
  recipeSchema,
} from "../recipe.js";
import { utcDateTimeSchema } from "../time.js";
import {
  actorRefSchema,
  emptyBodySchema,
  uniqueArraySchema,
  userRefSchema,
  versionNumberParamSchema,
} from "./common.js";
import { defineEndpoint } from "./endpoint.js";
import { jobResponseSchema, jobSchema } from "./jobs.js";
import { repoSchema } from "./repos.js";

// `/v1/repos/{repo}/recipe`: the active recipe with calibration and CI deviations, versions,
// recipe diffs (structured recipe changes, never source diffs), overrides with ETag/If-Match,
// rediscovery jobs, approval and rollback (SPEC "Recipes and verification", "Approval and
// activation", Public API rows 10–16).

// ---- Recipe versions ----

const recipeVersionSummaryShape = {
  id: recipeVersionIdSchema,
  version: z.int().positive(),
  parent_version_id: recipeVersionIdSchema.nullable(),
  fingerprint: sha256HexSchema,
  calibration_status: calibrationStatusSchema,
  approval_status: approvalStatusSchema,
  approved_via: approvedViaSchema.nullable(),
  approved_via_consent_id: z.uuid().exactOptional(),
  approved_by_key_id: apiKeyIdSchema.nullable().exactOptional(),
  approved_by: userRefSchema.nullable(),
  approved_at: utcDateTimeSchema.nullable(),
  approved_from_version_id: recipeVersionIdSchema.nullable(),
  /** Relative to the parent version; null for a first version. */
  strength_delta: recipeStrengthDeltaSchema.nullable(),
  superseded_at: utcDateTimeSchema.nullable(),
  created_by: actorRefSchema,
  created_at: utcDateTimeSchema,
  /** Whether this is the repository's active recipe version. */
  active: z.boolean(),
  /**
   * Why a repository admin cannot approve this version now (`POST …/approve` would answer
   * `recipe_not_approvable`), as `@kovo/core/recipe` `approvalRefusal` decides it: still
   * calibrating, calibrated weak, stale (the repository's current fingerprint differs) or
   * superseded. Null when it can be approved, and for an approved version (approving it again
   * changes nothing).
   */
  approval_refusal: recipeApprovalRefusalSchema.nullable(),
};

type RecipeVersionSummaryValue = z.output<z.ZodObject<typeof recipeVersionSummaryShape>>;

function checkRecipeVersionSummary(version: RecipeVersionSummaryValue, ctx: z.RefinementCtx): void {
  const approved = version.approval_status === "approved";
  if (approved !== (version.approved_via !== null) || approved !== (version.approved_at !== null)) {
    ctx.addIssue({
      code: "custom",
      path: ["approved_via"],
      message: "exactly approved versions record how and when they were approved",
    });
  }
  if (approved && version.calibration_status !== "calibrated") {
    // "approves a specific calibrated version"; "Weak recipes cannot authorize autopilot".
    ctx.addIssue({
      code: "custom",
      path: ["approval_status"],
      message: "only calibrated versions are approved",
    });
  }
  if ((version.approved_via === "inherited") !== (version.approved_from_version_id !== null)) {
    ctx.addIssue({
      code: "custom",
      path: ["approved_from_version_id"],
      message: "exactly inherited approvals record the parent approval",
    });
  }
  if (
    (version.approved_via === "autopilot_policy") !==
    (version.approved_via_consent_id !== undefined)
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["approved_via_consent_id"],
      message: "policy approval references exactly its standing consent",
    });
  }
  const keyedOnboarding =
    version.approved_via === "onboarding" && version.approved_by_key_id != null;
  const keyedPolicy =
    version.approved_via === "autopilot_policy" && version.approved_by_key_id != null;
  if (
    (version.approved_via === "management_key" || keyedOnboarding || keyedPolicy) !==
    (version.approved_by_key_id != null)
  )
    ctx.addIssue({
      code: "custom",
      path: ["approved_by_key_id"],
      message: "only Management, keyed onboarding and keyed policy approvals record the actual key",
    });
  const namedApprover =
    version.approved_via === "human" ||
    (version.approved_via === "onboarding" && !keyedOnboarding) ||
    version.approved_via === "management_key" ||
    (version.approved_via === "autopilot_policy" && !keyedPolicy);
  if (namedApprover && version.approved_by === null) {
    ctx.addIssue({
      code: "custom",
      path: ["approved_by"],
      message: "a human, Management or human-consent approval names the admin",
    });
  }
  if ((keyedOnboarding || keyedPolicy) && version.approved_by !== null) {
    ctx.addIssue({
      code: "custom",
      path: ["approved_by"],
      message: "keyed consent identifies the key without a fabricated human approver",
    });
  }
  if (version.active && version.superseded_at !== null) {
    ctx.addIssue({
      code: "custom",
      path: ["superseded_at"],
      message: "the active version is not superseded",
    });
  }
  if ((version.parent_version_id === null) !== (version.strength_delta === null)) {
    ctx.addIssue({
      code: "custom",
      path: ["strength_delta"],
      message: "exactly versions with a parent record their strength delta",
    });
  }
  if (!refusalMatchesState(version)) {
    ctx.addIssue({
      code: "custom",
      path: ["approval_refusal"],
      message:
        "only an unapproved version is refused, for its own state; an approvable one is calibrated and not superseded",
    });
  }
}

/**
 * The refusal names the version's own state (the decision itself is `@kovo/core/recipe`
 * `approvalRefusal`'s): none for an approved version; `superseded` exactly with `superseded_at`;
 * `calibrating` and `weak` with that calibration status; `stale` for a calibrated version whose
 * fingerprint is no longer current; none only for a calibrated version still in line.
 */
function refusalMatchesState(version: RecipeVersionSummaryValue): boolean {
  const refusal = version.approval_refusal;
  if (version.approval_status === "approved") return refusal === null;
  if (refusal === "superseded") return version.superseded_at !== null;
  if (version.superseded_at !== null) return false;
  const status = refusal === null || refusal === "stale" ? "calibrated" : refusal;
  return version.calibration_status === status;
}

export const recipeVersionSummarySchema = z
  .strictObject(recipeVersionSummaryShape)
  .superRefine(checkRecipeVersionSummary, whenValid);
export type RecipeVersionSummary = z.output<typeof recipeVersionSummarySchema>;

/**
 * A recipe version with its body, normalized CI steps, deviations and calibration record. The
 * calibration belongs to this exact version: same fingerprint, image and runtime.
 */
export const recipeVersionDetailSchema = z
  .strictObject({
    ...recipeVersionSummaryShape,
    recipe: recipeSchema,
    ci_steps: discoveryProvenanceReader(ciStepSchema),
    deviations: discoveryProvenanceReader(ciDeviationSchema),
    calibration: calibrationSchema.nullable(),
    step_diagnostics: z.array(stepDiagnosticRecordSchema).max(1000).exactOptional(),
  })
  .superRefine((version, ctx) => {
    checkRecipeVersionSummary(version, ctx);
    const calibration = version.calibration;
    if ((version.calibration_status === "calibrating") !== (calibration === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["calibration"],
        message: "exactly finished calibrations have a record",
      });
    }
    if (calibration !== null) {
      const runtime = version.recipe.runtime;
      const matches =
        calibration.status === version.calibration_status &&
        calibration.fingerprint === version.fingerprint &&
        calibration.image_digest === runtime.imageDigest &&
        calibration.node_version === runtime.node &&
        calibration.pm_version === runtime.pmVersion;
      if (!matches) {
        ctx.addIssue({
          code: "custom",
          path: ["calibration"],
          message:
            "the calibration record belongs to this version's fingerprint, image and runtime",
        });
      }
    }
    const stepIds = new Set(version.ci_steps.map((step) => step.id));
    for (const deviation of version.deviations.filter((d) => !stepIds.has(d.ci_step_id))) {
      ctx.addIssue({
        code: "custom",
        path: ["deviations"],
        message: `deviation for unknown CI step ${deviation.ci_step_id}`,
      });
    }
  }, whenValid);
export type RecipeVersionDetail = z.output<typeof recipeVersionDetailSchema>;

/** `GET /v1/repos/{repo}/recipe/versions/{v}`: one version with everything an approval covers. */
export const recipeVersionResponseSchema = z.strictObject({ version: recipeVersionDetailSchema });

// ---- Overrides and disclosure ----

/** `recipe_overrides`: the versioned override body. Its version is the recipe ETag. */
export const recipeOverridesStateSchema = z
  .strictObject({
    version: resourceVersionSchema,
    body: recipeOverrideSchema,
    updated_at: utcDateTimeSchema.nullable(),
    updated_by: actorRefSchema.nullable(),
  })
  .refine((state) => (state.updated_at === null) === (state.updated_by === null), {
    ...whenValid,
    error: "updated_at and updated_by are recorded together",
  });

/**
 * What an admin authorizes when enabling autopilot: "sees CI deviations/egress/environment scope";
 * `when_ready` records "authorization for the initial recipe and disclosed policy scope".
 * `scope_hash` is the value `PUT /v1/repos/{repo}/mode` binds the authorization to.
 */
export const activationDisclosureSchema = z.strictObject({
  scope_hash: sha256HexSchema,
  /**
   * The scope itself (`activationScopeSchema`, stored as `repos.activation_scope` once consented).
   * `recipe_version_id` is the version the disclosure describes; null before the first recipe
   * exists (`when_ready`).
   */
  ...activationScopeShape,
});

/** `GET /v1/repos/{repo}/recipe`: "Active recipe, calibration and deviations; version ETag". */
export const recipeStateResponseSchema = z
  .strictObject({
    repo_id: repoIdSchema,
    active: recipeVersionDetailSchema.nullable(),
    latest: recipeVersionSummarySchema.nullable(),
    overrides: recipeOverridesStateSchema,
    stale: z.boolean(),
    disclosure: activationDisclosureSchema,
  })
  .superRefine((state, ctx) => {
    if (state.active !== null && !state.active.active) {
      ctx.addIssue({
        code: "custom",
        path: ["active", "active"],
        message: "the active version is flagged active",
      });
    }
    if (
      state.active !== null &&
      (state.latest === null || state.latest.version < state.active.version)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["latest"],
        message: "the latest version is at least the active one",
      });
    }
    const described = state.disclosure.recipe_version_id;
    if (described !== null && described !== state.active?.id && described !== state.latest?.id) {
      ctx.addIssue({
        code: "custom",
        path: ["disclosure", "recipe_version_id"],
        message: "the disclosure describes the active or latest version",
      });
    }
  }, whenValid);

// ---- Diff ----

/** Top-level recipe areas a change falls into (SPEC `Recipe` keys). */
export const RECIPE_CHANGE_AREAS = [
  "runtime",
  "install",
  "envStubs",
  "buildEgress",
  "setup",
  "steps",
  "smoke",
  "sabotageTargets",
] as const;
export const recipeChangeAreaSchema = z.enum(RECIPE_CHANGE_AREAS);

export const RECIPE_CHANGE_KINDS = ["added", "removed", "changed"] as const;
export const recipeChangeKindSchema = z.enum(RECIPE_CHANGE_KINDS);

/** One structural change: a JSON Pointer into the recipe body and its judged effect. */
export const recipeChangeSchema = z.strictObject({
  pointer: jsonPointerSchema,
  area: recipeChangeAreaSchema,
  change: recipeChangeKindSchema,
  effect: recipeStrengthDeltaSchema,
});

/** Authority a version adds or removes: egress, environment, runtime and commands. */
export const recipeAuthorityChangesSchema = z.strictObject({
  egress_added: uniqueArraySchema(egressHostSchema, 50),
  egress_removed: uniqueArraySchema(egressHostSchema, 50),
  env_stubs_added: uniqueArraySchema(envVarNameSchema, 100),
  env_stubs_removed: uniqueArraySchema(envVarNameSchema, 100),
  runtime_changed: z.boolean(),
  commands_changed: z.boolean(),
});

/**
 * A version compared with another. "Runtime/image changes require recalibration; broader authority
 * or any weakening requires a human session and approval of the new version"; "Arbitrary
 * shell-command changes are not automatically comparable as 'stronger'".
 */
export const recipeComparisonSchema = z
  .strictObject({
    base_version: z.int().positive(),
    strength_delta: recipeStrengthDeltaSchema,
    changes: z.array(recipeChangeSchema).max(500),
    authority: recipeAuthorityChangesSchema,
    requires_recalibration: z.boolean(),
    requires_human_approval: z.boolean(),
  })
  .superRefine((comparison, ctx) => {
    if (comparison.changes.length === 0 && comparison.strength_delta !== "equivalent") {
      ctx.addIssue({
        code: "custom",
        path: ["strength_delta"],
        message: "no changes is equivalent",
      });
    }
    const weakening = comparison.changes.some((change) => change.effect === "weaker");
    if (
      weakening &&
      (comparison.strength_delta === "stronger" || comparison.strength_delta === "equivalent")
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["strength_delta"],
        message: "a weakening change makes the version weaker or incomparable",
      });
    }
    const authority = comparison.authority;
    const broader =
      authority.egress_added.length > 0 ||
      authority.env_stubs_added.length > 0 ||
      authority.runtime_changed;
    const needsApproval =
      broader ||
      comparison.strength_delta === "weaker" ||
      comparison.strength_delta === "incomparable";
    if (needsApproval && !comparison.requires_human_approval) {
      ctx.addIssue({
        code: "custom",
        path: ["requires_human_approval"],
        message: "weakening, incomparable or broader-authority versions need human approval",
      });
    }
    if (authority.runtime_changed && !comparison.requires_recalibration) {
      ctx.addIssue({
        code: "custom",
        path: ["requires_recalibration"],
        message: "runtime or image changes require recalibration",
      });
    }
  }, whenValid);

/** The version against its discovered CI: each CI step is preserved or recorded as a deviation. */
export const ciComparisonSchema = z
  .strictObject({
    ci_steps: countSchema,
    preserved: countSchema,
    deviations: discoveryProvenanceReader(ciDeviationSchema),
  })
  .refine(
    (comparison) => comparison.preserved + comparison.deviations.length === comparison.ci_steps,
    {
      ...whenValid,
      error: "every CI step is preserved or a deviation",
      path: ["preserved"],
    },
  );

export const recipeDiffResponseSchema = z
  .strictObject({
    version: recipeVersionSummarySchema,
    /** Null when there is no active version or this version is the active one. */
    from_active: recipeComparisonSchema.nullable(),
    from_ci: ciComparisonSchema,
  })
  .refine(
    (diff) => diff.from_active === null || diff.from_active.base_version !== diff.version.version,
    {
      ...whenValid,
      error: "a version is not compared with itself",
      path: ["from_active"],
    },
  );
export type RecipeDiffResponse = z.output<typeof recipeDiffResponseSchema>;

export const updateRecipeOverridesResponseSchema = z.strictObject({
  overrides: recipeOverridesStateSchema,
  strength_delta: recipeStrengthDeltaSchema,
  requires_approval: z.boolean(),
  /** The rediscovery the change started (overrides are part of the fingerprint). */
  job: jobSchema.nullable(),
});

// ---- Endpoints ----

const READERS = ["human_session", "api_key_read", "api_key_write"] as const;
const WRITERS = ["human_session", "api_key_write"] as const;
const READ_REPO = { level: "read", over: "path_repo" } as const;
/** SPEC "Scoped write": current GitHub push access (docs/decisions/contracts.md). */
const WRITE_REPO = { level: "write", over: "path_repo" } as const;
const ADMIN_REPO = { level: "admin", over: "path_repo" } as const;
const ROW_APPROVE = "Human repo admin; exact version and current authority";
const ROW_ROLLBACK = "Human repo admin; recalibration/approval semantics apply";

const repoParams = z.strictObject({ repo: repoIdSchema });
const versionParams = z.strictObject({ repo: repoIdSchema, v: versionNumberParamSchema });

export const RECIPE_ENDPOINTS = {
  getRecipeDoctor: defineEndpoint({
    operationId: "getRecipeDoctor",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions/{v}/doctor",
    summary: "Read validated doctor proposals and category guidance.",
    source: {
      kind: "owner_directed",
      decision: "recipes.md",
      heading: "Recipe doctor W1 (owner-directed)",
    },
    params: versionParams,
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        attempts: z
          .array(
            z.strictObject({
              attempt: z.int().min(1).max(2),
              status: z.enum(["claimed", "pending", "rejected", "applied"]),
              recipe: recipeSchema.nullable(),
              overrides: z.array(doctorOverrideSchema).max(20),
              applied_version_id: recipeVersionIdSchema.nullable(),
            }),
          )
          .max(2),
        guidance: z.array(z.string().max(512)).max(50),
      }),
    },
    authorization: {
      managementPermission: "getRecipeVersion",
      spec: "Repository visibility always requires current GitHub read access",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: READ_REPO,
    },
  }),
  applyRecipeDoctor: defineEndpoint({
    operationId: "applyRecipeDoctor",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/doctor/{attempt}/approve",
    summary: "Authorize exact doctor configuration and queue recalibration.",
    source: {
      kind: "owner_directed",
      decision: "recipes.md",
      heading: "Recipe doctor W1 (owner-directed)",
    },
    auditActions: ["recipe.overrides_updated"],
    params: z.strictObject({
      ...versionParams.shape,
      attempt: z.coerce.number().int().min(1).max(2),
    }),
    query: null,
    body: emptyBodySchema,
    responses: { 202: z.strictObject({ recipe_version_id: recipeVersionIdSchema }) },
    authorization: {
      spec: ROW_APPROVE,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: ADMIN_REPO,
    },
    problems: ["conflict", "repo_not_enabled"],
  }),
  getRecipe: defineEndpoint({
    operationId: "getRecipe",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe",
    summary: "Read the active recipe, its calibration, deviations and overrides.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe" },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: recipeStateResponseSchema },
    authorization: {
      spec: "Active recipe, calibration and deviations; version ETag",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: READ_REPO,
    },
    etag: "/overrides/version",
  }),
  listRecipeVersions: defineEndpoint({
    operationId: "listRecipeVersions",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions",
    summary: "List recipe versions, newest first.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe/versions" },
    params: repoParams,
    query: z.strictObject(paginationQueryShape),
    body: null,
    responses: { 200: pageSchema(recipeVersionSummarySchema) },
    authorization: {
      spec: "Scoped read",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: READ_REPO,
    },
    paginated: true,
  }),
  getRecipeVersion: defineEndpoint({
    operationId: "getRecipeVersion",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions/{v}",
    summary:
      "Read one recipe version with its commands, runtime, CI steps, deviations and calibration record.",
    // The versions list and the diff carry summaries and deltas only; approving "a specific
    // calibrated version" means seeing that version itself, not only the active one.
    source: { kind: "spec_implied", section: "Recipes and verification" },
    params: versionParams,
    query: null,
    body: null,
    responses: { 200: recipeVersionResponseSchema },
    authorization: {
      spec: "a current GitHub repo admin/org owner approves a specific calibrated version, sees CI deviations/egress/environment scope",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: READ_REPO,
    },
  }),
  getRecipeDiff: defineEndpoint({
    operationId: "getRecipeDiff",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions/{v}/diff",
    summary: "Compare a version with the active version and with discovered CI.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe/versions/{v}/diff" },
    params: versionParams,
    query: null,
    body: null,
    responses: { 200: recipeDiffResponseSchema },
    authorization: {
      spec: "Diff from active and from CI; strength/authority changes",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: READ_REPO,
    },
  }),
  updateRecipeOverrides: defineEndpoint({
    operationId: "updateRecipeOverrides",
    area: "recipes",
    method: "PATCH",
    path: "/v1/repos/{repo}/recipe/overrides",
    summary: "Change recipe overrides against the version in If-Match.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe/overrides" },
    auditActions: ["recipe.overrides_updated"],
    params: repoParams,
    query: null,
    body: recipeOverrideSchema,
    responses: { 200: updateRecipeOverridesResponseSchema },
    authorization: {
      spec: "Scoped write; weakening/broader authority requires human repo admin",
      actors: WRITERS,
      tenant: "path_resource",
      repoAuthority: WRITE_REPO,
      escalations: [
        {
          when: "weakens_or_broadens_recipe",
          requires: { humanSession: true, repoAdmin: true },
          unmet: "deny",
        },
      ],
    },
    ifMatch: true,
    etag: "/overrides/version",
    problems: ["repo_not_enabled"],
  }),
  rediscoverRecipe: defineEndpoint({
    operationId: "rediscoverRecipe",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/rediscover",
    summary: "Start recipe rediscovery and calibration as an asynchronous job.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe/rediscover" },
    auditActions: ["recipe.rediscovery_requested"],
    params: repoParams,
    query: null,
    body: z.strictObject({
      /** Explicitly gather fresh calibration evidence even when the fingerprint is unchanged. */
      recalibrate: z.boolean().exactOptional(),
    }),
    responses: {
      202: jobResponseSchema.refine((body) => body.job.kind === "recipe_rediscovery", {
        ...whenValid,
        error: "a rediscovery job",
      }),
    },
    authorization: {
      spec: "Scoped write; async job; rate/cost limits",
      actors: WRITERS,
      tenant: "path_resource",
      repoAuthority: WRITE_REPO,
    },
    idempotency: "accepted",
    // Rate limits answer `rate_limited` with `Retry-After` (four discoveries per rolling hour, three
    // calibrations per rolling day); spend never refuses it: a deterministic rediscovery is never
    // denied for budget, and an unfunded or capped Plus gap-fill is skipped, not refused
    // (docs/decisions/recipes.md "Rediscovery rate and cost limits"). `conflict`: the repository's
    // first discovery has not run yet.
    problems: ["repo_not_enabled", "rate_limited", "conflict"],
  }),
  approveRecipeVersion: defineEndpoint({
    operationId: "approveRecipeVersion",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/approve",
    summary: "Approve exactly this calibrated version; approval alone does not enable merging.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe/versions/{v}/approve" },
    // An approved version that replaces the active one becomes active in the same change.
    auditActions: ["recipe.approved", "recipe.activated"],
    params: versionParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      200: z
        .strictObject({ version: recipeVersionSummarySchema, repo: repoSchema })
        .refine((body) => body.version.approval_status === "approved", {
          ...whenValid,
          error: "the version is approved",
        }),
    },
    authorization: {
      spec: ROW_APPROVE,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: ADMIN_REPO,
    },
    problems: ["recipe_not_approvable", "conflict"],
  }),
  rollbackRecipeVersion: defineEndpoint({
    operationId: "rollbackRecipeVersion",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/rollback",
    summary:
      "Create a new version from an earlier one; it recalibrates and needs approval like any other.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/recipe/versions/{v}/rollback" },
    auditActions: ["recipe.rolled_back"],
    params: versionParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      202: z.strictObject({ version: recipeVersionSummarySchema, job: jobSchema.nullable() }),
    },
    authorization: {
      spec: ROW_ROLLBACK,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: ADMIN_REPO,
    },
    idempotency: "accepted",
    problems: ["conflict"],
  }),
} as const;
