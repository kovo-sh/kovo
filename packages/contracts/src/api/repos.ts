import { z } from "zod";
import { writerPinned } from "../compatibility.js";

import { branchProtectionAssessmentSchema } from "../branch-protection.js";
import { fixHoldReasonSchema } from "../enums/fixes.js";
import {
  approvalStatusSchema,
  calibrationStatusSchema,
  packageManagerSchema,
  storedPackageManagerSchema,
} from "../enums/recipes.js";
import {
  MODE_REASONS,
  MODE_REASON_CATEGORY,
  MODE_REASON_NEXT_ACTIONS,
  PAUSE_SCOPES,
  activationPolicySchema,
  desiredModeSchema,
  modeReasonCategorySchema,
  modeReasonSchema,
  pauseReasonCodeSchema,
  pauseScopeSchema,
  repoModeSchema,
  unsupportedRepoReasonSchema,
  type ModeReason,
} from "../enums/repos.js";
import { NEXT_ACTION_WRITE_COUNT, nextActionSchema } from "../enums/waits.js";
import {
  apiKeyIdSchema,
  fixIdSchema,
  githubRepoIdSchema,
  installationIdSchema,
  installRootIdSchema,
  projectIdSchema,
  installRootObservationIdSchema,
  recipeVersionIdSchema,
  repoIdSchema,
  userIdSchema,
} from "../ids.js";
import { nonNegativeMicroUsdWireSchema } from "../money.js";
import { packageNameSchema } from "../npm.js";
import { workspacePathSchema } from "../workspace-inventory.js";
import { LIMITS } from "../limits.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { countSchema, gitShaSchema, sha256HexSchema, whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { repoFullNameSchema } from "../github.js";
import { branchNameSchema, emptyBodySchema, tierCountsSchema, userRefSchema } from "./common.js";
import { defineEndpoint, type RepoAuthorityLevel } from "./endpoint.js";

// `/v1/repos`: protected-repository health, explicit protection selection and repo modes (SPEC
// "Repo modes", "Repository billing", "Approval and activation", Public API rows 5–7).

// ---- Shapes ----

/**
 * Protection selection: "Installation access alone does not enable protection or incur charges."
 * `pending_capacity` is the two-actor flow: "a repository admin authorizes protection, and a
 * billing-authorized actor approves additional capacity". A pending request is filled by a later
 * capacity confirmation, in request order (docs/decisions/contracts.md "Billing shapes"), and
 * `DELETE …/protection` withdraws it.
 */
export const PROTECTION_STATES = ["enabled", "pending_capacity", "disabled"] as const;
export const protectionStateSchema = z.enum(PROTECTION_STATES);
export type ProtectionState = z.infer<typeof protectionStateSchema>;

const repositoryProtectionSchema = z
  .strictObject({
    state: protectionStateSchema,
    enabled_at: utcDateTimeSchema.nullable(),
    disabled_at: utcDateTimeSchema.nullable(),
    capacity_requested_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((protection, ctx) => {
    if (protection.state === "enabled" && protection.enabled_at === null) {
      ctx.addIssue({
        code: "custom",
        path: ["enabled_at"],
        message: "enabled protection has enabled_at",
      });
    }
    if ((protection.state === "pending_capacity") !== (protection.capacity_requested_at !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["capacity_requested_at"],
        message: "exactly pending protection records when capacity was requested",
      });
    }
  }, whenValid);

export const repoProtectionSchema = writerPinned(
  repositoryProtectionSchema.safeExtend({
    projects: z
      .strictObject({
        discovered: countSchema,
        protected: countSchema,
        pending_capacity: countSchema,
      })
      .exactOptional(),
  }),
  repositoryProtectionSchema,
);

/**
 * One reason the effective mode is gated, with its dashboard category and the next actions that
 * clear it, most relevant first ("Show next required action without exposing infrastructure
 * implementation details"). Both follow from the reason (`MODE_REASON_CATEGORY`,
 * `MODE_REASON_NEXT_ACTIONS`); {@link modeReasonEntryOf} builds an entry.
 */
export const modeReasonEntrySchema = z
  .strictObject({
    reason: modeReasonSchema,
    category: modeReasonCategorySchema,
    next_actions: z.array(nextActionSchema).max(NEXT_ACTION_WRITE_COUNT),
  })
  .superRefine((entry, ctx) => {
    if (MODE_REASON_CATEGORY[entry.reason] !== entry.category) {
      ctx.addIssue({
        code: "custom",
        path: ["category"],
        message: "category must match the reason",
      });
    }
    const expected: readonly string[] = MODE_REASON_NEXT_ACTIONS[entry.reason];
    const same =
      entry.next_actions.length === expected.length &&
      entry.next_actions.every((action, index) => action === expected[index]);
    if (!same) {
      ctx.addIssue({
        code: "custom",
        path: ["next_actions"],
        message: "next actions must be the reason's own, in order",
      });
    }
  }, whenValid);
export type ModeReasonEntry = z.infer<typeof modeReasonEntrySchema>;

/** The `/v1` entry for a mode reason: its category and next actions from the contracts tables. */
export function modeReasonEntryOf(reason: ModeReason): ModeReasonEntry {
  return {
    reason,
    category: MODE_REASON_CATEGORY[reason],
    next_actions: [...MODE_REASON_NEXT_ACTIONS[reason]],
  };
}

/**
 * Activation intent: `activation_policy`, "authorization actor/time" and the consent scope the
 * authorization is bound to (`activation_scope_hash`). Consent fields are all set or all null.
 */
export const repoActivationSchema = z
  .strictObject({
    policy: activationPolicySchema,
    consent_id: z.uuid().exactOptional(),
    authorized_by: userRefSchema.nullable(),
    authorized_by_key_id: apiKeyIdSchema.exactOptional(),
    state: z.enum(["pending", "fulfilled"]).exactOptional(),
    authorized_at: utcDateTimeSchema.nullable(),
    scope_hash: sha256HexSchema.nullable(),
    /**
     * The consent version (`repos.activation_version`): it rises with every consent granted or
     * cleared, and a merge decision records the version it relied on (`authorization_version`).
     */
    version: z.int().nonnegative(),
  })
  .refine(
    (activation) => {
      if (activation.authorized_by_key_id !== undefined) {
        return (
          activation.authorized_by === null &&
          activation.authorized_at !== null &&
          activation.scope_hash !== null &&
          activation.state !== undefined
        );
      }
      if (activation.state !== undefined) return false;
      const set = [
        activation.authorized_by,
        activation.authorized_at,
        activation.scope_hash,
      ].filter((value) => value !== null).length;
      return set === 0 || set === 3;
    },
    { ...whenValid, error: "authorization actor, time and scope are recorded together" },
  );

/** One pause blocking a repository's merges: its scope, when it was set and the closed reason. */
export const repoPauseSchema = z.strictObject({
  scope: pauseScopeSchema,
  paused_at: utcDateTimeSchema,
  reason: pauseReasonCodeSchema,
});
export type RepoPause = z.infer<typeof repoPauseSchema>;

/**
 * A post-revert package hold: "A post-revert hold blocks re-enqueue until expiry or a newly
 * actionable advisory, with a visible reason." `fix_id` is the reverted fix.
 */
export const repoHoldSchema = z.strictObject({
  package: packageNameSchema,
  held_until: utcDateTimeSchema,
  reason: fixHoldReasonSchema,
  fix_id: fixIdSchema,
});
export type RepoHold = z.infer<typeof repoHoldSchema>;

/** At most this many held packages are listed on a repository (the oldest-expiring first). */
export const MAX_LISTED_HOLDS = 100;

/** A recipe version as other resources reference it. */
export const recipeVersionRefSchema = z.strictObject({
  id: recipeVersionIdSchema,
  version: z.int().positive(),
  calibration_status: calibrationStatusSchema,
  approval_status: approvalStatusSchema,
});
export type RecipeVersionRef = z.infer<typeof recipeVersionRefSchema>;

/** "recipe state": the active version, the newest version and whether the fingerprint is stale. */
export const repoRecipeStateSchema = z
  .strictObject({
    active: recipeVersionRefSchema.nullable(),
    latest: recipeVersionRefSchema.nullable(),
    /** "A recipe with a stale fingerprint cannot authorize merges while rediscovery waits". */
    stale: z.boolean(),
  })
  .refine(
    (recipe) =>
      recipe.active === null ||
      (recipe.latest !== null && recipe.latest.version >= recipe.active.version),
    { ...whenValid, error: "the latest version is at least the active one", path: ["latest"] },
  );

/**
 * "shadow stats": would-merge verdicts in the SPEC window and progress toward the activation
 * suggestion ("After five unchanged-head human merges of would-merge PRs with no closes/reverts in
 * 30 days, suggest activation by email").
 */
export const shadowStatsSchema = z
  .strictObject({
    window_days: z.literal(30),
    would_merge: countSchema,
    would_not_merge: countSchema,
    qualifying_merges: countSchema,
    closes_or_reverts: countSchema,
    suggestion_eligible: z.boolean(),
    suggested_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((shadow, ctx) => {
    if (shadow.qualifying_merges > shadow.would_merge) {
      ctx.addIssue({
        code: "custom",
        path: ["qualifying_merges"],
        message: "qualifying merges are would-merge PRs",
      });
    }
    const eligible =
      shadow.qualifying_merges >= LIMITS.shadow.suggestionMergeCount &&
      shadow.closes_or_reverts === 0;
    if (shadow.suggestion_eligible !== eligible) {
      ctx.addIssue({
        code: "custom",
        path: ["suggestion_eligible"],
        message: "eligible exactly at five qualifying merges with no closes or reverts",
      });
    }
  }, whenValid);

/**
 * The caller's own GitHub authority over a repository, as `/v1` reports it on every repository it
 * returns (SPEC Web UI: "Explicitly show plan restrictions, permission restrictions, weak
 * verification and missing branch protections as distinct reasons"): `read` (which includes read
 * access held as a collaborator), `write` (push access, SPEC's "scoped write") or `admin`
 * ("verified GitHub repository admin or organization owner"), the `REPO_AUTHORITY_LEVELS` a reader
 * can hold. For an API key it is the effective level: "the
 * intersection of key scope, explicitly delegated repo scope, and the creator's current GitHub
 * authority" (a `read` key is `read`). It comes from the check that authorized the read, which may
 * be a cached positive check at most ten minutes old ("Cache positive GitHub permission checks for
 * at most 10 minutes for ordinary reads"), so it describes what a request may try; every mutation
 * still revalidates it at execution time.
 */
export const VIEWER_PERMISSIONS = [
  "read",
  "write",
  "admin",
] as const satisfies readonly RepoAuthorityLevel[];
export const viewerPermissionSchema = z.enum(VIEWER_PERMISSIONS);
export type ViewerPermission = z.infer<typeof viewerPermissionSchema>;

/** Parallel fix PRs in PR-only mode: "defaults to three (configurable 1–10)". */
export const prParallelCapSchema = z
  .int()
  .min(LIMITS.slots.prParallelCapMin)
  .max(LIMITS.slots.prParallelCapMax);

/**
 * A repository as `GET /v1/repos` lists it: "mode, reason, recipe state and shadow stats". `mode` is
 * effective, `desired_mode` the intent; `mode_reasons` lists every current gate with its category
 * (plan, permission, weak verification and branch protection stay distinct) and `mode_reason` is
 * the first, as stored in `repos.mode_reason`.
 */
export const repoSchema = z
  .strictObject({
    id: repoIdSchema,
    github_repo_id: githubRepoIdSchema,
    full_name: repoFullNameSchema,
    default_branch: branchNameSchema,
    installation_id: installationIdSchema,
    package_manager: storedPackageManagerSchema.nullable(),
    unsupported_reason: unsupportedRepoReasonSchema.nullable(),
    archived_at: utcDateTimeSchema.nullable(),
    protection: repoProtectionSchema,
    mode: repoModeSchema,
    desired_mode: desiredModeSchema,
    mode_reason: modeReasonSchema.nullable(),
    mode_reason_category: modeReasonCategorySchema.nullable(),
    mode_reasons: z.array(modeReasonEntrySchema).max(MODE_REASONS.length),
    activation: repoActivationSchema,
    /**
     * The latest branch-protection assessment with the concrete blocking rules ("keep PR-only and
     * show the concrete blocking rule"); null before the first assessment.
     */
    branch_protection: branchProtectionAssessmentSchema.nullable(),
    /**
     * Pauses currently blocking merges ("Repo, account, installation, and global pauses"), one per
     * scope, each with when and why it was set.
     */
    pauses: z.array(repoPauseSchema).max(PAUSE_SCOPES.length),
    pr_parallel_cap: prParallelCapSchema.describe(
      "Deprecated legacy numeric cap retained for rollback compatibility; use getRepoFixConcurrency for the effective nullable cap in every mode.",
    ),
    /** Packages whose fixes are held, so reopened findings get no fix until the hold ends. */
    holds: z.array(repoHoldSchema).max(MAX_LISTED_HOLDS),
    recipe: repoRecipeStateSchema,
    shadow: shadowStatsSchema,
    open_findings: tierCountsSchema,
    /** The caller's own GitHub authority over this repository ({@link VIEWER_PERMISSIONS}). */
    viewer_permission: viewerPermissionSchema,
  })
  .superRefine((repo, ctx) => {
    const held = repo.holds.map((hold) => hold.package);
    if (new Set(held).size !== held.length) {
      ctx.addIssue({ code: "custom", path: ["holds"], message: "one hold per package" });
    }
    const scopes = repo.pauses.map((pause) => pause.scope);
    if (new Set(scopes).size !== scopes.length) {
      ctx.addIssue({ code: "custom", path: ["pauses"], message: "one pause per scope" });
    }
    const first = repo.mode_reasons[0];
    if (repo.mode_reason !== (first?.reason ?? null)) {
      ctx.addIssue({
        code: "custom",
        path: ["mode_reason"],
        message: "mode_reason is the first of mode_reasons",
      });
    }
    if (repo.mode_reason_category !== (first?.category ?? null)) {
      ctx.addIssue({
        code: "custom",
        path: ["mode_reason_category"],
        message: "mode_reason_category is the category of mode_reason",
      });
    }
    const reasons = repo.mode_reasons.map((entry) => entry.reason);
    if (new Set(reasons).size !== reasons.length) {
      ctx.addIssue({ code: "custom", path: ["mode_reasons"], message: "mode reasons are unique" });
    }
    if (repo.mode !== repo.desired_mode && repo.mode_reason === null) {
      ctx.addIssue({
        code: "custom",
        path: ["mode_reason"],
        message: "an effective mode that differs from the desired mode records why",
      });
    }
    if (repo.mode === "autopilot") {
      const eligible =
        repo.desired_mode === "autopilot" &&
        reasons.length === 0 &&
        repo.protection.state === "enabled" &&
        repo.unsupported_reason === null &&
        repo.archived_at === null &&
        repo.branch_protection?.status === "supported" &&
        repo.activation.authorized_at !== null;
      if (!eligible) {
        ctx.addIssue({
          code: "custom",
          path: ["mode"],
          message: "effective autopilot needs desired autopilot, enabled protection and no gates",
        });
      }
    }
  }, whenValid);
export type Repo = z.output<typeof repoSchema>;

export const repoResponseSchema = z.strictObject({ repo: repoSchema });

/**
 * `POST /v1/repos/{repo}/protection/check` (#7275): the repository after its GitHub branch
 * protection was read again (`repo.branch_protection.assessed_at` is that read), and when Kovo's
 * scheduled nightly check last visited the repository's installation (null: not yet).
 */
export const protectionCheckResponseSchema = z.strictObject({
  repo: repoSchema,
  scheduled_check_at: utcDateTimeSchema.nullable(),
});
export type ProtectionCheckResponse = z.output<typeof protectionCheckResponseSchema>;

/** How often one repository's protection may be checked again on request (any caller). */
export const PROTECTION_RECHECK_INTERVAL_SECONDS = 30;

/**
 * `PUT /v1/repos/{repo}/mode`: a partial update, where an absent member is left unchanged, so a
 * key can change `pr_parallel_cap` without resending consent. Requesting autopilot (either
 * activation path) binds the authorization to the disclosed consent scope the admin reviewed
 * (`activation_scope_hash`, from the recipe disclosure), and the hash is sent only then: carrying
 * it is an authorization (`authorizes_activation_scope`) that only a human repo admin can give.
 * `when_ready` is a way to reach autopilot, so it needs `desired_mode: autopilot`.
 */
export const setRepoModeBodySchema = z
  .strictObject({
    desired_mode: desiredModeSchema.exactOptional(),
    activation_policy: activationPolicySchema.exactOptional(),
    activation_scope_hash: sha256HexSchema.exactOptional(),
    pr_parallel_cap: prParallelCapSchema.nullable().exactOptional(),
  })
  .superRefine((body, ctx) => {
    if (Object.keys(body).length === 0) {
      ctx.addIssue({ code: "custom", path: [], message: "name at least one setting to change" });
    }
    const autopilot = body.desired_mode === "autopilot";
    if (autopilot !== (body.activation_scope_hash !== undefined)) {
      ctx.addIssue({
        code: "custom",
        path: ["activation_scope_hash"],
        message:
          "requesting autopilot requires the reviewed activation scope hash, which is sent only then",
      });
    }
    if (
      (body.activation_policy === "when_ready" || body.activation_policy === "full_autopilot") &&
      !autopilot
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["activation_policy"],
        message: "when_ready authorizes autopilot and needs desired_mode autopilot",
      });
    }
  }, whenValid);

// ---- Endpoints ----

const READERS = ["human_session", "api_key_read", "api_key_write"] as const;
const ROW_REPOS =
  "Readable repos in the selected account; mode, reason, recipe state and shadow stats";
const ROW_PROTECTION = "Human repo admin; billing-authorized capacity grant if needed";
const ROW_MODE = "Human repo admin for autopilot/activation policy; enforce plan and consent scope";

const repoParams = z.strictObject({ repo: repoIdSchema });

/**
 * Read-only identity inventory. Project selection and protection have their own endpoints (M10b,
 * `projectSelectionSchema` below).
 */
export const repoProjectsResponseSchema = z.strictObject({
  roots: z.array(
    z.strictObject({
      id: installRootIdSchema,
      path: z.string().min(1).max(1024),
      stale: z.boolean(),
      generation: countSchema,
      published_generation: countSchema.nullable(),
    }),
  ),
  projects: z.array(
    z.strictObject({
      id: projectIdSchema,
      install_root_id: installRootIdSchema,
      path: z.string().min(1).max(1024),
      kind: z.enum(["app", "library", "library_bundle"]),
      classification_rule: z.enum([
        "override_v1",
        "apps_path_v1",
        "leaf_framework_v1",
        "library_v1",
        "root_application_v1",
        "single_package_v1",
        "library_bundle_v1",
      ]),
    }),
  ),
  observations: z.array(
    z.strictObject({
      id: installRootObservationIdSchema,
      install_root_id: installRootIdSchema,
      commit_sha: gitShaSchema,
      generation: countSchema,
      kind: z.enum(["single_package", "workspace", "refused"]),
      package_manager: packageManagerSchema.nullable(),
      reason: z.string().max(128).nullable(),
      member_count: countSchema,
      project_count: countSchema,
    }),
  ),
});

/**
 * A repository's project selection (M10b, plans/monorepo-projects.md §6.4, SPEC "Project billing:
 * interpretations"): every live project with its protection state. `selection_due_at` is set while
 * the repository is in its no-charge selection grace: every listed project stays protected at no
 * new charge until then, and `PUT …/projects/selection` ends the grace with the customer's choice.
 * Counts and states only, never charges.
 */
export const projectSelectionSchema = z
  .strictObject({
    repo_id: repoIdSchema,
    /** Whether the account's billing counts projects; before it, protection is per repository. */
    project_billing: z.boolean(),
    selection_due_at: utcDateTimeSchema.nullable(),
    projects: z
      .array(
        z
          .strictObject({
            id: projectIdSchema,
            install_root_id: installRootIdSchema,
            path: z.string().min(1).max(1024),
            kind: z.enum(["app", "library", "library_bundle"]),
            protection: protectionStateSchema,
            capacity_requested_at: utcDateTimeSchema.nullable(),
          })
          .refine(
            (project) =>
              (project.protection === "pending_capacity") ===
              (project.capacity_requested_at !== null),
            {
              ...whenValid,
              error: "exactly a pending project records when capacity was requested",
              path: ["capacity_requested_at"],
            },
          ),
      )
      .max(100),
  })
  .refine((selection) => selection.project_billing || selection.selection_due_at === null, {
    ...whenValid,
    error: "only project billing has a selection grace",
    path: ["selection_due_at"],
  });
export type ProjectSelection = z.infer<typeof projectSelectionSchema>;

/** `PUT …/projects/selection`: the projects to keep protected; every other one is released. */
export const selectProjectsBodySchema = z.strictObject({
  project_ids: z
    .array(projectIdSchema)
    .min(1)
    .max(100)
    .refine((ids) => new Set(ids).size === ids.length, {
      ...whenValid,
      error: "duplicate project",
    }),
});

const projectParams = z.strictObject({ repo: repoIdSchema, project: projectIdSchema });
const ROW_PROJECT_SELECTION =
  "Human session: repo read to view, repo admin to change; billing-authorized capacity grant if needed; reuses paid capacity first ([#2135](https://github.com/kovo-sh/kovo-cloud/issues/2135))";

/** A project change's response: the selection after it, and the project it changed. */
const projectChangeSchema = (state: ProtectionState) =>
  z
    .strictObject({ selection: projectSelectionSchema, project_id: projectIdSchema })
    .refine(
      (body) =>
        body.selection.projects.find((project) => project.id === body.project_id)?.protection ===
        state,
      { ...whenValid, error: `the project's protection is ${state}` },
    );

// ---- Classification overrides (M10b, plans/monorepo-projects.md §5.3) ----

const memberKindSchema = z.enum(["app", "library"]);

/**
 * One customer classification declaration for a member of the repository-root workspace: binding
 * (§5.2 rule 1), keyed by member path (a renamed member loses it), applied by the next discovery.
 * Identifiers only: never manifests, scripts or dependency values.
 */
export const classificationOverrideSchema = z.strictObject({
  member_path: workspacePathSchema,
  kind: memberKindSchema,
  /** The member's kind when it was declared; null when unknown. */
  previous_kind: memberKindSchema.nullable(),
  declared_by: userIdSchema,
  declared_at: utcDateTimeSchema,
});
export type ClassificationOverride = z.infer<typeof classificationOverrideSchema>;

const previewProjectSchema = z.strictObject({
  path: workspacePathSchema,
  kind: z.enum(["app", "library", "library_bundle"]),
  /** The project is protected now (only a removed project can be). */
  protected: z.boolean(),
});

export const CLASSIFICATION_CHARGE_UNAVAILABLE = [
  "billing_authority_required",
  "plan_required",
  "payment_past_due",
] as const;

/**
 * What a declaration would change, charging nothing and recording nothing: the repository's live
 * projects before and after, and the paid slots that protecting the projects it adds would need
 * beyond the free ones. The prorated amount is the billing preview's own price
 * (`/v1/billing/capacity/preview`), shown only to a billing-authorized person; paying for it still
 * takes that preview and its two-actor confirm. Before project billing, protection counts
 * repositories, so a declaration needs no slot.
 */
export const classificationPreviewSchema = z
  .strictObject({
    member_path: workspacePathSchema,
    current_kind: memberKindSchema,
    kind: memberKindSchema,
    project_count: z.int().min(0).max(100),
    resulting_project_count: z.int().min(0).max(101),
    added_projects: z.array(previewProjectSchema).max(101),
    removed_projects: z.array(previewProjectSchema).max(100),
    project_billing: z.boolean(),
    available_slots: z.int().min(0),
    additional_slots: z.int().min(0).max(101),
    prorated_charge_usd: nonNegativeMicroUsdWireSchema.nullable(),
    charge_unavailable: z.enum(CLASSIFICATION_CHARGE_UNAVAILABLE).nullable(),
  })
  .refine(
    (preview) =>
      preview.additional_slots === 0
        ? preview.prorated_charge_usd === null && preview.charge_unavailable === null
        : (preview.prorated_charge_usd === null) !== (preview.charge_unavailable === null),
    {
      ...whenValid,
      error: "a needed slot has either its prorated charge or why it cannot be shown",
      path: ["prorated_charge_usd"],
    },
  )
  .refine((preview) => preview.project_billing || preview.additional_slots === 0, {
    ...whenValid,
    error: "only project billing counts projects",
    path: ["additional_slots"],
  });
export type ClassificationPreview = z.infer<typeof classificationPreviewSchema>;

/** `POST …/projects/classification/preview`: `kind` null previews withdrawing the declaration. */
export const previewClassificationBodySchema = z.strictObject({
  member_path: workspacePathSchema,
  kind: memberKindSchema.nullable(),
});
export const setClassificationBodySchema = z.strictObject({
  member_path: workspacePathSchema,
  kind: memberKindSchema,
});
const ROW_PROJECT_CLASSIFICATION =
  "Human session: repo read to view, repo admin to change; never charges; added paid capacity only through the billing preview and confirm ([#2135](https://github.com/kovo-sh/kovo-cloud/issues/2135))";

const ROW_PROJECT_CLASSIFICATION_POSTS =
  "Human session: repo admin for both; never charges; added paid capacity only through the billing preview and confirm ([#2135](https://github.com/kovo-sh/kovo-cloud/issues/2135))";

export const REPO_ENDPOINTS = {
  getProjectSelection: defineEndpoint({
    operationId: "getProjectSelection",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/projects/selection",
    summary:
      "Read the repository's live projects with their protection state and any no-charge selection grace.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/selection" },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ selection: projectSelectionSchema }) },
    authorization: {
      spec: ROW_PROJECT_SELECTION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  selectProjects: defineEndpoint({
    operationId: "selectProjects",
    area: "repos",
    method: "PUT",
    path: "/v1/repos/{repo}/projects/selection",
    summary:
      "End a repository's no-charge selection grace: keep the listed projects protected and release the rest. Already-paid capacity is reused first; a selection that needs more paid capacity is refused until a billing-authorized purchase is confirmed.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/selection" },
    auditActions: ["project.protection_enabled", "project.protection_disabled"],
    params: repoParams,
    query: null,
    body: selectProjectsBodySchema,
    responses: { 200: z.strictObject({ selection: projectSelectionSchema }) },
    authorization: {
      spec: ROW_PROJECT_SELECTION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["plan_required", "payment_past_due", "installation_suspended", "conflict"],
  }),
  protectProject: defineEndpoint({
    operationId: "protectProject",
    area: "repos",
    method: "PUT",
    path: "/v1/repos/{repo}/projects/{project}/protection",
    summary:
      "Select one project for protection: 200 when an included or already-paid unused slot is free, otherwise 202 pending a billing-authorized capacity confirmation.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/{project}/protection" },
    // 200 into an unprotected repository writes `repo.protection_enabled`, into a protected one
    // `project.protection_enabled`; 202 (pending capacity) writes `repo.protection_requested`.
    auditActions: [
      "repo.protection_enabled",
      "project.protection_enabled",
      "repo.protection_requested",
    ],
    params: projectParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      200: projectChangeSchema("enabled"),
      202: projectChangeSchema("pending_capacity"),
    },
    authorization: {
      // Never charged here: beyond free capacity the selection waits as a pending request (202)
      // until a billing-authorized person previews and confirms paid capacity.
      spec: ROW_PROJECT_SELECTION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: [
      "plan_required",
      "payment_past_due",
      "account_not_linked",
      "installation_suspended",
      "conflict",
    ],
  }),
  unprotectProject: defineEndpoint({
    operationId: "unprotectProject",
    area: "repos",
    method: "DELETE",
    path: "/v1/repos/{repo}/projects/{project}/protection",
    summary:
      "Stop protecting one project or withdraw its pending request; paid capacity drops only at the next renewal, with no mid-cycle refund.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/{project}/protection" },
    // The repository's last protected project ends its protection (`repo.protection_disabled`).
    auditActions: ["project.protection_disabled", "repo.protection_disabled"],
    params: projectParams,
    query: null,
    body: null,
    responses: { 200: projectChangeSchema("disabled") },
    authorization: {
      spec: ROW_PROJECT_SELECTION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["conflict"],
  }),
  getClassificationOverrides: defineEndpoint({
    operationId: "getClassificationOverrides",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/projects/classification",
    summary:
      "Read the customer's binding app or library declarations for members of the repository-root workspace.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/classification" },
    params: repoParams,
    query: null,
    body: null,
    responses: {
      200: z.strictObject({ overrides: z.array(classificationOverrideSchema).max(101) }),
    },
    authorization: {
      spec: ROW_PROJECT_CLASSIFICATION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  previewClassificationOverride: defineEndpoint({
    operationId: "previewClassificationOverride",
    area: "repos",
    method: "POST",
    path: "/v1/repos/{repo}/projects/classification/preview",
    summary:
      "Preview declaring a member an app or a library (or withdrawing the declaration): the project count before and after, and the paid slots and prorated charge protecting added projects would need. Charges and records nothing.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/classification/preview" },
    params: repoParams,
    query: null,
    body: previewClassificationBodySchema,
    responses: { 200: z.strictObject({ preview: classificationPreviewSchema }) },
    authorization: {
      spec: ROW_PROJECT_CLASSIFICATION_POSTS,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["conflict", "upstream_error"],
  }),
  setClassificationOverride: defineEndpoint({
    operationId: "setClassificationOverride",
    area: "repos",
    method: "PUT",
    path: "/v1/repos/{repo}/projects/classification",
    summary:
      "Declare a member of the repository-root workspace an app or a library. The next discovery applies it; it protects nothing and charges nothing.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/classification" },
    auditActions: ["project.classification_overridden"],
    params: repoParams,
    query: null,
    body: setClassificationBodySchema,
    responses: {
      200: z
        .strictObject({
          override: classificationOverrideSchema,
          preview: classificationPreviewSchema,
        })
        .refine(
          (body) =>
            body.override.member_path === body.preview.member_path &&
            body.override.kind === body.preview.kind,
          { ...whenValid, error: "the preview is the declaration's own" },
        ),
    },
    authorization: {
      spec: ROW_PROJECT_CLASSIFICATION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["conflict", "upstream_error"],
  }),
  revokeClassificationOverride: defineEndpoint({
    operationId: "revokeClassificationOverride",
    area: "repos",
    method: "POST",
    path: "/v1/repos/{repo}/projects/classification/revoke",
    summary:
      "Withdraw a member's declaration: the next discovery classifies it by Kovo's rules again. A member without one is unchanged.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects/classification/revoke" },
    auditActions: ["project.classification_override_revoked"],
    params: repoParams,
    query: null,
    body: z.strictObject({ member_path: workspacePathSchema }),
    responses: {
      200: z
        .strictObject({
          member_path: workspacePathSchema,
          revoked: z.boolean(),
          preview: classificationPreviewSchema.nullable(),
        })
        .refine((body) => body.revoked === (body.preview !== null), {
          ...whenValid,
          error: "a withdrawn declaration has its preview",
          path: ["preview"],
        }),
    },
    authorization: {
      spec: ROW_PROJECT_CLASSIFICATION_POSTS,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["conflict", "upstream_error"],
  }),
  listRepoProjects: defineEndpoint({
    operationId: "listRepoProjects",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/projects",
    summary:
      "Read install roots, project identities and the latest complete-discovery observations.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/projects" },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: repoProjectsResponseSchema },
    authorization: {
      managementPermission: "getRepo",
      spec: "Scoped read; install-root and project identities, kinds, classification rules and latest complete-discovery counts; stale roots retain their last published state. Read-only before project activation ([#2135](https://github.com/kovo-sh/kovo-cloud/issues/2135)).",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  getRepoFixConcurrency: defineEndpoint({
    operationId: "getRepoFixConcurrency",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/fix-concurrency",
    summary: "Read the optional fix concurrency cap; null means uncapped in every mode.",
    source: {
      kind: "owner_directed",
      decision: "fix-orchestration.md",
      heading: "Owner-directed no fixed fix-PR slots by default (2026-10-03)",
    },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ cap: prParallelCapSchema.nullable() }) },
    authorization: {
      managementPermission: "getRepo",
      spec: "Repository visibility always requires current GitHub read access.",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  listRepos: defineEndpoint({
    operationId: "listRepos",
    area: "repos",
    method: "GET",
    path: "/v1/repos",
    summary: "List the readable repositories of the selected account.",
    source: { kind: "spec_row", path: "/v1/repos" },
    params: null,
    query: z.strictObject({
      ...paginationQueryShape,
      protection: protectionStateSchema.exactOptional(),
      mode: repoModeSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(repoSchema) },
    authorization: {
      spec: ROW_REPOS,
      actors: READERS,
      tenant: "account_context",
      repoAuthority: { level: "read", over: "listed_items" },
    },
    paginated: true,
  }),
  getRepo: defineEndpoint({
    operationId: "getRepo",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}",
    summary: "Read one repository's health, mode and recipe state.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: repoResponseSchema },
    authorization: {
      spec: "Repository visibility always requires current GitHub read access.",
      actors: READERS,
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  enableProtection: defineEndpoint({
    operationId: "enableProtection",
    area: "repos",
    method: "PUT",
    path: "/v1/repos/{repo}/protection",
    summary:
      "Select a repository for protection: 200 when an included or already-paid unused slot is free, otherwise 202 pending a billing-authorized capacity confirmation, whoever calls.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/protection" },
    // 200 writes `repo.protection_enabled`; 202 (pending capacity) `repo.protection_requested`.
    auditActions: ["repo.protection_enabled", "repo.protection_requested"],
    params: repoParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      200: repoResponseSchema.refine((body) => body.repo.protection.state === "enabled", {
        ...whenValid,
        error: "200 means protection is enabled",
      }),
      202: repoResponseSchema.refine((body) => body.repo.protection.state === "pending_capacity", {
        ...whenValid,
        error: "202 means protection waits for capacity",
      }),
    },
    authorization: {
      spec: ROW_PROTECTION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
      escalations: [
        // Never charged here: paid capacity is added only by a quoted confirmation.
        { when: "needs_paid_capacity", requires: { capacityGrant: true }, unmet: "defer" },
      ],
    },
    problems: [
      // Free's one slot is taken and Free cannot buy capacity ("Free has one active slot").
      "plan_required",
      "payment_past_due",
      "account_not_linked",
      "installation_suspended",
      "unsupported_repository",
      "conflict",
    ],
  }),
  recheckProtection: defineEndpoint({
    operationId: "recheckProtection",
    area: "repos",
    method: "POST",
    path: "/v1/repos/{repo}/protection/check",
    summary:
      "Read a protected repository's GitHub branch protection again now and recompute its mode (Check again); at most once every 30 seconds per repository.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    // Written only when the fresh read changes the effective mode (the recompute's own event).
    auditActions: ["repo.mode_changed"],
    params: repoParams,
    query: null,
    body: emptyBodySchema,
    responses: { 200: protectionCheckResponseSchema },
    authorization: {
      spec: "Check again reads the repository's GitHub branch protection again in a human session, at most once every 30 seconds per repository",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
    problems: ["repo_not_enabled", "upstream_error"],
  }),
  disableProtection: defineEndpoint({
    operationId: "disableProtection",
    area: "repos",
    method: "DELETE",
    path: "/v1/repos/{repo}/protection",
    summary:
      "Stop protecting a repository or withdraw its pending request; paid capacity drops only at the next renewal, with no mid-cycle refund.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/protection" },
    auditActions: ["repo.protection_disabled"],
    params: repoParams,
    query: null,
    body: null,
    responses: {
      200: repoResponseSchema.refine((body) => body.repo.protection.state === "disabled", {
        ...whenValid,
        error: "protection is disabled",
      }),
    },
    authorization: {
      spec: ROW_PROTECTION,
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
  }),
  setRepoMode: defineEndpoint({
    operationId: "setRepoMode",
    area: "repos",
    method: "PUT",
    path: "/v1/repos/{repo}/mode",
    summary:
      "Change the desired mode, activation policy or PR cap; the effective mode still follows plan, recipe and GitHub gates.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/mode" },
    auditActions: ["repo.mode_changed", "repo.activation_authorized"],
    params: repoParams,
    query: null,
    body: setRepoModeBodySchema,
    responses: { 200: repoResponseSchema },
    authorization: {
      spec: ROW_MODE,
      actors: ["human_session", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
      escalations: [
        { when: "enables_autopilot", requires: { humanSession: true }, unmet: "deny" },
        { when: "changes_activation_policy", requires: { humanSession: true }, unmet: "deny" },
        {
          when: "authorizes_activation_scope",
          requires: { humanSession: true, repoAdmin: true },
          unmet: "deny",
        },
        // "keys may only tighten": a key may lower the cap, never raise it.
        { when: "raises_pr_parallel_cap", requires: { humanSession: true }, unmet: "deny" },
      ],
    },
    problems: ["plan_required", "precondition_failed", "repo_not_enabled"],
  }),
} as const;
