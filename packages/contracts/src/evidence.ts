import { REGRESSION_LIMITS } from "./regression.js";
import { z } from "zod";

import { fixTierSchema } from "./enums/advisories.js";
import {
  mergeMethodSchema,
  verificationResultSchema,
  type VerificationResult,
} from "./enums/fixes.js";
import {
  MERGE_GATES,
  ciEvidenceLevelSchema,
  gateOfReason,
  gateOutcomeSchema,
  mergeBlockReasonSchema,
  mergeGateSchema,
  requiredCheckSourceSchema,
  requiredCheckStateSchema,
} from "./enums/merge.js";
import {
  baseFreshnessSchema,
  CLOSURE_FALLBACK_CAUSES,
  repoModeSchema,
  type ClosureFallbackCause,
} from "./enums/repos.js";
import {
  POLICY_CHECKS,
  dependencyChangeKindSchema,
  fileChangeKindSchema,
  fileRoleSchema,
  policyCheckSchema,
  provenanceFindingKindSchema,
  provenanceResultSchema,
  semverBumpSchema,
} from "./enums/verification.js";
import {
  advisoryIdSchema,
  evidenceIdSchema,
  findingIdSchema,
  fixIdSchema,
  githubAppIdSchema,
  installRootIdSchema,
  projectIdSchema,
  recipeVersionIdSchema,
} from "./ids.js";
import { exactVersionSchema, packageNameSchema, packageVersionSchema } from "./npm.js";
import { tierConfigVersionSchema } from "./policy.js";
import {
  countSchema,
  gitShaSchema,
  hasControlCharacter,
  imageDigestSchema,
  jsonPointerSchema,
  repoFilePathSchema,
  sha256HexSchema,
  whenValid,
} from "./primitives.js";
import {
  completeRegressionProof,
  regressionRequiredChecksSchema,
  stepResultSchema,
} from "./step-result.js";
import { tierSchema } from "./tier.js";
import { DURATIONS, utcDateTimeSchema } from "./time.js";
import { toolchainSchema } from "./toolchain.js";

// JSONB shapes of `fix_evidence` and `fixes.decision` (SPEC "Fixes and evidence", fixWorkflow steps
// 4–8, `decideMerge`). Evidence holds names, versions, paths, codes, counts, hashes and durations
// only: "not raw manifests", "sanitized codes/counts/hashes"; never source, diffs or output.

// ---- dependency_changes ----

/** A dependency path from a direct dependency down to the changed package, by package name. */
export const dependencyPathSchema = z.array(packageNameSchema).min(1).max(64);

/** One changed resolved package instance between the base and patched lockfiles. */
export const dependencyChangeSchema = z
  .strictObject({
    name: packageNameSchema,
    from: packageVersionSchema.nullable(),
    to: packageVersionSchema.nullable(),
    change: dependencyChangeKindSchema,
    /** SemVer distance for upgrades/downgrades; null for additions and removals. */
    bump: semverBumpSchema.nullable(),
    is_direct: z.boolean(),
    /** False if any production path reaches the package (SPEC inventory rule). */
    is_dev: z.boolean(),
    paths: z.array(dependencyPathSchema).max(100),
    /**
     * Additions only, and always recorded for them: every version of `name` the base lockfile
     * already resolves (empty when the package is new to the graph). A new instance of a package
     * the graph already has is a version step from those versions, so policy can see "a nominally
     * patch-only direct update that adds a transitive major".
     */
    base_versions: z.array(packageVersionSchema).max(100).exactOptional(),
  })
  .superRefine((dep, ctx) => {
    const versioned = dep.change === "upgraded" || dep.change === "downgraded";
    const shape =
      (dep.change === "added" && dep.from === null && dep.to !== null) ||
      (dep.change === "removed" && dep.from !== null && dep.to === null) ||
      (versioned && dep.from !== null && dep.to !== null && dep.from !== dep.to);
    if (!shape) {
      ctx.addIssue({
        code: "custom",
        path: ["change"],
        message: "from/to do not match the change kind",
      });
    }
    if (versioned !== (dep.bump !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["bump"],
        message: "exactly upgrades and downgrades carry a SemVer bump",
      });
    }
    const baseVersions = dep.base_versions;
    if ((dep.change === "added") !== (baseVersions !== undefined)) {
      ctx.addIssue({
        code: "custom",
        path: ["base_versions"],
        message: "exactly additions record the base graph's versions of the package",
      });
    } else if (
      baseVersions !== undefined &&
      (new Set(baseVersions).size !== baseVersions.length ||
        baseVersions.some((version) => version === dep.to))
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["base_versions"],
        message: "base versions are unique and exclude the added version",
      });
    }
  }, whenValid);
export type DependencyChange = z.infer<typeof dependencyChangeSchema>;

export const dependencyChangesSchema = z.array(dependencyChangeSchema).max(5000);

/**
 * Non-registry dependencies Kovo left alone as opaque nodes in the verified base (an owner
 * decision): counts by kind, plus the packages reachable only through them. Kovo did
 * not resolve, update or vet any of them, and the fix changed none of them (a fix that does is
 * refused). Counts only: no names, specs or URLs. The fix PR discloses them.
 */
export const opaqueDependenciesSchema = z.strictObject({
  git_count: z.int().nonnegative().max(100_000),
  tarball_count: z.int().nonnegative().max(100_000),
  local_path_count: z.int().nonnegative().max(100_000),
  hidden_package_count: z.int().nonnegative().max(100_000),
});
export type OpaqueDependencies = z.infer<typeof opaqueDependenciesSchema>;

// ---- changed_files ----

/** A changed file: path, change kind and role; for manifests, the JSON pointers that changed. */
export const changedFileSchema = z
  .strictObject({
    path: repoFilePathSchema,
    change: fileChangeKindSchema,
    role: fileRoleSchema,
    manifest_pointers: z.array(jsonPointerSchema).max(500).exactOptional(),
  })
  .refine((file) => file.role === "manifest" || file.manifest_pointers === undefined, {
    ...whenValid,
    error: "only manifests record changed JSON pointers",
    path: ["manifest_pointers"],
  });
export type ChangedFile = z.infer<typeof changedFileSchema>;

export const changedFilesSchema = z
  .array(changedFileSchema)
  .max(1000)
  .refine((files) => new Set(files.map((file) => file.path)).size === files.length, {
    ...whenValid,
    error: "each path appears once",
  });

// ---- restored protected files ----

/**
 * The kinds of protected path (core `@kovo/core/manifest` `PROTECTED_PATH_CATEGORIES`, which is
 * this list): tests, CI configuration, `.kovo*` files, package-manager configuration, runtime
 * declarations, verification configuration, Git metadata and the repository's own policy globs.
 */
export const PROTECTED_FILE_KINDS = [
  "tests",
  "ci",
  "kovo",
  "package_manager_config",
  "runtime_config",
  "verification_config",
  "repository_config",
  "policy",
] as const;
export const protectedFileKindSchema = z.enum(PROTECTED_FILE_KINDS);
export type ProtectedFileKind = z.infer<typeof protectedFileKindSchema>;

/** The fixed reason code of a restore: logs and the PR disclosure name it. */
export const PROTECTED_RESTORE_REASON = "protected_config_restored";

/**
 * The protected files a fix's tooling changed and Kovo restored to their base bytes
 * before the candidate was checked and verified (`fixes.restored_protected`). Kinds and counts only,
 * never paths or contents; one entry per kind, in {@link PROTECTED_FILE_KINDS} order.
 */
export const restoredProtectedFilesSchema = z
  .array(z.strictObject({ kind: protectedFileKindSchema, count: z.int().positive().max(1000) }))
  .min(1)
  .max(PROTECTED_FILE_KINDS.length)
  .refine(
    (entries) =>
      entries.every(
        (entry, index) =>
          index === 0 ||
          PROTECTED_FILE_KINDS.indexOf(entries[index - 1]!.kind) <
            PROTECTED_FILE_KINDS.indexOf(entry.kind),
      ),
    { ...whenValid, error: "one entry per kind, in kind order" },
  );
export type RestoredProtectedFiles = z.infer<typeof restoredProtectedFilesSchema>;

// ---- step_results ----

export const stepResultsSchema = z.array(stepResultSchema).max(100);

export const regressionVerificationComparisonSchema = z.strictObject({
  schema: z.literal("kovo.regression-verification/1"),
  basis: z.literal("no_new_regressions"),
  outcome: z.enum(["no_new_regressions", "regressed", "incomparable"]),
  baseline_base_sha: gitShaSchema,
  baseline_tree_sha: gitShaSchema,
  baseline_verified_at: utcDateTimeSchema,
  baseline_authority: z.strictObject({
    recipe_version_id: recipeVersionIdSchema,
    fingerprint: sha256HexSchema,
    image_digest: imageDigestSchema,
    node_version: exactVersionSchema,
    pm_version: exactVersionSchema,
  }),
  baseline_steps: stepResultsSchema,
  required_checks: regressionRequiredChecksSchema,
});

export type RegressionVerificationComparison = z.output<
  typeof regressionVerificationComparisonSchema
>;

// ---- advisory_recheck ----

/**
 * The trusted re-match after verification: "targeted findings resolved, no newly introduced P0/P1
 * or malicious findings … Existing unrelated findings and new digest findings are disclosed".
 */
export const advisoryRecheckSchema = z.strictObject({
  checked_at: utcDateTimeSchema,
  tier_config_version: tierConfigVersionSchema,
  targeted: z
    .array(
      z.strictObject({
        finding_id: findingIdSchema,
        advisory_id: advisoryIdSchema,
        package: packageNameSchema,
        version: packageVersionSchema,
        cleared: z.boolean(),
      }),
    )
    .min(1)
    .max(500),
  introduced: z
    .array(
      z.strictObject({
        advisory_id: advisoryIdSchema,
        package: packageNameSchema,
        version: packageVersionSchema,
        tier: tierSchema,
        is_malicious: z.boolean(),
      }),
    )
    .max(500),
  existing_unrelated: countSchema,
});
export type AdvisoryRecheck = z.output<typeof advisoryRecheckSchema>;

// ---- policy_checks ----

/** One fixWorkflow step 5 check with its reason codes (empty exactly when it passed). */
export const policyCheckResultSchema = z
  .strictObject({
    check: policyCheckSchema,
    outcome: gateOutcomeSchema,
    reasons: z.array(mergeBlockReasonSchema).max(20),
  })
  .refine((result) => (result.outcome === "pass") === (result.reasons.length === 0), {
    ...whenValid,
    error: "a check records reasons exactly when it does not pass",
    path: ["reasons"],
  });
export type PolicyCheckResult = z.infer<typeof policyCheckResultSchema>;

/** A provenance observation for a changed package (SPEC provenance table). */
export const provenanceObservationSchema = z.strictObject({
  package: packageNameSchema,
  version: packageVersionSchema,
  kind: provenanceFindingKindSchema,
  result: provenanceResultSchema,
});
export type ProvenanceObservation = z.infer<typeof provenanceObservationSchema>;

/** At most this many provenance observations are recorded with the evidence. */
export const MAX_PROVENANCE_OBSERVATIONS = 1000;

export const provenanceMissingCauseSchema = provenanceObservationSchema
  .pick({ package: true, version: true })
  .extend({
    cause: z.enum([
      "attestation_lost",
      "metadata_unknown",
      "install_record_missing",
      "install_record_unmatched",
    ]),
  });
export type ProvenanceMissingCause = z.infer<typeof provenanceMissingCauseSchema>;

/** Separate additive storage: previous FixEvidence readers never parse this report. */
export const provenanceReportSchema = z.strictObject({
  evaluated_at: utcDateTimeSchema,
  records_available: z.boolean(),
  observations: z.array(provenanceObservationSchema).max(MAX_PROVENANCE_OBSERVATIONS),
  missing: z
    .array(provenanceObservationSchema.pick({ package: true, version: true }))
    .max(MAX_PROVENANCE_OBSERVATIONS),
  unmatched: z
    .array(provenanceObservationSchema.pick({ package: true, version: true }))
    .max(MAX_PROVENANCE_OBSERVATIONS),
  missing_causes: z.array(provenanceMissingCauseSchema).max(MAX_PROVENANCE_OBSERVATIONS),
  checks: z.tuple([
    policyCheckResultSchema.safeExtend({ check: z.literal("cooldown") }),
    policyCheckResultSchema.safeExtend({ check: z.literal("provenance") }),
  ]),
});
export type ProvenanceReport = z.infer<typeof provenanceReportSchema>;

/** `fix_evidence.policy_checks`: one result per check, in `POLICY_CHECKS` order. */
export const policyChecksSchema = z
  .strictObject({
    checks: z.array(policyCheckResultSchema),
    provenance: z.array(provenanceObservationSchema).max(MAX_PROVENANCE_OBSERVATIONS),
  })
  .refine(
    (value) =>
      value.checks.length === POLICY_CHECKS.length &&
      value.checks.every((result, index) => result.check === POLICY_CHECKS[index]),
    { ...whenValid, error: "records every policy check once, in order", path: ["checks"] },
  );
export type PolicyChecks = z.infer<typeof policyChecksSchema>;

// ---- required_checks ----

/**
 * One required context. `app_id` is the required originating app ("do not accept a same-named
 * check from an arbitrary app"); null means any source. `source` is null while the context has not
 * reported (`missing`).
 */
export const requiredCheckSchema = z
  .strictObject({
    context: z.string().min(1).max(255),
    app_id: githubAppIdSchema.nullable(),
    source: requiredCheckSourceSchema.nullable(),
    state: requiredCheckStateSchema,
  })
  .refine((check) => (check.source === null) === (check.state === "missing"), {
    ...whenValid,
    error: "exactly the missing checks have no source",
    path: ["source"],
  });
export type RequiredCheck = z.infer<typeof requiredCheckSchema>;

/** `fix_evidence.required_checks`: "Empty required-check sets are explicitly recorded." */
export const requiredChecksSchema = z
  .strictObject({
    evaluated_sha: gitShaSchema,
    evaluated_at: utcDateTimeSchema,
    empty: z.boolean(),
    /** Whether the branch requires being up to date before merging (classic `strict`). */
    strict_up_to_date: z.boolean(),
    checks: z.array(requiredCheckSchema).max(200),
  })
  .refine((value) => value.empty === (value.checks.length === 0), {
    ...whenValid,
    error: "empty must match the recorded checks",
    path: ["empty"],
  });
export type RequiredChecks = z.output<typeof requiredChecksSchema>;

// ---- fix_evidence row ----

function providerLabelSchema(max: number) {
  return z
    .string()
    .min(1)
    .max(max)
    .refine((value) => value.trim() === value && !hasControlCharacter(value), {
      ...whenValid,
      error: "must be a trimmed single-line identifier",
    });
}

/** The actual model identifier the relay reported (e.g. `deepseek/deepseek-v4.1-flash`). */
export const modelIdSchema = providerLabelSchema(128);
/** The actual inference provider the relay reported. */
export const inferenceProviderSchema = providerLabelSchema(64);

/** Joins the labels of one served list (`servedModelIdsSchema`, `servedProvidersSchema`). */
export const SERVED_LABEL_SEPARATOR = ", ";
/** At most this many distinct labels are recorded in one served list. */
export const MAX_SERVED_LABELS = 16;

/**
 * Every label of one kind that served an agent's run, in one evidence field: distinct, in code-unit
 * order, joined by `, ` (a single label is its own list). An agent run is many model requests, and
 * the relay may fall back among compliant providers of the same model between them ("Allow fallback
 * only among compliant providers for that same model"), so "the actual inference provider" of the
 * patch is every provider that served it (docs/decisions/ai.md "Every provider that served an agent
 * run is on its evidence"). A label containing a comma cannot be listed unambiguously and is
 * refused.
 */
function servedLabelsSchema(label: z.ZodType<string>, maxLength: number) {
  return z
    .string()
    .min(1)
    .max(MAX_SERVED_LABELS * (maxLength + SERVED_LABEL_SEPARATOR.length))
    .refine(
      (value) => {
        const labels = value.split(SERVED_LABEL_SEPARATOR);
        return (
          labels.length <= MAX_SERVED_LABELS &&
          labels.every((item) => !item.includes(",") && label.safeParse(item).success) &&
          labels.every((item, index) => index === 0 || (labels[index - 1] ?? "") < item)
        );
      },
      {
        ...whenValid,
        error: "must list distinct labels in code-unit order, joined by ', '",
      },
    );
}

/** Every model ID that served the run (`fix_evidence.model_id`). */
export const servedModelIdsSchema = servedLabelsSchema(modelIdSchema, 128);
/** Every inference provider that served the run (`fix_evidence.provider`). */
export const servedProvidersSchema = servedLabelsSchema(inferenceProviderSchema, 64);

/**
 * The served list of `labels` (duplicates dropped, code-unit order), or null when one cannot be
 * listed: none given, more than `MAX_SERVED_LABELS`, or a label the list's schema refuses.
 */
export function servedLabels(
  labels: Iterable<string>,
  schema: ReturnType<typeof servedLabelsSchema>,
): string | null {
  const distinct = [...new Set(labels)];
  // Checked before joining: a joined comma would read back as two labels.
  if (distinct.some((label) => label.includes(","))) return null;
  const parsed = schema.safeParse(distinct.toSorted().join(SERVED_LABEL_SEPARATOR));
  return parsed.success ? parsed.data : null;
}

/**
 * The published head and tree an evidence record authorizes (`fixes.verified_head_sha`,
 * `verified_tree_sha`): "Successful unexpired evidence for the exact PR head/tree". Null until the
 * evidence is bound to the deterministic commit, which happens before any ref moves.
 */
export const evidenceBindingSchema = z.strictObject({
  head_sha: gitShaSchema,
  tree_sha: gitShaSchema,
});
export type EvidenceBinding = z.output<typeof evidenceBindingSchema>;

/** The recipe version a verification ran and the fingerprint it was calibrated for. */
export const evidenceRecipeSchema = z.strictObject({
  version_id: recipeVersionIdSchema,
  fingerprint: sha256HexSchema,
});
export type EvidenceRecipe = z.output<typeof evidenceRecipeSchema>;

/** Results that are possible without an approved or calibrated recipe (install-only harness). */
const RECIPELESS_RESULTS: ReadonlySet<VerificationResult> = new Set(["failed", "unverified"]);

/**
 * A `fix_evidence` row. "Every evidence record identifies the resolved runtime, PM, image, model
 * ID, actual inference provider, and relevant config versions"; "Record exact head/base/tree,
 * recipe/config/image versions and sanitized results"; evidence "expires after 30 days".
 * Deterministic fixes have no model or provider.
 *
 * `result` is the verification outcome the `Kovo verification` check reports. SPEC step 4: "Verify
 * in fresh Sandbox B using the approved/calibrated recipe when available. Without sufficient
 * verification, retain findings and produce a review-only PR only under the failed/unverified-PR
 * policy." So:
 * - `recipe` is null when no approved or calibrated recipe was available; Sandbox B then ran only
 *   the install-only harness (never sufficient: `unverified`, or `failed` when the install failed).
 * - the runtime (`image_digest`, `node_version`, `pm_version`) is null only when nothing ran at all
 *   (`unverified`, no steps), for example an unsupported runtime.
 * The trusted checks (dependency changes, changed files, advisory recheck, policy checks) always
 * run in trusted code, so every published fix has evidence.
 *
 * `base_freshness` is the policy mode the evidence was evaluated under: `selective` evidence covers
 * the recorded base only ("show that this is not proof of the final merged tree").
 */
export const fixEvidenceSchema = z
  .strictObject({
    id: evidenceIdSchema,
    fix_id: fixIdSchema,
    result: verificationResultSchema,
    /** The base commit the verification ran on. */
    base_sha: gitShaSchema,
    /**
     * The SHA-256 of the staged patch document the verification applied and the trusted checks
     * evaluated: only a head built from exactly that patch may be bound to this evidence ("Exact
     * head/tree binding" against a "Stale or substituted commit"). Null for evidence of a commit
     * that already existed (a re-verified published head, bound at record).
     */
    patch_sha256: sha256HexSchema.nullable(),
    binding: evidenceBindingSchema.nullable(),
    recipe: evidenceRecipeSchema.nullable(),
    /** The repository policy version the trusted checks evaluated. */
    policy_version: z.int().positive(),
    base_freshness: baseFreshnessSchema,
    dependency_changes: dependencyChangesSchema,
    /**
     * Whether the verified lockfile diff held more changes than `dependency_changes` records
     * (core `toDependencyChanges`). Absent on older evidence: readers treat it as unknown and
     * fall back to the length rule (core `evidenceBoundRefusal`), never as false.
     */
    dependency_changes_truncated: z.boolean().exactOptional(),
    /**
     * Non-registry dependencies left alone as opaque nodes. Absent when the base
     * has none, or on evidence recorded before the field.
     */
    opaque_dependencies: opaqueDependenciesSchema.exactOptional(),
    changed_files: changedFilesSchema,
    step_results: stepResultsSchema,
    comparison: regressionVerificationComparisonSchema.exactOptional(),
    /** The verified tree's toolchain fingerprint (diagnostics only); absent on older evidence. */
    toolchain: toolchainSchema.exactOptional(),
    advisory_recheck: advisoryRecheckSchema,
    policy_checks: policyChecksSchema,
    required_checks: requiredChecksSchema.nullable(),
    image_digest: imageDigestSchema.nullable(),
    node_version: exactVersionSchema.nullable(),
    pm_version: exactVersionSchema.nullable(),
    /** Every model ID that served an agent-produced patch's run (`servedModelIdsSchema`). */
    model_id: servedModelIdsSchema.nullable(),
    /** Every inference provider that served it (`servedProvidersSchema`). */
    provider: servedProvidersSchema.nullable(),
    verified_at: utcDateTimeSchema,
    expires_at: utcDateTimeSchema,
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
    if ((evidence.model_id === null) !== (evidence.provider === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["provider"],
        message: "model and provider are recorded together",
      });
    }
    const runtime = [evidence.image_digest, evidence.node_version, evidence.pm_version];
    const ran = runtime.every((value) => value !== null);
    if (!ran && runtime.some((value) => value !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["image_digest"],
        message: "the image, runtime and package manager versions are recorded together",
      });
    }
    if (!ran && (evidence.result !== "unverified" || evidence.step_results.length > 0)) {
      ctx.addIssue({
        code: "custom",
        path: ["image_digest"],
        message: "only unverified evidence that ran no step has no runtime",
      });
    }
    if (evidence.recipe === null && !RECIPELESS_RESULTS.has(evidence.result)) {
      ctx.addIssue({
        code: "custom",
        path: ["recipe"],
        message: "without an approved or calibrated recipe, verification is failed or unverified",
      });
    }
    const blocking = evidence.step_results.some(
      (step) => step.status !== "passed" && step.status !== "skipped",
    );
    const comparison = evidence.comparison;
    if (
      comparison !== undefined &&
      [...comparison.baseline_steps, ...evidence.step_results].reduce(
        (sum, s) => sum + (s.regression?.issues.length ?? 0),
        0,
      ) > REGRESSION_LIMITS.maxIssuesPerPair
    )
      ctx.addIssue({
        code: "custom",
        path: ["comparison"],
        message: "paired observation budget exceeded",
      });
    const authorityMatches =
      comparison !== undefined &&
      comparison.baseline_authority.recipe_version_id === evidence.recipe?.version_id &&
      comparison.baseline_authority.fingerprint === evidence.recipe?.fingerprint &&
      comparison.baseline_authority.image_digest === evidence.image_digest &&
      comparison.baseline_authority.node_version === evidence.node_version &&
      comparison.baseline_authority.pm_version === evidence.pm_version;
    const validComparison =
      authorityMatches &&
      comparison !== undefined &&
      comparison.baseline_base_sha === evidence.base_sha &&
      comparison.baseline_verified_at.getTime() <= evidence.verified_at.getTime() &&
      completeRegressionProof(comparison.baseline_steps, comparison.required_checks) &&
      completeRegressionProof(evidence.step_results, comparison.required_checks);
    if (comparison !== undefined && comparison.outcome === "no_new_regressions" && !validComparison)
      ctx.addIssue({
        code: "custom",
        path: ["comparison"],
        message: "no new regressions requires exact-base complete paired proof",
      });
    if (
      evidence.result === "passed" &&
      (evidence.step_results.length === 0 ||
        (comparison === undefined
          ? blocking
          : !validComparison || comparison.outcome !== "no_new_regressions"))
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["result"],
        message: "passed verification ran steps and every step passed or was skipped",
      });
    }
  }, whenValid);
export type FixEvidence = z.output<typeof fixEvidenceSchema>;

/**
 * How a per-project fix verification found its
 * projects. `affected`: the change's dependency closure, `affected` of the root's `total`
 * projects. `fallback_all`: the graph was unknown or ambiguous, so every protected project of the
 * root ran (`closure_fallback_all`, disclosed), with its closed cause. Counts and codes only.
 */
//
// One flat object with a refinement, not a discriminated union: the compatibility diff proves a
// writer `oneOf` only against an identical reader `oneOf`, and a tolerant reader's branches differ
// from the strict writer's (open versus closed objects), so a union could never be proven.
export const projectClosureSchema = z
  .strictObject({
    mode: z.enum(["affected", "fallback_all"]),
    affected: z.number().int().min(0).max(100).optional(),
    total: z.number().int().min(0).max(100).optional(),
    cause: z.enum(CLOSURE_FALLBACK_CAUSES).optional(),
  })
  .superRefine((closure, ctx) => {
    const counts = closure.affected !== undefined && closure.total !== undefined;
    if (
      closure.mode === "affected"
        ? !counts || closure.cause !== undefined
        : closure.cause === undefined ||
          closure.affected !== undefined ||
          closure.total !== undefined
    )
      ctx.addIssue({
        code: "custom",
        path: ["mode"],
        message: "affected carries counts only; fallback_all carries its cause only",
      });
  });
/** The closure a writer records (exactly one of the two shapes `projectClosureSchema` admits). */
export type ProjectClosure =
  | { readonly mode: "affected"; readonly affected: number; readonly total: number }
  | { readonly mode: "fallback_all"; readonly cause: ClosureFallbackCause };

/** Reader-first M7 proof. Kept outside fixEvidenceSchema for old-release rollback safety. */
export const projectScopeEvidenceSchema = z
  .strictObject({
    schema: z.literal("kovo.project-scope/1"),
    evidence_id: evidenceIdSchema,
    fix_id: fixIdSchema,
    install_root_id: installRootIdSchema,
    base_sha: gitShaSchema,
    patch_sha256: sha256HexSchema.nullable(),
    base_graph_sha256: sha256HexSchema,
    candidate_graph_sha256: sha256HexSchema,
    /** Hash of the complete protection snapshot, including selection generations. */
    protection_sha256: sha256HexSchema,
    projects: z
      .array(
        z.strictObject({
          project_id: projectIdSchema,
          /** Each protected project's own recipe and sanitized execution results. */
          evidence: fixEvidenceSchema,
        }),
      )
      .min(1)
      .max(100),
    /** Disclosure only: these projects never acquire verification evidence. */
    unprotected_moved_paths: z.array(repoFilePathSchema).max(100),
    /** The R8 disclosure; absent on proofs written before it. */
    closure: projectClosureSchema.optional(),
  })
  .superRefine((proof, ctx) => {
    if (new Set(proof.projects.map((p) => p.project_id)).size !== proof.projects.length)
      ctx.addIssue({
        code: "custom",
        path: ["projects"],
        message: "protected project identities are unique",
      });
    if (new Set(proof.unprotected_moved_paths).size !== proof.unprotected_moved_paths.length)
      ctx.addIssue({
        code: "custom",
        path: ["unprotected_moved_paths"],
        message: "disclosure paths are unique",
      });
    for (const [index, project] of proof.projects.entries()) {
      const evidence = project.evidence;
      if (
        evidence.id !== proof.evidence_id ||
        evidence.fix_id !== proof.fix_id ||
        evidence.base_sha !== proof.base_sha ||
        evidence.patch_sha256 !== proof.patch_sha256 ||
        evidence.recipe === null
      )
        ctx.addIssue({
          code: "custom",
          path: ["projects", index],
          message: "project proof requires its own recipe and the exact candidate identity",
        });
    }
  }, whenValid);
export type ProjectScopeEvidence = z.output<typeof projectScopeEvidenceSchema>;

// ---- decideMerge record (`fixes.decision`) ----

/** One gate's result: reasons belong to that gate and are present exactly when it did not pass. */
export const gateResultSchema = z
  .strictObject({
    gate: mergeGateSchema,
    outcome: gateOutcomeSchema,
    reasons: z.array(mergeBlockReasonSchema).max(20),
  })
  .superRefine((result, ctx) => {
    if ((result.outcome === "pass") !== (result.reasons.length === 0)) {
      ctx.addIssue({
        code: "custom",
        path: ["reasons"],
        message: "a gate records reasons exactly when it does not pass",
      });
    }
    for (const reason of result.reasons.filter((r) => gateOfReason(r) !== result.gate)) {
      ctx.addIssue({
        code: "custom",
        path: ["reasons"],
        message: `${reason} belongs to gate ${gateOfReason(reason)}`,
      });
    }
    if (new Set(result.reasons).size !== result.reasons.length) {
      ctx.addIssue({ code: "custom", path: ["reasons"], message: "reasons are unique" });
    }
  }, whenValid);
export type GateResult = z.infer<typeof gateResultSchema>;

/**
 * "`decideMerge` records a rule-by-rule decision": all seven gates in order, the exact bindings it
 * evaluated, and the merge result when autopilot merged. "Merge request pins `sha =
 * verified_head_sha`; record resulting `merged_sha`, policy/recipe versions and decision
 * timestamp." Unknown head/base/tree are null and can never produce `would_merge`.
 */
export const mergeDecisionSchema = z
  .strictObject({
    decided_at: utcDateTimeSchema,
    effective_mode: repoModeSchema,
    tier: fixTierSchema,
    would_merge: z.boolean(),
    gates: z.array(gateResultSchema),
    head_sha: gitShaSchema.nullable(),
    base_sha: gitShaSchema.nullable(),
    tree_sha: gitShaSchema.nullable(),
    recipe_version_id: recipeVersionIdSchema.nullable(),
    policy_version: z.int().positive().nullable(),
    authorization_version: z.int().positive().nullable(),
    tier_config_version: tierConfigVersionSchema,
    /**
     * The fix's evidence level at this decision (including `build_verified`), shown on the
     * dashboard as on the PR. Absent on decisions recorded before it existed.
     */
    evidence_level: ciEvidenceLevelSchema.exactOptional(),
    merge: z
      .strictObject({
        merged_sha: gitShaSchema,
        method: mergeMethodSchema,
        merged_at: utcDateTimeSchema,
      })
      .nullable(),
  })
  .superRefine((decision, ctx) => {
    const inOrder =
      decision.gates.length === MERGE_GATES.length &&
      decision.gates.every((result, index) => result.gate === MERGE_GATES[index]);
    if (!inOrder) {
      ctx.addIssue({
        code: "custom",
        path: ["gates"],
        message: "records all seven gates in order",
      });
    }
    const allPass = decision.gates.every((result) => result.outcome === "pass");
    if (decision.would_merge !== allPass) {
      ctx.addIssue({
        code: "custom",
        path: ["would_merge"],
        message: "would_merge holds exactly when every gate passes",
      });
    }
    const bound =
      decision.head_sha !== null &&
      decision.base_sha !== null &&
      decision.tree_sha !== null &&
      decision.recipe_version_id !== null &&
      decision.policy_version !== null &&
      decision.authorization_version !== null;
    if (decision.would_merge && !bound) {
      ctx.addIssue({
        code: "custom",
        path: ["would_merge"],
        message: "a passing decision binds head, base, tree, recipe, policy and authorization",
      });
    }
    if (
      decision.merge !== null &&
      !(decision.would_merge && decision.effective_mode === "autopilot")
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["merge"],
        message: "only a passing autopilot decision merges",
      });
    }
  }, whenValid);
export type MergeDecision = z.output<typeof mergeDecisionSchema>;

/**
 * Shadow verdict: "evaluate eligibility as if the mode were autopilot, but retain real plan,
 * permissions, pause and verification gates. Record `would_merge`, reasons and a PR label."
 * Which gate reasons shadow waives is merge policy: `@kovo/core/policy` `shadowResult` derives the
 * verdict from a decision (its only definition).
 */
export const shadowVerdictSchema = z
  .strictObject({
    would_merge: z.boolean(),
    reasons: z.array(mergeBlockReasonSchema).max(140),
    decided_at: utcDateTimeSchema,
    head_sha: gitShaSchema.nullable(),
  })
  .refine((verdict) => verdict.would_merge === (verdict.reasons.length === 0), {
    ...whenValid,
    error: "would_merge holds exactly when there are no blocking reasons",
    path: ["reasons"],
  });
export type ShadowVerdict = z.output<typeof shadowVerdictSchema>;
