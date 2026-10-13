import { REGRESSION_LIMITS } from "./regression.js";
import { z } from "zod";

import {
  SABOTAGE_EXERCISES_APP_CODE,
  SUPPORTED_NODE_MAJORS,
  SUPPORTED_PM_MAJORS,
  calibrationWeakReasonSchema,
  deviationKindSchema,
  deviationReasonSchema,
  packageManagerSchema,
  recipeSourceSchema,
  reportFormatSchema,
  sabotageInapplicableReasonSchema,
  sabotageKindSchema,
  sabotageOutcomeSchema,
  type PackageManager,
} from "./enums/recipes.js";
import type { UnsupportedRepoReason } from "./enums/repos.js";
import { LIMITS } from "./limits.js";
import { exactVersionSchema, semverMajor } from "./npm.js";
import {
  egressHostSchema,
  gitShaSchema,
  envVarNameSchema,
  hasControlCharacter,
  httpStatusSchema,
  imageDigestSchema,
  repoFilePathSchema,
  sha256HexSchema,
  shellCommandSchema,
  urlPathSchema,
  whenValid,
} from "./primitives.js";
import {
  completeRegressionProof,
  regressionRequiredChecksSchema,
  stepNameSchema,
  stepResultSchema,
} from "./step-result.js";
import { utcDateTimeSchema } from "./time.js";
import { toolchainSchema } from "./toolchain.js";

// SPEC "Recipes and verification": the `Recipe`, `Cmd` and `Source` types, field for field, plus
// the JSONB shapes stored beside a recipe version (`ci_steps`, `deviations`, `calibration`) and the
// `recipe_overrides.body`. Recipe fields keep SPEC's camelCase; Kovo-defined records use snake_case.

// ---- Runtime compatibility ----

/**
 * The compatibility-matrix verdict for a resolved runtime: `null` when supported, otherwise the
 * explicit unsupported reason ("never substitute the nearest runtime").
 */
export function runtimeSupport(runtime: {
  readonly node: string;
  readonly packageManager: PackageManager;
  readonly pmVersion: string;
}): Extract<UnsupportedRepoReason, "unsupported_node_version" | "unsupported_pm_version"> | null {
  const nodeMajors: readonly number[] = SUPPORTED_NODE_MAJORS;
  const pmMajors: readonly number[] = SUPPORTED_PM_MAJORS[runtime.packageManager];
  if (!nodeMajors.includes(semverMajor(runtime.node))) return "unsupported_node_version";
  if (!pmMajors.includes(semverMajor(runtime.pmVersion))) return "unsupported_pm_version";
  return null;
}

// ---- SPEC types ----

/** A per-command timeout in seconds; never beyond the 60-minute sandbox lifetime. */
export const timeoutSecSchema = z
  .int()
  .positive()
  .max(LIMITS.sandbox.maxLifetimeMs / 1000);

/** SPEC `Source`. */
export const sourceSchema = recipeSourceSchema;
export type Source = z.infer<typeof sourceSchema>;

/** SPEC `Cmd = { run: string; timeoutSec: number; source: Source }`. */
export const cmdSchema = z.strictObject({
  run: shellCommandSchema,
  timeoutSec: timeoutSecSchema,
  source: sourceSchema,
});
export type Cmd = z.infer<typeof cmdSchema>;

/** A forbidden command-line flag such as `--passWithNoTests` or `-u`. */
export const forbidFlagSchema = z
  .string()
  .max(64)
  .regex(/^--?[A-Za-z0-9][A-Za-z0-9_-]*(?:=[^\s]*)?$/, { error: "must be a command-line flag" });

const stepExpectSchema = z.strictObject({
  baselineTests: z.int().nonnegative().exactOptional(),
  reportFormat: reportFormatSchema.exactOptional(),
  forbidFlags: z.array(forbidFlagSchema).max(32).exactOptional(),
});

/** SPEC `Cmd & { name: string; expect: { … } }`. */
export const recipeStepSchema = z.strictObject({
  ...cmdSchema.shape,
  name: stepNameSchema,
  expect: stepExpectSchema,
});
export type RecipeStep = z.infer<typeof recipeStepSchema>;

/** SPEC `smoke`. */
export const smokeSchema = z.strictObject({
  start: cmdSchema,
  readyPath: urlPathSchema,
  routes: z.array(z.strictObject({ path: urlPathSchema, status: httpStatusSchema })).max(50),
  timeoutSec: timeoutSecSchema,
});
export type Smoke = z.infer<typeof smokeSchema>;

/** SPEC `sabotageTargets[]`. */
export const sabotageTargetSchema = z.strictObject({
  kind: sabotageKindSchema,
  path: repoFilePathSchema,
});
export type SabotageTarget = z.infer<typeof sabotageTargetSchema>;

/**
 * An environment stub value: "Environment stubs must be non-secret fixtures". Bounded, single-line
 * text.
 */
export const envStubValueSchema = z
  .string()
  .max(4096)
  .refine((value) => !hasControlCharacter(value), {
    ...whenValid,
    error: "must not contain control characters",
  });

/** SPEC `runtime`: exact resolved versions within the compatibility matrix. */
export const recipeRuntimeSchema = z
  .strictObject({
    node: exactVersionSchema,
    packageManager: packageManagerSchema,
    pmVersion: exactVersionSchema,
    imageDigest: imageDigestSchema,
  })
  .superRefine((runtime, ctx) => {
    const unsupported = runtimeSupport(runtime);
    if (unsupported === "unsupported_node_version") {
      ctx.addIssue({ code: "custom", path: ["node"], message: "Node major must be 22 or 24" });
    } else if (unsupported === "unsupported_pm_version") {
      ctx.addIssue({
        code: "custom",
        path: ["pmVersion"],
        message: `${runtime.packageManager} major is outside the compatibility matrix`,
      });
    }
  }, whenValid);
export type RecipeRuntime = z.infer<typeof recipeRuntimeSchema>;

function duplicates(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated];
}

/** SPEC `Recipe`. Step names, egress hosts and sabotage targets are unique. */
export const recipeSchema = z
  .strictObject({
    runtime: recipeRuntimeSchema,
    install: cmdSchema,
    envStubs: z.record(
      envVarNameSchema,
      z.strictObject({ value: envStubValueSchema, source: sourceSchema }),
    ),
    buildEgress: z.array(z.strictObject({ host: egressHostSchema, source: sourceSchema })).max(50),
    setup: z.array(cmdSchema).max(20),
    steps: z.array(recipeStepSchema).max(50),
    smoke: smokeSchema.exactOptional(),
    sabotageTargets: z.array(sabotageTargetSchema).max(20),
  })
  .superRefine((recipe, ctx) => {
    for (const name of duplicates(recipe.steps.map((step) => step.name))) {
      ctx.addIssue({ code: "custom", path: ["steps"], message: `duplicate step name ${name}` });
    }
    for (const host of duplicates(recipe.buildEgress.map((entry) => entry.host))) {
      ctx.addIssue({ code: "custom", path: ["buildEgress"], message: `duplicate host ${host}` });
    }
    const targets = recipe.sabotageTargets.map((target) => `${target.kind}:${target.path}`);
    for (const target of duplicates(targets)) {
      ctx.addIssue({
        code: "custom",
        path: ["sabotageTargets"],
        message: `duplicate sabotage target ${target}`,
      });
    }
    if (Object.keys(recipe.envStubs).length > 100) {
      ctx.addIssue({
        code: "custom",
        path: ["envStubs"],
        message: "at most 100 environment stubs",
      });
    }
  }, whenValid);
export type Recipe = z.infer<typeof recipeSchema>;

// ---- Recipe overrides (`recipe_overrides.body`) ----

/** An override command; its source is always `override` once merged into a recipe. */
export const overrideCmdSchema = z.strictObject({
  run: shellCommandSchema,
  timeoutSec: timeoutSecSchema,
});

/**
 * `PATCH /v1/repos/{repo}/recipe/overrides` body, stored in `recipe_overrides.body`. Absent fields
 * leave the discovered recipe unchanged. Keyed maps (`envStubs`, `steps`) add or replace entries,
 * and `null` removes one (removing a step or narrowing checks is a weakening that needs a human repo
 * admin). `setup`, `install` and `sabotageTargets` replace the discovered values; `smoke: null`
 * removes smoke checks.
 */
export const recipeOverrideSchema = z
  .strictObject({
    runtime: z
      .strictObject({
        node: exactVersionSchema.exactOptional(),
        pmVersion: exactVersionSchema.exactOptional(),
      })
      .exactOptional(),
    install: overrideCmdSchema.exactOptional(),
    envStubs: z
      .record(envVarNameSchema, z.strictObject({ value: envStubValueSchema }).nullable())
      .exactOptional(),
    buildEgress: z
      .strictObject({
        add: z.array(egressHostSchema).max(50),
        remove: z.array(egressHostSchema).max(50),
      })
      .exactOptional(),
    setup: z.array(overrideCmdSchema).max(20).exactOptional(),
    steps: z
      .record(
        stepNameSchema,
        z
          .strictObject({
            ...overrideCmdSchema.shape,
            expect: stepExpectSchema,
          })
          .nullable(),
      )
      .exactOptional(),
    smoke: z
      .strictObject({
        start: overrideCmdSchema,
        readyPath: urlPathSchema,
        routes: z.array(z.strictObject({ path: urlPathSchema, status: httpStatusSchema })).max(50),
        timeoutSec: timeoutSecSchema,
      })
      .nullable()
      .exactOptional(),
    sabotageTargets: z.array(sabotageTargetSchema).max(20).exactOptional(),
  })
  .superRefine((override, ctx) => {
    if (override.buildEgress !== undefined) {
      const removed = new Set(override.buildEgress.remove);
      for (const host of override.buildEgress.add.filter((h) => removed.has(h))) {
        ctx.addIssue({
          code: "custom",
          path: ["buildEgress"],
          message: `host ${host} is both added and removed`,
        });
      }
    }
    if (override.envStubs !== undefined && Object.keys(override.envStubs).length > 100) {
      ctx.addIssue({
        code: "custom",
        path: ["envStubs"],
        message: "at most 100 environment stubs",
      });
    }
    if (override.steps !== undefined && Object.keys(override.steps).length > 50) {
      ctx.addIssue({ code: "custom", path: ["steps"], message: "at most 50 step overrides" });
    }
  }, whenValid);
export type RecipeOverride = z.infer<typeof recipeOverrideSchema>;

// ---- Discovery records (`recipe_versions.ci_steps`, `deviations`) ----

/**
 * Where a recipe command came from: "Store normalized commands/config and source references/hashes,
 * not complete CI files or secrets". `locator` addresses the step inside the file (for example
 * `jobs.test.steps[3]` or `scripts.test`); `sha256` hashes the referenced source text.
 */
export const sourceRefSchema = z
  .strictObject({
    source: sourceSchema,
    path: repoFilePathSchema.exactOptional(),
    locator: z.string().min(1).max(256).exactOptional(),
    sha256: sha256HexSchema.exactOptional(),
  })
  .superRefine((ref, ctx) => {
    if (
      (ref.source === "ci" || ref.source === "package.json") &&
      (ref.path === undefined || ref.sha256 === undefined)
    ) {
      ctx.addIssue({
        code: "custom",
        message: "ci and package.json references need a path and a content hash",
      });
    }
  }, whenValid);
export type SourceRef = z.infer<typeof sourceRefSchema>;

/**
 * A stable identifier for a discovered CI step. `_` is allowed because GitHub job IDs and workflow
 * file names commonly contain it (`build_and_test`, `node_ci.yml`).
 */
export const ciStepIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9._:/#[\]_-]{1,200}$/, { error: "must be a CI step identifier" });

/**
 * One normalized, discovered command with its provenance ("Store normalized commands/config and
 * source references/hashes, not complete CI files or secrets"). `run` is the normalized command,
 * or, for a CI step that is not a shell command (an action, a reusable workflow, a workflow file
 * that could not be parsed), its normalized descriptor such as `uses: actions/setup-node@v4`.
 * `run_sha256` hashes `run`; `ref.sha256` hashes the source file, whose content is never stored.
 */
export const ciStepSchema = z.strictObject({
  id: ciStepIdSchema,
  name: stepNameSchema.exactOptional(),
  run: shellCommandSchema,
  run_sha256: sha256HexSchema.exactOptional(),
  ref: sourceRefSchema,
});
export type CiStep = z.infer<typeof ciStepSchema>;

/**
 * A CI deviation: "record any unavailable or narrowed step as an explicit deviation. Never silently
 * delete a failing CI check." `replacement_step` names the recipe step that runs instead of a
 * narrowed CI step. `run_sha256` is the deviating CI step's `run_sha256`: step IDs are positional
 * (`jobs.test.steps[3]`), so versions and consent scopes compare deviations by what the step runs.
 */
export const ciDeviationSchema = z
  .strictObject({
    ci_step_id: ciStepIdSchema,
    kind: deviationKindSchema,
    reason: deviationReasonSchema,
    replacement_step: stepNameSchema.exactOptional(),
    run_sha256: sha256HexSchema.exactOptional(),
  })
  .refine(
    (deviation) => deviation.kind === "narrowed" || deviation.replacement_step === undefined,
    { ...whenValid, error: "an unavailable step has no replacement", path: ["replacement_step"] },
  );
export type CiDeviation = z.infer<typeof ciDeviationSchema>;

// ---- Calibration (`recipe_versions.calibration`) ----

/** One sabotage run ("Run each applicable sabotage in isolation and identify the check detecting it"). */
export const sabotageRunSchema = z
  .strictObject({
    kind: sabotageKindSchema,
    path: repoFilePathSchema.exactOptional(),
    outcome: sabotageOutcomeSchema,
    detected_by: stepNameSchema.exactOptional(),
    inapplicable_reason: sabotageInapplicableReasonSchema.exactOptional(),
    duration_ms: z.int().nonnegative().exactOptional(),
    /** Sanitized mutation steps, retained when they contain an output excerpt reference. */
    steps: z.array(stepResultSchema).max(100).exactOptional(),
  })
  .superRefine((run, ctx) => {
    if ((run.outcome === "caught") !== (run.detected_by !== undefined)) {
      ctx.addIssue({
        code: "custom",
        path: ["detected_by"],
        message: "exactly the caught mutations name the detecting step",
      });
    }
    if ((run.outcome === "inapplicable") !== (run.inapplicable_reason !== undefined)) {
      ctx.addIssue({
        code: "custom",
        path: ["inapplicable_reason"],
        message: "exactly the inapplicable mutations record why",
      });
    }
    if (run.outcome !== "inapplicable" && run.path === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["path"],
        message: "an applied mutation names its target",
      });
    }
  }, whenValid);
export type SabotageRun = z.infer<typeof sabotageRunSchema>;

/**
 * A finished calibration. The verdict is cross-checked against SPEC's bar: "Require at least two
 * meaningful applicable mutations, all caught, with at least one exercising application code/build
 * behavior … All-skipped, install-only, insufficient working checks or undetected mutations produce `weak`
 * with reasons."
 */
export const debtCheckKindSchema = z.enum([
  "reproducible",
  "flaky",
  "reproducible_timeout",
  "reproducible_killed",
]);
export const debtCheckAuthoritySchema = z.strictObject({
  name: stepNameSchema,
  kind: debtCheckKindSchema,
});
export type DebtCheckAuthority = z.output<typeof debtCheckAuthoritySchema>;

export const regressionCalibrationComparisonSchema = z.strictObject({
  schema: z.literal("kovo.regression-calibration/1"),
  basis: z.literal("no_new_regressions"),
  base_sha: gitShaSchema,
  base_tree_sha: gitShaSchema,
  control_verified_at: utcDateTimeSchema,
  baseline_comparable: z.boolean(),
  required_checks: regressionRequiredChecksSchema,
  control_steps: z.array(stepResultSchema).min(1).max(100),
  debt_checks: z
    .array(
      z.strictObject({
        name: stepNameSchema,
        kind: debtCheckKindSchema,
        fingerprint_sha256: sha256HexSchema.exactOptional(),
      }),
    )
    .max(100)
    .exactOptional(),
});

export type RegressionCalibrationComparison = z.output<
  typeof regressionCalibrationComparisonSchema
>;

export const calibrationSchema = z
  .strictObject({
    status: z.enum(["calibrated", "weak"]),
    weak_reasons: z.array(calibrationWeakReasonSchema).max(10),
    /** "Select applicable sabotage targets deterministically with a fixed seed". */
    seed: z.string().min(1).max(64),
    fingerprint: sha256HexSchema,
    image_digest: imageDigestSchema,
    node_version: exactVersionSchema,
    pm_version: exactVersionSchema,
    started_at: utcDateTimeSchema,
    completed_at: utcDateTimeSchema,
    baseline: z.strictObject({ passed: z.boolean(), steps: z.array(stepResultSchema).max(100) }),
    mutations: z.array(sabotageRunSchema).max(20),
    /** New immutable records only; absence keeps legacy clean-baseline semantics. */
    comparison: regressionCalibrationComparisonSchema.exactOptional(),
    /** The baseline tree's toolchain fingerprint (diagnostics only); absent on older records. */
    toolchain: toolchainSchema.exactOptional(),
  })
  .superRefine((calibration, ctx) => {
    const applied = calibration.mutations.filter((run) => run.outcome !== "inapplicable");
    const caught = applied.filter((run) => run.outcome === "caught");
    const appCodeCaught = caught.filter((run) => SABOTAGE_EXERCISES_APP_CODE[run.kind]);
    const comparison = calibration.comparison;
    if (
      calibration.weak_reasons.includes("baseline_incomparable") &&
      (comparison === undefined || comparison.baseline_comparable)
    )
      ctx.addIssue({
        code: "custom",
        path: ["weak_reasons"],
        message: "baseline incomparable belongs only to an incomparable new-basis record",
      });
    if (
      comparison !== undefined &&
      [...calibration.baseline.steps, ...comparison.control_steps].reduce(
        (sum, s) => sum + (s.regression?.issues.length ?? 0),
        0,
      ) > REGRESSION_LIMITS.maxIssuesPerPair
    )
      ctx.addIssue({
        code: "custom",
        path: ["comparison"],
        message: "paired observation budget exceeded",
      });
    const comparable =
      comparison !== undefined &&
      comparison.baseline_comparable &&
      completeRegressionProof(calibration.baseline.steps, comparison.required_checks) &&
      completeRegressionProof(comparison.control_steps, comparison.required_checks);
    if (comparison?.baseline_comparable === true && !comparable)
      ctx.addIssue({
        code: "custom",
        path: ["comparison"],
        message: "comparable baseline requires complete fresh control and baseline proof",
      });
    if (
      comparison !== undefined &&
      (comparison.control_verified_at.getTime() < calibration.started_at.getTime() ||
        comparison.control_verified_at.getTime() > calibration.completed_at.getTime())
    )
      ctx.addIssue({
        code: "custom",
        path: ["comparison", "control_verified_at"],
        message: "control belongs to this calibration interval",
      });
    if (
      comparison !== undefined &&
      calibration.baseline.passed &&
      calibration.baseline.steps.some((s) => s.status !== "passed")
    )
      ctx.addIssue({
        code: "custom",
        path: ["baseline", "passed"],
        message: "regression basis preserves actual failed steps",
      });
    const meetsBar =
      (comparison === undefined ? calibration.baseline.passed : comparable) &&
      caught.length === applied.length &&
      caught.length >= LIMITS.calibration.minMeaningfulMutations &&
      appCodeCaught.length >= LIMITS.calibration.minAppCodeMutations;
    if (calibration.status === "calibrated" && !meetsBar) {
      ctx.addIssue({
        code: "custom",
        path: ["status"],
        message:
          "calibrated requires a passing legacy or comparable regression baseline and two caught mutations, one in app code, none undetected",
      });
    }
    if (calibration.status === "calibrated" && calibration.weak_reasons.length > 0) {
      ctx.addIssue({
        code: "custom",
        path: ["weak_reasons"],
        message: "calibrated has no weak reasons",
      });
    }
    if (calibration.status === "weak" && calibration.weak_reasons.length === 0) {
      ctx.addIssue({ code: "custom", path: ["weak_reasons"], message: "weak records its reasons" });
    }
    if (calibration.completed_at.getTime() < calibration.started_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["completed_at"],
        message: "completes after it starts",
      });
    }
  }, whenValid);
export type Calibration = z.output<typeof calibrationSchema>;
