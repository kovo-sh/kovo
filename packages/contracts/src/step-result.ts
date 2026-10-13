import { z } from "zod";

import { sandboxPhaseSchema } from "./enums/operations.js";
import { stepFailureCodeSchema, stepStatusSchema } from "./enums/verification.js";
import { FAILURE_EXCERPT_STEP_STATUSES, failureExcerptRefSchema } from "./failure-excerpt.js";
import { countSchema, hasControlCharacter, sha256HexSchema, whenValid } from "./primitives.js";
import { regressionObservationSchema } from "./regression.js";
import { wellKnownPackageSchema } from "./well-known-packages.js";

/** Advisory classification of bounded untrusted install output; never changes a verdict. */
export const INSTALL_DIAGNOSTICS = [
  "lockfile_mismatch",
  "registry_unavailable",
  "registry_refused",
  "integrity_mismatch",
  "lifecycle_failed",
  "unsupported_runtime",
  "unknown",
] as const;
export const installDiagnosticSchema = z.enum(INSTALL_DIAGNOSTICS);
export type InstallDiagnostic = z.infer<typeof installDiagnosticSchema>;

/** Advisory hints from bounded failed-check output; never change verification or calibration. */
export const CHECK_DIAGNOSTICS = [
  "lint_setup_required",
  "lint_tool_missing",
  "lint_configuration_invalid",
  "lint_violations",
  "typecheck_errors",
  "module_not_found",
] as const;
export const checkDiagnosticSchema = z.enum(CHECK_DIAGNOSTICS);
export type CheckDiagnostic = z.infer<typeof checkDiagnosticSchema>;

/**
 * Why a failed step failed, as far as Kovo can tell without keeping its output (docs/decisions/
 * recipes.md "Toolchain fingerprints and failure categories"): an enum from fixed signatures over
 * the ephemeral output and trusted facts (the exit code, the parsed report's counts). Advisory
 * only: hostile output can imitate a signature, so a category never changes a verdict.
 */
export const FAILURE_CATEGORIES = [
  "eslint_not_installed",
  "eslint_config_missing",
  "next_lint_setup_required",
  "lint_errors",
  "tool_attempted_package_install",
  "npm_proxy_refused",
  "module_not_found",
  "typescript_errors",
  "test_failures",
  "out_of_memory",
  "killed_by_signal",
  "command_not_found",
  "lockfile_out_of_date",
  "engine_mismatch",
  // Read first, written later: a check that failed after an install the completeness probe found
  // incomplete, with the count of declared packages missing from node_modules.
  "dependencies_not_installed",
  "unclassified",
] as const;
export const failureCategoryNameSchema = z.enum(FAILURE_CATEGORIES);
export type FailureCategoryName = z.infer<typeof failureCategoryNameSchema>;

/** Categories that may name the well-known public package involved. */
export const FAILURE_CATEGORIES_WITH_PACKAGE: ReadonlySet<FailureCategoryName> = new Set([
  "npm_proxy_refused",
  "module_not_found",
]);
/** Categories that may carry a count (errors or failed tests). */
export const FAILURE_CATEGORIES_WITH_COUNT: ReadonlySet<FailureCategoryName> = new Set([
  "dependencies_not_installed",
  "lint_errors",
  "typescript_errors",
  "test_failures",
]);
/** The largest count a category records (a bounded hint, not a measurement). */
export const FAILURE_CATEGORY_MAX_COUNT = 1_000_000;

/** A failed step's category: an enum, an optional allowlisted package and an optional count. */
export const failureCategorySchema = z
  .strictObject({
    category: failureCategoryNameSchema,
    /** Only a well-known public package (`WELL_KNOWN_PACKAGES`); anything else is never kept. */
    package: wellKnownPackageSchema.exactOptional(),
    count: z.int().min(0).max(FAILURE_CATEGORY_MAX_COUNT).exactOptional(),
  })
  .superRefine((value, ctx) => {
    if (value.package !== undefined && !FAILURE_CATEGORIES_WITH_PACKAGE.has(value.category)) {
      ctx.addIssue({
        code: "custom",
        path: ["package"],
        message: "this category names no package",
      });
    }
    if (value.count !== undefined && !FAILURE_CATEGORIES_WITH_COUNT.has(value.category)) {
      ctx.addIssue({ code: "custom", path: ["count"], message: "this category has no count" });
    }
  }, whenValid);
export type FailureCategory = z.infer<typeof failureCategorySchema>;

// Sanitized results of executed recipe steps, shared by calibration records and fix evidence.
// SPEC "Sandbox B": "Capture only exit codes, durations, counts, failure codes and hashes; raw
// stdout/stderr stays ephemeral."

/** A recipe step name (`Recipe.steps[].name`): 1–100 characters, no surrounding whitespace. */
export const stepNameSchema = z
  .string()
  .min(1)
  .max(100)
  .refine((name) => name.trim() === name && !hasControlCharacter(name), {
    ...whenValid,
    error: "must be a single-line name without surrounding whitespace",
  });

/** Test counts parsed from a reporter file (untrusted; cross-checked by the verifier). */
export const testCountsSchema = z
  .strictObject({
    total: countSchema,
    passed: countSchema,
    failed: countSchema,
    skipped: countSchema,
  })
  .refine((counts) => counts.passed + counts.failed + counts.skipped === counts.total, {
    ...whenValid,
    error: "passed + failed + skipped must equal total",
  });
export type TestCounts = z.infer<typeof testCountsSchema>;

/** One executed step: codes, counts, durations and hashes only. */
export const stepResultSchema = z
  .strictObject({
    name: stepNameSchema,
    phase: sandboxPhaseSchema,
    status: stepStatusSchema,
    /** Process exit code; null when the step never ran or was killed before exiting. */
    exit_code: z.int().min(0).max(255).nullable(),
    duration_ms: countSchema,
    failure_code: stepFailureCodeSchema.exactOptional(),
    /** Optional for old records; a hint from output, not proof of the underlying cause. */
    install_diagnostic: installDiagnosticSchema.exactOptional(),
    /** Optional for old records; only a failed check with a nonzero process exit may carry it. */
    check_diagnostic: checkDiagnosticSchema.exactOptional(),
    /** Optional for old records; only a failed install or check with a nonzero exit carries it. */
    failure_category: failureCategorySchema.exactOptional(),
    tests: testCountsSchema.exactOptional(),
    /** SHA-256 of the reporter file the verifier parsed. */
    report_sha256: sha256HexSchema.exactOptional(),
    /** SHA-256 of the captured output; the output itself is never stored. */
    output_sha256: sha256HexSchema.exactOptional(),
    /** Additive evidence only; legacy records do not gain a regression exception. */
    regression: regressionObservationSchema.exactOptional(),
    /**
     * The encrypted, redacted tail of a failed or timed-out step's output, by reference only
     * (docs/decisions/verification.md "Failed-step output excerpts"). Optional: absent on every
     * other step, on records written before excerpts existed, and while excerpts are switched off.
     */
    failure_excerpt: failureExcerptRefSchema.exactOptional(),
  })
  .superRefine((step, ctx) => {
    const problems: [path: string, message: string][] = [];
    const hasFailureCode = step.failure_code !== undefined;
    if (step.install_diagnostic !== undefined && step.failure_code !== "install_failed") {
      problems.push(["install_diagnostic", "install diagnostics belong to failed installs only"]);
    }
    if (
      step.check_diagnostic !== undefined &&
      (step.failure_code !== "nonzero_exit" ||
        step.status !== "failed" ||
        step.exit_code === null ||
        step.exit_code === 0 ||
        (step.phase !== "B_build" && step.phase !== "B_tests"))
    ) {
      problems.push([
        "check_diagnostic",
        "check diagnostics require a failed check with nonzero exit",
      ]);
    }
    if (
      step.failure_category !== undefined &&
      ((step.failure_code !== "nonzero_exit" && step.failure_code !== "install_failed") ||
        step.status !== "failed" ||
        step.exit_code === null ||
        step.exit_code === 0)
    ) {
      problems.push([
        "failure_category",
        "failure categories require a failed install or check with nonzero exit",
      ]);
    }
    if (
      step.failure_excerpt !== undefined &&
      !(FAILURE_EXCERPT_STEP_STATUSES as readonly string[]).includes(step.status)
    ) {
      problems.push(["failure_excerpt", "only a failed or timed-out step keeps an output excerpt"]);
    }
    switch (step.status) {
      case "passed":
        if (step.exit_code !== 0) problems.push(["exit_code", "a passed step exits 0"]);
        if (hasFailureCode) problems.push(["failure_code", "a passed step has no failure code"]);
        if ((step.tests?.failed ?? 0) > 0) {
          problems.push(["tests", "a passed step has no failed tests"]);
        }
        break;
      case "skipped":
        if (step.exit_code !== null) {
          problems.push(["exit_code", "a skipped step has no exit code"]);
        }
        if (hasFailureCode) problems.push(["failure_code", "a skipped step has no failure code"]);
        break;
      case "timed_out":
        if (step.failure_code !== "timeout") {
          problems.push(["failure_code", "a timed-out step has failure code timeout"]);
        }
        break;
      case "failed":
      case "inconclusive":
      case "error":
        if (!hasFailureCode) problems.push(["failure_code", "a non-passing step records why"]);
        break;
    }
    for (const [path, message] of problems) ctx.addIssue({ code: "custom", path: [path], message });
  }, whenValid);
export type StepResult = z.infer<typeof stepResultSchema>;

/** Required recipe checks remain explicit in paired comparison evidence. */
export const regressionRequiredChecksSchema = z
  .array(
    z.strictObject({
      name: stepNameSchema,
      report_required: z.boolean(),
      phase: z.enum(["B_install", "B_build", "B_tests"]),
    }),
  )
  .min(1)
  .max(100)
  .refine((checks) => new Set(checks.map((c) => c.name)).size === checks.length, {
    error: "required check names are unique",
  });

export type RegressionRequiredCheck = z.infer<typeof regressionRequiredChecksSchema>[number];

/** Structural proof validation only; core compares actual fresh observations and their deltas. */
export function completeRegressionProof(
  steps: readonly StepResult[],
  checks: z.infer<typeof regressionRequiredChecksSchema>,
): boolean {
  const byName = new Map(steps.map((s) => [s.name, s]));
  return (
    steps.some((s) => s.name === "install" && s.phase === "B_install" && s.status === "passed") &&
    byName.size === steps.length &&
    byName.size === checks.length &&
    checks.every((check) => {
      const step = byName.get(check.name);
      const observation = step?.regression;
      const interrupted =
        step !== undefined &&
        step.phase !== "B_install" &&
        ((step.status === "timed_out" && step.failure_code === "timeout") ||
          (step.status === "failed" &&
            (step.exit_code ?? 0) >= 128 &&
            [
              "nonzero_exit",
              "report_missing",
              "report_unparseable",
              "test_count_mismatch",
            ].includes(step.failure_code ?? "")));
      if (
        step === undefined ||
        step.phase !== check.phase ||
        observation === undefined ||
        (observation.completeness !== "complete" &&
          !(
            observation.parser === "opaque-v1" &&
            observation.failure_fingerprint_sha256 !== undefined
          )) ||
        !observation.harness_intact ||
        !observation.process_cleanup_complete ||
        (step.status !== "passed" && step.status !== "failed" && !interrupted)
      )
        return false;
      if (step.phase === "B_install" && step.status !== "passed") return false;
      if (
        interrupted &&
        (observation.parser !== "opaque-v1" ||
          observation.observation !== "opaque_failure" ||
          observation.failure_fingerprint_sha256 === undefined)
      )
        return false;
      if (step.status === "passed" && observation.observation !== "clean") return false;
      if (
        step.status === "failed" &&
        ((step.failure_code !== "nonzero_exit" &&
          !(
            observation.parser === "opaque-v1" &&
            ["report_missing", "report_unparseable", "test_count_mismatch"].includes(
              step.failure_code ?? "",
            )
          )) ||
          step.exit_code === null ||
          step.exit_code === 0 ||
          observation.observation === "clean" ||
          (observation.issues.length === 0 && observation.observation !== "opaque_failure"))
      )
        return false;
      const reportRequired =
        check.report_required ||
        ["vitest-json-v1", "jest-json-v1", "tap-v1"].includes(observation.parser) ||
        step.tests !== undefined;
      return (
        !reportRequired ||
        (observation.parser === "opaque-v1" &&
          (interrupted ||
            (step.status === "failed" &&
              step.exit_code !== null &&
              step.exit_code > 0 &&
              step.exit_code < 128))) ||
        (step.tests !== undefined &&
          step.report_sha256 !== undefined &&
          observation.test_inventory_sha256 !== undefined &&
          observation.issues
            .filter((i) => i.kind === "test_failure")
            .reduce((sum, i) => sum + i.count, 0) === step.tests.failed)
      );
    })
  );
}
