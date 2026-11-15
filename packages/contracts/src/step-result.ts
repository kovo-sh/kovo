import { z } from "zod";

import { sandboxPhaseSchema } from "./enums/operations.js";
import { stepFailureCodeSchema, stepStatusSchema } from "./enums/verification.js";
import { FAILURE_EXCERPT_STEP_STATUSES, failureExcerptRefSchema } from "./failure-excerpt.js";
import { countSchema, hasControlCharacter, sha256HexSchema, whenValid } from "./primitives.js";
import { regressionObservationSchema } from "./regression.js";
import { persistedReader } from "./tolerant-reader.js";
import { wellKnownPackageSchema } from "./well-known-packages.js";

/** Advisory classification of bounded untrusted install output; never changes a verdict. */
export const INSTALL_DIAGNOSTICS = [
  "lockfile_mismatch",
  "registry_unavailable",
  "registry_refused",
  "integrity_mismatch",
  "lifecycle_failed",
  "unsupported_runtime",
  "package_not_found",
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
 * Which workspace orchestrator a pinned Turbo or Nx check ran (repository-locked Turbo and Nx):
 * `*_unproven_repo_version` discloses that the
 * repository's own locked release, not the proven one, ran (an ordinary result of any status);
 * `*_not_installed` (no package of that name installed) and `*_proof_failed` (the proven command's
 * version check failed) are harness errors.
 */
export const ORCHESTRATION_REASONS = [
  "turbo_unproven_repo_version",
  "turbo_not_installed",
  "turbo_proof_failed",
  "nx_unproven_repo_version",
  "nx_not_installed",
  "nx_proof_failed",
] as const;
export const orchestrationReasonSchema = persistedReader(z.enum(ORCHESTRATION_REASONS));
export type OrchestrationReason = z.infer<typeof orchestrationReasonSchema>;

/**
 * The public-fetch list version 2 host classes (E3): the
 * closed names an `egress_blocked:<class>` category may carry. Each class's trigger packages and
 * hosts are the reviewed list in `@kovo/core/recipe` (`CURATED_PUBLIC_FETCH_HOSTS`). A name grants
 * nothing.
 */
export const EGRESS_HOST_CLASSES = [
  "next-fonts",
  "playwright",
  "puppeteer",
  "electron",
  "github-release-assets",
  "node-gyp",
  "cypress",
  "sentry-cli",
] as const;
export type EgressHostClass = (typeof EGRESS_HOST_CLASSES)[number];

/**
 * Why a failed step failed, as far as Kovo can tell without keeping its output: an enum from fixed signatures over
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
  // An install that failed because the registry (Kovo's proxy or its upstream) was unavailable: a
  // 5xx, a connection error or a timeout, from the install hint.
  "registry_unavailable",
  // A dependency's install lifecycle script exited nonzero during the install step. It
  // names the package only when the package is well known.
  "install_script_failed",
  // The repository's own (root or workspace) install lifecycle script failed: an install step's
  // lifecycle failure that names no dependency's directory. Never names a package.
  "project_install_script_failed",
  // A build-phase check exited nonzero and printed nothing any fixed signature or vocabulary bit
  // matches: no failing output to classify. Chosen by a closed output-shape hash.
  "no_failure_output",
  // A test step exited nonzero with a test runner and a lifecycle-failure footer in its output
  // but no failed-test count or suite report. Chosen by a closed output-shape hash.
  "test_run_failed_without_report",
  // V1 failure taxonomy. `egress_blocked:<class>` names the E3 host
  // class (`EGRESS_HOST_CLASSES`) of a refused fetch, from trusted facts only; `unknown` is the
  // shell's category and any refusal no applicable class explains. The plan's `oom` is
  // `out_of_memory` above, kept under its recorded name.
  "egress_blocked:unknown",
  "egress_blocked:next-fonts",
  "egress_blocked:playwright",
  "egress_blocked:puppeteer",
  "egress_blocked:electron",
  "egress_blocked:github-release-assets",
  "egress_blocked:node-gyp",
  "egress_blocked:cypress",
  "egress_blocked:sentry-cli",
  "node_version_mismatch",
  "native_build_missing_toolchain",
  "next_font_fetch_failed",
  "browser_binary_missing",
  "test_needs_display",
  // A step stopped by its own timeout that printed nothing at all: the one category a timed-out
  // step carries.
  "timeout_no_output",
  "prisma_generate_missing",
  "pm_version_unsupported",
  "script_missing",
  // The plain outcomes: a failed check whose output no signature names, by what the check runs.
  "typecheck_failed",
  "build_failed",
  "test_failed",
  "unclassified",
] as const;
type FailureCategoryEnum = { [K in (typeof FAILURE_CATEGORIES)[number]]: K };
/**
 * Named so declaration emit refers to it instead of inlining every category in each API schema
 * that embeds a step result (the API registry's type otherwise exceeds TS7056's bound).
 */
export interface FailureCategoryNameSchema extends z.ZodEnum<FailureCategoryEnum> {}
export const failureCategoryNameSchema: FailureCategoryNameSchema = z.enum(FAILURE_CATEGORIES);
export type FailureCategoryName = z.infer<typeof failureCategoryNameSchema>;

/** Categories that may name the well-known public package involved. */
export const FAILURE_CATEGORIES_WITH_PACKAGE: ReadonlySet<FailureCategoryName> = new Set([
  "npm_proxy_refused",
  "module_not_found",
  "install_script_failed",
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

/**
 * What a watched file a step rewrote is (the base-relative Sandbox B guard): the
 * kinds a paired verification discloses when both runs rewrote the same files to the same bytes.
 * Kinds and counts only, never a path or content.
 */
export const REWRITE_KINDS = [
  "kovo",
  "lockfile",
  "manifest",
  "other",
  "package_manager_config",
  "tests",
  "verification_config",
] as const;
export const rewriteKindSchema = persistedReader(z.enum(REWRITE_KINDS));
export type RewriteKind = z.infer<typeof rewriteKindSchema>;

/**
 * Disclosure: by the end of this step the repository's own commands had rewritten
 * watched files, and the paired unchanged-base run rewrote exactly the same files from the same
 * bytes to the same bytes, so Kovo ignored that rewrite on both sides. Kinds (sorted, unique) and
 * the number of distinct files only.
 */
export interface ExpectedRewrite {
  readonly kinds: readonly RewriteKind[];
  readonly files: number;
}
// Annotated so the step schema's (widely embedded) declared type stays a short named reference.
export const expectedRewriteSchema: z.ZodType<ExpectedRewrite> = z
  .strictObject({
    kinds: z.array(rewriteKindSchema).min(1).max(REWRITE_KINDS.length).readonly(),
    files: z.int().min(1).max(1_000_000),
  })
  .readonly()
  .refine(
    (rewrite) =>
      rewrite.kinds.every((kind, index) => index === 0 || (rewrite.kinds[index - 1] ?? "") < kind),
    { ...whenValid, error: "rewrite kinds are sorted and unique" },
  );

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
    /**
     * Optional for old records; only a failed install or check with a nonzero exit carries it, and
     * a timed-out step only `timeout_no_output`.
     */
    failure_category: failureCategorySchema.exactOptional(),
    tests: testCountsSchema.exactOptional(),
    /** SHA-256 of the reporter file the verifier parsed. */
    report_sha256: sha256HexSchema.exactOptional(),
    /** SHA-256 of the captured output; the output itself is never stored. */
    output_sha256: sha256HexSchema.exactOptional(),
    /** Additive evidence only; legacy records do not gain a regression exception. */
    regression: regressionObservationSchema.exactOptional(),
    /**
     * The encrypted, redacted tail of a failed or timed-out step's output, by reference only.
     * Optional: absent on every other step, on records written before excerpts existed, and while excerpts are switched off.
     */
    failure_excerpt: failureExcerptRefSchema.exactOptional(),
    /**
     * Open-install disclosure: this passed install ran its dependency install scripts with internet
     * access before the code was present (open install, sealed code). Only a passed B_install step
     * carries it; absent on every other step and on records written before open install.
     */
    open_install: z.literal(true).exactOptional(),
    /**
     * The `ci_like_open` disclosure and posture record: this build or test step ran under `ci_like_open`
     * (CI-like internet access in the sealed isolation-tier VM). Only an executed B_build or
     * B_tests step carries it; absent on every other step and on records written before it.
     */
    ci_like_open: z.literal(true).exactOptional(),
    /** Optional for old records; only an executed pinned Turbo or Nx check carries it. */
    orchestration_reason: orchestrationReasonSchema.exactOptional(),
    /**
     * The rewrite this executed step's run shared with its paired unchanged-base run
     * (`expectedRewriteSchema`). Absent on every other step and on records written before it.
     */
    expected_rewrite: expectedRewriteSchema.exactOptional(),
  })
  .superRefine((step, ctx) => {
    const problems: [path: string, message: string][] = [];
    if (step.open_install !== undefined && (step.phase !== "B_install" || step.status !== "passed"))
      problems.push(["open_install", "only a passed install discloses the open install"]);
    if (
      step.ci_like_open !== undefined &&
      ((step.phase !== "B_build" && step.phase !== "B_tests") || step.status === "skipped")
    )
      problems.push(["ci_like_open", "only an executed build or test step discloses ci_like_open"]);
    const hasFailureCode = step.failure_code !== undefined;
    if (step.expected_rewrite !== undefined && step.status === "skipped")
      problems.push(["expected_rewrite", "only an executed step discloses a shared rewrite"]);
    if (
      step.orchestration_reason !== undefined &&
      (step.status === "skipped" ||
        (step.phase !== "B_build" && step.phase !== "B_tests") ||
        (!step.orchestration_reason.endsWith("_unproven_repo_version") && step.status !== "error"))
    ) {
      problems.push([
        "orchestration_reason",
        "orchestration reasons belong to executed checks; a missing installation is an error",
      ]);
    }
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
    if (step.failure_category?.category === "timeout_no_output") {
      if (step.status !== "timed_out" || step.failure_code !== "timeout")
        problems.push(["failure_category", "timeout_no_output belongs to a timed-out step only"]);
    } else if (
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
