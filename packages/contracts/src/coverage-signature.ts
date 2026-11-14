import { z } from "zod";

import { packageManagerSchema } from "./enums/recipes.js";
import { exactVersionSchema, packageVersionSchema } from "./npm.js";
import { FAILURE_CATEGORIES } from "./step-result.js";
import { WELL_KNOWN_PACKAGES, type WellKnownPackage } from "./well-known-packages.js";

// V3 signature telemetry (#8256, plans/js-coverage-phase1.md section 2.10; docs/decisions/
// recipes.md "Toolchain fingerprints and failure categories"): one `coverage_signature`
// structured log line per verification
// run, so engineering sees what breaks, clustered by stack, without reading any content. Every
// field is a closed enum, a count, an ID, a boolean, or a public package name and exact version
// from the closed framework allowlist below (loggable metadata, D-242): never source, a manifest,
// a lockfile, a command, a step name or a host. A tool outside the allowlist is only counted.

/**
 * Public framework and tool packages whose exact versions a signature names: a subset of the
 * well-known packages a toolchain fingerprint can record, so a private package never appears.
 */
export const COVERAGE_FRAMEWORKS = [
  "@angular/core",
  "@nestjs/core",
  "@playwright/test",
  "@prisma/client",
  "@remix-run/dev",
  "@sveltejs/kit",
  "@tanstack/react-start",
  "astro",
  "cypress",
  "eslint",
  "express",
  "jest",
  "mocha",
  "next",
  "nuxt",
  "nx",
  "playwright",
  "prisma",
  "react",
  "react-router",
  "svelte",
  "turbo",
  "typescript",
  "vite",
  "vitest",
  "vue",
  "webpack",
] as const;
export type CoverageFramework = (typeof COVERAGE_FRAMEWORKS)[number];
/** Fails to compile when a framework is not a well-known package (plain syntax for readers). */
export type CoverageFrameworksAreWellKnown = [CoverageFramework] extends [WellKnownPackage]
  ? true
  : never;
export const COVERAGE_FRAMEWORKS_ARE_WELL_KNOWN: CoverageFrameworksAreWellKnown = true;
export const coverageFrameworkSchema = z.enum(COVERAGE_FRAMEWORKS);

/** The framework a stack is clustered by: the first of these the toolchain resolves. */
export const PRIMARY_FRAMEWORK_ORDER: readonly CoverageFramework[] = [
  "next",
  "nuxt",
  "@sveltejs/kit",
  "astro",
  "@remix-run/dev",
  "react-router",
  "@tanstack/react-start",
  "@angular/core",
  "@nestjs/core",
  "vite",
  "vue",
  "svelte",
  "react",
  "express",
];

/** Framework entries a line names at most; more are counted in `frameworks_other`. */
export const COVERAGE_FRAMEWORKS_MAX = COVERAGE_FRAMEWORKS.length;

/** `name@version` entries sorted by name, comma-separated: only allowlisted names, exact versions. */
export const coverageFrameworksFieldSchema = z
  .string()
  .max(1500)
  .regex(/^(?:[a-z0-9@._\u002f-]+@[A-Za-z0-9.-]+(?:,[a-z0-9@._\u002f-]+@[A-Za-z0-9.-]+)*)?$/)
  .refine(
    (value) => {
      if (value === "") return true;
      const names = value.split(",").map((entry) => {
        const at = entry.lastIndexOf("@");
        const name = entry.slice(0, at);
        return coverageFrameworkSchema.safeParse(name).success &&
          exactVersionSchema.safeParse(entry.slice(at + 1)).success
          ? name
          : null;
      });
      return (
        names.every((name) => name !== null) &&
        names.length <= COVERAGE_FRAMEWORKS_MAX &&
        names.every((name, index) => index === 0 || names[index - 1]! < name)
      );
    },
    { error: "allowlisted name@version entries, sorted and unique" },
  )
  // Branded, so the typed log fields never admit a plain string through this schema.
  .brand<"CoverageFrameworks">();

/**
 * Coverage tiers (plans/js-coverage-phase1.md section 2.3): T0 install, T1 static checks
 * (typecheck and lint), T2 build, T3 unit tests; `none` when no tier applies.
 */
export const COVERAGE_TIERS = ["t0_install", "t1_check", "t2_build", "t3_tests", "none"] as const;
export const coverageTierSchema = z.enum(COVERAGE_TIERS);
export type CoverageTier = (typeof COVERAGE_TIERS)[number];

/** Workspace package-manifest count, bucketed (the root counts as one). */
export const WORKSPACE_MEMBER_BUCKETS = [
  "members_1",
  "members_2_5",
  "members_6_20",
  "members_21_100",
  "members_101_plus",
  "members_unknown",
] as const;
export const workspaceMemberBucketSchema = z.enum(WORKSPACE_MEMBER_BUCKETS);

export const COVERAGE_ORCHESTRATORS = ["turbo", "nx", "none"] as const;
export const coverageOrchestratorSchema = z.enum(COVERAGE_ORCHESTRATORS);

/** The playbook v1 remediation the first failure would get next, or none. */
export const COVERAGE_PLAYBOOK_CODES = [
  "switch_runtime",
  "enable_class",
  "add_display",
  "raise_memory",
  "drop_check",
  "lower_tier",
  "playbook_no_remediation",
  "playbook_exhausted",
  "playbook_unavailable",
  "none",
] as const;
export const coveragePlaybookSchema = z.enum(COVERAGE_PLAYBOOK_CODES);

export const coverageFailureCategorySchema = z.enum([...FAILURE_CATEGORIES, "none"]);
export const coverageMajorSchema = z.int().min(0).max(999);

/** The closed shape of one `coverage_signature` line's fields (besides the event itself). */
export const coverageSignatureSchema = z.strictObject({
  account_id: z.uuid(),
  repo_id: z.uuid(),
  project_id: z.uuid().nullable(),
  package_manager: packageManagerSchema,
  pm_version: packageVersionSchema.nullable(),
  pm_major: coverageMajorSchema.nullable(),
  node_major: coverageMajorSchema.nullable(),
  frameworks: coverageFrameworksFieldSchema,
  framework: z.union([coverageFrameworkSchema, z.literal("none")]),
  framework_major: coverageMajorSchema.nullable(),
  frameworks_other: z.int().min(0).max(WELL_KNOWN_PACKAGES.length),
  workspace_members: workspaceMemberBucketSchema,
  orchestrator: coverageOrchestratorSchema,
  ci_present: z.boolean(),
  highest_tier: coverageTierSchema,
  failing_tier: coverageTierSchema,
  failure_category: coverageFailureCategorySchema,
  playbook: coveragePlaybookSchema,
});
export type CoverageSignature = z.infer<typeof coverageSignatureSchema>;
