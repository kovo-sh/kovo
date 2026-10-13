import { repoFilePathSchema, type MergeBlockReason } from "@kovo/contracts";
import {
  isPnpmWorkspaceEntryChange,
  type PnpmWorkspaceEntryChange,
} from "./pnpm-workspace-edits.js";

import {
  compilePathMatcher,
  GlobWorkExceeded,
  PreparedPath,
  type GlobWork,
  type PathMatcher,
} from "./glob.js";

// Protected paths (SPEC decideMerge gate 4: "Exact allowed paths and allowed manifest fields;
// tests, CI, `.kovo*`, `.npmrc`, recipe/harness/config protections unchanged"; threat table:
// "Tests/CI/config edited to pass | Trusted protected-path and manifest-field checks"). A fix may
// change only the files its plan allows, and never a protected one. The built-in protections cannot
// be removed by policy; policy `protected_paths` globs only add to them (contracts
// DEFAULT_POLICY_BODY, docs/decisions/contracts.md "Policy defaults").

export const PROTECTED_PATH_CATEGORIES = [
  "tests", // test sources, fixtures and snapshots
  "ci", // CI configuration
  "kovo", // `.kovo*` files
  "package_manager_config", // .npmrc, pnpm hooks and workspace settings
  "runtime_config", // runtime declarations and environment files
  "verification_config", // test runner, typecheck, lint and build configuration, Dockerfiles
  "repository_config", // git metadata that changes what a checkout contains
  "policy", // the repository's own `protected_paths`
] as const;
export type ProtectedPathCategory = (typeof PROTECTED_PATH_CATEGORIES)[number];

/** Version of the built-in list, recorded with evidence so a later change is attributable. */
export const PROTECTED_PATHS_VERSION = "2026-10-04-nx-project";

export const BUILT_IN_PROTECTED_PATHS: readonly {
  readonly pattern: string;
  readonly category: Exclude<ProtectedPathCategory, "policy">;
}[] = [
  // tests
  ...[
    "**/test",
    "**/tests",
    "**/spec",
    "**/__tests__",
    "**/__mocks__",
    "**/__snapshots__",
    "**/__fixtures__",
    "**/fixtures",
    "**/e2e",
    "**/cypress",
    "**/*.test.*",
    "**/*.spec.*",
    "**/*.snap",
  ].map((pattern) => ({ pattern, category: "tests" as const })),
  // CI
  ...[
    ".github",
    ".gitlab",
    ".gitlab-ci.yml",
    ".circleci",
    ".travis.yml",
    ".buildkite",
    ".drone.yml",
    "azure-pipelines.yml",
    ".azure-pipelines",
    "bitbucket-pipelines.yml",
    "appveyor.yml",
    "Jenkinsfile",
  ].map((pattern) => ({ pattern, category: "ci" as const })),
  { pattern: "**/.kovo*", category: "kovo" },
  // package manager configuration: registries, hooks that rewrite manifests, workspace settings
  ...[
    "**/.npmrc",
    "**/.yarnrc",
    "**/.yarnrc.yml",
    "**/.pnpmfile.cjs",
    "**/.pnpmfile.mjs",
    "**/pnpm-workspace.yaml",
    "**/npm-shrinkwrap.json",
  ].map((pattern) => ({ pattern, category: "package_manager_config" as const })),
  // runtime declarations and environment
  ...["**/.nvmrc", "**/.node-version", "**/.tool-versions", "**/.env*"].map((pattern) => ({
    pattern,
    category: "runtime_config" as const,
  })),
  // verification harness: test runners, coverage, typecheck, lint, build and container config
  ...[
    "**/vitest.config.*",
    "**/vitest.workspace.*",
    "**/vitest.setup.*",
    "**/vite.config.*",
    "**/jest.config.*",
    "**/jest.setup.*",
    "**/playwright.config.*",
    "**/cypress.config.*",
    "**/.mocharc*",
    "**/karma.conf.*",
    "**/ava.config.*",
    "**/.taprc",
    "**/.c8rc*",
    "**/.nycrc*",
    "**/tsconfig*.json",
    "**/jsconfig*.json",
    "**/.eslintrc*",
    "**/eslint.config.*",
    "**/.oxlintrc*",
    "**/biome.json",
    "**/biome.jsonc",
    "**/.prettierrc*",
    "**/prettier.config.*",
    "**/babel.config.*",
    "**/.babelrc*",
    "**/.swcrc",
    "**/next.config.*",
    "**/nuxt.config.*",
    "**/svelte.config.*",
    "**/astro.config.*",
    "**/remix.config.*",
    "**/webpack.config.*",
    "**/rollup.config.*",
    "**/tsup.config.*",
    "**/turbo.json",
    "**/nx.json",
    "**/project.json",
    "**/lerna.json",
    "**/Dockerfile*",
    "**/*.dockerfile",
    "**/.dockerignore",
    "**/docker-compose*.yml",
    "**/docker-compose*.yaml",
    "**/compose.yml",
    "**/compose.yaml",
    "**/Makefile",
  ].map((pattern) => ({ pattern, category: "verification_config" as const })),
  ...[".gitmodules", ".gitattributes", "**/.gitignore"].map((pattern) => ({
    pattern,
    category: "repository_config" as const,
  })),
];

export const PATH_VIOLATION_REASONS = [
  "protected_path_changed",
  "path_not_allowed",
  "invalid_path", // not a normalized repository-relative path: never trusted
  "protection_unverified", // the matching step budget ran out before this path was checked
] as const;
export type PathViolationReason = (typeof PATH_VIOLATION_REASONS)[number];

/** decideMerge gate 4 (`allowed_changes`) reason each violation is reported as. */
export const PATH_VIOLATION_MERGE_REASON = {
  protected_path_changed: "protected_path_changed",
  path_not_allowed: "path_not_allowed",
  invalid_path: "path_not_allowed",
  protection_unverified: "protected_path_changed",
} as const satisfies Record<PathViolationReason, MergeBlockReason>;

/**
 * Glob steps one check may spend (`GlobWork`). Matching costs at most (path length × pattern
 * states) steps per path and pattern, without backtracking, but policy globs are hostile and a
 * check multiplies up to 1 000 changed paths by up to 100 policy globs and the built-ins. A real
 * check of 1 000 paths against every built-in and 100 policy globs takes about 15 M steps (0.2 s);
 * at about 12 ns per step the bound stops a hostile one within a second. What the budget leaves
 * unchecked is reported as protected (`protection_unverified`): it never merges.
 */
export const PROTECTED_PATH_MATCH_STEPS = 64 * 1024 * 1024;

export interface PathViolation {
  /** The changed path (null when it is not even a valid path; its value is not repeated). */
  readonly path: string | null;
  readonly reason: PathViolationReason;
  readonly category: ProtectedPathCategory | null;
  /** The built-in or policy pattern that protects it. */
  readonly pattern: string | null;
}

export interface ChangedFilesInput {
  /** Every path the patch adds, modifies or deletes (renames list both sides). */
  readonly changedPaths: readonly string[];
  /**
   * The exact files the fix may change (a dependency plan: package.json and the lockfile), or null
   * to allow any non-protected path (reviewed source migrations).
   */
  readonly allowedPaths: readonly string[] | null;
  /** Policy `protected_paths` globs (contracts `pathGlobSchema`), in addition to the built-ins. */
  readonly policyProtectedPaths: readonly string[];
  /** Trusted, byte-checked root entry edit only; arbitrary caller objects grant nothing. */
  readonly pnpmWorkspaceEntryChange?: PnpmWorkspaceEntryChange;
}

interface CompiledProtection {
  readonly pattern: string;
  readonly category: ProtectedPathCategory;
  readonly matches: PathMatcher;
}

const BUILT_IN_COMPILED: readonly CompiledProtection[] = BUILT_IN_PROTECTED_PATHS.map((entry) => ({
  pattern: entry.pattern,
  category: entry.category,
  matches: compilePathMatcher(entry.pattern),
}));

function compileProtections(policyProtectedPaths: readonly string[]): CompiledProtection[] {
  const policy = policyProtectedPaths.map((pattern) => ({
    pattern,
    category: "policy" as const,
    matches: compilePathMatcher(pattern),
  }));
  return [...BUILT_IN_COMPILED, ...policy];
}

/**
 * The first protection covering `path` within `work`; throws `GlobWorkExceeded` with the entry
 * being checked in `checking.entry`.
 */
function firstProtection(
  protections: readonly CompiledProtection[],
  path: PreparedPath,
  work: GlobWork,
  checking: { entry: CompiledProtection | null },
): CompiledProtection | undefined {
  return protections.find((entry) => {
    checking.entry = entry;
    return entry.matches(path, work);
  });
}

/**
 * The protection covering `path`, built-ins first, or null. Matching is bounded by `work`
 * (default: a fresh {@link PROTECTED_PATH_MATCH_STEPS}; pass one to share it across paths); when
 * it runs out, the pattern being checked is returned, since it may protect the path (fail closed).
 */
export function protectionFor(
  path: string,
  policyProtectedPaths: readonly string[] = [],
  work: GlobWork = { remaining: PROTECTED_PATH_MATCH_STEPS },
): { readonly pattern: string; readonly category: ProtectedPathCategory } | null {
  const checking: { entry: CompiledProtection | null } = { entry: null };
  let match: CompiledProtection | null | undefined;
  try {
    match = firstProtection(
      compileProtections(policyProtectedPaths),
      new PreparedPath(path),
      work,
      checking,
    );
  } catch (error) {
    if (!(error instanceof GlobWorkExceeded)) throw error;
    match = checking.entry;
  }
  return match === undefined || match === null
    ? null
    : { pattern: match.pattern, category: match.category };
}

/**
 * Checks a patch's changed files: each must be a valid path, unprotected (built-in or policy), and
 * one of the allowed paths when the plan names them. Violations are sorted by path. Matching shares
 * one {@link PROTECTED_PATH_MATCH_STEPS} budget; paths it leaves unchecked are
 * `protection_unverified`.
 */
export function checkChangedFiles(input: ChangedFilesInput): PathViolation[] {
  const protections = compileProtections(input.policyProtectedPaths);
  const allowed = input.allowedPaths === null ? null : new Set(input.allowedPaths);
  const violations: PathViolation[] = [];
  const work: GlobWork = { remaining: PROTECTED_PATH_MATCH_STEPS };
  let exhausted = false;
  for (const path of [...new Set(input.changedPaths)].toSorted()) {
    if (!repoFilePathSchema.safeParse(path).success) {
      violations.push({ path: null, reason: "invalid_path", category: null, pattern: null });
      continue;
    }
    let protection: CompiledProtection | undefined;
    if (!exhausted) {
      try {
        const active =
          path === "pnpm-workspace.yaml" &&
          isPnpmWorkspaceEntryChange(input.pnpmWorkspaceEntryChange)
            ? protections.filter(
                (entry) =>
                  !(
                    entry.category === "package_manager_config" &&
                    entry.pattern === "**/pnpm-workspace.yaml"
                  ),
              )
            : protections;
        protection = firstProtection(active, new PreparedPath(path), work, { entry: null });
      } catch (error) {
        if (!(error instanceof GlobWorkExceeded)) throw error;
        exhausted = true;
      }
    }
    if (exhausted) {
      violations.push({ path, reason: "protection_unverified", category: null, pattern: null });
    } else if (protection !== undefined) {
      violations.push({
        path,
        reason: "protected_path_changed",
        category: protection.category,
        pattern: protection.pattern,
      });
    } else if (allowed !== null && !allowed.has(path)) {
      violations.push({ path, reason: "path_not_allowed", category: null, pattern: null });
    }
  }
  return violations;
}
