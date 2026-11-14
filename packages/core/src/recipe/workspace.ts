import {
  SABOTAGE_EXERCISES_APP_CODE,
  type Calibration,
  type PackageManager,
  type RecipeStep,
  type SabotageTarget,
  type Sha256Hex,
} from "@kovo/contracts";
import { sha256HexSchema } from "@kovo/contracts/primitives";
import { z } from "zod";

import { canonicalWorkspacePath } from "../lockfile/workspace/discover.js";
import type { WorkspaceLayout } from "../lockfile/workspace/types.js";
import { expectationsFor, scriptCommand } from "./commands.js";
import { canonicalHash } from "./digest/canonical-json.js";
import { RECIPE_INPUT_LIMITS, repoFilesSchema, type RepoFile } from "./inputs.js";
import { readPackageFacts, type PackageFacts } from "./package-json.js";
import { proposeSabotageTargets } from "./proposals.js";

/** Aggregate repository bounds, never a fresh allowance for each member. */
export const WORKSPACE_RECIPE_LIMITS = {
  maxMembers: 100,
  maxChecks: 50,
  maxManifestBytes: 8 * 1024 * 1024,
  maxMetadataBytes: 256 * 1024,
} as const;

const CHECK_FAMILIES = [
  ["typecheck", "type-check", "check-types", "types:check", "check:types", "tsc", "types"],
  ["lint", "lint:ci"],
  ["build"],
  ["test", "test:ci", "test:unit"],
  ["test:run"],
  ["format:check"],
  ["check"],
  ["verify"],
  ["validate"],
  ["ci"],
] as const;

export interface WorkspaceCheck {
  readonly id: string;
  readonly name: string;
  readonly memberPath: string;
  readonly cwd: string;
  readonly argv: readonly string[];
  /** Relative to cwd; trusted harness supplies cwd separately, never interpolates it. */
  readonly run: string;
  readonly expect: RecipeStep["expect"];
  readonly source: {
    readonly path: string;
    readonly sha256: Sha256Hex;
    readonly locator: string;
  };
}
export interface WorkspaceRecipeMember {
  readonly path: string;
  readonly manifestPath: string;
  readonly manifestSha256: Sha256Hex;
  /** In-memory facts only, not a persisted projection. */
  readonly facts: PackageFacts;
  readonly checks: readonly WorkspaceCheck[];
  readonly sabotageTargets: readonly SabotageTarget[];
}
export interface WorkspaceChecks {
  readonly selection: "whole_repo";
  readonly members: readonly WorkspaceRecipeMember[];
  readonly checks: readonly WorkspaceCheck[];
}
export type WorkspaceChecksResult =
  | { readonly ok: true; readonly value: WorkspaceChecks | null }
  | {
      readonly ok: false;
      readonly reason: "missing_manifest" | "invalid_manifest" | "resource_limit" | "invalid_path";
    };

/** The deepest owning member; root ownership never swallows declared siblings. */
export function workspaceMemberOf(path: string, members: readonly string[]): string | null {
  if (!canonicalWorkspacePath(path)) return null;
  let owner: string | null = members.includes(".") ? "." : null;
  for (const member of members) {
    if (
      member !== "." &&
      path.startsWith(`${member}/`) &&
      (owner === null || owner === "." || member.length > owner.length)
    )
      owner = member;
  }
  return owner;
}

/**
 * Member fallback checks and immutable provenance for whole-repo discovery. CI discovery keeps
 * its original ordering separately; no orchestration command implies sibling coverage here.
 * Null is intentional for settings-only/undeclared layouts: callers retain exact legacy behavior.
 */
export function discoverWorkspaceChecks(input: {
  readonly layout: WorkspaceLayout;
  readonly files: readonly RepoFile[];
  readonly tree: readonly string[];
}): WorkspaceChecksResult {
  if (!input.layout.hasWorkspaces) return { ok: true, value: null };
  const paths = input.layout.members.map((member) => member.path);
  if (
    paths.length > WORKSPACE_RECIPE_LIMITS.maxMembers + 1 ||
    input.tree.length > RECIPE_INPUT_LIMITS.maxTreePaths
  )
    return { ok: false, reason: "resource_limit" };
  if (
    !paths.includes(".") ||
    new Set(paths).size !== paths.length ||
    paths.some((path) => !canonicalWorkspacePath(path, true))
  )
    return { ok: false, reason: "invalid_path" };
  const files = repoFilesSchema.safeParse(input.files);
  if (!files.success) return { ok: false, reason: "invalid_manifest" };
  const byPath = new Map(files.data.map((file) => [file.path, file]));
  const tree = new Set(input.tree);
  const members: WorkspaceRecipeMember[] = [];
  const checks: WorkspaceCheck[] = [];
  const memberTrees = new Map<string, string[]>(paths.map((path) => [path, []]));
  for (const file of input.tree) {
    const owner = workspaceMemberOf(file, paths);
    if (owner === null) continue;
    memberTrees.get(owner)?.push(owner === "." ? file : file.slice(owner.length + 1));
  }
  let manifestBytes = 0;
  for (const path of paths) {
    const manifestPath = path === "." ? "package.json" : `${path}/package.json`;
    const manifest = byPath.get(manifestPath);
    if (manifest === undefined || !tree.has(manifestPath))
      return { ok: false, reason: "missing_manifest" };
    manifestBytes += manifest.content.length * 3;
    if (manifestBytes > WORKSPACE_RECIPE_LIMITS.maxManifestBytes)
      return { ok: false, reason: "resource_limit" };
    const facts = readPackageFacts(manifest.content);
    if (!facts.ok) return { ok: false, reason: "invalid_manifest" };
    const memberChecks: WorkspaceCheck[] = [];
    for (const family of CHECK_FAMILIES) {
      const script = family.find((name) => facts.facts.scripts.has(name));
      if (script === undefined || /no test specified/u.test(facts.facts.scripts.get(script) ?? ""))
        continue;
      const run = scriptCommand(input.layout.packageManager, script);
      const id = `workspace#${canonicalHash([path, script]).slice(0, 24)}`;
      const check: WorkspaceCheck = {
        id,
        name: `workspace ${id.slice(10)} ${script}`,
        memberPath: path,
        cwd: path,
        argv: scriptArgv(input.layout.packageManager, script),
        run,
        expect: expectationsFor(run, facts.facts.scripts),
        source: { path: manifestPath, sha256: facts.facts.sha256, locator: `scripts.${script}` },
      };
      memberChecks.push(check);
      checks.push(check);
      if (checks.length > WORKSPACE_RECIPE_LIMITS.maxChecks)
        return { ok: false, reason: "resource_limit" };
    }
    const localTree = memberTrees.get(path) ?? [];
    const sabotageTargets = proposeSabotageTargets(
      localTree,
      facts.facts.dependencyNames.size > 0,
    ).map((target) => ({
      kind: target.kind,
      path: path === "." ? target.path : `${path}/${target.path}`,
    }));
    members.push({
      path,
      manifestPath,
      manifestSha256: facts.facts.sha256,
      facts: facts.facts,
      checks: memberChecks,
      sabotageTargets,
    });
  }
  // Only sanitized identities/provenance/normalized checks belong in a projection; facts are
  // intentionally excluded. The UTF-16 multiplier upper-bounds UTF-8 bytes without host APIs.
  const metadata = {
    checks,
    members: members.map(({ facts: _facts, checks: _checks, ...member }) => member),
  };
  if (JSON.stringify(metadata).length * 3 > WORKSPACE_RECIPE_LIMITS.maxMetadataBytes)
    return { ok: false, reason: "resource_limit" };
  return { ok: true, value: { selection: "whole_repo", members, checks } };
}

function scriptArgv(pm: PackageManager, script: string): string[] {
  return script === "test" ? [pm, "test"] : [pm, "run", script];
}

export interface WorkspaceMemberCoverage {
  readonly memberPath: string;
  readonly covered: boolean;
  readonly checkIds: readonly string[];
}
export interface WorkspaceCoverage {
  readonly contextSha256: Sha256Hex;
  readonly fingerprint: Sha256Hex;
  readonly members: readonly WorkspaceMemberCoverage[];
}

/**
 * Existing calibration judgment is authoritative for debt/report/count/control rules. This
 * additional proof only restricts it: a caught application mutation proves its owning member,
 * never every member reached by a root command. At most the existing 20 mutations are consumed;
 * member count never multiplies sandbox runs or spend. Missing proof grants no eligibility.
 */
export function evaluateWorkspaceCoverage(input: {
  readonly memberPaths: readonly string[];
  readonly checks: readonly WorkspaceCheck[];
  readonly calibration: Calibration;
  readonly fingerprint: Sha256Hex;
  readonly contextSha256: Sha256Hex;
  readonly debtChecks: readonly string[];
}): WorkspaceCoverage {
  const empty: WorkspaceCoverage = {
    contextSha256: input.contextSha256,
    fingerprint: input.fingerprint,
    members: [],
  };
  if (
    input.memberPaths.length > WORKSPACE_RECIPE_LIMITS.maxMembers + 1 ||
    new Set(input.memberPaths).size !== input.memberPaths.length ||
    input.memberPaths.some((path) => !canonicalWorkspacePath(path, true)) ||
    input.checks.length > WORKSPACE_RECIPE_LIMITS.maxChecks ||
    input.checks.some((check) => check.id.length > 100 || check.name.length > 100) ||
    input.calibration.mutations.length > 20
  )
    return empty;
  const covered = new Map<string, Set<string>>();
  const debt = new Set([
    ...input.debtChecks,
    ...(input.calibration.comparison?.debt_checks ?? []).map((check) => check.name),
  ]);
  const baseline = new Map(input.calibration.baseline.steps.map((step) => [step.name, step]));
  if (
    input.memberPaths.length <= WORKSPACE_RECIPE_LIMITS.maxMembers + 1 &&
    input.checks.length <= WORKSPACE_RECIPE_LIMITS.maxChecks &&
    input.calibration.mutations.length <= 20 &&
    input.calibration.status === "calibrated" &&
    input.calibration.fingerprint === input.fingerprint
  ) {
    for (const mutation of input.calibration.mutations) {
      if (
        mutation.outcome !== "caught" ||
        mutation.path === undefined ||
        !SABOTAGE_EXERCISES_APP_CODE[mutation.kind] ||
        mutation.detected_by === undefined ||
        debt.has(mutation.detected_by)
      )
        continue;
      const check = input.checks.find((candidate) => candidate.name === mutation.detected_by);
      const step = baseline.get(mutation.detected_by);
      if (check === undefined || step?.status !== "passed" || step.phase === "B_install") continue;
      const member = workspaceMemberOf(mutation.path, input.memberPaths);
      if (member === null) continue;
      const ids = covered.get(member) ?? new Set<string>();
      ids.add(check.id);
      covered.set(member, ids);
    }
  }
  const proof: WorkspaceCoverage = {
    contextSha256: input.contextSha256,
    fingerprint: input.fingerprint,
    members: input.memberPaths.map((memberPath) => ({
      memberPath,
      covered: (covered.get(memberPath)?.size ?? 0) > 0,
      checkIds: [...(covered.get(memberPath) ?? [])].toSorted(),
    })),
  };
  return JSON.stringify(proof).length * 3 <= WORKSPACE_RECIPE_LIMITS.maxMetadataBytes
    ? proof
    : empty;
}

const workspaceCoverageSchema = z
  .strictObject({
    contextSha256: sha256HexSchema,
    fingerprint: sha256HexSchema,
    members: z
      .array(
        z.strictObject({
          memberPath: z
            .string()
            .max(1024)
            .refine((path) => canonicalWorkspacePath(path, true)),
          covered: z.boolean(),
          checkIds: z.array(z.string().min(1).max(100)).max(20),
        }),
      )
      .max(WORKSPACE_RECIPE_LIMITS.maxMembers + 1),
  })
  .refine(
    (proof) =>
      new Set(proof.members.map((member) => member.memberPath)).size === proof.members.length &&
      proof.members.every((member) => !member.covered || member.checkIds.length > 0),
  );

/** A fresh exact-context sidecar is required for every concretely affected member. */
export function workspaceCoverageAllows(input: {
  readonly coverage: WorkspaceCoverage | null;
  readonly memberPaths: readonly string[];
  readonly contextSha256: Sha256Hex;
  readonly fingerprint: Sha256Hex;
}): boolean {
  if (
    input.coverage === null ||
    input.memberPaths.length === 0 ||
    input.memberPaths.length > WORKSPACE_RECIPE_LIMITS.maxMembers + 1 ||
    new Set(input.memberPaths).size !== input.memberPaths.length ||
    input.memberPaths.some((path) => !canonicalWorkspacePath(path, true))
  )
    return false;
  const parsed = workspaceCoverageSchema.safeParse(input.coverage);
  if (
    !parsed.success ||
    JSON.stringify(parsed.data).length * 3 > WORKSPACE_RECIPE_LIMITS.maxMetadataBytes ||
    parsed.data.contextSha256 !== input.contextSha256 ||
    parsed.data.fingerprint !== input.fingerprint
  )
    return false;
  return input.memberPaths.every((path) =>
    parsed.data.members.some((member) => member.memberPath === path && member.covered),
  );
}

/**
 * Root application presence is independent of sabotage applicability. Source without an import
 * or supported mutation still needs detection coverage. Only conventional tooling/generated/test
 * trees and config/build entry files are exempt; declared package entry points override exemptions.
 */
export function workspaceRootHasApplication(
  layout: WorkspaceLayout,
  tree: readonly string[],
): boolean {
  if (!layout.hasWorkspaces) return false;
  if (tree.length > RECIPE_INPUT_LIMITS.maxTreePaths || layout.members.length > 101) return true;
  const root = layout.members.find((member) => member.path === ".");
  if (root === undefined) return true;
  const document = root.manifest.document;
  for (const field of ["main", "module", "browser", "bin", "exports", "source"] as const) {
    // A package entry declaration identifies root first-party behavior even if its generated
    // target is absent from Git. Complex entry objects are conservative too; no content persists.
    const entry = document[field];
    if (
      (typeof entry === "string" && entry.length > 0) ||
      (entry !== null && typeof entry === "object" && Object.keys(entry).length > 0)
    )
      return true;
  }
  const members = layout.members.map((member) => member.path);
  return tree.some((path) => {
    if (
      workspaceMemberOf(path, members) !== "." ||
      !/\.(?:[cm]?[jt]sx?|vue|svelte|astro|html)$/u.test(path)
    )
      return false;
    if (
      /(?:^|\/)(?:\.github|node_modules|dist|build|coverage|\.next|out|scripts|tools|__tests__|__mocks__|tests?|e2e)\//u.test(
        path,
      ) ||
      /\.(?:test|spec|stories|d)\.(?:[cm]?[jt]sx?|vue|svelte|astro|html)$/u.test(path)
    )
      return false;
    // A tooling-looking basename in an application directory is still first-party source.
    if (path.includes("/") || !/\.[cm]?[jt]sx?$/u.test(path)) return true;
    const name = path;
    return !(
      /(?:^|\.)config\.[cm]?[jt]s$/u.test(name) ||
      /^(?:build|eslint|prettier|postcss|tailwind|vite|vitest|jest|webpack|rollup|babel)(?:\.|$)/u.test(
        name,
      )
    );
  });
}
