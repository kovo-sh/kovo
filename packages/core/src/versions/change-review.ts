import type { DependencyChangeKind, MergeBlockReason, SemverBump } from "@kovo/contracts";
import semver from "semver";

import { VERSION_STEP_SEVERITY, versionStep, type VersionStep } from "./step.js";

// Why one changed resolved package makes a fix review-only (decideMerge gate 3: "a
// dependency-only patch/minor diff throughout the graph. Major upgrades, overrides,
// removals/rollbacks, source migrations and new top-level dependencies require review"; fix
// ladder: "a nominally patch-only direct update that adds a transitive major is review-only").
// core/policy judges the evidence's `dependency_changes` with it and core/lockfile's whole-graph
// diff with it, so a plan the ladder expects to be eligible is one decideMerge can merge.

export const DEPENDENCY_REVIEW_KINDS = [
  "direct_major", // a direct dependency leaves its caret line
  "transitive_major", // a transitive one does, or a new instance opens a line
  "new_top_level_dependency",
  "top_level_removal",
  "downgrade", // a version moves backwards (a rollback), or a new instance lies below all others
  "prerelease", // a prerelease on either side of a step
] as const;
export type DependencyReviewKind = (typeof DEPENDENCY_REVIEW_KINDS)[number];

/** decideMerge gate 3 (`dependency_scope`) reason each kind is reported as. */
export const DEPENDENCY_REVIEW_MERGE_REASON = {
  direct_major: "major_update",
  transitive_major: "transitive_major_update",
  new_top_level_dependency: "new_top_level_dependency",
  top_level_removal: "removal_or_rollback",
  downgrade: "removal_or_rollback",
  prerelease: "prerelease_version",
} as const satisfies Record<DependencyReviewKind, MergeBlockReason>;

/** One changed resolved package instance (contracts `DependencyChange`, or a graph diff entry). */
export interface ReviewedChange {
  readonly change: DependencyChangeKind;
  readonly from: string | null;
  readonly to: string | null;
  /** The recorded SemVer bump (upgrades and downgrades). */
  readonly bump: SemverBump | null;
  readonly isDirect: boolean;
}

function isNotForward(from: string | null, to: string | null): boolean {
  if (from === null || to === null) return false;
  if (semver.valid(from) === null || semver.valid(to) === null) return false;
  return !semver.gt(to, from);
}

/** The more severe of the recorded bump and the step computed from the versions. */
function effectiveStep(change: ReviewedChange): VersionStep {
  const computed =
    change.from === null || change.to === null
      ? "unparseable"
      : versionStep(change.from, change.to);
  const recorded = change.bump ?? "unparseable";
  return VERSION_STEP_SEVERITY[recorded] > VERSION_STEP_SEVERITY[computed] ? recorded : computed;
}

/**
 * The version a new instance steps from: the highest base version at or below it, else the lowest
 * one above it (`below` false: a step backwards). Null when there is none or one cannot be parsed.
 */
export function nearestBaseVersion(
  to: string,
  baseVersions: readonly string[],
): { readonly version: string; readonly below: boolean } | null {
  const added = semver.parse(to);
  if (added === null || baseVersions.length === 0) return null;
  const parsed = baseVersions.map((version) => semver.parse(version));
  const valid = parsed.filter((version) => version !== null);
  if (valid.length !== parsed.length) return null;
  const below = valid.filter((version) => semver.lte(version, added)).toSorted(semver.rcompare)[0];
  if (below !== undefined) return { version: below.version, below: true };
  const above = valid.toSorted(semver.compare)[0];
  return above === undefined ? null : { version: above.version, below: false };
}

/**
 * A new transitive instance. A package new to the graph is judged by provenance (age, scripts,
 * integrity), unless it is a prerelease. A new instance of a package the graph already resolves is
 * a version step from the nearest base version, judged like an upgrade.
 */
function addedInstanceKinds(to: string, baseVersions: readonly string[]): DependencyReviewKind[] {
  const added = semver.parse(to);
  if (added === null) return ["transitive_major"];
  if (baseVersions.length === 0) return added.prerelease.length > 0 ? ["prerelease"] : [];
  const nearest = nearestBaseVersion(to, baseVersions);
  if (nearest === null) return ["transitive_major"];
  const step = versionStep(nearest.version, added.version);
  if (step === "major" || step === "unparseable") return ["transitive_major"];
  if (step === "prerelease") return ["prerelease"];
  return nearest.below ? [] : ["downgrade"];
}

/**
 * Why one change needs review (empty for a patch/minor step or a new transitive package).
 * `baseVersions` are the versions of the package the base graph resolves (for additions).
 */
export function changeReviewKinds(
  change: ReviewedChange,
  baseVersions: readonly string[],
): DependencyReviewKind[] {
  if (change.change === "downgraded") return ["downgrade"];
  if (change.change === "removed") {
    // A removed direct dependency is a removal; a transitive instance that leaves the graph
    // because its parent moved is part of that parent's (separately judged) update.
    return change.isDirect ? ["top_level_removal"] : [];
  }
  if (change.change === "added") {
    if (change.isDirect) return ["new_top_level_dependency"];
    return change.to === null ? ["transitive_major"] : addedInstanceKinds(change.to, baseVersions);
  }
  // An "upgrade" that does not move forward is a rollback, whatever the record says.
  if (isNotForward(change.from, change.to)) return ["downgrade"];
  const step = effectiveStep(change);
  if (step === "major" || step === "unparseable") {
    return [change.isDirect ? "direct_major" : "transitive_major"];
  }
  return step === "prerelease" ? ["prerelease"] : [];
}

/** Model output is a single boolean: it cannot supply prose, severity, or replacement reasons. */
export function withBreakingChangeHint<T>(
  reasons: readonly T[],
  likelyBreaking: boolean,
): readonly (T | { readonly kind: "likely_breaking_change"; readonly source: "model" })[] {
  return likelyBreaking
    ? [...reasons, { kind: "likely_breaking_change", source: "model" }]
    : [...reasons];
}
