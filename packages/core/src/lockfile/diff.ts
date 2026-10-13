import {
  dependencyChangeSchema,
  type DependencyChange,
  type DependencyChangeKind,
  type MergeBlockReason,
  type PackageName,
  type PackageVersion,
  type SemverBump,
} from "@kovo/contracts";
import semver from "semver";

import {
  changeReviewKinds,
  DEPENDENCY_REVIEW_KINDS,
  DEPENDENCY_REVIEW_MERGE_REASON,
  nearestBaseVersion,
  type DependencyReviewKind,
} from "../versions/change-review.js";
import { classifyVersionChange, compatibilityLine } from "./semver-change.js";
import {
  GRAPH_LIMITS,
  indexPackages,
  nameOfKey,
  type DependencyGraph,
  type DependencyPath,
  type PackageKey,
  type ResolvedPackageNode,
} from "./types.js";

// Before/after graph diff (BUILD_PLAN item 7; SPEC "Evaluate semantic version changes across the
// whole changed dependency graph, including transitives; a nominally patch-only direct update that
// adds a transitive major is review-only. Any override/source edit/new top-level dependency
// prevents auto-merge regardless of rung."; "Use package-manager adapters to make narrowly scoped
// lockfile edits; reject unintended graph churn").

export interface PackageChange {
  readonly name: PackageName;
  readonly from: PackageVersion | null;
  readonly to: PackageVersion | null;
  readonly change: DependencyChangeKind;
  /** SemVer distance for upgrades and downgrades; null for additions and removals. */
  readonly bump: SemverBump | null;
  /**
   * The change crosses a caret-compatibility line: from the paired version for an upgrade or
   * downgrade, from the nearest base version (`nearestBaseVersion`) for an addition.
   */
  readonly breaking: boolean;
  /** The new version is a prerelease. */
  readonly toPrerelease: boolean;
  readonly isDirect: boolean;
  readonly isDev: boolean;
  /** Paths to the changed instance (after graph; before graph for removals). */
  readonly paths: readonly DependencyPath[];
  /**
   * Additions only: every version of the package the before graph resolves, ascending (empty when
   * the package is new to the graph). A new instance steps from the nearest of them.
   */
  readonly baseVersions: readonly PackageVersion[] | null;
}

export interface TopLevelChanges {
  /** Aliases declared in the after graph only. */
  readonly added: readonly PackageName[];
  /** Aliases declared in the before graph only. */
  readonly removed: readonly PackageName[];
  /** Aliases whose resolved package/version changed. */
  readonly changed: readonly PackageName[];
  /**
   * Aliases now resolving to a different package (`foo: npm:bar` → `foo: npm:evil`): a removal
   * plus a new top-level dependency behind an unchanged name.
   */
  readonly replaced: readonly PackageName[];
}

/** A package/version both graphs resolve whose locked integrity or tarball URL differs. */
export interface IntegrityChange {
  readonly name: PackageName;
  readonly version: PackageVersion;
}

export interface GraphDiff {
  readonly changes: readonly PackageChange[];
  readonly topLevel: TopLevelChanges;
  /** SPEC provenance: "Integrity mismatch → Reject artifact/fix". */
  readonly integrityChanges: readonly IntegrityChange[];
}

function pathNames(paths: readonly DependencyPath[]): Set<string> {
  // A path's parent chain, by name, identifies "the same place" across versions.
  return new Set(
    paths.map((path) =>
      path
        .slice(0, -1)
        .map((key) => nameOfKey(key))
        .join(">"),
    ),
  );
}

function overlap(a: Set<string>, b: Set<string>): number {
  let count = 0;
  for (const value of a) if (b.has(value)) count += 1;
  return count;
}

/** Lexicographic comparison of pairing scores (higher is better). */
function isBetterScore(score: readonly number[], best: readonly number[]): boolean {
  for (const [index, value] of score.entries()) {
    const other = best[index] ?? Number.NEGATIVE_INFINITY;
    if (value !== other) return value > other;
  }
  return false;
}

function versionChange(from: ResolvedPackageNode, to: ResolvedPackageNode): PackageChange {
  const classified = classifyVersionChange(from.version, to.version);
  if (classified === null) throw new RangeError("paired versions are equal");
  return {
    name: to.name,
    from: from.version,
    to: to.version,
    change: classified.direction,
    bump: classified.bump,
    breaking: classified.breaking,
    toPrerelease: classified.toPrerelease,
    isDirect: to.isDirect,
    isDev: to.isDev,
    paths: to.paths,
    baseVersions: null,
  };
}

/** Pairs removed and added versions of one package by shared dependency paths, then proximity. */
function diffPackage(
  before: readonly ResolvedPackageNode[],
  after: readonly ResolvedPackageNode[],
): PackageChange[] {
  const beforeVersions = new Set(before.map((node) => node.version));
  const afterVersions = new Set(after.map((node) => node.version));
  const baseVersions = before.map((node) => node.version).toSorted(semver.compare);
  const removed = before.filter((node) => !afterVersions.has(node.version));
  const added = after.filter((node) => !beforeVersions.has(node.version));
  const changes: PackageChange[] = [];
  const unpaired = [...removed];
  for (const node of added) {
    const places = pathNames(node.paths);
    let bestIndex = -1;
    let bestScore: readonly number[] = [];
    for (const [index, candidate] of unpaired.entries()) {
      const score = [
        overlap(places, pathNames(candidate.paths)),
        compatibilityLine(candidate.version) === compatibilityLine(node.version) ? 1 : 0,
        -Math.abs(semver.major(candidate.version) - semver.major(node.version)),
      ];
      if (bestIndex === -1 || isBetterScore(score, bestScore)) {
        bestIndex = index;
        bestScore = score;
      }
    }
    const [paired] = bestIndex === -1 ? [] : unpaired.splice(bestIndex, 1);
    if (paired !== undefined) {
      changes.push(versionChange(paired, node));
      continue;
    }
    // A new version next to versions that stay steps from the nearest of them (a transitive
    // major arriving beside the old line crosses it).
    const nearest = nearestBaseVersion(node.version, baseVersions);
    changes.push({
      name: node.name,
      from: null,
      to: node.version,
      change: "added",
      bump: null,
      breaking:
        nearest !== null && compatibilityLine(nearest.version) !== compatibilityLine(node.version),
      toPrerelease: (semver.parse(node.version)?.prerelease.length ?? 0) > 0,
      isDirect: node.isDirect,
      isDev: node.isDev,
      paths: node.paths,
      baseVersions,
    });
  }
  for (const node of unpaired) {
    changes.push({
      name: node.name,
      from: node.version,
      to: null,
      change: "removed",
      bump: null,
      breaking: false,
      toPrerelease: false,
      isDirect: node.isDirect,
      isDev: node.isDev,
      paths: node.paths,
      baseVersions: null,
    });
  }
  return changes;
}

function groupByName(graph: DependencyGraph): Map<string, ResolvedPackageNode[]> {
  const groups = new Map<string, ResolvedPackageNode[]>();
  for (const node of graph.packages) {
    const group = groups.get(node.name);
    if (group === undefined) groups.set(node.name, [node]);
    else group.push(node);
  }
  return groups;
}

function directTargets(graph: DependencyGraph): Map<string, PackageKey | null> {
  return new Map(graph.direct.map((dependency) => [dependency.alias, dependency.target]));
}

function sortedUnique<T extends string>(values: Iterable<T>): T[] {
  return [...new Set(values)].toSorted();
}

/**
 * Whether a declaration kept its alias but now resolves to another package. A declaration that
 * starts or stops resolving is not a replacement: its package's addition or removal is a change.
 */
function isReplaced(before: PackageKey | null | undefined, after: PackageKey | null): boolean {
  if (before === null || before === undefined || after === null) return false;
  return nameOfKey(before) !== nameOfKey(after);
}

function topLevelChanges(before: DependencyGraph, after: DependencyGraph): TopLevelChanges {
  const was = directTargets(before);
  const now = directTargets(after);
  const sorted = sortedUnique<PackageName>;
  const kept = after.direct.filter((d) => was.has(d.alias));
  return {
    added: sorted(after.direct.filter((d) => !was.has(d.alias)).map((d) => d.alias)),
    removed: sorted(before.direct.filter((d) => !now.has(d.alias)).map((d) => d.alias)),
    changed: sorted(kept.filter((d) => was.get(d.alias) !== d.target).map((d) => d.alias)),
    replaced: sorted(
      kept.filter((d) => isReplaced(was.get(d.alias), d.target)).map((d) => d.alias),
    ),
  };
}

/**
 * Package/versions both graphs resolve whose integrity or tarball URL differs. A legacy sha1-only
 * entry gaining a sha512 integrity is not a change (the proxy verifies the sha512 against the
 * registry); losing or replacing a sha512 integrity is.
 */
function integrityChanges(before: DependencyGraph, after: DependencyGraph): IntegrityChange[] {
  const index = indexPackages(after);
  const changed: IntegrityChange[] = [];
  for (const node of before.packages) {
    const now = index.get(node.key);
    if (now === undefined) continue;
    const integrity = node.integrity !== null && now.integrity !== node.integrity;
    const resolved =
      node.resolved !== null && now.resolved !== null && now.resolved !== node.resolved;
    if (integrity || resolved) changed.push({ name: node.name, version: node.version });
  }
  return changed;
}

/** Every package/version added, removed, upgraded or downgraded between two graphs. */
export function diffGraphs(before: DependencyGraph, after: DependencyGraph): GraphDiff {
  const beforeGroups = groupByName(before);
  const afterGroups = groupByName(after);
  const names = sortedUnique([...beforeGroups.keys(), ...afterGroups.keys()]);
  const changes = names.flatMap((name) =>
    diffPackage(beforeGroups.get(name) ?? [], afterGroups.get(name) ?? []),
  );
  return {
    changes,
    topLevel: topLevelChanges(before, after),
    integrityChanges: integrityChanges(before, after),
  };
}

// ---- Classification ----

/**
 * Why a diff needs human review: the per-change kinds decideMerge gate 3 judges the evidence with
 * (`versions/change-review.ts`), plus top-level declarations that changed.
 */
export const DIFF_REVIEW_REASONS = DEPENDENCY_REVIEW_KINDS;
export type DiffReviewReason = DependencyReviewKind;

/** decideMerge gate 3 (`dependency_scope`) reason each review reason is reported as. */
export const DIFF_REVIEW_MERGE_REASON = DEPENDENCY_REVIEW_MERGE_REASON;

export interface DiffAssessment {
  /** Review reasons in `DIFF_REVIEW_REASONS` order; empty for a dependency-only patch/minor diff. */
  readonly reviewReasons: readonly DiffReviewReason[];
  readonly mergeBlockReasons: readonly MergeBlockReason[];
  /** Packages (or, for top-level declarations, aliases) behind each review reason. */
  readonly flagged: Readonly<Record<DiffReviewReason, readonly PackageName[]>>;
  /** At least one change, and every change is a patch/minor upgrade or a new transitive package. */
  readonly patchMinorOnly: boolean;
}

/**
 * Classifies a diff: patch/minor everywhere, or the reasons it needs human review. Each change is
 * judged exactly as decideMerge judges the evidence `toDependencyChanges` produces; declarations
 * add to that: an alias added, removed, or re-pointed at another package ("Never guess a
 * replacement package") needs review even when no resolved version changed.
 */
export function assessDiff(diff: GraphDiff): DiffAssessment {
  const flagged: Record<DiffReviewReason, Set<PackageName>> = {
    direct_major: new Set(),
    transitive_major: new Set(),
    new_top_level_dependency: new Set([...diff.topLevel.added, ...diff.topLevel.replaced]),
    top_level_removal: new Set([...diff.topLevel.removed, ...diff.topLevel.replaced]),
    downgrade: new Set(),
    prerelease: new Set(),
  };
  for (const change of diff.changes) {
    for (const kind of changeReviewKinds(change, change.baseVersions ?? [])) {
      flagged[kind].add(change.name);
    }
  }
  const reviewReasons = DIFF_REVIEW_REASONS.filter((reason) => flagged[reason].size > 0);
  const mergeBlockReasons = [
    ...new Set(reviewReasons.map((reason) => DIFF_REVIEW_MERGE_REASON[reason])),
  ];
  return {
    reviewReasons,
    mergeBlockReasons,
    flagged: {
      direct_major: sortedUnique(flagged.direct_major),
      transitive_major: sortedUnique(flagged.transitive_major),
      new_top_level_dependency: sortedUnique(flagged.new_top_level_dependency),
      top_level_removal: sortedUnique(flagged.top_level_removal),
      downgrade: sortedUnique(flagged.downgrade),
      prerelease: sortedUnique(flagged.prerelease),
    },
    patchMinorOnly: diff.changes.length > 0 && reviewReasons.length === 0,
  };
}

// ---- Churn ----

export interface ChurnOptions {
  /** The packages the plan meant to change (targets and edited ancestors). */
  readonly anchors: readonly string[];
  /** At most this many package changes are accepted. */
  readonly maxChangedPackages: number;
}

export const CHURN_REASONS = ["outside_target_closure", "too_many_changes"] as const;
export type ChurnReason = (typeof CHURN_REASONS)[number];

export interface ChurnAssessment {
  readonly rejected: boolean;
  readonly reasons: readonly ChurnReason[];
  /** Changed packages outside the anchors' dependency closure (sorted, at most 100). */
  readonly outsideClosure: readonly PackageName[];
}

/** Names reachable from the anchors (anchors included) through dependency edges. */
function closureNames(graph: DependencyGraph, anchors: ReadonlySet<string>): Set<string> {
  const index = indexPackages(graph);
  const names = new Set<string>(anchors);
  const queue = graph.packages.filter((node) => anchors.has(node.name)).map((node) => node.key);
  const seen = new Set<PackageKey>();
  for (let key = queue.pop(); key !== undefined; key = queue.pop()) {
    if (seen.has(key)) continue;
    seen.add(key);
    const node = index.get(key);
    if (node === undefined) continue;
    names.add(node.name);
    for (const edge of node.dependencies) if (!seen.has(edge.target)) queue.push(edge.target);
  }
  return names;
}

/**
 * Rejects unintended graph churn: every changed package must lie in the dependency closure of
 * the plan's anchors (in the before or the after graph), and the number of changes is bounded.
 */
export function assessChurn(
  before: DependencyGraph,
  after: DependencyGraph,
  diff: GraphDiff,
  options: ChurnOptions,
): ChurnAssessment {
  const anchors = new Set<string>(options.anchors);
  const allowed = new Set([...closureNames(before, anchors), ...closureNames(after, anchors)]);
  const outside = sortedUnique(
    diff.changes.filter((change) => !allowed.has(change.name)).map((change) => change.name),
  );
  const reasons: ChurnReason[] = [];
  if (outside.length > 0) reasons.push("outside_target_closure");
  if (diff.changes.length > options.maxChangedPackages) reasons.push("too_many_changes");
  return { rejected: reasons.length > 0, reasons, outsideClosure: outside.slice(0, 100) };
}

/** The default churn bound: a narrowly scoped fix rarely touches more packages than this. */
export const DEFAULT_MAX_CHANGED_PACKAGES = 50;

// ---- Evidence ----

/** contracts `dependencyChangesSchema` and `dependencyChangeSchema` bounds. */
export const MAX_DEPENDENCY_CHANGES = 5000;
const MAX_BASE_VERSIONS = 100;
const MAX_EVIDENCE_PATHS = 100;

/**
 * At most 100 base versions for an addition, always keeping the nearest one at or below it and
 * the lowest one above it (the ones gate 3 steps from), then the rest in ascending order.
 */
function evidenceBaseVersions(
  to: PackageVersion,
  baseVersions: readonly PackageVersion[],
): PackageVersion[] {
  const unique = [...new Set(baseVersions)].filter((version) => version !== to);
  if (unique.length <= MAX_BASE_VERSIONS) return unique.toSorted(semver.compare);
  const below = unique.filter((version) => semver.lte(version, to)).toSorted(semver.rcompare)[0];
  const above = unique.filter((version) => semver.gt(version, to)).toSorted(semver.compare)[0];
  const kept = new Set<PackageVersion>([below, above].filter((version) => version !== undefined));
  for (const version of unique.toSorted(semver.compare)) {
    if (kept.size >= MAX_BASE_VERSIONS) break;
    kept.add(version);
  }
  return [...kept].toSorted(semver.compare);
}

export interface DependencyChangesEvidence {
  /** The changes as contracts evidence, at most `MAX_DEPENDENCY_CHANGES`. */
  readonly changes: DependencyChange[];
  /**
   * The diff held more changes than evidence records. Changes that need review come first, so a
   * truncated list still carries every review reason the full diff has (up to the bound).
   */
  readonly truncated: boolean;
}

/**
 * The diff as `fix_evidence.dependency_changes` (contracts `dependencyChangeSchema`): names,
 * versions and name paths only, at most 100 paths per change and 64 names per path; additions
 * record the base graph's versions of the package (`base_versions`), which gate 3 needs to judge
 * a new instance next to an old line.
 */
export function toDependencyChanges(diff: GraphDiff): DependencyChangesEvidence {
  const ordered =
    diff.changes.length <= MAX_DEPENDENCY_CHANGES
      ? diff.changes
      : [
          ...diff.changes.filter((c) => changeReviewKinds(c, c.baseVersions ?? []).length > 0),
          ...diff.changes.filter((c) => changeReviewKinds(c, c.baseVersions ?? []).length === 0),
        ];
  const changes = ordered.slice(0, MAX_DEPENDENCY_CHANGES).map((change) =>
    dependencyChangeSchema.parse({
      name: change.name,
      from: change.from,
      to: change.to,
      change: change.change,
      bump: change.bump,
      is_direct: change.isDirect,
      is_dev: change.isDev,
      paths: change.paths
        .slice(0, MAX_EVIDENCE_PATHS)
        .map((path) => path.slice(-GRAPH_LIMITS.maxPathDepth).map((key) => nameOfKey(key))),
      ...(change.change === "added" && change.to !== null
        ? { base_versions: evidenceBaseVersions(change.to, change.baseVersions ?? []) }
        : {}),
    }),
  );
  return { changes, truncated: diff.changes.length > MAX_DEPENDENCY_CHANGES };
}
