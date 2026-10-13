import {
  dependencyVerdictChangeSchema,
  type DependencyVerdictChangeWire,
  type UnsupportedRepoReason,
} from "@kovo/contracts";
import { dependencySourceOf } from "@kovo/core/dependency-verdicts";
import {
  aggregateWorkspaceGraph,
  classifyVersionChange,
  diffGraphs,
  indexPackages,
  packageKey,
  parseLockfile,
  parseWorkspaceGraph,
  type DependencyGraph,
  type LockfileName,
  type ResolvedPackageNode,
  type WorkspaceInput,
} from "@kovo/core/lockfile";
import { parsePackageJson } from "@kovo/core/manifest";

// The change list `kovo deps check` sends (plans/dependency-firewall.md Part 2 "Distribution for any
// CI"): the changed and new versions between a base and a head lockfile, as
// `dependencyVerdictChangeSchema` items, identifiers only. Pure: the caller reads the files into
// memory and passes their text; nothing here does I/O, and no lockfile or manifest text leaves this
// module. Graphs and diffs are `@kovo/core/lockfile`'s, the same code Kovo's PR gate uses.

/** One side of the diff: the files a lockfile's graph is parsed from. */
export interface ProjectSnapshot {
  /** The lockfile's text; never persisted or printed. */
  readonly lockfile: string;
  /** The project's root package.json text, when it exists (Yarn v1 graphs need it). */
  readonly manifest: string | null;
  /**
   * The project's complete tree, with the text of every workspace authority file, for a workspace
   * lockfile. Absent until a single-package parse reports a workspace.
   */
  readonly workspace?: WorkspaceInput;
}

/** Why a lockfile cannot be judged: Kovo's stable unsupported reason and the parser's reasons. */
export interface UnsupportedLockfile {
  readonly unsupported: UnsupportedRepoReason;
  /** The parser's reason codes, deduplicated (lockfile rejections or a workspace reason). */
  readonly reasons: readonly string[];
  /** Packages the reasons name, when the lockfile names valid ones (at most 20). */
  readonly packages: readonly string[];
}

export type SnapshotGraph =
  | { readonly ok: true; readonly graph: DependencyGraph }
  /** A workspace: parse again with the project's tree in `ProjectSnapshot.workspace`. */
  | { readonly ok: false; readonly needsWorkspace: true }
  | { readonly ok: false; readonly needsWorkspace: false; readonly refusal: UnsupportedLockfile };

const MAX_NAMED_PACKAGES = 20;

function refused(
  unsupported: UnsupportedRepoReason,
  reasons: readonly string[],
  packages: readonly (string | null)[] = [],
): SnapshotGraph {
  return {
    ok: false,
    needsWorkspace: false,
    refusal: {
      unsupported,
      reasons: [...new Set(reasons)].toSorted(),
      packages: [...new Set(packages.filter((name) => name !== null))]
        .toSorted()
        .slice(0, MAX_NAMED_PACKAGES),
    },
  };
}

function workspaceGraph(fileName: LockfileName, snapshot: ProjectSnapshot): SnapshotGraph {
  if (snapshot.workspace === undefined) return { ok: false, needsWorkspace: true };
  const parsed = parseWorkspaceGraph(snapshot.workspace, { fileName, text: snapshot.lockfile });
  if (!parsed.ok)
    return refused(parsed.reason === "resource_limit" ? "too_large" : "workspaces", [
      parsed.reason,
    ]);
  if (!parsed.value.layout.hasWorkspaces) return refused("workspaces", ["unsupported_layout"]);
  try {
    return { ok: true, graph: aggregateWorkspaceGraph(parsed.value) };
  } catch (error) {
    if (error instanceof RangeError) return refused("workspaces", ["invalid_lockfile"]);
    throw error;
  }
}

/**
 * The graph a snapshot's lockfile resolves: the single-package parse first, then (for a workspace)
 * the workspace parse aggregated over every member, as Kovo's verification reads a repository.
 */
export function snapshotGraph(fileName: LockfileName, snapshot: ProjectSnapshot): SnapshotGraph {
  let manifest;
  if (fileName === "yarn.lock") {
    if (snapshot.manifest === null) return refused("missing_package_json", ["missing_manifest"]);
    const parsed = parsePackageJson({
      text: snapshot.manifest,
      packageManager: "yarn",
      pnpmWorkspaceYamlPresent: false,
    });
    if (!parsed.ok) {
      if (parsed.unsupported === "workspaces") return workspaceGraph(fileName, snapshot);
      return refused(
        parsed.unsupported,
        parsed.rejections.map((rejection) => rejection.reason),
      );
    }
    manifest = parsed.manifest;
  }
  const parsed = parseLockfile({
    fileName,
    text: snapshot.lockfile,
    ...(manifest === undefined ? {} : { manifest }),
  });
  if (parsed.ok) return { ok: true, graph: parsed.graph };
  if (parsed.unsupported === "workspaces") return workspaceGraph(fileName, snapshot);
  return refused(
    parsed.unsupported,
    parsed.rejections.map((rejection) => rejection.reason),
    parsed.rejections.map((rejection) => rejection.package),
  );
}

/** `a` orders before `b` (SemVer precedence; build metadata ignored). */
function before(a: string, b: string): boolean {
  return classifyVersionChange(a, b)?.direction === "upgraded";
}

/**
 * The version a new instance of an already-resolved package steps from: the highest base version at
 * or below it, else the lowest above it (as decideMerge judges a new instance next to an old line).
 */
function nearestBaseVersion(to: string, baseVersions: readonly string[]): string | null {
  const below = baseVersions.filter((version) => !before(to, version));
  const pool = below.length > 0 ? below : baseVersions;
  let nearest: string | null = null;
  for (const version of pool) {
    if (nearest === null) nearest = version;
    else if (below.length > 0 ? before(nearest, version) : before(version, nearest))
      nearest = version;
  }
  return nearest;
}

function emptyGraph(like: DependencyGraph): DependencyGraph {
  return {
    packageManager: like.packageManager,
    format: like.format,
    direct: [],
    packages: [],
    unresolved: [],
    lockfileOverrides: [],
  };
}

function wireChange(
  node: ResolvedPackageNode,
  previousVersion: string | null,
): DependencyVerdictChangeWire {
  const parsed = dependencyVerdictChangeSchema.safeParse({
    ecosystem: "npm",
    name: node.name,
    version: node.version,
    integrity: node.integrity,
    kind: previousVersion === null ? "new" : "changed",
    direct: node.isDirect,
    previous_version: previousVersion,
    source: dependencySourceOf(node.resolved, node.name, node.version),
  });
  if (!parsed.success) throw new RangeError("a changed version does not fit the change schema");
  return parsed.data;
}

/**
 * Every version the head graph resolves that the base graph does not, as wire changes, sorted by
 * name then version. A base of null (no lockfile at the base) makes every head version new.
 *
 * - An upgrade or downgrade is `changed` from the version it replaces.
 * - A version of a package the base resolves only at other versions is `changed` from the nearest
 *   of them; a package new to the graph is `new`.
 * - A version both graphs resolve whose locked integrity or tarball URL changed is judged again, as
 *   `new`: its integrity is checked against the registry's.
 * - Removals are not judged. Pre-existing versions are never judged (principle 2).
 *
 * Errors: RangeError when a change does not fit the wire schema (the lockfile parser's bounds
 * normally make that impossible) or the diff cannot pair two versions.
 */
export function changeListOf(
  base: DependencyGraph | null,
  head: DependencyGraph,
): DependencyVerdictChangeWire[] {
  const diff = diffGraphs(base ?? emptyGraph(head), head);
  const nodes = indexPackages(head);
  const node = (name: string, version: string): ResolvedPackageNode => {
    const found = nodes.get(packageKey(name, version));
    if (found === undefined) throw new RangeError("a changed version is not in the head graph");
    return found;
  };
  const changes: DependencyVerdictChangeWire[] = [];
  for (const change of diff.changes) {
    if (change.to === null) continue;
    const previous =
      change.change === "added"
        ? nearestBaseVersion(change.to, change.baseVersions ?? [])
        : change.from;
    changes.push(wireChange(node(change.name, change.to), previous));
  }
  for (const changed of diff.integrityChanges)
    changes.push(wireChange(node(changed.name, changed.version), null));
  return changes.toSorted(compareChanges);
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** By name, then SemVer precedence, then the version string (build metadata). */
export function compareChanges(
  a: Pick<DependencyVerdictChangeWire, "name" | "version">,
  b: Pick<DependencyVerdictChangeWire, "name" | "version">,
): number {
  if (a.name !== b.name) return compareStrings(a.name, b.name);
  if (before(a.version, b.version)) return -1;
  if (before(b.version, a.version)) return 1;
  return compareStrings(a.version, b.version);
}

export type ChangeListResult =
  | { readonly ok: true; readonly changes: readonly DependencyVerdictChangeWire[] }
  | { readonly ok: false; readonly side: "base" | "head"; readonly refusal: UnsupportedLockfile };

/**
 * The change list between two snapshots of the same lockfile, or why one side cannot be judged.
 * Both snapshots must already carry their workspace tree when `snapshotGraph` asked for it.
 */
export function lockfileChangeList(
  fileName: LockfileName,
  base: ProjectSnapshot | null,
  head: ProjectSnapshot,
): ChangeListResult {
  const graphs: Partial<Record<"base" | "head", DependencyGraph>> = {};
  for (const [side, snapshot] of [
    ["base", base],
    ["head", head],
  ] as const) {
    if (snapshot === null) continue;
    const parsed = snapshotGraph(fileName, snapshot);
    if (parsed.ok) graphs[side] = parsed.graph;
    else
      return {
        ok: false,
        side,
        refusal: parsed.needsWorkspace
          ? { unsupported: "workspaces", reasons: ["incomplete_tree"], packages: [] }
          : parsed.refusal,
      };
  }
  const headGraph = graphs.head;
  if (headGraph === undefined) throw new RangeError("the head graph is missing");
  try {
    return { ok: true, changes: changeListOf(graphs.base ?? null, headGraph) };
  } catch (error) {
    if (error instanceof RangeError)
      return {
        ok: false,
        side: "head",
        refusal: { unsupported: "unsupported_lockfile_format", reasons: ["diff"], packages: [] },
      };
    throw error;
  }
}
