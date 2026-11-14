import { GlobWorkExceeded } from "../../manifest/glob.js";
import type { LockfileName } from "../parse.js";
import { diffWorkspaceGraphs } from "../workspace/diff.js";
import { importerInstances } from "../workspace/parse.js";
import type { WorkspaceGraph, WorkspaceTreeEntry } from "../workspace/types.js";
import {
  classifyInstallRoots,
  type ClassificationOverrides,
  type ClassifiedRoot,
} from "./classify.js";
import { rootFileOwnership } from "./ownership.js";
import { DISCOVERY_LIMITS, type InstallRoot } from "./types.js";

// M7 slice a (plans/monorepo-projects.md §7.1 "Affected projects" and "Edits"). Pure and
// transient: inputs are trusted immutable reads, outputs are member paths and fixed reason codes.

export type ProjectScopeReason = "out_of_project_scope" | "project_scope_ambiguous";

/** One side (base or candidate) of a single workspace install root, classified and owned. */
export interface ScopedWorkspaceRoot {
  readonly graph: WorkspaceGraph;
  readonly lockfileName: LockfileName;
  readonly classified: ClassifiedRoot;
  readonly files: InstallRoot["files"];
}

/**
 * Classify a parsed workspace root at repository path '.', with the M2 ownership rules and the
 * customer's binding classification overrides (§5.3: keyed by root path, then member path).
 * Returns null when ownership or classification cannot be established (callers refuse that as
 * `project_scope_ambiguous`); single-package roots are not workspaces and are never scoped here.
 */
export function scopeWorkspaceRoot(
  graph: WorkspaceGraph,
  entries: readonly WorkspaceTreeEntry[],
  lockfileName: LockfileName,
  overrides: ClassificationOverrides = {},
): ScopedWorkspaceRoot | null {
  if (!graph.layout.hasWorkspaces) return null;
  let files: InstallRoot["files"];
  try {
    files = rootFileOwnership(".", graph.layout, lockfileName, entries, [], {
      remaining: DISCOVERY_LIMITS.maxWork,
    });
  } catch (error) {
    // A hostile tree exhausting the glob budget has no established ownership.
    if (error instanceof GlobWorkExceeded) return null;
    throw error;
  }
  const classified = classifyInstallRoots(
    [{ path: ".", lockfileName, layout: graph.layout, excludedTrees: [], files }],
    overrides,
  );
  if (!classified.ok || classified.roots.length !== 1) return null;
  return { graph, lockfileName, classified: classified.roots[0]!, files };
}

export interface ChangedMembers {
  /** Member paths whose owned files, manifest, declarations or resolved instances changed. */
  readonly members: ReadonlySet<string>;
  /**
   * A root-shared source changed (root manifest, including overrides/resolutions, the workspace
   * manifest and its catalogs, or shared configuration). It may affect every project in the root.
   */
  readonly rootShared: boolean;
}

/**
 * Today's workspace invalidation rules (`diffWorkspaceGraphs`, importer instance reachability),
 * evaluated on both sides, plus the owners of changed files on both sides.
 */
export function changedWorkspaceMembers(
  base: ScopedWorkspaceRoot,
  candidate: ScopedWorkspaceRoot,
  changedPaths: readonly string[],
): ChangedMembers {
  const members = new Set<string>();
  let rootShared = false;
  for (const side of [base, candidate]) {
    const owners = new Map(side.files.map((file) => [file.path, file]));
    for (const path of changedPaths) {
      const owner = owners.get(path);
      if (owner === undefined) continue;
      // The lockfile's effect is attributed below through the instances it changes.
      if (owner.access === "shared_editable" && path === side.lockfileName) continue;
      if (owner.access === "owned") members.add(owner.member);
      else rootShared = true;
    }
  }
  const diff = diffWorkspaceGraphs(base.graph, candidate.graph);
  if (diff.workspaceConfigChanged || diff.manifestsChanged.includes(".")) rootShared = true;
  for (const path of [
    ...diff.addedMembers,
    ...diff.removedMembers,
    ...diff.declarationsChanged,
    ...diff.manifestsChanged,
  ])
    members.add(path);
  const changed = new Set(diff.instancesChanged);
  if (changed.size > 0) {
    for (const graph of [base.graph, candidate.graph]) {
      for (const id of changed) {
        const local = graph.instances.get(id)?.localMember;
        if (local !== undefined) members.add(local);
      }
      for (const importer of graph.importers) {
        if (members.has(importer.member.path)) continue;
        for (const id of importerInstances(graph, importer.member.path))
          if (changed.has(id)) {
            members.add(importer.member.path);
            break;
          }
      }
    }
  }
  return { members, rootShared };
}

/** Members a project covers on one side: itself and its library closure. */
function covered(project: ClassifiedRoot["projects"][number]): readonly string[] {
  return [project.path, ...project.closure];
}

/**
 * Affected projects on the union of the base and candidate graphs: a project is affected when a
 * changed member is in its base or candidate closure, when a root-shared source changed, or when
 * it requires (app-to-app) an affected app. A removed edge therefore never shrinks the set below
 * the base graph's.
 */
export function affectedWorkspaceProjects(
  base: ScopedWorkspaceRoot,
  candidate: ScopedWorkspaceRoot,
  changed: ChangedMembers,
): readonly string[] {
  const affected = new Set<string>();
  for (const side of [base, candidate])
    for (const project of side.classified.projects)
      if (changed.rootShared || covered(project).some((path) => changed.members.has(path)))
        affected.add(project.path);
  // Reverse local dependents across app-to-app edges, on both sides, to a fixed point.
  const edges = [...base.classified.appEdges, ...candidate.classified.appEdges];
  for (let grew = true; grew;) {
    grew = false;
    for (const edge of edges)
      if (affected.has(edge.to) && !affected.has(edge.from)) {
        affected.add(edge.from);
        grew = true;
      }
  }
  return [...affected].toSorted(compare);
}

export type ProjectEditScope =
  | {
      readonly ok: true;
      readonly affected: readonly string[];
      readonly protectedAffected: readonly string[];
    }
  | { readonly ok: false; readonly reason: ProjectScopeReason };

/**
 * Scoped edits: a fix may change only files owned by members in the base closures of the affected
 * protected projects, plus the root's shared editable files (lockfile, root package.json, root
 * workspace manifest), whose edits the existing ladder checks still confine. Shared read-only
 * configuration is never edited. Protected identity and edit permission come from the base
 * (trusted) side; the candidate can never widen them.
 */
export function projectEditScope(input: {
  readonly base: ScopedWorkspaceRoot | null;
  readonly candidate: ScopedWorkspaceRoot | null;
  readonly changedPaths: readonly string[];
  /** Protected project paths in this install root. */
  readonly protectedProjects: readonly string[];
}): ProjectEditScope {
  const ambiguous = { ok: false, reason: "project_scope_ambiguous" } as const;
  const outside = { ok: false, reason: "out_of_project_scope" } as const;
  const { base, candidate } = input;
  if (base === null || candidate === null) return ambiguous;
  const baseProjects = new Map(base.classified.projects.map((project) => [project.path, project]));
  const candidateProjects = new Map(
    candidate.classified.projects.map((project) => [project.path, project]),
  );
  for (const path of input.protectedProjects) {
    const before = baseProjects.get(path);
    const after = candidateProjects.get(path);
    // A protected project the candidate removes or reclassifies has no single identity.
    if (before === undefined || after === undefined || before.kind !== after.kind) return ambiguous;
  }
  const changed = changedWorkspaceMembers(base, candidate, input.changedPaths);
  const affected = affectedWorkspaceProjects(base, candidate, changed);
  const selected = new Set(input.protectedProjects);
  const protectedAffected = affected.filter((path) => selected.has(path));
  const inScope = new Set(protectedAffected.flatMap((path) => covered(baseProjects.get(path)!)));
  const baseMembers = new Set(base.graph.layout.members.map((member) => member.path));
  const baseFiles = new Map(base.files.map((file) => [file.path, file]));
  const candidateFiles = new Map(candidate.files.map((file) => [file.path, file]));
  let refused: ProjectScopeReason | null = null;
  for (const path of input.changedPaths) {
    const before = baseFiles.get(path);
    const after = candidateFiles.get(path);
    if (
      before !== undefined &&
      after !== undefined &&
      (before.member !== after.member || before.access !== after.access)
    )
      return ambiguous;
    const owner = before ?? after;
    if (owner === undefined) {
      refused = "out_of_project_scope";
      continue;
    }
    // A file under a member the base does not declare has no trusted owner.
    if (!baseMembers.has(owner.member)) return ambiguous;
    const allowed =
      owner.access === "shared_editable"
        ? protectedAffected.length > 0
        : owner.access === "owned" && inScope.has(owner.member);
    if (!allowed) refused = "out_of_project_scope";
  }
  if (refused !== null) return outside;
  return { ok: true, affected, protectedAffected };
}

/**
 * Members a fix may edit before a candidate exists (fix planning): the base closures of the
 * protected projects that cover any of `members`, or any protected project when a root-shared
 * source is involved.
 */
export function plannedScopeMembers(
  base: ScopedWorkspaceRoot,
  protectedProjects: readonly string[],
  members: readonly string[],
  rootShared: boolean,
): readonly string[] {
  const selected = new Set(protectedProjects);
  const touched = new Set(members);
  const scope = new Set<string>();
  for (const project of base.classified.projects) {
    if (!selected.has(project.path)) continue;
    const paths = covered(project);
    if (rootShared || paths.some((path) => touched.has(path)))
      for (const path of paths) scope.add(path);
  }
  return [...scope].toSorted(compare);
}

/**
 * The ladder planner's project scope for one target package (fix planning, M7 scoped edits): the
 * members whose importer graphs hold an affected registry instance of the target are the members
 * the fix touches, and a root importer holding one touches the root manifest, a root-shared
 * source, exactly as `changedWorkspaceMembers` later attributes that edit.
 */
export function plannedTargetScopeMembers(
  base: ScopedWorkspaceRoot,
  protectedProjects: readonly string[],
  target: { readonly name: string; readonly affectedVersions: readonly string[] },
): readonly string[] {
  const graph = base.graph;
  const targets = new Set(
    [...graph.instances.values()]
      .filter(
        (node) =>
          node.localMember === undefined &&
          node.name === target.name &&
          target.affectedVersions.includes(node.version),
      )
      .map((node) => node.id),
  );
  const members = graph.importers
    .filter((importer) =>
      [...importerInstances(graph, importer.member.path)].some((id) => targets.has(id)),
    )
    .map((importer) => importer.member.path);
  return plannedScopeMembers(base, protectedProjects, members, members.includes("."));
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
