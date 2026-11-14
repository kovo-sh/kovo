import type { ClosureFallbackCause } from "@kovo/contracts";

import { affectedClosure } from "./affected-closure.js";
import {
  affectedWorkspaceProjects,
  changedWorkspaceMembers,
  type ScopedWorkspaceRoot,
} from "./project-scope.js";

// M7 slice b (plans/monorepo-projects.md §7.1 "Verification" and "Disclosure"). Pure and
// transient: inputs are trusted immutable reads and the stored protection selection; outputs are
// project identities, member paths and fixed reason codes, never file contents.

/** One protected project of the repository's complete protection selection. */
export interface ProtectedProject {
  readonly projectId: string;
  readonly installRootId: string;
  /** The project's path inside its install root (`.` for a root app or a single-package root). */
  readonly path: string;
  /** The project's own active recipe version; null when it has none yet. */
  readonly recipeVersionId: string | null;
  /** The selection generation: when this protection was enabled (ISO 8601, UTC). */
  readonly enabledAt: string;
}

/**
 * The repository's complete protection selection, or null for today's repository-wide protection
 * (no selection written, or a single-project repository, whose one project is the repository).
 */
export interface ProtectionSnapshot {
  readonly projects: readonly ProtectedProject[];
}

export type ProjectVerificationReason =
  | "project_scope_ambiguous"
  | "out_of_project_scope"
  | "required_app_unprotected"
  | "project_recipe_missing";

/**
 * The affected-closure outcome of a per-project plan (#8256 R8): `affected` counts the affected
 * projects of the install root among `total`; `fallback_all` ran every protected project of the
 * root because the graph was unknown or ambiguous (`closure_fallback_all`, with its cause).
 */
export type ProjectClosure =
  | { readonly mode: "affected"; readonly affected: number; readonly total: number }
  | { readonly mode: "fallback_all"; readonly cause: ClosureFallbackCause };

export type ProjectVerificationPlan =
  /** Today's verification: the repository recipe, exactly as before (single project, or no selection). */
  | { readonly ok: true; readonly mode: "repository" }
  | {
      readonly ok: true;
      readonly mode: "projects";
      /** Every affected protected project in the root, each verified with its own recipe. */
      readonly verify: readonly ProtectedProject[];
      /** Affected unprotected projects (by path): disclosed, never verified (C2). */
      readonly unverified: readonly string[];
      /** How the affected set was found (#8256 R8): its closure, or every project, disclosed. */
      readonly closure: ProjectClosure;
    }
  | { readonly ok: false; readonly reason: ProjectVerificationReason };

/**
 * Which projects a fix's verification covers. `protection` null keeps today's repository-wide
 * verification; a single-package root is one project and also keeps it when that project is
 * protected. In a workspace root, verification covers exactly the affected protected projects
 * (affected on the union of the base and candidate graphs, M7a), and the affected unprotected
 * projects are disclosed by path. Protected identity comes from the base (trusted) side.
 */
export function planProjectVerification(input: {
  readonly installRootId: string;
  readonly root:
    | { readonly kind: "single_package" }
    | {
        readonly kind: "workspace";
        readonly base: ScopedWorkspaceRoot | null;
        readonly candidate: ScopedWorkspaceRoot | null;
        readonly changedPaths: readonly string[];
      };
  readonly protection: ProtectionSnapshot | null;
  /**
   * #8256 R8 (`worker.affectedClosureEnabled`, default on): the member closure widens the
   * affected set and an unknown or ambiguous graph runs every protected project. Off restores
   * M7 exactly: a missing graph is refused and only the classified closure decides.
   */
  readonly closure?: boolean;
}): ProjectVerificationPlan {
  if (input.protection === null) return { ok: true, mode: "repository" };
  const inRoot = input.protection.projects.filter(
    (project) => project.installRootId === input.installRootId,
  );
  const root = input.root;
  if (root.kind === "single_package") {
    // One project per single-package root: protected keeps today's verification exactly.
    if (inRoot.length === 0) return { ok: false, reason: "out_of_project_scope" };
    if (inRoot.length > 1 || inRoot[0]!.path !== ".")
      return { ok: false, reason: "project_scope_ambiguous" };
    return { ok: true, mode: "repository" };
  }
  const { base, candidate } = root;
  const r8 = input.closure !== false;
  if (!r8 && (base === null || candidate === null))
    return { ok: false, reason: "project_scope_ambiguous" };
  const sides = [base, candidate].filter((side): side is ScopedWorkspaceRoot => side !== null);
  const kinds = sides.map(
    (side) => new Map(side.classified.projects.map((project) => [project.path, project.kind])),
  );
  const byPath = new Map<string, ProtectedProject>();
  for (const project of inRoot) {
    // A protected project the base does not declare, or the candidate removes or reclassifies,
    // has no single identity; duplicate selections of one path are never resolved by guessing.
    // A side whose graph is unavailable (#8256 R8 fallback) cannot contradict it; each project's
    // own run re-derives its member commands at the base and refuses a lost identity.
    const seen = new Set(kinds.map((side) => side.get(project.path)));
    if (seen.has(undefined) || seen.size > 1 || byPath.has(project.path))
      return { ok: false, reason: "project_scope_ambiguous" };
    byPath.set(project.path, project);
  }
  // App-to-app: a protected app may require only protected apps, on either side (§4).
  for (const edge of sides.flatMap((side) => side.classified.appEdges))
    if (byPath.has(edge.from) && !byPath.has(edge.to))
      return { ok: false, reason: "required_app_unprotected" };
  // #8256 R8: the dependency closure of the change, on the union of both graphs. An unknown or
  // ambiguous graph (a side unavailable, a cycle, an unknown importer) affects every project:
  // every protected project of the root runs (`closure_fallback_all`, disclosed), and every
  // unprotected one is disclosed.
  const projectPaths = [
    ...new Set(sides.flatMap((side) => side.classified.projects.map((project) => project.path))),
  ].toSorted(compare);
  let affected: readonly string[];
  let closure: ProjectClosure;
  const changed =
    base === null || candidate === null
      ? null
      : changedWorkspaceMembers(base, candidate, root.changedPaths);
  const members =
    base === null || candidate === null || changed === null
      ? affectedClosure({ base: null, candidate: null, changed: NOTHING_CHANGED })
      : r8
        ? affectedClosure({ base: base.graph, candidate: candidate.graph, changed })
        : ({ kind: "affected", members: [], total: 0 } as const);
  if (members.kind === "all" || base === null || candidate === null || changed === null) {
    affected = [...new Set([...projectPaths, ...byPath.keys()])].toSorted(compare);
    closure = {
      mode: "fallback_all",
      cause: members.kind === "all" ? members.cause : "graph_unavailable",
    };
  } else {
    // M7's classified closure, widened by R8's member closure: never smaller than either.
    const inClosure = new Set(members.members);
    affected = [
      ...new Set([
        ...affectedWorkspaceProjects(base, candidate, changed),
        ...projectPaths.filter((path) => inClosure.has(path)),
      ]),
    ].toSorted(compare);
    closure = { mode: "affected", affected: affected.length, total: projectPaths.length };
  }
  const verify = affected.flatMap((path) => {
    const project = byPath.get(path);
    return project === undefined ? [] : [project];
  });
  if (verify.length === 0) return { ok: false, reason: "out_of_project_scope" };
  if (verify.some((project) => project.recipeVersionId === null))
    return { ok: false, reason: "project_recipe_missing" };
  return {
    ok: true,
    mode: "projects",
    verify,
    unverified: affected.filter((path) => !byPath.has(path)),
    closure,
  };
}

const NOTHING_CHANGED = { members: new Set<string>(), rootShared: false } as const;

/**
 * Canonical text of a protection snapshot, hashed by the caller into `protection_sha256`. Any
 * selection, deselection, re-selection (a new generation) or active-recipe change alters it.
 */
export function protectionCanonical(snapshot: ProtectionSnapshot | null): string {
  if (snapshot === null) return "kovo.project-protection/1\nrepository";
  const lines = snapshot.projects
    .map((project) =>
      [
        project.projectId,
        project.installRootId,
        project.path,
        project.recipeVersionId ?? "-",
        project.enabledAt,
      ].join("\t"),
    )
    .toSorted(compare);
  return ["kovo.project-protection/1", "projects", ...lines].join("\n");
}

/** What per-project verification evidence is bound to (the stored `kovo.project-scope/1` proof). */
export interface ProjectEvidenceBinding {
  readonly installRootId: string;
  readonly baseSha: string;
  /** The verified published head, or null for a staged patch (then `patchSha256` names it). */
  readonly headSha: string | null;
  readonly patchSha256: string | null;
  readonly baseGraphSha256: string;
  readonly candidateGraphSha256: string;
  readonly protectionSha256: string;
  /** The verified protected projects and the recipe version each was verified with. */
  readonly projects: readonly { readonly projectId: string; readonly recipeVersionId: string }[];
  /** Disclosed unprotected project paths. */
  readonly unverifiedPaths: readonly string[];
}

/** The binding a per-project verification must carry for `plan` at this exact candidate. */
export function projectEvidenceBinding(
  plan: Extract<ProjectVerificationPlan, { mode: "projects" }>,
  identity: Omit<ProjectEvidenceBinding, "projects" | "unverifiedPaths">,
): ProjectEvidenceBinding {
  return {
    ...identity,
    projects: plan.verify
      .map((project) => ({
        projectId: project.projectId,
        recipeVersionId: project.recipeVersionId!,
      }))
      .toSorted((a, b) => compare(a.projectId, b.projectId)),
    unverifiedPaths: plan.unverified.toSorted(compare),
  };
}

export type ProjectEvidenceCheck =
  | { readonly ok: true }
  /**
   * `project_protection_changed`: the selection changed during the fix (deselection, a new
   * app-to-app requirement, a re-selection or a new active recipe); the evidence is invalid and
   * the fix re-plans. `project_evidence_mismatch`: the evidence is another set, head, graph or
   * recipe version's, never this candidate's.
   */
  | {
      readonly ok: false;
      readonly reason: "project_protection_changed" | "project_evidence_mismatch";
    };

/** Recorded evidence admits only its exact binding; a protection change always invalidates it. */
export function checkProjectEvidenceBinding(
  recorded: ProjectEvidenceBinding,
  expected: ProjectEvidenceBinding,
): ProjectEvidenceCheck {
  if (recorded.protectionSha256 !== expected.protectionSha256)
    return { ok: false, reason: "project_protection_changed" };
  const sameProjects =
    recorded.projects.length === expected.projects.length &&
    sortedProjects(recorded).every((project, index) => {
      const other = sortedProjects(expected)[index]!;
      return (
        project.projectId === other.projectId && project.recipeVersionId === other.recipeVersionId
      );
    });
  const samePaths =
    recorded.unverifiedPaths.length === expected.unverifiedPaths.length &&
    recorded.unverifiedPaths
      .toSorted(compare)
      .every((path, index) => path === expected.unverifiedPaths.toSorted(compare)[index]);
  if (
    !sameProjects ||
    !samePaths ||
    recorded.installRootId !== expected.installRootId ||
    recorded.baseSha !== expected.baseSha ||
    recorded.headSha !== expected.headSha ||
    recorded.patchSha256 !== expected.patchSha256 ||
    recorded.baseGraphSha256 !== expected.baseGraphSha256 ||
    recorded.candidateGraphSha256 !== expected.candidateGraphSha256
  )
    return { ok: false, reason: "project_evidence_mismatch" };
  return { ok: true };
}

function sortedProjects(binding: ProjectEvidenceBinding) {
  return binding.projects.toSorted((a, b) => compare(a.projectId, b.projectId));
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
