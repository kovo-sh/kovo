import type { MemberKind } from "./classify.js";

// The project-count preview of one classification declaration (plans/monorepo-projects.md §5.2
// and §5.3; the M10b "overrides with billing preview"). Pure and transient: identifiers in, member
// paths out. It applies the declaration to a workspace install root's current projects with the
// classifier's own project rules: every app is a project, and a workspace root with no app is one
// library bundle at '.'. Rule 3's same-component interaction (an app in a cycle with a framework
// leaf keeps that leaf a library) is re-evaluated only by the next discovery, which applies the
// declaration to the full workspace graph; the preview is the count the customer is shown and
// nothing is charged from it (paid capacity is still only the billing preview and confirm).

/** A current project of the install root, as inventory recorded it (`projects`). */
export interface RootProject {
  readonly path: string;
  readonly kind: MemberKind | "library_bundle";
}

export interface ClassificationPreview {
  /** The member's kind before the declaration: app when it is a current app project. */
  readonly currentKind: MemberKind;
  /** The root's projects after the declaration, by path. */
  readonly projects: readonly RootProject[];
  /** Projects the declaration adds (path and kind are a project's identity), by path. */
  readonly added: readonly RootProject[];
  /** Current projects the declaration removes, by path. */
  readonly removed: readonly RootProject[];
}

const BUNDLE: RootProject = { path: ".", kind: "library_bundle" };

/** The root's projects once `member` is declared `kind` (or its declaration is withdrawn to it). */
export function previewMemberClassification(input: {
  readonly projects: readonly RootProject[];
  readonly member: string;
  readonly kind: MemberKind;
}): ClassificationPreview {
  const apps = new Set(
    input.projects.filter((project) => project.kind === "app").map((project) => project.path),
  );
  const currentKind: MemberKind = apps.has(input.member) ? "app" : "library";
  if (input.kind === "app") apps.add(input.member);
  else apps.delete(input.member);
  const projects: readonly RootProject[] =
    apps.size === 0
      ? [BUNDLE]
      : [...apps].toSorted(compare).map((path) => ({ path, kind: "app" as const }));
  const key = (project: RootProject) => `${project.kind}\u0000${project.path}`;
  const before = new Set(input.projects.map(key));
  const after = new Set(projects.map(key));
  return {
    currentKind,
    projects,
    added: projects.filter((project) => !before.has(key(project))),
    removed: input.projects
      .filter((project) => !after.has(key(project)))
      .toSorted((a, b) => compare(a.path, b.path)),
  };
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
