import { z } from "zod";

import { workspaceRootHasApplication } from "../../recipe/workspace.js";
import { canonicalWorkspacePath } from "../workspace/discover.js";
import { WORKSPACE_LIMITS, type WorkspaceMember } from "../workspace/types.js";
import { DISCOVERY_LIMITS, type InstallRoot } from "./types.js";

/** Agent interpretation pending owner review (#2140); changes require a new version. */
export const APPLICATION_FRAMEWORKS = {
  version: 1,
  names: [
    "next",
    "nuxt",
    "@remix-run/*",
    "react-router",
    "vite",
    "astro",
    "@sveltejs/kit",
    "express",
    "fastify",
    "koa",
    "hono",
    "@nestjs/core",
    "electron",
    "expo",
    "react-native",
  ],
} as const;

export type MemberKind = "app" | "library";
export type ClassificationRule =
  | "override_v1"
  | "apps_path_v1"
  | "leaf_framework_v1"
  | "library_v1"
  | "root_application_v1";
/** Both keys are relative paths: repository root path, then install-root member path. */
export type ClassificationOverrides = Readonly<
  Record<string, Readonly<Record<string, MemberKind>>>
>;
export interface ClassifiedMember {
  readonly path: string;
  readonly name: string | null;
  readonly kind: MemberKind;
  readonly ruleId: ClassificationRule;
}
export interface ClassifiedProject {
  readonly path: string;
  readonly name: string | null;
  readonly kind: MemberKind | "library_bundle";
  readonly ruleId: ClassificationRule | "single_package_v1" | "library_bundle_v1";
  /** Library members only for apps; all members for a library bundle. */
  readonly closure: readonly string[];
}
export interface ClassifiedRoot {
  readonly path: string;
  readonly members: readonly ClassifiedMember[];
  readonly projects: readonly ClassifiedProject[];
  /** Direct local edges between apps; also reached through libraries, stopping at another app. */
  readonly appEdges: readonly { readonly from: string; readonly to: string }[];
}
export type ClassificationResult =
  | { readonly ok: true; readonly roots: readonly ClassifiedRoot[] }
  | {
      readonly ok: false;
      readonly reason: "invalid_classification_input" | "too_many_projects" | "too_large";
    };

const pathSchema = z
  .string()
  .max(1024)
  .refine((path) => canonicalWorkspacePath(path, true));
const overridesSchema = z.record(pathSchema, z.record(pathSchema, z.enum(["app", "library"])));

/** Pure, transient M2 output in; explicitly constructed identifier-only projection out. */
export function classifyInstallRoots(
  roots: readonly InstallRoot[],
  overrides: unknown = {},
): ClassificationResult {
  const fail = (
    reason: Extract<ClassificationResult, { ok: false }>["reason"],
  ): ClassificationResult => ({ ok: false, reason });
  if (roots.length > DISCOVERY_LIMITS.maxRoots) return fail("too_many_projects");
  // Zod records intentionally omit __proto__; reject it explicitly rather than silently
  // losing a binding override. Ordinary own directory keys such as constructor remain valid.
  if (overrides !== null && typeof overrides === "object") {
    if (Object.hasOwn(overrides, "__proto__")) return fail("invalid_classification_input");
    for (const value of Object.values(overrides)) {
      if (value !== null && typeof value === "object" && Object.hasOwn(value, "__proto__"))
        return fail("invalid_classification_input");
    }
  }
  const parsed = overridesSchema.safeParse(overrides);
  if (!parsed.success) return fail("invalid_classification_input");
  if (JSON.stringify(parsed.data).length * 3 > 256 * 1024) return fail("too_large");
  const output: ClassifiedRoot[] = [];
  let projects = 0;
  let work = DISCOVERY_LIMITS.maxGraphWork;
  const rootPaths = new Set<string>();
  for (const root of roots.toSorted((a, b) => compare(a.path, b.path))) {
    if (!canonicalWorkspacePath(root.path, true) || rootPaths.has(root.path))
      return fail("invalid_classification_input");
    rootPaths.add(root.path);
    const members = root.layout.members.toSorted((a, b) => compare(a.path, b.path));
    if (members.length > WORKSPACE_LIMITS.maxMembers + 1) return fail("too_large");
    const paths = new Set(members.map((member) => member.path));
    if (
      !paths.has(".") ||
      paths.size !== members.length ||
      members.some((member) => !canonicalWorkspacePath(member.path, true)) ||
      (!root.layout.hasWorkspaces && members.length !== 1)
    )
      return fail("invalid_classification_input");
    const edges = new Map<string, string[]>();
    for (const member of members) {
      if (member.local.some((edge) => !paths.has(edge.target)))
        return fail("invalid_classification_input");
      work -= member.local.length + 1;
      if (work < 0) return fail("too_large");
      edges.set(
        member.path,
        [...new Set(member.local.map((edge) => edge.target))].toSorted(compare),
      );
    }
    const components = stronglyConnected(paths, edges);
    const dependent = new Set<number>();
    for (const [from, targets] of edges)
      for (const to of targets) {
        if (components.get(from) !== components.get(to)) dependent.add(components.get(to)!);
      }
    const rootOverrides = Object.hasOwn(parsed.data, root.path)
      ? parsed.data[root.path]
      : undefined;
    const tree = root.files.map(({ path }) =>
      root.path === "." ? path : path.slice(root.path.length + 1),
    );
    const rootApp = workspaceRootHasApplication(root.layout, tree);
    const preliminary = members.map((member): ClassifiedMember => {
      const override =
        rootOverrides !== undefined && Object.hasOwn(rootOverrides, member.path)
          ? rootOverrides[member.path]
          : undefined;
      if (override !== undefined) return identity(member, override, "override_v1");
      if (member.path.startsWith("apps/")) return identity(member, "app", "apps_path_v1");
      if (member.path === "." && rootApp) return identity(member, "app", "root_application_v1");
      return identity(member, "library", "library_v1");
    });
    const appComponents = new Set(
      preliminary
        .filter((member) => member.kind === "app")
        .map((member) => components.get(member.path)),
    );
    // Resolve the entire SCC at once. A rule-3-only SCC can contain several app candidates;
    // none is allowed to become an app merely because iteration encountered it first.
    const candidates = members.filter(
      (member, index) =>
        member.path !== "." &&
        preliminary[index]!.ruleId === "library_v1" &&
        !dependent.has(components.get(member.path)!) &&
        !appComponents.has(components.get(member.path)) &&
        frameworkApplication(member),
    );
    const candidateCounts = new Map<number, number>();
    for (const member of candidates) {
      const component = components.get(member.path)!;
      candidateCounts.set(component, (candidateCounts.get(component) ?? 0) + 1);
    }
    const candidatePaths = new Set(
      candidates
        .filter((member) => candidateCounts.get(components.get(member.path)!) === 1)
        .map((member) => member.path),
    );
    const classified = preliminary.map((member) =>
      candidatePaths.has(member.path)
        ? {
            path: member.path,
            name: member.name,
            kind: "app" as const,
            ruleId: "leaf_framework_v1" as const,
          }
        : member,
    );
    const byPath = new Map(classified.map((member) => [member.path, member]));
    const apps = classified.filter((member) => member.kind === "app");
    const appEdges: { from: string; to: string }[] = [];
    const rootProjects: ClassifiedProject[] = [];
    for (const app of apps) {
      const closure = new Set<string>();
      const required = new Set<string>();
      const seen = new Set([app.path]);
      const queue = [...(edges.get(app.path) ?? [])];
      while (queue.length > 0) {
        work -= 1;
        if (work < 0) return fail("too_large");
        const path = queue.pop()!;
        if (seen.has(path)) continue;
        seen.add(path);
        if (byPath.get(path)!.kind === "app") {
          required.add(path);
          continue;
        }
        closure.add(path);
        queue.push(...(edges.get(path) ?? []));
      }
      rootProjects.push({ ...app, closure: [...closure].toSorted(compare) });
      for (const to of [...required].toSorted(compare)) appEdges.push({ from: app.path, to });
    }
    if (!root.layout.hasWorkspaces) {
      const member = classified[0]!;
      rootProjects.splice(0, rootProjects.length, {
        ...member,
        ruleId: "single_package_v1",
        closure: [],
      });
    } else if (apps.length === 0) {
      rootProjects.push({
        path: ".",
        name: members[0]!.manifest.name,
        kind: "library_bundle",
        ruleId: "library_bundle_v1",
        closure: classified.map((member) => member.path),
      });
    }
    projects += rootProjects.length;
    if (projects > 100) return fail("too_many_projects");
    output.push({ path: root.path, members: classified, projects: rootProjects, appEdges });
  }
  return { ok: true, roots: output };
}

function identity(
  member: WorkspaceMember,
  kind: MemberKind,
  ruleId: ClassificationRule,
): ClassifiedMember {
  return { path: member.path, name: member.manifest.name, kind, ruleId };
}
function frameworkApplication(member: WorkspaceMember): boolean {
  return (
    ["start", "dev", "serve", "build"].some((script) =>
      Object.hasOwn(member.manifest.scripts, script),
    ) &&
    member.manifest.dependencies.some(({ name }) =>
      APPLICATION_FRAMEWORKS.names.some((framework) =>
        framework === "@remix-run/*" ? name.startsWith("@remix-run/") : name === framework,
      ),
    )
  );
}
function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Tarjan over validated, bounded local members (at most 101), never registry dependencies. */
function stronglyConnected(
  paths: ReadonlySet<string>,
  edges: ReadonlyMap<string, readonly string[]>,
): Map<string, number> {
  const indices = new Map<string, number>();
  const low = new Map<string, number>();
  const stack: string[] = [];
  const active = new Set<string>();
  const components = new Map<string, number>();
  let component = 0;
  const visit = (path: string): void => {
    const index = indices.size;
    indices.set(path, index);
    low.set(path, index);
    stack.push(path);
    active.add(path);
    for (const target of edges.get(path) ?? []) {
      if (!indices.has(target)) {
        visit(target);
        low.set(path, Math.min(low.get(path)!, low.get(target)!));
      } else if (active.has(target)) low.set(path, Math.min(low.get(path)!, indices.get(target)!));
    }
    if (low.get(path) !== index) return;
    let target: string;
    do {
      target = stack.pop()!;
      active.delete(target);
      components.set(target, component);
    } while (target !== path);
    component += 1;
  };
  for (const path of paths) if (!indices.has(path)) visit(path);
  return components;
}
