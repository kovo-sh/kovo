import { packageNameSchema } from "@kovo/contracts";

import type { DependencyGraph } from "../types.js";
import type { LockfileName } from "../parse.js";
import { discoverWorkspaces } from "../workspace/discover.js";
import type { RegistryIntegrityFill } from "../registry-source.js";
import { parseWorkspaceGraph } from "../workspace/parse.js";
import { aggregateWorkspaceGraph } from "../workspace/planner.js";
import type { WorkspaceGraph, WorkspaceInput } from "../workspace/types.js";
import { classifyInstallRoots } from "./classify.js";
import { rootFileOwnership } from "./ownership.js";

/** Identifier-only presentation; never retain a manifest or an arbitrary display value. */
export interface GateProjectSection {
  readonly path: string;
  readonly name: string | null;
}

export interface GateRootScope {
  readonly graph: WorkspaceGraph | null;
  readonly projects: readonly (GateProjectSection & { readonly members: readonly string[] })[];
}

/**
 * M3 classification/ownership, reused by hosted and CLI gates. All inputs/outputs are transient.
 * `overrides` are the customer's binding classification declarations (§5.3), keyed by root path
 * then member path, exactly as discovery and the eligibility reader apply them, so the gate's
 * projects are discovery's projects. The default (no declarations) is the historical scope. The
 * map arrives over transient IPC, so it is validated here by `classifyInstallRoots`, which refuses
 * (null: `project_scope_ambiguous`) a malformed or hostile map rather than dropping a declaration.
 * `registryIntegrity` is the registry-sourced integrity (#7338) the caller looked up for this
 * side's workspace graph; absent keeps today's parse exactly.
 */
export function discoverGateScope(
  input: WorkspaceInput,
  lockfileName: LockfileName,
  lockfile: string,
  selected?: readonly string[],
  overrides: unknown = {},
  registryIntegrity?: RegistryIntegrityFill,
): GateRootScope | null {
  const layout = discoverWorkspaces(input);
  if (!layout.ok) return null;
  const files = rootFileOwnership(".", layout.value, lockfileName, input.entries, [], {
    remaining: 64 * 1024 * 1024,
  });
  const classified = classifyInstallRoots(
    [{ path: ".", lockfileName, layout: layout.value, excludedTrees: [], files }],
    overrides,
  );
  if (!classified.ok) return null;
  const projects = (selected ?? classified.roots[0]!.projects.map(({ path }) => path)).map(
    (path) => {
      const project = classified.roots[0]?.projects.find((candidate) => candidate.path === path);
      if (project === undefined) return null;
      const name = packageNameSchema.safeParse(project.name);
      return {
        path,
        name: name.success ? name.data : null,
        members: [...new Set([project.path, ...project.closure])],
      };
    },
  );
  if (projects.some((project) => project === null)) return null;
  const validated = projects.filter((project) => project !== null);
  if (!layout.value.hasWorkspaces) return { graph: null, projects: validated };
  const graph = parseWorkspaceGraph(
    input,
    { fileName: lockfileName, text: lockfile },
    undefined,
    undefined,
    registryIntegrity,
  );
  return graph.ok ? { graph: graph.value, projects: validated } : null;
}

/**
 * Union member closures before projecting either graph. A removed edge must not hide a package
 * that belonged to the protected closure on the base. This projection is verdict evidence only.
 */
export function gateScopeGraphs(
  base: GateRootScope | null,
  head: GateRootScope,
): { readonly base: DependencyGraph | null; readonly head: DependencyGraph | null } {
  const members = new Set(
    [...(base?.projects ?? []), ...head.projects].flatMap((project) => project.members),
  );
  const project = (scope: GateRootScope | null): DependencyGraph | null => {
    if (scope?.graph == null) return null;
    const graph = scope.graph;
    // Keep the root importer as the aggregate's format carrier, with an empty projection when
    // the root is outside scope. Do not pull its dependencies into an app's closure.
    const root = graph.importers.find((importer) => importer.member.path === ".");
    if (root === undefined) throw new RangeError("missing workspace root");
    const importers = graph.importers.filter((importer) => members.has(importer.member.path));
    if (!members.has("."))
      importers.unshift({
        ...root,
        graph: { ...root.graph, packages: [], direct: [], unresolved: [] },
      });
    // Importer projections include local app dependencies transitively. Stop traversal at a
    // local member outside the classified protected union rather than accidentally judging an
    // unprotected app's registry packages through its parent app.
    const reachable = new Set<string>();
    const queue = graph.importers
      .filter((importer) => members.has(importer.member.path))
      .flatMap((importer) =>
        importer.direct.flatMap(({ edge }) => (edge.target === null ? [] : [edge.target])),
      );
    let work = 20_000_000;
    for (let id = queue.pop(); id !== undefined; id = queue.pop()) {
      if (--work < 0) throw new RangeError("gate scope work exceeded");
      if (reachable.has(id)) continue;
      const instance = graph.instances.get(id);
      if (
        instance === undefined ||
        (instance.localMember !== undefined && !members.has(instance.localMember))
      )
        continue;
      reachable.add(id);
      for (const edge of instance.edges) if (edge.target !== null) queue.push(edge.target);
    }
    const aggregate = aggregateWorkspaceGraph({ ...graph, importers });
    return {
      ...aggregate,
      packages: aggregate.packages.filter((node) => node.instances.some((id) => reachable.has(id))),
    };
  };
  return { base: project(base), head: project(head) };
}
