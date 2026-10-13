import semver from "semver";

import { buildGraph } from "../build-graph.js";
import type { Instance, InstanceEdge, InstanceSet, RootDependency } from "../instances.js";
import { parseYarnLockfile } from "../yarn.js";
import { parseNpmLockfile } from "../npm.js";
import { parsePnpmLockfile } from "../pnpm.js";
import { GRAPH_LIMITS, packageKey, type LockfileLimits } from "../types.js";
import type { LockfileInput } from "../parse.js";
import type { ResolvedRuntime } from "../compat.js";
import { discoverWorkspaces } from "./discover.js";
import { WorkspaceParserContext } from "./parser-context.js";
import {
  WORKSPACE_LIMITS,
  workspaceFailure,
  type WorkspaceGraph,
  type WorkspaceInput,
  type WorkspaceLayout,
  type WorkspaceLimits,
  type WorkspaceResult,
} from "./types.js";

/** All member declarations must accept the exact root runtime resolved by the existing matrix. */
export function workspaceRuntimeCompatible(
  layout: WorkspaceLayout,
  runtime: ResolvedRuntime,
): boolean {
  if (layout.packageManager !== runtime.packageManager) return false;
  const pm = runtime.packageManager;
  return layout.members.every(({ manifest }) => {
    for (const [range, version] of [
      [manifest.engines.node, runtime.node],
      [manifest.engines[pm] ?? null, runtime.pmVersion],
    ] as const) {
      if (
        range !== null &&
        (semver.validRange(range) === null || !semver.satisfies(version, range))
      )
        return false;
    }
    if (manifest.packageManager !== null) {
      const match = /^(npm|pnpm|yarn)@(\d+\.\d+\.\d+)(?:\+[^\s]+)?$/u.exec(manifest.packageManager);
      if (
        match?.[1] !== runtime.packageManager ||
        match[2] === undefined ||
        semver.major(match[2]) !== semver.major(runtime.pmVersion)
      )
        return false;
    }
    for (const [pin, version] of [
      [manifest.volta.node, runtime.node],
      [manifest.volta[pm] ?? null, runtime.pmVersion],
    ] as const) {
      if (
        pin !== null &&
        (semver.valid(pin) === null || semver.major(pin) !== semver.major(version))
      )
        return false;
    }
    return true;
  });
}

/** Collapse local traversal only in legacy registry projections; keep the exact edges separately. */
function registryRoots(
  set: InstanceSet,
  roots: readonly RootDependency[],
  budget: { remaining: number },
): RootDependency[] {
  const expanded: RootDependency[] = [];
  for (const root of roots) {
    const queue: InstanceEdge[] = [root.edge];
    const seen = new Set<string>();
    for (let edge = queue.pop(); edge !== undefined; edge = queue.pop()) {
      if (--budget.remaining < 0) throw new RangeError("workspace projection bound");
      const instance = edge.target === null ? undefined : set.instances.get(edge.target);
      if (instance?.localMember === undefined) {
        expanded.push({ ...root, edge });
        continue;
      }
      const state = `${instance.id}\u0000${edge.kind}\u0000${edge.optional}`;
      if (seen.has(state)) continue;
      seen.add(state);
      for (const child of instance.edges)
        queue.push({
          ...child,
          kind: edge.kind === "dev" ? "dev" : child.kind,
          optional: edge.optional || child.optional,
        });
    }
  }
  return expanded;
}

/** Explicit P1 entry point. Legacy parseLockfile stays single-root and refuses workspaces. */
export function parseWorkspaceGraph(
  input: WorkspaceInput,
  lockfile: LockfileInput,
  limits: WorkspaceLimits = WORKSPACE_LIMITS,
  graphLimits: LockfileLimits = GRAPH_LIMITS,
): WorkspaceResult<WorkspaceGraph> {
  const discovered = discoverWorkspaces(input, limits);
  if (!discovered.ok) return discovered;
  const layout = discovered.value;
  if (
    lockfile.fileName !==
    (layout.packageManager === "npm"
      ? "package-lock.json"
      : layout.packageManager === "yarn"
        ? "yarn.lock"
        : "pnpm-lock.yaml")
  )
    return workspaceFailure("manager_mismatch");
  const treeLock = input.entries.find((entry) => entry.path === lockfile.fileName);
  if (treeLock?.mode !== "file" || treeLock.text !== lockfile.text)
    return workspaceFailure("invalid_lockfile");
  const context = new WorkspaceParserContext(layout);
  const parsed =
    layout.packageManager === "yarn"
      ? parseYarnLockfile(lockfile.text, graphLimits, undefined, context)
      : layout.packageManager === "npm"
        ? parseNpmLockfile(lockfile.text, graphLimits, context)
        : parsePnpmLockfile(lockfile.text, graphLimits, context);
  if (!parsed.ok)
    return workspaceFailure(
      parsed.rejections.rejections.some((rejection) => rejection.reason === "catalog_protocol")
        ? "catalogs_unsupported"
        : "invalid_lockfile",
    );
  const set = parsed.instances;
  const registry = new Map(
    [...set.instances].filter(([, instance]) => instance.localMember === undefined),
  );
  const integrity = new Map<string, string>();
  const resolved = new Map<string, string>();
  for (const instance of registry.values()) {
    if (instance.integrity !== null) {
      const key = `${instance.name}@${instance.version}`;
      const previous = integrity.get(key);
      if (previous !== undefined && previous !== instance.integrity)
        return workspaceFailure("invalid_lockfile");
      integrity.set(key, instance.integrity);
    }
    if (instance.resolved !== null) {
      const key = `${instance.name}@${instance.version}`;
      const previous = resolved.get(key);
      if (previous !== undefined && previous !== instance.resolved)
        return workspaceFailure("invalid_lockfile");
      resolved.set(key, instance.resolved);
    }
  }
  const projectionCost =
    layout.members.length *
    (registry.size +
      [...registry.values()].reduce((total, instance) => total + instance.edges.length, 0));
  const budget = { remaining: limits.maxProjectionWork - projectionCost };
  if (budget.remaining < 0) return workspaceFailure("resource_limit");
  const rootsByMember = new Map<string, RootDependency[]>();
  try {
    for (const member of layout.members)
      rootsByMember.set(
        member.path,
        registryRoots(
          set,
          set.root.filter((dep) => dep.importer === member.path),
          budget,
        ),
      );
  } catch {
    return workspaceFailure("resource_limit");
  }
  const importers = layout.members.map((member) => {
    const direct = set.root.filter((dep) => dep.importer === member.path);
    const graph = buildGraph(
      { ...set, instances: registry, root: rootsByMember.get(member.path) ?? [] },
      {
        ...graphLimits,
        maxPathWork: Math.floor(graphLimits.maxPathWork / layout.members.length),
        maxTotalPaths: Math.floor(graphLimits.maxTotalPaths / layout.members.length),
      },
    );
    const immediate = new Set(
      direct.flatMap((dep) => (dep.edge.target === null ? [] : [dep.edge.target])),
    );
    return {
      member,
      direct,
      graph: {
        ...graph,
        direct: direct
          .filter((dep) => dep.edge.target === null || registry.has(dep.edge.target))
          .map((dep) => {
            const target = dep.edge.target === null ? undefined : registry.get(dep.edge.target);
            return {
              alias: dep.alias,
              section: dep.section,
              spec: dep.spec,
              target: target === undefined ? null : packageKey(target.name, target.version),
            };
          })
          .toSorted((a, b) => (a.alias < b.alias ? -1 : a.alias > b.alias ? 1 : 0)),
        packages: graph.packages.map((node) =>
          Object.assign({}, node, {
            isDirect: node.instances.some((id) => immediate.has(id)),
          }),
        ),
      },
    };
  });
  if (importers.some(({ graph }) => graph.unresolved.length > 0))
    return workspaceFailure("incomplete_graph");
  // Required local-member edges must resolve too (registry projections intentionally omit locals).
  for (const root of set.root)
    if (root.edge.target === null && !root.edge.optional && root.edge.kind !== "peer")
      return workspaceFailure("incomplete_graph");
  return { ok: true, value: { layout, importers, instances: set.instances } };
}

/** Iterative instance traversal: local cycles and peer contexts retain their exact identity. */
export function importerInstances(graph: WorkspaceGraph, path: string): ReadonlySet<string> {
  const seen = new Set<string>();
  const roots = graph.importers.find((item) => item.member.path === path)?.direct ?? [];
  const queue = roots.flatMap((dep) => (dep.edge.target === null ? [] : [dep.edge.target]));
  for (let id = queue.pop(); id !== undefined; id = queue.pop()) {
    if (seen.has(id)) continue;
    seen.add(id);
    const instance: Instance | undefined = graph.instances.get(id);
    for (const edge of instance?.edges ?? []) if (edge.target !== null) queue.push(edge.target);
  }
  return seen;
}
