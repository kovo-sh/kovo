import semver from "semver";

import type { Instance, InstanceEdge, InstanceSet } from "./instances.js";
import {
  GRAPH_LIMITS,
  packageKey,
  type DependencyEdge,
  type DependencyGraph,
  type DependencyPath,
  type DirectDependency,
  type LockfileLimits,
  type PackageKey,
  type ResolvedPackageNode,
  type UnresolvedDependency,
} from "./types.js";
import { compareStrings, required } from "./util.js";

// Aggregates a format parser's instances into the normalized graph: reachability from the root,
// production/development classification ("production if any production path reaches it; optional
// dependencies count as production"), and bounded dependency-path enumeration.

/** Path-enumeration bounds (defaults: `GRAPH_LIMITS`). */
export type GraphLimits = Pick<
  LockfileLimits,
  "maxPathsPerPackage" | "maxPathDepth" | "maxTotalPaths" | "maxPathWork"
>;

interface PathRef {
  readonly instance: string;
  readonly key: PackageKey;
  readonly prev: PathRef | null;
  readonly depth: number;
}

interface ResolvedEdge {
  readonly edge: InstanceEdge;
  readonly target: string;
}

function keyOf(instance: Instance): PackageKey {
  return packageKey(instance.name, instance.version);
}

function byAlias(a: InstanceEdge, b: InstanceEdge): number {
  return compareStrings(a.alias, b.alias);
}

/** The edges of `instance` that resolve, in alias order. */
function resolvedEdges(instance: Instance): ResolvedEdge[] {
  return instance.edges
    .toSorted(byAlias)
    .flatMap((edge) => (edge.target === null ? [] : [{ edge, target: edge.target }]));
}

/** Each instance's resolved edges, sorted once (path enumeration visits instances repeatedly). */
function edgeTable(set: InstanceSet): ReadonlyMap<string, readonly ResolvedEdge[]> {
  const table = new Map<string, readonly ResolvedEdge[]>();
  for (const [id, instance] of set.instances) table.set(id, resolvedEdges(instance));
  return table;
}

/** Instances reachable from `starts`, following edges `follow` accepts. */
function reachable(
  set: InstanceSet,
  edges: ReadonlyMap<string, readonly ResolvedEdge[]>,
  starts: Iterable<string>,
  follow: (edge: InstanceEdge) => boolean,
): Set<string> {
  const seen = new Set<string>();
  const queue = [...starts];
  for (let id = queue.pop(); id !== undefined; id = queue.pop()) {
    if (seen.has(id) || !set.instances.has(id)) continue;
    seen.add(id);
    for (const { edge, target } of edges.get(id) ?? []) {
      if (follow(edge) && !seen.has(target)) queue.push(target);
    }
  }
  return seen;
}

function chainContains(ref: PathRef, key: PackageKey): boolean {
  for (let current: PathRef | null = ref; current !== null; current = current.prev) {
    if (current.key === key) return true;
  }
  return false;
}

function materialize(ref: PathRef): DependencyPath {
  const keys: PackageKey[] = [];
  for (let current: PathRef | null = ref; current !== null; current = current.prev) {
    keys.push(current.key);
  }
  return keys.toReversed();
}

interface PathTable {
  readonly paths: Map<PackageKey, DependencyPath[]>;
  readonly truncated: Set<PackageKey>;
}

/**
 * Enumerates simple dependency paths breadth-first (shortest first) under four bounds: paths kept
 * per package, path depth, paths recorded across the graph, and a whole-graph work budget.
 *
 * At most `maxPathsPerPackage` partial paths are ever queued per instance (breadth-first, so they
 * are its shortest), so at most `instances × maxPathsPerPackage` paths exist and at most
 * `maxPathsPerPackage × edges` edges are examined. The work budget (`maxPathWork`) counts every
 * examined edge plus the chain steps of every cycle check and recorded path, so even a dense
 * hostile graph far below the lockfile size limit finishes within it: when the budget runs out,
 * enumeration stops and every package is marked truncated. Any package whose paths may be
 * incomplete (a capped instance or ancestor, the depth limit, a budget) is marked truncated.
 */
function enumeratePaths(
  set: InstanceSet,
  edges: ReadonlyMap<string, readonly ResolvedEdge[]>,
  limits: GraphLimits,
): PathTable {
  const paths = new Map<PackageKey, DependencyPath[]>();
  const seenPaths = new Map<PackageKey, Set<string>>();
  const cappedInstances = new Set<string>();
  const queued = new Map<string, number>();
  let total = 0;
  let work = 0;
  let exhausted = false;

  const record = (ref: PathRef): void => {
    let list = paths.get(ref.key);
    let seen = seenPaths.get(ref.key);
    if (list === undefined || seen === undefined) {
      list = [];
      seen = new Set();
      paths.set(ref.key, list);
      seenPaths.set(ref.key, seen);
    }
    work += ref.depth;
    const path = materialize(ref);
    const id = path.join("\u0000");
    if (seen.has(id)) return;
    if (list.length >= limits.maxPathsPerPackage) {
      cappedInstances.add(ref.instance);
      return;
    }
    seen.add(id);
    list.push(path);
    total += 1;
  };

  /** Queues a partial path to `instance` unless the instance already has its share. */
  const enqueue = (list: PathRef[], ref: PathRef): void => {
    const count = queued.get(ref.instance) ?? 0;
    if (count >= limits.maxPathsPerPackage) {
      cappedInstances.add(ref.instance);
      return;
    }
    queued.set(ref.instance, count + 1);
    list.push(ref);
  };

  let frontier: PathRef[] = [];
  for (const root of set.root.toSorted((a, b) => byAlias(a.edge, b.edge))) {
    const target = root.edge.target === null ? undefined : set.instances.get(root.edge.target);
    if (target === undefined) continue;
    enqueue(frontier, { instance: target.id, key: keyOf(target), prev: null, depth: 1 });
  }

  while (frontier.length > 0 && !exhausted) {
    const next: PathRef[] = [];
    for (const ref of frontier) {
      if (total >= limits.maxTotalPaths || work >= limits.maxPathWork) {
        exhausted = true;
        break;
      }
      record(ref);
      const children = edges.get(ref.instance) ?? [];
      if (children.length === 0) continue;
      if (ref.depth >= limits.maxPathDepth) {
        cappedInstances.add(ref.instance);
        continue;
      }
      for (const { target } of children) {
        // Checked per edge too: one instance may declare hundreds of thousands of edges.
        if (work >= limits.maxPathWork) {
          exhausted = true;
          break;
        }
        work += 1;
        const child = set.instances.get(target);
        if (child === undefined) continue;
        if ((queued.get(child.id) ?? 0) >= limits.maxPathsPerPackage) {
          cappedInstances.add(child.id);
          continue;
        }
        work += ref.depth;
        const childKey = keyOf(child);
        if (chainContains(ref, childKey)) continue;
        enqueue(next, { instance: child.id, key: childKey, prev: ref, depth: ref.depth + 1 });
      }
      if (exhausted) break;
    }
    frontier = next;
  }

  // Descendants of a capped instance may be missing paths through it.
  const truncated = new Set<PackageKey>();
  const affected = exhausted
    ? set.instances.keys()
    : reachable(set, edges, cappedInstances, () => true);
  for (const id of affected) truncated.add(keyOf(required(set.instances, id)));
  return { paths, truncated };
}

function compareNodes(a: ResolvedPackageNode, b: ResolvedPackageNode): number {
  return a.name === b.name ? semver.compare(a.version, b.version) : compareStrings(a.name, b.name);
}

function aggregate(
  set: InstanceSet,
  key: PackageKey,
  instances: readonly Instance[],
  facts: {
    readonly production: ReadonlySet<string>;
    readonly required: ReadonlySet<string>;
    readonly directTargets: ReadonlySet<string>;
    readonly edges: ReadonlyMap<string, readonly ResolvedEdge[]>;
    readonly paths: PathTable;
  },
): ResolvedPackageNode {
  const [first] = instances;
  if (first === undefined) throw new RangeError("lockfile graph invariant: empty group");
  const edges = new Map<string, DependencyEdge>();
  for (const instance of instances) {
    for (const { edge, target } of facts.edges.get(instance.id) ?? []) {
      const resolved: DependencyEdge = {
        alias: edge.alias,
        kind: edge.kind,
        range: edge.range,
        target: keyOf(required(set.instances, target)),
      };
      edges.set(`${edge.alias}\u0000${edge.kind}\u0000${resolved.target}`, resolved);
    }
  }
  const installScripts = instances.map((instance) => instance.hasInstallScript);
  const integrityOf = instances.find((instance) => instance.integrity !== null);
  return {
    key,
    name: first.name,
    version: first.version,
    integrity: integrityOf?.integrity ?? null,
    integrityAlgorithm:
      integrityOf?.integrityAlgorithm ??
      instances.find((instance) => instance.integrityAlgorithm !== null)?.integrityAlgorithm ??
      null,
    resolved: instances.find((instance) => instance.resolved !== null)?.resolved ?? null,
    isDirect: instances.some((instance) => facts.directTargets.has(instance.id)),
    isDev: !instances.some((instance) => facts.production.has(instance.id)),
    isOptional: !instances.some((instance) => facts.required.has(instance.id)),
    bundled: instances.every((instance) => instance.bundled),
    bundles: [...new Set(instances.flatMap((instance) => instance.bundles))].toSorted(),
    hasInstallScript: installScripts.includes(true)
      ? true
      : installScripts.every((value) => value === null)
        ? null
        : false,
    patched: instances.some((instance) => instance.patched),
    paths: facts.paths.paths.get(key) ?? [],
    pathsTruncated: facts.paths.truncated.has(key),
    dependencies: [...edges.values()].toSorted((a, b) =>
      a.alias === b.alias ? compareStrings(a.target, b.target) : compareStrings(a.alias, b.alias),
    ),
    instances: instances.map((instance) => instance.id).toSorted(),
  };
}

/** Builds the normalized graph from a parser's instances. */
export function buildGraph(set: InstanceSet, limits: GraphLimits = GRAPH_LIMITS): DependencyGraph {
  const rootTargets = (predicate: (edge: InstanceEdge) => boolean): string[] =>
    set.root.flatMap((root) =>
      root.edge.target !== null && predicate(root.edge) ? [root.edge.target] : [],
    );

  const edges = edgeTable(set);
  const production = reachable(
    set,
    edges,
    rootTargets((edge) => edge.kind !== "dev"),
    () => true,
  );
  const all = reachable(
    set,
    edges,
    rootTargets(() => true),
    () => true,
  );
  const requiredInstances = reachable(
    set,
    edges,
    rootTargets((edge) => !edge.optional),
    (edge) => !edge.optional,
  );
  const facts = {
    production,
    required: requiredInstances,
    directTargets: new Set(rootTargets(() => true)),
    edges,
    paths: enumeratePaths(set, edges, limits),
  };

  const grouped = new Map<PackageKey, Instance[]>();
  for (const id of [...all].toSorted()) {
    const instance = required(set.instances, id);
    const key = keyOf(instance);
    const group = grouped.get(key);
    if (group === undefined) grouped.set(key, [instance]);
    else group.push(instance);
  }

  const unresolved: UnresolvedDependency[] = [];
  const unresolvedSeen = new Set<string>();
  const noteUnresolved = (from: PackageKey | "root", edge: InstanceEdge): void => {
    if (edge.target !== null || edge.optional || edge.kind === "peer") return;
    const id = `${from}\u0000${edge.alias}`;
    if (unresolvedSeen.has(id)) return;
    unresolvedSeen.add(id);
    unresolved.push({ from, alias: edge.alias });
  };
  for (const root of set.root) noteUnresolved("root", root.edge);
  for (const [key, instances] of grouped) {
    for (const instance of instances) for (const edge of instance.edges) noteUnresolved(key, edge);
  }

  const packages = [...grouped]
    .map(([key, instances]) => aggregate(set, key, instances, facts))
    .toSorted(compareNodes);

  const direct: DirectDependency[] = set.root
    .map((root) => {
      const target = root.edge.target === null ? undefined : set.instances.get(root.edge.target);
      return {
        alias: root.alias,
        section: root.section,
        spec: root.spec,
        target: target === undefined ? null : keyOf(target),
      };
    })
    .toSorted((a, b) => compareStrings(a.alias, b.alias));

  return {
    packageManager: set.packageManager,
    format: set.format,
    direct,
    packages,
    unresolved,
    lockfileOverrides: set.lockfileOverrides.toSorted(),
  };
}
