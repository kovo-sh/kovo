import { assessChurn, diffGraphs, type GraphDiff } from "../diff.js";
import type { Instance, InstanceEdge } from "../instances.js";
import { compareStrings } from "../util.js";
import { importerInstances } from "./parse.js";
import type { WorkspaceGraph } from "./types.js";

export interface WorkspaceDiff {
  readonly addedMembers: readonly string[];
  readonly removedMembers: readonly string[];
  readonly importers: readonly { readonly path: string; readonly diff: GraphDiff }[];
  /** Declaration ownership includes local edges and ranges, not just aggregate package names. */
  readonly declarationsChanged: readonly string[];
  readonly manifestsChanged: readonly string[];
  readonly workspaceConfigChanged: boolean;
  /** Exact install locations/peer contexts; reparenting is observable even at identical versions. */
  readonly instancesChanged: readonly string[];
}
function declarations(graph: WorkspaceGraph, path: string): string {
  return JSON.stringify(
    graph.importers
      .find((item) => item.member.path === path)
      ?.direct.map((dep) => [dep.section, dep.alias, dep.spec, dep.edge.target])
      .toSorted((a, b) => compareStrings(JSON.stringify(a), JSON.stringify(b))) ?? [],
  );
}
function instanceIdentity(graph: WorkspaceGraph, id: string): string {
  const instance = graph.instances.get(id);
  return JSON.stringify(
    instance === undefined
      ? null
      : {
          ...instance,
          edges: instance.edges
            .map((edge) => [edge.alias, edge.kind, edge.range, edge.optional, edge.target])
            .toSorted((a, b) => compareStrings(JSON.stringify(a), JSON.stringify(b))),
        },
  );
}
/** Compare within each owner; a version disappearing in one member cannot pair with a sibling. */
export function diffWorkspaceGraphs(before: WorkspaceGraph, after: WorkspaceGraph): WorkspaceDiff {
  const a = new Map(before.importers.map((item) => [item.member.path, item.graph]));
  const b = new Map(after.importers.map((item) => [item.member.path, item.graph]));
  const paths = [...new Set([...a.keys(), ...b.keys()])].toSorted();
  return {
    addedMembers: paths.filter((path) => !a.has(path)),
    removedMembers: paths.filter((path) => !b.has(path)),
    importers: paths.flatMap((path) => {
      const base = a.get(path);
      const head = b.get(path);
      return base === undefined || head === undefined
        ? []
        : [{ path, diff: diffGraphs(base, head) }];
    }),
    declarationsChanged: paths.filter(
      (path) => declarations(before, path) !== declarations(after, path),
    ),
    manifestsChanged: paths.filter((path) => {
      const base = before.importers.find((item) => item.member.path === path)?.member;
      const head = after.importers.find((item) => item.member.path === path)?.member;
      return (
        base?.manifestOid !== head?.manifestOid ||
        JSON.stringify(base?.manifest) !== JSON.stringify(head?.manifest)
      );
    }),
    workspaceConfigChanged: before.layout.workspaceConfigOid !== after.layout.workspaceConfigOid,
    instancesChanged: [...new Set([...before.instances.keys(), ...after.instances.keys()])]
      .toSorted()
      .filter((id) => instanceIdentity(before, id) !== instanceIdentity(after, id)),
  };
}
/** Fail closed on member churn or any changed instance owned by an unauthorized sibling. */
export function workspaceChurnWithinOwners(
  before: WorkspaceGraph,
  after: WorkspaceGraph,
  allowedOwners: readonly string[],
): boolean {
  const diff = diffWorkspaceGraphs(before, after);
  if (diff.addedMembers.length > 0 || diff.removedMembers.length > 0) return false;
  const allowed = new Set(allowedOwners);
  if ([...diff.declarationsChanged, ...diff.manifestsChanged].some((path) => !allowed.has(path)))
    return false;
  if (diff.workspaceConfigChanged && !allowed.has(".")) return false;
  const ownership = new Map<string, Set<string>>();
  for (const graph of [before, after]) {
    // A first-party member owns its local instance even when no other member imports it.
    // Its registry edge declarations change on legitimate pins, just like its manifest.
    for (const instance of graph.instances.values()) {
      if (instance.localMember === undefined) continue;
      const owners = ownership.get(instance.id) ?? new Set<string>();
      owners.add(instance.localMember);
      ownership.set(instance.id, owners);
    }
    for (const importer of graph.importers) {
      for (const id of importerInstances(graph, importer.member.path)) {
        const owners = ownership.get(id) ?? new Set<string>();
        owners.add(importer.member.path);
        ownership.set(id, owners);
      }
    }
  }
  return diff.instancesChanged.every((id) => {
    const owners = ownership.get(id);
    return (
      owners !== undefined && owners.size > 0 && [...owners].every((path) => allowed.has(path))
    );
  });
}

function edgeDeclarationKey(edge: InstanceEdge): string {
  return JSON.stringify([edge.alias, edge.kind, edge.range, edge.optional]);
}
/** A stable registry parent may retarget only an existing edge into the authorized closure. */
function stableParentRetarget(
  before: Instance | undefined,
  after: Instance | undefined,
  allowed: ReadonlySet<string>,
): boolean {
  if (
    before === undefined ||
    after === undefined ||
    before.localMember !== undefined ||
    after.localMember !== undefined ||
    JSON.stringify({ ...before, edges: [] }) !== JSON.stringify({ ...after, edges: [] })
  )
    return false;

  const a = before.edges.toSorted((left, right) =>
    compareStrings(edgeDeclarationKey(left), edgeDeclarationKey(right)),
  );
  const b = after.edges.toSorted((left, right) =>
    compareStrings(edgeDeclarationKey(left), edgeDeclarationKey(right)),
  );
  if (a.length !== b.length) return false;
  let changed = false;
  for (let i = 0; i < a.length; i++) {
    const base = a[i];
    const head = b[i];
    if (
      base === undefined ||
      head === undefined ||
      edgeDeclarationKey(base) !== edgeDeclarationKey(head)
    )
      return false;
    if (base.target === head.target) continue;
    if (
      base.target === null ||
      head.target === null ||
      !allowed.has(base.target) ||
      !allowed.has(head.target)
    )
      return false;
    changed = true;
  }
  return changed;
}

/** Importer-qualified anchors complement owner confinement with the existing target-closure rule. */
export function assessWorkspaceChurn(
  before: WorkspaceGraph,
  after: WorkspaceGraph,
  options: {
    readonly anchors: readonly { readonly importer: string; readonly name: string }[];
    readonly maxChangedInstances: number;
  },
): { readonly rejected: boolean; readonly reasons: readonly string[] } {
  const diff = diffWorkspaceGraphs(before, after);
  const owners = options.anchors.map((anchor) => anchor.importer);
  const reasons = new Set<string>();
  if (!workspaceChurnWithinOwners(before, after, owners)) reasons.add("unauthorized_owner");
  if (diff.instancesChanged.length > options.maxChangedInstances) reasons.add("too_many_changes");
  for (const { path, diff: memberDiff } of diff.importers) {
    const base = before.importers.find((item) => item.member.path === path)?.graph;
    const head = after.importers.find((item) => item.member.path === path)?.graph;
    if (base === undefined || head === undefined) continue;
    if ([...base.packages, ...head.packages].some((node) => node.pathsTruncated))
      reasons.add("incomplete_graph");
    const anchors = options.anchors
      .filter((anchor) => anchor.importer === path)
      .map((anchor) => anchor.name);
    for (const reason of assessChurn(base, head, memberDiff, {
      anchors,
      maxChangedPackages: options.maxChangedInstances,
    }).reasons)
      reasons.add(reason);
    // Name/version aggregation cannot hide peer-context or location-only reparenting.
    for (const graph of [before, after]) {
      const importer = graph.importers.find((item) => item.member.path === path);
      const other = (graph === before ? after : before).importers.find(
        (item) => item.member.path === path,
      );
      for (const dep of importer?.direct ?? []) {
        const matching = other?.direct.find(
          (candidate) => candidate.section === dep.section && candidate.alias === dep.alias,
        );
        if (matching?.spec === dep.spec && matching.edge.target === dep.edge.target) continue;
        const name =
          dep.edge.target === null ? dep.alias : graph.instances.get(dep.edge.target)?.name;
        if (name === undefined || !anchors.includes(name)) reasons.add("outside_target_closure");
      }
    }
    const allowedInstances = new Set<string>();
    const owned = new Set<string>();
    for (const graph of [before, after]) {
      const reachable = importerInstances(graph, path);
      for (const id of reachable)
        if (graph.instances.get(id)?.localMember === undefined) owned.add(id);
      const queue = [...reachable].filter((id) => {
        const name = graph.instances.get(id)?.name;
        return name !== undefined && anchors.includes(name);
      });
      const seen = new Set<string>();
      for (let id = queue.pop(); id !== undefined; id = queue.pop()) {
        if (seen.has(id)) continue;
        seen.add(id);
        allowedInstances.add(id);
        for (const edge of graph.instances.get(id)?.edges ?? [])
          if (edge.target !== null) queue.push(edge.target);
      }
    }
    if (
      diff.instancesChanged.some(
        (id) =>
          owned.has(id) &&
          !allowedInstances.has(id) &&
          !stableParentRetarget(
            before.instances.get(id),
            after.instances.get(id),
            allowedInstances,
          ),
      )
    )
      reasons.add("outside_target_closure");
  }
  return { rejected: reasons.size > 0, reasons: [...reasons].toSorted() };
}
