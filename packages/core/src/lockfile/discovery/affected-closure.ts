import type { ClosureFallbackCause } from "@kovo/contracts";

import type { WorkspaceGraph } from "../workspace/types.js";
import type { ChangedMembers } from "./project-scope.js";

// #8256 phase 2 R8 (plans/js-coverage-phase2.md §2.6): monorepo checks by affected closure. Pure
// and transient: inputs are the parsed workspace graphs (manifests' local declarations and the
// lockfile importers, read in Sandbox A's trusted reads as today), outputs are member paths,
// counts and closed cause codes, never file contents.

/**
 * The disclosed reason code of a run that checked every project. Its cause (`@kovo/contracts`
 * `CLOSURE_FALLBACK_CAUSES`): `graph_unavailable`, a side's workspace graph could not be read or
 * scoped; `dependency_cycle`, the local member graph has a cycle, so "depends on" has no order;
 * `unknown_importer`, a lockfile importer or local edge names a member the layout lacks.
 */
export const CLOSURE_FALLBACK_ALL = "closure_fallback_all";

export type AffectedClosure =
  | {
      readonly kind: "affected";
      /** Members whose dependency closure contains a changed member (themselves included). */
      readonly members: readonly string[];
      /** Every member of the union of both sides' layouts. */
      readonly total: number;
    }
  | {
      readonly kind: "all";
      readonly reason: typeof CLOSURE_FALLBACK_ALL;
      readonly cause: ClosureFallbackCause;
    };

type Edges = ReadonlyMap<string, ReadonlySet<string>>;

/**
 * One side's local member dependency edges (member path to the member paths it depends on), from
 * the manifests' local declarations and the lockfile importers' local instance edges. Fails with
 * `unknown_importer` when an importer or a local edge names a path outside the layout.
 */
export function memberDependencyEdges(
  graph: WorkspaceGraph,
):
  | { readonly ok: true; readonly edges: Edges }
  | { readonly ok: false; readonly cause: "unknown_importer" } {
  const members = new Set(graph.layout.members.map((member) => member.path));
  const edges = new Map<string, Set<string>>([...members].map((path) => [path, new Set<string>()]));
  const add = (from: string, to: string): boolean => {
    if (!members.has(from) || !members.has(to)) return false;
    edges.get(from)!.add(to);
    return true;
  };
  for (const member of graph.layout.members)
    for (const declaration of member.local)
      if (!add(member.path, declaration.target)) return { ok: false, cause: "unknown_importer" };
  for (const importer of graph.importers) {
    if (!members.has(importer.member.path)) return { ok: false, cause: "unknown_importer" };
    for (const dep of importer.direct) {
      if (dep.edge.target === null) continue;
      const local = graph.instances.get(dep.edge.target)?.localMember;
      if (local !== undefined && !add(importer.member.path, local))
        return { ok: false, cause: "unknown_importer" };
    }
  }
  // A local instance's own edges to other local instances (Yarn classic records links there).
  for (const instance of graph.instances.values()) {
    if (instance.localMember === undefined) continue;
    if (!members.has(instance.localMember)) return { ok: false, cause: "unknown_importer" };
    for (const edge of instance.edges) {
      if (edge.target === null) continue;
      const local = graph.instances.get(edge.target)?.localMember;
      if (local !== undefined && !add(instance.localMember, local))
        return { ok: false, cause: "unknown_importer" };
    }
  }
  return { ok: true, edges };
}

/** Whether the member graph has a cycle (a self-edge included). Iterative three-colour DFS. */
export function hasMemberCycle(edges: Edges): boolean {
  const state = new Map<string, 1 | 2>();
  for (const start of edges.keys()) {
    if (state.has(start)) continue;
    const stack: { node: string; next: Iterator<string> }[] = [
      { node: start, next: (edges.get(start) ?? new Set<string>()).values() },
    ];
    state.set(start, 1);
    while (stack.length > 0) {
      const top = stack[stack.length - 1]!;
      const step = top.next.next();
      if (step.done === true) {
        state.set(top.node, 2);
        stack.pop();
        continue;
      }
      const seen = state.get(step.value);
      if (seen === 1) return true;
      if (seen === 2) continue;
      state.set(step.value, 1);
      stack.push({
        node: step.value,
        next: (edges.get(step.value) ?? new Set<string>()).values(),
      });
    }
  }
  return false;
}

const fallback = (cause: ClosureFallbackCause): AffectedClosure => ({
  kind: "all",
  reason: CLOSURE_FALLBACK_ALL,
  cause,
});

/**
 * The affected closure of a change on the union of the base and candidate graphs: every member
 * whose dependency closure (on either side) contains a changed member, the changed members
 * included. A root-shared change affects every member. A missing side, a cycle or an unknown
 * importer on either side runs every project instead (`closure_fallback_all`).
 */
export function affectedClosure(input: {
  readonly base: WorkspaceGraph | null;
  readonly candidate: WorkspaceGraph | null;
  readonly changed: ChangedMembers;
}): AffectedClosure {
  if (input.base === null || input.candidate === null) return fallback("graph_unavailable");
  const reverse = new Map<string, Set<string>>();
  const all = new Set<string>();
  for (const graph of [input.base, input.candidate]) {
    const side = memberDependencyEdges(graph);
    if (!side.ok) return fallback(side.cause);
    if (hasMemberCycle(side.edges)) return fallback("dependency_cycle");
    for (const [from, targets] of side.edges) {
      all.add(from);
      for (const to of targets) {
        const dependents = reverse.get(to) ?? new Set<string>();
        dependents.add(from);
        reverse.set(to, dependents);
      }
    }
  }
  if (input.changed.rootShared)
    return { kind: "affected", members: [...all].toSorted(compare), total: all.size };
  const affected = new Set<string>();
  const queue = [...input.changed.members].filter((path) => all.has(path));
  for (let path = queue.pop(); path !== undefined; path = queue.pop()) {
    if (affected.has(path)) continue;
    affected.add(path);
    for (const dependent of reverse.get(path) ?? []) queue.push(dependent);
  }
  return { kind: "affected", members: [...affected].toSorted(compare), total: all.size };
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
