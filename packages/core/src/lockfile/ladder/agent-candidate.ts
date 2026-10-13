import type { MergeBlockReason, PackageName } from "@kovo/contracts";
import semver from "semver";

import type { PackageKey, ResolvedPackageNode } from "../types.js";
import { dependencyPointer, LadderContext } from "./context.js";
import type { LadderInput, LadderPlan, LockfileExpectation } from "./types.js";

// The trusted checks an agent-produced candidate must pass (SPEC: "agent output is only a candidate
// patch"; rung 6 "Major upgrade, optionally agent-assisted on Plus", rung 7 "Major upgrade plus
// source migration, Plus agent"; "Any override/source edit/new top-level dependency prevents
// auto-merge regardless of rung"; "reject unintended graph churn"). The agent has no plan, so the
// expectations are the ones every plan of the target carries (no affected version remains; every
// remaining version is safe or an untargeted copy), churn is measured against the target and the
// direct dependencies its affected instances hang from, and package.json may change only at those
// dependencies' own declarations: an agent that adds a script, an override or a new dependency
// fails the allowlist and its candidate is never staged.

export type AgentRung = "6" | "7";

/** The outcome and manifest checks of an agent candidate (the fields the plan checks read). */
export type AgentCandidateChecks = Pick<
  LadderPlan,
  | "expectations"
  | "anchors"
  | "allowedManifestPointers"
  | "expectedManifest"
  | "autoMergeEligible"
  | "reviewReasons"
> & { readonly rung: AgentRung };

/** The nearest direct dependency on each path to `node` (the node itself when it is direct). */
function nearestDirect(ctx: LadderContext, node: ResolvedPackageNode): ResolvedPackageNode[] {
  if (ctx.directDeclarations(node.key).length > 0) return [node];
  const found = new Map<PackageKey, ResolvedPackageNode>();
  for (const path of node.paths) {
    for (let index = path.length - 2; index >= 0; index -= 1) {
      const key = path[index];
      if (key === undefined) continue;
      if (ctx.directDeclarations(key).length > 0) {
        found.set(key, ctx.node(key));
        break;
      }
    }
  }
  return [...found.values()];
}

/** The checks for an agent candidate of `input`'s target at `rung`. */
export function agentCandidateChecks(input: LadderInput, rung: AgentRung): AgentCandidateChecks {
  const ctx = new LadderContext(input);
  const target = input.target;
  const instances = input.graph.packages.filter(
    (node) => node.name === target.name && ctx.affected.has(node.version),
  );
  const unaffected = ctx.versionsOf(target.name).filter((version) => !ctx.affected.has(version));
  const expectations: LockfileExpectation[] = [
    ...[...new Set(target.affectedVersions)]
      .toSorted(semver.compare)
      .map((version): LockfileExpectation => ({
        kind: "version_absent",
        name: target.name,
        version,
      })),
    {
      kind: "versions_within",
      name: target.name,
      allowed: [...new Set([...ctx.safe, ...unaffected])].toSorted(semver.compare),
    },
  ];
  const ancestors = instances.flatMap((node) => nearestDirect(ctx, node));
  const anchors = [
    ...new Set<PackageName>([target.name, ...ancestors.map((node) => node.name)]),
  ].toSorted();
  const pointers = new Set<string>();
  for (const ancestor of ancestors) {
    for (const direct of ctx.directDeclarations(ancestor.key)) {
      const declaration = ctx.declaration(direct);
      if (declaration !== undefined && direct.section !== "peerDependencies") {
        pointers.add(dependencyPointer(declaration));
      }
    }
  }
  const reviewReasons: MergeBlockReason[] = ["ladder_rung_review_only", "major_update"];
  if (rung === "7") reviewReasons.push("source_migration");
  return {
    rung,
    expectations,
    anchors,
    allowedManifestPointers: [...pointers].toSorted(),
    expectedManifest: [],
    autoMergeEligible: false,
    reviewReasons,
  };
}
