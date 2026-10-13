import { packageVersionSchema, type PackageName, type PackageVersion } from "@kovo/contracts";
import semver from "semver";

import { isCompatibleUpgrade } from "../semver-change.js";
import type { DependencyPath, PackageKey, ResolvedPackageNode } from "../types.js";
import { skip, type LadderContext, type Pin, type TechniqueResult } from "./context.js";
import { pinDirect } from "./rung-updates.js";
import type { LadderSkipReason, LadderStep, ManifestEdit, PmCommand } from "./types.js";

// Rung 4: "Nearest direct ancestor patch/minor update" that pulls a fixed transitive. For every
// dependency path to the affected instance, the nearest ancestor that is itself a direct
// dependency is moved to the smallest patch/minor version whose declared ranges force the package
// manager off the affected version and onto a safe one. The prediction follows how npm and pnpm
// resolve: a range still admitting a locked version may keep it, a fresh range resolves to
// `latest` or the newest admitted version (docs/decisions/lockfile.md "The ladder planner").

type Simulation =
  | { readonly ok: true; readonly target: PackageVersion | null }
  | { readonly ok: false; readonly reason: "metadata_missing" | "no_parent_version" };

const NO_VERSION: Simulation = { ok: false, reason: "no_parent_version" };
const NO_METADATA: Simulation = { ok: false, reason: "metadata_missing" };

/**
 * Predicts where `chain` (ancestor → … → affected instance) leads once the ancestor is at
 * `version`. `target` is the safe target version reached, or null when the new versions no longer
 * depend on the target along this chain.
 */
function simulateChain(
  ctx: LadderContext,
  chain: readonly ResolvedPackageNode[],
  version: string,
): Simulation {
  const [ancestor] = chain;
  if (ancestor === undefined) return NO_VERSION;
  let current = { name: ancestor.name, version };
  for (let index = 1; index < chain.length; index += 1) {
    const previous = chain[index - 1];
    const next = chain[index];
    if (previous === undefined || next === undefined) return NO_VERSION;
    const alias = previous.dependencies.find((edge) => edge.target === next.key)?.alias;
    if (alias !== next.name) return NO_VERSION;
    if (ctx.registry.version(current.name, current.version) === undefined) return NO_METADATA;
    const range = ctx.registry.rangeFor(current.name, current.version, alias);
    // The new version dropped the dependency: this path no longer reaches the target.
    if (range === undefined) return { ok: true, target: null };
    if (semver.validRange(range) === null) return NO_VERSION;

    const locked = ctx.graph.packages.filter(
      (node) => node.name === next.name && semver.satisfies(node.version, range),
    );
    if (ctx.registry.package(next.name) === undefined) return NO_METADATA;
    const picked = ctx.registry.pick(next.name, range);
    if (index === chain.length - 1) {
      // A range that still admits an affected version lets the package manager keep it.
      if (locked.some((node) => ctx.affected.has(node.version))) return NO_VERSION;
      const target = ctx.safeVersion(picked);
      return target === null ? NO_VERSION : { ok: true, target };
    }
    // An intermediate package may be deduplicated onto a locked version (none of which may lead
    // to the affected instance) or resolved fresh (which must lead somewhere safe too).
    if (locked.some((node) => ctx.reachesAffected(node.key))) return NO_VERSION;
    if (picked === null) return NO_VERSION;
    current = { name: next.name, version: picked };
  }
  return NO_VERSION;
}

/** Groups the instance's paths by their nearest direct ancestor; each chain starts there. */
function chainsByAncestor(
  ctx: LadderContext,
  paths: readonly DependencyPath[],
): Map<PackageKey, ResolvedPackageNode[][]> {
  const groups = new Map<PackageKey, ResolvedPackageNode[][]>();
  for (const path of paths) {
    const nodes = path.map((key) => ctx.node(key));
    let start = 0;
    for (let index = nodes.length - 2; index > 0; index -= 1) {
      const candidate = nodes[index];
      if (candidate !== undefined && ctx.directDeclarations(candidate.key).length > 0) {
        start = index;
        break;
      }
    }
    const chain = nodes.slice(start);
    const [ancestor] = chain;
    if (ancestor === undefined) continue;
    const list = groups.get(ancestor.key);
    if (list === undefined) groups.set(ancestor.key, [chain]);
    else list.push(chain);
  }
  return groups;
}

type AncestorChoice =
  | { readonly ok: true; readonly version: PackageVersion; readonly target: PackageVersion | null }
  | { readonly ok: false; readonly reason: LadderSkipReason };

/** The smallest patch/minor version of `ancestor` that leads every chain to a safe target. */
function chooseAncestorVersion(
  ctx: LadderContext,
  ancestor: ResolvedPackageNode,
  chains: readonly ResolvedPackageNode[][],
): AncestorChoice {
  // Other packages depending on the ancestor keep their own (old) copy unless their ranges admit
  // the new version; pnpm never re-points them on `add`.
  const dependents = ctx.parents(ancestor.key);
  if (dependents.length > 0 && (ctx.pm === "pnpm" || ctx.pm === "yarn"))
    return { ok: false, reason: "shared_ancestor" };
  const ranges = ctx.knownRanges(dependents);
  if (ranges === null) return { ok: false, reason: "range_unknown" };
  const pkg = ctx.registry.package(ancestor.name);
  if (pkg === undefined) return { ok: false, reason: "metadata_missing" };
  const candidates = Object.entries(pkg.versions)
    .filter(
      ([version, manifest]) =>
        !manifest.deprecated && isCompatibleUpgrade(ancestor.version, version),
    )
    .map(([version]) => version)
    .toSorted(semver.compare);

  let failure: LadderSkipReason = "no_parent_version";
  for (const version of candidates) {
    if (!ranges.every((range) => semver.satisfies(version, range))) {
      failure = "shared_ancestor";
      continue;
    }
    const outcomes = chains.map((chain) => simulateChain(ctx, chain, version));
    if (outcomes.some((outcome) => !outcome.ok && outcome.reason === "metadata_missing")) {
      failure = "metadata_missing";
    }
    const targets: (PackageVersion | null)[] = [];
    for (const outcome of outcomes) if (outcome.ok) targets.push(outcome.target);
    const chosen = packageVersionSchema.safeParse(version);
    if (targets.length === outcomes.length && chosen.success) {
      return {
        ok: true,
        version: chosen.data,
        target: targets.find((target) => target !== null) ?? null,
      };
    }
  }
  return { ok: false, reason: failure };
}

/** Rung 4: update the nearest direct ancestors so they pull a safe version of the target. */
export function parentUpdate(ctx: LadderContext, node: ResolvedPackageNode): TechniqueResult {
  if (node.isDirect) return skip("not_transitive");
  if (node.pathsTruncated || node.paths.length === 0) return skip("paths_truncated");
  if (ctx.overridesTarget(node.name)) return skip("override_conflict");

  const writtenEdits: ManifestEdit[] = [];
  const commands: PmCommand[] = [];
  const pins: Pin[] = [];
  const via: LadderStep["via"][number][] = [];
  const anchors: PackageName[] = [node.name];
  let reached: PackageVersion | null = null;

  for (const [ancestorKey, chains] of chainsByAncestor(ctx, node.paths)) {
    const ancestor = ctx.node(ancestorKey);
    if (ancestor.patched) return skip("patched_instance");
    const choice = chooseAncestorVersion(ctx, ancestor, chains);
    if (!choice.ok) return skip(choice.reason);
    const pinned = pinDirect(ctx, ctx.directDeclarations(ancestorKey), choice.version);
    if (!pinned.ok) return skip(pinned.reason);
    writtenEdits.push(...pinned.pinning.writtenEdits);
    commands.push(...pinned.pinning.commands);
    pins.push(...pinned.pinning.pins);
    via.push({ name: ancestor.name, from: ancestor.version, to: choice.version });
    anchors.push(ancestor.name);
    reached ??= choice.target;
  }

  return {
    ok: true,
    technique: {
      rung: "4",
      kind: "parent_update",
      from: node.version,
      to: reached,
      via,
      applyEdits: [],
      writtenEdits,
      preCommands: [],
      commands,
      pins,
      anchors,
    },
  };
}
