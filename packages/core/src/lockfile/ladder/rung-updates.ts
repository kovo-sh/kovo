import type { PackageVersion } from "@kovo/contracts";
import semver from "semver";

import type { ManifestDependency } from "../../manifest/package-json.js";
import { classifyVersionChange, isCompatibleUpgrade } from "../semver-change.js";
import type { DirectDependency, ResolvedPackageNode } from "../types.js";
import { installCommand, updateCommand } from "./commands.js";
import {
  dependencyPointer,
  installSpecFor,
  saveStyleOf,
  skip,
  specFor,
  unsafeNames,
  type LadderContext,
  type Pin,
  type TechniqueResult,
} from "./context.js";
import type { LadderSkipReason, ManifestEdit, PmCommand } from "./types.js";

// Rungs 1–3 (SPEC ladder: "1 | Lockfile-only transitive patch/minor update", "2 | Direct dependency
// patch update", "3 | Direct dependency minor update"). Each function clears one affected instance
// or says why it cannot.

/** Rung 1: move a transitive instance within every dependent's declared range, lockfile only. */
export function lockfileUpdate(ctx: LadderContext, node: ResolvedPackageNode): TechniqueResult {
  // Yarn install preserves satisfying transitive entries; resolutions is the reliable rung.
  if (ctx.pm === "yarn") return skip("no_compatible_version");
  if (node.isDirect) return skip("not_transitive");
  if (ctx.nameIsDirect(node.name)) return skip("name_shared_with_direct");
  if (node.bundled) return skip("bundled_instance");
  if (node.patched) return skip("patched_instance");
  if (ctx.overridesTarget(node.name)) return skip("override_conflict");
  if (unsafeNames(node.name)) return skip("unsafe_package_name");
  const parents = ctx.parents(node.key);
  if (parents.some((link) => link.edge.alias !== node.name)) return skip("aliased_edge");
  const ranges = ctx.knownRanges(parents);
  if (ranges === null) return skip("range_unknown");
  const candidate = ctx.safe.find(
    (version) =>
      isCompatibleUpgrade(node.version, version) &&
      ranges.every((range) => semver.satisfies(version, range)),
  );
  if (candidate === undefined) return skip("no_compatible_version");

  // `npm update`/`pnpm update` take the newest version the ranges admit, not the smallest safe
  // one. When the registry metadata shows that version is not safe, the rung cannot work.
  const predicted = ctx.registry.pickWithin(node.name, ranges);
  if (predicted !== null && !ctx.isSafe(predicted)) return skip("predicted_version_unsafe");
  return {
    ok: true,
    technique: {
      rung: "1",
      kind: "lockfile_update",
      from: node.version,
      to: candidate,
      via: [],
      applyEdits: [],
      writtenEdits: [],
      preCommands: [],
      commands: [updateCommand(ctx.pm, node.name)],
      pins: [],
      anchors: [node.name],
    },
  };
}

export interface DirectPinning {
  readonly writtenEdits: readonly ManifestEdit[];
  readonly commands: readonly PmCommand[];
  readonly pins: readonly Pin[];
}

export type PinningResult =
  | { readonly ok: true; readonly pinning: DirectPinning }
  | { readonly ok: false; readonly reason: LadderSkipReason };

/**
 * The edits, commands and pins that move every root declaration in `declarations` to `version`,
 * keeping each declaration's section and save style (`forceExact` pins exactly). Fails for
 * declarations package.json does not match, duplicated across sections, peer declarations and
 * unsafe names.
 */
export function pinDirect(
  ctx: LadderContext,
  declarations: readonly DirectDependency[],
  version: PackageVersion,
  forceExact = false,
): PinningResult {
  const aliases = declarations.map((declaration) => declaration.alias);
  if (new Set(aliases).size !== aliases.length)
    return { ok: false, reason: "ambiguous_declaration" };
  const writtenEdits: ManifestEdit[] = [];
  const commands: PmCommand[] = [];
  const pins: Pin[] = [];
  for (const direct of declarations) {
    const declaration: ManifestDependency | undefined = ctx.declaration(direct);
    if (declaration === undefined) return { ok: false, reason: "ambiguous_declaration" };
    if (direct.section === "peerDependencies") return { ok: false, reason: "peer_declaration" };
    if (unsafeNames(direct.alias, declaration.name)) {
      return { ok: false, reason: "unsafe_package_name" };
    }
    // Classic regenerates via install rather than an exact CLI add; a range could select a
    // newer unassessed release than the chosen safe version. Pin its trusted manifest edit.
    const style = forceExact || ctx.pm === "yarn" ? "exact" : saveStyleOf(declaration);
    writtenEdits.push({
      op: "set",
      pointer: dependencyPointer(declaration),
      value: specFor(declaration, version, style),
    });
    commands.push(
      installCommand(
        ctx.pm,
        direct.alias,
        installSpecFor(declaration, version),
        direct.section,
        style,
      ),
    );
    pins.push({ alias: direct.alias, name: declaration.name, version });
  }
  return { ok: true, pinning: { writtenEdits, commands, pins } };
}

/**
 * Rungs 2 and 3: move a direct dependency to the smallest safe patch (rung 2) or minor (rung 3)
 * version. When other packages also depend on the same instance, their ranges must admit the new
 * version and a lockfile update moves them first (pnpm never re-points other dependents on its own).
 */
export function directUpdate(
  ctx: LadderContext,
  node: ResolvedPackageNode,
  rung: "2" | "3",
): TechniqueResult {
  const declarations = ctx.directDeclarations(node.key);
  if (declarations.length === 0) return skip("not_direct");
  if (node.patched) return skip("patched_instance");
  const wanted = rung === "2" ? "patch" : "minor";
  const candidate = ctx.safe.find(
    (version) =>
      isCompatibleUpgrade(node.version, version) &&
      classifyVersionChange(node.version, version)?.bump === wanted,
  );
  if (candidate === undefined) return skip("no_compatible_version");

  const parents = ctx.parents(node.key);
  const preCommands: PmCommand[] = [];
  if (parents.length > 0) {
    if (parents.some((link) => link.edge.alias !== node.name)) return skip("aliased_edge");
    if (unsafeNames(node.name)) return skip("unsafe_package_name");
    const ranges = ctx.knownRanges(parents);
    if (ranges === null) return skip("range_unknown");
    if (!ranges.every((range) => semver.satisfies(candidate, range)))
      return skip("shared_ancestor");
    preCommands.push(updateCommand(ctx.pm, node.name));
  }
  const pinned = pinDirect(ctx, declarations, candidate);
  if (!pinned.ok) return skip(pinned.reason);
  return {
    ok: true,
    technique: {
      rung,
      kind: "direct_update",
      from: node.version,
      to: candidate,
      via: [],
      applyEdits: [],
      writtenEdits: pinned.pinning.writtenEdits,
      preCommands,
      commands: pinned.pinning.commands,
      pins: pinned.pinning.pins,
      anchors: [node.name],
    },
  };
}
