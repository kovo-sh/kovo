import type { PackageVersion } from "@kovo/contracts";
import semver from "semver";

import {
  dependencyPointer,
  skip,
  type LadderContext,
  type Pin,
  type Technique,
  type TechniqueResult,
} from "./context.js";
import { overrideEdits } from "./rung-override.js";
import { pinDirect } from "./rung-updates.js";
import type { ManifestEdit, PmCommand } from "./types.js";
import type { ResolvedPackageNode } from "../types.js";

// Rung M: "Evidenced rollback/removal for malicious package". SPEC: "A rollback requires evidence
// that the chosen version is outside all known malicious/affected ranges; older does not
// automatically mean safe. If no safe version is known, alert immediately and prepare a reviewed
// removal only when feasible, otherwise request human action. Never guess a replacement package."
// The evidence is the caller's: `safeVersions` are the versions target resolution checked against
// every known malicious/affected range (`advisoryIds`). This planner only ever picks from them,
// never from "older than the affected one", and never adds a package.

/** The newest evidenced safe version below `version`, if any. */
export function rollbackVersion(
  ctx: LadderContext,
  version: PackageVersion,
): PackageVersion | null {
  const older = ctx.safe.filter((candidate) => semver.lt(candidate, version));
  return older[older.length - 1] ?? null;
}

/** Rolls one malicious instance back: a pinned exact direct spec and/or narrow parent overrides. */
export function rollback(ctx: LadderContext, node: ResolvedPackageNode): TechniqueResult {
  const version = rollbackVersion(ctx, node.version);
  if (version === null) return skip("no_rollback_version");
  if (node.bundled) return skip("bundled_instance");
  const applyEdits: ManifestEdit[] = [];
  const writtenEdits: ManifestEdit[] = [];
  const commands: PmCommand[] = [];
  const pins: Pin[] = [];
  const declarations = ctx.directDeclarations(node.key);
  if (declarations.length > 0) {
    // Exact, so a later install cannot float back up into the malicious range.
    const pinned = pinDirect(ctx, declarations, version, true);
    if (!pinned.ok) return skip(pinned.reason);
    writtenEdits.push(...pinned.pinning.writtenEdits);
    commands.push(...pinned.pinning.commands);
    pins.push(...pinned.pinning.pins);
  }
  if (ctx.parents(node.key).length > 0) {
    const edits = overrideEdits(ctx, node, version);
    if (!edits.ok) return skip(edits.reason);
    applyEdits.push(...edits.edits);
  }
  return {
    ok: true,
    technique: {
      rung: "M",
      kind: "rollback",
      from: node.version,
      to: version,
      via: [],
      applyEdits,
      writtenEdits,
      preCommands: [],
      commands,
      pins,
      anchors: [node.name],
    },
  };
}

/**
 * Removes a malicious package that only package.json itself requires: every instance is a direct
 * dependency nothing else depends on. Anything else is infeasible without guessing (removing a
 * parent would remove unrelated functionality), so a human decides.
 */
export function removal(
  ctx: LadderContext,
  nodes: readonly ResolvedPackageNode[],
): TechniqueResult {
  const edits: ManifestEdit[] = [];
  for (const node of nodes) {
    if (!node.isDirect || node.pathsTruncated || ctx.parents(node.key).length > 0) {
      return skip("removal_infeasible");
    }
    for (const direct of ctx.directDeclarations(node.key)) {
      const declaration = ctx.declaration(direct);
      if (declaration === undefined) return skip("ambiguous_declaration");
      edits.push({ op: "remove", pointer: dependencyPointer(declaration) });
    }
  }
  const first = nodes[0];
  if (first === undefined) return skip("removal_infeasible");
  const technique: Technique = {
    rung: "M",
    kind: "removal",
    from: first.version,
    to: null,
    via: [],
    applyEdits: edits,
    writtenEdits: [],
    preCommands: [],
    commands: [],
    pins: [],
    anchors: [first.name],
  };
  return { ok: true, technique };
}
