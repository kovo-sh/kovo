import semver from "semver";

import { isCompatibleUpgrade } from "../semver-change.js";
import type { ResolvedPackageNode } from "../types.js";
import { updateCommand } from "./commands.js";
import { skip, unsafeNames, type LadderContext, type TechniqueResult } from "./context.js";
import { pinDirect } from "./rung-updates.js";
import { MAJOR_RUNG, type PmCommand } from "./types.js";

// Rung 6 (SPEC ladder: "6 | Major upgrade, optionally agent-assisted on Plus | Human review"): the
// deterministic part. A direct instance moves to the smallest safe version on a newer major line,
// keeping its declarations' sections and save styles, exactly as rungs 2 and 3 move within a line.
// A transitive instance has no deterministic major technique here: moving a direct ancestor across
// a major line is what the agent does (a major ancestor may drop, rename or re-range the target).
// Every plan at this rung needs human review ("Major upgrade … Human review"; "Any override/source
// edit/new top-level dependency prevents auto-merge regardless of rung").

/** Rung 6: move a direct dependency to the smallest safe version of a newer major line. */
export function majorUpgrade(ctx: LadderContext, node: ResolvedPackageNode): TechniqueResult {
  const declarations = ctx.directDeclarations(node.key);
  if (declarations.length === 0) return skip("not_direct");
  if (node.patched) return skip("patched_instance");
  const candidate = ctx.safe.find(
    (version) =>
      semver.gt(version, node.version) &&
      semver.prerelease(version) === null &&
      !isCompatibleUpgrade(node.version, version),
  );
  if (candidate === undefined) return skip("no_major_version");

  // Other packages depending on the same instance keep it unless their ranges admit the new major
  // (they rarely do); a lockfile update moves them first when they do.
  const parents = ctx.parents(node.key);
  const preCommands: PmCommand[] = [];
  if (parents.length > 0) {
    if (parents.some((link) => link.edge.alias !== node.name)) return skip("aliased_edge");
    if (unsafeNames(node.name)) return skip("unsafe_package_name");
    const ranges = ctx.knownRanges(parents);
    if (ranges === null) return skip("range_unknown");
    if (!ranges.every((range) => semver.satisfies(candidate, range))) {
      return skip("shared_ancestor");
    }
    preCommands.push(updateCommand(ctx.pm, node.name));
  }
  const pinned = pinDirect(ctx, declarations, candidate);
  if (!pinned.ok) return skip(pinned.reason);
  return {
    ok: true,
    technique: {
      rung: MAJOR_RUNG,
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
