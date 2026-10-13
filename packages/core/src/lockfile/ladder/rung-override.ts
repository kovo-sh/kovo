import type { PackageName, PackageVersion } from "@kovo/contracts";
import semver from "semver";

import { isJsonObject, type JsonValue } from "../../manifest/bounded-json.js";
import { parseYarnSelector } from "../../manifest/selectors.js";
import { getAtPointer, pointerOf } from "../../manifest/json-pointer.js";
import { compatibilityLine } from "../semver-change.js";
import type { ResolvedPackageNode } from "../types.js";
import { compareStrings } from "../util.js";
import { skip, type LadderContext, type TechniqueResult } from "./context.js";
import type { LadderSkipReason, ManifestEdit } from "./types.js";

// Rung 5: "Narrow npm `overrides` or pnpm parent-scoped override". The override is scoped to each
// exact parent package/version that depends on the affected instance and pins the child to an
// exact safe version:
//   npm   package.json#/overrides/<parent>@<version>/<child>        = "<safe version>"
//   pnpm  package.json#/pnpm/overrides/<parent>@<version>><child>   = "<safe version>"
// Both forms were run with npm 10/11 and pnpm 9/10 (test-fixtures/lockfiles/override). Overrides
// may qualify for auto-merge under the owner's narrow override rule (2026-10-04), after trusted
// manifest/whole-graph checks, provenance and every other merge gate pass.

/**
 * The narrow override edits that force every parent of `node` onto `version`, or why they cannot
 * be written (an existing rule already covers the selector, an aliased edge).
 */
export function overrideEdits(
  ctx: LadderContext,
  node: ResolvedPackageNode,
  version: PackageVersion,
):
  | { readonly ok: true; readonly edits: readonly ManifestEdit[] }
  | { readonly ok: false; readonly reason: LadderSkipReason } {
  if (
    ctx.pm === "pnpm" &&
    ctx.input.pmVersion !== undefined &&
    (!semver.valid(ctx.input.pmVersion) || semver.major(ctx.input.pmVersion) >= 11)
  )
    return { ok: false, reason: "override_storage_unsupported" };
  if (ctx.overridesTarget(node.name)) return { ok: false, reason: "override_conflict" };
  const parents = ctx.parents(node.key);
  if (parents.length === 0) return { ok: false, reason: "not_transitive" };
  if (parents.some((link) => link.edge.alias !== node.name))
    return { ok: false, reason: "aliased_edge" };
  const document: JsonValue = ctx.manifest.document;
  const edits = new Map<string, ManifestEdit>();
  for (const { parent } of parents) {
    const selector = `${parent.name}@${parent.version}`;
    let pointer: string;
    if (ctx.pm === "npm") {
      // A string at the parent selector overrides the parent itself; nesting under it is invalid.
      const existing = getAtPointer(document, pointerOf(["overrides", selector]));
      if (existing !== undefined && !isJsonObject(existing)) {
        return { ok: false, reason: "override_conflict" };
      }
      pointer = pointerOf(["overrides", selector, node.name]);
      // A rule keyed by a direct dependency also sets that dependency's own spec (npm reads the
      // key's `@<version>` as the rule's value), and npm refuses an override that changes a direct
      // dependency's declared spec (EOVERRIDE) unless both are the same: `"."` keeps it by
      // reference (`$<name>`) when the declaration is not exactly the locked version.
      const selfPointer = pointerOf(["overrides", selector, "."]);
      const declared = ctx.graph.direct.filter((direct) => direct.target === parent.key);
      if (declared.some((direct) => direct.alias !== parent.name)) {
        return { ok: false, reason: "aliased_edge" };
      }
      if (declared.some((direct) => direct.spec !== parent.version)) {
        if (getAtPointer(document, selfPointer) !== undefined) {
          return { ok: false, reason: "override_conflict" };
        }
        edits.set(selfPointer, { op: "set", pointer: selfPointer, value: `$${parent.name}` });
      }
    } else if (ctx.pm === "yarn") {
      // Classic resolves package-name paths, never parent@version paths. Trusted whole-graph
      // validation must account for every matching parent version.
      const path = `**/${parent.name}/${node.name}`;
      if (parseYarnSelector(path) === null) return { ok: false, reason: "unsafe_package_name" };
      pointer = pointerOf(["resolutions", path]);
    } else {
      pointer = pointerOf(["pnpm", "overrides", `${selector}>${node.name}`]);
    }
    if (getAtPointer(document, pointer) !== undefined)
      return { ok: false, reason: "override_conflict" };
    edits.set(pointer, { op: "set", pointer, value: version });
  }
  return {
    ok: true,
    edits: [...edits.values()].toSorted((a, b) => compareStrings(a.pointer, b.pointer)),
  };
}

/**
 * Rung 5: the smallest safe version on the affected version's compatibility line, otherwise the
 * smallest safe version above it (crossing a major is still review-only and verified).
 */
export function narrowOverride(ctx: LadderContext, node: ResolvedPackageNode): TechniqueResult {
  if (node.isDirect) return skip("not_transitive");
  if (node.bundled) return skip("bundled_instance");
  const above = ctx.safe.filter((version) => semver.gt(version, node.version));
  const version =
    above.find((candidate) => compatibilityLine(candidate) === compatibilityLine(node.version)) ??
    above[0];
  if (version === undefined) return skip("no_safe_version");
  const edits = overrideEdits(ctx, node, version);
  if (!edits.ok) return skip(edits.reason);
  const anchors: PackageName[] = [node.name];
  return {
    ok: true,
    technique: {
      rung: "5",
      kind: "override",
      from: node.version,
      to: version,
      via: [],
      applyEdits: edits.edits,
      writtenEdits: [],
      preCommands: [],
      commands: [],
      pins: [],
      anchors,
    },
  };
}
