import semver from "semver";

import { npmTarballUrl, packageVersionSchema } from "@kovo/contracts/npm";

import type { PackageManifest } from "../manifest/package-json.js";
import type { Instance, InstanceSet, RootDependency } from "./instances.js";
import { RejectionCollector } from "./reasons.js";
import { GRAPH_LIMITS, SECTION_KIND, type LockfileLimits } from "./types.js";

// A root with a package.json and no lockfile (no longer refused before any sandbox, for direct
// dependencies only). Nothing pins what an install gets, so
// the graph is the declared ranges' floors: each registry dependency is one direct instance at the
// lowest version its range admits (`semver.minVersion`), and nothing is known below it. A finding is
// then "this range still admits an affected version", and the only fix is a range edit at the
// dependency's own package.json pointer. Transitive findings cannot exist here and the ladder refuses
// them as `lockfile_absent_transitive`. Dist-tags and unbounded floors (`*`, `>=0`) name no floor and
// are left out: Kovo cannot say which version they install.

export type ManifestOnlyResult =
  | { readonly ok: true; readonly instances: InstanceSet }
  | { readonly ok: false; readonly rejections: RejectionCollector };

/** The lowest version `range` admits, or null when it names none (a tag, `*`, `>=0.0.0`). */
export function rangeFloor(range: string): string | null {
  let floor: semver.SemVer | null;
  try {
    floor = semver.minVersion(range);
  } catch {
    return null;
  }
  if (floor === null || floor.version === "0.0.0") return null;
  return floor.version;
}

export function manifestOnlyInstances(
  manifest: PackageManifest,
  limits: LockfileLimits = GRAPH_LIMITS,
): ManifestOnlyResult {
  const rejections = new RejectionCollector();
  const instances = new Map<string, Instance>();
  const root: RootDependency[] = [];
  if (manifest.dependencies.length > limits.maxDependencyEdges) {
    rejections.add("too_many_dependencies");
    return { ok: false, rejections };
  }
  for (const dep of manifest.dependencies) {
    if (dep.section === "peerDependencies" || dep.registrySpec.kind !== "range") continue;
    const floor = rangeFloor(dep.registrySpec.range);
    const version = floor === null ? null : packageVersionSchema.safeParse(floor);
    if (version === null || !version.success) continue;
    const id = `manifest:${dep.section}:${dep.alias}`;
    instances.set(id, {
      id,
      name: dep.name,
      version: version.data,
      integrity: null,
      integrityAlgorithm: null,
      resolved: npmTarballUrl(dep.name, version.data),
      bundled: false,
      bundles: [],
      hasInstallScript: null,
      patched: false,
      edges: [],
    });
    root.push({
      alias: dep.alias,
      section: dep.section,
      spec: dep.spec,
      edge: {
        alias: dep.alias,
        kind: SECTION_KIND[dep.section],
        range: dep.spec,
        optional: dep.section === "optionalDependencies",
        target: id,
      },
    });
  }
  return {
    ok: true,
    instances: {
      packageManager: "manifest-only",
      format: "manifest-only",
      root,
      instances,
      lockfileOverrides: [],
    },
  };
}
