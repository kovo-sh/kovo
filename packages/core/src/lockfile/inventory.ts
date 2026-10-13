import type { PackageName, PackageVersion } from "@kovo/contracts";

import { GRAPH_LIMITS, indexPackages, type DependencyGraph } from "./types.js";

// The inventory view of a graph: one row per resolved package/version (SPEC `resolved_packages(
// snapshot_id, name, version, is_direct, is_dev, dep_paths JSONB)`: "retain all paths needed to
// resolve multiple affected instances; is_dev is false if any prod path exists"). Paths are package
// name chains from a direct dependency, never manifests.

export interface InventoryPackage {
  readonly name: PackageName;
  readonly version: PackageVersion;
  readonly isDirect: boolean;
  readonly isDev: boolean;
  readonly depPaths: readonly (readonly PackageName[])[];
  /** Some paths were not recorded (see `ResolvedPackageNode.pathsTruncated`). */
  readonly pathsTruncated: boolean;
}

/** One inventory row per package/version, with name paths deduplicated and bounded. */
export function toInventoryPackages(graph: DependencyGraph): InventoryPackage[] {
  const index = indexPackages(graph);
  return graph.packages.map((node) => {
    const seen = new Set<string>();
    const depPaths: PackageName[][] = [];
    for (const path of node.paths) {
      const names = path.slice(-GRAPH_LIMITS.maxPathDepth).flatMap((key) => {
        const step = index.get(key);
        return step === undefined ? [] : [step.name];
      });
      const id = names.join("\u0000");
      if (seen.has(id)) continue;
      seen.add(id);
      depPaths.push(names);
    }
    return {
      name: node.name,
      version: node.version,
      isDirect: node.isDirect,
      isDev: node.isDev,
      depPaths,
      pathsTruncated: node.pathsTruncated,
    };
  });
}
