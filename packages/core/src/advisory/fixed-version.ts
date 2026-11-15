import type { PackageName } from "@kovo/contracts";

import type { AdvisoryRange } from "./model.js";
import { compileRange, compiledRangeAffects } from "./ranges.js";
import { parseNpmVersion, type NpmVersion } from "./version.js";

// The public repo check's "Kovo would update it to" version: the lowest
// version above the installed one that a range of the package names as `fixed` and that no known
// advisory range or listed version of the package affects. It is read from advisory data alone (no
// registry read), so it is the first fixed version, not a verified install target: the real fix
// resolves its target against published versions (`resolveTarget`).

/**
 * The lowest `fixed` event version above `installed` that none of `ranges` (every known range of
 * `packageName`, from every advisory) affects; null when there is none. A prerelease is a candidate
 * only when the installed version is one.
 */
export function firstUnaffectedVersion(
  packageName: PackageName,
  installed: string,
  ranges: readonly AdvisoryRange[],
): string | null {
  const current = parseNpmVersion(installed);
  if (current === null) return null;
  const compiled = ranges.filter((range) => range.package === packageName).map(compileRange);
  const candidates = new Map<string, NpmVersion>();
  for (const range of ranges) {
    if (range.package !== packageName || range.rangeType === null || range.rangeType === "GIT")
      continue;
    for (const event of range.events) {
      if (event.kind !== "fixed") continue;
      const version = parseNpmVersion(event.version);
      if (version === null || version.compare(current) <= 0) continue;
      if (version.prerelease.length > 0 && current.prerelease.length === 0) continue;
      candidates.set(version.version, version);
    }
  }
  const ordered = [...candidates.values()].toSorted((a, b) => a.compare(b));
  for (const candidate of ordered) {
    if (!compiled.some((range) => compiledRangeAffects(range, candidate))) return candidate.version;
  }
  return null;
}
