import type { AdvisoryId, PackageVersion } from "@kovo/contracts";
import semver from "semver";

import type { TargetRequest, TargetResolution } from "../../advisory/target.js";
import type { LadderTarget } from "./types.js";

// The ladder's input from target resolution (SPEC fixWorkflow step 1 "Resolve an eligible target
// from current findings and registry metadata", then step 3 "run the deterministic ladder"). The
// safe set is `resolveTarget`'s `eligibleVersions`: every candidate that clears the targeted ranges,
// introduces no new P0/P1 or malicious finding and (for P1) has cleared the 24-hour cooldown.

function uniqueSorted(versions: Iterable<PackageVersion>): PackageVersion[] {
  return [...new Set(versions)].toSorted(semver.compare);
}

/**
 * The ladder target for a resolved fix target, or null when there is nothing to plan: a P1 target
 * still in its cooldown (the fix waits), no fixed version of a non-malicious package, or no
 * actionable advisory. A malicious package without any safe version is still a target, with an
 * empty safe set: rung M then plans a reviewed removal when that is feasible.
 */
export function ladderTargetFor(
  request: TargetRequest,
  resolution: TargetResolution,
): LadderTarget | null {
  const targeted = request.instances.filter((instance) => instance.advisoryIds.length > 0);
  const targetedIds = new Set<AdvisoryId>(targeted.flatMap((instance) => instance.advisoryIds));
  const active = request.advisories.filter(
    (advisory) => targetedIds.has(advisory.id) && advisory.withdrawnAt === null,
  );
  const malicious = active.some((advisory) => advisory.isMalicious);
  const affectedVersions = uniqueSorted(targeted.map((instance) => instance.version));

  switch (resolution.status) {
    case "target": {
      const safeVersions = uniqueSorted(resolution.eligibleVersions);
      return malicious
        ? {
            kind: "malicious",
            name: request.package,
            affectedVersions,
            safeVersions,
            advisoryIds: resolution.clearedAdvisoryIds,
          }
        : { kind: "upgrade", name: request.package, affectedVersions, safeVersions };
    }
    case "no_eligible_target":
      return resolution.reason === "no_safe_version"
        ? {
            kind: "malicious",
            name: request.package,
            affectedVersions,
            safeVersions: [],
            advisoryIds: active.map((advisory) => advisory.id),
          }
        : null;
    case "wait":
    case "no_actionable_advisories":
      return null;
    default: {
      const unreachable: never = resolution;
      throw new RangeError(`unknown resolution ${JSON.stringify(unreachable)}`);
    }
  }
}
