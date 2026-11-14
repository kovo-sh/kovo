import type { AdvisoryMatch } from "./match.js";

function pairKey(match: Pick<AdvisoryMatch, "advisoryId" | "package">): string {
  return `${match.advisoryId}\u0000${match.package}`;
}

function instanceKey(match: Pick<AdvisoryMatch, "advisoryId" | "package" | "version">): string {
  return `${pairKey(match)}\u0000${match.version}`;
}

function copyKey(match: AdvisoryMatch): string {
  return `${instanceKey(match)}\u0000${match.isDev}`;
}

/**
 * Targeted instances must disappear, including moves to another affected version. An affected
 * copy may remain only if it already matched in the base, was not targeted, and kept its dev/prod
 * status. Findings identify instances by (advisory, package, version), not dependency path.
 * Withdrawn matches supply neither a refusal nor permission to carry a live match.
 */
export function targetedFindingsCleared(input: {
  readonly targeted: readonly Pick<AdvisoryMatch, "advisoryId" | "package" | "version">[];
  readonly base: readonly AdvisoryMatch[];
  readonly patched: readonly AdvisoryMatch[];
}): readonly boolean[] {
  const targeted = new Set(input.targeted.map(instanceKey));
  const untargetedBase = new Set(
    input.base
      .filter((match) => !match.withdrawn && !targeted.has(instanceKey(match)))
      .map(copyKey),
  );
  const remaining = new Set(
    input.patched
      .filter((match) => !match.withdrawn && !untargetedBase.has(copyKey(match)))
      .map(pairKey),
  );
  return input.targeted.map((finding) => !remaining.has(pairKey(finding)));
}
