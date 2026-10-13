import type { AdvisoryId, PackageName, PackageVersion } from "@kovo/contracts";

import type { TierDecision } from "./tier.js";

// SPEC target resolution: "A candidate must clear the union of all affected ranges/explicit
// versions for every targeted package instance and avoid new P0/P1 or malicious findings."
// fixWorkflow step 5: "no newly introduced P0/P1 or malicious findings … Existing unrelated
// findings and new digest findings are disclosed, not treated as a globally clean-lockfile
// requirement." This is the one definition of "new" for both (docs/decisions/advisory.md "What a
// new P0/P1 or malicious finding is"); the trusted checks re-match the patched graph and use it too.
// Whether targeted findings were cleared is a separate check.

/** An advisory affecting a package version, tiered for it (`AdvisoryMatch` satisfies it). */
export interface TieredMatch {
  readonly advisoryId: AdvisoryId;
  readonly package: PackageName;
  readonly version: PackageVersion;
  readonly tier: Pick<TierDecision, "tier" | "reason">;
}

/** A P0/P1 match; malicious ones are always P0. */
export function isSevere(match: TieredMatch): boolean {
  return match.tier.tier === "P0" || match.tier.tier === "P1";
}

/** The P0/P1 findings before a change, indexed for {@link isIntroducedSevere}. */
export interface SevereBaseline {
  /** `(advisory, package, version)` of every P0/P1 match before the change. */
  readonly instances: ReadonlySet<string>;
  /** `(advisory, package)` of every P0/P1 match before the change. */
  readonly packages: ReadonlySet<string>;
}

const packageKey = (match: TieredMatch) => `${match.advisoryId}\u0000${match.package}`;
const instanceKey = (match: TieredMatch) => `${packageKey(match)}\u0000${match.version}`;

export function severeBaseline(before: Iterable<TieredMatch>): SevereBaseline {
  const instances = new Set<string>();
  const packages = new Set<string>();
  for (const match of before) {
    if (!isSevere(match)) continue;
    instances.add(instanceKey(match));
    packages.add(packageKey(match));
  }
  return { instances, packages };
}

/**
 * Whether a match after a change is a newly introduced P0/P1 or malicious finding:
 *
 * - a digest match never is (disclosed);
 * - a P0/P1 match on a version that already had it at P0/P1 is the existing finding;
 * - a malicious match on any other version always is: a change never lands on malware;
 * - any other P0/P1 match is new unless the same advisory already affected the same package at
 *   P0/P1 before the change (for example a dismissed finding the change cannot clear): the
 *   vulnerability was not introduced, only carried to the new version, and it is disclosed. A
 *   version that becomes production, or an advisory that only affected dev instances, is new.
 */
export function isIntroducedSevere(match: TieredMatch, baseline: SevereBaseline): boolean {
  if (!isSevere(match)) return false;
  if (baseline.instances.has(instanceKey(match))) return false;
  if (match.tier.reason === "malicious") return true;
  return !baseline.packages.has(packageKey(match));
}

/** The matches after a change that are newly introduced P0/P1 or malicious findings. */
export function introducedSevere<M extends TieredMatch>(
  before: Iterable<TieredMatch>,
  after: readonly M[],
): M[] {
  const baseline = severeBaseline(before);
  return after.filter((match) => isIntroducedSevere(match, baseline));
}
