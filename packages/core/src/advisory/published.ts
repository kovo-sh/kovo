import type { PackageName } from "@kovo/contracts";

import type { AdvisoryFacts } from "./model.js";
import { compileAdvisory, compiledAdvisoryAffects, type CompiledAdvisory } from "./ranges.js";
import { parseNpmVersion, type NpmVersion } from "./version.js";

// Evaluating a version that is only known as a range (plans/site-scanner.md §6.3): a detection that
// bounds a site's `next` between two versions is affected by an advisory only if EVERY published
// release inside the bounds is affected. Backports make "older than the fix" wrong (14.2.25 is fixed
// for a bug that 15.0.0–15.2.2 still have), so this always asks the advisory's own ranges, release
// by release. Like npm ranges, prereleases are left out: a range detection says nothing about
// canaries. Pure: the published list is a parameter.

export type RangeAffectedness =
  /** Every published release in the bounds is affected. */
  | "all"
  /** Some are and some are not: the site is possibly affected. */
  | "some"
  /** None is. */
  | "none"
  /** No published release lies in the bounds (nothing to judge). */
  | "empty";

export interface VersionBounds {
  /** Inclusive lower bound, or null for unbounded. */
  readonly min: string | null;
  /** Inclusive upper bound, or null for unbounded. */
  readonly max: string | null;
}

/** The published releases (no prereleases), parsed once and sorted oldest first. */
export function publishedReleases(published: readonly string[]): NpmVersion[] {
  const parsed: NpmVersion[] = [];
  for (const text of published) {
    const version = parseNpmVersion(text);
    if (version !== null && version.prerelease.length === 0) parsed.push(version);
  }
  return parsed.toSorted((a, b) => a.compare(b));
}

function bound(text: string | null): NpmVersion | null {
  if (text === null) return null;
  const parsed = parseNpmVersion(text);
  // An unreadable bound must never widen the range to unbounded.
  if (parsed === null) throw new RangeError(`not an exact version: ${JSON.stringify(text)}`);
  return parsed;
}

/**
 * The releases inside the bounds, oldest first, from {@link publishedReleases}' output. Throws
 * RangeError when a bound is not an exact version.
 */
export function releasesWithin(
  releases: readonly NpmVersion[],
  bounds: VersionBounds,
): NpmVersion[] {
  const min = bound(bounds.min);
  const max = bound(bounds.max);
  return releases.filter(
    (version) =>
      (min === null || version.compare(min) >= 0) && (max === null || version.compare(max) <= 0),
  );
}

/** Whether a compiled advisory affects every, some or none of the given releases. */
export function affectedWithin(
  compiled: CompiledAdvisory,
  packageName: PackageName,
  within: readonly NpmVersion[],
): RangeAffectedness {
  if (within.length === 0) return "empty";
  let affected = 0;
  for (const version of within) {
    if (compiledAdvisoryAffects(compiled, packageName, version)) affected += 1;
  }
  if (affected === within.length) return "all";
  return affected === 0 ? "none" : "some";
}

/**
 * Whether the advisory affects every, some or none of the published releases in the bounds. For
 * many judgements, parse once with {@link publishedReleases}, compile once with
 * `compileAdvisory`, and call {@link releasesWithin} and {@link affectedWithin}.
 */
export function rangeAffectedness(
  advisory: AdvisoryFacts,
  packageName: PackageName,
  published: readonly string[],
  bounds: VersionBounds,
): RangeAffectedness {
  return affectedWithin(
    compileAdvisory(advisory),
    packageName,
    releasesWithin(publishedReleases(published), bounds),
  );
}

/** The newest published release, or the newest of one major; null when there is none. */
export function latestRelease(published: readonly string[], major?: number): string | null {
  let latest: NpmVersion | null = null;
  for (const version of publishedReleases(published)) {
    if (major !== undefined && version.major !== major) continue;
    if (latest === null || version.compare(latest) > 0) latest = version;
  }
  return latest === null ? null : latest.version;
}
