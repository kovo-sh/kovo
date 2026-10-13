import { exactVersionSchema, type PackageVersion } from "@kovo/contracts";
import semver from "semver";

// npm version handling for advisory ranges. OSV evaluates SEMVER and ECOSYSTEM ranges on npm with
// SemVer 2.0.0 precedence (prereleases included, build metadata ignored); `semver.satisfies` with
// synthesized ranges is never used, because npm range semantics exclude prereleases
// (docs/libraries/sandbox-ai-feeds.md §5.2).

/** A parsed exact version (node-semver's `SemVer`, strict SemVer 2.0.0 input only). */
export type NpmVersion = semver.SemVer;

/**
 * Parses an exact SemVer 2.0.0 version (the contracts `exactVersionSchema` form: no leading `v`, no
 * range operators, no core component beyond `Number.MAX_SAFE_INTEGER`, which node-semver refuses)
 * or returns null. It accepts exactly what the schema accepts (`version.test.ts`).
 */
export function parseNpmVersion(text: string): NpmVersion | null {
  if (!exactVersionSchema.safeParse(text).success) return null;
  try {
    return new semver.SemVer(text);
  } catch {
    return null;
  }
}

/** Whether `text` is an exact version Kovo can compare (see {@link parseNpmVersion}). */
export function isNpmVersion(text: string): text is PackageVersion {
  return parseNpmVersion(text) !== null;
}

/** A version string with its parsed form, or null (see {@link parseNpmVersion}). */
export function parseVersionText(
  text: string,
): { readonly text: PackageVersion; readonly version: NpmVersion } | null {
  const version = parseNpmVersion(text);
  return version !== null && isNpmVersion(text) ? { text, version } : null;
}

/** SemVer 2.0.0 precedence: −1, 0 or 1. Build metadata does not count. */
export function compareNpmVersions(a: NpmVersion, b: NpmVersion): -1 | 0 | 1 {
  return a.compare(b);
}

/**
 * Orders version strings by SemVer precedence, then by text so that versions differing only in
 * build metadata (or unparseable ones) still sort deterministically.
 */
export function compareVersionText(a: string, b: string): number {
  const pa = parseNpmVersion(a);
  const pb = parseNpmVersion(b);
  if (pa !== null && pb !== null) {
    const order = pa.compare(pb);
    if (order !== 0) return order;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

function stripLeadingZeros(digits: string): string {
  const stripped = digits.replace(/^0+/, "");
  return stripped === "" ? "0" : stripped;
}

/** The result of coercing an OSV range bound or listed version to exact SemVer. */
export interface CoercedVersion {
  readonly version: PackageVersion;
  /** False when the input was already exact SemVer. */
  readonly coerced: boolean;
}

/**
 * Coerces a version string from an OSV record the way osv.dev's own SemVer index does
 * (`osv/semver_index.py` `coerce`): strip one leading `v`, pad a missing minor or patch with `0`
 * (`13.0` → `13.0.0`) and drop leading zeros from the numeric core and numeric prerelease
 * identifiers (`2026.04.1` → `2026.4.1`, which is also how npm itself publishes such a version).
 * Anything that is still not exact SemVer afterwards is null. GitHub-reviewed npm advisories carry
 * such bounds (e.g. `next` GHSA-3h52-269p-cp9r `introduced: "13.0"`), and ignoring them would
 * under-match.
 */
export function coerceOsvVersion(text: string): CoercedVersion | null {
  if (isNpmVersion(text)) return { version: text, coerced: false };
  const unprefixed = text.startsWith("v") ? text.slice(1) : text;
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?((?:-[^+]*)?(?:\+.*)?)$/.exec(unprefixed);
  if (match === null) return null;
  const [, major = "", minor = "0", patch = "0", suffix = ""] = match;
  const suffixMatch = /^(?:-([^+]*))?(?:\+(.*))?$/.exec(suffix);
  if (suffixMatch === null) return null;
  const [, prerelease, build] = suffixMatch;
  let candidate = `${stripLeadingZeros(major)}.${stripLeadingZeros(minor)}.${stripLeadingZeros(patch)}`;
  if (prerelease !== undefined) {
    const identifiers = prerelease
      .split(".")
      .map((id) => (/^\d+$/.test(id) ? stripLeadingZeros(id) : id));
    candidate += `-${identifiers.join(".")}`;
  }
  if (build !== undefined) candidate += `+${build}`;
  return isNpmVersion(candidate) ? { version: candidate, coerced: true } : null;
}

/** The `major.minor.patch` tuple as a string, for prerelease comparisons. */
export function releaseTuple(version: NpmVersion): string {
  return `${version.major}.${version.minor}.${version.patch}`;
}
