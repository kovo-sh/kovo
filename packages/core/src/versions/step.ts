import type { SemverBump } from "@kovo/contracts";
import semver from "semver";

// How far apart two versions are, defined once for every area that judges it: core/policy
// (decideMerge gate 3), core/lockfile (the whole-graph diff and the ladder's patch/minor rungs) and
// core/advisory (a target's distance per instance). SPEC: "Autopilot only merges dependency-only
// patch/minor updates"; "Evaluate semantic version changes across the whole changed dependency
// graph, including transitives".

/** A version step as policy judges it; anything but `patch`/`minor` needs review. */
export type VersionStep = SemverBump | "unparseable";

/** Order of severity, for combining a recorded bump with a computed step. */
export const VERSION_STEP_SEVERITY: Readonly<Record<VersionStep, number>> = {
  patch: 0,
  minor: 1,
  prerelease: 2,
  major: 3,
  unparseable: 4,
};

/**
 * The npm caret line a version belongs to (`^x` admits only versions on its line): `3` for 3.x,
 * `0.4` for 0.4.x, `0.0.7` for 0.0.7 and its prereleases.
 */
export function caretLine(version: semver.SemVer): string {
  if (version.major > 0) return `${version.major}`;
  if (version.minor > 0) return `0.${version.minor}`;
  return `0.0.${version.patch}`;
}

/**
 * The highest differing component, `prerelease` when only the prerelease differs (evidence
 * `bump`; node-semver's `diff` would call `1.0.0-rc.1 → 1.0.0` a major). Equal versions are
 * `prerelease` too; callers compare only different versions.
 */
export function bumpBetween(a: semver.SemVer, b: semver.SemVer): SemverBump {
  if (a.major !== b.major) return "major";
  if (a.minor !== b.minor) return "minor";
  if (a.patch !== b.patch) return "patch";
  return "prerelease";
}

/**
 * The step from `from` to `to` under npm's caret semantics: leaving the caret line (a major
 * change, a `0.x` minor change or a `0.0.x` patch change) is a major step; a prerelease on either
 * side is a prerelease step, never patch/minor (SemVer §9: no compatibility promise).
 */
export function versionStep(from: string, to: string): VersionStep {
  const a = semver.parse(from);
  const b = semver.parse(to);
  if (a === null || b === null) return "unparseable";
  if (a.prerelease.length > 0 || b.prerelease.length > 0) return "prerelease";
  if (caretLine(a) !== caretLine(b)) return "major";
  if (a.minor !== b.minor) return "minor";
  return "patch";
}

/** Whether `from → to` moves forward by a patch/minor step (what autopilot may merge). */
export function isPatchMinorUpgrade(from: string, to: string): boolean {
  const step = versionStep(from, to);
  return (step === "patch" || step === "minor") && semver.gt(to, from);
}
