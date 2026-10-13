import type { SemverBump } from "@kovo/contracts";
import semver from "semver";

import {
  bumpBetween,
  caretLine,
  isPatchMinorUpgrade,
  versionStep,
  type VersionStep,
} from "../versions/step.js";

// SemVer distance between two exact versions (SPEC: "Evaluate semantic version changes across the
// whole changed dependency graph, including transitives"; "Autopilot only merges dependency-only
// patch/minor updates"). The step is the one core/policy judges (`versions/step.ts`), so the
// ladder's patch/minor rungs and decideMerge gate 3 cannot disagree: leaving a caret line is a
// major step (below 1.0.0 a minor change, below 0.1.0 a patch change) and a prerelease on either
// side is a prerelease step.

export interface VersionChange {
  readonly direction: "upgraded" | "downgraded";
  /** The highest differing component (evidence `bump`). */
  readonly bump: SemverBump;
  /** The step policy judges (`patch`/`minor` may auto-merge; anything else needs review). */
  readonly step: VersionStep;
  /** Crosses a caret-compatibility line (`^from` does not admit `to`, or the reverse). */
  readonly breaking: boolean;
  /** The new version is a prerelease (no compatibility promise, SemVer §9). */
  readonly toPrerelease: boolean;
}

/** The caret line a version belongs to: `3`, `0.4`, or `0.0.7`. */
export function compatibilityLine(version: string): string {
  const parsed = semver.parse(version);
  if (parsed === null) throw new RangeError("not an exact SemVer version");
  return caretLine(parsed);
}

/** Classifies `from → to`, or returns null when the versions are equal (build metadata ignored). */
export function classifyVersionChange(from: string, to: string): VersionChange | null {
  const a = semver.parse(from);
  const b = semver.parse(to);
  if (a === null || b === null) throw new RangeError("not an exact SemVer version");
  const order = semver.compare(a, b);
  if (order === 0) return null;
  return {
    direction: order < 0 ? "upgraded" : "downgraded",
    bump: bumpBetween(a, b),
    step: versionStep(from, to),
    breaking: caretLine(a) !== caretLine(b),
    toPrerelease: b.prerelease.length > 0,
  };
}

/**
 * Whether moving `from → to` is a forward patch or minor step, the only upgrades rungs 1–4 plan
 * and autopilot merges. A prerelease on either side is not (`1.0.0-rc.1 → 1.0.1` is a prerelease
 * step, review-only in decideMerge).
 */
export function isCompatibleUpgrade(from: string, to: string): boolean {
  return isPatchMinorUpgrade(from, to);
}
