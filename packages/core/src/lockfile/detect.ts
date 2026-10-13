import {
  ADMITTED_PACKAGE_MANAGERS,
  type PackageManager,
  type UnsupportedRepoReason,
} from "@kovo/contracts";

import { LOCKFILE_NAMES, type LockfileName } from "./parse.js";

// Exactly one supported lockfile must be committed next to package.json; Berry/PnP remain refused.

/** Lockfiles of package managers Kovo does not support, and npm's publish-time shrinkwrap. */
export const FOREIGN_LOCKFILES = {
  "bun.lockb": "bun",
  "bun.lock": "bun",
  "npm-shrinkwrap.json": "npm-shrinkwrap",
} as const;

/** Files that make a `yarn.lock` a Yarn Berry/PnP project, which Kovo refuses. */
export const YARN_BERRY_MARKERS = [
  ".yarnrc.yml",
  ".pnp.js",
  ".pnp.cjs",
  ".pnp.loader.mjs",
] as const;

export const DETECTION_REJECTION_REASONS = [
  "missing_package_json",
  "missing_lockfile",
  "multiple_lockfiles", // two supported lockfiles, or a supported one next to a foreign one
  "foreign_lockfile", // only yarn.lock / bun.lock(b)
  "npm_shrinkwrap", // npm-shrinkwrap.json takes precedence over package-lock.json in npm
] as const;
export type DetectionRejectionReason = (typeof DETECTION_REJECTION_REASONS)[number];

export const DETECTION_REJECTION_UNSUPPORTED = {
  missing_package_json: "missing_package_json",
  missing_lockfile: "missing_lockfile",
  multiple_lockfiles: "ambiguous_package_manager",
  foreign_lockfile: "unsupported_package_manager",
  npm_shrinkwrap: "unsupported_lockfile_format",
} as const satisfies Record<DetectionRejectionReason, UnsupportedRepoReason>;

export type DetectionResult =
  | {
      readonly ok: true;
      readonly packageManager: PackageManager;
      readonly lockfileName: LockfileName;
    }
  | {
      readonly ok: false;
      readonly reason: DetectionRejectionReason;
      readonly unsupported: UnsupportedRepoReason;
    };

function reject(reason: DetectionRejectionReason): DetectionResult {
  return { ok: false, reason, unsupported: DETECTION_REJECTION_UNSUPPORTED[reason] };
}

/**
 * Detects the package manager from the names of the files at the repository root (the inventory
 * lists the root tree; nothing is cloned).
 */
export function detectPackageManager(rootFiles: readonly string[]): DetectionResult {
  const present = new Set(rootFiles);
  if (!present.has("package.json")) return reject("missing_package_json");
  const supported = ADMITTED_PACKAGE_MANAGERS.flatMap((pm) =>
    present.has(LOCKFILE_NAMES[pm]) ? [[pm, LOCKFILE_NAMES[pm]] as const] : [],
  );
  const foreign = Object.keys(FOREIGN_LOCKFILES).filter((file) => present.has(file));
  if (present.has("npm-shrinkwrap.json")) return reject("npm_shrinkwrap");
  if (supported.length > 1 || (supported.length === 1 && foreign.length > 0)) {
    return reject("multiple_lockfiles");
  }
  const [only] = supported;
  if (only === undefined)
    return reject(foreign.length > 0 ? "foreign_lockfile" : "missing_lockfile");
  if (only[0] === "yarn" && YARN_BERRY_MARKERS.some((name) => present.has(name)))
    return reject("foreign_lockfile");
  return { ok: true, packageManager: only[0], lockfileName: only[1] };
}
