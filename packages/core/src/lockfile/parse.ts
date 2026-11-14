import type { PackageManager, StoredPackageManager, UnsupportedRepoReason } from "@kovo/contracts";

import { PACKAGE_JSON_LIMITS, type PackageManifest } from "../manifest/package-json.js";
import { parseYarnLockfile, YARN_LOCKFILE_LIMITS } from "./yarn.js";

import { primaryUnsupportedReason } from "../manifest/reasons.js";
import { BUN_LOCKFILE_LIMITS, parseBunLockfile } from "./bun.js";
import { buildGraph } from "./build-graph.js";
import type { InstanceSet } from "./instances.js";
import { manifestOnlyInstances } from "./manifest-only.js";
import { NPM_LOCKFILE_LIMITS, parseNpmLockfile } from "./npm.js";
import { parsePnpmLockfile, PNPM_LOCKFILE_LIMITS } from "./pnpm.js";
import { RejectionCollector, type LockfileRejection } from "./reasons.js";
import { GRAPH_LIMITS, packageKey, type DependencyGraph, type LockfileLimits } from "./types.js";
import { isYarnBerryLockfile, parseYarnBerryLockfile } from "./yarn-berry.js";

// One entry point for every supported lockfile: the file name selects the format family, the
// content selects the version, and the result is the normalized graph or explicit rejections.

/** The lockfile each supported package manager commits at the repository root. */
export const LOCKFILE_NAMES = {
  npm: "package-lock.json",
  pnpm: "pnpm-lock.yaml",
  yarn: "yarn.lock",
} as const satisfies Record<PackageManager, string>;
export type LockfileName = (typeof LOCKFILE_NAMES)[PackageManager];

/**
 * The most bytes worth fetching for each lockfile (the GitHub port's `maxBytes`): its parser's
 * length bound. A UTF-8 file of n bytes decodes to at most n UTF-16 code units, so a file within
 * this many bytes is never refused for its length alone, and a larger one is `lockfile_too_large`
 * without being read.
 */
export const LOCKFILE_MAX_BYTES = {
  "package-lock.json": NPM_LOCKFILE_LIMITS.maxLength,
  "pnpm-lock.yaml": PNPM_LOCKFILE_LIMITS.maxLength,
  "yarn.lock": YARN_LOCKFILE_LIMITS.maxLength,
} as const satisfies Record<LockfileName, number>;

/**
 * The file that pins each stored package manager's versions (#8256 R2): the verifiable ones'
 * lockfiles, Yarn 4's `yarn.lock`, Bun's text `bun.lock`, and package.json itself for a root
 * without a lockfile. Only fix paths use it; discovery and the gate keep `LOCKFILE_NAMES`.
 */
export const STORED_LOCKFILE_NAMES = {
  ...LOCKFILE_NAMES,
  "yarn-berry": "yarn.lock",
  bun: "bun.lock",
  "manifest-only": "package.json",
} as const satisfies Record<StoredPackageManager, string>;
export type StoredLockfileName = (typeof STORED_LOCKFILE_NAMES)[StoredPackageManager];

/** A stored lockfile name as a verifiable one, or null for Bun's and a lockfile-less root's. */
export function verifiableLockfileName(name: StoredLockfileName): LockfileName | null {
  return name === "bun.lock" || name === "package.json" ? null : name;
}

export const STORED_LOCKFILE_MAX_BYTES = {
  ...LOCKFILE_MAX_BYTES,
  "bun.lock": BUN_LOCKFILE_LIMITS.maxLength,
  "package.json": PACKAGE_JSON_LIMITS.maxLength,
} as const satisfies Record<StoredLockfileName, number>;

export interface LockfileInput {
  readonly fileName: StoredLockfileName;
  /** The raw lockfile text; never persisted or logged. */
  readonly text: string;
  /** Required for Yarn v1, which contains no root dependency declarations. */
  readonly manifest?: PackageManifest;
  /**
   * Read the fix-only formats (#8256 R2): a Yarn 2+ `yarn.lock` as Yarn 4, `bun.lock`, and a
   * lockfile-less package.json. Off, a Berry `yarn.lock` stays `unsupported_package_manager` and the
   * other two are never parsed (every reader outside the fix paths).
   */
  readonly fixOnly?: boolean;
}

export type LockfileParseResult =
  | { readonly ok: true; readonly graph: DependencyGraph }
  | {
      readonly ok: false;
      readonly unsupported: UnsupportedRepoReason;
      readonly rejections: readonly LockfileRejection[];
    };

/** The same package/version installed twice must carry the same integrity. */
function checkConsistency(set: InstanceSet, rejections: RejectionCollector): void {
  const integrity = new Map<string, string>();
  for (const instance of set.instances.values()) {
    if (instance.integrity === null) continue;
    const key = packageKey(instance.name, instance.version);
    const known = integrity.get(key);
    if (known === undefined) integrity.set(key, instance.integrity);
    else if (known !== instance.integrity) rejections.add("invalid_integrity", instance.name);
  }
}

/**
 * Parses an npm v2/v3 or pnpm v9 lockfile into the normalized dependency graph. Everything outside
 * the supported model (other lockfile versions, workspaces, private registries, git/file/URL
 * sources, missing or inconsistent integrity, malformed or oversized content) is rejected with
 * explicit reasons.
 */
export function parseLockfile(
  input: LockfileInput,
  limits: LockfileLimits = GRAPH_LIMITS,
): LockfileParseResult {
  const berry = input.fileName === "yarn.lock" && isYarnBerryLockfile(input.text);
  if (berry && input.fixOnly !== true)
    return { ok: false, unsupported: "unsupported_package_manager", rejections: [] };
  if (
    (input.fileName === "bun.lock" || input.fileName === "package.json") &&
    input.fixOnly !== true
  )
    return { ok: false, unsupported: "unsupported_package_manager", rejections: [] };
  if ((berry || input.fileName === "package.json") && input.manifest === undefined)
    return {
      ok: false,
      unsupported: "unsupported_lockfile_format",
      rejections: [
        { reason: "missing_root", unsupported: "unsupported_lockfile_format", package: null },
      ],
    };
  const parsed = berry
    ? parseYarnBerryLockfile(input.text, input.manifest!, limits)
    : input.fileName === "bun.lock"
      ? parseBunLockfile(input.text, limits)
      : input.fileName === "package.json"
        ? manifestOnlyInstances(input.manifest!, limits)
        : input.fileName === LOCKFILE_NAMES.yarn
          ? parseYarnLockfile(input.text, limits, input.manifest)
          : input.fileName === LOCKFILE_NAMES.npm
            ? parseNpmLockfile(input.text, limits)
            : parsePnpmLockfile(input.text, limits);
  const rejections = parsed.ok ? new RejectionCollector() : parsed.rejections;
  if (parsed.ok) checkConsistency(parsed.instances, rejections);
  if (!parsed.ok || !rejections.empty) {
    return {
      ok: false,
      unsupported: primaryUnsupportedReason(rejections.rejections.map((r) => r.unsupported)),
      rejections: rejections.rejections,
    };
  }
  return { ok: true, graph: buildGraph(parsed.instances, limits) };
}
