import type { PackageManager, UnsupportedRepoReason } from "@kovo/contracts";

import type { PackageManifest } from "../manifest/package-json.js";
import { parseYarnLockfile, YARN_LOCKFILE_LIMITS } from "./yarn.js";

import { primaryUnsupportedReason } from "../manifest/reasons.js";
import { buildGraph } from "./build-graph.js";
import type { InstanceSet } from "./instances.js";
import { NPM_LOCKFILE_LIMITS, parseNpmLockfile } from "./npm.js";
import { parsePnpmLockfile, PNPM_LOCKFILE_LIMITS } from "./pnpm.js";
import { RejectionCollector, type LockfileRejection } from "./reasons.js";
import { GRAPH_LIMITS, packageKey, type DependencyGraph, type LockfileLimits } from "./types.js";

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

export interface LockfileInput {
  readonly fileName: LockfileName;
  /** The raw lockfile text; never persisted or logged. */
  readonly text: string;
  /** Required for Yarn v1, which contains no root dependency declarations. */
  readonly manifest?: PackageManifest;
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
  if (input.fileName === "yarn.lock" && /^__metadata\s*:/mu.test(input.text))
    return { ok: false, unsupported: "unsupported_package_manager", rejections: [] };
  const parsed =
    input.fileName === LOCKFILE_NAMES.yarn
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
