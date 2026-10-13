import type { PackageName, UnsupportedRepoReason } from "@kovo/contracts";

import {
  MANIFEST_REJECTION_UNSUPPORTED,
  SOURCE_REJECTION_REASONS,
  type SourceRejectionReason,
} from "../manifest/reasons.js";

// Explicit reasons why a lockfile is outside the supported model (SPEC: "npm lockfile v2/v3 and
// pnpm lockfile v9 are the initial accepted formats. Unsupported majors/formats produce an explicit
// unsupported reason"; "Reject private registries and external git/file/HTTP dependency sources").
// Each maps to the coarse contracts `UnsupportedRepoReason`. A rejection names a package only when
// its name is a valid package name; it never carries URLs, specs or other lockfile values.

export const LOCKFILE_REJECTION_REASONS = [
  ...SOURCE_REJECTION_REASONS,
  "workspace_packages", // npm workspace links, or pnpm importers other than "."
  "unsupported_lockfile_version",
  "lockfile_too_large",
  "lockfile_too_deep",
  "lockfile_duplicate_key",
  "lockfile_syntax",
  "lockfile_invalid", // valid JSON/YAML but not the lockfile shape
  "missing_root", // npm packages[""] or pnpm importers["."]
  "invalid_package_name",
  "invalid_package_version",
  "missing_integrity",
  "invalid_integrity",
  "registry_url_mismatch", // a public registry URL for a different package or version
  "dangling_reference", // pnpm: a snapshot or importer names a package the lockfile lacks
  "too_many_packages",
  "too_many_dependencies", // more declared dependency edges than GRAPH_LIMITS allows
] as const;
export type LockfileRejectionReason = (typeof LOCKFILE_REJECTION_REASONS)[number];

type LockfileOnlyReason = Exclude<LockfileRejectionReason, SourceRejectionReason>;

const LOCKFILE_ONLY_UNSUPPORTED = {
  workspace_packages: "workspaces",
  unsupported_lockfile_version: "unsupported_lockfile_format",
  lockfile_too_large: "too_large",
  lockfile_too_deep: "too_large",
  lockfile_duplicate_key: "unsupported_lockfile_format",
  lockfile_syntax: "unsupported_lockfile_format",
  lockfile_invalid: "unsupported_lockfile_format",
  missing_root: "unsupported_lockfile_format",
  invalid_package_name: "unsupported_lockfile_format",
  invalid_package_version: "unsupported_lockfile_format",
  missing_integrity: "unsupported_lockfile_format",
  invalid_integrity: "unsupported_lockfile_format",
  registry_url_mismatch: "non_registry_dependency",
  dangling_reference: "unsupported_lockfile_format",
  too_many_packages: "too_large",
  too_many_dependencies: "too_large",
} as const satisfies Record<LockfileOnlyReason, UnsupportedRepoReason>;

export const LOCKFILE_REJECTION_UNSUPPORTED: Readonly<
  Record<LockfileRejectionReason, UnsupportedRepoReason>
> = {
  workspace_protocol: MANIFEST_REJECTION_UNSUPPORTED.workspace_protocol,
  catalog_protocol: MANIFEST_REJECTION_UNSUPPORTED.catalog_protocol,
  git_dependency: MANIFEST_REJECTION_UNSUPPORTED.git_dependency,
  local_path_dependency: MANIFEST_REJECTION_UNSUPPORTED.local_path_dependency,
  remote_tarball_dependency: MANIFEST_REJECTION_UNSUPPORTED.remote_tarball_dependency,
  private_registry_dependency: MANIFEST_REJECTION_UNSUPPORTED.private_registry_dependency,
  unsupported_protocol: MANIFEST_REJECTION_UNSUPPORTED.unsupported_protocol,
  ...LOCKFILE_ONLY_UNSUPPORTED,
};

export interface LockfileRejection {
  readonly reason: LockfileRejectionReason;
  readonly unsupported: UnsupportedRepoReason;
  /** The package concerned, when the lockfile names a valid one. */
  readonly package: PackageName | null;
}

/** At most this many rejections are reported per lockfile; one is enough to reject it. */
export const MAX_LOCKFILE_REJECTIONS = 50;

/** Collects rejections, deduplicated by reason and package and bounded. */
export class RejectionCollector {
  private readonly seen = new Set<string>();
  readonly rejections: LockfileRejection[] = [];

  add(reason: LockfileRejectionReason, pkg: PackageName | null = null): void {
    const key = `${reason}\u0000${pkg ?? ""}`;
    if (this.seen.has(key) || this.rejections.length >= MAX_LOCKFILE_REJECTIONS) return;
    this.seen.add(key);
    this.rejections.push({
      reason,
      unsupported: LOCKFILE_REJECTION_UNSUPPORTED[reason],
      package: pkg,
    });
  }

  get empty(): boolean {
    return this.rejections.length === 0;
  }
}
