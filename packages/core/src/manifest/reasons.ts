import type { UnsupportedRepoReason } from "@kovo/contracts";

// Explicit, stable reasons why a repository's package manifest or lockfile is outside the supported
// model (SPEC inventoryWorkflow step 1: "Reject customer workspaces, unsupported package
// managers/runtime versions, missing lockfiles, and formats outside the compatibility matrix";
// proxy: "Reject private registries and external git/file/HTTP dependency sources outside the
// supported public-registry model"). Each detailed reason maps to one contracts
// `UnsupportedRepoReason`, the coarse code stored on the repository and shown as its mode reason.
//
// A rejection names where the problem is (a JSON pointer into package.json, or a package name),
// never the offending value: specs and URLs can embed credentials (a URL with userinfo).

export const SOURCE_REJECTION_REASONS = [
  "workspace_protocol", // `workspace:` specs only make sense inside a workspace
  "catalog_protocol", // pnpm catalogs are declared in pnpm-workspace.yaml
  "git_dependency", // git+ssh:, git+https:, github:, `user/repo` shorthand, …
  "local_path_dependency", // file:, link:, portal:, relative or absolute paths, local tarballs
  "remote_tarball_dependency", // an http(s) tarball URL
  "private_registry_dependency", // a registry origin other than https://registry.npmjs.org
  "unsupported_protocol", // any other `<scheme>:` spec (jsr:, patch:, exec:, …)
] as const;
export type SourceRejectionReason = (typeof SOURCE_REJECTION_REASONS)[number];

export const MANIFEST_REJECTION_REASONS = [
  ...SOURCE_REJECTION_REASONS,
  "npm_workspaces", // a non-empty `workspaces` field
  "pnpm_workspace_file", // pnpm-workspace.yaml at the repository root
  "json_too_large",
  "json_too_deep",
  "json_duplicate_key",
  "json_syntax",
  "not_an_object",
  "invalid_field", // a known field with the wrong shape
  "invalid_dependency_name",
  "invalid_dependency_spec",
  "invalid_override",
  // pnpm 9/10: a package.json `pnpm` setting the pnpm-workspace.yaml allowlist refuses (#1879), the
  // same reason `.npmrc` and pnpm-workspace.yaml settings get.
  "unsupported_workspace_setting",
] as const;
export type ManifestRejectionReason = (typeof MANIFEST_REJECTION_REASONS)[number];

export const MANIFEST_REJECTION_UNSUPPORTED = {
  workspace_protocol: "workspaces",
  catalog_protocol: "workspaces",
  git_dependency: "non_registry_dependency",
  local_path_dependency: "non_registry_dependency",
  remote_tarball_dependency: "non_registry_dependency",
  private_registry_dependency: "private_registry",
  unsupported_protocol: "non_registry_dependency",
  npm_workspaces: "workspaces",
  pnpm_workspace_file: "workspaces",
  json_too_large: "too_large",
  json_too_deep: "too_large",
  json_duplicate_key: "invalid_package_json",
  json_syntax: "invalid_package_json",
  not_an_object: "invalid_package_json",
  invalid_field: "invalid_package_json",
  invalid_dependency_name: "invalid_package_json",
  invalid_dependency_spec: "invalid_package_json",
  invalid_override: "invalid_package_json",
  unsupported_workspace_setting: "workspaces",
} as const satisfies Record<ManifestRejectionReason, UnsupportedRepoReason>;

/**
 * Which coarse reason wins when a manifest has several problems: the one a person must act on
 * first. Workspaces make everything else moot; private and non-registry sources come before
 * malformed content.
 */
export const UNSUPPORTED_PRIORITY: readonly UnsupportedRepoReason[] = [
  "workspaces",
  "too_large",
  "invalid_package_json",
  "private_registry",
  "non_registry_dependency",
  "missing_package_json",
  "missing_lockfile",
  "ambiguous_package_manager",
  "unsupported_package_manager",
  "unsupported_lockfile_format",
  "unsupported_node_version",
  "unsupported_pm_version",
];

/** The highest-priority coarse reason among `reasons` (which must be non-empty). */
export function primaryUnsupportedReason(
  reasons: readonly UnsupportedRepoReason[],
): UnsupportedRepoReason {
  for (const candidate of UNSUPPORTED_PRIORITY) {
    if (reasons.includes(candidate)) return candidate;
  }
  const first = reasons[0];
  if (first === undefined) throw new RangeError("no reasons");
  return first;
}

export interface ManifestRejection {
  readonly reason: ManifestRejectionReason;
  readonly unsupported: UnsupportedRepoReason;
  /** RFC 6901 pointer into package.json (dependency keys are package names, never values). */
  readonly pointer: string;
}

export function manifestRejection(
  reason: ManifestRejectionReason,
  pointer: string,
): ManifestRejection {
  return { reason, unsupported: MANIFEST_REJECTION_UNSUPPORTED[reason], pointer };
}
