import type { StoredPackageManagerChoice, UnsupportedRepoReason } from "@kovo/contracts";

import type { RuntimeCatalog } from "../compat.js";
import type { LockfileName } from "../parse.js";
import type { RegistryIntegrityCandidate, RegistryIntegrityFill } from "../registry-source.js";
import type { WorkspaceLayout, WorkspaceReason, WorkspaceTreeEntry } from "../workspace/types.js";

/** Transient inputs only: callers bind every blob to the immutable commit before calling. */
export interface InstallRootDiscoveryInput {
  readonly treeComplete: boolean;
  readonly entries: readonly WorkspaceTreeEntry[];
  /** Parsed from the base branch, never the candidate commit. Null means unreadable/invalid. */
  readonly baseIgnore: readonly string[] | null;
  readonly catalog: RuntimeCatalog;
  /**
   * The repository's recorded two-lockfile choice (`repos.package_manager_choice`, #5500). Applied
   * to the repository root only, and only when that root commits both npm and pnpm lockfiles.
   */
  readonly packageManagerChoice?: StoredPackageManagerChoice;
  /**
   * Registry-sourced integrity (#7338) the caller looked up, per install root path (`.` or the
   * root's repository-relative path): each root's workspace graph is parsed with its own map only.
   * Absent (or no entry for a root) keeps that root's parse exactly as today.
   */
  readonly registryIntegrity?: ReadonlyMap<string, RegistryIntegrityFill>;
}

/**
 * A workspace install root refused only for npm entries of the registry-sourced integrity shape
 * (#7338): their names and versions, and whether every `.npmrc` of the root names only the public
 * registry. The caller may look them up and discover again with that root's map.
 */
export interface RootRegistryIntegrityNeed {
  readonly path: string;
  readonly candidates: readonly RegistryIntegrityCandidate[];
  readonly publicRegistry: boolean;
}

/** Repository-wide budgets; per-root parser/workspace limits still apply independently. */
export const DISCOVERY_LIMITS = {
  maxRoots: 100,
  maxCandidateDepth: 8,
  maxTreeEntries: 100_000,
  maxTreePathBytes: 8 * 1024 * 1024,
  maxManifestBytes: 8 * 1024 * 1024,
  maxParseBytes: 64 * 1024 * 1024,
  maxGraphEdges: 500_000,
  maxGraphWork: 20_000_000,
  maxWork: 64 * 1024 * 1024,
} as const;
export type DiscoveryLimits = { readonly [K in keyof typeof DISCOVERY_LIMITS]: number };

export type CandidateRefusalReason = UnsupportedRepoReason | WorkspaceReason | "nested_project";
export interface RefusedCandidate {
  readonly path: string;
  readonly reason: CandidateRefusalReason;
}
export interface InstallRoot {
  readonly path: string;
  readonly lockfileName: LockfileName;
  /** Members and their local edges remain relative to this install root, including '.'. */
  readonly layout: WorkspaceLayout;
  readonly excludedTrees: readonly string[];
  /** Tracked files only, repository-relative. Directories/links never acquire ownership. */
  readonly files: readonly {
    readonly path: string;
    readonly member: string;
    readonly access: "owned" | "shared_editable" | "shared_readonly";
  }[];
}
export type InstallRootDiscoveryResult =
  | {
      readonly ok: true;
      readonly roots: readonly InstallRoot[];
      readonly refusals: readonly RefusedCandidate[];
      /** Refused roots that registry-sourced integrity could admit (#7338); absent when none. */
      readonly registryIntegrityNeeds?: readonly RootRegistryIntegrityNeed[];
    }
  | {
      readonly ok: false;
      readonly reason: CandidateRefusalReason | "too_many_projects" | "invalid_ignore_config";
      readonly refusals: readonly RefusedCandidate[];
      /** All candidates were inspected; no supported roots remain. Hard failures omit this. */
      readonly refusalsComplete?: true;
      /** As on success; set only with `refusalsComplete`. */
      readonly registryIntegrityNeeds?: readonly RootRegistryIntegrityNeed[];
    };
