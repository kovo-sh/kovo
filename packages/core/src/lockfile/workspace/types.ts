import type { PackageManager, PackageName } from "@kovo/contracts";

import type { PackageManifest, DependencySection } from "../../manifest/package-json.js";
import type { DependencyGraph } from "../types.js";
import type { Instance, RootDependency } from "../instances.js";
import type { PnpmCatalogs } from "../../manifest/pnpm-catalogs.js";
import type { JsonObject } from "../../manifest/bounded-json.js";

/** Pure, in-memory contract. Never persist manifests/tree content or send it through DBOS. */
export interface WorkspaceTreeEntry {
  readonly path: string;
  readonly mode: "file" | "directory" | "symlink" | "submodule";
  readonly oid: string;
  /** Required for parsed manifests/config/lockfiles; fetched by this entry's immutable blob oid.
   * The I/O caller verifies the blob identity. Core requires complete text, never a second read.
   */
  readonly text?: string;
}
export interface WorkspaceInput {
  readonly packageManager: PackageManager;
  readonly treeComplete: boolean;
  readonly entries: readonly WorkspaceTreeEntry[];
}
export interface LocalDeclaration {
  readonly alias: PackageName;
  readonly section: DependencySection;
  readonly spec: string;
  readonly target: string;
}
export interface WorkspaceMember {
  readonly path: string;
  readonly manifestOid: string;
  readonly manifest: PackageManifest;
  readonly local: readonly LocalDeclaration[];
  readonly catalogDeclarations?: readonly {
    readonly alias: PackageName;
    readonly section: DependencySection;
    readonly spec: string;
    readonly catalog: string;
  }[];
}
export interface WorkspaceLayout {
  readonly packageManager: PackageManager;
  /** Root is always included, including an orchestrator with no dependencies. */
  readonly members: readonly WorkspaceMember[];
  readonly hasWorkspaces: boolean;
  readonly workspaceConfigOid: string | null;
  readonly catalogs?: PnpmCatalogs;
  /** Validated root YAML rules; unqualified rules can replace importer specifiers in pnpm. */
  readonly pnpmWorkspaceOverrides?: Readonly<Record<string, string>>;
  /** Complete validated root settings, retained transiently for exact planned YAML checks. */
  readonly pnpmWorkspaceConfig?: JsonObject;
}
export const WORKSPACE_LIMITS = {
  maxMembers: 100,
  maxTreeEntries: 100_000,
  maxTreePathBytes: 8 * 1024 * 1024,
  maxManifestBytes: 8 * 1024 * 1024,
  maxDepth: 32,
  maxPatterns: 100,
  maxPatternLength: 256,
  maxGlobWork: 64 * 1024 * 1024,
  maxLocalEdges: 10_000,
  maxProjectionWork: 20_000_000,
} as const;
export type WorkspaceLimits = { readonly [K in keyof typeof WORKSPACE_LIMITS]: number };
export const WORKSPACE_REASONS = [
  "incomplete_tree",
  "invalid_path",
  "unsafe_tree_entry",
  "identity_collision",
  "resource_limit",
  "invalid_workspace_yaml",
  "unsupported_workspace_setting",
  "catalogs_unsupported",
  "catalog_entry_missing",
  "invalid_catalog",
  "unsupported_layout",
  "invalid_pattern",
  "missing_manifest",
  "invalid_manifest",
  "invalid_member_identity",
  "conflicting_lockfile",
  "manager_mismatch",
  "runtime_mismatch",
  "invalid_local_edge",
  "lockfile_members_mismatch",
  "lockfile_declarations_mismatch",
  "invalid_lockfile",
  "incomplete_graph",
] as const;
export type WorkspaceReason = (typeof WORKSPACE_REASONS)[number];
export type WorkspaceResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: WorkspaceReason };
export function workspaceFailure(reason: WorkspaceReason): WorkspaceResult<never> {
  return { ok: false, reason };
}
export interface WorkspaceImporter {
  readonly member: WorkspaceMember;
  /** Exact registry/local instance targets, preserving section and alias ownership. */
  readonly direct: readonly RootDependency[];
  /** Registry-only projection for existing pure diff/advisory functions. Never merge proof. */
  readonly graph: DependencyGraph;
}
export interface WorkspaceGraph {
  readonly layout: WorkspaceLayout;
  readonly importers: readonly WorkspaceImporter[];
  /** Exact registry instances, including npm location and pnpm peer context. */
  readonly instances: ReadonlyMap<string, Instance>;
}

/** A pure layout is never admission proof; P4 also requires complete current publication. */
export function workspaceAdmission(
  layout: WorkspaceLayout,
): { readonly admitted: true } | { readonly admitted: false; readonly reason: "workspaces" } {
  return layout.hasWorkspaces ? { admitted: false, reason: "workspaces" } : { admitted: true };
}
