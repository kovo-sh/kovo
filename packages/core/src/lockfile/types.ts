import type {
  LockfileFormat,
  PackageManager,
  PackageName,
  PackageVersion,
  SriSha512,
} from "@kovo/contracts";

import type { DependencySection } from "../manifest/package-json.js";

// The normalized dependency graph every supported lockfile format parses into (SPEC
// inventoryWorkflow step 2: "Parse every resolved package/version and dependency path. Aggregate a
// package/version as production if any production path reaches it; optional dependencies count as
// production. Peer dependencies are inventoried only when resolved in the lockfile."). One node per
// resolved package/version (the `resolved_packages` key); dependency paths run from a direct
// dependency down to the node.

/** `name@version`, the identity of a resolved package (`@auth/core@0.40.0`). */
export type PackageKey = `${string}@${string}`;

export function packageKey(name: string, version: string): PackageKey {
  return `${name}@${version}`;
}

/** The package name of a key (`@auth/core@0.40.0` → `@auth/core`). */
export function nameOfKey(key: PackageKey): string {
  return key.slice(0, key.indexOf("@", key.startsWith("@") ? 1 : 0));
}

/** How a dependency is declared by its dependent. */
export const DEPENDENCY_KINDS = ["prod", "dev", "optional", "peer"] as const;
export type DependencyKind = (typeof DEPENDENCY_KINDS)[number];

/** The dependency kind a package.json section declares. */
export const SECTION_KIND = {
  dependencies: "prod",
  devDependencies: "dev",
  optionalDependencies: "optional",
  peerDependencies: "peer",
} as const satisfies Record<DependencySection, DependencyKind>;

/** One declared dependency of a resolved package, resolved to another package. */
export interface DependencyEdge {
  /** The dependency key (the alias for `npm:` aliases). */
  readonly alias: PackageName;
  readonly kind: DependencyKind;
  /** The declared range, when the lockfile records it (npm does; pnpm v9 does not). */
  readonly range: string | null;
  readonly target: PackageKey;
}

/** A path from a direct dependency (first) down to a package (last), by package key. */
export type DependencyPath = readonly PackageKey[];

export interface ResolvedPackageNode {
  readonly key: PackageKey;
  readonly name: PackageName;
  readonly version: PackageVersion;
  /** sha512 SRI integrity, or null for bundled packages and legacy sha1-only entries. */
  readonly integrity: SriSha512 | null;
  /** Which integrity the lockfile records: sha512, only a legacy sha1, or none (bundled). */
  readonly integrityAlgorithm: "sha512" | "sha1" | null;
  /** The canonical public tarball URL when the lockfile records one. */
  readonly resolved: string | null;
  /** Reached by a root (package.json) dependency. */
  readonly isDirect: boolean;
  /** False when any production path reaches it (optional and peer paths count as production). */
  readonly isDev: boolean;
  /** Every path reaching it passes through an optional dependency. */
  readonly isOptional: boolean;
  /** Installed from inside another package's tarball (npm `inBundle`). */
  readonly bundled: boolean;
  /** Packages this one bundles, as the lockfile names them (pnpm lists names only). */
  readonly bundles: readonly string[];
  /** npm's `hasInstallScript`; null when the format does not record it (pnpm v9). */
  readonly hasInstallScript: boolean | null;
  /** Modified by a pnpm patch (`patchedDependencies`). */
  readonly patched: boolean;
  /** Dependency paths from the root, shortest first, at most `GRAPH_LIMITS.maxPathsPerPackage`. */
  readonly paths: readonly DependencyPath[];
  /** Some paths were not recorded (per-package cap, depth cap or the total path budget). */
  readonly pathsTruncated: boolean;
  /** Resolved dependencies (declared by any instance of this package/version). */
  readonly dependencies: readonly DependencyEdge[];
  /** Where the lockfile places it: npm `node_modules/…` locations or pnpm snapshot keys. */
  readonly instances: readonly string[];
}

/** A dependency declared in package.json and how the lockfile resolves it. */
export interface DirectDependency {
  readonly alias: PackageName;
  readonly section: DependencySection;
  /** The declared spec as the lockfile records it (npm root entry / pnpm importer specifier). */
  readonly spec: string;
  /** The resolved package, or null when the lockfile does not install it (e.g. a skipped optional). */
  readonly target: PackageKey | null;
}

/** A required dependency the lockfile does not resolve (inconsistent lockfile). */
export interface UnresolvedDependency {
  readonly from: PackageKey | "root";
  readonly alias: PackageName;
}

export interface DependencyGraph {
  readonly packageManager: PackageManager;
  readonly format: LockfileFormat;
  readonly direct: readonly DirectDependency[];
  /** Every package reachable from the root, sorted by name then SemVer precedence. */
  readonly packages: readonly ResolvedPackageNode[];
  readonly unresolved: readonly UnresolvedDependency[];
  /** pnpm lockfile `overrides` selectors (npm does not record overrides in the lockfile). */
  readonly lockfileOverrides: readonly string[];
}

/** Bounds on graph size and path enumeration (paths grow combinatorially in large graphs). */
export const GRAPH_LIMITS = {
  /** Resolved package entries a lockfile may hold. */
  maxPackages: 50_000,
  /** Declared dependency edges across all entries (real lockfiles hold a few per package). */
  maxDependencyEdges: 500_000,
  /** npm: nested `node_modules` levels in one install location (real lockfiles nest < 20). */
  maxNestingDepth: 64,
  /** Paths recorded per package; contracts evidence keeps at most 100 per changed package. */
  maxPathsPerPackage: 100,
  /** Path length; contracts `dependencyPathSchema` allows 64 names. */
  maxPathDepth: 64,
  /** Paths recorded across the whole graph. */
  maxTotalPaths: 500_000,
  /**
   * Path-enumeration work (edges examined plus chain steps of cycle checks and recorded paths)
   * across the whole graph; beyond it every package is marked `pathsTruncated`. The largest real
   * lockfiles measured need well under a tenth of it (docs/decisions/lockfile.md).
   */
  maxPathWork: 20_000_000,
} as const;

/** Every bound a lockfile parse applies (defaults: `GRAPH_LIMITS`). */
export type LockfileLimits = { readonly [K in keyof typeof GRAPH_LIMITS]: number };

/** Looks packages up by key. */
export function indexPackages(
  graph: DependencyGraph,
): ReadonlyMap<PackageKey, ResolvedPackageNode> {
  return new Map(graph.packages.map((node) => [node.key, node]));
}

/** Every resolved package/version of `name`. */
export function packagesNamed(graph: DependencyGraph, name: string): ResolvedPackageNode[] {
  return graph.packages.filter((node) => node.name === name);
}
