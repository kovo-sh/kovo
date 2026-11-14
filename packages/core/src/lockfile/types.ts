import type {
  LockfileFormat,
  OpaqueDependencies,
  PackageManager,
  PackageName,
  PackageVersion,
  SriSha512,
  StoredLockfileFormat,
  StoredPackageManager,
} from "@kovo/contracts";

import type { DependencySection } from "../manifest/package-json.js";
import type { OpaqueSourceKind } from "../manifest/reasons.js";

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
  /**
   * The distinct `sha1-` SRI tokens of this version's sha1-only instances, sorted: the
   * malware gate cross-checks them against the registry's `dist.shasum` before it trusts the
   * registry's sha512 for the version. Absent when no instance is sha1-only.
   */
  readonly legacySha1?: readonly string[];
  /** The canonical public tarball URL when the lockfile records one. */
  readonly resolved: string | null;
  /**
   * Fix-only: some instance is locked at a private HTTPS registry (its location is never
   * kept). Absent on every other node. A scope the repository's `.npmrc` declares private makes a
   * node private too (`privateRegistryPackages`), even when pnpm records no location for it.
   */
  readonly privateRegistry?: true;
  /** Reached by a root (package.json) dependency. */
  readonly isDirect: boolean;
  /** False when any production path reaches it (optional and peer paths count as production). */
  readonly isDev: boolean;
  /** Every path reaching it passes through an optional dependency. */
  readonly isOptional: boolean;
  /** Installed from inside another package's tarball (npm `inBundle`). */
  readonly bundled: boolean;
  /** Exact containing tarballs for every bundled instance; absent if coverage is unproven. */
  readonly bundleArtifacts?: readonly {
    readonly name: PackageName;
    readonly version: PackageVersion;
    readonly integrity: SriSha512 | null;
  }[];
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
  /** A fix-only value only on the fix paths' parses (`LockfileInput.fixOnly`). */
  readonly packageManager: StoredPackageManager;
  readonly format: StoredLockfileFormat;
  readonly direct: readonly DirectDependency[];
  /** Every package reachable from the root, sorted by name then SemVer precedence. */
  readonly packages: readonly ResolvedPackageNode[];
  readonly unresolved: readonly UnresolvedDependency[];
  /** pnpm lockfile `overrides` selectors (npm does not record overrides in the lockfile). */
  readonly lockfileOverrides: readonly string[];
  /** Non-registry sources left alone as opaque nodes; absent means none. */
  readonly opaque?: OpaqueGraph;
}

/** One non-registry dependency Kovo did not resolve, update or vet. */
export interface OpaqueNode {
  readonly name: PackageName;
  readonly kind: OpaqueSourceKind;
  /** Declared in package.json (otherwise a dependency of a registry package or another node). */
  readonly isDirect: boolean;
  /**
   * The SHA-256 of the node's lockfile identity (its instances' versions, locations and
   * integrity), compared between two graphs to find a new or changed node. A hash, so a location
   * with credentials never reaches the graph; still used in memory only.
   */
  readonly identity: string;
}

/** An opaque node `head` adds or changes relative to `base` (dependency gate input). */
export interface OpaqueNodeChange {
  readonly name: PackageName;
  readonly kind: OpaqueSourceKind;
  readonly isDirect: boolean;
  /** The base has no opaque node of this name and kind. */
  readonly isNew: boolean;
}

/** The opaque nodes `head` adds or changes relative to `base` (null: every node is new). */
export function opaqueNodeChanges(
  base: DependencyGraph | null,
  head: DependencyGraph,
): OpaqueNodeChange[] {
  const before = new Map(
    (base?.opaque?.nodes ?? []).map((node) => [`${node.name}\u0000${node.kind}`, node.identity]),
  );
  return (head.opaque?.nodes ?? []).flatMap((node) => {
    const known = before.get(`${node.name}\u0000${node.kind}`);
    if (known === node.identity) return [];
    return [
      { name: node.name, kind: node.kind, isDirect: node.isDirect, isNew: known === undefined },
    ];
  });
}

/** A registry package/version reachable only through opaque nodes. */
export interface HiddenPackage {
  readonly key: PackageKey;
  readonly name: PackageName;
  readonly version: PackageVersion;
  /** sha512 integrity, or null for bundled and legacy sha1-only entries. */
  readonly integrity: SriSha512 | null;
  /** The canonical public tarball URL when the lockfile records one. */
  readonly resolved: string | null;
}

/**
 * The opaque part of a graph: the non-registry nodes themselves, and the packages reachable only
 * through them (their own dependencies, which Kovo does not vet either). Neither appears in
 * `packages`, in dependency paths or in edges, so no advisory matches and no fix plans them.
 */
export interface OpaqueGraph {
  /** Sorted by name, then kind; one entry per name and kind. */
  readonly nodes: readonly OpaqueNode[];
  /** How many package/versions are reachable only through opaque nodes. */
  readonly hiddenPackages: number;
  /**
   * The registry package/versions reachable only through opaque nodes, sorted by key. They passed
   * the registry source checks (canonical URL, integrity), so the customer PR dependency gate
   * judges their changes like any other transitive registry change; fixes still never plan them.
   */
  readonly hidden: readonly HiddenPackage[];
  /**
   * Sorted SHA-256 identities (of `name`, `version`, `resolved`, `integrity`) of every opaque node
   * and hidden package, compared before and after a fix: a fix may never change any of them.
   * Hashed because `resolved` can be a URL with credentials; still used in memory only.
   */
  readonly identities: readonly string[];
}

/** The evidence counts of a graph's opaque nodes, or undefined when it has none. */
export function opaqueDependencyCounts(graph: DependencyGraph): OpaqueDependencies | undefined {
  const opaque = graph.opaque;
  if (opaque === undefined || opaque.nodes.length === 0) return undefined;
  const count = (kind: OpaqueSourceKind): number =>
    opaque.nodes.filter((node) => node.kind === kind).length;
  return {
    git_count: count("git"),
    tarball_count: count("tarball"),
    local_path_count: count("local_path"),
    hidden_package_count: opaque.hiddenPackages,
  };
}

/** Whether a graph change touched any opaque node or the packages only they reach. */
export function opaqueChanged(before: DependencyGraph, after: DependencyGraph): boolean {
  const a = before.opaque?.identities ?? [];
  const b = after.opaque?.identities ?? [];
  return a.length !== b.length || a.some((identity, index) => identity !== b[index]);
}

/** A graph of a package manager Kovo runs (every parse without `fixOnly` gives one). */
export type VerifiableGraph = DependencyGraph & {
  readonly packageManager: PackageManager;
  readonly format: LockfileFormat;
};

const VERIFIABLE_FORMATS: ReadonlySet<string> = new Set<LockfileFormat>([
  "npm-v2",
  "npm-v3",
  "pnpm-v9",
  "yarn-v1",
]);

/** Whether a graph belongs to a package manager Kovo runs, not a fix-only one. */
export function isVerifiableGraph(graph: DependencyGraph): graph is VerifiableGraph {
  return VERIFIABLE_FORMATS.has(graph.format);
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
