import type { PackageName, StoredPackageManager } from "@kovo/contracts";

import type { DependencyGraph } from "./types.js";

// Fix-only mode for private registries ("private registries and token lines in fix-only mode").
// A single-package npm repository whose root `.npmrc`
// names a private registry for some scopes (`checkNpmrcFixOnly`) is admitted. Kovo changes its
// lockfile and manifest for public packages only, through the proxy, and never sends a request to
// the private registry, never reads or injects its token and never runs the repository; the
// repository's own CI, which has the token, decides. Everything here is pure: it says which
// packages are private and refuses what fix-only cannot do.

/** `@acme/ui` → `@acme` (lower case, as package names are); null for an unscoped name. */
export function packageScope(name: string): string | null {
  if (!name.startsWith("@")) return null;
  const slash = name.indexOf("/");
  return slash <= 1 ? null : name.slice(0, slash).toLowerCase();
}

function scopeSet(scopes: readonly string[]): ReadonlySet<string> {
  return new Set(scopes.map((scope) => scope.toLowerCase()));
}

/**
 * The packages of a graph that come from a private registry: every node the lockfile locks at one
 * (`privateRegistry`), and every node in a scope the repository's `.npmrc` declares private (pnpm
 * may record no location for those, so the scope is what tells). Kovo never looks these names up
 * at the public registry (a squatter's package of the same name is not the customer's), never
 * lets the proxy serve them and never lets a fix change them.
 */
export function privateRegistryPackages(
  graph: DependencyGraph,
  privateScopes: readonly string[],
): ReadonlySet<PackageName> {
  const scopes = scopeSet(privateScopes);
  const names = new Set<PackageName>();
  for (const node of graph.packages) {
    const scope = packageScope(node.name);
    if (node.privateRegistry === true || (scope !== null && scopes.has(scope)))
      names.add(node.name);
  }
  return names;
}

/** Why a repository's graph is outside fix-only mode; null when it is admitted. */
export type PrivateRegistryRefusal =
  /** A package locked at a private registry whose scope `.npmrc` does not declare private. */
  | "private_registry_undeclared"
  /** Private scopes under a package manager fix-only does not cover (pnpm, Yarn). */
  | "private_registry_package_manager";

/**
 * Admission of a single-package graph against the root `.npmrc`'s private scopes: every package
 * locked at a private registry must be in a declared private scope (otherwise its registry is
 * configured somewhere Kovo cannot see), and only npm gets fix-only mode. npm's lockfile-only
 * update keeps a locked private entry without fetching it; pnpm's re-resolves the importer's
 * direct dependencies and needs the private registry's metadata (probed with pnpm 10 in the
 * hermetic generation test), and Yarn reads scope registries from other files. Each refusal is a
 * `private_registry` repository, as before fix-only mode.
 */
export function privateRegistryAdmission(
  graph: DependencyGraph,
  privateScopes: readonly string[],
  packageManager: StoredPackageManager,
): PrivateRegistryRefusal | null {
  const scopes = scopeSet(privateScopes);
  const locked = graph.packages.filter((node) => node.privateRegistry === true);
  if ((scopes.size > 0 || locked.length > 0) && packageManager !== "npm")
    return "private_registry_package_manager";
  for (const node of locked) {
    const scope = packageScope(node.name);
    if (scope === null || !scopes.has(scope)) return "private_registry_undeclared";
  }
  return null;
}

/**
 * The fixed reason a fix-only plan or fix is refused (every refusal says which setups it
 * blocks). A fix that needs a new version of a private-registry package, or moves one through a
 * parent bump, cannot be made without contacting that registry, so it is never attempted: the
 * customer updates private packages themselves. It blocks only fixes whose vulnerable package, or
 * the parent a fix would bump, is one of the repository's own private packages; public packages
 * of the same repository still get fix-only PRs.
 */
export const PRIVATE_REGISTRY_PACKAGE = "private_registry_package";

/** Whether a fix moved, added or removed any private-registry package (fix-only refuses it). */
export function privateRegistryChanged(
  before: DependencyGraph,
  after: DependencyGraph,
  privateScopes: readonly string[],
): boolean {
  const keys = (graph: DependencyGraph) => {
    const names = privateRegistryPackages(graph, privateScopes);
    return new Map(
      graph.packages
        .filter((node) => names.has(node.name))
        .map((node) => [node.key, node.integrity] as const),
    );
  };
  const was = keys(before);
  const now = keys(after);
  if (was.size !== now.size) return true;
  for (const [key, integrity] of now) {
    if (!was.has(key) || was.get(key) !== integrity) return true;
  }
  return false;
}
