import type { DependencySource } from "@kovo/contracts";

import { checkTarballSource } from "../lockfile/registry-source.js";

/**
 * Where a lockfile resolves `name@version` from, given its recorded location (`resolved` in npm
 * lockfiles, `resolution.tarball` in pnpm; null when the lockfile records none, which means the
 * configured registry) and the registry origins the account has explicitly configured.
 *
 * - The canonical public tarball URL (or no recorded location) is the public registry.
 * - A registry-shaped tarball path on an `https:` origin the account configured is a private
 *   registry. Kovo has no such configuration yet, so callers pass none and nothing is classified
 *   as a private registry: a registry-shaped path on an arbitrary host proves nothing.
 * - Everything else is exotic: git, a tarball URL on any other host (plain `http:` always), a
 *   local path, an unknown protocol, or a public-registry URL naming another package or version.
 */
export function dependencySourceOf(
  location: string | null,
  name: string,
  version: string,
  configuredRegistries: readonly string[] = [],
): DependencySource {
  if (location === null) return "registry";
  const rejection = checkTarballSource(location, name, version);
  if (rejection === null) return "registry";
  if (rejection !== "private_registry_dependency") return "exotic";
  let origin: string;
  try {
    const url = new URL(location);
    if (url.protocol !== "https:") return "exotic";
    origin = url.origin;
  } catch {
    return "exotic";
  }
  return configuredRegistries.some((configured) => configured === origin)
    ? "private_registry"
    : "exotic";
}

/**
 * The source of a parsed lockfile node. A node the lockfile locks at a private registry
 * (`privateRegistry`, D-726 fix-only) has no recorded location left, which `dependencySourceOf`
 * would read as the public registry: it is a private-registry package instead, so no caller ever
 * looks its name up at the public registry (a same-name public package is not the customer's).
 */
export function dependencySourceOfNode(node: {
  readonly resolved: string | null;
  readonly name: string;
  readonly version: string;
  readonly privateRegistry?: true;
}): DependencySource {
  if (node.privateRegistry === true) return "private_registry";
  return dependencySourceOf(node.resolved, node.name, node.version);
}
