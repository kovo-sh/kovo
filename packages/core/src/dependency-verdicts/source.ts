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
