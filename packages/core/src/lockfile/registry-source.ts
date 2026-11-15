import {
  NPM_PUBLIC_REGISTRY_ORIGIN,
  npmTarballUrl,
  packageVersionSchema,
} from "@kovo/contracts/npm";
import { sriSha512Schema } from "@kovo/contracts/primitives";
import type { PackageName, PackageVersion, SriSha512 } from "@kovo/contracts";

import { opaqueSourceKind, type OpaqueSourceKind } from "../manifest/reasons.js";
import type { LockfileRejectionReason } from "./reasons.js";

// Where a locked artifact comes from, and whether its integrity is usable. SPEC: "committed
// lockfiles retain valid canonical public URLs and integrity"; docs/libraries/sandbox-ai-feeds.md §3:
// "trusted code must still reject any lockfile diff whose `resolved`/`tarball` is not under
// `https://registry.npmjs.org/`".

const GIT_PREFIXES = ["git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:"];
const REGISTRY_TARBALL_PATH = /^\/(?:[^/]+\/)*(?:@[^/]+\/)?[^/]+\/-\/[^/]+\.tgz$/;

/**
 * Checks a recorded tarball location (`resolved` in npm lockfiles, `resolution.tarball` in pnpm) for
 * `name@version`. Returns null when it is exactly the canonical public registry URL of that package
 * and version, otherwise the rejection reason. A public-registry URL for a different package or
 * version is rejected too: it would install something other than what the lockfile claims.
 */
export function checkTarballSource(
  location: string,
  name: string,
  version: string,
): LockfileRejectionReason | null {
  const lower = location.toLowerCase();
  if (GIT_PREFIXES.some((prefix) => lower.startsWith(prefix))) return "git_dependency";
  if (lower.startsWith("file:") || lower.startsWith("link:")) return "local_path_dependency";
  if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
    // npm records file: dependencies' targets as bare relative paths.
    return /^[a-z][a-z0-9+.-]*:/i.test(location) ? "unsupported_protocol" : "local_path_dependency";
  }
  let url: URL;
  try {
    url = new URL(location);
  } catch {
    return "remote_tarball_dependency";
  }
  if (url.origin === NPM_PUBLIC_REGISTRY_ORIGIN) {
    return location === npmTarballUrl(name, version) ? null : "registry_url_mismatch";
  }
  // The public registry over plain HTTP (or another port) is not the canonical URL either.
  if (url.hostname === new URL(NPM_PUBLIC_REGISTRY_ORIGIN).hostname) return "registry_url_mismatch";
  return REGISTRY_TARBALL_PATH.test(url.pathname)
    ? "private_registry_dependency"
    : "remote_tarball_dependency";
}

/**
 * The opaque kind of a recorded location `checkTarballSource` refused, or null when
 * the refusal stands (a private registry, a public-registry URL mismatch, another protocol).
 */
export function opaqueLocationKind(
  reason: LockfileRejectionReason | null,
): OpaqueSourceKind | null {
  return reason === null ? null : opaqueSourceKind(reason);
}

/** An opaque instance's version: the lockfile's own when it is a valid version, else `0.0.0`. */
export function opaqueVersion(raw: string | undefined): PackageVersion {
  const parsed = packageVersionSchema.safeParse(raw);
  return parsed.success ? parsed.data : packageVersionSchema.parse("0.0.0");
}

/**
 * Fix-only: whether a recorded tarball location that
 * `checkTarballSource` refuses is a scoped package served by a private registry over HTTPS
 * (`https://npm.pkg.github.com/download/@acme/ui/1.2.0/…`, an Artifactory or Verdaccio scope).
 * The parsers keep such an entry as an opaque private-registry node (`privateRegistry`) with no
 * recorded location: Kovo never fetches it and no fix may change it. Whether the repository's own
 * `.npmrc` declares the scope private is checked where a repository is admitted
 * (`privateRegistryAdmission`). An unscoped package, plain HTTP, a URL carrying credentials and
 * the public registry's own host are never private-registry entries.
 */
export function isPrivateScopeTarball(location: string, name: string): boolean {
  if (!name.startsWith("@")) return false;
  let url: URL;
  try {
    url = new URL(location);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.username === "" &&
    url.password === "" &&
    url.hostname !== new URL(NPM_PUBLIC_REGISTRY_ORIGIN).hostname
  );
}

export type IntegrityCheck =
  | { readonly ok: true; readonly integrity: SriSha512; readonly algorithm: "sha512" }
  /**
   * Only a legacy sha1 digest (packages published before npm recorded sha512). `sha1` lists its
   * distinct `sha1-` SRI tokens, so a caller can cross-check them against the registry's
   * `dist.shasum` before trusting the registry's sha512 for the same version.
   */
  | {
      readonly ok: true;
      readonly integrity: null;
      readonly algorithm: "sha1";
      readonly sha1: readonly string[];
    }
  | { readonly ok: false; readonly reason: "missing_integrity" | "invalid_integrity" };

const SHA1_SRI = /^sha1-[A-Za-z0-9+/]{27}=$/;

/**
 * Reads an SRI integrity string (one or more space-separated `alg-base64` tokens). The strongest
 * usable token wins: sha512, else a legacy sha1. Any malformed token rejects the whole value.
 */
export function checkIntegrity(value: string | undefined): IntegrityCheck {
  if (value === undefined || value.trim() === "") return { ok: false, reason: "missing_integrity" };
  let sha512: SriSha512 | null = null;
  const sha1 = new Set<string>();
  for (const token of value.trim().split(/\s+/)) {
    const digest = token.split("?")[0] ?? "";
    const parsed = sriSha512Schema.safeParse(digest);
    if (parsed.success) sha512 ??= parsed.data;
    else if (SHA1_SRI.test(digest)) sha1.add(digest);
    else return { ok: false, reason: "invalid_integrity" };
  }
  if (sha512 !== null) return { ok: true, integrity: sha512, algorithm: "sha512" };
  if (sha1.size > 0)
    return { ok: true, integrity: null, algorithm: "sha1", sha1: [...sha1].toSorted() };
  return { ok: false, reason: "invalid_integrity" };
}

/**
 * Registry-sourced integrity (agent decision, pending owner review): an npm
 * workspace lockfile may record an entry under a member's `node_modules` with a `version` but no
 * `resolved` and no `integrity`, which `npm ci` installs by trusting the public registry's
 * metadata. Core never fetches anything: the caller supplies the registry's `dist.integrity` for
 * each `name@version` it looked up, and the parser accepts only that shape with a supplied value.
 * The supply-chain gate and the proxy still verify every tarball against that integrity.
 */
export interface RegistryIntegrityCandidate {
  readonly name: PackageName;
  readonly version: PackageVersion;
}

/** `name@version` → the public registry's sha512 `dist.integrity`, supplied by the caller. */
export type RegistryIntegrityFill = ReadonlyMap<string, SriSha512>;

/** The most entries one lockfile may have filled from the registry. */
export const REGISTRY_INTEGRITY_MAX_CANDIDATES = 200;

export function registryIntegrityKey(name: string, version: string): string {
  return `${name}@${version}`;
}
