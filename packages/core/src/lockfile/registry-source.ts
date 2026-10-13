import {
  NPM_PUBLIC_REGISTRY_ORIGIN,
  npmTarballUrl,
  sriSha512Schema,
  type SriSha512,
} from "@kovo/contracts";

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

export type IntegrityCheck =
  | { readonly ok: true; readonly integrity: SriSha512; readonly algorithm: "sha512" }
  /** Only a legacy sha1 digest (packages published before npm recorded sha512). */
  | { readonly ok: true; readonly integrity: null; readonly algorithm: "sha1" }
  | { readonly ok: false; readonly reason: "missing_integrity" | "invalid_integrity" };

const SHA1_SRI = /^sha1-[A-Za-z0-9+/]{27}=$/;

/**
 * Reads an SRI integrity string (one or more space-separated `alg-base64` tokens). The strongest
 * usable token wins: sha512, else a legacy sha1. Any malformed token rejects the whole value.
 */
export function checkIntegrity(value: string | undefined): IntegrityCheck {
  if (value === undefined || value.trim() === "") return { ok: false, reason: "missing_integrity" };
  let sha512: SriSha512 | null = null;
  let sha1 = false;
  for (const token of value.trim().split(/\s+/)) {
    const digest = token.split("?")[0] ?? "";
    const parsed = sriSha512Schema.safeParse(digest);
    if (parsed.success) sha512 ??= parsed.data;
    else if (SHA1_SRI.test(digest)) sha1 = true;
    else return { ok: false, reason: "invalid_integrity" };
  }
  if (sha512 !== null) return { ok: true, integrity: sha512, algorithm: "sha512" };
  if (sha1) return { ok: true, integrity: null, algorithm: "sha1" };
  return { ok: false, reason: "invalid_integrity" };
}
