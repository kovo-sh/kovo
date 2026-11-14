import { INSTALL_BINARY_FETCH_TARGETS } from "./install-binaries.js";

// The A1 shared public artifact cache (owner D-709, source:
// https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6725432185;
// plans/js-coverage-phase2.md §2.3; Refs #8256). Pure policy, shared by the trusted fetcher (the
// writer, in the control plane's install-binary receiver), the sandbox bridge and the tests.
//
// Only Kovo's trusted fetcher writes, and only when every rule holds: a reviewed catalog host
// (the D-658 install-binary catalog), HTTPS on every hop, no credentials, cookies or auth headers
// sent, no query, fragment or userinfo on any hop, a response that is not `Cache-Control: private`
// or `no-store`, and a sha256 pinned from an independent source when one exists (the vendor's
// checksum file), otherwise the sha256 of Kovo's own fetch, never a sandbox-supplied value.
//
// Agent decision (2026-11-10), pending owner review, narrower than D-709 allows: only the catalog
// routes whose every hop is query-free are cacheable. Cypress (its resolver URL carries a fixed
// query) and GitHub release assets (they redirect to signed query URLs) are never cached, and the
// checksum files that serve as independent pins are never cached themselves.

/** `cacheMaxBytes`: the bucket's total; past it the writer refuses with `artifact_cache_full`. */
export const ARTIFACT_CACHE_MAX_BYTES = 200n * 1024n ** 3n;
/** The largest single entry: the install-binary fetch limit. */
export const ARTIFACT_CACHE_MAX_ENTRY_BYTES = 512 * 1024 * 1024;
/** Entries not used for this many days are deleted. */
export const ARTIFACT_CACHE_UNUSED_DAYS = 30;
/** The cache edge's TCP port at its one internal address. */
export const ARTIFACT_CACHE_EDGE_PORT = 8080;

/**
 * The sandbox bridge asks for the cache through this request header: `edge` (it can reach the
 * cache edge, so a hit answers with the key instead of the bytes) or `bypass` (the edge failed:
 * download from the vendor). Any other value is refused.
 */
export const ARTIFACT_CACHE_REQUEST_HEADER = "x-kovo-artifact-cache";
/** A hit's answer: `<url sha256>/<content sha256>`, the only key the edge serves. */
export const ARTIFACT_CACHE_KEY_HEADER = "x-kovo-artifact-cache-key";
/** A hit's entry size, so the bridge bounds its read from the edge. */
export const ARTIFACT_CACHE_SIZE_HEADER = "x-kovo-artifact-cache-size";

/** Where an entry's content sha256 came from: the vendor's checksum file or Kovo's own fetch. */
export const ARTIFACT_CACHE_PIN_SOURCES = ["vendor_checksum", "own_fetch"] as const;
export type ArtifactCachePinSource = (typeof ARTIFACT_CACHE_PIN_SOURCES)[number];

/** The install-binary routes whose every hop can meet the rules above. */
export const ARTIFACT_CACHE_TARGETS = [
  "prisma",
  "node-dist",
  "node-download",
  "playwright",
] as const;
export type ArtifactCacheTarget = (typeof ARTIFACT_CACHE_TARGETS)[number];

/**
 * Stable reason codes (D-267), readable through the receiver's metadata log events. Writer
 * refusals leave the fetch uncached and never change what the sandbox receives.
 */
/** What the cache did, for its metadata metric (hit and miss are edge lookups). */
export const ARTIFACT_CACHE_OUTCOMES = ["hit", "miss", "stored", "refused", "deleted"] as const;
export type ArtifactCacheOutcome = (typeof ARTIFACT_CACHE_OUTCOMES)[number];

export const ARTIFACT_CACHE_REASONS = [
  /** The kill switch is off or no bucket is configured. */
  "artifact_cache_disabled",
  /** The route is not one of {@link ARTIFACT_CACHE_TARGETS} (Cypress, GitHub releases). */
  "artifact_cache_host_not_catalog",
  "artifact_cache_not_https",
  "artifact_cache_query",
  "artifact_cache_credentials",
  /** A redirect hop left the catalog host, used a query or was not HTTPS. */
  "artifact_cache_redirect",
  /** `Cache-Control: private` or `no-store`. */
  "artifact_cache_private",
  /** A vendor checksum file, the independent pin of other entries. */
  "artifact_cache_checksum_file",
  "artifact_cache_too_large",
  /** The bucket would pass {@link ARTIFACT_CACHE_MAX_BYTES}. */
  "artifact_cache_full",
  /** Another write holds the writer's one buffer. */
  "artifact_cache_busy",
  /** The vendor's checksum file names another sha256. */
  "artifact_cache_pin_mismatch",
  /** The vendor's checksum file could not be read or does not list the file. */
  "artifact_cache_pin_unavailable",
  /** The transfer did not complete. */
  "artifact_cache_incomplete",
  /** The bucket or index could not be read or written. */
  "artifact_cache_unavailable",
  /** A stored entry's bytes no longer match its content sha256: deleted. */
  "artifact_cache_entry_mismatch",
  /** Not used for {@link ARTIFACT_CACHE_UNUSED_DAYS} days: deleted. */
  "artifact_cache_entry_unused",
] as const;
export type ArtifactCacheReason = (typeof ARTIFACT_CACHE_REASONS)[number];

/** What the trusted fetcher observed about its own fetch; never a sandbox-supplied value. */
export interface ArtifactFetchFacts {
  /** The install-binary route; a constant chosen by the receiver's path, not a URL. */
  readonly target: string;
  /** The request URL Kovo fetched (from the catalog route and suffix). */
  readonly url: string;
  /** The headers Kovo sent upstream beyond its fixed ones. */
  readonly sentHeaders: Readonly<Record<string, string>>;
  /** Every redirect hop stayed on the request's catalog host, HTTPS, with no query or userinfo. */
  readonly hopsCacheSafe: boolean;
  /** The final response's `Cache-Control` value, or null. */
  readonly cacheControl: string | null;
}

const CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization", "cookie"]);

function cacheTarget(target: string): ArtifactCacheTarget | null {
  return ARTIFACT_CACHE_TARGETS.find((value) => value === target) ?? null;
}

/**
 * The canonical form of a cacheable URL: `https://<lowercase host><path>`, or null when the URL
 * has a query, fragment, userinfo or port, or is not HTTPS. The cache key is its sha256.
 */
export function canonicalArtifactUrl(raw: string): string | null {
  if (/[^\x21-\x7e]/.test(raw) || raw.includes("?") || raw.includes("#")) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname.length < 2
  )
    return null;
  return `https://${url.hostname.toLowerCase()}${url.pathname}`;
}

/** Whether a route's path is one of the vendor checksum files that pin other entries. */
export function isArtifactChecksumFile(target: string, path: string): boolean {
  return (
    (target === "prisma" && path.endsWith(".sha256")) ||
    ((target === "node-dist" || target === "node-download") && path.endsWith("/SHASUMS256.txt"))
  );
}

/**
 * The writer's admission rules for one completed fetch, before any byte is kept: null when the
 * response may be cached, else the reason it may not. Size, capacity and the pin are checked
 * after the transfer.
 */
export function artifactCacheRefusal(facts: ArtifactFetchFacts): ArtifactCacheReason | null {
  const target = cacheTarget(facts.target);
  if (target === null) return "artifact_cache_host_not_catalog";
  let url: URL;
  try {
    url = new URL(facts.url);
  } catch {
    return "artifact_cache_host_not_catalog";
  }
  if (url.hostname !== INSTALL_BINARY_FETCH_TARGETS[target].host)
    return "artifact_cache_host_not_catalog";
  if (url.protocol !== "https:") return "artifact_cache_not_https";
  if (facts.url.includes("?") || facts.url.includes("#") || url.search !== "" || url.hash !== "")
    return "artifact_cache_query";
  if (
    url.username !== "" ||
    url.password !== "" ||
    Object.keys(facts.sentHeaders).some((name) => CREDENTIAL_HEADERS.has(name.toLowerCase()))
  )
    return "artifact_cache_credentials";
  if (canonicalArtifactUrl(facts.url) === null) return "artifact_cache_query";
  if (!facts.hopsCacheSafe) return "artifact_cache_redirect";
  if (facts.cacheControl !== null) {
    const directives = new Set(
      facts.cacheControl
        .toLowerCase()
        .split(",")
        .map((directive) => directive.trim().split("=")[0]?.trim()),
    );
    if (directives.has("private") || directives.has("no-store")) return "artifact_cache_private";
  }
  if (isArtifactChecksumFile(target, url.pathname)) return "artifact_cache_checksum_file";
  return null;
}

/**
 * Where an entry's independent sha256 pin comes from, when the vendor publishes one:
 * - Prisma engines: the `<file>.sha256` beside each file;
 * - Node releases and headers: the release directory's `SHASUMS256.txt`, by file name.
 * Playwright builds publish none, so their pin is the sha256 of Kovo's own fetch.
 * Every source URL is on the same catalog route, fetched by Kovo, never by the sandbox.
 */
export type ArtifactPinSource =
  | { readonly kind: "sidecar"; readonly suffix: string }
  | { readonly kind: "shasums"; readonly suffix: string; readonly file: string }
  | { readonly kind: "own_fetch" };

export function artifactPinSource(target: string, suffix: string): ArtifactPinSource | null {
  const cached = cacheTarget(target);
  if (cached === null) return null;
  if (cached === "prisma") return { kind: "sidecar", suffix: `${suffix}.sha256` };
  if (cached === "node-dist" || cached === "node-download") {
    const slash = suffix.lastIndexOf("/");
    if (slash <= 0 || slash === suffix.length - 1) return null;
    const file = suffix.slice(slash + 1);
    // Header and release files sit in the release directory, or one level down (`win-x64/`).
    const directory = suffix.slice(0, slash);
    const release = /^v\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(directory)
      ? directory
      : /^(v\d{1,3}\.\d{1,3}\.\d{1,3})\/[a-z0-9-]{1,32}$/.exec(directory)?.[1];
    if (release === undefined) return null;
    const name = release === directory ? file : `${directory.slice(release.length + 1)}/${file}`;
    return { kind: "shasums", suffix: `${release}/SHASUMS256.txt`, file: name };
  }
  return { kind: "own_fetch" };
}

/** Reads one file's sha256 from a `SHASUMS256.txt` or `.sha256` body; null when absent. */
export function sha256FromChecksumFile(text: string, file: string | null): string | null {
  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64})(?:\s+\*?(\S+))?\s*$/.exec(line.trim());
    if (match === null) continue;
    if (file === null || match[2] === file) return match[1] ?? null;
  }
  return null;
}

/** A cache key as the key header carries it, or null when malformed. */
export function parseArtifactCacheKey(
  value: string,
): { readonly urlHash: string; readonly contentSha256: string } | null {
  const match = /^([0-9a-f]{64})\/([0-9a-f]{64})$/.exec(value);
  return match === null ? null : { urlHash: match[1] ?? "", contentSha256: match[2] ?? "" };
}
