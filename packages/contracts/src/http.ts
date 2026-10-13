import { z } from "zod";

// HTTP header contracts shared by the web client and the control-plane middleware (ARCHITECTURE §3
// "Pagination, concurrency control, idempotency"; docs/decisions/auth.md for the CSRF header).

export const HEADERS = {
  /** Release identity for cross-version web recovery; never an authorization input. */
  version: "Kovo-Version",
  requestId: "X-Request-Id",
  idempotencyKey: "Idempotency-Key",
  ifMatch: "If-Match",
  etag: "ETag",
  cacheControl: "Cache-Control",
  retryAfter: "Retry-After",
  csrf: "X-Kovo-CSRF",
  forwardedBy: "X-Kovo-Forwarded-By",
  /**
   * The explicit account context of account-scoped routes without an account in the path (SPEC:
   * "Account-scoped routes without an account in the path require an explicit validated account
   * context"). Required for sessions; optional for API keys, which must then name the key's own
   * account.
   */
  accountContext: "X-Kovo-Account",
  /**
   * The browser's IP address as the web server derived it (the rightmost `X-Forwarded-For` entry
   * Cloud Run appended), for the API's per-client rate limits. The API trusts it only together with
   * {@link HEADERS.webProxyAuth} and removes it from every other request.
   */
  clientIp: "X-Kovo-Client-IP",
  /** The web server's shared secret vouching for {@link HEADERS.clientIp} (web → API only). */
  webProxyAuth: "X-Kovo-Proxy-Auth",
} as const;

/**
 * `Cache-Control` of every `/v1` response (SPEC: authenticated content is "private, non-indexable,
 * and never shared-cacheable"). An `ETag` is a concurrency token for `If-Match` writes, not a cache
 * validator: `If-None-Match` is ignored and no route answers `304`, because a representation such
 * as `GET …/recipe` changes in parts its version does not cover.
 */
export const API_CACHE_CONTROL = "private, no-store";

/** Name of the double-submit CSRF cookie echoed in {@link HEADERS.csrf}. */
export const CSRF_COOKIE_NAME = "kovo_csrf";

/**
 * The path prefix of the web's session channel (docs/decisions/web.md "One path layout for the
 * browser and SSR"): the browser's same-origin proxy and SSR reach Better Auth at `/api/auth/*` and
 * the public API at `/api/v1/*`, so the control plane serves its `/v1` router under this prefix as
 * well as at `/v1` (API keys).
 */
export const WEB_API_PREFIX = "/api";

/**
 * `Idempotency-Key` for retriable billing/capacity/retry mutations (SPEC: "accept idempotency keys
 * for retriable billing/capacity operations"). A UUID is recommended; any 8–255 character token of
 * unreserved URL characters is accepted.
 */
export const idempotencyKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9._~+/=:-]{8,255}$/, { error: "must be an 8-255 character opaque token" })
  .brand<"IdempotencyKey">();
export type IdempotencyKey = z.infer<typeof idempotencyKeySchema>;

/** Version number of a versioned resource (recipe overrides, policy, notifications): from 1. */
export const resourceVersionSchema = z.int().positive();

/** The strong ETag for a resource version (`"3"`). */
export function versionEtag(version: number): string {
  return `"${resourceVersionSchema.parse(version)}"`;
}

export type IfMatch =
  | { readonly kind: "missing" }
  | { readonly kind: "any" }
  | { readonly kind: "versions"; readonly versions: readonly number[] }
  | { readonly kind: "invalid" };

const ENTITY_TAG = /^(W\/)?"([\x21\x23-\x7e]*)"$/;

/**
 * Parses an `If-Match` header (RFC 9110 §13.1.1). `If-Match` uses the strong comparison, so weak
 * tags never match and are dropped; tags that are not Kovo version tags cannot match either.
 * Whether `*` is acceptable is the route's decision.
 */
export function parseIfMatch(header: string | undefined | null): IfMatch {
  if (header === undefined || header === null) return { kind: "missing" };
  const trimmed = header.trim();
  if (trimmed === "") return { kind: "invalid" };
  if (trimmed === "*") return { kind: "any" };
  const versions: number[] = [];
  for (const raw of trimmed.split(",")) {
    const match = ENTITY_TAG.exec(raw.trim());
    if (match === null) return { kind: "invalid" };
    if (match[1] !== undefined) continue;
    const opaque = match[2] ?? "";
    if (!/^[1-9]\d{0,14}$/.test(opaque)) continue;
    versions.push(Number(opaque));
  }
  return { kind: "versions", versions };
}

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_CHARACTERS = /^[0-9A-Fa-f:.]+$/;

/** The canonical form of one IPv4 or IPv6 address, or null. */
export function canonicalIpAddress(value: string): string | null {
  if (IPV4.test(value)) return value;
  if (!value.includes(":") || !IPV6_CHARACTERS.test(value)) return null;
  try {
    // The URL parser validates and compresses IPv6 (`2001:DB8:0::1` → `2001:db8::1`).
    return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

/**
 * `X-Forwarded-For` entries the platform appends in front of a runtime: 1 with Cloud Run alone
 * (local and test runs), 2 behind the environment's HTTPS load balancer, which appends the client's
 * address and then its own (`web.trustedProxyHops`, `api.trustedProxyHops`,
 * `proxy.trustedProxyHops`).
 */
export type TrustedProxyHops = 1 | 2;

/**
 * The client's address among the `hops` rightmost `X-Forwarded-For` entries the platform appended
 * (the leftmost of them; with one hop, the rightmost entry). Everything to their left is whatever
 * the client sent and is never trusted. Every appended entry must be an address, or the header is
 * not the platform's. One implementation for the web server (the address it vouches for to the
 * API), the API and the npm proxy (their per-instance rate limiters' key;
 * docs/decisions/cost-reduction.md).
 */
export function clientIpFromForwardedFor(
  header: string | null | undefined,
  hops: TrustedProxyHops = 1,
): string | null {
  if (header === null || header === undefined) return null;
  const entries = header.split(",").map((entry) => entry.trim());
  if (entries.length < hops) return null;
  const appended = entries.slice(entries.length - hops).map(canonicalIpAddress);
  if (appended.some((address) => address === null)) return null;
  return appended[0] ?? null;
}

/**
 * The web paths the load balancer routes to the Cloud CDN-enabled backend `kovo-web-static`
 * (docs/decisions/cost-reduction.md "Cloud CDN"; infra/terraform/modules/edge keeps its route
 * matches equal to these). Only public, identical-for-everyone files: content-hashed assets, the
 * social images, the favicons, robots.txt, the sitemap and the uptime check's file. No HTML, no
 * server function, no `/api`: everything else takes the uncached `kovo-web` backend, and the web
 * server marks each of these `public` only when it is the file (a miss is `no-store`).
 */
export const WEB_CDN_PATHS = {
  prefixes: ["/assets/", "/og/"],
  exact: ["/favicon.ico", "/favicon.svg", "/robots.txt", "/sitemap.xml", "/edge-check.txt"],
} as const;

/** Whether the load balancer sends `path` (a URL path, no query) to the CDN-enabled backend. */
export function isWebCdnPath(path: string): boolean {
  return (
    (WEB_CDN_PATHS.exact as readonly string[]).includes(path) ||
    WEB_CDN_PATHS.prefixes.some((prefix) => path.startsWith(prefix))
  );
}
