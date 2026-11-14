import { egressModeSchema } from "./egress.js";
import { hasControlCharacter } from "./primitives.js";
import { z } from "zod";

/**
 * Reviewed download endpoints, not a general host allowlist. Bump on every agent-chosen authority
 * change. The owner's D-729 GitHub release bridge is a Trust Kovo / Open mode default (like
 * D-615's registry host), not a catalog change, so it applies to version 2 without a bump.
 */
export const INSTALL_BINARY_FETCH_CATALOG_VERSION = 2;

export const INSTALL_BINARY_FETCH_CATALOG = [
  {
    host: "binaries.prisma.sh",
    prefixes: ["/all_commits/"],
    packages: ["prisma", "@prisma/engines"],
    justification: "Prisma-owned engine distribution; this namespace serves static engine files.",
    documentation:
      "https://github.com/prisma/prisma/blob/6.19.0/packages/fetch-engine/src/utils.ts",
  },
  {
    host: "nodejs.org",
    prefixes: ["/dist/", "/download/"],
    packages: ["node-gyp"],
    justification: "Node-owned static releases and headers; no publishing endpoint in these paths.",
    documentation: "https://github.com/nodejs/node-gyp/blob/v11.4.2/lib/process-release.js",
  },
  {
    host: "download.cypress.io",
    prefixes: ["/desktop/"],
    packages: ["cypress"],
    justification:
      "Cypress-owned versioned binary download resolver; fixed Linux platform parameters only.",
    documentation: "https://github.com/cypress-io/cypress/blob/v15.3.0/cli/lib/tasks/download.ts",
  },
  {
    host: "cdn.cypress.io",
    prefixes: ["/desktop/"],
    packages: ["cypress"],
    justification:
      "Cypress-owned versioned binary CDN; used only by trusted-side download redirects.",
    documentation: "https://docs.cypress.io/app/references/advanced-installation",
  },
  {
    host: "cdn.playwright.dev",
    // The CDN root, which Playwright lists as a download mirror and the image's tool-cache build
    // fetches from (infra/sandbox-image/install-tool-cache.mjs).
    prefixes: ["/builds/"],
    packages: ["playwright-core"],
    justification:
      "Playwright-owned browser build CDN; Linux browser zips only, granted per recipe (D-730).",
    documentation:
      "https://github.com/microsoft/playwright/blob/v1.64.1/packages/playwright-core/src/server/registry/index.ts",
  },
] as const;

/**
 * Playwright browser builds, Linux zips only (D-730). Nothing else on the CDN is reachable:
 * - Playwright's own builds: `builds/<browser>/<revision>/<file>-linux.zip` (or
 *   `-ubuntu-24.04.zip`, optionally `-arm64`), the revision digits only;
 * - Chrome for Testing, which Chromium uses from Playwright 1.5x on:
 *   `builds/cft/<n.n.n.n>/linux64/<chrome|chrome-headless-shell>-linux64.zip`.
 */
const PLAYWRIGHT_BUILD_PATH =
  /^\/builds\/(?:(?:chromium|chromium-tip-of-tree|firefox|firefox-beta|webkit|ffmpeg)\/\d{1,8}\/[a-z0-9][a-z0-9-]{0,63}-(?:linux|ubuntu-\d{2}\.\d{2})(?:-arm64)?|cft\/\d{1,5}\.\d{1,5}\.\d{1,6}\.\d{1,5}\/linux64\/(?:chrome|chrome-headless-shell)-linux64)\.zip$/;

/**
 * Owner D-729 (https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6733241173): in Trust
 * Kovo and Open, GitHub release assets are fetched through this read-only bridge. Only the exact
 * `/<owner>/<repo>/releases/download/<tag>/<file>` shape on github.com, GET/HEAD, no query, no
 * body and no credentials; every other github.com path stays refused. A constant, never the
 * caller's owner, repository or file, is the logged prefix.
 */
export const GITHUB_RELEASE_HOST = "github.com";
export const GITHUB_RELEASE_PREFIX = "/{owner}/{repo}/releases/download/";
const GITHUB_RELEASE_PATH =
  /^\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}\/releases\/download\/[^/?%]{1,255}\/[^/?%]{1,255}$/;
/** The object-storage hosts a release download 302s to; reachable only from that redirect. */
export const GITHUB_RELEASE_REDIRECT_HOSTS = [
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
] as const;
const GITHUB_RELEASE_ASSET_PATH =
  /^\/github-production-release-asset(?:-[0-9a-f]{1,16})?\/[0-9]{1,20}\/[A-Za-z0-9._-]{1,128}$/;

/**
 * Whether a trusted-side redirect target is GitHub's release-asset storage. Its signed query is
 * accepted only here, from a vetted github.com redirect, and is never logged or stored.
 */
export function isGithubReleaseAssetRedirect(url: URL): boolean {
  return (
    url.protocol === "https:" &&
    url.username === "" &&
    url.password === "" &&
    url.port === "" &&
    url.hash === "" &&
    (GITHUB_RELEASE_REDIRECT_HOSTS as readonly string[]).includes(url.hostname) &&
    GITHUB_RELEASE_ASSET_PATH.test(url.pathname)
  );
}

const requestSchema = z.strictObject({
  // Trusted job/recipe authority only, never taken from the sandbox request.
  catalogVersion: z.literal(INSTALL_BINARY_FETCH_CATALOG_VERSION),
  mode: egressModeSchema,
  enabled: z.boolean(),
  method: z.enum(["GET", "HEAD"]),
  url: z.string().min(1).max(8192),
  headers: z.record(z.string().max(256), z.string().max(8192)),
});

export type InstallBinaryMatch = {
  readonly host: string;
  /** A catalog constant only, never a caller-supplied path. */
  readonly prefix: string;
};

/** Fail closed before I/O. Upstream redirects and DNS answers need independent verification. */
export function matchInstallBinaryRequest(input: unknown): InstallBinaryMatch | null {
  const parsed = requestSchema.safeParse(input);
  if (!parsed.success || !parsed.data.enabled || !["trust_kovo", "open"].includes(parsed.data.mode))
    return null;
  const { url: raw, headers } = parsed.data;
  // Reject before URL normalization can erase traversal, controls or encoded separators.
  if (/[^\x21-\x7e]|\\/.test(raw) || hasControlCharacter(raw) || /%|#/.test(raw)) return null;
  if (!raw.startsWith("https://") || raw.slice(8).split("/")[0]?.includes("@")) return null;
  if (raw.split("/").some((segment) => segment === "." || segment === "..")) return null;
  if (
    Object.keys(headers).some((key) =>
      ["authorization", "proxy-authorization", "cookie"].includes(key.toLowerCase()),
    )
  )
    return null;
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
    url.hash !== ""
  )
    return null;
  if (url.hostname === "download.cypress.io") {
    if (
      !/^\/desktop\/\d+\.\d+\.\d+$/.test(url.pathname) ||
      url.search !== "?platform=linux&arch=x64"
    )
      return null;
  } else if (url.search !== "") return null;
  if (url.hostname === "cdn.playwright.dev" && !PLAYWRIGHT_BUILD_PATH.test(url.pathname))
    return null;
  if (url.hostname === GITHUB_RELEASE_HOST)
    return GITHUB_RELEASE_PATH.test(url.pathname) && url.search === ""
      ? { host: GITHUB_RELEASE_HOST, prefix: GITHUB_RELEASE_PREFIX }
      : null;
  if (
    url.hostname === "cdn.cypress.io" &&
    !/^\/desktop\/\d+\.\d+\.\d+\/linux-x64\/cypress\.zip$/.test(url.pathname)
  )
    return null;
  for (const rule of INSTALL_BINARY_FETCH_CATALOG) {
    if (url.hostname !== rule.host) continue;
    for (const prefix of rule.prefixes) {
      if (url.pathname.startsWith(prefix) && url.pathname.length > prefix.length)
        return { host: rule.host, prefix };
    }
  }
  return null;
}

/** Fixed proxy route identities. These are download namespaces, never caller-provided origins. */
export const INSTALL_BINARY_FETCH_TARGETS = {
  prisma: {
    host: INSTALL_BINARY_FETCH_CATALOG[0].host,
    prefix: INSTALL_BINARY_FETCH_CATALOG[0].prefixes[0],
  },
  "node-dist": {
    host: INSTALL_BINARY_FETCH_CATALOG[1].host,
    prefix: INSTALL_BINARY_FETCH_CATALOG[1].prefixes[0],
  },
  "node-download": {
    host: INSTALL_BINARY_FETCH_CATALOG[1].host,
    prefix: INSTALL_BINARY_FETCH_CATALOG[1].prefixes[1],
  },
  cypress: {
    host: INSTALL_BINARY_FETCH_CATALOG[2].host,
    prefix: INSTALL_BINARY_FETCH_CATALOG[2].prefixes[0],
  },
  // Build phase only, when discovery granted it for a repository-pinned Playwright the image does
  // not cache and that passed the supply-chain checks (D-730).
  playwright: {
    host: INSTALL_BINARY_FETCH_CATALOG[4].host,
    prefix: INSTALL_BINARY_FETCH_CATALOG[4].prefixes[0],
  },
  "github-release": { host: GITHUB_RELEASE_HOST, prefix: "/" },
} as const;

/** Every fetch identity a request may name. Build grants stay the detector-selected subset. */
export const INSTALL_BINARY_TARGET_IDS = [
  "prisma",
  "node-dist",
  "node-download",
  "cypress",
  "playwright",
  "github-release",
] as const;

/** The identities a recipe's build grant may hold (detector-selected; D-730 adds Playwright). */
export const INSTALL_BINARY_BUILD_TARGETS = [
  "prisma",
  "node-dist",
  "node-download",
  "cypress",
  "playwright",
] as const;

const targetRequestSchema = z.strictObject({
  target: z.enum(INSTALL_BINARY_TARGET_IDS),
  suffix: z.string().min(1).max(4096),
});

/** URL construction only: callers must separately verify live job/recipe/command authority. */
export function installBinaryTargetUrl(input: unknown): string | null {
  const parsed = targetRequestSchema.safeParse(input);
  if (!parsed.success || parsed.data.suffix.startsWith("/")) return null;
  const rule = INSTALL_BINARY_FETCH_TARGETS[parsed.data.target];
  if (parsed.data.target === "cypress" && !/^\d+\.\d+\.\d+$/.test(parsed.data.suffix)) return null;
  const url = `https://${rule.host}${rule.prefix}${parsed.data.suffix}${parsed.data.target === "cypress" ? "?platform=linux&arch=x64" : ""}`;
  return matchInstallBinaryRequest({
    catalogVersion: INSTALL_BINARY_FETCH_CATALOG_VERSION,
    enabled: true,
    mode: "trust_kovo",
    method: "GET",
    headers: {},
    url,
  }) === null
    ? null
    : url;
}

/** Build grants use detector-selected rule identities, never arbitrary hosts or URL prefixes. */
export const installBinaryBuildTargetsSchema = z
  .array(z.enum(INSTALL_BINARY_BUILD_TARGETS))
  .max(INSTALL_BINARY_BUILD_TARGETS.length)
  .refine((targets) => new Set(targets).size === targets.length);
export type InstallBinaryBuildTarget = z.infer<typeof installBinaryBuildTargetsSchema>[number];

/**
 * Why a customer tool version is not fetched through the proxy (D-730): the npm supply-chain
 * checks a repository-pinned tool must pass. Reason codes only; logged with the public package
 * name and version (D-242).
 */
export const CUSTOMER_TOOL_REFUSALS = [
  /** Published less than 24 hours ago; it passes by itself once old enough. */
  "tool_min_age",
  /** An advisory or a Kovo hold names the version. */
  "tool_advisory",
  /** Earlier releases were attested and this one is not. */
  "tool_provenance_lost",
  /** The registry could not be read or does not list the version: unknown is never a pass. */
  "tool_evidence_unknown",
  /** The commit's lockfile evidence names no exact version of the tool. */
  "tool_version_unknown",
] as const;
export type CustomerToolRefusal = (typeof CUSTOMER_TOOL_REFUSALS)[number];
