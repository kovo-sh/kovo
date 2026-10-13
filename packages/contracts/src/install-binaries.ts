import { egressModeSchema } from "./egress.js";
import { hasControlCharacter } from "./primitives.js";
import { z } from "zod";

/** Reviewed download endpoints, not a general host allowlist. Bump on every authority change. */
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
] as const;

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
} as const;

const targetRequestSchema = z.strictObject({
  target: z.enum(["prisma", "node-dist", "node-download", "cypress"]),
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
  .array(z.enum(["prisma", "node-dist", "node-download", "cypress"]))
  .max(4)
  .refine((targets) => new Set(targets).size === targets.length);
export type InstallBinaryBuildTarget = z.infer<typeof installBinaryBuildTargetsSchema>[number];
