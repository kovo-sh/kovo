import { z } from "zod";

import { repoFullNameSchema, type RepoFullName } from "./github.js";
import { advisoryIdSchema } from "./ids.js";
import { exactVersionSchema, packageNameSchema } from "./npm.js";

// The public repo check (plans/public-repo-check.md; docs/decisions/dashboard.md "The public repo
// check"): a visitor with no account names a public GitHub repository and sees the serious findings
// of its root lockfile and the version Kovo's fix would move each package to. The web page posts
// `{ repo }` to its own server, which forwards it to the API's public route with the visitor's
// vouched address. The answer is findings metadata only (package names, versions, advisory IDs,
// tiers): never lockfile or manifest content, which no part of the check persists or logs.

/** The API's public route (outside `/v1`; no session, no key). */
export const PUBLIC_REPO_CHECK_PATH = "/public/repo-check";

/** The web page that serves the check, and the path its form posts to. */
export const PUBLIC_REPO_CHECK_PAGE_PATH = "/check";

/** Findings listed in one answer; the rest are counted in `more_findings`. */
export const PUBLIC_REPO_CHECK_MAX_FINDINGS = 50;

/** The largest request body the API reads (`{"repo":"<owner>/<name>"}` is at most ~160 bytes). */
export const PUBLIC_REPO_CHECK_MAX_BODY_BYTES = 512;

export const publicRepoCheckRequestSchema = z.strictObject({ repo: repoFullNameSchema });
export type PublicRepoCheckRequest = z.infer<typeof publicRepoCheckRequestSchema>;

/** The root lockfiles the check reads, in the order it looks for them. */
export const PUBLIC_REPO_CHECK_LOCKFILES = [
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
] as const;
export type PublicRepoCheckLockfile = (typeof PUBLIC_REPO_CHECK_LOCKFILES)[number];

/** SPEC `tier()` branches that make a finding serious (P0 or P1). */
export const PUBLIC_REPO_CHECK_REASONS = [
  "malicious",
  "kev",
  "curated_package_and_cwe",
  "high_or_critical",
] as const;
export type PublicRepoCheckReason = (typeof PUBLIC_REPO_CHECK_REASONS)[number];

/**
 * Why a repository could not be checked here. `lockfile_too_large` is the public check's own size
 * bound; the rest are the lockfile parser's unsupported-repository reasons, passed through as codes.
 */
const unsupportedReasonSchema = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);

export const publicRepoCheckFindingSchema = z.strictObject({
  package: packageNameSchema,
  version: exactVersionSchema,
  advisory_id: advisoryIdSchema,
  tier: z.enum(["P0", "P1"]),
  reason: z.enum(PUBLIC_REPO_CHECK_REASONS),
  /** A dependency the root manifest names itself (else it arrives through another package). */
  direct: z.boolean(),
  /** The lowest version that no known advisory affects, or null when there is none yet. */
  fixed_version: exactVersionSchema.nullable(),
});
export type PublicRepoCheckFinding = z.infer<typeof publicRepoCheckFindingSchema>;

export const publicRepoCheckResponseSchema = z.discriminatedUnion("result", [
  z.strictObject({
    result: z.literal("checked"),
    repo: repoFullNameSchema,
    lockfile: z.enum(PUBLIC_REPO_CHECK_LOCKFILES),
    /** Resolved package versions in the lockfile. */
    packages: z.number().int().nonnegative(),
    findings: z.array(publicRepoCheckFindingSchema).max(PUBLIC_REPO_CHECK_MAX_FINDINGS),
    /** Serious findings beyond the listed ones. */
    more_findings: z.number().int().nonnegative(),
    /** Findings below P1 (development-only, or not high or critical), counted only. */
    other_findings: z.number().int().nonnegative(),
  }),
  z.strictObject({ result: z.literal("no_lockfile"), repo: repoFullNameSchema }),
  z.strictObject({
    result: z.literal("unsupported"),
    repo: repoFullNameSchema,
    reason: unsupportedReasonSchema,
  }),
]);
export type PublicRepoCheckResponse = z.infer<typeof publicRepoCheckResponseSchema>;

const GITHUB_HOSTS: ReadonlySet<string> = new Set(["github.com", "www.github.com"]);

/**
 * The `owner/name` a visitor typed: `owner/name`, or a github.com URL of the repository or any page
 * under it (`https://github.com/owner/name/tree/main`, `github.com/owner/name.git`). Null when it
 * names no GitHub repository. Nothing but the two path segments survives, so the check can only ever
 * address `owner/name` on GitHub.
 */
export function parsePublicRepoInput(input: string): RepoFullName | null {
  const text = input.trim();
  if (text.length === 0 || text.length > 300) return null;
  let path = text;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text) || /^(?:www\.)?github\.com\//i.test(text)) {
    let url: URL;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (!GITHUB_HOSTS.has(url.hostname.toLowerCase()) || url.port !== "") return null;
    if (url.username !== "" || url.password !== "") return null;
    path = url.pathname;
  }
  const segments = path.split("/").filter((segment) => segment.length > 0);
  if (segments.length < 2) return null;
  if (path === text && segments.length !== 2) return null;
  const owner = segments[0]!;
  const name = segments[1]!.replace(/\.git$/i, "");
  const parsed = repoFullNameSchema.safeParse(`${owner}/${name}`);
  return parsed.success ? parsed.data : null;
}
