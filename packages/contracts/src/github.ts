import { z } from "zod";

import type { AccountType } from "./enums/accounts.js";
import { whenValid } from "./primitives.js";

// GitHub naming shared by the `/v1` contracts, webhook payloads, the GitHub adapters and the
// database CHECKs (docs/decisions/contracts.md "GitHub logins"). SPEC keys accounts "by immutable
// GitHub account ID, not login": logins and full names are display and addressing data only.
//
// GitHub, "Username considerations for external authentication" (checked 2026-09-26): Enterprise
// Managed Users are "@IDP-USERNAME_SHORT-CODE" (e.g. `mona-cat_octo`), the short code is "an
// alphanumeric string between three and eight characters", and "Usernames, including underscore and
// short code, must not exceed 39 characters". Organization logins never contain an underscore.

/** GitHub's maximum login length, the Enterprise Managed User suffix included. */
export const GITHUB_LOGIN_MAX_LENGTH = 39;

/** Regex source of an organization login: alphanumerics and hyphens, at most 39 characters. */
export const GITHUB_ORG_LOGIN_PATTERN = "[A-Za-z0-9][A-Za-z0-9-]{0,38}";

/**
 * Regex source of a user login: a classic login (`octocat`) or an Enterprise Managed User login
 * (`mona-cat_octo`). The 39-character cap is checked separately (a regex bound would have to be
 * split around the optional suffix). Every organization login also matches it.
 */
export const GITHUB_USER_LOGIN_PATTERN = "[A-Za-z0-9][A-Za-z0-9-]*(?:_[A-Za-z0-9]{3,8})?";

/** Regex source of a repository name (the part after `owner/`). */
export const GITHUB_REPO_NAME_PATTERN = "[A-Za-z0-9._-]{1,100}";

/** An organization login (`my-org`): never an underscore. */
export const githubOrgLoginSchema = z.string().regex(new RegExp(`^${GITHUB_ORG_LOGIN_PATTERN}$`), {
  error: "must be a GitHub organization login",
});
export type GithubOrgLogin = z.infer<typeof githubOrgLoginSchema>;

/**
 * Any GitHub login: a user (classic or Enterprise Managed User) or an organization. Use
 * {@link githubAccountLoginMatchesType} where the account type is known.
 */
export const githubLoginSchema = z
  .string()
  .max(GITHUB_LOGIN_MAX_LENGTH)
  .regex(new RegExp(`^${GITHUB_USER_LOGIN_PATTERN}$`), { error: "must be a GitHub login" });
export type GithubLogin = z.infer<typeof githubLoginSchema>;

/** Whether `login` is valid for an account of `type`: organizations never carry an EMU suffix. */
export function githubAccountLoginMatchesType(login: string, type: AccountType): boolean {
  return type === "user" || githubOrgLoginSchema.safeParse(login).success;
}

/** A repository name (the part after `owner/`); never `.` or `..`. */
export const githubRepoNameSchema = z
  .string()
  .regex(new RegExp(`^${GITHUB_REPO_NAME_PATTERN}$`), { error: "must be a GitHub repository name" })
  .refine((name) => name !== "." && name !== "..", { ...whenValid, error: "must not be . or .." });

/**
 * Regex source of a GitHub `owner/name`; the owner may be an EMU user. The owner's 39-character cap
 * is checked separately ({@link repoFullNameSchema}, and the `repos_full_name` CHECK).
 */
export const GITHUB_REPO_FULL_NAME_PATTERN = `${GITHUB_USER_LOGIN_PATTERN}/${GITHUB_REPO_NAME_PATTERN}`;

function ownerOf(fullName: string): string {
  return fullName.slice(0, fullName.indexOf("/"));
}

/** A GitHub `owner/name` repository name (a user-owned repository may belong to an EMU user). */
export const repoFullNameSchema = z
  .string()
  .regex(new RegExp(`^${GITHUB_REPO_FULL_NAME_PATTERN}$`), {
    error: "must be a GitHub owner/name",
  })
  .refine(
    (fullName) => {
      const name = fullName.slice(fullName.indexOf("/") + 1);
      return ownerOf(fullName).length <= GITHUB_LOGIN_MAX_LENGTH && name !== "." && name !== "..";
    },
    { ...whenValid, error: "must be a GitHub owner/name" },
  );
export type RepoFullName = z.infer<typeof repoFullNameSchema>;

/** A github.com pull request URL: `https://github.com/<owner>/<name>/pull/<number>`. */
export const githubPullRequestUrlSchema = z
  .string()
  .max(512)
  .regex(new RegExp(`^https://github\\.com/${GITHUB_REPO_FULL_NAME_PATTERN}/pull/[1-9]\\d*$`), {
    error: "must be a github.com pull request URL",
  })
  .refine(
    (url) => {
      const path = url.slice("https://github.com/".length);
      return repoFullNameSchema.safeParse(path.slice(0, path.indexOf("/pull/"))).success;
    },
    { ...whenValid, error: "must be a github.com pull request URL" },
  );
