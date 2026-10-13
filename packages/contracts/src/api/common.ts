import { z } from "zod";

import {
  accountIdSchema,
  apiKeyIdSchema,
  githubRepoIdSchema,
  githubUserIdSchema,
  repoIdSchema,
  userIdSchema,
} from "../ids.js";
import { countSchema, hasControlCharacter, labelSchema, whenValid } from "../primitives.js";
import { githubLoginSchema, repoFullNameSchema } from "../github.js";
import { ONE_TIME_SECRET_BODY_LENGTH } from "../secret-tokens.js";

// Shapes shared by several `/v1` areas. Wire fields are snake_case (docs/decisions/contracts.md);
// timestamps are `utcDateTimeSchema`, money is micro-USD strings, every object is strict so a
// response can never carry a field the contract does not name.

/** The `X-Kovo-Account` header value (`HEADERS.accountContext`). */
export const accountContextSchema = accountIdSchema;

/**
 * A Kovo user as other users see them: IDs and GitHub login, never an email address. The login may
 * be an Enterprise Managed User login (`mona-cat_octo`).
 */
export const userRefSchema = z.strictObject({
  id: userIdSchema,
  github_user_id: githubUserIdSchema,
  login: githubLoginSchema,
});
export type UserRef = z.infer<typeof userRefSchema>;

/** An API key's display name. */
export const apiKeyNameSchema = labelSchema(64);

/**
 * Who performed a change. Operators appear without identity in customer-facing responses; their
 * principal is visible only on operator routes.
 */
export const actorRefSchema = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("user"), user: userRefSchema }),
  z.strictObject({
    type: z.literal("api_key"),
    api_key_id: apiKeyIdSchema,
    name: apiKeyNameSchema,
  }),
  z.strictObject({ type: z.literal("operator") }),
  z.strictObject({ type: z.literal("system") }),
]);
export type ActorRef = z.infer<typeof actorRefSchema>;

/** A repository as referenced from other resources. */
export const repoRefSchema = z.strictObject({
  id: repoIdSchema,
  github_repo_id: githubRepoIdSchema,
  full_name: repoFullNameSchema,
});
export type RepoRef = z.infer<typeof repoRefSchema>;

/**
 * The `q` search of the account-wide findings and fixes lists: part of a package name, or an
 * advisory ID or alias (`GHSA-…`, `CVE-…`). Only the characters those can hold, so a search is a
 * plain term, never a pattern (docs/decisions/contracts.md "Account-wide findings and fixes").
 */
export const WORK_SEARCH_MIN_LENGTH = 2;
export const WORK_SEARCH_MAX_LENGTH = 214;
export const workSearchSchema = z
  .string()
  .min(WORK_SEARCH_MIN_LENGTH)
  .max(WORK_SEARCH_MAX_LENGTH)
  .regex(/^[A-Za-z0-9@/._~-]+$/, {
    error: "search by a package name or an advisory ID",
  });

/** The body of a mutation that takes no input (an explicit `{}`; unknown fields are rejected). */
export const emptyBodySchema = z.strictObject({});

/** A boolean query parameter spelled `true` or `false`. */
export const queryBooleanSchema = z.codec(z.enum(["true", "false"]), z.boolean(), {
  decode: (text) => text === "true",
  encode: (value) => (value ? "true" : "false"),
});

/** A per-repository version number in a path (`/recipe/versions/{v}`), `1`, `2`, … */
export const versionNumberParamSchema = z.codec(
  z.string().regex(/^[1-9]\d{0,8}$/, { error: "must be a positive version number" }),
  z.int().positive(),
  { decode: (text) => Number(text), encode: (version) => String(version) },
);

/** An array with no duplicate elements (compared with `===`, so use it for IDs and enums). */
export function uniqueArraySchema<Item extends z.ZodType>(item: Item, max: number, min = 0) {
  return z
    .array(item)
    .min(min)
    .max(max)
    .refine((values) => new Set(values).size === values.length, {
      ...whenValid,
      error: "values must be unique",
    });
}

/** Counts per fix-capable tier plus digest (`open_findings`). */
export const tierCountsSchema = z.strictObject({
  P0: countSchema,
  P1: countSchema,
  digest: countSchema,
});

/** The longest free-text note a person may type (a dismissal reason, for one). */
export const NOTE_MAX_LENGTH = 500;

/** A free-text note or reason typed by a person: trimmed, single line, bounded. */
export const noteSchema = labelSchema(NOTE_MAX_LENGTH);

/**
 * A GitHub branch name following `git check-ref-format` rules closely enough to reject anything
 * that could be a path trick or an option: no control characters, spaces, `..`, `//`, `@{`, the
 * characters `~^:?*[\`, and no leading `-`/`/` or trailing `/`, `.` or `.lock`.
 */
export const branchNameSchema = z
  .string()
  .min(1)
  .max(255)
  .refine(
    (name) =>
      !hasControlCharacter(name) &&
      !/[\s~^:?*[\\]/.test(name) &&
      !name.includes("..") &&
      !name.includes("//") &&
      !name.includes("@{") &&
      !name.startsWith("-") &&
      !name.startsWith("/") &&
      !name.endsWith("/") &&
      !name.endsWith(".") &&
      !name.endsWith(".lock") &&
      name !== "@",
    { error: "must be a valid Git branch name" },
  );

/**
 * An `https:` URL without credentials or fragment, optionally restricted to hosts matching
 * `hostname` (used for GitHub and Stripe redirect targets).
 */
export function httpsUrlSchema(hostname?: RegExp) {
  const base = z.url({ protocol: /^https$/, ...(hostname === undefined ? {} : { hostname }) });
  return base.max(2048).refine(
    (text) => {
      const url = new URL(text);
      return url.username === "" && url.password === "" && url.hash === "";
    },
    { ...whenValid, error: "must not contain credentials or a fragment" },
  );
}

/**
 * A one-time secret shown exactly once (API key, webhook signing secret, invitation token):
 * `<prefix>` followed by 43 base64url characters (256 random bits). Only the hash or the KMS
 * ciphertext is stored; replaying the response is impossible by design.
 */
export function oneTimeSecretSchema<const Brand extends string>(prefix: string, brand: Brand) {
  return z
    .string()
    .regex(new RegExp(`^${prefix}[A-Za-z0-9_-]{${ONE_TIME_SECRET_BODY_LENGTH}}$`), {
      error: `${brand} must be ${prefix} followed by ${ONE_TIME_SECRET_BODY_LENGTH} base64url characters`,
    })
    .brand<Brand>();
}
