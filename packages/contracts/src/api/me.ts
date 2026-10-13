import { z } from "zod";

import { accountRoleSchema, accountTypeSchema } from "../enums/accounts.js";
import { accountIdSchema, authSessionIdSchema } from "../ids.js";
import { LIMITS } from "../limits.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { countSchema, whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { githubLoginSchema } from "../github.js";
import { userRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// `/v1/me` and `/v1/me/sessions`: the signed-in person's own identity and sign-ins, for their
// personal settings (SPEC Web application: "Better Auth provides GitHub-only sign-in and
// database-backed secure sessions"; docs/decisions/auth.md "Personal identity and sign-ins"). A
// person's own data: human sessions only, never an API key. The email address itself never
// leaves the server (only whether a verified, deliverable one exists), and a sign-in is shown as a
// coarse browser and platform with its times: never its token, IP address or user agent string.

const SESSION_SPEC =
  "Better Auth provides GitHub-only sign-in and database-backed secure sessions; use CSRF protections and tenant-qualified cache keys.";
const SECTION = "Web application and onboarding UI";
const HUMAN = ["human_session"] as const;

/** One account the person is an active member of, as their settings name it. */
export const meMembershipSchema = z.strictObject({
  account_id: accountIdSchema,
  /** The linked GitHub account's login; null while the account is pending. */
  login: githubLoginSchema.nullable(),
  account_type: accountTypeSchema.nullable(),
  role: accountRoleSchema,
});

/** The signed-in person. */
export const meSchema = z
  .strictObject({
    user: userRefSchema,
    /**
     * Whether Kovo holds a GitHub-verified, deliverable email address for the person (P0 alerts and
     * digests need one). The address itself is never returned.
     */
    has_verified_email: z.boolean(),
    /** Active memberships, oldest first, at most `LIMITS.pagination.maxLimit`. */
    memberships: z.array(meMembershipSchema).max(LIMITS.pagination.maxLimit),
    /** Every active membership, including any beyond the list. */
    membership_count: countSchema,
  })
  .refine((me) => me.membership_count >= me.memberships.length, {
    ...whenValid,
    error: "the count includes every listed membership",
    path: ["membership_count"],
  });
export type Me = z.output<typeof meSchema>;

/** The browser family a sign-in's user agent names; `other` when it names none Kovo knows. */
export const SIGN_IN_BROWSERS = ["chrome", "edge", "firefox", "safari", "opera", "other"] as const;
export const signInBrowserSchema = z.enum(SIGN_IN_BROWSERS);
export type SignInBrowser = z.infer<typeof signInBrowserSchema>;

/** The operating system family a sign-in's user agent names. */
export const SIGN_IN_PLATFORMS = [
  "windows",
  "macos",
  "linux",
  "chromeos",
  "ios",
  "android",
  "other",
] as const;
export const signInPlatformSchema = z.enum(SIGN_IN_PLATFORMS);
export type SignInPlatform = z.infer<typeof signInPlatformSchema>;

/** One sign-in (a Better Auth session), as its owner sees it. */
export const signInSchema = z
  .strictObject({
    id: authSessionIdSchema,
    /** The sign-in this request was made with. */
    current: z.boolean(),
    browser: signInBrowserSchema,
    platform: signInPlatformSchema,
    created_at: utcDateTimeSchema,
    /**
     * When the sign-in was last extended; coarse: a session is extended at most once a day while
     * it is used, so this is "last active" to within a day.
     */
    last_active_at: utcDateTimeSchema,
    expires_at: utcDateTimeSchema,
  })
  .superRefine((signIn, ctx) => {
    if (signIn.last_active_at.getTime() < signIn.created_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["last_active_at"],
        message: "a sign-in is active after it was created",
      });
    }
  }, whenValid);
export type SignIn = z.output<typeof signInSchema>;

const signInParams = z.strictObject({ id: authSessionIdSchema });

export const ME_ENDPOINTS = {
  getMe: defineEndpoint({
    operationId: "getMe",
    area: "accounts",
    method: "GET",
    path: "/v1/me",
    summary:
      "The signed-in person: GitHub identity, whether a verified email exists, and memberships.",
    source: { kind: "spec_implied", section: SECTION },
    params: null,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ me: meSchema }) },
    authorization: { spec: SESSION_SPEC, actors: HUMAN, tenant: "user" },
  }),
  listSignIns: defineEndpoint({
    operationId: "listSignIns",
    area: "accounts",
    method: "GET",
    path: "/v1/me/sessions",
    summary: "The person's unexpired sign-ins, newest first, with the current one marked.",
    source: { kind: "spec_implied", section: SECTION },
    params: null,
    query: z.strictObject(paginationQueryShape),
    body: null,
    responses: { 200: pageSchema(signInSchema) },
    authorization: { spec: SESSION_SPEC, actors: HUMAN, tenant: "user" },
    paginated: true,
  }),
  revokeSignIn: defineEndpoint({
    operationId: "revokeSignIn",
    area: "accounts",
    method: "DELETE",
    path: "/v1/me/sessions/{id}",
    summary:
      "Sign one of the person's other sign-ins out at once (the current one signs out instead).",
    source: { kind: "spec_implied", section: SECTION },
    auditActions: ["sign_in.revoked"],
    params: signInParams,
    query: null,
    body: null,
    responses: {
      200: z
        .strictObject({ sign_in: signInSchema, revoked_at: utcDateTimeSchema })
        .refine((body) => !body.sign_in.current, {
          ...whenValid,
          error: "the current sign-in is signed out, not revoked",
        }),
    },
    authorization: { spec: SESSION_SPEC, actors: HUMAN, tenant: "user" },
    // `conflict`: the sign-in is the one making the request.
    problems: ["conflict"],
  }),
} as const;
