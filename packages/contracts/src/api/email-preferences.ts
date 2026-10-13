import { z } from "zod";

import { EMAIL_PREFERENCE_GROUPS, emailPreferenceGroupSchema } from "../enums/notifications.js";
import { githubLoginSchema } from "../github.js";
import { accountIdSchema } from "../ids.js";
import { LIMITS } from "../limits.js";
import { countSchema, whenValid } from "../primitives.js";
import { defineEndpoint } from "./endpoint.js";

// The signed-in person's own email preferences (docs/decisions/notifications.md "Email preferences
// and one-click unsubscribe"): per account they belong to, whether each optional email group
// reaches them. Required kinds (P0 alerts, actions waiting on a person, reverts, every payment,
// billing and capability notice) are never listed and cannot be turned off (SPEC Notifications:
// each goes to its authorized recipients). A person's own setting: human sessions only, never an
// API key, and the account is always one the caller is a current member of.

const PREFERENCES_SPEC =
  "Operational recipients must be verified Kovo users with current read access; arbitrary email addresses are not a way to export private repo data.";
const SECTION = "Notifications";
const HUMAN = ["human_session"] as const;

/** One optional group and whether it reaches the person. */
export const emailPreferenceSchema = z.strictObject({
  group: emailPreferenceGroupSchema,
  subscribed: z.boolean(),
});
export type EmailPreference = z.output<typeof emailPreferenceSchema>;

/** Every optional group once, in `EMAIL_PREFERENCE_GROUPS` order. */
const groupsSchema = z
  .array(emailPreferenceSchema)
  .length(EMAIL_PREFERENCE_GROUPS.length)
  .refine(
    (groups) => groups.every((entry, index) => entry.group === EMAIL_PREFERENCE_GROUPS[index]),
    {
      ...whenValid,
      error: "every optional group once, in order",
    },
  );

/** One account's preferences. */
export const accountEmailPreferencesSchema = z.strictObject({
  account_id: accountIdSchema,
  /** The linked GitHub account's login; null while the account is pending. */
  login: githubLoginSchema.nullable(),
  groups: groupsSchema,
});
export type AccountEmailPreferences = z.output<typeof accountEmailPreferencesSchema>;

export const EMAIL_PREFERENCE_ENDPOINTS = {
  getEmailPreferences: defineEndpoint({
    operationId: "getEmailPreferences",
    area: "notifications",
    method: "GET",
    path: "/v1/me/email-preferences",
    summary:
      "The signed-in person's optional email groups, per account they belong to (oldest membership first).",
    source: { kind: "spec_implied", section: SECTION },
    params: null,
    query: null,
    body: null,
    responses: {
      200: z
        .strictObject({
          accounts: z.array(accountEmailPreferencesSchema).max(LIMITS.pagination.maxLimit),
          /** Every active membership, including any beyond the list. */
          account_count: countSchema,
        })
        .refine((body) => body.account_count >= body.accounts.length, {
          ...whenValid,
          error: "the count includes every listed account",
          path: ["account_count"],
        }),
    },
    authorization: { spec: PREFERENCES_SPEC, actors: HUMAN, tenant: "user" },
  }),
  putEmailPreference: defineEndpoint({
    operationId: "putEmailPreference",
    area: "notifications",
    method: "PUT",
    path: "/v1/accounts/{account}/email-preferences/{group}",
    summary:
      "Turn one optional email group off or on for the signed-in person in one account; repeating the current state changes nothing.",
    source: { kind: "spec_implied", section: SECTION },
    auditActions: ["email_preferences.changed"],
    params: z.strictObject({ account: accountIdSchema, group: emailPreferenceGroupSchema }),
    query: null,
    body: z.strictObject({ subscribed: z.boolean() }),
    responses: { 200: z.strictObject({ email_preferences: accountEmailPreferencesSchema }) },
    // Any member: a person's own preferences need no account role.
    authorization: { spec: PREFERENCES_SPEC, actors: HUMAN, tenant: "path_account" },
  }),
} as const;
