import { z } from "zod";

import { ACCOUNT_ADMIN_ROLES } from "../enums/accounts.js";
import { notificationStatusSchema, weekdaySchema } from "../enums/notifications.js";
import { resourceVersionSchema } from "../http.js";
import { repoIdSchema, userIdSchema } from "../ids.js";
import { whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { actorRefSchema, uniqueArraySchema, userRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// Email recipients and the weekly digest day (SPEC "Notifications": "Operational recipients must be
// verified Kovo users with current read access; arbitrary email addresses are not a way to export
// private repo data … If no deliverable address exists, show `no_recipient` prominently").
// Recipients are Kovo users, never raw email addresses, and email addresses are never returned.
//
// Account-wide settings (`notification_settings`) and one repository's settings
// (`repo_notification_settings`: its recipients, plus SPEC's `repos.notify_emails` switch) are
// separate versioned documents, so a caller who can read only some repositories never rewrites, or
// silently drops, another repository's recipients.

/** The most recipients one settings document names (account-wide or one repository's). */
export const MAX_RECIPIENTS = 50;

function uniqueBy<T>(values: readonly T[], key: (value: T) => string): boolean {
  return new Set(values.map(key)).size === values.length;
}

const recipientRefsSchema = z
  .array(userRefSchema)
  .max(MAX_RECIPIENTS)
  .refine((users) => uniqueBy(users, (user) => user.id), {
    ...whenValid,
    error: "recipients are unique",
  });

/** Every named user must be a verified member with read access to what they receive. */
const recipientIdsSchema = uniqueArraySchema(userIdSchema, MAX_RECIPIENTS);

const editShape = {
  /** The ETag: `If-Match` on the write must name it. */
  version: resourceVersionSchema,
  updated_at: utcDateTimeSchema.nullable(),
  updated_by: actorRefSchema.nullable(),
};

const EDIT_RECORDED_TOGETHER = {
  ...whenValid,
  error: "updated_at and updated_by go together",
  path: ["updated_by"],
};

function editRecordedTogether(settings: { updated_at: Date | null; updated_by: unknown }) {
  return (settings.updated_at === null) === (settings.updated_by === null);
}

/** `GET/PUT /v1/notifications`: settings that apply to every protected repository. */
export const notificationSettingsSchema = z
  .strictObject({
    /** Account-wide operational recipients; empty means the relevant admins (SPEC default). */
    recipients: recipientRefsSchema,
    digest_weekday: weekdaySchema,
    /** `no_recipient` when nobody has a deliverable verified address. */
    status: notificationStatusSchema,
    ...editShape,
  })
  .refine(editRecordedTogether, EDIT_RECORDED_TOGETHER);
export type NotificationSettings = z.output<typeof notificationSettingsSchema>;

export const putNotificationsBodySchema = z.strictObject({
  recipients: recipientIdsSchema,
  digest_weekday: weekdaySchema,
});

/**
 * `GET/PUT /v1/repos/{repo}/notifications`: one repository's recipients (empty: the repository uses
 * the account-wide recipients) and `emails_enabled`, SPEC's `repos.notify_emails`: whether this
 * repository's operational email is sent at all. Outbound webhooks and billing email are not
 * affected by it.
 */
export const repoNotificationSettingsSchema = z
  .strictObject({
    repo_id: repoIdSchema,
    emails_enabled: z.boolean(),
    recipients: recipientRefsSchema,
    /** `no_recipient` when nobody who may receive this repository's mail has a verified address. */
    status: notificationStatusSchema,
    ...editShape,
  })
  .refine(editRecordedTogether, EDIT_RECORDED_TOGETHER);
export type RepoNotificationSettings = z.output<typeof repoNotificationSettingsSchema>;

export const putRepoNotificationsBodySchema = z.strictObject({
  emails_enabled: z.boolean(),
  recipients: recipientIdsSchema,
});

// ---- Endpoints ----

const ROW_NOTIFICATIONS = "Authorized account administration plus recipient/repo access checks";
const ROW_REPO_RECIPIENTS =
  "Operational recipients must be verified Kovo users with current read access; arbitrary email addresses are not a way to export private repo data.";
const READERS = ["human_session", "api_key_read", "api_key_write"] as const;
const WRITERS = ["human_session", "api_key_write"] as const;
const repoParams = z.strictObject({ repo: repoIdSchema });

export const NOTIFICATION_ENDPOINTS = {
  getNotifications: defineEndpoint({
    operationId: "getNotifications",
    area: "notifications",
    method: "GET",
    path: "/v1/notifications",
    summary: "Read the account-wide recipients, the digest day and delivery status.",
    source: { kind: "spec_row", path: "/v1/notifications" },
    params: null,
    query: null,
    body: null,
    responses: { 200: notificationSettingsSchema },
    authorization: {
      spec: ROW_NOTIFICATIONS,
      actors: READERS,
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
    etag: "/version",
  }),
  putNotifications: defineEndpoint({
    operationId: "putNotifications",
    area: "notifications",
    method: "PUT",
    path: "/v1/notifications",
    summary:
      "Replace the account-wide recipients and digest day against the version in If-Match; repository recipients are untouched.",
    source: { kind: "spec_row", path: "/v1/notifications" },
    auditActions: ["notifications.updated"],
    params: null,
    query: null,
    body: putNotificationsBodySchema,
    responses: { 200: notificationSettingsSchema },
    authorization: {
      spec: ROW_NOTIFICATIONS,
      actors: WRITERS,
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      // Account-wide settings reach every repository of the account; a key delegated fewer may not.
      escalations: [
        { when: "affects_undelegated_repos", requires: { humanSession: true }, unmet: "deny" },
      ],
    },
    ifMatch: true,
    etag: "/version",
  }),
  getRepoNotifications: defineEndpoint({
    operationId: "getRepoNotifications",
    area: "notifications",
    method: "GET",
    path: "/v1/repos/{repo}/notifications",
    summary: "Read one repository's recipients and delivery status.",
    source: { kind: "spec_implied", section: "Notifications" },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: repoNotificationSettingsSchema },
    authorization: {
      spec: ROW_REPO_RECIPIENTS,
      actors: READERS,
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "path_repo" },
    },
    etag: "/version",
  }),
  putRepoNotifications: defineEndpoint({
    operationId: "putRepoNotifications",
    area: "notifications",
    method: "PUT",
    path: "/v1/repos/{repo}/notifications",
    summary:
      "Replace one repository's recipients and email switch against the version in If-Match; an empty list falls back to the account-wide recipients.",
    source: { kind: "spec_implied", section: "Notifications" },
    auditActions: ["notifications.updated"],
    params: repoParams,
    query: null,
    body: putRepoNotificationsBodySchema,
    responses: { 200: repoNotificationSettingsSchema },
    authorization: {
      spec: ROW_REPO_RECIPIENTS,
      actors: WRITERS,
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "path_repo" },
    },
    ifMatch: true,
    etag: "/version",
  }),
} as const;
