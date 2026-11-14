import { z } from "zod";
import { utcDateTimeSchema } from "../time.js";
import { githubUserIdSchema } from "../ids.js";
import { defineEndpoint } from "./endpoint.js";

export const waitlistSettingsSchema = z.strictObject({
  enabled: z.boolean(),
  test_github_user_ids: z.array(githubUserIdSchema).max(100),
});
export const waitlistCodeSchema = z.strictObject({
  id: z.uuid(),
  label: z.string().min(1).max(120),
  max_uses: z.number().int().positive().nullable(),
  uses: z.number().int().nonnegative(),
  expires_at: utcDateTimeSchema.nullable(),
  revoked_at: utcDateTimeSchema.nullable(),
  created_by: z.string(),
  created_at: utcDateTimeSchema,
  status: z.enum(["active", "expired", "exhausted", "revoked"]),
});
export const waitlistEventSchema = z.strictObject({
  id: z.uuid(),
  action: z.enum(["created", "revoked", "used", "settings_changed", "listed"]),
  code_id: z.uuid().nullable(),
  account_id: z.uuid().nullable(),
  user_id: z.uuid().nullable(),
  operator_id: z.uuid().nullable(),
  at: utcDateTimeSchema,
});

const common = {
  area: "operator",
  source: { kind: "spec_implied", section: "Accounts and permissions" },
  auditStorage: "waitlist_audit",
  authorization: {
    spec: "Admins manage codes and the\ndefault-on gate through the existing human-authenticated admin portal",
    actors: ["operator"],
    tenant: "none",
  },
} as const;

export const WAITLIST_ENDPOINTS = {
  listAdminWaitlistCodes: defineEndpoint({
    ...common,
    operationId: "listAdminWaitlistCodes",
    method: "GET",
    path: "/v1/operator/admin/waitlist-codes",
    summary: "List hash-only waitlist code metadata, gate settings and the recent audit trail.",
    params: null,
    query: z.strictObject({ after: z.uuid().exactOptional() }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(waitlistCodeSchema).max(100),
        truncated: z.boolean(),
        next_after: z.uuid().nullable(),
        settings: waitlistSettingsSchema,
        events: z.array(waitlistEventSchema).max(100),
      }),
    },
  }),
  createAdminWaitlistCode: defineEndpoint({
    ...common,
    operationId: "createAdminWaitlistCode",
    method: "POST",
    path: "/v1/operator/admin/waitlist-codes",
    summary: "Create a waitlist code and return its secret once.",
    oneTimeFields: ["/code"],
    params: null,
    query: null,
    body: z.strictObject({
      label: z.string().trim().min(1).max(120),
      max_uses: z.number().int().min(1).max(1_000_000).nullable(),
      expires_at: utcDateTimeSchema.nullable(),
    }),
    responses: {
      201: z.strictObject({
        item: waitlistCodeSchema,
        code: z.string().regex(/^KOVO(?:-[0-9A-HJKMNP-TV-Z]{4}){5}$/),
      }),
    },
    problems: ["validation_failed", "forbidden_actor"],
  }),
  revokeAdminWaitlistCode: defineEndpoint({
    ...common,
    operationId: "revokeAdminWaitlistCode",
    method: "POST",
    path: "/v1/operator/admin/waitlist-codes/{id}/revoke",
    summary: "Revoke a waitlist code by ID.",
    params: z.strictObject({ id: z.uuid() }),
    query: null,
    body: z.strictObject({}),
    responses: { 200: z.strictObject({ item: waitlistCodeSchema }) },
    problems: ["not_found", "forbidden_actor"],
  }),
  setAdminWaitlistSettings: defineEndpoint({
    ...common,
    operationId: "setAdminWaitlistSettings",
    method: "POST",
    path: "/v1/operator/admin/waitlist-settings",
    summary: "Change the default-on signup gate and Kovo test-user configuration.",
    params: null,
    query: null,
    body: waitlistSettingsSchema,
    responses: { 200: waitlistSettingsSchema },
    problems: ["forbidden_actor"],
  }),
} as const;
