import { z } from "zod";

import { accountIdSchema } from "../ids.js";
import { emailStateSchema } from "../enums/notifications.js";
import { utcDateTimeSchema } from "../time.js";
import { defineEndpoint } from "./endpoint.js";
import { waitlistCodeSchema } from "./waitlist.js";

// The bounded production-verification operator channel (plans/kovo-tests-prod-verification.md,
// owner D-351 option E; SPEC "Accounts and permissions"). A keyless service account presents a
// Google ID token and resolves to an operator with `channel: "prod_verification"`. That channel is
// refused on every other operator route: the API admits it only on the paths below and only for
// the operations below. Its authority covers only Kovo's own synthetic verification user and the
// one-use, short-lived `prodverify-` codes and accounts that user created; anything else answers
// `not_found`.

/** The label prefix every verification waitlist code carries. */
export const PROD_VERIFICATION_CODE_LABEL_PREFIX = "prodverify-";
/** The longest a verification waitlist code may live. */
export const PROD_VERIFICATION_CODE_MAX_TTL_MS = 60 * 60_000;
/** Live (unrevoked, unexpired, unused) verification codes at once; the next create refuses. */
export const PROD_VERIFICATION_LIVE_CODE_LIMIT = 10;
/** Most verification codes one list returns, newest first. */
export const PROD_VERIFICATION_CODE_LIST_MAX = 50;
/** Most notifications one account read returns, newest first. */
export const PROD_VERIFICATION_NOTIFICATION_MAX = 20;

/**
 * The `X-Request-Id` every channel request carries: the run's ULID request ID, optionally with a
 * step suffix, so every audit row it writes correlates with the workflow run.
 */
export const PROD_VERIFICATION_REQUEST_ID_PATTERN =
  /^prodverify-[0-9A-HJKMNP-TV-Z]{26}(?:[._:-][A-Za-z0-9._:-]{1,64})?$/;

/** A verification label: the prefix, then the run's request ID and a short step name. */
export const prodVerificationLabelSchema = z
  .string()
  .regex(/^prodverify-[A-Za-z0-9._:-]{1,100}$/)
  .max(120);

const common = {
  area: "operator",
  source: { kind: "spec_implied", section: "Accounts and permissions" },
  auditStorage: "admin_audit",
  authorization: {
    spec: "`prod_verification` operator channel (option E). That channel may create and revoke only its own",
    actors: ["operator"],
    tenant: "none",
  },
} as const;

const PREFIX = "/v1/operator/prod-verification";

export const prodVerificationWaitlistGateSchema = z.strictObject({
  enabled: z.boolean(),
  /** Whether any allowlisted verification user is on the waitlist bypass list. */
  verification_user_bypassed: z.boolean(),
});

export const prodVerificationAccountStatusBodySchema = z.strictObject({
  deactivate: z.boolean(),
  /** Reactivation only: whether to email the owners; deactivation always emails. */
  send_email: z.boolean(),
  reason: prodVerificationLabelSchema,
});

export const prodVerificationNotificationSchema = z.strictObject({
  id: z.uuid(),
  kind: z.enum(["account_deactivated", "account_reactivated"]),
  state: emailStateSchema,
  created_at: utcDateTimeSchema,
  sent_at: utcDateTimeSchema.nullable(),
  delivered_at: utcDateTimeSchema.nullable(),
  provider_message_id: z.string().min(1).max(200).nullable(),
  failure_code: z
    .string()
    .regex(/^[a-z0-9_.]{1,64}$/)
    .nullable(),
});

export const PROD_VERIFICATION_ENDPOINTS = {
  getProdVerificationWaitlistGate: defineEndpoint({
    ...common,
    operationId: "getProdVerificationWaitlistGate",
    method: "GET",
    path: `${PREFIX}/waitlist-gate`,
    summary: "Whether the waitlist gate is on and whether the verification user bypasses it.",
    params: null,
    query: null,
    body: null,
    responses: { 200: prodVerificationWaitlistGateSchema },
    problems: ["validation_failed", "service_unavailable"],
  }),
  listProdVerificationWaitlistCodes: defineEndpoint({
    ...common,
    operationId: "listProdVerificationWaitlistCodes",
    method: "GET",
    path: `${PREFIX}/waitlist-codes`,
    summary: "List the verification channel's own waitlist codes, newest first.",
    params: null,
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(waitlistCodeSchema).max(PROD_VERIFICATION_CODE_LIST_MAX),
        truncated: z.boolean(),
      }),
    },
    problems: ["validation_failed", "service_unavailable"],
  }),
  createProdVerificationWaitlistCode: defineEndpoint({
    ...common,
    operationId: "createProdVerificationWaitlistCode",
    method: "POST",
    path: `${PREFIX}/waitlist-codes`,
    summary: "Create a one-use, short-lived prodverify- waitlist code and return its secret once.",
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
    problems: ["validation_failed", "conflict", "service_unavailable"],
  }),
  revokeProdVerificationWaitlistCode: defineEndpoint({
    ...common,
    operationId: "revokeProdVerificationWaitlistCode",
    method: "POST",
    path: `${PREFIX}/waitlist-codes/{id}/revoke`,
    summary: "Revoke one of the verification channel's own waitlist codes.",
    params: z.strictObject({ id: z.uuid() }),
    query: null,
    body: z.strictObject({}),
    responses: { 200: z.strictObject({ item: waitlistCodeSchema }) },
    problems: ["not_found", "validation_failed", "service_unavailable"],
  }),
  setProdVerificationAccountStatus: defineEndpoint({
    ...common,
    operationId: "setProdVerificationAccountStatus",
    method: "POST",
    path: `${PREFIX}/accounts/{account}/status`,
    summary: "Deactivate or reactivate an account the verification user alone created and holds.",
    params: z.strictObject({ account: accountIdSchema }),
    query: null,
    body: prodVerificationAccountStatusBodySchema,
    responses: {
      200: z.strictObject({
        account_id: accountIdSchema,
        deactivated_at: utcDateTimeSchema.nullable(),
      }),
    },
    problems: [
      "account_already_deactivated",
      "account_not_deactivated",
      "not_found",
      "validation_failed",
      "service_unavailable",
    ],
  }),
  listProdVerificationAccountNotifications: defineEndpoint({
    ...common,
    operationId: "listProdVerificationAccountNotifications",
    method: "GET",
    path: `${PREFIX}/accounts/{account}/notifications`,
    summary: "Delivery states of a verification account's deactivation and reactivation emails.",
    params: z.strictObject({ account: accountIdSchema }),
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(prodVerificationNotificationSchema).max(PROD_VERIFICATION_NOTIFICATION_MAX),
      }),
    },
    problems: ["not_found", "validation_failed", "service_unavailable"],
  }),
} as const;

/** The only operations the `prod_verification` channel may call; every other route refuses it. */
export const PROD_VERIFICATION_OPERATIONS: ReadonlySet<string> = new Set(
  Object.values(PROD_VERIFICATION_ENDPOINTS).map((endpoint) => endpoint.operationId),
);

/** The API paths (under `/v1`) the `prod_verification` channel may reach. */
export const PROD_VERIFICATION_PATHS: readonly RegExp[] = [/^\/v1\/operator\/prod-verification\//];

/** Whether the `prod_verification` channel may call an API path. */
export function prodVerificationMayCall(pathname: string): boolean {
  return PROD_VERIFICATION_PATHS.some((pattern) => pattern.test(pathname));
}
