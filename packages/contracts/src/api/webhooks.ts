import { z } from "zod";

import { ACCOUNT_ADMIN_ROLES } from "../enums/accounts.js";
import {
  webhookDeliveryStateSchema,
  webhookSubscriptionStateSchema,
  webhookSuspensionReasonSchema,
  webhookWithholdReasonSchema,
} from "../enums/notifications.js";
import {
  eventIdSchema,
  repoIdSchema,
  webhookDeliveryIdSchema,
  webhookSubscriptionIdSchema,
} from "../ids.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { isPublicDnsName, whenValid } from "../primitives.js";
import { KOVO_SECRET_TOKEN_PREFIXES } from "../secret-tokens.js";
import { utcDateTimeSchema } from "../time.js";
import {
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_TEST_EVENT_TYPE,
  webhookEnvelopeTypeSchema,
  webhookEventTypeSchema,
} from "../webhooks.js";
import {
  emptyBodySchema,
  httpsUrlSchema,
  oneTimeSecretSchema,
  uniqueArraySchema,
} from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// `/v1/webhooks`: outbound webhook subscriptions (SPEC "Validate webhook destinations against SSRF
// and enforce subscriber repo scope at delivery … support overlapping signing keys for 24 hours
// during rotation"; Public API rows "Account administration plus delegated repo scope; destination
// checks" and "Same subscription authority; 24-hour signing-key overlap"). Event payloads and the
// signature format are in `src/webhooks.ts`.

/** Whether a URL's text has no query string or fragment, empty ones included (`…/hook?`). */
function hasNoQueryOrFragment(text: string): boolean {
  return !text.includes("?") && !text.includes("#");
}

/**
 * A subscriber destination as submitted. The schema rejects what can be judged syntactically,
 * without DNS: non-`https`, credentials, query strings, fragments, IP literals, single-label names,
 * private-only and special-use TLDs, and names embedding an IPv4 address (wildcard-DNS services
 * resolve those to that address). It is not SSRF protection by itself: the control plane resolves
 * the name, pins the address and rejects private, loopback and link-local addresses at
 * registration and again at every delivery (`destination_not_allowed`).
 *
 * No query string: receivers put their own credential there, and Kovo would then store a
 * credential in plaintext next to the envelope-encrypted signing secret (SPEC: "Never persist …
 * secrets, tokens or capability URLs"). A receiver authenticates Kovo by the HMAC-SHA256 signature
 * on every delivery instead (docs/decisions/contracts.md "Webhook destinations carry no query").
 */
export const webhookDestinationUrlSchema = httpsUrlSchema()
  .refine(hasNoQueryOrFragment, {
    ...whenValid,
    error: "must not have a query string: receivers verify Kovo's signature instead",
  })
  .refine((text) => isPublicDnsName(new URL(text).hostname), {
    ...whenValid,
    error: "must use a public DNS host name, not an IP address or internal name",
  });

/** A destination as responses show it: exactly as stored, scheme, host, port and path only. */
export const webhookDisplayUrlSchema = httpsUrlSchema().refine(hasNoQueryOrFragment, {
  ...whenValid,
  error: "a displayed destination has no query string",
});

/** The HMAC-SHA256 signing secret, returned once on creation and on each rotation (`kwhsec_…`). */
export const webhookSigningSecretSchema = oneTimeSecretSchema(
  KOVO_SECRET_TOKEN_PREFIXES.webhookSigningSecret,
  "WebhookSigningSecret",
);
export type WebhookSigningSecret = z.infer<typeof webhookSigningSecretSchema>;

export const MAX_WEBHOOK_REPOS = 100;

export const webhookSubscriptionSchema = z
  .strictObject({
    id: webhookSubscriptionIdSchema,
    url: webhookDisplayUrlSchema,
    events: uniqueArraySchema(webhookEventTypeSchema, WEBHOOK_EVENT_TYPES.length, 1),
    /** The subscriber's repo scope, enforced again at delivery. */
    repo_ids: uniqueArraySchema(repoIdSchema, MAX_WEBHOOK_REPOS, 1),
    key_version: z.int().positive(),
    /** End of the 24-hour overlap during which the previous key still signs. */
    previous_key_valid_until: utcDateTimeSchema.nullable(),
    /**
     * `suspended`: its creator's key, membership or role was revoked; it delivers nothing and stays
     * visible with its reason until an administrator replaces it (never reactivated automatically).
     */
    state: webhookSubscriptionStateSchema,
    suspended_at: utcDateTimeSchema.nullable(),
    suspension_reason: webhookSuspensionReasonSchema.nullable(),
    created_at: utcDateTimeSchema,
    revoked_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((webhook, ctx) => {
    if (webhook.previous_key_valid_until !== null && webhook.key_version <= 1) {
      ctx.addIssue({
        code: "custom",
        path: ["previous_key_valid_until"],
        message: "only a rotated subscription has a previous key",
      });
    }
    if ((webhook.suspended_at === null) !== (webhook.suspension_reason === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["suspension_reason"],
        message: "a suspension records its time and reason together",
      });
    }
    const state =
      webhook.revoked_at !== null
        ? "revoked"
        : webhook.suspended_at !== null
          ? "suspended"
          : "active";
    if (webhook.state !== state) {
      ctx.addIssue({
        code: "custom",
        path: ["state"],
        message: "the state follows revocation, then suspension",
      });
    }
    if (
      webhook.suspended_at !== null &&
      webhook.revoked_at !== null &&
      webhook.suspended_at.getTime() > webhook.revoked_at.getTime()
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["suspended_at"],
        message: "a revoked subscription is not suspended afterwards",
      });
    }
  }, whenValid);
export type WebhookSubscription = z.output<typeof webhookSubscriptionSchema>;

export const createWebhookBodySchema = z.strictObject({
  url: webhookDestinationUrlSchema,
  events: uniqueArraySchema(webhookEventTypeSchema, WEBHOOK_EVENT_TYPES.length, 1),
  repo_ids: uniqueArraySchema(repoIdSchema, MAX_WEBHOOK_REPOS, 1),
});

/**
 * One delivery of one event to one subscription, as its delivery log shows it
 * (`webhook_deliveries`): identifiers, states, counts, times and value-free codes only, never the
 * payload, the destination's answer or a signature (docs/decisions/notifications.md "The delivery
 * log").
 */
export const webhookDeliverySchema = z
  .strictObject({
    id: webhookDeliveryIdSchema,
    /** The event ID receivers deduplicate on (the `Kovo-Webhook-Id` header). */
    event_id: eventIdSchema,
    event_type: webhookEnvelopeTypeSchema,
    /** The event's repository; null only for a requested test event. */
    repo_id: repoIdSchema.nullable(),
    /**
     * `pending`/`in_flight`: not answered yet; `retry_scheduled`: an attempt failed and the next
     * is due at `next_attempt_at`; `delivered`: a 2xx answer; `failed`: final (a refusal, the
     * attempts spent, or withheld).
     */
    state: webhookDeliveryStateSchema,
    attempts: z.int().nonnegative(),
    last_attempt_at: utcDateTimeSchema.nullable(),
    next_attempt_at: utcDateTimeSchema.nullable(),
    /** The receiver's last HTTP status, when it answered. */
    last_status_code: z.int().min(100).max(599).nullable(),
    /** The last failure as a value-free code (`http_503`, `not_sent_timeout`, `retries_exhausted`). */
    last_error_code: z
      .string()
      .regex(/^[a-z0-9_.]{1,64}$/)
      .nullable(),
    /** Why the delivery was withheld instead of sent (final); null when it was not withheld. */
    withheld_reason: webhookWithholdReasonSchema.nullable(),
    delivered_at: utcDateTimeSchema.nullable(),
    created_at: utcDateTimeSchema,
  })
  .superRefine((delivery, ctx) => {
    if ((delivery.state === "delivered") !== (delivery.delivered_at !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["delivered_at"],
        message: "exactly a delivered delivery has a delivery time",
      });
    }
    if (delivery.withheld_reason !== null && delivery.state !== "failed") {
      ctx.addIssue({
        code: "custom",
        path: ["withheld_reason"],
        message: "a withheld delivery is failed",
      });
    }
    if ((delivery.event_type === WEBHOOK_TEST_EVENT_TYPE) !== (delivery.repo_id === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["repo_id"],
        message: "exactly the test event concerns no repository",
      });
    }
    if (delivery.state === "retry_scheduled" && delivery.next_attempt_at === null) {
      ctx.addIssue({
        code: "custom",
        path: ["next_attempt_at"],
        message: "a scheduled retry has its time",
      });
    }
  }, whenValid);
export type WebhookDelivery = z.output<typeof webhookDeliverySchema>;

const ROW_WEBHOOKS = "Account administration plus delegated repo scope; destination checks";
const ROW_ROTATE = "Same subscription authority; 24-hour signing-key overlap";
const WRITERS = ["human_session", "api_key_write"] as const;
const webhookParams = z.strictObject({ id: webhookSubscriptionIdSchema });

export const WEBHOOK_ENDPOINTS = {
  listWebhooks: defineEndpoint({
    operationId: "listWebhooks",
    area: "webhooks",
    method: "GET",
    path: "/v1/webhooks",
    summary: "List webhook subscriptions within the caller's repository scope.",
    source: { kind: "spec_row", path: "/v1/webhooks" },
    params: null,
    query: z.strictObject(paginationQueryShape),
    body: null,
    responses: { 200: pageSchema(webhookSubscriptionSchema) },
    authorization: {
      spec: ROW_WEBHOOKS,
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "listed_items" },
    },
    paginated: true,
  }),
  createWebhook: defineEndpoint({
    operationId: "createWebhook",
    area: "webhooks",
    method: "POST",
    path: "/v1/webhooks",
    summary: "Subscribe a checked destination; the signing secret is returned once.",
    source: { kind: "spec_row", path: "/v1/webhooks" },
    auditActions: ["webhook.created"],
    params: null,
    query: null,
    body: createWebhookBodySchema,
    responses: {
      201: z.strictObject({
        webhook: webhookSubscriptionSchema,
        signing_secret: webhookSigningSecretSchema,
      }),
    },
    authorization: {
      spec: ROW_WEBHOOKS,
      actors: WRITERS,
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "body_repos" },
    },
    oneTimeFields: ["/signing_secret"],
    // `conflict`: the account already holds `LIMITS.accounts.maxLiveWebhookSubscriptions`.
    problems: ["destination_not_allowed", "conflict"],
  }),
  revokeWebhook: defineEndpoint({
    operationId: "revokeWebhook",
    area: "webhooks",
    method: "DELETE",
    path: "/v1/webhooks/{id}",
    summary: "Revoke a subscription; no further deliveries are attempted.",
    source: { kind: "spec_row", path: "/v1/webhooks" },
    auditActions: ["webhook.revoked"],
    params: webhookParams,
    query: null,
    body: null,
    responses: {
      200: z
        .strictObject({ webhook: webhookSubscriptionSchema })
        .refine((body) => body.webhook.revoked_at !== null, {
          ...whenValid,
          error: "the subscription is revoked",
        }),
    },
    authorization: {
      spec: ROW_WEBHOOKS,
      actors: WRITERS,
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "resource_repos" },
    },
  }),
  rotateWebhookSecret: defineEndpoint({
    operationId: "rotateWebhookSecret",
    area: "webhooks",
    method: "POST",
    path: "/v1/webhooks/{id}/rotate",
    summary: "Rotate the signing secret; the previous key keeps signing for 24 hours.",
    source: { kind: "spec_row", path: "/v1/webhooks/{id}/rotate" },
    auditActions: ["webhook.rotated"],
    params: webhookParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      200: z
        .strictObject({
          webhook: webhookSubscriptionSchema,
          signing_secret: webhookSigningSecretSchema,
        })
        .refine((body) => body.webhook.previous_key_valid_until !== null, {
          ...whenValid,
          error: "a rotation keeps the previous key during the overlap",
        }),
    },
    authorization: {
      spec: ROW_ROTATE,
      actors: WRITERS,
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "resource_repos" },
    },
    oneTimeFields: ["/signing_secret"],
    problems: ["conflict"],
  }),
  listWebhookDeliveries: defineEndpoint({
    operationId: "listWebhookDeliveries",
    area: "webhooks",
    method: "GET",
    path: "/v1/webhooks/{id}/deliveries",
    summary: "A subscription's delivery log, newest first: states, attempts and failure codes.",
    source: { kind: "spec_implied", section: "Public API" },
    params: webhookParams,
    query: z.strictObject(paginationQueryShape),
    body: null,
    responses: { 200: pageSchema(webhookDeliverySchema) },
    authorization: {
      spec: ROW_WEBHOOKS,
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "resource_repos" },
    },
    paginated: true,
  }),
  testWebhook: defineEndpoint({
    operationId: "testWebhook",
    area: "webhooks",
    method: "POST",
    path: "/v1/webhooks/{id}/test",
    summary:
      "Send one signed `webhook.test` event to the subscription (one attempt, no repository data).",
    source: { kind: "spec_implied", section: "Public API" },
    auditActions: ["webhook.test_requested"],
    params: webhookParams,
    query: null,
    body: emptyBodySchema,
    responses: {
      202: z
        .strictObject({ delivery: webhookDeliverySchema })
        .refine((body) => body.delivery.event_type === WEBHOOK_TEST_EVENT_TYPE, {
          ...whenValid,
          error: "the delivery carries the test event",
        }),
    },
    authorization: {
      spec: ROW_WEBHOOKS,
      actors: WRITERS,
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "resource_repos" },
    },
    // `conflict`: the subscription is revoked or suspended; `rate_limited`: more than
    // `LIMITS.webhookTests.maxPerSubscriptionPerWindow` tests in the window.
    problems: ["conflict", "rate_limited"],
  }),
} as const;
