import { z } from "zod";

import {
  ANALYTICS_CONSENT_VERSION,
  analyticsConsentChoiceSchema,
  analyticsConsentStateSchema,
  analyticsConsentVersionSchema,
} from "../analytics.js";
import { utcDateTimeSchema } from "../time.js";
import { defineEndpoint } from "./endpoint.js";

// `/v1/me/analytics-consent`: the signed-in person's product analytics choice, recorded on the
// server so the backend's analytics outbox follows it too (SPEC Product analytics: "Respect
// applicable consent choices"; docs/decisions/notifications.md "Server analytics follow the
// person's consent"). The web app sends the choice made in its banner or footer, and a refusal
// whenever the browser sends a privacy signal. A person's own setting: never an API key's.

const CONSENT_SPEC =
  "Respect applicable consent choices; billing, audits and operational metrics remain separate from optional analytics.";
const SECTION = "Operations, analytics, and deployment";
const HUMAN = ["human_session"] as const;

/** The person's analytics choice as it applies now. */
export const analyticsConsentViewSchema = z.strictObject({
  /**
   * `granted` only for a grant of the current version; `denied` for a refusal of any version;
   * `unset` without a choice that still counts (the person is asked again).
   */
  state: analyticsConsentStateSchema,
  /** The version of the recorded choice, or null without one. */
  version: analyticsConsentVersionSchema.nullable(),
  /** When the recorded choice was made, or null without one. */
  decided_at: utcDateTimeSchema.nullable(),
});
export type AnalyticsConsentView = z.infer<typeof analyticsConsentViewSchema>;

const consentResponseSchema = z.strictObject({ analytics_consent: analyticsConsentViewSchema });

export const ANALYTICS_CONSENT_ENDPOINTS = {
  getAnalyticsConsent: defineEndpoint({
    operationId: "getAnalyticsConsent",
    area: "accounts",
    method: "GET",
    path: "/v1/me/analytics-consent",
    summary: "The signed-in person's product analytics choice.",
    source: { kind: "spec_implied", section: SECTION },
    params: null,
    query: null,
    body: null,
    responses: { 200: consentResponseSchema },
    authorization: { spec: CONSENT_SPEC, actors: HUMAN, tenant: "user" },
  }),
  putAnalyticsConsent: defineEndpoint({
    operationId: "putAnalyticsConsent",
    area: "accounts",
    method: "PUT",
    path: "/v1/me/analytics-consent",
    summary:
      "Record the signed-in person's product analytics choice for the wording they were shown; server analytics identify them only while they grant it.",
    source: { kind: "spec_implied", section: SECTION },
    auditActions: ["analytics_consent.changed"],
    params: null,
    query: null,
    body: z.strictObject({
      choice: analyticsConsentChoiceSchema,
      /** The version of the wording the person answered: only the current one is accepted. */
      version: z.literal(ANALYTICS_CONSENT_VERSION),
    }),
    responses: { 200: consentResponseSchema },
    authorization: { spec: CONSENT_SPEC, actors: HUMAN, tenant: "user" },
  }),
} as const;
