import { z } from "zod";

import { planSchema } from "./enums/accounts.js";
import { downgradeCauseSchema } from "./enums/billing.js";
import { verificationResultSchema } from "./enums/fixes.js";
import { approvedViaSchema } from "./enums/recipes.js";
import { activationPolicySchema } from "./enums/repos.js";
import { accountIdSchema, analyticsEventIdSchema, userIdSchema } from "./ids.js";
import { tierSchema } from "./tier.js";
import { DAY_MS, HOUR_MS, MINUTE_MS, utcDateTimeSchema } from "./time.js";

// Product analytics allowlist (SPEC "Product analytics": "Explicit allowlisted events only … Initial
// events: signup completed, installation requested/linked, repository enabled, first finding,
// first PR, recipe calibrated/approved, autopilot authorized/activated, upgrade completed, overage
// consent changed, payment recovered and downgrade completed … Properties include plan, tier,
// outcome code, coarse duration and repo count, never names/URLs of private repos, advisory
// details, source, prompts, email addresses or raw route/query strings.")

export const ANALYTICS_EVENTS = [
  "signup_completed",
  "installation_requested",
  "installation_linked",
  "repository_enabled",
  "first_finding",
  "first_pr",
  "recipe_calibrated",
  "recipe_approved",
  "autopilot_authorized",
  "autopilot_activated",
  "upgrade_completed",
  "overage_consent_changed",
  "payment_recovered",
  "downgrade_completed",
] as const;
export const analyticsEventNameSchema = z.enum(ANALYTICS_EVENTS);
export type AnalyticsEventName = z.infer<typeof analyticsEventNameSchema>;

/** Coarse duration buckets ("coarse duration"), upper bounds exclusive. */
export const DURATION_BUCKETS = [
  "lt_1m",
  "1m_5m",
  "5m_15m",
  "15m_1h",
  "1h_6h",
  "6h_24h",
  "1d_7d",
  "gte_7d",
] as const;
export const durationBucketSchema = z.enum(DURATION_BUCKETS);
export type DurationBucket = z.infer<typeof durationBucketSchema>;

const BUCKET_UPPER_BOUNDS: readonly (readonly [number, DurationBucket])[] = [
  [MINUTE_MS, "lt_1m"],
  [5 * MINUTE_MS, "1m_5m"],
  [15 * MINUTE_MS, "5m_15m"],
  [HOUR_MS, "15m_1h"],
  [6 * HOUR_MS, "1h_6h"],
  [DAY_MS, "6h_24h"],
  [7 * DAY_MS, "1d_7d"],
];

/** Buckets a non-negative duration in milliseconds. */
export function durationBucket(ms: number): DurationBucket {
  if (!Number.isFinite(ms) || ms < 0) throw new RangeError(`invalid duration: ${ms}`);
  for (const [upperBound, bucket] of BUCKET_UPPER_BOUNDS) {
    if (ms < upperBound) return bucket;
  }
  return "gte_7d";
}

/** Repository count property ("repo count"). */
const repoCountSchema = z.int().nonnegative().max(100_000);

// Every property is optional (a capture may not know all of them) but nothing outside each event's
// allowlist is accepted.
const plan = planSchema.exactOptional();
const tier = tierSchema.exactOptional();
const duration_bucket = durationBucketSchema.exactOptional();
const repo_count = repoCountSchema.exactOptional();

/** Each event's strict property schema. */
export const ANALYTICS_EVENT_PROPERTIES = {
  signup_completed: z.strictObject({
    outcome: z.enum(["created_account", "joined_account"]).exactOptional(),
  }),
  installation_requested: z.strictObject({
    outcome: z.enum(["installed", "approval_requested"]).exactOptional(),
  }),
  installation_linked: z.strictObject({ plan, repo_count, duration_bucket }),
  repository_enabled: z.strictObject({ plan, repo_count }),
  first_finding: z.strictObject({ plan, tier, duration_bucket }),
  first_pr: z.strictObject({
    plan,
    tier,
    duration_bucket,
    outcome: verificationResultSchema.exactOptional(),
  }),
  recipe_calibrated: z.strictObject({
    plan,
    duration_bucket,
    outcome: z.enum(["calibrated", "weak"]).exactOptional(),
  }),
  recipe_approved: z.strictObject({ plan, outcome: approvedViaSchema.exactOptional() }),
  autopilot_authorized: z.strictObject({ plan, outcome: activationPolicySchema.exactOptional() }),
  autopilot_activated: z.strictObject({
    plan,
    duration_bucket,
    outcome: activationPolicySchema.exactOptional(),
  }),
  upgrade_completed: z.strictObject({ plan, repo_count }),
  overage_consent_changed: z.strictObject({
    plan,
    outcome: z.enum(["enabled", "disabled", "limit_changed"]).exactOptional(),
  }),
  payment_recovered: z.strictObject({ plan, duration_bucket }),
  downgrade_completed: z.strictObject({
    plan,
    repo_count,
    outcome: downgradeCauseSchema.exactOptional(),
  }),
} as const satisfies Record<AnalyticsEventName, z.ZodType>;

function eventVariant<const Name extends AnalyticsEventName>(name: Name) {
  return z.strictObject({
    name: z.literal(name),
    properties: ANALYTICS_EVENT_PROPERTIES[name],
  });
}

/** An allowlisted event with its allowlisted properties. */
export const analyticsEventSchema = z.discriminatedUnion("name", [
  eventVariant("signup_completed"),
  eventVariant("installation_requested"),
  eventVariant("installation_linked"),
  eventVariant("repository_enabled"),
  eventVariant("first_finding"),
  eventVariant("first_pr"),
  eventVariant("recipe_calibrated"),
  eventVariant("recipe_approved"),
  eventVariant("autopilot_authorized"),
  eventVariant("autopilot_activated"),
  eventVariant("upgrade_completed"),
  eventVariant("overage_consent_changed"),
  eventVariant("payment_recovered"),
  eventVariant("downgrade_completed"),
]);
export type AnalyticsEvent = z.infer<typeof analyticsEventSchema>;

export type SanitizeResult =
  | { readonly ok: true; readonly event: AnalyticsEvent }
  | {
      readonly ok: false;
      readonly reason: "unknown_event" | "invalid_properties";
      /** Offending property keys (never their values). */
      readonly keys: readonly string[];
    };

/**
 * Admits an event only if its name is allowlisted and its properties match that event's strict
 * schema. Anything else (unknown events, unknown or sensitive keys, wrong value types) is rejected
 * rather than stripped, and the rejection never echoes property values.
 */
export function sanitizeAnalyticsEvent(name: unknown, properties: unknown): SanitizeResult {
  const eventName = analyticsEventNameSchema.safeParse(name);
  if (!eventName.success) return { ok: false, reason: "unknown_event", keys: [] };
  const parsed = analyticsEventSchema.safeParse({ name: eventName.data, properties });
  if (parsed.success) return { ok: true, event: parsed.data };
  const keys = new Set<string>();
  for (const issue of parsed.error.issues) {
    if (issue.code === "unrecognized_keys") for (const key of issue.keys) keys.add(key);
    else if (issue.path.length > 1) keys.add(String(issue.path[1]));
  }
  return { ok: false, reason: "invalid_properties", keys: [...keys].toSorted() };
}

// Who sends what (SPEC: "Browser captures UI intent; backend events capture successful authoritative
// outcomes via a small outbox. Deduplicate by event UUID and avoid sending the same success from
// browser and server"; "use PostHog Cloud with a US project for landing and dashboard funnels";
// "anonymous landing visits are not enriched with GitHub/private repo data").

/** Which side sends an event. */
export const ANALYTICS_EMITTERS = ["server", "browser"] as const;
export type AnalyticsEmitter = (typeof ANALYTICS_EMITTERS)[number];

/**
 * Every SPEC event is an authoritative outcome, so only the server sends it (through
 * `analytics_outbox`); the browser never reports a success, which rules out double counting.
 */
export const ANALYTICS_EVENT_EMITTER = {
  signup_completed: "server",
  installation_requested: "server",
  installation_linked: "server",
  repository_enabled: "server",
  first_finding: "server",
  first_pr: "server",
  recipe_calibrated: "server",
  recipe_approved: "server",
  autopilot_authorized: "server",
  autopilot_activated: "server",
  upgrade_completed: "server",
  overage_consent_changed: "server",
  payment_recovered: "server",
  downgrade_completed: "server",
} as const satisfies Record<AnalyticsEventName, "server">;

/**
 * UI intent the browser captures for the landing and dashboard funnels: the step a person started,
 * never its outcome (the server reports those). Distinct names from every server event.
 */
export const BROWSER_ANALYTICS_EVENTS = [
  "landing_viewed",
  "pricing_viewed",
  "signup_started",
  "installation_started",
  "upgrade_started",
] as const;
export const browserAnalyticsEventNameSchema = z.enum(BROWSER_ANALYTICS_EVENTS);
export type BrowserAnalyticsEventName = z.infer<typeof browserAnalyticsEventNameSchema>;

/**
 * Browser event properties: only the plan shown or chosen. Never a URL, path, referrer, query string
 * or anything about a repository ("never names/URLs of private repos … or raw route/query
 * strings"), and landing events carry nothing at all.
 */
export const BROWSER_ANALYTICS_EVENT_PROPERTIES = {
  landing_viewed: z.strictObject({}),
  pricing_viewed: z.strictObject({}),
  signup_started: z.strictObject({}),
  installation_started: z.strictObject({ plan }),
  upgrade_started: z.strictObject({ plan }),
} as const satisfies Record<BrowserAnalyticsEventName, z.ZodType>;

function browserVariant<const Name extends BrowserAnalyticsEventName>(name: Name) {
  return z.strictObject({
    name: z.literal(name),
    properties: BROWSER_ANALYTICS_EVENT_PROPERTIES[name],
  });
}

/** An allowlisted browser intent event with its allowlisted properties. */
export const browserAnalyticsEventSchema = z.discriminatedUnion("name", [
  browserVariant("landing_viewed"),
  browserVariant("pricing_viewed"),
  browserVariant("signup_started"),
  browserVariant("installation_started"),
  browserVariant("upgrade_started"),
]);
export type BrowserAnalyticsEvent = z.infer<typeof browserAnalyticsEventSchema>;

/** Which side sends every allowlisted event, server outcomes and browser intent alike. */
export function analyticsEmitterOf(
  name: AnalyticsEventName | BrowserAnalyticsEventName,
): AnalyticsEmitter {
  return analyticsEventNameSchema.safeParse(name).success ? "server" : "browser";
}

export type SanitizeBrowserResult =
  | { readonly ok: true; readonly event: BrowserAnalyticsEvent }
  | {
      readonly ok: false;
      /** `server_event`: an outcome the browser must not send ("avoid sending the same success"). */
      readonly reason: "unknown_event" | "server_event" | "invalid_properties";
      readonly keys: readonly string[];
    };

/**
 * The browser's gate before capture: admits only allowlisted intent events with their allowlisted
 * properties, refuses server outcomes by name, and never echoes property values.
 */
export function sanitizeBrowserAnalyticsEvent(
  name: unknown,
  properties: unknown,
): SanitizeBrowserResult {
  if (analyticsEventNameSchema.safeParse(name).success) {
    return { ok: false, reason: "server_event", keys: [] };
  }
  const eventName = browserAnalyticsEventNameSchema.safeParse(name);
  if (!eventName.success) return { ok: false, reason: "unknown_event", keys: [] };
  const parsed = browserAnalyticsEventSchema.safeParse({ name: eventName.data, properties });
  if (parsed.success) return { ok: true, event: parsed.data };
  const keys = new Set<string>();
  for (const issue of parsed.error.issues) {
    if (issue.code === "unrecognized_keys") for (const key of issue.keys) keys.add(key);
    else if (issue.path.length > 1) keys.add(String(issue.path[1]));
  }
  return { ok: false, reason: "invalid_properties", keys: [...keys].toSorted() };
}

/**
 * An `analytics_outbox` row as dispatched to PostHog: "Deduplicate by event UUID"; identify users
 * by stable internal IDs and attach the internal `account_id`.
 */
export const analyticsOutboxEventSchema = z.strictObject({
  event_uuid: analyticsEventIdSchema,
  account_id: accountIdSchema.nullable(),
  user_id: userIdSchema.nullable(),
  event: analyticsEventSchema,
  at: utcDateTimeSchema,
});
export type AnalyticsOutboxEvent = z.output<typeof analyticsOutboxEventSchema>;

// Analytics consent (SPEC Product analytics: "Respect applicable consent choices; billing, audits
// and operational metrics remain separate from optional analytics"; "Identify authenticated users
// with stable internal user IDs"; docs/decisions/notifications.md "Server analytics follow the
// person's consent"). Product analytics is opt-in: a person is identified in PostHog, by the
// browser or by the server's outbox, only after granting it for the current wording.

/**
 * The version of the analytics choice people are shown (the consent banner's wording and what it
 * says is collected). Bump it when that changes: earlier grants then no longer count, and the
 * browser asks again (its stored choice is keyed by the version).
 */
export const ANALYTICS_CONSENT_VERSION = 1;

/** A recorded choice. */
export const ANALYTICS_CONSENT_CHOICES = ["granted", "denied"] as const;
export const analyticsConsentChoiceSchema = z.enum(ANALYTICS_CONSENT_CHOICES);
export type AnalyticsConsentChoice = z.infer<typeof analyticsConsentChoiceSchema>;

/** What applies now: a recorded choice, or `unset` when there is none that still counts. */
export const ANALYTICS_CONSENT_STATES = [...ANALYTICS_CONSENT_CHOICES, "unset"] as const;
export const analyticsConsentStateSchema = z.enum(ANALYTICS_CONSENT_STATES);
export type AnalyticsConsentState = z.infer<typeof analyticsConsentStateSchema>;

export const analyticsConsentVersionSchema = z.int().positive().max(1_000);

/** A person's recorded choice and the version of the wording it answered. */
export interface AnalyticsConsent {
  readonly choice: AnalyticsConsentChoice;
  readonly version: number;
}

/**
 * The choice that applies now. A grant counts only for the current version (the wording the person
 * agreed to must be what is shown today); a refusal of any version stands until the person grants
 * again. No record is `unset`.
 */
export function currentAnalyticsConsent(consent: AnalyticsConsent | null): AnalyticsConsentState {
  if (consent === null) return "unset";
  if (consent.choice === "denied") return "denied";
  return consent.version === ANALYTICS_CONSENT_VERSION ? "granted" : "unset";
}

/**
 * Whether analytics may identify the person (their internal user ID as the PostHog distinct ID and
 * a person profile). Only a current grant does: opt-in means `unset` is not a grant, and a browser
 * privacy signal is recorded as a refusal.
 */
export function analyticsConsentIdentifies(consent: AnalyticsConsent | null): boolean {
  return currentAnalyticsConsent(consent) === "granted";
}
