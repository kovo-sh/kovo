import { z } from "zod";

// Time (ARCHITECTURE §3 "Time"): timestamps are UTC, `Date` in memory, ISO-8601 with `Z` on the
// wire. Durations SPEC fixes live in one typed object so no module hard-codes them. OSV feed
// timestamps keep their nanoseconds in a canonical string form. Nothing here reads the clock; `now`
// always comes from the Clock port.

export const SECOND_MS = 1_000;
export const MINUTE_MS = 60 * SECOND_MS;
export const HOUR_MS = 60 * MINUTE_MS;
export const DAY_MS = 24 * HOUR_MS;
export const WEEK_MS = 7 * DAY_MS;

/** More than millisecond precision cannot survive a round trip through a JS `Date`. */
const SUB_MILLISECOND = /\.\d{4,}Z$/;

/**
 * The wire form of a timestamp: RFC 3339 in UTC with a `Z` suffix and at most millisecond
 * precision (`2026-09-26T02:05:00Z`, `2026-09-26T02:05:00.123Z`). Offsets and local times are
 * rejected, as are impossible dates such as February 30.
 */
export const utcDateTimeStringSchema = z.iso
  .datetime({ error: "must be an ISO-8601 UTC timestamp ending in Z" })
  .refine((text) => !SUB_MILLISECOND.test(text), {
    error: "must have at most millisecond precision",
  });

/**
 * Timestamp codec: decodes the wire string to a `Date` and encodes a valid `Date` with
 * `toISOString()` (always `Z`, always milliseconds). Invalid dates fail to encode.
 */
export const utcDateTimeSchema = z.codec(utcDateTimeStringSchema, z.date(), {
  decode: (text) => new Date(text),
  encode: (date) => date.toISOString(),
});

// ---- OSV timestamps (external feed with nanosecond precision) ----
//
// OSV writes RFC 3339 UTC times with 0–9 fractional digits (`2020-02-28T16:38:09Z`,
// `…09.714130484Z`). Raw strings do not compare correctly (`.` sorts before `Z`) and a JS `Date`
// drops the sub-millisecond digits that OSV cursors and `advisories.source_modified` depend on, so
// they are rewritten to one canonical nine-digit form. This is the single parser: the OSV adapter
// port validates the feed envelope with it and `@kovo/core/advisory` the documents it normalizes,
// so the two canonical values of one record are always byte-identical.

const OSV_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/;

function isCalendarDate(year: number, month: number, day: number): boolean {
  if (month < 1 || month > 12 || day < 1) return false;
  return day <= new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/**
 * Rewrites an OSV RFC 3339 UTC timestamp to the canonical nine-digit form
 * (`2026-09-25T19:45:09Z` → `2026-09-25T19:45:09.000000000Z`), which compares correctly as a string.
 * Returns null for anything else: other offsets, local times, impossible dates, more than nine
 * fractional digits.
 */
export function normalizeOsvTimestamp(text: string): string | null {
  const match = OSV_TIMESTAMP.exec(text);
  if (match === null) return null;
  const [, year = "", month = "", day = "", hour = "", minute = "", second = "", fraction = ""] =
    match;
  if (!isCalendarDate(Number(year), Number(month), Number(day))) return null;
  if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return null;
  return `${year}-${month}-${day}T${hour}:${minute}:${second}.${fraction.padEnd(9, "0")}Z`;
}

/** A canonical OSV timestamp as {@link normalizeOsvTimestamp} writes it (`source_modified`). */
export const canonicalOsvTimestampSchema = z
  .string()
  .refine((text) => normalizeOsvTimestamp(text) === text, {
    error: "must be a canonical OSV timestamp",
  });

/**
 * The instant of a canonical OSV timestamp truncated to milliseconds (`advisories.modified_at`).
 * Throws `RangeError` for anything that is not canonical.
 */
export function osvTimestampToDate(canonical: string): Date {
  if (normalizeOsvTimestamp(canonical) !== canonical) {
    throw new RangeError(`not a canonical OSV timestamp: ${JSON.stringify(canonical)}`);
  }
  return new Date(`${canonical.slice(0, 23)}Z`);
}

/** Canonical wire form of a `Date`; throws `RangeError` for an invalid date. */
export function toUtcIso(date: Date): string {
  if (Number.isNaN(date.getTime())) throw new RangeError("invalid Date");
  return date.toISOString();
}

/** Pure conversion of explicit epoch milliseconds; never reads the clock. */
export function epochMsToDate(ms: number): Date {
  if (!Number.isSafeInteger(ms) || Math.abs(ms) > 8_640_000_000_000_000)
    throw new RangeError("epoch milliseconds must identify a valid Date");
  return new Date(ms);
}

/** `date + ms` as a new `Date`. */
export function addMs(date: Date, ms: number): Date {
  if (!Number.isSafeInteger(ms)) throw new RangeError(`duration must be a safe integer: ${ms}`);
  return new Date(date.getTime() + ms);
}

/**
 * Adds whole calendar years in UTC for retention deadlines ("One year from event", "Seven years").
 * February 29 maps to March 1 in a non-leap target year, so the deadline is never early.
 */
export function addUtcCalendarYears(date: Date, years: number): Date {
  if (!Number.isSafeInteger(years)) throw new RangeError(`years must be an integer: ${years}`);
  const result = new Date(date.getTime());
  result.setUTCFullYear(date.getUTCFullYear() + years);
  // setUTCFullYear rolls Feb 29 into Mar 1 when the target year has no Feb 29, which is the
  // intended "never early" behaviour; every other day keeps its month and day.
  return result;
}

/** Shared P0/P1 publication and merge age (owner D-210). */
export const MINIMUM_PUBLICATION_AGE_MS = DAY_MS;

/**
 * Every duration SPEC fixes, in milliseconds. Keys name the rule; the comment quotes SPEC.
 */
export const DURATIONS = {
  /** "Cache positive GitHub permission checks for at most 10 minutes for ordinary reads". */
  permissionCacheMaxAge: 10 * MINUTE_MS,
  /** P1 tier: "24 hours on changed/new versions"; npm proxy: "at least 24 hours old". */
  p1PublicationCooldown: MINIMUM_PUBLICATION_AGE_MS,
  /** P0 publication and merge age (D-210), identical to P1. */
  p0MinimumAge: MINIMUM_PUBLICATION_AGE_MS,
  /** "Encrypted patch blobs: Delete on successful PR publication or at 72 hours". */
  patchBlobMaxAge: 72 * HOUR_MS,
  /** "old verification evidence expires after 30 days"; evidence retention "30 days from collection". */
  evidenceMaxAge: 30 * DAY_MS,
  /** "Verification evidence, dependency-change metadata, inventory history: 30 days from collection". */
  inventoryHistoryRetention: 30 * DAY_MS,
  /** "Inventory ceases to be 'current' when protection is disabled and expires within 30 days". */
  disabledInventoryExpiry: 30 * DAY_MS,
  /** "Sandbox defaults: … absolute 60-minute lifetime". */
  sandboxMaxLifetime: 60 * MINUTE_MS,
  /** "Run the sandbox watchdog at least every minute". */
  sandboxWatchdogInterval: MINUTE_MS,
  /** Agent per-attempt ceiling: "25 minutes". */
  agentAttemptMaxDuration: 25 * MINUTE_MS,
  /** "A failed renewal starts a 7-day grace period from the first failure for that invoice". */
  paymentGracePeriod: 7 * DAY_MS,
  /** Billing emails "on days 0, 3, 6 (24-hour warning), and 7": the day-3 reminder offset. */
  paymentFirstReminderOffset: 3 * DAY_MS,
  /** The day-6 reminder offset. */
  paymentFinalReminderOffset: 6 * DAY_MS,
  /** "day 6 says 24 hours remain". */
  paymentFinalWarningLead: 24 * HOUR_MS,
  /** "place a seven-day package hold" after a human merges a revert. */
  revertPackageHold: 7 * DAY_MS,
  /**
   * The lease of a revert PR's slot ("Failed-verification PRs and revert PRs use separate bounded
   * slots"): a revert PR no person merged or closed within a week has its slot reconciled against
   * the PR's state ("Reconcile expired leases against workflow/PR state before reclaiming").
   */
  revertSlotLease: 7 * DAY_MS,
  /**
   * The longest an account invitation stays valid ("expiring, single-use invitations"; the `/v1`
   * contract's `INVITATION_TTL_HOURS.max`, 168 hours).
   */
  invitationMaxTtl: 168 * HOUR_MS,
  /** "Await required checks … with a 24-hour wait deadline". */
  requiredChecksDeadline: 24 * HOUR_MS,
  /** "Fingerprint-changing pushes debounce for ten minutes". */
  fingerprintDebounce: 10 * MINUTE_MS,
  /** Window for "at most three calibrations per repo per day" (LIMITS.calibration). */
  calibrationRateWindow: DAY_MS,
  /** "Alert on P0 queue age over 15 minutes". */
  p0QueueAgeAlert: 15 * MINUTE_MS,
  /** "stale advisory polls over 30 minutes". */
  staleAdvisoryPollAlert: 30 * MINUTE_MS,
  /** `pollOsv`: "Every 5 minutes". */
  osvPollInterval: 5 * MINUTE_MS,
  /** `pollKev`: "Hourly". */
  kevPollInterval: HOUR_MS,
  /** "support overlapping signing keys for 24 hours during rotation". */
  webhookSigningKeyOverlap: 24 * HOUR_MS,
  /** Shadow: "five unchanged-head human merges … with no closes/reverts in 30 days". */
  shadowSuggestionWindow: 30 * DAY_MS,
  /** "Allowance/overage limit reached: … reminder after 24 hours". */
  allowanceLimitFirstReminder: 24 * HOUR_MS,
  /** "… and weekly while blocked". */
  allowanceLimitReminderInterval: WEEK_MS,
  /** "Weekly digest". */
  weeklyDigestInterval: WEEK_MS,
  /** "Email metadata and delivered analytics outbox: 30 days". */
  emailMetadataRetention: 30 * DAY_MS,
  /** Same row: delivered analytics outbox rows. */
  analyticsOutboxRetention: 30 * DAY_MS,
  /** "retain unresolved delivery records only until reconciled or 30 days, then alert/archive". */
  unresolvedDeliveryRetention: 30 * DAY_MS,
  /** "Recipes, policy and current account configuration: … purge within 30 days of account deletion". */
  accountDeletionPurge: 30 * DAY_MS,
  /** "Uninstall … starts the 30-day repo-data cleanup". */
  uninstallRepoDataCleanup: 30 * DAY_MS,
  /** "Logs/Sentry/PostHog use 30-day retention where configurable". */
  observabilityRetention: 30 * DAY_MS,
  /** Rollout: "at least five minutes of health/synthetic checks at each stage". */
  canaryStageMinimum: 5 * MINUTE_MS,
} as const satisfies Record<string, number>;

export type DurationName = keyof typeof DURATIONS;

/** Retention periods SPEC states in calendar years (use {@link addUtcCalendarYears}). */
export const CALENDAR_RETENTION_YEARS = {
  /** "Sanitized security/permission audit: One year from event". */
  audit: 1,
  /** "Financial ledger/invoice references: Seven years". */
  financialLedger: 7,
} as const satisfies Record<string, number>;

/** Billing email schedule, in days after the first failed renewal (SPEC "Failed payments"). */
export const PAYMENT_NOTICE_DAYS = {
  paymentFailed: 0,
  firstReminder: 3,
  finalReminder: 6,
  downgrade: 7,
} as const satisfies Record<string, number>;
