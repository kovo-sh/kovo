import { z } from "zod";

import { p0TriggerSchema, severitySchema, fixTierSchema } from "./enums/advisories.js";
import {
  NONTERMINAL_FIX_STATUSES,
  fixChangeKindSchema,
  ladderRungSchema,
  mergedBySchema,
  verificationResultSchema,
  type FixChangeKind,
} from "./enums/fixes.js";
import {
  approvalStatusSchema,
  approvedViaSchema,
  calibrationStatusSchema,
  calibrationWeakReasonSchema,
} from "./enums/recipes.js";
import { fixWaitSchema } from "./enums/waits.js";
import {
  accountIdSchema,
  advisoryIdSchema,
  eventIdSchema,
  findingIdSchema,
  fixIdSchema,
  githubRepoIdSchema,
  pullRequestNumberSchema,
  recipeVersionIdSchema,
  repoIdSchema,
  webhookSubscriptionIdSchema,
} from "./ids.js";
import { githubPullRequestUrlSchema, repoFullNameSchema } from "./github.js";
import { packageNameSchema, packageVersionSchema } from "./npm.js";
import { LIMITS } from "./limits.js";
import { gitShaSchema, whenValid } from "./primitives.js";
import { DURATIONS, utcDateTimeSchema } from "./time.js";
import { fixAttemptSchema } from "./workflow-ids.js";

// Outbound webhooks (SPEC "Public API": "Outbound events include P0 detection, recipe
// state/approval changes, PR opened, merge, human action needed, revert and autopilot suggestion.
// Sign with HMAC-SHA256, include event ID/timestamp … support overlapping signing keys for 24 hours
// during rotation … Receivers must deduplicate event IDs."). Payloads carry identifiers, versions
// and codes only: no source, diffs, secrets, manifests or free text.

export const WEBHOOK_EVENT_TYPES = [
  "finding.p0_detected",
  "recipe.state_changed",
  "recipe.approved",
  "fix.pr_opened",
  "fix.merged",
  "fix.human_action_needed",
  "fix.reverted",
  "autopilot.suggested",
] as const;
export const webhookEventTypeSchema = z.enum(WEBHOOK_EVENT_TYPES);
export type WebhookEventType = z.infer<typeof webhookEventTypeSchema>;

/**
 * The test event an account administrator sends to one subscription on request
 * (`POST /v1/webhooks/{id}/test`), so a receiver can check its signature verification before a
 * real event arrives. It is not a subscribable event type (subscriptions list only
 * {@link WEBHOOK_EVENT_TYPES}), concerns no repository and carries no repository data
 * (docs/decisions/notifications.md "Test events").
 */
export const WEBHOOK_TEST_EVENT_TYPE = "webhook.test";

/** Every envelope type a delivery can carry: the subscribable events plus the test event. */
export const WEBHOOK_ENVELOPE_TYPES = [...WEBHOOK_EVENT_TYPES, WEBHOOK_TEST_EVENT_TYPE] as const;
export const webhookEnvelopeTypeSchema = z.enum(WEBHOOK_ENVELOPE_TYPES);
export type WebhookEnvelopeType = z.infer<typeof webhookEnvelopeTypeSchema>;

// ---- Shared payload parts ----

/** The repository an event concerns. */
export const webhookRepositorySchema = z.strictObject({
  github_repo_id: githubRepoIdSchema,
  full_name: repoFullNameSchema,
});

/** A pull request on github.com. */
export const pullRequestRefSchema = z.strictObject({
  number: pullRequestNumberSchema,
  url: githubPullRequestUrlSchema,
});
export type PullRequestRef = z.infer<typeof pullRequestRefSchema>;

// ---- Payloads (`data`) ----

export const p0DetectedDataSchema = z
  .strictObject({
    repository: webhookRepositorySchema,
    finding_id: findingIdSchema,
    advisory_id: advisoryIdSchema,
    package: packageNameSchema,
    version: packageVersionSchema,
    severity: severitySchema,
    trigger: p0TriggerSchema,
    is_dev: z.boolean(),
    detected_at: utcDateTimeSchema,
  })
  .refine((data) => !data.is_dev || data.trigger === "malicious", {
    ...whenValid,
    error: "a dev-dependency finding is P0 only when malicious",
    path: ["trigger"],
  });

export const recipeStateChangedDataSchema = z.strictObject({
  repository: webhookRepositorySchema,
  recipe_version_id: recipeVersionIdSchema,
  version: z.int().positive(),
  calibration_status: calibrationStatusSchema,
  approval_status: approvalStatusSchema,
  weak_reasons: z.array(calibrationWeakReasonSchema).max(10),
});

export const recipeApprovedDataSchema = z
  .strictObject({
    repository: webhookRepositorySchema,
    recipe_version_id: recipeVersionIdSchema,
    version: z.int().positive(),
    approved_via: approvedViaSchema,
    approved_via_consent_id: z.uuid().exactOptional(),
    approved_at: utcDateTimeSchema,
  })
  .superRefine((value, ctx) => {
    if (
      (value.approved_via === "autopilot_policy") !==
      (value.approved_via_consent_id !== undefined)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["approved_via_consent_id"],
        message: "Autopilot-policy approval requires its consent reference",
      });
    }
  }, whenValid);

/** A reviewed removal has no target version; upgrades and rollbacks name the version they set. */
const TARGET_MATCHES_CHANGE = {
  ...whenValid,
  error: "exactly a removal has no target version",
  path: ["target_version"],
};

function targetMatchesChange(data: {
  readonly change: FixChangeKind;
  readonly target_version: string | null;
}): boolean {
  return (data.change === "removal") === (data.target_version === null);
}

export const fixPrOpenedDataSchema = z
  .strictObject({
    repository: webhookRepositorySchema,
    fix_id: fixIdSchema,
    attempt: fixAttemptSchema,
    tier: fixTierSchema,
    target_package: packageNameSchema,
    change: fixChangeKindSchema,
    /** Null for a reviewed removal of a malicious package. */
    target_version: packageVersionSchema.nullable(),
    ladder_rung: ladderRungSchema,
    pull_request: pullRequestRefSchema,
    verification: verificationResultSchema,
    /** True when policy or the change kind requires human review (never auto-merged). */
    review_only: z.boolean(),
  })
  .refine(targetMatchesChange, TARGET_MATCHES_CHANGE)
  .refine((data) => (data.ladder_rung === "M") === (data.change !== "upgrade"), {
    ...whenValid,
    error: "rollbacks and removals are exactly rung M",
    path: ["change"],
  })
  .refine((data) => data.change === "upgrade" || data.review_only, {
    ...whenValid,
    error: "rollbacks and removals always need human review",
    path: ["review_only"],
  });

export const fixMergedDataSchema = z
  .strictObject({
    repository: webhookRepositorySchema,
    fix_id: fixIdSchema,
    tier: fixTierSchema,
    target_package: packageNameSchema,
    change: fixChangeKindSchema,
    /** Null for a reviewed removal of a malicious package. */
    target_version: packageVersionSchema.nullable(),
    pull_request: pullRequestRefSchema,
    merged_sha: gitShaSchema,
    merged_by: mergedBySchema,
    merged_at: utcDateTimeSchema,
  })
  .refine(targetMatchesChange, TARGET_MATCHES_CHANGE)
  .refine((data) => data.change === "upgrade" || data.merged_by === "human", {
    ...whenValid,
    error: "Kovo never merges a rollback or removal (human review)",
    path: ["merged_by"],
  });

export const fixHumanActionNeededDataSchema = z.strictObject({
  repository: webhookRepositorySchema,
  fix_id: fixIdSchema,
  tier: fixTierSchema,
  target_package: packageNameSchema,
  status: z.enum(NONTERMINAL_FIX_STATUSES),
  wait: fixWaitSchema,
  pull_request: pullRequestRefSchema.nullable(),
});

export const fixRevertedDataSchema = z.strictObject({
  repository: webhookRepositorySchema,
  fix_id: fixIdSchema,
  target_package: packageNameSchema,
  revert_pull_request: pullRequestRefSchema,
  /** End of the seven-day package hold (a newly actionable advisory can clear it earlier). */
  hold_until: utcDateTimeSchema,
});

export const autopilotSuggestedDataSchema = z.strictObject({
  repository: webhookRepositorySchema,
  /** Unchanged-head human merges of would-merge PRs in the window (at least five). */
  qualifying_merges: z.int().min(LIMITS.shadow.suggestionMergeCount),
  /** The SPEC window: "no closes/reverts in 30 days". */
  window_days: z.literal(30),
});

/** The test event's payload: which subscription it was sent to, nothing else. */
export const webhookTestDataSchema = z.strictObject({
  subscription_id: webhookSubscriptionIdSchema,
});

// ---- Envelope ----

const envelopeBase = {
  id: eventIdSchema,
  created_at: utcDateTimeSchema,
  account_id: accountIdSchema,
};

function repoEvent<const Type extends WebhookEventType, Data extends z.ZodType>(
  type: Type,
  data: Data,
) {
  return z.strictObject({ ...envelopeBase, type: z.literal(type), repo_id: repoIdSchema, data });
}

/**
 * The event envelope `{ id, type, created_at, account_id, repo_id?, data }`, discriminated by
 * `type`. Every subscribable event is repository-scoped, so each carries `repo_id` (the
 * subscriber's repo scope is enforced against it at delivery); only the requested test event has
 * none.
 */
export const webhookEventSchema = z.discriminatedUnion("type", [
  repoEvent("finding.p0_detected", p0DetectedDataSchema),
  repoEvent("recipe.state_changed", recipeStateChangedDataSchema),
  repoEvent("recipe.approved", recipeApprovedDataSchema),
  repoEvent("fix.pr_opened", fixPrOpenedDataSchema),
  repoEvent("fix.merged", fixMergedDataSchema),
  repoEvent("fix.human_action_needed", fixHumanActionNeededDataSchema),
  repoEvent("fix.reverted", fixRevertedDataSchema),
  repoEvent("autopilot.suggested", autopilotSuggestedDataSchema),
  z.strictObject({
    ...envelopeBase,
    type: z.literal(WEBHOOK_TEST_EVENT_TYPE),
    data: webhookTestDataSchema,
  }),
]);
export type WebhookEvent = z.output<typeof webhookEventSchema>;
/** The JSON form sent on the wire (timestamps as strings). */
export type WebhookEventJson = z.input<typeof webhookEventSchema>;

// ---- Signatures ----

/** Request headers of a webhook delivery. */
export const WEBHOOK_HEADERS = {
  id: "Kovo-Webhook-Id",
  event: "Kovo-Webhook-Event",
  timestamp: "Kovo-Webhook-Timestamp",
  signature: "Kovo-Webhook-Signature",
} as const;

/** Signature scheme `v1`: lower-case hex HMAC-SHA256. */
export const WEBHOOK_SIGNATURE_SCHEME = "v1";

/** Recommended receiver tolerance for the signed timestamp (replay window). */
export const WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS = 300;

/** `Kovo-Webhook-Timestamp`: Unix seconds as a canonical decimal string. */
export const webhookTimestampSchema = z.codec(
  z.string().regex(/^(?:0|[1-9]\d{0,11})$/, { error: "must be Unix seconds" }),
  z.int().nonnegative(),
  { decode: (text) => Number(text), encode: (seconds) => String(seconds) },
);

/**
 * The exact bytes to sign: `${timestamp}.${rawBody}` (UTF-8), where `timestamp` is the
 * `Kovo-Webhook-Timestamp` header value and `rawBody` the unmodified request body.
 */
export function webhookSignedPayload(timestampSeconds: number, rawBody: string): string {
  return `${webhookTimestampSchema.encode(timestampSeconds)}.${rawBody}`;
}

/** One signature: the subscription key version that produced it and the HMAC hex digest. */
export const webhookSignatureSchema = z.strictObject({
  keyVersion: z.int().positive(),
  hmacHex: z.string().regex(/^[0-9a-f]{64}$/, { error: "must be a lower-case SHA-256 hex digest" }),
});
export type WebhookSignature = z.infer<typeof webhookSignatureSchema>;

const SIGNATURE_ENTRY = /^v1=([1-9]\d{0,8}):([0-9a-f]{64})$/;

/**
 * `Kovo-Webhook-Signature`: one `v1=<keyVersion>:<hex>` entry per active signing key, separated by
 * single spaces. During the 24-hour rotation overlap both the new and the previous key sign.
 */
export function formatWebhookSignatureHeader(signatures: readonly WebhookSignature[]): string {
  if (signatures.length === 0) throw new RangeError("at least one signature is required");
  return signatures
    .map((signature) => webhookSignatureSchema.parse(signature))
    .map((signature) => `${WEBHOOK_SIGNATURE_SCHEME}=${signature.keyVersion}:${signature.hmacHex}`)
    .join(" ");
}

/** Parses the signature header; `null` if any entry is malformed or the header is empty. */
export function parseWebhookSignatureHeader(header: string): WebhookSignature[] | null {
  const entries = header.split(" ");
  const signatures: WebhookSignature[] = [];
  for (const entry of entries) {
    const match = SIGNATURE_ENTRY.exec(entry);
    if (match === null) return null;
    signatures.push({ keyVersion: Number(match[1]), hmacHex: match[2] ?? "" });
  }
  return signatures.length === 0 ? null : signatures;
}

/** Receiver-side replay check for the signed timestamp. */
export function isWebhookTimestampFresh(
  timestampSeconds: number,
  nowSeconds: number,
  toleranceSeconds: number = WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS,
): boolean {
  return Math.abs(nowSeconds - timestampSeconds) <= toleranceSeconds;
}

/** How long the previous signing key keeps signing after a rotation. */
export const WEBHOOK_KEY_OVERLAP_MS = DURATIONS.webhookSigningKeyOverlap;
