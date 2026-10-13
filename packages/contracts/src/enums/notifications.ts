import { z } from "zod";

// Notifications and delivery (SPEC "Notifications", data model `emails`, `installations`).

/** SPEC Notifications table rows, one entry per row. */
export const NOTIFICATION_EVENTS = [
  "installation_onboarding",
  "p0_detection",
  "pr_opened",
  "fix_outcome", // "Auto-merge, actionable failure, revert"
  "recipe_state", // "Recipe weak/approval needed/calibrated"
  "autopilot_suggestion",
  "merge_pause", // "Merge pause/resume"
  "weekly_digest",
  "payment_failed",
  "payment_reminder",
  "downgraded_to_free",
  "payment_recovered",
  "usage_approaching_allowance",
  "allowance_limit_reached", // "Allowance/overage limit reached"
] as const;
export const notificationEventSchema = z.enum(NOTIFICATION_EVENTS);
export type NotificationEvent = z.infer<typeof notificationEventSchema>;

/**
 * `emails.kind`: one template per distinct message. Rows that SPEC groups ("Auto-merge, actionable
 * failure, revert") get one kind per message; {@link EMAIL_KIND_EVENT} maps every kind to its row.
 */
export const EMAIL_KINDS = [
  "onboarding_update",
  "p0_detected",
  "pr_opened",
  "fix_auto_merged",
  "fix_action_needed",
  "fix_reverted",
  "recipe_weak",
  "recipe_approval_needed",
  "recipe_calibrated",
  "autopilot_suggested",
  "merge_paused",
  "merge_resumed",
  "weekly_digest",
  "payment_failed",
  "payment_reminder",
  "downgraded_to_free",
  "downgrade_capability_notice", // "affected repo admins receive capability notice"
  "payment_recovered",
  "usage_approaching_allowance",
  "allowance_limit_reached",
  "installation_removed_billing", // uninstall: "notify billing admins with cancellation/management links"
  // Plus coupons: "Fourteen days before a Kovo grant ends, the billing page and an email ask which
  // repository to keep on Free".
  "coupon_grant_ending",
] as const;
export const emailKindSchema = z.enum(EMAIL_KINDS);
export type EmailKind = z.infer<typeof emailKindSchema>;

export const EMAIL_KIND_EVENT = {
  onboarding_update: "installation_onboarding",
  p0_detected: "p0_detection",
  pr_opened: "pr_opened",
  fix_auto_merged: "fix_outcome",
  fix_action_needed: "fix_outcome",
  fix_reverted: "fix_outcome",
  recipe_weak: "recipe_state",
  recipe_approval_needed: "recipe_state",
  recipe_calibrated: "recipe_state",
  autopilot_suggested: "autopilot_suggestion",
  merge_paused: "merge_pause",
  merge_resumed: "merge_pause",
  weekly_digest: "weekly_digest",
  payment_failed: "payment_failed",
  payment_reminder: "payment_reminder",
  downgraded_to_free: "downgraded_to_free",
  downgrade_capability_notice: "downgraded_to_free",
  payment_recovered: "payment_recovered",
  usage_approaching_allowance: "usage_approaching_allowance",
  allowance_limit_reached: "allowance_limit_reached",
  // Not a Notifications-table row; SPEC "Installation lifecycle" requires the billing notice.
  installation_removed_billing: "installation_onboarding",
  // The same billing row as the downgrade it announces.
  coupon_grant_ending: "downgraded_to_free",
} as const satisfies Record<EmailKind, NotificationEvent>;

/**
 * The longest `emails.event_key` (the `emails_event_key_format` CHECK): "Persist an outbox row keyed
 * by logical event and recipient"; "Deduplicate by account/cycle/invoice/milestone as applicable".
 */
export const EMAIL_EVENT_KEY_MAX_LENGTH = 200;

/**
 * Recipient classes (SPEC "Recipients" column). Billing notices must "not reveal inaccessible repo
 * names/findings".
 */
export const RECIPIENT_CLASSES = [
  "initiating_user_and_admins",
  "repo_recipients", // "Authorized repo recipients"
  "repo_admins",
  "account_and_repo_admins",
  "billing_users", // "Billing-authorized users"
] as const;
export const recipientClassSchema = z.enum(RECIPIENT_CLASSES);
export type RecipientClass = z.infer<typeof recipientClassSchema>;

export const EMAIL_KIND_RECIPIENTS = {
  onboarding_update: "initiating_user_and_admins",
  p0_detected: "repo_recipients",
  pr_opened: "repo_recipients",
  fix_auto_merged: "repo_recipients",
  fix_action_needed: "repo_recipients",
  fix_reverted: "repo_recipients",
  recipe_weak: "repo_admins",
  recipe_approval_needed: "repo_admins",
  recipe_calibrated: "repo_admins",
  autopilot_suggested: "repo_admins",
  merge_paused: "account_and_repo_admins",
  merge_resumed: "account_and_repo_admins",
  weekly_digest: "repo_recipients",
  payment_failed: "billing_users",
  payment_reminder: "billing_users",
  downgraded_to_free: "billing_users",
  downgrade_capability_notice: "repo_admins",
  payment_recovered: "billing_users",
  usage_approaching_allowance: "billing_users",
  allowance_limit_reached: "billing_users",
  installation_removed_billing: "billing_users",
  coupon_grant_ending: "billing_users",
} as const satisfies Record<EmailKind, RecipientClass>;

/**
 * `emails.state`. `uncertain`: "An ambiguous Postmark timeout becomes `uncertain`"; `obsolete`:
 * "suppress obsolete reminders after re-reading state"; bounces/complaints are tracked and
 * `suppressed` addresses are not sent to.
 */
export const EMAIL_STATES = [
  "pending",
  "sending",
  "sent",
  "uncertain",
  "bounced",
  "complained",
  "suppressed",
  "failed",
  "obsolete",
] as const;
export const emailStateSchema = z.enum(EMAIL_STATES);
export type EmailState = z.infer<typeof emailStateSchema>;

/** `installations.notification_status` ("ok|no_recipient"). */
export const NOTIFICATION_STATUSES = ["ok", "no_recipient"] as const;
export const notificationStatusSchema = z.enum(NOTIFICATION_STATUSES);
export type NotificationStatus = z.infer<typeof notificationStatusSchema>;

/** Outbound webhook delivery attempts ("retry with bounded exponential backoff"). */
export const WEBHOOK_DELIVERY_STATES = [
  "pending",
  "in_flight",
  "delivered",
  "retry_scheduled",
  "failed",
] as const;
export const webhookDeliveryStateSchema = z.enum(WEBHOOK_DELIVERY_STATES);
export type WebhookDeliveryState = z.infer<typeof webhookDeliveryStateSchema>;

/**
 * Why one delivery was withheld instead of sent ("enforce subscriber repo scope at delivery"). A
 * withheld delivery is final: it is recorded as `failed` with this reason
 * (`webhook_deliveries.failure_reason`) and never retried, which tells it apart from a transport
 * failure (docs/decisions/ports.md "Webhook subscriptions are bound to their creator").
 * - `subscription_inactive`: the subscription was suspended or revoked after fan-out.
 * - `repo_out_of_scope`: the event's repository left the subscription's repository scope.
 * - `creator_inactive`: the creating key was revoked, or the creator (the user, or the key's
 *   creator) is no longer an active owner/admin member.
 * - `creator_no_repo_access`: the creator can no longer read the event's repository, or the key's
 *   delegation no longer contains it.
 */
export const WEBHOOK_WITHHOLD_REASONS = [
  "subscription_inactive",
  "repo_out_of_scope",
  "creator_inactive",
  "creator_no_repo_access",
] as const;
export const webhookWithholdReasonSchema = z.enum(WEBHOOK_WITHHOLD_REASONS);
export type WebhookWithholdReason = z.infer<typeof webhookWithholdReasonSchema>;

/**
 * A subscription's lifecycle: `active` delivers; `suspended` delivers nothing and is never
 * reactivated automatically (an account administrator reviews it and creates a replacement);
 * `revoked` is final.
 */
export const WEBHOOK_SUBSCRIPTION_STATES = ["active", "suspended", "revoked"] as const;
export const webhookSubscriptionStateSchema = z.enum(WEBHOOK_SUBSCRIPTION_STATES);
export type WebhookSubscriptionState = z.infer<typeof webhookSubscriptionStateSchema>;

/**
 * Why a subscription was suspended, recorded in the transaction of the revocation that caused it:
 * - `creator_key_revoked`: the creating key was revoked;
 * - `creator_membership_revoked`: the creating user (or the creating key's creator) left the
 *   account;
 * - `creator_role_revoked`: the creating user (or the creating key's creator) is no longer an
 *   owner or admin.
 */
export const WEBHOOK_SUSPENSION_REASONS = [
  "creator_key_revoked",
  "creator_membership_revoked",
  "creator_role_revoked",
] as const;
export const webhookSuspensionReasonSchema = z.enum(WEBHOOK_SUSPENSION_REASONS);
export type WebhookSuspensionReason = z.infer<typeof webhookSuspensionReasonSchema>;

/** `notification_settings.digest_weekday` (ISO weekday names). */
export const WEEKDAYS = [
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
] as const;
export const weekdaySchema = z.enum(WEEKDAYS);
export type Weekday = z.infer<typeof weekdaySchema>;
/** The digest weekday before an account chooses one (the `notification_settings` default). */
export const DEFAULT_DIGEST_WEEKDAY: Weekday = "monday";

/**
 * Email preference groups: the optional email kinds a recipient may turn off, per account, in their
 * settings or with a message's one-click unsubscribe (RFC 8058; docs/decisions/notifications.md
 * "Email preferences and one-click unsubscribe"). A group names kinds that are turned off together.
 * Kinds outside every group are required and always reach their authorized recipients: P0 alerts,
 * actions that wait on a person (`fix_action_needed`, `recipe_approval_needed`), reverts, and every
 * payment, billing and capability notice (SPEC Notifications: each goes to its recipients).
 */
export const EMAIL_PREFERENCE_GROUPS = [
  "weekly_digest",
  "fix_updates",
  "recipe_updates",
  "autopilot_suggestions",
  "merge_pauses",
  "onboarding_updates",
] as const;
export const emailPreferenceGroupSchema = z.enum(EMAIL_PREFERENCE_GROUPS);
export type EmailPreferenceGroup = z.infer<typeof emailPreferenceGroupSchema>;

/** Each email kind's preference group, or null for a required kind (never unsubscribable). */
export const EMAIL_KIND_PREFERENCE_GROUP = {
  onboarding_update: "onboarding_updates",
  p0_detected: null,
  pr_opened: "fix_updates",
  fix_auto_merged: "fix_updates",
  fix_action_needed: null,
  fix_reverted: null,
  recipe_weak: "recipe_updates",
  recipe_approval_needed: null,
  recipe_calibrated: "recipe_updates",
  autopilot_suggested: "autopilot_suggestions",
  merge_paused: "merge_pauses",
  merge_resumed: "merge_pauses",
  weekly_digest: "weekly_digest",
  payment_failed: null,
  payment_reminder: null,
  downgraded_to_free: null,
  downgrade_capability_notice: null,
  payment_recovered: null,
  usage_approaching_allowance: null,
  allowance_limit_reached: null,
  installation_removed_billing: null,
  coupon_grant_ending: null,
} as const satisfies Record<EmailKind, EmailPreferenceGroup | null>;

/** The preference group of `kind`, or null when the kind is required. */
export function emailPreferenceGroupOf(kind: EmailKind): EmailPreferenceGroup | null {
  return EMAIL_KIND_PREFERENCE_GROUP[kind];
}

/** The email kinds of one preference group, in `EMAIL_KINDS` order. */
export function emailKindsOfGroup(group: EmailPreferenceGroup): readonly EmailKind[] {
  return EMAIL_KINDS.filter((kind) => EMAIL_KIND_PREFERENCE_GROUP[kind] === group);
}

/** How an opt-out was recorded: in the person's settings, or with a message's unsubscribe link. */
export const EMAIL_OPT_OUT_SOURCES = ["settings", "one_click"] as const;
export const emailOptOutSourceSchema = z.enum(EMAIL_OPT_OUT_SOURCES);
export type EmailOptOutSource = z.infer<typeof emailOptOutSourceSchema>;

/** How settings, the unsubscribe page and email footers name each group. */
export const EMAIL_PREFERENCE_GROUP_LABELS: Readonly<
  Record<EmailPreferenceGroup, { readonly title: string; readonly description: string }>
> = {
  weekly_digest: {
    title: "Weekly digest",
    description: "The weekly summary of lower-priority findings in repositories you can read.",
  },
  fix_updates: {
    title: "Fix updates",
    description: "When Kovo opens a P0 fix pull request, and when it merges a fix on autopilot.",
  },
  recipe_updates: {
    title: "Verification recipe updates",
    description: "When a verification recipe is calibrated or found weak. Approvals still arrive.",
  },
  autopilot_suggestions: {
    title: "Autopilot suggestions",
    description: "When a repository in shadow mode has earned a suggestion to turn on autopilot.",
  },
  merge_pauses: {
    title: "Merge pauses",
    description: "When merges are paused or resumed for the account or a repository.",
  },
  onboarding_updates: {
    title: "Onboarding updates",
    description: "Progress of the account's GitHub installation and linking.",
  },
};

/**
 * A one-click unsubscribe token (docs/decisions/notifications.md "Email preferences and one-click
 * unsubscribe"): `u1.<group>.<payload>.<mac>`, where the payload is the base64url recipient user ID
 * and account ID (16 bytes each) and the MAC is the base64url HMAC-SHA256 the control plane
 * computes over the version, group and payload. The group is readable so the unsubscribe page can
 * name it before anything is verified; only the control plane verifies a token.
 */
export const UNSUBSCRIBE_TOKEN_PATTERN = new RegExp(
  `^u1\\.(${EMAIL_PREFERENCE_GROUPS.join("|")})\\.([A-Za-z0-9_-]{43})\\.([A-Za-z0-9_-]{43})$`,
);
export const unsubscribeTokenSchema = z
  .string()
  .max(160)
  .regex(UNSUBSCRIBE_TOKEN_PATTERN, { error: "must be an unsubscribe token" })
  .brand<"UnsubscribeToken">();
export type UnsubscribeToken = z.infer<typeof unsubscribeTokenSchema>;

/** The group a well-formed token names (unverified), or null for anything else. */
export function unsubscribeTokenGroup(token: string): EmailPreferenceGroup | null {
  if (token.length > 160) return null;
  const group = UNSUBSCRIBE_TOKEN_PATTERN.exec(token)?.[1];
  const parsed = emailPreferenceGroupSchema.safeParse(group);
  return parsed.success ? parsed.data : null;
}

/** The web path of a token's unsubscribe page (GET shows it; RFC 8058 POSTs unsubscribe). */
export const UNSUBSCRIBE_PATH_PREFIX = "/unsubscribe/";
