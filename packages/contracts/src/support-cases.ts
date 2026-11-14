import { z } from "zod";

import { accountIdSchema, jobIdSchema, repoIdSchema, userIdSchema } from "./ids.js";

// Support cases (plans/support-flow.md, owner D-725, D-132 a, D-135 a; SPEC
// specs/security-model-and-data-retention.md "Support case store"). Everything here is T1: enums,
// IDs, counts, booleans and timestamps that Kovo's own server set. Nothing customer-written (ticket
// text, email headers, bodies, subjects, addresses or attachment names) is ever a field of these
// schemas, so the case card the coordinator reads cannot carry it (§11.3, §11.4).

const NIL_UUID = "00000000-0000-0000-0000-000000000000";

function supportIdSchema<const Brand extends string>(brand: Brand) {
  return z
    .uuid({ error: `${brand} must be a UUID` })
    .toLowerCase()
    .refine((value) => value !== NIL_UUID, { error: `${brand} cannot be the nil UUID` })
    .brand<Brand>();
}

export const supportCaseIdSchema = supportIdSchema("SupportCaseId");
export type SupportCaseId = z.infer<typeof supportCaseIdSchema>;
export const supportMessageIdSchema = supportIdSchema("SupportMessageId");
export type SupportMessageId = z.infer<typeof supportMessageIdSchema>;
export const supportAttachmentIdSchema = supportIdSchema("SupportAttachmentId");
export type SupportAttachmentId = z.infer<typeof supportAttachmentIdSchema>;
/** A verified human's grant to read support mail through the admin site (§9.4). */
export const supportContentGrantIdSchema = supportIdSchema("SupportContentGrantId");
export type SupportContentGrantId = z.infer<typeof supportContentGrantIdSchema>;

/** The display number `K-<n>`; shown in subjects only, it never binds a message to a case (§9.1). */
export const supportCaseNumberSchema = z.int().min(1).max(Number.MAX_SAFE_INTEGER);
export type SupportCaseNumber = z.infer<typeof supportCaseNumberSchema>;

/** `[K-1234]`: the subject tag Kovo adds to outbound mail for display. */
export function supportCaseTag(caseNumber: SupportCaseNumber): string {
  return `[K-${supportCaseNumberSchema.parse(caseNumber)}]`;
}

export const SUPPORT_CHANNELS = ["email", "in_app"] as const;
export const supportChannelSchema = z.enum(SUPPORT_CHANNELS);
export type SupportChannel = z.infer<typeof supportChannelSchema>;

/**
 * The case category. Until P1's triage (§7.2) an email case is always `unclassified`: no model
 * reads unconverted email. The in-app form's enum (P1) picks one of the others.
 */
export const SUPPORT_CASE_CATEGORIES = [
  "unclassified",
  "run_failure",
  "fix_pr",
  "billing",
  "access",
  "account",
  "security_report",
  "other",
] as const;
export const supportCaseCategorySchema = z.enum(SUPPORT_CASE_CATEGORIES);
export type SupportCaseCategory = z.infer<typeof supportCaseCategorySchema>;

export const SUPPORT_CASE_STATES = ["open", "closed"] as const;
export const supportCaseStateSchema = z.enum(SUPPORT_CASE_STATES);
export type SupportCaseState = z.infer<typeof supportCaseStateSchema>;

/** Why a case closed. `unconverted_expired`: an unbound email case 14 days old (§5.2). */
export const SUPPORT_CLOSE_REASONS = ["unconverted_expired", "owner", "account_deleted"] as const;
export const supportCloseReasonSchema = z.enum(SUPPORT_CLOSE_REASONS);
export type SupportCloseReason = z.infer<typeof supportCloseReasonSchema>;

/**
 * The fixed template intake sent for one inbound message, or why it sent none. Only these two
 * templates exist for unconverted email (§5.2, §9.1); no model writes to an unauthenticated sender.
 */
export const SUPPORT_REPLY_OUTCOMES = [
  "unknown_sender",
  "known_sender",
  "none_unauthenticated",
  "none_automated",
  "none_rate_limited",
  "none_threaded",
  "none_suppressed",
  "none_send_failed",
] as const;
export const supportReplyOutcomeSchema = z.enum(SUPPORT_REPLY_OUTCOMES);
export type SupportReplyOutcome = z.infer<typeof supportReplyOutcomeSchema>;

export const SUPPORT_CARD_EVENTS = ["opened", "message_added", "closed"] as const;
export const supportCardEventSchema = z.enum(SUPPORT_CARD_EVENTS);
export type SupportCardEvent = z.infer<typeof supportCardEventSchema>;

/** The case card schema's version tag: a consumer refuses any other. */
export const SUPPORT_CASE_CARD_SCHEMA = "kovo.support-case-card/1" as const;

/** The Pub/Sub topic intake publishes cards to, and the coordinator's pull subscription (§9.2). */
export const SUPPORT_CASES_TOPIC = "kovo-support-cases" as const;
export const SUPPORT_CASES_COORDINATOR_SUBSCRIPTION = "kovo-support-cases-coordinator" as const;

const isoInstant = z.iso.datetime({ offset: false });

/**
 * The deterministic case card (§7.2 first paragraph): T1 only, validated by Zod at the publisher
 * and again by every consumer. A strict object: an unknown field is refused, so a writer cannot add
 * free text. The IDs come from the case's server-set scope (§7.1) and are null while the case has
 * no tenant binding (every unconverted email case).
 */
export const supportCaseCardSchema = z
  .strictObject({
    schema: z.literal(SUPPORT_CASE_CARD_SCHEMA),
    event: supportCardEventSchema,
    caseId: supportCaseIdSchema,
    caseNumber: supportCaseNumberSchema,
    channel: supportChannelSchema,
    category: supportCaseCategorySchema,
    state: supportCaseStateSchema,
    closeReason: supportCloseReasonSchema.nullable(),
    accountId: accountIdSchema.nullable(),
    repoId: repoIdSchema.nullable(),
    jobId: jobIdSchema.nullable(),
    /** Derived by the server from a live authorization; never by a model (§7.1). */
    consentPresent: z.boolean(),
    /** Aligned DKIM or DMARC passed on the case's first message (T1 boolean; grants nothing). */
    senderAuthenticated: z.boolean(),
    /** The latest inbound message's reply outcome; null for a card not caused by a message. */
    replyOutcome: supportReplyOutcomeSchema.nullable(),
    messageCount: z.int().min(0).max(10_000),
    occurredAt: isoInstant,
  })
  .refine((card) => card.repoId === null || card.accountId !== null, {
    error: "a repository needs its account",
  })
  .refine((card) => card.jobId === null || card.repoId !== null, {
    error: "a job needs its repository",
  })
  .refine((card) => (card.state === "closed") === (card.closeReason !== null), {
    error: "a close reason exactly when closed",
  })
  .refine((card) => !card.consentPresent || card.accountId !== null, {
    error: "consent needs a tenant binding",
  });
export type SupportCaseCard = z.infer<typeof supportCaseCardSchema>;

/**
 * Per-account admission (§7.1; agent decision pending owner review #8372). An unbound email case
 * counts against no account; its storage is bounded by the per-message limits and the mailbox's
 * own receiving caps.
 */
export const SUPPORT_ADMISSION = {
  maxOpenCasesPerAccount: 5,
  /** Enforced by the debugger (P2); stored on the case scope from P0 on. */
  maxRunningDebuggersPerAccount: 1,
  maxTextBytes: 256 * 1024,
  maxAttachmentBytes: 10 * 1024 * 1024,
  maxAttachmentsPerMessage: 10,
  maxMessageBytes: 25 * 1024 * 1024,
  maxMessagesPerCase: 200,
  /**
   * Sealed bytes all inbound mail may store per rolling 24 hours. Past it every message is still
   * stored (its case, T1 facts, the allowlisted headers and the first {@link degradedTextBytes} of
   * its text) and deleted from the mailbox, without attachments or HTML, and intake alerts. Anyone
   * can send mail, so this bounds what a flood can put into the shared database.
   */
  storedBytesPerDay: 256 * 1024 * 1024,
  degradedTextBytes: 16 * 1024,
  /** The reduced form keeps the first value of each allowlisted header, each value cut to 2 KiB, 8 KiB in all. */
  degradedHeaderValueBytes: 2 * 1024,
  degradedHeaderBytes: 8 * 1024,
  /** Past the budget plus this, a message keeps only its case and T1 facts (no text or headers). */
  reducedBytesPerDay: 32 * 1024 * 1024,
} as const;

/** The headers a message keeps once the storage budget is spent (lower-case names). */
export const SUPPORT_DEGRADED_HEADERS: readonly string[] = [
  "from",
  "to",
  "cc",
  "date",
  "subject",
  "message-id",
  "in-reply-to",
  "references",
  "reply-to",
  "authentication-results",
];

/** Retention (D-135 a, §5.2, §11.5). */
export const SUPPORT_RETENTION = {
  unconvertedCloseMs: 14 * 24 * 60 * 60 * 1000,
  shredAfterCloseMs: 90 * 24 * 60 * 60 * 1000,
  unknownSenderReplyWindowMs: 24 * 60 * 60 * 1000,
} as const;

/**
 * Hourly maintenance throughput (#8311). The close and the 90-day delete each run in batches until
 * drained, at most `maxBatchesPerRun` batches and `runBudgetMs` per run: 500 x 40 x 24 = 480,000
 * cases a day, over five times the mailbox's 86,400-message daily cap, so a sustained flood cannot
 * outrun maintenance and the store's size stays bounded by the 104-day case lifetime.
 */
export const SUPPORT_MAINTENANCE = {
  batchSize: 500,
  maxBatchesPerRun: 40,
  runBudgetMs: 120_000,
  runsPerDay: 24,
} as const;

/** Outbound rate limits for fixed templates (§5.2, §9.1). */
export const SUPPORT_REPLY_LIMITS = {
  /** Any template, per sender address, per rolling hour. */
  perSenderPerHour: 3,
  /** All support templates together, per rolling hour. */
  globalPerHour: 300,
} as const;

/**
 * Gmail's fixed receiving caps for one Workspace mailbox (§5.3), and the share of the hourly cap at
 * which intake alerts.
 */
export const SUPPORT_MAILBOX_CAPS = {
  perMinute: 60,
  perHour: 3600,
  perDay: 86_400,
  alertHourlyShare: 0.5,
} as const;

/** The sender, server and template constants of support mail (§5.3, §10 N5). */
export const SUPPORT_MAIL = {
  from: "Kovo Support <support@mail.kovo.sh>",
  replyTo: "support@kovo.sh",
  messageIdDomain: "mail.kovo.sh",
} as const;

/**
 * The fixed reply to an authenticated sender with no Kovo account (owner, 2026-10-07; §5.2). The
 * text is the owner's, verbatim, with the docs link filled by trusted code.
 */
export function unknownSenderReplyText(docsUrl: string): string {
  return (
    "We couldn't find a Kovo account for this email address. If you use Kovo with a different " +
    "address, write from that address, or sign in and use Report a problem. " +
    `Documentation: ${docsUrl}.`
  );
}

/**
 * The fixed acknowledgement to an authenticated sender with a Kovo account. Magic-link conversion
 * is P1; until its route exists this template carries no link (agent decision, PR #8311 slice P0).
 */
export function knownSenderReplyText(caseTag: string, docsUrl: string): string {
  return (
    `We got your message (${caseTag}). ` +
    "To let us look into it, sign in to Kovo and use Report a problem. " +
    `Help: ${docsUrl}.`
  );
}

/** Narrowed scope IDs that P1 consent fills (nullable until then). */
export const supportScopeIdsSchema = z.strictObject({
  accountId: accountIdSchema.nullable(),
  requesterUserId: userIdSchema.nullable(),
  repoId: repoIdSchema.nullable(),
  jobId: jobIdSchema.nullable(),
});
export type SupportScopeIds = z.infer<typeof supportScopeIdsSchema>;
