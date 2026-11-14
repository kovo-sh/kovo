import { z } from "zod";

import { advisoryIdSchema } from "../ids.js";
import { exactVersionSchema } from "../npm.js";
import { whenValid } from "../primitives.js";

// Outreach to sites on vulnerable Next.js (plans/outreach.md; SPEC "Internal admin site",
// owner decision D-232). Qualified scanner rows are imported into Kovo-internal tables that only
// the operator admin routes reach. These are the shared vocabularies of those tables, the import
// and the write-only export back to the scanner. Contact addresses are third-party personal data:
// they never enter logs, metrics or DBOS inputs and outputs.

/**
 * Plan §7.2: `new → qualified → ready → approved → sent → replied → fixed → converted`, with the
 * terminal `skipped`, `opted_out`, `bounced` and `stale`.
 */
export const OUTREACH_STAGES = [
  "new",
  "qualified",
  "ready",
  "approved",
  "sent",
  "replied",
  "fixed",
  "converted",
  "skipped",
  "opted_out",
  "bounced",
  "stale",
] as const;
export const outreachStageSchema = z.enum(OUTREACH_STAGES);
export type OutreachStage = z.infer<typeof outreachStageSchema>;

/** Stages a row is still being worked in: a recheck that no longer finds it moves it to `fixed`. */
export const OUTREACH_OPEN_STAGES = [
  "new",
  "qualified",
  "ready",
  "approved",
  "sent",
  "replied",
] as const satisfies readonly OutreachStage[];

/** Open stages before anything was sent: the import may still skip or stale these rows. */
export const OUTREACH_PRE_SEND_STAGES = [
  "new",
  "qualified",
  "ready",
  "approved",
] as const satisfies readonly OutreachStage[];

/** Whether a stage is open (plan §7.2: `fixed` and `opted_out` can come from any open stage). */
export function isOpenOutreachStage(stage: OutreachStage): boolean {
  return (OUTREACH_OPEN_STAGES as readonly OutreachStage[]).includes(stage);
}

/** Whether a stage precedes any send. */
export function isPreSendOutreachStage(stage: OutreachStage): boolean {
  return (OUTREACH_PRE_SEND_STAGES as readonly OutreachStage[]).includes(stage);
}

/**
 * Why a row is in its stage, when the stage alone does not say (a stable code, never free text):
 * - `geo_excluded`: a sure geography signal (plan §4.3);
 * - `no_contact`: qualified, but no role contact was found (it cannot become `ready`);
 * - `customer_domain`: the domain matches a verified Kovo user's email domain (plan §4.4);
 * - `finding_stale`: the observation is older than 7 days (plan §7.2 `stale`);
 * - `absent_from_view`: two consecutive imports no longer listed the domain (plan §6.3 `fixed`);
 * - `suppressed`: the domain or address is suppressed;
 * - `operator`: an operator moved it.
 */
export const OUTREACH_STAGE_REASONS = [
  "geo_excluded",
  "no_contact",
  "customer_domain",
  "finding_stale",
  "absent_from_view",
  "suppressed",
  "operator",
] as const;
export const outreachStageReasonSchema = z.enum(OUTREACH_STAGE_REASONS);
export type OutreachStageReason = z.infer<typeof outreachStageReasonSchema>;

/** The scanner's tiers (its `tier` column; plans/site-scanner.md §7.1). */
export const OUTREACH_TIERS = ["flagship", "medium", "indie", "niche", "unranked"] as const;
export const outreachTierSchema = z.enum(OUTREACH_TIERS);
export type OutreachTier = z.infer<typeof outreachTierSchema>;

/** Plan §4.1: `exact`, or `high` with the oracle not disagreeing. */
export const OUTREACH_CONFIDENCES = ["exact", "high"] as const;
export const outreachConfidenceSchema = z.enum(OUTREACH_CONFIDENCES);
export type OutreachConfidence = z.infer<typeof outreachConfidenceSchema>;

/** Where a role contact was published (plan §5.3), in preference order. */
export const OUTREACH_CONTACT_SOURCES = [
  "security_txt",
  "home_mailto",
  "linked_page_mailto",
  "rdap",
] as const;
export const outreachContactSourceSchema = z.enum(OUTREACH_CONTACT_SOURCES);
export type OutreachContactSource = z.infer<typeof outreachContactSourceSchema>;

/** Plan §6.2: a suppressed contact keeps only its address's SHA-256. */
export const OUTREACH_CONTACT_STATES = ["active", "bounced", "complained", "suppressed"] as const;
export const outreachContactStateSchema = z.enum(OUTREACH_CONTACT_STATES);
export type OutreachContactState = z.infer<typeof outreachContactStateSchema>;

export const OUTREACH_SUPPRESSION_REASONS = ["opt_out", "complaint", "bounce", "operator"] as const;
export const outreachSuppressionReasonSchema = z.enum(OUTREACH_SUPPRESSION_REASONS);
export type OutreachSuppressionReason = z.infer<typeof outreachSuppressionReasonSchema>;

/** Append-only history of a row (plan §6.2 `outreach_events`). */
export const OUTREACH_EVENT_KINDS = [
  "imported",
  "finding_updated",
  "contact_added",
  "stage_changed",
  "assigned",
  "tagged",
  "note_added",
  "suppressed",
] as const;
export const outreachEventKindSchema = z.enum(OUTREACH_EVENT_KINDS);
export type OutreachEventKind = z.infer<typeof outreachEventKindSchema>;

/** Who caused an event: the scheduled import (`system`) or an operator. */
export const OUTREACH_ACTOR_KINDS = ["system", "operator"] as const;
export const outreachActorKindSchema = z.enum(OUTREACH_ACTOR_KINDS);

/** How an import run ended (plan §6.3; a failed import changes nothing). */
export const OUTREACH_IMPORT_OUTCOMES = [
  "imported",
  "source_prerequisite_missing",
  "source_empty",
] as const;
export const outreachImportOutcomeSchema = z.enum(OUTREACH_IMPORT_OUTCOMES);
export type OutreachImportOutcome = z.infer<typeof outreachImportOutcomeSchema>;

/** Why an export was written, and how it ended (plan §6.4). */
export const OUTREACH_EXPORT_TRIGGERS = ["import", "suppression"] as const;
export const outreachExportTriggerSchema = z.enum(OUTREACH_EXPORT_TRIGGERS);
export const OUTREACH_EXPORT_OUTCOMES = ["written", "prerequisite_missing"] as const;
export const outreachExportOutcomeSchema = z.enum(OUTREACH_EXPORT_OUTCOMES);
export type OutreachExportOutcome = z.infer<typeof outreachExportOutcomeSchema>;

// ---- Values ----

// The scanner opt-out reader's label grammar (`scanner-optouts.ts`): lower-case LDH labels.
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";

/** A registrable domain (eTLD+1, as BigQuery's `NET.REG_DOMAIN` gives it), lower case. */
export const registrableDomainSchema = z
  .string()
  .min(3)
  .max(253)
  .regex(new RegExp(`^${LABEL}(?:\\.${LABEL})+$`), {
    error: "must be a lower-case registrable domain",
  });
export type RegistrableDomain = z.infer<typeof registrableDomainSchema>;

/** A site's https origin, lower case, no path or port (the scanner only fetches these). */
export const outreachOriginSchema = z
  .string()
  .max(261)
  .regex(new RegExp(`^https://${LABEL}(?:\\.${LABEL})+$`), {
    error: "must be a lower-case https origin",
  });
export type OutreachOrigin = z.infer<typeof outreachOriginSchema>;

/** The exact npm version a finding names (at most 64 characters, as the column allows). */
export const outreachVersionSchema = exactVersionSchema.max(64);

/** A hosting evidence token (`vercel`, `netlify`, `cloudflare`, `unknown`, ...). */
export const outreachHostingTokenSchema = z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/);

/** A geography signal (`cctld:de`, `rdap_country:CA`, `impressum`). */
export const outreachGeoSignalSchema = z.string().regex(/^[a-z_]{1,24}(?::[A-Za-z]{2})?$/);

/** At most this many advisories, fixed-in versions, hosting tokens or geography signals per row. */
export const OUTREACH_LIST_MAX = 32;

export const outreachAdvisoryIdsSchema = z
  .array(advisoryIdSchema)
  .min(1)
  .max(OUTREACH_LIST_MAX)
  .refine((ids) => new Set(ids).size === ids.length, { ...whenValid, error: "unique IDs" });

/**
 * A role contact address as published (lower-cased): a plain `local@domain` with no display name,
 * comments or quoting, at most 254 characters.
 */
export const outreachContactAddressSchema = z
  .string()
  .max(254)
  .regex(
    /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/,
    {
      error: "must be a plain lower-case email address",
    },
  );

/** Where on the site the contact was found (`/.well-known/security.txt`, `/contact`): a path. */
export const outreachSourcePathSchema = z
  .string()
  .max(512)
  .regex(/^\/[\x21-\x7e]*$/, { error: "must be a URL path" });

/** An operator tag: lower-case letters, digits and hyphens. */
export const outreachTagSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);
export const OUTREACH_TAGS_MAX = 16;

// The write-only export back to the scanner (plan §6.4) uses the scanner's own opt-out object
// contract, `scannerOptOutsSchema` (`@kovo/contracts/scanner-optouts`), so the writer cannot produce
// an object the scanner's reader refuses.
