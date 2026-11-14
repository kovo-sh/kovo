import { z } from "zod";

import { advisoryIdSchema } from "../ids.js";
import { hasControlCharacter, whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { adminRequestedBySchema } from "./admin.js";
import { defineEndpoint } from "./endpoint.js";
import { operatorPrincipalSchema } from "./operator.js";
import {
  OUTREACH_LIST_MAX,
  OUTREACH_STAGES,
  OUTREACH_TAGS_MAX,
  outreachActorKindSchema,
  outreachConfidenceSchema,
  outreachContactSourceSchema,
  outreachContactStateSchema,
  outreachEventKindSchema,
  outreachStageReasonSchema,
  outreachStageSchema,
  outreachTagSchema,
  outreachTierSchema,
  type OutreachStage,
} from "./outreach.js";

// The admin site's Outreach view (SPEC "Internal admin site", "Outreach"; plans/outreach.md §7.1,
// §7.2): operator-only, audited like every admin route (`admin_audit`, closed actions in
// `ADMIN_AUDIT_ACTIONS`). Rows are scanned public sites, not tenant data. A row's role contact
// address is third-party personal data: only the `admin_ui` channel (a person behind IAP) receives
// it; the CLI's service-identity channel, which agents use, gets the contact's source and state with
// the address withheld (agent decision 2026-10-14, pending owner review #2167).

const OUTREACH_SPEC = "the admin site gains an Outreach view to manage";

/** Most rows one list page or export returns. */
export const ADMIN_OUTREACH_PAGE_MAX = 200;
export const ADMIN_OUTREACH_EXPORT_MAX = 5000;

const requestedByQuery = { requested_by: adminRequestedBySchema };
const countSchema = z.int().nonnegative();

export const ADMIN_OUTREACH_SORTS = [
  "domain",
  "tier",
  "stage",
  "observed_at",
  "last_activity",
] as const;
export const adminOutreachSortSchema = z.enum(ADMIN_OUTREACH_SORTS);
export type AdminOutreachSort = z.infer<typeof adminOutreachSortSchema>;

/**
 * The operator stage moves the routes accept (plan §7.2), besides `fixed` and `opted_out` from any
 * open stage and `converted` after a send or a fix. `approved` and `sent` belong to the human
 * approval and the send workflow (O2); `stale` and `bounced` only to the import and delivery.
 */
export const OUTREACH_OPERATOR_MOVES: Readonly<Record<OutreachStage, readonly OutreachStage[]>> = {
  new: ["qualified", "skipped"],
  qualified: ["new", "ready", "skipped"],
  ready: ["qualified", "skipped"],
  approved: ["ready"],
  sent: ["replied"],
  replied: [],
  fixed: [],
  converted: [],
  skipped: ["qualified"],
  opted_out: [],
  bounced: [],
  stale: [],
};

/** The list filters, shared by the list, the export and saved views. */
export const adminOutreachFiltersSchema = z.strictObject({
  stage: outreachStageSchema.exactOptional(),
  tier: outreachTierSchema.exactOptional(),
  confidence: outreachConfidenceSchema.exactOptional(),
  /** Rows with an active role contact, or without one. */
  contact: z.enum(["any", "none"]).exactOptional(),
  geo: z.enum(["excluded", "included"]).exactOptional(),
  customer: z.enum(["true", "false"]).exactOptional(),
  /** An operator principal, or `none` for unassigned rows. */
  assignee: z.union([z.literal("none"), operatorPrincipalSchema]).exactOptional(),
  tag: outreachTagSchema.exactOptional(),
  advisory: advisoryIdSchema.exactOptional(),
  /** Text the registrable domain contains. */
  domain: z
    .string()
    .regex(/^[a-z0-9.-]{1,253}$/, { error: "lower-case letters, digits, '.' and '-' only" })
    .exactOptional(),
  sort: adminOutreachSortSchema.default("last_activity"),
  order: z.enum(["asc", "desc"]).default("desc"),
});
export type AdminOutreachFilters = z.output<typeof adminOutreachFiltersSchema>;

export const adminOutreachContactSchema = z.strictObject({
  /** Null when withheld (the CLI channel) or once suppressed (only its hash is kept). */
  address: z.string().min(3).max(254).nullable(),
  withheld: z.boolean(),
  source: outreachContactSourceSchema,
  source_path: z.string().max(512).nullable(),
  rank: z.int().min(1).max(100),
  state: outreachContactStateSchema,
});
export type AdminOutreachContact = z.output<typeof adminOutreachContactSchema>;

const listOf = <T extends z.ZodType>(item: T) => z.array(item).max(OUTREACH_LIST_MAX);

export const adminOutreachRowSchema = z.strictObject({
  site_id: z.uuid(),
  registrable_domain: z.string().min(3).max(253),
  origin: z.string().min(9).max(261),
  tier: outreachTierSchema,
  version: z.string().min(1).max(64),
  advisory_ids: listOf(advisoryIdSchema).min(1),
  fixed_in: listOf(z.string().min(1).max(64)),
  latest_in_major: z.string().min(1).max(64).nullable(),
  confidence: outreachConfidenceSchema,
  oracle_agrees: z.boolean().nullable(),
  hosting: listOf(z.string().min(1).max(32)),
  /** The best-ranked active contact, if any. */
  contact: adminOutreachContactSchema.nullable(),
  geo_excluded: z.boolean(),
  geo_signals: listOf(z.string().min(1).max(32)),
  customer_domain: z.boolean(),
  stage: outreachStageSchema,
  stage_reason: outreachStageReasonSchema.nullable(),
  observed_at: utcDateTimeSchema,
  last_activity_at: utcDateTimeSchema,
  /** The assigned operator's principal. */
  assignee: operatorPrincipalSchema.nullable(),
  tags: z.array(outreachTagSchema).max(OUTREACH_TAGS_MAX),
});
export type AdminOutreachRow = z.output<typeof adminOutreachRowSchema>;

export const adminOutreachFindingSchema = z.strictObject({
  eval_run: z.string().min(1).max(128),
  observed_at: utcDateTimeSchema,
  imported_at: utcDateTimeSchema,
  version: z.string().min(1).max(64),
  advisory_ids: listOf(advisoryIdSchema).min(1),
  fixed_in: listOf(z.string().min(1).max(64)),
  confidence: outreachConfidenceSchema,
  oracle_agrees: z.boolean().nullable(),
  hosting: listOf(z.string().min(1).max(32)),
});

export const adminOutreachNoteSchema = z.strictObject({
  id: z.uuid(),
  operator: operatorPrincipalSchema,
  requested_by: adminRequestedBySchema,
  body: z.string().min(1).max(2000),
  created_at: utcDateTimeSchema,
});

export const adminOutreachEventSchema = z.strictObject({
  kind: outreachEventKindSchema,
  from_stage: outreachStageSchema.nullable(),
  to_stage: outreachStageSchema.nullable(),
  reason: outreachStageReasonSchema.nullable(),
  actor: outreachActorKindSchema,
  operator: operatorPrincipalSchema.nullable(),
  requested_by: adminRequestedBySchema.nullable(),
  at: utcDateTimeSchema,
});

export const ADMIN_OUTREACH_HISTORY_MAX = 200;

export const adminOutreachSiteSchema = z.strictObject({
  site: adminOutreachRowSchema,
  first_imported_at: utcDateTimeSchema,
  last_imported_at: utcDateTimeSchema,
  /** Newest first. */
  findings: z.array(adminOutreachFindingSchema).max(ADMIN_OUTREACH_HISTORY_MAX),
  /** Best-ranked first, every state. */
  contacts: z.array(adminOutreachContactSchema).max(100),
  notes: z.array(adminOutreachNoteSchema).max(ADMIN_OUTREACH_HISTORY_MAX),
  events: z.array(adminOutreachEventSchema).max(ADMIN_OUTREACH_HISTORY_MAX),
});
export type AdminOutreachSite = z.output<typeof adminOutreachSiteSchema>;

export const adminOutreachViewSchema = z.strictObject({
  id: z.uuid(),
  name: z.string().regex(/^[ -~]{1,64}$/),
  filters: adminOutreachFiltersSchema,
  created_at: utcDateTimeSchema,
  updated_at: utcDateTimeSchema,
});
export type AdminOutreachView = z.output<typeof adminOutreachViewSchema>;

/** Note text: printable characters and line breaks, at most 2000 characters. */
const noteBodySchema = z
  .string()
  .trim()
  .min(1)
  .max(2000)
  .refine((text) => !hasControlCharacter(text, true), {
    ...whenValid,
    error: "printable text and line breaks only",
  });

const siteParams = z.strictObject({ site: z.uuid() });

export const OUTREACH_ADMIN_ENDPOINTS = {
  listAdminOutreach: defineEndpoint({
    operationId: "listAdminOutreach",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/outreach",
    summary:
      "Outreach rows (scanned sites with a critical Next.js finding), filtered and sorted, a page at a time.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: adminOutreachFiltersSchema.extend({
      ...requestedByQuery,
      /** The `next` of the previous page. */
      after: z
        .string()
        .regex(/^[A-Za-z0-9_-]{1,512}$/)
        .exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_OUTREACH_PAGE_MAX).default(50),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(adminOutreachRowSchema).max(ADMIN_OUTREACH_PAGE_MAX),
        /** Rows matching the filters. */
        total: countSchema,
        next: z.string().max(512).nullable(),
      }),
    },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminOutreachSite: defineEndpoint({
    operationId: "getAdminOutreachSite",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/outreach/sites/{site}",
    summary: "One outreach row with its finding history, contacts, notes and events.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: siteParams,
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminOutreachSiteSchema },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  setAdminOutreachStage: defineEndpoint({
    operationId: "setAdminOutreachStage",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/outreach/sites/{site}/stage",
    summary:
      "Move a row to another stage, validated against its current one; opting out suppresses the domain.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: siteParams,
    query: null,
    body: z.strictObject({
      ...requestedByQuery,
      stage: z.enum(OUTREACH_STAGES),
      /** The stage the operator saw: a row that moved meanwhile is a conflict. */
      from: outreachStageSchema,
    }),
    responses: { 200: adminOutreachRowSchema },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "conflict", "validation_failed"],
  }),
  setAdminOutreachAssignee: defineEndpoint({
    operationId: "setAdminOutreachAssignee",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/outreach/sites/{site}/assignee",
    summary: "Assign a row to a live operator, or unassign it.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: siteParams,
    query: null,
    body: z.strictObject({ ...requestedByQuery, assignee: operatorPrincipalSchema.nullable() }),
    responses: { 200: adminOutreachRowSchema },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "validation_failed"],
  }),
  setAdminOutreachTags: defineEndpoint({
    operationId: "setAdminOutreachTags",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/outreach/sites/{site}/tags",
    summary: "Replace a row's tags.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: siteParams,
    query: null,
    body: z.strictObject({
      ...requestedByQuery,
      tags: z
        .array(outreachTagSchema)
        .max(OUTREACH_TAGS_MAX)
        .refine((tags) => new Set(tags).size === tags.length, {
          ...whenValid,
          error: "each tag once",
        }),
    }),
    responses: { 200: adminOutreachRowSchema },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  addAdminOutreachNote: defineEndpoint({
    operationId: "addAdminOutreachNote",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/outreach/sites/{site}/notes",
    summary:
      "Add an operator note to a row (at most 2000 characters; pasted email text is refused).",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: siteParams,
    query: null,
    body: z.strictObject({ ...requestedByQuery, body: noteBodySchema }),
    responses: { 201: adminOutreachNoteSchema },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "validation_failed"],
  }),
  listAdminOutreachViews: defineEndpoint({
    operationId: "listAdminOutreachViews",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/outreach/views",
    summary: "The calling operator's saved Outreach views, by name.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: z.strictObject({ items: z.array(adminOutreachViewSchema).max(100) }) },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
  }),
  saveAdminOutreachView: defineEndpoint({
    operationId: "saveAdminOutreachView",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/outreach/views",
    summary: "Save the calling operator's filters under a name, replacing a view of that name.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: null,
    body: z.strictObject({
      ...requestedByQuery,
      name: z
        .string()
        .trim()
        .regex(/^[ -~]{1,64}$/, { error: "1 to 64 printable characters" }),
      filters: adminOutreachFiltersSchema,
    }),
    responses: { 200: adminOutreachViewSchema },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["validation_failed"],
  }),
  deleteAdminOutreachView: defineEndpoint({
    operationId: "deleteAdminOutreachView",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/outreach/views/{view}/delete",
    summary: "Delete one of the calling operator's saved views; idempotent.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ view: z.uuid() }),
    query: null,
    body: z.strictObject(requestedByQuery),
    responses: { 200: z.strictObject({ deleted: z.boolean() }) },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
  }),
  exportAdminOutreach: defineEndpoint({
    operationId: "exportAdminOutreach",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/outreach/export",
    summary:
      "The filtered rows' metadata as CSV text, for the operator's own download (at most 5000 rows).",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: adminOutreachFiltersSchema.extend(requestedByQuery),
    body: null,
    responses: {
      200: z.strictObject({
        generated_at: utcDateTimeSchema,
        rows: countSchema,
        truncated: z.boolean(),
        csv: z.string().max(8 * 1024 * 1024),
      }),
    },
    authorization: { spec: OUTREACH_SPEC, actors: ["operator"], tenant: "none" },
  }),
} as const;
