import { z } from "zod";

import {
  supportAttachmentIdSchema,
  supportCaseCategorySchema,
  supportCaseIdSchema,
  supportCaseNumberSchema,
  supportCaseStateSchema,
  supportCloseReasonSchema,
  supportContentGrantIdSchema,
  supportMessageIdSchema,
  supportReplyOutcomeSchema,
  SUPPORT_ADMISSION,
} from "../support-cases.js";
import { utcDateTimeSchema } from "../time.js";
import { adminRequestedBySchema } from "./admin.js";
import { defineEndpoint } from "./endpoint.js";

// The admin site's support mail routes (plans/support-flow.md §9.4; owner D-725, D-217; SPEC
// specs/security-model-and-data-retention.md "Support case store"). Two kinds of route, kept apart:
//
// - Metadata projections (the case list, one case and its message list): T1 only, so any operator
//   may read them, the `kovo-admin` CLI included. They carry IDs, enums, booleans, counts and times;
//   never a subject, address, header, body or attachment name.
// - The human-only content route (a support content grant, one message's text and headers, one
//   attachment's bytes): only a verified human principal behind the admin site may call it. The API
//   refuses every other caller: the `kovo-admin` CLI and every operator or agent service account,
//   whatever their classification, and an admin-site user whose `operators` row the owner has not
//   classified human. A message's HTML is never returned: email is shown as plain text only.
//
// Only email cases are reachable here: they have no tenant binding (support_cases_email_unbound).
// In-app cases and run records (the debugger's output) need the case's D-134 consent and a staff
// grant (plans/support-flow.md §9.4), which these routes never give.

/** Most cases one metadata page returns. */
export const ADMIN_SUPPORT_PAGE_MAX = 100;
/** The longest a support content grant lasts (as D9 and staff grants: two hours). */
export const SUPPORT_CONTENT_GRANT_MAX_SECONDS = 7200;
/** Most headers one message shows (the mailbox adapter's own bound). */
export const SUPPORT_CONTENT_MAX_HEADERS = 300;

const countSchema = z.int().min(0).max(SUPPORT_ADMISSION.maxMessagesPerCase);

/** One email case's metadata (T1). */
export const adminSupportCaseSchema = z.strictObject({
  case_id: supportCaseIdSchema,
  case_number: supportCaseNumberSchema,
  state: supportCaseStateSchema,
  category: supportCaseCategorySchema,
  close_reason: supportCloseReasonSchema.nullable(),
  sender_authenticated: z.boolean(),
  sender_known: z.boolean(),
  message_count: countSchema,
  last_reply_outcome: supportReplyOutcomeSchema.nullable(),
  created_at: utcDateTimeSchema,
  updated_at: utcDateTimeSchema,
  closed_at: utcDateTimeSchema.nullable(),
});
export type AdminSupportCase = z.infer<typeof adminSupportCaseSchema>;

export const adminSupportCasesSchema = z.strictObject({
  items: z.array(adminSupportCaseSchema).max(ADMIN_SUPPORT_PAGE_MAX),
  /** Pass as `before` for the next (older) page; null on the last page. */
  next_before: supportCaseNumberSchema.nullable(),
});
export type AdminSupportCases = z.infer<typeof adminSupportCasesSchema>;

const authSchema = z.strictObject({
  dkim_pass: z.boolean(),
  dkim_aligned: z.boolean(),
  spf_pass: z.boolean(),
  dmarc_pass: z.boolean(),
  arc_pass: z.boolean(),
});

/** One message's metadata (T1): what is stored, never what it says. */
export const adminSupportMessageSummarySchema = z.strictObject({
  message_id: supportMessageIdSchema,
  direction: z.enum(["inbound", "outbound"]),
  created_at: utcDateTimeSchema,
  auth: authSchema,
  automated: z.boolean(),
  truncated: z.boolean(),
  degraded: z.boolean(),
  size_bytes: z.int().min(0),
  attachment_count: z.int().min(0),
  dropped_attachments: z.int().min(0),
  outbound_template: z.enum(["unknown_sender", "known_sender"]).nullable(),
  reply_outcome: supportReplyOutcomeSchema.nullable(),
  has_text: z.boolean(),
  has_html: z.boolean(),
});
export type AdminSupportMessageSummary = z.infer<typeof adminSupportMessageSummarySchema>;

export const adminSupportCaseDetailSchema = z.strictObject({
  case: adminSupportCaseSchema,
  messages: z.array(adminSupportMessageSummarySchema).max(SUPPORT_ADMISSION.maxMessagesPerCase),
});
export type AdminSupportCaseDetail = z.infer<typeof adminSupportCaseDetailSchema>;

export const supportContentGrantRequestSchema = z.strictObject({
  justification: z.string().trim().min(20).max(1000),
  duration_seconds: z.int().min(60).max(SUPPORT_CONTENT_GRANT_MAX_SECONDS),
});
export type SupportContentGrantRequest = z.infer<typeof supportContentGrantRequestSchema>;

export const supportContentGrantSchema = z.strictObject({
  grant_id: supportContentGrantIdSchema,
  operator_id: z.uuid(),
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
});
export type SupportContentGrant = z.infer<typeof supportContentGrantSchema>;

/**
 * One message's content (T3, human-only). `text` is the plain-text body, shown as text and never
 * rendered; HTML is withheld (`html_withheld`), never sent to the browser.
 */
export const adminSupportMessageContentSchema = z.strictObject({
  case_id: supportCaseIdSchema,
  message: adminSupportMessageSummarySchema,
  headers: z
    .array(z.strictObject({ name: z.string().max(1000), value: z.string().max(1024 * 1024) }))
    .max(SUPPORT_CONTENT_MAX_HEADERS),
  text: z.string().max(SUPPORT_ADMISSION.maxMessageBytes).nullable(),
  html_withheld: z.boolean(),
  attachments: z
    .array(z.strictObject({ attachment_id: supportAttachmentIdSchema, size_bytes: z.int().min(0) }))
    .max(SUPPORT_ADMISSION.maxAttachmentsPerMessage),
});
export type AdminSupportMessageContent = z.infer<typeof adminSupportMessageContentSchema>;

/**
 * One attachment (T3, human-only), base64 in JSON. The admin site's server turns it into a
 * download (`Content-Disposition: attachment`, `application/octet-stream`, `nosniff`, a sandboxing
 * CSP); the browser never receives this JSON. The sender's declared media type is not returned.
 */
export const adminSupportAttachmentSchema = z.strictObject({
  attachment_id: supportAttachmentIdSchema,
  case_id: supportCaseIdSchema,
  filename: z.string().max(1000),
  size_bytes: z.int().min(0).max(SUPPORT_ADMISSION.maxAttachmentBytes),
  content_base64: z.base64(),
});
export type AdminSupportAttachment = z.infer<typeof adminSupportAttachmentSchema>;

// Quoted verbatim from SPEC "Support case store" (the registry test checks it).
const SPEC =
  "The `kovo-admin` CLI, the production-verification principal and every operator or agent service account are refused, whatever their classification.";
const METADATA_SPEC =
  "Metadata projections stay separate and content-free: the case list, a case and its messages, as IDs, enums, booleans, counts and times.";
const source = { kind: "spec_implied", section: "Security model and data retention" } as const;
const metadataAuthorization = {
  spec: METADATA_SPEC,
  actors: ["operator"],
  tenant: "none",
} as const;
const humanAuthorization = { spec: SPEC, actors: ["operator"], tenant: "none" } as const;
const grantQuery = z.strictObject({ grant_id: supportContentGrantIdSchema });

export const SUPPORT_ADMIN_ENDPOINTS = {
  listAdminSupportCases: defineEndpoint({
    operationId: "listAdminSupportCases",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/support/cases",
    summary: "Email support cases, newest first: metadata only, never content.",
    source,
    params: null,
    query: z.strictObject({
      requested_by: adminRequestedBySchema,
      state: supportCaseStateSchema.exactOptional(),
      before: z.coerce.number().int().min(1).max(Number.MAX_SAFE_INTEGER).exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_SUPPORT_PAGE_MAX).default(50),
    }),
    body: null,
    responses: { 200: adminSupportCasesSchema },
    authorization: metadataAuthorization,
    auditStorage: "admin_audit",
  }),
  getAdminSupportCase: defineEndpoint({
    operationId: "getAdminSupportCase",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/support/cases/{case}",
    summary: "One email support case and its messages: metadata only, never content.",
    source,
    params: z.strictObject({ case: supportCaseIdSchema }),
    query: z.strictObject({ requested_by: adminRequestedBySchema }),
    body: null,
    responses: { 200: adminSupportCaseDetailSchema },
    authorization: metadataAuthorization,
    auditStorage: "admin_audit",
    problems: ["not_found"],
  }),
  createSupportContentGrant: defineEndpoint({
    operationId: "createSupportContentGrant",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/support/grants",
    summary: "A verified human's justified grant to read support mail, at most two hours.",
    source,
    params: null,
    query: null,
    body: supportContentGrantRequestSchema,
    responses: { 201: supportContentGrantSchema },
    authorization: humanAuthorization,
    auditStorage: "support_content_grants",
    problems: ["service_unavailable"],
  }),
  revokeSupportContentGrant: defineEndpoint({
    operationId: "revokeSupportContentGrant",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/support/grants/{grant}/revoke",
    summary: "Revoke the caller's own support content grant.",
    source,
    params: z.strictObject({ grant: supportContentGrantIdSchema }),
    query: null,
    body: z.strictObject({}),
    responses: {
      200: z.strictObject({ grant_id: supportContentGrantIdSchema, revoked_at: utcDateTimeSchema }),
    },
    authorization: humanAuthorization,
    auditStorage: "support_content_grants",
    problems: ["not_found"],
  }),
  readSupportMessageContent: defineEndpoint({
    operationId: "readSupportMessageContent",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/support/messages/{message}",
    summary: "One support message's headers and plain text under a live grant; HTML is withheld.",
    source,
    params: z.strictObject({ message: supportMessageIdSchema }),
    query: grantQuery,
    body: null,
    responses: { 200: adminSupportMessageContentSchema },
    authorization: humanAuthorization,
    auditStorage: "support_content_audit",
    problems: ["not_found", "service_unavailable"],
  }),
  downloadSupportAttachment: defineEndpoint({
    operationId: "downloadSupportAttachment",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/support/attachments/{attachment}",
    summary:
      "One support attachment's bytes under a live grant, served by the admin site as a download.",
    source,
    params: z.strictObject({ attachment: supportAttachmentIdSchema }),
    query: grantQuery,
    body: null,
    responses: { 200: adminSupportAttachmentSchema },
    authorization: humanAuthorization,
    auditStorage: "support_content_audit",
    problems: ["not_found", "service_unavailable"],
  }),
} as const;

/** The admin-site path of an attachment download, which the admin server serves as a file. */
export const SUPPORT_ATTACHMENT_PATH =
  /^\/v1\/operator\/admin\/support\/attachments\/[0-9a-f-]{36}$/;
