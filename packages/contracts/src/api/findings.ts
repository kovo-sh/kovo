import { z } from "zod";

import {
  dismissReasonSchema,
  findingStatusSchema,
  severitySchema,
  severitySourceSchema,
} from "../enums/advisories.js";
import { fixStatusSchema } from "../enums/fixes.js";
import { emailStateSchema } from "../enums/notifications.js";
import { dependencyPathSchema } from "../evidence.js";
import {
  accountIdSchema,
  advisoryIdSchema,
  emailIdSchema,
  findingIdSchema,
  fixIdSchema,
  repoIdSchema,
  snapshotIdSchema,
} from "../ids.js";
import { packageNameSchema, packageVersionSchema } from "../npm.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { cweIdSchema, labelSchema, whenValid } from "../primitives.js";
import { tierSchema } from "../tier.js";
import { utcDateTimeSchema } from "../time.js";
import {
  noteSchema,
  repoRefSchema,
  uniqueArraySchema,
  userRefSchema,
  workSearchSchema,
} from "./common.js";
import { defineEndpoint } from "./endpoint.js";
import { viewerPermissionSchema } from "./repos.js";

// `/v1/repos/{repo}/findings`: findings per affected package version and their dismissal (SPEC
// "Inventory, advisories, and tiering", Public API rows 8–9).

// ---- Shapes ----

/** A CVSS base score, 0.0–10.0 in tenths. */
export const cvssScoreSchema = z
  .number()
  .min(0)
  .max(10)
  .refine((score) => Math.round(score * 10) / 10 === score, {
    ...whenValid,
    error: "a CVSS score has one decimal place",
  });

/**
 * The public advisory facts behind a finding. `severity_source` records where the severity came
 * from ("Record the source and parsing reason"); `kev` is true when an alias is in CISA KEV.
 */
export const advisorySummarySchema = z
  .strictObject({
    id: advisoryIdSchema,
    aliases: uniqueArraySchema(advisoryIdSchema, 50),
    summary: labelSchema(1000).nullable(),
    severity: severitySchema,
    severity_source: severitySourceSchema,
    cvss_score: cvssScoreSchema.nullable(),
    cwe_ids: uniqueArraySchema(cweIdSchema, 50),
    is_malicious: z.boolean(),
    kev: z.boolean(),
    withdrawn_at: utcDateTimeSchema.nullable(),
    modified_at: utcDateTimeSchema,
  })
  .refine(
    (advisory) => (advisory.severity === "UNKNOWN") === (advisory.severity_source === "none"),
    {
      ...whenValid,
      error: "exactly UNKNOWN severities have no source",
      path: ["severity_source"],
    },
  );
export type AdvisorySummary = z.output<typeof advisorySummarySchema>;

/**
 * A finding: one advisory affecting one resolved package version ("UNIQUE(repo_id, advisory_id,
 * package, version)"). Dismissal is "scoped to the affected version", so a dismissed finding names
 * the exact version it covers.
 */
export const findingSchema = z
  .strictObject({
    id: findingIdSchema,
    repo_id: repoIdSchema,
    /** Last-seen immutable snapshot; null after retention retires its provenance. */
    snapshot_id: snapshotIdSchema.nullable().optional(),
    advisory: advisorySummarySchema,
    package: packageNameSchema,
    version: packageVersionSchema,
    /** False if any production path reaches the package. */
    is_dev: z.boolean(),
    tier: tierSchema,
    status: findingStatusSchema,
    dismiss_reason: dismissReasonSchema.nullable(),
    first_seen_at: utcDateTimeSchema,
    last_seen_at: utcDateTimeSchema,
    resolved_at: utcDateTimeSchema.nullable(),
    dependency_paths: z.array(dependencyPathSchema).max(100),
    /** The fix currently or last linked to this finding. */
    fix: z.strictObject({ id: fixIdSchema, status: fixStatusSchema }).nullable(),
  })
  .superRefine((finding, ctx) => {
    if ((finding.status === "dismissed") !== (finding.dismiss_reason !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["dismiss_reason"],
        message: "exactly dismissed findings carry a dismiss reason",
      });
    }
    if (finding.status === "resolved" && finding.resolved_at === null) {
      ctx.addIssue({
        code: "custom",
        path: ["resolved_at"],
        message: "a resolved finding has resolved_at",
      });
    }
    if (finding.status === "open" && finding.resolved_at !== null) {
      ctx.addIssue({
        code: "custom",
        path: ["resolved_at"],
        message: "an open finding is not resolved",
      });
    }
    if (finding.last_seen_at.getTime() < finding.first_seen_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["last_seen_at"],
        message: "last seen after first seen",
      });
    }
  }, whenValid);
export type Finding = z.output<typeof findingSchema>;

/** "reason required"; the `other` reason needs a note (docs/decisions/contracts.md). */
export const dismissFindingBodySchema = z
  .strictObject({ reason: dismissReasonSchema, note: noteSchema.exactOptional() })
  .refine((body) => body.reason !== "other" || body.note !== undefined, {
    ...whenValid,
    error: "the other reason needs a note",
    path: ["note"],
  });

/**
 * A finding in the account-wide list: the finding as the repository's list shows it, the
 * repository it is in and the viewer's permission there (as `GET /v1/repos` reports it), so a
 * cross-repository page can name the repository and offer what the viewer may do.
 */
export const accountFindingSchema = z
  .strictObject({
    finding: findingSchema,
    repo: repoRefSchema,
    viewer_permission: viewerPermissionSchema,
  })
  .refine((item) => item.finding.repo_id === item.repo.id, {
    ...whenValid,
    error: "the finding is in the repository named",
    path: ["repo"],
  });
export type AccountFinding = z.output<typeof accountFindingSchema>;

/** SPEC's rule every cross-repository read follows. */
const REPO_VISIBILITY = "Repository visibility always requires current GitHub read access.";

/**
 * One P0 alert email about a finding (SPEC Notifications: "P0 detection | Immediately, before fix
 * attempt | Authorized repo recipients"; "Persist an outbox row keyed by logical event and
 * recipient"): who it went to, as the member's GitHub identity, never the address; which detection
 * it announced (`occurrence` counts detections, reopenings included); and where its delivery
 * stands (`state`, the email outbox's). `sent_at` is when the provider accepted it and
 * `delivered_at` when it reported delivery. Email metadata is kept 30 days (SPEC Retention), so
 * older alerts are no longer listed (docs/decisions/contracts.md "A finding's P0 alerts").
 */
export const findingAlertSchema = z
  .strictObject({
    id: emailIdSchema,
    occurrence: z.int().positive(),
    recipient: userRefSchema,
    state: emailStateSchema,
    queued_at: utcDateTimeSchema,
    sent_at: utcDateTimeSchema.nullable(),
    delivered_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((alert, ctx) => {
    if (alert.state === "sent" && alert.sent_at === null) {
      ctx.addIssue({ code: "custom", path: ["sent_at"], message: "a sent alert has sent_at" });
    }
    if (alert.delivered_at !== null && alert.sent_at === null) {
      ctx.addIssue({
        code: "custom",
        path: ["delivered_at"],
        message: "only a sent alert is delivered",
      });
    }
  }, whenValid);
export type FindingAlert = z.output<typeof findingAlertSchema>;

// ---- Endpoints ----

export const FINDING_ENDPOINTS = {
  listFindings: defineEndpoint({
    operationId: "listFindings",
    area: "findings",
    method: "GET",
    path: "/v1/repos/{repo}/findings",
    summary: "List a repository's findings.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/findings" },
    params: z.strictObject({ repo: repoIdSchema }),
    query: z.strictObject({
      ...paginationQueryShape,
      status: findingStatusSchema.exactOptional(),
      tier: tierSchema.exactOptional(),
      package: packageNameSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(findingSchema) },
    authorization: {
      spec: "Scoped read",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
    paginated: true,
  }),
  listAccountFindings: defineEndpoint({
    operationId: "listAccountFindings",
    area: "findings",
    method: "GET",
    path: "/v1/accounts/{account}/findings",
    summary:
      "List the findings of every repository of the account the caller can read, most urgent first.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: z.strictObject({ account: accountIdSchema }),
    query: z.strictObject({
      ...paginationQueryShape,
      repo_id: repoIdSchema.exactOptional(),
      status: findingStatusSchema.exactOptional(),
      tier: tierSchema.exactOptional(),
      package: packageNameSchema.exactOptional(),
      /** Part of a package name, or the start of an advisory ID or alias. */
      q: workSearchSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(accountFindingSchema) },
    authorization: {
      spec: REPO_VISIBILITY,
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_account",
      repoAuthority: { level: "read", over: "listed_items" },
    },
    paginated: true,
  }),
  dismissFinding: defineEndpoint({
    operationId: "dismissFinding",
    area: "findings",
    method: "POST",
    path: "/v1/repos/{repo}/findings/{id}/dismiss",
    summary: "Dismiss one finding for its affected version only.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/findings/{id}/dismiss" },
    auditActions: ["finding.dismissed"],
    params: z.strictObject({ repo: repoIdSchema, id: findingIdSchema }),
    query: null,
    body: dismissFindingBodySchema,
    responses: {
      200: z
        .strictObject({ finding: findingSchema })
        .refine((body) => body.finding.status === "dismissed", {
          ...whenValid,
          error: "the finding is dismissed",
        }),
    },
    authorization: {
      spec: "Scoped write; reason required; affected-version scope",
      actors: ["human_session", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "write", over: "path_repo" },
    },
    problems: ["conflict"],
  }),
  listFindingAlerts: defineEndpoint({
    operationId: "listFindingAlerts",
    area: "findings",
    method: "GET",
    path: "/v1/repos/{repo}/findings/{id}/alerts",
    summary:
      "List the P0 alert emails sent about one finding: the member alerted, when, and the delivery state; never addresses.",
    source: { kind: "spec_implied", section: "Notifications" },
    params: z.strictObject({ repo: repoIdSchema, id: findingIdSchema }),
    query: z.strictObject({ ...paginationQueryShape }),
    body: null,
    responses: { 200: pageSchema(findingAlertSchema) },
    authorization: {
      spec: "Persist an outbox row keyed by logical event and recipient",
      // It names the account's members, which only people read (`listMembers` is human-only).
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
    paginated: true,
  }),
} as const;
