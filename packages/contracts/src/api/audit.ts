import { z } from "zod";

import { ACCOUNT_ADMIN_ROLES, actorTypeSchema } from "../enums/accounts.js";
import { auditActionSchema, auditActionQuerySchema } from "../enums/operations.js";
import { apiKeyIdSchema, auditEventIdSchema, repoIdSchema } from "../ids.js";
import { microUsdWireSchema } from "../money.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { hasControlCharacter, sha256HexSchema, whenValid } from "../primitives.js";
import { utcDateTimeSchema, utcDateTimeStringSchema } from "../time.js";
import { actorRefSchema, repoRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";
import { isSensitiveFieldName } from "./sensitive.js";

// `GET /v1/audit` (SPEC: "All mutations write a sanitized audit event; exclude secrets and
// source-bearing before/after values"; Public API row "Human owner/admin; filter repository details
// by GitHub access"; retention "Sanitized security/permission audit: One year from event").

/** What an audit event changed. */
export const AUDIT_TARGET_TYPES = [
  "account",
  "membership",
  "invitation",
  "installation",
  "repo",
  "policy",
  "finding",
  "recipe_version",
  "recipe_overrides",
  "fix",
  "notification_settings",
  "api_key",
  "webhook",
  "subscription",
  "capacity_quote",
  "overage_consent",
  "global_setting",
  "proxy_capability",
] as const;
export const auditTargetTypeSchema = z.enum(AUDIT_TARGET_TYPES);
export type AuditTargetType = z.infer<typeof auditTargetTypeSchema>;

export const auditTargetSchema = z.strictObject({
  type: auditTargetTypeSchema,
  id: z.string().regex(/^[A-Za-z0-9._:@/-]{1,128}$/, { error: "must be a bounded identifier" }),
});

/** Every `scheme://…` run in a string (an audit value may quote a URL inside other text). */
const URL_RUN = /[a-z][a-z0-9+.-]*:\/\/\S*/gi;

/** A URL without credentials, query or fragment, which is where receivers put their secrets. */
function isBareUrl(text: string): boolean {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return false;
  }
  return url.username === "" && url.password === "" && url.search === "" && url.hash === "";
}

function hasOnlyBareUrls(text: string): boolean {
  return [...text.matchAll(URL_RUN)].every((match) => isBareUrl(match[0]));
}

/** A string an audit projection may hold: one line, bounded, URLs only without secrets. */
export function auditStringSchema(max: number) {
  return z
    .string()
    .max(max)
    .refine((text) => !hasControlCharacter(text), {
      error: "audited strings are single-line, without control characters",
    })
    .refine(hasOnlyBareUrls, {
      error: "audited URLs carry no credentials, query or fragment",
    });
}

const auditValueSchema = z.union([
  auditStringSchema(512),
  z.number(),
  z.boolean(),
  z.null(),
  z.array(auditStringSchema(256)).max(100),
]);
type AuditValue = z.output<typeof auditValueSchema>;

/**
 * Conventions a value must follow by its name, as in every API schema: `*_usd` is a micro-USD
 * decimal string (never a float), `at`/`*_at`/`*_until` a UTC timestamp, `*_url` a bare URL.
 */
function namingViolation(key: string, value: AuditValue): string | null {
  if (value === null) return null;
  if (key === "lockfile_hash") {
    return typeof value === "string" && sha256HexSchema.safeParse(value).success
      ? null
      : "lockfile metadata is a SHA-256 digest, never content";
  }
  if (key === "parent_key_id" || key === "approved_by_key_id" || key === "created_by_key_id") {
    return typeof value === "string" && apiKeyIdSchema.safeParse(value).success
      ? null
      : "key references are entity UUIDs, never key material";
  }
  if (key.endsWith("_usd")) {
    const money = typeof value === "string" && microUsdWireSchema.safeParse(value).success;
    return money ? null : "money is a micro-USD decimal string";
  }
  if (key === "at" || key.endsWith("_at") || key.endsWith("_until")) {
    const time = typeof value === "string" && utcDateTimeStringSchema.safeParse(value).success;
    return time ? null : "times are UTC timestamps";
  }
  if (key.endsWith("_url")) {
    return typeof value === "string" && isBareUrl(value)
      ? null
      : "URLs are absolute, without credentials, query or fragment";
  }
  return null;
}

/**
 * An allowlisted field projection: snake_case keys with scalar or short string-list values. Names
 * that denote secrets or source-bearing content are rejected even if a projection lists them, and
 * values must follow the naming conventions of the API schemas.
 */
export const auditValuesSchema = z
  .record(
    z.string().regex(/^[a-z][a-z0-9_]{0,63}$/, { error: "must be a snake_case field" }),
    auditValueSchema,
  )
  .superRefine((values, ctx) => {
    const entries = Object.entries(values);
    if (entries.length > 50) {
      ctx.addIssue({ code: "custom", message: "at most 50 audited fields" });
    }
    for (const [key, value] of entries) {
      if (isSensitiveFieldName(key)) {
        ctx.addIssue({
          code: "custom",
          path: [key],
          message: "sensitive fields are never audited",
        });
        continue;
      }
      const violation = namingViolation(key, value);
      if (violation !== null) ctx.addIssue({ code: "custom", path: [key], message: violation });
    }
  }, whenValid);

/**
 * One audit event. For an event that names a repository the viewer cannot currently read (as its
 * repository, in its values or through a webhook subscription's scope), the repository, target
 * and before/after values are withheld (`repo_redacted`).
 */
export const auditEventSchema = z
  .strictObject({
    id: auditEventIdSchema,
    at: utcDateTimeSchema,
    action: auditActionSchema,
    actor: actorRefSchema,
    repo: repoRefSchema.nullable(),
    repo_redacted: z.boolean(),
    target: auditTargetSchema.nullable(),
    before: auditValuesSchema.nullable(),
    after: auditValuesSchema.nullable(),
  })
  .refine(
    (event) =>
      !event.repo_redacted ||
      (event.repo === null &&
        event.target === null &&
        event.before === null &&
        event.after === null),
    {
      ...whenValid,
      error: "a redacted event withholds repository details",
      path: ["repo_redacted"],
    },
  );
export type AuditEvent = z.output<typeof auditEventSchema>;

export const auditQuerySchema = z
  .strictObject({
    ...paginationQueryShape,
    action: auditActionQuerySchema.exactOptional(),
    repo_id: repoIdSchema.exactOptional(),
    actor_type: actorTypeSchema.exactOptional(),
    since: utcDateTimeSchema.exactOptional(),
    until: utcDateTimeSchema.exactOptional(),
  })
  .refine(
    (query) =>
      query.since === undefined ||
      query.until === undefined ||
      query.since.getTime() < query.until.getTime(),
    { ...whenValid, error: "since must be before until", path: ["until"] },
  );

export const AUDIT_ENDPOINTS = {
  listAuditEvents: defineEndpoint({
    operationId: "listAuditEvents",
    area: "audit",
    method: "GET",
    path: "/v1/audit",
    summary: "List sanitized audit events, newest first.",
    source: { kind: "spec_row", path: "/v1/audit" },
    params: null,
    query: auditQuerySchema,
    body: null,
    responses: { 200: pageSchema(auditEventSchema) },
    authorization: {
      spec: "Human owner/admin; filter repository details by GitHub access",
      actors: ["human_session"],
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "listed_items" },
    },
    paginated: true,
  }),
} as const;
