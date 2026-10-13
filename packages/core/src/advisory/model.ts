import {
  advisoryEcosystemSchema,
  advisoryIdSchema,
  advisoryRangeEventKindSchema,
  advisoryRangeTypeSchema,
  canonicalOsvTimestampSchema,
  cweIdSchema,
  labelSchema,
  maliciousReasonSchema,
  packageNameSchema,
  packageVersionSchema,
  severityReasonSchema,
  severitySchema,
  severitySourceSchema,
  whenValid,
} from "@kovo/contracts";
import { cvssScoreSchema } from "@kovo/contracts/api";
import { z } from "zod";

import { parseNpmVersion } from "./version.js";

// The normalized npm advisory: the `advisories` row plus its `advisory_ranges` (SPEC data model
// `advisories(id PK, aliases, ecosystem, summary, severity, severity_source, cvss_score,
// cvss_vector, cwe_ids, is_malicious, withdrawn_at, modified_at, raw JSONB)` and
// `advisory_ranges(advisory_id, package, range_type, events JSONB, explicit_versions JSONB)`),
// in the camelCase shape of the control-plane `AdvisoryRecord`. `@kovo/core/advisory` produces it
// from an OSV record; the ingestion service stores it and reads it back through these schemas.

/** Special OSV event values: `introduced: "0"` sorts before every version, `limit: "*"` is ∞. */
export const INTRODUCED_ZERO = "0";
export const LIMIT_INFINITY = "*";

function isValidEventVersion(kind: string, version: string): boolean {
  if (kind === "introduced" && version === INTRODUCED_ZERO) return true;
  if (kind === "limit" && version === LIMIT_INFINITY) return true;
  return parseNpmVersion(version) !== null;
}

/** One OSV range event with an exact SemVer version (or `"0"` / `"*"`). */
export const advisoryRangeEventSchema = z
  .strictObject({ kind: advisoryRangeEventKindSchema, version: z.string().max(256) })
  .refine((event) => isValidEventVersion(event.kind, event.version), {
    ...whenValid,
    error: "must be an exact SemVer version (introduced may be 0, limit may be *)",
    path: ["version"],
  });
export type AdvisoryRangeEvent = z.infer<typeof advisoryRangeEventSchema>;

/**
 * One `advisory_ranges` row: a SEMVER/ECOSYSTEM range of one npm package, or (range type null) a
 * versions-only entry. A GIT row may be read back from storage but is never produced; its events
 * are ignored and only its explicit versions count.
 */
export const advisoryRangeSchema = z
  .strictObject({
    package: packageNameSchema,
    rangeType: advisoryRangeTypeSchema.nullable(),
    events: z.array(advisoryRangeEventSchema).max(256),
    explicitVersions: z.array(packageVersionSchema).max(10_000),
  })
  .superRefine((range, ctx) => {
    if (range.rangeType === null) {
      if (range.events.length > 0 || range.explicitVersions.length === 0) {
        ctx.addIssue({
          code: "custom",
          path: ["events"],
          message: "a versions-only entry has no events and at least one version",
        });
      }
    } else if (
      range.rangeType !== "GIT" &&
      !range.events.some((event) => event.kind === "introduced")
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["events"],
        message: "a range needs at least one introduced event",
      });
    }
  }, whenValid);
export type AdvisoryRange = z.infer<typeof advisoryRangeSchema>;

type JsonValue =
  | string
  | number
  | boolean
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
/** A JSON object (the sanitized public OSV record). */
export type JsonObject = { readonly [key: string]: JsonValue };
const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);
const jsonObjectSchema: z.ZodType<JsonObject> = z.record(z.string(), jsonValueSchema);

export const normalizedAdvisorySchema = z
  .strictObject({
    id: advisoryIdSchema,
    /** Other IDs of the same vulnerability (CVE, GHSA, MAL, …), deduplicated, never the own ID. */
    aliases: z.array(advisoryIdSchema).max(50),
    ecosystem: advisoryEcosystemSchema,
    /** One line of public, untrusted text; null when the record has none. */
    summary: labelSchema(1000).nullable(),
    severity: severitySchema,
    severitySource: severitySourceSchema,
    severityReason: severityReasonSchema,
    cvssScore: cvssScoreSchema.nullable(),
    cvssVector: z.string().max(512).nullable(),
    cweIds: z.array(cweIdSchema).max(50),
    isMalicious: z.boolean(),
    maliciousReason: maliciousReasonSchema.nullable(),
    publishedAt: z.date().nullable(),
    /** OSV `modified` truncated to milliseconds. */
    modifiedAt: z.date(),
    /** OSV `modified` with all its fractional digits (`advisories.source_modified`). */
    sourceModified: canonicalOsvTimestampSchema,
    withdrawnAt: z.date().nullable(),
    ranges: z.array(advisoryRangeSchema).max(10_000),
    /** The sanitized public OSV record (`advisories.raw`). */
    raw: jsonObjectSchema,
  })
  .superRefine((advisory, ctx) => {
    if ((advisory.severity === "UNKNOWN") !== (advisory.severitySource === "none")) {
      ctx.addIssue({
        code: "custom",
        path: ["severitySource"],
        message: "exactly UNKNOWN severities have no source",
      });
    }
    if ((advisory.cvssScore === null) !== (advisory.cvssVector === null)) {
      ctx.addIssue({
        code: "custom",
        path: ["cvssVector"],
        message: "a CVSS score and its vector come together",
      });
    }
    if (advisory.isMalicious !== (advisory.maliciousReason !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["maliciousReason"],
        message: "exactly malicious advisories carry a malicious reason",
      });
    }
    if (
      advisory.aliases.includes(advisory.id) ||
      new Set(advisory.aliases).size !== advisory.aliases.length
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["aliases"],
        message: "aliases are unique and exclude the ID",
      });
    }
    if (new Set(advisory.cweIds).size !== advisory.cweIds.length) {
      ctx.addIssue({ code: "custom", path: ["cweIds"], message: "CWE IDs are unique" });
    }
  }, whenValid);
export type NormalizedAdvisory = z.infer<typeof normalizedAdvisorySchema>;

/**
 * The advisory facts matching, tiering and target resolution read. A `NormalizedAdvisory`
 * satisfies it, and so does a row read back from storage.
 */
export type AdvisoryFacts = Pick<
  NormalizedAdvisory,
  "id" | "aliases" | "severity" | "cweIds" | "isMalicious" | "withdrawnAt" | "ranges"
>;
