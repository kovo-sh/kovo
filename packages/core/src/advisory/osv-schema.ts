import { z } from "zod";

// The OSV record as Kovo reads it (OSV schema 1.x, observed 1.7.3–1.9.0 in the npm export). Types
// and sizes are strict; unknown members are dropped rather than rejected, because OSV promises that
// "new minor and patch versions of the schema only add new fields" and tells clients to ignore
// them. Optional members may be absent or null. Every bound is well above the largest value in the
// full npm export (docs/decisions/advisory.md "OSV parsing: strict types and bounds, unknown members dropped") and keeps a hostile record from
// ballooning memory or storage. Semantic checks (IDs, versions, timestamps, package names) happen
// in `normalize.ts`, which can then drop or reject individual values with a recorded reason.

const text = (max: number) => z.string().max(max);
const optional = <T extends z.ZodType>(schema: T) =>
  schema.nullish().transform((value) => value ?? undefined);

export const OSV_LIMITS = {
  aliases: 50,
  related: 500,
  summaryChars: 4096,
  detailsChars: 256 * 1024,
  severity: 16,
  affected: 1000,
  ranges: 64,
  events: 256,
  versions: 10_000,
  references: 1000,
  credits: 100,
} as const;

export const osvSeveritySchema = z.object({
  type: text(32),
  score: text(512),
});
export type OsvSeverity = z.output<typeof osvSeveritySchema>;

/** A range event: kept as a loose object; `normalize.ts` requires exactly one known member. */
export const osvEventSchema = z.object({
  introduced: optional(text(256)),
  fixed: optional(text(256)),
  last_affected: optional(text(256)),
  limit: optional(text(256)),
});
export type OsvEvent = z.output<typeof osvEventSchema>;

export const osvRangeSchema = z.object({
  type: text(32),
  repo: optional(text(2048)),
  events: z.array(osvEventSchema).max(OSV_LIMITS.events),
});
export type OsvRange = z.output<typeof osvRangeSchema>;

const jsonRecord = z.record(z.string(), z.unknown());

export const osvAffectedSchema = z.object({
  package: optional(
    z.object({
      ecosystem: text(128),
      name: text(512),
      purl: optional(text(1024)),
    }),
  ),
  ranges: optional(z.array(osvRangeSchema).max(OSV_LIMITS.ranges)),
  versions: optional(z.array(text(256)).max(OSV_LIMITS.versions)),
  severity: optional(z.array(osvSeveritySchema).max(OSV_LIMITS.severity)),
  database_specific: optional(jsonRecord),
});
export type OsvAffected = z.output<typeof osvAffectedSchema>;

export const osvRecordSchema = z.object({
  schema_version: optional(text(32)),
  id: text(128),
  modified: text(64),
  published: optional(text(64)),
  withdrawn: optional(text(64)),
  aliases: optional(z.array(text(256)).max(OSV_LIMITS.aliases)),
  related: optional(z.array(text(256)).max(OSV_LIMITS.related)),
  summary: optional(text(OSV_LIMITS.summaryChars)),
  details: optional(text(OSV_LIMITS.detailsChars)),
  severity: optional(z.array(osvSeveritySchema).max(OSV_LIMITS.severity)),
  affected: optional(z.array(osvAffectedSchema).max(OSV_LIMITS.affected)),
  references: optional(
    z.array(z.object({ type: text(32), url: text(4096) })).max(OSV_LIMITS.references),
  ),
  credits: optional(
    z
      .array(
        z.object({
          name: text(512),
          contact: optional(z.array(text(2048)).max(20)),
          type: optional(text(64)),
        }),
      )
      .max(OSV_LIMITS.credits),
  ),
  database_specific: optional(jsonRecord),
});
export type OsvRecord = z.output<typeof osvRecordSchema>;

// ---- database_specific members Kovo reads or retains ----

/** GHSA `database_specific.cwe_ids` (`["CWE-79", …]`). */
export const ghsaCweIdsSchema = z.array(text(64)).max(1000);

/** MAL `affected[].database_specific.cwes` (`[{ cweId: "CWE-506", … }]`). */
export const malCwesSchema = z
  .array(
    z.object({ cweId: text(64), name: optional(text(512)), description: optional(text(2048)) }),
  )
  .max(1000);

/** OpenSSF malicious-packages provenance (`database_specific["malicious-packages-origins"]`). */
export const maliciousOriginsSchema = z
  .array(
    z.object({
      source: text(128),
      id: optional(text(128)),
      sha256: optional(text(128)),
      import_time: optional(text(64)),
      modified_time: optional(text(64)),
      versions: optional(z.array(text(256)).max(OSV_LIMITS.versions)),
      ranges: optional(z.array(osvRangeSchema).max(OSV_LIMITS.ranges)),
    }),
  )
  .max(1000);
