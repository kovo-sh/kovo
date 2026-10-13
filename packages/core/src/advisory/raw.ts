import type { JsonObject } from "./model.js";
import {
  ghsaCweIdsSchema,
  malCwesSchema,
  maliciousOriginsSchema,
  type OsvAffected,
  type OsvRange,
  type OsvRecord,
} from "./osv-schema.js";

// The sanitized public advisory JSON retained as `advisories.raw`: an allowlisted projection of the
// OSV record. It keeps the public facts a reviewer needs (IDs, dates, text, references, credits,
// severity entries, the npm `affected[]` entries as published, the GHSA and OpenSSF provenance
// members Kovo understands) and drops everything else: unknown members (already stripped by the
// parser), foreign-ecosystem entries, `ecosystem_specific`, and `database_specific` members outside
// the allowlist such as OpenSSF indicators of compromise (`iocs`, `indicators`), which are hostile
// URLs/hosts Kovo has no use for. `onDrop` reports only allowlisted members whose value has the
// wrong shape; members outside the allowlist are dropped by design. The result is bounded by the
// parser's limits.

type Json = JsonObject[string];
type Mutable = Record<string, Json>;

function put(target: Mutable, key: string, value: Json | undefined): void {
  if (value !== undefined) target[key] = value;
}

function scalar(value: unknown): string | boolean | null | undefined {
  return typeof value === "string" || typeof value === "boolean" || value === null
    ? value
    : undefined;
}

function rangeJson(range: OsvRange): JsonObject {
  const out: Mutable = { type: range.type };
  put(out, "repo", range.repo);
  out["events"] = range.events.map((event) => {
    const e: Mutable = {};
    put(e, "introduced", event.introduced);
    put(e, "fixed", event.fixed);
    put(e, "last_affected", event.last_affected);
    put(e, "limit", event.limit);
    return e;
  });
  return out;
}

function affectedJson(
  entry: OsvAffected,
  onDrop: (path: string) => void,
  path: string,
): JsonObject {
  const out: Mutable = {};
  if (entry.package !== undefined) {
    const pkg: Mutable = { ecosystem: entry.package.ecosystem, name: entry.package.name };
    put(pkg, "purl", entry.package.purl);
    out["package"] = pkg;
  }
  if (entry.ranges !== undefined) out["ranges"] = entry.ranges.map(rangeJson);
  if (entry.versions !== undefined) out["versions"] = [...entry.versions];
  if (entry.severity !== undefined) {
    out["severity"] = entry.severity.map((s) => ({ type: s.type, score: s.score }));
  }
  const specific = entry.database_specific;
  if (specific !== undefined) {
    const db: Mutable = {};
    for (const key of ["source", "last_known_affected_version_range"]) {
      const value = scalar(specific[key]);
      if (value !== undefined) db[key] = value;
      else if (specific[key] !== undefined) onDrop(`${path}.database_specific.${key}`);
    }
    if (specific["cwes"] !== undefined && specific["cwes"] !== null) {
      const cwes = malCwesSchema.safeParse(specific["cwes"]);
      if (cwes.success) {
        db["cwes"] = cwes.data.map((cwe) => {
          const c: Mutable = { cweId: cwe.cweId };
          put(c, "name", cwe.name);
          put(c, "description", cwe.description);
          return c;
        });
      } else onDrop(`${path}.database_specific.cwes`);
    }
    if (Object.keys(db).length > 0) out["database_specific"] = db;
  }
  return out;
}

const GHSA_SCALARS = ["severity", "github_reviewed", "github_reviewed_at", "nvd_published_at"];
const ORIGINS = "malicious-packages-origins";

function databaseSpecificJson(
  specific: Readonly<Record<string, unknown>>,
  onDrop: (path: string) => void,
): JsonObject | undefined {
  const db: Mutable = {};
  for (const key of GHSA_SCALARS) {
    const value = scalar(specific[key]);
    if (value !== undefined) db[key] = value;
    else if (specific[key] !== undefined) onDrop(`database_specific.${key}`);
  }
  if (specific["cwe_ids"] !== undefined && specific["cwe_ids"] !== null) {
    const cwes = ghsaCweIdsSchema.safeParse(specific["cwe_ids"]);
    if (cwes.success) db["cwe_ids"] = [...cwes.data];
    else onDrop("database_specific.cwe_ids");
  }
  if (specific[ORIGINS] !== undefined && specific[ORIGINS] !== null) {
    const origins = maliciousOriginsSchema.safeParse(specific[ORIGINS]);
    if (origins.success) {
      db[ORIGINS] = origins.data.map((origin) => {
        const o: Mutable = { source: origin.source };
        put(o, "id", origin.id);
        put(o, "sha256", origin.sha256);
        put(o, "import_time", origin.import_time);
        put(o, "modified_time", origin.modified_time);
        if (origin.versions !== undefined) o["versions"] = [...origin.versions];
        if (origin.ranges !== undefined) o["ranges"] = origin.ranges.map(rangeJson);
        return o;
      });
    } else onDrop(`database_specific.${ORIGINS}`);
  }
  return Object.keys(db).length > 0 ? db : undefined;
}

/** Builds the sanitized public record from a parsed OSV record and its npm `affected[]` entries. */
export function sanitizeOsvRecord(
  record: OsvRecord,
  npmAffected: readonly OsvAffected[],
  onDrop: (path: string) => void,
): JsonObject {
  const out: Mutable = {};
  put(out, "schema_version", record.schema_version);
  out["id"] = record.id;
  out["modified"] = record.modified;
  put(out, "published", record.published);
  put(out, "withdrawn", record.withdrawn);
  if (record.aliases !== undefined) out["aliases"] = [...record.aliases];
  if (record.related !== undefined) out["related"] = [...record.related];
  put(out, "summary", record.summary);
  put(out, "details", record.details);
  if (record.severity !== undefined) {
    out["severity"] = record.severity.map((s) => ({ type: s.type, score: s.score }));
  }
  const affectedIndex = new Map((record.affected ?? []).map((entry, index) => [entry, index]));
  out["affected"] = npmAffected.map((entry) =>
    affectedJson(entry, onDrop, `affected[${affectedIndex.get(entry) ?? -1}]`),
  );
  if (record.references !== undefined) {
    out["references"] = record.references.map((ref) => ({ type: ref.type, url: ref.url }));
  }
  if (record.credits !== undefined) {
    out["credits"] = record.credits.map((credit) => {
      const c: Mutable = { name: credit.name };
      if (credit.contact !== undefined) c["contact"] = [...credit.contact];
      put(c, "type", credit.type);
      return c;
    });
  }
  if (record.database_specific !== undefined) {
    put(out, "database_specific", databaseSpecificJson(record.database_specific, onDrop));
  }
  return out;
}
