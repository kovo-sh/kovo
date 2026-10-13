import {
  ADVISORY_RANGE_EVENT_KINDS,
  advisoryIdSchema,
  normalizeOsvTimestamp,
  osvTimestampToDate,
  packageNameSchema,
  type AdvisoryId,
  type AdvisoryRangeEventKind,
  type CweId,
  type MaliciousReason,
  type PackageName,
  type PackageVersion,
} from "@kovo/contracts";

import {
  INTRODUCED_ZERO,
  LIMIT_INFINITY,
  normalizedAdvisorySchema,
  type AdvisoryRange,
  type AdvisoryRangeEvent,
  type JsonObject,
  type NormalizedAdvisory,
} from "./model.js";
import {
  ghsaCweIdsSchema,
  malCwesSchema,
  osvRecordSchema,
  type OsvAffected,
  type OsvEvent,
  type OsvRange,
  type OsvRecord,
} from "./osv-schema.js";
import { sanitizeOsvRecord } from "./raw.js";
import { deriveSeverity, type SeverityAssessment } from "./severity.js";
import { coerceOsvVersion } from "./version.js";

// OSV/GHSA/MAL record → normalized npm advisory (docs/libraries/sandbox-ai-feeds.md §5.2).

/** Why a record could not be normalized at all. Nothing of it may be stored. */
export type NormalizeFailureReason =
  | "invalid_record" // types or bounds (the Zod issues say where)
  | "invalid_id"
  | "id_mismatch" // the record's ID differs from the ID the feed listed
  | "invalid_modified"
  | "invalid_withdrawn"
  | "wildcard_package" // OSV 1.9 `*`: every npm package; never acted on (docs/decisions/advisory.md)
  | "invalid_range"; // unknown range type, malformed event or unusable bound

/** A non-fatal observation, recorded with the advisory. Paths only: never the offending text. */
export type NormalizeDiagnosticCode =
  | "foreign_ecosystem_ignored"
  | "affected_without_package"
  | "invalid_package_name_ignored"
  | "git_range_ignored"
  | "range_without_introduced_ignored"
  | "mixed_fixed_and_last_affected"
  | "version_coerced"
  | "invalid_listed_version_ignored"
  | "invalid_alias_ignored"
  | "invalid_cwe_ignored"
  | "invalid_published_ignored"
  | "no_npm_affected_versions"
  | "summary_normalized"
  | "raw_member_dropped";

export interface NormalizeDiagnostic {
  readonly code: NormalizeDiagnosticCode;
  /** A JSON-path-like location in the record (`affected[2].ranges[0].events[1]`). */
  readonly path: string;
}

export interface NormalizeIssue {
  readonly path: string;
  readonly code: string;
}

export type NormalizeResult =
  | {
      readonly ok: true;
      readonly advisory: NormalizedAdvisory;
      readonly severity: SeverityAssessment;
      readonly diagnostics: readonly NormalizeDiagnostic[];
    }
  | {
      readonly ok: false;
      readonly reason: NormalizeFailureReason;
      readonly issues: readonly NormalizeIssue[];
    };

export interface NormalizeOptions {
  /** The ID the feed listed for this record; a different `id` fails with `id_mismatch`. */
  readonly expectedId?: AdvisoryId;
}

class RecordRejected extends Error {
  readonly reason: NormalizeFailureReason;
  readonly path: string;

  constructor(reason: NormalizeFailureReason, path: string) {
    super(reason);
    this.reason = reason;
    this.path = path;
  }
}

function fail(reason: NormalizeFailureReason, path: string): NormalizeResult {
  return { ok: false, reason, issues: [{ path, code: reason }] };
}

/** An OSV time in its canonical nine-digit form (contracts' shared parser) and as a `Date`. */
function parseOsvTime(text: string): { canonical: string; date: Date } | null {
  const canonical = normalizeOsvTimestamp(text);
  return canonical === null ? null : { canonical, date: osvTimestampToDate(canonical) };
}

/**
 * Invisible format characters (`\p{Cf}`: bidi embeddings, overrides, isolates and marks, zero-width
 * characters, the byte-order mark, soft hyphens, …) and unpaired surrogates. The summary is
 * untrusted text shown in the dashboard, P0 emails and webhooks, where these reorder or hide what is
 * displayed (Trojan Source); removing them loses nothing a reader can see.
 */
const INVISIBLE = /[\p{Cf}\p{Cs}]+/gu;

/**
 * One line of public text for display: invisible format characters removed, whitespace and
 * control characters collapsed to single spaces, at most 1000 characters.
 */
function normalizeSummary(summary: string | undefined): { value: string | null; changed: boolean } {
  if (summary === undefined) return { value: null, changed: false };
  let value = summary
    .replace(INVISIBLE, "")
    .replace(/[\s\p{Cc}]+/gu, " ")
    .trim();
  if (value.length > 1000) {
    value = value.slice(0, 1000);
    const last = value.charCodeAt(value.length - 1);
    if (last >= 0xd800 && last <= 0xdbff) value = value.slice(0, -1);
    value = value.trim();
  }
  return { value: value === "" ? null : value, changed: value !== summary };
}

function normalizeAliases(
  record: OsvRecord,
  id: AdvisoryId,
  diagnostics: NormalizeDiagnostic[],
): AdvisoryId[] {
  const aliases = new Set<AdvisoryId>();
  (record.aliases ?? []).forEach((alias, index) => {
    const parsed = advisoryIdSchema.safeParse(alias);
    if (!parsed.success) {
      diagnostics.push({ code: "invalid_alias_ignored", path: `aliases[${index}]` });
      return;
    }
    if (parsed.data !== id) aliases.add(parsed.data);
  });
  return [...aliases];
}

const CWE_TEXT = /^CWE-([1-9]\d{0,6})$/;

function parseCwe(text: string): CweId | null {
  const match = CWE_TEXT.exec(text);
  const value = match === null ? Number.NaN : Number(match[1]);
  return Number.isSafeInteger(value) && value <= 1_000_000 ? value : null;
}

/** CWE numbers from GHSA `database_specific.cwe_ids` and npm `affected[].database_specific.cwes`. */
function normalizeCwes(
  record: OsvRecord,
  npmAffected: readonly { readonly entry: OsvAffected; readonly index: number }[],
  diagnostics: NormalizeDiagnostic[],
): CweId[] {
  const found = new Set<CweId>();
  const add = (text: string, path: string) => {
    const cwe = parseCwe(text);
    if (cwe === null) diagnostics.push({ code: "invalid_cwe_ignored", path });
    else found.add(cwe);
  };
  const ghsaCwes = record.database_specific?.["cwe_ids"];
  if (ghsaCwes !== undefined && ghsaCwes !== null) {
    const ghsa = ghsaCweIdsSchema.safeParse(ghsaCwes);
    if (ghsa.success) ghsa.data.forEach((text, i) => add(text, `database_specific.cwe_ids[${i}]`));
    else diagnostics.push({ code: "invalid_cwe_ignored", path: "database_specific.cwe_ids" });
  }
  for (const { entry, index } of npmAffected) {
    const cwes = entry.database_specific?.["cwes"];
    if (cwes === undefined || cwes === null) continue;
    const parsed = malCwesSchema.safeParse(cwes);
    const path = `affected[${index}].database_specific.cwes`;
    if (parsed.success) parsed.data.forEach((cwe, i) => add(cwe.cweId, `${path}[${i}]`));
    else diagnostics.push({ code: "invalid_cwe_ignored", path });
  }
  return [...found].toSorted((a, b) => a - b);
}

/**
 * Malicious-package recognition (docs/decisions/advisory.md): an OpenSSF `MAL-` ID, an alias to a
 * `MAL-` record (GitHub malware advisories reach OSV as MAL records aliasing their GHSA ID, and a
 * GHSA may alias the MAL record), or CWE-506 "Embedded Malicious Code" (GitHub's compromised-release
 * advisories such as event-stream).
 */
function recognizeMalicious(
  id: AdvisoryId,
  aliases: readonly AdvisoryId[],
  cweIds: readonly CweId[],
): MaliciousReason | null {
  if (id.startsWith("MAL-")) return "mal_id";
  if (aliases.some((alias) => alias.startsWith("MAL-"))) return "mal_alias";
  if (cweIds.includes(506)) return "cwe_506";
  return null;
}

function eventOf(event: OsvEvent, path: string): { kind: AdvisoryRangeEventKind; text: string } {
  const present = ADVISORY_RANGE_EVENT_KINDS.filter((kind) => event[kind] !== undefined);
  const kind = present[0];
  if (present.length !== 1 || kind === undefined) throw new RecordRejected("invalid_range", path);
  return { kind, text: event[kind] ?? "" };
}

function normalizeEvent(
  event: OsvEvent,
  path: string,
  diagnostics: NormalizeDiagnostic[],
): AdvisoryRangeEvent {
  const { kind, text } = eventOf(event, path);
  if (kind === "introduced" && text === INTRODUCED_ZERO) return { kind, version: text };
  if (kind === "limit" && text === LIMIT_INFINITY) return { kind, version: text };
  const coerced = coerceOsvVersion(text);
  if (coerced === null) throw new RecordRejected("invalid_range", path);
  if (coerced.coerced) diagnostics.push({ code: "version_coerced", path });
  return { kind, version: coerced.version };
}

function normalizeRange(
  name: PackageName,
  range: OsvRange,
  path: string,
  diagnostics: NormalizeDiagnostic[],
): AdvisoryRange | null {
  if (range.type === "GIT") {
    diagnostics.push({ code: "git_range_ignored", path });
    return null;
  }
  if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") {
    throw new RecordRejected("invalid_range", `${path}.type`);
  }
  const events = range.events.map((event, i) =>
    normalizeEvent(event, `${path}.events[${i}]`, diagnostics),
  );
  if (!events.some((event) => event.kind === "introduced")) {
    // OSV requires an introduced event; without one the range affects nothing when evaluated.
    diagnostics.push({ code: "range_without_introduced_ignored", path });
    return null;
  }
  if (events.some((e) => e.kind === "fixed") && events.some((e) => e.kind === "last_affected")) {
    diagnostics.push({ code: "mixed_fixed_and_last_affected", path });
  }
  return { package: name, rangeType: range.type, events, explicitVersions: [] };
}

function normalizeListedVersions(
  versions: readonly string[],
  path: string,
  diagnostics: NormalizeDiagnostic[],
): PackageVersion[] {
  const result = new Set<PackageVersion>();
  versions.forEach((text, i) => {
    const coerced = coerceOsvVersion(text);
    if (coerced === null) {
      // No resolved package can have a version that is not exact SemVer, so nothing is lost.
      diagnostics.push({ code: "invalid_listed_version_ignored", path: `${path}[${i}]` });
      return;
    }
    if (coerced.coerced) diagnostics.push({ code: "version_coerced", path: `${path}[${i}]` });
    result.add(coerced.version);
  });
  return [...result];
}

/** The npm `affected[]` entries with their record index; others are counted and ignored. */
function npmEntries(
  record: OsvRecord,
  diagnostics: NormalizeDiagnostic[],
): { entry: OsvAffected; index: number; name: PackageName }[] {
  const result: { entry: OsvAffected; index: number; name: PackageName }[] = [];
  (record.affected ?? []).forEach((entry, index) => {
    const path = `affected[${index}]`;
    if (entry.package === undefined) {
      diagnostics.push({ code: "affected_without_package", path });
      return;
    }
    if (entry.package.ecosystem !== "npm") {
      diagnostics.push({ code: "foreign_ecosystem_ignored", path });
      return;
    }
    if (entry.package.name === "*") throw new RecordRejected("wildcard_package", `${path}.package`);
    const name = packageNameSchema.safeParse(entry.package.name);
    if (!name.success) {
      // Lockfile inventory validates names with the same schema, so no instance can match it.
      diagnostics.push({ code: "invalid_package_name_ignored", path: `${path}.package.name` });
      return;
    }
    result.push({ entry, index, name: name.data });
  });
  return result;
}

function normalizeRanges(
  entries: readonly { entry: OsvAffected; index: number; name: PackageName }[],
  diagnostics: NormalizeDiagnostic[],
): AdvisoryRange[] {
  const ranges: AdvisoryRange[] = [];
  for (const { entry, index, name } of entries) {
    const path = `affected[${index}]`;
    (entry.ranges ?? []).forEach((range, i) => {
      const normalized = normalizeRange(name, range, `${path}.ranges[${i}]`, diagnostics);
      if (normalized !== null) ranges.push(normalized);
    });
    const versions = normalizeListedVersions(entry.versions ?? [], `${path}.versions`, diagnostics);
    if (versions.length > 0) {
      ranges.push({ package: name, rangeType: null, events: [], explicitVersions: versions });
    }
  }
  if (ranges.length === 0) diagnostics.push({ code: "no_npm_affected_versions", path: "affected" });
  return ranges;
}

function normalizeParsed(
  record: OsvRecord,
  options: NormalizeOptions,
  diagnostics: NormalizeDiagnostic[],
): NormalizeResult {
  const idResult = advisoryIdSchema.safeParse(record.id);
  if (!idResult.success) return fail("invalid_id", "id");
  const id = idResult.data;
  if (options.expectedId !== undefined && options.expectedId !== id)
    return fail("id_mismatch", "id");

  const modified = parseOsvTime(record.modified);
  if (modified === null) return fail("invalid_modified", "modified");
  let withdrawnAt: Date | null = null;
  if (record.withdrawn !== undefined) {
    const withdrawn = parseOsvTime(record.withdrawn);
    if (withdrawn === null) return fail("invalid_withdrawn", "withdrawn");
    withdrawnAt = withdrawn.date;
  }
  let publishedAt: Date | null = null;
  if (record.published !== undefined) {
    const published = parseOsvTime(record.published);
    if (published === null)
      diagnostics.push({ code: "invalid_published_ignored", path: "published" });
    else publishedAt = published.date;
  }

  const entries = npmEntries(record, diagnostics);
  const ranges = normalizeRanges(entries, diagnostics);
  const aliases = normalizeAliases(record, id, diagnostics);
  const cweIds = normalizeCwes(record, entries, diagnostics);
  const maliciousReason = recognizeMalicious(id, aliases, cweIds);
  const severity = deriveSeverity({
    isGhsa: id.startsWith("GHSA-"),
    label: record.database_specific?.["severity"],
    entries: [...(record.severity ?? []), ...entries.flatMap(({ entry }) => entry.severity ?? [])],
  });
  const summary = normalizeSummary(record.summary);
  if (summary.changed) diagnostics.push({ code: "summary_normalized", path: "summary" });

  const raw: JsonObject = sanitizeOsvRecord(
    record,
    entries.map(({ entry }) => entry),
    (path) => diagnostics.push({ code: "raw_member_dropped", path }),
  );
  const candidate: NormalizedAdvisory = {
    id,
    aliases,
    ecosystem: "npm",
    summary: summary.value,
    severity: severity.severity,
    severitySource: severity.source,
    severityReason: severity.reason,
    cvssScore: severity.score ?? null,
    cvssVector: severity.vector ?? null,
    cweIds,
    isMalicious: maliciousReason !== null,
    maliciousReason,
    publishedAt,
    modifiedAt: modified.date,
    sourceModified: modified.canonical,
    withdrawnAt,
    ranges,
    raw,
  };
  const checked = normalizedAdvisorySchema.safeParse(candidate);
  if (!checked.success) {
    return {
      ok: false,
      reason: "invalid_record",
      issues: checked.error.issues.map((issue) => ({
        path: issue.path.map(String).join("."),
        code: issue.code,
      })),
    };
  }
  return { ok: true, advisory: checked.data, severity, diagnostics };
}

/**
 * Normalizes one OSV record (hostile public input) into Kovo's npm advisory model: ID, aliases,
 * summary, severity with its source and reason, CWE numbers, malicious flag, publication,
 * modification and withdrawal times, the npm `affected[]` ranges and listed versions, and the
 * sanitized public record. Foreign-ecosystem entries are ignored. Returns `ok: false` with a stable
 * reason when the record cannot be used as a whole.
 */
export function normalizeOsvRecord(
  input: unknown,
  options: NormalizeOptions = {},
): NormalizeResult {
  const parsed = osvRecordSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      reason: "invalid_record",
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.map(String).join("."),
        code: issue.code,
      })),
    };
  }
  const diagnostics: NormalizeDiagnostic[] = [];
  try {
    return normalizeParsed(parsed.data, options, diagnostics);
  } catch (error) {
    if (error instanceof RecordRejected) return fail(error.reason, error.path);
    throw error;
  }
}
