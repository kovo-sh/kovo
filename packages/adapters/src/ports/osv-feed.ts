import {
  advisoryIdSchema,
  normalizeOsvTimestamp,
  packageNameSchema,
  packageVersionSchema,
  type AdvisoryId,
} from "@kovo/contracts";
import { z } from "zod";

import { jsonObjectSchema } from "./common.js";

// OsvFeedPort: the OSV npm advisory feed. SPEC: "`pollOsv` | Every 5 minutes | OSV npm
// modified-record feed, then changed records; periodic full reconciliation"; "Persist source cursors
// only after durable ingestion." Notes: docs/libraries/sandbox-ai-feeds.md §5.
//
// Implementations (BUILD_PLAN item 11; status in docs/status/adapters.md): real HTTP client that
// polls the `npm/modified_id.csv` object metadata by generation (not the edge-cached public URL),
// reads records from `api.osv.dev/v1/vulns/{id}` and streams `npm/all.zip` for reconciliation; fake
// serving scripted records and a scripted change list.
//
// Everything here is a side-effect-free read: UnavailableError and RateLimitedError are retryable.
// Records are hostile input: the port validates only the envelope (ID, timestamps, JSON shape and
// size); `@kovo/core/advisory` normalizes the OSV document itself.

// ---- OSV timestamps (variable fractional precision; must not be compared as JS Dates) ----

// The parser is contracts' `normalizeOsvTimestamp`, shared with `@kovo/core/advisory`, so the
// canonical `modified` of the envelope and of the normalized document are byte-identical
// (docs/decisions/adapters.md). Contracts' `osvTimestampToDate` gives the millisecond `Date`.

/** A canonical OSV timestamp (nine fractional digits, `Z`). Accepts raw OSV input and normalizes. */
export const osvTimestampSchema = z
  .string()
  .transform((text, ctx) => {
    const canonical = normalizeOsvTimestamp(text);
    if (canonical === null) {
      ctx.addIssue({ code: "custom", message: "must be an RFC 3339 UTC timestamp" });
      return z.NEVER;
    }
    return canonical;
  })
  .brand<"OsvTimestamp">();
export type OsvTimestamp = z.output<typeof osvTimestampSchema>;

/** Orders canonical OSV timestamps. */
export function compareOsvTimestamps(a: OsvTimestamp, b: OsvTimestamp): -1 | 0 | 1 {
  return a < b ? -1 : a > b ? 1 : 0;
}

// ---- Change list and cursor ----

export const osvModifiedEntrySchema = z.strictObject({
  id: advisoryIdSchema,
  modified: osvTimestampSchema,
});
export type OsvModifiedEntry = z.output<typeof osvModifiedEntrySchema>;

/**
 * The durable `pollOsv` cursor: the newest `modified` fully ingested plus the IDs already ingested
 * at exactly that instant (several records can share a timestamp, and a poll can stop between them).
 */
export const osvCursorSchema = z.strictObject({
  modified: osvTimestampSchema,
  idsAtModified: z.array(advisoryIdSchema).max(10_000),
});
export type OsvCursor = z.output<typeof osvCursorSchema>;

function compareEntries(a: OsvModifiedEntry, b: OsvModifiedEntry): number {
  return compareOsvTimestamps(a.modified, b.modified) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/**
 * The entries not yet ingested under `cursor`, oldest first, deduplicated by (modified, id). An
 * entry at the cursor's own instant is new unless its ID is in `idsAtModified`.
 */
export function entriesAfterCursor(
  entries: readonly OsvModifiedEntry[],
  cursor: OsvCursor | null,
): OsvModifiedEntry[] {
  const seen = new Set<string>();
  const pending: OsvModifiedEntry[] = [];
  const done = new Set<AdvisoryId>(cursor?.idsAtModified ?? []);
  for (const entry of entries.toSorted(compareEntries)) {
    const key = `${entry.modified} ${entry.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (cursor !== null) {
      const order = compareOsvTimestamps(entry.modified, cursor.modified);
      if (order < 0 || (order === 0 && done.has(entry.id))) continue;
    }
    pending.push(entry);
  }
  return pending;
}

/** Largest change-list page a poll may ask for. */
export const OSV_CHANGE_LIST_MAX_ENTRIES = 10_000;

/** A Cloud Storage object generation (a decimal int64, kept as a string). */
export const osvGenerationSchema = z
  .string()
  .regex(/^[1-9][0-9]{0,24}$/, { error: "must be a storage generation" });

export const osvChangeListRequestSchema = z.strictObject({
  /** The durable `pollOsv` cursor; null before the first ingestion. */
  cursor: osvCursorSchema.nullable(),
  /**
   * The generation of the last poll that returned `complete: true` and was fully ingested; the
   * adapter answers `unchanged` while the change list still has it. Pass null (or that older
   * completed generation) while paging through a generation, or the rest would never be read.
   */
  knownGeneration: osvGenerationSchema.nullable(),
  maxEntries: z.int().min(1).max(OSV_CHANGE_LIST_MAX_ENTRIES),
});
export type OsvChangeListRequest = z.output<typeof osvChangeListRequestSchema>;

/**
 * One page of the change list for `cursor`: {@link entriesAfterCursor} first (dropping entries
 * before the cursor and ties already ingested), then the oldest `maxEntries` of what remains. Both
 * the real adapter and the fake page this way, so a poll makes progress whenever anything is left
 * to ingest, however many already-ingested records share the cursor's instant.
 */
export function osvChangeListPage(
  entries: readonly OsvModifiedEntry[],
  cursor: OsvCursor | null,
  maxEntries: number,
): { readonly entries: OsvModifiedEntry[]; readonly complete: boolean } {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw new RangeError("maxEntries must be a positive integer");
  }
  const pending = entriesAfterCursor(entries, cursor);
  return { entries: pending.slice(0, maxEntries), complete: pending.length <= maxEntries };
}

/**
 * The cursor after durably ingesting `ingested` (entries returned by {@link entriesAfterCursor}, in
 * order, possibly a prefix of them). Call it only after the records are committed.
 */
export function advanceOsvCursor(
  cursor: OsvCursor | null,
  ingested: readonly OsvModifiedEntry[],
): OsvCursor | null {
  let next = cursor;
  for (const entry of ingested) {
    if (next === null || compareOsvTimestamps(entry.modified, next.modified) > 0) {
      next = { modified: entry.modified, idsAtModified: [entry.id] };
    } else if (entry.modified === next.modified && !next.idsAtModified.includes(entry.id)) {
      next = { modified: next.modified, idsAtModified: [...next.idsAtModified, entry.id] };
    } else if (compareOsvTimestamps(entry.modified, next.modified) < 0) {
      throw new RangeError("ingested entries must not precede the cursor");
    }
  }
  return next;
}

// ---- Records ----

/** Largest single OSV record accepted (the biggest npm records are well under 1 MiB). */
export const OSV_RECORD_MAX_BYTES = 2 * 1024 * 1024;

/**
 * An OSV record: validated envelope fields plus the full untrusted document for
 * `@kovo/core/advisory` to normalize (and for `advisories.raw`).
 */
export const osvRecordSchema = z.strictObject({
  id: advisoryIdSchema,
  modified: osvTimestampSchema,
  /** Present when the record is withdrawn (SPEC: withdrawal withdraws its findings). */
  withdrawn: osvTimestampSchema.nullable(),
  raw: jsonObjectSchema,
});
export type OsvRecord = z.output<typeof osvRecordSchema>;

/**
 * Why an entry of the full export could not be handed over as a record: its `.json` name is not an
 * advisory ID, its bytes are not a UTF-8 JSON document or its envelope fails validation, it names
 * another ID than its file name, or it exceeds {@link OSV_RECORD_MAX_BYTES}.
 */
export const OSV_EXPORT_REJECTIONS = [
  "unexpected_entry",
  "malformed_record",
  "record_id_mismatch",
  "record_too_large",
] as const;
export type OsvExportRejection = (typeof OSV_EXPORT_REJECTIONS)[number];

/** One entry of the full export: a record, or an entry that could not be read as one. */
export type OsvExportItem =
  | { readonly kind: "record"; readonly record: OsvRecord }
  | {
      readonly kind: "rejected";
      /** The advisory the entry's file name names; null when the name is no advisory ID. */
      readonly id: AdvisoryId | null;
      readonly code: OsvExportRejection;
    };

export type OsvChangeListResult =
  | {
      /** The change list object has the generation the caller already processed. */
      readonly outcome: "unchanged";
      readonly generation: string;
    }
  | {
      readonly outcome: "changed";
      /** Storage generation of the change list read (see `knownGeneration`). */
      readonly generation: string;
      /** {@link osvChangeListPage}: entries not yet ingested under the cursor, oldest first. */
      readonly entries: readonly OsvModifiedEntry[];
      /** False when more entries remain beyond `maxEntries` (ingest, advance the cursor, poll again). */
      readonly complete: boolean;
    };

/** OSV's server-side matching for one npm package version (`POST /v1/query`). */
export const osvVersionQuerySchema = z.strictObject({
  name: packageNameSchema,
  version: packageVersionSchema,
});
export type OsvVersionQuery = z.infer<typeof osvVersionQuerySchema>;

/** The most result pages one version query follows (OSV pages large result sets). */
export const OSV_QUERY_MAX_PAGES = 20;
/** One result page: full records, so far larger than a single record. */
export const OSV_QUERY_PAGE_MAX_BYTES = 32 * 1024 * 1024;

export interface OsvFeedPort {
  /**
   * Reads the npm change list (`<modified>,<id>` lines, newest first in the file) and returns the
   * page {@link osvChangeListPage} selects for `cursor`: entries at the cursor's instant that the
   * cursor already lists are dropped BEFORE the `maxEntries` cut, so a page is never filled with
   * records that were ingested already. `cursor: null` pages from the oldest entry. Callers advance
   * the cursor with {@link advanceOsvCursor} after durable ingestion and poll again while
   * `complete` is false.
   */
  listModifiedSince(request: OsvChangeListRequest): Promise<OsvChangeListResult>;

  /** One record by ID, or null when OSV has none (HTTP 404). IntegrityError if `raw.id` differs. */
  fetchRecord(id: AdvisoryId): Promise<OsvRecord | null>;

  /**
   * Streams the full export for the initial load and periodic reconciliation: every npm record
   * (withdrawn ones included) as a `record` item. An entry that is not a usable record (see
   * {@link OSV_EXPORT_REJECTIONS}) is a `rejected` item and the iteration goes on, so one bad
   * upstream record never blocks reconciling the rest. Callers leave a rejected advisory's stored
   * state as it is (it is not absent from OSV) and alert on rejections.
   *
   * Iteration errors with UnavailableError on a broken download and IntegrityError when the archive
   * itself is corrupt (entry CRC or sizes, the object's size or MD5, layouts a forward-only reader
   * cannot trust); restart from the beginning (the export is immutable per generation).
   */
  exportAll(): AsyncIterable<OsvExportItem>;

  /**
   * The IDs of the advisories OSV's own matcher says affect an npm package version
   * (`POST api.osv.dev/v1/query`, every page), sorted and unique: an independent check of core's
   * range evaluation (plans/site-scanner.md §7.1). LimitExceededError past OSV_QUERY_MAX_PAGES
   * pages or OSV_QUERY_PAGE_MAX_BYTES per page.
   */
  queryVersion(query: OsvVersionQuery): Promise<readonly AdvisoryId[]>;
}
