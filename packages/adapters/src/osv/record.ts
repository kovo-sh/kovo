import { advisoryEcosystemSchema, advisoryIdSchema, type AdvisoryId } from "@kovo/contracts";
import { z } from "zod";

import { jsonObjectSchema, type JsonObject, type JsonValue } from "../ports/common.js";
import { IntegrityError } from "../ports/errors.js";
import {
  OSV_EXPORT_REJECTIONS,
  OSV_RECORD_MAX_BYTES,
  osvRecordSchema,
  osvTimestampSchema,
  type OsvExportItem,
  type OsvExportRejection,
  type OsvRecord,
} from "../ports/osv-feed.js";

// The OSV record envelope, shared by the real adapter and the fake so both hand callers the same
// view of a document. The port validates only the envelope; `@kovo/core/advisory` normalizes the
// rest (docs/decisions/adapters.md "OSV records"). One normalization happens here: `affected[]`
// entries for other ecosystems are removed (docs/decisions/adapter-feeds.md "Foreign-ecosystem entries are removed from OSV records at the adapter").

const envelopeSchema = z.looseObject({
  id: advisoryIdSchema,
  modified: osvTimestampSchema,
  withdrawn: osvTimestampSchema.optional(),
  affected: z.array(jsonObjectSchema).optional(),
});

/**
 * Whether an `affected[]` entry is for an ecosystem Kovo covers (`advisoryEcosystemSchema`: the
 * public npm registry only, SPEC "npm and pnpm, public npm registry only"). OSV spells it `npm`.
 */
function isCoveredEcosystem(entry: JsonObject): boolean {
  const pkg = entry["package"];
  if (typeof pkg !== "object" || pkg === null || Array.isArray(pkg)) return false;
  return advisoryEcosystemSchema.safeParse((pkg as Record<string, JsonValue>)["ecosystem"]).success;
}

export interface OsvRecordContext {
  readonly operation: string;
}

/**
 * Validates an OSV document's envelope and returns the port record. `affected[]` keeps only npm
 * entries (npm records carry Maven, PyPI, NuGet or GitHub Actions entries too, and a PyPI package
 * can share an npm package's name). IntegrityError when the document is malformed, larger than
 * {@link OSV_RECORD_MAX_BYTES} once serialized, or has an ID other than `expectedId`.
 */
export function osvRecordFromDocument(
  document: unknown,
  expectedId: AdvisoryId | null,
  context: OsvRecordContext,
): OsvRecord {
  const fail = (code: string, vendorCause?: unknown) =>
    new IntegrityError({ service: "osv", operation: context.operation, code, vendorCause });
  const raw = jsonObjectSchema.safeParse(document);
  if (!raw.success) throw fail("malformed_record", raw.error);
  const envelope = envelopeSchema.safeParse(raw.data);
  if (!envelope.success) throw fail("malformed_record", envelope.error);
  if (expectedId !== null && envelope.data.id !== expectedId) throw fail("record_id_mismatch");

  const filtered: JsonObject = { ...raw.data };
  if (envelope.data.affected !== undefined) {
    filtered["affected"] = envelope.data.affected.filter(isCoveredEcosystem);
  }
  if (new TextEncoder().encode(JSON.stringify(filtered)).byteLength > OSV_RECORD_MAX_BYTES) {
    throw fail("record_too_large");
  }
  return osvRecordSchema.parse({
    id: envelope.data.id,
    modified: envelope.data.modified,
    withdrawn: envelope.data.withdrawn ?? null,
    raw: filtered,
  });
}

/** An entry of the export archive: its file name and bytes (null when too large to read). */
export interface OsvExportEntry {
  readonly name: string;
  readonly data: Uint8Array | null;
}

function isExportRejection(code: string | undefined): code is OsvExportRejection {
  return (OSV_EXPORT_REJECTIONS as readonly (string | undefined)[]).includes(code);
}

/**
 * The export item for one archive entry, shared by the real adapter and the fake: null for a file
 * that is not a record (anything but `*.json`), otherwise the record, or a rejection when the entry
 * cannot be read as one (docs/decisions/adapter-feeds.md "One bad export entry is reported").
 */
export function osvExportItem(entry: OsvExportEntry): OsvExportItem | null {
  if (!entry.name.endsWith(".json")) return null;
  const id = advisoryIdSchema.safeParse(entry.name.slice(0, -".json".length));
  if (!id.success) return { kind: "rejected", id: null, code: "unexpected_entry" };
  if (entry.data === null) return { kind: "rejected", id: id.data, code: "record_too_large" };
  let document: unknown;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(entry.data)) as unknown;
  } catch {
    return { kind: "rejected", id: id.data, code: "malformed_record" };
  }
  try {
    return {
      kind: "record",
      record: osvRecordFromDocument(document, id.data, { operation: "exportAll" }),
    };
  } catch (error) {
    if (error instanceof IntegrityError && isExportRejection(error.code)) {
      return { kind: "rejected", id: id.data, code: error.code };
    }
    throw error;
  }
}
