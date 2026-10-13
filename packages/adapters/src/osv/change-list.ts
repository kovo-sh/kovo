import { IntegrityError } from "../ports/errors.js";
import {
  compareOsvTimestamps,
  osvModifiedEntrySchema,
  type OsvModifiedEntry,
  type OsvTimestamp,
} from "../ports/osv-feed.js";

// The OSV per-ecosystem change list, `npm/modified_id.csv`: no header, one `<RFC3339
// modified>,<ID>` line per record, newest first (docs/libraries/sandbox-ai-feeds.md §5.1).

export interface ChangeListRead {
  /** Entries read, in file order (newest first). */
  readonly entries: readonly OsvModifiedEntry[];
  /** Whether the file was read to its end (false when reading stopped at `stopBefore`). */
  readonly readToEnd: boolean;
}

const OPERATION = "listModifiedSince";

function malformed(code: string, vendorCause?: unknown): IntegrityError {
  return new IntegrityError({ service: "osv", operation: OPERATION, code, vendorCause });
}

/** Parses one change-list line; IntegrityError when it is not `<timestamp>,<advisory ID>`. */
export function parseChangeListLine(line: string): OsvModifiedEntry {
  const comma = line.indexOf(",");
  if (comma < 0) throw malformed("malformed_change_list");
  const parsed = osvModifiedEntrySchema.safeParse({
    modified: line.slice(0, comma),
    id: line.slice(comma + 1),
  });
  if (!parsed.success) throw malformed("malformed_change_list", parsed.error);
  return parsed.data;
}

/**
 * Reads change-list lines from `source`, newest first, and stops (cancelling the source) at the
 * first entry strictly older than `stopBefore`: the file is sorted, so nothing after it can be
 * newer. Entries at exactly `stopBefore` are kept (records can share an instant). The order the
 * early stop relies on is checked on everything read: a line newer than its predecessor is an
 * IntegrityError, as is any malformed line (the file is machine-written; a bad line means
 * corruption or a format change, and failing loudly trips the stale-poll alert).
 */
export async function readChangeList(
  source: ReadableStream<Uint8Array>,
  stopBefore: OsvTimestamp | null,
): Promise<ChangeListRead> {
  const reader = source.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const entries: OsvModifiedEntry[] = [];
  let previous: OsvTimestamp | null = null;
  let pending = "";

  // Returns false to stop reading.
  const take = (rawLine: string): boolean => {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line === "") return true;
    const entry = parseChangeListLine(line);
    if (previous !== null && compareOsvTimestamps(entry.modified, previous) > 0) {
      throw malformed("change_list_unsorted");
    }
    previous = entry.modified;
    if (stopBefore !== null && compareOsvTimestamps(entry.modified, stopBefore) < 0) return false;
    entries.push(entry);
    return true;
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      let text: string;
      try {
        text = done ? decoder.decode() : decoder.decode(value, { stream: true });
      } catch (error) {
        throw malformed("malformed_change_list", error);
      }
      pending += text;
      const lines = pending.split("\n");
      pending = done ? "" : (lines.pop() ?? "");
      for (const line of lines) {
        if (!take(line)) {
          await reader.cancel().catch(() => undefined);
          return { entries, readToEnd: false };
        }
      }
      if (done) return { entries, readToEnd: true };
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}
