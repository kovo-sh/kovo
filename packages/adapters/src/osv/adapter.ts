import { advisoryIdSchema, type AdvisoryId } from "@kovo/contracts";
import { z } from "zod";

import { limitByteStream, readJsonLimited } from "../http/body.js";
import { getWithRetries, type HttpClientDeps } from "../http/client.js";
import { digestTap } from "../http/digest.js";
import type { HttpCallContext } from "../http/errors.js";
import { DEFAULT_RETRY_POLICY, validateRetryPolicy, type RetryPolicy } from "../http/retry.js";
import { fetchTransport, timerSleep, type HttpTransport, type Sleep } from "../http/transport.js";
import type { Clock } from "../ports/clock.js";
import { IntegrityError, LimitExceededError, UnavailableError } from "../ports/errors.js";
import {
  OSV_QUERY_MAX_PAGES,
  OSV_QUERY_PAGE_MAX_BYTES,
  OSV_RECORD_MAX_BYTES,
  osvVersionQuerySchema,
  type OsvVersionQuery,
  osvChangeListPage,
  osvChangeListRequestSchema,
  type OsvChangeListRequest,
  type OsvChangeListResult,
  type OsvExportItem,
  type OsvFeedPort,
  type OsvModifiedEntry,
  type OsvRecord,
  type OsvTimestamp,
} from "../ports/osv-feed.js";
import { readChangeList } from "./change-list.js";
import {
  OSV_CHANGE_LIST_OBJECT,
  OSV_EXPORT_OBJECT,
  openGeneration,
  readObjectInfo,
  verifyObjectBytes,
  type GcsObjectInfo,
} from "./gcs.js";
import { osvExportItem, osvRecordFromDocument } from "./record.js";
import { readZipEntries } from "./zip.js";

// The real OsvFeedPort (BUILD_PLAN item 11). Change list and full export come from OSV's public
// bucket by object generation (gcs.ts); single records from `api.osv.dev/v1/vulns/{id}`, which is
// not edge-cached; OSV's own matching for one version from `api.osv.dev/v1/query`, a read-only JSON
// POST. Every read has a deadline, bounded retries and byte limits.

export const OSV_API_ORIGIN = "https://api.osv.dev";

export function vulnerabilityUrl(id: AdvisoryId): URL {
  return new URL(`/v1/vulns/${encodeURIComponent(id)}`, OSV_API_ORIGIN);
}

export const OSV_QUERY_URL = new URL("/v1/query", OSV_API_ORIGIN);

/** One page of `/v1/query`: only the IDs are kept; the full records are discarded. */
const queryPageSchema = z.object({
  vulns: z
    .array(z.object({ id: advisoryIdSchema }))
    .max(10_000)
    .optional(),
  next_page_token: z.string().min(1).max(4096).optional(),
});

export interface OsvFeedLimits {
  /** Largest change list accepted (8.66 MB on 2026-09-26). */
  readonly changeListMaxBytes: number;
  /** Largest export accepted (216.6 MB compressed on 2026-09-26). */
  readonly exportMaxBytes: number;
  /** Whole-transfer deadline for the change list download. */
  readonly changeListTimeoutMs: number;
  /** Longest wait for the next chunk of a download (never counts the consumer's own time). */
  readonly idleTimeoutMs: number;
}

export const DEFAULT_OSV_FEED_LIMITS: OsvFeedLimits = {
  changeListMaxBytes: 256 * 1024 * 1024,
  exportMaxBytes: 1024 * 1024 * 1024,
  changeListTimeoutMs: 5 * 60 * 1000,
  idleTimeoutMs: 60 * 1000,
};

export interface OsvHttpFeedOptions {
  readonly clock: Clock;
  /** Defaults to the global `fetch`. Tests route the fixed OSV origins to a local fake. */
  readonly transport?: HttpTransport;
  readonly sleep?: Sleep;
  readonly retry?: RetryPolicy;
  /** Deadline for one attempt of a small request (metadata, one record). */
  readonly requestTimeoutMs?: number;
  readonly limits?: Partial<OsvFeedLimits>;
}

const USER_AGENT = "kovo-osv-feed/1 (+https://kovo.dev)";

/** How often a generation that vanished between metadata and download is re-resolved. */
const GENERATION_RACE_ATTEMPTS = 3;

export class OsvHttpFeed implements OsvFeedPort {
  readonly #http: HttpClientDeps;
  readonly #limits: OsvFeedLimits;

  constructor(options: OsvHttpFeedOptions) {
    this.#http = {
      transport: options.transport ?? fetchTransport,
      clock: options.clock,
      sleep: options.sleep ?? timerSleep,
      retry: validateRetryPolicy(options.retry ?? DEFAULT_RETRY_POLICY),
      requestTimeoutMs: options.requestTimeoutMs ?? 30_000,
      userAgent: USER_AGENT,
    };
    this.#limits = { ...DEFAULT_OSV_FEED_LIMITS, ...options.limits };
  }

  async listModifiedSince(request: OsvChangeListRequest): Promise<OsvChangeListResult> {
    const { cursor, knownGeneration, maxEntries } = osvChangeListRequestSchema.parse(request);
    const context: HttpCallContext = { service: "osv", operation: "listModifiedSince" };
    for (let attempt = 1; ; attempt += 1) {
      const info = await readObjectInfo(this.#http, OSV_CHANGE_LIST_OBJECT, context);
      if (knownGeneration !== null && info.generation === knownGeneration) {
        return { outcome: "unchanged", generation: info.generation };
      }
      const download = await openGeneration(
        this.#http,
        info,
        context,
        this.#limits.changeListTimeoutMs,
      );
      if (download.outcome === "gone") {
        if (attempt >= GENERATION_RACE_ATTEMPTS) {
          throw new UnavailableError({
            ...context,
            reason: "server_error",
            code: "generation_gone",
          });
        }
        continue;
      }
      const entries = await this.#readEntries(download.response, info, cursor?.modified ?? null);
      const page = osvChangeListPage(entries, cursor, maxEntries);
      return { outcome: "changed", generation: info.generation, ...page };
    }
  }

  async #readEntries(
    response: Response,
    info: GcsObjectInfo,
    stopBefore: OsvTimestamp | null,
  ): Promise<readonly OsvModifiedEntry[]> {
    const context: HttpCallContext = { service: "osv", operation: "listModifiedSince" };
    if (response.body === null) throw new IntegrityError({ ...context, code: "empty_object" });
    const tap = digestTap(
      limitByteStream(response.body, this.#limits.changeListMaxBytes, context, {
        idleTimeoutMs: this.#limits.idleTimeoutMs,
      }),
      ["md5"],
    );
    const read = await readChangeList(tap.stream, stopBefore);
    if (read.readToEnd) verifyObjectBytes(info, tap.bytes(), tap.digest("md5"), context);
    return read.entries;
  }

  async fetchRecord(id: AdvisoryId): Promise<OsvRecord | null> {
    const parsedId = advisoryIdSchema.parse(id);
    const context: HttpCallContext = { service: "osv", operation: "fetchRecord" };
    return getWithRetries(
      this.#http,
      {
        url: vulnerabilityUrl(parsedId),
        context,
        headers: { accept: "application/json" },
        handledStatuses: [404],
      },
      async (response, callerSignal) => {
        if (response.status === 404) {
          await response.body?.cancel().catch(() => undefined);
          return null;
        }
        const document = await readJsonLimited(
          response,
          OSV_RECORD_MAX_BYTES,
          context,
          callerSignal,
        );
        return osvRecordFromDocument(document, parsedId, context);
      },
    );
  }

  async queryVersion(query: OsvVersionQuery): Promise<readonly AdvisoryId[]> {
    const { name, version } = osvVersionQuerySchema.parse(query);
    const context: HttpCallContext = { service: "osv", operation: "queryVersion" };
    const ids = new Set<AdvisoryId>();
    let pageToken: string | undefined;
    for (let page = 0; page < OSV_QUERY_MAX_PAGES; page += 1) {
      const body = JSON.stringify({
        package: { ecosystem: "npm", name },
        version,
        ...(pageToken === undefined ? {} : { page_token: pageToken }),
      });
      const parsed = await getWithRetries(
        this.#http,
        { url: OSV_QUERY_URL, context, headers: { accept: "application/json" }, jsonQuery: body },
        async (response, callerSignal) =>
          queryPageSchema.safeParse(
            await readJsonLimited(response, OSV_QUERY_PAGE_MAX_BYTES, context, callerSignal),
          ),
      );
      if (!parsed.success) throw new IntegrityError({ ...context, code: "malformed_query_page" });
      for (const vuln of parsed.data.vulns ?? []) ids.add(vuln.id);
      pageToken = parsed.data.next_page_token;
      if (pageToken === undefined) return [...ids].toSorted();
    }
    throw new LimitExceededError({
      ...context,
      code: "too_many_query_pages",
      // A page count, not a byte size, was exceeded.
      limitBytes: 0,
    });
  }

  async *exportAll(): AsyncIterable<OsvExportItem> {
    const context: HttpCallContext = { service: "osv", operation: "exportAll" };
    let download: Awaited<ReturnType<typeof openGeneration>> | undefined;
    let info: GcsObjectInfo | undefined;
    for (let attempt = 1; attempt <= GENERATION_RACE_ATTEMPTS; attempt += 1) {
      info = await readObjectInfo(this.#http, OSV_EXPORT_OBJECT, context);
      // No whole-transfer deadline: the caller ingests records between reads, which can take
      // longer than any fixed download budget; stalls are bounded by the idle timeout instead.
      download = await openGeneration(this.#http, info, context, null);
      if (download.outcome === "stream") break;
    }
    if (download?.outcome !== "stream" || info === undefined) {
      throw new UnavailableError({ ...context, reason: "server_error", code: "generation_gone" });
    }
    const body = download.response.body;
    if (body === null) throw new IntegrityError({ ...context, code: "empty_object" });
    const tap = digestTap(
      limitByteStream(body, this.#limits.exportMaxBytes, context, {
        idleTimeoutMs: this.#limits.idleTimeoutMs,
      }),
      ["md5"],
    );
    const entries = readZipEntries(
      tap.stream,
      // Compressed entries are never larger than the inflated bound plus deflate overhead.
      { maxCompressedBytes: OSV_RECORD_MAX_BYTES + 64 * 1024, maxEntryBytes: OSV_RECORD_MAX_BYTES },
      context,
    );
    for await (const entry of entries) {
      const item = osvExportItem(entry);
      if (item !== null) yield item;
    }
    verifyObjectBytes(info, tap.bytes(), tap.digest("md5"), context);
  }
}
