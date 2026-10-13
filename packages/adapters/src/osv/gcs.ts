import { z } from "zod";

import { getWithRetries, sendGet, type HttpClientDeps } from "../http/client.js";
import { malformedDocument, readJsonLimited } from "../http/body.js";
import type { HttpCallContext } from "../http/errors.js";
import { withRetries } from "../http/retry.js";
import { deadlineSignal, headersDeadline } from "../http/transport.js";
import { IntegrityError } from "../ports/errors.js";
import { osvGenerationSchema } from "../ports/osv-feed.js";

// OSV's public Cloud Storage bucket, read through the JSON API by object generation. The public
// object URLs are edge-cached for up to an hour (`cache-control: public, max-age=3600`, observed
// `age: 2869` on a stale generation), so polling reads the object metadata and then downloads that
// exact generation, which is immutable (docs/libraries/sandbox-ai-feeds.md §5.1). No credentials:
// the bucket is public.

export const GCS_ORIGIN = "https://storage.googleapis.com";
export const OSV_BUCKET = "osv-vulnerabilities";
/** The npm change list: `<modified>,<id>` lines, newest first. */
export const OSV_CHANGE_LIST_OBJECT = "npm/modified_id.csv";
/** The full npm export, one `<id>.json` per record, withdrawn records included. */
export const OSV_EXPORT_OBJECT = "npm/all.zip";

export function objectMetadataUrl(object: string): URL {
  return new URL(`/storage/v1/b/${OSV_BUCKET}/o/${encodeURIComponent(object)}`, GCS_ORIGIN);
}

export function objectMediaUrl(object: string, generation: string): URL {
  const url = new URL(
    `/download/storage/v1/b/${OSV_BUCKET}/o/${encodeURIComponent(object)}`,
    GCS_ORIGIN,
  );
  url.searchParams.set("alt", "media");
  url.searchParams.set("generation", generation);
  return url;
}

const objectMetadataSchema = z.looseObject({
  bucket: z.string(),
  name: z.string(),
  generation: osvGenerationSchema,
  size: z.string().regex(/^\d{1,15}$/),
  md5Hash: z
    .string()
    .regex(/^[A-Za-z0-9+/]{22}==$/)
    .optional(),
});

export interface GcsObjectInfo {
  readonly object: string;
  readonly generation: string;
  readonly size: number;
  /** MD5 of the object's bytes (absent for composite objects). */
  readonly md5: Buffer | null;
}

const METADATA_MAX_BYTES = 64 * 1024;

/** Reads an object's current generation, size and MD5. */
export async function readObjectInfo(
  deps: HttpClientDeps,
  object: string,
  context: HttpCallContext,
  signal?: AbortSignal,
): Promise<GcsObjectInfo> {
  return getWithRetries(
    deps,
    { url: objectMetadataUrl(object), context, signal, headers: { accept: "application/json" } },
    async (response, callerSignal) => {
      const document = await readJsonLimited(response, METADATA_MAX_BYTES, context, callerSignal);
      const parsed = objectMetadataSchema.safeParse(document);
      if (!parsed.success) throw malformedDocument(context, "malformed_object_metadata");
      if (parsed.data.bucket !== OSV_BUCKET || parsed.data.name !== object) {
        throw malformedDocument(context, "object_metadata_mismatch");
      }
      return {
        object,
        generation: parsed.data.generation,
        size: Number(parsed.data.size),
        md5: parsed.data.md5Hash === undefined ? null : Buffer.from(parsed.data.md5Hash, "base64"),
      };
    },
  );
}

export type GenerationDownload =
  | { readonly outcome: "stream"; readonly response: Response }
  /** The bucket no longer serves that generation (it was replaced after the metadata read). */
  | { readonly outcome: "gone" };

/**
 * Opens the download of exactly `info.generation`. Only the request phase is retried. With
 * `transferTimeoutMs`, one deadline covers the request and the whole body; with null, only the
 * response headers have a deadline (`deps.requestTimeoutMs`) and the caller bounds the body by an
 * idle timeout instead, so a slow consumer of a long download is never cut off. The caller checks
 * size and MD5 when it reads to the end.
 */
export async function openGeneration(
  deps: HttpClientDeps,
  info: GcsObjectInfo,
  context: HttpCallContext,
  transferTimeoutMs: number | null,
  signal?: AbortSignal,
): Promise<GenerationDownload> {
  const request = {
    url: objectMediaUrl(info.object, info.generation),
    context,
    signal,
    handledStatuses: [404],
  };
  const response = await withRetries(
    async () => {
      if (transferTimeoutMs !== null) {
        return sendGet(deps, request, deadlineSignal(transferTimeoutMs, signal));
      }
      const headers = headersDeadline(deps.requestTimeoutMs, signal);
      try {
        return await sendGet(deps, request, headers.signal);
      } finally {
        headers.settle();
      }
    },
    { policy: deps.retry, sleep: deps.sleep, signal },
  );
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined);
    return { outcome: "gone" };
  }
  const served = response.headers.get("x-goog-generation");
  if (served !== null && served !== info.generation) {
    await response.body?.cancel().catch(() => undefined);
    throw new IntegrityError({ ...context, code: "generation_mismatch" });
  }
  return { outcome: "stream", response };
}

/** Checks a fully read object against its metadata (size, and MD5 when the metadata has one). */
export function verifyObjectBytes(
  info: GcsObjectInfo,
  bytes: number,
  md5: Buffer,
  context: HttpCallContext,
): void {
  if (bytes !== info.size || (info.md5 !== null && !info.md5.equals(md5))) {
    throw new IntegrityError({ ...context, code: "object_digest_mismatch" });
  }
}
