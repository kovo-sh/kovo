import { hasControlCharacter, whenValid } from "@kovo/contracts";
import { z } from "zod";

// Building blocks shared by the port interfaces. Every port DTO is a Zod schema so the real adapter
// parses vendor responses with it and the fake produces values that pass the same schema
// (docs/libraries/github-and-gcp.md §12: "Every fake response must pass the same Zod schemas as
// the real adapter").

/** Raw bytes crossing a port (file contents, tarballs, signatures, wrapped keys). */
export const bytesSchema = z.instanceof(Uint8Array);

/** Byte array with a maximum length. */
export function boundedBytesSchema(maxBytes: number) {
  return bytesSchema.refine((bytes) => bytes.byteLength <= maxBytes, {
    ...whenValid,
    error: `must be at most ${maxBytes} bytes`,
  });
}

/** A non-empty byte array (signatures, wrapped keys). */
export const nonEmptyBytesSchema = bytesSchema.refine((bytes) => bytes.byteLength > 0, {
  ...whenValid,
  error: "must not be empty",
});

/** Largest byte bound a port accepts for a single buffered read (1 GiB). */
export const MAX_BYTE_LIMIT = 1024 * 1024 * 1024;

/** A caller-supplied byte bound for a buffered or streamed read: 1 byte to 1 GiB. */
export const byteLimitSchema = z.int().min(1).max(MAX_BYTE_LIMIT);

/** A caller-supplied timeout in milliseconds: 1 ms to 1 hour. */
export const timeoutMsSchema = z
  .int()
  .min(1)
  .max(60 * 60 * 1000);

/**
 * A streamed body (npm tarballs, stored objects). Consumers must read or cancel it; adapters
 * enforce their byte bound while streaming and error the stream with `LimitExceededError`.
 */
export type ByteStream = ReadableStream<Uint8Array>;

/** A JSON value as parsed from an untrusted vendor document. */
export const jsonValueSchema = z.json();
export type JsonValue = z.infer<typeof jsonValueSchema>;
/** A JSON object (vendor documents kept for trusted parsing elsewhere, e.g. OSV records). */
export const jsonObjectSchema = z.record(z.string(), jsonValueSchema);
export type JsonObject = z.infer<typeof jsonObjectSchema>;

// Port pagination is named `PortPage*` so it cannot be confused with the public API's cursor
// pagination in `@kovo/contracts/pagination` (`Page`/`pageSchema`, snake_case `next_cursor`,
// HMAC-bound cursors): control-plane code imports both packages.

/** An opaque, adapter-defined continuation token for paginated port reads. */
export const portPageCursorSchema = z.string().min(1).max(2048);
export type PortPageCursor = z.infer<typeof portPageCursorSchema>;

/** One page of a port listing. `nextCursor` is null on the last page. */
export interface PortPage<T> {
  readonly items: readonly T[];
  readonly nextCursor: PortPageCursor | null;
}

export function portPageSchema<T extends z.ZodType>(item: T) {
  return z.strictObject({
    items: z.array(item).readonly(),
    nextCursor: portPageCursorSchema.nullable(),
  });
}

/** Page size for port listings: 1–100 (provider maximums are enforced by adapters). */
export const portPageSizeSchema = z.int().min(1).max(100);

/** Optional cancellation for long-running port calls (sandbox exec, model calls, fetches). */
export interface CallOptions {
  readonly signal?: AbortSignal;
}

/** Longest URL a port accepts or returns, in characters of its serialized form. */
export const HTTPS_URL_MAX_LENGTH = 2048;

/**
 * An absolute `https:` URL without embedded credentials (Checkout/Portal return URLs, release
 * documentation). Destination safety (DNS, private ranges, redirects) is enforced by the adapter.
 */
export const httpsUrlSchema = z
  .url({ protocol: /^https$/, error: "must be an https URL" })
  .max(HTTPS_URL_MAX_LENGTH)
  .refine(
    (value) => {
      const url = new URL(value);
      return url.username === "" && url.password === "";
    },
    { ...whenValid, error: "must not embed credentials" },
  );

/**
 * An email address as sent to or received from the email and identity providers. Deliberately
 * conservative: one `@`, no whitespace, control characters or display names.
 */
export const emailAddressSchema = z
  .string()
  .trim()
  .max(254)
  .toLowerCase()
  .refine((value) => /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[^\s@<>()",;:]+$/.test(value), {
    error: "must be a plain email address",
  })
  .refine((value) => !hasControlCharacter(value), {
    ...whenValid,
    error: "must not contain control characters",
  })
  .brand<"EmailAddress">();
export type EmailAddress = z.infer<typeof emailAddressSchema>;

/** A short machine-readable token (provider codes, labels in telemetry). */
export const machineTokenSchema = z
  .string()
  .regex(/^[A-Za-z0-9_.:-]{1,128}$/, { error: "must be a short machine token" });
