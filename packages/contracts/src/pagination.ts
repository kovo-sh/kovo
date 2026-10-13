import { z } from "zod";

import { LIMITS } from "./limits.js";

// SPEC Public API: "Lists use `limit` (default 50, max 100) and opaque `cursor`; never page across
// inaccessible tenants." Cursors are minted and verified by the control plane (HMAC-bound to the
// account and route, ARCHITECTURE §3); to clients they are opaque base64url tokens.

export const PAGE_LIMIT_DEFAULT = LIMITS.pagination.defaultLimit;
export const PAGE_LIMIT_MAX = LIMITS.pagination.maxLimit;
export const PAGE_LIMIT_MIN = 1;

/**
 * The `limit` query parameter: a canonical decimal integer string (`"25"`) decoded to a number in
 * 1–100. Out-of-range values are rejected, not clamped.
 */
export const pageLimitSchema = z.codec(
  z.string().regex(/^[1-9]\d{0,2}$/, { error: "limit must be a positive integer" }),
  z.int().min(PAGE_LIMIT_MIN).max(PAGE_LIMIT_MAX),
  { decode: (text) => Number(text), encode: (limit) => String(limit) },
);

/** An opaque pagination cursor (base64url, bounded). */
export const cursorSchema = z
  .string()
  .min(1)
  .max(1024)
  .regex(/^[A-Za-z0-9_-]+$/, { error: "cursor must be an opaque token" })
  .brand<"Cursor">();
export type Cursor = z.infer<typeof cursorSchema>;

/** Shape to spread into a list route's query schema alongside its filters. */
export const paginationQueryShape = {
  limit: pageLimitSchema.default(PAGE_LIMIT_DEFAULT),
  cursor: cursorSchema.exactOptional(),
};

/** Query schema for list routes without filters. */
export const paginationQuerySchema = z.strictObject(paginationQueryShape);
export type PaginationQuery = z.output<typeof paginationQuerySchema>;

/** One page of results: at most {@link PAGE_LIMIT_MAX} items and the cursor of the next page. */
export interface Page<T> {
  items: T[];
  next_cursor: Cursor | null;
}

/** Builds the response schema of a list route from its item schema. */
export function pageSchema<Item extends z.ZodType>(item: Item) {
  return z.strictObject({
    items: z.array(item).max(PAGE_LIMIT_MAX),
    next_cursor: cursorSchema.nullable(),
  });
}
