import { z } from "zod";

// The ID schema builders ids.ts and ids-billing.ts share. No entry point re-exports this module.

const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

/**
 * A branded Kovo entity ID: an RFC 9562 UUID of any version (rows may also carry database-generated
 * v4 defaults), normalized to lower case so derived strings such as workflow IDs are canonical. The
 * nil and max UUIDs are never entity IDs.
 */
export function kovoIdSchema<const Brand extends string>(brand: Brand) {
  return z
    .uuid({ error: `${brand} must be a UUID` })
    .toLowerCase()
    .refine((value) => value !== NIL_UUID && value !== MAX_UUID, {
      error: `${brand} cannot be the nil or max UUID`,
    })
    .brand<Brand>();
}

/** An opaque provider reference: 1-255 printable ASCII characters. */
export function providerRefSchema<const Brand extends string>(brand: Brand) {
  return z
    .string()
    .regex(/^[\x21-\x7e]{1,255}$/, { error: `${brand} must be 1-255 printable ASCII characters` })
    .brand<Brand>();
}
