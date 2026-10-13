import { z } from "zod";

/** An ephemeral job secret set. Never put this context in durable inputs, results or telemetry. */
declare const jobRedactionContext: unique symbol;
export type JobRedactionContext = readonly string[] & { readonly [jobRedactionContext]: true };
const contexts = new WeakMap<object, readonly string[]>();
// Recipes permit 100 stubs, with another 100 doctor fixtures; retain room for job capabilities.
export const MAX_JOB_REDACTION_SECRETS = 256;
const MAX_JOB_REDACTION_LITERALS = MAX_JOB_REDACTION_SECRETS * 6;
const MAX_SECRET_LENGTH = 4096;
// A UTF-16 code unit takes at most three UTF-8 bytes, each encoded as three percent characters.
const MAX_LITERAL_LENGTH = MAX_SECRET_LENGTH * 9;
export const MAX_JOB_REDACTION_TRANSPORT_BYTES = 64 * 1024 * 1024;

const transportSchema = z
  .strictObject({
    version: z.literal(1),
    secrets: z
      .array(
        z
          .string()
          .min(1)
          .max(MAX_SECRET_LENGTH)
          .refine((value) => value.isWellFormed()),
      )
      .max(MAX_JOB_REDACTION_SECRETS)
      .readonly(),
    literals: z
      .array(
        z
          .string()
          .min(1)
          .max(MAX_LITERAL_LENGTH)
          .refine((value) => value.isWellFormed()),
      )
      .max(MAX_JOB_REDACTION_LITERALS)
      .readonly(),
  })
  .refine(({ secrets, literals }) => {
    const unique = new Set(literals);
    return (
      unique.size === literals.length &&
      new Set(secrets).size === secrets.length &&
      (secrets.length === 0
        ? literals.length === 0
        : secrets.every((secret) =>
            expandSecretEncodings(secret).every((literal) => unique.has(literal)),
          ))
    );
  })
  .readonly();

/** Plaintext for trusted, ephemeral IPC only; never store it or include it in telemetry. */
export type JobRedactionContextTransport = z.infer<typeof transportSchema>;

/** The sender must hold a genuine context; transport keeps expansion bytes and raw-slot accounting. */
export function serializeJobRedactionContext(
  context: JobRedactionContext,
): JobRedactionContextTransport {
  if (!isJobRedactionContext(context)) throw new Error("redaction_context_required");
  return validateTransport({ version: 1, secrets: contexts.get(context)!, literals: context });
}

/** Rebrand the received literal bytes, without treating encodings as new raw secrets. */
export function rehydrateJobRedactionContext(transport: unknown): JobRedactionContext {
  const packet = validateTransport(transport);
  const literals = Object.freeze([...packet.literals]);
  contexts.set(literals, Object.freeze([...packet.secrets]));
  if (isJobRedactionContext(literals)) return literals;
  throw new Error("redaction_context_required");
}

function validateTransport(value: unknown): JobRedactionContextTransport {
  // Check outer bounds before Zod clones arrays. Descriptor reads also refuse executable inputs.
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new Error();
    for (const key of ["version", "secrets", "literals"]) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) throw new Error();
    }
    const secrets: unknown = Object.getOwnPropertyDescriptor(value, "secrets")?.value;
    const literals: unknown = Object.getOwnPropertyDescriptor(value, "literals")?.value;
    if (
      !Array.isArray(secrets) ||
      secrets.length > MAX_JOB_REDACTION_SECRETS ||
      !Array.isArray(literals) ||
      literals.length > MAX_JOB_REDACTION_LITERALS
    )
      throw new Error();
    const encoder = new TextEncoder();
    // Includes JSON quoting/escapes and an upper bound for the fixed keys, punctuation and commas.
    let bytes = 128 + secrets.length + literals.length;
    for (const [strings, maxLength] of [
      [secrets, MAX_SECRET_LENGTH],
      [literals, MAX_LITERAL_LENGTH],
    ] as const) {
      for (let index = 0; index < strings.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(strings, String(index));
        const text: unknown =
          descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
        if (typeof text !== "string" || text.length === 0 || text.length > maxLength)
          throw new Error();
        bytes += encoder.encode(JSON.stringify(text)).length;
        if (bytes > MAX_JOB_REDACTION_TRANSPORT_BYTES) throw new Error();
      }
    }
    const result = transportSchema.safeParse(value);
    if (result.success) return result.data;
  } catch {
    // Never expose rejected literals, accessor errors, or Zod input values in the refusal.
  }
  throw new Error("redaction_context_transport");
}

/** All six encodings used by shell output, manifests and candidate patches. Browser-safe. */
export function expandSecretEncodings(secret: string): readonly string[] {
  if (typeof secret !== "string" || secret.length === 0 || secret.length > 4096)
    throw new Error("redaction_secret_limit");
  const bytes = new TextEncoder().encode(secret);
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const percent = [...bytes].map((byte) => `%${byte.toString(16).padStart(2, "0")}`).join("");
  return [
    ...new Set([
      secret,
      encodeURIComponent(secret),
      percent,
      percent.toUpperCase(),
      hex,
      hex.toUpperCase(),
    ]),
  ];
}

/** Mint at the secret source; an explicit empty set is valid for a secretless operation. */
export function createJobRedactionContext(secrets: readonly string[]): JobRedactionContext {
  if (!Array.isArray(secrets) || secrets.length > MAX_JOB_REDACTION_SECRETS)
    throw new Error("redaction_secret_limit");
  const literals = Object.freeze([...new Set(Array.from(secrets, expandSecretEncodings).flat())]);
  contexts.set(literals, Object.freeze([...new Set(secrets)]));
  if (isJobRedactionContext(literals)) return literals;
  throw new Error("redaction_context_required");
}

/** Reject plain arrays and forged structural values at in-process content boundaries. */
export function isJobRedactionContext(value: unknown): value is JobRedactionContext {
  return typeof value === "object" && value !== null && contexts.has(value);
}

/** Add freshly minted secrets without re-encoding an already expanded context. */
export function extendJobRedactionContext(
  context: JobRedactionContext,
  secrets: readonly string[],
): JobRedactionContext {
  if (!isJobRedactionContext(context)) throw new Error("redaction_context_required");
  const added = createJobRedactionContext(secrets);
  const secretsInJob = [...new Set([...contexts.get(context)!, ...contexts.get(added)!])];
  if (secretsInJob.length > MAX_JOB_REDACTION_SECRETS) throw new Error("redaction_secret_limit");
  const literals = Object.freeze([...new Set([...context, ...added])]);
  if (literals.length > MAX_JOB_REDACTION_LITERALS) throw new Error("redaction_secret_limit");
  contexts.set(literals, Object.freeze(secretsInJob));
  if (isJobRedactionContext(literals)) return literals;
  throw new Error("redaction_context_required");
}
