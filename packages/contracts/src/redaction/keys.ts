import { isSensitiveFieldName, nameTokens } from "../api/sensitive.js";

// Key-based redaction. The token rules are contracts' `isSensitiveFieldName` (the same rule the
// API response and audit projections use: credentials, key material, source, diffs, manifests,
// model traffic and raw output), extended with names that are harmless in an API response schema
// but carry content in logs and error reports: request/response bodies, signatures and source.

/** Extra tokens that make a log field sensitive wherever they appear in its name. */
const LOG_SENSITIVE_TOKENS: ReadonlySet<string> = new Set([
  "body",
  "bodies",
  "payload",
  "signature",
  "signatures",
  "sig",
  "source",
  "sources",
  "headers",
  "env",
  "environment",
  "input",
  "inputs",
  "authorization",
  "cookie",
]);

/** Suffixes that still mark metadata (a digest or size of a body is loggable). */
const METADATA_SUFFIXES: ReadonlySet<string> = new Set([
  "id",
  "ids",
  "version",
  "versions",
  "count",
  "size",
  "bytes",
  "length",
  "sha256",
  "sha512",
  "hash",
  "at",
]);

/**
 * Whether a log or error-report field named `key` must never carry its value. Metadata about a
 * sensitive thing (`body_sha256`, `session_id`, `key_version`) stays loggable.
 */
export function isSensitiveLogKey(key: string): boolean {
  if (isSensitiveFieldName(key)) return true;
  const tokens = nameTokens(key);
  const last = tokens.at(-1) ?? "";
  if (tokens.length > 1 && METADATA_SUFFIXES.has(last)) return false;
  return tokens.some((token) => LOG_SENSITIVE_TOKENS.has(token));
}
