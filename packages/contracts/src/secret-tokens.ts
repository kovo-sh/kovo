// Formats of every bearer secret Kovo itself issues. SPEC: "Never log … secrets, tokens or
// capability URLs"; "Redact capabilities from all logs". The prefixes are part of the wire contract
// (API keys, webhook signing secrets and invitation tokens are shown to customers once) and let the
// log, error and telemetry scrubbers recognise a Kovo secret by value, wherever it appears
// (docs/decisions/platform.md "Kovo secret token formats").

/** The prefix of each Kovo-issued bearer secret. */
export const KOVO_SECRET_TOKEN_PREFIXES = {
  /** Account API keys (`Authorization: Bearer kovo_…`). */
  apiKey: "kovo_",
  /** Management keys: strict versioned shape rejected by older Runtime-only readers. */
  managementApiKey: "kovo_m1_",
  /** Runtime keys delegated by Management authority. */
  delegatedRuntimeApiKey: "kovo_r1_",
  /** Outbound webhook HMAC signing secrets. */
  webhookSigningSecret: "kwhsec_",
  /** Single-use account invitation tokens. */
  invitationToken: "kinv_",
  /** Short-lived npm proxy job capabilities presented by sandboxes. */
  proxyCapability: "kcap_",
  /** Job-scoped model relay grant tokens presented by workers. */
  relayGrant: "krelay_",
} as const;
export type KovoSecretTokenKind = keyof typeof KOVO_SECRET_TOKEN_PREFIXES;

/**
 * Random secrets shown once: the prefix followed by exactly this many base64url characters
 * (256 bits).
 */
export const ONE_TIME_SECRET_BODY_LENGTH = 43;

/** Kinds whose body is a fixed-length random secret (the rest carry signed claims). */
export const FIXED_LENGTH_SECRET_KINDS = [
  "apiKey",
  "managementApiKey",
  "delegatedRuntimeApiKey",
  "webhookSigningSecret",
  "invitationToken",
] as const satisfies readonly KovoSecretTokenKind[];

/** Kinds whose body is a variable-length signed token (claims plus a MAC), base64url. */
export const SIGNED_SECRET_KINDS = [
  "proxyCapability",
  "relayGrant",
] as const satisfies readonly KovoSecretTokenKind[];

/**
 * Signed tokens (capabilities, relay grants) have a variable-length base64url body: at least 16
 * characters, at most 2048.
 */
export const SIGNED_TOKEN_BODY_MIN = 16;
export const SIGNED_TOKEN_BODY_MAX = 2048;

const escape = (text: string) => text.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A regular expression source matching any Kovo-issued secret anywhere in a text (global matching
 * is the caller's choice of flags). Fixed-length secrets must not be followed by another base64url
 * character, so identifiers such as `kovo_funded_usd` never match.
 */
export function kovoSecretTokenPatternSource(): string {
  const fixed = FIXED_LENGTH_SECRET_KINDS.map((kind) => escape(KOVO_SECRET_TOKEN_PREFIXES[kind]));
  const signed = SIGNED_SECRET_KINDS.map((kind) => escape(KOVO_SECRET_TOKEN_PREFIXES[kind]));
  const noBase64Before = "(?<![A-Za-z0-9_-])";
  const noBase64After = "(?![A-Za-z0-9_-])";
  return (
    `${noBase64Before}(?:(?:${fixed.join("|")})[A-Za-z0-9_-]{${ONE_TIME_SECRET_BODY_LENGTH}}${noBase64After}` +
    `|(?:${signed.join("|")})[A-Za-z0-9_-]{${SIGNED_TOKEN_BODY_MIN},${SIGNED_TOKEN_BODY_MAX}})`
  );
}
