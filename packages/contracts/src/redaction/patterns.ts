import {
  KOVO_SECRET_TOKEN_PREFIXES,
  SIGNED_SECRET_KINDS,
  SIGNED_TOKEN_BODY_MAX,
  kovoSecretTokenPatternSource,
} from "../secret-tokens.js";

import { REDACTED } from "./marker.js";

// Value-pattern redaction shared by the logger, the error reporter and the telemetry exporters.
// SPEC: "Never log raw source, manifests, prompts, tool output, capability URLs or secrets";
// "Redact capabilities from all logs"; "Sentry captures sanitized exceptions". Key-based redaction
// (`keys.ts`) removes values whose *name* is sensitive; these patterns catch secrets that travel in
// free text (error messages, URLs, stack traces) whatever the surrounding field is called.

/** A text rewrite applied by {@link redactText} (the proxy's capability issuer adds its own). */
export type TextRedactor = (text: string) => string;

export interface RedactionRule {
  readonly name: string;
  /** Retain at most this many preceding word characters for a residual terminal match. */
  readonly lookback?: number;
  readonly pattern: RegExp;
  readonly replace: string | ((substring: string, ...groups: string[]) => string);
}

/**
 * Query parameters whose values are credentials or capabilities (lower case; matched without regard
 * to case here). The single list: the http instrumentation redacts the same names
 * (`telemetry/bootstrap.ts`, through {@link queryParamSpellings}), and the span exporter drops every
 * query string anyway.
 */
export const SENSITIVE_QUERY_PARAMS: readonly string[] = [
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "code",
  "state",
  "cap",
  "capability",
  "sig",
  "signature",
  "key",
  "api_key",
  "apikey",
  "secret",
  "client_secret",
  "password",
  "pass",
  "auth",
  "session",
  "x-goog-signature",
  "x-goog-credential",
  "x-amz-signature",
  "x-amz-credential",
  "x-amz-security-token",
  // Kovo's opaque list cursors are bound to a tenant; they are not for logs either.
  "cursor",
];

/**
 * The spellings of a parameter list for consumers that match names exactly (the OpenTelemetry http
 * instrumentation): each name as listed and in the header case signed-URL providers use
 * (`x-goog-signature` → `X-Goog-Signature`).
 */
export function queryParamSpellings(names: readonly string[]): string[] {
  return [...new Set(names.flatMap((name) => [name, headerCase(name)]))];
}

/** `x-goog-signature` → `X-Goog-Signature`. */
function headerCase(name: string): string {
  return name
    .split("-")
    .map((part) => (part === "" ? part : `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`))
    .join("-");
}

// Also used by the streaming stages to retain incomplete credential prefixes. Keep assignment
// names bounded and explicit: scanning an arbitrary identifier prefix can become quadratic.
export const CAMEL_CREDENTIAL_NAMES =
  "(?:npm_config_)?_?authToken|apiToken|accessToken|refreshToken|dbPassword|clientSecret";
export const ENCODED_CREDENTIAL_NAMES = `${CAMEL_CREDENTIAL_NAMES}|db_password|password|passwd|secret|token|api_?key|private_?key|client_?secret|access_?key`;

// A value may be split by controls, but must leave the next assignment's name intact.
const CONTEXT_KEYWORDS = [
  "token",
  "secret",
  "key",
  "password",
  "passwd",
  "bearer",
  "basic",
  "digest",
  "cookie",
  "fail",
  "error",
]
  .map((word) => word.replace(/[a-z]/g, (character) => `[${character}${character.toUpperCase()}]`))
  .join("|");
const NEXT_CREDENTIAL_LINE = String.raw`(?:${CONTEXT_KEYWORDS})\b|[A-Za-z_][A-Za-z0-9_]*[\t ]*[:=]`;
export const CREDENTIAL_VALUE_CHARACTER = String.raw`[^\s\p{Cc}\p{Cf}"',;&}]`;
export const CREDENTIAL_VALUE = String.raw`${CREDENTIAL_VALUE_CHARACTER}+(?:(?:(?![\n\v\f\x85\u2028\u2029])[\p{Cc}\p{Cf}])+(?!${NEXT_CREDENTIAL_LINE}|[A-Za-z_][A-Za-z0-9_]*[\s\p{Cc}\p{Cf}]*[:=])${CREDENTIAL_VALUE_CHARACTER}+)*`;

// Only substantial split fragments continue. Keep the next credential's context, short
// diagnostic words such as FAIL, and every consumed line break.
const SPLIT_VALUE = String.raw`${CREDENTIAL_VALUE}(?:[\n\v\f\x85\u2028\u2029]+(?!${NEXT_CREDENTIAL_LINE})${CREDENTIAL_VALUE_CHARACTER}{8,})*`;
const redactLines = (text: string): string =>
  text.replace(/[^\r\n\v\f\x85\u2028\u2029]+/g, REDACTED);

/** Largest finite credential match, plus boundary context; entropy uses its own window. */
export const MAX_BOUNDED_REDACTION_PATTERN_LENGTH =
  Math.max(
    600,
    ...SIGNED_SECRET_KINDS.map(
      (kind) => KOVO_SECRET_TOKEN_PREFIXES[kind].length + SIGNED_TOKEN_BODY_MAX,
    ),
  ) + 1;

/** Numeric SGR, complete OSC and explicitly recognized harmless ECMA-48 display forms. */
export const TERMINAL_ESCAPE =
  // eslint-disable-next-line no-control-regex -- terminal escape and BEL terminators are the syntax being removed.
  /\x1b(?:\[(?:[0-9;:]{1,64}m|[0-9]{1,2}[KG]|(?:m|K|\?25[lh])(?![A-Za-z0-9_]))|\][^\x07\x1b]*(?:\x07|\x1b\\)|\([AB012]|[78=>cD](?![A-Za-z0-9_]))/g;

/** Invisible non-whitespace controls and format characters cannot divide a credential. */
// Cc is confined to these ASCII/C1 ranges; omit whitespace and the NEL line break.
// One class avoids repeating Unicode lookaheads at every assignment-name character.
export const INVISIBLE_SEPARATOR_CHARACTER = String.raw`[\p{Cf}\x00-\x08\x0e-\x1f\x7f-\x84\x86-\x9f]`;
// Bounded separators keep contextual labels inside the stream's fixed match window.
export const SEPARATED_CONTEXT_KEYWORDS = ["token", "secret", "key"]
  .map((word) => word.split("").join(`${INVISIBLE_SEPARATOR_CHARACTER}{0,8}`))
  .join("|");
export const CONTEXT_WHITESPACE = String.raw`${INVISIBLE_SEPARATOR_CHARACTER}{0,8}(?:\s|%20|%09)+`;
// Keep a following assignment name intact before excerpt/Python display normalization.
const separateAssignmentName = (source: string): string =>
  source.replace(
    /[a-zA-Z0-9_]/g,
    (character) => `(?:${character}${INVISIBLE_SEPARATOR_CHARACTER}{0,8})`,
  );
export const CONTEXTUAL_ASSIGNMENT_NAMES = separateAssignmentName(
  `${ENCODED_CREDENTIAL_NAMES}|key`,
);
const CONTEXTUAL_REGULAR_NAMES = separateAssignmentName(
  "db_password|password|passwd|secret|token|api_?key|private_?key|client_?secret|access_?key|key",
);
export const CONTEXTUAL_ENCODED_DELIMITER = String.raw`%${INVISIBLE_SEPARATOR_CHARACTER}{0,8}3${INVISIBLE_SEPARATOR_CHARACTER}{0,8}[da]`;
const CONTEXTUAL_ASSIGNMENT_DELIMITER = String.raw`(?:[:=]|${CONTEXTUAL_ENCODED_DELIMITER})`;
const CONTEXTUAL_NAME_SUFFIX = String.raw`["']?[\s\p{Cc}\p{Cf}]*`;
const CONTEXTUAL_ASSIGNMENT_NAME = String.raw`(?:${CONTEXTUAL_ASSIGNMENT_NAMES})${CONTEXTUAL_NAME_SUFFIX}${CONTEXTUAL_ASSIGNMENT_DELIMITER}`;
export const CREDENTIAL_NAME_PREFIX = String.raw`(?<![a-z0-9])(?:${CONTEXTUAL_ASSIGNMENT_NAMES})["']?[\s\p{Cc}\p{Cf}]*`;
// Keep camelCase's ordinary boundary; underscore suffixes and encoded assignments have
// their existing looser boundary. A glued camelCase prefix is absorbed by the context rule.
const CONTEXTUAL_RESTRICTED_CAMEL_NAMES = separateAssignmentName(
  "(?:npm_config_)?_?authToken|apiToken|accessToken|refreshToken|dbPassword",
);
export const CREDENTIAL_ASSIGNMENT_PREFIX = String.raw`((?<![a-z0-9])(?!(?<=_)(?:${CONTEXTUAL_RESTRICTED_CAMEL_NAMES})${CONTEXTUAL_NAME_SUFFIX}[:=])${CONTEXTUAL_ASSIGNMENT_NAME}[\s\p{Cc}\p{Cf}]*)`;
const CONTEXTUAL_PREFIXED_ASSIGNMENT = String.raw`${CONTEXTUAL_ASSIGNMENT_NAME}|[a-z_][a-z0-9_]{0,${MAX_BOUNDED_REDACTION_PATTERN_LENGTH - 64}}_(?:(?:${CONTEXTUAL_REGULAR_NAMES})${CONTEXTUAL_NAME_SUFFIX}${CONTEXTUAL_ASSIGNMENT_DELIMITER}|(?:${CONTEXTUAL_ASSIGNMENT_NAMES})${CONTEXTUAL_NAME_SUFFIX}${CONTEXTUAL_ENCODED_DELIMITER})`;
const CONTEXTUAL_VALUE_CHARACTER = String.raw`(?!${CONTEXTUAL_ASSIGNMENT_NAME})[a-z0-9._~+/=:-]`;

/** Bound nested normalization work; residual malformed escapes are withheld below. */
export const TERMINAL_NORMALIZATION_PASSES = 4;
export const TERMINAL_RESIDUAL_LOOKBACK = Math.min(2048, MAX_BOUNDED_REDACTION_PATTERN_LENGTH);
// eslint-disable-next-line no-control-regex -- malformed introducers withhold the remaining line.
const TERMINAL_RESIDUAL = /[\x1b\u009b][^\r\n]*/g;

/** Find bounded backward context once per introducer, rather than at every ordinary character. */
export function residualMatchStart(text: string, index: number, minimum = 0): number {
  const limit = Math.max(minimum, index - TERMINAL_RESIDUAL_LOOKBACK);
  let start = index;
  // eslint-disable-next-line no-control-regex -- do not cross another terminal introducer.
  while (start > limit && !/[\s\x1b\u009b]/.test(text.charAt(start - 1))) start -= 1;
  return start;
}

function redactTerminalResidual(text: string): string {
  TERMINAL_RESIDUAL.lastIndex = 0;
  let output = "";
  let start = 0;
  for (const match of text.matchAll(TERMINAL_RESIDUAL)) {
    output += text.slice(start, residualMatchStart(text, match.index, start)) + REDACTED;
    start = match.index + match[0].length;
  }
  return output + text.slice(start);
}

export function stripCompleteTerminalEscapes(text: string): string {
  let result = text;
  for (let pass = 0; pass < TERMINAL_NORMALIZATION_PASSES; pass += 1) {
    const next = result.replace(TERMINAL_ESCAPE, "");
    if (next === result) break;
    result = next;
  }
  return result;
}

// Fixed prefixes with separators between their characters; no arbitrary identifier scan.
export const OBFUSCATED_TOKEN_PREFIX = [
  "ghp_",
  "gho_",
  "ghu_",
  "ghs_",
  "ghr_",
  "github_pat_",
  "kovo_",
  "AKIA",
  "sk_live_",
  "sk_test_",
  "rk_live_",
  "rk_test_",
  "pk_live_",
  "pk_test_",
  "npm_",
  "whsec_",
  "xoxb-",
  "eyJ",
  "AIza",
]
  .map((prefix) => prefix.split("").join(String.raw`[\p{Cc}\p{Cf}]*`))
  .join("|");

// A lone ESC can consume a credential letter or delimiter as a valid escape final.
// Recognize that alternative raw interpretation before display normalization erases it.
const rawSeparated = (source: string): string =>
  source.replace(
    /\[[^\]]*\]|[a-zA-Z0-9_%/]/g,
    (character) => `(?:(?:[\\p{Cc}\\p{Cf}]{0,8}|\\x1b\\[[0-9;:]{0,64})${character})`,
  );
export const RAW_TERMINAL_CREDENTIAL_PREFIX = String.raw`(?:\x1b|(?<![a-z0-9]))(?=[a-z0-9_])(?:(?:${rawSeparated(ENCODED_CREDENTIAL_NAMES)})["']?[\s\p{Cc}\p{Cf}]*(?:[:=]|%[\p{Cc}\p{Cf}]*3[\p{Cc}\p{Cf}]*[da])|(?:${rawSeparated("Bearer|Basic|Digest")})[\s\p{Cc}\p{Cf}]+|[a-z][\p{Cc}\p{Cf}]*(?:[a-z0-9+.-][\p{Cc}\p{Cf}]*){0,31}:[\p{Cc}\p{Cf}]*/[\p{Cc}\p{Cf}]*/(?:[^\s\p{Cc}\p{Cf}/?#@]|[\p{Cc}\p{Cf}])*@|(?:${rawSeparated("token|secret|key")})[\s\p{Cc}\p{Cf}]+(?:\x1b\[[0-9;:]{0,64}[A-Za-z])*[a-z0-9](?:(?:[\p{Cc}\p{Cf}]{0,8}|\x1b\[)[a-z0-9]){31}|(?:${OBFUSCATED_TOKEN_PREFIX}|${rawSeparated("ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|kovo_|kcap_|krelay_|kwhsec_|kinv_|AKIA|sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|pk_test_|whsec_|npm_|xoxb-|eyJ|SG\\.|re_|ph[cx]_|sk-or-v1-|AIza")}))`;
export const RAW_TERMINAL_CREDENTIAL = new RegExp(
  String.raw`(?:(?=\x1b)|(?<![a-z0-9]))(?=[a-z0-9_]|\x1b[a-z0-9_])(?=[^\r\n]{0,256}\x1b(?!\]))${RAW_TERMINAL_CREDENTIAL_PREFIX}[^\r\n]*`,
  "giu",
);

// Inspect whole token-shaped words before display normalization can erase a class.
// Path separators and extension dots are boundaries that forbid a dense candidate.
// The first ESC must arrive within the retained window; distant display syntax cannot
// retroactively withhold a prefix already emitted by the stream.
const RAW_DENSE_CONTROL = String.raw`[\x00-\x08\x0e-\x1a\x1c-\x1f\x7f-\x84\x86-\x9a\x9c-\x9f\p{Cf}]`;
export const RAW_TERMINAL_DENSE = new RegExp(
  String.raw`(?<![A-Za-z0-9+/_=.\-\x00-\x08\x0e-\x1f\x7f-\x84\x86-\x9f\p{Cf}])(?=[A-Za-z0-9]|\x1b)(?=(?:[A-Za-z0-9+_=-]|${RAW_DENSE_CONTROL}){0,${MAX_BOUNDED_REDACTION_PATTERN_LENGTH}}\x1b)(?:(?=[^\s/.:]{${MAX_BOUNDED_REDACTION_PATTERN_LENGTH + 1}})[^\r\n]*|(?:[A-Za-z0-9+_=-]|${RAW_DENSE_CONTROL}|\x1b(?:\([AB012]|\[[0-9;:]{0,64}m?|[78=>cD])?)+(?![A-Za-z0-9+/_=.-]))`,
  "gu",
);

export function redactTerminalDense(candidate: string): string {
  // An ESC-bearing over-window word cannot await its final class in bounded stream memory.
  // The pattern's over-window branch includes the remaining line, sharing stream discard semantics.
  if (candidate.length > MAX_BOUNDED_REDACTION_PATTERN_LENGTH) return REDACTED;
  const normalized = stripCompleteTerminalEscapes(candidate);
  // Residual syntax must reach the residual rule with credential-name context intact.
  if (normalized.includes("\u001b") || normalized.includes("\u009b")) return candidate;
  const ambiguous = candidate.replaceAll("\u001b", "");
  // Numeric CSI can also consume a credential final such as G; retain that interpretation.
  // eslint-disable-next-line no-control-regex -- retain printable finals of ambiguous CSI fragments.
  const csiPrefix = /\x1b\[[0-9;:]{0,64}/g;
  const csiFragment = stripCompleteTerminalEscapes(candidate.replaceAll(csiPrefix, ""));
  return [normalized, ambiguous, csiFragment]
    .map((word) => word.replaceAll(/[\p{Cc}\p{Cf}]/gu, ""))
    .some(
      (word) =>
        word.length >= 24 &&
        /^[A-Za-z0-9+_=-]+$/.test(word) &&
        /[a-z]/.test(word) &&
        /[A-Z]/.test(word) &&
        /[0-9]/.test(word),
    )
    ? REDACTED
    : candidate;
}

// Line breaks are boundaries, except for an explicitly split token fragment. Never consume
// the name of the next assignment: later rules need that context to redact its value.
export const OBFUSCATED_BODY_CHARACTER = String.raw`(?:[A-Za-z0-9._~+/=\-]|(?![\r\n\v\f\x85\u2028\u2029])[\p{Cc}\p{Cf}](?![A-Za-z_][A-Za-z0-9_]*[\s\p{Cc}\p{Cf}]*[:=]))`;
const OBFUSCATED_BODY = String.raw`${OBFUSCATED_BODY_CHARACTER}*(?:[\r\n\v\f\x85\u2028\u2029]+(?!${NEXT_CREDENTIAL_LINE})[A-Za-z0-9._~+/=\-]{8,}${OBFUSCATED_BODY_CHARACTER}*)*`;

// Exact identifier shapes only, and only for the entropy heuristic. Earlier credential rules
// still win (notably re_ also names Resend keys). Kovo entity IDs are UUIDs; derived DBOS
// IDs contain those UUIDs and hex source hashes separated by punctuation.
const NON_SECRET_IDENTIFIER_PATTERNS: readonly RegExp[] = [
  /^(?:sub|pi|cus|in|price|evt|ch|re|prod|seti)_[A-Za-z0-9]{8,255}$/,
  /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-8][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$/,
  // Git SHA-1/SHA-256 and OTel trace/span IDs (exact hex lengths).
  /^(?:[a-fA-F0-9]{16}|[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/,
];

function tokenEntropy(token: string): number {
  const counts = new Map<string, number>();
  for (const char of token) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / token.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/** Same mixed-class Shannon threshold as failed-step excerpts; hex digests remain readable. */
function redactRandomToken(token: string): string {
  return redactRandomCandidate(token, true);
}

function redactRandomCandidate(token: string, preserveIdentifiers: boolean): string {
  if (preserveIdentifiers && NON_SECRET_IDENTIFIER_PATTERNS.some((pattern) => pattern.test(token)))
    return token;
  const classes =
    Number(/[a-z]/.test(token)) + Number(/[A-Z]/.test(token)) + Number(/[0-9]/.test(token));
  if (classes < 3) return token;
  return tokenEntropy(token) >= 4 ? REDACTED : token;
}

/**
 * The rules, most specific first. Every rule is global and scans a bounded window from each start
 * position (bounded repetitions, or runs that end where the next start would be), so redaction is
 * linear in the text: `patterns.perf.test.ts` (in `@kovo/adapters`) times each rule on 64 KiB of
 * text built against it. The first `assignment` rule matched an unbounded `[a-z0-9_-]*_` prefix
 * from every word boundary, which backtracked across the whole run: 16 KiB of `-_-_…` took 200 ms
 * (security review).
 */
const URL_CONTEXT_CSI = String.raw`\x1b\[[0-9;:]{0,64}[A-Za-z]`;
const URL_CONTEXT_KEYWORDS = ["token", "secret", "key"]
  .map((word) =>
    word
      .split("")
      .join(
        `${INVISIBLE_SEPARATOR_CHARACTER}{0,8}(?:${URL_CONTEXT_CSI}){0,2}${INVISIBLE_SEPARATOR_CHARACTER}{0,8}`,
      ),
  )
  .join("|");
export const URL_CONTEXT_BOUNDARY = String.raw`(?<![a-z0-9])(?:${URL_CONTEXT_CSI}){0,8}(?:${URL_CONTEXT_KEYWORDS})(?:${INVISIBLE_SEPARATOR_CHARACTER}|${URL_CONTEXT_CSI}){0,8}${CONTEXT_WHITESPACE}`;
export const URL_USERINFO_BODY = String.raw`(?:[^\s/?#@\p{Cc}\p{Cf}]|[\p{Cc}\p{Cf}])`;
// Complete userinfo withholds through @; only oversized/unterminated bodies stop at context.
export const URL_AUTHORITY_BODY = String.raw`(?:(?!${URL_CONTEXT_BOUNDARY})${URL_USERINFO_BODY})`;
const URL_USERINFO_RULE: RedactionRule = {
  name: "obfuscated_url_userinfo",
  pattern: new RegExp(
    String.raw`(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)${URL_USERINFO_BODY}+@`,
    "giu",
  ),
  replace: (_match, scheme: string) => `${scheme}${REDACTED}@`,
};

// A username-colon credential can contain slashes without turning ordinary /path@host
// URLs into userinfo. Bound the username; oversized passwords discard to their body delimiter.
export const SLASH_USERINFO_USERNAME_MAX = MAX_BOUNDED_REDACTION_PATTERN_LENGTH - 64;
export const SLASH_USERINFO_PREFIX = String.raw`(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)(?:[^\s/:?#@\p{Cc}\p{Cf}]|[\p{Cc}\p{Cf}]){0,${SLASH_USERINFO_USERNAME_MAX}}:`;
export const SLASH_USERINFO_SHORT_BODY = String.raw`(?:[^\s?#@\p{Cc}\p{Cf}]|[\p{Cc}\p{Cf}\u2028\u2029])`;
export const SLASH_USERINFO_BODY = String.raw`(?:(?!${URL_CONTEXT_BOUNDARY})${SLASH_USERINFO_SHORT_BODY})`;
const SLASH_USERINFO_GATE = SLASH_USERINFO_PREFIX.replace("([a-z]", "(?:[a-z]");
const RULES: readonly RedactionRule[] = [
  {
    name: "slash_url_userinfo",
    pattern: new RegExp(
      String.raw`(?<![a-z0-9+.-])(?=${SLASH_USERINFO_GATE})(?:(?=${SLASH_USERINFO_BODY}{${MAX_BOUNDED_REDACTION_PATTERN_LENGTH - 64}})${SLASH_USERINFO_PREFIX}${SLASH_USERINFO_BODY}+|${SLASH_USERINFO_PREFIX}${SLASH_USERINFO_SHORT_BODY}+@)`,
      "giu",
    ),
    replace: (_match, longScheme: string, shortScheme: string) =>
      `${longScheme ?? shortScheme}${REDACTED}${longScheme === undefined ? "@" : ""}`,
  },
  // Preserve URL delimiters before terminal withholding can erase the end of a long authority.
  URL_USERINFO_RULE,
  {
    name: "overlong_url_authority",
    pattern: new RegExp(
      String.raw`(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)${URL_AUTHORITY_BODY}+`,
      "giu",
    ),
    replace: (match, scheme: string) =>
      match.length > MAX_BOUNDED_REDACTION_PATTERN_LENGTH ? `${scheme}${REDACTED}` : match,
  },

  { name: "raw_terminal_credential", pattern: RAW_TERMINAL_CREDENTIAL, replace: REDACTED },
  { name: "raw_terminal_dense", pattern: RAW_TERMINAL_DENSE, replace: redactTerminalDense },
  ...Array.from({ length: TERMINAL_NORMALIZATION_PASSES }, () => ({
    name: "terminal_escape",
    pattern: TERMINAL_ESCAPE,
    replace: "",
  })),
  {
    // Quoted camelCase/encoded fields can contain spaces; redact the entire value first.
    name: "quoted_credential_assignment",
    pattern: new RegExp(String.raw`${CREDENTIAL_ASSIGNMENT_PREFIX}(["'])([^\r\n]*?)\2`, "giu"),
    replace: (_match, prefix: string, quote: string) => `${prefix}${quote}${REDACTED}${quote}`,
  },
  {
    // Deeper nesting and malformed introducers cannot survive the bounded normalization passes.
    name: "terminal_escape_residual",
    lookback: TERMINAL_RESIDUAL_LOOKBACK,
    pattern: TERMINAL_RESIDUAL,
    replace: REDACTED,
  },
  {
    // PEM blocks (private keys, certificates), including an unterminated block at the end.
    name: "pem",
    pattern: /-----BEGIN [A-Z0-9 ]{1,64}-----[\s\S]*?(?:-----END [A-Z0-9 ]{1,64}-----|$)/g,
    replace: `[REDACTED:pem]`,
  },
  {
    // Encoding is itself enough to withhold a byte run: decoding into output could reveal a
    // credential or terminal instruction. Keep opaque hex digests (without escapes) readable.
    name: "encoded_bytes",
    pattern: /(?:%[a-f0-9]{2}|\\x[a-f0-9]{2}){4,}/giu,
    replace: REDACTED,
  },
  {
    // Invisible and control separators can split recognizable token prefixes from their body.
    // Match the original text so streaming origins and batch replacement counts remain aligned.
    name: "obfuscated_token",
    pattern: new RegExp(
      String.raw`(?<![A-Za-z0-9_])(?:${OBFUSCATED_TOKEN_PREFIX})[\p{Cc}\p{Cf}]*[A-Za-z0-9]${OBFUSCATED_BODY}`,
      "gu",
    ),
    replace: (match) => {
      return /[\p{Cc}\p{Cf}]/u.test(match) ? redactLines(match) : match;
    },
  },
  {
    // Digest carries named parameters rather than one opaque authorization token.
    name: "authorization_parameters",
    pattern:
      /\b(Digest)[\s\p{Cc}\p{Cf}]+(?:username|realm|nonce|uri|response|algorithm|cnonce|opaque|qop|nc)[\s\p{Cc}\p{Cf}]*=[^\r\n]*/giu,
    replace: (_match, scheme: string) => `${scheme} ${REDACTED}`,
  },
  {
    name: "obfuscated_bearer",
    pattern: new RegExp(
      String.raw`\b(Bearer|Basic|Digest)[\s\p{Cc}\p{Cf}]+[A-Za-z0-9]${OBFUSCATED_BODY}`,
      "giu",
    ),
    replace: (match, scheme: string) =>
      `${scheme} ${redactLines(match.slice(scheme.length).trimStart())}`,
  },
  // Repeat after terminal normalization to recognize schemes split by display escapes.
  URL_USERINFO_RULE,
  {
    name: "obfuscated_cookie",
    pattern: new RegExp(
      String.raw`\b((?:set-)?cookie["']?\s*[:=]\s*)[A-Za-z0-9]${OBFUSCATED_BODY}`,
      "giu",
    ),
    replace: (_match, prefix: string) => `${prefix}${REDACTED}`,
  },
  {
    // Kovo-issued secrets: API keys, webhook signing secrets, invitations, capabilities, relay grants.
    name: "kovo_secret",
    pattern: new RegExp(kovoSecretTokenPatternSource(), "g"),
    replace: REDACTED,
  },
  {
    // GitHub tokens: personal (ghp_), OAuth (gho_), user-to-server (ghu_), installation (ghs_),
    // refresh (ghr_) and fine-grained personal access tokens.
    name: "github_token",
    pattern: /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{22,255})/g,
    replace: REDACTED,
  },
  {
    name: "npm_token",
    pattern: /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/g,
    replace: REDACTED,
  },
  {
    name: "slack_token",
    pattern: /(?<![A-Za-z0-9_])xox[abposre]-[A-Za-z0-9-]{10,255}/g,
    replace: REDACTED,
  },
  {
    // Stripe secret/restricted/publishable keys and webhook signing secrets.
    name: "stripe_key",
    pattern:
      /(?<![A-Za-z0-9_])(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,255}|whsec_[A-Za-z0-9+/=]{8,255})/g,
    replace: REDACTED,
  },
  {
    // AWS secret access keys have no vendor prefix; require an explicit AWS context.
    name: "aws_secret_key",
    pattern:
      /((?:aws_secret_access_key[ \t:=]{0,32}["']?|aws[ \t]{1,8}s3[ \t]{1,8}(?:cp|sync)[ \t]{1,8}))([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    replace: (match, prefix: string, token: string) =>
      /[a-z]/.test(token) && /[A-Z]/.test(token) && /[0-9]/.test(token)
        ? `${prefix}${REDACTED}`
        : match,
  },
  {
    // SendGrid API keys, including malformed shorter provider-shaped segments.
    name: "sendgrid_key",
    pattern: /(?<![A-Za-z0-9_])SG\.[A-Za-z0-9_-]{16,255}\.[A-Za-z0-9_-]{16,255}/g,
    replace: REDACTED,
  },
  {
    // Resend, OpenRouter, PostHog personal/project, Google API and AWS access keys.
    name: "vendor_key",
    pattern:
      /(?<![A-Za-z0-9_])(?:re_[A-Za-z0-9_]{16,255}|sk-or-v1-[A-Fa-f0-9]{32,128}|ph[cx]_[A-Za-z0-9]{20,128}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}[A-Za-z0-9._~+/=:-]*)/g,
    replace: REDACTED,
  },
  {
    // JSON Web Tokens (header.payload.signature, base64url, header starting with `{"`).
    name: "jwt",
    pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g,
    replace: REDACTED,
  },
  {
    // HTTP authorization schemes wherever they appear (`Authorization: Bearer …`).
    name: "authorization_scheme",
    pattern: /\b(Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=:-]{8,}/gi,
    replace: (_match, scheme: string) => `${scheme} ${REDACTED}`,
  },
  {
    // Keep the 32-alphanumeric floor, ignoring invisible separators. Withhold the whole
    // token-shaped tail, leaving assignment names and delimited prefixes intact. Over-window bodies
    // withhold their line before streaming overflow can erase a following label.
    name: "contextual_token",
    pattern: new RegExp(
      String.raw`(\b|${CONTEXTUAL_ENCODED_DELIMITER})((?:${SEPARATED_CONTEXT_KEYWORDS})${CONTEXT_WHITESPACE})(?=(?:${INVISIBLE_SEPARATOR_CHARACTER}*[a-z0-9]){32})(?:(?=(?:[a-z0-9._~+/=:-]|${INVISIBLE_SEPARATOR_CHARACTER}){${MAX_BOUNDED_REDACTION_PATTERN_LENGTH - 64}})[^\r\n]*|(?:${INVISIBLE_SEPARATOR_CHARACTER}*[a-z0-9]){32}(?:${CONTEXTUAL_VALUE_CHARACTER})*(?:${INVISIBLE_SEPARATOR_CHARACTER}+(?!(?:${SEPARATED_CONTEXT_KEYWORDS})${CONTEXT_WHITESPACE}|${CONTEXTUAL_PREFIXED_ASSIGNMENT})(?:${CONTEXTUAL_VALUE_CHARACTER})+)*)`,
      "giu",
    ),
    replace: (_match, delimiter: string, prefix: string) => `${delimiter}${prefix}${REDACTED}`,
  },
  {
    // Cookie headers wherever they appear (`Cookie: kovo_csrf=…; __Host-kovo.session_token=…`,
    // `"set-cookie": "…"`): every cookie value is a credential or tracks one, so the rest of the
    // line goes, whatever the cookies are called.
    name: "cookie_header",
    pattern: /\b((?:set-)?cookie["']?\s*[:=]\s*)[^\r\n]+/gi,
    replace: (_match, prefix: string) => `${prefix}${REDACTED}`,
  },

  {
    // Credentials in URL userinfo (both password and token forms).
    name: "url_credentials",
    pattern: /\b([a-z][a-z0-9+.-]{1,30}:\/\/)[^\s/?#@]{1,512}@/gi,
    replace: (_match, scheme: string) => `${scheme}${REDACTED}@`,
  },

  {
    // Credential-bearing query parameters in absolute and relative URLs.
    name: "query_credentials",
    pattern: new RegExp(
      `([?&;])(${SENSITIVE_QUERY_PARAMS.map((p) => p.replaceAll("-", "\\-")).join("|")})=[^&\\s#"'<>]*`,
      "gi",
    ),
    replace: (_match, separator: string, name: string) => `${separator}${name}=${REDACTED}`,
  },
  {
    name: "credential_assignment",
    pattern: new RegExp(String.raw`${CREDENTIAL_ASSIGNMENT_PREFIX}["']?${SPLIT_VALUE}`, "giu"),
    replace: (match, prefix: string) =>
      [REDACTED, `"${REDACTED}`, `'${REDACTED}`].includes(match.slice(prefix.length))
        ? match
        : `${prefix}${redactLines(match.slice(prefix.length))}`,
  },

  {
    // Key-value assignments of sensitive names inside free text (`password=…`, `"secret": "…"`,
    // `db_password=…`). The name must not continue a word (`mypassword` is not one), except
    // after `_` (`db_password`); the lookbehind states that without scanning back over the word.
    name: "assignment",
    pattern: new RegExp(
      String.raw`(?<![a-z0-9])((?:password|passwd|secret|token|key|api_?key|private_?key|client_?secret|access_?key)["']?[\s\p{Cc}\p{Cf}]*[:=][\s\p{Cc}\p{Cf}]*["']?)${SPLIT_VALUE}`,
      "giu",
    ),
    replace: (match, prefix: string) => `${prefix}${redactLines(match.slice(prefix.length))}`,
  },
  {
    // Bound candidate work to the 4096-character token window.
    name: "random_token",
    pattern: /[A-Za-z0-9+/_=-]{24,4096}/g,
    replace: redactRandomToken,
  },
];

/** A fresh copy of each rule's pattern by name, for tests that time each rule on hostile text. */
export function redactionRulePatterns(): ReadonlyMap<string, RegExp> {
  return new Map(RULES.map((rule) => [rule.name, new RegExp(rule.pattern)]));
}

/** The names of the built-in rules (tests pin that every class is covered). */
export const REDACTION_RULE_NAMES: readonly string[] = RULES.map((rule) => rule.name);

/** Longest text scanned; longer texts are truncated before redaction (bounds the work). */
export const MAX_REDACTED_TEXT_LENGTH = 16_384;
export const TRUNCATION_MARKER = "…[truncated]";

const WHITESPACE = /\s/;

/**
 * `text` cut to at most `maxLength` characters. A cut inside a word also drops the rest of that
 * word: it may be the start of a secret the cut made too short for its pattern (`Bearer abc`,
 * `password=ab`, part of a token), which would otherwise pass through unredacted.
 */
export function truncateForRedaction(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  let end = maxLength;
  if (!WHITESPACE.test(text.charAt(end))) {
    while (end > 0 && !WHITESPACE.test(text.charAt(end - 1))) end -= 1;
  }
  return `${text.slice(0, end)}${TRUNCATION_MARKER}`;
}

/**
 * Applies `extra` redactors (exact known values, such as the process's loaded secrets or the
 * capability issuer's), then every value-pattern rule, to `text`. The extra redactors run first so
 * a pattern cannot rewrite part of a known value before it is recognised. Texts longer than
 * `maxLength` (default {@link MAX_REDACTED_TEXT_LENGTH}) are truncated after the extra redactors
 * ({@link truncateForRedaction}), so nothing beyond the limit can leak and no known value is cut in
 * half before it is replaced.
 */
export function redactText(
  text: string,
  extra: readonly TextRedactor[] = [],
  maxLength: number = MAX_REDACTED_TEXT_LENGTH,
): string {
  let known = text;
  for (const redactor of extra) known = redactor(known);
  let result = truncateForRedaction(known, maxLength);
  for (const rule of RULES) {
    // The raw ambiguity rule requires ESC; avoid bounded lookahead at every ordinary offset.
    if (rule.name.startsWith("raw_terminal_") && !result.includes("\u001b")) continue;
    if (rule.lookback !== undefined) {
      result = redactTerminalResidual(result);
      continue;
    }
    rule.pattern.lastIndex = 0;
    result =
      typeof rule.replace === "string"
        ? result.replace(rule.pattern, rule.replace)
        : result.replace(rule.pattern, rule.replace);
  }
  return result;
}

/**
 * Every value-pattern rule applied to all of `text` (no truncation), counting the replacements: for
 * failed-step output excerpts, which report how many secrets were replaced and never which
 * (docs/decisions/verification.md "Failed-step output excerpts"). The caller bounds the text.
 */
export function redactTextCounting(text: string): {
  readonly text: string;
  readonly count: number;
} {
  let count = 0;
  let result = text;
  for (const rule of RULES) {
    // The raw ambiguity rule requires ESC; avoid bounded lookahead at every ordinary offset.
    if (rule.name.startsWith("raw_terminal_") && !result.includes("\u001b")) continue;
    if (rule.lookback !== undefined) {
      result = redactTerminalResidual(result);
      continue;
    }
    rule.pattern.lastIndex = 0;
    const { replace } = rule;
    // The replacer receives the match, its groups, then the offset and the input; each rule's own
    // replacer reads only the match and its leading groups.
    result = result.replace(rule.pattern, (match: string, ...groups: string[]) => {
      const replacement = typeof replace === "string" ? replace : replace(match, ...groups);
      // Excerpt-specific rules may already have replaced this value; count actual rewrites only.
      if (!rule.name.startsWith("terminal_escape") && replacement !== match) count += 1;
      return replacement;
    });
  }
  return { text: result, count };
}

/** Basic credentials encode user:password, including empty user/password. Pure decoding
 * of the base64 sextets keeps this contract usable without a platform dependency. */
function basicCredential(body: string): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body) || body.length % 4 === 1) return false;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let bits = 0;
  let size = 0;
  for (const character of body.replace(/=+$/, "")) {
    bits = (bits << 6) | alphabet.indexOf(character);
    size += 6;
    if (size >= 8) {
      size -= 8;
      if (((bits >> size) & 255) === 58) return true;
      bits &= (1 << size) - 1;
    }
  }
  return false;
}

/** Reject credential evidence without guessing from entropy; conservative redaction stays separate. */
export function containsCredential(value: string): boolean {
  const normalized = stripCompleteTerminalEscapes(value);
  // eslint-disable-next-line no-control-regex -- malformed terminal syntax fails closed.
  if (/[\x1b\u009b]/.test(normalized)) return true;
  return RULES.some((rule) => {
    if (rule.name === "random_token" || rule.name.startsWith("terminal_escape")) return false;
    if (rule.name.startsWith("raw_terminal_") && !value.includes("\u001b")) return false;
    return [value, normalized].some((text) => {
      const pattern = new RegExp(
        rule.pattern.source,
        rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g",
      );
      for (const match of text.matchAll(pattern)) {
        const prefix = text.slice(0, match.index);
        if (rule.name === "authorization_scheme" || rule.name === "obfuscated_bearer") {
          const scheme = match[1]?.toLowerCase();
          // Header context is always sensitive, even for incomplete or malformed values.
          const header = /authorization["']?\s*[:=]\s*["']?$/i.test(prefix);
          const body = match[0]
            .slice(match[1]?.length ?? 0)
            .trim()
            .replace(/[.,;:!?)\]'"]+$/, "");
          // Only short alphabetic prose may bypass Basic evidence. Encoded or raw
          // user:password, token-like bodies and malformed encodings remain refused.
          if (
            !header &&
            scheme === "basic" &&
            !basicCredential(body) &&
            /^[a-z]{1,15}$/i.test(body)
          )
            continue;
          // Digest's named parameters are caught by authorization_parameters; a plain
          // alphabetic word ("digest delivery") is prose, not a Digest credential.
          if (!header && scheme === "digest" && /^[a-z]+$/i.test(body)) continue;
        }
        if (
          (rule.name === "assignment" || rule.name === "credential_assignment") &&
          /^key\s*:/i.test(match[0]) &&
          /\bprimary\s+$/i.test(prefix) &&
          /^[a-z]{1,15}(?:\s|$)/.test(match[0].slice(match[1]?.length ?? 0))
        )
          continue;
        const replacement =
          typeof rule.replace === "string"
            ? rule.replace
            : rule.replace(match[0], ...match.slice(1));
        if (replacement !== match[0]) return true;
      }
      return false;
    });
  });
}

/** Correlation fields accept bounded opaque IDs; entropy is not credential evidence here. */
export function redactRequestId(value: string, extra: readonly TextRedactor[] = []): string {
  let known = value;
  for (const redactor of extra) known = redactor(known);
  return /^[A-Za-z0-9._:-]{8,128}$/.test(known) && !containsCredential(known)
    ? known
    : redactText(known);
}

/** Shortest value {@link knownValuesRedactor} replaces (shorter ones would match ordinary text). */
export const MIN_KNOWN_VALUE_LENGTH = 8;

/**
 * A redactor replacing exact occurrences of `values` (each as given and percent-encoded) with
 * `[REDACTED]`. For the free-form secrets a process loaded (webhook and session secrets, signing
 * keys, opaque vendor tokens), which have no recognisable pattern. Values shorter than
 * {@link MIN_KNOWN_VALUE_LENGTH} are ignored. Linear: one alternation of literals.
 */
export function knownValuesRedactor(values: readonly string[]): TextRedactor {
  const literals = [
    ...new Set(
      values.flatMap((value) =>
        value.length >= MIN_KNOWN_VALUE_LENGTH ? [value, encodeURIComponent(value)] : [],
      ),
    ),
  ].toSorted((a, b) => b.length - a.length);
  if (literals.length === 0) return (text) => text;
  const pattern = new RegExp(
    literals.map((literal) => literal.replaceAll(/[.*+?^${}()|[\]\\/-]/g, "\\$&")).join("|"),
    "g",
  );
  return (text) => text.replace(pattern, REDACTED);
}

/** A URL without its query string and fragment (`https://h/p?x=1#f` → `https://h/p`), unredacted. */
export function urlWithoutQuery(url: string): string {
  const cut = url.search(/[?#]/);
  return cut === -1 ? url : url.slice(0, cut);
}

/**
 * Strips the query string and fragment of a URL (`https://h/p?x=1#f` → `https://h/p`) and redacts
 * the rest, cut to `maxLength`.
 */
export function stripUrlQuery(url: string, maxLength: number = MAX_REDACTED_TEXT_LENGTH): string {
  return redactText(urlWithoutQuery(url), [], maxLength);
}

/** Fresh patterns for the ordered streaming implementation; shared rules remain the source of truth. */
export function streamingRedactionRules(
  options: { readonly preserveIdentifiers?: boolean } = {},
): readonly RedactionRule[] {
  return copyRules(RULES, options.preserveIdentifiers ?? true);
}

/** The excerpt's original terminal preparation, before literals and multiline context joining. */
export function terminalPreparationRules(): readonly RedactionRule[] {
  // A URL replacement must not make a later terminal guard consume a PEM header and leave its
  // short body fragments unrecognizable. All credential rules still run after this preparation.
  return copyRules(
    RULES.filter(
      (rule) => rule.name.startsWith("raw_terminal_") || rule.name === "terminal_escape",
    ),
  );
}

function copyRules(
  rules: readonly RedactionRule[],
  preserveIdentifiers = true,
): readonly RedactionRule[] {
  return rules.map((rule) => {
    const copy = {
      name: rule.name,
      pattern: new RegExp(rule.pattern),
      replace:
        rule.name === "random_token" && !preserveIdentifiers
          ? (token: string) => redactRandomCandidate(token, false)
          : rule.replace,
    };
    return rule.lookback === undefined ? copy : Object.assign(copy, { lookback: rule.lookback });
  });
}
