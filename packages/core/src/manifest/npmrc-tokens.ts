// The one strict `.npmrc` tokenizer every `.npmrc` check uses (#1841, #1842).
//
// npm 10/11 and pnpm 9/10 read `.npmrc` with the `ini` package: it splits lines on any run of CR
// and LF, treats a line starting with optional whitespace (any Unicode whitespace) and `#` or `;`
// as a comment, cuts an unquoted key or value at the first unescaped `#` or `;`, JSON-decodes a
// quoted key or value, trims Unicode whitespace and turns `[section]` into a nested object. npm
// then expands `${VAR}` and pnpm 9/10 also `${VAR:-default}`, in keys and values. pnpm 11/12 use
// their own readers: pnpm 12 keeps an inline comment in a value and ignores section headers,
// so the keys under one apply at the top level. (All probed against the real tools; the
// config-differential harness in `@kovo/adapters` keeps checking it.)
//
// Kovo does not model any of those readers. It accepts only a subset that every one of them reads
// the same way, and refuses everything else as unverifiable, so a hidden or rewritten key can
// never reach a check. Values are returned with how far Kovo could decode them; each check
// decides which kinds it accepts. Nothing here is ever returned to a caller outside the checks:
// the file often holds credentials.

/** A decoded value, and which readers decode it to exactly this text. */
export type NpmrcValue =
  /** Every supported reader reads exactly `text` (no inline comment, escape or expansion). */
  | { readonly kind: "plain"; readonly text: string }
  /**
   * `ini` (npm 10/11, pnpm 9/10) reads `text`: an inline `#` or `;` comment was cut. pnpm 12
   * keeps the comment in the value.
   */
  | { readonly kind: "ini"; readonly text: string }
  /** Escapes, environment expansion or nested quotes: no single reading. */
  | { readonly kind: "opaque" };

export interface NpmrcEntry {
  /** 1-based line. */
  readonly line: number;
  /** The key exactly as every reader sees it, without a trailing `[]`. */
  readonly key: string;
  /** `key[]=…`: an array element. */
  readonly array: boolean;
  /** null for a line without `=` (ini reads it as `true`). */
  readonly value: NpmrcValue | null;
}

export type NpmrcTokens =
  | { readonly ok: true; readonly entries: readonly NpmrcEntry[] }
  | { readonly ok: false; readonly reason: "npmrc_unverifiable"; readonly line: number };

/**
 * Characters Kovo refuses anywhere in the file. C0 controls other than tab, LF and CR, DEL, NEL,
 * U+2028, U+2029 and the BOM: readers disagree on whether each one ends a line or is trimmed.
 * A CR not followed by LF is refused separately.
 */
// eslint-disable-next-line no-control-regex -- control characters are exactly what is refused
const REFUSED_ANYWHERE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u0085\u2028\u2029\ufeff]/u;

/**
 * Unicode whitespace other than space and tab, refused outside comments: `ini` and pnpm trim it
 * from keys and values and treat it as indentation before a comment, Kovo does not.
 */
const OTHER_WHITESPACE = /[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/u;

const BLANK = /^[ \t]*$/u;
const COMMENT = /^[ \t]*[#;]/u;
const SECTION = /^[ \t]*\[/u;

/**
 * Keys every reader reads verbatim: a plain setting name, a scope setting (`@scope:registry`) or
 * a per-registry setting (`//host/path/:_authToken`). Only a per-registry key may hold an
 * environment reference, and only `${NAME}`: whatever it expands to, the key still starts with
 * `//` and names a per-registry setting, never `registry` or a scope (#1853 review N4). Quotes,
 * escapes, `#`, `;`, whitespace and every other `${` form are refused.
 */
const KEY =
  /^(?:[A-Za-z0-9_.-]+|@[A-Za-z0-9_.~-]+:[A-Za-z0-9_.-]+|\/\/(?:[A-Za-z0-9_.~:/@%+-]|\$\{[A-Za-z_][A-Za-z0-9_]*\})+)$/u;

/** Keys naming JavaScript object machinery; `ini` and pnpm treat them inconsistently. */
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Text inside a quoted value that every reader decodes to itself. */
const SAFE_QUOTED = /^[^"'\\#;[\]{}]*$/u;

function decodeValue(raw: string): NpmrcValue {
  if (raw.includes("${")) return { kind: "opaque" };
  const first = raw.charAt(0);
  if (raw.length >= 2 && (first === '"' || first === "'") && raw.endsWith(first)) {
    const inner = raw.slice(1, -1);
    return SAFE_QUOTED.test(inner) ? { kind: "plain", text: inner } : { kind: "opaque" };
  }
  if (/["'\\]/u.test(raw)) return { kind: "opaque" };
  const comment = raw.search(/[#;]/u);
  if (comment === -1) return { kind: "plain", text: raw };
  return { kind: "ini", text: raw.slice(0, comment).replace(/[ \t]+$/u, "") };
}

/**
 * Tokenizes root `.npmrc` text (callers bound its length first). Refuses, as
 * `npmrc_unverifiable` with the first offending line: a CR not followed by LF, the characters in
 * `REFUSED_ANYWHERE`, other Unicode whitespace outside comments, section headers, keys outside
 * `KEY` (quoted, escaped, commented, expanded), reserved keys, and a key given twice (except as
 * repeated `key[]` array elements).
 */
export function tokenizeNpmrc(text: string): NpmrcTokens {
  const lines = text.split("\n");
  const entries: NpmrcEntry[] = [];
  const seen = new Map<string, boolean>();
  for (const [index, withCr] of lines.entries()) {
    const line = index + 1;
    const refuse = { ok: false, reason: "npmrc_unverifiable", line } as const;
    // CRLF ends a line; a CR anywhere else, the end of the file included, is refused.
    const raw = withCr.endsWith("\r") && index < lines.length - 1 ? withCr.slice(0, -1) : withCr;
    if (raw.includes("\r") || REFUSED_ANYWHERE.test(raw)) return refuse;
    if (BLANK.test(raw) || COMMENT.test(raw)) continue;
    if (OTHER_WHITESPACE.test(raw) || SECTION.test(raw)) return refuse;
    const equals = raw.indexOf("=");
    const rawKey = (equals === -1 ? raw : raw.slice(0, equals)).replace(/^[ \t]+|[ \t]+$/gu, "");
    const array = rawKey.length > 2 && rawKey.endsWith("[]");
    const key = array ? rawKey.slice(0, -2) : rawKey;
    if (!KEY.test(key) || RESERVED_KEYS.has(key.toLowerCase())) return refuse;
    const previous = seen.get(key);
    if (previous !== undefined && !(previous && array)) return refuse;
    seen.set(key, array);
    const value =
      equals === -1 ? null : decodeValue(raw.slice(equals + 1).replace(/^[ \t]+|[ \t]+$/gu, ""));
    entries.push({ line, key, array, value });
  }
  return { ok: true, entries };
}

/**
 * The conservative name of a key: lower case, without `-`, `_` and a trailing `[]`. Checks match
 * refused keys on it, so every spelling a reader might fold together is caught.
 */
export function npmrcKeyName(key: string): string {
  return key
    .toLowerCase()
    .replace(/(?:\[\])+$/u, "")
    .replaceAll(/[-_]/gu, "");
}
