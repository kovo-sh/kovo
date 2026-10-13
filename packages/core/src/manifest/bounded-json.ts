// A strict, bounded JSON parser for hostile repository files (package.json, package-lock.json).
//
// `JSON.parse` has no size, depth or node limits, silently keeps the last of duplicate keys (a
// smuggling vector when two tools disagree on which one wins) and recurses on nesting. This parser
// is iterative, rejects duplicate keys, and stops at the first limit it crosses. It accepts exactly
// RFC 8259 JSON (plus one leading byte-order mark, which npm also strips).

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface JsonLimits {
  /** Maximum input length in UTF-16 code units. */
  readonly maxLength: number;
  /** Maximum nesting depth of arrays and objects (the top-level value is depth 1). */
  readonly maxDepth: number;
  /** Maximum number of values (every scalar, array and object counts once). */
  readonly maxNodes: number;
  /** Maximum length of any single string (keys included). */
  readonly maxStringLength: number;
}

export const BOUNDED_JSON_ERRORS = [
  "too_large",
  "too_deep",
  "too_many_nodes",
  "string_too_long",
  "duplicate_key",
  "syntax",
] as const;
export type BoundedJsonError = (typeof BOUNDED_JSON_ERRORS)[number];

export type BoundedJsonResult =
  | { readonly ok: true; readonly value: JsonValue }
  | { readonly ok: false; readonly error: BoundedJsonError; readonly offset: number };

export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

type Frame =
  | { readonly kind: "array"; readonly value: JsonValue[] }
  | {
      readonly kind: "object";
      readonly value: JsonObject;
      readonly keys: Set<string>;
      key: string;
    };

const WHITESPACE = /[ \t\n\r]*/y;
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

class JsonFailure extends Error {
  readonly error: BoundedJsonError;
  readonly offset: number;

  constructor(error: BoundedJsonError, offset: number) {
    super(error);
    this.error = error;
    this.offset = offset;
  }
}

/** Sets an own enumerable property, including `__proto__`, exactly as `JSON.parse` does. */
function defineOwn(target: JsonObject, key: string, value: JsonValue): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

class Parser {
  private readonly text: string;
  private readonly limits: JsonLimits;
  private pos: number;
  private nodes = 0;

  constructor(text: string, limits: JsonLimits) {
    this.text = text;
    this.limits = limits;
    this.pos = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  }

  parse(): JsonValue {
    const stack: Frame[] = [];
    for (;;) {
      // Parse one value start; containers push a frame and loop for their first member.
      this.skipWhitespace();
      let value: JsonValue;
      const char = this.text[this.pos];
      if (char === "{" || char === "[") {
        this.countNode();
        if (stack.length + 1 > this.limits.maxDepth) throw new JsonFailure("too_deep", this.pos);
        this.pos += 1;
        this.skipWhitespace();
        if (char === "[") {
          if (this.text[this.pos] === "]") {
            this.pos += 1;
            value = [];
          } else {
            stack.push({ kind: "array", value: [] });
            continue;
          }
        } else if (this.text[this.pos] === "}") {
          this.pos += 1;
          value = {};
        } else {
          const frame: Frame = { kind: "object", value: {}, keys: new Set(), key: "" };
          frame.key = this.parseKey(frame.keys);
          stack.push(frame);
          continue;
        }
      } else {
        value = this.parseScalar();
      }

      // Attach the completed value, closing every container it completes.
      for (;;) {
        const top = stack[stack.length - 1];
        if (top === undefined) {
          this.skipWhitespace();
          if (this.pos !== this.text.length) throw new JsonFailure("syntax", this.pos);
          return value;
        }
        if (top.kind === "array") top.value.push(value);
        else defineOwn(top.value, top.key, value);
        this.skipWhitespace();
        const next = this.text[this.pos];
        if (next === ",") {
          this.pos += 1;
          if (top.kind === "object") top.key = this.parseKey(top.keys);
          break;
        }
        if ((top.kind === "array" && next === "]") || (top.kind === "object" && next === "}")) {
          this.pos += 1;
          stack.pop();
          value = top.value;
          continue;
        }
        throw new JsonFailure("syntax", this.pos);
      }
    }
  }

  private countNode(): void {
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) throw new JsonFailure("too_many_nodes", this.pos);
  }

  private skipWhitespace(): void {
    WHITESPACE.lastIndex = this.pos;
    WHITESPACE.exec(this.text);
    this.pos = WHITESPACE.lastIndex;
  }

  /** Parses `"key" :` and rejects a key the object already has. */
  private parseKey(keys: Set<string>): string {
    this.skipWhitespace();
    if (this.text[this.pos] !== '"') throw new JsonFailure("syntax", this.pos);
    const start = this.pos;
    const key = this.parseString();
    if (keys.has(key)) throw new JsonFailure("duplicate_key", start);
    keys.add(key);
    this.skipWhitespace();
    if (this.text[this.pos] !== ":") throw new JsonFailure("syntax", this.pos);
    this.pos += 1;
    return key;
  }

  private parseScalar(): JsonValue {
    const char = this.text[this.pos];
    this.countNode();
    if (char === '"') return this.parseString();
    if (char === "t") return this.parseLiteral("true", true);
    if (char === "f") return this.parseLiteral("false", false);
    if (char === "n") return this.parseLiteral("null", null);
    NUMBER.lastIndex = this.pos;
    const match = NUMBER.exec(this.text);
    if (match === null) throw new JsonFailure("syntax", this.pos);
    this.pos = NUMBER.lastIndex;
    return Number(match[0]);
  }

  private parseLiteral<T extends JsonValue>(word: string, value: T): T {
    if (!this.text.startsWith(word, this.pos)) throw new JsonFailure("syntax", this.pos);
    this.pos += word.length;
    return value;
  }

  private parseString(): string {
    const start = this.pos;
    this.pos += 1; // opening quote
    const parts: string[] = [];
    let length = 0;
    for (;;) {
      // Consume a run of ordinary characters (not a quote, backslash or control character).
      let runEnd = this.pos;
      while (runEnd < this.text.length) {
        const code = this.text.charCodeAt(runEnd);
        if (code === 0x22 || code === 0x5c || code < 0x20) break;
        runEnd += 1;
      }
      if (runEnd > this.pos) {
        parts.push(this.text.slice(this.pos, runEnd));
        length += runEnd - this.pos;
        this.pos = runEnd;
      }
      if (length > this.limits.maxStringLength) throw new JsonFailure("string_too_long", start);
      const char = this.text[this.pos];
      if (char === '"') {
        this.pos += 1;
        return parts.join("");
      }
      if (char !== "\\") throw new JsonFailure("syntax", this.pos); // control character or EOF
      const escape = this.text[this.pos + 1];
      if (escape === undefined) throw new JsonFailure("syntax", this.pos);
      let decoded: string;
      switch (escape) {
        case '"':
        case "\\":
        case "/":
          decoded = escape;
          break;
        case "b":
          decoded = "\b";
          break;
        case "f":
          decoded = "\f";
          break;
        case "n":
          decoded = "\n";
          break;
        case "r":
          decoded = "\r";
          break;
        case "t":
          decoded = "\t";
          break;
        case "u": {
          const hex = this.text.slice(this.pos + 2, this.pos + 6);
          if (!HEX4.test(hex)) throw new JsonFailure("syntax", this.pos);
          decoded = String.fromCharCode(Number.parseInt(hex, 16));
          this.pos += 4;
          break;
        }
        default:
          throw new JsonFailure("syntax", this.pos);
      }
      parts.push(decoded);
      length += 1;
      this.pos += 2;
    }
  }
}

/**
 * Parses `text` as strict JSON within `limits`. Never throws: every failure, including a limit, is
 * returned with the offset where it was detected (offsets are safe to log; content is not).
 */
export function parseBoundedJson(text: string, limits: JsonLimits): BoundedJsonResult {
  if (text.length > limits.maxLength) return { ok: false, error: "too_large", offset: 0 };
  try {
    return { ok: true, value: new Parser(text, limits).parse() };
  } catch (error) {
    if (error instanceof JsonFailure)
      return { ok: false, error: error.error, offset: error.offset };
    throw error;
  }
}
