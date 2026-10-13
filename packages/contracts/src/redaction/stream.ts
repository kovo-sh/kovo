import { REDACTED } from "./marker.js";
import {
  CREDENTIAL_ASSIGNMENT_PREFIX,
  SEPARATED_CONTEXT_KEYWORDS,
  CONTEXT_WHITESPACE,
  SLASH_USERINFO_PREFIX,
  SLASH_USERINFO_BODY,
  SLASH_USERINFO_SHORT_BODY,
  URL_AUTHORITY_BODY,
  URL_USERINFO_BODY,
  CREDENTIAL_NAME_PREFIX,
  ENCODED_CREDENTIAL_NAMES,
  CONTEXTUAL_ASSIGNMENT_NAMES,
  CONTEXTUAL_ENCODED_DELIMITER,
  OBFUSCATED_TOKEN_PREFIX,
  INVISIBLE_SEPARATOR_CHARACTER,
  OBFUSCATED_BODY_CHARACTER,
  MAX_BOUNDED_REDACTION_PATTERN_LENGTH,
  residualMatchStart,
  streamingRedactionRules,
  terminalPreparationRules,
  type RedactionRule,
} from "./patterns.js";

export interface RedactionTextSpan {
  readonly text: string;
  readonly stream: string;
  readonly offset: number;
  /** Replacement characters all retain the replaced source's starting offset. */
  readonly replacement?: true;
}

const MAX_ORIGIN_SPANS = 8192;
class Origins {
  private spans: (RedactionTextSpan & { readonly endOffset: number })[] = [];
  private head = 0;
  readonly output: RedactionTextSpan[] = [];
  append(spans: readonly RedactionTextSpan[]): void {
    if (this.head > 0) {
      this.spans = this.spans.slice(this.head);
      this.head = 0;
    }
    for (const span of spans) {
      if (span.text === "") continue;
      const last = this.spans.at(-1);
      if (
        last !== undefined &&
        !last.replacement &&
        !span.replacement &&
        last.stream === span.stream &&
        last.endOffset === span.offset
      ) {
        this.spans[this.spans.length - 1] = {
          ...last,
          text: last.text + span.text,
          endOffset: span.offset + new TextEncoder().encode(span.text).byteLength,
        };
      } else
        this.spans.push({
          ...span,
          endOffset: span.offset + new TextEncoder().encode(span.text).byteLength,
        });
      if (this.spans.length > MAX_ORIGIN_SPANS) throw new Error("redaction_origin_budget");
    }
  }
  get bufferedSpans(): number {
    return this.spans.length - this.head;
  }
  take(length: number, keep: boolean): RedactionTextSpan | undefined {
    let first: RedactionTextSpan | undefined;
    while (length > 0) {
      const span = this.spans[this.head];
      if (span === undefined) throw new Error("redaction_origin_missing");
      first ??= span;
      const count = Math.min(length, span.text.length);
      const text = span.text.slice(0, count);
      if (keep)
        this.output.push({
          text,
          stream: span.stream,
          offset: span.offset,
          ...(span.replacement ? { replacement: true } : {}),
        });
      if (this.output.length > MAX_ORIGIN_SPANS) throw new Error("redaction_origin_budget");
      if (count === span.text.length) this.head += 1;
      else
        this.spans[this.head] = {
          ...span,
          text: span.text.slice(count),
          offset: span.replacement
            ? span.offset
            : span.offset + new TextEncoder().encode(text).byteLength,
        };
      length -= count;
    }
    return first;
  }
  replace(length: number, text: string): void {
    const first = this.take(length, false);
    if (first !== undefined && text !== "")
      this.output.push({ text, stream: first.stream, offset: first.offset, replacement: true });
    if (this.output.length > MAX_ORIGIN_SPANS) throw new Error("redaction_origin_budget");
  }
  drain(): RedactionTextSpan[] {
    return this.output.splice(0);
  }
}
interface Stage {
  origins?: Origins;
  push(text: string, final: boolean): string;
  readonly count: number;
  readonly bufferedCharacters: number;
}

// Derived from shared token formats; includes the trailing lookahead character. Unbounded values
// cap-and-flush at this window: a recognized value is replaced once and its continuation discarded.
// An incomplete over-window credential prefix is conservatively redacted through its delimiter.
// This deliberately redacts some malformed overlong JWTs/prefixes that the nonstreaming scrubber
// would leave unchanged. Input is processed in fixed blocks, independently of caller chunk sizes.
const PATTERN_MATCH_WINDOW = MAX_BOUNDED_REDACTION_PATTERN_LENGTH;
const ENTROPY_MATCH_WINDOW = 4097;
/** Maximum retained working window per built-in rule, including its amortized input batch. */
export const STREAM_REDACTION_CARRY = 2 * Math.max(PATTERN_MATCH_WINDOW, ENTROPY_MATCH_WINDOW);

const INCOMPLETE_PREFIX_PATTERNS: Readonly<Record<string, readonly RegExp[]>> = {
  // eslint-disable-next-line no-control-regex -- hold incomplete terminal escapes until their terminator arrives.
  terminal_escape: [/\x1b(?:\[[0-9;:]{0,64}|\][^\x07\x1b]*|[ -/]+)?$/],
  // eslint-disable-next-line no-control-regex -- retain residual malformed terminal syntax to its delimiter.
  terminal_escape_residual: [/[\x1b\u009b][^\r\n]*$/],
  slash_url_userinfo: [
    new RegExp(String.raw`${SLASH_USERINFO_PREFIX}${SLASH_USERINFO_SHORT_BODY}*$`, "iu"),
  ],
  obfuscated_url_userinfo: [
    /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)(?:[^\s/?#@\p{Cc}\p{Cf}]|[\p{Cc}\p{Cf}])*$/iu,
  ],
  obfuscated_token: [
    new RegExp(String.raw`(?<![A-Za-z0-9_])(?:${OBFUSCATED_TOKEN_PREFIX})[\p{Cc}\p{Cf}]*$`, "u"),
  ],
  obfuscated_bearer: [/\b(?:Bearer|Basic|Digest)[\p{Cc}\p{Cf}]+$/iu],
  authorization_parameters: [
    /\bDigest[\s\p{Cc}\p{Cf}]+$/iu,
    /\bDigest[\s\p{Cc}\p{Cf}]+(?:username|realm|nonce|uri|response|algorithm|cnonce|opaque|qop|nc)[\s\p{Cc}\p{Cf}]*$/iu,
  ],
  jwt: [/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_.-]*$/],
  authorization_scheme: [/\b(?:Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=:-]{0,7}$/i],
  cookie_header: [/\b(?:set-)?cookie["']?\s*$/i, /\b(?:set-)?cookie["']?\s*[:=]\s*$/i],
  credential_assignment: [
    new RegExp(`${CREDENTIAL_NAME_PREFIX}$`, "iu"),
    new RegExp(`${CREDENTIAL_ASSIGNMENT_PREFIX}["']?$`, "iu"),
  ],
  quoted_credential_assignment: [
    new RegExp(`${CREDENTIAL_NAME_PREFIX}$`, "iu"),
    new RegExp(`${CREDENTIAL_ASSIGNMENT_PREFIX}$`, "iu"),
    new RegExp(String.raw`${CREDENTIAL_ASSIGNMENT_PREFIX}"[^"\r\n]*$`, "iu"),
    new RegExp(String.raw`${CREDENTIAL_ASSIGNMENT_PREFIX}'[^'\r\n]*$`, "iu"),
  ],
  contextual_token: [
    new RegExp(
      String.raw`(?:\b|${CONTEXTUAL_ENCODED_DELIMITER})(?:${SEPARATED_CONTEXT_KEYWORDS})${CONTEXT_WHITESPACE}(?:${INVISIBLE_SEPARATOR_CHARACTER}*[a-z0-9]){0,31}${INVISIBLE_SEPARATOR_CHARACTER}*$`,
      "iu",
    ),
  ],
  assignment: [
    /(?<![a-z0-9])(?:password|passwd|secret|token|api_?key|private_?key|client_?secret|access_?key)["']?\s*$/i,
    /(?<![a-z0-9])(?:password|passwd|secret|token|api_?key|private_?key|client_?secret|access_?key)["']?\s*[:=]\s*["']?[^\s"',;&}]{0,3}$/i,
  ],
};

// These ASCII words are required by both the corresponding complete-match and incomplete-prefix
// patterns, with the same Unicode case folding. Skip their heavy scans only when the whole retained
// window lacks a required word; keep carry, origin tracking and flush boundaries unchanged.
const REQUIRED_WORDS: Readonly<Record<string, RegExp>> = {
  slash_url_userinfo: /:\/\//,
  obfuscated_url_userinfo: /:\/\//,
  overlong_url_authority: /:\/\//,
  // eslint-disable-next-line no-control-regex -- raw ambiguity requires ESC.
  raw_terminal_credential: /\x1b/,
  // eslint-disable-next-line no-control-regex -- dense ambiguity also requires ESC.
  raw_terminal_dense: /\x1b/,
  // Both complete escapes and incomplete escape prefixes require ESC.
  // eslint-disable-next-line no-control-regex -- terminal normalization requires ESC.
  terminal_escape: /\x1b/,
  // eslint-disable-next-line no-control-regex -- residual matches require a terminal introducer.
  terminal_escape_residual: /[\x1b\u009b]/,
  authorization_parameters: /digest/iu,
  obfuscated_bearer: /bearer|basic|digest/iu,
  obfuscated_cookie: /cookie/iu,
  credential_assignment: new RegExp(`${ENCODED_CREDENTIAL_NAMES}|key`, "iu"),
  quoted_credential_assignment: new RegExp(`${ENCODED_CREDENTIAL_NAMES}|key`, "iu"),
  contextual_token: /token|secret|key/iu,
};

// A split name necessarily has a separator. Keep the ordinary-word check cheap;
// invoke the bounded split-name grammar only when the ordinary spelling is absent.
const ASSIGNMENT_SEPARATOR = new RegExp(INVISIBLE_SEPARATOR_CHARACTER, "u");
const SPLIT_ASSIGNMENT_WORDS = new RegExp(CONTEXTUAL_ASSIGNMENT_NAMES, "iu");
const SPLIT_CONTEXT_WORDS = new RegExp(SEPARATED_CONTEXT_KEYWORDS, "iu");

class PatternStage implements Stage {
  origins?: Origins;
  private pending = "";
  private context = "";
  private discard: RegExp | undefined;
  count = 0;
  private readonly rule: RedactionRule;
  private readonly carry: number;

  constructor(rule: RedactionRule, carry: number) {
    this.rule = rule;
    this.carry = carry;
  }

  push(text: string, final: boolean): string {
    let output = "";
    let index = 0;
    while (index < text.length) {
      if (this.discard !== undefined && this.retainsUrlContext()) {
        const amount = Math.min(2 * this.carry - this.pending.length, text.length - index);
        this.pending += text.slice(index, index + amount);
        index += amount;
        if (this.pending.length === 2 * this.carry) this.flushUrlDiscard(false);
        continue;
      }
      if (this.discard !== undefined) {
        const discardStart = index;
        // Consume one contiguous run rather than invoking a regex once per character.
        // Sticky matching preserves the exact start and exposes assignment lookahead context.
        this.discard.lastIndex = index;
        const run = this.discard.exec(text);
        if (run !== null) {
          index += run[0].length;
          this.context = text.charAt(index - 1);
        }
        this.origins?.take(index - discardStart, false);
        if (index === text.length) break;
        this.discard = undefined;
      }
      const amount = Math.min(2 * this.carry - this.pending.length, text.length - index);
      this.pending += text.slice(index, index + amount);
      index += amount;
      // Wait for a fixed block; rescanning the carry on every tiny push would be quadratic.
      if (this.pending.length === 2 * this.carry) output += this.flush(false);
    }
    if (final) {
      if (this.discard !== undefined && this.retainsUrlContext()) this.flushUrlDiscard(true);
      this.discard = undefined;
      output += this.flush(true);
    }
    return output;
  }

  private retainsUrlContext(): boolean {
    return (
      this.rule.name === "slash_url_userinfo" ||
      this.rule.name === "overlong_url_authority" ||
      this.rule.name === "obfuscated_url_userinfo"
    );
  }

  /** Keep a bounded suffix so a split contextual label can terminate URL withholding. */
  private flushUrlDiscard(final: boolean): void {
    const source = this.context + this.pending;
    const offset = this.context.length;
    let discard = this.discard!;
    // A complete short tail still belongs to the withheld userinfo, even if its
    // authority began before the window. Keep @ for the normal output path.
    if (this.rule.name === "obfuscated_url_userinfo") {
      const terminated = new RegExp(`${URL_USERINFO_BODY}+@`, "iuy");
      terminated.lastIndex = offset;
      if (terminated.test(source)) discard = new RegExp(`${URL_USERINFO_BODY}+`, "iuy");
    }
    discard.lastIndex = offset;
    const run = discard.exec(source);
    const end = offset + (run?.[0].length ?? 0);
    // The bounded URL label grammar, including CSI sequences, fits within one carry window.
    const cut = final ? source.length : Math.max(offset, source.length - this.carry);
    const consumed = Math.min(end, cut);
    this.origins?.take(consumed - offset, false);
    if (consumed > offset) this.context = source.charAt(consumed - 1);
    this.pending = source.slice(consumed);
    if (end < cut || final) this.discard = undefined;
  }

  get bufferedCharacters(): number {
    return this.pending.length;
  }

  private flush(final: boolean): string {
    // Entropy candidates are consecutive bounded windows, not boundary-sensitive tokens. A
    // previous emitted character must not restart a candidate at index zero and hide the next
    // window from the context filter (which would leak long random runs).
    const context = this.rule.name === "random_token" ? "" : this.context;
    const source = context + this.pending;
    const offset = context.length;
    let cut = final ? source.length : source.length - this.carry;
    this.rule.pattern.lastIndex = 0;
    let applicable = REQUIRED_WORDS[this.rule.name]?.test(source) ?? true;
    if (
      !applicable &&
      (this.rule.name === "credential_assignment" ||
        this.rule.name === "quoted_credential_assignment" ||
        this.rule.name === "contextual_token") &&
      ASSIGNMENT_SEPARATOR.test(source)
    ) {
      if (
        this.rule.name === "credential_assignment" ||
        this.rule.name === "quoted_credential_assignment"
      )
        applicable = SPLIT_ASSIGNMENT_WORDS.test(source);
      else if (this.rule.name === "contextual_token") applicable = SPLIT_CONTEXT_WORDS.test(source);
    }
    const matches = applicable
      ? [...source.matchAll(this.rule.pattern)]
          .filter((match) => match.index >= offset)
          .map((match) => {
            if (this.rule.lookback === undefined) return match;
            const end = match.index + match[0].length;
            match.index = residualMatchStart(source, match.index, offset);
            match[0] = source.slice(match.index, end);
            return match;
          })
      : [];
    if (!final) {
      for (const match of matches) {
        const end = match.index + match[0].length;
        if ((match.index < cut && end > cut) || end === source.length)
          cut = Math.min(cut, match.index);
      }
      const incomplete = applicable ? this.incompletePrefix(source) : undefined;
      if (incomplete !== undefined && incomplete >= offset)
        cut = Math.min(
          cut,
          this.rule.lookback === undefined
            ? incomplete
            : residualMatchStart(source, incomplete, offset),
        );
    }
    const overflow = !final && source.length - cut > this.carry;
    // Emit whole code points so the origin tracker and downstream UTF-8 encoding agree.
    if (
      !overflow &&
      cut > offset &&
      cut < source.length &&
      /[\uD800-\uDBFF]/.test(source.charAt(cut - 1)) &&
      /[\uDC00-\uDFFF]/.test(source.charAt(cut))
    )
      cut -= 1;
    let output = "";
    let start = offset;
    // Match decisions use the complete source (including the unconsumed lookahead), never a
    // truncated substring whose synthetic end could satisfy a Kovo secret's negative lookahead.
    for (const match of matches) {
      const end = match.index + match[0].length;
      if (end > cut) break;
      output += source.slice(start, match.index);
      this.origins?.take(match.index - start, true);
      const replacement = this.replacement(match);
      output += replacement;
      if (replacement === match[0]) this.origins?.take(match[0].length, true);
      else this.origins?.replace(match[0].length, replacement);
      if (!this.rule.name.startsWith("terminal_escape") && replacement !== match[0])
        this.count += 1;
      start = end;
    }
    output += source.slice(start, cut);
    this.origins?.take(cut - start, true);
    if (overflow) {
      // Cap-and-flush an over-window candidate. Completed matches retain shared replacement
      // semantics; unresolved prefixes are conservatively redacted, never buffered indefinitely.
      const match = matches.find((candidate) => candidate.index === cut);
      const scheme =
        match === undefined && this.rule.name === "obfuscated_url_userinfo"
          ? (/^[a-z][a-z0-9+.-]{0,31}:\/\//iu.exec(source.slice(cut))?.[0] ?? "")
          : "";
      const replacement = match === undefined ? `${scheme}${REDACTED}` : this.replacement(match);
      output += replacement;
      if (
        !this.rule.name.startsWith("terminal_escape") &&
        (match === undefined || replacement !== match[0])
      )
        this.count += 1;
      const matchEnd = match === undefined ? source.length : cut + match[0].length;
      // Keep a possible split label before entering URL discard mode, as well as during it.
      const end =
        this.retainsUrlContext() && matchEnd === source.length
          ? Math.max(cut, matchEnd - this.carry)
          : matchEnd;
      this.origins?.replace(end - cut, replacement);
      this.context = source.charAt(end - 1);
      this.pending = source.slice(end);
      if (matchEnd === source.length) {
        const continuation = this.continuation(match !== undefined);
        this.discard = new RegExp(`(?:${continuation.source})+`, `${continuation.flags}y`);
      }
    } else {
      if (cut > offset) this.context = source.charAt(cut - 1);
      this.pending = source.slice(cut);
    }
    return output;
  }

  private replacement(match: RegExpMatchArray): string {
    return typeof this.rule.replace === "string"
      ? this.rule.replace
      : this.rule.replace(match[0], ...match.slice(1));
  }

  // Overflow continuations are oversized/unterminated forms; preserve following context.
  // Complete short @-terminated matches use the unguarded rule and incomplete-prefix body.
  private continuation(recognized: boolean): RegExp {
    if (
      !recognized &&
      this.rule.name !== "jwt" &&
      this.rule.name !== "obfuscated_url_userinfo" &&
      !this.retainsUrlContext()
    )
      return /[^\r\n]/;
    switch (this.rule.name) {
      case "slash_url_userinfo":
        return new RegExp(SLASH_USERINFO_BODY, "iu");
      case "raw_terminal_credential":
      case "raw_terminal_dense":
      case "terminal_escape_residual":
        return /[^\r\n]/;
      case "terminal_escape":
        // eslint-disable-next-line no-control-regex -- BEL and ESC terminate an oversized OSC sequence.
        return /[^\x07\x1b]/;
      case "encoded_bytes":
        return /[a-f0-9%x\\]/i;
      case "obfuscated_token":
      case "obfuscated_bearer":
        return new RegExp(OBFUSCATED_BODY_CHARACTER, "u");
      case "obfuscated_cookie":
        return new RegExp(OBFUSCATED_BODY_CHARACTER, "u");
      case "overlong_url_authority":
      case "obfuscated_url_userinfo":
        return new RegExp(URL_AUTHORITY_BODY, "iu");
      case "jwt":
        return recognized ? /[A-Za-z0-9_-]/ : /[A-Za-z0-9_.-]/;
      case "authorization_parameters":
        return /[^\r\n]/;
      case "authorization_scheme":
        return /[A-Za-z0-9._~+/=:-]/;
      case "credential_assignment":
      case "assignment":
        return /[^\s"',;&}]/;
      case "quoted_credential_assignment":
        return /[^\r\n]/;
      case "contextual_token":
        // The shared over-window branch withholds the line, including partial labels.
        return /[^\r\n]/;
      case "vendor_key":
        return /[a-z0-9._~+/=:-]/i;
      case "query_credentials":
        return /[^&\s#"'<>]/;
      case "cookie_header":
        return /[^\r\n]/;
      default:
        throw new Error("Bounded redaction pattern exceeded its window");
    }
  }

  private incompletePrefix(source: string): number | undefined {
    // These patterns scan at most two fixed windows and have no ambiguous adjacent whitespace
    // quantifiers. A prefix exceeding the window is conservatively flushed, not repeatedly scanned.
    for (const pattern of INCOMPLETE_PREFIX_PATTERNS[this.rule.name] ?? []) {
      const match = pattern.exec(source);
      if (match !== null) return match.index;
    }
    return undefined;
  }
}

class PemStage implements Stage {
  origins?: Origins;
  private pending = "";
  private inside = false;
  constructor(inside = false) {
    this.inside = inside;
  }
  count = 0;

  get bufferedCharacters(): number {
    return this.pending.length;
  }

  push(text: string, final: boolean): string {
    this.pending += text;
    let output = "";
    for (;;) {
      if (this.inside) {
        const end = /-----END [A-Z0-9 ]{1,64}-----/.exec(this.pending);
        if (end === null) {
          this.origins?.take(
            final ? this.pending.length : Math.max(0, this.pending.length - 80),
            false,
          );
          this.pending = final ? "" : this.pending.slice(-80);
          return output;
        }
        this.origins?.take(end.index + end[0].length, false);
        this.pending = this.pending.slice(end.index + end[0].length);
        this.inside = false;
      }
      const begin = /-----BEGIN [A-Z0-9 ]{1,64}-----/.exec(this.pending);
      if (begin === null) {
        let cut = final ? this.pending.length : Math.max(0, this.pending.length - 80);
        if (
          cut > 0 &&
          cut < this.pending.length &&
          /[\uD800-\uDBFF]/.test(this.pending.charAt(cut - 1)) &&
          /[\uDC00-\uDFFF]/.test(this.pending.charAt(cut))
        )
          cut -= 1;
        output += this.pending.slice(0, cut);
        this.origins?.take(cut, true);
        this.pending = this.pending.slice(cut);
        return output;
      }
      output += this.pending.slice(0, begin.index) + "[REDACTED:pem]";
      this.origins?.take(begin.index, true);
      this.origins?.replace(begin[0].length, "[REDACTED:pem]");
      this.pending = this.pending.slice(begin.index + begin[0].length);
      this.inside = true;
      this.count += 1;
    }
  }
}

// PatternStage resets lastIndex before synchronous matchAll (which clones the RegExp).
// Share compiled built-ins, while each stream retains its own stages, pending text and counts.
const STREAM_RULES = streamingRedactionRules();
const EXCERPT_RULES = streamingRedactionRules({ preserveIdentifiers: false });
const TERMINAL_PREPARATION_RULES = terminalPreparationRules();

/** Ordered, browser-safe chunk redaction. Supply decoded text (a streaming UTF-8 decoder for bytes). */
export class StreamingRedactor {
  private readonly stages: readonly Stage[];
  private ended = false;
  private tagged = false;

  constructor(
    extraLiterals: readonly string[] = [],
    insidePem = false,
    options: {
      readonly terminalProjectionFirst?: boolean;
      /** Excerpts historically withhold mixed-class entropy candidates even if they resemble IDs. */
      readonly preserveIdentifiers?: boolean;
    } = {},
  ) {
    // Exact job capabilities are redacted even when shorter than the logger's known-value minimum.
    const literals = [
      ...new Set(
        extraLiterals.flatMap((value) =>
          value.length > 0 ? [value, encodeURIComponent(value)] : [],
        ),
      ),
    ].toSorted((a, b) => b.length - a.length);
    const extra: Stage[] =
      literals.length === 0
        ? []
        : [
            new PatternStage(
              {
                name: "literal",
                pattern: new RegExp(
                  literals
                    .map((value) => value.replaceAll(/[.*+?^${}()|[\]\\/-]/g, "\\$&"))
                    .join("|"),
                  "g",
                ),
                replace: REDACTED,
              },
              Math.max(PATTERN_MATCH_WINDOW, ...literals.map((value) => value.length)),
            ),
          ];
    const stageFor = (rule: RedactionRule): Stage =>
      rule.name === "pem"
        ? new PemStage(insidePem)
        : new PatternStage(
            rule,
            rule.name === "random_token" ? ENTROPY_MATCH_WINDOW : PATTERN_MATCH_WINDOW,
          );
    const rules = options.preserveIdentifiers === false ? EXCERPT_RULES : STREAM_RULES;
    this.stages = [
      ...(options.terminalProjectionFirst ? TERMINAL_PREPARATION_RULES.map(stageFor) : []),
      ...extra,
      // Excerpt values must be withheld before a URL rule can consume their closing quote.
      ...(options.terminalProjectionFirst
        ? rules.filter((rule) => rule.name === "quoted_credential_assignment").map(stageFor)
        : []),
      ...rules.map(stageFor),
    ];
  }

  /** Retained undecided text only; excludes caller-owned chunks and already emitted output. */
  get bufferedOriginSpans(): number {
    return this.stages.reduce((sum, stage) => sum + (stage.origins?.bufferedSpans ?? 0), 0);
  }

  get bufferedCharacters(): number {
    return this.stages.reduce((sum, stage) => sum + stage.bufferedCharacters, 0);
  }

  get redactionCount(): number {
    return this.stages.reduce((sum, stage) => sum + stage.count, 0);
  }

  /** Uses the identical stages while retaining original stream tags and byte positions. */
  pushTagged(spans: readonly RedactionTextSpan[]): readonly RedactionTextSpan[] {
    if (this.ended) throw new Error("Redactor already finished");
    this.tagged = true;
    return this.taggedStages(spans, false);
  }

  finishTagged(): readonly RedactionTextSpan[] {
    if (this.ended) throw new Error("Redactor already finished");
    this.ended = true;
    this.tagged = true;
    return this.taggedStages([], true);
  }

  private taggedStages(
    spans: readonly RedactionTextSpan[],
    final: boolean,
  ): readonly RedactionTextSpan[] {
    let current = spans;
    for (const stage of this.stages) {
      stage.origins ??= new Origins();
      stage.origins.append(current);
      stage.push(current.map((span) => span.text).join(""), final);
      current = stage.origins.drain();
      if (
        this.stages.reduce((count, item) => count + (item.origins?.bufferedSpans ?? 0), 0) +
          current.length >
        MAX_ORIGIN_SPANS
      )
        throw new Error("redaction_origin_budget");
    }
    return current;
  }

  push(chunk: string): string {
    if (this.ended || this.tagged) throw new Error("Redactor already finished or tagged");
    return this.stages.reduce((text, stage) => stage.push(text, false), chunk);
  }

  finish(): string {
    if (this.ended || this.tagged) throw new Error("Redactor already finished");
    this.ended = true;
    return this.stages.reduce((text, stage) => stage.push(text, true), "");
  }
}
