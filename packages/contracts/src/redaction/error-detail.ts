import { NON_PUBLIC_TLDS, hostNameEmbedsIpv4 } from "../primitives.js";
import { registeredErrorMessage } from "./error-messages.js";
import {
  ERROR_MESSAGE_MAX_LENGTH,
  CAUSE_MESSAGE_MAX_LENGTH,
  causeClassesSchema,
  causeMessagesSchema,
  errorMessageSchema,
  logErrorClassSchema,
  logErrorIdentity,
  type LogFields,
} from "./log-metadata.js";
import { ERROR_MESSAGE_CODES, ERROR_MESSAGE_WORDS } from "./error-words.js";
import { redactText } from "./patterns.js";

// D-423 ERROR-DETAIL (owner, 2026-10-29, option a): an error log line carries a redacted
// `error_message` and its cause chain (`cause_classes`, `cause_messages`, `cause_count`), as D-267
// asks. Metadata only: the redaction keeps the message's shape and drops every token that could be a
// value. See GLOSSARY.md "Loggable metadata".

/** What replaces a token, a quoted span or a run of them that could carry a value. */
export const VALUE_MARKER = "[v]";
/** Causes named on one line, at most; `cause_count` counts further (up to {@link MAX_CAUSE_COUNT}). */
export const MAX_LOGGED_CAUSES = 3;
/** The cause chain is walked this far, at most; a longer or cyclic chain reports this count. */
export const MAX_CAUSE_COUNT = 8;
/** Input read from a message, at most: a message is diagnostics, never a document. */
const MAX_INPUT = 2048;
const TRUNCATED = "...";

const LEADING = /^[(<{"']+/;
const TRAILING = /[)>}"',.;:!?]+$/;
/** A capitalised word: kept only where a sentence starts, and only if its lowercase is a word. */
const CAPITALISED = /^[A-Z][a-z']{1,19}$/;
/** A value-free identifier of a registered message (`billing.createCheckoutSession`, `KOVO_ENV`). */
const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,48}$/;
const DIGIT = /[0-9]/;
/** A message that is one snake_case reason (`calibration_snapshot_janitor_key_missing`). */
const REASON_ONLY = /^[a-z]+(?:_[a-z]+){1,11}$/;
/** Where a new sentence starts; a colon, semicolon or `=` never starts one (values follow them). */
const SENTENCE_END = /[.!?]$/;

/**
 * Fails closed (D-423 review B1): a strict-mode word survives only if it is in the closed
 * {@link ERROR_MESSAGE_WORDS} vocabulary (a capitalised one only at a sentence start) or is a
 * listed {@link ERROR_MESSAGE_CODES} code. Every other word, however plain, becomes `[v]`.
 */
function knownWord(core: string, sentenceStart: boolean): boolean {
  if (ERROR_MESSAGE_CODES.has(core)) return true;
  if (ERROR_MESSAGE_WORDS.has(core)) return true;
  return sentenceStart && CAPITALISED.test(core) && ERROR_MESSAGE_WORDS.has(core.toLowerCase());
}
/** A quoted span; an apostrophe inside a word (`can't`) does not open one. */
const QUOTED = /(^|[^A-Za-z0-9])(["'`])(?:(?!\2)[\s\S])*\2(?![A-Za-z0-9])/g;
const UNTERMINATED = /(^|[^A-Za-z0-9])["`][\s\S]*$/;

/**
 * `strict` is for any message: only vocabulary words survive. `registered` is for the value-free
 * application families (KovoError, PortError, ConfigError; error-messages.ts), whose messages
 * name settings, services and operations by contract: identifiers survive too.
 */
type Mode = "strict" | "registered";

const IPV4_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HOST_PORT = /:\d{1,5}$/;

/**
 * Whether `core` names an internal or private-network host (D-423 review, coordinator ruling): a
 * dotted name whose last label is a non-public TLD (`db-host.internal`, `printer.local`,
 * `kubernetes.default.svc`; the shared {@link NON_PUBLIC_TLDS} list), a name embedding an IPv4
 * address (`10-0-0-1.sslip.io`; {@link hostNameEmbedsIpv4}), or an IPv4 literal. An optional
 * `:port` is ignored. Such a host names Kovo infrastructure, so it is never logged.
 */
function internalHost(core: string): boolean {
  const host = core.toLowerCase().replace(HOST_PORT, "");
  if (host === "localhost") return true;
  if (!host.includes(".")) return false;
  if (IPV4_LITERAL.test(host)) return true;
  return NON_PUBLIC_TLDS.has(host.split(".").at(-1) ?? "") || hostNameEmbedsIpv4(host);
}

function keepCore(core: string, mode: Mode, sentenceStart: boolean): boolean {
  if (core === VALUE_MARKER) return true;
  if (internalHost(core)) return false;
  if (mode === "registered")
    return IDENTIFIER.test(core) && !(DIGIT.test(core) && core.length >= 16);
  return knownWord(core, sentenceStart);
}

function redactToken(token: string, mode: Mode, sentenceStart: boolean): string {
  const lead = LEADING.exec(token)?.[0] ?? "";
  const rest = token.slice(lead.length);
  const trail = TRAILING.exec(rest)?.[0] ?? "";
  const core = rest.slice(0, rest.length - trail.length);
  if (core === "") return lead + trail;
  return lead + (keepCore(core, mode, sentenceStart) ? core : VALUE_MARKER) + trail;
}

/**
 * The shape of `message` with every token that could carry a value replaced by `[v]`: quoted spans
 * and every word outside the closed error vocabulary (error-words.ts), including names, logins,
 * paths, URLs, emails and IDs. A registered message also keeps its identifiers. Only the first line
 * is read and the result is bounded to `maxLength`. Secrets the shared rules recognise are removed
 * first. Undefined when nothing is left to say.
 */
export function redactErrorMessage(
  message: unknown,
  options: { readonly registered?: boolean; readonly maxLength?: number } = {},
): string | undefined {
  if (typeof message !== "string") return undefined;
  const mode: Mode = options.registered === true ? "registered" : "strict";
  const maxLength = Math.max(8, Math.min(options.maxLength ?? ERROR_MESSAGE_MAX_LENGTH, 256));
  const input = message.slice(0, MAX_INPUT);
  const [firstLine = ""] = input.split(/\r?\n/, 1);
  const moreLines = firstLine.length < input.trimEnd().length;
  // Kovo throws stable reasons as whole messages; one whose every part is a vocabulary word is a
  // code, not a value.
  const whole = firstLine.trim();
  if (
    !moreLines &&
    whole.length <= maxLength &&
    REASON_ONLY.test(whole) &&
    whole.split("_").every((part) => ERROR_MESSAGE_WORDS.has(part)) &&
    redactText(whole) === whole
  )
    return whole;
  const text = redactText(firstLine, [], MAX_INPUT)
    .replace(QUOTED, `$1${VALUE_MARKER}`)
    .replace(UNTERMINATED, `$1${VALUE_MARKER}`);
  const tokens: string[] = [];
  let sentenceStart = true;
  for (const raw of text.split(/\s+/)) {
    if (raw === "") continue;
    const token = redactToken(raw, mode, sentenceStart);
    sentenceStart = SENTENCE_END.test(token);
    // Adjacent markers say nothing more than one.
    if (token === VALUE_MARKER && tokens.at(-1) === VALUE_MARKER) continue;
    if (token !== "") tokens.push(token);
  }
  let result = "";
  let truncated = moreLines;
  for (const token of tokens) {
    const next = result === "" ? token : `${result} ${token}`;
    if (next.length > maxLength - TRUNCATED.length - 1) {
      truncated = true;
      break;
    }
    result = next;
  }
  if (result === "") return undefined;
  return truncated ? `${result} ${TRUNCATED}` : result;
}

function ownValue(target: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(target, key);
  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

/**
 * The error's `name`, read as a data property on the error or its prototype chain (a bounded walk),
 * so an inherited getter never runs (review N1).
 */
function nameOf(error: object): unknown {
  let current: object | null = error;
  for (let depth = 0; current !== null && depth < 16; depth++) {
    const descriptor = Object.getOwnPropertyDescriptor(current, "name");
    if (descriptor !== undefined) return "value" in descriptor ? descriptor.value : undefined;
    const next: unknown = Object.getPrototypeOf(current);
    current = typeof next === "object" ? next : null;
  }
  return undefined;
}

/** The redacted message of one error; a ZodError's issues are logged as fields instead. */
function messageOf(error: Error, maxLength: number): string | undefined {
  const name = nameOf(error);
  if (name === "ZodError") return undefined;
  const registered = registeredErrorMessage(error);
  return redactErrorMessage(registered ?? ownValue(error, "message"), {
    // A ConfigError is value-free but names its settings, secret ones included
    // (`api--STRIPE_API_KEY (secret)`): its message gets the strict, name-free redaction.
    registered: registered !== undefined && name !== "ConfigError",
    maxLength,
  });
}

function classOf(value: unknown): string {
  if (!(value instanceof Error)) return "NonError";
  const parsed = logErrorClassSchema.safeParse(nameOf(value));
  return parsed.success ? parsed.data : "Error";
}

/**
 * The redacted `error_message` and the cause chain of `error`: each cause's class and redacted
 * message (the first {@link MAX_LOGGED_CAUSES}) and how many causes there are (bounded, cycle-safe).
 * Reads data properties only, so no getter runs. A Proxy's traps may run (`instanceof` and the
 * descriptor reads), but their results are enum-bounded or redacted, and a throwing trap adds
 * nothing.
 */
export function errorDetailFields(error: unknown): LogFields {
  try {
    if (!(error instanceof Error)) return {};
    const message = errorMessageSchema.safeParse(messageOf(error, ERROR_MESSAGE_MAX_LENGTH));
    const seen = new Set<unknown>([error]);
    const classes: string[] = [];
    const messages: string[] = [];
    let count = 0;
    let current: unknown = ownValue(error, "cause");
    while (current !== undefined && count < MAX_CAUSE_COUNT) {
      count++;
      if (classes.length < MAX_LOGGED_CAUSES) {
        classes.push(classOf(current));
        messages.push(
          (current instanceof Error ? messageOf(current, CAUSE_MESSAGE_MAX_LENGTH) : undefined) ??
            "-",
        );
      }
      // A non-Error is not read further; a cycle ends the walk where it repeats.
      if (!(current instanceof Error) || seen.has(current)) break;
      seen.add(current);
      current = ownValue(current, "cause");
    }
    const causeClasses = causeClassesSchema.safeParse(classes.join(","));
    const causeMessages = messages.some((value) => value !== "-")
      ? causeMessagesSchema.safeParse(messages.join(" | "))
      : undefined;
    return {
      ...(message.success ? { error_message: message.data } : {}),
      ...(count > 0 ? { cause_count: count } : {}),
      ...(count > 0 && causeClasses.success ? { cause_classes: causeClasses.data } : {}),
      ...(causeMessages?.success === true ? { cause_messages: causeMessages.data } : {}),
    };
  } catch {
    return {};
  }
}

/** {@link logErrorIdentity} plus {@link errorDetailFields}: what an error log line carries. */
export function logErrorDetail(error: unknown): LogFields {
  return { ...logErrorIdentity(error), ...errorDetailFields(error) };
}
