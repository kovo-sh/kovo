import { ERROR_MESSAGE_MARKER, registeredErrorMessage } from "./error-messages.js";
import { isSensitiveLogKey } from "./keys.js";
import { REDACTED } from "./marker.js";
import { redactText, stripUrlQuery, type TextRedactor } from "./patterns.js";
import {
  DATABASE_ERROR_MARKER,
  VALIDATION_ERROR_MARKER,
  describeValidationError,
  isParameterEmbeddingError,
  isValidationError,
  sanitizeValue,
  safeErrorName,
  validatedErrorFrames,
  type Sanitized,
  type SanitizeOptions,
} from "./sanitize.js";

// Scrubbing of exception reports (Sentry events and breadcrumbs) with the shared redaction rules,
// for every process that reports exceptions: the control plane's Sentry reporter
// (`@kovo/adapters/telemetry`) and the web app's server and browser reporters (`apps/web`). SPEC
// Observability: "Sentry captures sanitized exceptions with default PII capture disabled and
// request/body/console scrubbing." The shapes below are the members of Sentry's `ErrorEvent`,
// `EventHint` and `Breadcrumb` these functions touch, declared structurally so this package imports
// no SDK; the SDK types satisfy them.

/** A stack frame of an exception report. */
export interface ScrubbableFrame {
  vars?: unknown;
  pre_context?: unknown;
  context_line?: unknown;
  post_context?: unknown;
  module_metadata?: unknown;
  abs_path?: string;
  filename?: string;
}

/** One exception value of an exception report (the captured error or one of its causes). */
export interface ScrubbableException {
  type?: string;
  value?: string;
  stacktrace?: { frames?: ScrubbableFrame[] };
}

/** A breadcrumb (an event that happened before the exception). */
export interface ScrubbableBreadcrumb {
  type?: string;
  category?: string;
  message?: string;
  data?: { [key: string]: unknown };
}

/** The members of an exception report that can carry request, user or content data. */
export interface ScrubbableEvent {
  request?: unknown;
  user?: unknown;
  server_name?: unknown;
  modules?: unknown;
  threads?: unknown;
  message?: string;
  logentry?: { message?: string };
  transaction?: string;
  exception?: { values?: ScrubbableException[] };
  extra?: { [key: string]: unknown };
  tags?: { [key: string]: unknown };
  contexts?: { [key: string]: unknown };
  breadcrumbs?: ScrubbableBreadcrumb[];
}

/** What the reporter knows about the event: the thrown value itself. */
export interface ScrubbableHint {
  originalException?: unknown;
}

const NO_BODIES: never[] = [];

/**
 * The data-collection lockdown of every exception reporter (Sentry's `dataCollection` option,
 * docs/libraries/billing-comms-telemetry.md §4: the v11 defaults collect user info, cookies,
 * headers, bodies, query strings, AI inputs and outputs, database data and frame locals). A fresh
 * object per call, so no SDK can mutate the policy another reporter reads.
 */
export function exceptionReportDataCollection() {
  return {
    userInfo: false,
    cookies: false,
    httpHeaders: false,
    httpBodies: NO_BODIES,
    urlQueryParams: false,
    genAI: { inputs: false, outputs: false },
    databaseQueryData: false,
    queues: false,
    graphQL: { document: false, variables: false },
    stackFrameVariables: false,
    frameContextLines: 0,
  };
}

/** Event contexts kept (runtime and trace linkage); every other context is dropped. */
export const KEPT_EVENT_CONTEXTS: ReadonlySet<string> = new Set([
  "trace",
  "runtime",
  "os",
  "app",
  "device",
  "browser",
]);

/** Breadcrumb data members kept for http/fetch breadcrumbs. */
const KEPT_BREADCRUMB_DATA: ReadonlySet<string> = new Set(["method", "status_code", "url"]);

function chainOf(error: unknown): unknown[] {
  const chain: unknown[] = [];
  let current: unknown = error;
  while (current !== undefined && current !== null && chain.length < 10) {
    if (chain.includes(current)) break;
    chain.push(current);
    current = typeof current === "object" ? Reflect.get(current, "cause") : undefined;
  }
  return chain;
}

/** Replace SDK-parsed stacks: the SDK may parse message text as frames after its first line. */
export function rebuildErrorEventFrames<E extends ScrubbableEvent>(
  event: E,
  hint: ScrubbableHint | undefined,
  parse: ((stack: string) => ScrubbableFrame[]) | undefined,
  options: SanitizeOptions = {},
): E {
  const values = event.exception?.values;
  if (values === undefined) return event;
  const chain = chainOf(hint?.originalException);
  const aligned = chain.length === values.length;
  values.forEach((exception, index) => {
    const hadStacktrace = exception.stacktrace !== undefined;
    delete exception.stacktrace;
    // Rebuild existing SDK stacks only; do not add runtime metadata to stackless events.
    if (!hadStacktrace || !aligned || parse === undefined) return;
    const region = validatedErrorFrames(chain[values.length - 1 - index], options);
    if (region === undefined) return;
    const frames = parse(region);
    if (frames.length > 0) exception.stacktrace = { frames };
  });
  return event;
}

function nameOf(error: unknown): unknown {
  return typeof error === "object" && error !== null ? Reflect.get(error, "name") : "";
}

function scrubFrames(event: ScrubbableEvent, extra: readonly TextRedactor[]): void {
  for (const exception of event.exception?.values ?? []) {
    for (const frame of exception.stacktrace?.frames ?? []) {
      delete frame.vars;
      delete frame.pre_context;
      delete frame.context_line;
      delete frame.post_context;
      delete frame.module_metadata;
      if (frame.abs_path !== undefined) frame.abs_path = redactText(frame.abs_path, extra);
      if (frame.filename !== undefined) frame.filename = redactText(frame.filename, extra);
    }
  }
}

/**
 * Exception values follow the logger's error rules (`serializeError`): a driver error that embeds
 * SQL parameters loses its message, a Zod error keeps only issue codes and paths, and only an
 * aligned constructor-registered application error retains its pattern-redacted message.
 */
function scrubExceptionValues(
  event: ScrubbableEvent,
  hint: ScrubbableHint | undefined,
  extra: readonly TextRedactor[],
): void {
  const values = event.exception?.values;
  if (values === undefined) return;
  // Linked errors are ordered innermost cause first, the captured error last.
  const chain = chainOf(hint?.originalException);
  const aligned = chain.length === values.length;
  const embeddingTypes = new Set(chain.filter(isParameterEmbeddingError).map(nameOf));
  const validationErrors = chain.filter(isValidationError);
  values.forEach((exception, index) => {
    const original = aligned ? chain[values.length - 1 - index] : undefined;
    const embeds = aligned
      ? isParameterEmbeddingError(original)
      : exception.type !== undefined && embeddingTypes.has(exception.type);
    const validation = aligned
      ? isValidationError(original)
      : exception.type === "ZodError" && validationErrors.length > 0;
    // Without alignment a Zod value is described only when the chain has exactly one Zod error.
    const zodSource = aligned
      ? original
      : validationErrors.length === 1
        ? validationErrors[0]
        : undefined;
    if (exception.value !== undefined) {
      if (embeds) exception.value = DATABASE_ERROR_MARKER;
      else if (validation) {
        exception.value =
          zodSource === undefined
            ? VALIDATION_ERROR_MARKER
            : describeValidationError(zodSource, { extraRedactors: extra });
      } else {
        const message = registeredErrorMessage(original);
        exception.value = message === undefined ? ERROR_MESSAGE_MARKER : redactText(message, extra);
      }
    }
    if (exception.type !== undefined)
      exception.type = safeErrorName(redactText(exception.type, extra));
  });
}

function isRecord(value: Sanitized): value is { readonly [key: string]: Sanitized } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scrubRecord(
  record: Readonly<Record<string, unknown>>,
  extra: readonly TextRedactor[],
): Record<string, unknown> {
  const sanitized = sanitizeValue(record, { extraRedactors: extra });
  return isRecord(sanitized) ? { ...sanitized } : {};
}

/**
 * The breadcrumb scrubber: drops console breadcrumbs, strips query strings from http/fetch URLs and
 * keeps only method, status and URL; withholds messages and redacts other data.
 */
export function scrubBreadcrumb<B extends ScrubbableBreadcrumb>(
  breadcrumb: B,
  extra: readonly TextRedactor[] = [],
): B | null {
  if (breadcrumb.category === "console") return null;
  const scrubbed: B = { ...breadcrumb };
  delete scrubbed.message;
  if (scrubbed.data !== undefined) {
    const isHttp =
      breadcrumb.category === "http" ||
      breadcrumb.category === "fetch" ||
      breadcrumb.category === "xhr" ||
      breadcrumb.type === "http";
    const data: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(scrubbed.data)) {
      if (isHttp && !KEPT_BREADCRUMB_DATA.has(key)) continue;
      data[key] =
        key === "url" && typeof value === "string"
          ? redactText(stripUrlQuery(value), extra)
          : value;
    }
    scrubbed.data = isHttp ? data : scrubRecord(data, extra);
  }
  return scrubbed;
}

/**
 * The exception-report scrubber (`beforeSend`): drops request, user and server identity, module
 * and thread lists, frame locals and source lines and non-runtime contexts; redacts messages,
 * exception values (dropping those of driver errors that embed SQL parameters and the received
 * values of Zod errors, including linked causes), tags and extras; withholds serialized thrown
 * values and breadcrumb messages. `extra` redactors
 * (known values) run before the patterns everywhere. Mutates and returns the event.
 */
export function scrubErrorEvent<E extends ScrubbableEvent>(
  event: E,
  hint?: ScrubbableHint,
  extra: readonly TextRedactor[] = [],
): E {
  const target: ScrubbableEvent = event;
  delete target.request;
  delete target.user;
  delete target.server_name;
  delete target.modules;
  delete target.threads;
  const registered = registeredErrorMessage(hint?.originalException);
  if (target.message !== undefined)
    target.message =
      registered === undefined ? ERROR_MESSAGE_MARKER : redactText(registered, extra);
  if (target.logentry !== undefined) {
    target.logentry =
      target.logentry.message === undefined ? {} : { message: ERROR_MESSAGE_MARKER };
  }
  if (target.transaction !== undefined) {
    target.transaction = redactText(stripUrlQuery(target.transaction), extra);
  }
  scrubExceptionValues(target, hint, extra);
  scrubFrames(target, extra);
  if (target.extra !== undefined) {
    // Sentry puts thrown non-error content here. Withhold it before traversing or redacting it,
    // including accessor-backed payloads; copying descriptors does not execute their getters.
    const descriptors = Object.getOwnPropertyDescriptors(target.extra);
    delete descriptors["__serialized__"];
    target.extra = scrubRecord(Object.defineProperties({}, descriptors), extra);
  }
  if (target.tags !== undefined) {
    const tags: Record<string, string> = {};
    for (const [key, value] of Object.entries(target.tags)) {
      // Tags are primitives; anything else is dropped rather than stringified. A sensitive name
      // withholds the value whole, as in logs.
      if (isSensitiveLogKey(key)) tags[key] = REDACTED;
      else if (typeof value === "string") tags[key] = redactText(value, extra);
      else if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint")
        tags[key] = redactText(String(value), extra);
    }
    target.tags = tags;
  }
  if (target.contexts !== undefined) {
    target.contexts = Object.fromEntries(
      Object.entries(target.contexts).filter(([key]) => KEPT_EVENT_CONTEXTS.has(key)),
    );
  }
  if (target.breadcrumbs !== undefined) {
    target.breadcrumbs = target.breadcrumbs
      .map((breadcrumb) => scrubBreadcrumb(breadcrumb, extra))
      .filter((breadcrumb): breadcrumb is ScrubbableBreadcrumb => breadcrumb !== null);
  }
  return event;
}
