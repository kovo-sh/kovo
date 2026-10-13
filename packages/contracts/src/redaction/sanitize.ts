import { ERROR_MESSAGE_MARKER, registeredErrorMessage } from "./error-messages.js";
import { REDACTED } from "./marker.js";
import { isSensitiveLogKey } from "./keys.js";
import { redactRequestId, redactText, type TextRedactor } from "./patterns.js";

// Deep sanitization of anything that leaves the process as a log line, an error report or a span
// event. SPEC: "Never persist or log source, diffs, manifests, CI files, prompts, model/tool
// output, stdout/stderr, secrets, tokens or capability URLs." ARCHITECTURE §6: "The logger redacts
// by key and by value pattern and refuses unknown payload shapes in sensitive paths."
//
// - Values under a sensitive key are replaced whole (`[REDACTED]`), whatever their shape.
// - Strings are redacted by value pattern (`patterns.ts`) and truncated.
// - Binary data, streams and unknown class instances are refused (replaced by a marker): only
//   plain data, errors, dates and objects that serialize themselves (`toJSON`) are traversed.
// - Errors go through {@link serializeError}. Messages require constructor registration by
//   KovoError, PortError or ConfigError; generic errors and non-error throwables never retain
//   their text.
//   Driver errors keep codes, and validation errors keep issue codes and paths.

export type Sanitized =
  | null
  | boolean
  | number
  | string
  | readonly Sanitized[]
  | { readonly [key: string]: Sanitized };

export interface SanitizeOptions {
  /** Nesting depth beyond which values become `[Truncated]` (default 6). */
  readonly maxDepth?: number;
  /** Members kept per object (default 50). */
  readonly maxKeys?: number;
  /** Items kept per array (default 50). */
  readonly maxArrayItems?: number;
  /** Characters kept per string (default 4096). */
  readonly maxStringLength?: number;
  /** Application frame roots derived from the running module URL at startup. */
  readonly frameRoots?: readonly string[];
  /** Browser stacks permit only application HTTP(S) locations. */
  readonly frameMode?: "node" | "browser";
  /** Additional text redactors (e.g. the proxy capability issuer's). */
  readonly extraRedactors?: readonly TextRedactor[];
}

interface Limits {
  readonly maxDepth: number;
  readonly maxKeys: number;
  readonly maxArrayItems: number;
  readonly maxStringLength: number;
  readonly extra: readonly TextRedactor[];
  readonly frameRoots: readonly string[];
  readonly frameMode: "node" | "browser";
}

function limitsOf(options: SanitizeOptions): Limits {
  return {
    maxDepth: options.maxDepth ?? 6,
    maxKeys: options.maxKeys ?? 50,
    maxArrayItems: options.maxArrayItems ?? 50,
    maxStringLength: options.maxStringLength ?? 4096,
    extra: options.extraRedactors ?? [],
    frameRoots: options.frameRoots ?? MODULE_FRAME_ROOTS,
    frameMode: options.frameMode ?? "node",
  };
}

export const BINARY_MARKER = "[REDACTED:binary]";
export const CIRCULAR_MARKER = "[Circular]";
export const TRUNCATED_MARKER = "[Truncated]";
export const DATABASE_ERROR_MARKER = "[REDACTED:database error]";
export const VALIDATION_ERROR_MARKER = "[validation error]";

/**
 * A string field: known values replaced first, then cut (dropping a word the cut splits), then
 * pattern-redacted (`redactText`), so no known value or secret is left half behind at the limit.
 */
function text(value: string, limits: Limits): string {
  return redactText(value, limits.extra, limits.maxStringLength);
}

function isBinary(value: object): boolean {
  return (
    ArrayBuffer.isView(value) ||
    value instanceof ArrayBuffer ||
    (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer) ||
    (typeof Blob !== "undefined" && value instanceof Blob) ||
    (typeof ReadableStream !== "undefined" && value instanceof ReadableStream) ||
    // Node streams and other event-emitting sources.
    (typeof (value as { pipe?: unknown }).pipe === "function" &&
      typeof (value as { on?: unknown }).on === "function")
  );
}

function isPlainObject(value: object): boolean {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasToJson(value: object): value is { toJSON(): unknown } {
  return typeof (value as { toJSON?: unknown }).toJSON === "function";
}

function constructorName(value: object): string {
  const ctor = (value as { constructor?: { name?: unknown } }).constructor;
  const name = typeof ctor?.name === "string" ? ctor.name : "";
  return /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/.test(name) ? name : "Object";
}

function sanitizeEntries(
  entries: Iterable<readonly [string, unknown]>,
  limits: Limits,
  depth: number,
  seen: WeakSet<object>,
): { [key: string]: Sanitized } {
  const out: { [key: string]: Sanitized } = {};
  let count = 0;
  for (const [key, value] of entries) {
    if (value === undefined || typeof value === "function" || typeof value === "symbol") continue;
    if (count >= limits.maxKeys) {
      out["…"] = TRUNCATED_MARKER;
      break;
    }
    count += 1;
    const safeKey = key.length > 128 ? `${key.slice(0, 128)}…` : key;
    out[safeKey] = isSensitiveLogKey(key)
      ? REDACTED
      : ["requestId", "request_id", "kovo.request_id"].includes(key) && typeof value === "string"
        ? redactRequestId(value, limits.extra)
        : walk(value, limits, depth + 1, seen);
  }
  return out;
}

function walk(value: unknown, limits: Limits, depth: number, seen: WeakSet<object>): Sanitized {
  switch (typeof value) {
    case "string":
      return text(value, limits);
    case "number":
      return Number.isFinite(value) ? value : String(value);
    case "boolean":
      return value;
    case "bigint":
      return value.toString();
    case "undefined":
      return null;
    case "symbol":
    case "function":
      return `[${typeof value}]`;
    case "object":
      break;
  }
  if (value === null) return null;
  if (depth > limits.maxDepth) return TRUNCATED_MARKER;
  if (seen.has(value)) return CIRCULAR_MARKER;
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString();
  }
  if (value instanceof Error) return serializeErrorWith(value, limits, depth, seen);
  if (isBinary(value)) return BINARY_MARKER;
  if (value instanceof URL) return text(value.href, limits);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const items = value
        .slice(0, limits.maxArrayItems)
        .map((item: unknown) => walk(item, limits, depth + 1, seen));
      return value.length > limits.maxArrayItems ? [...items, TRUNCATED_MARKER] : items;
    }
    if (value instanceof Map) {
      const entries = [...value.entries()].map(
        ([key, item]: [unknown, unknown]) => [String(key), item] as const,
      );
      return sanitizeEntries(entries, limits, depth, seen);
    }
    if (value instanceof Set) {
      return walk([...value], limits, depth, seen);
    }
    if (hasToJson(value)) {
      let json: unknown;
      try {
        json = value.toJSON();
      } catch {
        return `[Object ${constructorName(value)}]`;
      }
      // A value that serializes to itself would loop.
      return json === value
        ? `[Object ${constructorName(value)}]`
        : walk(json, limits, depth, seen);
    }
    if (isPlainObject(value)) {
      return sanitizeEntries(Object.entries(value), limits, depth, seen);
    }
    // Unknown shapes (class instances, vendor objects) are refused rather than traversed.
    return `[Object ${constructorName(value)}]`;
  } finally {
    seen.delete(value);
  }
}

/** Deep-sanitizes a value for a log line, error report or telemetry event. */
export function sanitizeValue(value: unknown, options: SanitizeOptions = {}): Sanitized {
  return walk(value, limitsOf(options), 0, new WeakSet());
}

/** Sanitizes the members of a record (log fields). */
export function sanitizeFields(
  fields: Readonly<Record<string, unknown>>,
  options: SanitizeOptions = {},
): { readonly [key: string]: Sanitized } {
  return sanitizeEntries(Object.entries(fields), limitsOf(options), 0, new WeakSet());
}

// ---- Errors ----

/** The loggable description of an error. */
export type SerializedError = {
  readonly name: string;
  readonly message: string;
  readonly code?: string;
  readonly status?: number;
  readonly stack?: string;
  /** The error's own `toJSON()` projection, flattened to primitives and sanitized. */
  readonly fields?: { readonly [key: string]: Sanitized };
  /** Zod issues as codes and paths only (messages may quote the rejected input). */
  readonly issues?: readonly { readonly code: string; readonly path: string }[];
  readonly cause?: SerializedError;
  readonly errors?: readonly SerializedError[];
};

const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
const SAFE_NAME = /^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$/;

/** The bounded code name shared by logger and exception-report error identities. */
export function safeErrorName(name: unknown): string {
  return typeof name === "string" && SAFE_NAME.test(name) ? name : "Error";
}
const SQLSTATE = /^[0-9A-Z]{5}$/;
const MAX_CAUSE_DEPTH = 4;
const MAX_AGGREGATED = 10;
const MAX_STACK_FRAMES = 25;

function prop(error: object, name: string): unknown {
  try {
    const value: unknown = Reflect.get(error, name);
    return value;
  } catch {
    return undefined;
  }
}

/**
 * A node-postgres `DatabaseError`: its message and `detail`/`where` quote row values ("invalid input
 * syntax for type uuid: …", "Key (email)=(…) already exists").
 */
function isPostgresDriverError(error: object): boolean {
  const code = prop(error, "code");
  return (
    typeof code === "string" &&
    SQLSTATE.test(code) &&
    typeof prop(error, "severity") === "string" &&
    ("routine" in error || "file" in error || "detail" in error)
  );
}

/** A Drizzle `DrizzleQueryError`, whose message is the SQL text plus every bound parameter. */
function isDrizzleQueryError(error: object): boolean {
  return (
    prop(error, "name") === "DrizzleQueryError" ||
    (typeof prop(error, "query") === "string" && Array.isArray(prop(error, "params")))
  );
}

/**
 * Whether an error's message (and so its stack header) is known to embed query parameters or row
 * values and must never be logged or reported.
 */
export function isParameterEmbeddingError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (isDrizzleQueryError(error) || isPostgresDriverError(error))
  );
}

function isZodError(error: object): boolean {
  return prop(error, "name") === "ZodError" && Array.isArray(prop(error, "issues"));
}

/** Whether `error` is a Zod error, whose message quotes the rejected input. */
export function isValidationError(error: unknown): boolean {
  return typeof error === "object" && error !== null && isZodError(error);
}

/**
 * The one-line description of a Zod error for sinks that take text only (Sentry exception values):
 * the same issue codes and paths {@link serializeError} keeps, never the received values.
 */
export function describeValidationError(error: unknown, options: SanitizeOptions = {}): string {
  const issues = serializeError(error, options).issues ?? [];
  const described = issues.map((issue) =>
    issue.path === "" ? issue.code : `${issue.code} at ${issue.path}`,
  );
  return described.length === 0
    ? VALIDATION_ERROR_MARKER
    : `${VALIDATION_ERROR_MARKER} ${described.join("; ")}`;
}

/** Derive application roots from first-party module layout; never trust error-supplied roots. */
export function errorFrameRoots(moduleUrl: string, mode: "node" | "browser" = "node"): string[] {
  try {
    const url = new URL(moduleUrl);
    if (mode === "browser") {
      if (url.protocol !== "https:" && url.protocol !== "http:") return [];
      return [`${url.origin}/assets/`];
    }
    if (url.protocol !== "file:") return [];
    const path = decodeURIComponent(url.pathname);
    const source = path.match(/^(.*\/)(?:packages|apps)\/[^/]+\/(?:src|dist)\//);
    const installed = path.match(/^(.*?\/)node_modules\//);
    const deployed = path.match(/^(.*\/)dist\//);
    const root =
      source?.[1] ?? installed?.[1] ?? deployed?.[1] ?? path.slice(0, path.lastIndexOf("/") + 1);
    return root === "/" ? [] : [root, `file://${root}`];
  } catch {
    return [];
  }
}

const MODULE_FRAME_ROOTS = errorFrameRoots(import.meta.url);
// Anchored V8 shape: function tokens contain no spaces; locations never contain free text.
const STACK_FRAME =
  /^ {4}at (?:(?:async |new )?([A-Za-z0-9_$.[\]<>]{1,128}) \(([^()\s]+)\)|(?:async )?([^()\s]+))$/;

const NODE_BUILTINS: ReadonlySet<string> = new Set([
  "assert",
  "assert/strict",
  "async_hooks",
  "buffer",
  "child_process",
  "cluster",
  "console",
  "constants",
  "crypto",
  "dgram",
  "diagnostics_channel",
  "dns",
  "dns/promises",
  "domain",
  "events",
  "fs",
  "fs/promises",
  "http",
  "http2",
  "https",
  "inspector",
  "inspector/promises",
  "module",
  "net",
  "os",
  "path",
  "path/posix",
  "path/win32",
  "perf_hooks",
  "process",
  "punycode",
  "querystring",
  "readline",
  "readline/promises",
  "repl",
  "sea",
  "sqlite",
  "stream",
  "stream/consumers",
  "stream/promises",
  "stream/web",
  "string_decoder",
  "sys",
  "test",
  "test/reporters",
  "timers",
  "timers/promises",
  "tls",
  "trace_events",
  "tty",
  "url",
  "util",
  "util/types",
  "v8",
  "vm",
  "wasi",
  "worker_threads",
  "zlib",
]);

function allowedFrameLocation(location: string, limits: Limits, hasFunction: boolean): boolean {
  if (limits.frameMode === "node" && (location === "native" || location === "<anonymous>"))
    return hasFunction;
  const match = /^(.*):(\d+):(\d+)$/.exec(location);
  const path = match?.[1];
  if (path === undefined || path.split("/").some((part) => part === "." || part === ".."))
    return false;
  if (limits.frameMode === "node" && path.startsWith("node:")) {
    const module = path.slice(5);
    return /^internal\/[A-Za-z0-9_./-]+$/.test(module) || NODE_BUILTINS.has(module);
  }
  if (limits.frameMode === "browser" && !/^https?:\/\//.test(path)) return false;
  if (path.includes("?") || path.includes("#") || path.includes("%") || path.includes("\\"))
    return false;
  return limits.frameRoots.some(
    (root) => root !== "/" && root.endsWith("/") && path.startsWith(root),
  );
}

/** Engine frames after the complete message header only, validated and bounded. */
function framesOf(error: object, limits: Limits): string | undefined {
  if (!(error instanceof Error)) return undefined;
  const stack = prop(error, "stack");
  const name = prop(error, "name");
  const message = registeredErrorMessage(error) ?? prop(error, "message");
  if (typeof stack !== "string" || typeof name !== "string" || typeof message !== "string")
    return undefined;
  const header = name === "" ? message : message === "" ? name : `${name}: ${message}`;
  if (!stack.startsWith(`${header}\n`)) return undefined;
  const frames: string[] = [];
  let length = 0;
  for (const line of stack.slice(header.length + 1).split("\n")) {
    const match = STACK_FRAME.exec(line);
    const location = match?.[2] ?? match?.[3];
    if (
      line.length > limits.maxStringLength ||
      location === undefined ||
      !allowedFrameLocation(location, limits, match?.[1] !== undefined) ||
      redactText(line, limits.extra) !== line
    ) {
      if (frames.length === 0) return undefined;
      continue;
    }
    if (length + line.length + (frames.length > 0 ? 1 : 0) > limits.maxStringLength) break;
    length += line.length + (frames.length > 0 ? 1 : 0);
    frames.push(line);
    if (frames.length === MAX_STACK_FRAMES) break;
  }
  return frames.length === 0 ? undefined : frames.join("\n");
}

/** The validated, message-free frame region shared by logging and exception reporters. */
export function validatedErrorFrames(
  error: unknown,
  options: SanitizeOptions = {},
): string | undefined {
  return typeof error === "object" && error !== null
    ? framesOf(error, limitsOf(options))
    : undefined;
}

function flatFields(json: unknown, limits: Limits): { [key: string]: Sanitized } | undefined {
  if (typeof json !== "object" || json === null || Array.isArray(json)) return undefined;
  const out: { [key: string]: Sanitized } = {};
  let count = 0;
  for (const key in json) {
    if (!Object.hasOwn(json, key)) continue;
    if (count >= limits.maxKeys) break;
    const descriptor = Object.getOwnPropertyDescriptor(json, key);
    const value: unknown =
      descriptor !== undefined && "value" in descriptor ? descriptor.value : "[Object]";
    if (value === undefined) continue;
    count += 1;
    if (isSensitiveLogKey(key)) {
      out[key] = REDACTED;
    } else if (typeof value === "string") {
      out[key] = text(value, limits);
    } else if (typeof value === "number" || typeof value === "boolean" || value === null) {
      out[key] = typeof value === "number" && !Number.isFinite(value) ? String(value) : value;
    } else if (typeof value === "bigint") {
      out[key] = value.toString();
    } else {
      // Nested vendor structures (requests, responses) are never copied.
      out[key] = "[Object]";
    }
  }
  return out;
}

function serializeErrorWith(
  error: unknown,
  limits: Limits,
  depth: number,
  seen: WeakSet<object>,
): SerializedError {
  if (typeof error !== "object" || error === null) {
    return {
      name: "NonError",
      message: ERROR_MESSAGE_MARKER,
    };
  }
  if (!(error instanceof Error) && !("message" in error)) {
    return { name: "NonError", message: ERROR_MESSAGE_MARKER };
  }
  if (seen.has(error)) return { name: "Error", message: CIRCULAR_MARKER };
  seen.add(error);
  try {
    const rawName = prop(error, "name");
    const declared = safeErrorName(rawName);
    // Subclasses that keep the inherited `name` (drizzle's DrizzleQueryError) are named by class.
    const className = constructorName(error);
    const name = declared === "Error" && className !== "Object" ? className : declared;
    const embedsParameters = isParameterEmbeddingError(error);
    const zod = isZodError(error);
    const rawMessage = registeredErrorMessage(error);
    const message = embedsParameters
      ? DATABASE_ERROR_MARKER
      : zod
        ? VALIDATION_ERROR_MARKER
        : typeof rawMessage === "string"
          ? text(rawMessage, limits)
          : ERROR_MESSAGE_MARKER;
    const code = prop(error, "code");
    const status = prop(error, "status") ?? prop(error, "statusCode");
    const result: {
      -readonly [K in keyof SerializedError]: SerializedError[K];
    } = { name, message };
    if (typeof code === "string" && SAFE_CODE.test(code)) result.code = code;
    if (typeof code === "number" && Number.isInteger(code)) result.code = String(code);
    if (typeof status === "number" && Number.isInteger(status)) result.status = status;
    const stack = framesOf(error, limits);
    if (stack !== undefined) result.stack = stack;
    if (embedsParameters) {
      // Keep only the object names a Postgres error identifies (never values or SQL).
      const fields: { [key: string]: Sanitized } = {};
      for (const key of ["constraint", "table", "column", "schema"] as const) {
        const value = prop(error, key);
        if (typeof value === "string" && SAFE_CODE.test(value)) fields[key] = value;
      }
      if (Object.keys(fields).length > 0) result.fields = fields;
    } else if (zod) {
      const rawIssues = prop(error, "issues");
      const issues: readonly unknown[] = Array.isArray(rawIssues) ? rawIssues : [];
      result.issues = issues.slice(0, 20).map((issue) => {
        const issueCode = typeof issue === "object" && issue !== null ? prop(issue, "code") : "";
        const path = typeof issue === "object" && issue !== null ? prop(issue, "path") : [];
        return {
          code: typeof issueCode === "string" && SAFE_CODE.test(issueCode) ? issueCode : "custom",
          path: Array.isArray(path)
            ? path
                .slice(0, 16)
                .map((segment: unknown) =>
                  typeof segment === "number" ? String(segment) : text(String(segment), limits),
                )
                .join(".")
            : "",
        };
      });
    } else if (registeredErrorMessage(error) !== undefined && hasToJson(error)) {
      try {
        const fields = flatFields(error.toJSON(), limits);
        if (fields !== undefined) result.fields = fields;
      } catch {
        // A throwing toJSON contributes nothing.
      }
    }
    if (depth < MAX_CAUSE_DEPTH) {
      const cause = prop(error, "cause");
      if (cause !== undefined && cause !== null) {
        result.cause = serializeErrorWith(cause, limits, depth + 1, seen);
      }
      const errors = prop(error, "errors");
      if (Array.isArray(errors) && errors.length > 0) {
        result.errors = errors
          .slice(0, MAX_AGGREGATED)
          .map((inner: unknown) => serializeErrorWith(inner, limits, depth + 1, seen));
      }
    }
    return result;
  } finally {
    seen.delete(error);
  }
}

/**
 * The safe, loggable description of a thrown value. Only constructor-registered KovoError,
 * PortError and ConfigError messages are retained and pattern-redacted; all other messages are
 * withheld. Driver errors
 * that embed SQL parameters or row values (Drizzle's `DrizzleQueryError`, node-postgres'
 * `DatabaseError`) keep only their SQLSTATE and object names; Zod errors keep issue codes and
 * paths; vendor request/response objects are never copied; causes are followed four levels deep.
 */
export function serializeError(error: unknown, options: SanitizeOptions = {}): SerializedError {
  return serializeErrorWith(error, limitsOf(options), 0, new WeakSet());
}
