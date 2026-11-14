import { z } from "zod";
import {
  FREE_TEXT_MARKER,
  logErrorIdentity,
  logErrorClassSchema,
  projectLogFields,
} from "./log-metadata.js";
import type { SanitizeOptions } from "./sanitize.js";
import type { TextRedactor } from "./patterns.js";

export interface ScrubbableFrame {
  vars?: unknown;
  pre_context?: unknown;
  context_line?: unknown;
  post_context?: unknown;
  module_metadata?: unknown;
  abs_path?: string;
  filename?: string;
}
export interface ScrubbableException {
  type?: string;
  value?: string;
  stacktrace?: { frames?: ScrubbableFrame[] };
}
export interface ScrubbableBreadcrumb {
  type?: string;
  category?: string;
  message?: string;
  data?: { [key: string]: unknown };
}
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
export interface ScrubbableHint {
  originalException?: unknown;
}

/** SDK collection is off before scrubbing; content never enters SDK request/AI integrations. */
export function exceptionReportDataCollection() {
  return {
    userInfo: false,
    cookies: false,
    httpHeaders: false,
    httpBodies: [] as never[],
    urlQueryParams: false,
    genAI: { inputs: false, outputs: false },
    databaseQueryData: false,
    queues: false,
    graphQL: { document: false, variables: false },
    stackFrameVariables: false,
    frameContextLines: 0,
  };
}
export const KEPT_EVENT_CONTEXTS: ReadonlySet<string> = new Set(["trace"]);

/** SDK-parsed stacks and application stack strings are never exported. */
export function rebuildErrorEventFrames<E extends ScrubbableEvent>(
  event: E,
  _hint: ScrubbableHint | undefined,
  _parse: ((stack: string) => ScrubbableFrame[]) | undefined,
  _options: SanitizeOptions = {},
): E {
  for (const value of event.exception?.values ?? []) delete value.stacktrace;
  return event;
}

/** Free-text breadcrumbs are dropped whole; retained data uses exactly the logger schema. */
export function scrubBreadcrumb(
  breadcrumb: ScrubbableBreadcrumb,
  extra: readonly TextRedactor[] = [],
): { data: ReturnType<typeof projectLogFields>["fields"] } | null {
  try {
    if (breadcrumb.message !== undefined || breadcrumb.category === "console") return null;
    const projected = projectLogFields(breadcrumb.data ?? {}, extra);
    if (projected.redacted > 0) return null;
    // No category, URL or type supplied by an SDK is forwarded as an unchecked string.
    return { data: projected.fields };
  } catch {
    return null;
  }
}
/**
 * Fields that ordinary log lines may carry (D-423, #5514) but a Sentry event never does: the
 * request's route, method and operation, an error's redacted message and cause chain, and Zod
 * issue paths. Sentry keeps only the closed error identity and its existing tag allowlist; a
 * supplied log-only field stays the withheld marker, as before those fields had a log schema.
 */
const LOG_ONLY_FIELDS: ReadonlySet<string> = new Set([
  "route",
  "method",
  "operation_id",
  "error_message",
  "cause_classes",
  "cause_messages",
  "cause_count",
  "zod_issue_paths",
  "zod_issue_codes",
  "zod_issue_count",
]);

function withholdLogOnly(fields: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => [
      key,
      LOG_ONLY_FIELDS.has(key) ? FREE_TEXT_MARKER : value,
    ]),
  );
}

const routing = {
  event_id: z.string().regex(/^[a-f0-9]{32}$/i),
  timestamp: z.number().finite(),
  level: z.enum(["fatal", "error", "warning", "log", "info", "debug"]),
  platform: z.enum(["node", "javascript"]),
  environment: z.enum(["prod", "test", "local"]),
  release: z.string().regex(/^[a-f0-9]{40,64}$/i),
} as const;
const routingSchemas: ReadonlyMap<string, z.ZodType> = new Map(Object.entries(routing));
const routingSchema = z.strictObject(routing).partial();
// Missing SDK routing fields are omitted, never assigned undefined. This preserves
// the SDK's exact-optional-property contract without asserting a vendor event type.
type SafeRouting = {
  [K in keyof z.output<typeof routingSchema>]?: Exclude<
    z.output<typeof routingSchema>[K],
    undefined
  >;
};
interface SafeErrorEvent extends SafeRouting {
  type: undefined;
  request?: never;
  user?: never;
  server_name?: never;
  contexts?: never;
  message?: never;
  exception?: { values: { type: string; stacktrace?: { frames?: never[] } }[] };
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
  breadcrumbs?: ScrubbableBreadcrumb[];
}

/** Closed beforeSend projection; messages, stacks, request bodies and arbitrary extras disappear. */
export function scrubErrorEvent(
  event: ScrubbableEvent,
  hint?: ScrubbableHint,
  extra: readonly TextRedactor[] = [],
): SafeErrorEvent {
  const output: SafeErrorEvent = { type: undefined };
  try {
    const routed: Record<string, unknown> = {};
    for (const [key, schema] of routingSchemas) {
      const descriptor = Object.getOwnPropertyDescriptor(event, key);
      const parsed = schema.safeParse(descriptor?.value);
      if (parsed.success) routed[key] = parsed.data;
    }
    Object.assign(output, routingSchema.parse(routed));
    const sdkClass = logErrorClassSchema.safeParse(event.exception?.values?.at(-1)?.type);
    const identity =
      hint?.originalException === undefined
        ? {
            error_class: sdkClass.success ? sdkClass.data : "Error",
            reason_code: "untrusted_error",
          }
        : logErrorIdentity(hint.originalException);
    if (event.exception !== undefined)
      output["exception"] = { values: [{ type: logErrorClassSchema.parse(identity.error_class) }] };
    const tags = withholdLogOnly(projectLogFields(event.tags ?? {}, extra).fields);
    output["tags"] = Object.fromEntries(
      Object.entries({ ...tags, ...identity }).map(([key, value]) => [key, String(value)]),
    );
    if (event.extra !== undefined)
      output["extra"] = withholdLogOnly(projectLogFields(event.extra, extra).fields);
    if (event.breadcrumbs !== undefined)
      output["breadcrumbs"] = event.breadcrumbs
        .slice(0, 30)
        .map((value) => scrubBreadcrumb(value, extra))
        .filter((value) => value !== null);
  } catch {
    /* A malformed SDK event carries no content, even when accessors throw. */
  }
  return output;
}
