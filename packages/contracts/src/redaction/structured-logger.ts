import {
  FREE_TEXT_MARKER,
  logEventCodeSchema,
  logEventSchema,
  projectLogFields,
  type LogEventCode,
  type LogFields,
} from "./log-metadata.js";
import type { TextRedactor } from "./patterns.js";
export const LOG_LEVELS = ["trace", "debug", "info", "warn", "error", "fatal", "silent"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
type Level = Exclude<LogLevel, "silent">;
type LogWarningArgs =
  | [event: LogEventCode, fields?: LogFields]
  | [
      event: "workflow.correlation_unavailable",
      fields: { readonly workflow_id: string | undefined },
    ];
export interface StructuredLogger {
  trace(this: void, event: LogEventCode, fields?: LogFields): void;
  debug(this: void, event: LogEventCode, fields?: LogFields): void;
  info(this: void, event: LogEventCode, fields?: LogFields): void;
  /** Byte-pinned DBOS registry call; projected at this boundary like every other call. */
  warn(this: void, ...args: LogWarningArgs): void;
  error(this: void, event: LogEventCode, fields?: LogFields): void;
  fatal(this: void, event: LogEventCode, fields?: LogFields): void;
  child(this: void, fields: LogFields): StructuredLogger;
  isLevelEnabled(this: void, level: Level): boolean;
}
const SEVERITY = {
  trace: "DEBUG",
  debug: "DEBUG",
  info: "INFO",
  warn: "WARNING",
  error: "ERROR",
  fatal: "CRITICAL",
} as const;
export interface StructuredLoggerOptions {
  readonly level: LogLevel;
  readonly base?: LogFields;
  readonly clock: { now(): Date };
  readonly write: (event: zodEvent) => void;
  readonly onRedaction?: (count: number) => void;
  readonly correlation?: () => unknown;
  readonly extraRedactors?: readonly TextRedactor[];
  /** Boot evidence gates must refuse if their output cannot be delivered. */
  readonly requireDelivery?: boolean;
}
type zodEvent = ReturnType<typeof logEventSchema.parse>;

/** Pure, injectable I/O boundary used by every production process and the browser. */
export function createStructuredLogger(options: StructuredLoggerOptions): StructuredLogger {
  const count = (n: number) => {
    if (n > 0) {
      try {
        options.onRedaction?.(n);
      } catch {
        /* Best effort. */
      }
    }
  };
  const initial = projectLogFields(options.base ?? {}, options.extraRedactors);
  count(initial.redacted);
  const enabled = (level: Level) => LOG_LEVELS.indexOf(level) >= LOG_LEVELS.indexOf(options.level);
  function bound(bindings: LogFields): StructuredLogger {
    const write = (
      level: Level,
      event: LogEventCode | "workflow.correlation_unavailable",
      fields: LogFields | { readonly workflow_id: string | undefined } = {},
    ) => {
      if (!enabled(level)) return;
      const code = logEventCodeSchema.safeParse(
        level === "warn" && event === "workflow.correlation_unavailable"
          ? "workflow_correlation_unavailable"
          : event,
      );
      // D-423: a line the closed schema refuses, or whose projection throws, is replaced by this
      // minimal line instead of vanishing: the logger's own bindings (projected when bound) and no
      // field of this call, so the call's content cannot cause a second refusal.
      // Once a write was attempted, a throw is the sink's: never write a second line (review N3).
      let attempted = false;
      const refused = (redacted: number) => {
        if (attempted) return;
        const fallback = logEventSchema.safeParse({
          ...bindings,
          event: code.success ? code.data : FREE_TEXT_MARKER,
          severity: SEVERITY[level],
          level,
          time: options.clock.now().toISOString(),
          redacted_fields: Math.min(128, Math.max(1, redacted)),
          reason_code: "log_line_refused",
        });
        if (fallback.success) {
          attempted = true;
          options.write(fallback.data);
        }
      };
      try {
        const explicit = projectLogFields(fields, options.extraRedactors);
        const active = projectLogFields(options.correlation?.() ?? {}, options.extraRedactors);
        const projected = projectLogFields(
          { ...bindings, ...explicit.fields, ...active.fields },
          options.extraRedactors,
        );
        const upstream =
          typeof explicit.fields.redactions === "number"
            ? Math.min(128, Math.max(0, Math.floor(explicit.fields.redactions)))
            : 0;
        const redacted = explicit.redacted + active.redacted + upstream + (code.success ? 0 : 1);
        count(redacted);
        // D-423: an error line that names neither an error class nor a reason is near-empty; the
        // floor marks it so the gap is queryable rather than silent.
        const floor =
          (level === "error" || level === "fatal") &&
          projected.fields.error_class === undefined &&
          projected.fields.reason_code === undefined
            ? { reason_code: "error_detail_missing" }
            : {};
        const result = logEventSchema.safeParse({
          ...projected.fields,
          ...floor,
          event: code.success ? code.data : FREE_TEXT_MARKER,
          severity: SEVERITY[level],
          level,
          time: options.clock.now().toISOString(),
          redacted_fields: redacted,
        });
        if (result.success) {
          attempted = true;
          options.write(result.data);
        } else refused(redacted + 1);
      } catch (error) {
        if (options.requireDelivery === true) throw error;
        // Logging must never change a product outcome or echo a refusal.
        try {
          refused(1);
        } catch {
          /* The sink itself failed; there is nowhere left to say so. */
        }
      }
    };
    return {
      trace: (event, fields) => write("trace", event, fields),
      debug: (event, fields) => write("debug", event, fields),
      info: (event, fields) => write("info", event, fields),
      warn: (...args: LogWarningArgs) => write("warn", args[0], args[1]),
      error: (event, fields) => write("error", event, fields),
      fatal: (event, fields) => write("fatal", event, fields),
      isLevelEnabled: enabled,
      child: (fields) => {
        const projected = projectLogFields(fields, options.extraRedactors);
        count(projected.redacted);
        return bound({ ...bindings, ...projected.fields });
      },
    };
  }
  return bound(initial.fields);
}
