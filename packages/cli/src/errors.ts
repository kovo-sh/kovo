import { EXIT, type ExitCode } from "./exit.js";

// Errors the CLI reports with a fixed message and exit code. Messages never carry file contents,
// lockfile text, the API key or another program's raw output: only fixed text, identifiers (a
// path, a ref, a package name) and stable codes.

/** Identifiers an error may carry into `--format json`: an HTTP status and a reason code. */
export interface CliErrorDetails {
  readonly status?: number;
  readonly reason?: string;
}

export class CliError extends Error {
  readonly exit: ExitCode;
  /** A stable code, printed and carried in `--format json`. */
  readonly code: string;
  readonly details: CliErrorDetails;

  constructor(exit: ExitCode, code: string, message: string, details: CliErrorDetails = {}) {
    super(message);
    this.name = "CliError";
    this.exit = exit;
    this.code = code;
    this.details = details;
  }
}

/** Exit 2: a usage error, or a lockfile that is missing, unreadable or unsupported. */
export function usageError(code: string, message: string, details?: CliErrorDetails): CliError {
  return new CliError(EXIT.usage, code, message, details);
}

/** Exit 3: the check could not be answered. */
export function unavailableError(
  code: string,
  message: string,
  details?: CliErrorDetails,
): CliError {
  return new CliError(EXIT.unavailable, code, message, details);
}
