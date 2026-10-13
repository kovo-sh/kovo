import { registerErrorMessage } from "@kovo/contracts/redaction";
// Typed errors every port may throw (ARCHITECTURE §5). Adapters translate vendor failures into
// these classes so callers branch on `kind`, never on vendor error types or message text.
//
// Messages are built from the service, operation and kind only. Vendor messages, request bodies,
// URLs, tokens, email addresses and customer content never reach a PortError's message, own
// properties or stack, so an error can be logged, reported to Sentry or recorded by DBOS as a step
// failure without leaking anything.
//
// The underlying vendor error is kept in an ES private field, never in the standard `cause`:
// `util.inspect`, console output, pino's `err` serializer and Sentry's LinkedErrors integration all
// print `error.cause` (message and stack), and vendor errors carry request bodies and tokens (an
// Octokit RequestError does not redact `request.body` or `response.data`). Private fields are
// invisible to all of them, even with `util.inspect(…, { showHidden: true })`. Local debugging reads
// it explicitly through `vendorCause()`, which must never be logged or reported.

/** Every external service behind a port, used to label errors and telemetry. */
export const PORT_SERVICES = [
  "github_app",
  "github_user",
  "osv",
  "malware_scanner",
  "kev",
  "npm",
  "sandbox",
  "model",
  "email",
  "billing",
  "kms",
  "secrets",
  "object_storage",
  "scan_store",
  "site_fetch",
  "analytics",
  "docs",
  "webhook",
  "workload_identity",
  "iap",
] as const;
export type PortService = (typeof PORT_SERVICES)[number];

/** The kinds of port failure. Each kind has one class below. */
export const PORT_ERROR_KINDS = [
  "rate_limited",
  "ambiguous_outcome",
  "not_found",
  "conflict",
  "precondition_failed",
  "permission_denied",
  "authentication_failed",
  "invalid_request",
  "unavailable",
  "integrity",
  "limit_exceeded",
  "blocked_destination",
  "isolation_unavailable",
  "installation_suspended",
  "payment_declined",
  "recipient_inactive",
  "no_compliant_provider",
] as const;
export type PortErrorKind = (typeof PORT_ERROR_KINDS)[number];

/**
 * Why a service was unavailable. The request did not take effect (or was a pure read).
 * `insufficient_credits` and `account_restricted` describe Kovo's own provider account (out of
 * credits; an unconfirmed sender, an account pending approval, a sending IP not allowed): the call
 * succeeds again only after an operator fixes the account, so callers retry with backoff and alert.
 */
export const UNAVAILABLE_REASONS = [
  "timeout",
  "network",
  "server_error",
  "overloaded",
  "insufficient_credits",
  "maintenance",
  "account_restricted",
] as const;
export type UnavailableReason = (typeof UNAVAILABLE_REASONS)[number];

const SAFE_TOKEN = /^[A-Za-z0-9_.:-]{1,128}$/;

/**
 * Keeps only a short machine token (a vendor error code such as `resource_missing`, a request ID,
 * an operation name). Anything else is dropped rather than risk copying free text into logs.
 */
export function safeToken(value: string | null | undefined): string | undefined {
  return value != null && SAFE_TOKEN.test(value) ? value : undefined;
}

export interface PortErrorInit {
  readonly service: PortService;
  /** The port method, e.g. `mergePullRequest`. */
  readonly operation: string;
  /** A vendor error code or sub-reason; kept only when it is a short machine token. */
  readonly code?: string | undefined;
  /** The provider's request ID (e.g. `x-github-request-id`) for support correlation. */
  readonly providerRequestId?: string | undefined;
  /**
   * The underlying vendor error, for local debugging only. It is stored privately (never as the
   * standard `cause`) and is reachable only through {@link PortError.vendorCause}.
   */
  readonly vendorCause?: unknown;
}

/** The sanitized, loggable form of a port error. */
export interface PortErrorDescription {
  readonly name: string;
  readonly kind: PortErrorKind;
  readonly service: PortService;
  readonly operation: string;
  readonly retryable: boolean;
  readonly code?: string;
  readonly providerRequestId?: string;
  readonly retryAfterMs?: number;
}

/** Base class of every port error. Use the subclasses; `kind` discriminates them. */
export abstract class PortError extends Error {
  abstract readonly kind: PortErrorKind;
  /**
   * Whether repeating the same call later is safe and may succeed. Ambiguous outcomes are never
   * retryable as-is: the caller reconciles with provider state first.
   */
  abstract readonly retryable: boolean;
  readonly service: PortService;
  readonly operation: string;
  readonly code: string | undefined;
  readonly providerRequestId: string | undefined;
  readonly #vendorCause: unknown;

  protected constructor(kind: PortErrorKind, init: PortErrorInit) {
    const operation = safeToken(init.operation) ?? "unknown_operation";
    super(`${init.service}.${operation}: ${kind}`);
    this.name = new.target.name;
    this.service = init.service;
    this.operation = operation;
    this.code = safeToken(init.code);
    this.providerRequestId = safeToken(init.providerRequestId);
    this.#vendorCause = init.vendorCause;
    registerErrorMessage(this);
  }

  /**
   * The vendor error this port error was translated from (undefined when none was given). It may
   * contain tokens, request bodies and customer content: use it only for local debugging, never
   * log it, report it, attach it as a `cause` or return it across a DBOS step.
   */
  vendorCause(): unknown {
    return this.#vendorCause;
  }

  /** Sanitized fields for logs and telemetry. The vendor cause is deliberately omitted. */
  toJSON(): PortErrorDescription {
    return describePortError(this);
  }
}

export function describePortError(error: PortError): PortErrorDescription {
  return {
    name: error.name,
    kind: error.kind,
    service: error.service,
    operation: error.operation,
    retryable: error.retryable,
    ...(error.code === undefined ? {} : { code: error.code }),
    ...(error.providerRequestId === undefined
      ? {}
      : { providerRequestId: error.providerRequestId }),
    ...(error instanceof RateLimitedError ? { retryAfterMs: error.retryAfterMs } : {}),
  };
}

export function isPortError(value: unknown): value is PortError {
  return value instanceof PortError;
}

/**
 * The provider throttled the call (HTTP 429, GitHub primary/secondary limits, gRPC
 * RESOURCE_EXHAUSTED). The request did not take effect. Wait at least `retryAfterMs` (a DBOS
 * durable sleep, never while holding a sandbox) and retry.
 */
export class RateLimitedError extends PortError {
  readonly kind = "rate_limited";
  readonly retryable = true;
  /** Milliseconds to wait before retrying; 0 when the provider gave no hint. */
  readonly retryAfterMs: number;

  constructor(init: PortErrorInit & { readonly retryAfterMs: number }) {
    super("rate_limited", init);
    if (!Number.isSafeInteger(init.retryAfterMs) || init.retryAfterMs < 0) {
      throw new RangeError("retryAfterMs must be a non-negative safe integer");
    }
    this.retryAfterMs = init.retryAfterMs;
  }
}

/**
 * The call may or may not have taken effect: a timeout, dropped connection or 5xx after a write was
 * sent. Never blind-retry. Reconcile with provider state using the reconciliation read each port
 * documents (search PR by head, reread merge state, search outbound email by metadata, retry a
 * Stripe mutation with the same idempotency key, …), or record an explicit uncertain state.
 */
export class AmbiguousOutcomeError extends PortError {
  readonly kind = "ambiguous_outcome";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("ambiguous_outcome", init);
  }
}

/** The addressed resource does not exist, or the credential cannot see it (GitHub returns 404 for both). */
export class NotFoundError extends PortError {
  readonly kind = "not_found";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("not_found", init);
  }
}

/**
 * The request conflicts with current provider state in a way the port does not model as a normal
 * result (e.g. an idempotency key reused with different parameters, a concurrent modification).
 */
export class ConflictError extends PortError {
  readonly kind = "conflict";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("conflict", init);
  }
}

/**
 * A precondition the caller relied on no longer holds (a disabled KMS key version, a pinned
 * generation that moved, a PR head that is not the expected SHA where the port has no dedicated
 * result for it).
 */
export class PreconditionFailedError extends PortError {
  readonly kind = "precondition_failed";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("precondition_failed", init);
  }
}

/**
 * The credential is valid but lacks the permission or scope (HTTP 403, gRPC PERMISSION_DENIED, an
 * installation token minted without the operation's permission). Authorization lookups that fail
 * this way deny access.
 */
export class PermissionDeniedError extends PortError {
  readonly kind = "permission_denied";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("permission_denied", init);
  }
}

/**
 * The credential was rejected (HTTP 401): a revoked user token, an expired installation token, bad
 * configuration. For a user-to-server token this means the user's GitHub authorization is gone.
 */
export class AuthenticationError extends PortError {
  readonly kind = "authentication_failed";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("authentication_failed", init);
  }
}

/** The provider rejected the request as invalid (HTTP 400/422). Permanent; retrying cannot help. */
export class InvalidRequestError extends PortError {
  readonly kind = "invalid_request";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("invalid_request", init);
  }
}

/**
 * The provider could not serve the request and it did not take effect: a failed read, a refusal
 * before any write, an outage. Retry with bounded backoff.
 */
export class UnavailableError extends PortError {
  readonly kind = "unavailable";
  readonly retryable = true;
  readonly reason: UnavailableReason;

  constructor(init: PortErrorInit & { readonly reason: UnavailableReason }) {
    super("unavailable", init);
    this.reason = init.reason;
  }

  override toJSON(): PortErrorDescription & { readonly reason: UnavailableReason } {
    return { ...describePortError(this), reason: this.reason };
  }
}

/**
 * Bytes were corrupted or did not match what was expected: a KMS or Cloud Storage CRC32C mismatch,
 * an AEAD authentication failure, an uploaded file whose hash differs, a Git commit whose SHA
 * differs from the predicted one. Treat the data as untrusted; never proceed with it.
 */
export class IntegrityError extends PortError {
  readonly kind = "integrity";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("integrity", init);
  }
}

/** A response or upload exceeded the caller's byte bound. Nothing beyond the bound was kept. */
export class LimitExceededError extends PortError {
  readonly kind = "limit_exceeded";
  readonly retryable = false;
  readonly limitBytes: number;

  constructor(init: PortErrorInit & { readonly limitBytes: number }) {
    super("limit_exceeded", init);
    this.limitBytes = init.limitBytes;
  }

  override toJSON(): PortErrorDescription & { readonly limitBytes: number } {
    return { ...describePortError(this), limitBytes: this.limitBytes };
  }
}

/**
 * An outbound request was refused by Kovo's own destination policy (SSRF: private, loopback or
 * link-local addresses, non-HTTPS schemes, credentials in URLs, unsafe redirects). No request was
 * sent to the blocked destination.
 */
export class BlockedDestinationError extends PortError {
  readonly kind = "blocked_destination";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("blocked_destination", init);
  }
}

/**
 * A sandbox could not be created with, or no longer demonstrably enforces, the required network
 * isolation (SPEC: "Fail sandbox creation if required isolation cannot be established"). The
 * sandbox must be destroyed and no customer source uploaded to it.
 */
export class IsolationUnavailableError extends PortError {
  readonly kind = "isolation_unavailable";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("isolation_unavailable", init);
  }
}

/** The GitHub App installation is suspended (installation token minting returned 403). */
export class InstallationSuspendedError extends PortError {
  readonly kind = "installation_suspended";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("installation_suspended", init);
  }
}

/**
 * The payment was declined synchronously (Stripe 402 with `payment_behavior:
 * error_if_incomplete`). The requested subscription change was not applied.
 */
export class PaymentDeclinedError extends PortError {
  readonly kind = "payment_declined";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("payment_declined", init);
  }
}

/**
 * The email provider refused the recipient as inactive or suppressed. The
 * message was not sent; suppress the address instead of retrying.
 */
export class RecipientInactiveError extends PortError {
  readonly kind = "recipient_inactive";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("recipient_inactive", init);
  }
}

/**
 * No model endpoint satisfies the routing constraints (ZDR, data-collection deny, required
 * parameters, explicit provider list). SPEC: "If none is available, AI waits; deterministic flows
 * continue." The request was not served and incurred no cost.
 */
export class NoCompliantProviderError extends PortError {
  readonly kind = "no_compliant_provider";
  readonly retryable = false;

  constructor(init: PortErrorInit) {
    super("no_compliant_provider", init);
  }
}
