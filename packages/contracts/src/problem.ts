import { z } from "zod";

import { writerPinned } from "./compatibility.js";

import { jsonPointerSchema, whenValid } from "./primitives.js";

// RFC 9457 problem details with stable reason codes (ARCHITECTURE §3 "Errors"; SPEC: "Use RFC 9457
// errors with stable reasons"). A reason's HTTP status and title are part of the public API and
// never change; add new reasons instead of repurposing old ones.

export const PROBLEM_CONTENT_TYPE = "application/problem+json";
export const PROBLEM_TYPE_BASE = "https://kovo.dev/problems/";

interface ReasonDefinition {
  readonly status: number;
  readonly title: string;
}

/** Stable reason codes (public API). */
export const REASON_CODES = [
  "unauthenticated",
  "invalid_signature",
  "csrf_failed",
  "forbidden_actor",
  "human_approval_required",
  "insufficient_repo_permission",
  "insufficient_account_role",
  "insufficient_key_scope",
  "billing_authority_required",
  "plan_required",
  "authorization_unavailable",
  "budget_exhausted",
  "overage_limit_reached",
  "capacity_exceeded",
  "egress_account_share_exhausted",
  "quote_expired",
  "quote_mismatch",
  "payment_declined",
  "payment_past_due",
  "coupon_not_redeemable",
  "malformed_request",
  "invalid_cursor",
  "not_found",
  "method_not_allowed",
  "payload_too_large",
  "unsupported_media_type",
  "validation_failed",
  "precondition_failed",
  "precondition_required",
  "idempotency_conflict",
  "idempotency_in_progress",
  "rate_limited",
  "conflict",
  "not_reevaluable",
  "already_evaluated_at_version",
  "reevaluation_budget_exhausted",
  "account_link_conflict",
  "account_not_linked",
  "installation_not_authorized",
  "onboarding_mismatch",
  "owner_required",
  "invitation_invalid",
  "repo_not_enabled",
  "repo_paused",
  "installation_suspended",
  "unsupported_repository",
  "recipe_not_approvable",
  "fix_not_retriable",
  "fix_not_merged",
  "evidence_expired",
  "record_expired",
  "record_unavailable",
  "record_failed",
  "failure_excerpt_expired",
  "destination_not_allowed",
  "internal_error",
  "upstream_error",
  "packument_too_large",
  "service_unavailable",
] as const;
/**
 * Reasons allowed in durable job/recovery rows. On-demand API refusals never become
 * background job failures; keep this tuple compatible with the deployed constraints.
 */
export const PERSISTED_REASON_CODES: readonly [ReasonCode, ...ReasonCode[]] = [
  REASON_CODES[0],
  ...REASON_CODES.slice(1).filter(
    (reason) =>
      reason !== "not_reevaluable" &&
      reason !== "already_evaluated_at_version" &&
      reason !== "reevaluation_budget_exhausted" &&
      reason !== "coupon_not_redeemable" &&
      reason !== "packument_too_large" &&
      reason !== "egress_account_share_exhausted",
  ),
] as const;
// Reader first: promote this reader before publishing new top-level API reasons. Packument
// limits currently use upstream_error plus a fixed subreason, and the proxy's separate catalog.
export const PUBLIC_REASON_CODES = REASON_CODES.filter(
  (reason) => reason !== "egress_account_share_exhausted" && reason !== "packument_too_large",
);
export const reasonCodeSchema = writerPinned(z.enum(REASON_CODES), z.enum(PUBLIC_REASON_CODES));
// Transient packument refusals use upstream_error details, never durable job/dead-letter reasons.
// Keep these nested readers identical to their promoted boundary and its compatibility proofs.
export const durableFailureReasonCodeSchema = writerPinned(
  z.enum(REASON_CODES.filter((reason) => reason !== "packument_too_large")),
  z.enum(PUBLIC_REASON_CODES),
);
export type ReasonCode = z.infer<typeof reasonCodeSchema>;

/** Every reason code with its fixed HTTP status and title. */
export const REASONS = {
  // Authentication and authorization
  unauthenticated: { status: 401, title: "Authentication required" },
  invalid_signature: { status: 401, title: "Signature verification failed" },
  csrf_failed: { status: 403, title: "CSRF check failed" },
  forbidden_actor: { status: 403, title: "This kind of caller cannot use this route" },
  human_approval_required: { status: 403, title: "A human session is required" },
  insufficient_repo_permission: { status: 403, title: "Insufficient repository permission" },
  insufficient_account_role: { status: 403, title: "Insufficient account role" },
  insufficient_key_scope: { status: 403, title: "API key scope does not cover this request" },
  billing_authority_required: { status: 403, title: "Billing authority required" },
  plan_required: { status: 403, title: "A Kovo Plus plan is required" },
  authorization_unavailable: { status: 503, title: "Authorization could not be verified" },

  // Billing, capacity and spend
  budget_exhausted: { status: 402, title: "AI budget exhausted" },
  overage_limit_reached: { status: 402, title: "Overage spending limit reached" },
  capacity_exceeded: { status: 409, title: "Protected repository capacity exceeded" },
  egress_account_share_exhausted: { status: 429, title: "Account egress share exhausted" },
  quote_expired: { status: 409, title: "Capacity quote expired" },
  quote_mismatch: { status: 409, title: "Capacity quote does not match the request" },
  payment_declined: { status: 402, title: "Payment was declined" },
  payment_past_due: { status: 402, title: "Payment is past due" },
  // One refusal for every reason a code cannot be redeemed, so codes cannot be probed.
  coupon_not_redeemable: { status: 422, title: "Coupon code cannot be redeemed" },

  // Request handling
  malformed_request: { status: 400, title: "Malformed request" },
  invalid_cursor: { status: 400, title: "Invalid pagination cursor" },
  not_found: { status: 404, title: "Resource not found" },
  method_not_allowed: { status: 405, title: "Method not allowed" },
  payload_too_large: { status: 413, title: "Request body too large" },
  unsupported_media_type: { status: 415, title: "Unsupported media type" },
  validation_failed: { status: 422, title: "Validation failed" },
  precondition_failed: { status: 412, title: "Resource version is stale" },
  precondition_required: { status: 428, title: "If-Match header required" },
  idempotency_conflict: {
    status: 422,
    title: "Idempotency key was used with a different request",
  },
  idempotency_in_progress: {
    status: 409,
    title: "A request with this idempotency key is in progress",
  },
  rate_limited: { status: 429, title: "Rate limit exceeded" },
  conflict: { status: 409, title: "Conflict with current state" },
  not_reevaluable: { status: 409, title: "Fix is not eligible for re-evaluation" },
  already_evaluated_at_version: { status: 409, title: "Fix already evaluated at this version" },
  reevaluation_budget_exhausted: {
    status: 409,
    title: "Repository re-evaluation budget exhausted",
  },

  // Accounts, onboarding and membership
  account_link_conflict: { status: 409, title: "GitHub account is already linked" },
  account_not_linked: { status: 409, title: "Account is not linked to GitHub" },
  installation_not_authorized: { status: 403, title: "Installation authorization not verified" },
  onboarding_mismatch: {
    status: 409,
    title: "Installation does not match the onboarding request",
  },
  owner_required: { status: 409, title: "The account must keep an owner" },
  invitation_invalid: { status: 410, title: "Invitation is invalid or expired" },

  // Repositories, recipes and fixes
  repo_not_enabled: { status: 409, title: "Repository protection is not enabled" },
  repo_paused: { status: 409, title: "Repository is paused" },
  installation_suspended: { status: 409, title: "GitHub App installation is suspended" },
  unsupported_repository: { status: 422, title: "Repository is not supported" },
  recipe_not_approvable: { status: 409, title: "Recipe version cannot be approved" },
  fix_not_retriable: { status: 409, title: "Fix cannot be retried" },
  fix_not_merged: { status: 409, title: "Fix is not merged" },
  evidence_expired: { status: 409, title: "Verification evidence expired" },
  record_expired: { status: 410, title: "Run record expired" },
  record_unavailable: { status: 503, title: "Run record unavailable" },
  record_failed: { status: 503, title: "Run record failed" },
  failure_excerpt_expired: { status: 410, title: "Step output excerpt expired" },
  destination_not_allowed: { status: 422, title: "Webhook destination is not allowed" },

  // Server
  internal_error: { status: 500, title: "Internal error" },
  upstream_error: { status: 502, title: "Upstream service error" },
  packument_too_large: { status: 503, title: "The registry metadata exceeds safe parsing limits" },
  service_unavailable: { status: 503, title: "Service unavailable" },
} as const satisfies Record<ReasonCode, ReasonDefinition>;

export function isReasonCode(value: string): value is ReasonCode {
  return Object.hasOwn(REASONS, value);
}

/** `https://kovo.dev/problems/<reason>`. */
export function problemTypeUri(reason: ReasonCode): string {
  return `${PROBLEM_TYPE_BASE}${reason}`;
}

/** The reason encoded in a problem `type` URI, or `null` for any other URI. */
export function reasonFromProblemType(type: string): ReasonCode | null {
  if (!type.startsWith(PROBLEM_TYPE_BASE)) return null;
  const reason = type.slice(PROBLEM_TYPE_BASE.length);
  return isReasonCode(reason) ? reason : null;
}

/** A field-level validation error: an RFC 6901 pointer into the request body plus a message. */
export const problemFieldErrorSchema = z.strictObject({
  pointer: jsonPointerSchema,
  detail: z.string().min(1).max(1000),
});
export type ProblemFieldError = z.infer<typeof problemFieldErrorSchema>;

/**
 * An RFC 9457 problem document. Extension members are allowed (RFC 9457 §3.2: consumers must ignore
 * unrecognized extensions); the standard members must agree with the reason's fixed definition.
 */
export const problemDetailsSchema = z
  .looseObject({
    type: z.string().max(256),
    title: z.string().min(1).max(200),
    status: z.int().min(400).max(599),
    detail: z.string().min(1).max(2000).exactOptional(),
    instance: z.string().min(1).max(2048).exactOptional(),
    reason: reasonCodeSchema,
    request_id: z.string().min(1).max(128),
    trace_id: z
      .string()
      .regex(/^[a-f0-9]{32}$/)
      .exactOptional(),
    job_id: z.uuid().exactOptional(),
    repo_id: z.uuid().exactOptional(),
    record_id: z.uuid().exactOptional(),
    workflow_id: z
      .string()
      .regex(/^[A-Za-z0-9@/._:~-]{1,512}$/)
      .exactOptional(),
    errors: z.array(problemFieldErrorSchema).min(1).max(100).exactOptional(),
  })
  .superRefine((problem, ctx) => {
    const definition = REASONS[problem.reason];
    if (problem.type !== problemTypeUri(problem.reason)) {
      ctx.addIssue({ code: "custom", path: ["type"], message: "type must match the reason" });
    }
    if (problem.status !== definition.status) {
      ctx.addIssue({ code: "custom", path: ["status"], message: "status must match the reason" });
    }
    if (problem.title !== definition.title) {
      ctx.addIssue({ code: "custom", path: ["title"], message: "title must match the reason" });
    }
    if (problem.errors !== undefined && problem.reason !== "validation_failed") {
      ctx.addIssue({
        code: "custom",
        path: ["errors"],
        message: "field errors are only valid for validation_failed",
      });
    }
  }, whenValid);
export type ProblemDetails = z.infer<typeof problemDetailsSchema>;

export interface ProblemInit {
  readonly requestId: string;
  readonly traceId?: string;
  readonly jobId?: string;
  readonly repoId?: string;
  readonly recordId?: string;
  readonly workflowId?: string;
  readonly detail?: string;
  readonly instance?: string;
  readonly errors?: readonly ProblemFieldError[];
}

/** Builds a validated problem document for `reason`. */
export function problemDetails(reason: ReasonCode, init: ProblemInit): ProblemDetails {
  // Keep HTTP writers compatible with r776 while the tolerant reader rolls out.
  if (reason === "egress_account_share_exhausted") reason = "rate_limited";
  if (reason === "packument_too_large") reason = "service_unavailable";
  const definition: ReasonDefinition = REASONS[reason];
  return problemDetailsSchema.parse({
    type: problemTypeUri(reason),
    title: definition.title,
    status: definition.status,
    ...(init.detail === undefined ? {} : { detail: init.detail }),
    ...(init.instance === undefined ? {} : { instance: init.instance }),
    reason,
    request_id: init.requestId,
    ...(init.traceId === undefined ? {} : { trace_id: init.traceId }),
    ...(init.jobId === undefined ? {} : { job_id: init.jobId }),
    ...(init.repoId === undefined ? {} : { repo_id: init.repoId }),
    ...(init.recordId === undefined ? {} : { record_id: init.recordId }),
    ...(init.workflowId === undefined ? {} : { workflow_id: init.workflowId }),
    ...(init.errors === undefined ? {} : { errors: [...init.errors] }),
  });
}
