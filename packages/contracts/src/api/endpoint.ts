import type { z } from "zod";

import {
  managementKeyPermissionSchema,
  type ManagementKeyPermission,
} from "../api-key-authority-schemas.js";

import type { AccountRole } from "../enums/accounts.js";
import type { AuditAction } from "../enums/operations.js";
import { REASON_CODES, type ReasonCode } from "../problem.js";

// The building blocks of the typed `/v1` endpoint registry (SPEC "Public API"). Every endpoint
// declares its HTTP shape (method, path template, params, query, body, responses), an
// authorization descriptor derived from SPEC's table and "Accounts and permissions" section
// (docs/decisions/auth.md, docs/decisions/contracts.md "Public API"), its concurrency and replay
// rules (Idempotency-Key, If-Match, ETag, CSRF) and the stable problem reasons it may return.
// The control plane enforces these descriptors through core/authz and its middleware; the web
// client uses the same schemas and flags. Nothing here performs I/O.

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Areas of the API; each has its file under `src/api/` (accounts also has `onboarding.ts`). */
export const API_AREAS = [
  "accounts",
  "repos",
  "findings",
  "recipes",
  "policy",
  "fixes",
  "jobs",
  "pauses",
  "notifications",
  "api-keys",
  "audit",
  "webhooks",
  "billing",
  "usage",
  "operator",
  "health",
  "dependency-verdicts",
] as const;
export type ApiArea = (typeof API_AREAS)[number];

/**
 * Who may call an endpoint at all. `human_session` is a Better Auth session (cookie; CSRF applies to
 * its mutations); `api_key_read`/`api_key_write` are account API keys by scope (a write key is not
 * implicitly a read key here: each endpoint lists every kind it accepts); `operator` is the service
 * identity plus explicit operator authorization; `anonymous` is only for health probes.
 */
export const ENDPOINT_ACTORS = [
  "human_session",
  "api_key_read",
  "api_key_write",
  "operator",
  "anonymous",
] as const;
export type EndpointActor = (typeof ENDPOINT_ACTORS)[number];

/**
 * How the tenant is resolved. SPEC: "Each request resolves tenant ownership … Account-scoped routes
 * without an account in the path require an explicit validated account context. Never infer
 * authorization from a caller-supplied repo, job, invoice or Stripe customer ID."
 *
 * - `none`: not tenant-scoped (health, operator).
 * - `user`: the caller's own identity (joined accounts, joining, accepting an invitation).
 * - `path_account`: the `{account}` path parameter, checked against the caller's membership.
 * - `account_context`: the `X-Kovo-Account` header for sessions; an API key's own account (the
 *   header, when sent, must match it).
 * - `path_resource`: the owning account of the repo/fix/job/installation/key/webhook/invitation/
 *   onboarding request addressed in the path, read from that row, never from the caller.
 *
 * For the three account tenants the caller must be a current member of that account (an API key:
 * belong to it), unless the descriptor sets `accountMember: false`, which only a GitHub account
 * administrator's decision on an onboarding request does. A session that also sends
 * `X-Kovo-Account` on a `path_account` or `path_resource` route must name the addressed account;
 * naming another one is `not_found`, exactly as if the resource did not exist in the selected
 * account (a UI that switched accounts must not act on the previous account's resource).
 */
export const TENANT_SOURCES = [
  "none",
  "user",
  "path_account",
  "account_context",
  "path_resource",
] as const;
export type TenantSource = (typeof TENANT_SOURCES)[number];

/**
 * Verified GitHub authority over repositories (docs/decisions/contracts.md "Account context, scoped
 * reads and writes"; docs/decisions/ports.md "Repository access levels and freshness"):
 * - `read`: current GitHub read access ("Repository visibility always requires current GitHub read
 *   access"). For a public repository every GitHub user has it.
 * - `explicit_read`: read access held as a collaborator (directly, through a team, or through
 *   organization membership or base permission), never through public visibility. Joining an
 *   account through repository access needs it.
 * - `write`: current GitHub push access, SPEC's "Scoped write" (dismissing a finding, retrying a
 *   fix, recipe overrides and rediscovery spend allowance or suppress fixes).
 * - `admin`: "verified GitHub repository admin or organization owner".
 * `admin` implies `write`, `write` implies `explicit_read` (push access is always an explicit
 * grant) and `explicit_read` implies `read`. For API keys the effective authority is the
 * intersection of the key scope, its delegated repositories and its creator's current GitHub
 * authority.
 */
export const REPO_AUTHORITY_LEVELS = ["read", "explicit_read", "write", "admin"] as const;
export type RepoAuthorityLevel = (typeof REPO_AUTHORITY_LEVELS)[number];

/**
 * Which repositories the authority is checked over:
 * - `path_repo`: the `{repo}` in the path;
 * - `resource_repos`: the repositories of the addressed resource (a fix's repo, a job's repo, a
 *   webhook subscription's repo scope);
 * - `body_repos`: every repository named in the request body (delegations, recipients);
 * - `installation_repos`: every enabled repository of the addressed installation;
 * - `listed_items`: lists and reports include only repositories the caller can read and redact
 *   details of the others;
 * - `any_account_repo`: at least one protected repository of the target account (joining).
 */
export const REPO_AUTHORITY_SCOPES = [
  "path_repo",
  "resource_repos",
  "body_repos",
  "installation_repos",
  "listed_items",
  "any_account_repo",
] as const;
export type RepoAuthorityScope = (typeof REPO_AUTHORITY_SCOPES)[number];

export interface RepoAuthority {
  readonly level: RepoAuthorityLevel;
  readonly over: RepoAuthorityScope;
}

/**
 * Request properties that raise the requirement beyond the endpoint's base rule. Most are evaluated
 * by the service against current state, not trusted from the caller; the ones listed in
 * {@link REQUEST_MEMBER_ESCALATIONS} hold whenever the request carries a member, whatever the state.
 * - `enables_autopilot`, `changes_activation_policy`: "Human repo admin for autopilot/activation
 *   policy"; "API keys cannot enable autopilot".
 * - `authorizes_activation_scope`: the request (re)binds autopilot consent to a disclosed scope
 *   (`activation_scope_hash`). Resending autopilot with another hash on an autopilot repository
 *   enables nothing, yet authorizes a scope no human reviewed ("Any undisclosed egress … outside
 *   the recorded scope still needs approval"), so it is decided from the request alone.
 * - `weakens_or_broadens_recipe`: "weakening/broader authority requires human repo admin".
 * - `weakens_policy`: "keys may only tighten"; "API keys cannot … weaken policy".
 * - `resumes_into_autopilot`: "keys may pause, never resume into autopilot".
 * - `needs_paid_capacity`: "billing-authorized capacity grant if needed": no included or already
 *   paid unused slot is free. Only a separate, quoted confirmation adds paid capacity ("Preview
 *   and explicitly confirm the prorated charge before adding paid capacity"), so the requirement
 *   is `capacityGrant` and the request is deferred whoever calls, a billing-authorized repo admin
 *   included.
 * - `changes_owner_membership`: granting, demoting or removing an owner ("preserve an account
 *   owner"; an admin cannot take over or remove the owner).
 * - `affects_undelegated_repos`: the change applies to repositories outside an API key's
 *   delegated scope (account-wide notification settings reach every repository of the account,
 *   whatever its state, and the repositories it gains later):
 *   "Effective repository permissions are the intersection of key scope, explicitly delegated repo
 *   scope, and the creator's current GitHub authority".
 * - `reads_account_totals`: "Billing scope for account totals; otherwise only authorized repo
 *   operational usage".
 * - `raises_pr_parallel_cap`: the request raises the PR-only parallel cap ("configurable 1–10");
 *   like policy, a key "may only tighten", so raising it needs a human repository admin.
 */
export const ESCALATION_CONDITIONS = [
  "enables_autopilot",
  "changes_activation_policy",
  "authorizes_activation_scope",
  "weakens_or_broadens_recipe",
  "weakens_policy",
  "resumes_into_autopilot",
  "needs_paid_capacity",
  "changes_owner_membership",
  "affects_undelegated_repos",
  "reads_account_totals",
  "raises_pr_parallel_cap",
] as const;
export type EscalationCondition = (typeof ESCALATION_CONDITIONS)[number];

/**
 * What happens when an escalated requirement is not met: `deny` refuses the request with a
 * problem; `defer` accepts it in a pending state for another authorized actor (the two-actor
 * protection flow); `omit` answers without the gated part (usage totals are `null`).
 */
export const ESCALATION_OUTCOMES = ["deny", "defer", "omit"] as const;
export type EscalationOutcome = (typeof ESCALATION_OUTCOMES)[number];

export interface EscalationRequirement {
  readonly humanSession?: true;
  readonly repoAdmin?: true;
  readonly accountRoles?: readonly AccountRole[];
  readonly billingAuthority?: true;
  /**
   * A billing-authorized capacity confirmation (`POST /v1/billing/capacity/confirm`). No caller
   * meets it within the escalated request itself, so it is only used with `unmet: "defer"`.
   */
  readonly capacityGrant?: true;
}

export interface Escalation {
  readonly when: EscalationCondition;
  readonly requires: EscalationRequirement;
  readonly unmet: EscalationOutcome;
}

/**
 * Escalation conditions that hold whenever the request body carries the named top-level member,
 * independent of current state: sending the value is itself the authorization.
 */
export const REQUEST_MEMBER_ESCALATIONS = {
  authorizes_activation_scope: "activation_scope_hash",
} as const satisfies Partial<Record<EscalationCondition, string>>;

/**
 * The escalations of an endpoint that a (parsed) request body triggers by itself. The service
 * evaluates the remaining conditions against current state; these need no state at all.
 */
export function requestTriggeredEscalations(
  authorization: Pick<EndpointAuthorization, "escalations">,
  body: unknown,
): Escalation[] {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return [];
  const members: Readonly<Partial<Record<EscalationCondition, string>>> =
    REQUEST_MEMBER_ESCALATIONS;
  return authorization.escalations.filter((escalation) => {
    const member = members[escalation.when];
    return member !== undefined && Object.hasOwn(body, member);
  });
}

/** The authorization descriptor as written in an area file. */
export interface AuthorizationInit {
  /** SPEC's "Authorization/behavior" cell verbatim, or the SPEC text an implied endpoint follows. */
  readonly spec: string;
  readonly actors: readonly EndpointActor[];
  readonly tenant: TenantSource;
  /** Kovo account roles the caller (for a key: its creator) must currently hold; absent = any member. */
  readonly accountRoles?: readonly AccountRole[];
  readonly repoAuthority?: RepoAuthority;
  /** Exact Management grant; defaults to the operation ID only when it is in the catalog. */
  readonly managementPermission?: ManagementKeyPermission;
  /** "Billing" means Kovo owner/admin/billing manager (always required for the endpoint). */
  readonly billingAuthority?: boolean;
  /**
   * Verified GitHub administration of the GitHub account the addressed resource would link: an
   * owner of that organization, or the user itself for a personal account ("ambiguous ownership
   * requires confirmation from an authorized GitHub administrator"). Always revalidated at
   * execution time; Kovo roles never satisfy it.
   */
  readonly githubAccountAdmin?: boolean;
  /**
   * Whether the caller must be a member of the tenant account. Defaults to `true` for the
   * `path_account`, `account_context` and `path_resource` tenants and `false` otherwise; `false`
   * for an account tenant is only valid with `githubAccountAdmin`.
   */
  readonly accountMember?: boolean;
  readonly escalations?: readonly Escalation[];
}

/** The resolved authorization descriptor. */
export interface EndpointAuthorization {
  readonly spec: string;
  readonly actors: readonly EndpointActor[];
  readonly tenant: TenantSource;
  readonly accountRoles: readonly AccountRole[] | null;
  readonly repoAuthority: RepoAuthority | null;
  readonly managementPermission?: ManagementKeyPermission;
  readonly billingAuthority: boolean;
  readonly githubAccountAdmin: boolean;
  readonly accountMember: boolean;
  /** Only a human session may call (no API key or operator). Derived from `actors`. */
  readonly humanOnly: boolean;
  readonly escalations: readonly Escalation[];
}

/**
 * - `accepted`: an `Idempotency-Key` header is optional; a replay returns the stored response.
 * - `required`: the header is mandatory (charges, where a lost response must never double-charge).
 * Endpoints with `oneTimeFields` (secrets, bearer links) never accept keys: replaying would need
 * the stored plaintext.
 */
export const IDEMPOTENCY_MODES = ["none", "accepted", "required"] as const;
export type IdempotencyMode = (typeof IDEMPOTENCY_MODES)[number];

/**
 * Where an endpoint comes from: a SPEC Public API row, SPEC behaviour that needs a route, or an
 * explicit owner-directed exception, or an agent decision pending owner review.
 */
export type EndpointSource =
  | {
      readonly kind: "spec_row";
      /** The row's path exactly as SPEC prints it (one path of a two-path row). */
      readonly path: string;
    }
  | {
      readonly kind: "spec_implied";
      /** The SPEC section whose behaviour needs this route. */
      readonly section: string;
    }
  | {
      readonly kind: "owner_directed";
      /** The decision record under `docs/decisions/` (`verification.md`). */
      readonly decision: string;
      /** The record's `##` heading for the exception, exactly as written. */
      readonly heading: string;
    }
  | {
      readonly kind: "agent_decision";
      readonly decision: string;
      readonly heading: string;
      readonly reviewIssue: number;
    };

/** Success responses by HTTP status. */
export type ResponseMap = { readonly [status: number]: z.ZodType };

export interface EndpointInit<
  Method extends HttpMethod,
  Path extends string,
  Params extends z.ZodType | null,
  Query extends z.ZodType | null,
  Body extends z.ZodType | null,
  Responses extends ResponseMap,
> {
  readonly operationId: string;
  readonly area: ApiArea;
  readonly method: Method;
  /** Path template with `{name}` parameters (`/v1/repos/{repo}/findings`). */
  readonly path: Path;
  readonly summary: string;
  readonly source: EndpointSource;
  readonly params: Params;
  readonly query: Query;
  /** `null`: the route takes no body. */
  readonly body: Body;
  readonly responses: Responses;
  readonly authorization: AuthorizationInit;
  readonly idempotency?: IdempotencyMode;
  /** Versioned write: `If-Match` is required and a stale version is `412 precondition_failed`. */
  readonly ifMatch?: boolean;
  /**
   * JSON Pointer to the resource version in the success body; the response carries its ETag. It
   * is the concurrency token `If-Match` writes compare, not a cache validator: every response is
   * `API_CACHE_CONTROL` and nothing answers `304`. `GET …/recipe` shows the active version,
   * calibration and disclosure next to the overrides version it tags, and those change on their own.
   */
  readonly etag?: string;
  /** A cursor-paginated list (`limit` default 50, max 100, opaque `cursor`). */
  readonly paginated?: boolean;
  /** JSON Pointers to one-time secrets in the success body (shown once, never stored in plain). */
  readonly oneTimeFields?: readonly string[];
  /**
   * JSON Pointers to redacted step output the success body deliberately reveals: the owner-directed
   * exception for failed-step output excerpts (docs/decisions/verification.md "Failed-step output
   * excerpts"). Nothing else may carry output.
   */
  readonly revealedOutputFields?: readonly string[];
  /**
   * The sanitized audit events a successful call writes ("All mutations write a sanitized audit
   * event"). Every mutation declares at least one; reads declare none.
   */
  readonly auditActions?: readonly AuditAction[];
  /** Dedicated immutable access metadata storage for scoped operator diagnostics. */
  readonly auditStorage?:
    | "diagnostic_grants"
    | "diagnostic_query_audit"
    | "staff_access_grants"
    | "run_record_authorizations"
    | "staff_access_audit"
    | "flag_override_audit"
    | "flag_email_acknowledgments"
    | "malware_hold_audit"
    | "admin_audit";
  /** Endpoint-specific reasons; the reasons implied by the descriptor are added automatically. */
  readonly problems?: readonly ReasonCode[];
}

export interface Endpoint<
  Method extends HttpMethod = HttpMethod,
  Path extends string = string,
  Params extends z.ZodType | null = z.ZodType | null,
  Query extends z.ZodType | null = z.ZodType | null,
  Body extends z.ZodType | null = z.ZodType | null,
  Responses extends ResponseMap = ResponseMap,
> {
  readonly operationId: string;
  readonly area: ApiArea;
  readonly method: Method;
  readonly path: Path;
  readonly summary: string;
  readonly source: EndpointSource;
  readonly params: Params;
  readonly query: Query;
  readonly body: Body;
  readonly responses: Responses;
  readonly authorization: EndpointAuthorization;
  readonly idempotency: IdempotencyMode;
  readonly ifMatch: boolean;
  readonly etag: string | null;
  readonly paginated: boolean;
  readonly oneTimeFields: readonly string[];
  readonly revealedOutputFields: readonly string[];
  readonly auditActions: readonly AuditAction[];
  readonly auditStorage:
    | "diagnostic_grants"
    | "diagnostic_query_audit"
    | "staff_access_grants"
    | "run_record_authorizations"
    | "staff_access_audit"
    | "flag_override_audit"
    | "flag_email_acknowledgments"
    | "malware_hold_audit"
    | "admin_audit"
    | null;
  /** Session-cookie mutations need the Origin check and the double-submit token. */
  readonly csrf: boolean;
  /** Every stable reason the endpoint may return, in `REASON_CODES` order. */
  readonly problems: readonly ReasonCode[];
}

/** Any registered endpoint. */
export type AnyEndpoint = Endpoint;

/** Tenants that name a Kovo account, whose membership the caller needs by default. */
const ACCOUNT_TENANTS: ReadonlySet<TenantSource> = new Set([
  "path_account",
  "account_context",
  "path_resource",
]);

/** Reasons any endpoint may return (throttling and server failures). */
const UNIVERSAL_PROBLEMS: readonly ReasonCode[] = [
  "rate_limited",
  "internal_error",
  "service_unavailable",
];

/** Every method except GET changes state (and so needs CSRF protection under a cookie). */
export function isMutation(method: HttpMethod): boolean {
  return method !== "GET";
}

/** The reasons implied by an endpoint's shape and authorization descriptor. */
export function impliedProblems(endpoint: {
  readonly method: HttpMethod;
  readonly params: z.ZodType | null;
  readonly query: z.ZodType | null;
  readonly body: z.ZodType | null;
  readonly authorization: EndpointAuthorization;
  readonly idempotency: IdempotencyMode;
  readonly ifMatch: boolean;
  readonly paginated: boolean;
  readonly csrf: boolean;
}): ReasonCode[] {
  const reasons = new Set<ReasonCode>(UNIVERSAL_PROBLEMS);
  const auth = endpoint.authorization;
  const authenticated = !auth.actors.includes("anonymous");
  if (authenticated) {
    reasons.add("unauthenticated");
    reasons.add("forbidden_actor");
  }
  // Escalations that omit or defer never refuse the request, so only `deny` adds reasons.
  const denying = auth.escalations.filter((escalation) => escalation.unmet === "deny");
  const humanRequired =
    auth.humanOnly || denying.some((escalation) => escalation.requires.humanSession);
  if (humanRequired) reasons.add("human_approval_required");
  if (auth.actors.some((actor) => actor === "api_key_read" || actor === "api_key_write")) {
    reasons.add("insufficient_key_scope");
  }
  const roleGated =
    auth.accountRoles !== null ||
    denying.some((escalation) => escalation.requires.accountRoles !== undefined);
  if (roleGated) reasons.add("insufficient_account_role");
  if (auth.repoAuthority !== null || denying.some((escalation) => escalation.requires.repoAdmin)) {
    reasons.add("insufficient_repo_permission");
    reasons.add("authorization_unavailable");
  }
  if (auth.billingAuthority || denying.some((escalation) => escalation.requires.billingAuthority)) {
    reasons.add("billing_authority_required");
  }
  if (auth.githubAccountAdmin) {
    reasons.add("installation_not_authorized");
    reasons.add("authorization_unavailable");
  }
  if (endpoint.csrf) reasons.add("csrf_failed");
  if (endpoint.body !== null) {
    reasons.add("malformed_request");
    reasons.add("unsupported_media_type");
    reasons.add("payload_too_large");
    reasons.add("validation_failed");
  }
  if (endpoint.params !== null || endpoint.query !== null) reasons.add("validation_failed");
  // A resource or account the caller cannot see is indistinguishable from one that does not exist.
  if (endpoint.params !== null) reasons.add("not_found");
  if (auth.tenant === "account_context") {
    // A session without an `X-Kovo-Account` header, or a header naming another account than the
    // API key's, is malformed; an account the caller is not a member of is not found.
    reasons.add("malformed_request");
    reasons.add("not_found");
  }
  if (endpoint.paginated) reasons.add("invalid_cursor");
  if (endpoint.ifMatch) {
    reasons.add("precondition_required");
    reasons.add("precondition_failed");
  }
  if (endpoint.idempotency !== "none") {
    reasons.add("idempotency_conflict");
    reasons.add("idempotency_in_progress");
  }
  return REASON_CODES.filter((reason) => reasons.has(reason));
}

// Check at declaration time, before registry object spreads could hide duplicate operation IDs.
const managementPermissions = new Map<string, ManagementKeyPermission | undefined>();

function resolveManagementPermission(
  operationId: string,
  declared: ManagementKeyPermission | undefined,
): ManagementKeyPermission | undefined {
  const parsed = managementKeyPermissionSchema.safeParse(
    declared === undefined ? operationId : declared,
  );
  if (declared !== undefined && !parsed.success) {
    throw new RangeError(`unknown Management permission for ${operationId}`);
  }
  const permission = parsed.success ? parsed.data : undefined;
  if (
    managementPermissions.has(operationId) &&
    managementPermissions.get(operationId) !== permission
  ) {
    throw new RangeError(`conflicting Management permission for ${operationId}`);
  }
  managementPermissions.set(operationId, permission);
  return permission;
}

/**
 * Declares an endpoint: fills defaults, derives `humanOnly` and `csrf` from the descriptor and
 * merges the implied problem reasons with the endpoint-specific ones.
 */
export function defineEndpoint<
  const Method extends HttpMethod,
  const Path extends string,
  Params extends z.ZodType | null,
  Query extends z.ZodType | null,
  Body extends z.ZodType | null,
  const Responses extends ResponseMap,
>(
  init: EndpointInit<Method, Path, Params, Query, Body, Responses>,
): Endpoint<Method, Path, Params, Query, Body, Responses> {
  const managementPermission = resolveManagementPermission(
    init.operationId,
    init.authorization.managementPermission,
  );
  const actors = init.authorization.actors;
  const tenant = init.authorization.tenant;
  const authorization: EndpointAuthorization = {
    spec: init.authorization.spec,
    ...(managementPermission === undefined ? {} : { managementPermission }),
    actors,
    tenant,
    accountRoles: init.authorization.accountRoles ?? null,
    repoAuthority: init.authorization.repoAuthority ?? null,
    billingAuthority: init.authorization.billingAuthority ?? false,
    githubAccountAdmin: init.authorization.githubAccountAdmin ?? false,
    accountMember: init.authorization.accountMember ?? ACCOUNT_TENANTS.has(tenant),
    humanOnly: actors.length === 1 && actors[0] === "human_session",
    escalations: init.authorization.escalations ?? [],
  };
  const base = {
    operationId: init.operationId,
    area: init.area,
    method: init.method,
    path: init.path,
    summary: init.summary,
    source: init.source,
    params: init.params,
    query: init.query,
    body: init.body,
    responses: init.responses,
    authorization,
    idempotency: init.idempotency ?? "none",
    ifMatch: init.ifMatch ?? false,
    etag: init.etag ?? null,
    paginated: init.paginated ?? false,
    oneTimeFields: init.oneTimeFields ?? [],
    revealedOutputFields: init.revealedOutputFields ?? [],
    auditActions: init.auditActions ?? [],
    auditStorage: init.auditStorage ?? null,
    csrf: isMutation(init.method) && actors.includes("human_session"),
  };
  const reasons = new Set<ReasonCode>([...impliedProblems(base), ...(init.problems ?? [])]);
  return { ...base, problems: REASON_CODES.filter((reason) => reasons.has(reason)) };
}

// ---- Path templates ----

const PARAM = /\{([a-z][a-z0-9_]*)\}/g;

/** The `{name}` parameters of a path template, in order. */
export function pathParamNames(template: string): string[] {
  return [...template.matchAll(PARAM)].map((match) => match[1] ?? "");
}

/**
 * Fills a path template. Every parameter must be supplied and non-empty; values are
 * percent-encoded so an identifier can never add path segments. `.` and `..` survive
 * percent-encoding and URL resolution would remove them together with the segment before
 * (`/v1/repos/../pause` is `/v1/pause`), so they are refused too.
 */
export function buildPath(
  template: string,
  params: Readonly<Record<string, string | number>>,
): string {
  return template.replace(PARAM, (_match, name: string) => {
    const value = params[name];
    const text = value === undefined ? "" : String(value);
    if (text === "") {
      throw new RangeError(`missing path parameter ${name} for ${template}`);
    }
    if (text === "." || text === "..") {
      throw new RangeError(`path parameter ${name} for ${template} is a dot segment`);
    }
    return encodeURIComponent(text);
  });
}

/** The template in router syntax (`/v1/repos/:repo`), as Hono registers routes. */
export function toRouterPath(template: string): string {
  return template.replace(PARAM, (_match, name: string) => `:${name}`);
}
