import { z } from "zod";
import {
  BILLING_EXCEPTION_REASONS,
  BILLING_EXCEPTION_SUBJECT_TYPES,
} from "../billing-exceptions.js";
import { REASON_CODES } from "../problem.js";
import { packageNameSchema, packageVersionSchema } from "../npm.js";
import { releaseIdSchema } from "../deployment.js";
import { planSchema } from "../enums/accounts.js";
import { MANAGED_PAYMENTS_GATE_REASONS, downgradeCauseSchema } from "../enums/billing.js";
import { verificationResultSchema } from "../enums/fixes.js";
import { approvedViaSchema } from "../enums/recipes.js";
import { activationPolicySchema } from "../enums/repos.js";
import { durationBucketSchema } from "../analytics.js";
import { SANDBOX_FAILURE_CODES } from "../enums/operations.js";
import { CUSTOMER_TOOL_REFUSALS } from "../install-binaries.js";
import { tierSchema } from "../tier.js";
import {
  coverageFailureCategorySchema,
  coverageFrameworkSchema,
  coverageFrameworksFieldSchema,
  coverageMajorSchema,
  coverageOrchestratorSchema,
  coveragePlaybookSchema,
  coverageTierSchema,
  workspaceMemberBucketSchema,
} from "../coverage-signature.js";
import { packageManagerSchema } from "../enums/recipes.js";
import { egressHostSchema, isPublicDnsName } from "../primitives.js";
import {
  BILLING_PROVIDER_CODES,
  EGRESS_AUTHORITY_OPERATIONS,
  EGRESS_NETWORK_CLASSES,
  EGRESS_TUNNEL_STAGES,
  BILLING_PROVIDER_OPERATIONS,
  BILLING_PROVIDER_PARAMS,
  LOG_DB_ROUND_TRIP_OUTCOMES,
  LOG_DB_ROUND_TRIP_PATHS,
  LOG_DB_STATEMENT_PHASES,
  LOG_FIX_ENQUEUE_OUTCOMES,
  LOG_FIX_PIPELINE_STAGES,
  LOG_DEPENDENCIES,
  LOG_DEPENDENCY_STATUSES,
  LOG_EVENT_CODES,
  LOG_FIELD_KEYS,
  LOG_ENUM_CODES,
  LOG_LISTING_FAILURES,
  LOG_VENDOR_EMITTERS,
  LOG_DELIVERY_AGE_BUCKETS,
  LOG_WALK_RESET_REASONS,
  LOG_SETTING_KEYS,
  LOG_FIX_ONLY_REASONS,
  LOG_INTEGRITY_SOURCES,
  LOG_LOCKFILE_REASONS,
  LOG_RUNTIME_REASONS,
  LOG_WORKSPACE_REASONS,
  LOG_CONTENT_PATH_CLASSES,
  LOG_CONTENT_TYPE_CLASSES,
  PROJECT_SCOPE_CAUSES,
  KMS_KEY_VERSION_STATES,
  PG_BACKEND_STATES,
  PG_WAIT_EVENT_TYPES,
  POOL_WAIT_SAMPLE_OUTCOMES,
  RUN_RECORD_KEY_VERSION_SKIP_REASONS,
  STRIPE_ERROR_NAME,
  STRIPE_ERROR_REASONS,
  STRIPE_ERROR_TYPES,
  STRIPE_PRICE_INTERVALS,
  STRIPE_PRICE_TAX_BEHAVIORS,
  STRIPE_PRICE_USAGE_TYPES,
  CHECKOUT_PROBE_OUTCOMES,
} from "./log-vocabulary.js";
import { MAINTENANCE_REASON_CODES } from "./maintenance-codes.js";
import { redactText, type TextRedactor } from "./patterns.js";

/** See [loggable metadata](../../../../GLOSSARY.md#loggable-metadata).
 * This is the sole jsonPayload key allowlist. */
export const LOGGABLE_METADATA_KEYS = [
  "event",
  "severity",
  "level",
  "time",
  "redacted_fields",
  ...LOG_FIELD_KEYS,
] as const;
export const FREE_TEXT_MARKER = "[redacted:free_text]";
const withheld = z.literal(FREE_TEXT_MARKER);
const step = z
  .string()
  .max(128)
  .regex(/^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)+$/)
  .brand<"LogStep">();
/** A registered DBOS step or workflow name such as `inventory.readTree`; never message text. */
export const logStepSchema = step;
// A unit-of-work transaction name (`TransactionOptions.name`), a code constant such as
// `billing.grace_due.read` or `retention.purgeAccount.decision_traces` (#5500): dotted segments
// that, unlike a durable step name, may use snake_case. Never message text or an input.
const operation = z
  .string()
  .max(128)
  .regex(/^[a-z][A-Za-z0-9_]*(\.[a-z][A-Za-z0-9_]*)+$/)
  .brand<"LogOperation">();
/** A unit-of-work operation name such as `billing.grace_due.read`; never message text. */
export const logOperationSchema = operation;
// The long-hold wait sample (#5500): its outcome, and the holding backend's state and wait event
// as Postgres reports them. A wait event is a server-defined identifier such as `transactionid`,
// `ClientRead` or `LockManager`: letters and digits only, so no credential-shaped value fits.
/** The `wait_sample` outcome of a long-hold line. */
export const logWaitSampleSchema = z.enum(POOL_WAIT_SAMPLE_OUTCOMES);
/** `pg_stat_activity.wait_event_type`. */
export const logWaitEventTypeSchema = z.enum(PG_WAIT_EVENT_TYPES);
/** `pg_stat_activity.state` as a log code. */
export const logBackendStateSchema = z.enum(PG_BACKEND_STATES);
const waitEvent = z
  .string()
  .max(48)
  .regex(/^[A-Za-z][A-Za-z0-9]*$/)
  .brand<"LogWaitEvent">();
/** `pg_stat_activity.wait_event`, a server-defined identifier; never message text. */
export const logWaitEventSchema = waitEvent;
// A Cloud Run revision name (`K_REVISION`, such as `kovo-api-00794-x7k`): the service name, a
// sequence number and a suffix Cloud Run generates. Lowercase letters, digits and hyphens only.
const revision = z
  .string()
  .max(63)
  .regex(/^[a-z][a-z0-9-]*$/)
  .brand<"LogRevision">();
/** The running Cloud Run revision (`K_REVISION`); never message text. */
export const logRevisionSchema = revision;
const upstreamService = z.enum([
  "github",
  "npm_registry",
  "gcs",
  "model_provider",
  "sandbox",
  "kms",
  "secrets",
  "osv",
  "kev",
  "workload_identity",
]);
const statusClass = z.enum(["4xx", "5xx", "timeout", "network", "rate_limited"]);
/** The egress gateway's validated public target host (D-461): DNS-name syntax only, never a
 * URL, path, IP literal or free text. */
const upstreamHost = egressHostSchema.refine(isPublicDnsName).brand<"LogUpstreamHost">();
const egressNetworkClass = z.enum(EGRESS_NETWORK_CLASSES);
const egressAuthorityOperation = z.enum(EGRESS_AUTHORITY_OPERATIONS);
const egressTunnelStage = z.enum(EGRESS_TUNNEL_STAGES);
/** The closed dependency a `dependency_failure` names (#5667, D-267). */
export const logDependencySchema = z.enum(LOG_DEPENDENCIES);
export type LogDependency = z.output<typeof logDependencySchema>;
/** How that dependency failed (#5667). */
export const logDependencyStatusSchema = z.enum(LOG_DEPENDENCY_STATUSES);
export type LogDependencyStatus = z.output<typeof logDependencyStatusSchema>;
/** What ended a redelivery tick's delivery-log listing (#5669). */
export const logListingFailureSchema = z.enum(LOG_LISTING_FAILURES);
export const logVendorEmitterSchema = z.enum(LOG_VENDOR_EMITTERS);
export type LogVendorEmitter = z.output<typeof logVendorEmitterSchema>;
export type LogListingFailure = z.output<typeof logListingFailureSchema>;
/** The oldest listed delivery's age on a redelivery tick (#5669). */
export const logDeliveryAgeBucketSchema = z.enum(LOG_DELIVERY_AGE_BUCKETS);
export type LogDeliveryAgeBucket = z.output<typeof logDeliveryAgeBucketSchema>;
/** Why a redelivery tick restarted its backward pass (#5669 N1). */
export const logWalkResetReasonSchema = z.enum(LOG_WALK_RESET_REASONS);
export type LogWalkResetReason = z.output<typeof logWalkResetReasonSchema>;
/** Why the run-records janitor kept a KMS key version, or `scheduled` (#7194). */
export const logKeyVersionSkipReasonSchema = z.enum(RUN_RECORD_KEY_VERSION_SKIP_REASONS);
export type LogKeyVersionSkipReason = z.output<typeof logKeyVersionSkipReasonSchema>;
/** A Cloud KMS key version state (#7194). */
export const logKeyVersionStateSchema = z.enum(KMS_KEY_VERSION_STATES);
export type LogKeyVersionState = z.output<typeof logKeyVersionStateSchema>;
/** The name (never the value) of the request parameter a billing provider refused (#5500). */
const billingParam = z.enum(BILLING_PROVIDER_PARAMS);
/** A Stripe refusal's type, reason, and its code or parameter name (#5514, D-267). */
const stripeErrorType = z.enum(STRIPE_ERROR_TYPES);
const stripeReason = z.enum(STRIPE_ERROR_REASONS);
const stripeErrorName = z.string().regex(STRIPE_ERROR_NAME).brand<"LogStripeErrorName">();
/**
 * The payment-method health check's Stripe object IDs (#5514): a price (`price_…`), a payment
 * method configuration (`pmc_…`), a billing meter (`mtr_…`) and a product (`prod_…`). Kovo's own
 * catalog and account configuration, never a customer's object.
 */
const stripeConfigObjectId = z
  .string()
  .regex(/^(?:price|pmc|mtr|prod)_[A-Za-z0-9_]{1,128}$/)
  .brand<"LogStripeConfigObjectId">();
/** The overage price check's terms (#5514): Stripe's own enum values, null when absent. */
const priceInterval = z.enum(STRIPE_PRICE_INTERVALS);
const priceUsageType = z.enum(STRIPE_PRICE_USAGE_TYPES);
const priceTaxBehavior = z.enum(STRIPE_PRICE_TAX_BEHAVIORS);
/** The live Checkout probe's outcome (#9122): a closed code the money-correct SLO counts. */
const checkoutProbeOutcome = z.enum(CHECKOUT_PROBE_OUTCOMES);
/**
 * A comma list of OVERAGE_PRICE_CHECKS names (`active,interval`), empty when none. A literal
 * pattern, so `scripts/ops/prod-logs` can evaluate it; overage-price-log.test.ts keeps it in step.
 */
const overagePriceChecks = z
  .string()
  .max(256)
  .regex(
    /^(?:(?:active|interval|usage_type|meter|unit_amount|currency|tax_behavior|product)(?:,(?:active|interval|usage_type|meter|unit_amount|currency|tax_behavior|product))*)?$/,
  )
  .brand<"LogOveragePriceChecks">();
/** A three-letter ISO currency code in Stripe's lowercase form (`usd`). */
const currencyCode = z
  .string()
  .regex(/^[a-z]{3}$/)
  .brand<"LogCurrencyCode">();
/** The core workspace reason behind a refused workspace graph (#2135). */
const workspaceReason = z.enum(LOG_WORKSPACE_REASONS);
/** Which project recipe discovery check refused (#8127). */
const scopeCause = z.enum(PROJECT_SCOPE_CAUSES);
const lockfileReason = z.enum(LOG_LOCKFILE_REASONS);
/** Which gate of the one runtime resolver refused a root (#8256), from a closed set. */
const runtimeReason = z.enum(LOG_RUNTIME_REASONS);
/** A rejected setting key from a closed set, never free text (#2135). */
const settingKey = z.enum(LOG_SETTING_KEYS);
/** Why CI-first admission refused a root or a fix (#8256 R2), from a closed set. */
const fixOnlyReason = z.enum(LOG_FIX_ONLY_REASONS);
/** Where an inventory's package integrity came from (#7338). */
const integritySource = z.enum(LOG_INTEGRITY_SOURCES);
/** Zod 4's issue codes: what kind of check an unhandled ZodError failed (#5514, D-267). */
export const ZOD_ISSUE_CODES = [
  "invalid_type",
  "too_big",
  "too_small",
  "invalid_format",
  "not_multiple_of",
  "unrecognized_keys",
  "invalid_union",
  "invalid_key",
  "invalid_element",
  "invalid_value",
  "custom",
] as const;
/** Comma-separated {@link ZOD_ISSUE_CODES}, one per logged issue. */
const zodIssueCodes = z
  .string()
  .max(128)
  .regex(new RegExp(`^(?:${ZOD_ISSUE_CODES.join("|")})(?:,(?:${ZOD_ISSUE_CODES.join("|")}))*$`))
  .brand<"LogZodIssueCodes">();
/**
 * Comma-separated paths of an unhandled ZodError's issues (`checkout_url`, `items.0.id`,
 * `envStubs.[key].value`): keys the refusing schema declares and array indexes; a key taken from
 * the data is `[key]` (apps/control-plane/src/logging/zod-paths.ts). Never values or messages.
 */
const zodIssuePaths = z
  .string()
  .max(128)
  .regex(/^[A-Za-z0-9_.[\]]*(?:,[A-Za-z0-9_.[\]]*)*$/)
  .brand<"LogZodIssuePaths">();
/**
 * The matched route template (`/v1/repos/:repo`) or `unmatched`. Its only producer is the API's
 * `routeTemplate(c.req.routePath)` (middleware/request-context.ts), never a request path. The shape
 * refuses what a concrete path would carry: literal segments are lowercase words or `v<n>`, so an
 * ID, a number or a mixed-case name in a segment is withheld.
 */
/**
 * The running release a process logs as `version` (`2026.09.28-1`, `r1-0123456789ab`, `dev`): the
 * deployment's {@link releaseIdSchema}, which `KOVO_VERSION` already passed at startup (#2290).
 * The free-text redaction still runs first, so a credential-shaped value is withheld.
 */
const releaseVersion = releaseIdSchema.brand<"LogReleaseVersion">();
const routeTemplate = z
  .string()
  .max(128)
  .regex(
    /^(?:unmatched|(?:\/(?:[a-z][a-z_-]{0,63}|v[0-9]{1,3}|:[A-Za-z_][A-Za-z0-9_]{0,63}|\*))+)$/,
  )
  .brand<"LogRouteTemplate">();
const valueType = z.enum([
  "undefined",
  "null",
  "string",
  "number",
  "boolean",
  "bigint",
  "symbol",
  "function",
  "object",
]);
/**
 * The port error class an upstream failure was translated from (D-267: the underlying exception
 * class). Only the fixed `PortError` subclass names of `@kovo/adapters`; never vendor text.
 * `packages/adapters/src/ports/error-class-vocabulary.test.ts` keeps this list complete.
 */
const upstreamErrorClass = z.enum([
  "RateLimitedError",
  "AmbiguousOutcomeError",
  "NotFoundError",
  "ConflictError",
  "PreconditionFailedError",
  "PermissionDeniedError",
  "AuthenticationError",
  "InvalidRequestError",
  "UnavailableError",
  "IntegrityError",
  "LimitExceededError",
  "BlockedDestinationError",
  "IsolationUnavailableError",
  "InstallationSuspendedError",
  "PaymentDeclinedError",
  "RecipientInactiveError",
  "NoCompliantProviderError",
  "UpstreamCircuitOpenError",
  "PackumentHeapRefusal",
  "PackumentParseLimit",
  "PackumentAdmissionRefusal",
]);
/**
 * The upstream failure's own code: an HTTP status code (`http_403`), or Kovo's GitHub pacing reason
 * when the request was never sent (`rate_budget_exhausted`, `secondary_limit_wait`, `request_pace`).
 */
const upstreamCode = z
  .string()
  .regex(/^(?:http_[1-5]\d\d|rate_budget_exhausted|secondary_limit_wait|request_pace)$/)
  .brand<"LogUpstreamCode">();
/** The HTTP status the upstream answered with; absent when nothing was sent or no status came. */
const httpStatus = z.int().min(100).max(599);
export const upstreamFailureSchema = z.object({
  upstream_service: upstreamService.optional(),
  status_class: statusClass.optional(),
  package_name: packageNameSchema.optional(),
  package_version: packageVersionSchema.optional(),
  upstream_error_class: upstreamErrorClass.optional(),
  upstream_code: upstreamCode.optional(),
  http_status: httpStatus.optional(),
});
export type UpstreamFailureMetadata = z.output<typeof upstreamFailureSchema>;

/** Only own scalar metadata is read. Never inspect a vendor cause, message or response body. */
export function upstreamFailureMetadata(error: unknown): UpstreamFailureMetadata {
  if (typeof error !== "object" || error === null) return {};
  try {
    const own = (key: string): unknown => Object.getOwnPropertyDescriptor(error, key)?.value;
    const services: Readonly<Record<string, z.output<typeof upstreamService>>> = {
      github_app: "github",
      github_user: "github",
      npm: "npm_registry",
      object_storage: "gcs",
      model: "model_provider",
      sandbox: "sandbox",
      kms: "kms",
      secrets: "secrets",
      osv: "osv",
      kev: "kev",
      workload_identity: "workload_identity",
    };
    const service = own("service");
    const kind = own("kind");
    const reason = own("reason");
    const code = own("code");
    const status =
      kind === "rate_limited"
        ? "rate_limited"
        : reason === "timeout" || code === "timeout"
          ? "timeout"
          : reason === "network" || code === "network"
            ? "network"
            : typeof code === "string" && /^http_4\d\d$/.test(code)
              ? "4xx"
              : typeof code === "string" && /^http_5\d\d$/.test(code)
                ? "5xx"
                : reason === "server_error" || reason === "overloaded"
                  ? "5xx"
                  : typeof kind === "string" &&
                      [
                        "authentication_failed",
                        "permission_denied",
                        "not_found",
                        "invalid_request",
                        "conflict",
                        "precondition_failed",
                        "installation_suspended",
                      ].includes(kind)
                    ? "4xx"
                    : undefined;
    const candidate = {
      upstream_service:
        own("upstream_service") ??
        (typeof service === "string" && Object.hasOwn(services, service)
          ? services[service]
          : undefined),
      status_class: own("status_class") ?? status,
      package_name: own("package_name"),
      package_version: own("package_version"),
      // D-267: the port error's own class, code and HTTP status. A KovoError carries the copy
      // taken from the port error it translated; its own `status` is Kovo's answer, never read.
      upstream_error_class:
        own("upstream_error_class") ?? (typeof kind === "string" ? own("name") : undefined),
      upstream_code: own("upstream_code") ?? code,
      http_status:
        own("http_status") ??
        (typeof code === "string" && /^http_[1-5]\d\d$/.test(code)
          ? Number(code.slice(5))
          : undefined),
    };
    return Object.fromEntries(
      (
        [
          "upstream_service",
          "status_class",
          "package_name",
          "package_version",
          "upstream_error_class",
          "upstream_code",
          "http_status",
        ] as const
      ).flatMap((key) => {
        const parsed = upstreamFailureSchema.shape[key].safeParse(candidate[key]);
        return parsed.success && parsed.data !== undefined ? [[key, parsed.data]] : [];
      }),
    );
  } catch {
    return {};
  }
}
const id = z.uuid().brand<"LogId">();
const hash = z
  .string()
  .regex(/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i)
  .brand<"LogHash">();
const codes = z.enum([
  ...LOG_ENUM_CODES,
  ...MAINTENANCE_REASON_CODES,
  ...REASON_CODES,
  ...BILLING_EXCEPTION_REASONS,
  ...BILLING_EXCEPTION_SUBJECT_TYPES,
  // Why the Managed Payments Checkout gate is closed (#5514 Phase 5).
  ...MANAGED_PAYMENTS_GATE_REASONS,
  // The sandbox service's fixed failure codes (`provider_<PortErrorKind>` of a failed create and
  // the rest), so a `sandbox_provider_fallback` line names its create failure instead of the
  // untrusted-error marker (S2, #5641, D-267).
  ...SANDBOX_FAILURE_CODES,
  // Why a repository-pinned customer tool was not fetched through the proxy (D-730).
  ...CUSTOMER_TOOL_REFUSALS,
  "published",
  "model_outcome_truncated_length",
  "model_outcome_truncated_body_cap",
  "unknown",
  "none",
  "unexpected",
  "unavailable",
  "invalid_request",
  "integrity",
  "ambiguous_outcome",
  "isolation_unavailable",
  "cancelled",
  "timeout",
  "failed",
  "succeeded",
  "success",
  "failure",
  "delivered",
  "timeout_or_failure",
  "api",
  "worker",
  "proxy",
  "egress-proxy",
  "worker-smoke",
  "prod",
  "test",
  "local",
  "kovo-control-plane",
  "kovo-web",
  "kovo-admin",
  "incident-bridge",
  "shadow",
  "pr_only",
  "autopilot",
  "P0",
  "P1",
  "P2",
  "Free",
  "Plus",
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "generation",
  "verification",
  "calibration",
  "patches",
  "better_auth",
  "SIGTERM",
  "SIGINT",
  "A",
  "B_install",
  "B_build",
  "B_tests",
  "npm",
  "pnpm",
  "yarn",
  "docker",
  "daytona",
  "restore-drill",
  "destroying",
  "starting",
  "running",
  "stopped",
  "pending",
  "completed",
  "destroyed",
  "expired",
  "untrusted_error",
  "non_error",
  "non_error_value",
  "vendor_console_text",
  // `readiness_check_failed` (apps/control-plane/src/api/health.ts, P0 Refs #626).
  "readiness_check_timeout",
  "readiness_check_not_ready",
  "readiness_check_unreachable",
  "dbos",
  "error",
  "warn",
  "info",
  "debug",
  "trace",
  "fatal",
  "permission_service_not_wired",
  "invalid_token",
  "flag_read_failed",
  "calibrated",
  "weak",
  "limited",
  "enabled",
  "disabled",
  "limit_changed",
  "outreach",
  "outreach_export_prerequisite_missing",
  "outreach_domain_invalid",
  "outreach_source_prerequisite_missing",
  "source_prerequisite_missing",
  "source_empty",
  "imported",
  "import",
  "suppression",
  "not_found",
  "permission_denied",
  "worker_system_database_unavailable",
  "inventory",
  // Workflow-failure fallback classes must survive logging as distinct finite codes.
  "recipes",
  "fixes",
  "billing",
  "installations",
  "advisory",
  "changelog_document_failed",
  "changelog_check_failed",
  "review_hints_failed",
  "review_hints_document_failed",
  "review_hints_document_unusable",
  "review_hints_rate_limited",
  "review_hints_ambiguous_outcome",
  "review_hints_not_found",
  "review_hints_conflict",
  "review_hints_precondition_failed",
  "review_hints_permission_denied",
  "review_hints_authentication_failed",
  "review_hints_invalid_request",
  "review_hints_unavailable",
  "review_hints_integrity",
  "review_hints_limit_exceeded",
  "review_hints_blocked_destination",
  "review_hints_isolation_unavailable",
  "review_hints_installation_suspended",
  "review_hints_payment_declined",
  "review_hints_recipient_inactive",
  "review_hints_no_compliant_provider",
  "lookup_unavailable",
  "identity_unavailable",
  // A billing provider refusal's operation and code (#5500, D-267).
  ...BILLING_PROVIDER_OPERATIONS,
  ...BILLING_PROVIDER_CODES,
]);
/** The closed code vocabulary a `reason_code` or other generic code field may carry. */
export const logReasonCodeSchema = codes;
export const logErrorClassSchema = z.enum([
  "database_connection",
  "database_capacity",
  "database_shutdown",
  "database_query_canceled",
  "database_permission",
  "database_conflict",
  "database_lock",
  "database_constraint",
  "database_other",
  "PoolAcquireTimeoutError",
  "PoolerWaitTimeoutError",
  "PoolDrainingError",
  "validation",
  "unexpected",
  "Error",
  "TypeError",
  "RangeError",
  "SyntaxError",
  "ReferenceError",
  "URIError",
  "EvalError",
  "AggregateError",
  "KovoError",
  "PortError",
  "ConfigError",
  "ZodError",
  "DatabaseError",
  "DrizzleQueryError",
  // @kovo/db's value-free database error (its `kind`, such as `query_canceled`, is the line's
  // `reason_code` or `error_kind`); it logged as a bare `Error` before #8710.
  "KovoDatabaseError",
  "NotFoundError",
  "UnavailableError",
  "InvalidRequestError",
  "IntegrityError",
  "AmbiguousOutcomeError",
  "IsolationUnavailableError",
  "PreconditionFailedError",
  "DependencyVerdictFailure",
  // A broken read-path invariant (D-686 pick 7, #7972; apps/control-plane/src/ports/read-path.ts).
  "ReadInvariantError",
  // A write handler's or the route helper's broken invariant, and a refused route registration
  // (#7972 follow-up; apps/control-plane/src/ports/read-path.ts).
  "RouteInvariantError",
  "RouteWiringError",
  // A bounded call of the D-561 e pre-launch DBOS reset outran its timeout (#7003).
  "DbosPrelaunchResetTimeoutError",
  "NonError",
]);
const errorClass = logErrorClassSchema;
/** The longest `error_message` (error-detail.ts) and each message within `cause_messages`. */
export const ERROR_MESSAGE_MAX_LENGTH = 128;
export const CAUSE_MESSAGE_MAX_LENGTH = 60;
/**
 * One token of a redacted message (D-423): a word or identifier with surrounding punctuation, or the
 * `[v]` marker. The character set refuses what a value would need: no `/`, `@`, `=`, `%`, `$`, `\`,
 * `#`, `&`, `+`, `*`, `|` and no square bracket but the marker's (parentheses, angle brackets, braces
 * and quotes are punctuation around words), so no URL, path, email or query fits.
 */
const MESSAGE_TOKEN = String.raw`(?:[A-Za-z0-9_.:,;'"()<>{}!?-]|\[v\])+`;
const MESSAGE = `${MESSAGE_TOKEN}(?: ${MESSAGE_TOKEN})*`;
/**
 * An error's message after `redactErrorMessage` (error-detail.ts): its shape, with every token that
 * could carry a value replaced by `[v]`. Never the raw message.
 */
export const errorMessageSchema = z
  .string()
  .max(ERROR_MESSAGE_MAX_LENGTH)
  .regex(new RegExp(`^${MESSAGE}$`))
  .brand<"LogErrorMessage">();
/** Up to three redacted cause messages, ` | `-separated, in chain order (`-` for none). */
export const causeMessagesSchema = z
  .string()
  .max(3 * CAUSE_MESSAGE_MAX_LENGTH + 6)
  .regex(new RegExp(`^${MESSAGE}(?: \\| ${MESSAGE}){0,2}$`))
  .brand<"LogCauseMessages">();
const ERROR_CLASS = `(?:${logErrorClassSchema.options.join("|")})`;
/** Up to three causes' {@link logErrorClassSchema} classes, comma-separated, in chain order. */
export const causeClassesSchema = z
  .string()
  .max(128)
  .regex(new RegExp(`^${ERROR_CLASS}(?:,${ERROR_CLASS}){0,2}$`))
  .brand<"LogCauseClasses">();
/** The HTTP method of the request a line is about. */
const httpMethod = z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
/**
 * The API endpoint's `operationId` (`listMembers`). Its only producer is the endpoint registration
 * (api/routes/register.ts), never request input; the shape refuses anything but an identifier.
 */
const operationId = z
  .string()
  .regex(/^[a-z][A-Za-z0-9]{0,63}$/)
  .brand<"LogOperationId">();
const scalar = z.union([z.number().finite(), z.boolean(), z.null()]);
const safeString = z.union([codes, id, hash, withheld]);
const genericValue = z.union([scalar, safeString]);
const numberKeys = new Set([
  "support_closed",
  "support_duplicates",
  "support_gone",
  "support_inbound_last_hour",
  "support_ingested",
  "support_pruned",
  "support_replies",
  "support_republished",
  "support_resynced",
  "support_shredded",
  "support_stored_bytes_last_day",
  "support_threaded",
  "requested_bytes",
  "budget_capacity_bytes",
  "budget_in_use_bytes",
  "queue_depth",
  "status",
  "status_code",
  "issueNumber",
  "rotated",
  "scheduled",
  "oldestUnexpiredObjectAgeSeconds",
  "oldestEnabledKeyVersionAgeSeconds",
  "objectsPastBound",
  "versionsPastBound",
  "objectStatusFailures",
  "unknownVersionBindings",
  "listingPages",
  "cleanupBacklog",
  "repo_count",
  "checked",
  "deliveries_listed",
  "deliveries_unreadable",
  "unreadable_id",
  "unreadable_guid",
  "unreadable_time",
  "unreadable_redelivery",
  "unreadable_shape",
  "listing_stopped_unreadable",
  "head_gap",
  "walk_reset",
  "oldest_age_hours",
  "pass_failed",
  "cursor_failures",
  "deliveries_unacknowledged",
  "redelivered",
  "redelivery_failed",
  "redelivery_backoff",
  "redelivery_exhausted",
  "redelivery_stuck",
  "redelivery_capped",
  "listing_truncated",
  "redelivery_outage_skip",
  "futureDated",
  "oldestSnapshotAgeSeconds",
  "unparseablePrefixed",
  "attempt",
  "attempts",
  "bytes",
  "costMicroUsd",
  "count",
  "deferrals",
  "deleted",
  "dependencies",
  "dependenciesMissing",
  "devDependencies",
  "devDependenciesMissing",
  "durationMs",
  "elapsedMs",
  "waitMs",
  "outputTokenCount",
  "outputTokenLimitCount",
  "deadlineMs",
  "failures",
  "p50Ms",
  "p95Ms",
  "maxMs",
  "emails",
  "epoch",
  "exit",
  "exitCode",
  "failed",
  "hidden",
  "inUse",
  "jobs",
  "liveWork",
  "missing",
  "oldestAgeSeconds",
  "overdue",
  "port",
  "redactions",
  "repoCount",
  "stopped",
  "unknown",
  "violations",
  "waiting",
  "clients",
  "deliveries",
  "events",
  "modules",
  "samples",
  "versions",
  "github_installation_id",
  "pull_number",
  "enqueued",
  "changes",
  "blocked",
  "warned",
  "reset_at_ms",
  "wait_ms",
  "pending_ms",
  "hold_ms",
  "timeout_ms",
  "pool_total",
  "pool_idle",
  "pool_waiting",
  "pooler_wait_ms",
  // The `db_round_trip` probe's fastest and slowest `select 1` round trip (#8283).
  "round_trip_ms",
  "round_trip_max_ms",
  // A long hold's time with a statement outstanding (#8112 round 4); `statement_count` is its count.
  "query_ms",
  // The longest gap between a long hold's statements, idle in transaction (D-712).
  "idle_max_ms",
  // A long hold's slowest statement, its 0-based position, the time to its first backend message,
  // and the gaps from acquire to the first statement, from the statement before COMMIT to COMMIT
  // and from the last statement to release (#8283).
  "slowest_statement_ms",
  "slowest_statement_index",
  "slowest_statement_first_response_ms",
  "acquire_to_first_ms",
  "last_to_commit_ms",
  "last_to_release_ms",
  "loop_stall_max_ms",
  "stall_ms",
  "stalls_suppressed",
  // The event-loop stall attribution and the capture deadline it is checked against (#7274).
  "stall_inflight",
  // The CPU and garbage-collection milliseconds inside the stall (#7578): CPU far below
  // `stall_ms` means the process was not running, not that JavaScript blocked the loop.
  "stall_cpu_ms",
  "stall_gc_ms",
  "deadline_ms",
  "deadlines_suppressed",
  "zod_issue_count",
  "authority_ms",
  "cause_count",
  // An inventory publication phase's statements, slowest statement and counts (#7578).
  "statement_count",
  "max_statement_ms",
  "package_count",
  "root_count",
  "refusal_count",
  "project_count",
  "row_count",
  // A bundled copy's byte comparison with its registry artifact (#8951): file counts only.
  "file_count",
  "differing_count",
  "extra_count",
  // The OSV export ingest's per-window write mix (`osv_export_ingest_chunks`, #7580): counts and
  // serialized sizes in bytes only.
  "replaced",
  "unchanged",
  "malicious",
  "upserted",
  "range_rows",
  "holds_sent",
  "holds_created",
  "reclassify_starts",
  "record_max_bytes",
  "chunk_max_bytes",
]);
const idKeys = new Set([
  "job_id",
  "accountId",
  "account_id",
  "analyticsOutboxId",
  "outboxRowId",
  "cycle_id",
  "deliveryId",
  "emailId",
  "excerptId",
  "fixId",
  "generationId",
  "grantId",
  "installationId",
  "jobId",
  "project_id",
  "recipeVersionId",
  "repoId",
  "repo_id",
  "row_id",
  "reservationId",
  "sandboxId",
  "subject_id",
  "userId",
  "released_user_id",
  "requestId",
  "request_id",
]);
const hashKeys = new Set([
  "operation_hash",
  "db_object_hash",
  "shapeSha256",
  "workflow_hash",
  "trace_id",
  "incident_hash",
  "policy_hash",
  // A Git commit SHA: loggable metadata (GLOSSARY), never content.
  "head_sha",
  // sha256 hex of a dependency alert's account, repository, pull and head IDs (#3703).
  "alert_id",
  // sha256 of a billing provider code or parameter name outside the closed lists (#5500).
  "code_hash",
  "param_hash",
]);
const analyticsFields: ReadonlyMap<string, z.ZodType> = new Map<string, z.ZodType>([
  ["value_type", valueType],
  ["emitter", logVendorEmitterSchema],
  ["step", step],
  // The registered workflow and step holding a pooled connection (#4930); names only.
  ["holder_workflow", step],
  ["holder_step", step],
  // The registered workflow a duration summary aggregates (D-731, #8373); names only.
  ["workflow_name", step],
  // DBOS's numeric error code (`dbosErrorCode`, e.g. 26 UnexpectedStep) of a DBOS failure (#8733);
  // a closed number, never the error's message.
  ["dbos_error_code", z.int().min(1).max(99)],
  // The unit-of-work operation (`TransactionOptions.name`) holding it (#5542), or the fixed
  // acquire-path fallback (POOL_HOLDER_FALLBACK_OPERATIONS, #5500); names only.
  ["holder_operation", operation],
  // The unit-of-work operation of a caller that queued for a connection (#8112 round 4), or the
  // same fixed fallback; names only.
  ["waiter_operation", operation],
  // The long-hold wait sample (#5500): fixed Postgres vocabulary, and the blocking backend's
  // unit-of-work operation or the fixed fallback (POOL_BLOCKER_EXTERNAL_OPERATION); names only.
  ["wait_sample", logWaitSampleSchema],
  ["backend_state", logBackendStateSchema],
  ["wait_event_type", logWaitEventTypeSchema],
  ["wait_event", waitEvent],
  ["lock_blocked", z.boolean()],
  ["blocker_operation", operation],
  // What an event-loop stall is attributed to (#7274): a synchronous phase or unit-of-work
  // operation name, or a fixed `loop.*` fallback (LOOP_STALL_FALLBACK_OPERATIONS); names only.
  ["stall_operation", operation],
  // The `db_round_trip` probe (#8283): the connection path it timed, how it ended, and the Cloud
  // Run revision (`K_REVISION`) that ran it, so a slow pooler is told per revision.
  ["db_path", z.enum(LOG_DB_ROUND_TRIP_PATHS)],
  ["round_trip_outcome", z.enum(LOG_DB_ROUND_TRIP_OUTCOMES)],
  // A long hold's slowest statement's protocol phase (#8283): a closed code, never statement text.
  ["slowest_statement_phase", z.enum(LOG_DB_STATEMENT_PHASES)],
  // The `fix_pipeline_stage` line (#8256): the advisory-to-fix stage and the enqueue's decision.
  ["fix_stage", z.enum(LOG_FIX_PIPELINE_STAGES)],
  ["enqueue_outcome", z.enum(LOG_FIX_ENQUEUE_OUTCOMES)],
  ["revision", revision],
  // The egress gateway's `egress_tunnel` line (D-461).
  ["upstream_host", upstreamHost],
  ["network_class", egressNetworkClass],
  ["authority_operation", egressAuthorityOperation],
  ["egress_stage", egressTunnelStage],
  ["upstream_service", upstreamService],
  ["status_class", statusClass],
  ["dependency", logDependencySchema],
  ["dependency_status", logDependencyStatusSchema],
  ["listing_failure", logListingFailureSchema],
  ["oldest_age_bucket", logDeliveryAgeBucketSchema],
  ["walk_reset_reason", logWalkResetReasonSchema],
  // The run-records janitor's per-version line (#7194): the version number (the trailing part of
  // the version name only), its age in whole seconds, its state and why it was kept.
  ["key_version", z.int().min(1).max(1_000_000_000_000)],
  ["age_s", z.int().nonnegative().max(1_000_000_000_000)],
  // The incident bridge's resolve audit (#9416): the resolution reason, the incident-duty
  // identity that resolved it and the issue its acknowledgement named. Closed values only.
  [
    "resolution_reason",
    z.enum([
      "source_condition_cleared",
      "mitigation_verified",
      "paging_suppressed_root_cause_open",
    ]),
  ],
  ["resolve_actor", z.enum(["kovo-devbox-ops"])],
  ["acked_issue", z.int().min(1).max(9_999_999)],
  ["key_version_state", logKeyVersionStateSchema],
  ["skip_reason", logKeyVersionSkipReasonSchema],
  ["past_bound", z.boolean()],
  ["window_reached", z.boolean()],
  ["upstream_error_class", upstreamErrorClass],
  ["upstream_code", upstreamCode],
  ["http_status", httpStatus],
  ["package_name", packageNameSchema],
  ["migration_id", z.int().nonnegative().nullable()],
  [
    "stage",
    z.enum([
      "configuration",
      "arguments",
      "target",
      "drizzle",
      "authorizers",
      "dbos",
      "operators",
      "restore",
      "job",
    ]),
  ],
  ["plan", planSchema],
  ["tier", tierSchema],
  // The `coverage_signature` line (#8256 V3, contracts coverage-signature.ts): each field's own
  // closed schema; framework names only from the allowlist, versions exact.
  ["package_manager", packageManagerSchema],
  ["pm_version", packageVersionSchema.nullable()],
  ["pm_major", coverageMajorSchema.nullable()],
  ["node_major", coverageMajorSchema.nullable()],
  ["frameworks", coverageFrameworksFieldSchema],
  ["framework", z.union([coverageFrameworkSchema, z.literal("none")])],
  ["framework_major", coverageMajorSchema.nullable()],
  ["frameworks_other", z.int().min(0).max(1000)],
  ["workspace_members", workspaceMemberBucketSchema],
  ["orchestrator", coverageOrchestratorSchema],
  ["ci_present", z.boolean()],
  ["highest_tier", coverageTierSchema],
  ["failing_tier", coverageTierSchema],
  ["failure_category", coverageFailureCategorySchema],
  ["playbook", coveragePlaybookSchema],
  ["duration_bucket", durationBucketSchema],
  ["latency_bucket", z.enum(["lt_1s", "1s_5s", "5s_30s", "gte_30s"])],
  ["upstream_host_class", z.enum(["npm_registry", "github_release_asset", "none"])],
  ["param", billingParam],
  ["stripe_error_type", stripeErrorType],
  ["stripe_error_code", stripeErrorName],
  ["stripe_error_param", stripeErrorName],
  ["stripe_reason", stripeReason],
  ["stripe_price_id", stripeConfigObjectId],
  ["stripe_configuration_id", stripeConfigObjectId],
  ["currency", currencyCode],
  // The overage price check's `overage_price_checked` line (#5514): Kovo's own catalog IDs and
  // the price's terms, plus which checks passed and failed.
  ["stripe_meter_id", stripeConfigObjectId.nullable()],
  ["stripe_product_id", stripeConfigObjectId],
  ["price_active", z.boolean()],
  ["price_interval", priceInterval.nullable()],
  ["price_usage_type", priceUsageType.nullable()],
  ["tax_behavior", priceTaxBehavior.nullable()],
  ["unit_amount", z.int().nonnegative().max(1_000_000_000).nullable()],
  ["checks_passed", overagePriceChecks],
  ["checks_failed", overagePriceChecks],
  // The live Checkout probe's `checkout_probe_checked` line (#9122): its outcome in a field of its
  // own that holds only CHECKOUT_PROBE_OUTCOMES, so the money-correct SLO counts failed probes by
  // codes no other emitter shares, and any other value is withheld, never read as a pass.
  ["probe_outcome", checkoutProbeOutcome],
  ["workspace_reason", workspaceReason],
  // A GitHub content read inventory found missing (#8491): fixed classes, never a path or header.
  ["content_type_class", z.enum(LOG_CONTENT_TYPE_CLASSES)],
  ["path_class", z.enum(LOG_CONTENT_PATH_CLASSES)],
  ["scope_cause", scopeCause],
  ["lockfile_reason", lockfileReason],
  ["runtime_reason", runtimeReason],
  ["integrity_source", integritySource],
  ["setting_key", settingKey],
  ["fix_only_reason", fixOnlyReason],
  ["route", routeTemplate],
  ["zod_issue_paths", zodIssuePaths],
  ["zod_issue_codes", zodIssueCodes],
  // D-423: what failed, where and why, as metadata (error-detail.ts).
  ["method", z.union([httpMethod, codes])],
  ["operation_id", operationId],
  ["error_message", errorMessageSchema],
  ["cause_classes", causeClassesSchema],
  ["cause_messages", causeMessagesSchema],
  ["repo_count", z.int().nonnegative().max(100_000)],
  // The dependency gate's outcome events (#4657): the start's trigger and the counted outcome
  // (the `kovo.dependency_gate.evaluations` metric's `gate_outcome` codes).
  [
    "gate_trigger",
    z.enum([
      "pull_request",
      "hold_changed",
      "wait_ended",
      "override_accepted",
      "default_branch_push",
    ]),
  ],
  [
    "gate_outcome",
    z.enum([
      "evaluated",
      "no_dependency_changes",
      "lockfile_missing",
      "lockfile_unsupported",
      "unreadable",
      "too_many_changes",
      "could_not_evaluate",
      "repo_unavailable",
      "pull_request_moved",
      "could_not_record",
      "could_not_reevaluate_hold",
      "unsupported_dependency_layout",
      "unsupported_dependency_file",
      "evaluation_pending",
      "earlier_check_kept",
      "rate_deferred_until_reset",
    ]),
  ],
  ["$process_person_profile", z.boolean()],
  [
    "outcome",
    z.union([
      codes,
      downgradeCauseSchema,
      verificationResultSchema,
      approvedViaSchema,
      activationPolicySchema,
      z.enum(["created_account", "joined_account", "installed", "approval_requested"]),
      // The live Checkout probe's outcome, a closed code; the same line also carries it as
      // `probe_outcome`, the field the money-correct SLO counts (#9122).
      checkoutProbeOutcome,
    ]),
  ],
]);

/** A closed schema even for JavaScript callers; no record<string, string> escape hatch. */
export const LOG_FIELD_SCHEMAS = Object.fromEntries(
  LOG_FIELD_KEYS.map((key) => [
    key,
    z
      .union([
        analyticsFields.get(key) ??
          (key === "error_class"
            ? errorClass
            : numberKeys.has(key)
              ? scalar
              : idKeys.has(key)
                ? id.nullable()
                : hashKeys.has(key)
                  ? hash
                  : key === "package"
                    ? packageNameSchema
                    : key === "package_version"
                      ? packageVersionSchema
                      : key === "version"
                        ? // A secret's version number stays a scalar; a release ID is now kept.
                          z.union([genericValue, releaseVersion])
                        : genericValue),
        withheld,
      ])
      .optional(),
  ]),
);
// Every string admitted by the public type is a finite enum or an already validated brand.
export type LogPrimitive =
  | number
  | boolean
  | null
  | undefined
  | z.output<typeof safeString>
  | z.output<typeof packageNameSchema>
  | z.output<typeof packageVersionSchema>
  | z.output<typeof releaseVersion>
  | z.output<typeof step>
  | z.output<typeof operation>
  | z.output<typeof logWaitSampleSchema>
  | z.output<typeof logWaitEventTypeSchema>
  | z.output<typeof logBackendStateSchema>
  | z.output<typeof waitEvent>
  | z.output<typeof upstreamService>
  | z.output<typeof statusClass>
  | z.output<typeof upstreamHost>
  | z.output<typeof egressNetworkClass>
  | z.output<typeof egressAuthorityOperation>
  | z.output<typeof egressTunnelStage>
  | (typeof LOG_FIX_PIPELINE_STAGES)[number]
  | (typeof LOG_FIX_ENQUEUE_OUTCOMES)[number]
  | LogDependency
  | LogDependencyStatus
  | LogListingFailure
  | LogDeliveryAgeBucket
  | LogWalkResetReason
  | LogKeyVersionSkipReason
  | LogKeyVersionState
  | z.output<typeof upstreamErrorClass>
  | z.output<typeof upstreamCode>
  | z.output<typeof billingParam>
  | z.output<typeof stripeErrorType>
  | z.output<typeof stripeErrorName>
  | z.output<typeof stripeReason>
  | z.output<typeof stripeConfigObjectId>
  | z.output<typeof priceInterval>
  | z.output<typeof priceUsageType>
  | z.output<typeof priceTaxBehavior>
  | z.output<typeof overagePriceChecks>
  | z.output<typeof currencyCode>
  | z.output<typeof workspaceReason>
  | z.output<typeof lockfileReason>
  | z.output<typeof integritySource>
  | z.output<typeof settingKey>
  | z.output<typeof fixOnlyReason>
  | z.output<typeof routeTemplate>
  | z.output<typeof zodIssuePaths>
  | z.output<typeof zodIssueCodes>
  | z.output<typeof httpMethod>
  | z.output<typeof operationId>
  | z.output<typeof errorMessageSchema>
  | z.output<typeof causeClassesSchema>
  | z.output<typeof causeMessagesSchema>
  | z.output<typeof valueType>
  | LogVendorEmitter
  | z.output<typeof errorClass>
  | z.output<(typeof COVERAGE_SIGNATURE_VALUE_SCHEMAS)[number]>;
export type LogFields = Partial<Readonly<Record<(typeof LOG_FIELD_KEYS)[number], LogPrimitive>>>;
export const logMetadataSchema = z.strictObject(LOG_FIELD_SCHEMAS);
export const logEventCodeSchema = z.enum(LOG_EVENT_CODES);
export type LogEventCode = z.output<typeof logEventCodeSchema>;
export const logEventSchema = z.strictObject({
  ...LOG_FIELD_SCHEMAS,
  event: z.union([logEventCodeSchema, withheld]),
  severity: z.enum(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
  level: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]),
  time: z.iso.datetime(),
  redacted_fields: z.int().nonnegative(),
});

/** The `coverage_signature` value schemas (#8256 V3): closed enums and the allowlisted list. */
const COVERAGE_SIGNATURE_VALUE_SCHEMAS = [
  packageManagerSchema,
  coverageFrameworkSchema,
  coverageFrameworksFieldSchema,
  workspaceMemberBucketSchema,
  coverageOrchestratorSchema,
  coverageTierSchema,
  coverageFailureCategorySchema,
  coveragePlaybookSchema,
  z.literal("none"),
] as const;
const primitiveSchema = z.union([
  valueType,
  step,
  operation,
  logWaitSampleSchema,
  logWaitEventTypeSchema,
  logBackendStateSchema,
  waitEvent,
  upstreamService,
  statusClass,
  upstreamHost,
  egressNetworkClass,
  egressAuthorityOperation,
  egressTunnelStage,
  logDependencySchema,
  logDependencyStatusSchema,
  logListingFailureSchema,
  logDeliveryAgeBucketSchema,
  logWalkResetReasonSchema,
  logKeyVersionSkipReasonSchema,
  logKeyVersionStateSchema,
  billingParam,
  stripeErrorType,
  stripeErrorName,
  stripeReason,
  stripeConfigObjectId,
  priceInterval,
  priceUsageType,
  priceTaxBehavior,
  overagePriceChecks,
  currencyCode,
  workspaceReason,
  lockfileReason,
  integritySource,
  settingKey,
  fixOnlyReason,
  routeTemplate,
  zodIssuePaths,
  zodIssueCodes,
  httpMethod,
  operationId,
  errorMessageSchema,
  causeClassesSchema,
  causeMessagesSchema,
  scalar,
  safeString,
  packageNameSchema,
  packageVersionSchema,
  releaseVersion,
  errorClass,
  ...COVERAGE_SIGNATURE_VALUE_SCHEMAS,
]);
const schemas: ReadonlyMap<string, z.ZodType> = new Map(Object.entries(LOG_FIELD_SCHEMAS));

/** Project untyped SDK/IPC input without executing getters or echoing unknown keys. */
export function projectLogFields(
  input: unknown,
  extra: readonly TextRedactor[] = [],
): { fields: LogFields; redacted: number } {
  const fields: Record<string, LogPrimitive> = {};
  let redacted = 0;
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input))
      return { fields: {}, redacted: 1 };
    const prototype: unknown = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return { fields: {}, redacted: 1 };
    let count = 0;
    for (const key in input) {
      if (!Object.hasOwn(input, key)) continue;
      if (++count > 128) {
        redacted++;
        break;
      }
      const schema = schemas.get(key);
      if (schema === undefined) {
        redacted++;
        continue;
      }
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      let value: unknown =
        descriptor !== undefined && "value" in descriptor ? descriptor.value : FREE_TEXT_MARKER;
      if (typeof value === "string" && redactText(value, extra) !== value) value = FREE_TEXT_MARKER;
      if (numberKeys.has(key) && typeof value === "string" && /^\d{1,15}$/.test(value))
        value = Number(value);
      if (value === undefined) continue;
      const parsed = schema.safeParse(typeof value === "bigint" ? Number(value) : value);
      if (!parsed.success || value === FREE_TEXT_MARKER) redacted++;
      fields[key] = parsed.success ? primitiveSchema.parse(parsed.data) : FREE_TEXT_MARKER;
    }
  } catch {
    return { fields: {}, redacted: 1 };
  }
  return { fields, redacted };
}

/** Explicit validation for historical scalar metadata; logger methods themselves stay typed. */
export function logFields(input: unknown): LogFields {
  const projected = projectLogFields(input);
  return projected.redacted > 0
    ? { ...projected.fields, redactions: projected.redacted }
    : projected.fields;
}

/** Error identity and closed metadata only. Neither own nor vendor messages/stacks are read. */
export function logErrorIdentity(error: unknown): LogFields {
  const nonError = (): LogFields =>
    logFields({
      error_class: "NonError",
      reason_code: "non_error_value",
      value_type: error === null ? "null" : typeof error,
    });
  try {
    if (!(error instanceof Error)) return nonError();
    const parsedClass = errorClass.safeParse(error.name);
    const reason =
      Object.getOwnPropertyDescriptor(error, "reason")?.value ??
      Object.getOwnPropertyDescriptor(error, "kind")?.value;
    const parsedReason = codes.safeParse(reason);
    const parsedStep = step.safeParse(Object.getOwnPropertyDescriptor(error, "stepName")?.value);
    // A pool acquire timeout's lane and configured timeout (#4930); closed values only.
    const parsedLane = codes.safeParse(Object.getOwnPropertyDescriptor(error, "lane")?.value);
    const timeoutMs: unknown = Object.getOwnPropertyDescriptor(error, "timeoutMs")?.value;
    return {
      ...(parsedLane.success ? { lane: parsedLane.data } : {}),
      ...(typeof timeoutMs === "number" && Number.isInteger(timeoutMs) && timeoutMs > 0
        ? { timeout_ms: timeoutMs }
        : {}),
      ...(parsedStep.success ? { step: parsedStep.data } : {}),
      ...upstreamFailureMetadata(error),
      error_class: parsedClass.success ? parsedClass.data : "Error",
      reason_code: parsedReason.success ? parsedReason.data : "untrusted_error",
    };
  } catch {
    return nonError();
  }
}
