import { z } from "zod";

import { packageNameSchema, packageVersionSchema } from "../npm.js";

// The upstream-failure log metadata a port error carries, on its own so the port errors
// (and the CLI bundle that loads them) need not load the whole log schema. ./log-metadata.js
// re-exports `upstreamFailureSchema`, `upstreamFailureMetadata` and `UpstreamFailureMetadata`
// under the same names and builds its log fields from the field schemas here.

export const upstreamService = z.enum([
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
export const statusClass = z.enum(["4xx", "5xx", "timeout", "network", "rate_limited"]);
/**
 * The port error class an upstream failure was translated from (the underlying exception
 * class). Only the fixed `PortError` subclass names of `@kovo/adapters`; never vendor text.
 * `packages/adapters/src/ports/error-class-vocabulary.test.ts` keeps this list complete.
 */
export const upstreamErrorClass = z.enum([
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
export const upstreamCode = z
  .string()
  .regex(/^(?:http_[1-5]\d\d|rate_budget_exhausted|secondary_limit_wait|request_pace)$/)
  .brand<"LogUpstreamCode">();
/** The HTTP status the upstream answered with; absent when nothing was sent or no status came. */
export const httpStatus = z.int().min(100).max(599);
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
      // The port error's own class, code and HTTP status. A KovoError carries the copy
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
