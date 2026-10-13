import { z } from "zod";
import { whenValid } from "./primitives.js";
import { jobIdSchema } from "./ids.js";
import { failureExcerptRunKindSchema } from "./failure-excerpt.js";
import { stepNameSchema } from "./step-result.js";

// Sidecar metadata, never embedded in legacy strict StepResult/calibration records.
// Identifiers only: no messages, command output, URLs, paths or environment values.
export const diagnosticPackageSchema = z
  .string()
  .max(214)
  .regex(/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/);
export const diagnosticEnvNameSchema = z
  .string()
  .max(128)
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
export const diagnosticHostnameSchema = z
  .string()
  .max(253)
  .regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/);

export const stepDiagnosticFailureSchema = z
  .strictObject({
    category: z.enum([
      "native_binary_missing",
      "missing_env_var",
      "interactive_prompt",
      "network_egress_blocked",
      "registry_artifact_rejected",
      "out_of_memory",
      "timeout",
      "killed",
      "command_not_found",
      "unclassified",
    ]),
    package: diagnosticPackageSchema.exactOptional(),
    env_var_names: z.array(diagnosticEnvNameSchema).min(1).max(20).exactOptional(),
    hostnames: z.array(diagnosticHostnameSchema).min(1).max(20).exactOptional(),
  })
  .superRefine((value, ctx) => {
    for (const [field, category] of [
      ["package", "native_binary_missing"],
      ["env_var_names", "missing_env_var"],
      ["hostnames", "network_egress_blocked"],
    ] as const) {
      if (value[field] !== undefined && value.category !== category)
        ctx.addIssue({
          code: "custom",
          path: [field],
          message: "identifier does not belong to this category",
        });
    }
  }, whenValid);

export const installIssueSchema = z.strictObject({
  package: diagnosticPackageSchema,
  version: z
    .string()
    .max(100)
    .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/)
    .exactOptional(),
  kind: z.enum(["optional_dependency_failed", "required_dependency_failed", "lifecycle_failed"]),
  fetch_error: z
    .enum([
      "ERR_PNPM_FETCH_400",
      "ERR_PNPM_FETCH_401",
      "ERR_PNPM_FETCH_403",
      "ERR_PNPM_FETCH_404",
      "ERR_PNPM_FETCH_429",
      "ERR_PNPM_FETCH_500",
      "ERR_PNPM_FETCH_502",
      "ERR_PNPM_FETCH_503",
      "ERR_PNPM_FETCH_504",
      "ERR_PNPM_TARBALL_INTEGRITY",
      "EINTEGRITY",
      "ECONNRESET",
      "ECONNREFUSED",
      "ETIMEDOUT",
      "ENOTFOUND",
      "EAI_AGAIN",
      "E401",
      "E403",
      "E404",
      "E429",
      "E500",
      "E502",
      "E503",
      "E504",
    ])
    .exactOptional(),
  proxy_status: z.int().min(100).max(599).nullable().exactOptional(),
  proxy_size_bytes: z.int().min(0).max(Number.MAX_SAFE_INTEGER).nullable().exactOptional(),
  proxy_reason: z
    .enum([
      "response_too_large",
      "artifact_too_large",
      "upstream_error",
      "upstream_unavailable",
      "integrity_mismatch",
      "artifact_not_allowed",
      "capability_refused",
      "registry_refused",
      "unknown",
    ])
    .nullable()
    .exactOptional(),
});

export const stepDiagnosticsSchema = z.strictObject({
  failure_category: stepDiagnosticFailureSchema.nullable(),
  install_issues: z.array(installIssueSchema).max(100),
});
export type StepDiagnostics = z.infer<typeof stepDiagnosticsSchema>;
export type StepDiagnosticFailure = z.infer<typeof stepDiagnosticFailureSchema>;

export const stepDiagnosticRecordSchema = stepDiagnosticsSchema.extend({
  job_id: jobIdSchema,
  run_kind: failureExcerptRunKindSchema,
  phase: z.enum(["B_install", "B_build", "B_tests"]),
  step_name: stepNameSchema,
  step_identity: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[A-Za-z0-9:._-]+$/),
});
export type StepDiagnosticRecord = z.infer<typeof stepDiagnosticRecordSchema>;

/** Response-shape negotiation keeps deployed strict clients readable during rolling updates. */
export const STEP_DIAGNOSTICS_ACCEPT = "application/json; kovo-step-diagnostics=1";
export function acceptsStepDiagnostics(accept: string | undefined): boolean {
  return (
    accept
      ?.split(",")
      .some((media) => /^\s*application\/json\s*;\s*kovo-step-diagnostics=1\s*$/i.test(media)) ??
    false
  );
}
