import { z } from "zod";

import { dependencyVerdictWireSchema } from "../dependency-verdicts.js";
import { pullRequestNumberSchema, repoIdSchema } from "../ids.js";
import { gitShaSchema, sha256HexSchema } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { defineEndpoint } from "./endpoint.js";

/** Confirmation of the exact identifiers/reasons shown to the human, never caller-supplied verdicts. */
export const dependencyOverrideBindingSchema = z.strictObject({
  base_sha: gitShaSchema,
  head_sha: gitShaSchema,
  verdicts_digest: sha256HexSchema,
});
export type DependencyOverrideBinding = z.infer<typeof dependencyOverrideBindingSchema>;

export const dependencyOverrideAvailabilityReasonSchema = z.enum([
  "eligible",
  "dependency_override_blocked",
  "dependency_override_malware_hold",
  "dependency_override_unevaluated",
  "dependency_override_no_verdicts",
  "dependency_override_head_changed",
]);

/** A separate response leaves previously deployed strict fix and repository readers unchanged. */
export const dependencyOverrideAvailabilitySchema = z.strictObject({
  pull_number: pullRequestNumberSchema,
  head_sha: gitShaSchema,
  base_sha: gitShaSchema,
  available: z.boolean(),
  reason: dependencyOverrideAvailabilityReasonSchema,
  binding: dependencyOverrideBindingSchema.nullable(),
  verdicts: z.array(dependencyVerdictWireSchema).max(500),
});
export type DependencyOverrideAvailability = z.infer<typeof dependencyOverrideAvailabilitySchema>;

const params = z.strictObject({
  repo: repoIdSchema,
  pull: z.coerce.number().pipe(pullRequestNumberSchema),
});
const authorization = {
  spec: "Human session and fresh GitHub repository administration; exact-head dependency verdicts and acceptance confirmation; D-238 internal-test Custom drill exception below",
  actors: ["human_session"] as const,
  managementPermission: "acceptDependencyOverrideDrill" as const,
  tenant: "path_resource" as const,
  repoAuthority: { level: "admin" as const, over: "path_repo" as const },
};
export const DEPENDENCY_OVERRIDE_ENDPOINTS = {
  getDependencyGateAlerts: defineEndpoint({
    operationId: "getDependencyGateAlerts",
    area: "dependency-verdicts",
    method: "GET",
    path: "/v1/repos/{repo}/dependency-alerts",
    summary: "Read unresolved exact-head dependency evaluation alerts.",
    source: { kind: "spec_implied", section: "Recipes and verification" },
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        items: z
          .array(
            z.strictObject({
              pull_number: pullRequestNumberSchema,
              head_sha: gitShaSchema,
              reason: z.literal("dependency_gate_unevaluated:retry_window_expired"),
              overridden: z.boolean(),
            }),
          )
          .max(100),
      }),
    },
    authorization: {
      spec: "Reading the dashboard alert requires a human session with current repository read access",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  retryDependencyGate: defineEndpoint({
    operationId: "retryDependencyGate",
    area: "dependency-verdicts",
    method: "POST",
    path: "/v1/repos/{repo}/pulls/{pull}/dependency-alert/retry",
    summary: "Retry evaluation of the confirmed alert head.",
    source: { kind: "spec_implied", section: "Recipes and verification" },
    auditActions: ["dependency_gate.retry_requested"],
    params,
    query: null,
    body: z.strictObject({ head_sha: gitShaSchema }),
    responses: { 202: z.strictObject({ status: z.literal("recorded"), head_sha: gitShaSchema }) },
    authorization: {
      spec: "Retry evaluation requires a human session with fresh repository administration, is audited and requires an Idempotency-Key",
      actors: ["human_session"],
      // D-238 (#3703): only the distinct internal-test Custom drill grant reaches the key path.
      managementPermission: "retryDependencyGateDrill",
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    idempotency: "required",
    problems: ["conflict"],
  }),
  overrideUnevaluatedDependencyGate: defineEndpoint({
    operationId: "overrideUnevaluatedDependencyGate",
    area: "dependency-verdicts",
    method: "POST",
    path: "/v1/repos/{repo}/pulls/{pull}/dependency-alert/override",
    summary: "Merge anyway for one confirmed unevaluated head, with a human admin audit.",
    source: { kind: "spec_implied", section: "Recipes and verification" },
    auditActions: ["dependency_gate.override_accepted"],
    params,
    query: null,
    body: z.strictObject({ head_sha: gitShaSchema }),
    responses: { 202: z.strictObject({ status: z.literal("recorded"), head_sha: gitShaSchema }) },
    authorization: {
      spec: "Merge anyway requires fresh repository-admin authorization in a human session, denies failed authorization lookups, is audited and applies only to the confirmed head SHA",
      actors: ["human_session"],
      // D-238 (#3703): only the distinct internal-test Custom drill grant reaches the key path.
      managementPermission: "overrideUnevaluatedDependencyGateDrill",
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    idempotency: "required",
    problems: ["conflict"],
  }),
  configureDependencyGateDrillFault: defineEndpoint({
    operationId: "configureDependencyGateDrillFault",
    area: "dependency-verdicts",
    method: "PUT",
    path: "/v1/repos/{repo}/pulls/{pull}/dependency-gate/drill-fault",
    summary: "Arm or clear the deny-only kovo-tests drill fault for one exact pull request head.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditActions: ["dependency_gate.drill_fault_changed"],
    params,
    query: null,
    body: z.strictObject({
      head_sha: gitShaSchema,
      /** 1 to 10 minutes arms (and shortens that head's pending window); null clears. */
      pending_window_minutes: z.number().int().min(1).max(10).nullable(),
    }),
    responses: {
      200: z.strictObject({
        head_sha: gitShaSchema,
        armed: z.boolean(),
        expires_at: utcDateTimeSchema.nullable(),
      }),
    },
    authorization: {
      spec: "Customer accounts cannot configure faults.",
      actors: ["human_session"],
      tenant: "path_resource",
      managementPermission: "armDependencyGateDrillFault",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["forbidden_actor", "conflict"],
  }),
  getDependencyOverrideAvailability: defineEndpoint({
    operationId: "getDependencyOverrideAvailability",
    area: "dependency-verdicts",
    method: "GET",
    path: "/v1/repos/{repo}/pulls/{pull}/dependency-override",
    summary: "Read dependency verdicts and exact-head acceptance confirmation facts.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/pulls/{pull}/dependency-override" },
    params,
    query: null,
    body: null,
    responses: { 200: dependencyOverrideAvailabilitySchema },
    authorization,
    problems: ["conflict", "upstream_error"],
  }),
  acceptDependencyOverride: defineEndpoint({
    operationId: "acceptDependencyOverride",
    area: "dependency-verdicts",
    method: "POST",
    path: "/v1/repos/{repo}/pulls/{pull}/dependency-override",
    summary: "Accept only the confirmed wait/warn verdicts for one exact pull request head.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/pulls/{pull}/dependency-override" },
    auditActions: ["dependency_gate.override_accepted"],
    params,
    query: null,
    body: dependencyOverrideBindingSchema,
    responses: { 202: z.strictObject({ status: z.literal("recorded"), head_sha: gitShaSchema }) },
    authorization: {
      ...authorization,
      spec: "Same human administration; required Idempotency-Key; echo base/head SHA and verdicts_digest; accept only current wait/warn identifiers and reasons; D-238 internal-test Custom drill exception below",
    },
    idempotency: "required",
    problems: ["conflict", "upstream_error"],
  }),
} as const;
