import { z } from "zod";
import { exactVersionSchema, packageNameSchema } from "../npm.js";
import { advisoryIdSchema } from "../ids.js";
import { defineEndpoint } from "./endpoint.js";
import { reasonCodeSchema } from "../problem.js";

export const syntheticAdvisoryRequestSchema = z.strictObject({
  request_id: z.uuid(),
  state: z.enum(["pending", "succeeded", "failed"]),
  advisory_id: advisoryIdSchema.nullable(),
  reason: reasonCodeSchema.nullable(),
});

/** Exact ASCII scope and a complete npm name; never normalize before this check. */
export const syntheticPackageSchema = packageNameSchema.refine((name) =>
  /^@kovo-internal-testing\/[a-z0-9_~-][a-z0-9._~!'()*-]*$(?![\s\S])/.test(name),
);
const drillVersionSchema = exactVersionSchema.refine((version) => !/[^0-9A-Za-z.+-]/.test(version));
/** One bounded half-open SemVer interval; semantic ordering is checked in the service. */
export const syntheticAdvisoryBodySchema = z.strictObject({
  package: syntheticPackageSchema,
  introduced: drillVersionSchema,
  fixed: drillVersionSchema,
});
export const syntheticReportBodySchema = z.strictObject({
  package: syntheticPackageSchema,
  version: drillVersionSchema,
});
const reportId = z.uuid();
const common = {
  area: "dependency-verdicts",
  method: "POST",
  source: { kind: "spec_implied", section: "Inventory, advisories, and tiering" },
  params: null,
  query: null,
  // Deterministic subject identity and transactional no-op handling make retries safe.
  idempotency: "none",
  problems: ["validation_failed", "not_found", "conflict"],
  authorization: {
    spec: "Management cannot confirm, clear or separately hold a version.",
    // Core admits only Management keys with the exact Custom permission; the service also
    // checks the immutable kovo-tests account allowlist before writing.
    actors: ["api_key_write"],
    tenant: "account_context",
    accountRoles: ["owner", "admin"],
  },
} as const;

export const SYNTHETIC_DRILL_ENDPOINTS = {
  createSyntheticAdvisory: defineEndpoint({
    ...common,
    operationId: "createSyntheticAdvisory",
    path: "/v1/synthetic-advisories/create",
    summary: "Management-only: create a kovo-tests synthetic advisory through normal ingestion.",
    body: syntheticAdvisoryBodySchema,
    responses: {
      202: z.strictObject({ request_id: z.uuid() }),
    },
    auditActions: ["synthetic_advisory.created"],
  }),
  retractSyntheticAdvisory: defineEndpoint({
    ...common,
    operationId: "retractSyntheticAdvisory",
    path: "/v1/synthetic-advisories/retract",
    summary:
      "Management-only: withdraw the kovo-tests exact synthetic advisory through normal ingestion.",
    body: syntheticAdvisoryBodySchema,
    responses: {
      202: z.strictObject({ request_id: z.uuid() }),
    },
    auditActions: ["synthetic_advisory.retracted"],
  }),
  createMalwareReport: defineEndpoint({
    ...common,
    operationId: "createMalwareReport",
    path: "/v1/malware-reports/create",
    summary: "Management-only: report a kovo-tests internal-testing version; never confirm.",
    body: syntheticReportBodySchema,
    responses: { 200: z.strictObject({ report_id: reportId }) },
    auditStorage: "malware_hold_audit",
  }),
  retractMalwareReport: defineEndpoint({
    ...common,
    operationId: "retractMalwareReport",
    path: "/v1/malware-reports/retract",
    summary:
      "Management-only: retract the kovo-tests synthetic report, preserving independent holds.",
    body: syntheticReportBodySchema,
    responses: { 200: z.strictObject({ report_id: reportId }) },
    auditStorage: "malware_hold_audit",
  }),
  getSyntheticAdvisoryCreateRequest: defineEndpoint({
    ...common,
    operationId: "getSyntheticAdvisoryCreateRequest",
    method: "GET",
    path: "/v1/synthetic-advisories/create/requests/{id}",
    summary: "Read an authorized internal-test advisory create request result.",
    params: z.strictObject({ id: z.uuid() }),
    body: null,
    responses: { 200: syntheticAdvisoryRequestSchema },
    authorization: { ...common.authorization, managementPermission: "createSyntheticAdvisory" },
  }),
  getSyntheticAdvisoryRetractRequest: defineEndpoint({
    ...common,
    operationId: "getSyntheticAdvisoryRetractRequest",
    method: "GET",
    path: "/v1/synthetic-advisories/retract/requests/{id}",
    summary: "Read an authorized internal-test advisory retract request result.",
    params: z.strictObject({ id: z.uuid() }),
    body: null,
    responses: { 200: syntheticAdvisoryRequestSchema },
    authorization: { ...common.authorization, managementPermission: "retractSyntheticAdvisory" },
  }),
} as const;
