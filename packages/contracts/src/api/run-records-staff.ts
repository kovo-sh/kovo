import { z } from "zod";
import {
  accountIdSchema,
  userIdSchema,
  repoIdSchema,
  jobIdSchema,
  runRecordIdSchema,
  staffAccessGrantIdSchema,
} from "../ids.js";
import { utcDateTimeSchema } from "../time.js";
import { defineEndpoint } from "./endpoint.js";

export const staffGrantRequestSchema = z.strictObject({
  account_id: accountIdSchema,
  repo_id: repoIdSchema,
  job_id: jobIdSchema.optional(),
  justification: z.string().trim().min(20).max(1000),
  duration_seconds: z.int().min(1).max(7200),
});
export const staffGrantSchema = z.strictObject({
  id: staffAccessGrantIdSchema,
  account_id: accountIdSchema,
  repo_id: repoIdSchema,
  job_id: jobIdSchema.nullable(),
  operator_id: z.uuid(),
  justification: z.string().min(20).max(1000),
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
});
export type StaffGrantRequest = z.infer<typeof staffGrantRequestSchema>;
const authorization = {
  spec: "Human Kovo operators debugging a customer report require an account/repository-scoped grant (optionally narrowed to one job), with a 20–1000 character justification and duration at most two hours.",
  actors: ["operator"],
  tenant: "none",
} as const;
const source = { kind: "spec_implied", section: "Security model and data retention" } as const;
export const STAFF_RECORD_ENDPOINTS = {
  createStaffRecordGrant: defineEndpoint({
    operationId: "createStaffRecordGrant",
    area: "operator",
    method: "POST",
    path: "/v1/operator/run-record-grants",
    summary: "Request a human-only scoped run-record grant.",
    source,
    params: null,
    query: null,
    body: staffGrantRequestSchema,
    responses: { 201: staffGrantSchema },
    authorization,
    auditStorage: "staff_access_grants",
  }),
  revokeStaffRecordGrant: defineEndpoint({
    operationId: "revokeStaffRecordGrant",
    area: "operator",
    method: "POST",
    path: "/v1/operator/run-record-grants/{grant}/revoke",
    summary: "Revoke an owned run-record grant.",
    source,
    params: z.strictObject({ grant: staffAccessGrantIdSchema }),
    query: null,
    body: z.strictObject({}),
    responses: {
      200: z.strictObject({ id: staffAccessGrantIdSchema, revoked_at: utcDateTimeSchema }),
    },
    authorization,
    auditStorage: "staff_access_grants",
  }),
  getStaffRunRecord: defineEndpoint({
    operationId: "getStaffRunRecord",
    area: "operator",
    method: "GET",
    path: "/v1/operator/run-records/{record}",
    summary: "Stream an internally audited record under a live justified staff grant.",
    source,
    params: z.strictObject({ record: runRecordIdSchema }),
    query: z.strictObject({ grant_id: staffAccessGrantIdSchema }),
    body: null,
    responses: { 200: z.instanceof(ReadableStream<Uint8Array>) },
    authorization,
    auditStorage: "staff_access_audit",
    problems: ["record_expired", "record_unavailable"],
  }),
} as const;

export const runRecordAuthorizationRequestSchema = z.strictObject({
  purpose: z.string().trim().min(20).max(1000),
  repo_ids: z.array(repoIdSchema).min(1).max(100).optional(),
  max_duration_seconds: z.int().min(1).max(2592000),
});
export const runRecordAuthorizationSchema = z.strictObject({
  id: z.uuid(),
  account_id: accountIdSchema,
  repo_ids: z.array(repoIdSchema).nullable(),
  purpose: z.string().min(20).max(1000),
  created_by: userIdSchema,
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
  revoked_at: utcDateTimeSchema.nullable(),
});
export const agentStaffGrantRequestSchema = staffGrantRequestSchema.extend({
  authorization_id: z.uuid(),
  requested_by: z.string().regex(/^agent:[a-z0-9][a-z0-9-]{0,62}$/),
});
export const agentStaffGrantSchema = staffGrantSchema.extend({
  authorization_id: z.uuid(),
  requested_by: z.string().regex(/^agent:[a-z0-9][a-z0-9-]{0,62}$/),
});
const adminAuthorization = {
  spec: "Only a human Better Auth session that is an admin of the target account may create it; API keys, Management keys, operator service accounts and agents cannot.",
  actors: ["human_session"],
  tenant: "path_account",
  accountRoles: ["owner", "admin"],
} as const;
const accountParams = z.strictObject({ account: accountIdSchema });
export const RECORD_AUTHORIZATION_ENDPOINTS = {
  getRunRecordAuthorizerEligibility: defineEndpoint({
    operationId: "getRunRecordAuthorizerEligibility",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/run-record-authorizations/eligibility",
    summary: "Check whether this signed-in account admin may originate AI debugging authority.",
    source,
    params: accountParams,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ allowed: z.boolean() }) },
    authorization: {
      spec: adminAuthorization.spec,
      actors: adminAuthorization.actors,
      tenant: adminAuthorization.tenant,
    },
  }),
  listRunRecordAuthorizations: defineEndpoint({
    operationId: "listRunRecordAuthorizations",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/run-record-authorizations",
    summary: "List account admin authorizations for AI debugging.",
    source,
    params: accountParams,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ authorizations: z.array(runRecordAuthorizationSchema) }) },
    authorization: adminAuthorization,
  }),
  createRunRecordAuthorization: defineEndpoint({
    operationId: "createRunRecordAuthorization",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts/{account}/run-record-authorizations",
    summary: "Authorize scoped AI debugging from an original human admin request.",
    source,
    params: accountParams,
    query: null,
    body: runRecordAuthorizationRequestSchema,
    responses: { 201: runRecordAuthorizationSchema },
    authorization: adminAuthorization,
    auditStorage: "run_record_authorizations",
  }),
  revokeRunRecordAuthorization: defineEndpoint({
    operationId: "revokeRunRecordAuthorization",
    area: "accounts",
    method: "POST",
    path: "/v1/accounts/{account}/run-record-authorizations/{authorization}/revoke",
    summary: "Stop AI access under an account authorization.",
    source,
    params: accountParams.extend({ authorization: z.uuid() }),
    query: null,
    body: z.strictObject({}),
    responses: { 200: runRecordAuthorizationSchema },
    authorization: adminAuthorization,
    auditStorage: "run_record_authorizations",
  }),
} as const;
export const AGENT_RECORD_ENDPOINTS = {
  createAgentRecordGrant: defineEndpoint({
    operationId: "createAgentRecordGrant",
    area: "operator",
    method: "POST",
    path: "/v1/operator/agent-run-record-grants",
    summary: "Request a scoped AI grant backed by a live original admin authorization.",
    source,
    params: null,
    query: null,
    body: agentStaffGrantRequestSchema,
    responses: { 201: agentStaffGrantSchema },
    authorization: {
      ...authorization,
      spec: "An agent-classified operator or the operator service account may request a repository-required grant, optionally narrowed to a job, referencing a live authorization that covers the account and repo.",
    },
    auditStorage: "staff_access_grants",
  }),
} as const;
