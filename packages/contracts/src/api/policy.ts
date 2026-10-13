import { z } from "zod";

import { resourceVersionSchema } from "../http.js";
import { repoIdSchema } from "../ids.js";
import { policyBodySchema } from "../policy.js";
import { whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { actorRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// `/v1/repos/{repo}/policy`: the versioned repository policy (SPEC data model `policies`, Public API
// row "Scoped read; repo-admin authority for writes; keys may only tighten"). Reads return an ETag
// of the version; writes require If-Match and a stale version is `412 precondition_failed`.

/** The repository policy resource. Its `version` is the ETag. */
export const repoPolicySchema = z
  .strictObject({
    repo_id: repoIdSchema,
    body: policyBodySchema,
    version: resourceVersionSchema,
    updated_at: utcDateTimeSchema.nullable(),
    updated_by: actorRefSchema.nullable(),
  })
  .refine((policy) => (policy.updated_at === null) === (policy.updated_by === null), {
    ...whenValid,
    error: "updated_at and updated_by are recorded together",
  });
export type RepoPolicy = z.output<typeof repoPolicySchema>;

const ROW_POLICY = "Scoped read; repo-admin authority for writes; keys may only tighten";
const repoParams = z.strictObject({ repo: repoIdSchema });

export const POLICY_ENDPOINTS = {
  getPolicy: defineEndpoint({
    operationId: "getPolicy",
    area: "policy",
    method: "GET",
    path: "/v1/repos/{repo}/policy",
    summary: "Read the repository policy and its version.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/policy" },
    params: repoParams,
    query: null,
    body: null,
    responses: { 200: repoPolicySchema },
    authorization: {
      spec: ROW_POLICY,
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
    etag: "/version",
  }),
  putPolicy: defineEndpoint({
    operationId: "putPolicy",
    area: "policy",
    method: "PUT",
    path: "/v1/repos/{repo}/policy",
    summary: "Replace the policy; an API key may only tighten it.",
    source: { kind: "spec_row", path: "/v1/repos/{repo}/policy" },
    auditActions: ["policy.updated"],
    params: repoParams,
    query: null,
    body: policyBodySchema,
    responses: { 200: repoPolicySchema },
    authorization: {
      spec: ROW_POLICY,
      actors: ["human_session", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
      escalations: [{ when: "weakens_policy", requires: { humanSession: true }, unmet: "deny" }],
    },
    ifMatch: true,
    etag: "/version",
    problems: ["repo_not_enabled"],
  }),
} as const;
