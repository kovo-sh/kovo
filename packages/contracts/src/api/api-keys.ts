import { z } from "zod";
import {
  apiKeyAuthoritySchema,
  apiKeyKindSchema,
  apiKeyRepositoryAuthoritySchema,
  managementKeyPermissionWriteSchema,
} from "../api-key-authority-schemas.js";

import { ACCOUNT_ADMIN_ROLES, apiKeyScopeSchema } from "../enums/accounts.js";
import { apiKeyIdSchema, repoIdSchema } from "../ids.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { KOVO_SECRET_TOKEN_PREFIXES } from "../secret-tokens.js";
import { whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import {
  apiKeyNameSchema,
  oneTimeSecretSchema,
  queryBooleanSchema,
  uniqueArraySchema,
  userRefSchema,
} from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// `/v1/api-keys` (SPEC "API keys are account-scoped, hashed, revocable, and created by an account
// owner/admin. Effective repository permissions are the intersection of key scope, explicitly
// delegated repo scope, and the creator's current GitHub authority"; Public API row "Human
// owner/admin; explicit repo delegation; key shown once").

/** Keys authenticate as `Authorization: Bearer kovo_…` (docs/decisions/auth.md). */
export const API_KEY_AUTH_SCHEME = "Bearer";
export const API_KEY_PREFIX = KOVO_SECRET_TOKEN_PREFIXES.apiKey;
export const MANAGEMENT_API_KEY_PREFIX = KOVO_SECRET_TOKEN_PREFIXES.managementApiKey;
export const DELEGATED_RUNTIME_API_KEY_PREFIX = KOVO_SECRET_TOKEN_PREFIXES.delegatedRuntimeApiKey;

/** The plaintext key, returned once by `POST /v1/api-keys`; only its hash is stored. */
export const apiKeySecretSchema = z.union([
  oneTimeSecretSchema(API_KEY_PREFIX, "ApiKeySecret"),
  oneTimeSecretSchema(MANAGEMENT_API_KEY_PREFIX, "ApiKeySecret"),
  oneTimeSecretSchema(DELEGATED_RUNTIME_API_KEY_PREFIX, "ApiKeySecret"),
]);
export type ApiKeySecret = z.infer<typeof apiKeySecretSchema>;

/** Explicit delegation: a key names every repository it may act on (no wildcard). */
export const MAX_API_KEY_REPOS = 100;
/** Random 256-bit nonsecret intent; reused only to reconcile one immutable issuance. */
export const apiKeyIssuanceIntentSchema = z.string().regex(/^[0-9a-f]{64}$/);

export const apiKeySchema = z
  .strictObject({
    id: apiKeyIdSchema,
    name: apiKeyNameSchema,
    scope: apiKeyScopeSchema,
    repo_ids: uniqueArraySchema(repoIdSchema, MAX_API_KEY_REPOS, 0),
    authority: apiKeyAuthoritySchema.exactOptional(),
    issuance_intent: apiKeyIssuanceIntentSchema.exactOptional(),
    created_by: userRefSchema,
    created_at: utcDateTimeSchema,
    last_used_at: utcDateTimeSchema.nullable(),
    revoked_at: utcDateTimeSchema.nullable(),
  })
  .refine((key) => key.authority?.kind === "management" || key.repo_ids.length > 0, {
    ...whenValid,
    error: "Runtime keys delegate at least one repository",
    path: ["repo_ids"],
  })
  .superRefine((key, ctx) => {
    const authority = key.authority;
    if (authority === undefined) return;
    if (authority.kind === "management" && key.scope !== "write")
      ctx.addIssue({
        code: "custom",
        path: ["scope"],
        message: "Management keys use explicit operation permissions",
      });
    if (authority.repo_authority.kind === "installation") {
      if (authority.kind !== "management" || key.repo_ids.length !== 0)
        ctx.addIssue({
          code: "custom",
          path: ["repo_ids"],
          message:
            "Installation authority belongs to Management keys without explicit repositories",
        });
    } else if (
      authority.repo_authority.repo_ids.length !== key.repo_ids.length ||
      authority.repo_authority.repo_ids.some((id) => !key.repo_ids.includes(id))
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["repo_ids"],
        message: "Key authority must match delegated repositories",
      });
    }
  })
  .refine(
    (key) => key.revoked_at === null || key.revoked_at.getTime() >= key.created_at.getTime(),
    {
      ...whenValid,
      error: "a key is revoked after it is created",
      path: ["revoked_at"],
    },
  );
export type ApiKey = z.output<typeof apiKeySchema>;

export const createApiKeyBodySchema = z
  .strictObject({
    name: apiKeyNameSchema,
    scope: apiKeyScopeSchema,
    repo_ids: uniqueArraySchema(repoIdSchema, MAX_API_KEY_REPOS, 0),
    kind: apiKeyKindSchema.exactOptional(),
    issuance_intent: apiKeyIssuanceIntentSchema.exactOptional(),
    permission_preset: z.enum(["full", "custom"]).exactOptional(),
    permissions: uniqueArraySchema(managementKeyPermissionWriteSchema, 100, 0).exactOptional(),
    repo_authority: apiKeyRepositoryAuthoritySchema.exactOptional(),
    expires_at: utcDateTimeSchema.nullable().exactOptional(),
  })
  .superRefine((value, ctx) => {
    if (value.kind !== "management") {
      if (value.repo_ids.length === 0)
        ctx.addIssue({
          code: "custom",
          path: ["repo_ids"],
          message: "Runtime keys delegate at least one repository",
        });
      if (
        value.permission_preset !== undefined ||
        value.permissions !== undefined ||
        value.repo_authority !== undefined
      )
        ctx.addIssue({
          code: "custom",
          path: ["kind"],
          message: "Runtime keys cannot grant Management permissions",
        });
    } else {
      if (value.issuance_intent === undefined)
        ctx.addIssue({
          code: "custom",
          path: ["issuance_intent"],
          message: "Management issuance requires a stable intent",
        });
      if (value.scope !== "write")
        ctx.addIssue({
          code: "custom",
          path: ["scope"],
          message: "Management keys use explicit operation permissions",
        });
      if (value.permission_preset === undefined || value.repo_authority === undefined)
        ctx.addIssue({
          code: "custom",
          path: ["kind"],
          message: "Management permission preset and repository authority required",
        });
      if (value.permission_preset === "custom" && value.permissions === undefined)
        ctx.addIssue({
          code: "custom",
          path: ["permissions"],
          message: "Custom permissions required",
        });
      if (value.permission_preset === "full" && value.permissions !== undefined)
        ctx.addIssue({
          code: "custom",
          path: ["permissions"],
          message: "Full uses the server's fixed current permission catalog",
        });
      if (value.repo_authority?.kind === "installation" && value.repo_ids.length > 0)
        ctx.addIssue({
          code: "custom",
          path: ["repo_ids"],
          message: "Installation authority does not supply explicit repositories",
        });
      if (
        value.repo_authority?.kind === "explicit" &&
        (value.repo_authority.repo_ids.length !== value.repo_ids.length ||
          value.repo_authority.repo_ids.some((id) => !value.repo_ids.includes(id)))
      )
        ctx.addIssue({
          code: "custom",
          path: ["repo_ids"],
          message: "Explicit authority must match delegated repositories",
        });
    }
  });

const ROW_API_KEYS = "Human owner/admin; explicit repo delegation; key shown once";

export const API_KEY_ENDPOINTS = {
  listApiKeys: defineEndpoint({
    operationId: "listApiKeys",
    area: "api-keys",
    method: "GET",
    path: "/v1/api-keys",
    summary: "List the account's API keys (never their secrets).",
    source: { kind: "spec_row", path: "/v1/api-keys" },
    params: null,
    query: z.strictObject({
      ...paginationQueryShape,
      include_revoked: queryBooleanSchema.exactOptional(),
      issuance_intent: apiKeyIssuanceIntentSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: pageSchema(apiKeySchema) },
    authorization: {
      spec: ROW_API_KEYS,
      actors: ["human_session"],
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
    paginated: true,
  }),
  createApiKey: defineEndpoint({
    operationId: "createApiKey",
    area: "api-keys",
    method: "POST",
    path: "/v1/api-keys",
    summary: "Create a key delegated to explicit repositories; the plaintext is returned once.",
    source: { kind: "spec_row", path: "/v1/api-keys" },
    auditActions: ["api_key.created"],
    params: null,
    query: null,
    body: createApiKeyBodySchema,
    responses: { 201: z.strictObject({ api_key: apiKeySchema, secret: apiKeySecretSchema }) },
    authorization: {
      spec: ROW_API_KEYS,
      actors: ["human_session"],
      tenant: "account_context",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      repoAuthority: { level: "read", over: "body_repos" },
    },
    oneTimeFields: ["/secret"],
  }),
  revokeApiKey: defineEndpoint({
    operationId: "revokeApiKey",
    area: "api-keys",
    method: "DELETE",
    path: "/v1/api-keys/{id}",
    summary: "Revoke a key immediately.",
    source: { kind: "spec_row", path: "/v1/api-keys" },
    auditActions: ["api_key.revoked"],
    params: z.strictObject({ id: apiKeyIdSchema }),
    query: null,
    body: null,
    responses: {
      200: z
        .strictObject({ api_key: apiKeySchema })
        .refine((body) => body.api_key.revoked_at !== null, {
          ...whenValid,
          error: "the key is revoked",
        }),
    },
    authorization: {
      spec: ROW_API_KEYS,
      actors: ["human_session"],
      tenant: "path_resource",
      accountRoles: ACCOUNT_ADMIN_ROLES,
    },
  }),
} as const;
