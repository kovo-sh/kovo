import { z } from "zod";
import { ACCOUNT_ADMIN_ROLES } from "../enums/accounts.js";
import {
  selectableEgressModeSchema,
  deniedEgressHostnameSchema,
  recipeEgressDisclosureSchema,
} from "../egress.js";
import {
  accountIdSchema,
  apiKeyIdSchema,
  githubAccountIdSchema,
  recipeVersionIdSchema,
  repoIdSchema,
  userIdSchema,
} from "../ids.js";
import { utcDateTimeSchema } from "../time.js";
import { emptyBodySchema, versionNumberParamSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

/**
 * One owner D-617 acknowledgement the dyad-sh Management key recorded: IDs, the reviewed list's
 * version, the GitHub organization ID, a build-host count and the time. Host names are not
 * included; the version's egress disclosure lists them.
 */
export const dogfoodEgressAcknowledgementSchema = z.strictObject({
  repo_id: repoIdSchema,
  recipe_version_id: recipeVersionIdSchema,
  version: z.int().positive(),
  source: z.literal("management_key_dogfood"),
  api_key_id: apiKeyIdSchema,
  created_by: userIdSchema,
  github_org_id: githubAccountIdSchema,
  list_version: z.int().positive(),
  host_count: z.int().min(1).max(100),
  acknowledged_at: utcDateTimeSchema,
  /** D-618: the dyad-sh key's approval of the same version, when it approved it. */
  approved_by_key_id: apiKeyIdSchema.nullable(),
  approved_at: utcDateTimeSchema.nullable(),
});

const mutationResult = z.strictObject({
  recipe_version_id: recipeVersionIdSchema,
  version: z.int().positive(),
});
const params = z.strictObject({ repo: repoIdSchema, v: versionNumberParamSchema });
const source = {
  kind: "owner_directed",
  decision: "sandbox.md",
  heading: "Owner-directed egress policy (2026-10-02)",
} as const;
const humanAdmin = {
  spec: "Human repo admin; exact version and current authority",
  actors: ["human_session"],
  tenant: "path_resource",
  repoAuthority: { level: "admin", over: "path_repo" },
} as const;
export const EGRESS_ENDPOINTS = {
  getRecipeEgress: defineEndpoint({
    operationId: "getRecipeEgress",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions/{v}/egress",
    summary: "Read disclosed network authority and advisory denied-host proposals.",
    source,
    params,
    query: null,
    body: null,
    responses: { 200: recipeEgressDisclosureSchema },
    authorization: {
      managementPermission: "getRecipeVersion",
      spec: "Active recipe, calibration and deviations; version ETag",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  setRepoEgressMode: defineEndpoint({
    operationId: "setRepoEgressMode",
    area: "recipes",
    method: "PUT",
    path: "/v1/repos/{repo}/recipe/versions/{v}/egress/mode",
    summary:
      "Set the egress mode (Trust Kovo or Open) or refresh the current host catalog into a child version.",
    source: {
      kind: "owner_directed",
      decision: "auth.md",
      heading: "Owner-directed Runtime and Management keys (2026-10-01)",
    },
    params,
    query: null,
    body: z.strictObject({ mode: selectableEgressModeSchema }),
    responses: { 202: mutationResult },
    authorization: { ...humanAdmin, managementPermission: "recipe.egress.refresh_catalog" },
    auditActions: ["recipe.overrides_updated"],
    problems: ["conflict", "human_approval_required"],
  }),
  acknowledgeRecipeEgress: defineEndpoint({
    operationId: "acknowledgeRecipeEgress",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/egress/acknowledge",
    summary: "Acknowledge the exact disclosed recipe egress before recipe approval.",
    source: {
      kind: "owner_directed",
      decision: "auth.md",
      heading: "Owner-directed Runtime and Management keys (2026-10-01)",
    },
    params,
    query: null,
    body: emptyBodySchema,
    responses: { 200: recipeEgressDisclosureSchema },
    authorization: { ...humanAdmin, managementPermission: "recipe.egress.refresh_catalog" },
    auditActions: ["recipe.overrides_updated"],
    problems: ["conflict", "human_approval_required"],
  }),
  listDogfoodEgressAcknowledgements: defineEndpoint({
    operationId: "listDogfoodEgressAcknowledgements",
    area: "recipes",
    method: "GET",
    path: "/v1/accounts/{account}/egress-key-acknowledgements",
    summary: "List the dyad-sh Management key's recipe egress acknowledgements since a time.",
    source: {
      kind: "owner_directed",
      decision: "auth.md",
      heading: "Owner-directed dyad-sh Management-key egress acknowledgement D-617 (2026-11-06)",
    },
    params: z.strictObject({ account: accountIdSchema }),
    query: z.strictObject({ since: utcDateTimeSchema }),
    body: null,
    responses: {
      200: z.strictObject({
        acknowledgements: z.array(dogfoodEgressAcknowledgementSchema).max(200),
      }),
    },
    authorization: {
      spec: "Each key acknowledgement records the actual key and its root creator, is audited and is listed for the dogfood morning report",
      actors: ["human_session"],
      tenant: "path_account",
      accountRoles: ACCOUNT_ADMIN_ROLES,
      managementPermission: "recipe.egress.refresh_catalog",
    },
  }),
  revokeEgressHost: defineEndpoint({
    operationId: "revokeEgressHost",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/egress/hosts/revoke",
    summary: "Revoke a build hostname and create a new recipe for recalibration.",
    source,
    params,
    query: null,
    body: z.strictObject({ hostname: deniedEgressHostnameSchema }),
    responses: { 202: mutationResult },
    authorization: humanAdmin,
    auditActions: ["recipe.overrides_updated"],
    problems: ["conflict", "human_approval_required"],
  }),
  approveEgressProposal: defineEndpoint({
    operationId: "approveEgressProposal",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/egress/proposals/approve",
    summary: "Add one proposed hostname to a new build allowlist and recalibrate.",
    source,
    params,
    query: null,
    body: z.strictObject({ hostname: deniedEgressHostnameSchema }),
    responses: { 202: mutationResult },
    authorization: humanAdmin,
    auditActions: ["recipe.overrides_updated"],
    problems: ["conflict", "human_approval_required"],
  }),
} as const;
