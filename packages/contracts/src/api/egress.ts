import { z } from "zod";
import {
  writableEgressModeSchema,
  deniedEgressHostnameSchema,
  recipeEgressDisclosureSchema,
} from "../egress.js";
import { recipeVersionIdSchema, repoIdSchema } from "../ids.js";
import { emptyBodySchema, versionNumberParamSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

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
    summary: "Set egress policy or refresh the current host catalog into a child version.",
    source: {
      kind: "owner_directed",
      decision: "auth.md",
      heading: "Owner-directed Runtime and Management keys (2026-10-01)",
    },
    params,
    query: null,
    body: z.strictObject({ mode: writableEgressModeSchema }),
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
