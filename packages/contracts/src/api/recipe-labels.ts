import { z } from "zod";
import { repoIdSchema, recipeVersionIdSchema } from "../ids.js";
import { recipeLabelsSchema, recipeLabelDeviationSchema } from "../recipe-labels.js";
import { emptyBodySchema, versionNumberParamSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";
import { recipeVersionSummarySchema } from "./recipes.js";
import { repoSchema } from "./repos.js";

export const recipeLabelsDisclosureSchema = z.strictObject({
  recipe_version_id: recipeVersionIdSchema,
  environment: recipeLabelsSchema.shape.envFormats,
  referenced_names: recipeLabelsSchema.shape.secrets,
  action_labels: recipeLabelsSchema.shape.actions,
  script_ranking: recipeLabelsSchema.shape.scripts,
  deviations: z.array(recipeLabelDeviationSchema).max(400),
  requires_approval: z.boolean(),
  human_approved: z.boolean(),
  baseline_rejected: z.boolean(),
});
const params = z.strictObject({ repo: repoIdSchema, v: versionNumberParamSchema });
export const RECIPE_LABEL_ENDPOINTS = {
  getRecipeLabels: defineEndpoint({
    operationId: "getRecipeLabels",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions/{v}/labels",
    summary: "Read validated model proposals and their disclosed CI deviations.",
    source: {
      kind: "owner_directed",
      decision: "recipes.md",
      heading: "Discovery model labels (owner-directed)",
    },
    params,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ labels: recipeLabelsDisclosureSchema.nullable() }) },
    authorization: {
      managementPermission: "getRecipeVersion",
      spec: "Active recipe, calibration and deviations; version ETag",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  approveRecipeLabels: defineEndpoint({
    operationId: "approveRecipeLabels",
    area: "recipes",
    method: "POST",
    path: "/v1/repos/{repo}/recipe/versions/{v}/labels/approve",
    summary: "Approve exactly this calibrated recipe including disclosed model proposals.",
    source: {
      kind: "owner_directed",
      decision: "recipes.md",
      heading: "Discovery model labels (owner-directed)",
    },
    params,
    query: null,
    body: emptyBodySchema,
    responses: { 200: z.strictObject({ version: recipeVersionSummarySchema, repo: repoSchema }) },
    auditActions: ["recipe.approved", "recipe.activated"],
    authorization: {
      spec: "Human repo admin; exact version and current authority",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "admin", over: "path_repo" },
    },
    problems: ["recipe_not_approvable", "conflict"],
  }),
} as const;
