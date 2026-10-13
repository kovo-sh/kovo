import { z } from "zod";

import { weakRecipeReasonCodeSchema } from "../weak-recipe-judgment.js";
import { repoIdSchema, recipeVersionIdSchema } from "../ids.js";
import { versionNumberParamSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

/** Additive disclosure: legacy recipe responses keep their original strict schemas. */
export const recipeLimitedDisclosureSchema = z.strictObject({
  recipe_version_id: recipeVersionIdSchema,
  verdict: z.enum(["acceptable_for_low_risk", "not_acceptable"]),
  reasons: z.array(weakRecipeReasonCodeSchema).min(1).max(5),
  consent_id: z.uuid(),
  approved_by_management_consent: z.boolean(),
});
export type RecipeLimitedDisclosure = z.output<typeof recipeLimitedDisclosureSchema>;

export const RECIPE_LIMITED_ENDPOINTS = {
  getRecipeLimited: defineEndpoint({
    operationId: "getRecipeLimited",
    area: "recipes",
    method: "GET",
    path: "/v1/repos/{repo}/recipe/versions/{v}/limited",
    summary: "Read the limited recipe verdict and sanitized reasons.",
    source: {
      kind: "owner_directed",
      decision: "recipes.md",
      heading: "Owner-directed weak-but-acceptable recipes (Full autopilot A4)",
    },
    params: z.strictObject({ repo: repoIdSchema, v: versionNumberParamSchema }),
    query: null,
    body: null,
    responses: { 200: z.strictObject({ limited: recipeLimitedDisclosureSchema.nullable() }) },
    authorization: {
      managementPermission: "getRecipeVersion",
      spec: "The PR and dashboard disclose the limited qualification and reasons.",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
} as const;
