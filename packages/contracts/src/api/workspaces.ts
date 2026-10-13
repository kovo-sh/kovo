import { z } from "zod";
import { recipeVersionIdSchema, repoIdSchema } from "../ids.js";
import { gitShaSchema } from "../primitives.js";
import { workspacePathSchema, workspaceInventorySchema } from "../workspace-inventory.js";
import { defineEndpoint } from "./endpoint.js";

/** Separate response, so strict previous-release repo readers see no new fields. */
export const WORKSPACE_ENDPOINTS = {
  getRepoWorkspaceStatus: defineEndpoint({
    operationId: "getRepoWorkspaceStatus",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/workspace-status",
    summary: "Read complete workspace admission and member calibration limitations.",
    source: {
      kind: "agent_decision",
      decision: "generation.md",
      heading: "P4 complete workspace admission (2026-10-04)",
      reviewIssue: 302,
    },
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        admission: z.enum(["supported", "refused"]),
        reason: z.enum(["inventory_required", "recipe_required", "no_supported_recipe"]).nullable(),
        recipe_version_id: recipeVersionIdSchema.nullable(),
        weak_members: z
          .array(
            z.strictObject({ member: workspacePathSchema, reason: z.literal("coverage_missing") }),
          )
          .max(101)
          .nullable(),
      }),
    },
    authorization: {
      managementPermission: "getRepo",
      spec: "Repository visibility always requires current GitHub read access.",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
  getRepoWorkspaceInventory: defineEndpoint({
    operationId: "getRepoWorkspaceInventory",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/workspace-inventory",
    summary: "Read refused workspace inventory; admitted inventory returns null.",
    source: {
      kind: "agent_decision",
      decision: "inventory-advisories.md",
      heading: "P2 workspace inventory and compatible projections (2026-10-04)",
      reviewIssue: 302,
    },
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: null,
    responses: {
      200: z.strictObject({
        inventory: z
          .strictObject({
            sha: gitShaSchema,
            generation: z.int().positive(),
            admission: z.literal("refused"),
            reason: z.literal("workspaces"),
            metadata: workspaceInventorySchema,
          })
          .nullable(),
      }),
    },
    authorization: {
      managementPermission: "getRepo",
      spec: "Repository visibility always requires current GitHub read access.",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
} as const;
