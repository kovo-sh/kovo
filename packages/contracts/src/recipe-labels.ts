import { z } from "zod";
import { envFixtureFormatSchema } from "./env-fixture.js";
import { ciStepIdSchema } from "./recipe.js";
import { repoFilePathSchema, sha256HexSchema, envVarNameSchema } from "./primitives.js";

/** Transient model response; never extends any legacy recipe JSON schema. */
export const recipeLabelsSchema = z.strictObject({
  envFormats: z
    .array(z.strictObject({ name: envVarNameSchema, format: envFixtureFormatSchema }))
    .max(100),
  secrets: z
    .array(
      z.strictObject({
        name: envVarNameSchema,
        label: z.enum(["optional", "fixture", "required"]),
      }),
    )
    .max(100),
  actions: z
    .array(
      z.strictObject({
        ci_step_id: ciStepIdSchema,
        label: z.enum(["inert", "irrelevant_setup", "check", "network"]),
      }),
    )
    .max(200),
  scripts: z
    .array(
      z.strictObject({
        name: z
          .string()
          .min(1)
          .max(100)
          .regex(/^[A-Za-z0-9:_-]+$/),
      }),
    )
    .max(50),
});
export type RecipeLabels = z.infer<typeof recipeLabelsSchema>;

/** Additive disclosure stored separately from strict legacy deviations. */
export const recipeLabelDeviationSchema = z.strictObject({
  ci_step_id: ciStepIdSchema,
  kind: z.enum(["narrowed", "unavailable"]),
  reason: z.enum([
    "model_action_inert",
    "model_action_irrelevant_setup",
    "model_action_check",
    "model_action_network",
    "model_run_without_secret",
    "model_fixture_secret",
  ]),
  referenced_names: z.array(envVarNameSchema).max(100),
});
export type RecipeLabelDeviation = z.infer<typeof recipeLabelDeviationSchema>;

export const recipeLabelFixtureSchema = z.strictObject({
  name: envVarNameSchema,
  format: envFixtureFormatSchema,
  path: repoFilePathSchema,
  sha256: sha256HexSchema,
});
export type RecipeLabelFixture = z.infer<typeof recipeLabelFixtureSchema>;
