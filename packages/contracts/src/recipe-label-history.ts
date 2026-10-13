import { z } from "zod";
import { discoveryProvenanceReader } from "./discovery-validation.js";
import { gitShaSchema } from "./primitives.js";
import { envExampleBindingSchema } from "./env-fixture.js";
import { envVarNameSchema } from "./primitives.js";
import { ciDeviationSchema, recipeSchema } from "./recipe.js";

/** Deterministic bounded configuration, retained to restore rejected model authority. */
export const recipeLabelFallbackSchema = z.strictObject({
  body: recipeSchema,
  deviations: discoveryProvenanceReader(ciDeviationSchema),
  envBindings: z.array(envExampleBindingSchema).max(100),
  baseSha: gitShaSchema,
});
/** Keep the existing storage writer bound until the reader release is promoted. */
export const recipeLabelFallbackWriteSchema = recipeLabelFallbackSchema.extend({
  deviations: z.array(ciDeviationSchema).max(200),
});
export type RecipeLabelFallback = z.output<typeof recipeLabelFallbackSchema>;
export const recipeLabelRejectionsSchema = z.strictObject({
  envNames: z.array(envVarNameSchema).max(100),
  secretNames: z.array(envVarNameSchema).max(100),
  scriptNames: z
    .array(
      z
        .string()
        .min(1)
        .max(100)
        .regex(/^[A-Za-z0-9:_-]+$/),
    )
    .max(50),
});
export type RecipeLabelRejections = z.output<typeof recipeLabelRejectionsSchema>;
