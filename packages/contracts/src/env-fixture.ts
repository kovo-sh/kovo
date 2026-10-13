import { z } from "zod";
import { envVarNameSchema, repoFilePathSchema, sha256HexSchema } from "./primitives.js";

export const ENV_FIXTURE_FORMATS = ["url", "length32", "base64", "hex", "json"] as const;
export const envFixtureFormatSchema = z.enum(ENV_FIXTURE_FORMATS);
export type EnvFixtureFormat = z.infer<typeof envFixtureFormatSchema>;

/** Additive sidecar, outside the legacy Recipe and SPEC Source enums. */
export const envExampleBindingSchema = z
  .strictObject({
    name: envVarNameSchema,
    kind: z.enum(["kovo_fixture", "env_example"]),
    source: z.literal("env_example"),
    format: envFixtureFormatSchema.nullable(),
    path: repoFilePathSchema,
    sha256: sha256HexSchema,
  })
  .refine((binding) => (binding.kind === "kovo_fixture") === (binding.format !== null));
export type EnvExampleBinding = z.infer<typeof envExampleBindingSchema>;
