import { z } from "zod";

import { deviationReasonSchema } from "./enums/recipes.js";
import { envFixtureFormatSchema } from "./env-fixture.js";
import {
  egressHostSchema,
  envVarNameSchema,
  hasControlCharacter,
  repoFilePathSchema,
} from "./primitives.js";
import { cmdSchema, recipeStepSchema, smokeSchema } from "./recipe.js";
import { stepNameSchema } from "./step-result.js";

const fixtureRequestSchema = z.strictObject({
  kind: z.literal("kovo_fixture"),
  name: envVarNameSchema,
  format: envFixtureFormatSchema,
});
export const doctorOverrideSchema = z.discriminatedUnion("kind", [
  fixtureRequestSchema,
  z.strictObject({
    kind: z.literal("replace_command"),
    target: z.strictObject({ kind: z.enum(["setup", "step", "smoke"]), name: stepNameSchema }),
    command: cmdSchema,
  }),
  z.strictObject({ kind: z.literal("build_egress"), host: egressHostSchema }),
  z.strictObject({
    kind: z.literal("revive_step"),
    ci_step_id: z.string().min(1).max(1024),
    step: recipeStepSchema,
    env_refs: z
      .array(
        z.strictObject({
          name: envVarNameSchema,
          label: z.enum(["optional", "fixture", "required"]),
          format: envFixtureFormatSchema.nullable(),
        }),
      )
      .min(1)
      .max(20),
  }),
]);
export type DoctorOverride = z.infer<typeof doctorOverrideSchema>;
/** Ephemeral model proposals only. Never store this union in legacy doctor overrides. */
export const doctorProposalOverrideSchema = z.union([
  doctorOverrideSchema,
  z.strictObject({
    kind: z.literal("sabotage_probe"),
    paths: z.array(repoFilePathSchema.max(384)).min(1).max(4),
  }),
]);
export type DoctorProposalOverride = z.infer<typeof doctorProposalOverrideSchema>;
export const doctorProposalSchema = z.strictObject({
  setup: z.array(cmdSchema).max(5),
  envStubs: z
    .record(
      envVarNameSchema,
      z.strictObject({ value: z.string().max(4096), source: z.literal("agent").exactOptional() }),
    )
    .refine((stubs) => Object.keys(stubs).length <= 20),
  smoke: smokeSchema.nullable(),
  overrides: z.array(doctorProposalOverrideSchema).max(20).exactOptional(),
});
export type DoctorProposal = z.infer<typeof doctorProposalSchema>;
export const doctorFactsSchema = z.strictObject({
  deviationReasons: z.array(deviationReasonSchema).max(200),
  stepNames: z
    .array(
      z
        .string()
        .min(1)
        .max(256)
        .refine((name) => !hasControlCharacter(name)),
    )
    .max(200),
  rejectedStubNames: z.array(envVarNameSchema).max(100),
});
export type DoctorFacts = z.infer<typeof doctorFactsSchema>;
