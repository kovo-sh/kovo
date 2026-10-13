import { z } from "zod";
import { accountIdSchema, jobIdSchema, recipeVersionIdSchema, repoIdSchema } from "./ids.js";

/** Scalars only: no source, check names, output, paths or model prose. */
export const weakRecipeEvidenceSchema = z
  .strictObject({
    baselinePassed: z.boolean(),
    workingChecks: z.int().min(0).max(1000),
    failedChecks: z.int().min(0).max(1000),
    passingProbes: z.int().min(0).max(1000),
    totalProbes: z.int().min(0).max(1000),
    controlPassed: z.boolean().nullable(),
  })
  .refine((data) => data.passingProbes <= data.totalProbes);
export type WeakRecipeEvidence = z.infer<typeof weakRecipeEvidenceSchema>;
export const weakRecipeReasonCodeSchema = z.enum([
  "sufficient_working_checks",
  "insufficient_working_checks",
  "baseline_failed",
  "weak_probe_coverage",
  "control_failed",
  "plus_required",
  "judge_unavailable",
]);
export const weakRecipeJudgmentSchema = z.strictObject({
  verdict: z.enum(["acceptable_for_low_risk", "not_acceptable"]),
  reasonCodes: z.array(weakRecipeReasonCodeSchema).min(1).max(5),
  /** Only the trusted relay sets this after validating an actual model verdict. */
  modelVerdict: z.boolean().exactOptional(),
  /** Stable rejection from immutable calibration scalars; never an acceptance. */
  ruleVerdict: z.boolean().exactOptional(),
});
export type WeakRecipeJudgment = z.infer<typeof weakRecipeJudgmentSchema>;
export const weakRecipeJudgmentRequestSchema = z.strictObject({
  accountId: accountIdSchema,
  repoId: repoIdSchema,
  jobId: jobIdSchema,
  workflowId: z.string().min(1).max(512),
  versionId: recipeVersionIdSchema,
  evidence: weakRecipeEvidenceSchema,
  retryAttempt: z.int().min(1).max(1000000).exactOptional(),
});
export type WeakRecipeJudgmentRequest = z.infer<typeof weakRecipeJudgmentRequestSchema>;
