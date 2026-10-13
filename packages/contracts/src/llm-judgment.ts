import { whenValid } from "./primitives.js";
import { z } from "zod";
import { accountIdSchema, jobIdSchema, repoIdSchema } from "./ids.js";
import { sha256HexSchema } from "./primitives.js";
import { failureExcerptRunKindSchema } from "./failure-excerpt.js";
import { failureCategoryNameSchema } from "./step-result.js";

export const debtJudgmentSchema = z.strictObject({
  verdict: z.enum(["same", "fewer", "new_failures", "unclear"]),
  rationale_code: z.string().regex(/^[a-z][a-z0-9_]{0,79}$/),
  summary: z.string().max(300),
});
export type DebtJudgment = z.infer<typeof debtJudgmentSchema>;
export const failureDiagnosisSchema = z.strictObject({
  category: z.union([failureCategoryNameSchema, z.string().regex(/^other:[a-z][a-z0-9_-]{0,63}$/)]),
  confidence: z.number().min(0).max(1),
  summary: z.string().max(300),
  remediation: z.string().max(300),
  anchor_candidates: z
    .array(z.string().regex(/^[a-z][a-z0-9 _-]{0,79}$/))
    .max(5)
    .exactOptional(),
});
export type FailureDiagnosis = z.infer<typeof failureDiagnosisSchema>;
/** Internal transient HTTP body only. Never a DBOS input or a log payload. */
export const llmJudgmentRequestSchema = z
  .strictObject({
    accountId: accountIdSchema,
    repoId: repoIdSchema,
    jobId: jobIdSchema,
    workflowId: z.string().min(1).max(512),
    stepIdentity: z.string().min(1).max(512),
    kind: z.enum(["judge", "diagnose"]),
    purpose: z.enum(["baseline_judgment", "failure_diagnosis"]),
    metadata: z
      .strictObject({
        runKind: failureExcerptRunKindSchema,
        phase: z.enum(["B_install", "B_build", "B_tests"]),
        stepName: z.string().max(100),
        excerptId: z.uuid().nullable(),
        mutationKey: sha256HexSchema.nullable().exactOptional(),
      })
      .exactOptional(),
    baseTail: z.string().max(32768),
    candidateTail: z.string().max(32768),
  })
  .refine(
    (value) =>
      value.purpose === (value.kind === "judge" ? "baseline_judgment" : "failure_diagnosis"),
    { ...whenValid, error: "purpose does not match operation" },
  );
export type LlmJudgmentRequest = z.infer<typeof llmJudgmentRequestSchema>;
export const llmJudgmentResponseSchema = z.strictObject({
  judgment: debtJudgmentSchema.nullable(),
  diagnosis: failureDiagnosisSchema.nullable(),
});
export type LlmJudgmentResponse = z.infer<typeof llmJudgmentResponseSchema>;
export const learningLoopReportSchema = z.strictObject({
  category: failureDiagnosisSchema.shape.category,
  repositories: z.int().min(3),
  diagnoses: z.int().positive(),
  anchor_candidates: z.array(z.string().regex(/^[a-z][a-z0-9 _-]{0,79}$/)).max(5),
});
export type LearningLoopReport = z.infer<typeof learningLoopReportSchema>;
