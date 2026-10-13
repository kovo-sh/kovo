import { z } from "zod";
import { accountIdSchema, repoIdSchema, jobIdSchema } from "./ids.js";
import { failureCategoryNameSchema } from "./step-result.js";

/** Independent W5 wire contract; existing strict verification payloads stay unchanged. */
export const triageDecisionSchema = z.enum(["retry_same", "escalate", "pre_existing"]);
export type TriageDecision = z.infer<typeof triageDecisionSchema>;
export const triageProposalSchema = z.strictObject({ decision: triageDecisionSchema });
export const triageRequestSchema = z.strictObject({
  accountId: accountIdSchema,
  repoId: repoIdSchema,
  jobId: jobIdSchema,
  workflowId: z.string().min(1).max(512),
  stepName: z.string().min(1).max(100),
  command: z.string().max(8192),
  category: failureCategoryNameSchema,
  tail: z.string().max(32768),
});
export type TriageRequest = z.infer<typeof triageRequestSchema>;
