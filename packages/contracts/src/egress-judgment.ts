import { z } from "zod";
import { accountIdSchema, repoIdSchema, jobIdSchema } from "./ids.js";
import { deniedEgressHostnameSchema } from "./egress.js";

/** Transient hostname/package metadata only; never repository text or model output. */
export const egressJudgmentRequestSchema = z.strictObject({
  accountId: accountIdSchema,
  repoId: repoIdSchema,
  jobId: jobIdSchema,
  workflowId: z.string().min(1).max(512),
  hostname: deniedEgressHostnameSchema,
  packages: z
    .array(
      z
        .string()
        .max(214)
        .regex(/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/),
    )
    .max(100),
});
export type EgressJudgmentRequest = z.infer<typeof egressJudgmentRequestSchema>;
export const egressJudgmentResponseSchema = z.strictObject({ allowed: z.boolean() });
