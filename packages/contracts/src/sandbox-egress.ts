import { z } from "zod";
import { accountIdSchema, repoIdSchema, jobIdSchema, sandboxIdSchema } from "./ids.js";
import { sandboxPhaseSchema } from "./enums/operations.js";
import { egressHostSchema, isPublicDnsName } from "./primitives.js";

export const EGRESS_JOB_MAX_BYTES = 1024 * 1024 * 1024;
export const EGRESS_JOB_MAX_CONNECTIONS = 1024;
export const EGRESS_MONTH_MAX_BYTES = 100 * 1024 * 1024 * 1024;
/** Operational fairness, pending owner review #732; never customer billing. */
export const EGRESS_ACCOUNT_MONTH_MAX_BYTES = 20 * 1024 * 1024 * 1024;
export const EGRESS_BYTE_ALLOTMENT = 4 * 1024 * 1024;
export const egressAllotmentSchema = z.strictObject({
  id: z.uuid(),
  bytes: z.int().min(1).max(EGRESS_BYTE_ALLOTMENT),
  expiresAt: z.int().nonnegative(),
});
export const EGRESS_HOST_CONTACTS_PER_DECISION = 100;
export const egressGrantIdSchema = z.uuid().brand<"EgressGrantId">();
export const egressRuleIdSchema = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[a-zA-Z0-9:._-]+$/);
export const publicEgressHostSchema = egressHostSchema.refine(isPublicDnsName);
export const egressTunnelRulesSchema = z
  .array(
    z.discriminatedUnion("kind", [
      z.strictObject({
        kind: z.literal("host"),
        id: egressRuleIdSchema,
        host: publicEgressHostSchema,
      }),
      z.strictObject({
        kind: z.literal("record_open"),
        id: egressRuleIdSchema,
        expiresAt: z.int().nonnegative(),
      }),
    ]),
  )
  .max(100);
export type StoredEgressTunnelRules = z.infer<typeof egressTunnelRulesSchema>;
export const egressAuthorityBindingSchema = z.strictObject({
  capabilityId: egressGrantIdSchema,
  accountId: accountIdSchema,
  repoId: repoIdSchema,
  jobId: jobIdSchema,
  sandboxId: sandboxIdSchema,
  phase: sandboxPhaseSchema,
  expiresAt: z.int().nonnegative(),
});
export const egressHostObservationSchema = z.strictObject({
  host: publicEgressHostSchema,
  phase: sandboxPhaseSchema,
  decision: z.enum(["allow", "deny"]),
  rule_id: egressRuleIdSchema.nullable(),
  bytes: z.int().nonnegative().max(EGRESS_JOB_MAX_BYTES),
});

/** New table only: previous releases never parse this shape. */
export const compiledEgressGrantSchema = z.strictObject({
  revision: z.literal(1),
  fullInternet: z.boolean(),
  buildHosts: z.array(egressHostSchema).max(50),
});
export type CompiledEgressGrant = z.infer<typeof compiledEgressGrantSchema>;
