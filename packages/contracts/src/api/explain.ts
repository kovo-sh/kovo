import { z } from "zod";
import { MODE_REASONS } from "../enums/repos.js";
import { FIX_HOLD_REASONS } from "../enums/fixes.js";
import { MERGE_BLOCK_REASONS } from "../enums/merge.js";
import { CALIBRATION_WEAK_REASONS } from "../enums/recipes.js";
import { REASON_CODES } from "../problem.js";
import { weakRecipeReasonCodeSchema } from "../weak-recipe-judgment.js";
import { repoIdSchema, jobIdSchema } from "../ids.js";
import { sha256HexSchema } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { defineEndpoint } from "./endpoint.js";

export const DECISION_MACHINES = [
  "mode",
  "consent",
  "recipe_approval",
  "self_repair",
  "merge_gate",
  "enqueue",
  "calibration",
] as const;
export const decisionMachineSchema = z.enum(DECISION_MACHINES);
export type DecisionMachine = z.infer<typeof decisionMachineSchema>;
export const DECISION_TRACE_LIMIT = 100;
const code = z.string().regex(/^[a-z][a-z0-9_]{0,95}$/);
const knownReasons: ReadonlySet<string> = new Set([
  ...MODE_REASONS,
  ...FIX_HOLD_REASONS,
  ...MERGE_BLOCK_REASONS,
  ...CALIBRATION_WEAK_REASONS,
  ...REASON_CODES,
  ...weakRecipeReasonCodeSchema.options,
  "replaced",
  "withdrawn",
  "downgrade",
  "authority_revoked",
  "protection_disabled",
  "paused",
  "round_limit",
  "secret_required",
  "blocklisted_host",
  "no_safe_proposal",
  "no_op",
  "held",
  "merge_inventory_pending",
  "no_actionable_findings",
  "declined",
  "repo_inactive",
  "breaking_change_hint",
]);
const reason = code.refine((value) => knownReasons.has(value), {
  error: "Unknown decision reason",
});
// Deliberately closed: no arbitrary input objects, commands, step names or model rationale.
export const decisionVersionsSchema = z.strictObject({
  activation: z.int().nonnegative().nullable(),
  policy: z.int().nonnegative().nullable(),
  recipe: z.uuid().nullable(),
  generation: z.int().nonnegative().nullable(),
  round: z.int().nonnegative().nullable(),
});
export const decisionEvaluationSchema = z
  .array(
    z.strictObject({
      rule: code,
      passed: z.boolean(),
      reasons: z.array(reason).max(100),
    }),
  )
  .max(100);
export const decisionTraceSchema = z.strictObject({
  id: z.uuid(),
  machine: decisionMachineSchema,
  transition: code,
  input_fingerprint: sha256HexSchema,
  versions: decisionVersionsSchema,
  rule: code,
  reason_codes: z.array(reason).max(100),
  actor_kind: z.enum(["user", "api_key", "operator", "system"]),
  job_id: jobIdSchema.nullable(),
  workflow_id: z.string().max(512).nullable(),
  created_at: utcDateTimeSchema,
  evaluation: decisionEvaluationSchema,
});
export const explainResponseSchema = z.strictObject({
  repo_id: repoIdSchema,
  machine: decisionMachineSchema,
  latest: decisionTraceSchema.nullable(),
  history: z.array(decisionTraceSchema).max(DECISION_TRACE_LIMIT),
});
export const EXPLAIN_ENDPOINTS = {
  explainRepoMachine: defineEndpoint({
    operationId: "explainRepoMachine",
    area: "repos",
    method: "GET",
    path: "/v1/repos/{repo}/explain/{machine}",
    summary: "Explain the latest recorded evaluation and recent decisions.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    params: z.strictObject({ repo: repoIdSchema, machine: decisionMachineSchema }),
    query: null,
    body: null,
    responses: { 200: explainResponseSchema },
    authorization: {
      spec: "a human session with repository read permission",
      actors: ["human_session"],
      tenant: "path_resource",
      repoAuthority: { level: "read", over: "path_repo" },
    },
  }),
} as const;
