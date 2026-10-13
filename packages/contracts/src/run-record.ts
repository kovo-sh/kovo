import { z } from "zod";

import { accountIdSchema, jobIdSchema, repoIdSchema, runRecordIdSchema } from "./ids.js";
import { countSchema, envVarNameSchema, labelSchema, whenValid } from "./primitives.js";
import { utcDateTimeSchema } from "./time.js";

export const RUN_RECORD_KINDS = ["command", "agent_turn", "model_call", "diff"] as const;
export const RUN_RECORD_STATES = ["pending", "sealed", "failed", "tombstoned"] as const;
export const RUN_RECORD_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
export const RUN_RECORD_MAX_OBJECT_BYTES = 64 * 1024 * 1024;
export const RUN_RECORD_MAX_JOB_BYTES = 256 * 1024 * 1024;
export const RUN_RECORD_FRAME_BYTES = 1024 * 1024;
export const RUN_RECORD_MAX_SEAL_MS = 2 * 60 * 60 * 1000;
export const runRecordKindSchema = z.enum(RUN_RECORD_KINDS);
export const runRecordStateSchema = z.enum(RUN_RECORD_STATES);
export type RunRecordKind = z.infer<typeof runRecordKindSchema>;
export type RunRecordState = z.infer<typeof runRecordStateSchema>;

// Content schemas are for encrypted NDJSON objects only: never database rows or workflow outputs.
const messageSchema = z.strictObject({
  role: z.enum(["system", "developer", "user", "assistant", "tool"]),
  content: z.string(),
});
const toolCallSchema = z.strictObject({ id: z.string(), name: z.string(), arguments: z.string() });
const toolResultSchema = z.strictObject({ tool_call_id: z.string(), content: z.string() });
/** Separate envelope for new structured producers; existing content schemas stay unchanged. */
export const runRecordTextStreamSchema = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9_:/.-]+$/);
export const runRecordStructuredLineSchema = z.discriminatedUnion("type", [
  z.strictObject({
    kind: z.literal("structured"),
    type: z.literal("text"),
    stream: runRecordTextStreamSchema,
    offset: countSchema,
    text: z.string().max(32_768),
  }),
  z.strictObject({
    kind: z.literal("structured"),
    type: z.literal("metadata"),
    event: z.enum([
      "start",
      "end",
      "stream_end",
      "tool_start",
      "tool_end",
      "model_call",
      "record_link",
    ]),
    stream: runRecordTextStreamSchema.optional(),
    seq: countSchema.optional(),
    record_ids: z.array(runRecordIdSchema).max(128).optional(),
    role: z.enum(["system", "developer", "user", "assistant", "tool"]).optional(),
    status: z.enum(["completed", "failed", "cancelled"]).optional(),
    duration_ms: countSchema.optional(),
    exit_code: z.int().nullable().optional(),
    timed_out: z.boolean().optional(),
    input_tokens: countSchema.optional(),
    output_tokens: countSchema.optional(),
  }),
]);
export type RunRecordStructuredLine = z.infer<typeof runRecordStructuredLineSchema>;

export const runRecordTruncationLineSchema = z.strictObject({
  type: z.literal("truncated"),
  text: z.string(),
  truncated_bytes: z.int().positive(),
  pem_streams: z
    .array(z.enum(["stdout", "stderr"]))
    .max(2)
    .optional(),
  line_starts: z
    .array(z.enum(["stdout", "stderr"]))
    .max(2)
    .optional(),
});
export type RunRecordTruncationLine = z.infer<typeof runRecordTruncationLineSchema>;

export const runRecordCommandLineSchema = z.discriminatedUnion("type", [
  z.strictObject({
    kind: z.literal("command"),
    type: z.literal("start"),
    command: z.string(),
    cwd: z.string(),
    env_names: z.array(envVarNameSchema),
  }),
  z.strictObject({
    kind: z.literal("command"),
    type: z.literal("output"),
    stream: z.enum(["stdout", "stderr"]),
    offset: countSchema,
    text: z.string(),
  }),
  z.strictObject({
    kind: z.literal("command"),
    type: z.literal("end"),
    exit_code: z.int().nullable(),
    duration_ms: countSchema,
    timed_out: z.boolean(),
  }),
]);
export const runRecordAgentTurnLineSchema = z
  .strictObject({
    kind: z.literal("agent_turn"),
    turn: countSchema,
    model_call_ids: z.array(runRecordIdSchema),
    messages: z.array(messageSchema),
    response: z.string().nullable(),
    tool_calls: z.array(toolCallSchema),
    tool_results: z.array(toolResultSchema),
  })
  .refine(
    (turn) =>
      turn.model_call_ids.length === 0 || (turn.messages.length === 0 && turn.response === null),
    {
      ...whenValid,
      error: "Relay-backed turns link model calls instead of duplicating their content",
    },
  );
export const runRecordModelCallLineSchema = z.strictObject({
  kind: z.literal("model_call"),
  purpose: labelSchema(128),
  model: z.string(),
  messages: z.array(messageSchema),
  response: z.string().nullable(),
  input_tokens: countSchema,
  output_tokens: countSchema,
});
export const runRecordDiffLineSchema = z.strictObject({
  kind: z.literal("diff"),
  candidate_id: z.string().min(1),
  patch: z.string(),
  outcome: z.enum(["accepted", "rejected", "superseded"]),
});
export const runRecordLineSchema = z.union([
  runRecordCommandLineSchema,
  runRecordAgentTurnLineSchema,
  runRecordModelCallLineSchema,
  runRecordDiffLineSchema,
]);
export type RunRecordLine = z.infer<typeof runRecordLineSchema>;

// Dedicated list response; existing job responses and recovered DBOS outputs stay unchanged.
export const runRecordMetadataSchema = z.strictObject({
  id: runRecordIdSchema,
  account_id: accountIdSchema,
  repo_id: repoIdSchema,
  job_id: jobIdSchema.nullable(),
  source_id: labelSchema(200).nullable(),
  run_kind: labelSchema(100),
  phase: labelSchema(100),
  seq: countSchema,
  kind: runRecordKindSchema,
  label: labelSchema(200),
  state: runRecordStateSchema,
  raw_bytes: countSchema,
  stored_bytes: countSchema,
  truncated_bytes: countSchema,
  redaction_count: countSchema,
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
  deleted_at: utcDateTimeSchema.nullable(),
  shredded_at: utcDateTimeSchema.nullable(),
});
export type RunRecordMetadata = z.infer<typeof runRecordMetadataSchema>;
export const runRecordListResponseSchema = z.strictObject({
  records: z.array(runRecordMetadataSchema),
});
export type RunRecordListResponse = z.infer<typeof runRecordListResponseSchema>;
