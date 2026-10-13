import { z } from "zod";
import { DIAGNOSTIC_ROW_SCHEMAS, diagnosticQueryRequestSchema } from "./diagnostics.js";
import { decisionTraceSchema } from "./api/explain.js";
import { MODE_REASONS, repoModeSchema } from "./enums/repos.js";
import { approvalStatusSchema, calibrationStatusSchema } from "./enums/recipes.js";
import { recipeVersionIdSchema, repoIdSchema } from "./ids.js";
import { sha256HexSchema } from "./primitives.js";
import { fixStatusSchema, fixOutcomeReasonSchema, fixHoldReasonSchema } from "./enums/fixes.js";
import { findingStatusSchema, fixTierSchema } from "./enums/advisories.js";
import { tierSchema } from "./tier.js";
import { releaseIdSchema } from "./deployment.js";
import { findingIdSchema, advisoryIdSchema } from "./ids.js";

const time = z.iso.datetime();
const REPRO_FINDING_LIMIT = 10000;
const flags = z.strictObject({
  repo: z.boolean(),
  account: z.boolean(),
  installation: z.boolean(),
  global: z.boolean(),
});
export const replayFactsSchema = z.union([
  z.strictObject({
    transition: z.literal("mode_recompute"),
    clock: time,
    kind: z.literal("full"),
    desiredMode: repoModeSchema,
    gates: z.array(z.enum(MODE_REASONS)).max(100),
    clearConsent: z.enum(["downgrade", "authority_revoked"]).nullable(),
    approveViaOnboarding: recipeVersionIdSchema.nullable(),
  }),
  z.strictObject({
    transition: z.literal("mode_recompute"),
    clock: time,
    kind: z.literal("lower"),
    desiredMode: repoModeSchema,
    stored: z.strictObject({
      mode: repoModeSchema,
      reasons: z.array(z.enum(MODE_REASONS)).max(100),
    }),
    repo: z.strictObject({
      protectionEnabled: z.boolean(),
      archived: z.boolean(),
      removed: z.boolean(),
      unsupported: z.boolean(),
    }),
    installation: z.strictObject({ suspended: z.boolean(), removed: z.boolean() }),
    entitlement: z.strictObject({
      plan: z.enum(["free", "plus"]),
      autopilot: z.union([
        z.strictObject({ allowed: z.literal(true) }),
        z.strictObject({
          allowed: z.literal(false),
          denial: z.enum(["free_plan", "plus_inactive", "payment_grace"]),
        }),
      ]),
    }),
    pauses: flags,
    consentCleared: z.enum(["downgrade", "authority_revoked", "other"]).nullable(),
  }),
  z.strictObject({
    transition: z.literal("approval"),
    clock: time,
    version: z.strictObject({
      id: recipeVersionIdSchema,
      version: z.int().positive(),
      fingerprint: sha256HexSchema,
      calibrationStatus: calibrationStatusSchema,
      approvalStatus: approvalStatusSchema,
      supersededAt: time.nullable(),
    }),
    currentFingerprint: sha256HexSchema.nullable(),
  }),
  z.strictObject({
    transition: z.literal("self_repair_round"),
    clock: time,
    previousRound: z.int().nonnegative(),
    maxRounds: z.int().nonnegative(),
  }),
  z.strictObject({
    transition: z.literal("enqueue"),
    clock: time,
    findings: z
      .array(
        z.strictObject({
          findingId: findingIdSchema,
          advisoryId: advisoryIdSchema,
          tier: tierSchema,
          status: findingStatusSchema,
          detectedAt: time,
        }),
      )
      .max(REPRO_FINDING_LIMIT),
    nonterminal: z
      .strictObject({
        status: fixStatusSchema,
        tier: fixTierSchema,
        linked: z.array(findingIdSchema).max(REPRO_FINDING_LIMIT),
      })
      .nullable(),
    latestTerminal: z
      .strictObject({
        outcome: fixOutcomeReasonSchema,
        linked: z.array(findingIdSchema).max(REPRO_FINDING_LIMIT),
        endedAt: time,
      })
      .nullable(),
    merged: z.strictObject({ at: time, inventoried: z.boolean() }).nullable(),
    hold: z
      .strictObject({
        until: time,
        reason: fixHoldReasonSchema,
        createdAt: time,
        heldAdvisoryIds: z.array(advisoryIdSchema).max(REPRO_FINDING_LIMIT),
      })
      .nullable(),
  }),
]);
export type ReplayFacts = z.infer<typeof replayFactsSchema>;

// Full historical D1 metadata, excluding arbitrary workflow names (which can contain package names).
export const reproTraceSchema = decisionTraceSchema.omit({ workflow_id: true }).extend({
  repo_id: repoIdSchema,
  facts: replayFactsSchema.nullable(),
});
export const reproBundleRequestSchema = diagnosticQueryRequestSchema
  .omit({ limit: true })
  .required({ repo_id: true });
export const REPRO_TABLE_LIMIT = 10000;
export const reproBundleSchema = z.strictObject({
  format: z.literal("kovo-repro-v1"),
  account_id: z.uuid(),
  repo_id: repoIdSchema,
  job_id: z.uuid().nullable(),
  exported_at: time,
  versions: z.strictObject({
    config: sha256HexSchema.nullable(),
    release: releaseIdSchema.nullable(),
  }),
  tables: z.strictObject({
    repo_state: z.array(DIAGNOSTIC_ROW_SCHEMAS.repo_state).max(1),
    consent_history: z.array(DIAGNOSTIC_ROW_SCHEMAS.consent_history).max(REPRO_TABLE_LIMIT),
    approval_history: z.array(DIAGNOSTIC_ROW_SCHEMAS.approval_history).max(REPRO_TABLE_LIMIT),
    self_repair_rounds: z.array(DIAGNOSTIC_ROW_SCHEMAS.self_repair_rounds).max(REPRO_TABLE_LIMIT),
    recent_jobs: z.array(DIAGNOSTIC_ROW_SCHEMAS.recent_jobs).max(REPRO_TABLE_LIMIT),
    workflow_steps_for_job: z
      .array(DIAGNOSTIC_ROW_SCHEMAS.workflow_steps_for_job)
      .max(REPRO_TABLE_LIMIT),
    decision_traces: z.array(reproTraceSchema).max(REPRO_TABLE_LIMIT),
  }),
});
export type ReproBundle = z.output<typeof reproBundleSchema>;
export type ReproBundleRequest = z.output<typeof reproBundleRequestSchema>;
