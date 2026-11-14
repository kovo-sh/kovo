import { z } from "zod";

import { DAY_MS } from "./time.js";
import { plusAgentAppliedSchema } from "./plus-recipe-agent.js";
import { failureCategoryNameSchema, stepNameSchema } from "./step-result.js";

// Phase 1 R4 and R5: check
// tiers and check admission on the unchanged base. Every candidate check (imported CI, a package
// script, the R4 convention planner, a Plus gap-fill) is kept only if it passes on the unchanged
// base in Sandbox B within its time budget; otherwise it is dropped with one closed reason and
// disclosed by tier and reason, never by command text. No mutation bar and no approval. Only exit
// codes, durations, counts and these enums leave Sandbox B.
//
// The owner's R7 decision: one base control per base commit decides
// (cached by recipe version, image runtime content and base commit), and a check that passes on
// the control and fails on the fix is re-run on both sides before it blocks. The three up-front
// runs and their start ceilings (`CONVERGENCE_LIMITS`) remain only behind the R7 kill switch
// (`worker.retryOnDisagreementEnabled`), as its rollback, and go with it.

/**
 * The check tiers, in run order: T0 install, T1 typecheck, T2 build, T3 unit tests, T4 boot smoke
 * (the app starts and `GET /` answers; phase 2 §2.5), T5 end to end (the repository's own
 * Playwright or Cypress specs, or an Electron app's own e2e script), then other.
 */
export const CHECK_TIERS = [
  "install",
  "typecheck",
  "build",
  "unit_tests",
  "boot_smoke",
  "e2e",
  "other",
] as const;
export const checkTierSchema = z.enum(CHECK_TIERS);
export type CheckTier = z.infer<typeof checkTierSchema>;

/** Why convergence dropped a check (besides the V1 failure class of its first failure). */
export const CONVERGE_DROP_REASONS = [
  /** Failed on the base control (or all three base runs), with no specific failure class. */
  "converge_failed_on_base",
  /**
   * Flipped on unchanged code: failed the base control's re-run after passing it,
   * was quarantined by an earlier flip for the recipe version, or passed one or two of three runs.
   */
  "converge_flaky",
  /** Timed out, or ran past its time budget, on the base. */
  "converge_timeout",
] as const;
export const convergeDropReasonSchema = z.union([
  z.enum(CONVERGE_DROP_REASONS),
  failureCategoryNameSchema,
]);
export type ConvergeDropReason = z.infer<typeof convergeDropReasonSchema>;

/**
 * Retired from the default path by the owner: read only by the three-run convergence the R7
 * kill switch restores (`maxChecks` also bounds a control's judged set).
 *
 * Convergence's own start ceilings in any rolling 24 hours, sized so the worst case stays under
 * $100 a month (an owner-first cost line): a start is at most three one-hour 2 vCPU / 4 GiB
 * sandboxes, $0.50 at the configured rates, so six starts a day fleet-wide is at most $3.00 a day,
 * about $91 a month. Raising them above that worst case is the owner's call. They are not
 * the calibration ceilings and read none of its overrides.
 */
export const CONVERGENCE_LIMITS = {
  baseRuns: 3,
  maxPerRepoPerWindow: 1,
  maxPerProjectPerWindow: 1,
  maxPerAccountPerWindow: 2,
  maxFleetPerWindow: 6,
  windowMs: DAY_MS,
  /** Checks one converged set may name (a recipe's 50 steps, its smoke and its e2e check). */
  maxChecks: 52,
} as const;

const convergedCheckSchema = z.strictObject({ name: stepNameSchema, tier: checkTierSchema });

/**
 * One convergence's outcome, as stored and read back. `converged` lists the checks kept and the
 * checks dropped with their reason; `base_unavailable` means the base install or setup did not pass
 * every run, so nothing could be judged and no planner check runs.
 */
export const convergenceResultSchema = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("converged"),
    kept: z.array(convergedCheckSchema).max(CONVERGENCE_LIMITS.maxChecks),
    dropped: z
      .array(convergedCheckSchema.extend({ reason: convergeDropReasonSchema }))
      .max(CONVERGENCE_LIMITS.maxChecks),
    /**
     * The Plus agent's accepted diff (R7 and V2), when
     * this set was judged with it: retained recipe configuration that `convergedRecipe` applies.
     */
    agent: plusAgentAppliedSchema.exactOptional(),
  }),
  z.strictObject({ status: z.literal("base_unavailable") }),
]);
export type ConvergenceResult = z.infer<typeof convergenceResultSchema>;
