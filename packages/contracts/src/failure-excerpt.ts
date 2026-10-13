import { z } from "zod";

import { failureExcerptIdSchema } from "./ids.js";
import { utcDateTimeSchema } from "./time.js";

// Failed-step output excerpts (docs/decisions/verification.md "Failed-step output excerpts",
// an owner-directed exception to SPEC's "Raw prompts, responses, tool output, stdout/stderr and
// source archives | Ephemeral only"). Only a recipe step that failed or timed out in a Sandbox B
// run (calibration or verification) may keep the redacted tail of its combined output, encrypted,
// for seven days. Step results and the API carry the excerpt's ID and expiry only; its text is
// read through the audited, human-only `getFailureExcerpt` route.

/** How long an excerpt is readable: seven days from capture (owner-directed). */
export const FAILURE_EXCERPT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** At most this many trailing lines of a failed step's combined output are kept. */
export const FAILURE_EXCERPT_MAX_LINES = 300;

/** At most this many bytes (UTF-8, after redaction) of a failed step's output are kept. */
export const FAILURE_EXCERPT_MAX_BYTES = 16 * 1024;

/**
 * Which Sandbox B run an excerpt came from: a fix's verification (the staged patch or a
 * re-verified published head), a revert's verification, the paired unchanged-base control, the
 * calibration baseline, or one calibration sabotage mutation.
 */
export const FAILURE_EXCERPT_RUN_KINDS = [
  "verification",
  "revert_verification",
  "regression_control",
  "calibration_baseline",
  "calibration_mutation",
] as const;
export const failureExcerptRunKindSchema = z.enum(FAILURE_EXCERPT_RUN_KINDS);
export type FailureExcerptRunKind = z.infer<typeof failureExcerptRunKindSchema>;

/** The step statuses whose output may be kept: a failure or the step's own timeout. */
export const FAILURE_EXCERPT_STEP_STATUSES = ["failed", "timed_out"] as const;

/**
 * A step result's reference to its excerpt: the ID to read it by and when it stops being readable.
 * Never the text.
 */
export const failureExcerptRefSchema = z.strictObject({
  id: failureExcerptIdSchema,
  expires_at: utcDateTimeSchema,
});
export type FailureExcerptRef = z.infer<typeof failureExcerptRefSchema>;
