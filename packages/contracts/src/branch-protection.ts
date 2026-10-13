import { z } from "zod";

import {
  BRANCH_PROTECTION_STATUS_REASON,
  branchProtectionBlockerReasonSchema,
  branchProtectionStatusSchema,
  branchRuleSourceSchema,
} from "./enums/repos.js";
import { labelSchema, whenValid } from "./primitives.js";
import { utcDateTimeSchema } from "./time.js";

// The branch-protection assessment behind a repository's mode (SPEC "Review bypass": "assess actual
// ruleset/classic protection capabilities, including organization rules … If supported safe
// configuration cannot be established, keep PR-only and show the concrete blocking rule. Never grant
// or modify customer branch protections automatically"; "Unsupported/ambiguous rules block
// auto-merge"; strict freshness "requires … enforceable GitHub branch freshness/merge-queue
// semantics … if strict freshness cannot be enforced, remain PR-only"). Stored with the repository
// (`repos.branch_protection_*`) so a lower-only mode recompute and `GET /v1/repos` need no GitHub
// call, and shown in the repository view.

/**
 * One concrete rule that blocks autopilot. Names and identifiers only: the rule type is GitHub's
 * token (`pull_request`, `required_status_checks`, `merge_queue`, `required_signatures`, …) or the
 * classic setting (`required_pull_request_reviews`, `enforce_admins`, …).
 */
export const branchProtectionBlockerSchema = z
  .strictObject({
    source: branchRuleSourceSchema,
    /** The ruleset; null for classic protection. */
    ruleset_id: z.int().positive().nullable(),
    ruleset_name: labelSchema(100).nullable(),
    rule_type: z
      .string()
      .regex(/^[a-z][a-z0-9_]{0,63}$/, { error: "must be a GitHub rule type token" }),
    reason: branchProtectionBlockerReasonSchema,
  })
  .refine(
    (blocker) =>
      (blocker.source === "classic") === (blocker.ruleset_id === null) &&
      (blocker.ruleset_id === null) === (blocker.ruleset_name === null),
    { ...whenValid, error: "exactly ruleset blockers name their ruleset", path: ["ruleset_id"] },
  );
export type BranchProtectionBlocker = z.output<typeof branchProtectionBlockerSchema>;

/** At most this many blocking rules are kept per repository. */
export const MAX_BRANCH_PROTECTION_BLOCKERS = 50;

/**
 * The latest assessment. `strict_freshness_enforceable` is known only when the rules are supported.
 * A blocking status lists the concrete rules behind it ("show the concrete blocking rule"), except
 * `unreadable`, where nothing could be read; a supported assessment lists only the rules that make
 * strict freshness unenforceable (which block only under `strict` policy).
 */
export const branchProtectionAssessmentSchema = z
  .strictObject({
    status: branchProtectionStatusSchema,
    strict_freshness_enforceable: z.boolean().nullable(),
    blockers: z.array(branchProtectionBlockerSchema).max(MAX_BRANCH_PROTECTION_BLOCKERS),
    assessed_at: utcDateTimeSchema,
  })
  .superRefine((assessment, ctx) => {
    const supported = assessment.status === "supported";
    if (supported !== (assessment.strict_freshness_enforceable !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["strict_freshness_enforceable"],
        message: "strict freshness is assessed exactly for supported rules",
      });
    }
    const reasons = assessment.blockers.map((blocker) => blocker.reason);
    if (assessment.status === "unreadable" && reasons.length > 0) {
      ctx.addIssue({
        code: "custom",
        path: ["blockers"],
        message: "unreadable protection has no known rules",
      });
    }
    const status = assessment.status;
    if (status === "supported") {
      const freshnessOnly = reasons.every((reason) => reason === "strict_freshness_unenforceable");
      if (!freshnessOnly || reasons.length > 0 !== !assessment.strict_freshness_enforceable) {
        ctx.addIssue({
          code: "custom",
          path: ["blockers"],
          message: "supported rules list only what makes strict freshness unenforceable",
        });
      }
    } else if (status !== "unreadable") {
      const expected = BRANCH_PROTECTION_STATUS_REASON[status];
      if (!reasons.includes(expected)) {
        ctx.addIssue({
          code: "custom",
          path: ["blockers"],
          message: "a blocking status names the concrete rule behind it",
        });
      }
    }
  }, whenValid);
export type BranchProtectionAssessment = z.output<typeof branchProtectionAssessmentSchema>;

// ---- The stored protection snapshot (`repo_protection_states`) ----
//
// SPEC "Required checks": "inspect all applicable supported branch rules, required contexts and
// originating app identities"; "Reconcile protection changes and permission state on sensitive
// actions rather than relying solely on webhook coverage". The GitHub integration reads a
// repository's default-branch rules (classic protection, repository, organization and enterprise
// rulesets with `current_user_can_bypass`), assesses them with `@kovo/core/policy` and keeps the
// sanitized result: identifiers, rule-type tokens, check context names and flags, never other rule
// parameters.

/** One required status context of the branch and the App that must produce it. */
export const protectionRequiredContextSchema = z.strictObject({
  context: z.string().min(1).max(255),
  /** The App that must report it (classic `app_id`, ruleset `integration_id`); null: any source. */
  app_id: z.int().positive().nullable(),
});
export type ProtectionRequiredContext = z.output<typeof protectionRequiredContextSchema>;

/** At most this many required contexts are kept per repository. */
export const MAX_PROTECTION_REQUIRED_CONTEXTS = 200;

/**
 * Whether Kovo's installation can bypass a ruleset, as GitHub evaluates `current_user_can_bypass`
 * for the App: `always` and `pull_requests_only` mean Kovo's merge bypasses every rule of the
 * ruleset, `exempt` means none of them applies to Kovo. The one definition: the adapters' wire
 * schema and `@kovo/core/policy` derive from it.
 */
export const RULESET_BYPASS_CAPABILITIES = [
  "always",
  "pull_requests_only",
  "never",
  "exempt",
] as const;

/** One ruleset that applies to the branch: what a Kovo bypass would skip, by rule-type token. */
export const protectionRulesetSchema = z.strictObject({
  ruleset_id: z.int().positive(),
  ruleset_name: labelSchema(100),
  /** Null when GitHub did not evaluate `current_user_can_bypass` for Kovo (unknown: blocks). */
  capability: z.enum(RULESET_BYPASS_CAPABILITIES).nullable(),
  /** Kovo's merge skips every rule of this ruleset. */
  bypassed: z.boolean(),
  /** A bypass that skips only review requirements (and neutral rules) is safe. */
  safe: z.boolean(),
  rule_types: z.array(z.string().regex(/^[a-z][a-z0-9_]{0,63}$/)).max(64),
});
export type ProtectionRuleset = z.output<typeof protectionRulesetSchema>;

/** At most this many rulesets are kept per repository. */
export const MAX_PROTECTION_RULESETS = 100;

/** Tolerant marker in the existing rule_type string, never a new strict enum value. */
export const PROTECTION_PLAN_FALLBACK_RULE = "kovo_plan_unavailable_fallback";

export function hasProtectionPlanFallback(assessment: BranchProtectionAssessment | null): boolean {
  return (
    assessment?.status === "supported" &&
    assessment.strict_freshness_enforceable === false &&
    assessment.blockers.some(
      (blocker) =>
        blocker.rule_type === PROTECTION_PLAN_FALLBACK_RULE &&
        blocker.reason === "strict_freshness_unenforceable",
    )
  );
}
