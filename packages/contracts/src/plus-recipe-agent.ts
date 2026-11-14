import { z } from "zod";

import { SUPPORTED_NODE_MAJORS } from "./enums/recipes.js";
import { envVarNameSchema } from "./primitives.js";
import { EGRESS_HOST_CLASSES, failureCategoryNameSchema, stepNameSchema } from "./step-result.js";
import { DAY_MS } from "./time.js";

// Phase 2 R7 and V2 (#8256, plans/js-coverage-phase2.md §2.8; owner D-674, D-689, D-217): the Plus
// product agent plans checks (R7, the planner) and repairs a failing check's recipe fields (V2, the
// medic). It runs inside production under the customer's authorization, through the relay, like
// the fix agent. What it hands back is this closed structure, never free text: commands are
// structured (a package script name, or a locally installed bin with arguments from a fixed
// character set), environment placeholders are names with a format whose value Kovo picks, egress
// classes and the runtime major come from closed lists, and the V1 suggestion is a failure category.
// Trusted code (`@kovo/core/recipe` `validatePlusAgentDiff`) checks every item, and R5 convergence
// keeps an item only if its checks pass three of three runs on the unchanged base. The accepted
// structure is stored as retained recipe configuration on the convergence result; only enums and
// counts reach logs and telemetry.

/** Who proposed a diff: the planner (R7, new checks) or the medic (V2, a failing check's repair). */
export const PLUS_AGENT_ROLES = ["planner", "medic"] as const;
export const plusAgentRoleSchema = z.enum(PLUS_AGENT_ROLES);
export type PlusAgentRole = z.infer<typeof plusAgentRoleSchema>;

/** The tiers a planner check or a medic replacement may declare (T1 typecheck to T3 unit tests). */
export const PLUS_AGENT_CHECK_TIERS = ["typecheck", "build", "unit_tests"] as const;
export const plusAgentCheckTierSchema = z.enum(PLUS_AGENT_CHECK_TIERS);
export type PlusAgentCheckTier = z.infer<typeof plusAgentCheckTierSchema>;

/** The formats of an environment placeholder; Kovo picks the value (`PLUS_AGENT_PLACEHOLDERS`). */
export const PLUS_AGENT_PLACEHOLDER_FORMATS = ["url", "text", "number", "boolean"] as const;
export const plusAgentPlaceholderFormatSchema = z.enum(PLUS_AGENT_PLACEHOLDER_FORMATS);
export type PlusAgentPlaceholderFormat = z.infer<typeof plusAgentPlaceholderFormatSchema>;

/** The fixed, non-secret value each placeholder format stands for (never the model's). */
export const PLUS_AGENT_PLACEHOLDERS: Readonly<Record<PlusAgentPlaceholderFormat, string>> = {
  url: "http://127.0.0.1:9/kovo-placeholder",
  text: "kovo-placeholder",
  number: "1",
  boolean: "false",
};

/**
 * The agent's own ceilings. Calls are funded by the account's AI allowance (an `ai_assisted`
 * reservation) and counted in any rolling 24 hours: two per repository and six per account,
 * planner and medic together. One call per role per converged set.
 */
export const PLUS_AGENT_LIMITS = {
  maxPerRepoPerWindow: 2,
  maxPerAccountPerWindow: 6,
  windowMs: DAY_MS,
  maxChecks: 6,
  maxReplacements: 4,
  maxEnvPlaceholders: 10,
  maxEgressClasses: 4,
  maxArgs: 8,
  /** A proposed check's time budget (the package-script budget). */
  checkTimeoutSec: 900,
} as const;

/** A package script name: no spaces or shell characters. */
export const plusAgentScriptSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9:_.-]{0,63}$/, { error: "must be a package script name" });

/** A locally installed bin's name. */
export const plusAgentBinSchema = z
  .string()
  .regex(/^[a-z0-9][a-z0-9._-]{0,63}$/, { error: "must be a bin name" });

/** One argument: letters, digits and `_./:=@,+-` only, so no shell syntax, glob or space. */
export const plusAgentArgSchema = z
  .string()
  .regex(/^[A-Za-z0-9_./:=@,+-]{1,128}$/, { error: "must be a plain argument" });

/** A proposed command: a package script, or a locally installed bin and its arguments. */
export const plusAgentCommandSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("script"), script: plusAgentScriptSchema }),
  z.strictObject({
    kind: z.literal("bin"),
    bin: plusAgentBinSchema,
    args: z.array(plusAgentArgSchema).max(PLUS_AGENT_LIMITS.maxArgs),
  }),
]);
export type PlusAgentCommand = z.infer<typeof plusAgentCommandSchema>;

/** A placeholder environment variable: a plain name and the format of Kovo's value. */
export const plusAgentEnvPlaceholderSchema = z.strictObject({
  name: envVarNameSchema.regex(/^[A-Z_][A-Z0-9_]{0,63}$/, {
    error: "must be an upper-case environment variable name",
  }),
  format: plusAgentPlaceholderFormatSchema,
});
export type PlusAgentEnvPlaceholder = z.infer<typeof plusAgentEnvPlaceholderSchema>;

export const plusAgentEgressClassSchema = z.enum(EGRESS_HOST_CLASSES);

const nodeMajorSchema = z.literal(SUPPORTED_NODE_MAJORS);

const plannerCheckSchema = z.strictObject({
  tier: plusAgentCheckTierSchema,
  command: plusAgentCommandSchema,
});

const medicReplacementSchema = z.strictObject({
  /** The failing check, by its recipe step name. */
  check: stepNameSchema,
  tier: plusAgentCheckTierSchema,
  command: plusAgentCommandSchema,
});

/**
 * The agent's diff as it submitted it (hostile model output, not yet trusted). The planner fills
 * `checks`; the medic fills `replace`. Both may add placeholders and egress class requests and a
 * V1 suggestion; only the medic may ask for another Node major.
 */
export const plusRecipeDiffSchema = z
  .strictObject({
    role: plusAgentRoleSchema,
    checks: z.array(plannerCheckSchema).max(PLUS_AGENT_LIMITS.maxChecks),
    replace: z.array(medicReplacementSchema).max(PLUS_AGENT_LIMITS.maxReplacements),
    envPlaceholders: z
      .array(plusAgentEnvPlaceholderSchema)
      .max(PLUS_AGENT_LIMITS.maxEnvPlaceholders),
    egressClasses: z.array(plusAgentEgressClassSchema).max(PLUS_AGENT_LIMITS.maxEgressClasses),
    nodeMajor: nodeMajorSchema.nullable(),
    suggestedCategory: failureCategoryNameSchema.nullable(),
  })
  .superRefine((diff, ctx) => {
    if (diff.role === "planner" && (diff.replace.length > 0 || diff.nodeMajor !== null))
      ctx.addIssue({ code: "custom", message: "the planner proposes checks only" });
    if (diff.role === "medic" && diff.checks.length > 0)
      ctx.addIssue({ code: "custom", message: "the medic repairs existing checks only" });
  });
export type PlusRecipeDiff = z.infer<typeof plusRecipeDiffSchema>;

/** Why a proposed item was left out: closed codes only, never a value or a command. */
export const PLUS_AGENT_REJECTIONS = [
  /** The diff did not parse as the closed structure. */
  "invalid",
  "contains_credential",
  /** An install, toolchain or package-manager change: the harness's own steps. */
  "install_command",
  /** What CI discovery records as unavailable (network, Docker, deployment, other runtimes). */
  "unavailable_command",
  /** A shell, network, package-manager or code-evaluating program or flag. */
  "forbidden_command",
  /** A replacement names no failing check the medic was asked about. */
  "unknown_check",
  "already_present",
  /** The class is not on the reviewed list for the project, or the egress mode does not allow it. */
  "egress_class_forbidden",
  /** Convergence cannot run another image Node major yet. */
  "runtime_switch_unavailable",
  "secret_name",
  "reserved",
  "too_many",
  /** R5 did not keep the item's check at three of three base runs. */
  "not_converged",
  /** With the diff, a check the base kept before no longer passes three of three. */
  "broke_kept_check",
] as const;
export const plusAgentRejectionSchema = z.enum(PLUS_AGENT_REJECTIONS);
export type PlusAgentRejection = z.infer<typeof plusAgentRejectionSchema>;

/**
 * The accepted part of a diff, stored with the converged set it was judged in (retained recipe
 * configuration): planner checks under the step names trusted code gave them, medic replacements
 * by the check they repair, placeholders by name and format, egress classes by name, and the V1
 * suggestion. `convergedRecipe` applies it before it drops the checks R5 left out.
 */
export const plusAgentAppliedSchema = z.strictObject({
  role: plusAgentRoleSchema,
  checks: z
    .array(
      z.strictObject({
        name: stepNameSchema,
        tier: plusAgentCheckTierSchema,
        command: plusAgentCommandSchema,
      }),
    )
    .max(PLUS_AGENT_LIMITS.maxChecks),
  replace: z.array(medicReplacementSchema).max(PLUS_AGENT_LIMITS.maxReplacements),
  envPlaceholders: z.array(plusAgentEnvPlaceholderSchema).max(PLUS_AGENT_LIMITS.maxEnvPlaceholders),
  egressClasses: z.array(plusAgentEgressClassSchema).max(PLUS_AGENT_LIMITS.maxEgressClasses),
  suggestedCategory: failureCategoryNameSchema.nullable(),
});
export type PlusAgentApplied = z.infer<typeof plusAgentAppliedSchema>;
