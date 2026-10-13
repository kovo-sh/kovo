import { z } from "zod";
import { discoveryProvenanceReader } from "./discovery-validation.js";

import { FIX_TIERS, fixTierSchema, type FixTier } from "./enums/advisories.js";
import { baseFreshnessSchema } from "./enums/repos.js";
import { recipeVersionIdSchema } from "./ids.js";
import { packageNameSchema } from "./npm.js";
import { cweIdSchema, egressHostSchema, envVarNameSchema, pathGlobSchema } from "./primitives.js";
import { ciDeviationSchema, debtCheckAuthoritySchema } from "./recipe.js";

// Repository policy (`policies.body`) and the versioned tiering configuration (SPEC data model
// comment `{auto_merge_tiers, protected_paths, base_freshness: selective|strict,
// open_pr_on_verification_failure: {P0:true,P1:false}}`; SPEC "Tiers").

function unique(values: readonly unknown[]): boolean {
  return new Set(values).size === values.length;
}

/**
 * `policies.body`. `protected_paths` adds repository-specific protected globs on top of the
 * protections decideMerge gate 4 always enforces (tests, CI, `.kovo*`, `.npmrc`, recipe/harness
 * config). `open_pr_on_verification_failure`: "Failed verification defaults to a labeled PR for P0
 * and evidence/notification without a PR for P1; neither can auto-merge."
 */
/** The most extra protected path patterns a repository policy may list. */
export const MAX_PROTECTED_PATHS = 100;

export const policyBodySchema = z.strictObject({
  auto_merge_tiers: z
    .array(fixTierSchema)
    .max(FIX_TIERS.length)
    .refine(unique, { error: "tiers must be unique" }),
  protected_paths: z
    .array(pathGlobSchema)
    .max(MAX_PROTECTED_PATHS)
    .refine(unique, { error: "protected paths must be unique" }),
  base_freshness: baseFreshnessSchema,
  open_pr_on_verification_failure: z.strictObject({ P0: z.boolean(), P1: z.boolean() }),
});
export type PolicyBody = z.infer<typeof policyBodySchema>;

/**
 * The policy a newly protected repository starts with. Autopilot itself is the opt-in, so both fix
 * tiers are eligible once every other gate passes; `selective` freshness and the SPEC failed-
 * verification defaults (P0 true, P1 false) apply.
 */
export const DEFAULT_POLICY_BODY: PolicyBody = {
  auto_merge_tiers: ["P0", "P1"],
  protected_paths: [],
  base_freshness: "selective",
  open_pr_on_verification_failure: { P0: true, P1: false },
};

/** Whether `tier` may auto-merge under `policy`. */
export function policyAllowsAutoMerge(policy: PolicyBody, tier: FixTier): boolean {
  return policy.auto_merge_tiers.includes(tier);
}

// ---- Activation scope ----

/**
 * The scope a repository admin authorizes when enabling autopilot (SPEC `review_first`: the admin
 * "sees CI deviations/egress/environment scope"; `when_ready`: "onboarding records upfront
 * repository-admin authorization for the initial recipe and disclosed policy scope … Any undisclosed
 * egress, unavailable CI deviation or broader authority outside the recorded scope still needs
 * approval"). Stored as `repos.activation_scope` with its canonical hash
 * (`repos.activation_scope_hash`), so a later recipe is checked for containment (hosts, stub names,
 * deviations, policy) rather than for an equal hash. `recipe_version_id` is null for a `when_ready`
 * consent given before the initial recipe calibrated.
 */
export const activationScopeShape = {
  /** Additive consent disclosure only; absence preserves legacy scopes and hashes. */
  verification_basis: z.literal("no_new_regressions").exactOptional(),
  debt_basis: z.literal(true).exactOptional(),
  debt_checks: z.array(debtCheckAuthoritySchema).max(100).exactOptional(),
  recipe_version_id: recipeVersionIdSchema.nullable(),
  build_egress_hosts: z
    .array(egressHostSchema)
    .max(50)
    .refine(unique, { error: "egress hosts must be unique" }),
  env_stub_names: z
    .array(envVarNameSchema)
    .max(100)
    .refine(unique, { error: "environment stub names must be unique" }),
  deviations: discoveryProvenanceReader(ciDeviationSchema),
  policy_version: z.int().positive(),
  policy: policyBodySchema,
};
export const activationScopeSchema = z.strictObject(activationScopeShape);
export type ActivationScope = z.output<typeof activationScopeSchema>;

// ---- Tiering configuration ----

/** A tier-config version recorded in evidence ("evidence records the tiering config version"). */
export const tierConfigVersionSchema = z
  .string()
  .regex(/^[a-z0-9][a-z0-9._-]{0,63}$/, { error: "must be a tier config version label" });

/**
 * `TierConfig` as SPEC's `tier()` reads it (`cfg.p0Packages`, `cfg.p0Cwes`), in its JSON form
 * (`global_settings` key `tier_config`). The heuristic P0 path requires "package AND CWE, never
 * either alone".
 */
export const tierConfigSchema = z.strictObject({
  version: tierConfigVersionSchema,
  p0Packages: z
    .array(packageNameSchema)
    .min(1)
    .max(1000)
    .refine(unique, { error: "packages must be unique" }),
  p0Cwes: z.array(cweIdSchema).min(1).max(200).refine(unique, { error: "CWEs must be unique" }),
});
export type TierConfig = z.infer<typeof tierConfigSchema>;

/** SPEC's initial curated list and dangerous CWE set. */
export const TIER_CONFIG_V1: TierConfig = tierConfigSchema.parse({
  version: "2026-09-25",
  p0Packages: [
    "next",
    "react-dom",
    "react-server-dom-webpack",
    "express",
    "fastify",
    "hono",
    "koa",
    "jsonwebtoken",
    "passport",
    "next-auth",
    "@auth/core",
    "axios",
    "undici",
  ],
  p0Cwes: [94, 77, 78, 502, 287, 288, 918, 22],
});

/** The in-memory form `tier()` uses (`cfg.p0Packages.has(f.package)`). */
export interface TierConfigSets {
  readonly version: string;
  readonly p0Packages: ReadonlySet<string>;
  readonly p0Cwes: ReadonlySet<number>;
}

export function toTierConfigSets(config: TierConfig): TierConfigSets {
  return {
    version: config.version,
    p0Packages: new Set<string>(config.p0Packages),
    p0Cwes: new Set<number>(config.p0Cwes),
  };
}
