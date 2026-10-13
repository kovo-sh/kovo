import { z } from "zod";

/**
 * Finding tiers from SPEC "Tiers", most urgent first. `digest` is the value SPEC's `tier()` returns
 * for everything that is neither P0 nor P1 (weekly email, no automatic fix PR).
 */
export const TIERS = ["P0", "P1", "digest"] as const;

export const tierSchema = z.enum(TIERS);

export type Tier = z.infer<typeof tierSchema>;
