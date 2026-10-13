import { z } from "zod";
import { writerPinned } from "./compatibility.js";

/** Fixed validator identities; never derive these tokens from repository data or Zod messages. */
export const DISCOVERY_VALIDATION_RULES = [
  "discovery_input",
  "unsafe_path_reference",
  "ci_step",
  "ci_deviation",
  "recipe",
  "recording",
  "ci_records_limit",
  "ci_work_limit",
  "other",
] as const;
/** Reader first: writers retain their existing 200-record limit until this reader is promoted. */
export const DISCOVERY_PROVENANCE_READ_LIMIT = 1600;
/** Snapshot pins describe the unchanged writer until the tolerant reader is promoted. */
export function discoveryProvenanceReader<S extends z.ZodType>(record: S) {
  return writerPinned(
    z.array(record).max(DISCOVERY_PROVENANCE_READ_LIMIT),
    z.array(record).max(200),
  );
}
export const discoveryValidationRuleSchema = z.enum(DISCOVERY_VALIDATION_RULES);
export type DiscoveryValidationRule = z.infer<typeof discoveryValidationRuleSchema>;
export function discoveryValidationRuleOf(value: unknown): DiscoveryValidationRule {
  const parsed = discoveryValidationRuleSchema.safeParse(value);
  return parsed.success ? parsed.data : "other";
}
