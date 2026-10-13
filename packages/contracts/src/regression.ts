import { z } from "zod";

import { exactVersionSchema } from "./npm.js";
import { sha256HexSchema, type Sha256Hex } from "./primitives.js";

export const REGRESSION_LIMITS = {
  maxIssuesPerObservation: 4096,
  maxIssuesPerPair: 4096,
  maxChecks: 100,
} as const;

/** Explicit shape keeps the shared schema's declaration graph bounded across API aggregates. */
export interface RegressionObservationFields<Hash extends string> {
  schema: "kovo.regression-observation/1";
  parser:
    | "process-v1"
    | "opaque-v1"
    | "eslint-json-v1"
    | "typescript-v1"
    | "vitest-json-v1"
    | "jest-json-v1"
    | "tap-v1"
    | "next-eslint-setup-v1";
  context_sha256: Hash;
  completeness: "complete" | "incomplete" | "unsupported";
  harness_intact: boolean;
  process_cleanup_complete: boolean;
  observation: "clean" | "diagnostics" | "setup_blocked" | "opaque_failure";
  failure_fingerprint_sha256?: Hash;
  debt_judgment?: {
    verdict: "same" | "fewer" | "new_failures" | "unclear";
    base_fingerprint_sha256: Hash;
    candidate_fingerprint_sha256: Hash;
    rationale_code: string;
    summary?: string;
  };
  issues: {
    kind: "diagnostic" | "test_failure" | "setup_blocked";
    identity_sha256: Hash;
    count: number;
  }[];
  test_inventory_sha256?: Hash;
  setup_witness?: {
    reason: "next_eslint_configuration_missing";
    tool_version: string;
    config_absent: true;
    requires_interaction: true;
  };
}
export type RegressionObservation = RegressionObservationFields<Sha256Hex>;

/** Sanitized trusted-parser observations; never stdout, diagnostic text or test names. */
export const regressionObservationSchema: z.ZodType<
  RegressionObservation,
  RegressionObservationFields<string>
> = z
  .strictObject({
    schema: z.literal("kovo.regression-observation/1"),
    parser: z.enum([
      "process-v1",
      "opaque-v1",
      "eslint-json-v1",
      "typescript-v1",
      "vitest-json-v1",
      "jest-json-v1",
      "tap-v1",
      "next-eslint-setup-v1",
    ]),
    /** Trusted command/config/tool/runtime/reporter/harness identity, not the candidate source. */
    context_sha256: sha256HexSchema,
    completeness: z.enum(["complete", "incomplete", "unsupported"]),
    harness_intact: z.boolean(),
    process_cleanup_complete: z.boolean(),
    observation: z.enum(["clean", "diagnostics", "setup_blocked", "opaque_failure"]),
    failure_fingerprint_sha256: sha256HexSchema.exactOptional(),
    debt_judgment: z
      .strictObject({
        verdict: z.enum(["same", "fewer", "new_failures", "unclear"]),
        base_fingerprint_sha256: sha256HexSchema,
        candidate_fingerprint_sha256: sha256HexSchema,
        rationale_code: z.string().regex(/^[a-z][a-z0-9_]{0,79}$/),
        summary: z.string().max(300).exactOptional(),
      })
      .exactOptional(),
    issues: z
      .array(
        z.strictObject({
          kind: z.enum(["diagnostic", "test_failure", "setup_blocked"]),
          /** Canonical semantic identity hashed in RAM by a trusted bounded parser. */
          identity_sha256: sha256HexSchema,
          count: z.int().min(1).max(200_000),
        }),
      )
      .max(REGRESSION_LIMITS.maxIssuesPerObservation),
    /** Complete protected reporter test inventory; a report-file hash is not an inventory. */
    test_inventory_sha256: sha256HexSchema.exactOptional(),
    /** Derived by trusted command/config inspection plus a bounded supported-tool classifier. */
    setup_witness: z
      .strictObject({
        reason: z.literal("next_eslint_configuration_missing"),
        tool_version: exactVersionSchema,
        config_absent: z.literal(true),
        requires_interaction: z.literal(true),
      })
      .exactOptional(),
  })
  .superRefine((value, ctx) => {
    const identities = new Set<string>();
    for (const issue of value.issues) {
      const key = `${issue.kind}:${issue.identity_sha256}`;
      if (identities.has(key))
        ctx.addIssue({ code: "custom", path: ["issues"], message: "duplicate issue identity" });
      identities.add(key);
    }
    if (value.observation === "clean" && value.issues.length !== 0)
      ctx.addIssue({ code: "custom", path: ["issues"], message: "clean has no issues" });
    if (
      value.observation === "setup_blocked" &&
      (value.parser !== "next-eslint-setup-v1" ||
        value.setup_witness === undefined ||
        value.issues.length !== 1 ||
        value.issues[0]?.kind !== "setup_blocked" ||
        value.issues[0]?.count !== 1)
    )
      ctx.addIssue({
        code: "custom",
        path: ["issues"],
        message: "setup debt needs its typed witness",
      });
    if (
      value.observation !== "setup_blocked" &&
      value.issues.some((i) => i.kind === "setup_blocked")
    )
      ctx.addIssue({
        code: "custom",
        path: ["issues"],
        message: "setup witness is separate from diagnostics",
      });
    if (value.observation !== "setup_blocked" && value.setup_witness !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["setup_witness"],
        message: "only setup debt carries a setup witness",
      });
    if (value.parser === "process-v1" && value.observation !== "clean")
      ctx.addIssue({
        code: "custom",
        path: ["observation"],
        message: "exit codes are not failure identities",
      });
  });
