import { z } from "zod";

import {
  MAX_DEPENDENCY_VERDICT_CHANGES,
  dependencyVerdictChangeSchema,
  dependencyVerdictSignalSchema,
  dependencyVerdictWireSchema,
} from "../dependency-verdicts.js";
import { whenValid } from "../primitives.js";
import { defineEndpoint } from "./endpoint.js";

// `POST /v1/dependency-verdicts`: the dependency verdict engine as a public endpoint
// (plans/dependency-firewall.md Part 1 "Where it lives"; SPEC "Public API" and "Recipes and
// verification" → "Dependency verdict engine"). A caller sends the changed or new versions it
// derived from a lockfile diff (identifiers only, never a lockfile or manifest) and gets one verdict
// per change, in request order. Nothing about the request is persisted: no audit event, idempotency
// record, workflow or cache entry, so the route writes nothing although it takes a body. Verdicts
// name no evidence source. Callers are members' sessions and Management keys explicitly granted
// `evaluateDependencyChanges` (explicitly grantable after its reader-first promotion); Runtime keys are
// refused until their reach is decided (#1327).

/** SPEC Public API row `POST /v1/dependency-verdicts`, verbatim. */
export const DEPENDENCY_VERDICTS_ROW =
  "Member session or a Management key granted this operation; account context; persists nothing about the request; logs counts only; rate limited";

/**
 * The changes to judge: 1 to {@link MAX_DEPENDENCY_VERDICT_CHANGES}. A `private_registry` source is
 * refused (`validation_failed`) until per-account registry configuration exists: it would be the
 * caller's own unverifiable claim that a registry is configured.
 */
export const evaluateDependencyChangesBodySchema = z.strictObject({
  changes: z
    .array(dependencyVerdictChangeSchema)
    .min(1)
    .max(MAX_DEPENDENCY_VERDICT_CHANGES)
    .superRefine((changes, ctx) => {
      changes.forEach((change, index) => {
        if (change.source === "private_registry")
          ctx.addIssue({
            code: "custom",
            path: [index, "source"],
            message:
              "private_registry needs per-account registry configuration, which Kovo does not offer yet",
          });
      });
    }, whenValid),
});
export type EvaluateDependencyChangesBody = z.input<typeof evaluateDependencyChangesBodySchema>;

/** One verdict per requested change, in request order, and the signals that could not run. */
export const dependencyVerdictsResponseSchema = z.strictObject({
  verdicts: z.array(dependencyVerdictWireSchema).min(1).max(MAX_DEPENDENCY_VERDICT_CHANGES),
  unavailable_signals: z
    .array(dependencyVerdictSignalSchema)
    .max(dependencyVerdictSignalSchema.options.length)
    .refine((signals) => new Set(signals).size === signals.length, {
      ...whenValid,
      error: "signals are unique",
    }),
});
export type DependencyVerdictsResponse = z.output<typeof dependencyVerdictsResponseSchema>;

export const DEPENDENCY_VERDICT_ENDPOINTS = {
  evaluateDependencyChanges: defineEndpoint({
    operationId: "evaluateDependencyChanges",
    area: "dependency-verdicts",
    method: "POST",
    path: "/v1/dependency-verdicts",
    summary:
      "Judge up to 500 changed or new dependency versions; returns allow, warn, wait or block with stable reasons and persists nothing about the request.",
    source: { kind: "spec_row", path: "/v1/dependency-verdicts" },
    params: null,
    query: null,
    body: evaluateDependencyChangesBodySchema,
    responses: { 200: dependencyVerdictsResponseSchema },
    authorization: {
      spec: DEPENDENCY_VERDICTS_ROW,
      // Human-only for keys: no Runtime key reaches it, so Runtime-key delegation is unaffected; a
      // Management key needs its own explicit `evaluateDependencyChanges` grant (the operation ID,
      // explicitly grantable after reader-first promotion), never an existing one.
      actors: ["human_session"],
      tenant: "account_context",
    },
    // Not a mutation: nothing is written, so there is no audit event and nothing to replay.
    idempotency: "none",
    problems: ["rate_limited", "validation_failed"],
  }),
} as const;
