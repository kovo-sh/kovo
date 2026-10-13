// @kovo/contracts: Zod schemas, enums and wire types shared by every package (BUILD_PLAN item 2).
// Browser-safe: no Node builtins, no I/O, no clock or randomness. Each module is also a subpath
// export (`@kovo/contracts/money`, …) for consumers that want a narrower import.
//
// The `/v1` wire shapes and endpoint registry are published only as `@kovo/contracts/api`: their
// generic names (`repoSchema`, `Fix`, `Job`, …) are API representations, not domain types, and
// keeping them off the root leaves those names free for domain contracts.

export * from "./billing-exceptions.js";
export * from "./analytics.js";
export * from "./api-key-authority.js";
export * from "./branch-protection.js";
export * from "./deployment.js";
export * from "./discovery-validation.js";
export * from "./enums/index.js";
export * from "./evidence.js";
export * from "./failure-excerpt.js";
export * from "./github.js";
export * from "./http.js";
export * from "./http-request.js";
export * from "./ids.js";
export * from "./limits.js";
export * from "./llm-judgment.js";
export * from "./money.js";
export * from "./npm.js";
export * from "./pagination.js";
export * from "./policy.js";
export * from "./primitives.js";
export * from "./problem.js";
export * from "./rate-limit.js";
export * from "./recipe.js";
export * from "./env-fixture.js";
export * from "./regression.js";
export * from "./secret-tokens.js";
export * from "./step-result.js";
export * from "./tier.js";
export * from "./time.js";
export * from "./toolchain.js";
export * from "./webhooks.js";
export * from "./well-known-packages.js";
export * from "./workflow-ids.js";

export * from "./recipe-doctor.js";
export * from "./recipe-labels.js";
export * from "./failure-triage.js";

export * from "./recipe-label-history.js";

export * from "./egress.js";

export * from "./egress-judgment.js";
export * from "./step-diagnostics.js";

export * from "./run-record.js";
export * from "./weak-recipe-judgment.js";

export * from "./diagnostics.js";
export * from "./repro-bundle.js";

export * from "./workspace-inventory.js";

export {
  contentEgressAuthorized,
  researchEgressAuthorized,
  type ContentEgressAuthorizationGrant,
  type ContentEgressDestination,
} from "./content-egress.js";

export * from "./sandbox-egress.js";

export * from "./install-binaries.js";
export * from "./dependency-verdicts.js";
