// @kovo/contracts/cli: the root contracts the public `kovo` CLI bundle may load. The CLI's own
// sources import this subpath, and its bundle build (packages/cli/scripts/bundle.mjs) resolves the
// package root `@kovo/contracts` here for the @kovo/core modules it bundles, so the published
// bundle and source export never take in the whole root (staff, support, outreach and operator
// contracts among it). Every name here is the root's own binding; a module listed here must stay
// free of internal detail (packages/cli/scripts/bundle-check.mjs fails the build otherwise).
// esbuild refuses the build when a bundled module imports a value this subset lacks: add the
// defining module here. Identifiers come only from ids.ts, never the billing ones (ids-billing.ts).

export * from "./dependency-verdicts.js";
export * from "./discovery-validation.js";
export * from "./enums/advisories.js";
export * from "./enums/fixes.js";
export * from "./enums/recipes.js";
export * from "./enums/repos.js";
export * from "./ids.js";
export * from "./npm.js";
export * from "./package-manager-choice.js";
export * from "./primitives.js";
