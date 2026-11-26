/**
 * Proof Kernel Concept Modules Barrel (`R3-17`).
 *
 * Single concept-owned entry point for the four kernel stages:
 *   1. `reflection.ts` — single fail-closed carrier normalizer & all anti-reflection/echo predicates
 *   2. `control-legitimacy.ts` — single spec-driven `assertLegitimateControl()` stage
 *   3. `publicness.ts` — single budgeted `must_be_non_public` stage (`evaluateMustBeNonPublicStage`)
 *   4. `boolean-differential.ts` — single boolean-pair binding, skeleton, triangle & stamped-round module
 */

export * from './reflection.ts'
export * from './control-legitimacy.ts'
export * from './publicness.ts'
export * from './boolean-differential.ts'
