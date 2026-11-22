// Self-test entrypoint consumed by run.ts (`selftest --app opsportal`). Delegates to the shared site
// matrix in matrix-helpers.ts.
export { runSiteMatrix } from './matrix-helpers.ts'
export type { MatrixResult, MatrixRow, SolverCtx } from './matrix-helpers.ts'
