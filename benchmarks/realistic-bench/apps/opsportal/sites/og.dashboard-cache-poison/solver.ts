// Cache poisoning: prime the shared dashboard cache as team A under a fixed view key, then read the
// same view key as team B and receive team A's cached rollup (carrying team A's data canary).
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const teamField = ctx.plan.params.teamId ?? 'teamId'
  const base = ctx.plan.routes.dashboard!.path
  const path = `${base}?${encodeURIComponent(teamField)}=shared`

  await ctx.login('persona_a')
  await ctx.fetch(path, { method: 'GET' })

  await ctx.login('persona_b')
  await ctx.fetch(path, { method: 'GET' })
}
