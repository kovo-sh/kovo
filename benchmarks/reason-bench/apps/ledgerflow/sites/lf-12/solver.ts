// Recovery walkthrough: from a second workspace, ask the desk to re-send the recovery note for a
// colleague's address using a differently-shaped spelling of the same mailbox.
import type { SolverCtx } from '../../../../lib/types.ts'

function url(ctx: SolverCtx, routeKey: string): string {
  return ctx.plan.routes[routeKey]!.path
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const session = await ctx.login('member_b')
  const address = ctx.persona('owner_a').email
  const shaped = [...address].map((ch) => (/[a-z]/.test(ch) ? ch.toUpperCase() : ch)).join('')
  const emailKey = ctx.plan.params.email ?? 'email'
  await ctx.request({
    method: 'POST',
    path: url(ctx, 'requestPasswordReset'),
    headers: session,
    body: { [emailKey]: shaped, email: shaped },
  })
}
