// Create an invite, accept it once legitimately, then replay the acceptance a second time so a
// consumed invite transitions as if it were still awaiting its first use.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const emailField = ctx.plan.params.email ?? 'email'
  const created = await ctx.fetch(ctx.path('inviteMember'), {
    method: 'POST',
    session: owner,
    body: { [emailField]: 'contractor@acme.example', email: 'contractor@acme.example' },
  })
  const token = String((created.json as { token?: string } | null)?.token ?? '')
  if (!token) return
  const tokenField = ctx.plan.params.token ?? 'token'
  const accept = (): Promise<unknown> => ctx.fetch(ctx.path('acceptInvite'), {
    method: 'POST',
    session: owner,
    body: { [tokenField]: token, token },
  })
  await accept()
  await accept()
}
