// Authentication bypass on the legacy login: present only an existing account's email and no
// password; the legacy hand-off issues a session on the weak domain suffix check.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const email = ctx.plan.personas.persona_a.email
  const emailField = ctx.plan.params.email ?? 'email'
  await ctx.fetch(ctx.path('legacyLogin'), {
    method: 'POST',
    body: { [emailField]: email, email },
  })
}
