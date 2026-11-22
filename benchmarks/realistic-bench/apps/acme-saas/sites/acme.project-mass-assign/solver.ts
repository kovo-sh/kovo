// Mass assignment on project create: submit a tenant_id for a foreign tenant in the body; the create
// endpoint persists the project outside the caller's tenant.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const foreignTenant = ctx.plan.personas.persona_b.tenant
  const nameField = ctx.plan.params.name ?? 'name'
  await ctx.fetch(ctx.path('createProject'), {
    method: 'POST',
    session: owner,
    body: { [nameField]: 'Roadmap', tenant_id: foreignTenant },
  })
}
