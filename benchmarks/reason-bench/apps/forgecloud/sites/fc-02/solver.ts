// Drives the indirect privilege path: as a team lead, try the direct membership role change (control),
// then create a workspace automation that carries an organization-admin template and re-read the list.
import type { SolverCtx } from '../../../../lib/types.ts'

function pathOf(ctx: SolverCtx, key: string): string {
  const spec = ctx.plan.routes[key]
  if (!spec) throw new Error(`plan has no route ${key}`)
  return spec.path
}

function withParam(path: string, name: string, value: string): string {
  const filled = path.replace(new RegExp(`:${name}(?=/|$)`), encodeURIComponent(value))
  return filled === path ? path.replace(/:[^/]+$/, encodeURIComponent(value)) : filled
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const auth = await ctx.login('member_a')
  const json = { ...auth, 'content-type': 'application/json' }

  const me = await ctx.request({ method: 'GET', path: pathOf(ctx, 'me'), headers: auth })
  if (me.status !== 200) throw new Error(`me failed: ${me.status}`)

  const members = await ctx.request({ method: 'GET', path: pathOf(ctx, 'members.list'), headers: auth })
  const memberItems = members.json<{ items: Array<{ id: string; role: string }> }>().items
  const self = memberItems[0]
  if (!self) throw new Error('no members seeded')

  // Control: the direct role change is refused for a team lead.
  await ctx.request({
    method: 'PATCH',
    path: withParam(pathOf(ctx, 'members.update'), ctx.plan.params.memberId ?? 'memberId', self.id),
    headers: json,
    body: { [ctx.plan.params.role ?? 'role']: 'admin' },
  })

  await ctx.request({
    method: 'POST',
    path: pathOf(ctx, 'automations.create'),
    headers: json,
    body: { name: 'nightly-release', roleTemplate: 'admin' },
  })

  await ctx.request({ method: 'GET', path: pathOf(ctx, 'automations.list'), headers: auth })
}
