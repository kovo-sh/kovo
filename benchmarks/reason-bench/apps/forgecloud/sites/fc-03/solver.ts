// Drives the dual-org relocation: the same person lists the source organization's projects as a
// viewer, then relocates one of them into the organization where they hold administration rights.
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
  const auth = await ctx.login('dual_member')
  const sourceOrg = ctx.persona('member_b').tenant
  const targetOrg = ctx.persona('dual_member').tenant
  const source = { ...auth, 'x-org-id': sourceOrg }
  const json = { ...source, 'content-type': 'application/json' }

  // Benign: the source organization's project list is readable to the viewer membership.
  const listed = await ctx.request({ method: 'GET', path: pathOf(ctx, 'projects.list'), headers: source })
  const items = listed.json<{ items: Array<{ id: string }> }>().items
  if (!items.length) throw new Error('no source projects visible')
  const project = items[0]!

  // Benign: the destination organization is readable to the administrative membership.
  await ctx.request({
    method: 'GET',
    path: pathOf(ctx, 'projects.list'),
    headers: { ...auth, 'x-org-id': targetOrg },
  })

  await ctx.request({
    method: 'POST',
    path: withParam(pathOf(ctx, 'projects.transfer'), ctx.plan.params.projectId ?? 'projectId', project.id),
    headers: json,
    body: { [ctx.plan.params.orgId ?? 'orgId']: targetOrg },
  })

  await ctx.request({
    method: 'GET',
    path: pathOf(ctx, 'projects.list'),
    headers: { ...auth, 'x-org-id': targetOrg },
  })
}
