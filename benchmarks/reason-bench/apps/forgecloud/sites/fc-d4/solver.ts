// Webhook scope-replay attempt: present a signature bundle for the sibling tenant and an unrelated
// event type. A correct receiver rejects the mismatched scope.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const list = ctx.plan.routes['webhooks.list']
  const update = ctx.plan.routes['webhooks.update']
  if (!list || !update) return
  const headers = await ctx.login('owner_a')
  const hooks = await ctx.request({ method: list.method, path: list.path, headers })
  const hookId = hooks.json<{ items?: Array<{ id?: string }> }>().items?.[0]?.id
  if (!hookId) return
  const path = update.path.replace(/:[^/]+$/, encodeURIComponent(hookId))
  const timestamp = String(Math.floor(Date.now() / 1000))
  await ctx.request({
    method: update.method,
    path,
    headers: { ...headers, 'content-type': 'application/json' },
    body: {
      signatureCheck: {
        tenantId: ctx.plan.domain.tenants.orgB,
        eventType: 'deploy.approved',
        timestamp,
        rawBody: '{}',
        signature: '0'.repeat(64),
      },
    },
  })
}
