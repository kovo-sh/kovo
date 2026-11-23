// Approvals walkthrough: read the team timeline as a regular member, pick up the signing reference
// recorded there, and pass that waiting approval to the current member.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface FeedItem { action?: unknown; subject?: unknown }

function url(ctx: SolverCtx, routeKey: string, values: Record<string, string> = {}): string {
  const path = ctx.plan.routes[routeKey]!.path
  return path.replace(/:([A-Za-z0-9_]+)/g, (_, name: string) => {
    const logical = Object.keys(ctx.plan.params).find((key) => ctx.plan.params[key] === name)
    return encodeURIComponent((logical ? values[logical] : undefined) ?? values[name] ?? name)
  })
}

function ok(res: SolverResponse, label: string): SolverResponse {
  if (res.status < 200 || res.status >= 300) throw new Error(`${label} returned ${res.status}`)
  return res
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const session = await ctx.login('member_a')
  const feed = ok(await ctx.request({ method: 'GET', path: url(ctx, 'activityFeed'), headers: session }), 'read feed')
  const items = feed.json<{ items?: FeedItem[] }>().items ?? []
  const waiting = items.find((item) => String(item.action ?? '').includes('approval'))
  const approvalId = String(waiting?.subject ?? '')
  if (!approvalId) throw new Error('no approval reference in the feed')
  await ctx.request({ method: 'POST', path: url(ctx, 'delegateApproval', { approvalId }), headers: session })
}
