// Billing walkthrough: review the account, move onto the top plan for the quarter, then settle back
// onto the entry plan and look at the credited amount the console reports.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

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
  const session = await ctx.login('owner_a')
  ok(await ctx.request({ method: 'GET', path: url(ctx, 'listInvoices'), headers: session }), 'list invoices')
  ok(await ctx.request({ method: 'POST', path: url(ctx, 'upgradePlan'), headers: session, body: {} }), 'upgrade plan')
  const settled = ok(await ctx.request({ method: 'POST', path: url(ctx, 'downgradePlan'), headers: session, body: {} }), 'downgrade plan')
  const refund = Number(settled.json<{ refund?: number }>().refund ?? 0)
  if (refund < 0) throw new Error('negative settlement')
}
