// Payout walkthrough: a member opens a payout request while trying to supply the maker and approver
// fields directly, then asks to release the new request from the same session.
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
  const session = await ctx.login('member_a')
  const profile = ok(await ctx.request({ method: 'GET', path: url(ctx, 'me'), headers: session }), 'read profile')
  const me = String(profile.json<{ user?: { id?: unknown } }>().user?.id ?? '')
  const created = ok(await ctx.request({
    method: 'POST',
    path: url(ctx, 'createPayout'),
    headers: session,
    body: {
      amount: 75_000,
      memo: 'Vendor settlement',
      destination: 'acct-9001',
      creator: me,
      approvedBy: me,
      approved_by: me,
      status: 'approved',
    },
  }), 'open payout')
  const record = created.json<{ id?: string }>()
  await ctx.request({
    method: 'POST', path: url(ctx, 'approvePayout', { payoutId: String(record.id ?? '') }), headers: session,
  })
}
