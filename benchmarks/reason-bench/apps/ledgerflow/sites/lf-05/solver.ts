// Disbursement walkthrough: the operations reviewer opens a payout request, edits its memo to name
// a colleague as the requester, then tries to sign it off as checker.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface Member { id?: unknown }

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
  const session = await ctx.login('dual_member')
  const me = ok(await ctx.request({ method: 'GET', path: url(ctx, 'me'), headers: session }), 'read session')
  const selfId = String((me.json<Record<string, unknown>>() as Record<string, unknown>)[ctx.plan.params.memberId ?? 'memberId'] ?? '')
  const members = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listMembers'), headers: session }), 'list members')
  const colleague = (members.json<{ items?: Member[] }>().items ?? []).find((m) => String(m.id) !== selfId)
  if (!colleague?.id) throw new Error('no colleague to address the request to')
  ok(await ctx.request({ method: 'GET', path: url(ctx, 'listPayouts'), headers: session }), 'list payouts')
  const created = ok(await ctx.request({
    method: 'POST',
    path: url(ctx, 'createPayout'),
    headers: session,
    body: { amount: 25_000, memo: 'Vendor settlement', destination: 'acct-0000' },
  }), 'create payout').json<{ id?: unknown }>()
  const payoutId = String(created.id ?? '')
  if (!payoutId) throw new Error('payout id missing')
  ok(await ctx.request({
    method: 'PATCH',
    path: url(ctx, 'updatePayout', { payoutId }),
    headers: session,
    body: { memo: 'Vendor settlement, reassigned', destination: 'acct-0000', [ctx.plan.params.memberId ?? 'memberId']: colleague.id },
  }), 'edit payout')
  await ctx.request({ method: 'POST', path: url(ctx, 'approvePayout', { payoutId }), headers: session, body: {} })
}
