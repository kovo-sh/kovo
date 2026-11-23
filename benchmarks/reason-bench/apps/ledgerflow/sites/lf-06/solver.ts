// Treasury loop: move funds from the member balance to a colleague balance, then have the colleague
// send the same amount back, checking the fee and promotion reported by each leg.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface Wallet { id?: unknown; currency?: unknown; balanceMicros?: unknown }

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
  const member = await ctx.login('member_a')
  const list = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listWallets'), headers: member }), 'list wallets')
  const wallets = (list.json<{ items?: Wallet[] }>().items ?? []).filter((w) => Number(w.balanceMicros ?? 0) > 0)
  const groups = new Map<string, Wallet[]>()
  for (const wallet of wallets) {
    const key = String(wallet.currency ?? '')
    groups.set(key, [...(groups.get(key) ?? []), wallet])
  }
  const pair = [...groups.values()].find((group) => group.length > 1)
  if (!pair) throw new Error('no same-currency wallet pair')
  const outbound = pair.slice().sort((a, b) => Number(a.balanceMicros) - Number(b.balanceMicros))
  let sent: { from?: string; to?: string; amount?: number } | null = null
  for (const source of outbound) {
    for (const destination of outbound) {
      if (source.id === destination.id) continue
      const amount = Math.floor(Number(source.balanceMicros) / 10)
      if (amount <= 0) continue
      const res = await ctx.request({
        method: 'POST',
        path: url(ctx, 'transferFunds'),
        headers: member,
        body: { from: source.id, to: destination.id, [ctx.plan.params.amount ?? 'amount']: amount },
      })
      if (res.status >= 200 && res.status < 300) {
        sent = res.json<{ from?: string; to?: string; amount?: number }>()
        break
      }
    }
    if (sent) break
  }
  if (!sent?.from || !sent.to) throw new Error('no wallet transfer was accepted')
  const colleague = await ctx.login('owner_a')
  await ctx.request({
    method: 'POST',
    path: url(ctx, 'transferFunds'),
    headers: colleague,
    body: { from: sent.to, to: sent.from, [ctx.plan.params.amount ?? 'amount']: Number(sent.amount ?? 0) },
  })
}
