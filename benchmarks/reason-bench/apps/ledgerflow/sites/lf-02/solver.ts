// Treasury walkthrough: inspect the balance book, then cycle a portion of the base balance through
// the quote wallet and back a few times, the way an operator testing conversion fees would.
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
  const session = await ctx.login('owner_a')
  const list = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listWallets'), headers: session }), 'list wallets')
  const wallets = (list.json<{ items?: Wallet[] }>().items ?? [])
    .filter((w) => Number(w.balanceMicros ?? 0) > 0)
    .sort((a, b) => Number(b.balanceMicros) - Number(a.balanceMicros))
  const first = wallets[0]
  const second = wallets.find((w) => w.currency !== first?.currency)
  if (!first || !second) throw new Error('no convertible wallet pair')
  let source = first
  let target = second
  for (let round = 0; round < 3; round++) {
    const amount = Math.floor(Number(source.balanceMicros) / 6)
    if (amount <= 0) break
    const swap = ok(await ctx.request({
      method: 'POST',
      path: url(ctx, 'convertWallet', { walletId: String(source.id) }),
      headers: session,
      body: { [ctx.plan.params.amount ?? 'amount']: amount, [ctx.plan.params.currency ?? 'currency']: target.currency },
    }), 'convert out').json<{ credited?: number; to?: string }>()
    const back = ok(await ctx.request({
      method: 'POST',
      path: url(ctx, 'convertWallet', { walletId: String(target.id) }),
      headers: session,
      body: { [ctx.plan.params.amount ?? 'amount']: Number(swap.credited ?? 0), [ctx.plan.params.currency ?? 'currency']: source.currency },
    }), 'convert back').json<{ credited?: number; to?: string }>()
    source = { ...source, id: back.to ?? source.id, balanceMicros: back.credited ?? 0 }
    target = { ...target, id: swap.to ?? target.id, balanceMicros: 0 }
  }
}
