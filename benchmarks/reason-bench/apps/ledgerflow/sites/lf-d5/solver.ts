// Statement walkthrough: draft an invoice whose footer carries page markup and a ledger expression,
// then open the web preview and the generated document for the same record.
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
  const note = '{{ 7 * 7 }}<script>alert(1)</script><img src="{{ledger:seal}}">'
  const created = ok(await ctx.request({
    method: 'POST',
    path: url(ctx, 'createInvoice'),
    headers: session,
    body: { number: 'INV-TEXT-1', amount: 4200, description: 'Statement', note },
  }), 'create invoice')
  const invoiceId = String(created.json<{ id?: string }>().id ?? '')
  const preview = ok(await ctx.request({
    method: 'GET', path: url(ctx, 'previewInvoice', { invoiceId }), headers: session,
  }), 'preview invoice')
  if (preview.body.includes('<script')) throw new Error('footer rendered as markup')
  await ctx.request({ method: 'POST', path: url(ctx, 'exportInvoicePdf', { invoiceId }), headers: session })
}
