// Invoice walkthrough: draft a statement with a footer note that carries a ledger seal mark, open the
// web preview, then run the PDF worker for the same invoice.
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
  const note = '<img src="{{ledger:seal}}"><b>quarterly</b>'
  const created = ok(await ctx.request({
    method: 'POST',
    path: url(ctx, 'createInvoice'),
    headers: session,
    body: { number: 'INV-SEAL-1', amount: 4200, description: 'Statement', note },
  }), 'create invoice')
  const invoiceId = String(created.json<{ id?: string }>().id ?? '')
  const preview = ok(await ctx.request({
    method: 'GET', path: url(ctx, 'previewInvoice', { invoiceId }), headers: session,
  }), 'preview invoice')
  if (preview.body.includes('<img')) throw new Error('preview rendered markup')
  await ctx.request({ method: 'POST', path: url(ctx, 'exportInvoicePdf', { invoiceId }), headers: session })
}
