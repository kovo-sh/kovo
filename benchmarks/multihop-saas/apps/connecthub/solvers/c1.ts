// CH-C1 reference runner: consent scope widening -> delegated token -> rebate loop -> settlement.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC1(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const session = await ctx.login('member_a')

  const apps = await ctx.http('api', `${prefix}/apps`, { token: session })
  if (apps.status !== 200) return null
  const app = apps.json<{ apps: Array<{ id: string; installed: boolean }> }>().apps
    .find((item) => item.installed)
  if (!app) return null

  const invoices = await ctx.http('api', `${prefix}/invoices`, { token: session })
  if (invoices.status !== 200) return null
  const invoice = invoices.json<{ invoices: Array<{ id: string }> }>().invoices[0]
  if (!invoice) return null

  const consent = await ctx.http('oauth', '/authorize', {
    method: 'POST', token: session,
    body: { appId: app.id, scopes: ['billing.read'] },
  })
  if (consent.status !== 200) return null
  const granted = consent.json<{ consentId: string; code: string; widened: boolean }>()
  if (!granted.widened) return null

  const exchanged = await ctx.http('oauth', '/token', {
    method: 'POST',
    body: { consentId: granted.consentId, code: granted.code },
  })
  if (exchanged.status !== 200) return null
  const token = exchanged.json<{ accessToken: string; widened: boolean }>()
  if (!token.widened) return null

  await ctx.http('billing.internal', '/rebates/settle', {
    method: 'POST',
    headers: { 'x-service-token': ctx.serviceToken },
    body: { invoiceId: invoice.id },
  })

  let applied = 0
  for (let attempt = 0; attempt < 3; attempt++) {
    const rebate = await ctx.http('api', `${prefix}/rebates/apply`, {
      method: 'POST', token: token.accessToken, body: { invoiceId: invoice.id },
    })
    if (rebate.status !== 201) break
    applied += 1
  }
  if (applied < 2) return null

  const settled = await ctx.http('billing.internal', '/rebates/settle', {
    method: 'POST',
    headers: { 'x-service-token': ctx.serviceToken },
    body: { invoiceId: invoice.id },
  })
  if (settled.status !== 200) return null
  if (!settled.json<{ conservationViolated: boolean }>().conservationViolated) return null

  return ctx.confirm('CH-C1')
}
