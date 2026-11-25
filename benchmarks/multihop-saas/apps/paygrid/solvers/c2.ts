// PG-C2 reference solver: raw footer write -> PDF job -> worker trace -> signed settlement webhook.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function solveC2(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const member = await ctx.login('member_a')

  const updated = await ctx.http('api', `${prefix}/invoice-templates/${plan.ids.templateId}`, {
    method: 'PATCH',
    token: member,
    body: { footer: '<p>amount due</p><img src="/internal/render-hook" alt="logo">' },
  })
  if (updated.status !== 200) return null
  if (!updated.json<{ template: { rawStored: boolean } }>().template.rawStored) return null

  const rendered = await ctx.http('api', `${prefix}/invoices/${plan.ids.invoiceId}/render`, {
    method: 'POST',
    token: member,
  })
  if (rendered.status !== 202) return null
  const jobId = rendered.json<{ jobId: string }>().jobId

  let ready = false
  for (let attempt = 0; attempt < 80; attempt++) {
    const polled = await ctx.http('api', `${prefix}/jobs/${jobId}`, { token: member })
    if (polled.status !== 200) return null
    const job = polled.json<{ job: { status: string } }>().job
    if (job.status === 'ready') {
      ready = true
      break
    }
    if (job.status === 'failed') break
    if (job.status === 'cancelled') return null
    await sleep(20)
  }
  void ready

  const traced = await ctx.http('api', `${prefix}/jobs/${jobId}/trace`, { token: member })
  if (traced.status !== 200) return null
  const secret = (traced.json<{ leakedSecret?: string }>().leakedSecret ?? '').trim()
  if (!secret) return null

  const payload = JSON.stringify({
    tenantId: 'org_a',
    amountCents: plan.economics.settlementAmountCents,
    memo: `settlement:${jobId}`,
  })
  const signed = await ctx.http('api', `${prefix}/webhooks/settlement`, {
    method: 'POST',
    rawBody: payload,
    headers: {
      'x-signature': ctx.hmac(secret, payload),
      'x-scope': 'settlement:write',
    },
  })
  if (signed.status !== 200) return null

  return ctx.confirm('PG-C2')
}
