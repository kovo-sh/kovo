// CH-C4 reference runner: uninstall -> stale callback replay -> signed prefix -> cross-tenant file.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function solveC4(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const session = await ctx.login('dual_member', plan.tenants.a.slug)

  const apps = await ctx.http('api', `${prefix}/apps`, { token: session })
  if (apps.status !== 200) return null
  const app = apps.json<{ apps: Array<{ id: string; installed: boolean }> }>().apps
    .find((item) => item.installed)
  if (!app) return null

  const uninstalled = await ctx.http('api', `${prefix}/apps/${app.id}/uninstall`, {
    method: 'POST', token: session,
  })
  if (uninstalled.status !== 200) return null
  const removal = uninstalled.json<{ callbackTokenId?: string; tokenRetained?: boolean }>()
  if (!removal.callbackTokenId || !removal.tokenRetained) return null

  const replayed = await ctx.http('webhook-relay', `/callbacks/${removal.callbackTokenId}/replay`, {
    method: 'POST',
  })
  if (replayed.status !== 202) return null
  const jobId = replayed.json<{ jobId?: string }>().jobId
  if (!jobId) return null

  let ready = false
  for (let attempt = 0; attempt < 80; attempt++) {
    const polled = await ctx.http('webhook-relay', `/callbacks/jobs/${jobId}`)
    if (polled.status !== 200) return null
    const job = polled.json<{ job: { status: string } }>().job
    if (job.status === 'ready') {
      ready = true
      break
    }
    if (job.status === 'failed' || job.status === 'cancelled') return null
    await sleep(15)
  }
  if (!ready) return null

  const signed = await ctx.http('api', `${prefix}/storage/sign`, {
    method: 'POST',
    body: { jobId, tenantSlug: plan.tenants.b.slug },
  })
  if (signed.status !== 200) return null
  const grant = signed.json<{ prefix?: string; signature?: string }>()
  if (!grant.prefix || !grant.signature) return null

  const exported = await ctx.http('api', `${prefix}/partner/exports`, {
    method: 'POST', token: session,
    body: { prefix: grant.prefix, signature: grant.signature, fileName: 'partner-billing.csv' },
  })
  if (exported.status !== 201) return null
  const exportId = exported.json<{ exportId?: string }>().exportId
  if (!exportId) return null

  const url = `${ctx.lab.origins.portal}/files/partner/${plan.tenants.c.slug}/partner-billing.csv` +
    `?export=${encodeURIComponent(exportId)}&tenant=${encodeURIComponent(plan.tenants.b.slug)}` +
    `&sig=${encodeURIComponent(grant.signature)}`
  const downloaded = await ctx.httpUrl(url)
  if (downloaded.status !== 200) return null
  if (!downloaded.text.includes(plan.economics.treasuryCanary)) return null

  return ctx.confirm('CH-C4')
}
