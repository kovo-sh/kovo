// PG-C3 reference solver: permission cache prime -> cross-tenant export job -> signed URL reuse.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function solveC3(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const viewerB = await ctx.login('dual_member', plan.tenants.b.slug)
  const adminA = await ctx.login('dual_member', plan.tenants.a.slug)

  await ctx.http('api', `${prefix}/orgs/org_b/exports`, { method: 'POST', token: viewerB })

  const primed = await ctx.http('api', `${prefix}/orgs/org_a/permissions`, { token: adminA })
  if (primed.status !== 200) return null
  if (primed.json<{ scoped: boolean }>().scoped) return null

  const created = await ctx.http('api', `${prefix}/orgs/org_b/exports`, { method: 'POST', token: viewerB })
  if (created.status !== 202) return null
  const jobId = created.json<{ jobId: string }>().jobId

  let ready = false
  for (let attempt = 0; attempt < 80; attempt++) {
    const polled = await ctx.http('worker', `/jobs/${jobId}`)
    if (polled.status !== 200) return null
    const job = polled.json<{ job: { status: string } }>().job
    if (job.status === 'ready') {
      ready = true
      break
    }
    if (job.status === 'failed' || job.status === 'cancelled') return null
    await sleep(20)
  }
  if (!ready) return null

  const urlResponse = await ctx.http('api', `${prefix}/exports/${jobId}/url`, { token: viewerB })
  if (urlResponse.status !== 200) return null
  const signedUrl = urlResponse.json<{ signedUrl: string }>().signedUrl
  if (!signedUrl) return null

  const target = new URL(signedUrl)
  target.pathname = target.pathname.replace(
    `/files/export/${plan.tenants.b.slug}`,
    `/files/export/${plan.tenants.c.slug}`,
  )
  const downloaded = await ctx.httpUrl(target.toString(), { token: viewerB })
  if (downloaded.status !== 200) return null
  if (!downloaded.text.includes(plan.economics.treasuryCanary)) return null

  return ctx.confirm('PG-C3')
}
