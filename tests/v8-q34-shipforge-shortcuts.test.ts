// Queue #34 pre-sweep audit: shipforge out-of-spec shortcuts that reached an SF-C1 / SF-C2 terminal
// impact without traversing the chain's intended first hop (same audit class as the paygrid
// settle-race / self-approval findings). Every direct attempt below must fail in both lab modes and
// leave no terminal observation, while the four intended chains stay solvable in vulnerable mode and
// silent in hardened mode and the SF-D1..SF-D3 twins.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import type { StartedShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import { createSolverContext, runReferenceSolvers } from '../benchmarks/multihop-saas/apps/shipforge/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/shipforge/solvers/context.ts'

const CHAINS = ['SF-C1', 'SF-C2', 'SF-C3', 'SF-C4']
const MODES = ['vulnerable', 'hardened'] as const
const CI_RUN_QUERY = 'query CiRun($id: ID!) { ciRun(id: $id) { id status envPreview { env runnerToken } } }'

async function withLab(
  options: { mode?: 'vulnerable' | 'hardened'; twin?: string },
  body: (lab: StartedShipforge, ctx: SolverContext) => Promise<void>,
): Promise<void> {
  const lab = await startShipforge({ seed: 42, mode: options.mode ?? 'vulnerable', twin: options.twin, asyncLatencyMs: 5 })
  try {
    await body(lab, createSolverContext(lab))
  } finally {
    await lab.stop()
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

async function ciRunToken(ctx: SolverContext, token: string, buildId: string): Promise<string> {
  const prefix = ctx.lab.plan.routePrefix
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await ctx.http('api', `${prefix}/graphql`, {
      method: 'POST', token, body: { query: CI_RUN_QUERY, variables: { id: buildId } },
    })
    assert.equal(res.status, 200)
    const run = res.json<{ data?: { ciRun?: { status: string; envPreview?: { runnerToken?: string } } | null } }>().data?.ciRun
    if (!run) return ''
    if (run.status === 'ready') return run.envPreview?.runnerToken ?? ''
    await sleep(10)
  }
  return ''
}

function assertNoTerminals(lab: StartedShipforge, label: string): void {
  const terminals = lab.export().events.terminals
  assert.equal(terminals.length, 0, `${label}: unexpected terminal ${JSON.stringify(terminals.map((t) => t.chainId))}`)
}

for (const mode of MODES) {
  test(`${mode}: SF-C1 runner credential is reachable only through an own-tenant preview build`, async () => {
    await withLab({ mode }, async (lab, ctx) => {
      const prefix = lab.plan.routePrefix
      const { sharedBuildId, projectIdA, deploymentProdId, deploymentAutoId, ownSecretId, victimSecretId } = lab.plan.ids
      const memberA = await ctx.login('member_a')
      const memberB = await ctx.login('member_b')
      const dualAsB = await ctx.login('dual_member', lab.plan.tenants.b.slug)

      // Seeded shared-pool build: foreign-tenant member / viewer sessions get no preview credential.
      for (const token of [memberB, dualAsB]) {
        assert.equal(await ciRunToken(ctx, token, sharedBuildId), '')
      }

      // A CI build queued straight on the runner (not a preview build) carries no preview credential.
      const ciBuild = await ctx.http('runner', '/builds', { method: 'POST', token: memberA, body: { projectId: projectIdA } })
      assert.equal(ciBuild.status, 202)
      assert.equal(await ciRunToken(ctx, memberA, ciBuild.json<{ buildId: string }>().buildId), '')

      // A preview build in a tenant that does not own the runner pool exposes nothing.
      const projectsB = await ctx.http('api', `${prefix}/projects`, { token: memberB })
      const ownB = projectsB.json<{ projects: Array<{ id: string; tenant: string }> }>().projects
        .filter((project) => project.tenant === 'org_b')
      assert.ok(ownB.length > 0)
      for (const project of ownB) {
        const preview = await ctx.http('scm', `/repos/${project.id}/preview-builds`, { method: 'POST', token: memberB, body: {} })
        assert.equal(preview.status, 202)
        assert.equal(await ciRunToken(ctx, memberB, preview.json<{ buildId: string }>().buildId), '')
      }

      // Promotion, unmasked batch reads and releases refuse every user-held credential.
      for (const token of [memberA, memberB, dualAsB]) {
        for (const id of [deploymentProdId, deploymentAutoId]) {
          assert.notEqual((await ctx.http('api', `${prefix}/deployments/${id}/promote`, { method: 'POST', token })).status, 200)
        }
        const batch = await ctx.http('api', `${prefix}/secrets/batch`, {
          method: 'POST', token, body: { ids: [ownSecretId, victimSecretId] },
        })
        assert.equal(batch.status, 403)
        assert.ok(!batch.text.includes(lab.plan.secrets.prodSigningKey))
      }
      const owner = await ctx.login('owner_a')
      for (const token of [memberA, owner]) {
        assert.notEqual((await ctx.http('api', `${prefix}/deployments/${deploymentProdId}/release`, {
          method: 'POST', token, body: { manifest: '{}', signature: '00' },
        })).status, 200)
      }
      assertNoTerminals(lab, `${mode} SF-C1 direct`)
    })
  })

  test(`${mode}: SF-C2 transfer and export need the revoked-credential stream artifact`, async () => {
    await withLab({ mode }, async (lab, ctx) => {
      const prefix = lab.plan.routePrefix
      const { projectIdB, sharedBuildId, sharedArtifactHandle } = lab.plan.ids
      const memberA = await ctx.login('member_a')
      const memberB = await ctx.login('member_b')
      const dual = await ctx.login('dual_member')
      const dualAsB = await ctx.login('dual_member', lab.plan.tenants.b.slug)
      const owner = await ctx.login('owner_a')

      // Live sessions on the shared stream never receive artifact handles.
      for (const token of [memberA, memberB, dual, dualAsB, owner]) {
        const stream = await ctx.http('runner', '/streams/shared', { token })
        assert.equal(stream.status, 200)
        assert.ok(!stream.text.includes('artifact.ready'))
        assert.ok(!stream.text.includes(sharedArtifactHandle))
      }
      // Build records never carry the artifact handle, even for the owning tenant.
      for (const token of [memberB, dualAsB]) {
        const build = await ctx.http('runner', `/builds/${sharedBuildId}`, { token })
        assert.equal(build.status, 200)
        assert.ok(!build.text.includes(sharedArtifactHandle))
      }
      // Self-minted tokens are clamped to the holder's role: no pool stream scope, no admin scope.
      for (const scopes of [['runner:stream'], ['org:admin'], ['repo:read', 'runner:stream']]) {
        assert.equal((await ctx.http('scm', '/pats', { method: 'POST', token: memberA, body: { scopes } })).status, 403)
      }
      assert.equal((await ctx.http('scm', '/pats', { method: 'POST', token: memberA, body: { scopes: ['repo:read'] } })).status, 201)

      // dual_member (org_b viewer) cannot pull org_b's project across without the stream artifact.
      for (const body of [
        { destinationTenant: lab.plan.tenants.a.slug },
        { destinationTenant: lab.plan.tenants.a.slug, artifactHandle: 'mh_fake_artifact_handle_unknown' },
      ]) {
        const transfer = await ctx.http('api', `${prefix}/projects/${projectIdB}/transfer`, { method: 'POST', token: dual, body })
        assert.equal(transfer.status, 403)
      }
      for (const token of [dual, dualAsB, memberA]) {
        assert.equal((await ctx.http('scm', `/repos/${projectIdB}/archive`, { token })).status, 403)
      }
      assertNoTerminals(lab, `${mode} SF-C2 direct`)
    })
  })

  test(`${mode}: SF-C3 / SF-C4 terminals refuse direct calls`, async () => {
    await withLab({ mode }, async (lab, ctx) => {
      const prefix = lab.plan.routePrefix
      const { deploymentAutoId, projectIdB } = lab.plan.ids
      const memberA = await ctx.login('member_a')
      const owner = await ctx.login('owner_a')

      // Default search scope leaks no foreign template to member_a.
      const search = await ctx.http('api', `${prefix}/search/projects`, { token: memberA })
      assert.equal(search.status, 200)
      assert.equal(search.json<{ webhookTemplates: unknown[] }>().webhookTemplates.length, 0)
      const syncHeaders: Array<Record<string, string>> = [{}, { 'x-registry-token': memberA }]
      for (const headers of syncHeaders) {
        const sync = await ctx.http('registry.internal', '/sync', {
          method: 'POST', headers, body: { tenant: lab.plan.tenants.b.slug, projectId: projectIdB },
        })
        assert.equal(sync.status, 401)
        assert.ok(!sync.text.includes(lab.plan.secrets.internalBearerToken))
      }

      for (const token of [memberA, owner]) {
        assert.equal((await ctx.http('api', `${prefix}/deployments/${deploymentAutoId}/release`, {
          method: 'POST', token, body: { version: '2026.11.1' },
        })).status, 409)
      }
      assertNoTerminals(lab, `${mode} SF-C3/C4 direct`)
    })
  })
}

test('vulnerable: the revoked pool credential is the only stream that publishes the artifact', async () => {
  await withLab({}, async (lab, ctx) => {
    const stream = await ctx.http('runner', '/streams/shared', { token: lab.plan.ids.revokedPatToken })
    assert.equal(stream.status, 200)
    assert.ok(stream.text.includes(lab.plan.ids.sharedArtifactHandle))
  })
  await withLab({ mode: 'hardened' }, async (lab, ctx) => {
    assert.equal((await ctx.http('runner', '/streams/shared', { token: lab.plan.ids.revokedPatToken })).status, 401)
  })
})

test('intended chains: SF-C1..SF-C4 confirmed in vulnerable mode; hardened and SF-D1..SF-D3 silent', async () => {
  await withLab({}, async (lab) => {
    const findings = await runReferenceSolvers(lab)
    assert.deepEqual(findings.map((finding) => finding.chainId).sort(), CHAINS)
    for (const chainId of CHAINS) {
      const evaluation = lab.oracle.evaluate(chainId)
      assert.equal(evaluation.confirmed, true, `${chainId}: ${evaluation.failureReason ?? 'incomplete'}`)
    }
  })
  await withLab({ mode: 'hardened' }, async (lab) => {
    assert.equal((await runReferenceSolvers(lab)).length, 0)
    assertNoTerminals(lab, 'hardened')
  })
  for (const twin of ['SF-D1', 'SF-D2', 'SF-D3']) {
    await withLab({ twin }, async (lab) => {
      assert.equal((await runReferenceSolvers(lab)).length, 0, twin)
      assertNoTerminals(lab, twin)
    })
  }
})
