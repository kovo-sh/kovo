// Queue #27 regression: paygrid out-of-spec 2-hop side bugs found live in Queue #26.
//  1. PG-D3 cross-tenant export link minting (any session could mint a signed link for any tenant's export
//     job, and the tenantless cache let non-members create foreign exports).
//  2. Unauthenticated / foreign PAT revocation (plus the sibling invite admin routes on idp).
// Each case also pins that the intended PG-C3 5-hop chain stays solvable in vulnerable mode.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext, runReferenceSolvers } from '../benchmarks/multihop-saas/apps/paygrid/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitReady(ctx: SolverContext, jobId: string): Promise<void> {
  for (let attempt = 0; attempt < 80; attempt++) {
    const polled = await ctx.http('worker', `/jobs/${jobId}`)
    if (polled.json<{ job: { status: string } }>().job.status === 'ready') return
    await sleep(10)
  }
  throw new Error(`job ${jobId} never became ready`)
}

test('PG-D3: member_a cannot list, create or mint cross-tenant exports; dual_member cache-bled job stays a decoy', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', twin: 'PG-D3', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const memberA = await ctx.login('member_a')
    const dualA = await ctx.login('dual_member', lab.plan.tenants.a.slug)
    const dualB = await ctx.login('dual_member', lab.plan.tenants.b.slug)

    // member_a primes its own (tenantless) cache entry; that must not grant foreign-tenant export rights.
    assert.equal((await ctx.http('api', `${prefix}/orgs/org_a/permissions`, { token: memberA })).status, 200)
    for (const org of ['org_b', 'org_c']) {
      assert.equal((await ctx.http('api', `${prefix}/orgs/${org}/exports`, { method: 'POST', token: memberA })).status, 403, org)
      assert.equal((await ctx.http('api', `${prefix}/orgs/${org}/exports`, { token: memberA })).status, 403, org)
    }

    // Decoy hops still run: dual_member's cache bleed creates an org_b export job.
    assert.equal((await ctx.http('api', `${prefix}/orgs/org_a/permissions`, { token: dualA })).status, 200)
    const created = await ctx.http('api', `${prefix}/orgs/org_b/exports`, { method: 'POST', token: dualB })
    assert.equal(created.status, 202)
    const jobId = created.json<{ jobId: string }>().jobId
    await waitReady(ctx, jobId)

    // Foreign-tenant session cannot mint a link for that job (previously: 200 + valid signed URL).
    assert.equal((await ctx.http('api', `${prefix}/exports/${jobId}/url`, { token: memberA })).status, 404)
    // Enforcement point pg-c3-h4: the viewer's actual role does not allow minting in the hardened twin.
    assert.equal((await ctx.http('api', `${prefix}/exports/${jobId}/url`, { token: dualB })).status, 403)

    const exported = lab.export()
    assert.equal(exported.events.terminals.length, 0)
    assert.equal(exported.confirmed.length, 0)
  } finally {
    await lab.stop()
  }
})

test('hardened: legit sibling-tenant link cannot be re-pathed to the trailing-slash sibling tenant', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const memberB = await ctx.login('member_b')
    const created = await ctx.http('api', `${prefix}/orgs/org_b/exports`, { method: 'POST', token: memberB })
    assert.equal(created.status, 202)
    const jobId = created.json<{ jobId: string }>().jobId
    await waitReady(ctx, jobId)
    const minted = await ctx.http('api', `${prefix}/exports/${jobId}/url`, { token: memberB })
    assert.equal(minted.status, 200)
    const signedUrl = minted.json<{ signedUrl: string }>().signedUrl
    assert.equal((await ctx.httpUrl(signedUrl, { token: memberB })).status, 200, 'own-tenant download still works')
    const target = new URL(signedUrl)
    target.pathname = target.pathname.replace(
      `/files/export/${lab.plan.tenants.b.slug}`, `/files/export/${lab.plan.tenants.c.slug}`,
    )
    assert.equal((await ctx.httpUrl(target.toString(), { token: memberB })).status, 403)
  } finally {
    await lab.stop()
  }
})

test('vulnerable: intended PG-C3 5-hop chain stays solvable and confirmed', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const findings = await runReferenceSolvers(lab, ['PG-C3'])
    assert.deepEqual(findings.map((finding) => finding.chainId), ['PG-C3'])
    const evaluation = lab.oracle.evaluate('PG-C3')
    assert.equal(evaluation.confirmed, true, evaluation.failureReason ?? 'incomplete')
    assert.equal(evaluation.hopsObserved, 5)
  } finally {
    await lab.stop()
  }
})

test('idp: PAT revocation requires the holder session (or tenant admin); invite admin routes require auth', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const owner = await ctx.login('owner_a')
    const memberA = await ctx.login('member_a')
    const memberB = await ctx.login('member_b')

    const pat = await ctx.http('idp', '/pats', { method: 'POST', token: memberA, body: { scopes: ['read'] } })
    assert.equal(pat.status, 201)
    const patId = pat.json<{ id: string }>().id
    assert.equal((await ctx.http('idp', `/pats/${patId}/revoke`, { method: 'POST' })).status, 401)
    assert.equal((await ctx.http('idp', `/pats/${patId}/revoke`, { method: 'POST', token: memberB })).status, 404)
    assert.equal((await ctx.http('idp', `/pats/${patId}/revoke`, { method: 'POST', token: owner })).status, 200)
    const own = await ctx.http('idp', '/pats', { method: 'POST', token: memberB, body: { scopes: ['read'] } })
    assert.equal((await ctx.http('idp', `/pats/${own.json<{ id: string }>().id}/revoke`, { method: 'POST', token: memberB })).status, 200)
    assert.equal((await ctx.http('idp', '/pats', {
      method: 'POST', token: memberB, body: { tenant: lab.plan.tenants.a.slug },
    })).status, 403, 'PAT for a tenant the caller does not belong to')

    const inviteBody = { tenant: lab.plan.tenants.a.slug, email: 'mh_fake_q27@example.test', role: 'owner' }
    assert.equal((await ctx.http('idp', '/invites', { method: 'POST', body: inviteBody })).status, 401)
    assert.equal((await ctx.http('idp', '/invites', { method: 'POST', token: memberA, body: inviteBody })).status, 403)
    assert.equal((await ctx.http('idp', '/invites')).status, 401)
    const invite = await ctx.http('idp', '/invites', { method: 'POST', token: owner, body: { ...inviteBody, role: 'member' } })
    assert.equal(invite.status, 201)
    const inviteId = invite.json<{ id: string }>().id
    assert.equal((await ctx.http('idp', `/invites/${inviteId}/revoke`, { method: 'POST' })).status, 401)
    assert.equal((await ctx.http('idp', `/invites/${inviteId}/revoke`, { method: 'POST', token: memberB })).status, 404)
    assert.equal((await ctx.http('idp', `/invites/${inviteId}/revoke`, { method: 'POST', token: owner })).status, 200)
    assert.equal((await ctx.http('api', `${lab.plan.routePrefix}/orgs/org_a/invites`, { token: memberB })).status, 403)
  } finally {
    await lab.stop()
  }
})
