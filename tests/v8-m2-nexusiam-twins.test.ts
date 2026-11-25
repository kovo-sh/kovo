// M2 pre-sweep audit: nexusiam out-of-spec side routes (1-2 step authz gaps outside NX-C1..NX-C4).
//  1. SCIM: any member could mint a scim.write token and PATCH itself to owner (in every mode), and a
//     token for one org could change roles in another; token list/revoke lacked auth/ownership.
//  2. idp: unauthenticated invite/PAT revoke, cross-tenant invite create (any role) and PAT minting,
//     global PAT/user/audit listing, session-less invite redemption, /token accepting any code,
//     unregistered redirect_uri, /sessions/revoke shadowed by /sessions/:id.
//  3. app/api/docs-worker: foreign org roster, inbox material for other authors' comments, global
//     moderation queue, unauthenticated benign routes, docs-worker job list/create/cancel/audit.
// Each case pins that vulnerable mode still solves 4/4 and hardened/twin modes stay silent.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { createSolverContext, runNexusiamSolvers } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/context.ts'

type Lab = Awaited<ReturnType<typeof startNexusiam>>

async function probeSideRoutes(lab: Lab, ctx: SolverContext): Promise<void> {
  const prefix = lab.plan.routePrefix
  const slugA = lab.plan.tenants.a.slug
  const slugB = lab.plan.tenants.b.slug
  const memberA = await ctx.login('member_a')
  const memberB = await ctx.login('member_b')
  const viewerA = await ctx.login('viewer_a')
  const dualA = await ctx.login('dual_member', slugA)
  const owner = await ctx.login('owner_a')

  // SCIM: member/viewer/admin cannot mint write tokens; admin may mint read-only.
  for (const token of [memberA, viewerA, dualA]) {
    const minted = await ctx.http('api', `${prefix}/scim/tokens`, { method: 'POST', token, body: { scopes: ['scim.write'] } })
    assert.equal(minted.status, 403)
  }
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens`, { method: 'POST', token: dualA, body: { scopes: ['scim.read'] } })).status, 201)
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens`, { method: 'POST', token: memberA, body: { scopes: ['scim.read'] } })).status, 403)
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens`, { method: 'POST', token: owner, body: { scopes: ['root'] } })).status, 400)
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens`, { token: memberA })).status, 403)
  const ownerScim = await ctx.http('api', `${prefix}/scim/tokens`, { method: 'POST', token: owner, body: { scopes: ['scim.write'] } })
  assert.equal(ownerScim.status, 201)
  const { id: scimId, token: scimToken } = ownerScim.json<{ id: string; token: string }>()
  // An org_a provisioning token cannot change roles inside org_b.
  const crossPatch = await ctx.http('api', `${prefix}/scim/users/${lab.plan.personas.member_b.userId}`, {
    method: 'PATCH', headers: { 'x-scim-token': scimToken }, body: { role: 'owner', tenant: slugB },
  })
  assert.equal(crossPatch.status, 403)
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens/${scimId}/revoke`, { method: 'POST' })).status, 401)
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens/${scimId}/revoke`, { method: 'POST', token: memberB })).status, 404)
  assert.equal((await ctx.http('api', `${prefix}/scim/tokens/${scimId}/revoke`, { method: 'POST', token: memberA })).status, 404)

  // Org roster and audit surfaces.
  assert.equal((await ctx.http('api', `${prefix}/orgs/org_a/members`, { token: memberB })).status, 403)
  assert.equal((await ctx.http('api', `${prefix}/orgs/org_a/members`, { token: memberA })).status, 200)
  assert.equal((await ctx.http('api', `${prefix}/audit`, { token: memberA })).status, 403)
  for (const path of ['/audit', '/pats', '/customers', '/settings']) {
    assert.equal((await ctx.http('api', `${prefix}${path}`)).status, 401, path)
  }
  const customers = await ctx.http('api', `${prefix}/customers`, { token: memberB })
  assert.ok(customers.json<{ customers: Array<{ tenant: string }> }>().customers.every((item) => item.tenant === 'org_b'))

  // idp invitations.
  assert.equal((await ctx.http('idp', '/invites', {
    method: 'POST', token: memberB, body: { tenant: slugA, email: 'mh_fake_side@example.test', role: 'admin' },
  })).status, 403)
  assert.equal((await ctx.http('idp', '/invites', {
    method: 'POST', token: owner, body: { tenant: slugA, email: 'mh_fake_side@example.test', role: 'owner' },
  })).status, 400)
  const staleId = lab.plan.nexus.staleInviteId
  assert.equal((await ctx.http('idp', `/invites/${staleId}/revoke`, { method: 'POST' })).status, 401)
  assert.equal((await ctx.http('idp', `/invites/${staleId}/revoke`, { method: 'POST', token: memberB })).status, 404)
  assert.equal((await ctx.http('idp', '/invites/redeem', { method: 'POST', body: { token: lab.plan.nexus.staleInviteToken } })).status, 401)

  // idp PATs, users, audit, sessions, OAuth endpoints.
  assert.equal((await ctx.http('idp', '/pats', { method: 'POST', token: memberB, body: { tenant: slugA } })).status, 403)
  const ownPat = await ctx.http('idp', '/pats', { method: 'POST', token: owner, body: { scopes: ['read'] } })
  const patId = ownPat.json<{ id: string }>().id
  assert.equal((await ctx.http('idp', `/pats/${patId}/revoke`, { method: 'POST' })).status, 401)
  assert.equal((await ctx.http('idp', `/pats/${patId}/revoke`, { method: 'POST', token: memberB })).status, 404)
  const listed = await ctx.http('idp', '/pats', { token: memberB })
  assert.equal(listed.json<{ tokens: unknown[] }>().tokens.length, 0)
  assert.equal((await ctx.http('idp', '/users')).status, 401)
  const users = await ctx.http('idp', '/users', { token: memberB })
  assert.ok(!users.text.includes(lab.plan.personas.owner_a.userId))
  assert.equal((await ctx.http('idp', '/audit')).status, 401)
  assert.equal((await ctx.http('idp', '/audit', { token: memberA })).status, 403)
  assert.equal((await ctx.http('idp', `/sessions/${owner}`)).status, 401)
  assert.equal((await ctx.http('idp', `/sessions/${owner}`, { token: memberB })).status, 404)
  assert.equal((await ctx.http('idp', '/sessions/revoke', { method: 'POST', body: { token: owner } })).status, 401)
  await ctx.http('idp', '/sessions/revoke', { method: 'POST', token: memberB, body: { token: owner } })
  assert.equal((await ctx.http('api', `${prefix}/me`, { token: owner })).status, 200)
  assert.equal((await ctx.http('idp', '/token', { method: 'POST', body: { code: 'mh_fake_code_unissued' } })).status, 400)
  assert.equal((await ctx.http('idp', `/authorize?client_id=nexus-desktop&redirect_uri=${encodeURIComponent('https://example.test/cb')}`)).status, 400)
  const authorized = await ctx.http('idp', `/authorize?client_id=nexus-desktop&redirect_uri=${encodeURIComponent(`${lab.origins.app}/cb`)}`)
  assert.equal(authorized.status, 200)
  const code = authorized.json<{ code: string }>().code
  assert.equal((await ctx.http('idp', '/token', { method: 'POST', body: { code } })).status, 200)
  assert.equal((await ctx.http('idp', '/token', { method: 'POST', body: { code } })).status, 400)

  // app moderation surfaces: material is visible to the comment author only.
  assert.equal((await ctx.http('app', '/v1/moderation/queue')).status, 401)
  const comment = await ctx.http('api', `${prefix}/comments`, { method: 'POST', token: memberA, body: { body: 'side note' } })
  const commentId = comment.json<{ comment: { id: string } }>().comment.id
  assert.equal((await ctx.http('app', `${prefix}/inbox/${commentId}`, { token: memberB })).status, 404)

  // docs-worker administration requires the service credential; the seeded job cannot be listed or cancelled.
  assert.equal((await ctx.http('docs-worker', '/jobs')).status, 401)
  assert.equal((await ctx.http('docs-worker', '/jobs/export', { method: 'POST', body: { tenantId: 'org_a' } })).status, 401)
  assert.equal((await ctx.http('docs-worker', `/jobs/${lab.plan.nexus.exportJobId}/cancel`, { method: 'POST' })).status, 401)
  assert.equal((await ctx.http('docs-worker', '/audit')).status, 401)
}

for (const [mode, twin] of [['hardened', undefined], ['vulnerable', 'NX-D1'], ['vulnerable', 'NX-D2'], ['vulnerable', 'NX-D3']] as const) {
  test(`${twin ?? mode}: out-of-spec side routes are closed and no terminal fires`, async () => {
    const lab = await startNexusiam({ seed: 42, mode, twin, asyncLatencyMs: 5 })
    try {
      const ctx = createSolverContext(lab)
      await probeSideRoutes(lab, ctx)
      const findings = await runNexusiamSolvers(lab)
      assert.equal(findings.length, 0)
      const exported = lab.export()
      assert.equal(exported.events.terminals.length, 0)
      assert.equal(exported.confirmed.length, 0)
    } finally {
      await lab.stop()
    }
  })
}

test('vulnerable: side routes closed while all four intended chains stay solvable', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    await probeSideRoutes(lab, ctx)
    const findings = await runNexusiamSolvers(lab)
    assert.deepEqual(findings.map((finding) => finding.chainId).sort(), ['NX-C1', 'NX-C2', 'NX-C3', 'NX-C4'])
    assert.equal(lab.export().confirmed.length, 4)
  } finally {
    await lab.stop()
  }
})
