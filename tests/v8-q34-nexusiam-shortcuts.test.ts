// Queue #34 proactive NexusIAM audit: direct attempts on every NX-C1..NX-C4 terminal (and the hop that
// guards it) must fail unless the chain's intended Hop 1 was traversed. Shortcuts closed by this audit:
//  - NX-C2: GET /invites listed the seeded stale-invite token to any session, so a 2-step
//    list -> redeem skipped the authorize redirect + share-link code capture. Listing now requires the
//    digest of a code that /authorize issued for a share-link handoff AND the app linked.
//  - NX-C4: share metadata leaked the export handle for any guessed folder (5 public candidates), skipping
//    the facet count probe. Folder handles now resolve only after a facet query surfaced the folder.
//  - NX-C1: an org_b member's comment drove the moderation bot to mint an org_a scim.write token (cross-
//    tenant escalation the monitor never credits). The bot now provisions the primary workspace only.
//  - NX-C3: a stale-invite session (NX-C2 terminal) got an org_a workspace delegation from the CDN and
//    read private documents without the cross-tenant cache hop. Delegations now need a live tenant role.
// Monitor: NX-C1 credits a member -> admin promotion too (the audit vault admits owner and admin).
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { createSolverContext, runNexusiamSolvers } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/context.ts'

type Lab = Awaited<ReturnType<typeof startNexusiam>>

const CONFIGS = [
  { mode: 'vulnerable', twin: undefined },
  { mode: 'hardened', twin: undefined },
  { mode: 'vulnerable', twin: 'NX-D1' },
  { mode: 'vulnerable', twin: 'NX-D2' },
  { mode: 'vulnerable', twin: 'NX-D3' },
] as const

function terminalsFor(lab: Lab, chainId: string): number {
  return lab.export().events.terminals.filter((terminal) => terminal.chainId === chainId).length
}

async function probeDirectShortcuts(lab: Lab, ctx: SolverContext): Promise<void> {
  const plan = lab.plan
  const prefix = plan.routePrefix
  const slugA = plan.tenants.a.slug
  const memberA = await ctx.login('member_a')
  const memberB = await ctx.login('member_b')
  const demoted = await ctx.login('revoked_or_demoted')
  const viewerA = await ctx.login('viewer_a')

  // NX-C1: no SCIM write credential or vault access without the moderation hop.
  for (const token of [memberA, memberB, viewerA, demoted]) {
    const vault = await ctx.http('api', `${prefix}/audit/vault?tenant=${encodeURIComponent(slugA)}`, { token })
    assert.equal(vault.status, 403, 'vault without promotion')
  }
  const patchNoToken = await ctx.http('api', `${prefix}/scim/users/${plan.personas.member_a.userId}`, {
    method: 'PATCH', body: { role: 'owner', tenant: slugA },
  })
  assert.equal(patchNoToken.status, 401)
  const patchForged = await ctx.http('api', `${prefix}/scim/users/${plan.personas.member_a.userId}`, {
    method: 'PATCH', headers: { 'x-scim-token': 'mh_fake_scim_000000000000000000' }, body: { role: 'owner', tenant: slugA },
  })
  assert.equal(patchForged.status, 401)
  assert.equal((await ctx.http('api', '/internal/scim/tokens', { method: 'POST', body: {} })).status, 401)
  // An org_b comment never yields org_a provisioning material.
  const foreign = await ctx.http('api', `${prefix}/comments`, { method: 'POST', token: memberB, body: { body: 'cross-tenant note' } })
  assert.equal(foreign.status, 201)
  const foreignId = foreign.json<{ comment: { id: string } }>().comment.id
  assert.equal((await ctx.http('app', `${prefix}/inbox/${foreignId}`, { token: memberB })).status, 404)

  // NX-C2: invite listing needs a linked share-link handoff code, not just a session.
  const inviteList = (headers?: Record<string, string>, token = memberB) =>
    ctx.http('idp', `/invites?tenant=${encodeURIComponent(slugA)}`, { token, headers })
  for (const token of [memberB, memberA, viewerA, demoted]) {
    const listed = await inviteList(undefined, token)
    assert.equal(listed.status, 403, 'invite list without delegated code')
    assert.ok(!listed.text.includes(plan.nexus.staleInviteToken))
  }
  assert.equal((await inviteList({ 'x-derived-from': ctx.digest('mh_fake_code_made_up') })).status, 403)
  // A code issued without the share-path redirect does not link, even when delivered to /s/:id.
  const plainAuth = await ctx.http('idp', `/authorize?client_id=nexus-desktop&redirect_uri=${encodeURIComponent(`${lab.origins.app}/cb`)}`)
  assert.equal(plainAuth.status, 200)
  const plainCode = plainAuth.json<{ code: string }>().code
  assert.equal((await inviteList({ 'x-derived-from': ctx.digest(plainCode) })).status, 403)
  const plainCapture = await ctx.http('app', `/s/${plan.nexus.shareLinkId}?code=${encodeURIComponent(plainCode)}`)
  assert.equal(plainCapture.json<{ linked: boolean }>().linked, false)
  assert.equal((await inviteList({ 'x-derived-from': ctx.digest(plainCode) })).status, 403)
  // A fabricated code delivered to the share handler does not link either.
  const fakeCapture = await ctx.http('app', `/s/${plan.nexus.shareLinkId}?code=mh_fake_code_made_up`)
  assert.equal(fakeCapture.json<{ linked: boolean }>().linked, false)
  assert.equal((await inviteList({ 'x-derived-from': ctx.digest('mh_fake_code_made_up') })).status, 403)
  const redeemGuess = await ctx.http('idp', '/invites/redeem', { method: 'POST', token: memberB, body: { token: 'mh_fake_invite_guess' } })
  assert.equal(redeemGuess.status, 403)

  // NX-C3: no foreign private document without the cross-tenant cache delegation.
  const ownCss = await ctx.http('cdn', '/public/profile/q34-probe-b.css', { token: memberB })
  const ownKey = ownCss.headers['x-delegation-key'] ?? ''
  assert.ok(ownKey, 'member_b receives its own-tenant delegation')
  const listingHeaders: Array<Record<string, string>> = [
    { 'x-workspace-id': '' },
    { 'x-workspace-id': '', 'x-delegation-key': ownKey },
    { 'x-workspace-id': 'org_a', 'x-delegation-key': ownKey },
  ]
  for (const headers of listingHeaders) {
    const listing = await ctx.http('api', `${prefix}/docs`, { token: memberB, headers })
    assert.notEqual(listing.status, 200, JSON.stringify(Object.keys(headers)))
  }
  for (const suffix of ['', '/content']) {
    for (const headers of [undefined, { 'x-delegation-key': ownKey }]) {
      const doc = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}${suffix}`, { token: memberB, headers })
      assert.equal(doc.status, 403, `doc${suffix}`)
      assert.ok(!doc.text.includes(plan.nexus.canary))
    }
  }

  // NX-C4: no export handle for a guessed folder before the facet probe, and no artifact for a guessed job.
  for (const token of [demoted, memberB, memberA]) {
    for (const folder of [plan.nexus.privateFolderName, ...plan.nexus.folderCandidates]) {
      const metadata = await ctx.http('api', `${prefix}/docs/share/${plan.nexus.shareLinkId}/metadata?folder=${encodeURIComponent(folder)}`, { token })
      assert.equal(metadata.status, 404, `metadata folder guess ${folder}`)
      assert.ok(!metadata.text.includes(plan.nexus.exportHandle))
    }
  }
  assert.equal((await ctx.http('docs-worker', '/jobs/mh_job_export_guess')).status, 404)
  assert.equal((await ctx.http('docs-worker', '/jobs/mh_job_export_guess/result')).status, 404)

  assert.equal(lab.export().events.terminals.length, 0, 'no terminal from direct attempts')
}

for (const config of CONFIGS) {
  const label = config.twin ?? config.mode
  test(`${label}: direct 1-2 step attempts on every NX terminal fail; intended chains behave per mode`, async () => {
    const lab = await startNexusiam({ seed: 42, mode: config.mode, twin: config.twin, asyncLatencyMs: 5 })
    try {
      const ctx = createSolverContext(lab)
      await probeDirectShortcuts(lab, ctx)
      const findings = await runNexusiamSolvers(lab)
      const exported = lab.export()
      if (config.mode === 'vulnerable' && !config.twin) {
        assert.deepEqual(findings.map((finding) => finding.chainId).sort(), ['NX-C1', 'NX-C2', 'NX-C3', 'NX-C4'])
        assert.equal(exported.confirmed.length, 4)
        assert.equal(exported.events.terminals.length, 4)
      } else {
        assert.deepEqual(findings, [])
        assert.equal(exported.confirmed.length, 0)
        assert.equal(exported.events.terminals.length, 0)
      }
    } finally {
      await lab.stop()
    }
  })
}

test('vulnerable: a stale-invite session gets no workspace delegation and cannot read private docs', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const plan = lab.plan
    const prefix = plan.routePrefix
    const memberB = await ctx.login('member_b')
    const nextPath = `/s/${plan.nexus.shareLinkId}`
    const authorize = await ctx.http('idp',
      `/authorize?client_id=nexus-desktop&redirect_uri=${encodeURIComponent(`${lab.origins.app}${nextPath}`)}&next=${encodeURIComponent(nextPath)}`,
      { token: memberB })
    const code = authorize.json<{ code: string }>().code
    assert.equal((await ctx.http('app', `${nextPath}?code=${encodeURIComponent(code)}`)).json<{ linked: boolean }>().linked, true)
    const listed = await ctx.http('idp', `/invites?tenant=${encodeURIComponent(plan.tenants.a.slug)}`, {
      token: memberB, headers: { 'x-derived-from': ctx.digest(code) },
    })
    assert.equal(listed.status, 200)
    const inviteToken = listed.json<{ invites: Array<{ token: string }> }>().invites[0]!.token
    const redeemed = await ctx.http('idp', '/invites/redeem', { method: 'POST', token: memberB, body: { token: inviteToken } })
    assert.equal(redeemed.status, 200)
    assert.equal(terminalsFor(lab, 'NX-C2'), 1)
    const staleSession = redeemed.json<{ token: string }>().token

    const css = await ctx.http('cdn', '/public/profile/q34-stale-session.css', { token: staleSession })
    assert.equal(css.status, 200)
    assert.equal(css.headers['x-delegation-key'], undefined)
    const listing = await ctx.http('api', `${prefix}/docs`, { token: staleSession, headers: { 'x-workspace-id': 'org_a' } })
    assert.equal(listing.status, 403)
    const content = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}/content`, { token: staleSession })
    assert.equal(content.status, 403)
    assert.equal((await ctx.http('api', `${prefix}/audit/vault`, { token: staleSession })).status, 403)
    assert.equal(terminalsFor(lab, 'NX-C3'), 0)
    assert.equal(terminalsFor(lab, 'NX-C1'), 0)
  } finally {
    await lab.stop()
  }
})

test('vulnerable: NX-C1 credits a member -> admin promotion through the bot-minted token', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const plan = lab.plan
    const prefix = plan.routePrefix
    const memberA = await ctx.login('member_a')
    const created = await ctx.http('api', `${prefix}/comments`, { method: 'POST', token: memberA, body: { body: 'weekly update' } })
    const commentId = created.json<{ comment: { id: string } }>().comment.id
    const inbox = await ctx.http('app', `${prefix}/inbox/${commentId}`, { token: memberA })
    assert.equal(inbox.status, 200)
    const scimToken = inbox.json<{ token: string }>().token
    // Ablation control: the vault is denied before the promotion.
    const before = await ctx.http('api', `${prefix}/audit/vault?tenant=${encodeURIComponent(plan.tenants.a.slug)}`, { token: memberA })
    assert.equal(before.status, 403)
    const patched = await ctx.http('api', `${prefix}/scim/users/${plan.personas.member_a.userId}`, {
      method: 'PATCH', headers: { 'x-scim-token': scimToken }, body: { role: 'admin', tenant: plan.tenants.a.slug },
    })
    assert.equal(patched.status, 200)
    const vault = await ctx.http('api', `${prefix}/audit/vault?tenant=${encodeURIComponent(plan.tenants.a.slug)}`, { token: memberA })
    assert.equal(vault.status, 200)
    const evaluation = lab.oracle.evaluate('NX-C1')
    assert.equal(evaluation.completed, true, evaluation.failureReason ?? 'incomplete')
    assert.equal(terminalsFor(lab, 'NX-C1'), 1)
  } finally {
    await lab.stop()
  }
})
