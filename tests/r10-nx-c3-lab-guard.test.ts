// Regression guard for the NexusIAM NX-C3 lab shortcut closed in R10:
// GET /v1/docs with an explicit cross-tenant x-workspace-id header must require a live
// role in that workspace (403 otherwise), so the empty-workspace fallback path (nx-c3-h2 /
// api.docsWorkspaceFallback) is the only cross-tenant listing path.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { createSolverContext } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/context.ts'

async function leakOrgADelegation(ctx: SolverContext, slugA: string): Promise<{
  ownerToken: string
  memberBToken: string
  ownerKey: string
  memberBServedKey: string
}> {
  const ownerToken = await ctx.login('owner_a')
  const primed = await ctx.http('cdn', `/public/profile/${slugA}.css`, { token: ownerToken })
  assert.equal(primed.status, 200)
  const ownerKey = primed.headers['x-delegation-key'] ?? ''
  assert.ok(ownerKey, 'owner_a receives org_a delegation key from CDN')

  const memberBToken = await ctx.login('member_b')
  const served = await ctx.http('cdn', `/public/profile/${slugA}.css`, { token: memberBToken })
  assert.equal(served.status, 200)
  const memberBServedKey = served.headers['x-delegation-key'] ?? ''
  return { ownerToken, memberBToken, ownerKey, memberBServedKey }
}

test('NX-C3 guard: explicit cross-tenant x-workspace-id + leaked delegation key is denied 403 and cannot shortcut nx-c3-h2', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const { plan } = lab
    const prefix = plan.routePrefix
    const slugA = plan.tenants.a.slug

    const { memberBToken, ownerKey, memberBServedKey } = await leakOrgADelegation(ctx, slugA)
    assert.equal(memberBServedKey, ownerKey, 'vulnerable CDN cache leaks owner_a delegation key to member_b')

    // Explicit cross-tenant workspace header (by tenant id or slug) must be denied 403 without a workspace role.
    for (const explicitWorkspace of ['org_a', slugA]) {
      const listing = await ctx.http('api', `${prefix}/docs`, {
        token: memberBToken,
        headers: {
          'x-workspace-id': explicitWorkspace,
          'x-delegation-key': memberBServedKey,
        },
      })
      assert.equal(listing.status, 403, `explicit cross-tenant x-workspace-id=${explicitWorkspace} must be denied 403`)
    }

    // Because listing was denied, private doc metadata/content remain gated and nx-c3-h2 is never recorded.
    const opened = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}`, {
      token: memberBToken,
      headers: { 'x-delegation-key': memberBServedKey, 'x-workspace-id': 'org_a' },
    })
    assert.equal(opened.status, 403, 'private doc metadata must remain denied without fallback listing')

    const content = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}/content`, {
      token: memberBToken,
      headers: { 'x-delegation-key': memberBServedKey, 'x-workspace-id': 'org_a' },
    })
    assert.equal(content.status, 403, 'private doc content must remain denied without fallback listing')
    assert.ok(!content.text.includes(plan.nexus.canary), 'canary must not leak via explicit-workspace shortcut')

    const exported = lab.export()
    assert.equal(
      exported.events.hops.some((hop) => hop.hopId === 'nx-c3-h2'),
      false,
      'explicit cross-tenant header must not record nx-c3-h2',
    )
    assert.equal(exported.events.terminals.length, 0, 'no terminal should be recorded')
  } finally {
    await lab.stop()
  }
})

test('NX-C3 guard: empty x-workspace-id fallback + leaked delegation key lists docs and records nx-c3-h2 in vulnerable mode', async () => {
  const lab = await startNexusiam({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const { plan } = lab
    const prefix = plan.routePrefix
    const slugA = plan.tenants.a.slug

    const { memberBToken, ownerKey, memberBServedKey } = await leakOrgADelegation(ctx, slugA)
    assert.equal(memberBServedKey, ownerKey)

    const listing = await ctx.http('api', `${prefix}/docs`, {
      token: memberBToken,
      headers: {
        'x-workspace-id': '',
        'x-delegation-key': memberBServedKey,
      },
    })
    assert.equal(listing.status, 200, 'empty-workspace fallback with leaked delegation key must succeed 200')
    const listedDocs = listing.json<{ docs: Array<{ id: string }> }>().docs
    assert.ok(listedDocs.some((doc) => doc.id === plan.nexus.privateDocId), 'listing includes private org_a doc')

    const h2 = lab.export().events.hops.find((hop) => hop.hopId === 'nx-c3-h2')
    assert.ok(h2, 'nx-c3-h2 hop must be recorded')
    assert.equal(h2.routeKey, 'api.docsWorkspaceFallback')

    // Complete ablation control + h3 + h4 to confirm all 4 NX-C3 hops bind end-to-end.
    const control = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}/content`, { token: memberBToken })
    assert.equal(control.status, 403)

    const opened = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}`, {
      token: memberBToken,
      headers: { 'x-delegation-key': memberBServedKey, 'x-workspace-id': '' },
    })
    assert.equal(opened.status, 200)

    const content = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}/content`, {
      token: memberBToken,
      headers: { 'x-delegation-key': memberBServedKey, 'x-workspace-id': '' },
    })
    assert.equal(content.status, 200)
    assert.ok(content.text.includes(plan.nexus.canary))

    const evaluation = lab.oracle.evaluate('NX-C3')
    assert.equal(evaluation.completed, true, evaluation.failureReason ?? 'NX-C3 should complete all 4 hops')
  } finally {
    await lab.stop()
  }
})

test('NX-C3 guard: NX-D3 twin and hardened mode still block cross-tenant private doc read', async () => {
  // NX-D3 twin: explicit cross-tenant header is denied 403; empty fallback is benign decoy h2,
  // and privateDocScopeCheck blocks h3/h4 with 403 and zero terminals.
  const twinLab = await startNexusiam({ seed: 42, mode: 'vulnerable', twin: 'NX-D3', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(twinLab)
    const { plan } = twinLab
    const prefix = plan.routePrefix
    const slugA = plan.tenants.a.slug

    const { memberBToken, ownerKey, memberBServedKey } = await leakOrgADelegation(ctx, slugA)
    assert.equal(memberBServedKey, ownerKey)

    const explicitCrossTenant = await ctx.http('api', `${prefix}/docs`, {
      token: memberBToken,
      headers: { 'x-workspace-id': 'org_a', 'x-delegation-key': memberBServedKey },
    })
    assert.equal(explicitCrossTenant.status, 403, 'NX-D3 must deny explicit cross-tenant header 403')

    const fallbackListing = await ctx.http('api', `${prefix}/docs`, {
      token: memberBToken,
      headers: { 'x-workspace-id': '', 'x-delegation-key': memberBServedKey },
    })
    assert.equal(fallbackListing.status, 200, 'NX-D3 decoy h2 listing succeeds')

    const opened = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}`, {
      token: memberBToken,
      headers: { 'x-workspace-id': '', 'x-delegation-key': memberBServedKey },
    })
    assert.equal(opened.status, 403, 'NX-D3 privateDocScopeCheck blocks doc open')

    const content = await ctx.http('api', `${prefix}/docs/${plan.nexus.privateDocId}/content`, {
      token: memberBToken,
      headers: { 'x-workspace-id': '', 'x-delegation-key': memberBServedKey },
    })
    assert.equal(content.status, 403, 'NX-D3 privateDocScopeCheck blocks doc content')
    assert.ok(!content.text.includes(plan.nexus.canary))

    const exported = twinLab.export()
    assert.equal(exported.events.terminals.length, 0, 'NX-D3 must record zero terminals')
    assert.equal(twinLab.oracle.evaluate('NX-C3').completed, false)
  } finally {
    await twinLab.stop()
  }

  // Hardened mode: CDN does not leak cross-tenant delegation, empty workspace fallback returns 400,
  // and explicit cross-tenant workspace returns 403.
  const hardenedLab = await startNexusiam({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(hardenedLab)
    const { plan } = hardenedLab
    const prefix = plan.routePrefix
    const slugA = plan.tenants.a.slug

    const { memberBToken, ownerKey, memberBServedKey } = await leakOrgADelegation(ctx, slugA)
    assert.notEqual(memberBServedKey, ownerKey, 'hardened CDN must not leak owner_a delegation key')

    const fallbackListing = await ctx.http('api', `${prefix}/docs`, {
      token: memberBToken,
      headers: { 'x-workspace-id': '', 'x-delegation-key': ownerKey },
    })
    assert.equal(fallbackListing.status, 400, 'hardened mode must reject empty workspace fallback with 400')

    const explicitCrossTenant = await ctx.http('api', `${prefix}/docs`, {
      token: memberBToken,
      headers: { 'x-workspace-id': 'org_a', 'x-delegation-key': ownerKey },
    })
    assert.equal(explicitCrossTenant.status, 403, 'hardened mode must reject explicit cross-tenant workspace with 403')

    const exported = hardenedLab.export()
    assert.equal(exported.events.hops.some((hop) => hop.hopId === 'nx-c3-h2'), false)
    assert.equal(exported.events.terminals.length, 0)
  } finally {
    await hardenedLab.stop()
  }
})

test('NX-C3 guard: own-workspace explicit x-workspace-id with valid role still succeeds 200', async () => {
  for (const mode of ['vulnerable', 'hardened'] as const) {
    const lab = await startNexusiam({ seed: 42, mode, asyncLatencyMs: 5 })
    try {
      const ctx = createSolverContext(lab)
      const { plan } = lab
      const prefix = plan.routePrefix

      const ownerToken = await ctx.login('owner_a')
      const ownerCss = await ctx.http('cdn', `/public/profile/${plan.tenants.a.slug}.css`, { token: ownerToken })
      const ownerKey = ownerCss.headers['x-delegation-key'] ?? ''
      assert.ok(ownerKey)

      for (const workspaceHeader of ['org_a', plan.tenants.a.slug]) {
        const ownListing = await ctx.http('api', `${prefix}/docs`, {
          token: ownerToken,
          headers: { 'x-workspace-id': workspaceHeader, 'x-delegation-key': ownerKey },
        })
        assert.equal(ownListing.status, 200, `${mode}: owner_a explicit x-workspace-id=${workspaceHeader} must succeed 200`)
        const body = ownListing.json<{ workspace: string; docs: Array<{ id: string }> }>()
        assert.equal(body.workspace, plan.tenants.a.slug)
        assert.ok(body.docs.some((doc) => doc.id === plan.nexus.privateDocId))
      }

      const memberBToken = await ctx.login('member_b')
      const memberBCss = await ctx.http('cdn', `/public/profile/${plan.tenants.b.slug}.css`, { token: memberBToken })
      const memberBKey = memberBCss.headers['x-delegation-key'] ?? ''
      assert.ok(memberBKey)

      const memberBListing = await ctx.http('api', `${prefix}/docs`, {
        token: memberBToken,
        headers: { 'x-workspace-id': 'org_b', 'x-delegation-key': memberBKey },
      })
      assert.equal(memberBListing.status, 200, `${mode}: member_b explicit own workspace org_b must succeed 200`)
      assert.equal(memberBListing.json<{ workspace: string }>().workspace, plan.tenants.b.slug)
    } finally {
      await lab.stop()
    }
  }
})
