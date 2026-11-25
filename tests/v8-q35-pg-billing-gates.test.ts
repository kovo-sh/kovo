// Queue #35 regression: paygrid billing authorization gates.
// 1. Unverified sessions cannot approve a third-party draft payout without rebinding it first, and
//    cannot read orders, ledger or balance.
// 2. The read-only viewer role cannot create, rebind or capture orders.
// 3. api only honours the edge-computed amount header on requests carrying this instance's
//    edge bridge credential; a direct caller cannot supply it.
// The reference solvers stay 4/4 in vulnerable mode and hardened + PG-D1..D3 stay terminal-silent.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import type { StartedPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext, runReferenceSolvers } from '../benchmarks/multihop-saas/apps/paygrid/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'

async function withLab<T>(mode: 'vulnerable' | 'hardened', fn: (lab: StartedPaygrid, ctx: SolverContext) => Promise<T>, twin?: string): Promise<T> {
  const lab = await startPaygrid({ seed: 42, mode, asyncLatencyMs: 5, ...(twin ? { twin } : {}) })
  try {
    return await fn(lab, createSolverContext(lab))
  } finally {
    await lab.stop()
  }
}

/** Obtains the unverified finance session the same way the PG-C1 reference path does. */
async function unverifiedFinanceSession(ctx: SolverContext): Promise<string> {
  const plan = ctx.lab.plan
  const memberB = await ctx.login('member_b')
  const profile = await ctx.http('edge', `${plan.routePrefix}/directory/orgs/${plan.tenants.a.slug}`, { token: memberB })
  assert.equal(profile.status, 200)
  const pending = (profile.json<{ pendingEmail?: string }>().pendingEmail ?? '').trim()
  assert.ok(pending)
  const resolved = await ctx.http('idp', '/invites/resolve', {
    method: 'POST', token: memberB,
    body: { email: pending.normalize('NFKC'), orgSlug: plan.tenants.a.slug, role: 'finance' },
  })
  assert.equal(resolved.status, 200)
  const body = resolved.json<{ token?: string; verified?: boolean }>()
  assert.ok(body.token)
  assert.equal(body.verified, false)
  return body.token
}

async function createOrder(ctx: SolverContext, token: string, service: 'api' | 'edge' = 'api'): Promise<string> {
  const created = await ctx.http(service, `${ctx.lab.plan.routePrefix}/orders`, {
    method: 'POST', token, body: { amountCents: Math.floor(ctx.lab.plan.economics.payoutCapCents / 4), beneficiary: 'acct_vendor_1' },
  })
  assert.equal(created.status, 201)
  return created.json<{ order: { id: string } }>().order.id
}

test('unverified session: third-party draft approval requires a rebind first', async () => {
  await withLab('vulnerable', async (lab, ctx) => {
    const prefix = lab.plan.routePrefix
    const finance = await unverifiedFinanceSession(ctx)
    const listed = await ctx.http('api', `${prefix}/payouts`, { token: finance })
    const payout = listed.json<{ payouts: Array<{ id: string; status: string }> }>().payouts.find((item) => item.status === 'draft')
    assert.ok(payout)

    const direct = await ctx.http('api', `${prefix}/payouts/${payout.id}/approve`, { method: 'POST', token: finance })
    assert.equal(direct.status, 403)
    assert.equal(direct.json<{ error: string }>().error, 'rebind required before approval')
    const owner = await ctx.login('owner_a')
    const after = await ctx.http('api', `${prefix}/payouts/${payout.id}`, { token: owner })
    assert.equal(after.json<{ payout: { status: string } }>().payout.status, 'draft')
    assert.equal(lab.export().events.terminals.length, 0)
  })
})

test('unverified session: order, ledger and balance reads require a verified session', async () => {
  await withLab('vulnerable', async (lab, ctx) => {
    const prefix = lab.plan.routePrefix
    const member = await ctx.login('member_a')
    const orderId = await createOrder(ctx, member)
    const finance = await unverifiedFinanceSession(ctx)
    for (const path of ['/orders', `/orders/${orderId}`, '/ledger', '/balance']) {
      const denied = await ctx.http('api', `${prefix}${path}`, { token: finance })
      assert.equal(denied.status, 403, path)
      assert.equal(denied.json<{ error: string }>().error, 'verified session required', path)
    }
    // Verified sessions keep read access.
    assert.equal((await ctx.http('api', `${prefix}/orders/${orderId}`, { token: member })).status, 200)
    assert.equal((await ctx.http('api', `${prefix}/ledger`, { token: member })).status, 200)
    assert.equal((await ctx.http('api', `${prefix}/balance`, { token: member })).status, 200)
  })
})

for (const mode of ['vulnerable', 'hardened'] as const) {
  test(`${mode}: viewer role cannot create, rebind or capture orders`, async () => {
    await withLab(mode, async (lab, ctx) => {
      const prefix = lab.plan.routePrefix
      const viewer = await ctx.login('viewer_a')
      const member = await ctx.login('member_a')
      const expectWriteDenied = (status: number, text: string, label: string) => {
        assert.equal(status, 403, label)
        assert.equal(JSON.parse(text).error, 'write role required', label)
      }
      for (const service of ['api', 'edge'] as const) {
        const created = await ctx.http(service, `${prefix}/orders`, {
          method: 'POST', token: viewer, body: { amountCents: 500, beneficiary: 'acct_vendor_1' },
        })
        expectWriteDenied(created.status, created.text, `create via ${service}`)
      }
      const orderId = await createOrder(ctx, member)
      const rebind = await ctx.http('api', `${prefix}/orders/${orderId}/rebind`, {
        method: 'PATCH', token: viewer, body: { beneficiary: 'acct_vendor_2' },
      })
      expectWriteDenied(rebind.status, rebind.text, 'rebind')
      assert.equal((await ctx.http('api', `${prefix}/orders/${orderId}/rebind`, { method: 'PATCH', token: member, body: {} })).status, 200)
      const settle = await ctx.http('api', `${prefix}/orders/${orderId}/settle-race`, { method: 'POST', token: viewer })
      expectWriteDenied(settle.status, settle.text, 'settle-race')
      const order = await ctx.http('api', `${prefix}/orders/${orderId}`, { token: member })
      assert.equal(order.json<{ order: { status: string; captureSeq: number } }>().order.captureSeq, 0)
      assert.equal(lab.export().events.terminals.length, 0)
    })
  })
}

test('vulnerable: edge amount header is ignored on direct api requests without the bridge credential', async () => {
  await withLab('vulnerable', async (lab, ctx) => {
    const prefix = lab.plan.routePrefix
    const member = await ctx.login('member_a')
    const cap = lab.plan.economics.payoutCapCents
    const overCap = cap + lab.plan.economics.orderAmountCents
    const raw = `{"amountCents":${overCap},"beneficiary":"acct_vendor_1","amountCents":${overCap + 1}}`
    const variants: Array<Record<string, string>> = [
      { 'x-lab-edge-amount': '100' },
      { 'x-lab-edge-amount': '100', 'x-edge-bridge': 'not-the-instance-credential' },
      { 'x-lab-edge-amount': '100', 'x-edge-bridge': '' },
    ]
    for (const headers of variants) {
      const created = await ctx.http('api', `${prefix}/orders`, { method: 'POST', token: member, rawBody: raw, headers })
      assert.equal(created.status, 422, JSON.stringify(Object.keys(headers)))
    }
    assert.equal(lab.export().events.hops.filter((hop) => hop.chainId === 'PG-C4').length, 0)

    // Requests the edge forwards still carry the credential, so normal edge-created orders work.
    await createOrder(ctx, member, 'edge')
  })
})

test('vulnerable: PG-C1..C4 reference solvers stay 4/4; hardened and PG-D1..D3 stay terminal-silent', async () => {
  await withLab('vulnerable', async (lab) => {
    const findings = await runReferenceSolvers(lab)
    assert.deepEqual(findings.map((finding) => finding.chainId).sort(), ['PG-C1', 'PG-C2', 'PG-C3', 'PG-C4'])
    assert.equal(lab.export().confirmed.length, 4)
  })
  await withLab('hardened', async (lab) => {
    assert.deepEqual(await runReferenceSolvers(lab), [])
    assert.equal(lab.export().events.terminals.length, 0)
  })
  for (const [twin, chain] of [['PG-D1', 'PG-C1'], ['PG-D2', 'PG-C2'], ['PG-D3', 'PG-C3']] as const) {
    await withLab('vulnerable', async (lab) => {
      assert.deepEqual(await runReferenceSolvers(lab, [chain]), [], twin)
      assert.equal(lab.export().events.terminals.length, 0, twin)
      assert.equal(lab.oracle.evaluate(chain).confirmed, false, twin)
    }, twin)
  }
})
