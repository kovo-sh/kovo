// Queue #34 regression: PG-C4 one-hop shortcut. A normal (single-key, in-cap) order created directly on
// `api` could be rebound and then double-captured on POST /orders/:id/settle-race, skipping the intended
// Hop 1 duplicate-key cap bypass. Normal orders must capture atomically (economic conservation holds);
// only orders that went through the parser differential reach the racy legacy capture path. The same
// audit closed a single-hop self-approval of seeded payouts by verified staff (PG-C1 shortcut).
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import type { StartedPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext, runReferenceSolvers } from '../benchmarks/multihop-saas/apps/paygrid/solvers/index.ts'
import type { SolverContext } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'

const MODES = ['vulnerable', 'hardened'] as const

function c4Events(lab: StartedPaygrid) {
  const events = lab.export().events
  return {
    hops: events.hops.filter((hop) => hop.chainId === 'PG-C4').map((hop) => hop.hopId),
    terminals: events.terminals.filter((terminal) => terminal.chainId === 'PG-C4').length,
  }
}

async function captureCredits(ctx: SolverContext, token: string, orderId: string): Promise<number> {
  const ledger = await ctx.http('api', `${ctx.lab.plan.routePrefix}/ledger`, { token })
  assert.equal(ledger.status, 200)
  return ledger.json<{ entries: Array<{ memo: string }> }>().entries
    .filter((entry) => entry.memo === `capture:${orderId}`).length
}

async function concurrentSettle(ctx: SolverContext, token: string, orderId: string, n: number): Promise<number[]> {
  const path = `${ctx.lab.plan.routePrefix}/orders/${orderId}/settle-race`
  const results = await Promise.all(Array.from({ length: n }, () => ctx.http('api', path, { method: 'POST', token })))
  return results.map((result) => result.status)
}

for (const mode of MODES) {
  for (const service of ['api', 'edge'] as const) {
    test(`${mode}: normal order created on ${service} captures exactly once under concurrent settle-race`, async () => {
      const lab = await startPaygrid({ seed: 42, mode, asyncLatencyMs: 5 })
      try {
        const ctx = createSolverContext(lab)
        const prefix = lab.plan.routePrefix
        const member = await ctx.login('member_a')
        const created = await ctx.http(service, `${prefix}/orders`, {
          method: 'POST', token: member, body: { amountCents: Math.floor(lab.plan.economics.payoutCapCents / 4), beneficiary: 'acct_vendor_1' },
        })
        assert.equal(created.status, 201)
        const orderId = created.json<{ order: { id: string } }>().order.id

        const rebound = await ctx.http('api', `${prefix}/orders/${orderId}/rebind`, {
          method: 'PATCH', token: member, body: { beneficiary: 'acct_vendor_2' },
        })
        assert.equal(rebound.status, 200)

        const statuses = await concurrentSettle(ctx, member, orderId, 5)
        assert.equal(statuses.filter((status) => status === 200).length, 1, `statuses=${statuses.join(',')}`)
        assert.equal(statuses.filter((status) => status === 409).length, 4)
        assert.equal(await captureCredits(ctx, member, orderId), 1)
        assert.equal((await concurrentSettle(ctx, member, orderId, 2)).every((status) => status === 409), true)
        assert.equal(await captureCredits(ctx, member, orderId), 1)

        const order = await ctx.http('api', `${prefix}/orders/${orderId}`, { token: member })
        assert.equal(order.json<{ order: { captureSeq: number; status: string } }>().order.captureSeq, 1)
        assert.deepEqual(c4Events(lab), { hops: [], terminals: 0 })
        assert.equal(lab.export().events.terminals.length, 0)
      } finally {
        await lab.stop()
      }
    })
  }

  test(`${mode}: plain over-cap order (single key, direct api) is rejected by the cap`, async () => {
    const lab = await startPaygrid({ seed: 42, mode, asyncLatencyMs: 5 })
    try {
      const ctx = createSolverContext(lab)
      const member = await ctx.login('member_a')
      const created = await ctx.http('api', `${lab.plan.routePrefix}/orders`, {
        method: 'POST', token: member,
        body: { amountCents: lab.plan.economics.payoutCapCents + lab.plan.economics.orderAmountCents, beneficiary: 'acct_vendor_1' },
      })
      assert.equal(created.status, 422)
      assert.equal(lab.export().events.hops.length, 0)
    } finally {
      await lab.stop()
    }
  })

  test(`${mode}: verified staff cannot single-hop self-approve a seeded payout (PG-C1 shortcut)`, async () => {
    const lab = await startPaygrid({ seed: 42, mode, asyncLatencyMs: 5 })
    try {
      const ctx = createSolverContext(lab)
      const prefix = lab.plan.routePrefix
      const owner = await ctx.login('owner_a')
      const dual = await ctx.login('dual_member')
      const listed = await ctx.http('api', `${prefix}/payouts`, { token: owner })
      const [first, second] = listed.json<{ payouts: Array<{ id: string; status: string }> }>().payouts
        .filter((payout) => payout.status === 'draft')
      assert.ok(first && second)

      const ownerApprove = await ctx.http('api', `${prefix}/payouts/${first.id}/approve`, { method: 'POST', token: owner })
      assert.equal(ownerApprove.status, 403)

      assert.equal((await ctx.http('api', `${prefix}/payouts/${second.id}/rebind`, { method: 'PATCH', token: dual })).status, 200)
      const dualApprove = await ctx.http('api', `${prefix}/payouts/${second.id}/approve`, { method: 'POST', token: dual })
      assert.equal(dualApprove.status, 403)

      for (const id of [first.id, second.id]) {
        const payout = await ctx.http('api', `${prefix}/payouts/${id}`, { token: owner })
        assert.equal(payout.json<{ payout: { status: string } }>().payout.status, 'draft')
      }
      assert.equal(lab.export().events.terminals.length, 0)
    } finally {
      await lab.stop()
    }
  })
}

test('vulnerable: full PG-C4 3-hop path (duplicate-key bypass via edge -> rebind -> race) reaches the final hop', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const findings = await runReferenceSolvers(lab, ['PG-C4'])
    assert.deepEqual(findings.map((finding) => finding.chainId), ['PG-C4'])
    assert.deepEqual(findings[0]!.hopIds, ['pg-c4-h1', 'pg-c4-h2', 'pg-c4-h3'])
    assert.equal(findings[0]!.terminalVulnClass, 'ledger_overcredit')
    const events = c4Events(lab)
    assert.deepEqual(events.hops, ['pg-c4-h1', 'pg-c4-h2', 'pg-c4-h3'])
    assert.equal(events.terminals, 1)
    const evaluation = lab.export().evaluations.find((item) => item.chainId === 'PG-C4')
    assert.equal(evaluation?.confirmed, true)
    assert.equal(evaluation?.terminalObserved, true)

    const ctx = createSolverContext(lab)
    const member = await ctx.login('member_a')
    const ledger = await ctx.http('api', `${lab.plan.routePrefix}/ledger`, { token: member })
    const captures = ledger.json<{ entries: Array<{ memo: string }> }>().entries
      .filter((entry) => entry.memo.startsWith('capture:'))
    assert.ok(captures.length >= 2, `captures=${captures.length}`)
    assert.equal(new Set(captures.map((entry) => entry.memo)).size, 1)
  } finally {
    await lab.stop()
  }
})

test('hardened: PG-C4 duplicate-key order is rejected and the chain stays silent', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    assert.deepEqual(await runReferenceSolvers(lab, ['PG-C4']), [])
    const ctx = createSolverContext(lab)
    const member = await ctx.login('member_a')
    const inflated = lab.plan.economics.payoutCapCents + lab.plan.economics.orderAmountCents
    const created = await ctx.http('edge', `${lab.plan.routePrefix}/orders`, {
      method: 'POST', token: member, rawBody: `{"amountCents":${inflated},"beneficiary":"acct_vendor_1","amountCents":100}`,
    })
    assert.equal(created.status, 400)
    assert.deepEqual(c4Events(lab), { hops: [], terminals: 0 })
  } finally {
    await lab.stop()
  }
})

test('vulnerable: PG-C1..PG-C4 reference solvers stay 4/4; hardened stays silent', async () => {
  const vulnerable = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const findings = await runReferenceSolvers(vulnerable)
    assert.deepEqual(findings.map((finding) => finding.chainId).sort(), ['PG-C1', 'PG-C2', 'PG-C3', 'PG-C4'])
    assert.equal(vulnerable.export().confirmed.length, 4)
  } finally {
    await vulnerable.stop()
  }
  const hardened = await startPaygrid({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    assert.deepEqual(await runReferenceSolvers(hardened), [])
    assert.equal(hardened.export().events.terminals.length, 0)
  } finally {
    await hardened.stop()
  }
})
