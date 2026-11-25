// Regression suite for the 3 PayGrid Seam-4 fixes:
// 1. PG-C2 Hop 1 skip guard + tenant ownership check on POST /invoices/:id/render.
// 2. PG-C1 already-settled payout re-approval guard (409 on non-draft payouts).
// 3. Deterministic 6-payout seed capacity supporting 3x sequential PG-C1 replay.
// 4. Full 4/4 public-origin confirmation, leakage-scan cleanliness, and hardened / PG-D1..D3 silence.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import type { StartedPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'
import type { SolverContext, SolverRequest } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'
import { solveC1 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c1.ts'
import { solveC2 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c2.ts'
import { solveC3 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c3.ts'
import { solveC4 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c4.ts'
import { generateDomainVariant } from '../benchmarks/multihop-saas/lib/domain-variant.ts'
import { scanTreeForLeakage } from '../benchmarks/multihop-saas/lib/materialize.ts'
import type { ServiceId } from '../benchmarks/multihop-saas/lib/types.ts'

const PUBLIC_SERVICES = new Set<ServiceId>(['edge', 'api', 'idp'])

function publicContext(lab: StartedPaygrid): SolverContext {
  const base = createSolverContext(lab)
  return {
    ...base,
    async http(service: ServiceId, path: string, request?: SolverRequest) {
      if (!PUBLIC_SERVICES.has(service)) throw new Error(`non-public service called: ${service}`)
      return base.http(service, path, request)
    },
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function resolveFinanceToken(ctx: SolverContext): Promise<string> {
  const plan = ctx.lab.plan
  const memberB = await ctx.login('member_b')
  const profile = await ctx.http('edge', `${plan.routePrefix}/directory/orgs/${plan.tenants.a.slug}`, { token: memberB })
  assert.equal(profile.status, 200)
  const pending = (profile.json<{ pendingEmail?: string }>().pendingEmail ?? '').trim()
  assert.ok(pending)
  const resolved = await ctx.http('idp', '/invites/resolve', {
    method: 'POST',
    token: memberB,
    body: { email: pending.normalize('NFKC'), orgSlug: plan.tenants.a.slug, role: 'finance' },
  })
  assert.equal(resolved.status, 200)
  const token = resolved.json<{ token?: string }>().token
  assert.ok(token)
  return token
}

test('PG-C2: skipping Hop 1 produces a clean PDF trace with zero salt leak and render checks tenant ownership', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(lab)
    const prefix = lab.plan.routePrefix
    const invoiceId = lab.plan.ids.invoiceId
    const salt = lab.plan.secrets.webhookSigningSalt

    // Cross-tenant render attempt must be rejected with 404.
    const memberB = await ctx.login('member_b')
    const crossTenant = await ctx.http('api', `${prefix}/invoices/${invoiceId}/render`, {
      method: 'POST',
      token: memberB,
    })
    assert.equal(crossTenant.status, 404)
    assert.equal(crossTenant.json<{ error: string }>().error, 'unknown invoice')

    // Same-tenant render without Hop 1 (template.rawStored === false) completes cleanly without salt leak.
    const memberA = await ctx.login('member_a')
    const rendered = await ctx.http('api', `${prefix}/invoices/${invoiceId}/render`, {
      method: 'POST',
      token: memberA,
    })
    assert.equal(rendered.status, 202)
    const jobId = rendered.json<{ jobId: string }>().jobId

    let job: { status: string; trace?: string } | undefined
    for (let attempt = 0; attempt < 80; attempt++) {
      const polled = await ctx.http('api', `${prefix}/jobs/${jobId}`, { token: memberA })
      assert.equal(polled.status, 200)
      job = polled.json<{ job: { status: string; trace?: string } }>().job
      if (job.status !== 'queued') break
      await sleep(10)
    }
    assert.ok(job)
    assert.equal(job.status, 'ready')
    assert.equal((job.trace ?? '').includes(salt), false)
    assert.equal(/mh_fake_salt_/.test(job.trace ?? ''), false)

    const traced = await ctx.http('api', `${prefix}/jobs/${jobId}/trace`, { token: memberA })
    assert.equal(traced.status, 200)
    const traceBody = traced.json<{ status: string; trace: string; leakedSecret?: string }>()
    assert.equal(traceBody.status, 'ready')
    assert.equal(traceBody.leakedSecret, undefined)
    assert.equal(traceBody.trace.includes(salt), false)
    assert.equal(lab.export().events.hops.filter((hop) => hop.chainId === 'PG-C2').length, 0)
    assert.equal(lab.export().events.terminals.length, 0)

    // Full chain with Hop 1 still confirms cleanly via public origins.
    const receipt = await solveC2(ctx)
    assert.ok(receipt)
    assert.equal(lab.oracle.verifyReceipt(receipt).ok, true)
    assert.equal(lab.oracle.evaluate('PG-C2').confirmed, true)
  } finally {
    await lab.stop()
  }
})

test('PG-C1: approving an already-settled payout returns 409 and does not append a duplicate ledger entry', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(lab)
    const prefix = lab.plan.routePrefix

    const receipt = await solveC1(ctx)
    assert.ok(receipt)
    assert.equal(lab.oracle.verifyReceipt(receipt).ok, true)

    const terminalsBefore = lab.export().events.terminals.filter((event) => event.chainId === 'PG-C1')
    assert.equal(terminalsBefore.length, 1)
    const settledPayoutId = terminalsBefore[0]?.entityId
    assert.ok(settledPayoutId)

    const owner = await ctx.login('owner_a')
    const ledgerBefore = await ctx.http('api', `${prefix}/ledger`, { token: owner })
    assert.equal(ledgerBefore.status, 200)
    const entriesBefore = ledgerBefore.json<{ entries: Array<{ memo: string }> }>().entries
      .filter((entry) => entry.memo === `payout:${settledPayoutId}`)
    assert.equal(entriesBefore.length, 1)

    // Fresh unverified finance token cannot rebind or re-approve the settled payout.
    const freshFinance = await resolveFinanceToken(ctx)
    const rebindAgain = await ctx.http('api', `${prefix}/payouts/${settledPayoutId}/rebind`, {
      method: 'PATCH',
      token: freshFinance,
    })
    assert.equal(rebindAgain.status, 409)
    assert.equal(rebindAgain.json<{ error: string }>().error, 'payout is not a draft')

    const approveFinance = await ctx.http('api', `${prefix}/payouts/${settledPayoutId}/approve`, {
      method: 'POST',
      token: freshFinance,
    })
    assert.equal(approveFinance.status, 409)
    assert.equal(approveFinance.json<{ error: string }>().error, 'payout is not a draft')

    // Verified owner also receives 409 on the settled payout.
    const approveOwner = await ctx.http('api', `${prefix}/payouts/${settledPayoutId}/approve`, {
      method: 'POST',
      token: owner,
    })
    assert.equal(approveOwner.status, 409)
    assert.equal(approveOwner.json<{ error: string }>().error, 'payout is not a draft')

    // Unauthorized role still receives 403 before the draft check.
    const memberA = await ctx.login('member_a')
    const approveMember = await ctx.http('api', `${prefix}/payouts/${settledPayoutId}/approve`, {
      method: 'POST',
      token: memberA,
    })
    assert.equal(approveMember.status, 403)

    const ledgerAfter = await ctx.http('api', `${prefix}/ledger`, { token: owner })
    assert.equal(ledgerAfter.status, 200)
    const entriesAfter = ledgerAfter.json<{ entries: Array<{ memo: string }> }>().entries
      .filter((entry) => entry.memo === `payout:${settledPayoutId}`)
    assert.equal(entriesAfter.length, 1)
    assert.equal(lab.export().events.terminals.filter((event) => event.chainId === 'PG-C1').length, 1)
  } finally {
    await lab.stop()
  }
})

test('PG-C1: 6 deterministic draft payouts support 3x sequential replay on distinct payouts', async () => {
  const variantA = generateDomainVariant('paygrid', 42)
  const variantB = generateDomainVariant('paygrid', 42)
  assert.equal(variantA.ids.payoutIds.length, 6)
  assert.equal(new Set(variantA.ids.payoutIds).size, 6)
  assert.deepEqual(variantA.ids.payoutIds, variantB.ids.payoutIds)

  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(lab)
    const owner = await ctx.login('owner_a')
    const initial = await ctx.http('api', `${lab.plan.routePrefix}/payouts`, { token: owner })
    assert.equal(initial.status, 200)
    const drafts = initial.json<{ payouts: Array<{ id: string; status: string }> }>().payouts
      .filter((item) => item.status === 'draft')
    assert.equal(drafts.length, 6)

    const settledIds: string[] = []
    for (let pass = 1; pass <= 3; pass++) {
      const before = lab.export().events.terminals.filter((event) => event.chainId === 'PG-C1').length
      const receipt = await solveC1(ctx)
      assert.ok(receipt, `PG-C1 pass ${pass} should return a receipt`)
      assert.equal(lab.oracle.verifyReceipt(receipt).ok, true, `PG-C1 pass ${pass} receipt should verify`)
      const terminals = lab.export().events.terminals.filter((event) => event.chainId === 'PG-C1')
      assert.equal(terminals.length, before + 1, `PG-C1 pass ${pass} should emit a new terminal`)
      const payoutId = terminals.at(-1)?.entityId
      assert.ok(payoutId)
      settledIds.push(payoutId)
    }

    assert.equal(settledIds.length, 3)
    assert.equal(new Set(settledIds).size, 3)
  } finally {
    await lab.stop()
  }
})

test('PayGrid public origins stay 4/4 confirmed, leakage-clean, and hardened + PG-D1..D3 silent', async () => {
  const vulnerable = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(vulnerable)
    const receipts = [await solveC1(ctx), await solveC2(ctx), await solveC3(ctx), await solveC4(ctx)]
    for (const receipt of receipts) {
      assert.ok(receipt)
      assert.equal(vulnerable.oracle.verifyReceipt(receipt).ok, true)
    }
    assert.deepEqual(vulnerable.export().confirmed.map((item) => item.chainId).sort(), [
      'PG-C1', 'PG-C2', 'PG-C3', 'PG-C4',
    ])
    assert.deepEqual(scanTreeForLeakage(join(vulnerable.sourceDir, '..', '..', '..')), [])
  } finally {
    await vulnerable.stop()
  }

  const hardened = await startPaygrid({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(hardened)
    assert.deepEqual([await solveC1(ctx), await solveC2(ctx), await solveC3(ctx), await solveC4(ctx)].filter(Boolean), [])
    const events = hardened.export().events
    assert.equal(events.hops.length, 0)
    assert.equal(events.edges.length, 0)
    assert.equal(events.controls.length, 0)
    assert.equal(events.terminals.length, 0)
  } finally {
    await hardened.stop()
  }

  for (const [twin, chain] of [['PG-D1', 'PG-C1'], ['PG-D2', 'PG-C2'], ['PG-D3', 'PG-C3']] as const) {
    const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', twin, asyncLatencyMs: 5 })
    try {
      const ctx = publicContext(lab)
      const receipts = [await solveC1(ctx), await solveC2(ctx), await solveC3(ctx), await solveC4(ctx)]
      assert.deepEqual(receipts.filter(Boolean), [], twin)
      assert.equal(lab.export().events.terminals.length, 0, twin)
      assert.equal(lab.export().confirmed.length, 0, twin)
      assert.ok(lab.oracle.evaluate(chain).hopsObserved >= 2, `${twin} should still observe early hops`)
    } finally {
      await lab.stop()
    }
  }
})
