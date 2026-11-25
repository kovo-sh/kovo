process.env.KOVO_ALLOW_LOCAL_LAB = '1'

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

async function signedExport(
  ctx: SolverContext, token: string, tenantId: 'org_a' | 'org_b',
): Promise<{ jobId: string; signedUrl: string; prefix: string }> {
  const routePrefix = ctx.lab.plan.routePrefix
  const created = await ctx.http('api', `${routePrefix}/orgs/${tenantId}/exports`, {
    method: 'POST', token,
  })
  assert.equal(created.status, 202)
  const jobId = created.json<{ jobId: string }>().jobId

  let ready = false
  for (let attempt = 0; attempt < 80; attempt++) {
    const polled = await ctx.http('api', `${routePrefix}/exports/${jobId}`, { token })
    assert.equal(polled.status, 200)
    const status = polled.json<{ job: { status: string } }>().job.status
    if (status === 'ready') {
      ready = true
      break
    }
    assert.notEqual(status, 'failed')
    assert.notEqual(status, 'cancelled')
    await sleep(10)
  }
  assert.ok(ready, 'export job did not become ready')

  const minted = await ctx.http('api', `${routePrefix}/exports/${jobId}/url`, { token })
  assert.equal(minted.status, 200)
  return { jobId, ...minted.json<{ signedUrl: string; prefix: string }>() }
}

function retargetExport(signedUrl: string, fromSlug: string, toSlug: string): string {
  const target = new URL(signedUrl)
  const marker = `/files/export/${fromSlug}/`
  assert.ok(target.pathname.startsWith(marker))
  const fileName = target.pathname.slice(marker.length)
  target.pathname = `/files/export/${toSlug}/${fileName}`
  return target.toString()
}

test('PG-C2 confirms without an auxiliary derivation header and binds the verified key digest', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const base = publicContext(lab)
    let observedWebhook = false
    const ctx: SolverContext = {
      ...base,
      async http(service, path, request) {
        if (path === `${lab.plan.routePrefix}/webhooks/settlement`) {
          observedWebhook = true
          assert.equal(request?.headers?.['x-lab-derived-from'], undefined)
        }
        return base.http(service, path, request)
      },
    }

    const receipt = await solveC2(ctx)
    assert.ok(observedWebhook)
    assert.ok(receipt)
    assert.equal(receipt.chainId, 'PG-C2')
    assert.deepEqual(receipt.hops.map((hop) => hop.hopId), [
      'pg-c2-h1', 'pg-c2-h2', 'pg-c2-h3', 'pg-c2-h4',
    ])
    assert.equal(lab.oracle.verifyReceipt(receipt).ok, true)
    assert.equal(lab.oracle.evaluate('PG-C2').confirmed, true)

    const binding = lab.export().events.edges.find((edge) =>
      edge.chainId === 'PG-C2' && edge.fromHopId === 'pg-c2-h3' && edge.toHopId === 'pg-c2-h4')
    assert.ok(binding)
    assert.equal(binding.derivedFromDigest, ctx.digest(lab.plan.secrets.webhookSigningSalt))
  } finally {
    await lab.stop()
  }
})

test('PG-C3: org_a export paths deny org_c while the direct org_b overlap still confirms', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(lab)
    const memberA = await ctx.login('member_a')
    const own = await signedExport(ctx, memberA, 'org_a')
    assert.equal((await ctx.httpUrl(own.signedUrl, { token: memberA })).status, 200)

    const foreign = new URL(retargetExport(own.signedUrl, lab.plan.tenants.a.slug, lab.plan.tenants.c.slug))
    const denied = await ctx.httpUrl(foreign.toString(), { token: memberA })
    assert.equal(denied.status, 403)
    assert.equal(denied.text.includes(lab.plan.economics.treasuryCanary), false)
    assert.equal(lab.export().events.terminals.length, 0)

    const receipt = await solveC3(ctx)
    assert.ok(receipt)
    assert.equal(receipt.chainId, 'PG-C3')
    assert.deepEqual(receipt.hops.map((hop) => hop.hopId), [
      'pg-c3-h1', 'pg-c3-h2', 'pg-c3-h3', 'pg-c3-h4', 'pg-c3-h5',
    ])
    const evaluation = lab.oracle.evaluate('PG-C3')
    assert.equal(evaluation.confirmed, true, evaluation.failureReason ?? 'unconfirmed')
    assert.equal(evaluation.hopsObserved, 5)
    assert.equal(lab.export().events.terminals.filter((event) => event.chainId === 'PG-C3').length, 1)
  } finally {
    await lab.stop()
  }
})

test('POST /sessions/revoke removes the caller token and /v1/payouts then returns 401', async () => {
  const lab = await startPaygrid({ seed: 1, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(lab)
    assert.equal(lab.plan.routePrefix, '/v1')
    const token = await ctx.login('member_a')
    assert.equal((await ctx.http('api', '/v1/payouts', { token })).status, 200)

    const before = await ctx.http('idp', '/metrics')
    assert.equal(before.json<{ sessions: number }>().sessions, 1)
    const revoked = await ctx.http('idp', '/sessions/revoke', { method: 'POST', token })
    assert.equal(revoked.status, 200)

    const after = await ctx.http('idp', '/metrics')
    assert.equal(after.json<{ sessions: number }>().sessions, 0)
    assert.equal((await ctx.http('api', '/v1/payouts', { token })).status, 401)
    assert.equal((await ctx.http('idp', '/sessions/revoke', { method: 'POST', token })).status, 401)
  } finally {
    await lab.stop()
  }
})

test('PayGrid public reference flows remain 4/4 with hardened and PG-D1..PG-D3 terminal-silent', async () => {
  const vulnerable = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicContext(vulnerable)
    const receipts = [await solveC1(ctx), await solveC2(ctx), await solveC3(ctx), await solveC4(ctx)]
    assert.ok(receipts.every(Boolean))
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

  for (const twin of ['PG-D1', 'PG-D2', 'PG-D3'] as const) {
    const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', twin, asyncLatencyMs: 5 })
    try {
      const ctx = publicContext(lab)
      const receipts = [await solveC1(ctx), await solveC2(ctx), await solveC3(ctx), await solveC4(ctx)]
      assert.deepEqual(receipts.filter(Boolean), [], twin)
      assert.equal(lab.export().events.terminals.length, 0, twin)
      assert.equal(lab.export().confirmed.length, 0, twin)
    } finally {
      await lab.stop()
    }
  }
})
