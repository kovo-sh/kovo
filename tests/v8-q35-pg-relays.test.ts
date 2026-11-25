process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'
import { solveC1 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c1.ts'
import { solveC2 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c2.ts'
import { solveC3 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c3.ts'
import { solveC4 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c4.ts'
import type { ServiceId } from '../benchmarks/multihop-saas/lib/types.ts'

function publicOnlyContext(lab: Awaited<ReturnType<typeof startPaygrid>>) {
  const base = createSolverContext(lab)
  const publicServices = new Set<ServiceId>(['edge', 'api', 'idp'])
  return {
    ...base,
    http: async (service: ServiceId, path: string, opts?: Parameters<typeof base.http>[2]) => {
      if (!publicServices.has(service)) {
        throw new Error(`non-public service called: ${service} ${path}`)
      }
      return base.http(service, path, opts)
    },
  }
}

test('PayGrid: PG-C1..PG-C4 all complete using ONLY public origins (edge, api, idp)', async () => {
  const lab = await startPaygrid({ seed: 1, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicOnlyContext(lab)
    const r1 = await solveC1(ctx)
    const r2 = await solveC2(ctx)
    const r3 = await solveC3(ctx)
    const r4 = await solveC4(ctx)
    assert.ok(r1, 'PG-C1 should confirm via public origins')
    assert.ok(r2, 'PG-C2 should confirm via public origins')
    assert.ok(r3, 'PG-C3 should confirm via public origins')
    assert.ok(r4, 'PG-C4 should confirm via public origins')
    assert.equal(lab.export().confirmed.length, 4)
  } finally {
    await lab.stop()
  }
})

test('PayGrid: public relays stay silent in hardened mode and partial twins PG-D1..PG-D3', async () => {
  for (const cfg of [
    { mode: 'hardened' as const, twin: undefined },
    { mode: 'vulnerable' as const, twin: 'PG-D1' },
    { mode: 'vulnerable' as const, twin: 'PG-D2' },
    { mode: 'vulnerable' as const, twin: 'PG-D3' },
  ]) {
    const lab = await startPaygrid({ seed: 1, mode: cfg.mode, twin: cfg.twin, asyncLatencyMs: 5 })
    try {
      const ctx = publicOnlyContext(lab)
      const results = [await solveC1(ctx), await solveC2(ctx), await solveC3(ctx), await solveC4(ctx)]
      assert.deepEqual(results.filter(Boolean), [], `expected silence for ${cfg.mode}/${cfg.twin ?? 'none'}`)
      assert.equal(lab.export().events.terminals.length, 0)
    } finally {
      await lab.stop()
    }
  }
})

test('PayGrid: public job & trace relays enforce session and tenant boundaries', async () => {
  const lab = await startPaygrid({ seed: 1, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = publicOnlyContext(lab)
    const p = lab.plan.routePrefix
    const unauth = await ctx.http('api', `${p}/jobs/mh_job_fake`)
    assert.equal(unauth.status, 401)
    const unauthTrace = await ctx.http('api', `${p}/jobs/mh_job_fake/trace`)
    assert.equal(unauthTrace.status, 401)

    const memberA = await ctx.login('member_a')
    const memberB = await ctx.login('member_b')
    const rendered = await ctx.http('api', `${p}/invoices/${lab.plan.ids.invoiceId}/render`, {
      method: 'POST', token: memberA,
    })
    assert.equal(rendered.status, 202)
    const jobId = rendered.json<{ jobId: string }>().jobId
    const crossTenant = await ctx.http('api', `${p}/jobs/${jobId}/trace`, { token: memberB })
    assert.equal(crossTenant.status, 404)
  } finally {
    await lab.stop()
  }
})
