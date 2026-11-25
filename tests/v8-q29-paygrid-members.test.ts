// Queue #29 regression: paygrid org-scoped read routes outside the intended chains must enforce tenant
// membership. The member roster and the org record were readable for foreign tenants (and the org record
// without any session), which surfaced as an out-of-spec single-hop authorization finding.
// The intended PG-C1..PG-C4 chains must stay solvable in vulnerable mode and silent in hardened mode.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext, runReferenceSolvers } from '../benchmarks/multihop-saas/apps/paygrid/solvers/index.ts'

const CHAINS = ['PG-C1', 'PG-C2', 'PG-C3', 'PG-C4']

for (const mode of ['vulnerable', 'hardened'] as const) {
  test(`${mode}: org roster and org record are member-only`, async () => {
    const lab = await startPaygrid({ seed: 42, mode, asyncLatencyMs: 5 })
    try {
      const ctx = createSolverContext(lab)
      const prefix = lab.plan.routePrefix
      const memberA = await ctx.login('member_a')
      const memberB = await ctx.login('member_b')

      assert.equal((await ctx.http('api', `${prefix}/orgs/org_a/members`)).status, 401)
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_a`)).status, 401)

      const own = await ctx.http('api', `${prefix}/orgs/org_a/members`, { token: memberA })
      assert.equal(own.status, 200)
      assert.ok(own.json<{ members: unknown[] }>().members.length > 0)
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_a`, { token: memberA })).status, 200)
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_b/members`, { token: memberB })).status, 200)
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_b`, { token: memberB })).status, 200)

      for (const org of ['org_b', 'org_c']) {
        assert.equal((await ctx.http('api', `${prefix}/orgs/${org}/members`, { token: memberA })).status, 403, org)
        assert.equal((await ctx.http('api', `${prefix}/orgs/${org}`, { token: memberA })).status, 404, org)
      }
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_a/members`, { token: memberB })).status, 403)
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_a`, { token: memberB })).status, 404)
      assert.equal((await ctx.http('api', `${prefix}/orgs/org_zz/members`, { token: memberA })).status, 404)

      assert.equal(lab.export().events.terminals.length, 0)
    } finally {
      await lab.stop()
    }
  })
}

test('vulnerable: intended PG-C1..PG-C4 chains stay solvable and confirmed', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const findings = await runReferenceSolvers(lab, CHAINS)
    assert.deepEqual(findings.map((finding) => finding.chainId).sort(), CHAINS)
    for (const chainId of CHAINS) {
      const evaluation = lab.oracle.evaluate(chainId)
      assert.equal(evaluation.confirmed, true, `${chainId}: ${evaluation.failureReason ?? 'incomplete'}`)
    }
  } finally {
    await lab.stop()
  }
})

test('hardened: reference solvers stay silent', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'hardened', asyncLatencyMs: 5 })
  try {
    const findings = await runReferenceSolvers(lab, CHAINS)
    assert.deepEqual(findings, [])
    assert.equal(lab.export().confirmed.length, 0)
  } finally {
    await lab.stop()
  }
})
