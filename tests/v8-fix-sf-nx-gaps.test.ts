// Regression coverage for two lab state gaps found by the bench invariants harness:
//  - ShipForge SF-C1: the h4 batch read rotates the signing secret, and release verified only the
//    originally provisioned key, so a second pass on the same lab got 403 on release. Release now
//    verifies the current key version and the provisioned one.
//  - NexusIAM NX-C4: the export status/result relay accepted any session holding the seeded job id,
//    so an outsider could read the export without the share-handle and status-poll hops. The api
//    now requires share-handle lineage per session, and the worker scopes reads to the caller tenant
//    and requires a ready status poll by the same requester before serving the artifact.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import { createSolverContext as createSfCtx, runReferenceSolvers } from '../benchmarks/multihop-saas/apps/shipforge/solvers/index.ts'
import { solveC1 as sfC1 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c1.ts'
import { TWINS as SF_TWINS } from '../benchmarks/multihop-saas/apps/shipforge/truth/blueprint.ts'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { createSolverContext as createNxCtx, runNexusiamSolvers } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/index.ts'
import { solveC4 as nxC4 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c4.ts'
import { TWINS as NX_TWINS } from '../benchmarks/multihop-saas/apps/nexusiam/truth/blueprint.ts'

type SfLab = Awaited<ReturnType<typeof startShipforge>>
type NxLab = Awaited<ReturnType<typeof startNexusiam>>

function terminals(lab: SfLab | NxLab, chainId: string): number {
  return lab.export().events.terminals.filter((terminal) => terminal.chainId === chainId).length
}

async function withSf(mode: 'vulnerable' | 'hardened', twin: string | undefined, fn: (lab: SfLab) => Promise<void>): Promise<void> {
  const lab = await startShipforge({ seed: 42, mode, twin, asyncLatencyMs: 5 } as Parameters<typeof startShipforge>[0])
  try { await fn(lab) } finally { await lab.stop() }
}

async function withNx(mode: 'vulnerable' | 'hardened', twin: string | undefined, fn: (lab: NxLab) => Promise<void>): Promise<void> {
  const lab = await startNexusiam({ seed: 42, mode, twin, asyncLatencyMs: 5 } as Parameters<typeof startNexusiam>[0])
  try { await fn(lab) } finally { await lab.stop() }
}

test('SF-C1: two sequential passes on one lab both confirm with verified receipts', async () => {
  await withSf('vulnerable', undefined, async (lab) => {
    const first = await sfC1(createSfCtx(lab))
    const second = await sfC1(createSfCtx(lab))
    assert.ok(first, 'first pass produced no receipt')
    assert.ok(second, 'second pass produced no receipt')
    assert.equal(lab.oracle.verifyReceipt(first).ok, true)
    assert.equal(lab.oracle.verifyReceipt(second).ok, true)
    assert.equal(lab.oracle.evaluate('SF-C1').confirmed, true)
    assert.equal(terminals(lab, 'SF-C1'), 2)
  })
})

test('SF-C1: two concurrent passes on one lab both confirm with verified receipts', async () => {
  await withSf('vulnerable', undefined, async (lab) => {
    const receipts = await Promise.all([sfC1(createSfCtx(lab)), sfC1(createSfCtx(lab))])
    for (const [index, receipt] of receipts.entries()) {
      assert.ok(receipt, `pass ${index} produced no receipt`)
      assert.equal(lab.oracle.verifyReceipt(receipt).ok, true)
    }
    assert.equal(lab.oracle.evaluate('SF-C1').confirmed, true)
    assert.equal(terminals(lab, 'SF-C1'), 2)
  })
})

test('ShipForge hardened and twins D1..D3 stay silent on their base chain', async () => {
  await withSf('hardened', undefined, async (lab) => {
    assert.deepEqual(await runReferenceSolvers(lab), [])
    assert.equal(lab.export().events.terminals.length, 0)
  })
  for (const twin of SF_TWINS) {
    await withSf('vulnerable', twin.id, async (lab) => {
      const findings = await runReferenceSolvers(lab)
      assert.equal(findings.some((finding) => finding.chainId === twin.baseChainId), false, `${twin.id}: base chain receipt`)
      assert.equal(terminals(lab, twin.baseChainId), 0, `${twin.id}: base chain terminal`)
    })
  }
})

test('NX-C4: seeded export cannot be read directly without share-handle and poll lineage', async () => {
  await withNx('vulnerable', undefined, async (lab) => {
    const ctx = createNxCtx(lab)
    const prefix = lab.plan.routePrefix
    const jobId = encodeURIComponent(lab.plan.nexus.exportJobId)
    const canary = lab.plan.nexus.canary
    const sessions = [
      await ctx.login('member_b'),
      await ctx.login('member_a'),
      await ctx.login('revoked_or_demoted'),
    ]
    // Let the seeded job reach its ready state first.
    await new Promise((resolve) => setTimeout(resolve, 30))
    for (const token of sessions) {
      for (let round = 0; round < 2; round++) {
        const status = await ctx.http('api', `${prefix}/exports/${jobId}`, { token })
        assert.notEqual(status.status, 200)
        assert.equal(status.text.includes(lab.plan.nexus.exportHandle), false)
        const result = await ctx.http('api', `${prefix}/exports/${jobId}/result`, { token })
        assert.notEqual(result.status, 200)
        assert.equal(result.text.includes(canary), false)
      }
    }
    assert.equal(terminals(lab, 'NX-C4'), 0)
    assert.equal(lab.export().events.edges.filter((edge) => edge.chainId === 'NX-C4').length, 0)

    // An outsider that resolved the handle is still scoped out by tenant at the worker.
    const memberB = sessions[0]!
    const facets = await ctx.http('api',
      `${prefix}/search/facets?tenant=${encodeURIComponent(lab.plan.tenants.a.slug)}&q=${encodeURIComponent(lab.plan.nexus.privateFolderName)}`,
      { token: memberB })
    assert.equal(facets.status, 200)
    const metadata = await ctx.http('api',
      `${prefix}/docs/share/${lab.plan.nexus.shareLinkId}/metadata?folder=${encodeURIComponent(lab.plan.nexus.privateFolderName)}`,
      { token: memberB })
    assert.equal(metadata.status, 200)
    {
      const status = await ctx.http('api', `${prefix}/exports/${jobId}`, { token: memberB })
      assert.equal(status.status, 404)
      const result = await ctx.http('api', `${prefix}/exports/${jobId}/result`, { token: memberB })
      assert.notEqual(result.status, 200)
      assert.equal(result.text.includes(canary), false)
    }
    assert.equal(terminals(lab, 'NX-C4'), 0)
  })
})

test('NX-C4: the reference solver confirms in single, sequential and concurrent passes', async () => {
  await withNx('vulnerable', undefined, async (lab) => {
    const single = await nxC4(createNxCtx(lab))
    assert.ok(single, 'single pass produced no receipt')
    assert.equal(lab.oracle.verifyReceipt(single).ok, true)
    const second = await nxC4(createNxCtx(lab))
    assert.ok(second, 'sequential second pass produced no receipt')
    assert.equal(lab.oracle.verifyReceipt(second).ok, true)
    assert.equal(lab.oracle.evaluate('NX-C4').confirmed, true)
  })
  await withNx('vulnerable', undefined, async (lab) => {
    const receipts = await Promise.all([nxC4(createNxCtx(lab)), nxC4(createNxCtx(lab))])
    for (const [index, receipt] of receipts.entries()) {
      assert.ok(receipt, `concurrent pass ${index} produced no receipt`)
      assert.equal(lab.oracle.verifyReceipt(receipt).ok, true)
    }
    assert.equal(lab.oracle.evaluate('NX-C4').confirmed, true)
    assert.ok(terminals(lab, 'NX-C4') >= 2)
  })
})

test('NexusIAM hardened and twins D1..D3 stay silent on their base chain', async () => {
  await withNx('hardened', undefined, async (lab) => {
    assert.deepEqual(await runNexusiamSolvers(lab), [])
    assert.equal(lab.export().events.terminals.length, 0)
  })
  for (const twin of NX_TWINS) {
    await withNx('vulnerable', twin.id, async (lab) => {
      const findings = await runNexusiamSolvers(lab)
      assert.equal(findings.some((finding) => finding.chainId === twin.baseChainId), false, `${twin.id}: base chain receipt`)
      assert.equal(terminals(lab, twin.baseChainId), 0, `${twin.id}: base chain terminal`)
    })
  }
})
