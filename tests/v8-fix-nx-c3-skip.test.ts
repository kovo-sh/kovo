// Regression coverage for NexusIAM NX-C3 document lineage enforcement:
//  - Private document content reads (GET {prefix}/docs/:id/content) require the caller's
//    (session, delegation) pair to have opened the document's metadata via GET {prefix}/docs/:id.
//  - Private document metadata opens (GET {prefix}/docs/:id) require the document to have been
//    listed via GET {prefix}/docs for the same (session, delegation) pair.
//  - Public documents remain readable without prior listing or metadata open, and full NX-C3
//    confirmation continues to pass in single, concurrent, and 3x sequential runs while hardened
//    mode and NX-D1..NX-D3 twins remain silent.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { scanTreeForLeakage } from '../benchmarks/multihop-saas/lib/materialize.ts'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { createSolverContext, runNexusiamSolvers } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/index.ts'
import { solveC3 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c3.ts'
import { TWINS } from '../benchmarks/multihop-saas/apps/nexusiam/truth/blueprint.ts'
import type { PersonaKey } from '../benchmarks/multihop-saas/apps/nexusiam/src/shared.ts'

type NxLab = Awaited<ReturnType<typeof startNexusiam>>

async function withLab(
  mode: 'vulnerable' | 'hardened',
  twin: string | undefined,
  fn: (lab: NxLab) => Promise<void>,
): Promise<void> {
  const lab = await startNexusiam({ seed: 42, mode, twin, asyncLatencyMs: 5 } as Parameters<typeof startNexusiam>[0])
  try {
    await fn(lab)
  } finally {
    await lab.stop()
  }
}

function terminals(lab: NxLab, chainId: string): number {
  return lab.export().events.terminals.filter((terminal) => terminal.chainId === chainId).length
}

async function primeAndFetchDelegation(lab: NxLab, ctx: ReturnType<typeof createSolverContext>): Promise<string> {
  const slug = lab.plan.tenants.a.slug
  const owner = await ctx.login('owner_a')
  const primed = await ctx.http('cdn', `/public/profile/${slug}.css`, { token: owner })
  assert.equal(primed.status, 200)
  const member = await ctx.login('member_b')
  const served = await ctx.http('cdn', `/public/profile/${slug}.css`, { token: member })
  assert.equal(served.status, 200)
  const key = served.headers['x-delegation-key']
  assert.ok(key, 'expected cached org_a delegation key')
  return key
}

const SKIP_PERSONAS: readonly PersonaKey[] = ['member_b', 'viewer_a', 'member_a']

test('NX-C3: skipping Hop 3 (GET /docs/:id) returns 403 and leaks no canary across personas', async () => {
  await withLab('vulnerable', undefined, async (lab) => {
    const ctx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const canary = lab.plan.nexus.canary
    const delegationKey = await primeAndFetchDelegation(lab, ctx)

    for (const persona of SKIP_PERSONAS) {
      const token = await ctx.login(persona)
      const listing = await ctx.http('api', `${prefix}/docs`, {
        token,
        headers: { 'x-delegation-key': delegationKey, 'x-workspace-id': '' },
      })
      assert.equal(listing.status, 200, `${persona} listing should succeed with org_a delegation`)
      const docId = listing.json<{ docs: Array<{ id: string }> }>().docs[0]?.id
      assert.equal(docId, lab.plan.nexus.privateDocId)

      const content = await ctx.http('api', `${prefix}/docs/${docId}/content`, {
        token,
        headers: { 'x-delegation-key': delegationKey, 'x-workspace-id': '' },
      })
      assert.equal(content.status, 403, `${persona} skipping Hop 3 must get 403`)
      assert.equal(content.json<{ error: string }>().error, 'document metadata must be opened first')
      assert.equal(content.text.includes(canary), false, `${persona} must not receive canary`)
    }
    assert.equal(terminals(lab, 'NX-C3'), 0)
  })
})

test('NX-C3: skipping Hop 2 (GET /docs) or both Hops 2-3 returns 403 and leaks no canary across personas', async () => {
  await withLab('vulnerable', undefined, async (lab) => {
    const ctx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const docId = lab.plan.nexus.privateDocId
    const canary = lab.plan.nexus.canary
    const delegationKey = await primeAndFetchDelegation(lab, ctx)

    for (const persona of SKIP_PERSONAS) {
      const token = await ctx.login(persona)
      const headers = { 'x-delegation-key': delegationKey, 'x-workspace-id': '' }

      // Skipping both H2 and H3.
      const directContent = await ctx.http('api', `${prefix}/docs/${docId}/content`, { token, headers })
      assert.equal(directContent.status, 403, `${persona} skipping H2+H3 must get 403`)
      assert.equal(directContent.json<{ error: string }>().error, 'document metadata must be opened first')
      assert.equal(directContent.text.includes(canary), false)

      // Skipping H2 and attempting H3 -> H4.
      const directOpen = await ctx.http('api', `${prefix}/docs/${docId}`, { token, headers })
      assert.equal(directOpen.status, 403, `${persona} skipping H2 must get 403 on metadata open`)
      assert.equal(directOpen.text.includes(canary), false)

      const afterFailedOpen = await ctx.http('api', `${prefix}/docs/${docId}/content`, { token, headers })
      assert.equal(afterFailedOpen.status, 403, `${persona} content after denied open must get 403`)
      assert.equal(afterFailedOpen.json<{ error: string }>().error, 'document metadata must be opened first')
      assert.equal(afterFailedOpen.text.includes(canary), false)
    }
    assert.equal(terminals(lab, 'NX-C3'), 0)
  })
})

test('NX-C3: opened metadata lineage is scoped per session (another session cannot skip Hop 3)', async () => {
  await withLab('vulnerable', undefined, async (lab) => {
    const firstCtx = createSolverContext(lab)
    const receipt = await solveC3(firstCtx)
    assert.ok(receipt, 'initial full NX-C3 pass should confirm')
    assert.equal(lab.oracle.verifyReceipt(receipt).ok, true)

    const secondCtx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const docId = lab.plan.nexus.privateDocId
    const canary = lab.plan.nexus.canary
    const delegationKey = await primeAndFetchDelegation(lab, secondCtx)

    for (const persona of SKIP_PERSONAS) {
      const freshToken = await secondCtx.login(persona)
      const content = await secondCtx.http('api', `${prefix}/docs/${docId}/content`, {
        token: freshToken,
        headers: { 'x-delegation-key': delegationKey, 'x-workspace-id': '' },
      })
      assert.equal(content.status, 403, `fresh ${persona} session must not inherit prior opened doc`)
      assert.equal(content.json<{ error: string }>().error, 'document metadata must be opened first')
      assert.equal(content.text.includes(canary), false)
    }
    assert.equal(terminals(lab, 'NX-C3'), 1)
  })
})

test('public document access remains intact without prior listing or metadata open', async () => {
  await withLab('vulnerable', undefined, async (lab) => {
    const ctx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const owner = await ctx.login('owner_a')
    const css = await ctx.http('cdn', `/public/profile/${lab.plan.tenants.a.slug}.css`, { token: owner })
    const delegationKey = css.headers['x-delegation-key']
    assert.ok(delegationKey)
    const publicDocId = `mh_doc_${createHash('sha256').update(`${lab.plan.seed}:${lab.plan.seedSet}:shared-doc`).digest('hex').slice(0, 24)}`

    const content = await ctx.http('api', `${prefix}/docs/${publicDocId}/content`, {
      token: owner,
      headers: { 'x-delegation-key': delegationKey },
    })
    assert.equal(content.status, 200)
    assert.match(content.text, /shared workspace handbook/)

    const metadata = await ctx.http('api', `${prefix}/docs/${publicDocId}`, {
      token: owner,
      headers: { 'x-delegation-key': delegationKey },
    })
    assert.equal(metadata.status, 200)
    assert.equal(metadata.json<{ doc: { id: string } }>().doc.id, publicDocId)
    assert.equal(terminals(lab, 'NX-C3'), 0)
  })
})

test('NX-C3: full solver confirms cleanly in single, concurrent, and 3x sequential passes', async () => {
  // Single pass + 3x sequential passes on one live lab.
  await withLab('vulnerable', undefined, async (lab) => {
    for (let pass = 1; pass <= 3; pass++) {
      const receipt = await solveC3(createSolverContext(lab))
      assert.ok(receipt, `sequential pass ${pass} produced no receipt`)
      assert.equal(lab.oracle.verifyReceipt(receipt).ok, true, `sequential pass ${pass} receipt invalid`)
    }
    assert.equal(lab.oracle.evaluate('NX-C3').confirmed, true)
    assert.equal(terminals(lab, 'NX-C3'), 3)
  })

  // Concurrent passes on one live lab.
  await withLab('vulnerable', undefined, async (lab) => {
    const receipts = await Promise.all([
      solveC3(createSolverContext(lab)),
      solveC3(createSolverContext(lab)),
      solveC3(createSolverContext(lab)),
    ])
    for (const [index, receipt] of receipts.entries()) {
      assert.ok(receipt, `concurrent pass ${index} produced no receipt`)
      assert.equal(lab.oracle.verifyReceipt(receipt).ok, true, `concurrent pass ${index} receipt invalid`)
    }
    assert.equal(lab.oracle.evaluate('NX-C3').confirmed, true)
    assert.equal(terminals(lab, 'NX-C3'), 3)
  })
})

test('NexusIAM hardened, NX-D1..NX-D3 twins stay silent, and materialized tree is leakage-clean', async () => {
  await withLab('vulnerable', undefined, async (lab) => {
    assert.deepEqual(scanTreeForLeakage(lab.sourceRoot), [])
  })
  await withLab('hardened', undefined, async (lab) => {
    assert.deepEqual(await runNexusiamSolvers(lab), [])
    assert.equal(lab.export().events.terminals.length, 0)
  })
  for (const twin of TWINS) {
    await withLab('vulnerable', twin.id, async (lab) => {
      const findings = await runNexusiamSolvers(lab)
      assert.equal(findings.some((finding) => finding.chainId === twin.baseChainId), false, `${twin.id}: base chain receipt`)
      assert.equal(terminals(lab, twin.baseChainId), 0, `${twin.id}: base chain terminal`)
    })
  }
})
