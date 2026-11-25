/**
 * Queue #36 unit tests: CompositeProofReceipt-to-chain matcher in
 * `benchmarks/multihop-saas/run.ts` and receipt extraction hygiene in
 * `scripts/benchmark-multihop.ts`.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  gradeRun,
  startMultihopApp,
  type ProductGradeInput,
  type ProductSubmittedCompositeProof,
  type ProductSubmittedFinding,
  type StartedMultihopApp,
} from '../benchmarks/multihop-saas/run.ts'
import type { ChainEvaluation, OracleExport } from '../benchmarks/multihop-saas/lib/types.ts'
import {
  evaluateTwoSideConfirmation,
  extractCompositeReceipts,
  type MultihopChainVerdict,
  type SubmittedCompositeProof,
} from '../scripts/benchmark-multihop.ts'
import type { Finding } from '../src/domain.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function routePrefixOf(started: StartedMultihopApp): string {
  const apiRef = started.briefing('grey-box').apiReference ?? []
  const me = apiRef.find((entry) => entry.path.endsWith('/me'))
  assert.ok(me, `${started.app} seed=${started.seed} missing /me route in apiReference`)
  return me.path.slice(0, -'/me'.length)
}

async function startPairOfPrefixes(app: 'paygrid' | 'shipforge' | 'nexusiam'): Promise<{
  v1: StartedMultihopApp
  apiV1: StartedMultihopApp
}> {
  let v1: StartedMultihopApp | undefined
  let apiV1: StartedMultihopApp | undefined
  for (let seed = 1; seed <= 30 && (!v1 || !apiV1); seed += 1) {
    const started = await startMultihopApp({ app, seed, mode: 'grey-box', fastLab: true })
    const prefix = routePrefixOf(started)
    if (prefix === '/v1' && !v1) {
      v1 = started
    } else if (prefix === '/api/v1' && !apiV1) {
      apiV1 = started
    } else {
      await started.stop()
    }
  }
  assert.ok(v1, `failed to find /v1 seed for ${app}`)
  assert.ok(apiV1, `failed to find /api/v1 seed for ${app}`)
  return { v1, apiV1 }
}

function makeOracleExport(
  started: StartedMultihopApp,
  observedChainIds: readonly string[],
): OracleExport {
  const observed = new Set(observedChainIds)
  const evaluations: ChainEvaluation[] = started.groundTruth.expectedChains.map((expected) => {
    const ok = observed.has(expected.chainId)
    return {
      chainId: expected.chainId,
      completed: ok,
      confirmed: ok,
      hopsObserved: ok ? expected.hopIds.length : 0,
      hopsTotal: expected.hopIds.length,
      missingHopIds: ok ? [] : [...expected.hopIds],
      terminalObserved: ok,
      receiptVerified: ok,
      ...(ok ? { terminalAt: 100 } : { dropReason: 'capability_not_extracted' }),
    }
  })
  return {
    runId: started.runId,
    evaluations,
    confirmed: [],
    events: { hops: [], edges: [], controls: [], terminals: [] },
    receipts: [],
    receiptVerification: [],
  }
}

interface ChainFixture {
  expectedChainId: string
  findingId: string
  genericChainId: string
  terminalVulnClass: string
  hops: Array<{ hopId: string; method: string; path: string }>
  causalEdges: Array<{ kind: string }>
  terminalEndpoint?: string
}

function toProductProof(fixture: ChainFixture, overrides: Partial<ProductSubmittedCompositeProof> = {}): ProductSubmittedCompositeProof {
  const lastHop = fixture.hops[fixture.hops.length - 1]!
  return {
    findingId: fixture.findingId,
    chainId: fixture.genericChainId,
    terminalVulnClass: fixture.terminalVulnClass,
    hopCount: fixture.hops.length,
    replayMode: 'fresh_clean_replay',
    confirmed: true,
    attackerProvenanceValid: true,
    receipt: {
      hops: fixture.hops.map((hop) => ({
        hopId: hop.hopId,
        target: { method: hop.method, pathAndQuery: hop.path },
      })),
      causalEdges: fixture.causalEdges,
      terminalImpact: { terminalHopId: lastHop.hopId },
    },
    verification: {
      terminalEndpoint: fixture.terminalEndpoint ?? lastHop.path,
      terminalOracleFamily: fixture.terminalVulnClass,
    },
    ...overrides,
  }
}

function toProductFinding(fixture: ChainFixture): ProductSubmittedFinding {
  return {
    id: fixture.findingId,
    findingId: fixture.findingId,
    title: `Generic finding for ${fixture.genericChainId}`,
    vulnClass: fixture.terminalVulnClass,
    endpoints: fixture.hops.map((hop) => ({ method: hop.method, path: hop.path })),
    status: 'confirmed',
  }
}

function devChainFixtures(app: 'paygrid' | 'shipforge' | 'nexusiam', p: string): ChainFixture[] {
  if (app === 'paygrid') {
    return [
      {
        expectedChainId: 'PG-C1',
        findingId: 'finding-pg-c1',
        genericChainId: 'chain-generic-payout-approval',
        terminalVulnClass: 'dual_tenant_abac',
        hops: [
          { hopId: 'h1', method: 'POST', path: '/invites/resolve' },
          { hopId: 'h2', method: 'POST', path: `${p}/payouts/mh_pay_6776f9ed83/approve` },
        ],
        causalEdges: [{ kind: 'derived_crypto_binding' }],
      },
      {
        expectedChainId: 'PG-C2',
        findingId: 'finding-pg-c2',
        genericChainId: 'chain-generic-settlement-relay',
        terminalVulnClass: 'economic_conservation',
        hops: [
          { hopId: 'h1', method: 'PATCH', path: `${p}/invoice-templates/tpl_001` },
          { hopId: 'h2', method: 'POST', path: `${p}/invoices/inv_001/render` },
          { hopId: 'h3', method: 'GET', path: `${p}/jobs/job_001/trace` },
          // Public relay terminal POST ${p}/webhooks/settlement
          { hopId: 'h4', method: 'POST', path: `${p}/webhooks/settlement` },
        ],
        causalEdges: [{ kind: 'async_pivot_binding' }, { kind: 'value_binding' }, { kind: 'derived_crypto_binding' }],
      },
      {
        expectedChainId: 'PG-C3',
        findingId: 'finding-pg-c3',
        genericChainId: 'chain-generic-export-bleed',
        terminalVulnClass: 'parser_cache_differential',
        hops: [
          { hopId: 'h1', method: 'POST', path: `${p}/orgs/org_b/exports` },
          { hopId: 'h2', method: 'GET', path: `${p}/exports/exp_901` },
          { hopId: 'h3', method: 'GET', path: `${p}/exports/exp_901/url` },
          { hopId: 'h4', method: 'GET', path: '/files/export/org-c-slug/treasury-q4.csv?sig=abc' },
        ],
        causalEdges: [{ kind: 'async_pivot_binding' }, { kind: 'value_binding' }],
      },
      {
        expectedChainId: 'PG-C4',
        findingId: 'finding-pg-c4',
        genericChainId: 'chain-generic-order-race',
        terminalVulnClass: 'economic_conservation',
        hops: [
          { hopId: 'h1', method: 'POST', path: `${p}/orders` },
          { hopId: 'h2', method: 'PATCH', path: `${p}/orders/ord_77/rebind` },
          { hopId: 'h3', method: 'POST', path: `${p}/orders/ord_77/settle-race` },
        ],
        causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
      },
    ]
  }
  if (app === 'shipforge') {
    return [
      {
        expectedChainId: 'SF-C1',
        findingId: 'finding-sf-c1',
        genericChainId: 'chain-generic-preview-release',
        terminalVulnClass: 'cryptographic_scope_replay',
        hops: [
          { hopId: 'h1', method: 'POST', path: '/repos/repo_1/preview-builds' },
          { hopId: 'h2', method: 'POST', path: `${p}/graphql` },
          { hopId: 'h3', method: 'POST', path: `${p}/deployments/dep_42/promote` },
          { hopId: 'h4', method: 'POST', path: `${p}/secrets/batch` },
          { hopId: 'h5', method: 'POST', path: `${p}/deployments/dep_42/release` },
        ],
        causalEdges: [{ kind: 'async_pivot_binding' }, { kind: 'value_binding' }, { kind: 'derived_crypto_binding' }],
      },
      {
        expectedChainId: 'SF-C2',
        findingId: 'finding-sf-c2',
        genericChainId: 'chain-generic-stream-transfer',
        terminalVulnClass: 'temporal_revocation',
        hops: [
          { hopId: 'h1', method: 'GET', path: `${p}/runners/shared/events` },
          { hopId: 'h2', method: 'POST', path: `${p}/projects/proj_9/transfer` },
          { hopId: 'h3', method: 'GET', path: '/repos/repo_9/archive' },
        ],
        causalEdges: [{ kind: 'async_pivot_binding' }, { kind: 'value_binding' }, { kind: 'state_transition_binding' }],
      },
      {
        expectedChainId: 'SF-C3',
        findingId: 'finding-sf-c3',
        genericChainId: 'chain-generic-webhook-registry-sync',
        terminalVulnClass: 'cryptographic_scope_replay',
        hops: [
          { hopId: 'h1', method: 'GET', path: `${p}/search/projects?q=internal` },
          { hopId: 'h2', method: 'POST', path: `${p}/projects/proj_3/webhooks` },
          { hopId: 'h3', method: 'GET', path: `${p}/projects/proj_3/webhooks/wh_5/deliveries` },
          // Public relay terminal POST ${p}/integrations/registry/sync
          { hopId: 'h4', method: 'POST', path: `${p}/integrations/registry/sync` },
        ],
        causalEdges: [{ kind: 'derived_crypto_binding' }, { kind: 'value_binding' }],
      },
      {
        expectedChainId: 'SF-C4',
        findingId: 'finding-sf-c4',
        genericChainId: 'chain-generic-automation-release',
        terminalVulnClass: 'dual_tenant_abac',
        hops: [
          { hopId: 'h1', method: 'POST', path: `${p}/automations` },
          { hopId: 'h2', method: 'POST', path: `${p}/deployments/dep_99/dispute` },
          { hopId: 'h3', method: 'POST', path: `${p}/deployments/dep_99/release` },
        ],
        causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
      },
    ]
  }
  return [
    {
      expectedChainId: 'NX-C1',
      findingId: 'finding-nx-c1',
      genericChainId: 'chain-generic-moderation-scim',
      terminalVulnClass: 'cross_surface_pivot',
      hops: [
        { hopId: 'h1', method: 'POST', path: `${p}/comments` },
        { hopId: 'h2', method: 'GET', path: `${p}/inbox/cmt_10` },
        { hopId: 'h3', method: 'POST', path: `${p}/scim/tokens` },
        { hopId: 'h4', method: 'PATCH', path: `${p}/scim/users/usr_2` },
        { hopId: 'h5', method: 'GET', path: `${p}/audit/vault?tenant=org_a` },
      ],
      causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
    },
    {
      expectedChainId: 'NX-C2',
      findingId: 'finding-nx-c2',
      genericChainId: 'chain-generic-oauth-invite-redeem',
      terminalVulnClass: 'temporal_revocation',
      hops: [
        { hopId: 'h1', method: 'GET', path: '/authorize?client_id=web' },
        { hopId: 'h2', method: 'GET', path: '/s/share_77' },
        { hopId: 'h3', method: 'GET', path: '/invites?tenant=org_a' },
        { hopId: 'h4', method: 'POST', path: '/invites/redeem' },
      ],
      causalEdges: [{ kind: 'value_binding' }, { kind: 'derived_crypto_binding' }],
    },
    {
      expectedChainId: 'NX-C3',
      findingId: 'finding-nx-c3',
      genericChainId: 'chain-generic-cache-doc-read',
      terminalVulnClass: 'parser_cache_differential',
      hops: [
        { hopId: 'h1', method: 'GET', path: '/public/profile/acme-corp.css' },
        { hopId: 'h2', method: 'GET', path: `${p}/docs?workspace=` },
        { hopId: 'h3', method: 'GET', path: `${p}/docs/doc_55` },
        { hopId: 'h4', method: 'GET', path: `${p}/docs/doc_55/content` },
      ],
      causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
    },
    {
      expectedChainId: 'NX-C4',
      findingId: 'finding-nx-c4',
      genericChainId: 'chain-generic-export-result-relay',
      terminalVulnClass: 'temporal_revocation',
      hops: [
        { hopId: 'h1', method: 'GET', path: `${p}/search/facets?q=secret` },
        { hopId: 'h2', method: 'GET', path: `${p}/docs/share/shr_8/metadata` },
        { hopId: 'h3', method: 'GET', path: `${p}/exports/job_8` },
        // Public relay terminal GET ${p}/exports/:id/result
        { hopId: 'h4', method: 'GET', path: `${p}/exports/job_8/result` },
      ],
      causalEdges: [{ kind: 'value_binding' }, { kind: 'async_pivot_binding' }],
    },
  ]
}

// ---------------------------------------------------------------------------
// 1. All 12 Dev chains match Kovo-style arbitrary chainIds across /v1 & /api/v1
// ---------------------------------------------------------------------------

test('all 12 Dev chains (PG-C1..C4, SF-C1..C4, NX-C1..C4) match generic chainIds under both /v1 and /api/v1', async () => {
  for (const app of ['paygrid', 'shipforge', 'nexusiam'] as const) {
    const pair = await startPairOfPrefixes(app)
    try {
      for (const [label, started] of [['/v1', pair.v1], ['/api/v1', pair.apiV1]] as const) {
        const prefix = routePrefixOf(started)
        assert.equal(prefix, label)
        const fixtures = devChainFixtures(app, prefix)
        const compositeReceipts = fixtures.map((f) => toProductProof(f))
        const findings = fixtures.map((f) => toProductFinding(f))
        const oracleExport = makeOracleExport(started, fixtures.map((f) => f.expectedChainId))

        const card = gradeRun({
          groundTruth: started.groundTruth,
          findings,
          compositeReceipts,
          oracleEvents: [],
          oracleExport,
          mode: 'grey-box',
        } satisfies ProductGradeInput)

        assert.equal(card.chainsTotal, 4, `${app} ${label}: chainsTotal`)
        assert.equal(card.chainsOracleObserved, 4, `${app} ${label}: chainsOracleObserved`)
        assert.equal(card.chainsCompositeConfirmed, 4, `${app} ${label}: chainsCompositeConfirmed`)
        assert.equal(card.chainsConfirmed, 4, `${app} ${label}: chainsConfirmed`)
        assert.equal(card.recall, 1, `${app} ${label}: recall`)
        assert.equal(card.precision, 1, `${app} ${label}: precision`)
        assert.equal(card.hardenedTwinDecoyFps, 0, `${app} ${label}: zero decoy FPs`)
        assert.equal(card.unmatchedFalsePositives, 0, `${app} ${label}: zero unmatched FPs`)

        for (const fixture of fixtures) {
          const verdict = card.chains.find((c) => c.chainId === fixture.expectedChainId)
          assert.ok(verdict, `${app} ${label}: missing verdict for ${fixture.expectedChainId}`)
          assert.equal(verdict.twoSideConfirmed, true, `${app} ${label}: ${fixture.expectedChainId} twoSideConfirmed`)
          assert.deepEqual(verdict.matchedFindingIds, [fixture.findingId])
        }

        // Verify evaluateTwoSideConfirmation wires through via matchedFindingIds
        const twoSide = evaluateTwoSideConfirmation(
          card.chains as unknown as MultihopChainVerdict[],
          compositeReceipts as unknown as SubmittedCompositeProof[],
        )
        assert.equal(twoSide.twoSideConfirmed, 4, `${app} ${label}: evaluateTwoSideConfirmation`)
        assert.equal(twoSide.oracleOnlyCount, 0)
        assert.equal(twoSide.receiptOnlyCount, 0)
      }
    } finally {
      await pair.v1.stop()
      await pair.apiV1.stop()
    }
  }
})

// ---------------------------------------------------------------------------
// 2. SF-C1 vs SF-C4 disambiguation on shared terminal POST ${p}/deployments/:id/release
// ---------------------------------------------------------------------------

test('SF-C1 vs SF-C4 disambiguation on POST ${p}/deployments/:id/release via upstream hops & causal edges', async () => {
  const started = await startMultihopApp({ app: 'shipforge', seed: 1, mode: 'grey-box', fastLab: true })
  try {
    const p = routePrefixOf(started)
    const [sfC1, , , sfC4] = devChainFixtures('shipforge', p)
    const bothObserved = makeOracleExport(started, ['SF-C1', 'SF-C4'])

    // Only SF-C1 receipt submitted -> must resolve exclusively to SF-C1 (not SF-C4)
    const c1Card = gradeRun({
      groundTruth: started.groundTruth,
      findings: [toProductFinding(sfC1!)],
      compositeReceipts: [toProductProof(sfC1!)],
      oracleEvents: [],
      oracleExport: bothObserved,
      mode: 'grey-box',
    })
    assert.equal(c1Card.chains.find((c) => c.chainId === 'SF-C1')?.twoSideConfirmed, true)
    assert.deepEqual(c1Card.chains.find((c) => c.chainId === 'SF-C1')?.matchedFindingIds, [sfC1!.findingId])
    assert.equal(c1Card.chains.find((c) => c.chainId === 'SF-C4')?.twoSideConfirmed, false)
    assert.equal(c1Card.chains.find((c) => c.chainId === 'SF-C4')?.compositeReceiptConfirmed, false)

    // Only SF-C4 receipt submitted -> must resolve exclusively to SF-C4 (not SF-C1)
    const c4Card = gradeRun({
      groundTruth: started.groundTruth,
      findings: [toProductFinding(sfC4!)],
      compositeReceipts: [toProductProof(sfC4!)],
      oracleEvents: [],
      oracleExport: bothObserved,
      mode: 'grey-box',
    })
    assert.equal(c4Card.chains.find((c) => c.chainId === 'SF-C4')?.twoSideConfirmed, true)
    assert.deepEqual(c4Card.chains.find((c) => c.chainId === 'SF-C4')?.matchedFindingIds, [sfC4!.findingId])
    assert.equal(c4Card.chains.find((c) => c.chainId === 'SF-C1')?.twoSideConfirmed, false)
    assert.equal(c4Card.chains.find((c) => c.chainId === 'SF-C1')?.compositeReceiptConfirmed, false)
    assert.equal(c4Card.hardenedTwinDecoyFps, 0)

    // Edge-kind tie-break when upstream hop paths are generic/unrecognized
    const edgeOnlyC4: ProductSubmittedCompositeProof = {
      findingId: 'edge-only-c4',
      chainId: 'generic-edge-c4',
      terminalVulnClass: 'dual_tenant_abac',
      hopCount: 2,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'GET', pathAndQuery: `${p}/ping` } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: `${p}/deployments/dep_7/release` } },
        ],
        causalEdges: [{ kind: 'state_transition_binding' }],
        terminalImpact: { terminalHopId: 'h2' },
      },
      verification: { terminalEndpoint: `${p}/deployments/dep_7/release` },
    }
    const edgeCard = gradeRun({
      groundTruth: started.groundTruth,
      findings: [{ id: 'edge-only-c4', endpoints: [{ method: 'POST', path: `${p}/deployments/dep_7/release` }] }],
      compositeReceipts: [edgeOnlyC4],
      oracleEvents: [],
      oracleExport: bothObserved,
      mode: 'grey-box',
    })
    assert.equal(edgeCard.chains.find((c) => c.chainId === 'SF-C4')?.twoSideConfirmed, true)
    assert.equal(edgeCard.chains.find((c) => c.chainId === 'SF-C1')?.twoSideConfirmed, false)

    // Unconfirmed SF-C4 receipt must NOT be misattributed to SF-D1 (baseChainId SF-C1)
    const unconfirmedC4Card = gradeRun({
      groundTruth: started.groundTruth,
      findings: [toProductFinding(sfC4!)],
      compositeReceipts: [toProductProof(sfC4!, { confirmed: false })],
      oracleEvents: [],
      oracleExport: makeOracleExport(started, []),
      mode: 'grey-box',
    })
    assert.equal(unconfirmedC4Card.hardenedTwins.find((t) => t.twinId === 'SF-D1')?.falsePositive, false)
  } finally {
    await started.stop()
  }
})

// ---------------------------------------------------------------------------
// 3. PG-C1 (b025b159 shape) clears PG-D1 decoy FP while genuine decoy & hardened fail
// ---------------------------------------------------------------------------

test('confirmed PG-C1 (b025b159 shape) clears PG-D1 decoy FP, while decoy-hop-only & hardened-mode still fail', async () => {
  const vuln = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  const hardened = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'hardened', fastLab: true })
  const twinD1 = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', twin: 'PG-D1', fastLab: true })
  try {
    const p = routePrefixOf(vuln)
    const b025b159Receipt: ProductSubmittedCompositeProof = {
      findingId: 'b025b159',
      chainId: 'chain-kovo-payout-self-approval',
      terminalVulnClass: 'dual_tenant_abac',
      hopCount: 2,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'hop_invite', target: { method: 'POST', pathAndQuery: '/invites/resolve' } },
          { hopId: 'hop_approve', target: { method: 'POST', pathAndQuery: `${p}/payouts/mh_pay_6776f9ed83/approve` } },
        ],
        causalEdges: [{ kind: 'derived_crypto_binding' }],
        terminalImpact: { terminalHopId: 'hop_approve' },
      },
      verification: {
        terminalEndpoint: `${p}/payouts/mh_pay_6776f9ed83/approve`,
        terminalOracleFamily: 'dual_tenant_abac',
      },
    }
    const b025b159Finding: ProductSubmittedFinding = {
      id: 'b025b159',
      findingId: 'b025b159',
      title: 'Cross-tenant invite collision to unauthorized payout approval',
      vulnClass: 'dual_tenant_abac',
      // Includes decoy hop POST /invites/resolve (just like translateFindings -> endpointsFromReplaySpec)
      endpoints: [
        { method: 'POST', path: '/invites/resolve' },
        { method: 'POST', path: `${p}/payouts/mh_pay_6776f9ed83/approve` },
      ],
      status: 'confirmed',
    }

    // (a) Vulnerable mode with PG-C1 oracleObserved=true -> twoSideConfirmed=true, PG-D1 decoy FP cleared!
    const okCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [b025b159Finding],
      compositeReceipts: [b025b159Receipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C1']),
      mode: 'grey-box',
    })
    const pgC1 = okCard.chains.find((c) => c.chainId === 'PG-C1')
    assert.equal(pgC1?.twoSideConfirmed, true)
    assert.equal(pgC1?.compositeReceiptConfirmed, true)
    assert.deepEqual(pgC1?.matchedFindingIds, ['b025b159'])
    assert.equal(okCard.hardenedTwins.find((t) => t.twinId === 'PG-D1')?.falsePositive, false)
    assert.equal(okCard.hardenedTwinDecoyFps, 0)
    assert.equal(okCard.precision, 1)

    // (b) Genuine decoy-hop-only finding (only hits /invites/resolve) MUST still fail hardenedTwinDecoyFps > 0
    const decoyOnlyReceipt: ProductSubmittedCompositeProof = {
      findingId: 'decoy-only-1',
      chainId: 'chain-decoy-invite-only',
      terminalVulnClass: 'dual_tenant_abac',
      hopCount: 2,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'GET', pathAndQuery: `${p}/directory/orgs/acme` } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: '/invites/resolve' } },
        ],
        causalEdges: [{ kind: 'value_binding' }],
        terminalImpact: { terminalHopId: 'h2' },
      },
      verification: { terminalEndpoint: '/invites/resolve' },
    }
    const decoyOnlyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [{
        id: 'decoy-only-1',
        vulnClass: 'dual_tenant_abac',
        endpoints: [
          { method: 'GET', path: `${p}/directory/orgs/acme` },
          { method: 'POST', path: '/invites/resolve' },
        ],
      }],
      compositeReceipts: [decoyOnlyReceipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, ['PG-C1']),
      mode: 'grey-box',
    })
    assert.equal(decoyOnlyCard.chainsConfirmed, 0)
    assert.equal(decoyOnlyCard.hardenedTwins.find((t) => t.twinId === 'PG-D1')?.falsePositive, true)
    assert.ok(decoyOnlyCard.hardenedTwinDecoyFps > 0)

    // (c) Public-relay decoy endpoint on PG-D2 (POST ${p}/invoices/:id/render) MUST trigger PG-D2 decoy FP
    const relayDecoyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [{
        id: 'pg-d2-relay-fp',
        vulnClass: 'forged_settlement',
        endpoints: [{ method: 'POST', path: `${p}/invoices/inv_99/render` }],
      }],
      compositeReceipts: [],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'grey-box',
    })
    assert.equal(relayDecoyCard.hardenedTwins.find((t) => t.twinId === 'PG-D2')?.falsePositive, true)
    assert.ok(relayDecoyCard.hardenedTwinDecoyFps > 0)

    // (d) Hardened mode MUST still fail hardenedTwinDecoyFps > 0 even with a confirmed-looking receipt
    const hardenedCard = gradeRun({
      groundTruth: hardened.groundTruth,
      findings: [b025b159Finding],
      compositeReceipts: [b025b159Receipt],
      oracleEvents: [],
      oracleExport: hardened.export(),
      mode: 'grey-box',
    })
    assert.equal(hardenedCard.chainsConfirmed, 0)
    assert.ok(hardenedCard.hardenedTwinDecoyFps > 0)

    // (e) Hardened-twin mode (PG-D1) MUST fail hardenedTwinDecoyFps > 0 even on receipt-only submission
    const twinCard = gradeRun({
      groundTruth: twinD1.groundTruth,
      findings: [],
      compositeReceipts: [b025b159Receipt],
      oracleEvents: [],
      oracleExport: twinD1.export(),
      mode: 'grey-box',
    })
    assert.equal(twinCard.chainsConfirmed, 0)
    assert.equal(twinCard.hardenedTwins.find((t) => t.twinId === 'PG-D1')?.falsePositive, true)
    assert.ok(twinCard.hardenedTwinDecoyFps > 0)
  } finally {
    await vuln.stop()
    await hardened.stop()
    await twinD1.stop()
  }
})

// ---------------------------------------------------------------------------
// 4. 1-hop rejection & unconfirmed receipt never shadows confirmed Mode-A receipt
// ---------------------------------------------------------------------------

test('1-hop receipt rejected from matching multi-hop chain; unconfirmed receipt never shadows confirmed Mode-A receipt', async () => {
  const started = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  try {
    const p = routePrefixOf(started)
    const oracleExport = makeOracleExport(started, ['PG-C1', 'PG-C4'])

    // 1-hop receipt with arbitrary chainId on PG-C1 terminal MUST be rejected
    const oneHopReceipt: ProductSubmittedCompositeProof = {
      findingId: 'one-hop-pg1',
      chainId: 'single-hop-approval-claim',
      terminalVulnClass: 'dual_tenant_abac',
      hopCount: 1,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [{ hopId: 'hop_1', target: { method: 'POST', pathAndQuery: `${p}/payouts/mh_pay_123/approve` } }],
        causalEdges: [],
        terminalImpact: { terminalHopId: 'hop_1' },
      },
      verification: { terminalEndpoint: `${p}/payouts/mh_pay_123/approve` },
    }
    const oneHopCard = gradeRun({
      groundTruth: started.groundTruth,
      findings: [{ id: 'one-hop-pg1', endpoints: [{ method: 'POST', path: `${p}/payouts/mh_pay_123/approve` }] }],
      compositeReceipts: [oneHopReceipt],
      oracleEvents: [],
      oracleExport,
      mode: 'grey-box',
    })
    assert.equal(oneHopCard.chains.find((c) => c.chainId === 'PG-C1')?.compositeReceiptConfirmed, false)
    assert.equal(oneHopCard.chains.find((c) => c.chainId === 'PG-C1')?.twoSideConfirmed, false)

    // Unconfirmed Mode-B receipt BEFORE confirmed Mode-A receipt on PG-C4 MUST NOT shadow Mode-A
    const unconfirmedFirst: ProductSubmittedCompositeProof = {
      findingId: 'pg4-unconfirmed',
      chainId: 'chain-pg4-attempt-1',
      terminalVulnClass: 'economic_conservation',
      hopCount: 3,
      replayMode: 'one_shot_transcript',
      confirmed: false,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${p}/orders` } },
          { hopId: 'h2', target: { method: 'PATCH', pathAndQuery: `${p}/orders/ord_1/rebind` } },
          { hopId: 'h3', target: { method: 'POST', pathAndQuery: `${p}/orders/ord_1/settle-race` } },
        ],
        causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
        terminalImpact: { terminalHopId: 'h3' },
      },
      verification: { terminalEndpoint: `${p}/orders/ord_1/settle-race` },
    }
    const confirmedSecond: ProductSubmittedCompositeProof = {
      findingId: 'pg4-confirmed',
      chainId: 'chain-pg4-attempt-2',
      terminalVulnClass: 'economic_conservation',
      hopCount: 3,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${p}/orders` } },
          { hopId: 'h2', target: { method: 'PATCH', pathAndQuery: `${p}/orders/ord_2/rebind` } },
          { hopId: 'h3', target: { method: 'POST', pathAndQuery: `${p}/orders/ord_2/settle-race` } },
        ],
        causalEdges: [{ kind: 'value_binding' }, { kind: 'state_transition_binding' }],
        terminalImpact: { terminalHopId: 'h3' },
      },
      verification: { terminalEndpoint: `${p}/orders/ord_2/settle-race` },
    }
    const shadowCard = gradeRun({
      groundTruth: started.groundTruth,
      findings: [{ id: 'pg4-confirmed', endpoints: [{ method: 'POST', path: `${p}/orders/ord_2/settle-race` }] }],
      compositeReceipts: [unconfirmedFirst, confirmedSecond],
      oracleEvents: [],
      oracleExport,
      mode: 'grey-box',
    })
    const pgC4 = shadowCard.chains.find((c) => c.chainId === 'PG-C4')
    assert.equal(pgC4?.compositeReceiptConfirmed, true)
    assert.equal(pgC4?.twoSideConfirmed, true)
    assert.deepEqual(pgC4?.matchedFindingIds, ['pg4-confirmed'])
  } finally {
    await started.stop()
  }
})

// ---------------------------------------------------------------------------
// 5. extractCompositeReceipts skips dismissed/superseded & reads row.proofReceipt
// ---------------------------------------------------------------------------

test('extractCompositeReceipts skips dismissed/superseded findings and falls back to row.proofReceipt', () => {
  const makeReceipt = (chainId: string) => ({
    chainId,
    terminalVulnClass: 'dual_tenant_abac',
    replayMode: 'fresh_clean_replay',
    hops: [
      { hopId: 'h1', target: { origin: 'http://127.0.0.1:4000', method: 'POST', pathAndQuery: '/step1' } },
      { hopId: 'h2', target: { origin: 'http://127.0.0.1:4000', method: 'POST', pathAndQuery: '/step2' } },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2' }],
    terminalImpact: { terminalHopId: 'h2', claimedImpact: 'Confirmed cross-tenant escalation' },
  })
  const verifiedBlock = (chainId: string) => ({
    confirmed: true,
    chainId,
    terminalVulnClass: 'dual_tenant_abac',
    replayMode: 'fresh_clean_replay',
    modeBVerified: false,
    hopCount: 2,
    verifiedEdges: [],
    reason: 'ok',
    terminalEndpoint: '/step2',
  })

  const findings = [
    { id: 'f-active-proof-col', status: 'confirmed', evidence: {} },
    { id: 'f-dismissed', status: 'dismissed', evidence: { compositeReceipt: makeReceipt('chain-dismissed'), compositeVerification: verifiedBlock('chain-dismissed') } },
    { id: 'f-superseded', status: 'confirmed', supersededByFindingId: 'f-active-proof-col', evidence: { compositeReceipt: makeReceipt('chain-superseded'), compositeVerification: verifiedBlock('chain-superseded') } },
  ] as unknown as Finding[]

  const extracted = extractCompositeReceipts({
    findings,
    replaySpecs: [
      {
        id: 'spec-1',
        findingId: 'f-active-proof-col',
        // spec has unverified receipt without verification; proofReceipt has full verified bundle
        spec: { compositeReceipt: makeReceipt('chain-proof-col') },
        proofReceipt: {
          compositeReceipt: makeReceipt('chain-proof-col'),
          compositeVerification: verifiedBlock('chain-proof-col'),
        },
      },
      {
        id: 'spec-dismissed',
        findingId: 'f-dismissed',
        spec: { compositeReceipt: makeReceipt('chain-dismissed'), compositeVerification: verifiedBlock('chain-dismissed') },
      },
      {
        id: 'spec-superseded',
        findingId: 'f-superseded',
        spec: {},
        proofReceipt: { compositeReceipt: makeReceipt('chain-superseded'), compositeVerification: verifiedBlock('chain-superseded') },
      },
    ],
  })

  assert.equal(extracted.length, 1)
  assert.equal(extracted[0]!.findingId, 'f-active-proof-col')
  assert.equal(extracted[0]!.chainId, 'chain-proof-col')
  assert.equal(extracted[0]!.confirmed, true)
  assert.equal(extracted[0]!.attackerProvenanceValid, true)
  assert.equal(extracted[0]!.verification?.terminalEndpoint, '/step2')
})
