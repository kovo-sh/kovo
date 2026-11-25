/**
 * Regression suite for Queue #35 Stream 1 (`src/server/exec-verify.ts`):
 * Verifies canonical endpoint/method fingerprinting and deduplication in `persistAgentScriptProof`:
 *  1. Two script-proof confirmations on `/v1/orders/[redacted:cap:hop_1:order_id]/settle-race` and
 *     `/v1/orders/mh_ord_9_5ed534/settle-race` with different titles collapse to 1 persisted finding
 *     with `fingerprintHash` set and corroborating evidence/exchanges merged, while a different route
 *     persists as a distinct 2nd finding.
 *  2. Single-hop `ProofReceipt` confirmations deduplicate via canonical endpoint + fingerprintHash.
 *  3. Cross-port loopback origins (e.g. proxy origin vs direct API origin) on the same parameterized
 *     route collapse cleanly with merged `sourceOrigins`, while different routes or distinct
 *     non-loopback hosts stay separate.
 *  4. CWE aliases sharing the same `terminalOracleFamily` (e.g. `economic_conservation` CWE-840 vs
 *     `race_double_spend` CWE-362) on the same normalized endpoint collapse cleanly, while distinct
 *     oracle families, distinct vulnerability classes, and distinct HTTP methods stay separate.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'

import type { AgentScriptProofResult, V8CompositeProofBundle } from '../src/server/agent-script-proof.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  extractAgentProofTarget,
  methodsCompatibleForAgentProofDedupe,
  originsEquivalentForAgentProofDedupe,
  vulnClassesEquivalentForAgentProofDedupe,
} from '../src/server/exec-verify.ts'
import { Execution } from '../src/server/execution.ts'
import { computeFindingFingerprint, normalizeEndpointTemplate } from '../src/server/finding-fingerprint.ts'
import { findings, replaySpecs } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeStore(t: { after: (fn: () => void) => void }): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v8-q35-dedupe-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

type PersistFn = (input: {
  run: ReturnType<Store['run']>
  assignment: ReturnType<Store['makeWorker']>
  script: string
  runtime: 'ts'
  title?: string
  proof: AgentScriptProofResult
  secrets: readonly []
}) => { findingId: string; replaySpecId: string; receiptId: string | null }

function persistViaExecution(execution: Execution): PersistFn {
  return (execution as unknown as { persistAgentScriptProof: PersistFn }).persistAgentScriptProof.bind(execution)
}

function makeAttemptReport(attempt: 1 | 2, digest: string) {
  return {
    attempt,
    nonce: `nonce-${digest}`,
    exitCode: 0,
    durationMs: 12,
    oraclePassed: true,
    failures: [],
    claimCount: 1,
    exchangeCount: 2,
    transcriptDigest: digest,
    signaturesValid: true,
    causal: [],
    title: null,
    nonceMismatch: false,
    rejectedBy: null,
    missingEvidence: [],
    transcriptSummary: [],
  }
}

function makeCompositeProof(opts: {
  origin: string
  endpoint: string
  method?: string
  terminalVulnClass?: string
  terminalOracleFamily?: string
  chainId: string
  exchangePrefix: string
  claimTitle: string
  severity?: 'low' | 'medium' | 'high' | 'critical'
}): AgentScriptProofResult {
  const method = opts.method ?? 'POST'
  const terminalVulnClass = opts.terminalVulnClass ?? 'economic_conservation'
  const terminalOracleFamily = opts.terminalOracleFamily ?? 'economic_conservation'
  const ctrlId = `${opts.exchangePrefix}-ctrl`
  const probeId = `${opts.exchangePrefix}-probe`
  const readbackId = `${opts.exchangePrefix}-rb`

  const compositeReceipt: V8CompositeProofBundle = {
    receipt: {
      chainId: opts.chainId,
      terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      hops: [
        {
          hopId: 'hop_1',
          surface: 'http',
          target: {
            origin: opts.origin,
            method,
            pathAndQuery: opts.endpoint,
          },
          exchangeIds: [ctrlId, probeId],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'Concurrent settlement exceeded conserved balance.',
          producedCapabilities: [],
          consumedCapabilities: [],
        },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_1',
        claimedImpact: 'Double settlement debited more than available balance.',
        summary: 'Double settlement debited more than available balance.',
        terminalExchangeId: probeId,
        oracleFamily: terminalOracleFamily as V8CompositeProofBundle['receipt']['terminalImpact']['oracleFamily'],
        preChainControlExchangeIds: [ctrlId],
        postChainReadbackExchangeIds: [readbackId],
      },
    },
    verification: {
      confirmed: true,
      chainId: opts.chainId,
      terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      modeBVerified: false,
      hopCount: 1,
      verifiedEdges: [],
      reason: 'Conservation invariant violated across fresh runs.',
      terminalOracleFamily,
      terminalEndpoint: opts.endpoint,
    },
    hopActors: { hop_1: 'member_a' },
  }

  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh script attempts agreed on conservation violation.',
      attempts: [
        makeAttemptReport(1, `d1-${opts.chainId}`),
        makeAttemptReport(2, `d2-${opts.chainId}`),
      ],
      disagreements: [],
      claimTitle: opts.claimTitle,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges: [
      {
        exchangeId: ctrlId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 403,
        durationMs: 4,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"error":"forbidden"}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
      {
        exchangeId: probeId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 200,
        durationMs: 6,
        personaHandle: 'member_a',
        sessionRole: 'probe',
        actorRoleLabel: 'member',
        body: '{"settled":true,"remaining":-50}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
      {
        exchangeId: readbackId,
        op: 'http',
        method: 'GET',
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 200,
        durationMs: 3,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"balance":-50}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
    ],
    receipt: null,
    compositeReceipt,
    vulnClass: terminalVulnClass,
    transcriptDigests: [`d1-${opts.chainId}`, `d2-${opts.chainId}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: opts.severity ?? 'high',
    description: 'Verified conservation violation.',
  }
}

function makeSingleHopProof(opts: {
  origin: string
  endpoint: string
  method?: string
  vulnClass?: string
  exchangePrefix: string
  claimTitle: string
  severity?: 'low' | 'medium' | 'high' | 'critical'
}): AgentScriptProofResult {
  const method = opts.method ?? 'POST'
  const vulnClass = opts.vulnClass ?? 'race_double_spend'
  const ctrlId = `${opts.exchangePrefix}-ctrl`
  const probeId = `${opts.exchangePrefix}-probe`

  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh runs confirmed the single-hop receipt.',
      attempts: [
        makeAttemptReport(1, `s1-${opts.exchangePrefix}`),
        makeAttemptReport(2, `s2-${opts.exchangePrefix}`),
      ],
      disagreements: [],
      claimTitle: opts.claimTitle,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges: [
      {
        exchangeId: ctrlId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 409,
        durationMs: 3,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"error":"conflict"}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
      {
        exchangeId: probeId,
        op: 'http',
        method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 200,
        durationMs: 5,
        personaHandle: 'member_a',
        sessionRole: 'probe',
        actorRoleLabel: 'member',
        body: '{"ok":true}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
    ],
    receipt: {
      receipt: {
        vulnClass,
        target: {
          origin: opts.origin,
          method,
          pathAndQuery: opts.endpoint,
        },
        exchangeIds: [ctrlId, probeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Parallel requests settled the same order twice.',
      },
      verification: {
        confirmed: true,
        vulnClass,
        rule: 'conserved_balance',
        reason: 'Conserved balance exceeded by concurrent burst.',
        observed: '2 winning settlements',
        expected: 'at most 1 settlement',
      },
    },
    compositeReceipt: null,
    vulnClass,
    transcriptDigests: [`s1-${opts.exchangePrefix}`, `s2-${opts.exchangePrefix}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: opts.severity ?? 'high',
    description: 'Single-hop verified proof.',
  }
}

test('1. Two composite confirmations on parameterized redacted vs concrete ID routes collapse to 1 finding; distinct route stays 2nd finding', async (t) => {
  const origin = 'http://127.0.0.1:4101'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker1 = storage.makeWorker(run, 'investigation', asset, 'Worker 1', 'Verify order settlement race')
  const worker2 = storage.makeWorker(run, 'investigation', asset, 'Worker 2', 'Independent verification')
  const worker3 = storage.makeWorker(run, 'investigation', asset, 'Worker 3', 'Verify wallet payout route')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  const proofA = makeCompositeProof({
    origin,
    endpoint: '/v1/orders/[redacted:cap:hop_1:order_id]/settle-race',
    method: 'POST',
    chainId: 'chain-settle-a',
    exchangePrefix: 'ex-a',
    claimTitle: 'Order double-settlement race via sealed capability handle',
    severity: 'high',
  })
  const proofB = makeCompositeProof({
    origin,
    endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
    method: 'POST',
    chainId: 'chain-settle-b',
    exchangePrefix: 'ex-b',
    claimTitle: 'Concurrent settlement violates economic conservation on orders',
    severity: 'critical',
  })
  const proofDistinctRoute = makeCompositeProof({
    origin,
    endpoint: '/v1/wallets/mh_wal_4_ab12cd/payout',
    method: 'POST',
    chainId: 'chain-payout-c',
    exchangePrefix: 'ex-c',
    claimTitle: 'Wallet payout conservation bypass',
    severity: 'high',
  })

  const first = persist({
    run,
    assignment: worker1,
    script: '// worker 1 script',
    runtime: 'ts',
    title: proofA.claimTitle ?? undefined,
    proof: proofA,
    secrets: [],
  })
  const second = persist({
    run,
    assignment: worker2,
    script: '// worker 2 corroborating script',
    runtime: 'ts',
    title: proofB.claimTitle ?? undefined,
    proof: proofB,
    secrets: [],
  })

  assert.equal(second.findingId, first.findingId, 'same parameterized route with different titles must collapse to 1 finding')
  assert.equal(second.replaySpecId, first.replaySpecId, 'corroborating confirmation should reuse canonical confirmed replaySpecId')

  const rowsAfterTwo = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(rowsAfterTwo.length, 1, 'exactly 1 persisted finding row after two confirmations on the same normalized route')

  const canonicalRow = rowsAfterTwo[0]!
  const expectedFp = computeFindingFingerprint({
    origin,
    cwe: 'CWE-840',
    category: 'business-logic-race',
    endpoint: '/v1/orders/:id/settle-race',
    method: 'POST',
  })
  assert.equal(canonicalRow.fingerprintHash, expectedFp.hash, 'findings.fingerprint_hash column must be populated')
  assert.equal(canonicalRow.finding.fingerprintHash, expectedFp.hash, 'finding.fingerprintHash JSON field must be populated')
  assert.equal(canonicalRow.finding.status, 'confirmed')
  assert.equal(canonicalRow.finding.severity, 'high', 'H-18: confirmed finding severity must stay frozen to canonical confirming receipt')
  assert.equal(canonicalRow.finding.evidenceIds.length, 2, 'both workers artifacts must be preserved in evidenceIds')
  assert.ok(canonicalRow.finding.exchangeIds?.includes('ex-a-probe'), 'original exchangeIds must be preserved')
  assert.ok(canonicalRow.finding.exchangeIds?.includes('ex-b-probe'), 'corroborating exchangeIds must be merged')

  const specsAfterTwo = storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, runId)).all()
  assert.equal(specsAfterTwo.length, 1, 'no duplicate replay_specs row should be created for duplicate confirmed composite proof')

  // Distinct route MUST persist as a 2nd independent finding!
  const third = persist({
    run,
    assignment: worker3,
    script: '// worker 3 distinct route script',
    runtime: 'ts',
    title: proofDistinctRoute.claimTitle ?? undefined,
    proof: proofDistinctRoute,
    secrets: [],
  })
  assert.notEqual(third.findingId, first.findingId, 'different route must remain a distinct finding')

  const rowsAfterThree = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(rowsAfterThree.length, 2, 'two distinct routes must remain 2 persisted findings')
  assert.notEqual(rowsAfterThree[0]!.fingerprintHash, rowsAfterThree[1]!.fingerprintHash)
})

test('2. Single-hop ProofReceipt confirmations on redacted vs concrete ID paths deduplicate via fingerprintHash while distinct routes stay separate', async (t) => {
  const origin = 'http://127.0.0.1:4105'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker1 = storage.makeWorker(run, 'investigation', asset, 'Worker A', 'Check settle-race')
  const worker2 = storage.makeWorker(run, 'investigation', asset, 'Worker B', 'Check settle-race independently')
  const worker3 = storage.makeWorker(run, 'investigation', asset, 'Worker C', 'Check invoices export')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  const res1 = persist({
    run,
    assignment: worker1,
    script: '// single-hop 1',
    runtime: 'ts',
    title: 'TOCTOU race on order settlement',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/orders/[redacted:cap:hop_1:order_id]/settle-race',
      method: 'POST',
      vulnClass: 'race_double_spend',
      exchangePrefix: 'sh-1',
      claimTitle: 'TOCTOU race on order settlement',
    }),
    secrets: [],
  })
  const res2 = persist({
    run,
    assignment: worker2,
    script: '// single-hop 2',
    runtime: 'ts',
    title: 'Double-spend on concrete order ID',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
      method: 'POST',
      vulnClass: 'race_double_spend',
      exchangePrefix: 'sh-2',
      claimTitle: 'Double-spend on concrete order ID',
    }),
    secrets: [],
  })
  assert.equal(res2.findingId, res1.findingId, 'single-hop proofs on the same normalized endpoint must collapse to 1 finding')

  const res3 = persist({
    run,
    assignment: worker3,
    script: '// single-hop distinct route',
    runtime: 'ts',
    title: 'Double-spend on coupon redeem',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/coupons/mh_cpn_3_f00baa/redeem',
      method: 'POST',
      vulnClass: 'race_double_spend',
      exchangePrefix: 'sh-3',
      claimTitle: 'Double-spend on coupon redeem',
    }),
    secrets: [],
  })
  assert.notEqual(res3.findingId, res1.findingId)

  const persistedRows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(persistedRows.length, 2)
  assert.ok(persistedRows.every(r => Boolean(r.fingerprintHash && r.finding.fingerprintHash)))
})

test('3. Cross-port loopback origins (proxy vs direct API) collapse on same normalized route while distinct routes and non-loopback hosts stay separate', async (t) => {
  const proxyOrigin = 'http://127.0.0.1:4201'
  const directApiOrigin = 'http://127.0.0.1:4202'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, {
    seeds: [proxyOrigin, directApiOrigin],
    environment: 'local-lab',
    tier: 3,
  })
  const run = storage.run(runId)
  const proxyAsset = run.candidates.find(c => c.origin === proxyOrigin)!
  const apiAsset = run.candidates.find(c => c.origin === directApiOrigin)!
  const w1 = storage.makeWorker(run, 'investigation', proxyAsset, 'Proxy worker', 'Verify via proxy')
  const w2 = storage.makeWorker(run, 'investigation', apiAsset, 'Direct API worker', 'Verify via direct API')
  const w3 = storage.makeWorker(run, 'investigation', apiAsset, 'Direct API worker 2', 'Verify other route')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  const viaProxy = persist({
    run,
    assignment: w1,
    script: '// proxy proof',
    runtime: 'ts',
    title: 'Proxy order settle race',
    proof: makeCompositeProof({
      origin: proxyOrigin,
      endpoint: '/v1/orders/[redacted:cap:hop_1:order_id]/settle-race',
      method: 'POST',
      chainId: 'chain-proxy-1',
      exchangePrefix: 'px-1',
      claimTitle: 'Proxy order settle race',
    }),
    secrets: [],
  })
  const viaDirect = persist({
    run,
    assignment: w2,
    script: '// direct api proof',
    runtime: 'ts',
    title: 'Direct API order settle race',
    proof: makeCompositeProof({
      origin: directApiOrigin,
      endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
      method: 'POST',
      chainId: 'chain-direct-2',
      exchangePrefix: 'dx-2',
      claimTitle: 'Direct API order settle race',
    }),
    secrets: [],
  })
  assert.equal(viaDirect.findingId, viaProxy.findingId, 'same route across local proxy & direct API loopback ports must collapse')

  const mergedRow = storage.db.select().from(findings).where(eq(findings.id, viaProxy.findingId)).get()!
  assert.ok(mergedRow.sourceOrigins.includes(proxyOrigin))
  assert.ok(mergedRow.sourceOrigins.includes(directApiOrigin))
  assert.equal(mergedRow.finding.evidenceIds.length, 2)

  // Different route on directApiOrigin must NOT collapse!
  const otherRoute = persist({
    run,
    assignment: w3,
    script: '// direct api other route',
    runtime: 'ts',
    title: 'Refund double credit',
    proof: makeCompositeProof({
      origin: directApiOrigin,
      endpoint: '/v1/refunds/mh_ref_2_dead01/apply',
      method: 'POST',
      chainId: 'chain-refund-3',
      exchangePrefix: 'dx-3',
      claimTitle: 'Refund double credit',
    }),
    secrets: [],
  })
  assert.notEqual(otherRoute.findingId, viaProxy.findingId, 'different route on loopback port must remain distinct')

  const allRows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(allRows.length, 2)

  // Distinct non-loopback hosts must NEVER collapse even on the same normalized endpoint.
  assert.equal(
    originsEquivalentForAgentProofDedupe('https://api-a.example.test', 'https://api-b.example.test', '/v1/orders/:id/settle-race'),
    false,
  )
  assert.equal(
    originsEquivalentForAgentProofDedupe('http://127.0.0.1:4201', 'http://127.0.0.1:4202', '/'),
    false,
    'root path must not collapse across different loopback ports',
  )
})

test('4. CWE aliases with same terminalOracleFamily collapse on same route, while distinct oracle families, distinct classes, and distinct HTTP methods stay separate', async (t) => {
  const origin = 'http://127.0.0.1:4301'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Multi-class worker', 'Verify classes')

  const execution = new Execution(storage, { broker: new RequestBroker({ rejectUnauthorized: false }) })
  t.after(() => { void execution.stop() })
  const persist = persistViaExecution(execution)

  // Worker 1 labels it `economic_conservation` (CWE-840); Worker 2 labels it `race_double_spend` (CWE-362),
  // both with `terminalOracleFamily: 'economic_conservation'` on POST /v1/orders/:id/settle-race.
  const first = persist({
    run,
    assignment: worker,
    script: '// econ conservation',
    runtime: 'ts',
    title: 'Economic conservation breach on settle-race',
    proof: makeCompositeProof({
      origin,
      endpoint: '/v1/orders/[redacted:cap:hop_1:order_id]/settle-race',
      method: 'POST',
      terminalVulnClass: 'economic_conservation',
      terminalOracleFamily: 'economic_conservation',
      chainId: 'chain-cwe840',
      exchangePrefix: 'c1',
      claimTitle: 'Economic conservation breach on settle-race',
    }),
    secrets: [],
  })
  const aliasDup = persist({
    run,
    assignment: worker,
    script: '// race double spend alias',
    runtime: 'ts',
    title: 'Race double spend on settle-race',
    proof: makeCompositeProof({
      origin,
      endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
      method: 'POST',
      terminalVulnClass: 'race_double_spend',
      terminalOracleFamily: 'economic_conservation',
      chainId: 'chain-cwe362',
      exchangePrefix: 'c2',
      claimTitle: 'Race double spend on settle-race',
    }),
    secrets: [],
  })
  assert.equal(aliasDup.findingId, first.findingId, 'CWE-840 and CWE-362 with same terminalOracleFamily on same route must collapse')

  // Distinct terminalOracleFamily (`dual_tenant_abac`, CWE-639) on same route must remain distinct!
  const diffFamily = persist({
    run,
    assignment: worker,
    script: '// cross-tenant abac on same route',
    runtime: 'ts',
    title: 'Cross-tenant ABAC on settle-race',
    proof: makeCompositeProof({
      origin,
      endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
      method: 'POST',
      terminalVulnClass: 'dual_tenant_abac',
      terminalOracleFamily: 'dual_tenant_abac',
      chainId: 'chain-abac',
      exchangePrefix: 'c3',
      claimTitle: 'Cross-tenant ABAC on settle-race',
    }),
    secrets: [],
  })
  assert.notEqual(diffFamily.findingId, first.findingId, 'different terminalOracleFamily on same route must stay distinct')

  // Distinct HTTP verb (`GET` vs `POST`) on same route + same oracle family must remain distinct!
  const diffMethod = persist({
    run,
    assignment: worker,
    script: '// GET dual_tenant_abac',
    runtime: 'ts',
    title: 'Cross-tenant ABAC read on settle-race',
    proof: makeCompositeProof({
      origin,
      endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
      method: 'GET',
      terminalVulnClass: 'dual_tenant_abac',
      terminalOracleFamily: 'dual_tenant_abac',
      chainId: 'chain-abac-get',
      exchangePrefix: 'c4',
      claimTitle: 'Cross-tenant ABAC read on settle-race',
    }),
    secrets: [],
  })
  assert.notEqual(diffMethod.findingId, diffFamily.findingId, 'distinct HTTP methods on same route must stay distinct')

  const rows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(rows.length, 3)
})

test('5. Pure helper checks for target extraction, method compatibility, and CWE/oracle-family equivalence', () => {
  assert.equal(
    normalizeEndpointTemplate('/v1/orders/[redacted:cap:hop_1:order_id]/settle-race'),
    '/v1/orders/:id/settle-race',
  )
  assert.equal(
    normalizeEndpointTemplate('/v1/orders/mh_ord_9_5ed534/settle-race'),
    '/v1/orders/:id/settle-race',
  )

  // Method compatibility: missing/ANY matches explicit verb, distinct explicit verbs stay distinct.
  assert.equal(methodsCompatibleForAgentProofDedupe('POST', 'post'), true)
  assert.equal(methodsCompatibleForAgentProofDedupe('POST', null), true)
  assert.equal(methodsCompatibleForAgentProofDedupe('ANY', 'DELETE'), true)
  assert.equal(methodsCompatibleForAgentProofDedupe('GET', 'DELETE'), false)

  // Vulnerability class equivalence.
  assert.equal(
    vulnClassesEquivalentForAgentProofDedupe(
      { cwe: 'CWE-840', terminalOracleFamily: 'economic_conservation' },
      { cwe: 'CWE-362', terminalOracleFamily: 'economic_conservation' },
    ),
    true,
  )
  assert.equal(
    vulnClassesEquivalentForAgentProofDedupe(
      { cwe: 'CWE-840', terminalOracleFamily: 'economic_conservation' },
      { cwe: 'CWE-639', terminalOracleFamily: 'dual_tenant_abac' },
    ),
    false,
  )
  assert.equal(
    vulnClassesEquivalentForAgentProofDedupe(
      { cwe: 'CWE-639', terminalOracleFamily: null },
      { cwe: 'CWE-89', terminalOracleFamily: null },
    ),
    false,
  )

  // extractAgentProofTarget prefers cleanCompositeBundle.verification.terminalEndpoint and parses leading verb.
  const dummySpec = {
    version: 1 as const,
    kind: 'http_chain' as const,
    spaCatchallControl: false,
    origin: 'http://127.0.0.1:4101',
    title: 'Test',
    category: 'business-logic-race' as const,
    cwe: 'CWE-840',
    severity: 'high' as const,
    severityRationale: 'r',
    impact: 'i',
    remediation: 'rem',
    recheckInstructions: 'rc',
    assertionsJq: 'true',
    steps: [
      {
        id: 'proof_1',
        role: 'probe' as const,
        description: 'GET /v1/fallback',
        request: { origin: 'http://127.0.0.1:4101', method: 'GET' as const, pathAndQuery: '/v1/fallback', followRedirects: false },
      },
    ],
  }
  const proof = makeCompositeProof({
    origin: 'http://127.0.0.1:4101',
    endpoint: 'POST /v1/orders/[redacted:cap:hop_1:order_id]/settle-race',
    method: 'POST',
    chainId: 'chain-parse',
    exchangePrefix: 'p1',
    claimTitle: 'Parse verb prefix',
  })
  const extracted = extractAgentProofTarget({
    cleanCompositeBundle: proof.compositeReceipt,
    receipt: null,
    baseSpec: dummySpec,
    proof,
  })
  assert.equal(extracted.endpoint, '/v1/orders/[redacted:cap:hop_1:order_id]/settle-race')
  assert.equal(extracted.normalizedEndpoint, '/v1/orders/:id/settle-race')
  assert.equal(extracted.method, 'POST')
  assert.equal(extracted.terminalOracleFamily, 'economic_conservation')
})
