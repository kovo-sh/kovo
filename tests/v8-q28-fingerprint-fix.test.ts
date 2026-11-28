/**
 * Regression suite for v8 Q28 Smoking Gun #1 (`verify-claims.ts` + `verify-runner.ts`):
 * Two independently passing verification runs must agree when only fresh-run dynamic
 * identifiers/counters/timestamps/race-win-counts differ, while genuine causal
 * disagreements or oracle failures must still fail closed.
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  TranscriptStore,
  causalFingerprints,
  normalizeDynamic,
} from '../src/server/verify-claims.ts'
import type { VerifyClaim, VerifyClaimCheck } from '../src/server/verify-claims.ts'
import { verifyScript } from '../src/server/verify-runner.ts'
import type { AttemptExecution, VerifyAttemptSession } from '../src/server/verify-runner.ts'

function recordHttp(
  store: TranscriptStore,
  input: {
    method: string
    pathAndQuery: string
    status: number
    body: string
    nonce: string
    personaHandle?: string
    sessionRole?: 'control' | 'probe' | 'setup'
    op?: 'http' | 'http2'
    bodySha256?: string
  },
) {
  return store.record({
    op: input.op ?? 'http',
    startedAt: Date.now(),
    durationMs: 4,
    request: {
      origin: 'http://127.0.0.1:9999',
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      headers: {},
      bodyBytes: 0,
      bodySha256: 'req000',
      nonce: input.nonce,
      ...(input.personaHandle ? { personaHandle: input.personaHandle } : {}),
      ...(input.sessionRole ? { sessionRole: input.sessionRole } : {}),
    },
    response: {
      status: input.status,
      mediaType: 'application/json',
      headers: { 'content-type': 'application/json' },
      bodyBytes: Buffer.byteLength(input.body),
      bodySha256: input.bodySha256 ?? `sha_${input.status}_${Buffer.byteLength(input.body)}_${input.pathAndQuery}`,
    },
    body: input.body,
  })
}

function makeMockOpenAttempt(
  runFn: (transcript: TranscriptStore, attempt: 1 | 2, nonce: string) => AttemptExecution,
) {
  return async ({ attempt, nonce }: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const transcript = new TranscriptStore()
    return {
      nonce,
      transcript,
      async execute() {
        return runFn(transcript, attempt, nonce)
      },
      async close() { /* no-op */ },
    }
  }
}

const dummyCandidate = {
  name: 'q28-fingerprint.ts',
  runtime: 'ts' as const,
  code: '// mock',
  title: 'Q28 fingerprint regression',
}

test('normalizeDynamic normalizes gx IDs, cap handles, and prefixed entity IDs while preserving CWE/static labels', () => {
  const nonce = 'nonce-abc999'
  const input = [
    `nonce=${nonce}`,
    'ex=gx-550e8400-e29b-41d4-a716-446655440000',
    'ex2=gx-11223344',
    'cap=cap:hop_1:ord_a1b2.secret-v2',
    'uuid=123e4567-e89b-12d3-a456-426614174000',
    'ts=2026-11-25T12:07:40.123Z',
    'hex=deadbeef0123456789abcdef',
    'ord=ord_a1b2',
    'ord2=ord_123',
    'inv=inv-9001',
    'chain=chain_ord_c3d4',
  ].join(' ')

  const normalized = normalizeDynamic(input, nonce)
  assert.equal(
    normalized,
    'nonce=<nonce> ex=<gx> ex2=<gx> cap=<cap> uuid=<uuid> ts=<ts> hex=<hex> ord=<id> ord2=<id> inv=<id> chain=chain_<id>',
  )

  // Security-meaningful labels and non-ID snake_case identifiers must NOT be collapsed.
  assert.equal(normalizeDynamic('CWE-639 vs CWE-1321 with SHA-256 and AES-256'), 'CWE-639 vs CWE-1321 with SHA-256 and AES-256')
  assert.equal(normalizeDynamic('dual_tenant_abac fresh_clean_replay user_profile hop_1 tenant_1'), 'dual_tenant_abac fresh_clean_replay user_profile hop_1 tenant_1')
  assert.notEqual(normalizeDynamic('CWE-639 IDOR'), normalizeDynamic('CWE-862 IDOR'))
  assert.notEqual(normalizeDynamic('CWE-1321 proto'), normalizeDynamic('CWE-1236 csv'))
})

test('pathFingerprint templates hyphenated prefixed IDs, gx segments, cap handles, and [redacted:...] segments', () => {
  const store1 = new TranscriptStore()
  const store2 = new TranscriptStore()
  const r1 = recordHttp(store1, {
    method: 'POST',
    pathAndQuery: '/api/orders/ord-a1b2/gx-550e8400-e29b-41d4-a716-446655440000/[redacted:secret]/cap:hop_1:tok?id=ord_123&nonce=n1',
    status: 200,
    body: '{"ok":true}',
    nonce: 'n1',
  })
  const r2 = recordHttp(store2, {
    method: 'POST',
    pathAndQuery: '/api/orders/ord-c3d4/gx-99998888/%5Bredacted%3Atoken%5D/cap:hop_2:other?nonce=n2&id=ord_456',
    status: 200,
    body: '{"ok":true}',
    nonce: 'n2',
  })

  const fp1 = causalFingerprints(store1, [{ claim: { kind: 'status', exchangeId: r1.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n1')
  const fp2 = causalFingerprints(store2, [{ claim: { kind: 'status', exchangeId: r2.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n2')

  assert.equal(fp1[0]!.path, '/api/orders/*/*/*/*?id&nonce')
  assert.equal(fp2[0]!.path, '/api/orders/*/*/*/*?id&nonce')

  // Static kebab/snake route segments without digits stay distinct.
  const s3 = recordHttp(store1, { method: 'GET', pathAndQuery: '/api/v1/user-profile/credit_cards', status: 200, body: '{}', nonce: 'n1' })
  const fp3 = causalFingerprints(store1, [{ claim: { kind: 'status', exchangeId: s3.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n1')
  assert.equal(fp3[0]!.path, '/api/v1/user-profile/credit_cards')
})

test('composite_receipt fingerprints agree across fresh runs with volatile IDs/timestamps and disagree on structural differences', () => {
  const buildCompositeRun = (opts: {
    nonce: string
    chainId: string
    orderId: string
    tFrom: number
    tTo: number
    oracleFamily: string
    edgeKinds: string[]
    replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
    hopCount?: number
  }) => {
    const store = new TranscriptStore()
    const ex = recordHttp(store, {
      method: 'POST',
      pathAndQuery: `/api/orders/${opts.orderId}/refund`,
      status: 200,
      body: JSON.stringify({ orderId: opts.orderId, balance: opts.tFrom }),
      nonce: opts.nonce,
    })
    const hostRec = store.recordCompositeVerification({
      chainId: opts.chainId,
      terminalVulnClass: 'economic_conservation',
      replayMode: opts.replayMode ?? 'fresh_clean_replay',
      hopCount: opts.hopCount ?? 2,
      confirmed: true,
      verifiedEdgeCount: opts.edgeKinds.length,
      reason: `verified ${opts.orderId} at ${opts.tTo}`,
      rejectedBy: null,
      missingEvidence: [],
      exchangeIds: [ex.exchangeId],
      terminalExchangeId: ex.exchangeId,
      route: `/api/orders/${opts.orderId}/refund`,
    })
    const claim: VerifyClaim = {
      kind: 'composite_receipt',
      verificationId: hostRec.verificationId,
      chainId: opts.chainId,
      terminalVulnClass: 'economic_conservation',
      route: `/api/orders/${opts.orderId}/refund`,
      exchangeIds: [ex.exchangeId],
      terminalExchangeId: ex.exchangeId,
      replayMode: opts.replayMode ?? 'fresh_clean_replay',
      hopCount: opts.hopCount ?? 2,
      compositeReceipt: {
        causalEdges: opts.edgeKinds.map(kind => ({ kind })),
        terminalImpact: { oracleFamily: opts.oracleFamily },
      },
    }
    const check: VerifyClaimCheck = {
      claim,
      passed: true,
      detail: 'ok',
      observed: {
        confirmed: true,
        terminalOracleFamily: opts.oracleFamily,
        hopCount: opts.hopCount ?? 2,
        verifiedEdgeKinds: opts.edgeKinds,
        modeBVerified: (opts.replayMode ?? 'fresh_clean_replay') === 'one_shot_transcript',
        // Volatile fields that previously broke agreement:
        tFrom: opts.tFrom,
        tTo: opts.tTo,
        entityId: opts.orderId,
        exchangeIds: [ex.exchangeId],
      },
    }
    return causalFingerprints(store, [check], opts.nonce)[0]!
  }

  const run1 = buildCompositeRun({
    nonce: 'nonce-run-1',
    chainId: 'chain_ord_a1b2',
    orderId: 'ord_a1b2',
    tFrom: 1795600001,
    tTo: 1795600009,
    oracleFamily: 'economic_conservation',
    edgeKinds: ['value_binding', 'state_transition_binding'],
  })
  const run2 = buildCompositeRun({
    nonce: 'nonce-run-2',
    chainId: 'chain_ord_c3d4',
    orderId: 'ord_c3d4',
    tFrom: 1795700123,
    tTo: 1795700456,
    oracleFamily: 'economic_conservation',
    edgeKinds: ['state_transition_binding', 'value_binding'],
  })
  assert.deepEqual(run1, run2)
  assert.deepEqual(run1.observed, {
    confirmed: true,
    terminalOracleFamily: 'economic_conservation',
    hopCount: 2,
    verifiedEdgeKinds: ['state_transition_binding', 'value_binding'],
    modeBVerified: false,
  })

  // Structural differences MUST still disagree.
  const diffFamily = buildCompositeRun({
    nonce: 'nonce-run-3',
    chainId: 'chain_ord_e5f6',
    orderId: 'ord_e5f6',
    tFrom: 1795800001,
    tTo: 1795800009,
    oracleFamily: 'dual_tenant_abac',
    edgeKinds: ['value_binding', 'state_transition_binding'],
  })
  assert.notDeepEqual(run1, diffFamily)

  const diffEdges = buildCompositeRun({
    nonce: 'nonce-run-4',
    chainId: 'chain_ord_g7h8',
    orderId: 'ord_g7h8',
    tFrom: 1795800001,
    tTo: 1795800009,
    oracleFamily: 'economic_conservation',
    edgeKinds: ['derived_crypto_binding'],
  })
  assert.notDeepEqual(run1, diffEdges)

  const diffModeB = buildCompositeRun({
    nonce: 'nonce-run-5',
    chainId: 'chain_ord_i9j0',
    orderId: 'ord_i9j0',
    tFrom: 1795800001,
    tTo: 1795800009,
    oracleFamily: 'economic_conservation',
    edgeKinds: ['value_binding', 'state_transition_binding'],
    replayMode: 'one_shot_transcript',
  })
  assert.notDeepEqual(run1, diffModeB)
})

test('impact, boundary, and race fingerprints agree across fresh runs with volatile deltas/counts and reject genuine mismatches', () => {
  // 1. Impact: different entity IDs, numeric balances, and counters -> SAME structural fingerprint.
  const s1 = new TranscriptStore()
  const s2 = new TranscriptStore()
  const p1 = recordHttp(s1, { method: 'PATCH', pathAndQuery: '/api/orders/ord_a1b2', status: 200, body: '{"balance":200,"seq":10}', nonce: 'n1', sessionRole: 'probe' })
  const p2 = recordHttp(s2, { method: 'PATCH', pathAndQuery: '/api/orders/ord_c3d4', status: 200, body: '{"balance":300,"seq":11}', nonce: 'n2', sessionRole: 'probe' })

  const impactFp1 = causalFingerprints(s1, [{
    claim: { kind: 'impact', impactClass: 'business_logic', probeExchangeId: p1.exchangeId, oracleEvents: ['invariant_violation'] },
    passed: true,
    detail: 'persisted balance 100 -> 200',
    observed: {
      persisted: true,
      changedFields: ['status', 'balance'],
      protectedFields: ['balance'],
      beforeBalance: 100,
      afterBalance: 200,
      entityId: 'ord_a1b2',
      autoIncrementId: 10,
    },
  }], 'n1')[0]!
  const impactFp2 = causalFingerprints(s2, [{
    claim: { kind: 'impact', impactClass: 'business_logic', probeExchangeId: p2.exchangeId, oracleEvents: ['invariant_violation'] },
    passed: true,
    detail: 'persisted balance 200 -> 300',
    observed: {
      persisted: true,
      changedFields: ['balance', 'status'],
      protectedFields: ['balance'],
      beforeBalance: 200,
      afterBalance: 300,
      entityId: 'ord_c3d4',
      autoIncrementId: 11,
    },
  }], 'n2')[0]!
  assert.deepEqual(impactFp1, impactFp2)
  assert.deepEqual(impactFp1.observed, {
    passed: true,
    impactClass: 'business_logic',
    changedFields: ['balance', 'status'],
    deltaKind: 'protected_field',
    hasPersistedDelta: true,
    hasProtectedDelta: true,
    statusCode: 200,
  })

  // Different changedFields MUST disagree.
  const impactFpDiff = causalFingerprints(s2, [{
    claim: { kind: 'impact', impactClass: 'business_logic', probeExchangeId: p2.exchangeId, oracleEvents: ['invariant_violation'] },
    passed: true,
    detail: 'different field',
    observed: { persisted: true, changedFields: ['note'], protectedFields: [] },
  }], 'n2')[0]!
  assert.notDeepEqual(impactFp1, impactFpDiff)

  // 2. Boundary: different fresh entity paths, controlStep gx IDs, body lengths, timestamps -> SAME fingerprint.
  const c1 = recordHttp(s1, { method: 'GET', pathAndQuery: '/api/orders/ord-a1b2', status: 403, body: '{"error":"denied"}', nonce: 'n1', personaHandle: 'guest', sessionRole: 'control' })
  const b1 = recordHttp(s1, { method: 'GET', pathAndQuery: '/api/orders/ord-a1b2', status: 200, body: '{"id":"ord-a1b2","total":100}', nonce: 'n1', personaHandle: 'member', sessionRole: 'probe' })
  const c2 = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/orders/ord-c3d4', status: 403, body: '{"error":"denied","ts":1795700000}', nonce: 'n2', personaHandle: 'guest', sessionRole: 'control' })
  const b2 = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/orders/ord-c3d4', status: 200, body: '{"id":"ord-c3d4","total":250,"extra":"longer"}', nonce: 'n2', personaHandle: 'member', sessionRole: 'probe' })

  const boundFp1 = causalFingerprints(s1, [{
    claim: { kind: 'boundary', boundaryClass: 'access', controlExchangeId: c1.exchangeId, probeExchangeId: b1.exchangeId },
    passed: true,
    detail: 'crossed',
    observed: { boundaryClass: 'access', controlDenied: true, controlStep: c1.exchangeId, actorDifferential: true, bodyLength: 29, ts: 1795600001 },
  }], 'n1')[0]!
  const boundFp2 = causalFingerprints(s2, [{
    claim: { kind: 'boundary', boundaryClass: 'access', controlExchangeId: c2.exchangeId, probeExchangeId: b2.exchangeId },
    passed: true,
    detail: 'crossed',
    observed: { boundaryClass: 'access', controlDenied: true, controlStep: c2.exchangeId, actorDifferential: true, bodyLength: 45, ts: 1795700009 },
  }], 'n2')[0]!
  assert.deepEqual(boundFp1, boundFp2)
  assert.deepEqual(boundFp1.observed, {
    passed: true,
    boundaryClass: 'access',
    controlStatus: 403,
    probeStatus: 200,
    actorRoleDiff: true,
  })

  // Different control status (401 vs 403) MUST disagree.
  const c2Unauth = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/orders/ord-c3d4', status: 401, body: '{"error":"unauth"}', nonce: 'n2', personaHandle: 'guest', sessionRole: 'control' })
  const boundFpDiff = causalFingerprints(s2, [{
    claim: { kind: 'boundary', boundaryClass: 'access', controlExchangeId: c2Unauth.exchangeId, probeExchangeId: b2.exchangeId },
    passed: true,
    detail: 'crossed',
    observed: { boundaryClass: 'access', controlDenied: true, controlStep: c2Unauth.exchangeId, actorDifferential: true },
  }], 'n2')[0]!
  assert.notDeepEqual(boundFp1, boundFpDiff)

  // 3. Race: 3 successes in Run 1 vs 4 successes in Run 2 (even with reordered 409) -> SAME bucket '>=2'.
  const r1Ids = [200, 200, 200, 409, 409].map((status, idx) =>
    recordHttp(s1, { method: 'POST', pathAndQuery: '/api/coupons/cpn_a1b2/redeem', status, body: `{"r":${idx}}`, nonce: 'n1', op: 'http2', bodySha256: `h1_${idx}` }).exchangeId,
  )
  const r2Ids = [409, 200, 200, 200, 200].map((status, idx) =>
    recordHttp(s2, { method: 'POST', pathAndQuery: '/api/coupons/cpn_c3d4/redeem', status, body: `{"r":${idx}}`, nonce: 'n2', op: 'http2', bodySha256: `h2_${idx}` }).exchangeId,
  )
  const raceFp1 = causalFingerprints(s1, [{
    claim: { kind: 'race', exchangeIds: r1Ids, mode: 'h2-single-packet', expectAllSuccess: false },
    passed: true,
    detail: '3 succeeded',
    observed: { distinctBodies: 3, distinctStatuses: 2, distinctOutcomes: 3, statuses: [200, 200, 200, 409, 409], mode: 'h2-single-packet' },
  }], 'n1')[0]!
  const raceFp2 = causalFingerprints(s2, [{
    claim: { kind: 'race', exchangeIds: r2Ids, mode: 'h2-single-packet', expectAllSuccess: false },
    passed: true,
    detail: '4 succeeded',
    observed: { distinctBodies: 4, distinctStatuses: 2, distinctOutcomes: 4, statuses: [409, 200, 200, 200, 200], mode: 'h2-single-packet' },
  }], 'n2')[0]!
  assert.deepEqual(raceFp1, raceFp2)
  assert.deepEqual(raceFp1.observed, {
    passed: true,
    mode: 'h2-single-packet',
    succeededCountBucket: '>=2',
  })

  // Only 1 success does NOT bucket as '>=2'.
  const raceFpSingle = causalFingerprints(s2, [{
    claim: { kind: 'race', exchangeIds: r2Ids, mode: 'h2-single-packet', expectAllSuccess: false },
    passed: false,
    detail: '1 succeeded',
    observed: { distinctBodies: 1, distinctStatuses: 2, distinctOutcomes: 1, statuses: [200, 409, 409, 409, 409], mode: 'h2-single-packet' },
  }], 'n2')[0]!
  assert.deepEqual(raceFpSingle.observed, {
    passed: false,
    mode: 'h2-single-packet',
    succeededCountBucket: 1,
  })
})

test('verifyScript confirms dual fresh composite runs with volatile entity IDs and normalized titles', async () => {
  const verdict = await verifyScript({
    candidate: dummyCandidate,
    openAttempt: makeMockOpenAttempt((transcript, attempt, nonce) => {
      const orderId = attempt === 1 ? 'ord_123' : 'ord_456'
      const chainId = attempt === 1 ? 'chain_ord_a1b2' : 'chain_ord_c3d4'
      const ex = recordHttp(transcript, {
        method: 'POST',
        pathAndQuery: `/api/orders/${orderId}/refund`,
        status: 200,
        body: JSON.stringify({ orderId, balance: attempt === 1 ? 200 : 300 }),
        nonce,
      })
      const hostRec = transcript.recordCompositeVerification({
        chainId,
        terminalVulnClass: 'economic_conservation',
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        confirmed: true,
        verifiedEdgeCount: 1,
        reason: `Economic overcredit verified on ${orderId}`,
        rejectedBy: null,
        missingEvidence: [],
        exchangeIds: [ex.exchangeId],
        terminalExchangeId: ex.exchangeId,
        route: `/api/orders/${orderId}/refund`,
      })
      return {
        result: {
          sdk: 'kovo_verify.ts',
          nonce,
          title: `Order ${orderId} overcredit (${nonce})`,
          claims: [
            {
              kind: 'composite_receipt',
              verificationId: hostRec.verificationId,
              chainId,
              terminalVulnClass: 'economic_conservation',
              route: `/api/orders/${orderId}/refund`,
              exchangeIds: [ex.exchangeId],
              terminalExchangeId: ex.exchangeId,
              replayMode: 'fresh_clean_replay',
              hopCount: 2,
              compositeReceipt: {
                causalEdges: [{ kind: 'value_binding' }],
                terminalImpact: { oracleFamily: 'economic_conservation' },
              },
            },
          ],
        },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 10,
      }
    }),
  })

  assert.equal(verdict.confirmed, true, `expected confirmed=true, got ${verdict.reason}: ${verdict.detail} (${verdict.disagreements.join('; ')})`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])
})

test('verifyScript still rejects genuinely different proof titles or when one fresh run fails the oracle', async () => {
  // (a) Different normalized proof titles -> transcript_mismatch
  const titleMismatch = await verifyScript({
    candidate: dummyCandidate,
    doubleReplay: true,
    openAttempt: makeMockOpenAttempt((transcript, attempt, nonce) => {
      const orderId = attempt === 1 ? 'ord_123' : 'ord_456'
      const ex = recordHttp(transcript, {
        method: 'POST',
        pathAndQuery: `/api/orders/${orderId}/refund`,
        status: 200,
        body: '{"ok":true}',
        nonce,
      })
      const hostRec = transcript.recordCompositeVerification({
        chainId: `chain_${orderId}`,
        terminalVulnClass: 'economic_conservation',
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        confirmed: true,
        verifiedEdgeCount: 1,
        reason: 'verified',
        rejectedBy: null,
        missingEvidence: [],
        exchangeIds: [ex.exchangeId],
        terminalExchangeId: ex.exchangeId,
        route: `/api/orders/${orderId}/refund`,
      })
      return {
        result: {
          sdk: 'kovo_verify.ts',
          nonce,
          title: attempt === 1 ? `Order ${orderId} overcredit` : `Invoice ${orderId} cross-tenant disclosure`,
          claims: [
            {
              kind: 'composite_receipt',
              verificationId: hostRec.verificationId,
              chainId: `chain_${orderId}`,
              terminalVulnClass: 'economic_conservation',
              route: `/api/orders/${orderId}/refund`,
              exchangeIds: [ex.exchangeId],
              terminalExchangeId: ex.exchangeId,
              replayMode: 'fresh_clean_replay',
              hopCount: 2,
            },
          ],
        },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 8,
      }
    }),
  })
  assert.equal(titleMismatch.confirmed, false)
  assert.equal(titleMismatch.reason, 'transcript_mismatch')
  assert.equal(titleMismatch.detail, 'Runs reported different proof titles.')

  // (b) Run 1 passes, Run 2 fails host composite oracle -> NEVER confirms!
  const oneFails = await verifyScript({
    candidate: dummyCandidate,
    doubleReplay: true,
    openAttempt: makeMockOpenAttempt((transcript, attempt, nonce) => {
      const orderId = attempt === 1 ? 'ord_123' : 'ord_456'
      const ex = recordHttp(transcript, {
        method: 'POST',
        pathAndQuery: `/api/orders/${orderId}/refund`,
        status: attempt === 1 ? 200 : 409,
        body: attempt === 1 ? '{"ok":true}' : '{"error":"already_refunded"}',
        nonce,
      })
      const hostRec = transcript.recordCompositeVerification({
        chainId: `chain_${orderId}`,
        terminalVulnClass: 'economic_conservation',
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        confirmed: attempt === 1,
        verifiedEdgeCount: attempt === 1 ? 1 : 0,
        reason: attempt === 1 ? 'verified' : 'Replay rejected duplicate refund',
        ...(attempt === 2 ? { failedStage: 'terminal_impact' } : {}),
        rejectedBy: attempt === 1 ? null : 'composite_terminal_impact',
        missingEvidence: attempt === 1 ? [] : ['economic_conservation'],
        exchangeIds: [ex.exchangeId],
        terminalExchangeId: ex.exchangeId,
        route: `/api/orders/${orderId}/refund`,
      })
      return {
        result: {
          sdk: 'kovo_verify.ts',
          nonce,
          title: `Order ${orderId} overcredit`,
          claims: [
            {
              kind: 'composite_receipt',
              verificationId: hostRec.verificationId,
              chainId: `chain_${orderId}`,
              terminalVulnClass: 'economic_conservation',
              route: `/api/orders/${orderId}/refund`,
              exchangeIds: [ex.exchangeId],
              terminalExchangeId: ex.exchangeId,
              replayMode: 'fresh_clean_replay',
              hopCount: 2,
            },
          ],
        },
        stdout: '',
        stderr: '',
        exitCode: 0,
        durationMs: 8,
      }
    }),
  })
  assert.equal(oneFails.confirmed, false)
  assert.equal(oneFails.reason, 'oracle_failed')
})
