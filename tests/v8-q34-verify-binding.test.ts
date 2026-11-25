/**
 * Queue #34 Stream 3 regression suite:
 *  1. Cross-attempt `causalFingerprints` / `verifyScript` agreement for multi-hop
 *     composite proofs with fresh per-run compound IDs, redacted capability tokens,
 *     and multi-exchange race-burst terminal hops — while preserving strict
 *     `transcript_mismatch` rejection for route/method/claim-type/oracle-family/edge diffs.
 *  2. `value_binding` verification across multi-exchange `toHop.exchangeIds` (6-request
 *     race burst), host-attested `hmac_sign`/`jwt_sign` derivations, derived `actorPersona`,
 *     path-interpolated `valueDigest`, and late `capability.seal` backfill via
 *     `VerifyRpcServer` — while rejecting unbound, out-of-order, or tampered handles.
 *  3. `multihop-chains.md` guide coverage + LOC ceilings & zero-contamination check.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import {
  TranscriptStore,
  causalFingerprints,
  normalizeDynamic,
  type VerifyClaim,
  type VerifyClaimCheck,
} from '../src/server/verify-claims.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'
import { verifyScript, type AttemptExecution, type VerifyAttemptSession } from '../src/server/verify-runner.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN_API = 'http://127.0.0.1:48100'
const SIGNING_KEY = 'q34-verify-binding-signing-key-0011223344'

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
  },
) {
  return store.record({
    op: 'http',
    startedAt: Date.now(),
    durationMs: 5,
    request: {
      origin: ORIGIN_API,
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
      bodySha256: sha256Hex(`${input.status}:${input.pathAndQuery}:${input.body}`),
    },
    body: input.body,
  })
}

function makeStep(overrides: Partial<ImpactStep> & { id: string }): ImpactStep {
  return {
    arm: 'probe',
    method: 'POST',
    route: '/api/v1/items',
    pathAndQuery: '/api/v1/items',
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'cookie', sameSite: 'lax' },
    body: JSON.stringify({ ok: true, tenant: 'org_b', record: 'confidential-row' }),
    json: { ok: true, tenant: 'org_b', record: 'confidential-row' },
    requestHeaders: {},
    responseHeaders: { 'content-type': 'application/json' },
    durationMs: 4,
    ...overrides,
  }
}

function makeEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  return {
    exchangeId,
    step,
    timestampMs: 1000,
    actorPersona: step.actor.handle ?? null,
    ...extra,
  }
}

function signTranscript(transcript: HostSignedTranscript): HostSignedTranscript {
  return {
    ...(transcript.entries ? { entries: transcript.entries.map(e => ({ ...e, hostSignature: signHostRecord(e, SIGNING_KEY) })) } : {}),
    ...(transcript.oobEvents ? { oobEvents: transcript.oobEvents.map(o => ({ ...o, hostSignature: signHostRecord(o, SIGNING_KEY) })) } : {}),
    ...(transcript.browserTraces ? { browserTraces: transcript.browserTraces.map(t => ({ ...t, hostSignature: signHostRecord(t, SIGNING_KEY) })) } : {}),
    ...(transcript.asyncPollRecords ? { asyncPollRecords: transcript.asyncPollRecords.map(p => ({ ...p, hostSignature: signHostRecord(p, SIGNING_KEY) })) } : {}),
  }
}

function makeOpenAttempt(
  runFn: (transcript: TranscriptStore, attempt: 1 | 2, nonce: string) => AttemptExecution,
) {
  return async ({ attempt, nonce }: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const transcript = new TranscriptStore()
    return {
      nonce,
      transcript,
      async execute() { return runFn(transcript, attempt, nonce) },
      async close() { /* no-op */ },
    }
  }
}

async function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return await new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', c => chunks.push(Buffer.from(c)))
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(payload)
  })
}

function makeGrant(origin: string): Grant {
  return {
    canRead: (o: string) => { try { return new URL(o).origin === origin } catch { return o === origin } },
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    audit: () => undefined,
  }
}

// ============================================================================
// 1. Causal Fingerprint & `transcript_mismatch` Regression Tests
// ============================================================================

test('verifyScript confirms dual composite runs with compound per-run IDs, redacted cap segments, and non-deterministic race-burst winner order', async () => {
  const verdict = await verifyScript({
    candidate: { name: 'q34-composite-race.ts', runtime: 'ts', code: '// mock', title: 'Composite race proof' },
    openAttempt: makeOpenAttempt((store, attempt, nonce) => {
      const orderId = attempt === 1 ? 'mh_ord_9_5ed534' : 'mh_ord_10_7ab912'
      const route = attempt === 1
        ? `/api/v1/orders/[redacted:cap:hop_1:order_id]/settle-race`
        : `/api/v1/orders/${orderId}/settle-race`
      // Simulate 6-request race burst where Run 1's last exchange won (200) and Run 2's last exchange lost (409)
      const statuses = attempt === 1 ? [409, 200, 409, 409, 409, 200] : [200, 200, 409, 409, 409, 409]
      const burst = statuses.map(status =>
        recordHttp(store, {
          method: 'POST',
          pathAndQuery: `/api/v1/orders/${orderId}/settle-race`,
          status,
          body: JSON.stringify({ orderId, status }),
          nonce,
          personaHandle: 'member_b',
          sessionRole: 'probe',
        }),
      )
      const burstIds = burst.map(b => b.exchangeId)
      const hostRec = store.recordCompositeVerification({
        chainId: `chain-${orderId}`,
        terminalVulnClass: 'economic_conservation',
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        confirmed: true,
        verifiedEdgeCount: 1,
        reason: `CompositeProofReceipt confirmed for ${orderId}`,
        rejectedBy: null,
        missingEvidence: [],
        exchangeIds: burstIds,
        terminalExchangeId: burstIds[burstIds.length - 1]!,
        route,
      })
      const claim: VerifyClaim = {
        kind: 'composite_receipt',
        verificationId: hostRec.verificationId,
        chainId: `chain-${orderId}`,
        terminalVulnClass: 'economic_conservation',
        route,
        exchangeIds: burstIds,
        terminalExchangeId: burstIds[burstIds.length - 1]!,
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        compositeReceipt: {
          hops: [
            { hopId: 'hop_1', exchangeIds: [burstIds[0]!] },
            { hopId: 'hop_2', exchangeIds: burstIds },
          ],
          causalEdges: [{ kind: 'value_binding' }],
          terminalImpact: { terminalHopId: 'hop_2', oracleFamily: 'economic_conservation' },
        },
      }
      return {
        exitCode: 0,
        durationMs: 12,
        stdout: '',
        stderr: '',
        result: {
          nonce,
          title: `Concurrent double-settlement on ${orderId}`,
          claims: [claim],
        },
      }
    }),
  })

  assert.equal(verdict.confirmed, true, `Expected confirmed, got ${verdict.reason}: ${verdict.disagreements.join('; ')}`)
  assert.equal(verdict.reason, 'confirmed')
  assert.deepEqual(verdict.disagreements, [])
})

test('pathFingerprint and normalizeDynamic handle compound runtime IDs + bare [redacted] while keeping static route/tenant segments distinct', () => {
  const s1 = new TranscriptStore()
  const s2 = new TranscriptStore()
  const e1 = recordHttp(s1, {
    method: 'GET',
    pathAndQuery: '/api/v1/exports/mh_job_export_38_c4f8e5.json/[redacted]/inv-2026-0042',
    status: 200,
    body: '{"ok":true}',
    nonce: 'n1',
  })
  const e2 = recordHttp(s2, {
    method: 'GET',
    pathAndQuery: '/api/v1/exports/mh_job_export_39_a1b2c3.json/[redacted:cap:hop_2:tok]/inv-2026-0043',
    status: 200,
    body: '{"ok":true}',
    nonce: 'n2',
  })
  const fp1 = causalFingerprints(s1, [{ claim: { kind: 'status', exchangeId: e1.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n1')
  const fp2 = causalFingerprints(s2, [{ claim: { kind: 'status', exchangeId: e2.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n2')
  assert.equal(fp1[0]!.path, '/api/v1/exports/*.json/*/*')
  assert.equal(fp2[0]!.path, '/api/v1/exports/*.json/*/*')

  assert.equal(
    normalizeDynamic('order mh_ord_9_5ed534 job mh_job_export_38_c4f8e5 [redacted:cap:hop_1:id]'),
    normalizeDynamic('order mh_ord_10_7ab912 job mh_job_export_39_a1b2c3 [redacted]'),
  )

  // Static kebab/snake/version/tenant segments MUST NOT collapse.
  const t1 = recordHttp(s1, { method: 'GET', pathAndQuery: '/api/v1/orgs/tenant_1/settle-race/report.json', status: 200, body: '{}', nonce: 'n1' })
  const t2 = recordHttp(s2, { method: 'GET', pathAndQuery: '/api/v1/orgs/tenant_2/settle-race/report.json', status: 200, body: '{}', nonce: 'n2' })
  const fpT1 = causalFingerprints(s1, [{ claim: { kind: 'status', exchangeId: t1.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n1')
  const fpT2 = causalFingerprints(s2, [{ claim: { kind: 'status', exchangeId: t2.exchangeId, expected: 200 }, passed: true, detail: 'ok', observed: { status: 200 } }], 'n2')
  assert.equal(fpT1[0]!.path, '/api/v1/orgs/tenant_1/settle-race/report.json')
  assert.notEqual(fpT1[0]!.path, fpT2[0]!.path)
})

test('verifyScript still rejects genuine causal disagreements (route, claim type, oracle family) with transcript_mismatch', async () => {
  const runDivergent = async (mode: 'route' | 'oracle_family' | 'claim_kind') => verifyScript({
    candidate: { name: `q34-div-${mode}.ts`, runtime: 'ts', code: '// mock', title: 'Divergent proof' },
    openAttempt: makeOpenAttempt((store, attempt, nonce) => {
      const route = mode === 'route'
        ? (attempt === 1 ? '/api/v1/orders/mh_ord_9_5ed534/settle-race' : '/api/v1/orders/mh_ord_10_7ab912/refund')
        : `/api/v1/orders/${attempt === 1 ? 'mh_ord_9_5ed534' : 'mh_ord_10_7ab912'}/settle-race`
      const ex1 = recordHttp(store, { method: 'POST', pathAndQuery: route, status: 200, body: '{"ok":true,"delta":1}', nonce, personaHandle: 'member_b', sessionRole: 'probe' })
      const ex2 = recordHttp(store, { method: 'POST', pathAndQuery: route, status: 200, body: '{"ok":true,"delta":2}', nonce, personaHandle: 'member_b', sessionRole: 'probe' })
      const oracleFamily = mode === 'oracle_family'
        ? (attempt === 1 ? 'economic_conservation' : 'dual_tenant_abac')
        : 'economic_conservation'
      const hostRec = store.recordCompositeVerification({
        chainId: 'chain-div-1',
        terminalVulnClass: oracleFamily,
        replayMode: 'fresh_clean_replay',
        hopCount: 2,
        confirmed: true,
        verifiedEdgeCount: 1,
        reason: 'ok',
        rejectedBy: null,
        missingEvidence: [],
        exchangeIds: [ex1.exchangeId, ex2.exchangeId],
        terminalExchangeId: ex2.exchangeId,
        route,
      })
      const claim: VerifyClaim = mode === 'claim_kind' && attempt === 2
        ? { kind: 'race', exchangeIds: [ex1.exchangeId, ex2.exchangeId], minDistinctOutcomes: 2 }
        : {
            kind: 'composite_receipt',
            verificationId: hostRec.verificationId,
            chainId: 'chain-div-1',
            terminalVulnClass: oracleFamily,
            route,
            exchangeIds: [ex1.exchangeId, ex2.exchangeId],
            terminalExchangeId: ex2.exchangeId,
            replayMode: 'fresh_clean_replay',
            hopCount: 2,
            compositeReceipt: {
              hops: [{ hopId: 'hop_1', exchangeIds: [ex1.exchangeId] }, { hopId: 'hop_2', exchangeIds: [ex2.exchangeId] }],
              causalEdges: [{ kind: 'value_binding' }],
              terminalImpact: { terminalHopId: 'hop_2', oracleFamily },
            },
          }
      return { exitCode: 0, durationMs: 8, stdout: '', stderr: '', result: { nonce, title: 'Divergent proof', claims: [claim] } }
    }),
  })

  for (const mode of ['route', 'oracle_family', 'claim_kind'] as const) {
    const verdict = await runDivergent(mode)
    assert.equal(verdict.confirmed, false, `Expected ${mode} divergence to fail`)
    assert.equal(verdict.reason, 'transcript_mismatch', `Expected transcript_mismatch for ${mode}, got ${verdict.reason}`)
    assert.ok(verdict.disagreements.length > 0)
  }
})

// ============================================================================
// 2. `value_binding` Unit & Loopback Verification Tests
// ============================================================================

test('value_binding verifies multi-exchange race burst, derived hmac_sign/jwt_sign handles, actorPersona, and path valueDigest while rejecting unbound/out-of-order', () => {
  const orderCap = 'cap:hop_1:order_id'
  const keyCap = 'cap:hop_1:signing_key'
  const jwtCap = 'cap:hop_2:forged_jwt'
  const unusedCap = 'cap:hop_1:unused_token'
  const pathEntityId = 'mh_ord_77_a1b2c3'
  const pathDigest = sha256Hex(pathEntityId)
  const validSigDigest = sha256Hex('valid-hmac-sig')

  // (a) 6-request race burst where handle appears in a subset of toHop exchanges
  const burstIds = ['gx-3', 'gx-4', 'gx-5', 'gx-6', 'gx-7', 'gx-8']
  const burstTranscript: HostSignedTranscript = {
    entries: [
      makeEntry('gx-ctrl', makeStep({ id: 'gx-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: `/v1/orders/${pathEntityId}/settle-race`, body: '{"error":"forbidden"}' }), { timestampMs: 900, actorPersona: 'member_a' }),
      makeEntry('gx-1', makeStep({ id: 'gx-1', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/v1/orders', json: { id: pathEntityId } }), { timestampMs: 1000, actorPersona: 'member_a', emittedCapabilities: [orderCap] }),
      makeEntry('gx-2', makeStep({ id: 'gx-2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: `/v1/orders/${pathEntityId}` }), { timestampMs: 1050, actorPersona: 'member_a' }),
      ...burstIds.map((id, idx) =>
        makeEntry(id, makeStep({ id, arm: 'probe', method: 'POST', status: idx < 2 ? 200 : 409, pathAndQuery: `/v1/orders/${pathEntityId}/settle-race` }), {
          timestampMs: 1200 + idx,
          actorPersona: 'member_a',
          ...(idx >= 1 ? { consumedCapabilities: [orderCap] } : {}),
        }),
      ),
    ],
  }
  const burstReceipt: CompositeProofReceipt = {
    chainId: 'chain-vb-burst',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/v1/orders' }, exchangeIds: ['gx-1', 'gx-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created order', producedCapabilities: [orderCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: `/v1/orders/${pathEntityId}/settle-race` }, exchangeIds: burstIds, oobEventIds: [], browserTraceIds: [], claimedDelta: 'Race burst settled order twice', producedCapabilities: [], consumedCapabilities: [orderCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: orderCap }],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Duplicate settlement observed', preChainControlExchangeIds: ['gx-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }
  const burstOk = verifyCompositeReceipt(burstReceipt, signTranscript(burstTranscript), { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(burstOk.confirmed, true, burstOk.reason)

  // (a2) Path-interpolated valueDigest without consumedCapabilities passes on exact SHA-256 match
  const digestReceipt: CompositeProofReceipt = {
    ...burstReceipt,
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', valueDigest: pathDigest }],
  }
  const digestOk = verifyCompositeReceipt(digestReceipt, signTranscript(burstTranscript), { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(digestOk.confirmed, true, digestOk.reason)

  // (b) Derived signing handle (hmac_sign / jwt_sign) passes value_binding on source keyCap when monotonic
  const cryptoTranscript: HostSignedTranscript = {
    entries: [
      makeEntry('cx-ctrl', makeStep({ id: 'cx-ctrl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/v1/webhooks/trigger', body: '{"error":"forbidden"}' }), { timestampMs: 900, actorPersona: 'member_a' }),
      makeEntry('cx-1', makeStep({ id: 'cx-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/service-meta' }), { timestampMs: 1000, actorPersona: 'member_a', emittedCapabilities: [keyCap, unusedCap] }),
      makeEntry('cx-2', makeStep({ id: 'cx-2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/v1/webhooks/trigger' }), {
        timestampMs: 1300,
        actorPersona: 'member_a',
        consumedCapabilities: [jwtCap],
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: jwtCap, alg: 'HS256', artifactDigest: validSigDigest, timestampMs: 1150 }],
      }),
    ],
  }
  const cryptoReceipt: CompositeProofReceipt = {
    chainId: 'chain-vb-crypto',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN_API, pathAndQuery: '/v1/service-meta' }, exchangeIds: ['cx-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained signing key', producedCapabilities: [keyCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'webhook', target: { origin: ORIGIN_API, pathAndQuery: '/v1/webhooks/trigger' }, exchangeIds: ['cx-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Sent signed request using derived artifact', producedCapabilities: [], consumedCapabilities: [keyCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: keyCap }],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Signed webhook accepted across boundary', preChainControlExchangeIds: ['cx-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }
  const cryptoOk = verifyCompositeReceipt(cryptoReceipt, signTranscript(cryptoTranscript), { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(cryptoOk.confirmed, true, cryptoOk.reason)

  // (c) Soundness: unused handle MUST reject cleanly
  const unusedReceipt: CompositeProofReceipt = {
    ...cryptoReceipt,
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: unusedCap }],
  }
  const unusedRes = verifyCompositeReceipt(unusedReceipt, signTranscript(cryptoTranscript), { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(unusedRes.confirmed, false)
  assert.equal(unusedRes.failedStage, 'edge_binding')
  assert.match(unusedRes.reason, /value_binding handle "cap:hop_1:unused_token" not matched/)

  // (d) Soundness: out-of-order cryptoAttestation (tDerive < tSource) MUST reject
  const badOrderCrypto: HostSignedTranscript = {
    entries: [
      cryptoTranscript.entries![0]!,
      cryptoTranscript.entries![1]!,
      { ...cryptoTranscript.entries![2]!, cryptoAttestations: [{ derivedFromCapabilityId: keyCap, alg: 'sha256', artifactDigest: validSigDigest, timestampMs: 950 }] },
    ],
  }
  const badOrderRes = verifyCompositeReceipt(cryptoReceipt, signTranscript(badOrderCrypto), { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(badOrderRes.confirmed, false)
  assert.equal(badOrderRes.failedStage, 'edge_binding')
  assert.match(badOrderRes.reason, /monotonic/i)

  // (e) Soundness: malformed non-SHA256 artifactDigest MUST reject
  const badDigestCrypto: HostSignedTranscript = {
    entries: [
      cryptoTranscript.entries![0]!,
      cryptoTranscript.entries![1]!,
      { ...cryptoTranscript.entries![2]!, cryptoAttestations: [{ derivedFromCapabilityId: keyCap, alg: 'sha256', artifactDigest: 'not-a-sha256', timestampMs: 1150 }] },
    ],
  }
  const badDigestRes = verifyCompositeReceipt(cryptoReceipt, signTranscript(badDigestCrypto), { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(badDigestRes.confirmed, false)
  assert.equal(badDigestRes.failedStage, 'edge_binding')
})

test('VerifyRpcServer backfills late capability.seal onto subsequent 6-request race burst and verifies hmac_sign value_binding end-to-end', async () => {
  const ORDER_ID = 'mh_ord_42_c0ffee'
  const UNUSED_TOKEN = 'unused-secret-99887766'
  const SIGNING_KEY_VAL = 'q34-loopback-hmac-secret-778899'
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const send = (status: number, value: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(value))
      }
      if (url.pathname === '/api/pre-order' && req.method === 'GET') return send(200, { seen: ORDER_ID })
      if (url.pathname === '/api/orders' && req.method === 'POST') return send(201, { id: ORDER_ID, unused: UNUSED_TOKEN, signingKey: SIGNING_KEY_VAL })
      if (url.pathname === `/api/orders/${ORDER_ID}/settle-race` && req.method === 'POST') {
        return send(200, { settled: true, orderId: ORDER_ID, tenant: 'org_b', balance: 200 })
      }
      if (url.pathname === '/api/signed' && req.method === 'POST') {
        const sig = String(req.headers['x-sig'] ?? '')
        return send(sig.length >= 16 ? 200 : 403, { ok: sig.length >= 16, tenant: 'org_b', balance: 200 })
      }
      return send(403, { error: 'denied' })
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  const hostDir = mkdtempSync(join(tmpdir(), 'kovo-q34-vb-'))
  const rpc = new VerifyRpcServer({
    runId: 'run-q34-vb',
    assignmentId: 'assign-q34-vb',
    broker: new RequestBroker(),
    grant: makeGrant(origin),
    targetOrigins: [origin],
    hostDir,
    capabilityVault: new DerivedCapabilityVault({ runId: 'run-q34-vb' }),
  })
  await rpc.start()
  const call = (op: string, args: Record<string, unknown>) => rpcCall(rpc.socketPath, rpc.token, rpc.nonce, op, args)
  try {
    // Request BEFORE order creation (must NOT be backfilled when sealing order later)
    const pre = await call('http.send', { origin, method: 'GET', path: `/api/pre-order?id=${ORDER_ID}`, role: 'control' })
    assert.equal(pre.ok, true)
    const preId = (pre.result as { exchangeId: string }).exchangeId

    // Hop 1: create order (returns ORDER_ID + SIGNING_KEY_VAL + UNUSED_TOKEN)
    const h1 = await call('http.send', { origin, method: 'POST', path: '/api/orders', role: 'probe' })
    assert.equal(h1.ok, true)
    const h1Id = (h1.result as { exchangeId: string }).exchangeId

    // Hop 2: send 6-request race burst BEFORE sealing ORDER_ID (late-seal scenario!)
    const raceRes = await call('race', {
      requests: Array.from({ length: 6 }, () => ({ origin, method: 'POST', path: `/api/orders/${ORDER_ID}/settle-race`, role: 'probe' })),
    })
    assert.equal(raceRes.ok, true)
    const burstIds = ((raceRes.result as { results: Array<{ exchangeId: string }> }).results).map(r => r.exchangeId)
    assert.equal(burstIds.length, 6)

    // Late seal AFTER the race burst
    const sealedOrder = await call('capability.seal', { exchangeId: h1Id, hopReceiptId: '1', slot: 'order_id', jsonPath: '$.id' })
    assert.equal(sealedOrder.ok, true)
    const orderHandle = (sealedOrder.result as { handle: string }).handle

    const sealedUnused = await call('capability.seal', { exchangeId: h1Id, hopReceiptId: '1', slot: 'unused', jsonPath: '$.unused' })
    assert.equal(sealedUnused.ok, true)
    const unusedHandle = (sealedUnused.result as { handle: string }).handle

    // Verify backfilled transcript: burst exchanges carry orderHandle, pre-creation exchange does NOT!
    const hostTranscript = rpc.buildHostSignedTranscript()
    const preEntry = hostTranscript.entries?.find(e => e.exchangeId === preId)
    assert.equal(preEntry?.consumedCapabilities?.includes(orderHandle) ?? false, false, 'pre-creation request must NOT be backfilled')
    for (const bid of burstIds) {
      const entry = hostTranscript.entries?.find(e => e.exchangeId === bid)
      assert.ok(entry?.consumedCapabilities?.includes(orderHandle), `expected race burst exchange ${bid} to carry backfilled ${orderHandle}`)
    }

    // Confirm composite receipt via value_binding across the 6-exchange race burst
    const compOk = await call('composite.verify', {
      receipt: {
        chainId: 'chain-q34-late-seal-burst',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/orders' }, exchangeIds: [h1Id], claimedDelta: 'Created order', producedCapabilities: [orderHandle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${ORDER_ID}/settle-race` }, exchangeIds: burstIds, claimedDelta: 'Race burst executed', producedCapabilities: [], consumedCapabilities: [orderHandle] },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: orderHandle }],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Double settlement observed', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      },
    })
    assert.equal((compOk.result as { confirmed: boolean }).confirmed, true, JSON.stringify(compOk.result))

    // Unused handle MUST fail cleanly at edge_binding
    const compUnused = await call('composite.verify', {
      receipt: {
        chainId: 'chain-q34-unused',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/orders' }, exchangeIds: [h1Id], claimedDelta: 'Created order', producedCapabilities: [unusedHandle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${ORDER_ID}/settle-race` }, exchangeIds: burstIds, claimedDelta: 'Race burst executed', producedCapabilities: [], consumedCapabilities: [unusedHandle] },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: unusedHandle }],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Double settlement observed', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      },
    })
    assert.equal((compUnused.result as { confirmed: boolean }).confirmed, false)
    assert.equal((compUnused.result as { failedStage: string }).failedStage, 'edge_binding')

    // End-to-end hmac_sign -> value_binding using keyHandle
    const sealedKey = await call('capability.seal', { exchangeId: h1Id, hopReceiptId: '1', slot: 'signing_key', jsonPath: '$.signingKey', kind: 'hmac_key' })
    assert.equal(sealedKey.ok, true)
    const keyHandle = (sealedKey.result as { handle: string }).handle
    const sigRes = await call('crypto.hmacSign', { secretHandle: keyHandle, payload: '{"action":"settle"}', alg: 'sha256', encoding: 'hex' })
    assert.equal(sigRes.ok, true)
    const sig = sigRes.result as { exchangeId: string; signature: string }
    const signedEx = await call('http.send', {
      origin,
      method: 'POST',
      path: '/api/signed',
      headers: { 'x-sig': sig.signature, 'content-type': 'application/json' },
      body: '{"action":"settle"}',
      role: 'probe',
    })
    assert.equal(signedEx.ok, true)
    const signedExId = (signedEx.result as { exchangeId: string }).exchangeId
    const compHmac = await call('composite.verify', {
      receipt: {
        chainId: 'chain-q34-hmac-vb',
        terminalVulnClass: 'business_logic',
        replayMode: 'fresh_clean_replay',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/orders' }, exchangeIds: [h1Id], claimedDelta: 'Leaked signing key', producedCapabilities: [keyHandle], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'webhook', target: { origin, method: 'POST', pathAndQuery: '/api/signed' }, exchangeIds: [sig.exchangeId, signedExId], claimedDelta: 'Signed request accepted', producedCapabilities: [], consumedCapabilities: [keyHandle] },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: keyHandle }],
        terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Privileged signed action confirmed', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      },
    })
    assert.equal((compHmac.result as { confirmed: boolean }).confirmed, true, JSON.stringify(compHmac.result))
  } finally {
    await rpc.close()
    rmSync(hostDir, { recursive: true, force: true })
    server.close()
  }
})

// ============================================================================
// 3. SDK Guide Polish, LOC Ceilings & Zero Contamination
// ============================================================================

test('multihop-chains.md covers hmac_sign/jwt_sign binding and await_async flat return + artifact URL follow-up, within LOC ceilings & zero contamination', () => {
  const guide = readFileSync(join(REPO_ROOT, 'src/skills/multihop-chains.md'), 'utf8')
  assert.match(guide, /ctx\.hmac_sign/)
  assert.match(guide, /ctx\.jwt_sign/)
  assert.match(guide, /value_binding/)
  assert.match(guide, /derived_crypto_binding/)
  assert.match(guide, /ctx\.await_async/)
  assert.match(guide, /exchangeId.*exchange/s)
  assert.match(guide, /download\/artifact URL/i)

  const compLoc = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8').trimEnd().split('\n').length
  const rpcLoc = readFileSync(join(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8').trimEnd().split('\n').length
  assert.ok(compLoc <= 750, `composite-receipt.ts is ${compLoc} LOC (ceiling <= 750)`)
  assert.ok(rpcLoc <= 2300, `verify-rpc.ts is ${rpcLoc} LOC (ceiling <= 2300)`)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true)
  assert.deepEqual(scan.hits, [], `Unexpected v8 benchmark contamination: ${JSON.stringify(scan.hits)}`)
})
