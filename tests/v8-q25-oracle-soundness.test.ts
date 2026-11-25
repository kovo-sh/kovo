/**
 * Queue #25 Oracle Soundness & Multi-Hop Crypto/Async Proof-Ergonomics Regression Suite.
 *
 * Verifies:
 *  1. `cryptographic_scope_replay` decoy FP bypass is closed: removing the `hasDerivedCryptoEdge`
 *     control waiver enforces a clean denied control (401/403/404) on the exact terminal route
 *     family, non-empty terminal endpoint, and substantive foreign-tenant or persisted-mutation
 *     impact (rejecting stubs, own-tenant-only payloads, and missing endpoints).
 *  2. `dispatchDefaultV8Oracle` fails closed across all 6 `V8_ORACLE_FAMILIES` when required
 *     evidence is absent (never silently returning null) and populates `terminalOracleFamily` on
 *     confirmed `CompositeReceiptVerification` results.
 *  3. `isJobOrHandleStub` classifies signed-URL / presigned-download / export-job / token-handle
 *     envelopes as intermediate stubs while accepting genuine foreign-tenant records and mutation
 *     readbacks.
 *  4. `GUARDIAN_VERIFY_TOOL_DESCRIPTION` and `workerSessionInstructions` surface the compact
 *     (<= 12 lines) Multi-Hop Cryptographic & Async Pivot Pattern (`ctx.hmac_sign`, `ctx.jwt_sign`,
 *     `ctx.await_async`, `edge_binding`, exact terminal denied control, no stub stop) within byte
 *     budgets and with zero benchmark contamination.
 */
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  GUARDIAN_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  guardianVerifyHelperGuidance,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import {
  evaluateCryptographicScopeReplay,
  isJobOrHandleStub,
  type HostSignedRecord,
} from '../src/server/v8-oracle-families.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SIGNING_KEY = 'unit-test-q25-oracle-soundness-key-0123456789'

function makeSignedEntry(
  exchangeId: string,
  opts: {
    arm: 'control' | 'probe'
    method: string
    pathAndQuery?: string
    route?: string
    status: number
    timestampMs: number
    actorPersona?: string | null
    actorTenant?: string | null
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    cryptoAttestations?: HostTranscriptEntry['cryptoAttestations']
    json?: unknown
    body?: string
    evidenceRole?: string
  },
): HostTranscriptEntry {
  const actor = opts.actorPersona !== undefined ? opts.actorPersona : 'member_attacker'
  const tenant = opts.actorTenant !== undefined ? opts.actorTenant : 'org_attacker'
  const route = opts.route !== undefined ? opts.route : (opts.pathAndQuery ? opts.pathAndQuery.split('?')[0]! : undefined)
  const entry: HostTranscriptEntry = {
    exchangeId,
    timestampMs: opts.timestampMs,
    actorPersona: actor,
    actorRoleLabel: actor ? `member (${tenant ?? 'org_attacker'})` : null,
    cleanSession: true,
    ...(opts.emittedCapabilities ? { emittedCapabilities: opts.emittedCapabilities } : {}),
    ...(opts.consumedCapabilities ? { consumedCapabilities: opts.consumedCapabilities } : {}),
    ...(opts.cryptoAttestations ? { cryptoAttestations: opts.cryptoAttestations } : {}),
    ...(opts.evidenceRole ? { evidenceRole: opts.evidenceRole } : {}),
    step: {
      id: exchangeId,
      arm: opts.arm,
      method: opts.method,
      ...(route !== undefined ? { route } : {}),
      ...(opts.pathAndQuery !== undefined ? { pathAndQuery: opts.pathAndQuery } : {}),
      status: opts.status,
      actor: {
        handle: actor,
        role: actor ? 'member' : null,
        tenant,
        auth: actor ? 'bearer' : 'unknown',
        sameSite: null,
      },
      ...(opts.json !== undefined ? { json: opts.json } : {}),
      ...(opts.body !== undefined ? { body: opts.body } : {}),
    },
  }
  return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
}

// ============================================================================
// 1. cryptographic_scope_replay decoy FP bypass is CLOSED
// ============================================================================

test('cryptographic_scope_replay rejects missing denied control, missing endpoint, wrong-route control, stub, and own-tenant-only even with derived_crypto_binding', () => {
  const keyCap = 'cap:hop_1:signing_key'
  const derivedCap = 'cap:hop_2:derived_jwt'
  const digest = sha256Hex('derived-token-artifact')

  const transcript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl-exact-403', { arm: 'control', method: 'GET', pathAndQuery: '/api/vault/export', status: 403, timestampMs: 800 }),
      makeSignedEntry('ex-ctrl-other-403', { arm: 'control', method: 'GET', pathAndQuery: '/api/unrelated/admin', status: 403, timestampMs: 810 }),
      makeSignedEntry('ex-ctrl-anon-401', { arm: 'control', method: 'GET', pathAndQuery: '/api/vault/export', status: 401, timestampMs: 820, actorPersona: null, actorTenant: null }),
      makeSignedEntry('ex-hop1-key', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/runtime/config', status: 200, timestampMs: 1000,
        emittedCapabilities: [keyCap], json: { status: 'ok', keyId: 'k-1' },
      }),
      // Decoy hop 2: derived_crypto_binding with NO endpoint/route
      makeSignedEntry('ex-hop2-no-endpoint', {
        arm: 'probe', method: 'POST', status: 200, timestampMs: 1200,
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: derivedCap, alg: 'HS256', artifactDigest: digest, timestampMs: 1100 }],
        json: { tenantId: 'org_victim', records: [{ id: 'r1' }] },
      }),
      // Hop 2 with endpoint, returning signed URL / token stub
      makeSignedEntry('ex-hop2-stub', {
        arm: 'probe', method: 'POST', pathAndQuery: '/api/vault/export', status: 200, timestampMs: 1210,
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: derivedCap, alg: 'HS256', artifactDigest: digest, timestampMs: 1100 }],
        json: { downloadUrl: 'https://cdn.example.test/exp-1.csv?sig=abc', exportId: 'exp-1', token: 'tok_1', signature: 'deadbeef', expiresAt: 1_800_000_000 },
      }),
      // Hop 2 with endpoint, returning own-tenant-only payload
      makeSignedEntry('ex-hop2-own-tenant', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/vault/export', status: 200, timestampMs: 1220,
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: derivedCap, alg: 'HS256', artifactDigest: digest, timestampMs: 1100 }],
        json: { tenantId: 'org_attacker', records: [{ id: 'own-1', amountCents: 100 }] },
      }),
      // Hop 2 with endpoint, returning real foreign-tenant records
      makeSignedEntry('ex-hop2-foreign-data', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/vault/export', status: 200, timestampMs: 1230,
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: derivedCap, alg: 'HS256', artifactDigest: digest, timestampMs: 1100 }],
        json: { tenantId: 'org_victim', records: [{ id: 'inv-901', ownerEmail: 'cfo@victim.test', amountCents: 990000 }] },
      }),
      // Hop 2 mutation + Hop 3 readback
      makeSignedEntry('ex-hop2-mut', {
        arm: 'probe', method: 'POST', pathAndQuery: '/api/vault/export', status: 200, timestampMs: 1240,
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: derivedCap, alg: 'hmac-sha256', artifactDigest: digest, timestampMs: 1100 }],
        json: { ok: true, id: 'mut-1' },
      }),
      makeSignedEntry('ex-post-rb', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/vault/export/mut-1', status: 200, timestampMs: 1300,
        json: { tenantId: 'org_victim', settled: true, amountCents: 50000 },
      }),
    ],
  }

  const buildReceipt = (opts: {
    termExId: string
    pathAndQuery?: string
    ctrlIds?: string[]
    postRbIds?: string[]
    alg?: string
  }) => ({
    chainId: `chain-q25-crypto-${opts.termExId}`,
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/runtime/config' },
        exchangeIds: ['ex-hop1-key'], producedCapabilities: [keyCap],
        claimedDelta: 'Sealed runtime signing key handle.',
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: 'https://api.example.test', method: 'GET', ...(opts.pathAndQuery ? { pathAndQuery: opts.pathAndQuery } : {}) },
        exchangeIds: [opts.termExId], consumedCapabilities: [keyCap], producedCapabilities: [derivedCap],
        claimedDelta: 'Replayed derived credential on terminal target.',
      },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap, derivedCapabilityId: derivedCap, alg: opts.alg ?? 'HS256' },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Derived cryptographic token bypassed cross-tenant vault authorization.',
      terminalExchangeId: opts.termExId,
      preChainControlExchangeIds: opts.ctrlIds ?? [],
      postChainReadbackExchangeIds: opts.postRbIds ?? [],
    },
    replayMode: 'fresh_clean_replay',
  })

  // (a) Queue #24 decoy FP shape: derived_crypto_binding + NO control + NO endpoint -> MUST REJECT!
  const noCtrlNoEndpoint = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-no-endpoint', ctrlIds: [] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(noCtrlNoEndpoint.confirmed, false)
  assert.equal(noCtrlNoEndpoint.failedStage, 'terminal_impact')
  assert.equal(noCtrlNoEndpoint.rejectedBy, 'v8_oracle_cryptographic_scope_replay')
  assert.ok(noCtrlNoEndpoint.missingEvidence?.includes('clean_denied_control_401_403_404'))

  // (b) Even with unrelated 403 control, missing terminalEndpoint MUST NOT match control!
  const noEndpointWithOtherCtrl = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-no-endpoint', ctrlIds: ['ex-ctrl-other-403'] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(noEndpointWithOtherCtrl.confirmed, false)
  assert.equal(noEndpointWithOtherCtrl.rejectedBy, 'v8_oracle_cryptographic_scope_replay')

  // (c) Concrete foreign data + derived_crypto_binding but NO denied control -> MUST REJECT (waiver removed)!
  const noCtrlForeign = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-foreign-data', pathAndQuery: '/api/vault/export', ctrlIds: [] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(noCtrlForeign.confirmed, false)
  assert.equal(noCtrlForeign.rejectedBy, 'v8_oracle_cryptographic_scope_replay')
  assert.ok(noCtrlForeign.missingEvidence?.includes('clean_denied_control_401_403_404'))

  // (d) Wrong-route 403 control -> MUST REJECT!
  const wrongRoute = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-foreign-data', pathAndQuery: '/api/vault/export', ctrlIds: ['ex-ctrl-other-403'] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(wrongRoute.confirmed, false)
  assert.equal(wrongRoute.rejectedBy, 'v8_oracle_cryptographic_scope_replay')

  // (e) Anon 401 control for authenticated attacker probe -> MUST REJECT!
  const anonCtrl = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-foreign-data', pathAndQuery: '/api/vault/export', ctrlIds: ['ex-ctrl-anon-401'] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(anonCtrl.confirmed, false)
  assert.equal(anonCtrl.rejectedBy, 'v8_oracle_cryptographic_scope_replay')

  // (f) Signed URL / token stub WITH exact 403 control -> MUST REJECT as terminal_impact_unproven!
  const stubWithCtrl = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-stub', pathAndQuery: '/api/vault/export', ctrlIds: ['ex-ctrl-exact-403'] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(stubWithCtrl.confirmed, false)
  assert.equal(stubWithCtrl.rejectedBy, 'terminal_impact_unproven')

  // (g) Own-tenant-only payload WITH exact 403 control -> MUST REJECT as terminal_impact_unproven!
  const ownTenantWithCtrl = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-own-tenant', pathAndQuery: '/api/vault/export', ctrlIds: ['ex-ctrl-exact-403'] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(ownTenantWithCtrl.confirmed, false)
  assert.equal(ownTenantWithCtrl.rejectedBy, 'terminal_impact_unproven')

  // (h) TRUE POSITIVE: exact 403 control + derived_crypto_binding + foreign-tenant records -> CONFIRMS with terminalOracleFamily!
  const truePositive = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-foreign-data', pathAndQuery: '/api/vault/export', ctrlIds: ['ex-ctrl-exact-403'] }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(truePositive.confirmed, true, truePositive.reason)
  assert.equal(truePositive.terminalOracleFamily, 'cryptographic_scope_replay')
  assert.equal(truePositive.evidence?.terminalOracleFamily, 'cryptographic_scope_replay')

  // (i) TRUE POSITIVE with persisted mutation readback -> CONFIRMS with terminalOracleFamily!
  const truePositiveMut = verifyCompositeReceipt(
    buildReceipt({ termExId: 'ex-hop2-mut', pathAndQuery: '/api/vault/export', ctrlIds: ['ex-ctrl-exact-403'], postRbIds: ['ex-post-rb'], alg: 'hmac-sha256' }),
    transcript,
    { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY },
  )
  assert.equal(truePositiveMut.confirmed, true, truePositiveMut.reason)
  assert.equal(truePositiveMut.terminalOracleFamily, 'cryptographic_scope_replay')
})

// ============================================================================
// 2. dispatchDefaultV8Oracle fails closed across ALL V8_ORACLE_FAMILIES & records terminalOracleFamily
// ============================================================================

test('dispatchDefaultV8Oracle fails closed on missing evidence for all V8_ORACLE_FAMILIES and records terminalOracleFamily when confirmed', () => {
  const cap = 'cap:hop_1:tok'
  const transcript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl', { arm: 'control', method: 'GET', pathAndQuery: '/api/admin/records', status: 403, timestampMs: 800 }),
      makeSignedEntry('ex-h1', { arm: 'probe', method: 'POST', pathAndQuery: '/graphql', status: 200, timestampMs: 1000, emittedCapabilities: [cap], json: { ok: true } }),
      makeSignedEntry('ex-h2', { arm: 'probe', method: 'GET', pathAndQuery: '/api/admin/records', status: 200, timestampMs: 1200, consumedCapabilities: [cap], json: { tenantId: 'org_victim', records: [{ id: 'a1', amount: 500 }] } }),
      makeSignedEntry('ex-base', { arm: 'control', method: 'GET', pathAndQuery: '/api/orders/o1', status: 200, timestampMs: 900, json: { paid: 100, refunded: 0 } }),
      makeSignedEntry('ex-final', { arm: 'control', method: 'GET', pathAndQuery: '/api/orders/o1', status: 200, timestampMs: 1300, json: { paid: 100, refunded: 180 } }),
    ],
  }

  // (a) economic_conservation without oracleInput MUST fail closed (never return null)
  const econNoInput = verifyCompositeReceipt({
    chainId: 'chain-econ-missing-input',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['ex-h1'], producedCapabilities: [cap], claimedDelta: 'Step 1.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/records' }, exchangeIds: ['ex-h2'], consumedCapabilities: [cap], claimedDelta: 'Step 2.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: { terminalHopId: 'hop_2', summary: 'Claimed over-refund without structured ledger oracleInput.', terminalExchangeId: 'ex-h2', preChainControlExchangeIds: ['ex-ctrl'] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(econNoInput.confirmed, false)
  assert.equal(econNoInput.rejectedBy, 'v8_oracle_economic_conservation')
  assert.ok(econNoInput.missingEvidence?.includes('terminalImpact.oracleInput'))

  // (b) economic_conservation WITH valid oracleInput confirms and sets terminalOracleFamily
  const mkRec = (id: string) => {
    const e = transcript.entries!.find(x => x.exchangeId === id)!
    return { id: e.exchangeId, hostSignature: e.hostSignature!, timestampMs: e.timestampMs!, status: e.step.status }
  }
  const econPass = verifyCompositeReceipt({
    chainId: 'chain-econ-ok',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['ex-h1'], producedCapabilities: [cap], claimedDelta: 'Refund 1.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/records' }, exchangeIds: ['ex-h2'], consumedCapabilities: [cap], claimedDelta: 'Refund 2.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Confirmed over-refund exceeding paid order amount.',
      terminalExchangeId: 'ex-h2',
      oracleInput: {
        equation: 'over_refund',
        baselineReadback: mkRec('ex-base'),
        actions: [mkRec('ex-h1'), mkRec('ex-h2')],
        finalReadback: mkRec('ex-final'),
        paidAmount: 100,
        refundedAmounts: [90, 90],
      },
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(econPass.confirmed, true, econPass.reason)
  assert.equal(econPass.terminalOracleFamily, 'economic_conservation')

  // (c) 1-hop cross_surface_pivot MUST fail closed (never silently return null)
  const pivotOneHop = verifyCompositeReceipt({
    chainId: 'chain-pivot-1hop',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/records' }, exchangeIds: ['ex-h2'], claimedDelta: 'Single hop read.' },
    ],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'hop_1', summary: 'Claimed cross-surface pivot with only one hop.', terminalExchangeId: 'ex-h2', preChainControlExchangeIds: ['ex-ctrl'] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(pivotOneHop.confirmed, false)
  assert.equal(pivotOneHop.rejectedBy, 'v8_oracle_cross_surface_pivot')

  // (d) 1-hop temporal_revocation without oracleInput MUST fail closed
  const tempOneHop = verifyCompositeReceipt({
    chainId: 'chain-temp-1hop',
    terminalVulnClass: 'temporal_revocation',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/records' }, exchangeIds: ['ex-h2'], claimedDelta: 'Single hop.' },
    ],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'hop_1', summary: 'Claimed temporal revocation without upstream revocation hop.', terminalExchangeId: 'ex-h2', preChainControlExchangeIds: ['ex-ctrl'] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(tempOneHop.confirmed, false)
  assert.equal(tempOneHop.rejectedBy, 'v8_oracle_temporal_revocation')

  // (e) Confirmed 2-hop chains populate terminalOracleFamily for cross_surface_pivot, dual_tenant_abac, parser_cache_differential, temporal_revocation
  for (const family of ['cross_surface_pivot', 'dual_tenant_abac', 'parser_cache_differential', 'temporal_revocation'] as const) {
    const res = verifyCompositeReceipt({
      chainId: `chain-ok-${family}`,
      terminalVulnClass: family,
      hops: [
        { hopId: 'hop_1', surface: 'graphql', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/graphql' }, exchangeIds: ['ex-h1'], producedCapabilities: [cap], claimedDelta: 'Obtained capability.' },
        { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/admin/records' }, exchangeIds: ['ex-h2'], consumedCapabilities: [cap], claimedDelta: 'Accessed foreign admin records.' },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        summary: `Verified ${family} chain exposing foreign tenant admin records.`,
        terminalExchangeId: 'ex-h2',
        preChainControlExchangeIds: ['ex-ctrl'],
      },
      replayMode: 'fresh_clean_replay',
    }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, true, `${family} failed: ${res.reason}`)
    assert.equal(res.terminalOracleFamily, family)
    assert.equal(res.evidence?.terminalOracleFamily, family)
  }
})

// ============================================================================
// 3. isJobOrHandleStub catches signed-URL / presigned-download / export-job / token-handle envelopes
// ============================================================================

test('isJobOrHandleStub rejects signed-URL / presigned-download / export-job / token-handle envelopes and accepts real business payloads', () => {
  const stubs: Array<[unknown, number, string]> = [
    [{ signedUrl: 'https://cdn.example.test/files/out.csv?sig=deadbeef', expiresAt: 1_800_000_000 }, 200, 'GET'],
    [{ downloadUrl: '/api/exports/exp-4/download', exportId: 'exp-4', jobId: 'job-4', token: 'tok_4', signature: 'sig_4', expiresAt: '2026-12-01T00:00:00Z' }, 200, 'GET'],
    [{ token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.abc', signature: 'abc', alg: 'HS256', exp: 1_800_000_000 }, 200, 'GET'],
    [{ data: { presignedDownloadUrl: 'https://storage.example.test/b/k?sig=1', signature: 'sig1', expiresIn: 300 } }, 200, 'GET'],
    [{ receipt: { jobId: 'j-9', handle: 'h-9', status: 'queued', expiresIn: 120 } }, 202, 'POST'],
    [{ downloadId: 'dl-1', signedPath: '/files/dl-1?sig=1', hmac: 'a1b2c3', validUntil: '2026-12-01T00:00:00Z' }, 200, 'GET'],
  ]
  for (const [payload, status, method] of stubs) {
    assert.equal(isJobOrHandleStub(payload, undefined, status, method), true, `Expected stub=true for ${JSON.stringify(payload)}`)
  }

  const realPayloads: Array<[unknown, number, string]> = [
    [{ tenantId: 'org_victim', records: [{ id: 'inv-1', email: 'cfo@victim.test', amountCents: 42000 }] }, 200, 'GET'],
    [{ id: 'ord-1', status: 'settled', amount: 15000 }, 200, 'GET'],
    [{ role: 'owner' }, 200, 'GET'],
    [{ token: 'eyJ...', user: { email: 'admin@victim.test', role: 'admin' } }, 200, 'GET'],
  ]
  for (const [payload, status, method] of realPayloads) {
    assert.equal(isJobOrHandleStub(payload, undefined, status, method), false, `Expected stub=false for ${JSON.stringify(payload)}`)
  }

  // Direct evaluateCryptographicScopeReplay also rejects a signed-URL stub!
  const mkOracle = (id: string, ts: number, status: number, extra: Partial<HostSignedRecord> = {}): HostSignedRecord => ({
    id, hostSignature: 'sig-q25-1234567890', timestampMs: ts, status, ...extra,
  })
  const cryptoStub = evaluateCryptographicScopeReplay({
    tamperedSignatureControl: mkOracle('c1', 1000, 401, { route: '/api/presign', artifactDigest: 'sha256:bad' }),
    sourceValidIssuance: mkOracle('s1', 1100, 200, { route: '/api/sign', artifactDigest: 'sha256:good' }),
    replayedAcceptance: mkOracle('r1', 1200, 200, {
      route: '/api/presign', artifactDigest: 'sha256:good',
      json: { signedUrl: 'https://storage.example.test/exp-1.csv?sig=good', exportId: 'exp-1', expiresAt: 1_800_000_000 },
    }),
    sourceTenant: 'org_attacker',
    sourceScope: 'own:export',
    targetTenant: 'org_victim',
    targetScope: 'foreign:export',
  })
  assert.equal(cryptoStub.satisfied, false)
  assert.equal(cryptoStub.reason, 'terminal_impact_unproven_intermediate_stub')
})

// ============================================================================
// 4. Actionable Multi-Hop Crypto/Async SDK Pattern in agent-prompts.ts + Anti-Contamination
// ============================================================================

test('agent-prompts surfaces compact (<= 12 lines) Multi-Hop Cryptographic & Async Pivot Pattern within budgets and with zero contamination', () => {
  const lines = GUARDIAN_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n')
  assert.ok(lines.length <= 12, `Pattern must be <= 12 lines, got ${lines.length}`)

  const sysPrompt = workerSessionInstructions('worker-investigation', { hasGuardianVerify: true })
  const guidance = guardianVerifyHelperGuidance()
  assert.ok(
    Buffer.byteLength(guidance, 'utf8') <= GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `guidance ${Buffer.byteLength(guidance, 'utf8')} B > ${GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B`,
  )

  for (const [label, text] of [
    ['GUARDIAN_VERIFY_TOOL_DESCRIPTION', GUARDIAN_VERIFY_TOOL_DESCRIPTION],
    ['workerSessionInstructions', sysPrompt],
  ] as const) {
    assert.ok(text.includes('ctx.hmac_sign('), `${label} missing exact ctx.hmac_sign(...) call`)
    assert.ok(text.includes('ctx.jwt_sign('), `${label} missing exact ctx.jwt_sign(...) call`)
    assert.ok(text.includes('ctx.await_async('), `${label} missing exact ctx.await_async(...) call`)
    assert.ok(text.includes('derived_crypto_binding'), `${label} missing derived_crypto_binding`)
    assert.ok(text.includes('async_pivot_binding'), `${label} missing async_pivot_binding`)
    assert.ok(text.includes('edge_binding'), `${label} missing edge_binding guidance`)
    assert.ok(text.includes('preChainControlExchangeIds'), `${label} missing preChainControlExchangeIds`)
    assert.match(text, /401.*403.*404/, `${label} missing 401/403/404 denied control guidance`)
    assert.match(text, /NEVER stop at a job handle.*signed URL/i, `${label} missing no-stub terminal rule`)
  }

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected benchmark contamination: ${JSON.stringify(scan.hits)}`)
  assert.deepEqual(scan.hits, [])
})
