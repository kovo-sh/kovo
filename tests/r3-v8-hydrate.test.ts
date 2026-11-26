/**
 * R3-C-5 Regression Suite — V8 Hydration Host-Plane Isolation:
 *
 * Ensures tenant and scope are NEVER derived from the worker's own request plane
 * (`x-scope` header, request JSON, or raw request body) across:
 *  (a) `cryptographic_scope_replay`: identical signed URL with an extra worker `x-scope`
 *      header or request-body `scope`/`tenantId` MUST fail closed (`same_tenant_and_scope_not_replay`),
 *      while genuine cross-tenant / cross-resource replays confirm cleanly and route-only
 *      (mint→download) or caller-only (identical bearer signed URL) flows reject (`same_principal_not_replay`).
 *  (b) `batch_partial_authz`: worker-injected tenant fields in request body NEVER become
 *      `foreignTenantId`, and echoed foreign IDs inside `denied`/`errors`/`forbidden` or
 *      per-item error entries NEVER count as `foreignDataObserved`; genuine cross-tenant
 *      non-error batch reads confirm cleanly.
 *  (c) `dual_org_cache_bleed`: tenant IDs present only in the bled-access request body
 *      NEVER populate `targetTenantId` or `observedTenantId`; genuine response-side
 *      cross-tenant cache bleed confirms cleanly.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import {
  evaluateCryptographicScopeReplay,
  evaluateDualTenantAbac,
  type HostSignedRecord,
} from '../src/server/v8-oracle-families.ts'
import {
  hydrateV8OracleInput,
  type HydratableTranscriptIndex,
} from '../src/server/v8-oracle-hydrate.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'r3-c5-v8-hydrate-signing-key-0123456789abcdef'

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org-a',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined
      ? { route: partial.route }
      : partial.pathAndQuery
        ? { route: partial.pathAndQuery.split('?')[0]! }
        : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

const idxOf = (entries: readonly HostTranscriptEntry[]): HydratableTranscriptIndex => ({
  entriesById: new Map(entries.map(e => [e.exchangeId, e])),
})

// ============================================================================
// (a) cryptographic_scope_replay: no worker x-scope / request-plane bypass
// ============================================================================

test('R3-C-5(a): identical signed URL fetched twice with worker x-scope header or request-body scope/tenant MUST reject', () => {
  const ctrl = signedEntry('csr-ctrl', makeStep({
    id: 'csr-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-42?sig=tampered-bad-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })

  const issue = signedEntry('csr-issue', makeStep({
    id: 'csr-issue', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-42?sig=valid-sig-001',
    json: { fileId: 'export-42', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 2, timestampMs: 1100 })

  const replayWithHeader = signedEntry('csr-replay-hdr', makeStep({
    id: 'csr-replay-hdr', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-42?sig=valid-sig-001',
    requestHeaders: { 'x-scope': 'org-b:admin' },
    json: { fileId: 'export-42', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 3, timestampMs: 1200 })

  const replayWithReqBody = signedEntry('csr-replay-body', makeStep({
    id: 'csr-replay-body', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-42?sig=valid-sig-001',
    requestJson: { scope: 'org-b:admin', tenantId: 'org-b' },
    json: { fileId: 'export-42', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 4, timestampMs: 1300 })

  const entries = [ctrl, issue, replayWithHeader, replayWithReqBody]
  const factLog = HostFactLog.fromTranscript({ entries })

  // 1. Extra worker `x-scope` header on identical signed URL -> rejected via registry
  const hdrRes = defaultTerminalOracleRegistry.evaluate(factLog, {
    kind: 'v8_family',
    family: 'cryptographic_scope_replay',
    rawInput: {
      tamperedSignatureControl: 'csr-ctrl',
      sourceValidIssuance: 'csr-issue',
      replayedAcceptance: 'csr-replay-hdr',
      sourceTenant: 'org-a',
      sourceScope: 'org-a:read',
      targetTenant: 'org-b',
      targetScope: 'org-b:admin',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(hdrRes.confirmed, false, 'worker-added x-scope header must not fabricate cross-scope replay')
  assert.equal(hdrRes.reason, 'same_tenant_and_scope_not_replay')

  // 2. Worker-added `scope` and `tenantId` in requestJson -> rejected via registry
  const bodyRes = defaultTerminalOracleRegistry.evaluate(factLog, {
    kind: 'v8_family',
    family: 'cryptographic_scope_replay',
    rawInput: {
      tamperedSignatureControl: 'csr-ctrl',
      sourceValidIssuance: 'csr-issue',
      replayedAcceptance: 'csr-replay-body',
      targetTenant: 'org-b',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(bodyRes.confirmed, false, 'requestJson scope/tenantId must not fabricate cross-scope replay')
  assert.equal(bodyRes.reason, 'same_tenant_and_scope_not_replay')

  // 3. One-hop composite receipt citing the identical signed URL + x-scope header -> rejected
  const compRes = verifyCompositeReceipt({
    chainId: 'r3-c5-csr-hdr-forge',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [{
      hopId: 'h1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/downloads/export-42?sig=valid-sig-001' },
      exchangeIds: ['csr-issue', 'csr-replay-hdr'],
      oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Fetched same signed URL twice with custom x-scope header.',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'h1',
      terminalExchangeId: 'csr-replay-hdr',
      summary: 'Attempted to forge cryptographic scope replay using worker x-scope header.',
      preChainControlExchangeIds: ['csr-ctrl'],
      postChainReadbackExchangeIds: [],
      oracleFamily: 'cryptographic_scope_replay',
      oracleInput: {
        tamperedSignatureControl: 'csr-ctrl',
        sourceValidIssuance: 'csr-issue',
        replayedAcceptance: 'csr-replay-hdr',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(compRes.confirmed, false)
  assert.match(compRes.reason, /same_tenant_and_scope_not_replay/)

  // 4. Direct evaluator defense-in-depth: identical host-attested records differing only in x-scope header -> rejected
  const mkRec = (id: string, ts: number, status: number, extra: Partial<HostSignedRecord> = {}): HostSignedRecord => ({
    id, hostSignature: `hmac-sha256:${id}:deadbeef`, timestampMs: ts, status,
    method: 'GET', route: '/api/v1/downloads/export-42', actorId: 'member_a', tenantId: 'org-a',
    ...extra,
  })
  const directRes = evaluateCryptographicScopeReplay({
    tamperedSignatureControl: mkRec('d-ctl', 1000, 403, { json: { error: 'bad_sig' } }),
    sourceValidIssuance: mkRec('d-iss', 1100, 200, { json: { rows: [{ id: 'r1', amount: 500 }] } }),
    replayedAcceptance: mkRec('d-rep', 1200, 200, {
      requestHeaders: { 'x-scope': 'admin:all' },
      json: { rows: [{ id: 'r1', amount: 500 }] },
    }),
    sourceTenant: 'org-a',
    sourceScope: 'org-a:read',
    targetTenant: 'org-b',
    targetScope: 'org-b:admin',
    tamperedSignatureDigest: sha256Hex('bad'),
    signatureDigest: sha256Hex('good'),
    replayedSignatureDigest: sha256Hex('good'),
  })
  assert.equal(directRes.satisfied, false)
  assert.equal(directRes.reason, 'same_tenant_and_scope_not_replay')
})

test('R3-C-5(a) + R4-C-5: genuine cross-tenant/cross-resource replay confirms while caller-only and route-only bearer flows MUST reject', () => {
  // 1. Genuine cross-tenant + cross-resource signed-URL replay (org-a/report sig replayed on org-b/treasury) -> confirms
  const ctrl = signedEntry('csr-ok-ctrl', makeStep({
    id: 'csr-ok-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/exports/org-b/treasury?sig=bad-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  const issue = signedEntry('csr-ok-issue', makeStep({
    id: 'csr-ok-issue', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/exports/org-a/sign',
    json: { tenantId: 'org-a', signedUrl: 'https://api.example.test/api/v1/exports/org-a/report?sig=valid-sig-002' },
  }), { seq: 2, timestampMs: 1100 })
  const replay = signedEntry('csr-ok-replay', makeStep({
    id: 'csr-ok-replay', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/exports/org-b/treasury?sig=valid-sig-002',
    json: { tenantId: 'org-b', ledgerBalance: 985000, records: [{ id: 'tr-1', amount: 985000 }] },
  }), { seq: 3, timestampMs: 1200 })

  const crossTenantRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, issue, replay] }),
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'csr-ok-ctrl',
        sourceValidIssuance: 'csr-ok-issue',
        replayedAcceptance: 'csr-ok-replay',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(crossTenantRes.confirmed, true, crossTenantRes.reason)

  // 2. R4-C-5 FLIPPED: cross-persona fetch of a byte-identical signed bearer URL MUST reject (caller-only difference)
  const ctrlP = signedEntry('csr-p-ctrl', makeStep({
    id: 'csr-p-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/shared?sig=bad-sig',
    actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_b' })
  const issP = signedEntry('csr-p-iss', makeStep({
    id: 'csr-p-iss', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/shared?sig=valid-sig-003',
    actor: { handle: 'member_a', role: 'member', tenant: 'org-a', auth: 'bearer', sameSite: null },
    json: { records: [{ id: 'doc-1', amount: 1200 }] },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'member_a' })
  const repP = signedEntry('csr-p-rep', makeStep({
    id: 'csr-p-rep', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/shared?sig=valid-sig-003',
    actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
    json: { records: [{ id: 'doc-1', amount: 1200 }] },
  }), { seq: 3, timestampMs: 1200, actorPersona: 'member_b' })

  const crossPersonaRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlP, issP, repP] }),
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'csr-p-ctrl',
        sourceValidIssuance: 'csr-p-iss',
        replayedAcceptance: 'csr-p-rep',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(crossPersonaRes.confirmed, false, 'byte-identical bearer signed URL across personas must not confirm replay')
  assert.equal(crossPersonaRes.reason, 'same_principal_not_replay')

  // 3. R4-C-5 FLIPPED: route-only mint (/share) -> download (/download) for the same signed resource MUST reject
  const ctrlR = signedEntry('csr-r-ctrl', makeStep({
    id: 'csr-r-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-42?sig=bad-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  const issR = signedEntry('csr-r-iss', makeStep({
    id: 'csr-r-iss', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/exports/share',
    json: { signedUrl: 'https://api.example.test/api/v1/downloads/export-42?exp=1700000900&sig=valid-sig-004' },
  }), { seq: 2, timestampMs: 1100 })
  const repR = signedEntry('csr-r-rep', makeStep({
    id: 'csr-r-rep', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-42?exp=1700000900&sig=valid-sig-004',
    json: { fileId: 'export-42', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 3, timestampMs: 1200 })

  const crossRouteRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlR, issR, repR] }),
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'csr-r-ctrl',
        sourceValidIssuance: 'csr-r-iss',
        replayedAcceptance: 'csr-r-rep',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(crossRouteRes.confirmed, false, 'single-persona mint-to-download route difference must not confirm replay')
  assert.equal(crossRouteRes.reason, 'same_principal_not_replay')
})

// ============================================================================
// (b) batch_partial_authz: no request-body tenant & no echoed-denial false positive
// ============================================================================

test('R3-C-5(b): echoed foreign ID in denied/errors/forbidden and worker request-body tenant MUST reject', () => {
  const ctrl = signedEntry('bpa-ctrl', makeStep({
    id: 'bpa-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/secrets/sec_foreign_2',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })

  // Attack 1: worker puts tenantId in batch requestJson + server echoes foreign ID inside `denied` array
  const batchDenied = signedEntry('bpa-denied', makeStep({
    id: 'bpa-denied', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/secrets/batch',
    requestJson: { ids: ['sec_own_1', 'sec_foreign_2'], tenantId: 'org-victim' },
    json: {
      items: [{ id: 'sec_own_1', value: 'own-secret-val' }],
      denied: [{ id: 'sec_foreign_2', tenantId: 'org-victim', reason: 'forbidden' }],
    },
  }), { seq: 2, timestampMs: 1100 })

  // Attack 2: echoed foreign ID inside `errors` array even when host knows `org-victim` via another persona
  const victimPersonaEntry = signedEntry('bpa-other-persona', makeStep({
    id: 'bpa-other-persona', arm: 'setup', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/me',
    actor: { handle: 'member_b', role: 'member', tenant: 'org-victim', auth: 'bearer', sameSite: null },
    json: { ok: true },
  }), { seq: 0, timestampMs: 900, actorPersona: 'member_b', actorRoleLabel: 'member (org-victim)' })

  const batchErrors = signedEntry('bpa-errors', makeStep({
    id: 'bpa-errors', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/secrets/batch',
    requestJson: { ids: ['sec_own_1', 'sec_foreign_2'], tenantId: 'org-victim' },
    json: {
      items: [{ id: 'sec_own_1', value: 'own-secret-val' }],
      errors: [{ id: 'sec_foreign_2', code: 403, message: 'Access denied' }],
    },
  }), { seq: 3, timestampMs: 1200 })

  // Attack 3: per-item error object inside `results` (`ok: false` / `status: 403`)
  const batchPerItemErr = signedEntry('bpa-item-err', makeStep({
    id: 'bpa-item-err', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/secrets/batch',
    requestJson: { ids: ['sec_own_1', 'sec_foreign_2'] },
    json: {
      results: [
        { id: 'sec_own_1', ok: true, value: 'own-secret-val' },
        { id: 'sec_foreign_2', ok: false, status: 403, error: 'forbidden', detail: 'nope' },
      ],
    },
  }), { seq: 4, timestampMs: 1300 })

  // Attack 4: returned non-error item WITHOUT response tenant AND WITHOUT host-known foreign tenant (only requestJson)
  const batchUnknownTenant = signedEntry('bpa-unknown-tenant', makeStep({
    id: 'bpa-unknown-tenant', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/secrets/batch',
    requestJson: { ids: ['sec_own_1', 'sec_foreign_2'], tenantId: 'org-invented' },
    json: {
      items: [
        { id: 'sec_own_1', value: 'own-secret-val' },
        { id: 'sec_foreign_2', value: 'some-data' },
      ],
    },
  }), { seq: 5, timestampMs: 1400 })

  const hyd1 = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'batch_partial_authz',
    ownRecordId: 'sec_own_1',
    foreignRecordId: 'sec_foreign_2',
    requestedIds: ['sec_own_1', 'sec_foreign_2'],
    foreignTenantId: 'org-victim',
    singleForeignControlDenied: 'bpa-ctrl',
    batchRequest: 'bpa-denied',
  }, idxOf([ctrl, batchDenied]), 'sig')
  assert.equal(hyd1.foreignTenantId, undefined, 'request-body and denied-subtree tenant must not become foreignTenantId')
  assert.deepEqual(hyd1.returnedForeignIds, [])
  assert.equal(hyd1.foreignDataObserved, false)

  const res1 = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, batchDenied] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: {
        mode: 'batch_partial_authz',
        ownRecordId: 'sec_own_1', foreignRecordId: 'sec_foreign_2',
        requestedIds: ['sec_own_1', 'sec_foreign_2'],
        foreignTenantId: 'org-victim',
        singleForeignControlDenied: 'bpa-ctrl', batchRequest: 'bpa-denied',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(res1.confirmed, false)

  // Even with host-known `org-victim`, `errors` and per-item `ok: false` must reject
  for (const [label, batchEx] of [
    ['errors-list', batchErrors],
    ['per-item-error', batchPerItemErr],
  ] as const) {
    const res = defaultTerminalOracleRegistry.evaluate(
      HostFactLog.fromTranscript({ entries: [victimPersonaEntry, ctrl, batchEx] }),
      {
        kind: 'v8_family', family: 'dual_tenant_abac',
        rawInput: {
          mode: 'batch_partial_authz',
          ownRecordId: 'sec_own_1', foreignRecordId: 'sec_foreign_2',
          requestedIds: ['sec_own_1', 'sec_foreign_2'],
          foreignTenantId: 'org-victim',
          singleForeignControlDenied: 'bpa-ctrl', batchRequest: batchEx.exchangeId,
        },
      },
      { signingKey: SIGNING_KEY },
    )
    assert.equal(res.confirmed, false, `${label} must reject`)
    assert.equal(res.reason, 'foreign_record_not_returned_or_mutated')
  }

  // Worker-invented tenant only in requestJson must reject with missing_tenant_scope
  const resUnknown = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, batchUnknownTenant] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: {
        mode: 'batch_partial_authz',
        ownRecordId: 'sec_own_1', foreignRecordId: 'sec_foreign_2',
        requestedIds: ['sec_own_1', 'sec_foreign_2'],
        foreignTenantId: 'org-invented',
        singleForeignControlDenied: 'bpa-ctrl', batchRequest: 'bpa-unknown-tenant',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(resUnknown.confirmed, false)
  assert.equal(resUnknown.reason, 'missing_tenant_scope')

  // Direct evaluator defense-in-depth against echoed denial list
  const directErr = evaluateDualTenantAbac({
    mode: 'batch_partial_authz',
    actor: { actorId: 'member_a', rolesByTenant: { 'org-a': 'member' } },
    ownTenantId: 'org-a',
    foreignTenantId: 'org-b',
    ownRecordId: 'sec_own_1',
    foreignRecordId: 'sec_foreign_2',
    requestedIds: ['sec_own_1', 'sec_foreign_2'],
    singleForeignControlDenied: { id: 'c1', hostSignature: 'hmac-sha256:c1:deadbeef', timestampMs: 1000, status: 403 },
    batchRequest: {
      id: 'b1', hostSignature: 'hmac-sha256:b1:deadbeef', timestampMs: 1100, status: 200, method: 'POST',
      json: { items: [{ id: 'sec_own_1', val: 'a' }], forbidden: [{ id: 'sec_foreign_2', reason: 'denied' }] },
    },
    returnedForeignIds: ['sec_foreign_2'],
    foreignDataObserved: true,
  })
  assert.equal(directErr.satisfied, false)
  assert.equal(directErr.reason, 'foreign_record_not_returned_or_mutated')
})

test('R3-C-5(b): genuine batch_partial_authz with host-known tenant and non-error foreign item confirms cleanly', () => {
  const ctrl = signedEntry('bpa-ok-ctrl', makeStep({
    id: 'bpa-ok-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/secrets/sec_foreign_2',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })

  const batchOk = signedEntry('bpa-ok-req', makeStep({
    id: 'bpa-ok-req', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/secrets/batch',
    requestJson: { ids: ['sec_own_1', 'sec_foreign_2'] },
    json: {
      processed: [
        { id: 'sec_own_1', tenantId: 'org-a', value: 'own-val' },
        { id: 'sec_foreign_2', tenantId: 'org-b', value: 'victim-signing-key-999' },
      ],
    },
  }), { seq: 2, timestampMs: 1100 })

  const res = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, batchOk] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: {
        mode: 'batch_partial_authz',
        ownRecordId: 'sec_own_1', foreignRecordId: 'sec_foreign_2',
        requestedIds: ['sec_own_1', 'sec_foreign_2'],
        singleForeignControlDenied: 'bpa-ok-ctrl', batchRequest: 'bpa-ok-req',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(res.confirmed, true, res.reason)
})

// ============================================================================
// (c) dual_org_cache_bleed: tenant IDs strictly from host/response, never request body
// ============================================================================

test('R3-C-5(c): dual_org_cache_bleed with tenant IDs only in bled-access request body MUST reject', () => {
  const dualActor = { handle: 'dual_member', role: 'admin' as const, tenant: 'org-a', auth: 'bearer' as const, sameSite: null }
  const roleLabel = 'admin (org-a), viewer (org-b)'

  const ctrl = signedEntry('cb-ctrl', makeStep({
    id: 'cb-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/reports/export',
    actor: dualActor,
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: roleLabel })

  const prime = signedEntry('cb-prime', makeStep({
    id: 'cb-prime', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/permissions/prime',
    actor: dualActor,
    json: { primed: true, tenantId: 'org-a' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: roleLabel })

  // Request body carries tenantId: 'org-b', but response has NO target tenant ownership marker
  const bledReqOnly = signedEntry('cb-bled-req', makeStep({
    id: 'cb-bled-req', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/reports/export',
    actor: dualActor,
    requestJson: { tenantId: 'org-b', orgId: 'org-b' },
    json: { rows: [{ id: 'r-1', total: 4200 }] },
  }), { seq: 3, timestampMs: 1200, actorPersona: 'dual_member', actorRoleLabel: roleLabel })

  const hyd = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    targetTenantId: 'org-b',
    observedTenantId: 'org-b',
    baselineDeniedControl: 'cb-ctrl',
    primeAction: 'cb-prime',
    bledAccess: 'cb-bled-req',
  }, idxOf([ctrl, prime, bledReqOnly]), 'sig')
  assert.equal(hyd.targetTenantId, undefined, 'targetTenantId must never come from bled-access request body')
  assert.equal(hyd.observedTenantId, undefined, 'observedTenantId must never come from bled-access request body')

  const reqOnlyRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, prime, bledReqOnly] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: {
        mode: 'dual_org_cache_bleed',
        targetTenantId: 'org-b',
        observedTenantId: 'org-b',
        baselineDeniedControl: 'cb-ctrl',
        primeAction: 'cb-prime',
        bledAccess: 'cb-bled-req',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(reqOnlyRes.confirmed, false)
  assert.equal(reqOnlyRes.reason, 'missing_tenant_scope')

  // Positive control: genuine response-side ownership marker confirms cleanly
  const bledReal = signedEntry('cb-bled-real', makeStep({
    id: 'cb-bled-real', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/reports/export',
    actor: dualActor,
    json: { tenantId: 'org-b', rows: [{ id: 'r-99', total: 985000 }] },
  }), { seq: 4, timestampMs: 1300, actorPersona: 'dual_member', actorRoleLabel: roleLabel })

  const realRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, prime, bledReal] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: {
        mode: 'dual_org_cache_bleed',
        baselineDeniedControl: 'cb-ctrl',
        primeAction: 'cb-prime',
        bledAccess: 'cb-bled-real',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(realRes.confirmed, true, realRes.reason)
})
