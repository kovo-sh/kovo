/**
 * Option 2 Move 1 — HostFactLog + Unified TerminalOracleRegistry Verification Tests
 *
 * Defensive QA verification covering:
 *  1. HostFactLog dual-plane immutability (scrubbing worker views via EgressSanitizer never
 *     mutates stored pre-redaction host facts; TranscriptStore exposes no in-place rescrubBodies).
 *  2. Deterministic host `seq` ordering (worker-supplied ID order never reorders custody facts).
 *  3. Unified TerminalOracleRegistry dispatch across single-hop ProofReceipt rules (including
 *     1-hop CompositeProofReceipt custody boundary + form/xml boolean differentials) AND all 6
 *     v8 multi-hop oracle families.
 *  4. Fail-closed floor-recipe-engine behavior when a ProofReceipt cannot be constructed in
 *     strict mode, plus strict-default proofReceiptMode parity and oracle-invariants fixes.
 *  5. Property-based mutation tests proving mutating untrusted worker-supplied claim scalars
 *     (`requiredRole`, `resourceTenant`, `requestBody`, `ambient`, `unitDebit`, `oracleEvents`)
 *     NEVER flips an oracle verdict.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import { createEgressSanitizer } from '../src/server/egress-sanitizer.ts'
import {
  proofReceiptMode as floorProofReceiptMode,
  receiptCheckForResult,
} from '../src/server/floor-recipe-engine.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import {
  assessBusinessLogicImpact,
  classifyImpactDescriptor,
} from '../src/server/oracle-invariants.ts'
import {
  buildAgentScriptReceipt,
  buildProofReceipt,
  proofReceiptMode as canonicalProofReceiptMode,
  type ScriptProofExchange,
} from '../src/server/proof-receipt.ts'
import {
  REGISTERED_V8_ORACLE_FAMILIES,
  SINGLE_HOP_ORACLE_RULES,
  TerminalOracleRegistry,
  defaultTerminalOracleRegistry,
} from '../src/server/terminal-oracle-registry.ts'
import { TranscriptStore, evaluateClaims } from '../src/server/verify-claims.ts'
import { signHostRecord, type HostTranscriptEntry } from '../src/server/composite-receipt.ts'

const ORIGIN = 'https://app.example.invalid'
const SIGNING_KEY = 'host-fact-log-test-signing-key-32b'
const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

// ============================================================================
// 1. HostFactLog immutability & worker-view scrubbing isolation
// ============================================================================

test('HostFactLog: buildWorkerView scrubs secrets via EgressSanitizer without mutating immutable host facts', () => {
  const vault = new DerivedCapabilityVault({ runId: 'run-immut-test' })
  const sealedSecret = 'kovo_derived_secret_token_9876543210'
  const meta = vault.seal({
    rawValue: sealedSecret,
    kind: 'bearer_token',
    hopReceiptId: 'hop_1',
    slot: 'tok',
    allowedOrigins: [ORIGIN],
  })
  const sanitizer = createEgressSanitizer({
    secrets: [{ value: 'vault_persona_secret_abc123', placeholder: '[persona:alice]' }],
    capabilityVaults: [vault],
  })

  const factLog = new HostFactLog({ sanitizer })
  const rawReqBody = JSON.stringify({ token: sealedSecret, action: 'transfer', amount: 25 })
  const rawRespBody = JSON.stringify({
    issued: sealedSecret,
    echo: 'vault_persona_secret_abc123',
    balance: 100,
  })
  const stored = factLog.recordExchange({
    exchangeId: 'ex-1',
    op: 'http',
    method: 'POST',
    origin: ORIGIN,
    pathAndQuery: '/api/v1/transfer',
    status: 200,
    requestHeaders: {
      authorization: 'Bearer vault_persona_secret_abc123',
      cookie: 'sid=cookie_secret_999',
      'content-type': 'application/json',
    },
    rawRequestBody: rawReqBody,
    responseHeaders: {
      'set-cookie': 'sid=cookie_secret_999; HttpOnly; SameSite=Strict',
      'content-type': 'application/json',
    },
    rawResponseBody: rawRespBody,
    actor: 'alice',
    actorRoleLabel: 'member (acme)',
    durationMs: 42,
  })

  // Immutability check: stored fact & header maps are frozen.
  assert.equal(Object.isFrozen(stored), true)
  assert.equal(Object.isFrozen(stored.requestHeaders), true)
  assert.equal(Object.isFrozen(stored.responseHeaders), true)
  assert.throws(() => {
    ;(stored as { rawResponseBody: string | null }).rawResponseBody = 'tampered'
  }, TypeError)

  // Plane 2 worker view redacts sensitive headers and secret values.
  const workerView = factLog.buildWorkerView('ex-1')
  assert.ok(workerView)
  assert.equal(workerView.requestHeaders.authorization, '[redacted]')
  assert.equal(workerView.requestHeaders.cookie, '[redacted]')
  assert.equal(workerView.responseHeaders['set-cookie'], '[redacted]')
  assert.ok(!workerView.requestBody!.includes(sealedSecret), 'sealed secret must be scrubbed from worker request view')
  assert.ok(!workerView.responseBody!.includes(sealedSecret), 'sealed secret must be scrubbed from worker response view')
  assert.ok(!workerView.responseBody!.includes('vault_persona_secret_abc123'), 'vault secret must be scrubbed from worker response view')
  assert.ok(workerView.responseBody!.includes(meta.handle), 'derived secret should be masked with its opaque handle')

  // Plane 1 host fact remains completely untouched after worker view generation.
  const after = factLog.getExchange('ex-1')!
  assert.equal(after.rawRequestBody, rawReqBody)
  assert.equal(after.rawResponseBody, rawRespBody)
  assert.equal(after.requestHeaders.authorization, 'Bearer vault_persona_secret_abc123')
  assert.equal(after.responseHeaders['set-cookie'], 'sid=cookie_secret_999; HttpOnly; SameSite=Strict')
  assert.equal(after.ambientAuth, 'bearer')
  assert.equal(after.sameSite, 'Strict')
  assert.equal(after.actorRole, 'member')
  assert.equal(after.actorTenant, 'acme')

  // TranscriptStore no longer exposes in-place body mutation via rescrubBodies().
  const store = new TranscriptStore()
  assert.equal('rescrubBodies' in store, false, 'TranscriptStore must not expose mutating rescrubBodies()')
})

// ============================================================================
// 2. Host seq ordering (never trusting worker-supplied exchange ID order)
// ============================================================================

test('HostFactLog: orderedExchanges always sorts strictly by host monotonic seq', () => {
  const factLog = new HostFactLog()
  factLog.recordExchange({ seq: 10, exchangeId: 'ex-pre', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/wallet', status: 200, rawResponseBody: '{"balance":100}', durationMs: 10 })
  factLog.recordExchange({ seq: 20, exchangeId: 'ex-b1', method: 'POST', origin: ORIGIN, pathAndQuery: '/api/wallet/debit', status: 200, rawRequestBody: '{"amount":10}', rawResponseBody: '{"ok":true}', durationMs: 60, startedAt: 1050, endedAt: 1110 })
  factLog.recordExchange({ seq: 30, exchangeId: 'ex-b2', method: 'POST', origin: ORIGIN, pathAndQuery: '/api/wallet/debit', status: 200, rawRequestBody: '{"amount":10}', rawResponseBody: '{"ok":true}', durationMs: 65, startedAt: 1052, endedAt: 1117 })
  factLog.recordExchange({ seq: 40, exchangeId: 'ex-post', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/wallet', status: 200, rawResponseBody: '{"balance":90}', durationMs: 10 })

  const scrambled = ['ex-post', 'ex-b2', 'ex-pre', 'ex-b1', 'ex-b2']
  const ordered = factLog.orderedExchanges(scrambled)
  assert.deepEqual(
    ordered.map(f => f.exchangeId),
    ['ex-pre', 'ex-b1', 'ex-b2', 'ex-post'],
  )
})

// ============================================================================
// 3. TerminalOracleRegistry: single-hop + all 6 v8 oracle families
// ============================================================================

test('TerminalOracleRegistry: dispatches single-hop ProofReceipt rules (incl. 1-hop Composite envelope & form/xml boolean) and all 6 v8 oracle families', () => {
  const registry = new TerminalOracleRegistry()
  assert.deepEqual(new Set(registry.listRegisteredRules()), new Set(SINGLE_HOP_ORACLE_RULES))
  assert.deepEqual(new Set(registry.listRegisteredV8Families()), new Set(REGISTERED_V8_ORACLE_FAMILIES))

  // 3a. Single-hop form-encoded boolean differential via HostFactLog + TerminalOracleRegistry
  const formLog = new HostFactLog()
  const formTrue = 'q=1%27+AND+7919%3D7919--+-'
  const formFalse = 'q=1%27+AND+7919%3D7920--+-'
  formLog.recordExchange({ seq: 1, exchangeId: 'c1', arm: 'control', method: 'POST', origin: ORIGIN, pathAndQuery: '/bool-form', status: 200, requestHeaders: { 'content-type': 'application/x-www-form-urlencoded' }, rawRequestBody: formTrue, rawResponseBody: '{"rows":["a","b","c"]}' })
  formLog.recordExchange({ seq: 2, exchangeId: 'p1', arm: 'probe', method: 'POST', origin: ORIGIN, pathAndQuery: '/bool-form', status: 200, requestHeaders: { 'content-type': 'application/x-www-form-urlencoded' }, rawRequestBody: formFalse, rawResponseBody: '{"rows":[]}' })
  formLog.recordExchange({ seq: 3, exchangeId: 'c2', arm: 'control', method: 'POST', origin: ORIGIN, pathAndQuery: '/bool-form', status: 200, requestHeaders: { 'content-type': 'application/x-www-form-urlencoded' }, rawRequestBody: formTrue, rawResponseBody: '{"rows":["a","b","c"]}' })
  formLog.recordExchange({ seq: 4, exchangeId: 'p2', arm: 'probe', method: 'POST', origin: ORIGIN, pathAndQuery: '/bool-form', status: 200, requestHeaders: { 'content-type': 'application/x-www-form-urlencoded' }, rawRequestBody: formFalse, rawResponseBody: '{"rows":[]}' })
  const formReceipt = buildProofReceipt({
    vulnClass: 'sqli',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/bool-form', param: 'q' },
    exchangeIds: ['c1', 'p1', 'c2', 'p2'],
    claimedDelta: 'Form-encoded boolean predicate differential reproduced across 2 rounds.',
  })
  const formRes = registry.evaluate(formLog, { kind: 'single_hop', receipt: formReceipt })
  assert.equal(formRes.confirmed, true, formRes.reason)
  assert.equal(formRes.familyOrRule, 'boolean')

  // 3b. Single-hop auth_bypass routed through 1-hop CompositeProofReceipt envelope custody boundary
  const authLog = new HostFactLog()
  authLog.recordExchange({
    seq: 1, exchangeId: 'auth-ctl', arm: 'control', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/v1/admin/settings',
    status: 401, rawResponseBody: '{"error":"unauthorized"}', timestampMs: 1000, cleanSession: true,
  })
  authLog.recordExchange({
    seq: 2, exchangeId: 'auth-prb', arm: 'probe', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/v1/admin/settings',
    status: 200, requestHeaders: { authorization: 'Bearer forged.unsigned.token' },
    rawResponseBody: '{"admin":true,"email":"root@acme.example","apiKeys":["k_live_01"]}', timestampMs: 1100, cleanSession: true,
  })
  const authReceipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/admin/settings' },
    exchangeIds: ['auth-ctl', 'auth-prb'],
    claimedDelta: 'Forged token bypassed protected route returning account records.',
  })
  const authEnvRes = registry.evaluate(authLog, {
    kind: 'single_hop',
    receipt: authReceipt,
    enforceCompositeEnvelope: true,
  })
  assert.equal(authEnvRes.confirmed, true, authEnvRes.reason)
  assert.ok(authEnvRes.composite?.confirmed)

  // 3c. v8 multi-hop oracle families dispatched over the same HostFactLog + TerminalOracleRegistry
  const signedEntry = (raw: Omit<HostTranscriptEntry, 'hostSignature'>): HostTranscriptEntry => ({
    ...raw,
    hostSignature: signHostRecord(raw, SIGNING_KEY),
  })

  // Family 1: dual_tenant_abac (cross_org_transfer)
  const dualLog = HostFactLog.fromTranscript({
    entries: [
      signedEntry({
        exchangeId: 'dt-ctrl', seq: 1, timestampMs: 1000, actorPersona: 'bob', actorRoleLabel: 'member (tenant-a)',
        step: { id: 'dt-ctrl', arm: 'control', method: 'POST', route: '/api/transfer', pathAndQuery: '/api/transfer', status: 403, actor: { handle: 'bob', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, requestJson: { entityId: 'ent-9', destTenant: 'tenant-b' }, body: '{"error":"forbidden"}' },
      }),
      signedEntry({
        exchangeId: 'dt-xfer', seq: 2, timestampMs: 1100, actorPersona: 'bob', actorRoleLabel: 'admin (tenant-b)',
        step: { id: 'dt-xfer', arm: 'probe', method: 'POST', route: '/api/transfer', pathAndQuery: '/api/transfer', status: 200, actor: { handle: 'bob', role: 'admin', tenant: 'tenant-b', auth: 'bearer', sameSite: null }, requestJson: { entityId: 'ent-9', destTenant: 'tenant-b' }, body: '{"transferred":true}' },
      }),
      signedEntry({
        exchangeId: 'dt-rb', seq: 3, timestampMs: 1200, actorPersona: 'bob', actorRoleLabel: 'admin (tenant-b)',
        step: { id: 'dt-rb', arm: 'control', method: 'GET', route: '/api/assets/ent-9', pathAndQuery: '/api/assets/ent-9', status: 200, actor: { handle: 'bob', role: 'admin', tenant: 'tenant-b', auth: 'bearer', sameSite: null }, json: { id: 'ent-9', owner_tenant_id: 'tenant-b', title: 'Payroll Ledger' }, body: '{"id":"ent-9","owner_tenant_id":"tenant-b","title":"Payroll Ledger"}' },
      }),
    ],
  })
  const dualRes = registry.evaluate(
    dualLog,
    {
      kind: 'v8_family',
      family: 'dual_tenant_abac',
      rawInput: {
        mode: 'cross_org_transfer',
        actor: { actorId: 'bob', rolesByTenant: { 'tenant-a': 'member', 'tenant-b': 'admin' } },
        sourceTenantId: 'tenant-a',
        destTenantId: 'tenant-b',
        entityId: 'ent-9',
        sourceControlDenied: 'dt-ctrl',
        transferRecord: 'dt-xfer',
        postTransferReadback: 'dt-rb',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(dualRes.confirmed, true, dualRes.reason)
  assert.equal(dualRes.familyOrRule, 'dual_tenant_abac')

  // Family 2: temporal_revocation
  const revLog = HostFactLog.fromTranscript({
    entries: [
      signedEntry({
        exchangeId: 'rev-ev', seq: 1, timestampMs: 2000, actorPersona: 'alice',
        step: { id: 'rev-ev', arm: 'setup', method: 'POST', route: '/api/tokens/revoke', pathAndQuery: '/api/tokens/revoke', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, body: '{"revoked":true}' },
      }),
      signedEntry({
        exchangeId: 'rev-pri', seq: 2, timestampMs: 2100, actorPersona: 'alice', consumedCapabilities: ['cap:hop_1:pat'],
        step: { id: 'rev-pri', arm: 'control', method: 'GET', route: '/api/v1/profile', pathAndQuery: '/api/v1/profile', status: 401, actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, body: '{"error":"revoked"}' },
      }),
      signedEntry({
        exchangeId: 'rev-sec', seq: 3, timestampMs: 2200, actorPersona: 'alice', consumedCapabilities: ['cap:hop_1:pat'],
        step: { id: 'rev-sec', arm: 'probe', method: 'POST', route: '/graphql', pathAndQuery: '/graphql', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, json: { data: { me: { email: 'alice@acme.example', ssnLast4: '4321' } } }, body: '{"data":{"me":{"email":"alice@acme.example","ssnLast4":"4321"}}}' },
      }),
    ],
  })
  const revRes = registry.evaluate(
    revLog,
    {
      kind: 'v8_family',
      family: 'temporal_revocation',
      rawInput: {
        credentialKind: 'pat',
        credentialHandle: 'cap:hop_1:pat',
        actorId: 'alice',
        primarySurface: 'http',
        secondarySurface: 'graphql',
        revocationEvent: 'rev-ev',
        primaryDeniedCheck: 'rev-pri',
        secondarySuccess: 'rev-sec',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(revRes.confirmed, true, revRes.reason)

  // Family 3: economic_conservation (balance_minting)
  const econLog = HostFactLog.fromTranscript({
    entries: [
      signedEntry({
        exchangeId: 'ec-pre', seq: 1, timestampMs: 3000, actorPersona: 'alice',
        step: { id: 'ec-pre', arm: 'setup', method: 'GET', route: '/api/ledger', pathAndQuery: '/api/ledger', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, json: { balances: { a: 100, b: 100 } }, body: '{"balances":{"a":100,"b":100}}' },
      }),
      signedEntry({
        exchangeId: 'ec-act', seq: 2, timestampMs: 3100, actorPersona: 'alice',
        step: { id: 'ec-act', arm: 'probe', method: 'POST', route: '/api/ledger/transfer', pathAndQuery: '/api/ledger/transfer', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, requestJson: { from: 'a', to: 'b', amount: 50 }, body: '{"ok":true}' },
      }),
      signedEntry({
        exchangeId: 'ec-post', seq: 3, timestampMs: 3200, actorPersona: 'alice',
        step: { id: 'ec-post', arm: 'control', method: 'GET', route: '/api/ledger', pathAndQuery: '/api/ledger', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, json: { balances: { a: 100, b: 150 } }, body: '{"balances":{"a":100,"b":150}}' },
      }),
    ],
  })
  const econRes = registry.evaluate(
    econLog,
    {
      kind: 'v8_family',
      family: 'economic_conservation',
      rawInput: {
        equation: 'balance_minting',
        baselineReadback: 'ec-pre',
        actions: ['ec-act'],
        finalReadback: 'ec-post',
        authorizedDeposits: 0,
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(econRes.confirmed, true, econRes.reason)

  // Family 4: cryptographic_scope_replay
  const validSigDigest = sha256('valid-hmac-sig-tenant-a')
  const tamperedSigDigest = sha256('tampered-hmac-sig')
  const cryptoLog = HostFactLog.fromTranscript({
    entries: [
      signedEntry({
        exchangeId: 'cr-tamp', seq: 1, timestampMs: 4000, observedResponseDigests: [tamperedSigDigest],
        step: { id: 'cr-tamp', arm: 'control', method: 'POST', route: '/api/webhooks/ingest', pathAndQuery: '/api/webhooks/ingest', status: 401, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, requestHeaders: { 'x-signature': 'tampered-hmac-sig' }, body: '{"error":"invalid_sig"}' },
      }),
      signedEntry({
        exchangeId: 'cr-iss', seq: 2, timestampMs: 4100, emittedCapabilities: ['cap:hop_1:sig'], observedResponseDigests: [validSigDigest],
        step: { id: 'cr-iss', arm: 'probe', method: 'POST', route: '/api/webhooks/sign', pathAndQuery: '/api/webhooks/sign', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, body: '{"signed":true}' },
      }),
      signedEntry({
        exchangeId: 'cr-rep', seq: 3, timestampMs: 4200, cryptoAttestations: [{ derivedFromCapabilityId: 'cap:hop_1:sig', alg: 'hmac-sha256', artifactDigest: validSigDigest, timestampMs: 4150 }],
        step: { id: 'cr-rep', arm: 'probe', method: 'POST', route: '/api/webhooks/ingest', pathAndQuery: '/api/webhooks/ingest', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, requestHeaders: { 'x-signature': 'valid-hmac-sig-tenant-a' }, json: { tenantId: 'tenant-b', invoicePaid: true, amountCents: 9900 }, body: '{"tenantId":"tenant-b","invoicePaid":true,"amountCents":9900}' },
      }),
    ],
  })
  const cryptoRes = registry.evaluate(
    cryptoLog,
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'cr-tamp',
        sourceValidIssuance: 'cr-iss',
        replayedAcceptance: 'cr-rep',
        sourceTenant: 'tenant-a',
        sourceScope: 'tenant-a:webhook',
        targetTenant: 'tenant-b',
        targetScope: 'tenant-b:webhook',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(cryptoRes.confirmed, true, cryptoRes.reason)

  // Family 5: parser_cache_differential
  const parserLog = HostFactLog.fromTranscript({
    entries: [
      signedEntry({
        exchangeId: 'pd-ctl', seq: 1, timestampMs: 5000, observedResponseDigests: [sha256('{"error":"denied"}')],
        step: { id: 'pd-ctl', arm: 'control', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 403, actor: { handle: 'alice', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, requestHeaders: { 'content-type': 'application/json' }, requestJson: '{"tenantId":"tenant-b"}', body: '{"error":"denied"}' },
      }),
      signedEntry({
        exchangeId: 'pd-prb', seq: 2, timestampMs: 5100, observedResponseDigests: [sha256('{"records":[{"tenant":"tenant-b","amount":4200}]}')],
        step: { id: 'pd-prb', arm: 'probe', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 200, actor: { handle: 'alice', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, requestHeaders: { 'content-type': 'application/json' }, requestJson: '{"tenantId":"tenant-a","tenantId":"tenant-b"}', json: { records: [{ tenant: 'tenant-b', amount: 4200 }] }, body: '{"records":[{"tenant":"tenant-b","amount":4200}]}' },
      }),
    ],
  })
  const parserRes = registry.evaluate(
    parserLog,
    {
      kind: 'v8_family',
      family: 'parser_cache_differential',
      rawInput: {
        mode: 'parser_differential',
        differentialKind: 'duplicate_json_key',
        differentialFeature: 'duplicate tenantId key',
        canonicalValue: '{"tenantId":"tenant-b"}',
        variantValue: '{"tenantId":"tenant-a","tenantId":"tenant-b"}',
        impactKind: 'read',
        cleanControl: 'pd-ctl',
        differentialProbe: 'pd-prb',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(parserRes.confirmed, true, parserRes.reason)

  // Family 6: cross_surface_pivot (hardened fail-closed rejection when unsigned / missing pivot hops)
  const pivotFail = registry.evaluate(
    parserLog,
    {
      kind: 'v8_family',
      family: 'cross_surface_pivot',
      rawInput: {},
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(pivotFail.confirmed, false, 'empty cross_surface_pivot must fail closed')
  assert.equal(pivotFail.familyOrRule, 'cross_surface_pivot')
})

// ============================================================================
// 4. Fail-closed floor-recipe-engine & oracle-invariants regressions
// ============================================================================

test('floor-recipe-engine: fails closed when strict receipt cannot be built, uses strict default proofReceiptMode, and fixes open_redirect / oracleDeclared', () => {
  // Single strict-default proofReceiptMode (no stale shadow duplicate in floor-recipe-engine.ts)
  assert.equal(floorProofReceiptMode, canonicalProofReceiptMode)
  assert.equal(floorProofReceiptMode({} as NodeJS.ProcessEnv), 'strict')

  const unmodeledSpec = {
    version: 1,
    kind: 'http_chain',
    origin: ORIGIN,
    title: 'Unmodeled posture check',
    category: 'posture-note',
    cwe: 'CWE-693',
    severity: 'low',
    severityRationale: 'test',
    impact: 'Minimal.',
    remediation: 'None.',
    recheckInstructions: 'None.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    steps: [
      { id: 'c1', role: 'control', description: 'c1', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/health' } },
      { id: 'p1', role: 'probe', description: 'p1', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/health' } },
    ],
  } as unknown as DeclarativeReplaySpec

  // Strict mode MUST fail closed when buildReplayReceipt returns null!
  const strictFailClosed = receiptCheckForResult({
    mode: 'strict',
    verdict: 'confirmed',
    outcome: { confirmed: true, controlPassed: true, observed: 'ok', expected: 'ok' },
    spec: unmodeledSpec,
    evidencePayload: { steps: { c1: { id: 'c1', role: 'control', status: 200 }, p1: { id: 'p1', role: 'probe', status: 200 } } },
    exchangeIds: ['ex-1', 'ex-2'],
    exchanges: [],
  })
  assert.equal(strictFailClosed.verdict, 'inconclusive', 'strict mode must fail closed when receipt cannot be built')
  assert.equal(strictFailClosed.outcome.confirmed, false)
  assert.match(strictFailClosed.outcome.reason ?? '', /fail-closed/i)

  // Shadow mode keeps advisory non-blocking behavior when explicitly opted in
  const shadowMode = receiptCheckForResult({
    mode: 'shadow',
    verdict: 'confirmed',
    outcome: { confirmed: true, controlPassed: true, observed: 'ok', expected: 'ok' },
    spec: unmodeledSpec,
    evidencePayload: { steps: { c1: { id: 'c1', role: 'control', status: 200 }, p1: { id: 'p1', role: 'probe', status: 200 } } },
    exchangeIds: ['ex-1', 'ex-2'],
    exchanges: [],
  })
  assert.equal(shadowMode.verdict, 'confirmed')

  // oracle-invariants: open_redirect (CWE-601) must never be misclassified as disclosure even with "exposure"/"leak" text
  assert.equal(
    classifyImpactDescriptor({
      cwe: 'CWE-601',
      category: 'open-redirect',
      title: 'Open redirect via next parameter',
      impact: 'Exposes users to phishing and token leak.',
    }),
    'other',
  )

  // oracle-invariants: labels.oracleDeclared evaluated before attributability rejection
  const workflowRes = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    oracleEvents: ['workflow_skip'],
    steps: [
      { id: 'r1', arm: 'control', method: 'GET', route: '/api/jobs', status: 200, actor: { handle: 'owner', role: 'owner', tenant: null, auth: 'header', sameSite: null }, json: { items: [{ id: 'j1', status: 'pending' }] } },
      { id: 'p1', arm: 'probe', method: 'POST', route: '/api/jobs/j1/complete', status: 200, actor: { handle: 'owner', role: 'owner', tenant: null, auth: 'header', sameSite: null }, requestJson: {}, json: { ok: true, status: 'done' } },
      { id: 'r2', arm: 'control', method: 'GET', route: '/api/jobs', status: 200, actor: { handle: 'owner', role: 'owner', tenant: null, auth: 'header', sameSite: null }, json: { items: [{ id: 'j1', status: 'done' }] } },
    ],
  })
  assert.equal(workflowRes.satisfied, true, workflowRes.reason)
})

// ============================================================================
// 5. Property-based mutation tests: untrusted worker claim scalars NEVER flip verdicts
// ============================================================================

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6D2B79F5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

test('property-based: mutating untrusted worker claim scalars (requiredRole, resourceTenant, requestBody, ambient, unitDebit, oracleEvents) NEVER flips an oracle verdict', () => {
  const rng = mulberry32(0x5eed2026)
  const pick = <T,>(arr: readonly T[]): T => arr[Math.floor(rng() * arr.length)]!
  const roles = ['viewer', 'member', 'admin', 'owner', undefined] as const
  const tenants = ['acme', 'globex', 'initech', 'other-org', 'victim-tenant', undefined] as const
  const ambients = [
    { kind: 'cookie', sameSite: 'None' },
    { kind: 'cookie', sameSite: 'Lax' },
    { kind: 'bearer', sameSite: 'Strict' },
    { kind: 'header', sameSite: null },
    undefined,
  ] as const
  const spoofBodies = [
    { role: 'admin', is_admin: true, owner_id: 'victim', tenant_id: 'globex', amount: 9999 },
    { email: 'spoofed@evil.invalid', balance: 0, seats_used: 999 },
    { amount: 500 },
    {},
    undefined,
  ] as const
  const unitDebits = [0.01, 1, 25, 50, 500, 99999, undefined] as const
  const spoofEvents = [
    ['mass_assignment'],
    ['csrf_state_change'],
    ['privilege_escalation', 'invariant_violation'],
    ['cross_tenant_write', 'workflow_skip'],
    undefined,
  ] as const

  // Fixture A (Hardened negative — mass assignment where host request only sent `note`, NOT `role`)
  const hardenedMassExchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', seq: 1, method: 'GET', pathAndQuery: '/api/v1/users/1', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"1","note":"old","role":"member"}' },
    { exchangeId: 'prb', seq: 2, method: 'PATCH', pathAndQuery: '/api/v1/users/1', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', requestBody: '{"note":"new"}', body: '{"id":"1","note":"new","role":"admin"}' },
    { exchangeId: 'post', seq: 3, method: 'GET', pathAndQuery: '/api/v1/users/1', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"1","note":"new","role":"admin"}' },
  ]

  // Fixture B (Hardened negative — bearer-token write cannot be promoted to CSRF)
  const hardenedCsrfExchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', seq: 1, method: 'GET', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', requestHeaders: { authorization: 'Bearer tok_real' }, responseHeaders: { 'set-cookie': 'sid=s1; SameSite=Strict' }, body: '{"email":"a@acme.example"}' },
    { exchangeId: 'prb', seq: 2, method: 'POST', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', requestHeaders: { authorization: 'Bearer tok_real', origin: 'https://evil.invalid' }, requestBody: '{"email":"b@acme.example"}', body: '{"email":"b@acme.example"}' },
    { exchangeId: 'post', seq: 3, method: 'GET', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', requestHeaders: { authorization: 'Bearer tok_real' }, body: '{"email":"b@acme.example"}' },
  ]

  // Fixture C (Hardened negative — conserved wallet where 2 concurrent debits of 10 properly deduct 20)
  const conservedWalletExchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', seq: 1, startedAt: 1000, endedAt: 1010, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":100}' },
    { exchangeId: 'b1', seq: 2, op: 'race', raceBatchId: 'batch-prop-1', startedAt: 1050, endedAt: 1110, durationMs: 60, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'b2', seq: 3, op: 'race', raceBatchId: 'batch-prop-1', startedAt: 1055, endedAt: 1115, durationMs: 60, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'post', seq: 4, startedAt: 1150, endedAt: 1160, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":80}' },
    { exchangeId: 's1', seq: 5, startedAt: 1200, endedAt: 1220, durationMs: 20, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'spost', seq: 6, startedAt: 1250, endedAt: 1260, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":70}' },
  ]

  // Fixture D (Vulnerable positive — genuine conserved_balance under-debit race)
  const vulnerableRaceExchanges: ScriptProofExchange[] = conservedWalletExchanges.map(ex =>
    ex.exchangeId === 'post' ? { ...ex, body: '{"balance":90}' }
      : ex.exchangeId === 'spost' ? { ...ex, body: '{"balance":80}' }
        : ex,
  )

  // Fixture E (Hardened negative — self-service own-tenant mutation with no denied control)
  const selfServiceExchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', seq: 1, method: 'GET', pathAndQuery: '/api/v1/notes/7', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"7","title":"before"}' },
    { exchangeId: 'prb', seq: 2, method: 'PATCH', pathAndQuery: '/api/v1/notes/7', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', requestBody: '{"title":"after"}', body: '{"id":"7","title":"after"}' },
    { exchangeId: 'post', seq: 3, method: 'GET', pathAndQuery: '/api/v1/notes/7', origin: ORIGIN, status: 200, personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"7","title":"after"}' },
  ]

  // Also test TranscriptStore + evaluateClaims with HostFactLog custody attached.
  const makeStoreFor = (exchanges: readonly ScriptProofExchange[]) => {
    const store = new TranscriptStore()
    const idMap = new Map<string, string>()
    const rawReqBodies = new Map<string, string>()
    for (const ex of exchanges) {
      const rec = store.record({
        op: 'http',
        startedAt: ex.startedAt ?? ex.seq ?? 1,
        durationMs: ex.durationMs ?? 10,
        request: {
          origin: ex.origin,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          headers: ex.requestHeaders ?? {},
          bodyBytes: Buffer.byteLength(ex.requestBody ?? ''),
          bodySha256: sha256(ex.requestBody ?? ''),
          personaHandle: ex.personaHandle ?? null,
          actorRoleLabel: ex.actorRoleLabel ?? null,
          nonce: 'n-prop',
        },
        response: {
          status: ex.status ?? 200,
          headers: ex.responseHeaders ?? {},
          bodyBytes: Buffer.byteLength(ex.body ?? ''),
          bodySha256: sha256(ex.body ?? ''),
          mediaType: 'application/json',
        },
        body: ex.body,
        rawRequestBody: ex.requestBody ?? undefined,
      })
      idMap.set(ex.exchangeId, rec.exchangeId)
      if (ex.requestBody) rawReqBodies.set(rec.exchangeId, ex.requestBody)
    }
    const factLog = HostFactLog.fromTranscriptStore(store, { rawRequestBodies: rawReqBodies })
    return { store, idMap, factLog }
  }
  const hardenedMassCtx = makeStoreFor(hardenedMassExchanges)

  for (let trial = 0; trial < 40; trial += 1) {
    const reqRole = pick(roles)
    const resTenant = pick(tenants)
    const amb = pick(ambients)
    const body = pick(spoofBodies)
    const unitDebit = pick(unitDebits)
    const events = pick(spoofEvents)

    // 1. Hardened mass_assignment must NEVER flip to confirmed
    const massBuilt = buildAgentScriptReceipt({
      origin: ORIGIN,
      title: `Mutated mass_assignment trial ${trial}`,
      exchanges: hardenedMassExchanges,
      claims: [{
        kind: 'impact',
        impactClass: 'mass_assignment',
        vulnClass: 'mass_assignment',
        beforeExchangeId: 'pre',
        probeExchangeId: 'prb',
        afterExchangeId: 'post',
        requiredRole: reqRole,
        resourceTenant: resTenant,
        requestBody: body,
        ambient: amb,
        oracleEvents: events,
      }],
    })
    assert.ok(massBuilt)
    const massEval = defaultTerminalOracleRegistry.evaluate(massBuilt.factLog, {
      kind: 'single_hop',
      receipt: {
        ...massBuilt.receipt,
        ...(reqRole ? { requiredRole: reqRole } : {}),
        ...(resTenant ? { resourceTenant: resTenant } : {}),
        ...(events ? { oracleEvents: [...events] } : {}),
      },
      armOverrides: massBuilt.armOverrides,
    })
    assert.equal(massEval.confirmed, false, `trial ${trial}: hardened mass_assignment flipped!`)

    // 1b. evaluateClaims with HostFactLog must ALSO never flip on mutated worker claim scalars
    const claimsEval = evaluateClaims(
      hardenedMassCtx.store,
      [{
        kind: 'impact',
        impactClass: 'mass_assignment',
        beforeExchangeId: hardenedMassCtx.idMap.get('pre')!,
        probeExchangeId: hardenedMassCtx.idMap.get('prb')!,
        afterExchangeId: hardenedMassCtx.idMap.get('post')!,
        ...(reqRole ? { requiredRole: reqRole } : {}),
        ...(resTenant ? { resourceTenant: resTenant } : {}),
        ...(body !== undefined ? { requestBody: body } : {}),
        ...(amb ? { ambient: { kind: amb.kind, ...(amb.sameSite ? { sameSite: amb.sameSite } : {}) } } : {}),
        ...(events ? { oracleEvents: [...events] } : {}),
      }],
      { factLog: hardenedMassCtx.factLog, claimedImpact: 'mass_assignment' },
    )
    assert.equal(claimsEval.passed, false, `trial ${trial}: evaluateClaims mass_assignment flipped!`)

    // 2. Hardened bearer CSRF must NEVER flip to confirmed
    const csrfBuilt = buildAgentScriptReceipt({
      origin: ORIGIN,
      title: `Mutated csrf trial ${trial}`,
      exchanges: hardenedCsrfExchanges,
      claims: [{
        kind: 'impact',
        impactClass: 'csrf',
        vulnClass: 'csrf',
        beforeExchangeId: 'pre',
        probeExchangeId: 'prb',
        afterExchangeId: 'post',
        requiredRole: reqRole,
        resourceTenant: resTenant,
        requestBody: body,
        ambient: amb,
        oracleEvents: events,
      }],
    })
    assert.ok(csrfBuilt)
    const csrfEval = defaultTerminalOracleRegistry.evaluate(csrfBuilt.factLog, {
      kind: 'single_hop',
      receipt: {
        ...csrfBuilt.receipt,
        ...(reqRole ? { requiredRole: reqRole } : {}),
        ...(resTenant ? { resourceTenant: resTenant } : {}),
        ...(events ? { oracleEvents: [...events] } : {}),
      },
      armOverrides: csrfBuilt.armOverrides,
    })
    assert.equal(csrfEval.confirmed, false, `trial ${trial}: hardened bearer CSRF flipped!`)

    // 3. Conserved wallet must NEVER flip to confirmed under mutated unitDebit/requestBody
    const conservedBuilt = buildAgentScriptReceipt({
      origin: ORIGIN,
      title: `Mutated conserved wallet trial ${trial}`,
      exchanges: conservedWalletExchanges,
      claims: [{
        kind: 'race',
        baselineExchangeId: 'pre',
        burstExchangeIds: trial % 2 === 0 ? ['b2', 'b1'] : ['b1', 'b2'],
        postExchangeId: 'post',
        serialExchangeIds: ['s1'],
        serialPostExchangeId: 'spost',
        balanceField: 'balance',
        requestBody: body,
        unitDebit,
      }],
    })
    assert.ok(conservedBuilt)
    const conservedEval = defaultTerminalOracleRegistry.evaluate(conservedBuilt.factLog, {
      kind: 'single_hop',
      receipt: {
        ...conservedBuilt.receipt,
        ...(unitDebit !== undefined ? { conservedBalance: { ...conservedBuilt.receipt.conservedBalance, unitDebit } } : {}),
      },
      armOverrides: conservedBuilt.armOverrides,
      evidenceRoleOverrides: conservedBuilt.evidenceRoleOverrides,
    })
    assert.equal(conservedEval.confirmed, false, `trial ${trial}: conserved wallet flipped under unitDebit=${unitDebit}!`)

    // 4. Genuine vulnerable race must STAY confirmed regardless of mutated unitDebit/requestBody/order
    const vulnBuilt = buildAgentScriptReceipt({
      origin: ORIGIN,
      title: `Mutated vulnerable race trial ${trial}`,
      exchanges: vulnerableRaceExchanges,
      claims: [{
        kind: 'race',
        baselineExchangeId: 'pre',
        burstExchangeIds: trial % 2 === 0 ? ['b2', 'b1'] : ['b1', 'b2'],
        postExchangeId: 'post',
        serialExchangeIds: ['s1'],
        serialPostExchangeId: 'spost',
        balanceField: 'balance',
        requestBody: body,
        unitDebit,
      }],
    })
    assert.ok(vulnBuilt)
    const vulnEval = defaultTerminalOracleRegistry.evaluate(vulnBuilt.factLog, {
      kind: 'single_hop',
      receipt: {
        ...vulnBuilt.receipt,
        ...(unitDebit !== undefined ? { conservedBalance: { ...vulnBuilt.receipt.conservedBalance, unitDebit } } : {}),
      },
      armOverrides: vulnBuilt.armOverrides,
      evidenceRoleOverrides: vulnBuilt.evidenceRoleOverrides,
    })
    assert.equal(vulnEval.confirmed, true, `trial ${trial}: genuine race failed under unitDebit=${unitDebit}: ${vulnEval.reason}`)

    // 5. Hardened self-service business_logic write must NEVER flip under requiredRole/resourceTenant/oracleEvents
    const blBuilt = buildAgentScriptReceipt({
      origin: ORIGIN,
      title: `Mutated self-service write trial ${trial}`,
      exchanges: selfServiceExchanges,
      claims: [{
        kind: 'impact',
        impactClass: 'business_logic',
        vulnClass: 'business_logic',
        beforeExchangeId: 'pre',
        probeExchangeId: 'prb',
        afterExchangeId: 'post',
        requiredRole: reqRole,
        resourceTenant: resTenant,
        requestBody: body,
        ambient: amb,
        oracleEvents: events,
      }],
    })
    assert.ok(blBuilt)
    const blEval = defaultTerminalOracleRegistry.evaluate(blBuilt.factLog, {
      kind: 'single_hop',
      receipt: {
        ...blBuilt.receipt,
        ...(reqRole ? { requiredRole: reqRole } : {}),
        ...(resTenant ? { resourceTenant: resTenant } : {}),
        ...(events ? { oracleEvents: [...events] } : {}),
      },
      armOverrides: blBuilt.armOverrides,
    })
    assert.equal(blEval.confirmed, false, `trial ${trial}: self-service business_logic write flipped!`)
  }
})
