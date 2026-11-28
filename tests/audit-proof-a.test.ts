import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  signHostRecord,
  singleReceiptToComposite,
  verifyCompositeReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { buildReplayReceipt } from '../src/server/floor-recipe-engine.ts'
import { HostFactLog, parseBodyFromCarrierText } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { buildProofReceipt, verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ProofReceipt, ReceiptTranscriptEntry } from '../src/server/proof-receipt.ts'
import {
  defaultTerminalOracleRegistry,
  type TerminalOraclePointerRef,
  type TerminalOraclePolicyContext,
} from '../src/server/terminal-oracle-registry.ts'
import { hydrateV8OracleInput, type HydratableTranscriptIndex } from '../src/server/v8-oracle-hydrate.ts'
import { evaluateV8OracleFamily, type HostSignedRecord } from '../src/server/v8-oracle-families.ts'
import { TranscriptStore } from '../src/server/verify-claims.ts'
import { VerifyRpcServer } from '../src/server/verify-rpc.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'audit-proof-a-host-signing-key-0123456789'
const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? { handle: 'alice', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
    ...(partial.route !== undefined ? { route: partial.route } : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const raw: HostTranscriptEntry = {
    exchangeId,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...raw, hostSignature: signHostRecord(raw, SIGNING_KEY) }
}

function indexOf(entries: readonly HostTranscriptEntry[]): HydratableTranscriptIndex {
  return { entriesById: new Map(entries.map(entry => [entry.exchangeId, entry])) }
}

function parserEntries(): HostTranscriptEntry[] {
  return [
    signedEntry('parser-ctl', makeStep({
      id: 'parser-ctl', arm: 'control', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 403,
      requestHeaders: { 'content-type': 'application/json' }, requestJson: '{"tenantId":"tenant-b"}', body: '{"error":"denied"}',
    }), { seq: 1, timestampMs: 1000 }),
    signedEntry('parser-prb', makeStep({
      id: 'parser-prb', arm: 'probe', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 200,
      requestHeaders: { 'content-type': 'application/json' }, requestJson: '{"tenantId":"tenant-a","tenantId":"tenant-b"}',
      json: { tenantId: 'tenant-b', records: [{ id: 'r-1', amount: 25 }] }, body: '{"tenantId":"tenant-b","records":[{"id":"r-1","amount":25}]}',
    }), { seq: 2, timestampMs: 1100 }),
  ]
}

function parserComposite(): unknown {
  return {
    chainId: 'audit-parser-positive',
    terminalVulnClass: 'parser_cache_differential',
    hops: [{
      hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/reports/export' },
      exchangeIds: ['parser-prb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read a foreign tenant report through a parser differential.',
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1', terminalExchangeId: 'parser-prb', summary: 'Read a foreign tenant report through a parser differential.',
      preChainControlExchangeIds: ['parser-ctl'], postChainReadbackExchangeIds: [],
      oracleFamily: 'parser_cache_differential',
      oracleInput: {
        mode: 'parser_differential', differentialKind: 'duplicate_json_key', differentialFeature: 'duplicate tenant selector', impactKind: 'read',
        cleanControl: 'parser-ctl', differentialProbe: 'parser-prb',
      },
    },
    replayMode: 'fresh_clean_replay',
  }
}

test('C-1: composite proof/V8 dispatch is registry-routed and cannot relax strict host derivation', () => {
  const control = signedEntry('auth-ctl', makeStep({
    id: 'auth-ctl', arm: 'control', method: 'GET', route: '/api/admin/settings', pathAndQuery: '/api/admin/settings', status: 401,
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauthorized"}',
  }), { seq: 1, timestampMs: 1000 })
  const probe = signedEntry('auth-prb', makeStep({
    id: 'auth-prb', arm: 'probe', method: 'GET', route: '/api/admin/settings', pathAndQuery: '/api/admin/settings', status: 200,
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    requestHeaders: { authorization: 'Bearer forged.unsigned.token' }, body: '{"admin":true,"email":"root@example.test"}',
  }), { seq: 2, timestampMs: 1100 })
  const proof = buildProofReceipt({
    vulnClass: 'auth_bypass', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/settings' },
    exchangeIds: ['auth-ctl', 'auth-prb'], claimedDelta: 'A forged token crossed the unauthenticated control and returned account data.',
  })
  const composite = singleReceiptToComposite(proof)
  const original = defaultTerminalOracleRegistry.evaluate.bind(defaultTerminalOracleRegistry)
  const calls: Array<{ ref: TerminalOraclePointerRef; policy: TerminalOraclePolicyContext }> = []
  defaultTerminalOracleRegistry.evaluate = ((factLog: HostFactLog, ref: TerminalOraclePointerRef, policy: TerminalOraclePolicyContext = {}) => {
    calls.push({ ref, policy })
    return original(factLog, ref, policy)
  }) as typeof defaultTerminalOracleRegistry.evaluate
  try {
    const direct = verifyCompositeReceipt(composite, { entries: [control, probe] }, { signingKey: SIGNING_KEY, strictHostDerivation: false })
    assert.equal(direct.confirmed, true, direct.reason)
    assert.ok(calls.some(call => call.ref.kind === 'single_hop' && call.policy.strictHostDerivation === true))

    const fakeRpc = {
      options: { compositeVerifyOptions: { strictHostDerivation: false } },
      compositeSigningKey: SIGNING_KEY,
      buildHostSignedTranscript: () => ({ entries: [control, probe] }),
    } as unknown as VerifyRpcServer
    const rpcResult = VerifyRpcServer.prototype.verifyComposite.call(fakeRpc, composite)
    assert.equal(rpcResult.confirmed, true, rpcResult.reason)
    assert.ok(calls.some(call => call.ref.kind === 'composite' && call.policy.strictHostDerivation === true))

    calls.length = 0
    const parser = verifyCompositeReceipt(parserComposite(), { entries: parserEntries() }, { signingKey: SIGNING_KEY, strictHostDerivation: false })
    assert.equal(parser.confirmed, true, parser.reason)
    assert.ok(calls.some(call => call.ref.kind === 'v8_family' && call.policy.strictHostDerivation === true))
  } finally {
    defaultTerminalOracleRegistry.evaluate = original
  }
})

test('C-1: VerifyRpcServer stages its Unix socket beneath KOVO_CONTAINER_SCRATCH_DIR and rejects invalid roots', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'kovo-audit-rpc-'))
  const previous = process.env.KOVO_CONTAINER_SCRATCH_DIR
  process.env.KOVO_CONTAINER_SCRATCH_DIR = scratch
  const server = new VerifyRpcServer({
    broker: new RequestBroker(), grant: {} as Grant, runId: 'run-audit-rpc', assignmentId: 'assignment-audit-rpc', targetOrigins: [ORIGIN],
  })
  try {
    await server.start()
    assert.equal(dirname(server.hostDir), scratch)
    assert.equal(dirname(server.socketPath), server.hostDir)
  } finally {
    await server.close()
  }

  process.env.KOVO_CONTAINER_SCRATCH_DIR = 'relative/scratch'
  const invalid = new VerifyRpcServer({
    broker: new RequestBroker(), grant: {} as Grant, runId: 'run-audit-rpc-invalid', assignmentId: 'assignment-audit-rpc-invalid', targetOrigins: [ORIGIN],
  })
  try {
    await assert.rejects(() => invalid.start(), /Invalid KOVO_CONTAINER_SCRATCH_DIR/)
  } finally {
    await invalid.close()
    if (previous === undefined) delete process.env.KOVO_CONTAINER_SCRATCH_DIR
    else process.env.KOVO_CONTAINER_SCRATCH_DIR = previous
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('C-2: dual-tenant actor roles and tenant scope are derived from host records, not worker scalars', () => {
  const entries = [
    signedEntry('dual-ctl', makeStep({
      id: 'dual-ctl', arm: 'control', method: 'GET', route: '/api/assets/ent-9', pathAndQuery: '/api/assets/ent-9', status: 403,
      actor: { handle: 'bob', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, body: '{"error":"forbidden"}',
    }), { seq: 1, timestampMs: 1000, actorRoleLabel: 'member (tenant-a)' }),
    signedEntry('dual-xfer', makeStep({
      id: 'dual-xfer', arm: 'probe', method: 'POST', route: '/api/assets/ent-9/transfer', pathAndQuery: '/api/assets/ent-9/transfer', status: 200,
      actor: { handle: 'bob', role: 'admin', tenant: 'tenant-b', auth: 'bearer', sameSite: null },
      requestJson: { entityId: 'ent-9', destTenant: 'tenant-b' }, body: '{"transferred":true}',
    }), { seq: 2, timestampMs: 1100, actorRoleLabel: 'admin (tenant-b)' }),
    signedEntry('dual-rb', makeStep({
      id: 'dual-rb', arm: 'probe', method: 'GET', route: '/api/assets/ent-9', pathAndQuery: '/api/assets/ent-9', status: 200,
      actor: { handle: 'bob', role: 'admin', tenant: 'tenant-b', auth: 'bearer', sameSite: null },
      json: { id: 'ent-9', ownerTenantId: 'tenant-b', title: 'Foreign ledger' }, body: '{"id":"ent-9","ownerTenantId":"tenant-b","title":"Foreign ledger"}',
    }), { seq: 3, timestampMs: 1200, actorRoleLabel: 'admin (tenant-b)' }),
  ]
  const rawInput = {
    mode: 'cross_org_transfer',
    actor: { actorId: 'bob', rolesByTenant: { 'tenant-a': 'owner', 'tenant-b': 'viewer' } },
    sourceTenantId: 'tenant-b', destTenantId: 'tenant-a', requiredSourceRole: 'viewer', requiredDestRole: 'viewer', entityId: 'ent-9',
    sourceControlDenied: 'dual-ctl', transferRecord: 'dual-xfer', postTransferReadback: 'dual-rb',
  }
  const hydrated = hydrateV8OracleInput('dual_tenant_abac', rawInput, indexOf(entries), 'sig')
  assert.deepEqual(hydrated.actor, { actorId: 'bob', rolesByTenant: { 'tenant-a': 'member', 'tenant-b': 'admin' } })
  assert.equal(hydrated.sourceTenantId, 'tenant-a')
  assert.equal(hydrated.destTenantId, 'tenant-b')
  assert.equal(hydrated.requiredDestRole, undefined)
  const result = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript({ entries }), {
    kind: 'v8_family', family: 'dual_tenant_abac', rawInput,
  }, { signingKey: SIGNING_KEY })
  assert.equal(result.confirmed, true, result.reason)
})

test('C-2: explicit oracleFamily requires oracleInput and dual_tenant_abac rejects one-hop and bare-401 chains', () => {
  const parser = parserEntries()
  const noInput = parserComposite() as { terminalImpact: Record<string, unknown> }
  delete noInput.terminalImpact.oracleInput
  const missing = verifyCompositeReceipt(noInput, { entries: parser }, {
    signingKey: SIGNING_KEY,
    v8OracleInput: { mode: 'parser_differential', differentialKind: 'duplicate_json_key', differentialFeature: 'tenant', impactKind: 'read', cleanControl: 'parser-ctl', differentialProbe: 'parser-prb' },
  })
  assert.equal(missing.confirmed, false)
  assert.match(missing.reason, /oracleFamily requires terminalImpact\.oracleInput/)

  const dualEntries = [
    signedEntry('one-ctl', makeStep({ id: 'one-ctl', arm: 'control', method: 'GET', route: '/api/assets/ent-9', pathAndQuery: '/api/assets/ent-9', status: 403,
      actor: { handle: 'bob', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, body: '{"error":"forbidden"}' }), { seq: 1, timestampMs: 1000, actorRoleLabel: 'member (tenant-a)' }),
    signedEntry('one-xfer', makeStep({ id: 'one-xfer', arm: 'probe', method: 'POST', route: '/api/assets/ent-9/transfer', pathAndQuery: '/api/assets/ent-9/transfer', status: 200,
      actor: { handle: 'bob', role: 'admin', tenant: 'tenant-b', auth: 'bearer', sameSite: null }, requestJson: { entityId: 'ent-9' }, body: '{"transferred":true}' }), { seq: 2, timestampMs: 1100, actorRoleLabel: 'admin (tenant-b)' }),
    signedEntry('one-rb', makeStep({ id: 'one-rb', arm: 'probe', method: 'GET', route: '/api/assets/ent-9', pathAndQuery: '/api/assets/ent-9', status: 200,
      actor: { handle: 'bob', role: 'admin', tenant: 'tenant-b', auth: 'bearer', sameSite: null }, json: { id: 'ent-9', ownerTenantId: 'tenant-b' }, body: '{"id":"ent-9","ownerTenantId":"tenant-b"}' }), { seq: 3, timestampMs: 1200, actorRoleLabel: 'admin (tenant-b)' }),
  ]
  const oneHop = verifyCompositeReceipt({
    chainId: 'audit-dual-one-hop', terminalVulnClass: 'dual_tenant_abac',
    hops: [{ hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/assets/ent-9' }, exchangeIds: ['one-xfer', 'one-rb'], claimedDelta: 'Claimed a cross-tenant transfer.' }],
    causalEdges: [], replayMode: 'fresh_clean_replay',
    terminalImpact: {
      terminalHopId: 'hop_1', terminalExchangeId: 'one-rb', summary: 'Claimed a cross-tenant transfer with a full oracle payload.',
      preChainControlExchangeIds: ['one-ctl'], oracleFamily: 'dual_tenant_abac',
      oracleInput: { mode: 'cross_org_transfer', actor: { actorId: 'bob' }, entityId: 'ent-9', sourceControlDenied: 'one-ctl', transferRecord: 'one-xfer', postTransferReadback: 'one-rb' },
    },
  }, { entries: dualEntries }, { signingKey: SIGNING_KEY, attackerPersonas: ['bob'] })
  assert.equal(oneHop.confirmed, false)
  assert.match(oneHop.reason, /multi_hop_causal_chain_required/)

  const cap = 'cap:hop_1:prime_session'
  const bareEntries = [
    signedEntry('bare-ctl', makeStep({ id: 'bare-ctl', arm: 'control', method: 'GET', route: '/api/reports/latest', pathAndQuery: '/api/reports/latest', status: 401,
      actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauthorized"}' }), { seq: 1, timestampMs: 900 }),
    signedEntry('bare-prime', makeStep({ id: 'bare-prime', arm: 'probe', method: 'POST', route: '/api/reports/prime', pathAndQuery: '/api/reports/prime', status: 200,
      actor: { handle: 'alice', role: 'admin', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, json: { primed: true }, body: '{"primed":true}' }), { seq: 2, timestampMs: 1000, actorRoleLabel: 'admin (tenant-a)', emittedCapabilities: [cap] }),
    signedEntry('bare-bled', makeStep({ id: 'bare-bled', arm: 'probe', method: 'GET', route: '/api/reports/latest', pathAndQuery: '/api/reports/latest', status: 200,
      actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, json: { tenantId: 'tenant-b', report: 'foreign data' }, body: '{"tenantId":"tenant-b","report":"foreign data"}' }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] }),
  ]
  const bare = verifyCompositeReceipt({
    chainId: 'audit-dual-bare-401', terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/reports/prime' }, exchangeIds: ['bare-prime'], claimedDelta: 'Primed a permission cache.', producedCapabilities: [cap] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/reports/latest' }, exchangeIds: ['bare-bled'], claimedDelta: 'Read a foreign report.', consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }], replayMode: 'fresh_clean_replay',
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'bare-bled', summary: 'Claimed a cache bleed across tenant boundaries.', preChainControlExchangeIds: ['bare-ctl'],
      oracleFamily: 'dual_tenant_abac', oracleInput: { mode: 'dual_org_cache_bleed', actor: { actorId: 'alice' }, baselineDeniedControl: 'bare-ctl', primeAction: 'bare-prime', bledAccess: 'bare-bled' },
    },
  }, { entries: bareEntries }, { signingKey: SIGNING_KEY, attackerPersonas: ['alice'] })
  assert.equal(bare.confirmed, false)
  assert.match(bare.reason, /unauthenticated_baseline_control/)
})

test('C-2: parser differentials inspect real request bodies and ignore forged canonical/variant values', () => {
  const entries = parserEntries().map(entry => entry.exchangeId === 'parser-prb'
    ? signedEntry('parser-prb', makeStep({
      id: 'parser-prb', arm: 'probe', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 200,
      requestHeaders: { 'content-type': 'application/json' }, requestJson: '{"tenantId":"tenant-a"}',
      json: { tenantId: 'tenant-b', records: [{ id: 'r-1', amount: 25 }] }, body: '{"tenantId":"tenant-b","records":[{"id":"r-1","amount":25}]}',
    }), { seq: 2, timestampMs: 1100 })
    : entry)
  const hydrated = hydrateV8OracleInput('parser_cache_differential', {
    mode: 'parser_differential', differentialKind: 'duplicate_json_key', differentialFeature: 'tenant', impactKind: 'read',
    cleanControl: 'parser-ctl', differentialProbe: 'parser-prb',
    canonicalValue: '{"tenantId":"tenant-b"}', variantValue: '{"tenantId":"tenant-a","tenantId":"tenant-b"}',
  }, indexOf(entries), 'sig')
  assert.equal(hydrated.canonicalValue, hydrated.variantValue)
  const result = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript({ entries }), {
    kind: 'v8_family', family: 'parser_cache_differential', rawInput: {
      mode: 'parser_differential', differentialKind: 'duplicate_json_key', differentialFeature: 'tenant', impactKind: 'read',
      cleanControl: 'parser-ctl', differentialProbe: 'parser-prb',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(result.confirmed, false)
  assert.match(result.reason, /no_request_differential/)
})

test('H-7: V8 hydration uses carrier request bodies without invalidating original host signatures', () => {
  const headers = { 'content-type': 'application/json' }
  const controlRequest = '{"tenantId":"tenant-b"}'
  const probeRequest = '{"tenantId":"tenant-a","tenantId":"tenant-b"}'
  const control = signedEntry('carrier-ctl', makeStep({
    id: 'carrier-ctl', arm: 'control', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 403,
    requestHeaders: headers, body: '{"error":"denied"}',
  }), { seq: 1, timestampMs: 1000, carrierText: `/api/reports/export\n${JSON.stringify(headers)}\n${controlRequest}` })
  const probe = signedEntry('carrier-prb', makeStep({
    id: 'carrier-prb', arm: 'probe', method: 'POST', route: '/api/reports/export', pathAndQuery: '/api/reports/export', status: 200,
    requestHeaders: headers, json: { tenantId: 'tenant-b', records: [{ id: 'r-1' }] }, body: '{"tenantId":"tenant-b","records":[{"id":"r-1"}]}',
  }), { seq: 2, timestampMs: 1100, carrierText: `/api/reports/export\n${JSON.stringify(headers)}\n${probeRequest}` })
  const result = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript({ entries: [control, probe] }), {
    kind: 'v8_family', family: 'parser_cache_differential', rawInput: {
      mode: 'parser_differential', differentialKind: 'duplicate_json_key', differentialFeature: 'tenant selector', impactKind: 'read',
      cleanControl: 'carrier-ctl', differentialProbe: 'carrier-prb',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(result.confirmed, true, result.reason)
})

test('C-2: cryptographic replay digests require attestations or request signature headers, never response digests', () => {
  const valid = sha256('valid-signature-value')
  const responseOnly: HostSignedRecord[] = [
    { id: 'crypto-ctl', hostSignature: 'a'.repeat(64), timestampMs: 1000, status: 401, method: 'POST', route: '/hooks/run', artifactDigest: sha256('bad-response') },
    { id: 'crypto-src', hostSignature: 'b'.repeat(64), timestampMs: 1100, status: 200, method: 'POST', route: '/hooks/sign', artifactDigest: valid },
    { id: 'crypto-rep', hostSignature: 'c'.repeat(64), timestampMs: 1200, status: 200, method: 'POST', route: '/hooks/run', artifactDigest: valid, json: { tenantId: 'tenant-b', settled: true } },
  ]
  const direct = evaluateV8OracleFamily('cryptographic_scope_replay', {
    tamperedSignatureControl: responseOnly[0]!, sourceValidIssuance: responseOnly[1]!, replayedAcceptance: responseOnly[2]!,
    sourceTenant: 'tenant-a', sourceScope: 'tenant-a:hook', targetTenant: 'tenant-b', targetScope: 'tenant-b:hook',
  })
  assert.equal(direct.satisfied, false)
  assert.equal(direct.reason, 'missing_signature_digest_binding')

  const entries = [
    signedEntry('crypto-ctl', makeStep({ id: 'crypto-ctl', arm: 'control', method: 'POST', route: '/hooks/run', pathAndQuery: '/hooks/run', status: 401,
      actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, requestHeaders: { 'x-signature': 'invalid-signature-value' }, body: '{"error":"invalid signature"}' }), { seq: 1, timestampMs: 1000, observedResponseDigests: [sha256('bad-response')] }),
    signedEntry('crypto-src', makeStep({ id: 'crypto-src', arm: 'probe', method: 'POST', route: '/hooks/sign', pathAndQuery: '/hooks/sign', status: 200, body: '{"signed":true}' }), { seq: 2, timestampMs: 1100, emittedCapabilities: ['cap:hop_1:scope_sig'], observedResponseDigests: [valid] }),
    signedEntry('crypto-rep', makeStep({ id: 'crypto-rep', arm: 'probe', method: 'POST', route: '/hooks/run', pathAndQuery: '/hooks/run', status: 200,
      requestHeaders: { 'x-signature': 'valid-signature-value' }, json: { tenantId: 'tenant-b', settled: true }, body: '{"tenantId":"tenant-b","settled":true}' }), {
      seq: 3, timestampMs: 1200, observedResponseDigests: [valid],
      cryptoAttestations: [{ derivedFromCapabilityId: 'cap:hop_1:scope_sig', alg: 'hmac-sha256', artifactDigest: valid, timestampMs: 1150 }],
    }),
  ]
  const result = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript({ entries }), {
    kind: 'v8_family', family: 'cryptographic_scope_replay', rawInput: {
      tamperedSignatureControl: 'crypto-ctl', sourceValidIssuance: 'crypto-src', replayedAcceptance: 'crypto-rep',
      sourceTenant: 'tenant-a', sourceScope: 'tenant-a:hook', targetTenant: 'tenant-b', targetScope: 'tenant-b:hook',
      tamperedSignatureDigest: sha256('forged'), signatureDigest: sha256('forged'), replayedSignatureDigest: sha256('forged'),
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(result.confirmed, true, result.reason)
})

test('C-2: economic actions deduplicate and deposits sum without Math.max or transfer-only bypass', () => {
  const entries = [
    signedEntry('econ-base', makeStep({ id: 'econ-base', arm: 'control', method: 'GET', route: '/api/ledger', pathAndQuery: '/api/ledger', status: 200,
      json: { balances: { a: 100, b: 0 } }, body: '{"balances":{"a":100,"b":0}}' }), { seq: 1, timestampMs: 1000 }),
    signedEntry('econ-dep-1', makeStep({ id: 'econ-dep-1', arm: 'probe', method: 'POST', route: '/api/ledger/deposit', pathAndQuery: '/api/ledger/deposit', status: 200,
      requestJson: { amount: 20 }, json: { credited: 20 }, body: '{"credited":20}' }), { seq: 2, timestampMs: 1100 }),
    signedEntry('econ-dep-2', makeStep({ id: 'econ-dep-2', arm: 'probe', method: 'POST', route: '/api/ledger/deposit', pathAndQuery: '/api/ledger/deposit', status: 200,
      requestJson: { amount: 30 }, json: { credited: 30 }, body: '{"credited":30}' }), { seq: 3, timestampMs: 1200 }),
    signedEntry('econ-xfer', makeStep({ id: 'econ-xfer', arm: 'probe', method: 'POST', route: '/api/ledger/transfer', pathAndQuery: '/api/ledger/transfer', status: 200,
      requestJson: { from: 'a', to: 'b', amount: 100 }, json: { ok: true }, body: '{"ok":true}' }), { seq: 4, timestampMs: 1300 }),
    signedEntry('econ-final', makeStep({ id: 'econ-final', arm: 'control', method: 'GET', route: '/api/ledger', pathAndQuery: '/api/ledger', status: 200,
      json: { balances: { a: 20, b: 130 } }, body: '{"balances":{"a":20,"b":130}}' }), { seq: 5, timestampMs: 1400 }),
    signedEntry('econ-mint', makeStep({ id: 'econ-mint', arm: 'control', method: 'GET', route: '/api/ledger', pathAndQuery: '/api/ledger', status: 200,
      json: { balances: { a: 21, b: 130 } }, body: '{"balances":{"a":21,"b":130}}' }), { seq: 6, timestampMs: 1500 }),
  ]
  const rawInput = {
    equation: 'balance_minting', baselineReadback: 'econ-base', actions: ['econ-dep-1', 'econ-dep-2', 'econ-xfer', 'econ-dep-1'],
    finalReadback: 'econ-final', authorizedDeposits: 0,
  }
  const hydrated = hydrateV8OracleInput('economic_conservation', rawInput, indexOf(entries), 'sig')
  assert.equal((hydrated.actions as unknown[]).length, 3)
  assert.equal(hydrated.authorizedDeposits, 50)
  const log = HostFactLog.fromTranscript({ entries })
  const conserved = defaultTerminalOracleRegistry.evaluate(log, { kind: 'v8_family', family: 'economic_conservation', rawInput }, { signingKey: SIGNING_KEY })
  assert.equal(conserved.confirmed, false)
  assert.match(conserved.reason, /balance_ledger_conserved/)
  const minted = defaultTerminalOracleRegistry.evaluate(log, {
    kind: 'v8_family', family: 'economic_conservation', rawInput: { ...rawInput, finalReadback: 'econ-mint', authorizedDeposits: 999 },
  }, { signingKey: SIGNING_KEY })
  assert.equal(minted.confirmed, true, minted.reason)
})

test('C-3: replay OOB receipts require an independently checked CanaryBroker callback', async () => {
  const canaryBroker = new CanaryBroker()
  const runId = 'run-audit-canary'
  const minted = canaryBroker.mintCanary(runId, 'ssrf:callback', ORIGIN)
  const subscription = canaryBroker.subscribe({ runId, assignmentId: 'assignment-audit-canary', canaryId: minted.id, token: minted.token, artifact: '', immediateMs: 0, windowMs: 60_000 })
  const spec = {
    version: 1, kind: 'http_chain', origin: ORIGIN, title: 'SSRF callback verification', category: 'ssrf', cwe: 'CWE-918', severity: 'high',
    severityRationale: 'test', impact: 'Outbound callback.', remediation: 'Restrict outbound requests.', recheckInstructions: 'Replay the callback probe.',
    assertionsJq: '{controlPassed:true,confirmed:true,observed:"callback",expected:"none"}',
    steps: [{ id: 'probe', role: 'probe', description: 'Callback probe', request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/fetch' } }],
  } as unknown as DeclarativeReplaySpec
  const evidencePayload = {
    steps: { probe: { id: 'probe', role: 'probe', status: 200, requestBody: JSON.stringify({ url: minted.httpUrl }), requestHeaders: {} } },
    canary: { triggered: true, probeTriggered: true, controlTriggered: false, token: minted.token, callbackId: subscription.id, stage: 'immediate' },
  }
  try {
    const fabricated = buildReplayReceipt({ spec, evidencePayload, exchangeIds: ['ex-callback'], exchanges: [] })
    assert.equal(fabricated, null)

    canaryBroker.recordCallback(minted.token, {
      callbackId: 'callback-audit-1', protocol: 'http', sourceIp: '127.0.0.1', method: 'GET', path: `/c/${minted.token}`,
      runId, assignmentId: 'assignment-audit-canary', canaryId: minted.id,
    })
    const checked = canaryBroker.checkCanary(minted.token, { runId })
    assert.equal(checked.hit, true)
    const built = buildReplayReceipt({ spec, evidencePayload, exchangeIds: ['ex-callback'], exchanges: [], canaryBroker, canaryRunId: runId })
    assert.ok(built)
    assert.equal(built.transcript.oobEvents?.[0]?.delivered, true)
    assert.equal(built.transcript.oobEvents?.[0]?.callbackId, subscription.id)
    assert.equal(built.transcript.oobEvents?.[0]?.receivedAtMs, checked.detail?.timestamp)
    assert.equal(verifyReceipt(built.receipt, built.transcript).confirmed, true)

    const noCallbackId = buildReplayReceipt({
      spec, evidencePayload: { ...evidencePayload, canary: { ...evidencePayload.canary, callbackId: undefined } },
      exchangeIds: ['ex-callback'], exchanges: [], canaryBroker, canaryRunId: runId,
    })
    assert.equal(noCallbackId, null)
  } finally {
    await canaryBroker.stop()
  }
})

test('C-4: auth_bypass rejects ordinary authenticated request differences and self-sabotaged controls', () => {
  const receipt = buildProofReceipt({
    vulnClass: 'auth_bypass', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/profile' },
    exchangeIds: ['ctl', 'prb'], claimedDelta: 'Claimed an authentication bypass on an ordinary profile endpoint.',
  })
  const actor = { handle: 'alice', role: 'member' as const, tenant: 'tenant-a', auth: 'cookie' as const, sameSite: 'Lax' as const }
  const ordinary = verifyReceipt(receipt, { entries: [
    { exchangeId: 'ctl', step: makeStep({ id: 'ctl', arm: 'control', method: 'POST', route: '/api/profile', pathAndQuery: '/api/profile', status: 403,
      actor, requestHeaders: { cookie: 'sid=session-a' }, requestJson: { code: 'old' }, body: '{"error":"forbidden"}' }) },
    { exchangeId: 'prb', step: makeStep({ id: 'prb', arm: 'probe', method: 'POST', route: '/api/profile', pathAndQuery: '/api/profile', status: 200,
      actor, requestHeaders: { cookie: 'sid=session-a' }, requestJson: { code: 'new' }, body: '{"email":"alice@example.test","theme":"dark"}' }) },
  ] })
  assert.equal(ordinary.confirmed, false)
  assert.match(ordinary.reason, /ordinary request difference|authentication bypass/)

  const sabotaged = verifyReceipt(receipt, { entries: [
    { exchangeId: 'ctl', step: makeStep({ id: 'ctl', arm: 'control', method: 'POST', route: '/api/profile', pathAndQuery: '/api/profile', status: 401,
      actor, requestHeaders: { cookie: 'sid=session-a', authorization: 'Bearer invalid.control.token' }, body: '{"error":"unauthorized"}' }) },
    { exchangeId: 'prb', step: makeStep({ id: 'prb', arm: 'probe', method: 'POST', route: '/api/profile', pathAndQuery: '/api/profile', status: 200,
      actor, requestHeaders: { cookie: 'sid=session-a' }, body: '{"email":"alice@example.test","theme":"dark"}' }) },
  ] })
  assert.equal(sabotaged.confirmed, false)
  assert.match(sabotaged.reason, /self-sabotaged control/)

  const genuine = verifyReceipt(receipt, { entries: [
    { exchangeId: 'ctl', step: makeStep({ id: 'ctl', arm: 'control', method: 'POST', route: '/api/profile', pathAndQuery: '/api/profile', status: 401,
      actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauthorized"}' }) },
    { exchangeId: 'prb', step: makeStep({ id: 'prb', arm: 'probe', method: 'POST', route: '/api/profile', pathAndQuery: '/api/profile', status: 200,
      actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, requestHeaders: { authorization: 'Bearer forged.unsigned.token' }, body: '{"email":"alice@example.test","private":true}' }) },
  ] })
  assert.equal(genuine.confirmed, true, genuine.reason)
})

test('H-6: setup/cleanup capabilities cannot launders DAG provenance and async_job requires a real probe observation', () => {
  const cap = 'cap:hop_1:setup_cap'
  for (const arm of ['setup', 'cleanup'] as const) {
    const source = signedEntry(`launder-${arm}`, makeStep({
      id: `launder-${arm}`, arm, method: 'POST', route: '/api/bootstrap', pathAndQuery: '/api/bootstrap', status: 200,
      json: { handle: 'bootstrap' }, body: '{"handle":"bootstrap"}',
    }), { seq: 1, timestampMs: 1000, emittedCapabilities: [cap] })
    const target = signedEntry(`launder-target-${arm}`, makeStep({
      id: `launder-target-${arm}`, arm: 'probe', method: 'GET', route: '/api/records/r-1', pathAndQuery: '/api/records/r-1', status: 200,
      actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
      json: { tenantId: 'tenant-b', records: [{ id: 'r-1' }] }, body: '{"tenantId":"tenant-b","records":[{"id":"r-1"}]}',
    }), { seq: 2, timestampMs: 1100, consumedCapabilities: [cap] })
    const result = verifyCompositeReceipt({
      chainId: `audit-launder-${arm}`, terminalVulnClass: 'business_logic',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/bootstrap' }, exchangeIds: [source.exchangeId], claimedDelta: 'Claimed a bootstrap capability.' },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/records/r-1' }, exchangeIds: [target.exchangeId], claimedDelta: 'Claimed foreign data access.', consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: { terminalHopId: 'hop_2', terminalExchangeId: target.exchangeId, summary: 'Claimed impact through a non-probe capability source.' }, replayMode: 'fresh_clean_replay',
    }, { entries: [source, target] }, { attackerPersonas: ['alice'] })
    assert.equal(result.confirmed, false)
    assert.equal(result.failedStage, 'edge_binding')
  }

  const correlationId = 'corr-audit-12345'
  const trigger = signedEntry('async-trigger', makeStep({
    id: 'async-trigger', arm: 'probe', method: 'POST', route: '/api/jobs', pathAndQuery: '/api/jobs', status: 202,
    json: { correlationId, jobId: 'job-1' }, body: JSON.stringify({ correlationId, jobId: 'job-1' }),
  }), { seq: 1, timestampMs: 1000, correlationIds: [correlationId] })
  const control = signedEntry('async-ctl', makeStep({
    id: 'async-ctl', arm: 'control', method: 'GET', route: `/api/results/${correlationId}`, pathAndQuery: `/api/results/${correlationId}`, status: 403, body: '{"error":"forbidden"}',
  }), { seq: 2, timestampMs: 900 })
  const makeAsyncReceipt = (target: HostTranscriptEntry) => ({
    chainId: `audit-async-${target.step.arm}`, terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_1', surface: 'async_job', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/jobs' }, exchangeIds: [trigger.exchangeId], claimedDelta: 'Started an asynchronous job.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/results/${correlationId}` }, exchangeIds: [target.exchangeId], claimedDelta: 'Observed the asynchronous result.' },
    ],
    causalEdges: [{ kind: 'async_pivot_binding', fromHopId: 'hop_1', toHopId: 'hop_2', correlationId, channel: 'async_job' }],
    terminalImpact: { terminalHopId: 'hop_2', terminalExchangeId: target.exchangeId, summary: 'Claimed a completed asynchronous state transition.', preChainControlExchangeIds: [control.exchangeId] },
    replayMode: 'fresh_clean_replay',
  })
  const setupReadback = signedEntry('async-setup', makeStep({
    id: 'async-setup', arm: 'setup', method: 'GET', route: `/api/results/${correlationId}`, pathAndQuery: `/api/results/${correlationId}`, status: 200,
    json: { status: 'ready', tenantId: 'tenant-b', result: 'foreign record' }, body: '{"status":"ready","tenantId":"tenant-b","result":"foreign record"}',
  }), { seq: 3, timestampMs: 1100, correlationIds: [correlationId] })
  const setupResult = verifyCompositeReceipt(makeAsyncReceipt(setupReadback), { entries: [trigger, control, setupReadback] }, { attackerPersonas: ['alice'] })
  assert.equal(setupResult.confirmed, false)
  assert.equal(setupResult.failedStage, 'edge_binding')

  const probeReadback = signedEntry('async-probe', makeStep({
    id: 'async-probe', arm: 'probe', method: 'GET', route: `/api/results/${correlationId}`, pathAndQuery: `/api/results/${correlationId}`, status: 200,
    json: { status: 'ready', tenantId: 'tenant-b', result: 'foreign record' }, body: '{"status":"ready","tenantId":"tenant-b","result":"foreign record"}',
  }), { seq: 3, timestampMs: 1100, correlationIds: [correlationId] })
  const probeResult = verifyCompositeReceipt(makeAsyncReceipt(probeReadback), { entries: [trigger, control, probeReadback] }, { attackerPersonas: ['alice'] })
  assert.equal(probeResult.confirmed, true, probeResult.reason)
})

test('H-1/H-2/H-7: runner fact custody, floor oracle events, and carrier-body hydration stay host-derived', () => {
  const runnerSource = readFileSync(join(repoRoot, 'src/server/verify-runner.ts'), 'utf8')
  assert.match(runnerSource, /HostFactLog\.fromTranscriptStore\(session\.transcript\)/)
  assert.match(runnerSource, /evaluateClaims\(session\.transcript, parsed\.claims, \{\s*factLog,/s)

  const spec = {
    version: 1, kind: 'http_chain', origin: ORIGIN, title: 'Business logic mutation', category: 'business-logic', cwe: 'CWE-840', severity: 'medium',
    severityRationale: 'test', impact: 'Persisted mutation.', remediation: 'Enforce the invariant.', recheckInstructions: 'Replay the mutation.', expectedImpactEvents: ['workflow_skip', 'csrf_state_change'],
    assertionsJq: '{controlPassed:true,confirmed:true,observed:"changed",expected:"unchanged"}',
    steps: [
      { id: 'before', role: 'control', description: 'Before', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1' } },
      { id: 'probe', role: 'probe', description: 'Probe', request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/items/1' } },
      { id: 'after', role: 'control', description: 'After', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1' } },
    ],
  } as unknown as DeclarativeReplaySpec
  const built = buildReplayReceipt({
    spec, exchangeIds: ['before', 'probe', 'after'], exchanges: [],
    evidencePayload: {
      impactGate: { required: true, satisfied: true },
      steps: {
        before: { id: 'before', role: 'control', status: 200, json: { state: 'pending' } },
        probe: { id: 'probe', role: 'probe', status: 200, json: { state: 'done' } },
        after: { id: 'after', role: 'control', status: 200, json: { state: 'done' } },
      },
    },
  })
  assert.ok(built)
  assert.deepEqual(built.trustedOracleEvents, [])
  assert.equal(built.receipt.oracleEvents, undefined)

  const requestHeaders = { 'content-type': 'application/json' }
  const requestBody = '{\n  "q": "true"\n}'
  const responseBody = '{\n  "rows": []\n}'
  const carrier = `/api/search\n${JSON.stringify(requestHeaders)}\n${requestBody}\n${responseBody}`
  assert.equal(parseBodyFromCarrierText(carrier, requestHeaders, responseBody), requestBody)
  const legacy: ReceiptTranscriptEntry = {
    exchangeId: 'legacy-carrier',
    step: makeStep({ id: 'legacy-carrier', arm: 'probe', method: 'POST', route: '/api/search', pathAndQuery: '/api/search', status: 200, requestHeaders, body: responseBody, json: { rows: [] } }),
    carrierText: carrier,
  }
  const factLog = HostFactLog.fromTranscript({ entries: [legacy] })
  assert.equal(factLog.getExchange('legacy-carrier')?.rawRequestBody, requestBody)

  const store = new TranscriptStore()
  const record = store.record({
    op: 'http', startedAt: 1000, durationMs: 5,
    request: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/search', headers: {}, bodyBytes: 0, bodySha256: sha256(''), nonce: 'nonce-audit' },
    response: { status: 200, headers: {}, bodyBytes: Buffer.byteLength(responseBody), bodySha256: sha256(responseBody), mediaType: 'application/json' },
    body: responseBody,
  })
  const hostEntry = signedEntry(record.exchangeId, makeStep({
    id: record.exchangeId, arm: 'probe', method: 'POST', route: '/api/search', pathAndQuery: '/api/search', status: 200,
    actor: { handle: 'host-alice', role: 'member', tenant: 'tenant-host', auth: 'cookie', sameSite: 'Lax' }, requestHeaders, body: responseBody, json: { rows: [] } }),
  { actorPersona: 'host-alice', carrierText: carrier })
  const hydratedStore = HostFactLog.fromTranscriptStore(store, { hostTranscript: { entries: [hostEntry] } })
  const hydratedFact = hydratedStore.getExchange(record.exchangeId)!
  assert.equal(hydratedFact.actor, 'host-alice')
  assert.equal(hydratedFact.actorRole, 'member')
  assert.equal(hydratedFact.actorTenant, 'tenant-host')
  assert.equal(hydratedFact.arm, 'probe')
  assert.equal(hydratedFact.rawRequestBody, requestBody)
})

test('audit proof-kernel file budgets and benchmark-literal contamination remain clean', () => {
  const budgets: Record<string, number> = {
    'src/server/composite-receipt.ts': 750,
    // A2: hosts the 5 universal Tier-1 primitives + invariants absorbed from the retired own-org guard.
    'src/server/v8-oracle-families.ts': 1400,
    'src/server/verify-rpc.ts': 2300,
    'src/server/verify-claims.ts': 2300,
  }
  for (const [file, max] of Object.entries(budgets)) {
    assert.ok(readFileSync(join(repoRoot, file), 'utf8').split('\n').length <= max, `${file} exceeded ${max} LOC`)
  }
  assert.ok(readFileSync(join(repoRoot, 'src/server/replay-verifier.ts'), 'utf8').split('\n').length < 1000)
  const forbidden = [/\bpaygrid\b/i, /\bshipforge\b/i, /\bnexusiam\b/i, /\bconnecthub\b/i, /\b(?:PG|SF|NX|CH)-C\d+\b/, /vault\.internal/i, /registry\.internal/i, /billing\.internal/i, /mh_fake_/i]
  for (const file of [...Object.keys(budgets), 'src/server/replay-verifier.ts', 'src/server/host-fact-log.ts', 'src/server/v8-oracle-hydrate.ts', 'src/server/terminal-oracle-registry.ts', 'src/server/proof-receipt.ts', 'src/server/floor-recipe-engine.ts', 'src/server/verify-runner.ts']) {
    const source = readFileSync(join(repoRoot, file), 'utf8')
    for (const pattern of forbidden) assert.equal(pattern.test(source), false, `${file} contains a benchmark literal`)
  }
})
