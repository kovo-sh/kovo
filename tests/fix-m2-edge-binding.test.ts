/**
 * M2 Edge-Binding, Upstream Setup-Hop Custody & SDK Ergonomics Regression Suite.
 *
 * Verifies:
 *  1. Upstream (non-terminal) hops executed with `role: 'setup'` (`arm: 'setup'`) emit timestamped
 *     host outputs, propagate DAG capabilities, and pass `value_binding`, `derived_crypto_binding`,
 *     `state_transition_binding` (literal + logical-key fallback), and `attacker_provenance`.
 *  2. `value_binding` citing the host `SEAL` op (`host_capability_op`) as `sourceExchangeId` still
 *     binds strictly to `fromHop`'s own host-emitted exchange for that capability handle.
 *  3. All fail-closed security invariants remain 100% intact:
 *     - H-11: `arm: 'setup'` on 1-hop or terminal hop / `terminalExchangeId` MUST fail closed.
 *     - Privileged/forbidden personas on upstream `arm: 'setup'` hops MUST fail at `attacker_provenance`.
 *     - Cross-tenant collusion mixing `setup` (org_a) + `probe` (org_b) MUST fail at `attacker_provenance`.
 *     - `cleanSession: false` on upstream `arm: 'setup'` in Mode A MUST fail at `replay_mode`.
 *     - `arm: 'control'` / `arm: 'cleanup'` on `fromHop` MUST still fail at `edge_binding`.
 *     - Reversed timestamps, unmatched handles, and unrelated `sourceExchangeId` MUST fail closed.
 *  4. Live `VerifyRpcServer` + `VerifyContext` (`worker/kovo_verify/kovo_verify.ts`) + `HostFactLog`:
 *     - Multi-capability `ChainBuilder` tracks ALL `ex.consumedCapabilities` (not just `args.capability`).
 *     - `seal_capability` called between `chain.hop(...)` calls still resolves its producer hop.
 *     - `seal_capability` aliases (`exchange` string, `exchangeId` object, `setCookie`, `hopId`),
 *       `prove_persisted_mutation` aliases (`read`/`mutate`), and `prove_composite` ref normalization.
 *     - `HostFactLog.fromTranscriptStore` preserves `consumedCapabilityId` & `capability` artifact handles.
 *  5. Strict LOC ceilings (`composite-receipt.ts <= 750`, `kovo_verify.ts <= 800`) and zero benchmark literals.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'fix-m2-edge-binding-test-signing-key-987654321'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org_a',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined ? { route: partial.route } : partial.pathAndQuery ? { route: partial.pathAndQuery.split('?')[0]! } : {}),
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
  const base: HostTranscriptEntry = {
    exchangeId,
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

function json(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers })
  res.end(body)
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

function bindEnv(server: VerifyRpcServer): () => void {
  const keys = [VERIFY_RPC_SOCKET_ENV, VERIFY_RPC_TOKEN_ENV, VERIFY_RPC_CONTEXT_ENV, VERIFY_NONCE_ENV] as const
  const prev = keys.map(k => process.env[k])
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  return () => keys.forEach((k, i) => { if (prev[i] === undefined) delete process.env[k]; else process.env[k] = prev[i] })
}

// ============================================================================
// 1. Upstream `arm: 'setup'` multi-hop binding & seal sourceExchangeId
// ============================================================================

test('Upstream arm=setup on hop_1 passes value_binding, derived_crypto_binding, state_transition_binding, and SEAL sourceExchangeId', () => {
  const cap = 'cap:hop_1:export_tok'
  const keyCap = 'cap:hop_1:sign_key'
  const sigDigest = sha256Hex('derived-hmac-sig-01')

  // 1a. value_binding with hop_1 arm='setup' + SEAL op cited as sourceExchangeId
  const ctrl = signedEntry('ex-ctrl', makeStep({
    id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/foreign-doc',
    json: { error: 'forbidden' },
  }), { timestampMs: 900 })
  const h1Setup = signedEntry('ex-h1-setup', makeStep({
    id: 'ex-h1-setup', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
    json: { token: 'opaque-export-token-123' },
  }), { timestampMs: 1000, emittedCapabilities: [cap] })
  const h1Seal = signedEntry('ex-h1-seal', makeStep({
    id: 'ex-h1-seal', arm: 'setup', method: 'SEAL', status: 200, pathAndQuery: '/capability/seal/export_tok',
  }), { timestampMs: 1005, evidenceRole: 'host_capability_op', emittedCapabilities: [cap] })
  const h2Probe = signedEntry('ex-h2-probe', makeStep({
    id: 'ex-h2-probe', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/foreign-doc',
    json: { tenantId: 'org_b', rows: [{ id: 'row-1', total: 5000 }] },
  }), { timestampMs: 1200, consumedCapabilities: [cap] })

  const baseReceipt: CompositeProofReceipt = {
    chainId: 'm2-setup-hop1-vb',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/directory/items' }, exchangeIds: ['ex-h1-setup'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Setup hop fetched export capability', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/foreign-doc' }, exchangeIds: ['ex-h2-probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Probe hop read foreign tenant export', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Unauthorized cross-tenant export read using Hop 1 capability.',
      summary: 'Unauthorized cross-tenant export read using Hop 1 capability.',
      terminalExchangeId: 'ex-h2-probe',
      preChainControlExchangeIds: ['ex-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const transcript: HostSignedTranscript = { entries: [ctrl, h1Setup, h1Seal, h2Probe] }
  const res1 = verifyCompositeReceipt(baseReceipt, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(res1.confirmed, true, res1.reason)

  // Citing the host SEAL record as sourceExchangeId still binds strictly to fromHop's own timestamped emitter.
  const sealRefReceipt: CompositeProofReceipt = {
    ...baseReceipt,
    chainId: 'm2-setup-hop1-seal-src',
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap, sourceExchangeId: 'ex-h1-seal' }],
  }
  const resSeal = verifyCompositeReceipt(sealRefReceipt, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(resSeal.confirmed, true, resSeal.reason)

  // 1b. derived_crypto_binding with hop_1 arm='setup'
  const h1Key = signedEntry('ex-dc-h1', makeStep({
    id: 'ex-dc-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/trace',
    json: { signingSalt: 'secret-salt-value-123' },
  }), { timestampMs: 1000, emittedCapabilities: [keyCap] })
  const h2Signed = signedEntry('ex-dc-h2', makeStep({
    id: 'ex-dc-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/settlement/webhook',
    json: { tenantId: 'org_b', settled: true, amount: 5000 },
  }), {
    timestampMs: 1200,
    cryptoAttestations: [{ derivedFromCapabilityId: keyCap, alg: 'sha256', artifactDigest: sigDigest, timestampMs: 1100 }],
  })
  const dcRes = verifyCompositeReceipt({
    chainId: 'm2-setup-hop1-dc',
    terminalVulnClass: 'forged_settlement',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/trace' }, exchangeIds: ['ex-dc-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Extracted signing salt', producedCapabilities: [keyCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/settlement/webhook' }, exchangeIds: ['ex-dc-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Signed forged settlement webhook', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap, alg: 'sha256' }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Forged settlement webhook accepted using extracted signing salt.',
      summary: 'Forged settlement webhook accepted using extracted signing salt.',
      terminalExchangeId: 'ex-dc-h2',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [h1Key, h2Signed] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(dcRes.confirmed, true, dcRes.reason)

  // 1c. state_transition_binding (logical-key fallback) with hop_1 arm='setup'
  const stAbl = signedEntry('ex-st-abl', makeStep({
    id: 'ex-st-abl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v1/payouts/p-42/approve',
    json: { error: 'maker_checker_required' },
  }), { timestampMs: 900, replayAttempt: 'ablation_control' })
  const stH1 = signedEntry('ex-st-h1', makeStep({
    id: 'ex-st-h1', arm: 'setup', method: 'PATCH', status: 200, pathAndQuery: '/api/v1/cache/prime',
    json: { primed: true },
  }), { timestampMs: 1000 })
  const stH2 = signedEntry('ex-st-h2', makeStep({
    id: 'ex-st-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/payouts/p-42/approve',
    json: { tenantId: 'org_b', approved: true },
  }), { timestampMs: 1200 })
  const stRes = verifyCompositeReceipt({
    chainId: 'm2-setup-hop1-st',
    terminalVulnClass: 'maker_checker_bypass',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/v1/cache/prime' }, exchangeIds: ['ex-st-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed shared state', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/payouts/p-42/approve' }, exchangeIds: ['ex-st-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Approved payout after state prime', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: 'perm:member_a', ablationExchangeIds: ['ex-st-abl'], mutationKind: 'cache_prime' }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Maker-checker invariant bypassed after shared state mutation.',
      summary: 'Maker-checker invariant bypassed after shared state mutation.',
      terminalExchangeId: 'ex-st-h2',
      preChainControlExchangeIds: ['ex-st-abl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [stAbl, stH1, stH2] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(stRes.confirmed, true, stRes.reason)
})

// ============================================================================
// 2. Fail-Closed Security Invariants (H-11, Provenance, Mode A, Edge Integrity)
// ============================================================================

test('Security invariants remain strictly fail-closed for setup/control/cleanup/forbidden/cross-tenant/dirty/tampered cases', () => {
  const cap = 'cap:hop_1:sec_tok'
  const ctrl = signedEntry('s-ctrl', makeStep({
    id: 's-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/secret/doc',
    json: { error: 'denied' },
  }), { timestampMs: 900 })
  const h1Ok = signedEntry('s-h1', makeStep({
    id: 's-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/source',
    json: { token: 'tok-abc' },
  }), { timestampMs: 1000, emittedCapabilities: [cap] })
  const h2Probe = signedEntry('s-h2', makeStep({
    id: 's-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/secret/doc',
    json: { tenantId: 'org_b', secret: 'classified' },
  }), { timestampMs: 1200, consumedCapabilities: [cap] })

  const mkReceipt = (h1ExId: string, h2ExId: string, edgeExtra: Record<string, unknown> = {}): CompositeProofReceipt => ({
    chainId: 'sec-invariant-check',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/source' }, exchangeIds: [h1ExId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Hop 1', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/secret/doc' }, exchangeIds: [h2ExId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Hop 2', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap, ...edgeExtra }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Unauthorized cross-tenant secret document read.',
      summary: 'Unauthorized cross-tenant secret document read.',
      terminalExchangeId: h2ExId,
      preChainControlExchangeIds: ['s-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  // (a) H-11: arm='setup' on terminal hop MUST fail closed
  const h2Setup = signedEntry('s-h2-setup', makeStep({
    id: 's-h2-setup', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/secret/doc',
    json: { tenantId: 'org_b', secret: 'classified' },
  }), { timestampMs: 1200, consumedCapabilities: [cap] })
  const termSetupRes = verifyCompositeReceipt(mkReceipt('s-h1', 's-h2-setup'), { entries: [ctrl, h1Ok, h2Setup] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(termSetupRes.confirmed, false)
  assert.equal(termSetupRes.failedStage, 'terminal_impact')

  // (b) 1-hop receipt with arm='setup' ONLY MUST fail closed at attacker_provenance
  const oneHopSetup = verifyCompositeReceipt({
    chainId: 'sec-1hop-setup', terminalVulnClass: 'bola',
    hops: [{ hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/secret/doc' }, exchangeIds: ['s-h2-setup'], oobEventIds: [], browserTraceIds: [], claimedDelta: '1-hop setup', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'hop_1', terminalExchangeId: 's-h2-setup', summary: 'Attempted 1-hop setup confirmation.', preChainControlExchangeIds: ['s-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, h2Setup] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(oneHopSetup.confirmed, false)
  assert.equal(oneHopSetup.failedStage, 'attacker_provenance')

  // (c) Forbidden / admin persona on upstream arm='setup' MUST fail at attacker_provenance
  const h1Admin = signedEntry('s-h1-admin', makeStep({
    id: 's-h1-admin', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/source',
    actor: { handle: 'admin_a', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { token: 'tok-abc' },
  }), { timestampMs: 1000, actorPersona: 'admin_a', actorRoleLabel: 'admin (org_a)', emittedCapabilities: [cap] })
  const adminSetupRes = verifyCompositeReceipt(mkReceipt('s-h1-admin', 's-h2'), { entries: [ctrl, h1Admin, h2Probe] }, { forbiddenShortcutPersonas: ['admin_a'], signingKey: SIGNING_KEY })
  assert.equal(adminSetupRes.confirmed, false)
  assert.equal(adminSetupRes.failedStage, 'attacker_provenance')

  // (d) Cross-tenant collusion: setup hop in org_a + probe hop in org_b MUST fail at attacker_provenance
  const h2OtherTenant = signedEntry('s-h2-orgb', makeStep({
    id: 's-h2-orgb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/secret/doc',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_c', secret: 'classified' },
  }), { timestampMs: 1200, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)', consumedCapabilities: [cap] })
  const mixTenantRes = verifyCompositeReceipt(mkReceipt('s-h1', 's-h2-orgb'), { entries: [ctrl, h1Ok, h2OtherTenant] }, { signingKey: SIGNING_KEY })
  assert.equal(mixTenantRes.confirmed, false)
  assert.equal(mixTenantRes.failedStage, 'attacker_provenance')
  assert.match(mixTenantRes.reason, /Cross-tenant probe-arm persona mismatch/i)

  // (e) Mode A: cleanSession=false on upstream arm='setup' MUST fail at replay_mode
  const h1Dirty = signedEntry('s-h1-dirty', makeStep({
    id: 's-h1-dirty', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/source',
    json: { token: 'tok-abc' },
  }), { timestampMs: 1000, cleanSession: false, emittedCapabilities: [cap] })
  const dirtyRes = verifyCompositeReceipt(mkReceipt('s-h1-dirty', 's-h2'), { entries: [ctrl, h1Dirty, h2Probe] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(dirtyRes.confirmed, false)
  assert.equal(dirtyRes.failedStage, 'replay_mode')

  // (f) arm='control' and arm='cleanup' on fromHop MUST still fail at edge_binding
  for (const badArm of ['control', 'cleanup'] as const) {
    const h1Bad = signedEntry(`s-h1-${badArm}`, makeStep({
      id: `s-h1-${badArm}`, arm: badArm, method: 'GET', status: 200, pathAndQuery: '/api/v1/source',
      json: { token: 'tok-abc' },
    }), { timestampMs: 1000, emittedCapabilities: [cap] })
    const badRes = verifyCompositeReceipt(mkReceipt(h1Bad.exchangeId, 's-h2'), { entries: [ctrl, h1Bad, h2Probe] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(badRes.confirmed, false)
    assert.equal(badRes.failedStage, 'edge_binding')
    assert.match(badRes.reason, /has no timestamped host outputs/)
  }

  // (g) Reversed timestamps (t_from > t_to) on setup->probe MUST fail at edge_binding
  const h1Late = signedEntry('s-h1-late', makeStep({
    id: 's-h1-late', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/source',
    json: { token: 'tok-abc' },
  }), { timestampMs: 2500, emittedCapabilities: [cap] })
  const revRes = verifyCompositeReceipt(mkReceipt('s-h1-late', 's-h2'), { entries: [ctrl, h1Late, h2Probe] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(revRes.confirmed, false)
  assert.equal(revRes.failedStage, 'edge_binding')
  assert.match(revRes.reason, /monotonic/i)

  // (h) Unrelated non-SEAL sourceExchangeId outside fromHop MUST fail at edge_binding
  const unrelated = signedEntry('s-other', makeStep({
    id: 's-other', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/other',
    json: { ok: true },
  }), { timestampMs: 950, emittedCapabilities: [cap] })
  const badSrcRes = verifyCompositeReceipt(mkReceipt('s-h1', 's-h2', { sourceExchangeId: 's-other' }), { entries: [ctrl, h1Ok, h2Probe, unrelated] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(badSrcRes.confirmed, false)
  assert.equal(badSrcRes.failedStage, 'edge_binding')
})

// ============================================================================
// 3. Live VerifyRpcServer + VerifyContext SDK + HostFactLog End-to-End
// ============================================================================

async function startLiveFixture(t: test.TestContext): Promise<{ origin: string; server: VerifyRpcServer }> {
  const SESSION_TOK = 'live-session-tok-member-a-999'
  const JOB_HANDLE = 'job-m2-live-handle-888'
  let itemFlag = 'draft'

  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/login' && req.method === 'POST') {
      return json(res, 200, { token: SESSION_TOK }, { 'set-cookie': `sid=${SESSION_TOK}; Path=/; HttpOnly` })
    }
    if (url.pathname === '/api/v1/jobs' && req.method === 'POST') {
      if (req.headers.authorization !== `Bearer ${SESSION_TOK}`) return json(res, 401, { error: 'unauth' })
      return json(res, 200, { jobId: JOB_HANDLE })
    }
    if (url.pathname === `/api/v1/jobs/${JOB_HANDLE}/export` && req.method === 'GET') {
      if (req.headers.authorization !== `Bearer ${SESSION_TOK}`) return json(res, 403, { error: 'forbidden' })
      return json(res, 200, { tenantId: 'org_victim', records: [{ id: 'v-1', balance: 7700 }] })
    }
    if (url.pathname === '/api/v1/jobs/denied/export' && req.method === 'GET') {
      return json(res, 403, { error: 'forbidden' })
    }
    if (url.pathname === '/api/v1/items/1' && req.method === 'GET') {
      return json(res, 200, { id: '1', status: itemFlag })
    }
    if (url.pathname === '/api/v1/items/1' && req.method === 'PATCH') {
      const parsed = JSON.parse((await readBody(req)) || '{}') as { status?: string }
      if (parsed.status) itemFlag = parsed.status
      return json(res, 200, { id: '1', status: itemFlag })
    }
    return json(res, 404, { error: 'not found' })
  })
  const port = await new Promise<number>((resolvePort, reject) => {
    httpServer.once('error', reject)
    httpServer.listen(0, '127.0.0.1', () => {
      const addr = httpServer.address()
      if (!addr || typeof addr === 'string') reject(new Error('no port'))
      else resolvePort(addr.port)
    })
  })
  const origin = `http://127.0.0.1:${port}`
  t.after(() => new Promise<void>(r => { httpServer.closeAllConnections(); httpServer.close(() => r()) }))

  const actor: ResolvedPersona = {
    id: 'persona-member-a',
    handle: 'member_a',
    roleLabel: 'member (org_a)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: 'member-a-live-secret-01',
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin,
    tier: 3,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['member_a', actor]]),
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: `run-fix-m2-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-fix-m2',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)
  return { origin, server }
}

test('Live SDK: ChainBuilder tracks multi-cap URL+bearer, between-hop seal_capability, setup hop_1, and HostFactLog fallback', async t => {
  const { server } = await startLiveFixture(t)
  const ctx = new VerifyContext()

  // Login & seal bearer token via `setCookie` alias + `exchange` string alias
  const loginEx = await ctx.http_send('/login', { as: 'member_a', role: 'setup', method: 'POST' })
  assert.equal(loginEx.status, 200)
  const cookieCap = await ctx.seal_capability({ exchange: loginEx.exchangeId, hopId: 'setup', slot: 'sid', setCookie: 'sid' })
  assert.match(cookieCap.handle, /^cap:/)
  const sessionCap = await ctx.seal_capability({ exchangeId: loginEx, hopReceiptId: 'setup', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
  assert.match(sessionCap.handle, /^cap:/)

  // 3a. ChainBuilder: hop_1 uses role:'setup', seal_capability runs BETWEEN hop_1 and hop_2,
  //     hop_2 sends BOTH bearer sessionCap AND URL-interpolated jobCap -> must auto-wire value_binding and CONFIRM!
  const chain = ctx.chain('live-m2-multicap', 'cross_tenant_read')
  const h1 = await chain.hop('hop_1', { claimedDelta: 'Created export job in setup hop.' }, () =>
    ctx.http_send('/api/v1/jobs', { as: 'member_a', role: 'setup', method: 'POST', capability: { handle: sessionCap.handle, target: 'bearer' } }),
  )
  assert.equal(h1.status, 200)
  // Sealed OUTSIDE chain.hop — ChainBuilder must still link jobCap back to hop_1!
  const jobCap = await ctx.seal_capability({ exchange: h1, slot: 'job_id', jsonPath: '$.jobId' })

  const ctrl = await ctx.http_send(`/api/v1/jobs/${jobCap.handle}/export`, { as: 'member_a', role: 'control' })
  assert.equal(ctrl.status, 403)
  chain.control(ctrl)

  const h2 = await chain.hop('hop_2', { claimedDelta: 'Exported foreign tenant data.' }, () =>
    ctx.http_send(`/api/v1/jobs/${jobCap.handle}/export`, { as: 'member_a', role: 'probe', capability: { handle: sessionCap.handle, target: 'bearer' } }),
  )
  assert.equal(h2.status, 200)
  chain.readback(h2)

  const built = chain.build({ claimedImpact: 'Cross-tenant export confirmed via setup hop + multi-cap URL binding.' })
  assert.ok(
    built.causalEdges?.some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2' && e.capabilityHandle === jobCap.handle),
    `Expected auto-wired value_binding for jobCap, got: ${JSON.stringify(built.causalEdges)}`,
  )
  const proved = await chain.prove({ claimedImpact: 'Cross-tenant export confirmed via setup hop + multi-cap URL binding.' })
  assert.equal(proved.confirmed, true, `Expected live chain.prove() to confirm, got: ${JSON.stringify(proved)}`)

  // 3b. Manual prove_composite with `{ exchangeId }` / `{ handle }` refs and `edges` alias normalizes cleanly
  const manualRes = await ctx.prove_composite({
    chainId: 'live-m2-manual-aliases',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', target: { origin: ctx.targetOrigin, method: 'POST', path: '/api/v1/jobs' } as never, exchangeIds: [h1 as never], claimedDelta: 'Created job.', producedCapabilities: [jobCap as never] },
      { hopId: 'hop_2', target: { origin: ctx.targetOrigin, method: 'GET', path: `/api/v1/jobs/${jobCap.handle}/export` } as never, exchangeIds: [h2 as never], claimedDelta: 'Downloaded foreign export.', consumedCapabilities: [jobCap as never] },
    ],
    edges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: jobCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Manual receipt with object refs and edges alias confirmed.',
      terminalExchangeId: h2 as never,
      preChainControlExchangeIds: [ctrl as never],
    },
  } as never)
  assert.equal(manualRes.confirmed, true, `Expected manual normalized prove_composite to confirm: ${JSON.stringify(manualRes)}`)

  // 3c. prove_persisted_mutation aliases (`read` + `mutate`) work cleanly
  const mutRes = await ctx.prove_persisted_mutation({
    read: '/api/v1/items/1',
    mutate: { path: '/api/v1/items/1', method: 'PATCH', body: { status: 'published' }, as: 'member_a' },
    fieldPath: 'status',
    expectDelta: 'published',
  })
  assert.equal(mutRes.delta.changed, true)
  assert.equal(mutRes.delta.after, 'published')

  // 3d. HostFactLog.fromTranscriptStore (without hostTranscript) preserves consumedCapabilityId & capability artifact handles
  const storeLog = HostFactLog.fromTranscriptStore(server.transcript)
  const h2Fact = storeLog.getExchange(h2.exchangeId)
  assert.ok(h2Fact?.consumedCapabilities?.length, 'HostFactLog.fromTranscriptStore must populate consumedCapabilities from consumedCapabilityId')
  const sealFact = storeLog.getExchange(jobCap.sealExchangeId)
  assert.ok(sealFact?.emittedCapabilities?.includes(jobCap.handle), 'HostFactLog.fromTranscriptStore must populate emittedCapabilities on capability records')
})

// ============================================================================
// 4. Static Ceilings & Anti-Contamination Guards
// ============================================================================

test('LOC ceilings (composite-receipt <= 750, kovo_verify <= 800), zero new RegExp(), and zero benchmark literals hold', () => {
  const compSrc = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8')
  const sdkSrc = readFileSync(join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts'), 'utf8')
  const compLoc = compSrc.trimEnd().split('\n').length
  const sdkLoc = sdkSrc.trimEnd().split('\n').length
  assert.ok(compLoc <= 750, `composite-receipt.ts=${compLoc} > 750`)
  assert.ok(sdkLoc <= 800, `kovo_verify.ts=${sdkLoc} > 800`)
  assert.equal(/\bnew\s+RegExp\s*\(/.test(compSrc), false, 'composite-receipt.ts must not use new RegExp()')
  assert.equal(/\bnew\s+RegExp\s*\(/.test(sdkSrc), false, 'kovo_verify.ts must not use new RegExp()')
  for (const forbidden of ['paygrid', 'shipforge', 'nexusiam', 'connecthub']) {
    assert.equal(compSrc.toLowerCase().includes(forbidden), false, `composite-receipt.ts must not contain "${forbidden}"`)
    assert.equal(sdkSrc.toLowerCase().includes(forbidden), false, `kovo_verify.ts must not contain "${forbidden}"`)
  }
})
