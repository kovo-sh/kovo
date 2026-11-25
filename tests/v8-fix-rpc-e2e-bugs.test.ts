/**
 * Regression suite for the 3 engine bugs uncovered by full-stack RPC E2E verification:
 *  1. `verify-rpc.ts` (`handleCompositeVerify`): `chainId` and `route` scrubbed before
 *     `recordCompositeVerification` so `TranscriptStore` record and returned `claim` match
 *     under `evaluateClaim` even when `chainId`/`route` embeds a sealed value or persona secret.
 *  2. `composite-receipt.ts` (`dispatchDefaultV8Oracle` for `cross_surface_pivot`):
 *     source hops receive outgoing `async_pivot_binding` / `state_transition_binding`
 *     correlation tokens so default dispatch (without explicit `oracleInput`) passes.
 *  3. `redact.ts`: camelCase secret JSON keys (`vaultToken`, `downloadToken`, `signingKey`,
 *     `accessToken`, etc.) are redacted while preserving valid JSON and benign fields
 *     (`tokenType`, `tokenCount`, `secretCount`, `maxTokens`, `csrf`, `null`, nested objects).
 */
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
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
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { redact, redactJsonValue, redactZdrJsonValue, scanSecrets, sha256Prefix } from '../src/server/redact.ts'
import { evaluateClaim, type VerifyClaim } from '../src/server/verify-claims.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/guardian_verify/guardian_verify.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const MEMBER_A_BEARER = 'member_a_fixture_bearer_99887766'
const VAULT_TOKEN = 'vault_tok_camel_445566778899'
const DOWNLOAD_TOKEN = 'download_tok_camel_1122334455'
const SIGNING_KEY = 'signing_key_camel_aabbccddeeff'
const ACCESS_TOKEN = 'access_tok_camel_556677889900'
const SEALED_ORDER_ID = 'ord_sealed_778899aabb'

function jsonRes(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

const fixture = createServer((req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : ''

  if (url.pathname === '/v1/camel-secrets' && req.method === 'GET') {
    return jsonRes(res, 200, {
      vaultToken: VAULT_TOKEN,
      downloadToken: DOWNLOAD_TOKEN,
      signingKey: SIGNING_KEY,
      accessToken: ACCESS_TOKEN,
      tokenType: 'Bearer',
      tokenCount: 4,
      secretCount: 2,
      maxTokens: 4096,
      csrf: 'public-csrf-marker',
      nullableToken: null,
      nested: { token: { type: 'string' } },
    })
  }

  if (url.pathname === '/v1/orders' && req.method === 'POST') {
    if (auth !== `Bearer ${MEMBER_A_BEARER}`) return jsonRes(res, 401, { error: 'auth required' })
    return jsonRes(res, 201, { orderId: SEALED_ORDER_ID, owner: 'org_a' })
  }

  if (url.pathname === `/v1/orders/${SEALED_ORDER_ID}/export` && req.method === 'GET') {
    if (req.headers['x-vault-token'] === VAULT_TOKEN) {
      return jsonRes(res, 200, { tenant: 'org_b', orderId: SEALED_ORDER_ID, exportedData: 'foreign-tenant-ledger-row' })
    }
    return jsonRes(res, 403, { error: 'forbidden' })
  }

  return jsonRes(res, 404, { error: 'not_found' })
})

const port = await new Promise<number>((resolvePort, reject) => {
  fixture.once('error', reject)
  fixture.listen(0, '127.0.0.1', () => {
    const addr = fixture.address()
    if (!addr || typeof addr === 'string') reject(new Error('no port'))
    else resolvePort(addr.port)
  })
})
const origin = `http://127.0.0.1:${port}`
test.after(() => new Promise<void>(r => { fixture.closeAllConnections(); fixture.close(() => r()) }))

function makeGrant(): Grant {
  const memberA: ResolvedPersona = {
    id: 'persona-member-a', handle: 'member_a', roleLabel: 'member (org_a)',
    originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: MEMBER_A_BEARER, canaryMarkers: [],
  }
  return {
    origin, tier: 3, allowLocalLab: true, allowedPorts: [port], maxRpsPerOrigin: 200,
    personas: new Map([['member_a', memberA]]),
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
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

async function startRpc(t: test.TestContext): Promise<{ server: VerifyRpcServer; ctx: VerifyContext }> {
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(),
    runId: `run-fix-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-fix',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  t.after(bindEnv(server))
  return { server, ctx: new VerifyContext() }
}

// ============================================================================
// 1. Bug 1: handleCompositeVerify chainId/route scrub agreement with TranscriptStore
// ============================================================================

test('Bug 1: handleCompositeVerify scrubs chainId and route before TranscriptStore recording so evaluateClaim matches', async (t) => {
  const { server, ctx } = await startRpc(t)

  const orderEx = await ctx.http_send('/v1/orders', { method: 'POST', as: 'member_a', role: 'probe' })
  assert.equal(orderEx.status, 201)
  const capOrder = await ctx.seal_capability({ exchange: orderEx, hopReceiptId: 'h1', slot: 'order_id', jsonPath: '$.orderId' })

  const secretEx = await ctx.http_send('/v1/camel-secrets', { method: 'GET', as: 'member_a', role: 'probe' })
  assert.equal(secretEx.status, 200)
  const capVault = await ctx.seal_capability({ exchange: secretEx, hopReceiptId: 'h1', slot: 'vault_tok', jsonPath: '$.vaultToken' })

  const ctrlEx = await ctx.http_send(`/v1/orders/${SEALED_ORDER_ID}/export`, { method: 'GET', as: 'member_a', role: 'control' })
  assert.equal(ctrlEx.status, 403)

  const termEx = await ctx.http_send(`/v1/orders/${capOrder.handle}/export`, {
    method: 'GET',
    as: 'member_a',
    role: 'probe',
    headers: { 'X-Vault-Token': capVault.handle },
  })
  assert.equal(termEx.status, 200)

  // Embed BOTH the sealed orderId AND the persona bearer secret in chainId/route to verify full scrub parity.
  const verifyRes = await ctx.prove_composite({
    chainId: `chain-econ-${SEALED_ORDER_ID}`,
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin, method: 'GET', pathAndQuery: '/v1/camel-secrets' },
        exchangeIds: [orderEx.exchangeId, secretEx.exchangeId],
        producedCapabilities: [capOrder.handle, capVault.handle],
        claimedDelta: 'Issued order identifier and vault token capability',
      },
      {
        hopId: 'hop_2',
        surface: 'storage',
        target: { origin, method: 'GET', pathAndQuery: `/v1/orders/${SEALED_ORDER_ID}/export` },
        exchangeIds: [termEx.exchangeId],
        consumedCapabilities: [capOrder.handle, capVault.handle],
        claimedDelta: 'Read foreign tenant export record using sealed capabilities',
      },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capVault.handle },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: termEx.exchangeId,
      summary: 'Foreign tenant export record read across tenant boundary via sealed token',
      preChainControlExchangeIds: [ctrlEx.exchangeId],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  assert.equal(verifyRes.confirmed, true, `expected confirmed=true, got reason=${verifyRes.reason}`)
  const claim = verifyRes.claim as Extract<VerifyClaim, { kind: 'composite_receipt' }>
  assert.ok(claim && claim.kind === 'composite_receipt')
  assert.equal(claim.chainId.includes(SEALED_ORDER_ID), false, 'returned claim.chainId must scrub sealed value')
  assert.equal((claim.route ?? '').includes(SEALED_ORDER_ID), false, 'returned claim.route must scrub sealed value')

  assert.ok(claim.verificationId, 'claim.verificationId must be present')
  const hostRec = server.transcript.getCompositeVerification(claim.verificationId)
  assert.ok(hostRec, 'host composite verification record must exist')
  assert.equal(hostRec.chainId, claim.chainId, 'host record chainId must equal returned claim chainId')
  assert.equal(hostRec.route, claim.route ?? null, 'host record route must equal returned claim route')
  assert.equal(JSON.stringify(hostRec).includes(SEALED_ORDER_ID), false, 'host record must not leak raw sealed value')
  assert.equal(JSON.stringify(verifyRes).includes(SEALED_ORDER_ID), false, 'RPC response must not leak raw sealed value')

  const claimCheck = evaluateClaim(server.transcript, claim, {})
  assert.equal(claimCheck.passed, true, `evaluateClaim failed: ${claimCheck.detail}`)

  // Also test persona secret embedded in chainId
  const personaVerify = await ctx.prove_composite({
    chainId: `chain-persona-${MEMBER_A_BEARER}`,
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin, method: 'GET', pathAndQuery: '/v1/camel-secrets' },
        exchangeIds: [secretEx.exchangeId],
        producedCapabilities: [capVault.handle],
        claimedDelta: 'Issued vault token capability',
      },
      {
        hopId: 'hop_2',
        surface: 'storage',
        target: { origin, method: 'GET', pathAndQuery: `/v1/orders/${SEALED_ORDER_ID}/export` },
        exchangeIds: [termEx.exchangeId],
        consumedCapabilities: [capVault.handle],
        claimedDelta: 'Read foreign tenant export record using sealed vault token',
      },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capVault.handle },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: termEx.exchangeId,
      summary: 'Foreign tenant export record read across tenant boundary via sealed token',
      preChainControlExchangeIds: [ctrlEx.exchangeId],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })
  assert.equal(personaVerify.confirmed, true, `persona secret chainId verify failed: ${personaVerify.reason}`)
  const personaClaim = personaVerify.claim as Extract<VerifyClaim, { kind: 'composite_receipt' }>
  assert.equal(personaClaim.chainId.includes(MEMBER_A_BEARER), false, 'persona secret must be scrubbed from chainId')
  assert.equal(evaluateClaim(server.transcript, personaClaim, {}).passed, true, 'evaluateClaim must pass when chainId embeds persona secret')
})

// ============================================================================
// 2. Bug 2: Default cross_surface_pivot dispatch with async_pivot & state_transition
// ============================================================================

const ORACLE_SIGNING_KEY = 'fix-rpc-e2e-composite-signing-key-0123456789'

function makeStep(overrides: Partial<ImpactStep> & { id: string }): ImpactStep {
  return {
    arm: 'probe',
    method: 'POST',
    route: '/v1/step',
    pathAndQuery: '/v1/step',
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: 'lax' },
    body: JSON.stringify({ ok: true, tenant: 'org_b', data: 'cross-tenant-record' }),
    json: { ok: true, tenant: 'org_b', data: 'cross-tenant-record' },
    requestHeaders: {},
    responseHeaders: { 'content-type': 'application/json' },
    durationMs: 4,
    ...overrides,
  }
}

function makeSignedTranscript(entries: HostTranscriptEntry[], asyncPollRecords?: HostSignedTranscript['asyncPollRecords']): HostSignedTranscript {
  return {
    entries: entries.map(e => ({ ...e, hostSignature: signHostRecord(e, ORACLE_SIGNING_KEY) })),
    ...(asyncPollRecords ? { asyncPollRecords: asyncPollRecords.map(p => ({ ...p, hostSignature: signHostRecord(p, ORACLE_SIGNING_KEY) })) } : {}),
  }
}

test('Bug 2a: default cross_surface_pivot dispatch succeeds for 4-hop chain with async_pivot_binding without explicit oracleInput', () => {
  const corrId = 'job_pivot_7741'
  const capSign = 'cap:hop_1:sign_key'
  const capDl = 'cap:hop_3:dl_tok'
  const dlDigest = sha256Hex('dl-artifact-7741')

  const exCtrl: HostTranscriptEntry = {
    exchangeId: 'gx-ctrl-term',
    timestampMs: 900,
    actorPersona: 'member_a',
    cleanSession: true,
    step: makeStep({
      id: 'gx-ctrl-term', arm: 'control', method: 'GET', route: '/v1/storage/export', pathAndQuery: '/v1/storage/export',
      status: 403, body: '{"error":"forbidden"}', json: { error: 'forbidden' },
    }),
  }
  const ex1: HostTranscriptEntry = {
    exchangeId: 'gx-hop-1',
    timestampMs: 1000,
    actorPersona: 'member_a',
    emittedCapabilities: [capSign],
    step: makeStep({
      id: 'gx-hop-1', method: 'GET', route: '/v1/keys', pathAndQuery: '/v1/keys',
      body: '{"key":"[redacted]"}', json: { key: '[redacted]' },
    }),
  }
  const ex2: HostTranscriptEntry = {
    exchangeId: 'gx-hop-2',
    timestampMs: 1100,
    actorPersona: 'member_a',
    correlationIds: [corrId],
    cryptoAttestations: [{ derivedFromCapabilityId: capSign, alg: 'HS256', artifactDigest: sha256Hex('sig-2'), timestampMs: 1100 }],
    step: makeStep({
      id: 'gx-hop-2', method: 'POST', route: '/v1/webhooks/dispatch', pathAndQuery: '/v1/webhooks/dispatch',
      status: 202, body: JSON.stringify({ accepted: true, jobId: corrId }), json: { accepted: true, jobId: corrId },
    }),
  }
  const ex3: HostTranscriptEntry = {
    exchangeId: 'gx-hop-3',
    timestampMs: 1300,
    actorPersona: 'member_a',
    correlationIds: [corrId],
    emittedCapabilities: [capDl],
    observedResponseDigests: [dlDigest],
    step: makeStep({
      id: 'gx-hop-3', method: 'GET', route: `/v1/jobs/${corrId}`, pathAndQuery: `/v1/jobs/${corrId}`,
      status: 200, body: JSON.stringify({ status: 'ready', jobId: corrId, downloadToken: '[redacted]' }),
      json: { status: 'ready', jobId: corrId, downloadToken: '[redacted]' },
    }),
  }
  const ex4: HostTranscriptEntry = {
    exchangeId: 'gx-hop-4',
    timestampMs: 1400,
    actorPersona: 'member_a',
    consumedCapabilities: [capDl],
    step: makeStep({
      id: 'gx-hop-4', method: 'GET', route: '/v1/storage/export', pathAndQuery: '/v1/storage/export',
      status: 200, body: JSON.stringify({ tenant: 'org_b', records: [{ id: 'rec-1', secret: 'victim-row' }] }),
      json: { tenant: 'org_b', records: [{ id: 'rec-1', secret: 'victim-row' }] },
    }),
  }

  const transcript = makeSignedTranscript([exCtrl, ex1, ex2, ex3, ex4], [{
    id: 'poll-1',
    triggerExchangeId: 'gx-hop-2',
    tTriggerMs: 1100,
    tObservedMs: 1300,
    converged: true,
    correlationIds: [corrId],
    emittedCapabilities: [capDl],
  }])

  const receipt: CompositeProofReceipt = {
    chainId: 'chain-cross-surface-async',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/v1/keys' }, exchangeIds: ['gx-hop-1'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [capSign], consumedCapabilities: [], claimedDelta: 'Obtained signing key' },
      { hopId: 'hop_2', surface: 'webhook', target: { origin, method: 'POST', pathAndQuery: '/v1/webhooks/dispatch' }, exchangeIds: ['gx-hop-2'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [], consumedCapabilities: [], claimedDelta: 'Triggered signed webhook job' },
      { hopId: 'hop_3', surface: 'async_job', target: { origin, method: 'GET', pathAndQuery: `/v1/jobs/${corrId}` }, exchangeIds: ['gx-hop-3'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [capDl], consumedCapabilities: [], claimedDelta: 'Polled async job completion' },
      { hopId: 'hop_4', surface: 'storage', target: { origin, method: 'GET', pathAndQuery: '/v1/storage/export' }, exchangeIds: ['gx-hop-4'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [], consumedCapabilities: [capDl], claimedDelta: 'Exfiltrated foreign tenant storage export' },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: capSign, alg: 'HS256' },
      { kind: 'async_pivot_binding', fromHopId: 'hop_2', toHopId: 'hop_3', correlationId: corrId, channel: 'poll_convergence', pollRecordId: 'poll-1' },
      { kind: 'value_binding', fromHopId: 'hop_3', toHopId: 'hop_4', capabilityHandle: capDl },
    ],
    terminalImpact: {
      terminalHopId: 'hop_4',
      terminalExchangeId: 'gx-hop-4',
      claimedImpact: 'Cross-surface async pivot exposed foreign tenant storage export records',
      summary: 'Cross-surface async pivot exposed foreign tenant storage export records',
      preChainControlExchangeIds: ['gx-ctrl-term'],
      postChainReadbackExchangeIds: [],
      // Deliberately omit oracleInput to exercise dispatchDefaultV8Oracle!
    },
    replayMode: 'fresh_clean_replay',
  }

  const verdict = verifyCompositeReceipt(receipt, transcript, { signingKey: ORACLE_SIGNING_KEY })
  assert.equal(verdict.confirmed, true, `expected default cross_surface_pivot dispatch to pass, got: ${verdict.reason}`)
  assert.equal(verdict.terminalOracleFamily, 'cross_surface_pivot')
})

test('Bug 2b: default cross_surface_pivot dispatch succeeds for state_transition_binding without explicit oracleInput', () => {
  const entityId = 'ent_pivot_505'
  const exAbl: HostTranscriptEntry = {
    exchangeId: 'gx-abl-ctrl',
    timestampMs: 900,
    actorPersona: 'member_a',
    cleanSession: true,
    replayAttempt: 'ablation_control',
    entityId,
    step: makeStep({
      id: 'gx-abl-ctrl', arm: 'control', method: 'GET', route: `/v1/storage/${entityId}`, pathAndQuery: `/v1/storage/${entityId}`,
      status: 403, body: '{"error":"forbidden"}', json: { error: 'forbidden' },
    }),
  }
  const ex1: HostTranscriptEntry = {
    exchangeId: 'gx-st-1',
    timestampMs: 1000,
    actorPersona: 'member_a',
    entityId,
    step: makeStep({
      id: 'gx-st-1', method: 'POST', route: `/v1/acl/${entityId}`, pathAndQuery: `/v1/acl/${entityId}`,
      status: 200, body: JSON.stringify({ updated: true, entityId }), json: { updated: true, entityId },
    }),
  }
  const ex2: HostTranscriptEntry = {
    exchangeId: 'gx-st-2',
    timestampMs: 1200,
    actorPersona: 'member_a',
    entityId,
    step: makeStep({
      id: 'gx-st-2', method: 'GET', route: `/v1/storage/${entityId}`, pathAndQuery: `/v1/storage/${entityId}`,
      status: 200, body: JSON.stringify({ tenant: 'org_b', entityId, content: 'cross-tenant-blob' }),
      json: { tenant: 'org_b', entityId, content: 'cross-tenant-blob' },
    }),
  }

  const transcript = makeSignedTranscript([exAbl, ex1, ex2])
  const receipt: CompositeProofReceipt = {
    chainId: 'chain-cross-surface-state',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/v1/acl/${entityId}` }, exchangeIds: ['gx-st-1'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [], consumedCapabilities: [], entityId, claimedDelta: 'Mutated ACL state for entity' },
      { hopId: 'hop_2', surface: 'storage', target: { origin, method: 'GET', pathAndQuery: `/v1/storage/${entityId}` }, exchangeIds: ['gx-st-2'], oobEventIds: [], browserTraceIds: [], producedCapabilities: [], consumedCapabilities: [], entityId, claimedDelta: 'Read foreign tenant storage blob after ACL mutation' },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId, ablationExchangeIds: ['gx-abl-ctrl'] },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'gx-st-2',
      claimedImpact: 'Cross-surface state transition exposed foreign tenant storage entity',
      summary: 'Cross-surface state transition exposed foreign tenant storage entity',
      preChainControlExchangeIds: ['gx-abl-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const verdict = verifyCompositeReceipt(receipt, transcript, { signingKey: ORACLE_SIGNING_KEY })
  assert.equal(verdict.confirmed, true, `expected state_transition cross_surface_pivot to pass, got: ${verdict.reason}`)
  assert.equal(verdict.terminalOracleFamily, 'cross_surface_pivot')
})

// ============================================================================
// 3. Bug 3: redact.ts camelCase secret JSON keys + signingKey + benign exclusions
// ============================================================================

test('Bug 3: redact(), redactJsonValue(), scanSecrets(), and live broker scrub camelCase secret keys while preserving valid JSON and benign fields', async (t) => {
  const sampleObj = {
    vaultToken: VAULT_TOKEN,
    downloadToken: DOWNLOAD_TOKEN,
    signingKey: SIGNING_KEY,
    webhookSigningKey: 'wsk_live_9876543210',
    signing_key: 'sk_snake_1234567890',
    accessToken: ACCESS_TOKEN,
    refreshToken: 'ref_tok_11223344',
    privateKey: 'pk_raw_99887766',
    apiKey: 'ak_raw_55443322',
    userPassword: 'pw_raw_112233',
    adminPasswd: 'pwd_raw_445566',
    hmacSecret: 'hmac_raw_778899',
    sessionId: 'sid_raw_001122',
    // Benign fields that MUST remain intact:
    tokenType: 'Bearer',
    token_type: 'Bearer',
    tokenCount: 5,
    token_count: 5,
    secretCount: 2,
    maxTokens: 4096,
    secretary: 'alice',
    csrf: 'public-csrf-marker',
    nullableToken: null,
    nested: { token: { type: 'string' } },
    note: 'diagnostic with accessToken=inline_leak_42 inside json string',
  }

  const redactedStr = redact(JSON.stringify(sampleObj))
  const parsed = JSON.parse(redactedStr) as Record<string, unknown>

  for (const key of [
    'vaultToken', 'downloadToken', 'signingKey', 'webhookSigningKey', 'signing_key',
    'accessToken', 'refreshToken', 'privateKey', 'apiKey', 'userPassword', 'adminPasswd', 'hmacSecret', 'sessionId',
  ]) {
    assert.equal(parsed[key], '[redacted]', `expected JSON key "${key}" to be redacted`)
  }
  assert.equal(redactedStr.includes(VAULT_TOKEN), false)
  assert.equal(redactedStr.includes(DOWNLOAD_TOKEN), false)
  assert.equal(redactedStr.includes(SIGNING_KEY), false)
  assert.equal(redactedStr.includes(ACCESS_TOKEN), false)
  assert.equal(redactedStr.includes('inline_leak_42'), false)

  // Benign fields preserved
  assert.equal(parsed.tokenType, 'Bearer')
  assert.equal(parsed.token_type, 'Bearer')
  assert.equal(parsed.tokenCount, 5)
  assert.equal(parsed.token_count, 5)
  assert.equal(parsed.secretCount, 2)
  assert.equal(parsed.maxTokens, 4096)
  assert.equal(parsed.secretary, 'alice')
  assert.equal(parsed.csrf, 'public-csrf-marker')
  assert.equal(parsed.nullableToken, null)
  assert.deepEqual(parsed.nested, { token: { type: 'string' } })

  // Plain-text forms
  const plain = redact('vaultToken=vt_plain_99 signingKey="sk_plain_88" tokenType=opaque tokenCount=5 secretCount=1 maxTokens=4096 secretary=keep_public csrf=ok')
  assert.equal(plain.includes('vt_plain_99'), false)
  assert.equal(plain.includes('sk_plain_88'), false)
  assert.ok(plain.includes('tokenType=opaque'))
  assert.ok(plain.includes('tokenCount=5'))
  assert.ok(plain.includes('secretCount=1'))
  assert.ok(plain.includes('maxTokens=4096'))
  assert.ok(plain.includes('secretary=keep_public'))
  assert.ok(plain.includes('csrf=ok'))

  // redactJsonValue & redactZdrJsonValue parity
  const rjv = redactJsonValue({ vaultToken: VAULT_TOKEN, signingKey: SIGNING_KEY, tokenType: 'Bearer', maxTokens: 4096, csrf: 'ok' })
  assert.equal(rjv.vaultToken, '[redacted]')
  assert.equal(rjv.signingKey, '[redacted]')
  assert.equal(rjv.tokenType, 'Bearer')
  assert.equal(rjv.maxTokens, 4096)
  assert.equal(rjv.csrf, 'ok')

  const rzdr = redactZdrJsonValue({ downloadToken: DOWNLOAD_TOKEN, signingKey: SIGNING_KEY, tokenCount: 7 })
  assert.equal(rzdr.downloadToken, '[redacted]')
  assert.equal(rzdr.signingKey, '[redacted]')
  assert.equal(rzdr.tokenCount, 7)

  // scanSecrets fingerprints camelCase secret values without leaking raw bytes
  const matches = scanSecrets(JSON.stringify({ vaultToken: VAULT_TOKEN, signingKey: SIGNING_KEY }))
  assert.ok(matches.some(m => m.kind === 'key_value' && m.sha256Prefix === sha256Prefix(VAULT_TOKEN)))
  assert.ok(matches.some(m => m.kind === 'key_value' && m.sha256Prefix === sha256Prefix(SIGNING_KEY)))
  assert.equal(JSON.stringify(matches).includes(VAULT_TOKEN), false)
  assert.equal(JSON.stringify(matches).includes(SIGNING_KEY), false)

  // Live broker + VerifyRpcServer: worker sees redacted JSON, while seal_capability extracts the real raw secret
  const { ctx } = await startRpc(t)
  const ex = await ctx.http_send('/v1/camel-secrets', { method: 'GET', as: 'member_a' })
  assert.equal(ex.status, 200)
  const bodyJson = ex.json as Record<string, unknown>
  assert.equal(bodyJson.vaultToken, '[redacted]')
  assert.equal(bodyJson.downloadToken, '[redacted]')
  assert.equal(bodyJson.signingKey, '[redacted]')
  assert.equal(bodyJson.accessToken, '[redacted]')
  assert.equal(bodyJson.tokenType, 'Bearer')
  assert.equal(bodyJson.tokenCount, 4)
  assert.equal(bodyJson.secretCount, 2)
  assert.equal(bodyJson.maxTokens, 4096)
  assert.equal(bodyJson.csrf, 'public-csrf-marker')
  assert.equal(bodyJson.nullableToken, null)
  assert.deepEqual(bodyJson.nested, { token: { type: 'string' } })
  assert.equal(ex.body.includes(VAULT_TOKEN), false)
  assert.equal(ex.body.includes(SIGNING_KEY), false)

  const capSigning = await ctx.seal_capability({ exchange: ex, hopReceiptId: 'h1', slot: 'sign_key', jsonPath: '$.signingKey', kind: 'hmac_key' })
  const sig = await ctx.hmac_sign({ secretHandle: capSigning.handle, payload: 'hello-world', alg: 'sha256', encoding: 'hex' })
  assert.equal(sig.signature, createHmac('sha256', SIGNING_KEY).update('hello-world').digest('hex'))
})

// ============================================================================
// 4. LOC Ceilings & Zero Benchmark Contamination
// ============================================================================

test('LOC ceilings and zero benchmark contamination hold', () => {
  const loc = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8').trimEnd().split('\n').length
  assert.ok(loc('src/server/verify-rpc.ts') <= 2300, `verify-rpc.ts LOC=${loc('src/server/verify-rpc.ts')} > 2300`)
  assert.ok(loc('src/server/composite-receipt.ts') <= 750, `composite-receipt.ts LOC=${loc('src/server/composite-receipt.ts')} > 750`)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected contamination: ${JSON.stringify(scan.hits)}`)
})
