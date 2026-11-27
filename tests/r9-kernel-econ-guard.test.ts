// @kernel @fixes R3-05
/**
 * R9 Confirmation-Kernel Soundness & Custody Fixes Suite (`R3-05`):
 *  1. `syncVerifyArtifactsToLedger`: resolves ephemeral `"cap:..."` handles back to their owning
 *     approved base persona (never storing `"cap:..."` as `CapabilityNode.actorPersona`), and
 *     persists producer `endpoint`, `method`, and `fieldName` (when present) in `CapabilityNode.metadata`.
 *  2. `VerifyRpcServer` (`parseHttpArgs` / `applyCapabilityInjection`): auto-lifts sealed `cap:*`
 *     handles passed via `as` / `persona` into capability injection while preserving all vault scope,
 *     origin, and provenance invariants, and fails closed on unknown or conflicting `cap:*` handles.
 *  3. `balance_minting` (`hydrateBalanceMintingOperands`): deduplicates `authorizedDeposits` per
 *     distinct server-identified entity/order ID (and window-emitted non-auth capability lineage)
 *     without letting un-echoed request IDs or auth caps collapse real deposits, and requires an
 *     attacker-induced conservation break (race multiplicity, duplicate entity credit, internal
 *     transfer minting, negative-amount tampering, forged/control-denied credit, or a same-actor
 *     conserving benign control) — rejecting bare single benign captures fail-closed.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import '../src/server/terminal-oracle-registry.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'
import { CapabilityLedger } from '../src/server/capability-ledger.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import { syncVerifyArtifactsToLedger, type V8AgentScriptProofResult } from '../src/server/exec-verify.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { hydrateV8OracleInput } from '../src/server/v8-oracle-hydrate.ts'
import { VerifyRpcServer, VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER } from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'test-r9-kernel-econ-guard-signing-key-0123456789'

function makeStep(overrides: Partial<ImpactStep> & { id: string; arm: 'control' | 'probe' }): ImpactStep {
  return {
    method: 'GET',
    pathAndQuery: '/v1/resource',
    status: 200,
    actor: { handle: 'member_a', role: 'member', tenant: 'org_alpha', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry & { op?: string; raceBatchId?: string | null }> = {},
): HostTranscriptEntry {
  const rec = {
    exchangeId,
    origin: ORIGIN,
    timestampMs: extra.timestampMs ?? 1000,
    seq: extra.seq ?? 1,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : (step.actor.handle ?? 'member_a'),
    actorRoleLabel: extra.actorRoleLabel !== undefined ? extra.actorRoleLabel : 'member (org_alpha)',
    actorTenant: extra.actorTenant !== undefined ? extra.actorTenant : 'org_alpha',
    cleanSession: extra.cleanSession ?? true,
    step: { route: step.pathAndQuery?.split('?')[0], ...step },
    ...extra,
  } as HostTranscriptEntry
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

function verify(receipt: CompositeProofReceipt, entries: HostTranscriptEntry[]) {
  const transcript: HostSignedTranscript = { entries }
  return verifyCompositeReceipt(receipt, transcript, {
    signingKey: SIGNING_KEY,
    factLog: HostFactLog.fromTranscript(transcript),
    attackerPersonas: ['member_a'],
    personaRoleLabels: { member_a: 'member (org_alpha)' },
  })
}

async function rpcPost(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const http = await import('node:http')
  return await new Promise((resolve, reject) => {
    const payload = JSON.stringify({ op, args })
    const req = http.request({
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
      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => {
        try { resolve(JSON.parse(body)) } catch (e) { reject(e) }
      })
    })
    req.on('error', reject)
    req.write(payload)
    req.end()
  })
}

// ============================================================================
// 1. syncVerifyArtifactsToLedger: Base-Persona Resolution + Producer Metadata
// ============================================================================

test('1: syncVerifyArtifactsToLedger resolves ephemeral cap:* actorPersona to owning base persona and persists endpoint/method/fieldName metadata', () => {
  const ledger = new CapabilityLedger(':memory:', { runId: 'run-r9-sync-1' })
  const cap1 = 'cap:hop_h1:session_tok'
  const cap2 = 'cap:hop_h2:delegated_tok'
  const cap3 = 'cap:hop_h3:nested_key'

  const h1Entry = signedEntry('ex-1', makeStep({
    id: 'ex-1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/auth/session', status: 200,
    json: { sessionToken: 'tok_1' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_a', emittedCapabilities: [cap1] })
  const h2Entry = signedEntry('ex-2', makeStep({
    id: 'ex-2', arm: 'probe', method: 'GET', pathAndQuery: '/v1/delegations/export?format=json', status: 200,
    json: { delegation: { token: 'tok_2' } },
  }), { seq: 2, timestampMs: 1100, actorPersona: cap1, consumedCapabilities: [cap1], emittedCapabilities: [cap2] })
  const h3Entry = signedEntry('ex-3', makeStep({
    id: 'ex-3', arm: 'probe', method: 'POST', pathAndQuery: '/v1/keys/rotate', status: 201,
    json: { signing_salt: 'salt_3' },
  }), { seq: 3, timestampMs: 1200, actorPersona: cap2, consumedCapabilities: [cap2], emittedCapabilities: [cap3] })

  const proof: V8AgentScriptProofResult = {
    verdict: {
      confirmed: false, reason: 'checkpoint_only', detail: '', attempts: [],
      disagreements: [], claimTitle: null, rejectedBy: null, missingEvidence: [], transcriptSummary: [],
    },
    exchanges: [],
    receipt: null,
    compositeReceipt: null,
    vulnClass: null,
    transcriptDigests: [],
    sealedCapabilities: [
      {
        handle: cap1, runId: 'run-r9-sync-1', kind: 'bearer_token', hopReceiptId: 'h1', slot: 'session_tok',
        sha256: '1'.repeat(64), sha256Prefix: '11111111', createdAtMs: 1000, expiresAtMs: null, allowedOrigins: [ORIGIN],
      },
      {
        handle: cap2, runId: 'run-r9-sync-1', kind: 'api_token', hopReceiptId: 'h2', slot: 'delegated_tok',
        sha256: '2'.repeat(64), sha256Prefix: '22222222', createdAtMs: 1100, expiresAtMs: null,
        derivedFromCapabilityId: cap1, allowedOrigins: [ORIGIN],
      },
      {
        handle: cap3, runId: 'run-r9-sync-1', kind: 'signing_salt', hopReceiptId: 'h3', slot: 'nested_key',
        sha256: '3'.repeat(64), sha256Prefix: '33333333', createdAtMs: 1200, expiresAtMs: null,
        derivedFromCapabilityId: cap2, allowedOrigins: [ORIGIN],
      },
    ],
    transcriptRecords: [
      {
        exchangeId: 'ex-seal-1', seq: 1, op: 'capability', startedAt: 1005, durationMs: 0, signature: 's1',
        request: {
          origin: ORIGIN, method: 'SEAL', pathAndQuery: '/capability/seal/session_tok',
          headers: { 'x-kovo-seal-endpoint': '/v1/auth/session', 'x-kovo-seal-method': 'POST', 'x-kovo-seal-field': 'sessionToken' },
          bodyBytes: 0, bodySha256: 'a'.repeat(64), personaHandle: 'member_a', sessionRole: 'probe',
          actorRoleLabel: 'member (org_alpha)', actorTenant: 'org_alpha', actorPrivilege: 'member', nonce: 'n1',
        },
        artifact: { kind: 'capability', capabilityHandle: cap1 },
      },
      {
        exchangeId: 'ex-seal-2', seq: 2, op: 'capability', startedAt: 1105, durationMs: 0, signature: 's2',
        request: {
          origin: ORIGIN, method: 'SEAL', pathAndQuery: '/capability/seal/delegated_tok',
          headers: { 'x-kovo-seal-endpoint': '/v1/delegations/export', 'x-kovo-seal-method': 'GET', 'x-kovo-seal-field': 'delegation.token' },
          bodyBytes: 0, bodySha256: 'b'.repeat(64), personaHandle: cap1, sessionRole: 'probe',
          actorRoleLabel: 'member (org_alpha)', actorTenant: 'org_alpha', actorPrivilege: 'member', nonce: 'n1',
        },
        artifact: { kind: 'capability', capabilityHandle: cap2 },
      },
      {
        exchangeId: 'ex-seal-3', seq: 3, op: 'capability', startedAt: 1205, durationMs: 0, signature: 's3',
        request: {
          origin: ORIGIN, method: 'SEAL', pathAndQuery: '/capability/seal/nested_key',
          headers: { 'x-kovo-seal-endpoint': '/v1/keys/rotate', 'x-kovo-seal-method': 'POST', 'x-kovo-seal-field': 'signing_salt' },
          bodyBytes: 0, bodySha256: 'c'.repeat(64), personaHandle: cap2, sessionRole: 'probe',
          actorRoleLabel: 'member (org_alpha)', actorTenant: 'org_alpha', actorPrivilege: 'member', nonce: 'n1',
        },
        artifact: { kind: 'capability', capabilityHandle: cap3 },
      },
    ],
    hostTranscript: { entries: [h1Entry, h2Entry, h3Entry], oobEvents: [], browserTraces: [], asyncPollRecords: [] },
    claimTitle: null,
    severity: null,
    description: null,
  }

  syncVerifyArtifactsToLedger({ ledger, proof, defaultOrigin: ORIGIN, defaultPersona: 'fallback_user' })

  const n1 = ledger.getCapability(cap1)
  const n2 = ledger.getCapability(cap2)
  const n3 = ledger.getCapability(cap3)
  assert.ok(n1 && n2 && n3)

  // Every node resolves actorPersona back to base persona `member_a` — NEVER `cap:*`!
  for (const node of ledger.listCapabilities()) {
    assert.equal(node.actorPersona.startsWith('cap:'), false, `CapabilityNode ${node.capId} must never store cap:* as actorPersona`)
  }
  assert.equal(n1.actorPersona, 'member_a')
  assert.equal(n2.actorPersona, 'member_a')
  assert.equal(n3.actorPersona, 'member_a')

  // Producer endpoint, method, and fieldName persisted cleanly in CapabilityNode.metadata (never /capability/seal or SEAL)
  assert.equal(n1.metadata.endpoint, '/v1/auth/session')
  assert.equal(n1.metadata.method, 'POST')
  assert.equal(n1.metadata.fieldName, 'sessionToken')
  assert.equal(n2.metadata.endpoint, '/v1/delegations/export')
  assert.equal(n2.metadata.method, 'GET')
  assert.equal(n2.metadata.fieldName, 'delegation.token')
  assert.equal(n3.metadata.endpoint, '/v1/keys/rotate')
  assert.equal(n3.metadata.method, 'POST')
  assert.equal(n3.metadata.fieldName, 'signing_salt')
})

// ============================================================================
// 2. VerifyRpcServer: Auto-Lift `as`/`persona: "cap:..."` + Fail-Closed Unknown
// ============================================================================

test('2: VerifyRpcServer auto-lifts sealed cap:* passed via as/persona (http & race), stamps seal metadata headers, and fails closed on unknown/conflicting/out-of-scope cap:*', async () => {
  const seenAuths: string[] = []
  const seenCookies: string[] = []
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/v1/mint-token') {
      res.setHeader('set-cookie', 'sid=cookie_secret_val_998877; Path=/; HttpOnly')
      res.end(JSON.stringify({ access_token: 'sealed_bearer_val_112233' }))
      return
    }
    if (url.pathname === '/v1/protected') {
      const auth = String(req.headers.authorization ?? '')
      seenAuths.push(auth)
      if (auth === 'Bearer sealed_bearer_val_112233') {
        res.end(JSON.stringify({ ok: true, nested: { key: 'nested_secret_445566' } }))
      } else {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
      }
      return
    }
    if (url.pathname === '/v1/cookie-protected') {
      const ck = String(req.headers.cookie ?? '')
      seenCookies.push(ck)
      if (ck.includes('sid=cookie_secret_val_998877')) {
        res.end(JSON.stringify({ ok: true, via: 'cookie' }))
      } else {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
      }
      return
    }
    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not_found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const targetOrigin = `http://127.0.0.1:${port}`

  const scratch = mkdtempSync(join(tmpdir(), 'kovo-r9-rpc-'))
  const vault = new DerivedCapabilityVault({ runId: 'run-r9-rpc-2' })
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const personas = new Map([
    ['member_a', {
      id: 'member_a', handle: 'member_a', roleLabel: 'member (org_alpha)', tenantRef: 'org_alpha', privilege: 'member' as const,
      originAllowlist: [targetOrigin], authKind: 'bearer' as const, headerName: null, secret: 'base_member_tok', canaryMarkers: [],
      session: { headerType: 'bearer' as const, value: 'base_member_tok', adapterUsed: 'static' },
    }],
  ])
  const grant = makeLabGrant(targetOrigin, { tier: 3, personas })

  const rpc = new VerifyRpcServer({
    broker, grant, runId: 'run-r9-rpc-2', assignmentId: 'asg-r9-2',
    targetOrigins: [targetOrigin], capabilityVault: vault,
  })
  try {
    const started = await rpc.start()
    const { socketPath, token, nonce } = started

    // Mint + seal bearer token & cookie
    const mintRes = await rpcPost(socketPath, token, nonce, 'http.send', {
      origin: targetOrigin, method: 'POST', path: '/v1/mint-token', as: 'member_a', sessionGroupRole: 'probe',
    })
    assert.equal(mintRes.ok, true)
    const mintId = (mintRes.result as { exchangeId: string }).exchangeId

    const sealBearer = await rpcPost(socketPath, token, nonce, 'capability.seal', {
      exchangeId: mintId, hopReceiptId: 'login', slot: 'tok', jsonPath: '$.access_token', kind: 'bearer_token', allowedOrigins: [targetOrigin],
    })
    assert.equal(sealBearer.ok, true)
    const bearerHandle = (sealBearer.result as { handle: string }).handle

    const sealCookie = await rpcPost(socketPath, token, nonce, 'capability.seal', {
      exchangeId: mintId, hopReceiptId: 'login', slot: 'sid', setCookie: 'sid', kind: 'cookie', allowedOrigins: [targetOrigin],
    })
    assert.equal(sealCookie.ok, true)
    const cookieHandle = (sealCookie.result as { handle: string }).handle

    // Auto-lift `as: "cap:..."` into bearer capability injection
    const viaAs = await rpcPost(socketPath, token, nonce, 'http.send', {
      origin: targetOrigin, method: 'GET', path: '/v1/protected', as: bearerHandle, sessionGroupRole: 'probe',
    })
    assert.equal(viaAs.ok, true, `Expected as: cap:* to auto-lift cleanly, got error: ${viaAs.error}`)
    const viaAsObj = viaAs.result as { status: number; exchangeId: string; consumedCapabilityId: string }
    assert.equal(viaAsObj.status, 200)
    assert.equal(viaAsObj.consumedCapabilityId, bearerHandle)

    // Auto-lift `persona: "cap:..."` into cookie capability injection
    const viaPersonaCookie = await rpcPost(socketPath, token, nonce, 'http.send', {
      origin: targetOrigin, method: 'GET', path: '/v1/cookie-protected', persona: cookieHandle, sessionGroupRole: 'probe',
    })
    assert.equal(viaPersonaCookie.ok, true, `Expected persona: cap:* cookie to auto-lift, got error: ${viaPersonaCookie.error}`)
    assert.equal((viaPersonaCookie.result as { status: number }).status, 200)

    // Auto-lift `as: "cap:..."` inside `race` burst
    const viaRace = await rpcPost(socketPath, token, nonce, 'race', {
      requests: [
        { origin: targetOrigin, method: 'GET', path: '/v1/protected', as: bearerHandle },
        { origin: targetOrigin, method: 'GET', path: '/v1/protected', as: bearerHandle },
      ],
    })
    assert.equal(viaRace.ok, true, `Expected race with as: cap:* to auto-lift, got error: ${viaRace.error}`)
    const raceResults = (viaRace.result as { results: Array<{ status: number }> }).results
    assert.equal(raceResults.length, 2)
    assert.ok(raceResults.every(r => r.status === 200))

    // Seal a nested capability from the `viaAs` response (whose personaHandle is ephemeral `bearerHandle`)
    const sealNested = await rpcPost(socketPath, token, nonce, 'capability.seal', {
      exchangeId: viaAsObj.exchangeId, hopReceiptId: 'nested', slot: 'k', jsonPath: '$.nested.key', kind: 'api_token', allowedOrigins: [targetOrigin],
    })
    assert.equal(sealNested.ok, true)
    const nestedHandle = (sealNested.result as { handle: string }).handle

    // Sync real VerifyRpcServer transcript -> CapabilityLedger and verify actorPersona & metadata!
    const ledger = new CapabilityLedger(':memory:', { runId: 'run-r9-rpc-2' })
    syncVerifyArtifactsToLedger({
      ledger,
      defaultOrigin: targetOrigin,
      defaultPersona: 'fallback_actor',
      proof: {
        verdict: {
          confirmed: false, reason: 'checkpoint_only', detail: '', attempts: [],
          disagreements: [], claimTitle: null, rejectedBy: null, missingEvidence: [], transcriptSummary: [],
        },
        exchanges: [], receipt: null, compositeReceipt: null, vulnClass: null, transcriptDigests: [],
        sealedCapabilities: vault.list(),
        transcriptRecords: rpc.transcript.list(),
        hostTranscript: rpc.buildHostSignedTranscript(),
        claimTitle: null, severity: null, description: null,
      },
    })
    const nestedNode = ledger.getCapability(nestedHandle)
    assert.ok(nestedNode)
    assert.equal(nestedNode.actorPersona, 'member_a', 'Nested capability sealed under ephemeral cap handle must resolve to base persona member_a')
    assert.equal(nestedNode.metadata.endpoint, '/v1/protected')
    assert.equal(nestedNode.metadata.method, 'GET')
    assert.equal(nestedNode.metadata.fieldName, 'nested.key')

    // Fail-closed: unknown `cap:*` handle NOT in vault -> clear diagnostic
    const unknownCap = await rpcPost(socketPath, token, nonce, 'http.send', {
      origin: targetOrigin, method: 'GET', path: '/v1/protected', as: 'cap:hop_missing:nope',
    })
    assert.equal(unknownCap.ok, false)
    assert.match(unknownCap.error ?? '', /Unknown capability handle.*seal it first and pass \{ capability: handle \}/)

    // Fail-closed: conflicting `as: capA` + `capability: capB`
    const conflictingCap = await rpcPost(socketPath, token, nonce, 'http.send', {
      origin: targetOrigin, method: 'GET', path: '/v1/protected', as: bearerHandle, capability: cookieHandle,
    })
    assert.equal(conflictingCap.ok, false)
    assert.match(conflictingCap.error ?? '', /capability handle/i)

    // Fail-closed: out-of-scope origin still rejected even when auto-lifted
    const outOfScope = await rpcPost(socketPath, token, nonce, 'http.send', {
      origin: 'https://disallowed.example.invalid', method: 'GET', path: '/v1/protected', as: bearerHandle,
    })
    assert.equal(outOfScope.ok, false)

    // Verify real credentials were sent on the wire (not base persona token)
    assert.ok(seenAuths.length >= 3 && seenAuths.every(a => a === 'Bearer sealed_bearer_val_112233'))
    assert.ok(seenCookies.some(c => c.includes('sid=cookie_secret_val_998877')))
  } finally {
    await rpc.close()
    server.closeAllConnections()
    await new Promise<void>(r => server.close(() => r()))
    rmSync(scratch, { recursive: true, force: true })
  }
})

// ============================================================================
// 3. Economic Conservation (`balance_minting`): Per-Entity Dedup & Soundness
// ============================================================================

test('3A: balance_minting deduplicates echoed order amounts per distinct entity/order ID without letting un-echoed request IDs or auth caps collapse real deposits', () => {
  const ordCap = 'cap:hop_create:ord_500'
  const base = signedEntry('d-base', makeStep({
    id: 'd-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', status: 200,
    json: { tenant: 'org_alpha', balanceCents: 100000 },
  }), { seq: 1, timestampMs: 1000 })
  const create = signedEntry('d-create', makeStep({
    id: 'd-create', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders', status: 201,
    requestJson: { amountCents: 10000 },
    json: { order: { id: 'ord_500', amountCents: 10000, status: 'draft' } },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [ordCap] })
  const rebindCap = 'cap:hop_rebind:ord_500_auth'
  const rebind = signedEntry('d-rebind', makeStep({
    id: 'd-rebind', arm: 'probe', method: 'PATCH', pathAndQuery: '/v1/orders/ord_500/rebind', status: 200,
    json: { order: { id: 'ord_500', amountCents: 10000, status: 'authorized' } },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [ordCap], emittedCapabilities: [rebindCap] })
  // 2x concurrent race captures each echo order.amountCents = 10000 and double-credit (+20000 total).
  // Previously summing every 2xx mutation gave 10000*4 = 40000 and MASKED the real +20000 race overcredit!
  const race0 = signedEntry('d-race-0', makeStep({
    id: 'd-race-0', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_500/capture', status: 200,
    json: { order: { id: 'ord_500', amountCents: 10000, status: 'settled' } },
  }), { seq: 4, timestampMs: 1300, op: 'race', raceBatchId: 'rb_dedup_1', consumedCapabilities: [ordCap, rebindCap] })
  const race1 = signedEntry('d-race-1', makeStep({
    id: 'd-race-1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_500/capture', status: 200,
    json: { order: { id: 'ord_500', amountCents: 10000, status: 'settled' } },
  }), { seq: 5, timestampMs: 1300, op: 'race', raceBatchId: 'rb_dedup_1', consumedCapabilities: [ordCap, rebindCap] })
  const fin = signedEntry('d-fin', makeStep({
    id: 'd-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', status: 200,
    json: { tenant: 'org_alpha', balanceCents: 120000 },
  }), { seq: 6, timestampMs: 1400 })

  const entries = [base, create, rebind, race0, race1, fin]
  const hydrated = hydrateV8OracleInput(
    'economic_conservation',
    { equation: 'balance_minting', baselineReadback: 'd-base', actions: ['d-race-0', 'd-race-1'], finalReadback: 'd-fin' },
    { entriesById: new Map(entries.map(e => [e.exchangeId, e])) },
    'sig',
  )
  assert.equal(hydrated.authorizedDeposits, 10000, 'Echoed order amounts for ord_500 must deduplicate to 10000 (not 40000)')

  const res = verify({
    chainId: 'r9-race-dedup-overcredit',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['d-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create order', producedCapabilities: [ordCap], consumedCapabilities: [] },
      { hopId: 'rebind', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_500/rebind' }, exchangeIds: ['d-rebind'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Authorize order', producedCapabilities: [rebindCap], consumedCapabilities: [ordCap] },
      { hopId: 'capture', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_500/capture' }, exchangeIds: ['d-race-0', 'd-race-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Double-capture order via race', producedCapabilities: [], consumedCapabilities: [rebindCap] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'create', toHopId: 'rebind', capabilityHandle: ordCap },
      { kind: 'value_binding', fromHopId: 'rebind', toHopId: 'capture', capabilityHandle: rebindCap },
    ],
    terminalImpact: {
      terminalHopId: 'capture',
      summary: 'Concurrent race double-credited a single 10000-cent order for +20000.',
      claimedImpact: 'Concurrent race double-credited a single 10000-cent order for +20000.',
      oracleFamily: 'economic_conservation',
      oracleInput: { baselineReadbackExchangeId: 'd-base', finalReadbackExchangeId: 'd-fin', actionExchangeIds: ['d-race-0', 'd-race-1'] },
      preChainControlExchangeIds: ['d-base'],
      postChainReadbackExchangeIds: ['d-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, entries)
  assert.equal(res.confirmed, true, `Real race double-credit must confirm after deduplication, got: ${res.reason}`)

  // Distinct orders (`ord_a: 5000`, `ord_b: 7000`) MUST sum to 12000; attacker-spoofed un-echoed requestJson.orderId MUST NOT collapse deposits!
  const authCap = 'cap:hop_auth:sess'
  const b2 = signedEntry('s-base', makeStep({ id: 's-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balance: 100 } }), { seq: 1, timestampMs: 1000 })
  const dep1 = signedEntry('s-dep1', makeStep({
    id: 's-dep1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/deposit', status: 200,
    requestJson: { orderId: 'attacker_spoof_same', amount: 50 }, json: { credited: 50 },
  }), { seq: 2, timestampMs: 1100, actorPersona: authCap, consumedCapabilities: [authCap] })
  const dep2 = signedEntry('s-dep2', makeStep({
    id: 's-dep2', arm: 'probe', method: 'POST', pathAndQuery: '/v1/deposit', status: 200,
    requestJson: { orderId: 'attacker_spoof_same', amount: 70 }, json: { credited: 70 },
  }), { seq: 3, timestampMs: 1200, actorPersona: authCap, consumedCapabilities: [authCap] })
  const xfer = signedEntry('s-xfer', makeStep({
    id: 's-xfer', arm: 'probe', method: 'POST', pathAndQuery: '/v1/transfer', status: 200,
    requestJson: { from: 'a', to: 'b', amount: 10 }, json: { ok: true },
  }), { seq: 4, timestampMs: 1250 })
  const f2 = signedEntry('s-fin', makeStep({ id: 's-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balance: 220 } }), { seq: 5, timestampMs: 1300 })
  const h2 = hydrateV8OracleInput(
    'economic_conservation',
    { equation: 'balance_minting', baselineReadback: 's-base', actions: ['s-dep1', 's-dep2', 's-xfer'], finalReadback: 's-fin' },
    { entriesById: new Map([b2, dep1, dep2, xfer, f2].map(e => [e.exchangeId, e])) },
    'sig',
  )
  assert.equal(h2.authorizedDeposits, 120, 'Un-echoed requestJson.orderId and shared auth capability must NOT collapse distinct deposits')
})

test('3B: balance_minting rejects bare single benign capture (including padded duplicate rebind + 409 draft control) while confirming real multiplicity, forged credits, negative amounts, and conserving-control breaks', () => {
  const ordCap = 'cap:hop_c:ord_fp'
  const base = signedEntry('fp-base', makeStep({
    id: 'fp-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/ledger', status: 200,
    json: { entries: [{ id: 'e0', amountCents: 10000, type: 'credit' }] },
  }), { seq: 1, timestampMs: 1000 })
  const ctrl409 = signedEntry('fp-ctrl-409', makeStep({
    id: 'fp-ctrl-409', arm: 'control', method: 'POST', pathAndQuery: '/v1/orders/ord_fp/capture', status: 409,
    json: { error: 'order_not_authorized' },
  }), { seq: 2, timestampMs: 1050 })
  const create = signedEntry('fp-create', makeStep({
    id: 'fp-create', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders', status: 201,
    requestJson: { amountCents: 1 }, json: { order: { id: 'ord_fp', amountCents: 1, status: 'draft' } },
  }), { seq: 3, timestampMs: 1100, emittedCapabilities: [ordCap] })
  const rebind1 = signedEntry('fp-rebind-1', makeStep({
    id: 'fp-rebind-1', arm: 'probe', method: 'PATCH', pathAndQuery: '/v1/orders/ord_fp/rebind', status: 200,
    json: { order: { id: 'ord_fp', amountCents: 1, status: 'authorized' } },
  }), { seq: 4, timestampMs: 1150, consumedCapabilities: [ordCap] })
  const rebind2 = signedEntry('fp-rebind-2', makeStep({
    id: 'fp-rebind-2', arm: 'probe', method: 'PATCH', pathAndQuery: '/v1/orders/ord_fp/rebind', status: 200,
    json: { order: { id: 'ord_fp', amountCents: 1, status: 'authorized' } },
  }), { seq: 5, timestampMs: 1200, consumedCapabilities: [ordCap] })
  const singleCapture = signedEntry('fp-cap-single', makeStep({
    id: 'fp-cap-single', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_fp/capture', status: 200,
    json: { order: { id: 'ord_fp', amountCents: 1, status: 'settled' } },
  }), { seq: 6, timestampMs: 1250, consumedCapabilities: [ordCap] })
  const fin = signedEntry('fp-fin', makeStep({
    id: 'fp-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/ledger', status: 200,
    json: { entries: [{ id: 'e0', amountCents: 10000, type: 'credit' }, { id: 'e1', amountCents: 58000, type: 'credit' }] },
  }), { seq: 7, timestampMs: 1300 })

  // (1) Bare single benign capture (+ duplicate rebind + 409 draft control) -> MUST FAIL CLOSED!
  const fpRes = verify({
    chainId: 'bare-single-capture-fp',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['fp-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create 1-cent order', producedCapabilities: [ordCap], consumedCapabilities: [] },
      { hopId: 'rebind', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_fp/rebind' }, exchangeIds: ['fp-rebind-1', 'fp-rebind-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Rebind order', producedCapabilities: [], consumedCapabilities: [ordCap] },
      { hopId: 'capture', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_fp/capture' }, exchangeIds: ['fp-cap-single'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Single capture credited 58000', producedCapabilities: [], consumedCapabilities: [ordCap] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'create', toHopId: 'rebind', capabilityHandle: ordCap },
      { kind: 'value_binding', fromHopId: 'create', toHopId: 'capture', capabilityHandle: ordCap },
    ],
    terminalImpact: {
      terminalHopId: 'capture',
      summary: 'Single non-race capture credited fixed amount without multiplicity or conserving control.',
      claimedImpact: 'Single non-race capture credited fixed amount without multiplicity or conserving control.',
      oracleFamily: 'economic_conservation',
      oracleInput: { baselineReadbackExchangeId: 'fp-base', finalReadbackExchangeId: 'fp-fin', actionExchangeIds: ['fp-create', 'fp-rebind-1', 'fp-rebind-2', 'fp-cap-single'] },
      preChainControlExchangeIds: ['fp-base', 'fp-ctrl-409'],
      postChainReadbackExchangeIds: ['fp-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, [base, ctrl409, create, rebind1, rebind2, singleCapture, fin])
  assert.equal(fpRes.confirmed, false, 'Bare single benign capture without race/multiplicity/conserving control must FAIL CLOSED')

  // (2) Sequential duplicate capture on same order entity (2x POST /capture 200) -> MUST PASS!
  const dupCapture2 = signedEntry('tp-cap-2', makeStep({
    id: 'tp-cap-2', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_fp/capture', status: 200,
    json: { order: { id: 'ord_fp', amountCents: 1, status: 'settled' } },
  }), { seq: 7, timestampMs: 1275, consumedCapabilities: [ordCap] })
  const finDup = signedEntry('tp-fin-dup', makeStep({
    id: 'tp-fin-dup', arm: 'control', method: 'GET', pathAndQuery: '/v1/ledger', status: 200,
    json: { entries: [{ id: 'e0', amountCents: 10000, type: 'credit' }, { id: 'e1', amountCents: 1, type: 'credit' }, { id: 'e2', amountCents: 1, type: 'credit' }] },
  }), { seq: 8, timestampMs: 1350 })
  const dupRes = verify({
    chainId: 'seq-duplicate-capture-tp',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['fp-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create order', producedCapabilities: [ordCap], consumedCapabilities: [] },
      { hopId: 'capture', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_fp/capture' }, exchangeIds: ['fp-cap-single', 'tp-cap-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Replay capture twice on same order', producedCapabilities: [], consumedCapabilities: [ordCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'create', toHopId: 'capture', capabilityHandle: ordCap }],
    terminalImpact: {
      terminalHopId: 'capture',
      summary: 'Sequential duplicate capture credited same order twice beyond authorized amount.',
      claimedImpact: 'Sequential duplicate capture credited same order twice beyond authorized amount.',
      oracleFamily: 'economic_conservation',
      oracleInput: { baselineReadbackExchangeId: 'fp-base', finalReadbackExchangeId: 'tp-fin-dup', actionExchangeIds: ['fp-cap-single', 'tp-cap-2'] },
      preChainControlExchangeIds: ['fp-base'],
      postChainReadbackExchangeIds: ['tp-fin-dup'],
    },
    replayMode: 'fresh_clean_replay',
  }, [base, create, singleCapture, dupCapture2, finDup])
  assert.equal(dupRes.confirmed, true, `Sequential duplicate entity capture must confirm, got: ${dupRes.reason}`)

  // (3) Same-actor conserving benign control on same route family -> MUST PASS; non-conserving control -> MUST FAIL!
  const cPre = signedEntry('cc-pre', makeStep({ id: 'cc-pre', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 1000 } }), { seq: 1, timestampMs: 100 })
  const cAct = signedEntry('cc-act', makeStep({ id: 'cc-act', arm: 'control', method: 'POST', pathAndQuery: '/v1/orders/ord_ctrl/capture', requestJson: { amountCents: 100 }, json: { order: { id: 'ord_ctrl', amountCents: 100 } } }), { seq: 2, timestampMs: 200 })
  const cPost = signedEntry('cc-post', makeStep({ id: 'cc-post', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 1100 } }), { seq: 3, timestampMs: 300 })
  const pAct = signedEntry('cc-probe', makeStep({ id: 'cc-probe', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_probe/capture', requestJson: { amountCents: 100, bonusMultiplier: 50 }, json: { order: { id: 'ord_probe', amountCents: 100 } } }), { seq: 4, timestampMs: 400 })
  const pFin = signedEntry('cc-fin', makeStep({ id: 'cc-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 6100 } }), { seq: 5, timestampMs: 500 })

  const ctrlReceipt: CompositeProofReceipt = {
    chainId: 'conserving-control-tamper-tp',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'probe', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_probe/capture' }, exchangeIds: ['cc-probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Tampered capture minted excess balance', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'probe',
      summary: 'Tampered capture minted +5000 while benign control capture conserved +100.',
      claimedImpact: 'Tampered capture minted +5000 while benign control capture conserved +100.',
      oracleFamily: 'economic_conservation',
      oracleInput: { baselineReadbackExchangeId: 'cc-post', finalReadbackExchangeId: 'cc-fin', actionExchangeIds: ['cc-probe'] },
      preChainControlExchangeIds: ['cc-pre', 'cc-act', 'cc-post'],
      postChainReadbackExchangeIds: ['cc-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }
  const ctrlPass = verify(ctrlReceipt, [cPre, cAct, cPost, pAct, pFin])
  assert.equal(ctrlPass.confirmed, true, `Probe with verified conserving benign control must confirm, got: ${ctrlPass.reason}`)

  // Non-conserving control (benign control ALSO overcredited +58000) -> MUST FAIL CLOSED!
  const badCPost = signedEntry('cc-post', makeStep({ id: 'cc-post', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 59000 } }), { seq: 3, timestampMs: 300 })
  const badPFin = signedEntry('cc-fin', makeStep({ id: 'cc-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 117000 } }), { seq: 5, timestampMs: 500 })
  const ctrlFail = verify(ctrlReceipt, [cPre, cAct, badCPost, pAct, badPFin])
  assert.equal(ctrlFail.confirmed, false, 'Non-conserving benign control must NOT satisfy attacker-induced conservation break')

  // (4) Negative-amount request tampering -> MUST PASS!
  const nBase = signedEntry('neg-base', makeStep({ id: 'neg-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 1000 } }), { seq: 1, timestampMs: 100 })
  const nAct = signedEntry('neg-act', makeStep({ id: 'neg-act', arm: 'probe', method: 'POST', pathAndQuery: '/v1/withdraw', requestJson: { amountCents: -500 }, json: { ok: true } }), { seq: 2, timestampMs: 200 })
  const nFin = signedEntry('neg-fin', makeStep({ id: 'neg-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 1500 } }), { seq: 3, timestampMs: 300 })
  const negRes = verify({
    chainId: 'negative-amount-tamper-tp',
    terminalVulnClass: 'economic_conservation',
    hops: [{ hopId: 'w', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/withdraw' }, exchangeIds: ['neg-act'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Negative withdraw minted balance', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'w',
      summary: 'Negative withdrawal amount minted +500 into balance.',
      claimedImpact: 'Negative withdrawal amount minted +500 into balance.',
      oracleFamily: 'economic_conservation',
      oracleInput: { baselineReadbackExchangeId: 'neg-base', finalReadbackExchangeId: 'neg-fin', actionExchangeIds: ['neg-act'] },
      preChainControlExchangeIds: ['neg-base'],
      postChainReadbackExchangeIds: ['neg-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, [nBase, nAct, nFin])
  assert.equal(negRes.confirmed, true, `Negative-amount tampering must confirm, got: ${negRes.reason}`)

  // (5) Forged webhook credit with 401 denied control -> MUST PASS!
  const wBase = signedEntry('wh-base', makeStep({ id: 'wh-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 1000 } }), { seq: 1, timestampMs: 100 })
  const wCtrl = signedEntry('wh-ctrl', makeStep({ id: 'wh-ctrl', arm: 'control', method: 'POST', pathAndQuery: '/v1/webhooks/settlement', status: 401, requestHeaders: { 'x-signature': 'bad' }, json: { error: 'invalid_sig' } }), { seq: 2, timestampMs: 150 })
  const wProbe = signedEntry('wh-probe', makeStep({ id: 'wh-probe', arm: 'probe', method: 'POST', pathAndQuery: '/v1/webhooks/settlement', status: 200, requestHeaders: { 'x-signature': 'forged_valid' }, requestJson: { amountCents: 5000 }, json: { credited: 5000 } }), { seq: 3, timestampMs: 200, cryptoAttestations: [{ derivedFromCapabilityId: 'cap:hop_1:salt', alg: 'hmac-sha256', artifactDigest: 'f'.repeat(64), timestampMs: 190 }] })
  const wFin = signedEntry('wh-fin', makeStep({ id: 'wh-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 6000 } }), { seq: 4, timestampMs: 300 })
  const whRes = verify({
    chainId: 'forged-webhook-credit-tp',
    terminalVulnClass: 'economic_conservation',
    hops: [{ hopId: 'wh', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/settlement' }, exchangeIds: ['wh-probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Forged settlement webhook credited +5000', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'wh',
      summary: 'Forged settlement webhook bypassed 401 signature check and credited +5000.',
      claimedImpact: 'Forged settlement webhook bypassed 401 signature check and credited +5000.',
      oracleFamily: 'economic_conservation',
      oracleInput: { baselineReadbackExchangeId: 'wh-base', finalReadbackExchangeId: 'wh-fin', actionExchangeIds: ['wh-probe'] },
      preChainControlExchangeIds: ['wh-base', 'wh-ctrl'],
      postChainReadbackExchangeIds: ['wh-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, [wBase, wCtrl, wProbe, wFin])
  assert.equal(whRes.confirmed, true, `Forged webhook settlement with 401 control + crypto attestation must confirm, got: ${whRes.reason}`)
})

// ============================================================================
// 4. R3-05 Independent Review (claude-opus-5-5-high) Hardening Regressions
// ============================================================================

test('4 (R3-05 Opus B1/A1/A2): same-wallet repeated deposits & partial captures stay conserved (confirmed=false), partial over-capture confirms, and A1/A2 seal metadata & null-persona lineage hold', () => {
  // B1(a): Same-wallet repeated benign deposits with top-level JSON `id` AND wallet path segment -> MUST NOT under-count!
  const wBase = signedEntry('wal-base', makeStep({ id: 'wal-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/wallets/wal_901', json: { id: 'wal_901', balance: 100 } }), { seq: 1, timestampMs: 1000 })
  const wDep1 = signedEntry('wal-d1', makeStep({ id: 'wal-d1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/wallets/wal_901/deposit', requestJson: { amount: 50 }, json: { id: 'wal_901', balance: 150 } }), { seq: 2, timestampMs: 1100 })
  const wDep2 = signedEntry('wal-d2', makeStep({ id: 'wal-d2', arm: 'probe', method: 'POST', pathAndQuery: '/v1/wallets/wal_901/deposit', requestJson: { amount: 50 }, json: { id: 'wal_901', balance: 200 } }), { seq: 3, timestampMs: 1200 })
  const wFin = signedEntry('wal-fin', makeStep({ id: 'wal-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/wallets/wal_901', json: { id: 'wal_901', balance: 200 } }), { seq: 4, timestampMs: 1300 })

  const walReceipt = (d1Id: string, d2Id: string, finId: string, chainId: string): CompositeProofReceipt => ({
    chainId,
    terminalVulnClass: 'economic_conservation',
    hops: [{ hopId: 'dep', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/wallets/wal_901/deposit' }, exchangeIds: [d1Id, d2Id], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Two legit wallet deposits', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'dep',
      summary: 'Two benign deposits of 50 each on the same wallet conserve balance.',
      claimedImpact: 'Two benign deposits of 50 each on the same wallet conserve balance.',
      oracleFamily: 'economic_conservation',
      oracleInput: { equation: 'balance_minting', baselineReadbackExchangeId: 'wal-base', finalReadbackExchangeId: finId, actionExchangeIds: [d1Id, d2Id] },
      preChainControlExchangeIds: ['wal-base'],
      postChainReadbackExchangeIds: [finId],
    },
    replayMode: 'fresh_clean_replay',
  })
  const walJsonRes = verify(walReceipt('wal-d1', 'wal-d2', 'wal-fin', 'b1-wallet-json-id'), [wBase, wDep1, wDep2, wFin])
  assert.equal(walJsonRes.confirmed, false, `Same-wallet repeated deposits (json id) must stay conserved, got confirmed=true`)

  // B1(b): Same-wallet repeated deposits with `{ ok: true }` body (path segment only) -> MUST FAIL CLOSED!
  const wDep1Ok = signedEntry('wal-ok1', makeStep({ id: 'wal-ok1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/wallets/wal_901/deposit', requestJson: { amount: 50 }, json: { ok: true } }), { seq: 2, timestampMs: 1100 })
  const wDep2Ok = signedEntry('wal-ok2', makeStep({ id: 'wal-ok2', arm: 'probe', method: 'POST', pathAndQuery: '/v1/wallets/wal_901/deposit', requestJson: { amount: 50 }, json: { ok: true } }), { seq: 3, timestampMs: 1200 })
  const walPathRes = verify(walReceipt('wal-ok1', 'wal-ok2', 'wal-fin', 'b1-wallet-path-only'), [wBase, wDep1Ok, wDep2Ok, wFin])
  assert.equal(walPathRes.confirmed, false, `Same-wallet repeated deposits (path segment only) must stay conserved, got confirmed=true`)

  // B1(c): Benign partial captures (30 + 20 on ord_part when create is OUTSIDE window) -> MUST STAY CONSERVED (confirmed=false)!
  const pBase = signedEntry('pc-base', makeStep({ id: 'pc-base', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 100 } }), { seq: 1, timestampMs: 1000 })
  const pCap1 = signedEntry('pc-1', makeStep({ id: 'pc-1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_part/capture', requestJson: { amountCents: 30 }, json: { orderId: 'ord_part', captured: 30, amountCents: 30 } }), { seq: 2, timestampMs: 1100 })
  const pCap2 = signedEntry('pc-2', makeStep({ id: 'pc-2', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_part/capture', requestJson: { amountCents: 20 }, json: { orderId: 'ord_part', captured: 20, amountCents: 20 } }), { seq: 3, timestampMs: 1200 })
  const pFin = signedEntry('pc-fin', makeStep({ id: 'pc-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 150 } }), { seq: 4, timestampMs: 1300 })
  const partialConserved = verify({
    chainId: 'b1-partial-captures-outside-window',
    terminalVulnClass: 'economic_conservation',
    hops: [{ hopId: 'cap', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_part/capture' }, exchangeIds: ['pc-1', 'pc-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Partial captures 30+20', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'cap',
      summary: 'Benign partial captures 30+20 on existing order conserve total 50.',
      claimedImpact: 'Benign partial captures 30+20 on existing order conserve total 50.',
      oracleFamily: 'economic_conservation',
      oracleInput: { equation: 'balance_minting', baselineReadbackExchangeId: 'pc-base', finalReadbackExchangeId: 'pc-fin', actionExchangeIds: ['pc-1', 'pc-2'] },
      preChainControlExchangeIds: ['pc-base'],
      postChainReadbackExchangeIds: ['pc-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, [pBase, pCap1, pCap2, pFin])
  assert.equal(partialConserved.confirmed, false, 'Benign partial captures 30+20 (create outside window) must stay conserved (confirmed=false)')

  // B1(d): Partial OVER-capture (30 + 30 = 60 against a 50 order created IN-WINDOW) -> MUST CONFIRM (true)!
  const ordPartCap = 'cap:hop_create:ord_part_50'
  const pCreate = signedEntry('pc-create', makeStep({ id: 'pc-create', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders', status: 201, requestJson: { amountCents: 50 }, json: { order: { id: 'ord_part_50', amountCents: 50, status: 'authorized' } } }), { seq: 2, timestampMs: 1050, emittedCapabilities: [ordPartCap] })
  const pOver1 = signedEntry('pc-over-1', makeStep({ id: 'pc-over-1', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_part_50/capture', requestJson: { amountCents: 30 }, json: { orderId: 'ord_part_50', amountCents: 30 } }), { seq: 3, timestampMs: 1100, consumedCapabilities: [ordPartCap] })
  const pOver2 = signedEntry('pc-over-2', makeStep({ id: 'pc-over-2', arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord_part_50/capture', requestJson: { amountCents: 30 }, json: { orderId: 'ord_part_50', amountCents: 30 } }), { seq: 4, timestampMs: 1200, consumedCapabilities: [ordPartCap] })
  const pOverFin = signedEntry('pc-over-fin', makeStep({ id: 'pc-over-fin', arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { balanceCents: 160 } }), { seq: 5, timestampMs: 1300 })
  const partialOver = verify({
    chainId: 'b1-partial-overcapture-in-window',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'create', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' }, exchangeIds: ['pc-create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Create 50-cent order', producedCapabilities: [ordPartCap], consumedCapabilities: [] },
      { hopId: 'cap', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_part_50/capture' }, exchangeIds: ['pc-over-1', 'pc-over-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Over-capture 30+30 on 50 order', producedCapabilities: [], consumedCapabilities: [ordPartCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'create', toHopId: 'cap', capabilityHandle: ordPartCap }],
    terminalImpact: {
      terminalHopId: 'cap',
      summary: 'Two partial captures of 30 each minted 60 against a 50-cent order.',
      claimedImpact: 'Two partial captures of 30 each minted 60 against a 50-cent order.',
      oracleFamily: 'economic_conservation',
      oracleInput: { equation: 'balance_minting', baselineReadbackExchangeId: 'pc-base', finalReadbackExchangeId: 'pc-over-fin', actionExchangeIds: ['pc-over-1', 'pc-over-2'] },
      preChainControlExchangeIds: ['pc-base'],
      postChainReadbackExchangeIds: ['pc-over-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, [pBase, pCreate, pOver1, pOver2, pOverFin])
  assert.equal(partialOver.confirmed, true, `Over-capture 30+30 against in-window 50 order must confirm, got: ${partialOver.reason}`)

  // A1 & A2: Worker-spoofed `x-kovo-seal-field` on HTTP record MUST be ignored; null personaHandle with consumedCapabilityId resolves owning persona!
  const ledger = new CapabilityLedger(':memory:', { runId: 'run-r9-a1a2' })
  const parentCap = 'cap:hop_owner:seed_tok'
  const childCap = 'cap:hop_child:derived_url'
  const parentEntry = signedEntry('a2-parent', makeStep({ id: 'a2-parent', arm: 'probe', method: 'POST', pathAndQuery: '/v1/auth/login', status: 200, json: { tok: 'p1' } }), { seq: 1, timestampMs: 1000, actorPersona: 'real_owner', emittedCapabilities: [parentCap] })
  const childEntry = signedEntry('a2-child', makeStep({ id: 'a2-child', arm: 'probe', method: 'GET', pathAndQuery: '/v1/exports/link', status: 200, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, json: { url: 'https://api.example.test/dl' } }), { seq: 2, timestampMs: 1100, actorPersona: null, consumedCapabilities: [parentCap], emittedCapabilities: [childCap] })
  syncVerifyArtifactsToLedger({
    ledger,
    defaultOrigin: ORIGIN,
    defaultPersona: 'unrelated_default',
    proof: {
      verdict: { confirmed: false, reason: 'checkpoint_only', detail: '', attempts: [], disagreements: [], claimTitle: null, rejectedBy: null, missingEvidence: [], transcriptSummary: [] },
      exchanges: [], receipt: null, compositeReceipt: null, vulnClass: null, transcriptDigests: [],
      sealedCapabilities: [
        { handle: parentCap, runId: 'run-r9-a1a2', kind: 'bearer_token', hopReceiptId: 'owner', slot: 'seed_tok', sha256: 'a'.repeat(64), sha256Prefix: 'aaaaaaaa', createdAtMs: 1000, expiresAtMs: null, allowedOrigins: [ORIGIN] },
        { handle: childCap, runId: 'run-r9-a1a2', kind: 'signed_url', hopReceiptId: 'child', slot: 'derived_url', sha256: 'b'.repeat(64), sha256Prefix: 'bbbbbbbb', createdAtMs: 1100, expiresAtMs: null, allowedOrigins: [ORIGIN] },
      ],
      transcriptRecords: [
        {
          exchangeId: 'a2-parent', seq: 1, op: 'http', startedAt: 1000, durationMs: 5, signature: 's1',
          request: {
            origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/auth/login',
            headers: { 'x-kovo-seal-field': 'spoofed_http_field' },
            bodyBytes: 0, bodySha256: 'c'.repeat(64), personaHandle: 'real_owner', sessionRole: 'probe', nonce: 'n1',
          },
          artifact: { kind: 'capability', capabilityHandle: parentCap },
        },
        {
          exchangeId: 'a2-child', seq: 2, op: 'http', startedAt: 1100, durationMs: 5, signature: 's2',
          request: {
            origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/link',
            headers: { 'x-kovo-seal-field': 'spoofed_child_field' },
            bodyBytes: 0, bodySha256: 'd'.repeat(64), personaHandle: null, consumedCapabilityId: parentCap, sessionRole: 'probe', nonce: 'n1',
          },
          artifact: { kind: 'capability', capabilityHandle: childCap },
        },
      ],
      hostTranscript: { entries: [parentEntry, childEntry], oobEvents: [], browserTraces: [], asyncPollRecords: [] },
      claimTitle: null, severity: null, description: null,
    },
  })
  const parentNode = ledger.getCapability(parentCap)
  const childNode = ledger.getCapability(childCap)
  assert.ok(parentNode && childNode)
  assert.equal(parentNode.metadata.fieldName, undefined, 'A1: non-capability HTTP request headers must NEVER spoof CapabilityNode.metadata.fieldName')
  assert.equal(childNode.metadata.fieldName, undefined, 'A1: non-capability HTTP request headers must NEVER spoof child CapabilityNode.metadata.fieldName')
  assert.equal(childNode.actorPersona, 'real_owner', 'A2: null personaHandle with consumedCapabilityId must walk lineage to owning persona real_owner')
})
