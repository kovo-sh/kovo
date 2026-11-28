/**
 * Unit + live VerifyRpcServer tests for the zero-boilerplate ChainBuilder v2 proof surface:
 *   - Action-sending ch.control(target, opts?) & ch.readback(target, opts?) + sync ExchangeRef compat
 *   - One-liner ch.step(target, opts?) / ch.send(target, opts?) with auto hop_1..hop_N IDs
 *   - ch.seal(exchange, selector) auto-slot, outside-hop hopReceiptId inference, and auto value_binding
 *   - ch.race(opts) auto-named raceBurst + economic_conservation / multi-family oracleInput auto-synthesis
 *   - Strict <= 800 LOC ceiling on worker/kovo_verify/kovo_verify.ts
 */
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import test, { type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import { resetRunCustodyBudgets } from '../src/server/derived-custody.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext, accessDifferential, causalDag, wireFramingAndCacheDifferential } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_PATH = join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts')

const MINT_TOKEN = 'chain_v2_opaque_export_tok_918273'
const HEADER_TOKEN = 'chain_v2_hdr_secret_tok_665544'
const SIGNING_KEY = 'chain_v2_hmac_signing_key_55443322'

function sendJson(res: ServerResponse, status: number, payload: unknown, extraHeaders: Record<string, string> = {}): void {
  const body = JSON.stringify(payload)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...extraHeaders })
  res.end(body)
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

function makeGrant(origin: string, port: number): Grant {
  const memberA: ResolvedPersona = {
    id: 'member_a',
    handle: 'member_a',
    roleLabel: 'member (tenant-a)',
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: 'member-a-chain-v2-session-secret',
    canaryMarkers: [],
    session: { headerType: 'bearer', value: 'member-a-chain-v2-session-secret', adapterUsed: 'static' },
  }
  return {
    origin,
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 300,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map([['member_a', memberA]]),
    secrets: [],
  }
}

async function startFixture(t: TestContext, runId: string): Promise<{ origin: string; server: VerifyRpcServer; ctx: VerifyContext }> {
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  // Synthetic ledger state for over-refund economic_conservation verification.
  let paidAmount = 100
  let refundedTotal = 0
  let settingFlag = 'off'

  const httpServer = createServer(async (req, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    const hdrTok = String(req.headers['x-alt-token'] ?? '')

    if (u.pathname === '/api/v1/mint' && req.method === 'POST') {
      return sendJson(res, 200, { token: MINT_TOKEN, signingKey: SIGNING_KEY }, { 'x-mint-token': HEADER_TOKEN })
    }
    if (u.pathname === '/api/v1/export' && req.method === 'GET') {
      if (auth === `Bearer ${MINT_TOKEN}` || hdrTok === HEADER_TOKEN) {
        return sendJson(res, 200, { tenantId: 'tenant-b', records: [{ id: 'inv-b-1', amountCents: 84000, ownerEmail: 'finance@tenant-b.test' }] })
      }
      return sendJson(res, 403, { error: 'forbidden' })
    }
    if (u.pathname === '/api/v1/signed' && req.method === 'POST') {
      const body = await readBody(req)
      const expected = createHmac('sha256', SIGNING_KEY).update(body).digest('hex')
      if (req.headers['x-sig'] === expected) return sendJson(res, 200, { ok: true, tenantId: 'tenant-b', records: [{ id: 'settle-1', amountCents: 12000 }] })
      return sendJson(res, 403, { error: 'bad_signature' })
    }
    if (u.pathname === '/api/v1/settings') {
      if (req.method === 'GET') return sendJson(res, 200, { flag: settingFlag })
      if (req.method === 'POST') {
        if (auth !== `Bearer ${MINT_TOKEN}`) return sendJson(res, 403, { error: 'forbidden' })
        const body = JSON.parse((await readBody(req)) || '{}') as { flag?: string }
        if (body.flag) settingFlag = body.flag
        return sendJson(res, 200, { ok: true, flag: settingFlag })
      }
    }
    if (u.pathname === '/api/v1/orders/ord-1' && req.method === 'GET') {
      return sendJson(res, 200, { orderId: 'ord-1', paidAmount, refundedTotal })
    }
    if (u.pathname === '/api/v1/orders/ord-1/refund' && req.method === 'POST') {
      // Intentionally non-atomic TOCTOU check for deterministic race-burst test
      const snapshot = refundedTotal
      const body = JSON.parse((await readBody(req)) || '{}') as { amount?: number }
      const amt = Number(body.amount ?? 60)
      await new Promise(r => setTimeout(r, 25))
      if (snapshot + amt <= paidAmount) {
        refundedTotal += amt
        return sendJson(res, 200, { ok: true, refunded: amt, refundedTotal })
      }
      return sendJson(res, 409, { error: 'over_refund' })
    }
    if (u.pathname === '/api/v1/orders/ord-1/reset' && req.method === 'POST') {
      paidAmount = 100
      refundedTotal = 0
      return sendJson(res, 200, { ok: true })
    }
    return sendJson(res, 404, { error: 'not_found' })
  }).listen(0, '127.0.0.1')

  t.after(() => new Promise<void>(r => { httpServer.closeAllConnections(); httpServer.close(() => r()) }))
  await once(httpServer, 'listening')
  const port = (httpServer.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`

  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(origin, port),
    runId,
    assignmentId: `asg-${runId}`,
    targetOrigins: [origin],
    maxSealsPerExchange: 40,
  })
  await server.start()
  t.after(() => server.close())

  const prev = {
    sock: process.env[VERIFY_RPC_SOCKET_ENV],
    tok: process.env[VERIFY_RPC_TOKEN_ENV],
    ctx: process.env[VERIFY_RPC_CONTEXT_ENV],
    nonce: process.env[VERIFY_NONCE_ENV],
  }
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  t.after(() => {
    if (prev.sock === undefined) delete process.env[VERIFY_RPC_SOCKET_ENV]; else process.env[VERIFY_RPC_SOCKET_ENV] = prev.sock
    if (prev.tok === undefined) delete process.env[VERIFY_RPC_TOKEN_ENV]; else process.env[VERIFY_RPC_TOKEN_ENV] = prev.tok
    if (prev.ctx === undefined) delete process.env[VERIFY_RPC_CONTEXT_ENV]; else process.env[VERIFY_RPC_CONTEXT_ENV] = prev.ctx
    if (prev.nonce === undefined) delete process.env[VERIFY_NONCE_ENV]; else process.env[VERIFY_NONCE_ENV] = prev.nonce
  })

  return { origin, server, ctx: new VerifyContext() }
}

test('kovo_verify.ts stays strictly <= 800 LOC', () => {
  const loc = readFileSync(SDK_PATH, 'utf8').trimEnd().split('\n').length
  assert.ok(loc <= 800, `worker/kovo_verify/kovo_verify.ts must be <= 800 LOC, got ${loc}`)
})

test('live VerifyRpcServer: Option A zero-boilerplate control + step + seal + readback + prove confirms end-to-end', async t => {
  const { origin, server, ctx } = await startFixture(t, 'run-chain-v2-option-a')

  const ch = ctx.chain('chain-v2-opt-a', 'cross_tenant_read')

  // 1) Action-sending ch.control() with method-prefixed string -> arm:'control', NEVER creates an orphan hop
  const ctrl = await ch.control('GET /api/v1/export', { as: 'member_a' })
  assert.equal(ctrl.status, 403)

  // 2) One-liner ch.step() auto-generates hop_1 and extracts method from target string
  const mint = await ch.step('POST /api/v1/mint', { as: 'member_a' })
  assert.equal(mint.status, 200)

  // 3) ch.seal() OUTSIDE any ch.hop() auto-generates slot s1, infers hopReceiptId=hop_1, returns handle string
  const tok = await ch.seal(mint, { jsonPath: '$.token', kind: 'bearer_token' })
  assert.equal(typeof tok, 'string')
  assert.match(tok, /^cap:.*hop_1:s1$/)

  // Also test string selector shorthand ('header:x-mint-token') -> auto slot s2
  const hdrTok = await ch.seal(mint, 'header:x-mint-token')
  assert.equal(typeof hdrTok, 'string')
  assert.match(hdrTok, /^cap:.*hop_1:s2$/)

  // 4) ch.send() alias auto-generates hop_2 and consumes sealed capability handle
  const exp = await ch.send('GET /api/v1/export', { capability: tok })
  assert.equal(exp.status, 200)
  assert.equal(exp.consumedCapabilityId, tok)

  // 5) Action-sending ch.readback() with object target -> arm:'control', NEVER creates an orphan hop
  const rb = await ch.readback({ method: 'GET', path: '/api/v1/settings', as: 'member_a' })
  assert.equal(rb.status, 200)

  const receipt = ch.build({ claimedImpact: 'Cross-tenant export read via Option A ChainBuilder v2.', terminalExchange: exp })
  const parsed = compositeProofReceiptSchema.safeParse(receipt)
  assert.equal(parsed.success, true, `Receipt must pass schema: ${JSON.stringify(parsed)}`)

  // Exactly 2 hops (control and readback did NOT create orphan hops!)
  assert.deepEqual(receipt.hops.map(h => h.hopId), ['hop_1', 'hop_2'])
  assert.deepEqual(receipt.hops[0]!.target, { origin, method: 'POST', pathAndQuery: '/api/v1/mint' })
  assert.deepEqual(receipt.hops[1]!.target, { origin, method: 'GET', pathAndQuery: '/api/v1/export' })
  assert.ok(receipt.hops[0]!.producedCapabilities?.includes(tok))
  assert.ok(receipt.hops[0]!.producedCapabilities?.includes(hdrTok))
  assert.deepEqual(receipt.hops[1]!.consumedCapabilities, [tok])

  // Auto-wired value_binding edge from hop_1 -> hop_2
  const valEdge = (receipt.causalEdges ?? []).find(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2')
  assert.ok(valEdge && valEdge.kind === 'value_binding')
  assert.equal(valEdge.capabilityHandle, tok)
  assert.equal(valEdge.sourceExchangeId, mint.exchangeId)
  assert.equal(valEdge.targetExchangeId, exp.exchangeId)

  // Pre-chain control and post-chain readback registered cleanly
  assert.deepEqual(receipt.terminalImpact.preChainControlExchangeIds, [ctrl.exchangeId])
  assert.deepEqual(receipt.terminalImpact.postChainReadbackExchangeIds, [rb.exchangeId])

  // Host transcript confirms arm:'control' on both ch.control() and ch.readback()
  const transcript = server.buildHostSignedTranscript()
  const armByEx = new Map((transcript.entries ?? []).map(e => [e.exchangeId, e.step.arm]))
  assert.equal(armByEx.get(ctrl.exchangeId), 'control')
  assert.equal(armByEx.get(rb.exchangeId), 'control')
  assert.equal(armByEx.get(mint.exchangeId), 'probe')
  assert.equal(armByEx.get(exp.exchangeId), 'probe')

  // Live host confirmation passes!
  const proved = await ch.prove({ claimedImpact: 'Cross-tenant export read via Option A ChainBuilder v2.', terminalExchange: exp })
  assert.equal(proved.confirmed, true, `Expected live Option A chain to confirm: ${JSON.stringify(proved)}`)
})

test('live VerifyRpcServer: ch.seal works with hmac_sign / jwt_sign and backward-compat sync control/readback refs', async t => {
  const { ctx } = await startFixture(t, 'run-chain-v2-compat-crypto')

  // Backward-compatible sync control(ref) / readback(ref) still return ChainBuilder (`this`)
  const preCtrl = await ctx.http_send('/api/v1/signed', { method: 'POST', as: 'member_a', role: 'control', body: { ok: true } })
  assert.equal(preCtrl.status, 403)

  const ch = ctx.chain('chain-v2-crypto', 'cross_tenant_read')
  assert.strictEqual(ch.control(preCtrl), ch)
  assert.strictEqual(ch.control('ex-extra-id'), ch)
  assert.strictEqual(ch.readback(preCtrl), ch)

  // ch.step with explicit hopId + auto-generated next hop avoids collision
  const mint = await ch.step('POST /api/v1/mint', { hopId: 'hop_1', as: 'member_a' })
  const keyHandle = await ch.seal(mint, { jsonPath: '$.signingKey', kind: 'hmac_key' })
  assert.match(keyHandle, /^cap:.*hop_1:s1$/)

  // Use ch.seal handle directly in ctx.hmac_sign + ctx.jwt_sign inside hop_2;
  // also verify ch.control/ch.readback invoked inside a hop callback never leak into hop.exchangeIds
  const payload = JSON.stringify({ settle: 'ord-9' })
  let innerCtrlId = ''
  const signedEx = await ch.hop('hop_2', async () => {
    const innerCtrl = await ch.control('GET /api/v1/export', { as: 'member_a' })
    innerCtrlId = innerCtrl.exchangeId
    const sig = await ctx.hmac_sign(keyHandle, payload)
    const jwt = await ctx.jwt_sign({ secretHandle: keyHandle, claims: { sub: 'svc' } })
    assert.match(jwt.derivedHandle, /^cap:/)
    return ctx.http_send('POST /api/v1/signed', { as: 'member_a', role: 'probe', headers: { 'x-sig': sig.derivedHandle, 'content-type': 'application/json' }, body: payload })
  })
  assert.equal(signedEx.status, 200)

  // Auto next hop after hop_1 + hop_2 becomes hop_3 (no collision)
  const tokHandle = await ch.seal(mint, '$.token')
  const expEx = await ch.step('GET /api/v1/export', { capability: tokHandle })
  assert.equal(expEx.status, 200)

  const built = ch.build({ claimedImpact: 'Derived HMAC + capability chain verified.' })
  assert.deepEqual(built.hops.map(h => h.hopId), ['hop_1', 'hop_2', 'hop_3'])
  assert.equal(built.hops[1]!.exchangeIds?.includes(innerCtrlId), false, 'ch.control() inside hop must not attach to hop.exchangeIds')
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes(innerCtrlId))
  assert.ok((built.causalEdges ?? []).some(e => e.kind === 'derived_crypto_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2' && e.sourceCapabilityId === keyHandle))
  assert.ok((built.causalEdges ?? []).some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_3' && e.capabilityHandle === tokHandle))
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes(preCtrl.exchangeId))
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes('ex-extra-id'))
})

test('live VerifyRpcServer: ch.race() + economic_conservation auto-synthesizes oracleInput even when opts.oracleInput is omitted', async t => {
  const { ctx } = await startFixture(t, 'run-chain-v2-econ')

  const ch = ctx.chain('chain-v2-econ-race', 'economic_conservation')
  const base = await ch.control('GET /api/v1/orders/ord-1', { as: 'member_a' })
  assert.equal(base.status, 200)

  const burst = await ch.race({
    request: { method: 'POST', path: '/api/v1/orders/ord-1/refund', as: 'member_a', body: { amount: 60 } },
    count: 3,
  })
  assert.equal(burst.results.length, 3)

  const fin = await ch.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  assert.equal(fin.status, 200)
  assert.ok((fin.json as { refundedTotal: number }).refundedTotal > 100, 'Expected concurrent over-refund > 100')

  // Build WITHOUT passing opts.oracleInput at all -> must auto-synthesize all 3 economic_conservation refs!
  const built = ch.build({ claimedImpact: 'Concurrent refund burst exceeded original paid amount.' })
  assert.deepEqual(built.hops.map(h => h.hopId), ['hop_1'])
  assert.deepEqual(built.terminalImpact.oracleInput, {
    baselineReadbackExchangeId: base.exchangeId,
    finalReadbackExchangeId: fin.exchangeId,
    actionExchangeIds: burst.results.map(r => r.exchangeId),
  })

  // Caller-provided oracleInput fields must NEVER be overridden
  const builtOverride = ch.build({
    claimedImpact: 'Override preservation check.',
    oracleInput: { equation: 'over_refund', baselineReadbackExchangeId: 'custom-base-id' },
  })
  assert.equal(builtOverride.terminalImpact.oracleInput?.equation, 'over_refund')
  assert.equal(builtOverride.terminalImpact.oracleInput?.baselineReadbackExchangeId, 'custom-base-id')
  assert.equal(builtOverride.terminalImpact.oracleInput?.finalReadbackExchangeId, fin.exchangeId)
  assert.deepEqual(builtOverride.terminalImpact.oracleInput?.actionExchangeIds, burst.results.map(r => r.exchangeId))

  // Live VerifyRpcServer confirmation with omitted oracleInput!
  const proved = await ch.prove({ claimedImpact: 'Concurrent refund burst exceeded original paid amount.' })
  assert.equal(proved.confirmed, true, `Expected live economic_conservation with auto-synthesized oracleInput to confirm: ${JSON.stringify(proved)}`)
})

test('A2: explicit universal-primitive helpers build role-named oracleInput (no positional hop guessing) and pass caller fields through', async t => {
  const { ctx } = await startFixture(t, 'run-chain-v2-oracle-families')

  // 1) cryptographic_scope_replay -> access_differential helper; bare oracleFamily never guesses hops[0]/hops[1]
  const cCrypto = ctx.chain('c-crypto', 'cryptographic_scope_replay')
  cCrypto.control('ex-tampered')
  cCrypto.recordHop({ hopId: 'hop_1', target: 'POST /api/issue', exchangeIds: ['ex-issue'], claimedDelta: 'Issued signed token.' })
  cCrypto.recordHop({ hopId: 'hop_2', target: 'GET /api/replay', exchangeIds: ['ex-replay'], claimedDelta: 'Replayed across scope.' })
  assert.equal(cCrypto.build({ oracleFamily: 'cryptographic_scope_replay' }).terminalImpact.oracleInput, undefined)
  const rCrypto = cCrypto.build({ ...accessDifferential({ control: 'ex-tampered', issuance: 'ex-issue', variant: 'ex-replay' }) })
  assert.equal(rCrypto.terminalImpact.oracleFamily, 'cryptographic_scope_replay')
  assert.deepEqual(rCrypto.terminalImpact.oracleInput, {
    tamperedSignatureControlExchangeId: 'ex-tampered',
    sourceValidIssuanceExchangeId: 'ex-issue',
    replayedAcceptanceExchangeId: 'ex-replay',
  })
  // Explicit caller oracleInput is passed through verbatim (no positional fill of the other slots)
  const rCryptoOv = cCrypto.build({ oracleFamily: 'cryptographic_scope_replay', oracleInput: { replayedAcceptanceExchangeId: 'ex-custom' } })
  assert.deepEqual(rCryptoOv.terminalImpact.oracleInput, { replayedAcceptanceExchangeId: 'ex-custom' })

  // 2) temporal_revocation -> access_differential helper (time boundary)
  const cTemp = ctx.chain('c-temp', 'temporal_revocation')
  cTemp.control('ex-primary-denied')
  cTemp.recordHop({ hopId: 'hop_1', target: 'GET /api/me', exchangeIds: ['ex-pre'], claimedDelta: 'Pre-revocation baseline.' })
  cTemp.recordHop({ hopId: 'hop_2', target: 'POST /api/logout', exchangeIds: ['ex-revoke'], claimedDelta: 'Revoked token.' })
  cTemp.recordHop({ hopId: 'hop_3', target: 'GET /api/alt', exchangeIds: ['ex-secondary'], claimedDelta: 'Secondary accepted.' })
  assert.equal(cTemp.build({ oracleFamily: 'temporal_revocation' }).terminalImpact.oracleInput, undefined)
  assert.deepEqual(cTemp.build({ ...accessDifferential({ baseline: 'ex-pre', revocation: 'ex-revoke', control: 'ex-primary-denied', variant: 'ex-secondary' }) }).terminalImpact.oracleInput, {
    preRevocationBaselineExchangeId: 'ex-pre',
    revocationEventExchangeId: 'ex-revoke',
    primaryDeniedCheckExchangeId: 'ex-primary-denied',
    secondarySuccessExchangeId: 'ex-secondary',
  })

  // 3) parser_cache_differential -> wire_framing_and_cache_differential helper (parser vs cache priming never mix)
  const cParser = ctx.chain('c-parser', 'parser_cache_differential')
  cParser.control('ex-clean-ctrl')
  cParser.recordHop({ hopId: 'hop_1', target: 'GET /api/prime', exchangeIds: ['ex-prime'], claimedDelta: 'Primed.' })
  cParser.recordHop({ hopId: 'hop_2', target: 'GET /api/probe', exchangeIds: ['ex-probe'], claimedDelta: 'Probed.' })
  cParser.readback('ex-rb')
  assert.equal(cParser.build({ oracleFamily: 'parser_cache_differential' }).terminalImpact.oracleInput, undefined)
  assert.deepEqual(cParser.build({ ...wireFramingAndCacheDifferential({ control: 'ex-clean-ctrl', variant: 'ex-probe', readback: 'ex-rb', property: 'header_normalization', differentialFeature: 'x-forwarded-host' }) }).terminalImpact.oracleInput, {
    mode: 'parser_differential',
    differentialKind: 'header_normalization',
    differentialFeature: 'x-forwarded-host',
    impactKind: 'mutation',
    cleanControlExchangeId: 'ex-clean-ctrl',
    differentialProbeExchangeId: 'ex-probe',
    postMutationReadbackExchangeId: 'ex-rb',
  })
  assert.deepEqual(cParser.build({ ...wireFramingAndCacheDifferential({ control: 'ex-clean-ctrl', prime: 'ex-prime', variant: 'ex-probe', cacheKey: 'k1' }) }).terminalImpact.oracleInput, {
    mode: 'cache_primed',
    cacheKey: 'k1',
    cleanControlExchangeId: 'ex-clean-ctrl',
    victimOrPrimeRequestExchangeId: 'ex-prime',
    attackerProbeExchangeId: 'ex-probe',
  })

  // 4) cross_surface_pivot -> causal_dag: the chain DAG itself is the evidence; no synthesized pivot oracleInput
  const cPivot = ctx.chain('c-pivot', 'cross_surface_pivot')
  cPivot.control('ex-pivot-ctrl')
  cPivot.recordHop({ hopId: 'hop_1', surface: 'http', target: 'POST /api/trigger', exchangeIds: ['ex-h1'], producedCapabilities: ['cap:hop_1:s1'], claimedDelta: 'Triggered pivot.' })
  cPivot.recordHop({ hopId: 'hop_2', surface: 'storage', target: 'GET /api/blob', exchangeIds: ['ex-h2'], consumedCapabilities: ['cap:hop_1:s1'], claimedDelta: 'Read foreign storage.' })
  assert.equal(cPivot.build({ oracleFamily: 'cross_surface_pivot' }).terminalImpact.oracleInput, undefined)
  assert.deepEqual(causalDag(), { primitive: 'causal_dag', oracleInput: {} })

  // 5) dual_tenant_abac: mode-only caller input passes through verbatim; explicit cache-bleed helper names every slot
  const cDual = ctx.chain('c-dual', 'dual_tenant_abac')
  cDual.control('ex-dual-ctrl')
  cDual.recordHop({ hopId: 'hop_1', target: 'GET /api/prime', exchangeIds: ['ex-d1'], claimedDelta: 'Primed.' })
  cDual.recordHop({ hopId: 'hop_2', target: 'GET /api/bled', exchangeIds: ['ex-d2'], claimedDelta: 'Bled.' })
  assert.equal(cDual.build({ oracleFamily: 'dual_tenant_abac' }).terminalImpact.oracleInput, undefined)
  assert.deepEqual(cDual.build({ oracleFamily: 'dual_tenant_abac', oracleInput: { mode: 'dual_org_cache_bleed' } }).terminalImpact.oracleInput, { mode: 'dual_org_cache_bleed' })
  assert.deepEqual(cDual.build({ ...wireFramingAndCacheDifferential({ control: 'ex-dual-ctrl', prime: 'ex-d1', variant: 'ex-d2', dualTenant: true }) }).terminalImpact.oracleInput, {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControlExchangeId: 'ex-dual-ctrl',
    primeActionExchangeId: 'ex-d1',
    bledAccessExchangeId: 'ex-d2',
  })

  // 6) economic_conservation via oracleFamily (non-race sequential steps)
  const cEconSeq = ctx.chain('c-econ-seq', 'ledger_overcredit')
  cEconSeq.control('ex-econ-base')
  cEconSeq.recordHop({ hopId: 'hop_1', target: 'POST /api/apply', exchangeIds: ['ex-econ-act1'], claimedDelta: 'Applied credit.' })
  cEconSeq.readback('ex-econ-final')
  assert.deepEqual(cEconSeq.build({ oracleFamily: 'economic_conservation' }).terminalImpact.oracleInput, {
    baselineReadbackExchangeId: 'ex-econ-base',
    finalReadbackExchangeId: 'ex-econ-final',
    actionExchangeIds: ['ex-econ-act1'],
  })
})
