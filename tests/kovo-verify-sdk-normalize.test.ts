/**
 * Unit + live VerifyRpcServer regression tests for kovo_verify.ts capability handle unwrapping,
 * value_binding alias normalization, and unambiguous capability auto-inference.
 */
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import test, { type TestContext } from 'node:test'
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
import {
  VerifyContext,
  normalizeCompositeReceipt,
  unwrapCapabilityHandle,
} from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:4100'
const MINT_TOK = 'mint_sdk_norm_opaque_tok_442211'
const SIGN_KEY = 'hmac_sdk_norm_signing_key_887766'

function makeGrant(origin: string, port: number): Grant {
  const memberA: ResolvedPersona = {
    id: 'member_a',
    handle: 'member_a',
    roleLabel: 'member (tenant-a)',
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: 'member-a-sdk-norm-session-token',
    canaryMarkers: [],
    session: { headerType: 'bearer', value: 'member-a-sdk-norm-session-token', adapterUsed: 'static' },
  }
  return {
    origin,
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    allowedPorts: [port],
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map([['member_a', memberA]]),
    secrets: [],
  }
}

async function startFixture(t: TestContext, runId: string): Promise<{ origin: string; server: VerifyRpcServer; ctx: VerifyContext }> {
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const httpServer = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    const hdrTok = String(req.headers['x-export-token'] ?? '')

    if (u.pathname === '/api/v1/mint' && req.method === 'POST') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ token: MINT_TOK, signingKey: SIGN_KEY }))
      return
    }
    if (u.pathname === '/api/v1/export') {
      if (auth === `Bearer ${MINT_TOK}` || hdrTok === MINT_TOK) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ tenant: 'tenant-b', records: [{ id: 'rec-b-9', email: 'victim@tenant-b.test' }] }))
        return
      }
      res.writeHead(403, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }
    if (u.pathname === '/api/v1/signed' && req.method === 'POST') {
      const chunks: Buffer[] = []
      req.on('data', c => chunks.push(c))
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8')
        const expected = createHmac('sha256', SIGN_KEY).update(body).digest('hex')
        if (req.headers['x-sig'] === expected) {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ ok: true }))
        } else {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'bad_sig' }))
        }
      })
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'not_found' }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(resolve => httpServer.close(() => resolve())))
  await once(httpServer, 'listening')
  const port = (httpServer.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`

  const server = new VerifyRpcServer({
    broker: new RequestBroker(),
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

test('unwrapCapabilityHandle unwraps capability objects and preserves valid strings/JSON specs unchanged', () => {
  assert.equal(unwrapCapabilityHandle('cap:hop_1:tok'), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle('  cap:hop_1:tok  '), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle('cap_opaque_123'), 'cap_opaque_123')

  const jsonSpec = '{"handle":"cap:hop_1:tok","target":"bearer"}'
  assert.equal(unwrapCapabilityHandle(jsonSpec), jsonSpec)

  const sealedObj = { handle: 'cap:hop_1:tok', meta: { kind: 'bearer_token' }, exchangeId: 'ex-1', sealExchangeId: 'ex-2', scrubbedPreview: 'cap...' }
  assert.equal(unwrapCapabilityHandle(sealedObj), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ derivedHandle: 'cap:hop_2:jwt' }), 'cap:hop_2:jwt')
  assert.equal(unwrapCapabilityHandle({ capability: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ capabilityHandle: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ capability_handle: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ sealedHandle: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ sealedCapability: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ cap: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ token: 'cap:hop_1:tok' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ id: 'cap:hop_1:tok' }), 'cap:hop_1:tok')

  // Nested sealed capability objects unwrap cleanly
  assert.equal(unwrapCapabilityHandle({ handle: sealedObj, target: 'bearer' }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ sealedCapability: sealedObj }), 'cap:hop_1:tok')
  assert.equal(unwrapCapabilityHandle({ handle: '   ', capability: 'cap:hop_1:tok' }), 'cap:hop_1:tok')

  // Unrecognized objects & non-objects are returned untouched (never fabricated)
  const bogus = { unrelated: 'foo' }
  assert.strictEqual(unwrapCapabilityHandle(bogus), bogus)
  assert.equal(unwrapCapabilityHandle(null), null)
  assert.equal(unwrapCapabilityHandle(undefined), undefined)
  assert.equal(unwrapCapabilityHandle(42), 42)
})

test('normalizeCompositeReceipt normalizes value_binding capability aliases & hop capability objects', () => {
  const sealed = { handle: 'cap:hop_1:tok', meta: {}, exchangeId: 'ex-1', sealExchangeId: 'ex-s1', scrubbedPreview: '...' }
  const aliasCases: Array<Record<string, unknown>> = [
    { capability: 'cap:hop_1:tok' },
    { capability: sealed },
    { cap: 'cap:hop_1:tok' },
    { handle: sealed },
    { capabilityHandle: sealed },
    { capability_handle: 'cap:hop_1:tok' },
    { sealedHandle: 'cap:hop_1:tok' },
    { sealedCapability: sealed },
    { derivedHandle: 'cap:hop_1:tok' },
  ]

  for (const aliasFields of aliasCases) {
    const wrapped = normalizeCompositeReceipt({
      chainId: 'chain-alias-cap',
      terminalVulnClass: 'cross_tenant_read',
      hops: [
        { hopId: 'hop_1', target: 'POST /api/v1/mint', exchangeIds: ['ex-1'], claimedDelta: 'Minted token.', produces: [sealed] },
        { hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: ['ex-2'], claimedDelta: 'Read export.', consumes: [sealed], credentialHandle: sealed },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', ...aliasFields }],
      terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Foreign tenant read.' },
    }, ORIGIN)

    const rec = wrapped.receipt as Record<string, unknown>
    const hops = rec.hops as Array<Record<string, unknown>>
    assert.deepEqual(hops[0]!.producedCapabilities, ['cap:hop_1:tok'])
    assert.deepEqual(hops[1]!.consumedCapabilities, ['cap:hop_1:tok'])
    assert.equal(hops[1]!.credentialHandle, 'cap:hop_1:tok')

    const edges = rec.causalEdges as Array<Record<string, unknown>>
    assert.equal(edges[0]!.capabilityHandle, 'cap:hop_1:tok')
    for (const aliasKey of ['capability', 'cap', 'handle', 'capability_handle', 'sealedHandle', 'sealedCapability', 'derivedHandle']) {
      assert.equal(aliasKey in edges[0]!, false, `alias key ${aliasKey} should be stripped after normalization`)
    }
    const parsed = compositeProofReceiptSchema.safeParse(rec)
    assert.equal(parsed.success, true, `Alias ${JSON.stringify(aliasFields)} failed Zod schema: ${JSON.stringify(parsed)}`)
  }
})

test('normalizeCompositeReceipt auto-infers value_binding.capabilityHandle ONLY when unambiguous and never fabricates', () => {
  const sealedA = { handle: 'cap:hop_1:a', meta: {}, exchangeId: 'ex-1' }
  const sealedB = { handle: 'cap:hop_1:b', meta: {}, exchangeId: 'ex-1' }

  const runNorm = (hops: unknown[], edges: unknown[], capOrigins?: Map<string, string>) => {
    const res = normalizeCompositeReceipt({
      chainId: 'chain-infer',
      terminalVulnClass: 'cross_tenant_read',
      hops,
      causalEdges: edges,
      terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Read export.' },
    }, ORIGIN, capOrigins)
    return res.receipt as { causalEdges: Array<Record<string, unknown>> }
  }

  // 1) Intersection of fromHop.produces (2 handles) and toHop.consumes (1 handle) -> unambiguous
  const r1 = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1', produces: [sealedA, sealedB] },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2', consumes: [sealedB] },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(r1.causalEdges[0]!.capabilityHandle, 'cap:hop_1:b')

  // 2) Single fromHop.sealedCapability + toHop.target.pathAndQuery disambiguates 2 produced caps
  const r2 = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1', producedCapabilities: ['cap:hop_1:a', 'cap:hop_1:b'] },
      { hopId: 'hop_2', target: 'GET /export?tok=cap:hop_1:a', exchangeIds: ['ex-2'], claimedDelta: 'h2' },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(r2.causalEdges[0]!.capabilityHandle, 'cap:hop_1:a')

  // 3) Single fromHop.sealedCapability with no conflicting toHop consumes
  const r3 = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1', sealedCapability: sealedA },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2' },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: '' }],
  )
  assert.equal(r3.causalEdges[0]!.capabilityHandle, 'cap:hop_1:a')

  // 4) Unambiguous from ctx._capOrigins when fromHop omitted producedCapabilities
  const r4 = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1' },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2' },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
    new Map([['cap:hop_1:a', 'ex-1']]),
  )
  assert.equal(r4.causalEdges[0]!.capabilityHandle, 'cap:hop_1:a')

  // 5) Single toHop.consumedCapabilities when fromHop omitted producedCapabilities and no other hop produces it
  const r5 = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1' },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2', credentialHandle: sealedA },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(r5.causalEdges[0]!.capabilityHandle, 'cap:hop_1:a')

  // 6) Non-capability persona string in credentialHandle is NEVER mistaken for a capability handle
  const rPersona = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1' },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2', credentialHandle: 'member_a' },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(rPersona.causalEdges[0]!.capabilityHandle, undefined)

  // 7) Ambiguous (2 handles bridge fromHop -> toHop) -> must NOT guess
  const rAmbig = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1', producedCapabilities: ['cap:hop_1:a', 'cap:hop_1:b'] },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2', consumedCapabilities: ['cap:hop_1:a', 'cap:hop_1:b'] },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(rAmbig.causalEdges[0]!.capabilityHandle, undefined)
  assert.equal(compositeProofReceiptSchema.safeParse(rAmbig).success, false)

  // 8) No handles anywhere -> must NOT fabricate
  const rEmpty = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1' },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2' },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(rEmpty.causalEdges[0]!.capabilityHandle, undefined)
  assert.equal(compositeProofReceiptSchema.safeParse(rEmpty).success, false)

  // 9) Cross-hop mismatch (hop_0 produced cap, edge is hop_1 -> hop_2) -> must NOT misattribute
  const rWrongHop = runNorm(
    [
      { hopId: 'hop_0', target: 'POST /init', exchangeIds: ['ex-0'], claimedDelta: 'h0', producedCapabilities: ['cap:hop_0:a'] },
      { hopId: 'hop_1', target: 'POST /mid', exchangeIds: ['ex-1'], claimedDelta: 'h1' },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2', consumedCapabilities: ['cap:hop_0:a'] },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' }],
  )
  assert.equal(rWrongHop.causalEdges[0]!.capabilityHandle, undefined)

  // 10) Existing valueDigest is preserved without forcing capabilityHandle
  const digest = 'a'.repeat(64)
  const rDigest = runNorm(
    [
      { hopId: 'hop_1', target: 'POST /mint', exchangeIds: ['ex-1'], claimedDelta: 'h1', producedCapabilities: ['cap:hop_1:a'] },
      { hopId: 'hop_2', target: 'GET /export', exchangeIds: ['ex-2'], claimedDelta: 'h2' },
    ],
    [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', valueDigest: digest }],
  )
  assert.equal(rDigest.causalEdges[0]!.valueDigest, digest)
  assert.equal(rDigest.causalEdges[0]!.capabilityHandle, undefined)
})

test('live VerifyRpcServer: http_send, hmac_sign, jwt_sign, ChainBuilder, and prove_composite unwrap capability objects and normalize value_binding edges', async t => {
  const { ctx } = await startFixture(t, 'run-sdk-norm-live')

  const ctrl = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'control' })
  assert.equal(ctrl.status, 403)

  const mint = await ctx.http_send('/api/v1/mint', { method: 'POST', as: 'member_a', role: 'probe' })
  assert.equal(mint.status, 200)

  const tokCap = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'hop_1', slot: 'tok', jsonPath: '$.token', kind: 'bearer_token' })
  const keyCap = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'hop_1', slot: 'key', jsonPath: '$.signingKey', kind: 'hmac_key' })

  // 1) http_send accepts raw SealedCapability object, nested { handle: cap, target }, and aliased wrappers
  const exRawObj = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: tokCap as never })
  assert.equal(exRawObj.status, 200)
  assert.equal(exRawObj.consumedCapabilityId, tokCap.handle)

  const exNestedSpec = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { handle: tokCap, target: 'bearer' } as never })
  assert.equal(exNestedSpec.status, 200)
  assert.equal(exNestedSpec.consumedCapabilityId, tokCap.handle)

  const exHeaderAlias = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { capability: tokCap, target: 'header', headerName: 'X-Export-Token' } as never })
  assert.equal(exHeaderAlias.status, 200)
  assert.equal(exHeaderAlias.consumedCapabilityId, tokCap.handle)

  const exSealedHandle = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { sealedHandle: tokCap.handle } as never })
  assert.equal(exSealedHandle.status, 200)
  assert.equal(exSealedHandle.consumedCapabilityId, tokCap.handle)

  const exIdAlias = await ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { id: tokCap.handle } as never })
  assert.equal(exIdAlias.status, 200)
  assert.equal(exIdAlias.consumedCapabilityId, tokCap.handle)

  // Malformed object with no handle is still rejected cleanly by host
  await assert.rejects(
    () => ctx.http_send('/api/v1/export', { as: 'member_a', role: 'probe', capability: { bogus: 'nope' } as never }),
    /capability must be a handle string/i,
  )

  // 2) hmac_sign & jwt_sign unwrap aliased capability wrappers
  const payload = JSON.stringify({ action: 'sync' })
  const sig = await ctx.hmac_sign({ secretHandle: { sealedHandle: keyCap.handle } as never, payload })
  assert.match(sig.derivedHandle, /^cap:/)
  const signedRes = await ctx.http_send('/api/v1/signed', { method: 'POST', as: 'member_a', role: 'probe', headers: { 'x-sig': sig.derivedHandle, 'content-type': 'application/json' }, body: payload })
  assert.equal(signedRes.status, 200)

  const jwt = await ctx.jwt_sign({ secretHandle: { capability: keyCap } as never, claims: { sub: 'svc' }, hopReceiptId: 'hop_j', slot: 'jwt' })
  assert.match(jwt.derivedHandle, /^cap:/)

  // 3) prove_composite confirms live with aliased `capability: tokCap` on value_binding
  const confirmedAlias = await ctx.prove_composite({
    chainId: 'chain-live-cap-alias',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', target: 'POST /api/v1/mint', exchangeIds: [mint.exchangeId], claimedDelta: 'Minted token.', producedCapabilities: [tokCap] as never },
      { hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: [exRawObj.exchangeId], claimedDelta: 'Read export.', consumedCapabilities: [tokCap] as never },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capability: tokCap } as never],
    controlExchanges: [ctrl],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Foreign tenant read via aliased edge.', terminalExchangeId: exRawObj.exchangeId },
  } as never)
  assert.equal(confirmedAlias.confirmed, true, `Expected aliased value_binding to confirm: ${JSON.stringify(confirmedAlias)}`)

  // 4) prove_composite confirms live when value_binding omits capabilityHandle and hops unambiguously bridge via produces/consumes
  const confirmedInferred = await ctx.prove_composite({
    chainId: 'chain-live-cap-infer',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', target: 'POST /api/v1/mint', exchangeIds: [mint.exchangeId], claimedDelta: 'Minted token.', produces: [tokCap] },
      { hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: [exNestedSpec.exchangeId], claimedDelta: 'Read export.', consumes: [tokCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' } as never],
    controlExchanges: [ctrl],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Foreign tenant read via inferred value_binding.', terminalExchangeId: exNestedSpec.exchangeId },
  } as never)
  assert.equal(confirmedInferred.confirmed, true, `Expected inferred value_binding to confirm: ${JSON.stringify(confirmedInferred)}`)

  // 5) prove_composite rejects cleanly when value_binding omits capabilityHandle and hops have NO bridging capability (never fabricates)
  const rejectedUnbound = await ctx.prove_composite({
    chainId: 'chain-live-cap-missing',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', target: 'GET /api/v1/export', exchangeIds: [ctrl.exchangeId], claimedDelta: 'Control only.' },
      { hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: [exRawObj.exchangeId], claimedDelta: 'Read export.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2' } as never],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Should fail schema cleanly.', terminalExchangeId: exRawObj.exchangeId },
  } as never)
  assert.equal(rejectedUnbound.confirmed, false)

  // 6) ChainBuilder unwraps capability objects in recordHop() and edge()
  const chain = ctx.chain('chain-builder-unwrap', 'cross_tenant_read')
  chain.control(ctrl)
  chain.recordHop({ hopId: 'hop_1', target: 'POST /api/v1/mint', exchangeIds: [mint.exchangeId], claimedDelta: 'Minted token.', producedCapabilities: [tokCap as never] })
  chain.recordHop({ hopId: 'hop_2', target: 'GET /api/v1/export', exchangeIds: [exHeaderAlias.exchangeId], claimedDelta: 'Read export.', consumedCapabilities: [tokCap as never] })
  chain.edge({ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sealedCapability: tokCap } as never)
  const provedChain = await chain.prove({ claimedImpact: 'Foreign tenant read via ChainBuilder unwrap.', terminalExchange: exHeaderAlias })
  assert.equal(provedChain.confirmed, true, `Expected ChainBuilder with unwrapped capability objects to confirm: ${JSON.stringify(provedChain)}`)
})
