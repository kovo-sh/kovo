/**
 * Option D SDK (`kovo_verify.ts`) & `ChainBuilder` v2 regression tests:
 *  1. `splitTarget("cap:hop_1:signed_url")` preserves NO leading `/` (string, method-prefixed, `{ path }`)
 *     so `verify-rpc.ts` `EXACT_INLINE_CAP_RE` resolves both full & relative signed URLs and stamps `consumedCapabilities`.
 *  2. `jsonBody` / `textBody` parity in `buildHttpRpcArgs` (inline target object & options arg, `body` takes precedence).
 *  3. `ch.seal` `{ path }` alias and 3-arg `ch.step(hopId, meta, fn)` compatibility.
 *  4. Live `VerifyRpcServer` end-to-end execution of a `compileTraceToKovoVerifyScript` `ChainBuilder` v2 script
 *     with `signed_url` sealing + consumption confirming with 0 `value_binding handle not matched` errors.
 *  5. Strict `<= 800 LOC` pin on `worker/kovo_verify/kovo_verify.ts`.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import test, { type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { Script } from 'node:vm'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { resetRunCustodyBudgets } from '../src/server/derived-custody.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { compileTraceToKovoVerifyScript, type RecordedRequestExchange } from '../src/server/trace-proof-compiler.ts'
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
const SDK_PATH = join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts')

const SIGNED_SIG = 'sig_live_9f8e7d6c5b4a3210fedcba98'
const REL_TOK = 'rel_dl_tok_a1b2c3d4e5f6g7h8'

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
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
    secret: 'member-a-optd-sdk-secret',
    canaryMarkers: [],
    session: { headerType: 'bearer', value: 'member-a-optd-sdk-secret', adapterUsed: 'static' },
  }
  const dualMember: ResolvedPersona = {
    id: 'dual_member',
    handle: 'dual_member',
    roleLabel: 'admin (tenant-a), viewer (tenant-b)',
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: 'dual-member-optd-sdk-secret',
    canaryMarkers: [],
    session: { headerType: 'bearer', value: 'dual-member-optd-sdk-secret', adapterUsed: 'static' },
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
    personas: new Map([['member_a', memberA], ['dual_member', dualMember]]),
    secrets: [],
  }
}

async function startFixture(t: TestContext, runId: string): Promise<{ origin: string; server: VerifyRpcServer; ctx: VerifyContext }> {
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  let origin = ''
  let paidAmount = 100
  let refundedTotal = 0
  let cachePrimed = false
  let itemOwnerTenant = 'tenant-b'
  const httpServer = createServer(async (req, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')

    if (u.pathname === '/api/v1/exports/mint' && req.method === 'POST') {
      const raw = await readBody(req)
      const parsed = raw ? JSON.parse(raw) as Record<string, unknown> : {}
      if (parsed.scope !== 'tenant-b') return sendJson(res, 400, { error: 'missing_scope', got: raw })
      return sendJson(res, 200, {
        signedUrl: `${origin}/files/export/tenant-b/ledger.csv?sig=${SIGNED_SIG}`,
        downloadPath: `/files/export/tenant-b/relative.csv?token=${REL_TOK}`,
      })
    }
    if (u.pathname === '/files/export/tenant-b/ledger.csv' && req.method === 'GET') {
      if (u.searchParams.get('sig') === SIGNED_SIG) {
        return sendJson(res, 200, { tenantId: 'tenant-b', records: [{ id: 'inv-b-901', amountCents: 99000, ownerEmail: 'treasury@tenant-b.test' }] })
      }
      return sendJson(res, 403, { error: 'missing_or_invalid_sig' })
    }
    if (u.pathname === '/files/export/tenant-b/relative.csv' && req.method === 'GET') {
      if (u.searchParams.get('token') === REL_TOK) {
        return sendJson(res, 200, { tenantId: 'tenant-b', records: [{ id: 'inv-b-902', amountCents: 42000, ownerEmail: 'billing@tenant-b.test' }] })
      }
      return sendJson(res, 403, { error: 'missing_or_invalid_token' })
    }
    if (u.pathname === '/api/v1/permissions/prime' && req.method === 'POST') {
      cachePrimed = true
      return sendJson(res, 200, { ok: true, tenantId: 'tenant-a', primed: true })
    }
    if (u.pathname === '/api/v1/reports/export' && req.method === 'GET') {
      if (cachePrimed) {
        return sendJson(res, 200, { tenantId: 'tenant-b', records: [{ id: 'rep-b-401', balanceCents: 750000, ownerEmail: 'cfo@tenant-b.test' }] })
      }
      return sendJson(res, 403, { error: 'admin_role_required_in_tenant_b' })
    }
    if (u.pathname === '/api/v1/items/item-77/export' && req.method === 'GET') {
      if (itemOwnerTenant === 'tenant-a') {
        return sendJson(res, 200, { id: 'item-77', ownerTenantId: 'tenant-a', secretNote: 'transferred-record-payload' })
      }
      return sendJson(res, 403, { error: 'source_tenant_admin_required', entityId: 'item-77' })
    }
    if (u.pathname === '/api/v1/items/item-77/transfer' && req.method === 'POST') {
      itemOwnerTenant = 'tenant-a'
      return sendJson(res, 200, { id: 'item-77', transferred: true, destTenantId: 'tenant-a' })
    }
    if (u.pathname === '/api/v1/orders/ord-1' && req.method === 'GET') {
      return sendJson(res, 200, { orderId: 'ord-1', paidAmount, refundedTotal })
    }
    if (u.pathname === '/api/v1/orders/ord-1/refund' && req.method === 'POST') {
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
    if (u.pathname === '/api/v1/echo' && req.method === 'POST') {
      const raw = await readBody(req)
      return sendJson(res, 200, { raw, contentType: req.headers['content-type'] ?? '' })
    }
    return sendJson(res, 404, { error: 'not_found' })
  }).listen(0, '127.0.0.1')

  t.after(() => new Promise<void>(r => { httpServer.closeAllConnections(); httpServer.close(() => r()) }))
  await once(httpServer, 'listening')
  const port = (httpServer.address() as AddressInfo).port
  origin = `http://127.0.0.1:${port}`

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

test('worker/kovo_verify/kovo_verify.ts stays <= 800 LOC', () => {
  const loc = readFileSync(SDK_PATH, 'utf8').trimEnd().split('\n').length
  assert.ok(loc <= 800, `worker/kovo_verify/kovo_verify.ts must be <= 800 LOC, got ${loc}`)
})

test('live VerifyRpcServer: splitTarget preserves cap:... signed_url handles (no leading /) for full & relative URLs and stamps consumedCapabilities', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-signed-url')

  const ch = ctx.chain('chain-optd-signed-url', 'dual_tenant_abac')
  const ctrl = await ch.control('GET /files/export/tenant-b/ledger.csv', { as: 'member_a' })
  assert.equal(ctrl.status, 403)

  // Mint using jsonBody parity (no `body` field)
  const mint = await ch.step({ method: 'POST', path: '/api/v1/exports/mint', as: 'member_a', jsonBody: { scope: 'tenant-b' } }, { hopId: 'step_1', claimedDelta: 'POST /api/v1/exports/mint' })
  assert.equal(mint.status, 200)

  // Full http:// signed_url sealed via ch.seal (also verify `path` alias -> jsonPath)
  const fullUrlCap = await ch.seal(mint, { path: '$.signedUrl', kind: 'signed_url' })
  assert.match(fullUrlCap, /^cap:.*step_1:s1$/)

  // Consume via `{ method: 'GET', path: fullUrlCap }` -> MUST NOT prepend '/'
  const dlFull = await ch.step({ method: 'GET', path: fullUrlCap }, { hopId: 'step_2', claimedDelta: 'GET signed export' })
  assert.equal(dlFull.status, 200)
  assert.ok(dlFull.consumedCapabilities?.includes(fullUrlCap), `Expected consumedCapabilities to include ${fullUrlCap}, got ${JSON.stringify(dlFull.consumedCapabilities)}`)

  // Relative /... signed_url sealed via ch.seal and consumed as bare string handle in ctx.http_send(cap) inside 3-arg ch.step
  const relUrlCap = await ch.seal(mint, { jsonPath: '$.downloadPath', kind: 'signed_url' })
  const dlRel = await ch.step('step_3', { claimedDelta: 'GET relative signed export' }, () => ctx.http_send(relUrlCap))
  assert.equal(dlRel.status, 200)
  assert.ok(dlRel.consumedCapabilities?.includes(relUrlCap), `Expected consumedCapabilities to include ${relUrlCap}, got ${JSON.stringify(dlRel.consumedCapabilities)}`)

  // Confirm live composite proof using full signed_url chain (p_step_1 -> p_step_2)
  const chProof = ctx.chain('chain-optd-signed-url-confirm', 'cross_tenant_read')
  await chProof.control('GET /files/export/tenant-b/ledger.csv', { as: 'member_a' })
  const s1 = await chProof.step('/api/v1/exports/mint', { hopId: 'p_step_1', method: 'POST', as: 'member_a', jsonBody: { scope: 'tenant-b' } })
  const cap = await chProof.seal(s1, { jsonPath: '$.signedUrl', kind: 'signed_url' })
  const s2 = await chProof.step({ path: cap }, { hopId: 'p_step_2', method: 'GET' })
  assert.equal(s2.status, 200)
  const proved = await chProof.prove({ terminalHopId: 'p_step_2', terminalExchange: s2, claimedImpact: 'Cross-tenant export read via signed_url cap handle.' })
  assert.equal(proved.confirmed, true, `Expected live signed_url chain to confirm: ${JSON.stringify(proved)}`)
})

test('live VerifyRpcServer: jsonBody and textBody forwarding in buildHttpRpcArgs with body precedence', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-body-aliases')

  // 1) options.jsonBody
  const r1 = await ctx.http_send('/api/v1/echo', { method: 'POST', jsonBody: { hello: 'world', n: 7 } })
  assert.equal(r1.status, 200)
  assert.deepEqual(JSON.parse((r1.json as { raw: string }).raw), { hello: 'world', n: 7 })
  assert.match((r1.json as { contentType: string }).contentType, /application\/json/i)

  // 2) inline target.jsonBody
  const r2 = await ctx.http_send({ method: 'POST', path: '/api/v1/echo', jsonBody: { inline: true } })
  assert.equal(r2.status, 200)
  assert.deepEqual(JSON.parse((r2.json as { raw: string }).raw), { inline: true })

  // 3) options.textBody & inline target.textBody
  const r3 = await ctx.http_send('/api/v1/echo', { method: 'POST', textBody: 'plain-text-payload' })
  assert.equal(r3.status, 200)
  assert.equal((r3.json as { raw: string }).raw, 'plain-text-payload')

  const r4 = await ctx.http_send({ method: 'POST', path: '/api/v1/echo', textBody: 'inline-text-payload' })
  assert.equal(r4.status, 200)
  assert.equal((r4.json as { raw: string }).raw, 'inline-text-payload')

  // 4) explicit body wins over jsonBody / textBody
  const r5 = await ctx.http_send('/api/v1/echo', { method: 'POST', body: 'explicit-wins', jsonBody: { ignored: true }, textBody: 'ignored' })
  assert.equal(r5.status, 200)
  assert.equal((r5.json as { raw: string }).raw, 'explicit-wins')
})

test('live VerifyRpcServer: compiled ChainBuilder v2 script with signed_url confirms end-to-end', async t => {
  const { origin, ctx } = await startFixture(t, 'run-optd-compiler-live-e2e')

  const recorded: RecordedRequestExchange[] = [
    {
      exchangeId: 'rec_mint',
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/exports/mint',
      persona: 'member_a',
      requestJson: { scope: 'tenant-b' },
      status: 200,
      responseJson: { signedUrl: `${origin}/files/export/tenant-b/ledger.csv?sig=${SIGNED_SIG}` },
      timestampMs: 100,
    },
    {
      exchangeId: 'rec_dl',
      origin,
      method: 'GET',
      pathAndQuery: `/files/export/tenant-b/ledger.csv?sig=${SIGNED_SIG}`,
      persona: 'member_a',
      status: 200,
      responseJson: { tenantId: 'tenant-b', records: [{ id: 'inv-b-901' }] },
      timestampMs: 200,
    },
  ]

  const compiled = compileTraceToKovoVerifyScript({
    submission: {
      title: 'Signed export cross-tenant read',
      vulnClass: 'cross_tenant_read',
      exchangeIds: ['rec_mint', 'rec_dl'],
      terminalExchangeId: 'rec_dl',
      attackerPersona: 'member_a',
    },
    exchanges: recorded,
    runOrigin: origin,
  })
  assert.equal(compiled.ok, true)
  assert.ok(compiled.script)
  assert.match(compiled.script, /ch\.step\(/)
  assert.match(compiled.script, /ch\.seal\(/)
  assert.doesNotMatch(compiled.script, /\.handle\b/)
  assert.doesNotMatch(compiled.script, /ctx\.seal_capability\(/)
  assert.match(compiled.script, /path:\s*cap_1\b/)

  const rewritten = compiled.script.replace(/^export default\s+/, 'return ')
  new Script(`(function(){ ${rewritten} })`)
  const runCompiled = (new Function(rewritten) as () => (c: VerifyContext) => Promise<{ claims: Array<{ kind: string }> }>)()
  const out = await runCompiled(ctx)
  assert.ok(out.claims.some(c => c.kind === 'composite_receipt'), `Expected confirmed composite_receipt claim, got ${JSON.stringify(out)}`)
})

test('live VerifyRpcServer: ch.control(404) + pre-hop ch.readback(200) + ch.race + post-hop ch.readback(200) synthesizes valid economic baseline/final readbacks and aliases', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-econ-readback')

  const ch = ctx.chain('chain-optd-econ-readback', 'economic_conservation')
  const deniedCtrl = await ch.control('GET /api/v1/orders/missing', { as: 'member_a' })
  assert.equal(deniedCtrl.status, 404)

  // Pre-hop readback (hops.length === 0) MUST be recorded as baseline (NOT in postChainReadbackExchangeIds!)
  const preRb = await ch.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  assert.equal(preRb.status, 200)

  const burst = await ch.race({
    request: { method: 'POST', path: '/api/v1/orders/ord-1/refund', as: 'member_a', body: { amount: 60 } },
    count: 3,
  })
  assert.equal(burst.results.length, 3)

  // Post-hop readbacks: last 2xx MUST be chosen as finalReadbackExchangeId
  const postRb1 = await ch.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  const postRb2 = await ch.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  assert.equal(postRb1.status, 200)
  assert.equal(postRb2.status, 200)

  const built = ch.build({ claimedImpact: 'Concurrent over-refund exceeded paid order amount.' })
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes(deniedCtrl.exchangeId))
  assert.ok(built.terminalImpact.preChainControlExchangeIds?.includes(preRb.exchangeId))
  assert.deepEqual(built.terminalImpact.postChainReadbackExchangeIds, [postRb1.exchangeId, postRb2.exchangeId])
  assert.equal(built.terminalImpact.oracleInput?.baselineReadbackExchangeId, preRb.exchangeId)
  assert.equal(built.terminalImpact.oracleInput?.finalReadbackExchangeId, postRb2.exchangeId)
  assert.deepEqual(built.terminalImpact.oracleInput?.actionExchangeIds, burst.results.map(r => r.exchangeId))

  // All economic_conservation class aliases trigger oracleInput synthesis without picking 4xx controls
  for (const alias of ['conserved_balance', 'ledger_overcredit', 'over_refund', 'double_spend', 'race_condition']) {
    const c = ctx.chain(`chain-alias-${alias}`, alias)
    c.control(deniedCtrl)
    c.readback(preRb)
    c.recordHop({ hopId: 'hop_1', target: 'POST /api/v1/orders/ord-1/refund', exchangeIds: [burst.results[0]!.exchangeId], claimedDelta: 'Refund.' })
    c.readback(postRb2)
    const r = c.build()
    assert.equal(r.terminalImpact.oracleInput?.baselineReadbackExchangeId, preRb.exchangeId, `alias ${alias} baseline`)
    assert.equal(r.terminalImpact.oracleInput?.finalReadbackExchangeId, postRb2.exchangeId, `alias ${alias} final`)
  }

  // When ONLY a 404 control exists (no 2xx baseline), NEVER assign 404 to baselineReadbackExchangeId
  const cNoBase = ctx.chain('chain-optd-econ-no-base', 'economic_conservation')
  cNoBase.control(deniedCtrl)
  cNoBase.recordHop({ hopId: 'hop_1', target: 'POST /api/v1/orders/ord-1/refund', exchangeIds: [burst.results[0]!.exchangeId], claimedDelta: 'Refund.' })
  cNoBase.readback(postRb2)
  assert.equal(cNoBase.build().terminalImpact.oracleInput?.baselineReadbackExchangeId, undefined)

  // Live VerifyRpcServer confirmation succeeds end-to-end with omitted oracleInput & oracleFamily!
  const proved = await ch.prove({ claimedImpact: 'Concurrent over-refund exceeded paid order amount.' })
  assert.equal(proved.confirmed, true, `Expected live economic_conservation with 404 control + pre-hop readback to confirm: ${JSON.stringify(proved)}`)
})

test('ChainBuilder.build() produces strictly forward-only edges with zero cycles when capabilities are re-emitted or backward explicit edges are added', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-dag-acyclic')

  const ch = ctx.chain('chain-optd-acyclic', 'dual_tenant_abac')
  ch.recordHop({
    hopId: 'hop_1',
    target: 'POST /api/step1',
    exchangeIds: ['ex_1'],
    producedCapabilities: ['cap:hop_1:s1'],
    consumedCapabilities: ['cap:hop_2:s2'], // backward auto-edge candidate (hop_2 -> hop_1) MUST be rejected!
    claimedDelta: 'Step 1',
  })
  ch.recordHop({
    hopId: 'hop_2',
    target: 'POST /api/step2',
    exchangeIds: ['ex_2'],
    producedCapabilities: ['cap:hop_1:s1', 'cap:hop_2:s2'], // re-emitting cap:hop_1:s1 MUST NOT overwrite hop_1 as producer!
    consumedCapabilities: ['cap:hop_1:s1'],
    claimedDelta: 'Step 2',
  })
  ch.recordHop({
    hopId: 'hop_3',
    target: 'GET /api/step3',
    exchangeIds: ['ex_3'],
    consumedCapabilities: ['cap:hop_1:s1', 'cap:hop_2:s2'],
    claimedDelta: 'Step 3',
  })
  // Add explicit backward and self-loop edges that would otherwise create a cycle
  ch.edge({ kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_1', capabilityHandle: 'cap:hop_2:s2' })
  ch.edge({ kind: 'value_binding', fromHopId: 'hop_3', toHopId: 'hop_1', capabilityHandle: 'cap:hop_1:s1' })
  ch.edge({ kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_2', capabilityHandle: 'cap:hop_2:s2' })

  const built = ch.build()
  const idx = new Map(built.hops.map((h, i) => [h.hopId, i]))
  const edges = built.causalEdges ?? []
  assert.ok(edges.length >= 2, `Expected forward edges, got ${JSON.stringify(edges)}`)
  for (const e of edges) {
    const fi = idx.get(e.fromHopId)
    const ti = idx.get(e.toHopId)
    assert.ok(fi !== undefined && ti !== undefined && fi < ti, `Expected strictly forward edge, got ${e.fromHopId}(${fi}) -> ${e.toHopId}(${ti})`)
  }
  // cap:hop_1:s1 producer remains hop_1 (not overwritten by hop_2)
  assert.ok(edges.some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2' && e.capabilityHandle === 'cap:hop_1:s1'))
  assert.ok(edges.some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_3' && e.capabilityHandle === 'cap:hop_1:s1'))
  assert.ok(edges.some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_2' && e.toHopId === 'hop_3' && e.capabilityHandle === 'cap:hop_2:s2'))
})

test('live VerifyRpcServer: dual_tenant_abac synthOracleInput auto-populates oracleInput from 401/403/404 control + terminal exchange and confirms', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-dual-tenant-synth')

  // 1) dual_org_cache_bleed: 0 explicit oracleInput + 0 capability edges + preceding 200 readback before 403 control
  const ch = ctx.chain('chain-optd-dual-bleed', 'dual_tenant_abac')
  const okPre = await ch.readback('GET /api/v1/orders/ord-1', { as: 'dual_member' })
  assert.equal(okPre.status, 200)
  const ctrl = await ch.control('GET /api/v1/reports/export', { as: 'dual_member' })
  assert.equal(ctrl.status, 403)
  const s1 = await ch.step('POST /api/v1/permissions/prime', { hopId: 'step_1', as: 'dual_member', claimedDelta: 'Prime tenant-a admin cache.' })
  assert.equal(s1.status, 200)
  const s2 = await ch.step('GET /api/v1/reports/export', { hopId: 'step_2', as: 'dual_member', claimedDelta: 'Read tenant-b report after cache bleed.' })
  assert.equal(s2.status, 200)

  const built = ch.build({ terminalHopId: 'step_2', terminalExchange: s2, claimedImpact: 'Dual-tenant permission cache bleed into tenant-b.' })
  assert.deepEqual(built.terminalImpact.oracleInput, {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControlExchangeId: ctrl.exchangeId,
    primeActionExchangeId: s1.exchangeId,
    bledAccessExchangeId: s2.exchangeId,
  })
  const proved = await ch.prove({ terminalHopId: 'step_2', terminalExchange: s2, claimedImpact: 'Dual-tenant permission cache bleed into tenant-b.' })
  assert.equal(proved.confirmed, true, `Expected live dual_tenant_abac cache bleed to confirm without explicit oracleInput: ${JSON.stringify(proved)}`)

  // 2) cross_tenant_export alias triggers the same dual_tenant_abac synthesis
  const chAlias = ctx.chain('chain-optd-dual-alias', 'cross_tenant_export')
  chAlias.control(ctrl)
  chAlias.recordHop({ hopId: 'h1', target: 'POST /api/v1/permissions/prime', exchangeIds: [s1.exchangeId], claimedDelta: 'Prime.' })
  chAlias.recordHop({ hopId: 'h2', target: 'GET /api/v1/reports/export', exchangeIds: [s2.exchangeId], claimedDelta: 'Read.' })
  assert.deepEqual(chAlias.build().terminalImpact.oracleInput, {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControlExchangeId: ctrl.exchangeId,
    primeActionExchangeId: s1.exchangeId,
    bledAccessExchangeId: s2.exchangeId,
  })

  // 3) cross_org_transfer: auto-synthesizes mode + sourceControlDenied + transferRecord + postTransferReadback + entityId
  const chXfer = ctx.chain('chain-optd-dual-xfer', 'dual_tenant_abac')
  const xCtrl = await chXfer.control('GET /api/v1/items/item-77/export', { as: 'dual_member', entityId: 'item-77' })
  assert.equal(xCtrl.status, 403)
  const xHop1 = await chXfer.step('POST /api/v1/permissions/prime', { hopId: 'x_1', as: 'dual_member', claimedDelta: 'Setup session.' })
  assert.equal(xHop1.status, 200)
  const xHop2 = await chXfer.step('POST /api/v1/items/item-77/transfer', { hopId: 'x_2', as: 'dual_member', entityId: 'item-77', claimedDelta: 'Transfer item-77 to tenant-a.' })
  assert.equal(xHop2.status, 200)
  const xRb = await chXfer.readback('GET /api/v1/items/item-77/export', { as: 'dual_member', entityId: 'item-77' })
  assert.equal(xRb.status, 200)

  const builtXfer = chXfer.build({ claimedImpact: 'Unauthorized cross-org transfer of item-77.' })
  assert.deepEqual(builtXfer.terminalImpact.oracleInput, {
    mode: 'cross_org_transfer',
    sourceControlDeniedExchangeId: xCtrl.exchangeId,
    transferRecordExchangeId: xHop2.exchangeId,
    postTransferReadbackExchangeId: xRb.exchangeId,
    entityId: 'item-77',
  })

  // 4) partial caller oracleInput infers batch_partial_authz without overriding caller fields
  const chBatch = ctx.chain('chain-optd-dual-batch', 'dual_tenant_abac')
  chBatch.control(ctrl)
  chBatch.recordHop({ hopId: 'b1', target: 'POST /api/v1/batch', exchangeIds: [s2.exchangeId], claimedDelta: 'Batch read.' })
  const builtBatch = chBatch.build({ oracleInput: { ownRecordId: 'own-1', foreignRecordId: 'for-2', requestedIds: ['own-1', 'for-2'] } })
  assert.deepEqual(builtBatch.terminalImpact.oracleInput, {
    mode: 'batch_partial_authz',
    ownRecordId: 'own-1',
    foreignRecordId: 'for-2',
    requestedIds: ['own-1', 'for-2'],
    singleForeignControlDeniedExchangeId: ctrl.exchangeId,
    batchRequestExchangeId: s2.exchangeId,
  })
})
