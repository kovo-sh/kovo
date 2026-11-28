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
import { accessDifferential, normalizeCompositeReceipt, VerifyContext, wireFramingAndCacheDifferential } from '../worker/kovo_verify/kovo_verify.ts'

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
  const memberUnscoped: ResolvedPersona = {
    id: 'member_unscoped',
    handle: 'member_unscoped',
    roleLabel: 'member',
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: 'member-unscoped-optd-sdk-secret',
    canaryMarkers: [],
    session: { headerType: 'bearer', value: 'member-unscoped-optd-sdk-secret', adapterUsed: 'static' },
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
    personas: new Map([['member_a', memberA], ['dual_member', dualMember], ['member_unscoped', memberUnscoped]]),
    secrets: [],
  }
}

async function startFixture(t: TestContext, runId: string, opts?: { withCanary?: boolean }): Promise<{ origin: string; server: VerifyRpcServer; ctx: VerifyContext; triggerOob?: (token: string) => void }> {
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  let origin = ''
  let paidAmount = 100
  let refundedTotal = 0
  let cachePrimed = false
  let itemOwnerTenant = 'tenant-b'
  let entryWarmed = false
  const FWD_TOK = 'fwd_tok_aabbccddeeff112233'
  const oobHits = new Map<string, Array<{ protocol: string; token: string; remoteIp: string; timestamp: number }>>()
  const httpServer = createServer(async (req, res) => {
    const u = new URL(req.url ?? '/', 'http://127.0.0.1')

    if (u.pathname === '/api/v1/cache/warm' && req.method === 'POST') {
      entryWarmed = true
      return sendJson(res, 200, { ok: true, entityId: 'entry-99', warmed: true })
    }
    if (u.pathname === '/api/v1/cache/fwd' && req.method === 'POST') {
      if (!entryWarmed) return sendJson(res, 403, { error: 'not_warmed' })
      return sendJson(res, 200, { ok: true, entityId: 'entry-99', dlToken: FWD_TOK })
    }
    if (u.pathname === '/api/v1/cache/list' && req.method === 'GET') {
      if (req.headers.authorization === `Bearer ${FWD_TOK}`) return sendJson(res, 200, { items: ['doc-1'] })
      return sendJson(res, 403, { error: 'denied' })
    }
    if (u.pathname === '/api/v1/cache/open' && req.method === 'GET') {
      if (req.headers.authorization === `Bearer ${FWD_TOK}`) return sendJson(res, 200, { preview: 'header' })
      return sendJson(res, 403, { error: 'denied' })
    }
    if (u.pathname === '/api/v1/cache/content' && req.method === 'GET') {
      if (entryWarmed && req.headers.authorization === `Bearer ${FWD_TOK}`) {
        return sendJson(res, 200, { tenantId: 'tenant-b', records: [{ id: 'doc-99', ownerEmail: 'sec@tenant-b.test', secretValue: 'cross-tenant-doc-payload' }] })
      }
      return sendJson(res, 403, { error: 'forbidden_content' })
    }

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
      return sendJson(res, 200, { ok: true, tenantId: 'tenant-a', primed: true, sessionTok: 'dual_bleed_tok_001122334455' })
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

  let oobSeq = 0
  const canary = opts?.withCanary ? {
    mintCanary: (_r: string, label: string) => {
      const token = `oob_tok_${++oobSeq}_${label.replace(/[^a-z0-9]/gi, '')}`
      const httpUrl = `http://oob.local.test/${token}`
      return { token, httpUrl, url: httpUrl, dnsHost: `${token}.oob.local.test` }
    },
    checkCanary: (token: string) => {
      const hits = oobHits.get(token) ?? []
      return { found: true, triggered: hits.length > 0, hit: hits.length > 0, hits, detail: hits[hits.length - 1] }
    },
  } : undefined
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(origin, port),
    ...(canary ? { canary } : {}),
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

  const triggerOob = (token: string) => {
    const list = oobHits.get(token) ?? []
    list.push({ protocol: 'http', token, remoteIp: '127.0.0.1', timestamp: Date.now() })
    oobHits.set(token, list)
  }
  return { origin, server, ctx: new VerifyContext(), triggerOob }
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

  // Confirm live composite proof using full signed_url chain (p_step_1 -> p_step_2) in a fresh clean session
  const { ctx: proofCtx } = await startFixture(t, 'run-optd-sdk-signed-url-confirm')
  const chProof = proofCtx.chain('chain-optd-signed-url-confirm', 'cross_tenant_read')
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

  // A2: no benchmark class-alias table -> aliases never guess an oracleInput; explicit economic_conservation fills role-tagged slots (never 4xx controls)
  for (const alias of ['conserved_balance', 'ledger_overcredit', 'over_refund', 'double_spend', 'race_condition']) {
    const c = ctx.chain(`chain-alias-${alias}`, alias)
    c.control(deniedCtrl)
    c.readback(preRb)
    c.recordHop({ hopId: 'hop_1', target: 'POST /api/v1/orders/ord-1/refund', exchangeIds: [burst.results[0]!.exchangeId], claimedDelta: 'Refund.' })
    c.readback(postRb2)
    assert.equal(c.build().terminalImpact.oracleInput, undefined, `alias ${alias} must not guess an oracleInput`)
    const r = c.build({ oracleFamily: 'economic_conservation' })
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

test('live VerifyRpcServer: dual_tenant_abac leaves oracleInput undefined when omitted so host deriveHostDualTenantRawInput/multiHopDualDag runs, and explicit primitive helpers name refs by role', async t => {
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

  // Leaving oracleInput undefined lets host deriveHostDualTenantRawInput confirm cleanly without forging partial dual_org_cache_bleed
  const built = ch.build({ terminalHopId: 'step_2', terminalExchange: s2, claimedImpact: 'Dual-tenant permission cache bleed into tenant-b.' })
  assert.equal(built.terminalImpact.oracleInput, undefined)
  const proved = await ch.prove({ terminalHopId: 'step_2', terminalExchange: s2, claimedImpact: 'Dual-tenant permission cache bleed into tenant-b.' })
  assert.equal(proved.confirmed, true, `Expected live dual_tenant_abac cache bleed to confirm via host deriveHostDualTenantRawInput: ${JSON.stringify(proved)}`)

  // A2: partial caller oracleInput passes through verbatim (no positional prevEx/termEx guessing); the explicit
  // wire_framing_and_cache_differential helper names every slot by role.
  const builtPartialBleed = ch.build({ terminalHopId: 'step_2', terminalExchange: s2, oracleInput: { primeTenantId: 'tenant-a', targetTenantId: 'tenant-b' } })
  assert.deepEqual(builtPartialBleed.terminalImpact.oracleInput, { primeTenantId: 'tenant-a', targetTenantId: 'tenant-b' })
  const builtExplicitBleed = ch.build({ terminalHopId: 'step_2', terminalExchange: s2, ...wireFramingAndCacheDifferential({ control: ctrl, prime: s1, variant: s2, dualTenant: true }) })
  assert.equal(builtExplicitBleed.terminalImpact.oracleFamily, 'dual_tenant_abac')
  assert.deepEqual(builtExplicitBleed.terminalImpact.oracleInput, {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControlExchangeId: ctrl.exchangeId,
    primeActionExchangeId: s1.exchangeId,
    bledAccessExchangeId: s2.exchangeId,
  })

  // 2) cross_tenant_* aliases NEVER auto-synthesize dual_tenant_abac oracleInput when oracleFamily and oracleInput are omitted
  for (const cls of ['cross_tenant_export', 'cross_tenant_read', 'cross_tenant_write', 'cross_tenant_idor'] as const) {
    const chAlias = ctx.chain(`chain-optd-alias-${cls}`, cls)
    chAlias.control(ctrl)
    chAlias.recordHop({ hopId: 'h1', target: 'POST /api/v1/permissions/prime', exchangeIds: [s1.exchangeId], claimedDelta: 'Prime.' })
    chAlias.recordHop({ hopId: 'h2', target: 'GET /api/v1/reports/export', exchangeIds: [s2.exchangeId], claimedDelta: 'Read.' })
    assert.equal(chAlias.build().terminalImpact.oracleInput, undefined, `${cls} must not auto-synthesize dual_tenant_abac oracleInput`)
  }

  // 3) cross_org_transfer: omits oracleInput when caller omits it; fills exchange refs when caller supplies cross_org_transfer/entityId oracleInput
  const chXfer = ctx.chain('chain-optd-dual-xfer', 'dual_tenant_abac')
  const xCtrl = await chXfer.control('GET /api/v1/items/item-77/export', { as: 'dual_member', entityId: 'item-77' })
  assert.equal(xCtrl.status, 403)
  const xHop1 = await chXfer.step('POST /api/v1/permissions/prime', { hopId: 'x_1', as: 'dual_member', claimedDelta: 'Setup session.' })
  assert.equal(xHop1.status, 200)
  const xHop2 = await chXfer.step('POST /api/v1/items/item-77/transfer', { hopId: 'x_2', as: 'dual_member', entityId: 'item-77', claimedDelta: 'Transfer item-77 to tenant-a.' })
  assert.equal(xHop2.status, 200)
  const xRb = await chXfer.readback('GET /api/v1/items/item-77/export', { as: 'dual_member', entityId: 'item-77' })
  assert.equal(xRb.status, 200)

  assert.equal(chXfer.build({ claimedImpact: 'Unauthorized cross-org transfer of item-77.' }).terminalImpact.oracleInput, undefined)
  assert.deepEqual(chXfer.build({ claimedImpact: 'Unauthorized cross-org transfer of item-77.', oracleInput: { mode: 'cross_org_transfer' } }).terminalImpact.oracleInput, { mode: 'cross_org_transfer' })
  const builtXfer = chXfer.build({ claimedImpact: 'Unauthorized cross-org transfer of item-77.', ...accessDifferential({ control: xCtrl, variant: xHop2, readback: xRb, entityId: 'item-77' }) })
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
  const builtBatch = chBatch.build({ ...accessDifferential({ control: ctrl, variant: s2, ownRecordId: 'own-1', foreignRecordId: 'for-2', requestedIds: ['own-1', 'for-2'] }) })
  assert.deepEqual(builtBatch.terminalImpact.oracleInput, {
    mode: 'batch_partial_authz',
    ownRecordId: 'own-1',
    foreignRecordId: 'for-2',
    requestedIds: ['own-1', 'for-2'],
    singleForeignControlDeniedExchangeId: ctrl.exchangeId,
    batchRequestExchangeId: s2.exchangeId,
  })
})

test('live VerifyRpcServer: v8-m2-r3-wb regression — NO missing_tenant_scope on dual_tenant_abac, broken_access_control, bola, or cross_tenant_* multi-hop value_binding chains', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-dual-tenant-vb')

  // 1) dual_tenant_abac + value_binding edge + dual_member + omitted oracleInput -> host derives & confirms live
  const chBleed = ctx.chain('chain-optd-dual-vb-bleed', 'dual_tenant_abac')
  const ctrl = await chBleed.control('GET /api/v1/reports/export', { as: 'dual_member' })
  assert.equal(ctrl.status, 403)
  const s1 = await chBleed.step('POST /api/v1/permissions/prime', { hopId: 'vb_1', as: 'dual_member', claimedDelta: 'Prime tenant-a session.' })
  assert.equal(s1.status, 200)
  const tokCap = await chBleed.seal(s1, { jsonPath: '$.sessionTok', kind: 'header_secret' })
  const s2 = await chBleed.step('GET /api/v1/reports/export', {
    hopId: 'vb_2',
    as: 'dual_member',
    capability: { handle: tokCap, target: 'header', headerName: 'x-session-tok' },
    claimedDelta: 'Read tenant-b report with value_binding after cache bleed.',
  })
  assert.equal(s2.status, 200)

  const builtBleed = chBleed.build({ terminalHopId: 'vb_2', terminalExchange: s2, claimedImpact: 'Dual-tenant cache bleed on multi-hop value_binding chain.' })
  assert.ok((builtBleed.causalEdges ?? []).some(e => e.kind === 'value_binding' && e.fromHopId === 'vb_1' && e.toHopId === 'vb_2'))
  assert.equal(builtBleed.terminalImpact.oracleInput, undefined)
  const provedBleed = await chBleed.prove({ terminalHopId: 'vb_2', terminalExchange: s2, claimedImpact: 'Dual-tenant cache bleed on multi-hop value_binding chain.' })
  assert.equal(provedBleed.confirmed, true, `Expected live dual_tenant_abac value_binding chain to confirm: ${JSON.stringify(provedBleed)}`)

  // 2) Exact M2 R3 WB failure shape: unscoped persona (no tenant in roleLabel) + value_binding chain -> MUST NOT synthesize partial dual_org_cache_bleed or fail missing_tenant_scope!
  for (const vulnClass of ['dual_tenant_abac', 'broken_access_control', 'bola', 'cross_tenant_read', 'cross_tenant_export'] as const) {
    const { ctx: loopCtx } = await startFixture(t, `run-optd-sdk-m2r3-${vulnClass}`)
    const chM2 = loopCtx.chain(`chain-m2r3-${vulnClass}`, vulnClass)
    const c = await chM2.control('GET /files/export/tenant-b/ledger.csv', { as: 'member_unscoped' })
    assert.equal(c.status, 403)
    const m1 = await chM2.step('/api/v1/exports/mint', { hopId: `m1_${vulnClass}`, method: 'POST', as: 'member_unscoped', jsonBody: { scope: 'tenant-b' } })
    assert.equal(m1.status, 200)
    const urlCap = await chM2.seal(m1, { jsonPath: '$.signedUrl', kind: 'signed_url', slot: `s_${vulnClass}` })
    const m2 = await chM2.step({ path: urlCap }, { hopId: `m2_${vulnClass}`, method: 'GET' })
    assert.equal(m2.status, 200)
    const builtM2 = chM2.build({ terminalHopId: `m2_${vulnClass}`, terminalExchange: m2, claimedImpact: `Cross-tenant export read (${vulnClass}) via signed_url capability.` })
    assert.equal(builtM2.terminalImpact.oracleInput, undefined, `${vulnClass} must leave oracleInput undefined when caller omits it`)
    const provedM2 = await chM2.prove({ terminalHopId: `m2_${vulnClass}`, terminalExchange: m2, claimedImpact: `Cross-tenant export read (${vulnClass}) via signed_url capability.` })
    assert.doesNotMatch(provedM2.reason, /missing_tenant_scope/i, `${vulnClass} must never fail missing_tenant_scope: ${JSON.stringify(provedM2)}`)
    assert.equal(provedM2.confirmed, true, `Expected live ${vulnClass} multi-hop value_binding chain to confirm: ${JSON.stringify(provedM2)}`)
  }

  // 3) broken_access_control & bola with EXPLICIT oracleFamily: 'dual_tenant_abac' + omitted oracleInput MUST NOT synthesize partial dual_org_cache_bleed or fail missing_tenant_scope
  for (const vulnClass of ['broken_access_control', 'bola'] as const) {
    const { ctx: expCtx } = await startFixture(t, `run-optd-sdk-m2r3-exp-${vulnClass}`)
    const chExp = expCtx.chain(`chain-m2r3-explicit-${vulnClass}`, vulnClass)
    const c = await chExp.control('GET /files/export/tenant-b/ledger.csv', { as: 'dual_member' })
    assert.equal(c.status, 403)
    const m1 = await chExp.step('/api/v1/exports/mint', { hopId: `e1_${vulnClass}`, method: 'POST', as: 'dual_member', jsonBody: { scope: 'tenant-b' } })
    const urlCap = await chExp.seal(m1, { jsonPath: '$.signedUrl', kind: 'signed_url', slot: `se_${vulnClass}` })
    const m2 = await chExp.step({ path: urlCap }, { hopId: `e2_${vulnClass}`, method: 'GET' })
    const builtExp = chExp.build({ terminalHopId: `e2_${vulnClass}`, terminalExchange: m2, oracleFamily: 'dual_tenant_abac', claimedImpact: `Cross-tenant ${vulnClass} with explicit dual_tenant_abac family.` })
    assert.equal(builtExp.terminalImpact.oracleInput, undefined)
    const provedExp = await chExp.prove({ terminalHopId: `e2_${vulnClass}`, terminalExchange: m2, oracleFamily: 'dual_tenant_abac', claimedImpact: `Cross-tenant ${vulnClass} with explicit dual_tenant_abac family.` })
    assert.doesNotMatch(provedExp.reason, /missing_tenant_scope/i, `explicit dual_tenant_abac on ${vulnClass} must not fail missing_tenant_scope: ${JSON.stringify(provedExp)}`)
    assert.equal(provedExp.confirmed, true, `Expected explicit dual_tenant_abac on ${vulnClass} to confirm via host derivation / multiHopDualDag: ${JSON.stringify(provedExp)}`)
  }
})

test('ChainBuilder and normalizeCompositeReceipt normalize hyphenated/whitespace terminalVulnClass to canonical snake_case', async t => {
  const { origin, ctx } = await startFixture(t, 'run-optd-sdk-vuln-norm')

  for (const [raw, expected] of [
    ['broken-access-control', 'broken_access_control'],
    ['Privilege-Escalation', 'privilege_escalation'],
    ['  dual-tenant-abac  ', 'dual_tenant_abac'],
    ['economic conservation', 'economic_conservation'],
    ['over-refund', 'over_refund'],
  ] as const) {
    const ch = ctx.chain(`norm-${expected}`, raw)
    assert.equal(ch.terminalVulnClass, expected)
    ch.recordHop({ hopId: 'hop_1', target: 'GET /api/v1/reports/export', exchangeIds: ['ex_1'], claimedDelta: 'Probe.' })
    assert.equal(ch.build().terminalVulnClass, expected)

    const normDirect = normalizeCompositeReceipt({
      chainId: `norm-direct-${expected}`,
      terminalVulnClass: raw,
      hops: [{ hopId: 'hop_1', target: 'GET /api/v1/reports/export', exchangeIds: ['ex_1'], claimedDelta: 'Probe.' }],
      terminalImpact: { terminalHopId: 'hop_1' },
    }, origin).receipt as Record<string, unknown>
    assert.equal(normDirect.terminalVulnClass, expected)

    const normWrapped = normalizeCompositeReceipt({
      receipt: { chainId: `norm-wrap-${expected}`, terminalVulnClass: raw, hops: [] },
    }, origin).receipt as Record<string, unknown>
    assert.equal(normWrapped.terminalVulnClass, expected)
  }

  // Live VerifyRpcServer confirmation with hyphenated "dual-tenant-abac"
  const chLive = ctx.chain('chain-optd-hyphen-live', 'dual-tenant-abac')
  const ctrl = await chLive.control('GET /api/v1/reports/export', { as: 'dual_member' })
  assert.equal(ctrl.status, 403)
  await chLive.step('POST /api/v1/permissions/prime', { hopId: 'step_1', as: 'dual_member', claimedDelta: 'Prime cache.' })
  const s2 = await chLive.step('GET /api/v1/reports/export', { hopId: 'step_2', as: 'dual_member', claimedDelta: 'Read tenant-b.' })
  assert.equal(s2.status, 200)
  const proved = await chLive.prove({ terminalHopId: 'step_2', terminalExchange: s2, claimedImpact: 'Hyphenated dual-tenant-abac confirmed.' })
  assert.equal(proved.confirmed, true, `Expected hyphenated dual-tenant-abac to confirm: ${JSON.stringify(proved)}`)
})

test('live VerifyRpcServer: ch.race hopId alignment (explicit hopId, 3-arg hopId+target+opts, value_binding auto-edge, and terminalHopId "race" alias)', async t => {
  // 1) Auto-named ch.race after hop_1 + ch.seal -> ch.prove({ terminalHopId: "race" }) resolves to race hop and auto-binds value_binding!
  const { ctx: ctx1 } = await startFixture(t, 'run-optd-sdk-race-alias')
  const ch1 = ctx1.chain('chain-optd-race-alias', 'economic-conservation')
  const pre1 = await ch1.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  assert.equal(pre1.status, 200)
  const s1 = await ch1.step('POST /api/v1/permissions/prime', { hopId: 'hop_1', as: 'member_a', claimedDelta: 'Mint session token.' })
  const tok1 = await ch1.seal(s1, { jsonPath: '$.sessionTok', kind: 'header_secret' })
  const burst1 = await ch1.race({
    request: {
      method: 'POST',
      path: '/api/v1/orders/ord-1/refund',
      as: 'member_a',
      capability: { handle: tok1, target: 'header', headerName: 'x-session-tok' },
      body: { amount: 60 },
    },
    concurrency: 3,
  })
  assert.equal(burst1.results.length, 3)
  const post1 = await ch1.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  assert.equal(post1.status, 200)

  const built1 = ch1.build({ terminalHopId: 'race', claimedImpact: 'Auto-named race hop matched by terminalHopId="race".' })
  assert.equal(built1.terminalVulnClass, 'economic_conservation')
  assert.deepEqual(built1.hops.map(h => h.hopId), ['hop_1', 'hop_2'])
  assert.equal(built1.terminalImpact.terminalHopId, 'hop_2')
  assert.ok(built1.hops[1]!.consumedCapabilities?.includes(tok1), `Expected race hop consumedCapabilities to include ${tok1}`)
  assert.ok((built1.causalEdges ?? []).some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2' && e.capabilityHandle === tok1))
  const proved1 = await ch1.prove({ terminalHopId: 'race', claimedImpact: 'Auto-named race hop matched by terminalHopId="race".' })
  assert.equal(proved1.confirmed, true, `Expected live ch.race + terminalHopId="race" to confirm: ${JSON.stringify(proved1)}`)

  // 2) 3-arg ch.race("race", target, opts) registers hopId="race", consumedCapabilities, and value_binding hop_1 -> race
  const { ctx: ctx2 } = await startFixture(t, 'run-optd-sdk-race-3arg')
  const ch2 = ctx2.chain('chain-optd-race-3arg', 'economic_conservation')
  await ch2.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })
  const m2 = await ch2.step('POST /api/v1/permissions/prime', { hopId: 'hop_1', as: 'member_a', claimedDelta: 'Mint session token.' })
  const tok2 = await ch2.seal(m2, { jsonPath: '$.sessionTok', kind: 'header_secret' })
  const burst2 = await ch2.race('race', '/api/v1/orders/ord-1/refund', {
    method: 'POST',
    as: 'member_a',
    capability: { handle: tok2, target: 'header', headerName: 'x-session-tok' },
    body: { amount: 60 },
    concurrency: 3,
  })
  assert.equal(burst2.results.length, 3)
  await ch2.readback('GET /api/v1/orders/ord-1', { as: 'member_a' })

  const built2 = ch2.build({ terminalHopId: 'race', claimedImpact: '3-arg ch.race("race", target, opts) confirmed.' })
  assert.deepEqual(built2.hops.map(h => h.hopId), ['hop_1', 'race'])
  assert.equal(built2.terminalImpact.terminalHopId, 'race')
  assert.equal(built2.hops[1]!.exchangeIds?.length, 3)
  assert.ok(built2.hops[1]!.consumedCapabilities?.includes(tok2))
  assert.ok((built2.causalEdges ?? []).some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'race' && e.capabilityHandle === tok2))
  const proved2 = await ch2.prove({ terminalHopId: 'race', claimedImpact: '3-arg ch.race("race", target, opts) confirmed.' })
  assert.equal(proved2.confirmed, true, `Expected live 3-arg ch.race("race", target, opts) to confirm: ${JSON.stringify(proved2)}`)
})

test('live VerifyRpcServer: compiled trace with repeated concurrent refund POSTs compiles to ch.race + pre/post ch.readback and confirms end-to-end', async t => {
  const { origin, ctx } = await startFixture(t, 'run-optd-compiler-race-e2e')

  const recorded: RecordedRequestExchange[] = [
    {
      exchangeId: 'rec_r1',
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/orders/ord-1/refund',
      persona: 'member_a',
      requestHeaders: { 'Idempotency-Key': 'idem-refund-1' },
      requestJson: { amount: 60 },
      status: 200,
      responseJson: { ok: true, refunded: 60, refundedTotal: 60 },
      timestampMs: 100,
    },
    {
      exchangeId: 'rec_r2',
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/orders/ord-1/refund',
      persona: 'member_a',
      requestHeaders: { 'Idempotency-Key': 'idem-refund-1' },
      requestJson: { amount: 60 },
      status: 200,
      responseJson: { ok: true, refunded: 60, refundedTotal: 120 },
      timestampMs: 101,
    },
    {
      exchangeId: 'rec_r3',
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/orders/ord-1/refund',
      persona: 'member_a',
      requestHeaders: { 'Idempotency-Key': 'idem-refund-1' },
      requestJson: { amount: 60 },
      status: 200,
      responseJson: { ok: true, refunded: 60, refundedTotal: 180 },
      timestampMs: 102,
    },
    {
      exchangeId: 'rec_rb',
      origin,
      method: 'GET',
      pathAndQuery: '/api/v1/orders/ord-1',
      persona: 'member_a',
      status: 200,
      responseJson: { orderId: 'ord-1', paidAmount: 100, refundedTotal: 180 },
      timestampMs: 200,
    },
  ]

  const compiled = compileTraceToKovoVerifyScript({
    submission: {
      title: 'Concurrent over-refund via race burst',
      vulnClass: 'over_refund',
      oracleFamily: 'economic_conservation',
      exchangeIds: ['rec_r1', 'rec_r2', 'rec_r3', 'rec_rb'],
      terminalExchangeId: 'rec_r3',
      readbackExchangeId: 'rec_rb',
      attackerPersona: 'member_a',
    },
    exchanges: recorded,
    runOrigin: origin,
  })
  assert.equal(compiled.ok, true)
  assert.ok(compiled.script)
  assert.match(compiled.script, /ch\.race\(/)
  assert.match(compiled.script, /concurrency:\s*3\b/)
  assert.match(compiled.script, /"Idempotency-Key":\s*"idem-refund-1"/)

  const rewritten = compiled.script.replace(/^export default\s+/, 'return ')
  new Script(`(function(){ ${rewritten} })`)
  const runCompiled = (new Function(rewritten) as () => (c: VerifyContext) => Promise<{ claims: Array<{ kind: string }> }>)()
  const out = await runCompiled(ctx)
  assert.ok(out.claims.some(c => c.kind === 'composite_receipt'), `Expected live compiled ch.race script to confirm: ${JSON.stringify(out)}`)
})

test('live VerifyRpcServer: ChainBuilder prunes dangling side-branch hops (warm->fwd->content + fwd->list/open) while preserving disconnected 2-hop diagnostics', async t => {
  const { ctx } = await startFixture(t, 'run-optd-sdk-side-branch-prune')

  const ch = ctx.chain('chain-optd-side-branch', 'cross_tenant_read')
  const fwdAblation = await ch.control('POST /api/v1/cache/fwd', { as: 'member_a', entityId: 'entry-99' })
  assert.equal(fwdAblation.status, 403)
  const ctrl = await ch.control('GET /api/v1/cache/content', { as: 'member_a' })
  assert.equal(ctrl.status, 403)

  const warm = await ch.step('POST /api/v1/cache/warm', { hopId: 'warm', as: 'member_a', entityId: 'entry-99', claimedDelta: 'Warm cache entry.' })
  assert.equal(warm.status, 200)
  const fwd = await ch.step('POST /api/v1/cache/fwd', { hopId: 'fwd', as: 'member_a', entityId: 'entry-99', claimedDelta: 'Mint forwarded token.' })
  assert.equal(fwd.status, 200)
  ch.stateTransition({ fromHopId: 'warm', toHopId: 'fwd', entityId: 'entry-99', ablation: fwdAblation })

  const fwdCap = await ch.seal(fwd, { jsonPath: '$.dlToken', kind: 'bearer_token' })
  // Two dangling side-branch preview/listing hops branching off `fwd` that never feed into `content`
  const list = await ch.step('GET /api/v1/cache/list', { hopId: 'list', capability: fwdCap, claimedDelta: 'List items (side branch).' })
  assert.equal(list.status, 200)
  const open = await ch.step('GET /api/v1/cache/open', { hopId: 'open', capability: fwdCap, claimedDelta: 'Preview item (side branch).' })
  assert.equal(open.status, 200)
  // Real terminal hop `content`
  const content = await ch.step('GET /api/v1/cache/content', { hopId: 'content', capability: fwdCap, claimedDelta: 'Read cross-tenant content.' })
  assert.equal(content.status, 200)

  // Explicit terminalHopId in ch.build() prunes `list` and `open` and drops their edges
  const built = ch.build({ terminalHopId: 'content', terminalExchange: content, claimedImpact: 'Cross-tenant content read.' })
  assert.deepEqual(built.hops.map(h => h.hopId), ['warm', 'fwd', 'content'])
  const edgeSummary = (built.causalEdges ?? []).map(e => `${e.fromHopId}->${e.toHopId}:${e.kind}`)
  assert.deepEqual(edgeSummary, ['warm->fwd:state_transition_binding', 'fwd->content:value_binding'])

  // Live ch.prove() (even WITHOUT explicit terminalHopId) prunes `list` & `open` and confirms!
  const proved = await ch.prove({ terminalExchange: content, claimedImpact: 'Cross-tenant content read via warm->fwd->content.' })
  assert.equal(proved.confirmed, true, `Expected pruned warm->fwd->content chain to confirm live: ${JSON.stringify(proved)}`)

  // Disconnected 2-hop chain with 0 edges into terminalHopId MUST NOT collapse to 1 hop!
  const chDisc = ctx.chain('chain-optd-disconnected', 'cross_tenant_read')
  chDisc.control(ctrl)
  const d1 = await chDisc.step('GET /api/v1/orders/ord-1', { hopId: 'disc_1', as: 'member_a', claimedDelta: 'Unlinked read hop 1.' })
  const d2 = await chDisc.step('GET /api/v1/cache/content', { hopId: 'disc_2', capability: fwdCap, claimedDelta: 'Unlinked hop 2.' })
  assert.equal(d1.status, 200)
  assert.equal(d2.status, 200)
  const builtDisc = chDisc.build({ terminalHopId: 'disc_2', terminalExchange: d2 })
  assert.deepEqual(builtDisc.hops.map(h => h.hopId), ['disc_1', 'disc_2'], 'Disconnected 2-hop chain (reach.size < 2) must NOT prune away disc_1')
  const provedDisc = await chDisc.prove({ terminalHopId: 'disc_2', terminalExchange: d2 })
  assert.equal(provedDisc.confirmed, false)
  assert.equal(provedDisc.hopCount, 2, 'Live prove() must keep both disconnected hops instead of collapsing to 1 hop')
})

test('live VerifyRpcServer: parser_cache_differential uses explicit wire-primitive slots (no positional synthesis) and ctx.oob_create/ctx.oob_poll attach hop OOB events', async t => {
  const { ctx, triggerOob } = await startFixture(t, 'run-optd-sdk-parser-oob', { withCanary: true })

  // 1) A2: parser_cache_differential never guesses slots from hop positions; the explicit wire helper names them
  const chParser = ctx.chain('chain-optd-parser-auto', 'parser_cache_differential')
  chParser.control('ex-ctrl-clean')
  chParser.recordHop({ hopId: 'h1', target: 'GET /api/v1/probe', exchangeIds: ['ex-diff-probe'], claimedDelta: 'Differential probe.' })
  chParser.readback('ex-rb-post')
  assert.equal(chParser.build().terminalImpact.oracleInput, undefined)
  assert.deepEqual(chParser.build({ ...wireFramingAndCacheDifferential({ control: 'ex-ctrl-clean', variant: 'ex-diff-probe', readback: 'ex-rb-post', property: 'path_normalization', differentialFeature: 'dot-segment' }) }).terminalImpact.oracleInput, {
    mode: 'parser_differential',
    differentialKind: 'path_normalization',
    differentialFeature: 'dot-segment',
    impactKind: 'mutation',
    cleanControlExchangeId: 'ex-ctrl-clean',
    differentialProbeExchangeId: 'ex-diff-probe',
    postMutationReadbackExchangeId: 'ex-rb-post',
  })

  // 2) ctx.oob_create + ctx.oob_poll ergonomic aliases record hop-bound oobEventIds
  const chOob = ctx.chain('chain-optd-oob-ergo', 'ssrf')
  let mintedToken = ''
  const pollRes = await chOob.hop('oob_hop', { claimedDelta: 'Triggered OOB callback.' }, async () => {
    const h = await ctx.oob_create('ssrf-check')
    mintedToken = h.token
    assert.ok(h.url.includes(h.token))
    triggerOob!(h.token)
    return ctx.oob_poll(h, { timeoutMs: 250 })
  })
  assert.equal(pollRes.hit, true)
  assert.equal(pollRes.token, mintedToken)
  const oobBuilt = chOob.build()
  assert.ok((oobBuilt.hops[0]!.oobEventIds?.length ?? 0) >= 2, `Expected mint + poll oobEventIds on hop, got ${JSON.stringify(oobBuilt.hops[0]!.oobEventIds)}`)
})
