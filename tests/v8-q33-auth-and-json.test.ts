/**
 * v8 Queue #33 Regression Suite — Derived Bearer/Cookie Injection, `json: null` Hydration,
 * and Non-JSON `capability.seal` `jsonPath` Fallback / Scrubbed Diagnostics.
 *
 * Defensive QA: exercises real loopback HTTP server + `VerifyRpcServer` + TS SDK
 * to assert wire-level `Authorization: Bearer <rawToken>` and `Cookie:` headers across all
 * four call patterns, `hydrateExchange` handling of `json: null` and BOM bodies,
 * and non-JSON `capability.seal` diagnostics + regex fallback without ever leaking raw secrets.
 */
import assert from 'node:assert/strict'
import { createHash, createHmac, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { redact } from '../src/server/redact.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext, hydrateExchange } from '../worker/kovo_verify/kovo_verify.ts'
import type { HttpExchange } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const MINTED_SESSION_TOKEN = 'minted_sess_tok_q33_9a8b7c6d5e4f'
const MINTED_HMAC_SECRET = 'hmac_key_q33_real_secret_123456'
const MINTED_COOKIE_VAL = 'cookie_val_q33_1122334455667788'
const MEMBER_B_BEARER = 'member_b_base_bearer_token_00001'
const COOKIE_USER_SID = 'cookie_user_base_session_9988776655'
const HEADER_USER_SECRET = 'header_user_tenant_secret_554433'
const UNSEALED_PLAIN_SECRET = 'SUPER_UNSEALED_SECRET_VALUE_888777666'
const UNSEALED_JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0X2FkbWluIn0.fakeSig9988776655'

interface WireCapture {
  path: string
  authorization: string | undefined
  cookie: string | undefined
  xTenant: string | undefined
}
const wireCaptures: WireCapture[] = []

function jsonRes(res: ServerResponse, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...(extraHeaders ?? {}) })
  res.end(body)
}

const fixture = createServer((req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined
  const cookie = typeof req.headers.cookie === 'string' ? req.headers.cookie : undefined
  const xTenant = typeof req.headers['x-tenant'] === 'string' ? req.headers['x-tenant'] : undefined
  wireCaptures.push({ path: url.pathname, authorization: auth, cookie, xTenant })

  if (url.pathname === '/v1/mint-session' && req.method === 'POST') {
    return jsonRes(res, 200, {
      token: MINTED_SESSION_TOKEN,
      secret: MINTED_HMAC_SECRET,
      prefixed: `Bearer ${MINTED_SESSION_TOKEN}`,
      cookiePair: `sid=${MINTED_COOKIE_VAL}`,
      nullableToken: null,
      token_count: 5,
    }, { 'set-cookie': `sess_cookie=${MINTED_COOKIE_VAL}; Path=/; HttpOnly` })
  }

  if (url.pathname === '/v1/me') {
    if (auth === `Bearer ${MINTED_SESSION_TOKEN}`) {
      return jsonRes(res, 200, { ok: true, actor: 'minted', note: 'derived-value-intact', xTenant: xTenant ?? null })
    }
    return jsonRes(res, 401, { error: 'session required' })
  }

  if (url.pathname === '/v1/me-cookie') {
    if (cookie && (cookie.includes(`sess_cookie=${MINTED_COOKIE_VAL}`) || cookie.includes(`sid=${MINTED_COOKIE_VAL}`))) {
      return jsonRes(res, 200, { ok: true, actor: 'cookie-minted' })
    }
    return jsonRes(res, 401, { error: 'session required' })
  }

  if (url.pathname === '/v1/cookie-user-ping') {
    if (cookie && cookie.includes(`session=${COOKIE_USER_SID}`)) return jsonRes(res, 200, { ok: true, actor: 'cookie_user' })
    return jsonRes(res, 401, { error: 'session required' })
  }

  if (url.pathname === '/v1/boundary-item') {
    if (auth === `Bearer ${MEMBER_B_BEARER}`) return jsonRes(res, 200, { owner: 'member_b', item: 'item-q33', private: 'member-b-private-note-77' })
    return jsonRes(res, 403, { error: 'forbidden' })
  }

  if (url.pathname === '/v1/non-json-404') {
    const body = `Not found for resource: token=${UNSEALED_PLAIN_SECRET} Bearer ${UNSEALED_JWT} trailing text beyond sixty chars`
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'content-length': Buffer.byteLength(body) })
    return res.end(body)
  }

  if (url.pathname === '/v1/csv-export') {
    const body = 'id,token\nrow1,csv-tok-88776655\n'
    res.writeHead(200, { 'content-type': 'text/csv', 'content-length': Buffer.byteLength(body) })
    return res.end(body)
  }

  if (url.pathname === '/v1/bom-json') {
    const body = `\uFEFF${JSON.stringify({ status: 'ok', count: 3 })}`
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
    return res.end(body)
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
  const memberB: ResolvedPersona = {
    id: 'persona-member-b', handle: 'member_b', roleLabel: 'member (org_b)',
    originAllowlist: [origin], authKind: 'bearer', headerName: null, secret: MEMBER_B_BEARER, canaryMarkers: [],
  }
  const cookieUser: ResolvedPersona = {
    id: 'persona-cookie-user', handle: 'cookie_user', roleLabel: 'member (org_c)',
    originAllowlist: [origin], authKind: 'cookie', headerName: null, secret: `session=${COOKIE_USER_SID}`, canaryMarkers: [],
  }
  const headerUser: ResolvedPersona = {
    id: 'persona-header-user', handle: 'header_user', roleLabel: 'member (org_h)',
    originAllowlist: [origin], authKind: 'header', headerName: 'X-Tenant', secret: HEADER_USER_SECRET, canaryMarkers: [],
  }
  return {
    origin, tier: 3, allowLocalLab: true, allowedPorts: [port], maxRpsPerOrigin: 200,
    personas: new Map([['member_b', memberB], ['cookie_user', cookieUser], ['header_user', headerUser]]),
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
    runId: `run-q33-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-q33',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)
  return { server, ctx: new VerifyContext() }
}

// ============================================================================
// 1. Derived Session Token / Bearer / Cookie Injection (All 4 Patterns End-to-End)
// ============================================================================

test('derived session token injects Authorization: Bearer <rawToken> on wire across all 4 call patterns + cookie/override edge cases', async (t) => {
  wireCaptures.length = 0
  const { ctx } = await startRpc(t)

  const mint = await ctx.http_send('/v1/mint-session', { method: 'POST', as: 'member_b', role: 'probe' })
  assert.equal(mint.status, 200)
  // Worker MUST receive valid parseable JSON with secrets redacted (never broken JSON or raw secret leakage!)
  const mintJson = mint.json as Record<string, unknown>
  assert.ok(mintJson && typeof mintJson === 'object', `mint.json must parse cleanly, got body=${mint.body}`)
  assert.equal(mintJson.token, '[redacted]')
  assert.equal(mintJson.secret, '[redacted]')
  assert.equal(mintJson.nullableToken, null)
  assert.equal(mintJson.token_count, 5)
  assert.equal(mint.body.includes(MINTED_SESSION_TOKEN), false, 'raw session token must never leak in worker response body')
  assert.equal(mint.body.includes(MINTED_HMAC_SECRET), false, 'raw hmac secret must never leak in worker response body')
  assert.equal(mint.headers['set-cookie'], '[redacted]', 'Set-Cookie header must stay redacted for worker')

  // Seal across slot & kind combinations (omitted/generic_secret, api_token, bearer_token, session_token, header_secret without headerName, already-Bearer-prefixed)
  const capDefault = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'tok', jsonPath: 'token' })
  assert.equal(capDefault.scrubbedPreview.includes(MINTED_HMAC_SECRET), false, 'seal scrubbedPreview must never leak other unsealed secrets')
  assert.equal(capDefault.scrubbedPreview.includes(MINTED_SESSION_TOKEN), false, 'seal scrubbedPreview must never leak sealed secret')
  const capHmac = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'hmac_key', jsonPath: 'secret', kind: 'hmac_key' })
  const hmacSig = await ctx.hmac_sign({ secretHandle: capHmac.handle, payload: 'POST /v1/settle', alg: 'sha256', encoding: 'hex' })
  assert.equal(hmacSig.signature, createHmac('sha256', MINTED_HMAC_SECRET).update('POST /v1/settle').digest('hex'), 'hmac_sign must sign with REAL unredacted secret, not [redacted]')
  const capApi = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'token', jsonPath: '$.token', kind: 'api_token' })
  const capBearer = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'session', jsonPath: '$.token', kind: 'bearer_token' })
  const capSessAlias = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'session_token', jsonPath: '$.token', kind: 'session_token' as never })
  const capHeaderNoName = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'hdr_noname', jsonPath: '$.token', kind: 'header_secret' })
  const capPrefixed = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'prefixed_tok', jsonPath: '$.prefixed' })
  const capSetCookie = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'ck_hdr', cookie: 'sess_cookie' })
  const capCookiePair = await ctx.seal_capability({ exchange: mint, hopReceiptId: 'h1', slot: 'ck_pair', jsonPath: '$.cookiePair' })

  const assertWireBearer = async (label: string, fn: () => Promise<HttpExchange>, expectTenant?: string) => {
    const before = wireCaptures.length
    const res = await fn()
    assert.equal(res.status, 200, `${label}: expected 200, got ${res.status} body=${res.body}`)
    assert.equal((res.json as { actor: string; note: string }).actor, 'minted', label)
    // Ensure ephemeralPersona no longer scrubs the English word "derived" out of responses
    assert.equal((res.json as { note: string }).note, 'derived-value-intact', `${label}: must not scrub literal word "derived"`)
    const cap = wireCaptures[before]
    assert.ok(cap && cap.path === '/v1/me', `${label}: missing wire capture`)
    assert.equal(cap.authorization, `Bearer ${MINTED_SESSION_TOKEN}`, `${label}: wire Authorization mismatch`)
    if (expectTenant) assert.equal(cap.xTenant, expectTenant, `${label}: expected base persona X-Tenant`)
    return { res, cap }
  }

  // Pattern (a): `{ capability: capHandle }` (no target, no as) across slots/kinds + passing full sealed object
  for (const [label, handle] of [
    ['a-default-generic', capDefault.handle],
    ['a-api-token', capApi.handle],
    ['a-bearer-token', capBearer.handle],
    ['a-session-token-alias', capSessAlias.handle],
    ['a-header-secret-without-name', capHeaderNoName.handle],
    ['a-prefixed-no-double-bearer', capPrefixed.handle],
  ] as const) {
    await assertWireBearer(label, () => ctx.http_send('/v1/me', { capability: handle }))
  }
  await assertWireBearer('a-sealed-object', () => ctx.http('/v1/me', { capability: capDefault as unknown as string }))

  // Pattern (a) cookie variants: Set-Cookie sealed via `cookie:` and cookie-shaped `name=val`
  for (const [label, handle, expectedCookie] of [
    ['a-cookie-from-set-cookie', capSetCookie.handle, `sess_cookie=${MINTED_COOKIE_VAL}`],
    ['a-cookie-pair-shape', capCookiePair.handle, `sid=${MINTED_COOKIE_VAL}`],
  ] as const) {
    const before = wireCaptures.length
    const res = await ctx.http_send('/v1/me-cookie', { capability: handle })
    assert.equal(res.status, 200, `${label}: got ${res.status} ${res.body}`)
    assert.equal(wireCaptures[before]?.cookie, expectedCookie, label)
  }

  // Pattern (b): `{ capability: { handle, target: 'bearer' } }` without `as`, with bearer `as: 'member_b'`,
  // with cookie `as: 'cookie_user'` (after cookie_user has already been registered in broker session-sharing table),
  // and with header `as: 'header_user'`
  await assertWireBearer('b-explicit-bearer', () => ctx.http_send('/v1/me', { capability: { handle: capDefault.handle, target: 'bearer' } }))
  await assertWireBearer('b-override-member-b-bearer', () => ctx.http_send('/v1/me', { capability: { handle: capDefault.handle, target: 'bearer' }, as: 'member_b' }))
  await assertWireBearer('b-override-prefixed-no-double', () => ctx.http_send('/v1/me', { capability: { handle: capPrefixed.handle, target: 'bearer' }, as: 'member_b' }))

  const cookiePing = await ctx.http_send('/v1/cookie-user-ping', { as: 'cookie_user' })
  assert.equal(cookiePing.status, 200)
  const { cap: cookieUserOverride } = await assertWireBearer('b-override-cookie-user-no-collision', () =>
    ctx.http_send('/v1/me', { capability: { handle: capDefault.handle, target: 'bearer' }, as: 'cookie_user' }))
  assert.equal(cookieUserOverride.cookie, undefined, 'derived bearer must not carry base persona session cookie')

  await assertWireBearer('b-keep-non-auth-header-user', () =>
    ctx.http_send('/v1/me', { capability: { handle: capDefault.handle, target: 'bearer' }, as: 'header_user' }), HEADER_USER_SECRET)

  // Pattern (c): inline `headers` with Authorization (mixed/lower case, bare, double-Bearer) & Cookie
  await assertWireBearer('c-Authorization-Bearer', () => ctx.http_send('/v1/me', { headers: { Authorization: `Bearer ${capDefault.handle}` } }))
  await assertWireBearer('c-lowercase-authorization', () => ctx.http_send('/v1/me', { headers: { authorization: `Bearer ${capDefault.handle}` } }))
  await assertWireBearer('c-double-Bearer-collapsed', () => ctx.http_send('/v1/me', { headers: { authorization: `Bearer Bearer ${capDefault.handle}` } }))
  await assertWireBearer('c-bare-handle-Authorization', () => ctx.http_send('/v1/me', { headers: { Authorization: capDefault.handle } }))
  await assertWireBearer('c-inline-prefixed-no-double', () => ctx.http_send('/v1/me', { headers: { Authorization: `Bearer ${capPrefixed.handle}` } }))

  for (const [label, hdrs] of [
    ['c-Cookie-inline', { Cookie: `sess_cookie=${capSetCookie.handle}` }],
    ['c-lowercase-cookie-inline', { cookie: `sess_cookie=${capSetCookie.handle}` }],
  ] as const) {
    const before = wireCaptures.length
    const res = await ctx.http_send('/v1/me-cookie', { headers: hdrs })
    assert.equal(res.status, 200, `${label}: ${res.body}`)
    assert.equal(wireCaptures[before]?.cookie, `sess_cookie=${MINTED_COOKIE_VAL}`, label)
  }

  // Security control: raw non-capability Authorization header is STILL rejected by the broker
  await assert.rejects(
    () => ctx.http_send('/v1/me', { headers: { Authorization: 'Bearer unauthorized-raw-token' } }),
    /cannot be set directly/i,
  )
})

// ============================================================================
// 2. `hydrateExchange` `json: null` Bug
// ============================================================================

test('TS hydrateExchange parses valid JSON body even when raw.json is null (+ BOM & prove_* sub-exchanges)', async (t) => {
  const { ctx } = await startRpc(t)

  // Direct TS unit check: raw.json === null must fall through to parseJsonSafe(body)
  const withNullJson = hydrateExchange({
    exchangeId: 'gx-null-1', status: 200, method: 'GET', pathAndQuery: '/v1/me',
    mediaType: 'application/json', headers: { 'content-type': 'application/json' },
    body: '{"ok":true,"count":42}', text: '', json: null, data: null,
    bodyPreview: '{"ok":true,"count":42}', bodyBytes: 22, bodySha256: 'abc', durationMs: 1, personaHandle: null,
  })
  assert.deepEqual(withNullJson.json, { ok: true, count: 42 })
  assert.deepEqual(withNullJson.data, { ok: true, count: 42 })
  assert.equal(withNullJson.text, '{"ok":true,"count":42}')

  // Direct TS unit check: non-null raw.json is preserved
  const withPreParsed = hydrateExchange({
    exchangeId: 'gx-pre-1', status: 200, method: 'GET', pathAndQuery: '/v1/me',
    mediaType: 'application/json', headers: {}, body: '{"other":1}', text: '',
    json: { pre: true }, data: null, bodyPreview: '', bodyBytes: 11, bodySha256: 'abc', durationMs: 1, personaHandle: null,
  })
  assert.deepEqual(withPreParsed.json, { pre: true })
  assert.deepEqual(withPreParsed.data, { pre: true })

  // UTF-8 BOM JSON body parses cleanly via ctx.http_send
  const bom = await ctx.http_send('/v1/bom-json')
  assert.equal(bom.status, 200)
  assert.deepEqual(bom.json, { status: 'ok', count: 3 })
  assert.deepEqual(bom.data, { status: 'ok', count: 3 })

  // prove_access_boundary sub-exchanges hydrate .json and .data in TS SDK too
  const boundary = await ctx.prove_access_boundary({ controlPersona: 'header_user', probePersona: 'member_b', route: '/v1/boundary-item' })
  assert.equal(boundary.probe.status, 200)
  assert.deepEqual(boundary.probe.json, { owner: 'member_b', item: 'item-q33', private: 'member-b-private-note-77' })
  assert.deepEqual(boundary.probe.data, { owner: 'member_b', item: 'item-q33', private: 'member-b-private-note-77' })
  assert.deepEqual(boundary.control.json, { error: 'forbidden' })

  // Direct redact() JSON syntax preservation + plain-text backward compatibility
  const redactedJson = redact(JSON.stringify({ token: 'real_secret_xyz', secret: 'hmac_key_123', access_token: 'abc999', nullable_token: null, token_count: 5, nested: { token: { type: 'string' } } }))
  const parsedRedacted = JSON.parse(redactedJson) as Record<string, unknown>
  assert.equal(parsedRedacted.token, '[redacted]')
  assert.equal(parsedRedacted.secret, '[redacted]')
  assert.equal(parsedRedacted.access_token, '[redacted]')
  assert.equal(parsedRedacted.nullable_token, null)
  assert.equal(parsedRedacted.token_count, 5)
  assert.deepEqual(parsedRedacted.nested, { token: { type: 'string' } })
  assert.equal(redact('api_key = "super-secret-value"'), '[redacted]')
})

// ============================================================================
// 3. Non-JSON `capability.seal` `jsonPath` Fallback & Actionable Scrubbed Diagnostics
// ============================================================================

test('capability.seal falls back to regex on non-JSON when both jsonPath and regex are provided, else throws scrubbed status/content-type/preview diagnostic', async (t) => {
  const { server, ctx } = await startRpc(t)

  const csvEx = await ctx.http_send('/v1/csv-export')
  assert.equal(csvEx.status, 200)

  // Both jsonPath + regex on text/csv -> clean fallback to regex!
  const sealedCsv = await ctx.seal_capability({
    exchange: csvEx, hopReceiptId: 'h2', slot: 'csv_tok',
    jsonPath: '$.token', regex: 'row1,([a-z0-9-]+)',
  })
  assert.equal(sealedCsv.handle, 'cap:hop_h2:csv_tok')
  const expectedHash = createHash('sha256').update('csv-tok-88776655', 'utf8').digest('hex')
  assert.equal(server.capabilityVault.getMeta(sealedCsv.handle)?.sha256, expectedHash)

  // jsonPath only on 200 text/csv -> actionable error with HTTP 200 + text/csv + regex hint
  await assert.rejects(
    () => ctx.seal_capability({ exchange: csvEx, hopReceiptId: 'h2', slot: 'csv_fail', jsonPath: '$.token' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /HTTP 200/)
      assert.match(msg, /text\/csv/i)
      assert.match(msg, /regex/i)
      return true
    },
  )

  // jsonPath only on 404 text/plain containing unsealed secret & JWT -> includes HTTP 404, text/plain, preview <= 60 chars, NEVER raw secrets
  const notFoundEx = await ctx.http_send('/v1/non-json-404')
  assert.equal(notFoundEx.status, 404)
  await assert.rejects(
    () => ctx.seal_capability({ exchange: notFoundEx, hopReceiptId: 'h2', slot: 'nf_fail', jsonPath: '$.token' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /HTTP 404/)
      assert.match(msg, /text\/plain/i)
      assert.match(msg, /regex/i)
      assert.equal(msg.includes(UNSEALED_PLAIN_SECRET), false, 'must never leak unsealed raw secret in preview')
      assert.equal(msg.includes(UNSEALED_JWT), false, 'must never leak unsealed raw JWT in preview')
      const previewMatch = /preview: "([^"]*)"/.exec(msg)
      assert.ok(previewMatch, `expected preview in message: ${msg}`)
      assert.ok(previewMatch[1]!.length <= 60, `preview exceeded 60 chars: ${previewMatch[1]!.length}`)
      return true
    },
  )
})

// ============================================================================
// 4. LOC Ceilings & Zero Benchmark Contamination
// ============================================================================

test('LOC ceilings and zero v8 benchmark contamination hold', () => {
  const loc = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8').trimEnd().split('\n').length
  assert.ok(loc('src/server/verify-rpc.ts') <= 2300, `verify-rpc.ts LOC=${loc('src/server/verify-rpc.ts')} > 2300`)
  assert.ok(loc('worker/kovo_verify/kovo_verify.ts') <= 900, `kovo_verify.ts LOC=${loc('worker/kovo_verify/kovo_verify.ts')} > 900`)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected contamination: ${JSON.stringify(scan.hits)}`)
})
