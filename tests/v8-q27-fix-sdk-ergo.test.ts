/**
 * v8 Queue #27 — SDK Ergonomics & Documented Recipe Tests (Defect #3 from #391).
 *
 * Defensive QA: loopback fixture + real `VerifyRpcServer` exercising the TypeScript
 * `guardian_verify` SDK across positional, single-object, snake_case, camelCase, and flat-arg
 * calling conventions, result aliases (`.handle`/`.token`/
 * `.derivedHandle`/`.cap_id`), and documented recipe accuracy in `multihop-chains.md` and
 * `agent-prompts.ts`.
 */
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  GUARDIAN_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  GUARDIAN_VERIFY_TOOL_DESCRIPTION,
  guardianVerifyHelperGuidance,
} from '../src/server/agent-prompts.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { VerifyContext } from '../worker/guardian_verify/guardian_verify.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'guardian_verify')

const MEMBER_B_SECRET = 'member-b-ergo-secret-01'
const SIGNING_KEY = 'ergo-hmac-jwt-signing-secret-key-01'

function json(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

function verifyHs256Jwt(token: string, secret: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const expected = createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest('base64url')
  if (parts[2] !== expected) return null
  try {
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

const pollCounts = new Map<string, number>()

const fixture = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const who = req.headers['x-user'] === MEMBER_B_SECRET ? 'member_b' : 'anon'

  if (url.pathname === '/api/v1/service-meta') {
    return json(res, 200, { signingKey: SIGNING_KEY })
  }
  if (url.pathname === '/api/v1/webhooks/trigger' && req.method === 'POST') {
    const body = await readBody(req)
    const expected = createHmac('sha256', SIGNING_KEY).update(body).digest('hex')
    if (req.headers['x-signature'] !== expected) return json(res, 403, { error: 'bad signature' })
    return json(res, 200, { ok: true, jobId: 'job-ergo-1' })
  }
  if (url.pathname === '/api/v1/exports/foreign-item') {
    const auth = String(req.headers.authorization ?? '')
    if (!auth.startsWith('Bearer ')) return json(res, 403, { error: 'forbidden' })
    const claims = verifyHs256Jwt(auth.slice(7).trim(), SIGNING_KEY)
    if (!claims || claims.scope !== 'export') return json(res, 403, { error: 'bad token' })
    return json(res, 200, { record: 'foreign-ledger-row-99', actor: claims.sub ?? 'svc' })
  }
  if (url.pathname.startsWith('/api/v1/jobs/')) {
    const id = url.pathname.slice('/api/v1/jobs/'.length)
    const count = (pollCounts.get(id) ?? 0) + 1
    pollCounts.set(id, count)
    if (count < 2) return json(res, 202, { id, state: 'pending', actor: who, probeHeader: req.headers['x-probe'] ?? null })
    return json(res, 200, { id, state: 'ready', downloadToken: 'dl-tok-ergo-9', actor: who, probeHeader: req.headers['x-probe'] ?? null })
  }
  return json(res, 404, { error: 'not found' })
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
    id: 'persona-member-b',
    handle: 'member_b',
    roleLabel: 'member (org_b)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: MEMBER_B_SECRET,
    canaryMarkers: [],
  }
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['member_b', memberB]]),
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

test('TS SDK hmac_sign, jwt_sign, and await_async support options objects, positional args, flat calls, and result aliases', async (t) => {
  pollCounts.clear()
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(),
    runId: `run-q27-ts-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-q27-ts',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)

  const ctx = new VerifyContext()
  const h1 = await ctx.http_send('/api/v1/service-meta', { as: 'member_b', role: 'probe' })
  const keyCap = await ctx.seal_capability({
    exchange: h1,
    hopReceiptId: '1',
    slot: 'signing_key',
    jsonPath: '$.signingKey',
    kind: 'hmac_key',
  })
  assert.equal(keyCap.handle, 'cap:hop_1:signing_key')

  const payload = JSON.stringify({ action: 'export', tenant: 'org_a' })
  const expectedSig = createHmac('sha256', SIGNING_KEY).update(payload).digest('hex')

  // hmac_sign / hmacSign: options object (canonical + aliases) AND positional forms
  const sigObj = await ctx.hmac_sign({ secretHandle: keyCap.handle, payload, alg: 'sha256', encoding: 'hex' })
  const sigAlias = await ctx.hmacSign({ keyHandle: keyCap.handle, message: payload, algorithm: 'sha256', encoding: 'hex' })
  const sigSnake = await ctx.hmac_sign({ secret_handle: keyCap.handle, body: { action: 'export', tenant: 'org_a' }, alg: 'sha256' })
  const sigPos = await ctx.hmac_sign(keyCap.handle, payload, { alg: 'sha256', encoding: 'hex' })
  const sigPosShort = await ctx.hmacSign(keyCap.handle, payload, 'sha256')
  const sigCapObj = await ctx.hmac_sign(keyCap as unknown as Record<string, unknown>, payload)

  for (const s of [sigObj, sigAlias, sigSnake, sigPos, sigPosShort, sigCapObj]) {
    assert.equal(s.signature, expectedSig)
    assert.equal(s.handle, expectedSig)
    assert.equal(s.derivedHandle, expectedSig)
    assert.ok(s.exchangeId.length > 0)
  }

  // jwt_sign / jwtSign: options object (canonical + aliases) AND positional forms, with .handle & .token aliases
  const jwtObj = await ctx.jwt_sign({ secretHandle: keyCap.handle, claims: { sub: 'svc', scope: 'export' }, alg: 'HS256', hopReceiptId: '2a', slot: 'jwt_a' })
  const jwtAlias = await ctx.jwtSign({ keyHandle: keyCap.handle, payload: { sub: 'svc', scope: 'export' }, algorithm: 'HS256', hop_receipt_id: '2b', slot: 'jwt_b' })
  const jwtPos = await ctx.jwt_sign(keyCap.handle, { sub: 'svc', scope: 'export' }, { alg: 'HS256', hopReceiptId: '2c', slot: 'jwt_c' })
  const jwtPosAlg = await ctx.jwtSign(keyCap.handle, { sub: 'svc', scope: 'export' }, 'HS256')

  for (const j of [jwtObj, jwtAlias, jwtPos, jwtPosAlg]) {
    assert.match(j.derivedHandle, /^cap:hop_/)
    assert.equal(j.handle, j.derivedHandle)
    assert.equal(j.token, j.derivedHandle)
    assert.ok(j.exchangeId.length > 0)
  }

  // Injecting via .token alias works end-to-end against fixture
  const readback = await ctx.http_send('/api/v1/exports/foreign-item', { capability: jwtPos.token, role: 'probe' })
  assert.equal(readback.status, 200)
  assert.equal(readback.consumedCapabilityId, jwtPos.derivedHandle)

  // await_async / awaitAsync: nested AND flat forms never throw and converge cleanly
  const trig = await ctx.http_send('/api/v1/webhooks/trigger', {
    method: 'POST', as: 'member_b', role: 'probe',
    headers: { 'x-signature': sigPos.signature, 'content-type': 'application/json' },
    body: payload,
  })
  assert.equal(trig.status, 200)

  const polNested = await ctx.await_async({
    pollRequest: { path: '/api/v1/jobs/ts-nested', as: 'member_b', role: 'probe' },
    matchPredicate: { status: 200, jsonPath: '$.state', equals: 'ready' },
    triggerExchangeId: trig.exchangeId,
    correlationId: 'ts-nested',
    timeoutMs: 3000,
    intervalMs: 20,
  })
  assert.equal(polNested.converged, true)
  assert.ok(polNested.pollRecordId)

  const polFlatPath = await ctx.await_async({
    path: '/api/v1/jobs/ts-flat-path',
    method: 'GET',
    persona: 'member_b',
    headers: { 'x-probe': 'flat-ts' },
    expectStatus: 200,
    timeoutMs: 3000,
    intervalMs: 20,
  })
  assert.equal(polFlatPath.converged, true)
  assert.equal(polFlatPath.exchange?.status, 200)
  assert.match(polFlatPath.exchange?.body ?? '', /"actor":"member_b"/)
  assert.match(polFlatPath.exchange?.body ?? '', /"probeHeader":"flat-ts"/)

  const polFlatUrlUntil = await ctx.awaitAsync({
    url: `${origin}/api/v1/jobs/ts-flat-url`,
    method: 'GET',
    persona: 'member_b',
    until: { json_path: '$.state', equals: 'ready' } as unknown as Record<string, unknown>,
    timeout_ms: 3000,
    interval_ms: 20,
  })
  assert.equal(polFlatUrlUntil.converged, true)
  assert.equal(polFlatUrlUntil.exchange?.status, 200)

  const polFlatStrUntil = await ctx.await_async({
    path: '/api/v1/jobs/ts-flat-str',
    until: 'ready',
    timeout_ms: 3000,
    interval_ms: 20,
  })
  assert.equal(polFlatStrUntil.converged, true)
})

test('Documented recipes use valid DERIVED_SECRET_KINDS, stay within LOC/byte budgets, and have zero contamination', () => {
  const playbook = readFileSync(join(REPO_ROOT, 'src/skills/multihop-chains.md'), 'utf8')
  const prompts = readFileSync(join(REPO_ROOT, 'src/server/agent-prompts.ts'), 'utf8')
  const tsSdk = readFileSync(join(SDK_DIR, 'guardian_verify.ts'), 'utf8')

  const loc = (text: string) => text.trimEnd().split('\n').length
  assert.ok(loc(tsSdk) <= 900, `guardian_verify.ts is ${loc(tsSdk)} LOC (> 900)`)

  const guidance = guardianVerifyHelperGuidance()
  assert.ok(
    Buffer.byteLength(guidance, 'utf8') <= GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    `guardianVerifyHelperGuidance() is ${Buffer.byteLength(guidance, 'utf8')} B (> ${GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES} B)`,
  )
  assert.ok(GUARDIAN_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n').length <= 12)
  assert.ok(GUARDIAN_VERIFY_TOOL_DESCRIPTION.includes('kind: "hmac_key"'))

  // Line ~104 fix: invalid 'signing_material' must not appear; valid 'hmac_key' must be used in the 4-hop recipe
  assert.equal(playbook.includes('signing_material'), false, 'multihop-chains.md must not reference invalid kind signing_material')
  assert.ok(playbook.includes("kind: 'hmac_key'"), 'multihop-chains.md 4-hop recipe must use valid kind hmac_key')
  assert.equal(prompts.includes('signing_material'), false, 'agent-prompts.ts must not reference invalid kind signing_material')
  assert.equal(prompts.includes('prove_composite(replayMode='), false, 'agent-prompts.ts must pass object to prove_composite')

  // Every seal_capability kind mentioned in multihop-chains.md must be a valid DERIVED_SECRET_KINDS member
  const validKinds = new Set([
    'bearer_token', 'api_token', 'cookie', 'signed_url', 'oidc_assertion',
    'signing_salt', 'hmac_key', 'jwt', 'header_secret', 'generic_secret',
  ])
  for (const match of playbook.matchAll(/seal_capability\([^)]*kind:\s*['"]([^'"]+)['"]/g)) {
    assert.ok(validKinds.has(match[1]!), `invalid seal_capability kind "${match[1]}" in multihop-chains.md`)
  }

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected contamination: ${JSON.stringify(scan.hits)}`)
})
