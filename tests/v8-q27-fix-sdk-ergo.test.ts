/**
 * v8 Queue #27 — SDK Ergonomics & Documented Recipe Tests (Defect #3 from #391).
 *
 * Defensive QA: loopback fixture + real `VerifyRpcServer` exercising both TypeScript and Python
 * `guardian_verify` SDKs across positional, single-dict, snake_case, camelCase, and flat-arg
 * calling conventions, `_AttrDict` attribute/key dual access, result aliases (`.handle`/`.token`/
 * `.derivedHandle`/`.cap_id`), and documented recipe accuracy in `multihop-chains.md` and
 * `agent-prompts.ts`.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

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

const execFileAsync = promisify(execFile)
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

test('Python SDK _AttrDict dual access + snake_case/camelCase kwargs, single-dict, positional, flat await_async, and aliases', async (t) => {
  pollCounts.clear()
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(),
    runId: `run-q27-py-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-q27-py',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())

  const workDir = mkdtempSync(join(tmpdir(), 'guardian-q27-py-'))
  t.after(() => rmSync(workDir, { recursive: true, force: true }))

  const pyScript = join(workDir, 'test_ergo.py')
  writeFileSync(pyScript, `
import hashlib, hmac, json, sys
sys.path.insert(0, ${JSON.stringify(SDK_DIR)})
from guardian_verify import VerifyContext

ctx = VerifyContext()
h1 = ctx.http_send("/api/v1/service-meta", as_persona="member_b", role="probe")

# 1. seal_capability: positional, single-dict, camelCase kwargs, snake_case kwargs + _AttrDict dual access
c1 = ctx.seal_capability(h1, "k1", hop_receipt_id="p1", json_path="$.signingKey", kind="hmac_key")
c2 = ctx.seal_capability({"exchange": h1, "slot": "k2", "hopReceiptId": "p2", "jsonPath": "$.signingKey", "kind": "hmac_key"})
c3 = ctx.seal_capability(exchange=h1, slot="k3", hopReceiptId="p3", jsonPath="$.signingKey", kind="hmac_key")
c4 = ctx.seal_capability(exchange_id=h1.exchange_id, slot="k4", hop_receipt_id="p4", json_path="$.signingKey", kind="hmac_key")
for cap, expected_h in ((c1, "cap:hop_p1:k1"), (c2, "cap:hop_p2:k2"), (c3, "cap:hop_p3:k3"), (c4, "cap:hop_p4:k4")):
    assert cap["handle"] == expected_h
    assert cap.handle == expected_h
    assert cap.cap_id == expected_h
    assert cap["cap_id"] == expected_h
    assert cap.exchangeId == h1.exchange_id
    assert cap.exchange_id == h1.exchange_id

# 2. hmac_sign: positional, single-dict, camelCase kwargs, snake_case kwargs + _AttrDict dual access
payload = json.dumps({"action": "export", "tenant": "org_a"}, separators=(",", ":"))
expected_sig = hmac.new(${JSON.stringify(SIGNING_KEY)}.encode(), payload.encode(), hashlib.sha256).hexdigest()

s1 = ctx.hmac_sign(c1.handle, payload, "sha256", "hex")
s2 = ctx.hmac_sign({"secretHandle": c1.handle, "payload": payload, "alg": "sha256"})
s3 = ctx.hmac_sign({"keyHandle": c1.handle, "message": payload, "algorithm": "sha256"})
s4 = ctx.hmac_sign(secretHandle=c1.handle, payload=payload, algorithm="sha256")
s5 = ctx.hmac_sign(secret_handle=c1.handle, body={"action": "export", "tenant": "org_a"}, alg="sha256")
for s in (s1, s2, s3, s4):
    assert s["signature"] == expected_sig
    assert s.signature == expected_sig
    assert s.handle == expected_sig
    assert s.derivedHandle == expected_sig
    assert s.exchangeId == s["exchangeId"]
    assert s.exchange_id == s["exchangeId"]
assert len(s5.signature) == 64

# 3. jwt_sign: positional, single-dict, camelCase kwargs, snake_case kwargs + .handle/.token aliases
j1 = ctx.jwt_sign(c1.handle, {"sub": "svc", "scope": "export"}, "HS256", hop_receipt_id="j1", slot="jwt1")
j2 = ctx.jwt_sign({"secretHandle": c1.handle, "claims": {"sub": "svc", "scope": "export"}, "alg": "HS256", "hopReceiptId": "j2", "slot": "jwt2"})
j3 = ctx.jwt_sign(secretHandle=c1.handle, claims={"sub": "svc", "scope": "export"}, algorithm="HS256", hopReceiptId="j3", slot="jwt3")
j4 = ctx.jwt_sign(keyHandle=c1.handle, payload={"sub": "svc", "scope": "export"}, alg="HS256", hop_receipt_id="j4", slot="jwt4")
for j in (j1, j2, j3, j4):
    assert j["derivedHandle"].startswith("cap:hop_")
    assert j.derivedHandle == j["derivedHandle"]
    assert j.handle == j.derivedHandle
    assert j.token == j.derivedHandle
    assert j["handle"] == j.derivedHandle
    assert j["token"] == j.derivedHandle

# Inject via .token alias against fixture
pre = ctx.http_send("/api/v1/exports/foreign-item", as_persona="member_b", role="control")
assert pre.status == 403
readback = ctx.http_send("/api/v1/exports/foreign-item", capability=j3.token, role="probe")
assert readback.status == 200
assert readback.consumed_capability_id == j3.derivedHandle

# 4. await_async: positional nested, single-dict nested, single-dict flat, flat kwargs + _AttrDict dual access
trig = ctx.http_send("/api/v1/webhooks/trigger", method="POST", as_persona="member_b", role="probe", headers={"x-signature": s1.signature, "content-type": "application/json"}, body=payload)
assert trig.status == 200

p1 = ctx.await_async({"path": "/api/v1/jobs/py-pos", "as_persona": "member_b", "role": "probe"}, {"status": 200, "jsonPath": "$.state", "equals": "ready"}, timeout_ms=3000, interval_ms=20, trigger_exchange_id=trig.exchange_id, correlation_id="py-pos")
p2 = ctx.await_async({"pollRequest": {"path": "/api/v1/jobs/py-dict-nested", "persona": "member_b"}, "matchPredicate": {"status": 200}, "timeoutMs": 3000, "intervalMs": 20, "triggerExchangeId": trig.exchange_id, "correlationId": "py-dict-nested"})
p3 = ctx.await_async({"path": "/api/v1/jobs/py-dict-flat", "method": "GET", "persona": "member_b", "headers": {"x-probe": "flat-py"}, "expectStatus": 200, "timeoutMs": 3000, "intervalMs": 20})
p4 = ctx.await_async(url=${JSON.stringify(origin)} + "/api/v1/jobs/py-kw-flat", method="GET", persona="member_b", until={"json_path": "$.state", "equals": "ready"}, timeout_ms=3000, interval_ms=20)
for p in (p1, p2, p3, p4):
    assert p["converged"] is True
    assert p.converged is True
    assert p.pollRecordId == p["pollRecordId"]
    assert p.poll_record_id == p["pollRecordId"]
    assert p.exchange.exchangeId == p["exchange"]["exchangeId"]
    assert p.exchange.status == 200
assert '"probeHeader":"flat-py"' in p3.exchange.body

# Sealing directly from p3.exchange works too
dl_cap = ctx.seal_capability(p3.exchange, "dl_tok", hop_receipt_id="p5", json_path="$.downloadToken", kind="bearer_token")
assert dl_cap.handle == "cap:hop_p5:dl_tok"

# 5. prove_composite returns _AttrDict supporting both dict & attribute access
verdict = ctx.prove_composite({
    "chainId": "py-q27-ergo-chain",
    "terminalVulnClass": "cross_surface_pivot",
    "hops": [
        {"hopId": "hop_1", "surface": "http", "target": {"origin": ctx.target_origin, "method": "GET", "pathAndQuery": "/api/v1/service-meta"}, "exchangeIds": [h1.exchange_id], "claimedDelta": "Obtain key."},
        {"hopId": "hop_2", "surface": "webhook", "target": {"origin": ctx.target_origin, "method": "POST", "pathAndQuery": "/api/v1/webhooks/trigger"}, "exchangeIds": [j3.exchangeId], "claimedDelta": "Mint JWT."},
        {"hopId": "hop_3", "surface": "http", "target": {"origin": ctx.target_origin, "method": "GET", "pathAndQuery": "/api/v1/exports/foreign-item"}, "exchangeIds": [readback.exchange_id], "claimedDelta": "Read foreign record."},
    ],
    "causalEdges": [
        {"kind": "derived_crypto_binding", "fromHopId": "hop_1", "toHopId": "hop_2", "sourceCapabilityId": c1.handle, "derivedCapabilityId": j3.handle, "alg": "HS256"},
        {"kind": "value_binding", "fromHopId": "hop_2", "toHopId": "hop_3", "capabilityHandle": j3.token},
    ],
    "terminalImpact": {
        "terminalHopId": "hop_3",
        "claimedImpact": "Cross-tenant export readback.",
        "preChainControlExchangeIds": [pre.exchange_id],
        "postChainReadbackExchangeIds": [readback.exchange_id],
    },
})
assert verdict["confirmed"] is True, verdict
assert verdict.confirmed is True
assert verdict.ok is True
assert verdict.verified is True
print("PY_ERGO_OK")
`)

  const env = {
    ...process.env,
    [VERIFY_RPC_SOCKET_ENV]: server.socketPath,
    [VERIFY_RPC_TOKEN_ENV]: join(server.hostDir, 'token'),
    [VERIFY_RPC_CONTEXT_ENV]: join(server.hostDir, 'context.json'),
    [VERIFY_NONCE_ENV]: server.nonce,
  }
  const pyRun = await execFileAsync('python3', [pyScript], { env, timeout: 15_000 })
  assert.match(pyRun.stdout, /PY_ERGO_OK/)
})

test('Documented recipes use valid DERIVED_SECRET_KINDS, stay within LOC/byte budgets, and have zero contamination', () => {
  const playbook = readFileSync(join(REPO_ROOT, 'src/skills/multihop-chains.md'), 'utf8')
  const prompts = readFileSync(join(REPO_ROOT, 'src/server/agent-prompts.ts'), 'utf8')
  const tsSdk = readFileSync(join(SDK_DIR, 'guardian_verify.ts'), 'utf8')
  const pySdk = readFileSync(join(SDK_DIR, 'guardian_verify.py'), 'utf8')

  const loc = (text: string) => text.trimEnd().split('\n').length
  assert.ok(loc(tsSdk) <= 900, `guardian_verify.ts is ${loc(tsSdk)} LOC (> 900)`)
  assert.ok(loc(pySdk) <= 800, `guardian_verify.py is ${loc(pySdk)} LOC (> 800)`)

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
