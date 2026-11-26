/**
 * v8 Bucket 3 — SDK Strict camelCase Option & Canonical Surface Tests.
 *
 * Defensive QA: verifies that `worker/kovo_verify/kovo_verify.ts` removes dead v6/v7 shims
 * (`httpSend`, `http2`, `timing`, `TimingResult`) and legacy dual `snake_case` option-key
 * translators while preserving the canonical RPC wire contract (`http_send`, `seal_capability`,
 * `hmac_sign`, `jwt_sign`, `await_async`, `prove_composite`, `prove_*`) and strict camelCase
 * option interfaces, and that `src/skills/multihop-chains.md` and `src/server/agent-prompts.ts`
 * match the single canonical surface with zero contamination.
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
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  kovoVerifyHelperGuidance,
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
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_PATH = join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts')
const PLAYBOOK_PATH = join(REPO_ROOT, 'src/skills/multihop-chains.md')
const PROMPTS_PATH = join(REPO_ROOT, 'src/server/agent-prompts.ts')

const MEMBER_SECRET = 'strict-camel-member-secret-01'
const SIGNING_KEY = 'strict-camel-signing-key-01'

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

function bindEnv(server: VerifyRpcServer): () => void {
  const keys = [VERIFY_RPC_SOCKET_ENV, VERIFY_RPC_TOKEN_ENV, VERIFY_RPC_CONTEXT_ENV, VERIFY_NONCE_ENV] as const
  const prev = keys.map(k => process.env[k])
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  return () => keys.forEach((k, i) => { if (prev[i] === undefined) delete process.env[k]; else process.env[k] = prev[i] })
}

test('kovo_verify.ts drops dead v6/v7 shims and all redundant snake_case option aliases', () => {
  const sdk = readFileSync(SDK_PATH, 'utf8')
  const loc = sdk.trimEnd().split('\n').length
  assert.ok(loc <= 800, `kovo_verify.ts should stay <= 800 LOC after strict camelCase cleanup, got ${loc}`)

  const removedTokens = [
    'httpSend(',
    'async http2(',
    'readonly timing =',
    'interface TimingResult',
    'capability_target',
    'capability_header_name',
    'capability_cookie_name',
    'capability_query_param',
    'exchange_id',
    'hop_receipt_id',
    'hop_id',
    'json_path',
    'ttl_ms',
    'default_header_name',
    'default_cookie_name',
    'allowed_origins',
    'secret_handle',
    'key_handle',
    'poll_request',
    'match_predicate',
    'expect_status',
    'timeout_ms',
    'interval_ms',
    'max_attempts?:',
    'r.max_attempts',
    'trigger_exchange_id',
    't_trigger_ms',
    'correlation_id',
    'correlation_ids',
    'entity_id',
    'body_matches',
    'expect_delta',
    'immediate_ms',
    'window_ms',
    'cap_id',
    'hopId?:',
  ]
  for (const token of removedTokens) {
    assert.equal(sdk.includes(token), false, `legacy alias/shim "${token}" must be removed from kovo_verify.ts`)
  }
})

test('canonical strict camelCase options work end-to-end and legacy snake_case options fail closed', async (t) => {
  let pollCount = 0
  const fixture = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/v1/key') return json(res, 200, { signingKey: SIGNING_KEY })
    if (url.pathname === '/api/v1/trigger' && req.method === 'POST') {
      const body = await readBody(req)
      const expected = createHmac('sha256', SIGNING_KEY).update(body).digest('hex')
      if (req.headers['x-signature'] !== expected) return json(res, 403, { error: 'bad signature' })
      return json(res, 200, { ok: true, jobId: 'job-strict-1' })
    }
    if (url.pathname === '/api/v1/jobs/job-strict-1') {
      pollCount += 1
      if (pollCount < 2) return json(res, 202, { state: 'pending' })
      return json(res, 200, { state: 'ready', token: 'strict-export-tok' })
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
  t.after(() => new Promise<void>(r => { fixture.closeAllConnections(); fixture.close(() => r()) }))

  const member: ResolvedPersona = {
    id: 'persona-member',
    handle: 'member_b',
    roleLabel: 'member (org_b)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: MEMBER_SECRET,
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin,
    tier: 2,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['member_b', member]]),
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: `run-strict-camel-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-strict-camel',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)

  const ctx = new VerifyContext()
  const h1 = await ctx.http_send('/api/v1/key', { as: 'member_b', role: 'probe' })
  const keyCap = await ctx.seal_capability({
    exchange: h1,
    hopReceiptId: 'h1',
    slot: 'signing_key',
    jsonPath: '$.signingKey',
    kind: 'hmac_key',
  })
  assert.equal(keyCap.handle, 'cap:hop_h1:signing_key')

  // Legacy snake_case option keys on seal_capability fail closed (no silent translation).
  await assert.rejects(
    () => ctx.seal_capability({ exchange_id: h1.exchangeId, slot: 'bad', json_path: '$.signingKey' } as unknown as Parameters<VerifyContext['seal_capability']>[0]),
    /requires exchangeId or exchange/i,
  )

  // Canonical camelCase object + positional forms (used by seam1 golden E2E) both succeed.
  // R2-C-4: Sealed-key HMAC returns an opaque derived handle (never raw signature bytes).
  const payload = JSON.stringify({ action: 'export' })
  const sigObj = await ctx.hmac_sign({ secretHandle: keyCap.handle, payload, alg: 'sha256', encoding: 'hex' })
  const sigPos = await ctx.hmac_sign(keyCap.handle, payload)
  assert.equal(sigObj.signature, undefined)
  assert.equal(sigPos.signature, undefined)
  assert.match(sigObj.derivedHandle, /^cap:hop_/)
  assert.match(sigPos.derivedHandle, /^cap:hop_/)

  // Legacy snake_case secret_handle fails closed instead of silently translating.
  await assert.rejects(
    () => ctx.hmac_sign({ secret_handle: keyCap.handle, payload }),
    /secretHandle|capability|handle/i,
  )

  // Canonical camelCase jwt_sign + positional form both succeed.
  const jwtObj = await ctx.jwt_sign({ secretHandle: keyCap.handle, claims: { sub: 'svc' }, alg: 'HS256', hopReceiptId: 'h2', slot: 'jwt_a' })
  const jwtPos = await ctx.jwt_sign(keyCap.handle, { sub: 'svc' }, { hopReceiptId: 'h2b', slot: 'jwt_b' })
  assert.match(jwtObj.derivedHandle, /^cap:hop_/)
  assert.match(jwtPos.derivedHandle, /^cap:hop_/)

  // Canonical camelCase await_async converges cleanly.
  const trig = await ctx.http_send('/api/v1/trigger', {
    method: 'POST',
    as: 'member_b',
    role: 'probe',
    headers: { 'x-signature': sigObj.derivedHandle, 'content-type': 'application/json' },
    body: payload,
  })
  assert.equal(trig.status, 200)
  const pol = await ctx.await_async({
    pollRequest: { path: '/api/v1/jobs/job-strict-1', as: 'member_b', role: 'probe' },
    matchPredicate: { status: 200, jsonPath: '$.state', equals: 'ready' },
    triggerExchangeId: trig.exchangeId,
    correlationId: 'job-strict-1',
    timeoutMs: 3000,
    intervalMs: 20,
  })
  assert.equal(pol.converged, true)
  assert.equal(pol.exchange?.status, 200)
})

test('multihop-chains.md and agent-prompts.ts align with canonical surface, budgets, and zero contamination', () => {
  const playbook = readFileSync(PLAYBOOK_PATH, 'utf8')
  const prompts = readFileSync(PROMPTS_PATH, 'utf8')

  assert.equal(playbook.includes('hopId?'), false, 'multihop-chains.md must not advertise removed seal_capability hopId? alias')
  assert.equal(playbook.includes('ctx.httpSend'), false)
  assert.equal(playbook.includes('ctx.http2'), false)
  assert.equal(playbook.includes('ctx.timing'), false)
  assert.equal(prompts.includes('ctx.httpSend'), false)
  assert.equal(prompts.includes('ctx.http2'), false)
  assert.equal(prompts.includes('ctx.timing'), false)
  assert.ok(KOVO_VERIFY_TOOL_DESCRIPTION.includes('strict camelCase options'))
  assert.ok(Buffer.byteLength(kovoVerifyHelperGuidance(), 'utf8') <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination hits: ${JSON.stringify(scan.hits)}`)
})
