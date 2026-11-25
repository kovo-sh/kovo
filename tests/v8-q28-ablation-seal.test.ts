/**
 * v8 Queue #28 Regression Suite — Smoking Guns #2 & #3:
 *  1. Entity-scoped clean-session ablation tracking in `verify-rpc.ts` & `composite-receipt.ts`
 *     (`state_transition_binding` on fresh untouched sibling entities, short numeric IDs,
 *     pre-chain controls, `arm: 'control'`, and sound rejection of mutated-entity / session-wide
 *     ablations with actionable diagnostics).
 *  2. `capability.seal` `jsonPath` ergonomics (`$.items[0].id`, `data.token`, `token`,
 *     `$[0].token`, quoted bracket keys) + top-level key-only mismatch diagnostics (never values).
 *  3. Consistent top-level `.json`, `.data`, `.body`, `.text`, `.status`, `.headers`, `.exchangeId`
 *     (and `.exchange_id` / dict access in Python) on `ctx.http` / `ctx.http_send` / `ctx.await_async`.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
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
import { VerifyContext } from '../worker/guardian_verify/guardian_verify.ts'

const execFileAsync = promisify(execFile)
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'guardian_verify')
const MEMBER_A_SECRET = 'member-a-q28-secret-token-01'

function jsonRes(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

interface OrderState { id: string; primed: boolean; approved: boolean }
const orders = new Map<string, OrderState>()
let nextOrderSeq = 0
let sessionMutated = false

const fixture = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const method = (req.method ?? 'GET').toUpperCase()

  if (url.pathname === '/api/orders' && method === 'POST') {
    const raw = await readBody(req)
    let parsed: { numeric?: boolean } = {}
    try { parsed = raw ? JSON.parse(raw) : {} } catch { /* ignore */ }
    nextOrderSeq += 1
    const id = parsed.numeric ? String(nextOrderSeq) : `ord-${1000 + nextOrderSeq}`
    const order: OrderState = { id, primed: false, approved: false }
    orders.set(id, order)
    return jsonRes(res, 201, { id, status: 'draft', order })
  }

  const patchMatch = /^\/api\/orders\/([^/]+)$/.exec(url.pathname)
  if (patchMatch && method === 'PATCH') {
    const id = decodeURIComponent(patchMatch[1]!)
    const order = orders.get(id)
    if (!order) return jsonRes(res, 404, { error: 'not_found' })
    order.primed = true
    return jsonRes(res, 200, { id, status: 'primed', primed: true })
  }

  const approveMatch = /^\/api\/orders\/([^/]+)\/approve$/.exec(url.pathname)
  if (approveMatch && method === 'POST') {
    const id = decodeURIComponent(approveMatch[1]!)
    const order = orders.get(id)
    if (!order) return jsonRes(res, 404, { error: 'not_found' })
    if (!order.primed) return jsonRes(res, 403, { error: 'maker_checker_denied', id })
    order.approved = true
    return jsonRes(res, 200, { id, status: 'approved', approved: true, payoutCents: 250000 })
  }

  const invMatch = /^\/api\/invoices\/([^/]+)\/approve$/.exec(url.pathname)
  if (invMatch && method === 'POST') {
    return jsonRes(res, 403, { error: 'wrong_route_family' })
  }

  if (url.pathname === '/api/session/elevate' && method === 'POST') {
    sessionMutated = true
    return jsonRes(res, 200, { ok: true, elevated: true })
  }

  if (url.pathname === '/api/session/action' && method === 'POST') {
    if (!sessionMutated) return jsonRes(res, 403, { error: 'not_elevated' })
    return jsonRes(res, 200, { ok: true, done: true })
  }

  if (url.pathname === '/api/seal-sample') {
    return jsonRes(res, 200, {
      authRef: 'bare-tok-111',
      status: 'open',
      privateVal: 'SUPER_PRIVATE_NEVER_LEAK_999',
      data: { authRef: 'nested-tok-222' },
      items: [
        { id: 'item-tok-333', nested: [{ refVal: 'deep-tok-444' }] },
        { id: 'item-tok-555', nested: [{ refVal: 'deep-tok-666' }] },
      ],
      'meta-info': { 'x-tag': 'hyphen-tok-777' },
    })
  }

  if (url.pathname === '/api/seal-array') {
    return jsonRes(res, 200, [
      { authRef: 'arr-tok-888', privateVal: 'NEVER_LEAK_ARR_VAL_888' },
    ])
  }

  if (url.pathname === '/api/plain') {
    const body = 'plain-text-ok'
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body) })
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
  const memberA: ResolvedPersona = {
    id: 'persona-member-a',
    handle: 'member_a',
    roleLabel: 'member (org_a)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: MEMBER_A_SECRET,
    canaryMarkers: [],
  }
  return {
    origin,
    tier: 3,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
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
    runId: `run-q28-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-q28',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)
  return { server, ctx: new VerifyContext() }
}

// ============================================================================
// 1. Entity-Scoped Clean-Session Ablation Tracking
// ============================================================================

test('state_transition_binding confirms on post-chain untouched sibling entity (explicit entityId & numeric IDs & arm: control)', async (t) => {
  orders.clear()
  nextOrderSeq = 0
  const { server, ctx } = await startRpc(t)

  // --- Sub-case A: Create Entity A -> Hop 1 PATCH -> Hop 2 POST approve -> Create Entity B -> Ablation on untouched Entity B ---
  const createA = await ctx.http_send('/api/orders', { method: 'POST', as: 'member_a', role: 'setup' })
  assert.equal(createA.status, 201)
  const entityA = (createA.json as { id: string }).id

  const hop1 = await ctx.http_send(`/api/orders/${entityA}`, { method: 'PATCH', as: 'member_a', role: 'probe', entityId: entityA })
  assert.equal(hop1.status, 200)
  const hop2 = await ctx.http_send(`/api/orders/${entityA}/approve`, { method: 'POST', as: 'member_a', role: 'probe', entityId: entityA })
  assert.equal(hop2.status, 200)

  const createB = await ctx.http_send('/api/orders', { method: 'POST', as: 'member_a', role: 'setup' })
  assert.equal(createB.status, 201)
  const entityB = (createB.json as { id: string }).id
  assert.notEqual(entityA, entityB)

  const abUntouchedB = await ctx.http_send(`/api/orders/${entityB}/approve`, {
    method: 'POST', as: 'member_a', role: 'control', replayAttempt: 'ablation_control', entityId: entityB,
  })
  assert.equal(abUntouchedB.status, 403)

  // Verify transcript cleanSession=true on untouched sibling Entity B
  const transcript = server.buildHostSignedTranscript()
  const abBEntry = transcript.entries?.find(e => e.exchangeId === abUntouchedB.exchangeId)
  assert.equal(abBEntry?.cleanSession, true)
  assert.equal(abBEntry?.replayAttempt, 'ablation_control')

  const verdictB = await ctx.prove_composite({
    chainId: 'chain-q28-sibling-ablation',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin, method: 'PATCH', pathAndQuery: `/api/orders/${entityA}` }, exchangeIds: [hop1.exchangeId], entityId: entityA, claimedDelta: 'Primed order creator metadata.' },
      { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${entityA}/approve` }, exchangeIds: [hop2.exchangeId], entityId: entityA, claimedDelta: 'Self-approved order payout.' },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: entityA, ablationExchangeIds: [abUntouchedB.exchangeId] },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Bypassed maker-checker invariant via state transition on order.',
      terminalExchangeId: hop2.exchangeId,
      preChainControlExchangeIds: [abUntouchedB.exchangeId],
    },
    replayMode: 'fresh_clean_replay',
  })
  assert.equal(verdictB.confirmed, true, verdictB.reason)

  // --- Sub-case B: Short numeric IDs (/api/orders/3/approve vs /api/orders/4/approve) using arm: 'control' without replayAttempt ---
  const cNum1 = await ctx.http_send('/api/orders', { method: 'POST', as: 'member_a', body: { numeric: true } })
  const numA = (cNum1.json as { id: string }).id
  const h1Num = await ctx.http_send(`/api/orders/${numA}`, { method: 'PATCH', as: 'member_a', role: 'probe' })
  const h2Num = await ctx.http_send(`/api/orders/${numA}/approve`, { method: 'POST', as: 'member_a', role: 'probe' })
  const cNum2 = await ctx.http_send('/api/orders', { method: 'POST', as: 'member_a', body: { numeric: true } })
  const numB = (cNum2.json as { id: string }).id
  const abNumB = await ctx.http_send(`/api/orders/${numB}/approve`, { method: 'POST', as: 'member_a', arm: 'control' })
  assert.equal(abNumB.status, 403)

  const verdictNum = await ctx.prove_composite({
    chainId: 'chain-q28-numeric-sibling',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin, method: 'PATCH', pathAndQuery: `/api/orders/${numA}` }, exchangeIds: [h1Num.exchangeId], entityId: numA, claimedDelta: 'Primed numeric order.' },
      { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${numA}/approve` }, exchangeIds: [h2Num.exchangeId], entityId: numA, claimedDelta: 'Approved numeric order.' },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: numA, ablationExchangeIds: [abNumB.exchangeId] },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Bypassed maker-checker invariant on numeric order ID.',
      terminalExchangeId: h2Num.exchangeId,
    },
    replayMode: 'fresh_clean_replay',
  })
  assert.equal(verdictNum.confirmed, true, verdictNum.reason)

  // --- Sub-case C: Pre-chain control BEFORE Hop 1 on the SAME Entity C ---
  const createC = await ctx.http_send('/api/orders', { method: 'POST', as: 'member_a', role: 'setup' })
  const entityC = (createC.json as { id: string }).id
  const preCtrlC = await ctx.http_send(`/api/orders/${entityC}/approve`, { method: 'POST', as: 'member_a', role: 'control', entityId: entityC })
  assert.equal(preCtrlC.status, 403)
  const h1C = await ctx.http_send(`/api/orders/${entityC}`, { method: 'PATCH', as: 'member_a', role: 'probe', entityId: entityC })
  const h2C = await ctx.http_send(`/api/orders/${entityC}/approve`, { method: 'POST', as: 'member_a', role: 'probe', entityId: entityC })

  const verdictPre = await ctx.prove_composite({
    chainId: 'chain-q28-prechain-control',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin, method: 'PATCH', pathAndQuery: `/api/orders/${entityC}` }, exchangeIds: [h1C.exchangeId], entityId: entityC, claimedDelta: 'Primed order C.' },
      { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${entityC}/approve` }, exchangeIds: [h2C.exchangeId], entityId: entityC, claimedDelta: 'Approved order C.' },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_2', entityId: entityC, ablationExchangeIds: [preCtrlC.exchangeId] },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Pre-chain control denied before Hop 1 primed and approved order C.',
      terminalExchangeId: h2C.exchangeId,
    },
    replayMode: 'fresh_clean_replay',
  })
  assert.equal(verdictPre.confirmed, true, verdictPre.reason)
})

test('state_transition_binding STILL rejects mutated-entity ablation, session-wide dirty ablation, and wrong route family', async (t) => {
  orders.clear()
  nextOrderSeq = 0
  sessionMutated = false
  const { server, ctx } = await startRpc(t)

  // Mutate Entity A WITHOUT passing explicit entityId (path extraction must still track it!)
  const createA = await ctx.http_send('/api/orders', { method: 'POST', as: 'member_a', role: 'setup' })
  const entityA = (createA.json as { id: string }).id
  const hop1 = await ctx.http_send(`/api/orders/${entityA}`, { method: 'PATCH', as: 'member_a', role: 'probe' })
  const hop2 = await ctx.http_send(`/api/orders/${entityA}/approve`, { method: 'POST', as: 'member_a', role: 'probe' })

  // Even if server resets entityA.primed = false so the request returns 403, the host STILL knows entityA was mutated!
  orders.get(entityA)!.primed = false
  const dirtyAblationA = await ctx.http_send(`/api/orders/${entityA}/approve`, {
    method: 'POST', as: 'member_a', role: 'control', replayAttempt: 'ablation_control', entityId: entityA,
  })
  assert.equal(dirtyAblationA.status, 403)

  const dirtyArmOnlyA = await ctx.http_send(`/api/orders/${entityA}/approve`, {
    method: 'POST', as: 'member_a', arm: 'control',
  })
  assert.equal(dirtyArmOnlyA.status, 403)

  // Also test wrong route family control
  const wrongFamCtrl = await ctx.http_send('/api/invoices/inv-99/approve', {
    method: 'POST', as: 'member_a', role: 'control', replayAttempt: 'ablation_control', entityId: 'inv-99',
  })
  assert.equal(wrongFamCtrl.status, 403)

  // Also test non-entity session-wide mutation -> non-entity ablation MUST be cleanSession=false
  await ctx.http_send('/api/session/elevate', { method: 'POST', as: 'member_a', role: 'probe' })
  sessionMutated = false
  const dirtySessionAb = await ctx.http_send('/api/session/action', {
    method: 'POST', as: 'member_a', role: 'control', replayAttempt: 'ablation_control',
  })
  assert.equal(dirtySessionAb.status, 403)

  const tr = server.buildHostSignedTranscript()
  assert.equal(tr.entries?.find(e => e.exchangeId === dirtyAblationA.exchangeId)?.cleanSession, false)
  assert.equal(tr.entries?.find(e => e.exchangeId === dirtyArmOnlyA.exchangeId)?.cleanSession, false)
  assert.equal(tr.entries?.find(e => e.exchangeId === dirtySessionAb.exchangeId)?.cleanSession, false)

  // Mutated Entity A ablation rejects with crystal-clear actionable guidance
  const rejDirty = await ctx.prove_composite({
    chainId: 'chain-q28-dirty-ablation',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_prime', surface: 'http', target: { origin, method: 'PATCH', pathAndQuery: `/api/orders/${entityA}` }, exchangeIds: [hop1.exchangeId], entityId: entityA, claimedDelta: 'Primed.' },
      { hopId: 'hop_approve', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${entityA}/approve` }, exchangeIds: [hop2.exchangeId], entityId: entityA, claimedDelta: 'Approved.' },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'hop_prime', toHopId: 'hop_approve', entityId: entityA, ablationExchangeIds: [dirtyAblationA.exchangeId] },
    ],
    terminalImpact: { terminalHopId: 'hop_approve', summary: 'Attempted dirty ablation on already-mutated entity.', terminalExchangeId: hop2.exchangeId },
    replayMode: 'fresh_clean_replay',
  })
  assert.equal(rejDirty.confirmed, false)
  assert.equal(rejDirty.failedStage, 'edge_binding')
  assert.match(rejDirty.reason, /cleanSession=false/i)
  assert.match(rejDirty.reason, /BEFORE Hop "hop_prime"/i)
  assert.match(rejDirty.reason, /fresh untouched sibling entity/i)

  // Unrelated route family rejects
  const rejWrongFam = await ctx.prove_composite({
    chainId: 'chain-q28-wrong-fam',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_prime', surface: 'http', target: { origin, method: 'PATCH', pathAndQuery: `/api/orders/${entityA}` }, exchangeIds: [hop1.exchangeId], entityId: entityA, claimedDelta: 'Primed.' },
      { hopId: 'hop_approve', surface: 'http', target: { origin, method: 'POST', pathAndQuery: `/api/orders/${entityA}/approve` }, exchangeIds: [hop2.exchangeId], entityId: entityA, claimedDelta: 'Approved.' },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'hop_prime', toHopId: 'hop_approve', entityId: entityA, ablationExchangeIds: [wrongFamCtrl.exchangeId] },
    ],
    terminalImpact: { terminalHopId: 'hop_approve', summary: 'Attempted ablation on unrelated route family.', terminalExchangeId: hop2.exchangeId },
    replayMode: 'fresh_clean_replay',
  })
  assert.equal(rejWrongFam.confirmed, false)
  assert.equal(rejWrongFam.failedStage, 'edge_binding')
})

// ============================================================================
// 2. capability.seal jsonPath Ergonomics & Key-Only Diagnostics
// ============================================================================

test('capability.seal supports bare, dot, $., bracket array, root array, and quoted jsonPaths + lists top-level keys only on mismatch', async (t) => {
  const { server, ctx } = await startRpc(t)

  const sample = await ctx.http_send('/api/seal-sample', { as: 'member_a', role: 'probe' })
  assert.equal(sample.status, 200)

  const cases: Array<{ slot: string; jsonPath: string; expectedRaw: string }> = [
    { slot: 's_bare', jsonPath: 'authRef', expectedRaw: 'bare-tok-111' },
    { slot: 's_dot', jsonPath: 'data.authRef', expectedRaw: 'nested-tok-222' },
    { slot: 's_dollar', jsonPath: '$.data.authRef', expectedRaw: 'nested-tok-222' },
    { slot: 's_arr', jsonPath: '$.items[0].id', expectedRaw: 'item-tok-333' },
    { slot: 's_deep', jsonPath: 'items[1].nested[0].refVal', expectedRaw: 'deep-tok-666' },
    { slot: 's_quoted', jsonPath: "$['meta-info']['x-tag']", expectedRaw: 'hyphen-tok-777' },
  ]
  const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')
  for (const c of cases) {
    const sealed = await ctx.seal_capability({ exchange: sample, hopReceiptId: '1', slot: c.slot, jsonPath: c.jsonPath })
    assert.equal(sealed.handle, `cap:hop_1:${c.slot}`)
    assert.equal(server.capabilityVault.getMeta(sealed.handle)?.sha256, sha256(c.expectedRaw), `jsonPath ${c.jsonPath}`)
  }

  // Root-level array indexing ($[0].authRef)
  const arrSample = await ctx.http_send('/api/seal-array', { as: 'member_a', role: 'probe' })
  const arrSealed = await ctx.seal_capability({ exchange: arrSample, hopReceiptId: '2', slot: 's_root_arr', jsonPath: '$[0].authRef' })
  assert.equal(server.capabilityVault.getMeta(arrSealed.handle)?.sha256, sha256('arr-tok-888'))

  // Mismatch on object: lists top-level key names ONLY, NEVER secret values!
  await assert.rejects(
    () => ctx.seal_capability({ exchange: sample, hopReceiptId: '1', slot: 's_miss', jsonPath: 'foo.bar' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /jsonPath "foo\.bar" did not match exchange/)
      assert.match(msg, /top-level keys:.*authRef.*status.*privateVal.*data.*items/)
      assert.equal(msg.includes('SUPER_PRIVATE_NEVER_LEAK_999'), false, 'must never leak JSON values')
      assert.equal(msg.includes('bare-tok-111'), false, 'must never leak JSON values')
      return true
    },
  )

  // Mismatch on root array: lists array length + [0] keys ONLY, NEVER values!
  await assert.rejects(
    () => ctx.seal_capability({ exchange: arrSample, hopReceiptId: '2', slot: 's_arr_miss', jsonPath: '$[0].missing' }),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      assert.match(msg, /top-level array length=1, \[0\] keys: authRef, privateVal/)
      assert.equal(msg.includes('NEVER_LEAK_ARR_VAL_888'), false, 'must never leak array element values')
      return true
    },
  )
})

// ============================================================================
// 3. Consistent Top-Level .json / .data / .text / .body / .status / .headers / .exchangeId (TS + Python)
// ============================================================================

test('TS and Python ctx.http / ctx.http_send / ctx.await_async populate top-level .json, .data, .text, .body, .status, .headers, .exchangeId', async (t) => {
  const { server, ctx } = await startRpc(t)

  // TypeScript SDK: JSON response via ctx.http & ctx.http_send
  const tsHttp = await ctx.http('/api/seal-sample', { as: 'member_a' })
  const tsSend = await ctx.http_send('/api/seal-sample', { as: 'member_a' })
  for (const res of [tsHttp, tsSend]) {
    assert.equal(res.status, 200)
    assert.ok(res.exchangeId.startsWith('gx-'))
    assert.equal(res.text, res.body)
    assert.equal(typeof res.headers['content-type'], 'string')
    assert.equal((res.json as { authRef: string }).authRef, 'bare-tok-111')
    assert.deepEqual(res.data, res.json)
  }

  // TypeScript SDK: non-JSON response yields json=null, data=null, text===body
  const tsPlain = await ctx.http_send('/api/plain', { as: 'member_a' })
  assert.equal(tsPlain.status, 200)
  assert.equal(tsPlain.body, 'plain-text-ok')
  assert.equal(tsPlain.text, 'plain-text-ok')
  assert.equal(tsPlain.json, null)
  assert.equal(tsPlain.data, null)

  // TypeScript SDK: await_async hydrates exchange.json / exchange.text / exchange.data
  const tsAsync = await ctx.await_async({ path: '/api/seal-sample', persona: 'member_a', expectStatus: 200, timeoutMs: 2000, intervalMs: 20 })
  assert.equal(tsAsync.converged, true)
  assert.equal((tsAsync.exchange?.json as { status: string }).status, 'open')
  assert.equal(tsAsync.exchange?.text, tsAsync.exchange?.body)
  assert.deepEqual(tsAsync.exchange?.data, tsAsync.exchange?.json)

  // Python SDK: attribute + dict access on http, http_send, non-JSON, and await_async
  const workDir = mkdtempSync(join(tmpdir(), 'guardian-q28-py-'))
  t.after(() => rmSync(workDir, { recursive: true, force: true }))
  const pyScript = join(workDir, 'test_q28_http.py')
  writeFileSync(pyScript, `
import sys
sys.path.insert(0, ${JSON.stringify(SDK_DIR)})
from guardian_verify import VerifyContext

ctx = VerifyContext()
for res in (ctx.http("/api/seal-sample", as_persona="member_a"), ctx.http_send("/api/seal-sample", as_persona="member_a")):
    assert res.status == 200 and res["status"] == 200
    assert res.exchangeId.startswith("gx-") and res.exchange_id == res.exchangeId
    assert res["exchangeId"] == res.exchangeId and res["exchange_id"] == res.exchangeId
    assert res.text == res.body and res["text"] == res["body"]
    assert isinstance(res.headers, dict) and isinstance(res["headers"], dict)
    assert res.json["authRef"] == "bare-tok-111" and res["json"]["authRef"] == "bare-tok-111"
    assert res.data == res.json and res["data"] == res["json"]

plain = ctx.http_send("/api/plain", as_persona="member_a")
assert plain.status == 200
assert plain.body == "plain-text-ok" and plain.text == "plain-text-ok"
assert plain.json is None and plain["json"] is None and plain.data is None

pol = ctx.await_async(path="/api/seal-sample", persona="member_a", expect_status=200, timeout_ms=2000, interval_ms=20)
assert pol.converged is True
assert pol.exchange.json["status"] == "open"
assert pol.exchange["json"]["status"] == "open"
assert pol.exchange.exchange_id == pol.exchange.exchangeId
assert pol.exchange.text == pol.exchange.body
print("PY_Q28_OK")
`)
  const env = {
    ...process.env,
    [VERIFY_RPC_SOCKET_ENV]: server.socketPath,
    [VERIFY_RPC_TOKEN_ENV]: join(server.hostDir, 'token'),
    [VERIFY_RPC_CONTEXT_ENV]: join(server.hostDir, 'context.json'),
    [VERIFY_NONCE_ENV]: server.nonce,
  }
  const pyRun = await execFileAsync('python3', [pyScript], { env, timeout: 15_000 })
  assert.match(pyRun.stdout, /PY_Q28_OK/)
})

// ============================================================================
// 4. LOC Ceilings & Anti-Contamination Gate
// ============================================================================

test('LOC ceilings and zero v8 benchmark contamination hold across all touched files', () => {
  const loc = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8').trimEnd().split('\n').length
  assert.ok(loc('src/server/verify-rpc.ts') <= 2300, `verify-rpc.ts LOC=${loc('src/server/verify-rpc.ts')} > 2300`)
  assert.ok(loc('src/server/composite-receipt.ts') <= 750, `composite-receipt.ts LOC=${loc('src/server/composite-receipt.ts')} > 750`)
  assert.ok(loc('worker/guardian_verify/guardian_verify.ts') <= 900, `guardian_verify.ts LOC=${loc('worker/guardian_verify/guardian_verify.ts')} > 900`)
  assert.ok(loc('worker/guardian_verify/guardian_verify.py') <= 800, `guardian_verify.py LOC=${loc('worker/guardian_verify/guardian_verify.py')} > 800`)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected contamination: ${JSON.stringify(scan.hits)}`)
})
