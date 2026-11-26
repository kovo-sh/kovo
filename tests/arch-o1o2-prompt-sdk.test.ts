/**
 * Move O1 + O2 Regression Tests — Single-Source Prompt Contract & Stateful `ChainBuilder` SDK.
 *
 * Verifies (Docker-free, synthetic loopback fixtures, zero benchmark contamination):
 *  1. Move O2 (`worker/kovo_verify/kovo_verify.ts`):
 *     - File stays strictly <= 800 LOC while keeping full backward compatibility.
 *     - `ctx.chain(...)` / `ChainBuilder` auto-tracks hops, exchangeIds, targets, produced/consumed
 *       capabilities, crypto attestations, and async polls, auto-wiring `value_binding`,
 *       `derived_crypto_binding`, and `async_pivot_binding` edges into a `compositeProofReceiptSchema`-valid DAG.
 *     - `state_transition_binding` is NEVER auto-guessed and strictly requires explicit non-empty
 *       `entityId` + `ablationExchange` / `ablationExchangeIds`.
 *     - `prove_persisted_mutation` checks custom `expectDelta` BEFORE pushing `res.claim` into `ctx.claims`.
 *  2. Move O1 (`src/server/agent-prompts.ts`):
 *     - Eliminates duplicated boilerplate walls (`KOVO_VERIFY_SIGNATURES` removed), slashes static
 *       Turn-1 prompt overhead by >55% (from 35,201 chars to <= 16,000 chars), cuts net LOC by >500 lines
 *       (<= 2,550 LOC), advertises `ctx.chain`, and maintains zero benchmark contamination.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  kovoVerifyHelperGuidance,
  kovoVerifyPromptHint,
  workerInvestigationPrompt,
  workerSessionInstructions,
} from '../src/server/agent-prompts.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { compositeProofReceiptSchema } from '../src/server/composite-receipt.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { ChainBuilder, VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_PATH = join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts')
const PROMPTS_PATH = join(REPO_ROOT, 'src/server/agent-prompts.ts')

const ACTOR_SECRET = 'o1o2-actor-low-secret-01'
const SIGNING_KEY = 'o1o2-chain-builder-signing-key-01-high-entropy-99'
const EXPORT_TOKEN = 'o1o2-export-download-token-77'

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

async function startFixture(t: test.TestContext): Promise<{ origin: string; server: VerifyRpcServer }> {
  let pollCount = 0
  let itemStatus = 'open'
  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/v1/key') return json(res, 200, { signingKey: SIGNING_KEY })
    if (url.pathname === '/api/v1/jobs/trigger' && req.method === 'POST') {
      const auth = String(req.headers.authorization ?? '')
      if (!auth.startsWith('Bearer ')) return json(res, 403, { error: 'missing bearer' })
      return json(res, 200, { jobId: 'job-o1o2-1', state: 'queued' })
    }
    if (url.pathname === '/api/v1/jobs/job-o1o2-1') {
      pollCount += 1
      if (pollCount < 2) return json(res, 202, { state: 'pending' })
      return json(res, 200, { state: 'ready', downloadToken: EXPORT_TOKEN })
    }
    if (url.pathname === '/api/v1/exports/download') {
      const auth = String(req.headers.authorization ?? '')
      if (auth !== `Bearer ${EXPORT_TOKEN}`) return json(res, 403, { error: 'forbidden' })
      return json(res, 200, { tenant: 'org_victim', records: [{ id: 'rec-1', total: 4200 }] })
    }
    if (url.pathname === '/api/v1/items/1' && req.method === 'GET') {
      return json(res, 200, { id: '1', status: itemStatus })
    }
    if (url.pathname === '/api/v1/items/1' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)) || '{}') as { status?: string }
      if (body.status) itemStatus = body.status
      return json(res, 200, { id: '1', status: itemStatus })
    }
    return json(res, 404, { error: 'not found' })
  })
  const port = await new Promise<number>((resolvePort, reject) => {
    httpServer.once('error', reject)
    httpServer.listen(0, '127.0.0.1', () => {
      const addr = httpServer.address()
      if (!addr || typeof addr === 'string') reject(new Error('no port'))
      else resolvePort(addr.port)
    })
  })
  const origin = `http://127.0.0.1:${port}`
  t.after(() => new Promise<void>(r => { httpServer.closeAllConnections(); httpServer.close(() => r()) }))

  const actor: ResolvedPersona = {
    id: 'persona-actor-low',
    handle: 'actor_low',
    roleLabel: 'member (org_b)',
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret: ACTOR_SECRET,
    canaryMarkers: [],
  }
  const grant: Grant = {
    origin,
    tier: 2,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['actor_low', actor]]),
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant,
    runId: `run-arch-o1o2-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assign-arch-o1o2',
    targetOrigins: [origin],
  })
  await server.start()
  t.after(() => server.close())
  const restore = bindEnv(server)
  t.after(restore)
  return { origin, server }
}

test('O2.1: worker/kovo_verify/kovo_verify.ts stays strictly <= 800 LOC', () => {
  const sdk = readFileSync(SDK_PATH, 'utf8')
  const loc = sdk.trimEnd().split('\n').length
  assert.ok(loc <= 800, `kovo_verify.ts must be <= 800 LOC, got ${loc}`)
})

test('O2.2: ChainBuilder auto-tracks hops, capabilities, crypto & async edges into a schema-valid DAG', async t => {
  const { origin } = await startFixture(t)
  const ctx = new VerifyContext()
  const chain = ctx.chain({ chainId: 'chain-o2-auto', terminalVulnClass: 'dual_tenant_abac' })
  assert.ok(chain instanceof ChainBuilder)

  // Clean pre-chain denied control BEFORE Stage 1.
  const ctl = await ctx.http_send('/api/v1/exports/download', { as: 'actor_low', role: 'control' })
  assert.equal(ctl.status, 403)
  chain.control(ctl)

  // Hop 1: Fetch key & seal capability.
  const keyCap = await chain.hop('hop_1', { claimedDelta: 'Obtained signing key.' }, async () => {
    const res = await ctx.http_send('/api/v1/key', { as: 'actor_low', role: 'probe' })
    assert.equal(res.status, 200)
    return ctx.seal_capability({ exchange: res, hopReceiptId: 'hop_1', slot: 'signing_key', jsonPath: '$.signingKey', kind: 'hmac_key' })
  })

  // Hop 2: Derive JWT from keyCap & trigger async export job.
  const trig = await chain.hop('hop_2', { claimedDelta: 'Forged JWT and queued export job.' }, async () => {
    const jwt = await ctx.jwt_sign({ secretHandle: keyCap.handle, claims: { sub: 'svc', scope: 'export' }, alg: 'HS256', hopReceiptId: 'hop_2', slot: 'jwt' })
    const res = await ctx.http_send('/api/v1/jobs/trigger', {
      method: 'POST', role: 'probe', capability: { handle: jwt.derivedHandle, target: 'bearer' }, correlationIds: ['job-o1o2-1'],
    })
    assert.equal(res.status, 200)
    return res
  })

  // Hop 3: Poll async job convergence & seal download token.
  const dlCap = await chain.hop('hop_3', { surface: 'async_job', claimedDelta: 'Polled async export readiness.' }, async () => {
    const pol = await ctx.await_async({
      pollRequest: { path: '/api/v1/jobs/job-o1o2-1', as: 'actor_low', role: 'probe' },
      matchPredicate: { status: 200, jsonPath: '$.state', equals: 'ready' },
      triggerExchangeId: trig.exchangeId,
      correlationId: 'job-o1o2-1',
      timeoutMs: 3000,
      intervalMs: 20,
    })
    assert.equal(pol.converged, true)
    assert.ok(pol.exchange)
    return ctx.seal_capability({ exchange: pol.exchange!, hopReceiptId: 'hop_3', slot: 'dl_tok', jsonPath: '$.downloadToken', kind: 'bearer_token' })
  })

  // Hop 4: Consume download token for terminal foreign-tenant readback.
  const finalEx = await chain.hop('hop_4', { claimedDelta: 'Downloaded foreign-tenant records.' }, async () => {
    const res = await ctx.http_send('/api/v1/exports/download', { role: 'probe', capability: { handle: dlCap.handle, target: 'bearer' } })
    assert.equal(res.status, 200)
    return res
  })
  chain.readback(finalEx)

  const receipt = chain.build({ claimedImpact: 'Cross-tenant export read via derived JWT + async job.' })
  const parsed = compositeProofReceiptSchema.safeParse(receipt)
  assert.equal(parsed.success, true, `ChainBuilder receipt must pass schema: ${JSON.stringify(parsed)}`)
  assert.equal(receipt.hops.length, 4)
  assert.deepEqual(receipt.hops.map(h => h.hopId), ['hop_1', 'hop_2', 'hop_3', 'hop_4'])
  assert.deepEqual(receipt.hops[0]!.producedCapabilities, [keyCap.handle])
  assert.deepEqual(receipt.hops[3]!.consumedCapabilities, [dlCap.handle])
  assert.deepEqual(receipt.hops[3]!.target, { origin, method: 'GET', pathAndQuery: '/api/v1/exports/download' })
  assert.deepEqual(receipt.terminalImpact.preChainControlExchangeIds, [ctl.exchangeId])
  assert.deepEqual(receipt.terminalImpact.postChainReadbackExchangeIds, [finalEx.exchangeId])
  assert.equal(receipt.terminalImpact.terminalHopId, 'hop_4')
  assert.equal(receipt.replayMode, 'fresh_clean_replay')

  // Verify auto-wired edge kinds: derived_crypto_binding, async_pivot_binding, value_binding.
  const edges = receipt.causalEdges ?? []
  assert.ok(edges.some(e => e.kind === 'derived_crypto_binding' && e.fromHopId === 'hop_1' && e.toHopId === 'hop_2' && e.sourceCapabilityId === keyCap.handle))
  assert.ok(edges.some(e => e.kind === 'async_pivot_binding' && e.fromHopId === 'hop_2' && e.toHopId === 'hop_3' && e.correlationId === 'job-o1o2-1' && Boolean(e.pollRecordId)))
  assert.ok(edges.some(e => e.kind === 'value_binding' && e.fromHopId === 'hop_3' && e.toHopId === 'hop_4' && e.capabilityHandle === dlCap.handle))
  assert.equal(edges.some(e => e.kind === 'state_transition_binding'), false, 'state_transition_binding must never be auto-guessed')
})

test('O2.3: state_transition_binding requires explicit entityId + ablationExchange (never auto-guessed)', async t => {
  await startFixture(t)
  const ctx = new VerifyContext()
  const chain = ctx.chain('chain-o2-state', 'dual_tenant_abac')

  const ctl = await ctx.http_send('/api/v1/exports/download', { as: 'actor_low', role: 'control', entityId: 'ent-99' })
  await chain.hop('h1', { entityId: 'ent-99', claimedDelta: 'Mutated state.' }, () =>
    ctx.http_send('/api/v1/items/1', { method: 'POST', as: 'actor_low', role: 'probe', entityId: 'ent-99', body: { status: 'closed' } }),
  )
  await chain.hop('h2', { entityId: 'ent-99', claimedDelta: 'Read mutated state.' }, () =>
    ctx.http_send('/api/v1/items/1', { as: 'actor_low', role: 'probe', entityId: 'ent-99' }),
  )

  // Shared entityId alone must NEVER auto-guess a state_transition_binding edge.
  assert.equal((chain.build().causalEdges ?? []).some(e => e.kind === 'state_transition_binding'), false)

  // Missing entityId or ablationExchange must fail closed.
  assert.throws(() => chain.stateTransition({ fromHopId: 'h1', toHopId: 'h2', entityId: '   ', ablationExchange: ctl }), /entityId/i)
  assert.throws(() => chain.stateTransition({ fromHopId: 'h1', toHopId: 'h2', entityId: 'ent-99' }), /ablationExchange/i)
  assert.throws(() => chain.edge({ kind: 'state_transition_binding', fromHopId: 'h1', toHopId: 'h2', entityId: 'ent-99', ablationExchangeIds: [] }), /ablationExchangeIds/i)

  // Explicit entityId + ablationExchange succeeds and validates against compositeProofReceiptSchema.
  chain.stateTransition({ fromHopId: 'h1', toHopId: 'h2', entityId: 'ent-99', ablationExchange: ctl, mutationKind: 'status_transition' })
  const receipt = chain.build({ control: ctl })
  const parsed = compositeProofReceiptSchema.safeParse(receipt)
  assert.equal(parsed.success, true, `Explicit state_transition_binding must pass schema: ${JSON.stringify(parsed)}`)
  assert.ok((receipt.causalEdges ?? []).some(e => e.kind === 'state_transition_binding' && e.entityId === 'ent-99' && e.ablationExchangeIds.includes(ctl.exchangeId)))
})

test('O2.4: prove_persisted_mutation checks custom expectDelta before recording claim', async t => {
  await startFixture(t)
  const ctx = new VerifyContext()
  const res = await ctx.prove_persisted_mutation({
    readRoute: '/api/v1/items/1',
    mutation: { path: '/api/v1/items/1', method: 'POST', body: JSON.stringify({ status: 'updated' }), headers: { 'content-type': 'application/json' }, as: 'actor_low' },
    readPersona: 'actor_low',
    fieldPath: '$.status',
    expectDelta: () => false,
  })
  assert.equal(res.ok, false)
  assert.equal(res.confirmed, false)
  assert.equal(res.expectationMatched, false)
  assert.ok(res.missingEvidence.includes('expected_delta'))
  assert.equal(ctx.claims.length, 0, 'failed custom expectDelta must not leave a recorded claim in ctx.claims')
})

test('O1.1: single-source prompt contract cuts static Turn-1 overhead by >55%, trims LOC by >500, and eliminates duplicate blocks', () => {
  const promptsSrc = readFileSync(PROMPTS_PATH, 'utf8')
  const promptsLoc = promptsSrc.trimEnd().split('\n').length
  assert.ok(promptsLoc <= 2550, `agent-prompts.ts must drop by >500 LOC from 3083 (<= 2550), got ${promptsLoc}`)
  assert.equal(promptsSrc.includes('KOVO_VERIFY_SIGNATURES'), false, 'redundant KOVO_VERIFY_SIGNATURES wall must be removed')

  const sysActive = workerSessionInstructions('worker-investigation', { hasKovoVerify: true })
  const toolDesc = KOVO_VERIFY_TOOL_DESCRIPTION
  const guidance = kovoVerifyHelperGuidance()
  const hint = kovoVerifyPromptHint()
  const pattern = KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN
  const inv = workerInvestigationPrompt({
    goal: 'Verify multi-hop authorization invariant',
    step: {
      id: 'step-o1',
      title: 'Clean-session chain · Cross-service workflow verification',
      hypothesis: 'Stage 1 -> Stage 2 -> Terminal verification',
      category: 'broken-access-control',
      skills: ['multihop-chains'],
      specialistProfile: 'bola-bfla-specialist',
    },
    origins: ['https://app.example.invalid'],
    capabilityTier: 2,
    maxTurns: 12,
  })

  // Strict prompt budgets vs pre-Move-O1 baseline (35,201 chars total; toolDesc 13,908; sysActive 12,847; pattern 5,709).
  assert.ok(toolDesc.length <= 5000, `KOVO_VERIFY_TOOL_DESCRIPTION must be <= 5000 chars, got ${toolDesc.length}`)
  assert.ok(sysActive.length <= 5500, `workerSessionInstructions(active) must be <= 5500 chars, got ${sysActive.length}`)
  assert.ok(pattern.length <= 2000, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN must be <= 2000 chars, got ${pattern.length}`)
  assert.ok(pattern.split('\n').length <= 6, `KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN must be <= 6 lines, got ${pattern.split('\n').length}`)
  assert.ok(Buffer.byteLength(guidance, 'utf8') <= KOVO_VERIFY_HELPER_GUIDANCE_MAX_BYTES)
  assert.ok(Buffer.byteLength(hint, 'utf8') <= 512)

  const totalStaticTurn1 = sysActive.length + toolDesc.length + inv.length
  const reductionPct = (1 - totalStaticTurn1 / 35201) * 100
  assert.ok(reductionPct >= 55, `Expected >= 55% static Turn-1 prompt reduction vs 35,201 chars, got ${reductionPct.toFixed(1)}% (${totalStaticTurn1} chars)`)

  // Single-source contract advertises ctx.chain alongside canonical helpers.
  assert.ok(toolDesc.includes('ctx.chain'))
  assert.ok(sysActive.includes('ctx.chain'))
  assert.ok(guidance.includes('ctx.chain'))
  assert.ok(hint.includes('ctx.chain'))

  // Zero benchmark contamination across src/server/ and worker/.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
})
