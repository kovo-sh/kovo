import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Finding } from '../src/domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins, replaySpecSchema } from '../src/replay-spec.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  HEADER_POSTURE_CATEGORY,
  chainFindingDedupKey,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
  isBaselineHeaderHygieneFinding,
  isConsolidatedHeaderPostureFinding,
  mergeChainFindings,
  reportHighlights,
} from '../src/report-summary.ts'
import {
  classifyHostTier,
  codeAuditPrompt,
  loadSkill,
  skillsByTag,
} from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  Execution,
  applyCrownJewelStepBudget,
  buildBolaTestQueue,
  computeHostTiers,
  computeStepMaxTurns,
  extractPersonaResourcesFromExchange,
} from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { privateModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { findings as findingsTable } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }
const appOrigin = 'https://app.northstar.example'
const clerkOrigin = 'https://clerk.northstar.example'
const sandpackOrigin = 'https://sandpack.northstar.example'
const docsOrigin = 'https://docs.northstar.example'
const blogOrigin = 'https://blog.northstar.example'
const wwwOrigin = 'https://www.northstar.example'

async function httpFixture(handler: (req: IncomingMessage, res: ServerResponse) => void, host = '127.0.0.1') {
  const server = createServer(handler).listen(0, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  return {
    port: address.port,
    url: `http://${host}:${address.port}`,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: appOrigin,
    tier: 2,
    maxRpsPerOrigin: 30,
    canRead: origin => origin === appOrigin,
    audit: () => {},
    ...overrides,
  }
}

function replayBase(origin = appOrigin) {
  return {
    version: 1 as const,
    origin,
    title: 'V2 Upgrade Deterministic Verification',
    category: 'broken-access-control' as const,
    cwe: 'CWE-362',
    severity: 'high' as const,
    severityRationale: 'Direct deterministic proof without LLM involvement.',
    impact: 'An attacker can violate business-logic or cross-origin isolation invariants.',
    remediation: 'Enforce atomic server-side locking and strict origin allowlists.',
    recheckInstructions: 'Re-run the declarative replay spec after applying the fix.',
  }
}

type ResponsesToolCall = { name: string; args: Record<string, unknown> }

function sseResponsesPayload(text: string, toolCalls: ResponsesToolCall[] = []): string {
  const responseId = 'resp_' + randomUUID().slice(0, 12)
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
  ]
  const output: Record<string, unknown>[] = []
  let idx = 0

  if (text) {
    const msgId = 'msg_' + randomUUID().slice(0, 8)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', role: 'assistant', content: [] } },
      { type: 'response.output_text.delta', output_index: idx, item_id: msgId, content_index: 0, delta: text },
      { type: 'response.output_text.done', output_index: idx, item_id: msgId, content_index: 0, text },
      { type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] } },
    )
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] })
    idx += 1
  }

  for (const call of toolCalls) {
    const fcId = 'fc_' + randomUUID().slice(0, 8)
    const callId = 'call_' + randomUUID().slice(0, 8)
    const serialized = JSON.stringify(call.args)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: serialized },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: serialized },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized })
    idx += 1
  }

  events.push({
    type: 'response.completed',
    response: {
      id: responseId,
      status: 'completed',
      output,
      usage: { input_tokens: 250, output_tokens: 90, total_tokens: 340 },
    },
  })

  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

// ============================================================================
// 1. Priority #5A: Real Local OOB Canary HTTP Listener
// ============================================================================

test('CanaryBroker real local HTTP listener receives callbacks, redacts sensitive headers, and shuts down cleanly', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-canary-test-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Canary Project', seeds: [appOrigin], environment: 'local-lab',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Verify OOB canary listener', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 1, budgetRequests: 20, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 10,
  })

  const broker = new CanaryBroker({ storage })
  t.after(() => broker.stopListener())

  // Before starting listener, mintCanary falls back cleanly to synthetic URL
  const synthetic = broker.mintCanary(runId, 'offline-check', appOrigin)
  assert.equal(synthetic.listenerActive, false)
  assert.equal(synthetic.synthetic, true)
  assert.match(synthetic.token, /^kovo-canary-[a-f0-9]{24}$/)
  assert.equal(broker.checkCanary(synthetic.token).hit, false)

  // Start real local HTTP callback listener on ephemeral port
  const info = await broker.startListener({ host: '127.0.0.1', port: 0 })
  assert.equal(info.running, true)
  assert.equal(info.host, '127.0.0.1')
  assert.ok(info.port && info.port > 0)
  assert.ok(info.localBaseUrl?.startsWith('http://127.0.0.1:'))

  const canary = broker.mintCanary(runId, 'ssrf-probe', appOrigin)
  assert.equal(canary.listenerActive, true)
  assert.equal(canary.synthetic, false)
  assert.ok(canary.httpUrl.startsWith(info.localBaseUrl!))
  assert.equal(broker.checkCanary(canary.token).hit, false)

  // Send a real inbound HTTP callback with sensitive headers + secret query param
  const rawBearer = 'Bearer super-secret-canary-jwt-99999'
  const rawCookie = 'session=raw-cookie-secret-88888'
  const callbackResp = await fetch(`${canary.httpUrl}?probe=ok`, {
    method: 'POST',
    headers: {
      'User-Agent': 'KovoTargetBackend/2.0',
      Authorization: rawBearer,
      Cookie: rawCookie,
      'X-Custom-Trace': 'trace-123',
    },
    body: 'ignored-payload',
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(callbackResp.status, 200)
  assert.equal(await callbackResp.text(), 'kovo-canary-ok')

  const check = broker.checkCanary(canary.token)
  assert.equal(check.found, true)
  assert.equal(check.hit, true)
  assert.equal(check.triggered, true)
  assert.equal(check.hits.length, 1)
  assert.equal(check.hits[0].method, 'POST')
  assert.equal(check.hits[0].path, `/c/${canary.token}`)
  assert.equal(check.hits[0].userAgent, 'KovoTargetBackend/2.0')
  assert.equal(check.hits[0].headers['x-custom-trace'], 'trace-123')
  // Sensitive headers MUST be redacted
  assert.ok(!JSON.stringify(check.hits[0].headers).includes('super-secret-canary-jwt-99999'))
  assert.ok(!JSON.stringify(check.hits[0].headers).includes('raw-cookie-secret-88888'))

  // Token matching via query parameter also works
  const queryCanary = broker.mintCanary(runId, 'query-probe', appOrigin)
  await fetch(`${info.localBaseUrl}/hook?ref=${queryCanary.token}`, { signal: AbortSignal.timeout(5_000) })
  assert.equal(broker.checkCanary(queryCanary.token).hit, true)

  // Clean shutdown closes listener socket cleanly
  const stoppedUrl = canary.httpUrl
  await broker.stopListener()
  assert.equal(broker.listenerInfo().running, false)
  assert.equal(broker.listenerInfo().port, null)
  await assert.rejects(fetch(stoppedUrl, { signal: AbortSignal.timeout(2_000) }))
})

// ============================================================================
// 2. Priority #3A: RequestBroker.executeRaceBurst Security Boundaries & Concurrency
// ============================================================================

test('RequestBroker.executeRaceBurst hits local TOCTOU fixture concurrently and enforces Tier >= 2, 2..10 cap, scope, denylist, cross-origin persona stripping, and multi-origin cleanup', async t => {
  // Single-use coupon fixture with deliberate async TOCTOU window
  let couponRedeemed = false
  let receiptSeq = 0
  let atomicLock = false
  const receivedHeaders: Array<Record<string, string | string[] | undefined>> = []

  const fixture = await httpFixture(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    receivedHeaders.push(req.headers)

    if (url.pathname === '/api/redeem-once') {
      if (atomicLock) {
        if (couponRedeemed) {
          res.writeHead(409, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'already_redeemed' }))
          return
        }
        couponRedeemed = true
        receiptSeq += 1
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ redeemed: true, receiptId: `rcpt_${receiptSeq}` }))
        return
      }
      // Vulnerable non-atomic check-then-act window
      if (couponRedeemed) {
        res.writeHead(409, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'already_redeemed' }))
        return
      }
      await delay(35)
      couponRedeemed = true
      receiptSeq += 1
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        redeemed: true,
        receiptId: `rcpt_${receiptSeq}`,
        echoSecret: 'opaque-race-persona-secret-77711',
      }))
      return
    }

    if (url.pathname === '/redirect-cross') {
      res.writeHead(302, { Location: `${clerkOrigin}/landed` }).end()
      return
    }
    if (url.pathname === '/landed') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        hadAuth: Boolean(req.headers.authorization),
      }))
      return
    }

    res.writeHead(404).end('not found')
  })
  t.after(() => fixture.close())

  // Broker routing appOrigin & clerkOrigin to local fixture server
  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (url, _addr, signal, opts) => {
      const resp = await fetch(`${fixture.url}${url.pathname}${url.search}`, {
        method: opts?.method ?? 'GET',
        headers: opts?.headers,
        body: opts?.body,
        redirect: 'manual',
        signal,
      })
      const headers: Record<string, string> = {}
      resp.headers.forEach((v, k) => { headers[k] = v })
      return { status: resp.status, headers, body: await resp.text() }
    },
  })

  const personaSecret = 'opaque-race-persona-secret-77711'
  const personas = new Map<string, ResolvedPersona>([
    ['user_a', {
      id: 'p-a',
      handle: 'user_a',
      roleLabel: 'Standard User A',
      authKind: 'bearer',
      headerName: 'Authorization',
      originAllowlist: [appOrigin],
      secret: personaSecret,
      canaryMarkers: [],
    }],
  ])

  const sig = AbortSignal.timeout(10_000)

  // Tier 1 MUST be rejected
  await assert.rejects(
    broker.executeRaceBurst([
      { origin: appOrigin, method: 'GET', pathAndQuery: '/api/redeem-once' },
      { origin: appOrigin, method: 'GET', pathAndQuery: '/api/redeem-once' },
    ], makeGrant({ tier: 1 }), sig),
    /Tier 2 or Tier 3/,
  )

  // < 2 and > 10 caps MUST be rejected
  await assert.rejects(
    broker.executeRaceBurst([
      { origin: appOrigin, method: 'GET', pathAndQuery: '/api/redeem-once' },
    ], makeGrant({ tier: 2 }), sig),
    /between 2 and 10/,
  )
  await assert.rejects(
    broker.executeRaceBurst(
      Array.from({ length: 11 }, () => ({ origin: appOrigin, method: 'GET' as const, pathAndQuery: '/api/redeem-once' })),
      makeGrant({ tier: 2 }),
      sig,
    ),
    /between 2 and 10/,
  )

  // Out-of-scope origin and destructive payloads MUST be rejected before sending bytes
  const beforeRejectedCount = receivedHeaders.length
  await assert.rejects(
    broker.executeRaceBurst([
      { origin: appOrigin, method: 'GET', pathAndQuery: '/api/redeem-once' },
      { origin: 'https://unapproved.example', method: 'GET', pathAndQuery: '/' },
    ], makeGrant({ tier: 2 }), sig),
    /outside.*scope/,
  )
  await assert.rejects(
    broker.executeRaceBurst([
      { origin: appOrigin, method: 'GET', pathAndQuery: '/api/redeem-once' },
      { origin: appOrigin, method: 'GET', pathAndQuery: '/api/redeem-once?cmd=rm%20-rf%20/' },
    ], makeGrant({ tier: 2 }), sig),
    /destructive-payload denylist/,
  )
  assert.equal(receivedHeaders.length, beforeRejectedCount)

  // Real concurrent Tier 2 burst against vulnerable TOCTOU endpoint: multiple 200s + distinct receipts + secret redacted!
  const tier2Grant = makeGrant({
    tier: 2,
    canRead: origin => origin === appOrigin || origin === clerkOrigin,
    personas,
    // The legacy path-substring idempotent predicate no longer bypasses authorization. Tier-2
    // writes require the operator's explicit sandbox allowlist entry instead.
    sandboxWriteAllowlist: [{ origin: appOrigin, method: 'POST', pathPattern: '/api/redeem-once' }],
  })
  const burst = await broker.executeRaceBurst(
    Array.from({ length: 5 }, () => ({
      origin: appOrigin,
      method: 'POST' as const,
      pathAndQuery: '/api/redeem-once',
      persona: 'user_a',
      body: JSON.stringify({ code: 'SINGLE-USE-100' }),
    })),
    tier2Grant,
    sig,
  )
  assert.equal(burst.results.length, 5)
  assert.equal(burst.summary.total, 5)
  assert.ok((burst.summary.statusCounts['200'] ?? 0) >= 2, `Expected >=2 concurrent 200s, got ${JSON.stringify(burst.summary.statusCounts)}`)
  assert.ok(burst.summary.distinctBodies >= 2, `Expected >=2 distinct receipt bodies, got ${burst.summary.distinctBodies}`)
  assert.ok(burst.summary.spreadMs >= 0)
  // Persona secret MUST be redacted from captured bodies & headers
  for (const r of burst.results) {
    assert.ok(!r.body.includes(personaSecret))
    assert.ok(!JSON.stringify(r.reqHeaders).includes(personaSecret))
  }

  // Cross-origin redirect during burst MUST strip persona Authorization header
  const redirBurst = await broker.executeRaceBurst([
    { origin: appOrigin, method: 'GET', pathAndQuery: '/redirect-cross', persona: 'user_a', followRedirects: true },
    { origin: appOrigin, method: 'GET', pathAndQuery: '/redirect-cross', persona: 'user_a', followRedirects: true },
  ], tier2Grant, sig)
  for (const r of redirBurst.results) {
    assert.equal(r.status, 200)
    assert.equal(r.finalOrigin, clerkOrigin)
    assert.equal((JSON.parse(r.body) as { hadAuth: boolean }).hadAuth, false)
  }

  // Verify patched atomic lock allows at most 1 success
  atomicLock = true
  couponRedeemed = false
  const fixedBurst = await broker.executeRaceBurst(
    Array.from({ length: 4 }, () => ({
      origin: appOrigin,
      method: 'POST' as const,
      pathAndQuery: '/api/redeem-once',
      persona: 'user_a',
    })),
    tier2Grant,
    sig,
  )
  assert.equal(fixedBurst.summary.statusCounts['200'], 1)
  assert.equal(fixedBurst.summary.statusCounts['409'], 3)
})

// ============================================================================
// 3. Priorities #3B & #5B: Zero-LLM Replay Verification (race_burst & browser_chain)
// ============================================================================

test('verifyReplaySpec & retestReplaySpec verify race_burst and browser_chain specs with Zero LLM against local fixture servers', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-replay-v2-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const backend = new LinuxWorkerBackend({ workspace: { id: 'replay-v2', directory: dir } })

  let raceFixed = false
  let tokenUsed = false
  let txCounter = 0

  const fixture = await httpFixture(async (req, res) => {
    const targetOrigin = String(req.headers['x-test-origin'] ?? appOrigin)
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')

    if (targetOrigin === appOrigin) {
      if (url.pathname === '/api/coupon/reset') {
        tokenUsed = false
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ reset: true, used: false }))
        return
      }
      if (url.pathname === '/api/coupon/redeem') {
        if (raceFixed) {
          if (tokenUsed) {
            res.writeHead(409, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: false, error: 'already_used' }))
            return
          }
          tokenUsed = true
          txCounter += 1
          res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, tx: `tx_${txCounter}` }))
          return
        }
        if (tokenUsed) {
          res.writeHead(409, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: false, error: 'already_used' }))
          return
        }
        await delay(30)
        tokenUsed = true
        txCounter += 1
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true, tx: `tx_${txCounter}` }))
        return
      }
      if (url.pathname === '/api/coupon/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ used: tokenUsed, txCounter }))
        return
      }
    }

    // Multi-origin browser fixture: sandpack (user JS / postMessage) + clerk (wildcard credentialed CORS)
    if (targetOrigin === sandpackOrigin) {
      if (url.pathname === '/sink') {
        const q = url.searchParams.get('q') ?? ''
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(`<!doctype html>
<html><head><title>Sink preview</title></head><body>
  <div id="out"></div>
  <script>document.getElementById('out').innerHTML = ${JSON.stringify(q)}</script>
</body></html>`)
        return
      }
      if (url.pathname.startsWith('/.kovo-nonexistent-')) {
        res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not Found')
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(`<!doctype html>
<html><head><title>Sandpack Preview</title></head>
<body>
  <div id="status-banner">Sandpack Ready</div>
  <img src="https://evil-unapproved-third-party.invalid/leak.png" alt="blocked" />
  <script>
    window.addEventListener('message', function(ev) {
      // Deliberately missing event.origin validation
      if (ev.data && ev.data.kovoCanary) {
        document.getElementById('status-banner').textContent = 'PM_ACCEPTED:' + ev.data.kovoCanary;
      }
    });
  </script>
</body></html>`)
      return
    }

    if (targetOrigin === clerkOrigin) {
      if (url.pathname === '/api/session') {
        const hasAuth = req.headers.authorization === 'Bearer opaque-browser-session-555'
        const reqOrigin = typeof req.headers.origin === 'string' ? req.headers.origin : sandpackOrigin
        if (!hasAuth) {
          res.writeHead(401, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': reqOrigin,
            'Access-Control-Allow-Credentials': 'true',
          }).end(JSON.stringify({ error: 'unauthorized' }))
          return
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': reqOrigin,
          'Access-Control-Allow-Credentials': 'true',
        }).end(JSON.stringify({ user: 'alice', marker: 'clerk_session_cors_exposed' }))
        return
      }
    }

    res.writeHead(404).end('not found')
  })
  t.after(() => fixture.close())

  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (url, _addr, signal, opts) => {
      const resp = await fetch(`${fixture.url}${url.pathname}${url.search}`, {
        method: opts?.method ?? 'GET',
        headers: { ...(opts?.headers ?? {}), 'x-test-origin': url.origin },
        body: opts?.body,
        redirect: 'manual',
        signal,
      })
      const headers: Record<string, string> = {}
      resp.headers.forEach((v, k) => { headers[k] = v })
      return { status: resp.status, headers, body: await resp.text() }
    },
  })

  const personas = new Map<string, ResolvedPersona>([
    ['user_a', {
      id: 'p-browser-a',
      handle: 'user_a',
      roleLabel: 'Tenant A',
      authKind: 'bearer',
      headerName: 'Authorization',
      originAllowlist: [appOrigin, clerkOrigin, sandpackOrigin],
      secret: 'opaque-browser-session-555',
      canaryMarkers: [],
    }],
  ])

  const tier2Grant = makeGrant({
    tier: 2,
    canRead: origin => origin === appOrigin || origin === clerkOrigin || origin === sandpackOrigin,
    personas,
    sandboxWriteAllowlist: [{ origin: appOrigin, method: 'POST', pathPattern: '/api/coupon/redeem' }],
  })

  // --- 3A. race_burst Replay Spec ---
  const raceSpec: DeclarativeReplaySpec = replaySpecSchema.parse({
    ...replayBase(appOrigin),
    kind: 'race_burst',
    title: 'Single-Use Coupon TOCTOU Double-Redemption',
    cwe: 'CWE-362',
    controlStep: {
      id: 'reset',
      role: 'control',
      description: 'Reset test coupon before burst',
      request: { origin: appOrigin, method: 'GET', pathAndQuery: '/api/coupon/reset', followRedirects: false },
    },
    burst: Array.from({ length: 4 }, () => ({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/api/coupon/redeem',
      persona: 'user_a',
      jsonBody: { coupon: 'WELCOME-ONCE' },
    })),
    postCheckStep: {
      id: 'post',
      role: 'cleanup',
      description: 'Inspect coupon state after burst',
      request: { origin: appOrigin, method: 'GET', pathAndQuery: '/api/coupon/status', followRedirects: false },
    },
    assertionsJq: `{
      controlPassed: (.control.status == 200 and .control.json.reset == true),
      confirmed: (([.burst.results[] | select(.status == 200)] | length) > 1 and .burst.summary.distinctBodies > 1),
      observed: ("burst200s=" + ([.burst.results[] | select(.status == 200)] | length | tostring) + ", distinctBodies=" + (.burst.summary.distinctBodies | tostring)),
      expected: "At most one HTTP 200 redemption in concurrent burst"
    }`,
  })

  assert.deepEqual(replaySpecOrigins(raceSpec), [appOrigin])

  // Cut 3d retired the raw race_burst VM onto the conserved_balance recipe. A bare legacy spec now
  // fails closed at every tier; the broker-level burst above still exercises the transport.
  // Under R2-04 retest truthfulness, a retired spec that executed no control/probe arms and has no
  // buildable ProofReceipt MUST return 'inconclusive' (`receipt_unbuildable`), NEVER 'fixed'.
  const tier1Res = await verifyReplaySpec({
    spec: raceSpec, broker, backend, grant: makeGrant({ tier: 1 }), signal: AbortSignal.timeout(15_000),
  })
  assert.equal(tier1Res.verdict, 'dismissed')
  const raceRetired = await verifyReplaySpec({
    spec: raceSpec, broker, backend, grant: tier2Grant, signal: AbortSignal.timeout(15_000),
  })
  assert.equal(raceRetired.verdict, 'dismissed')
  const raceRetest = await retestReplaySpec({
    spec: raceSpec, broker, backend, grant: tier2Grant, signal: AbortSignal.timeout(15_000),
  })
  assert.equal(raceRetest.verdict, 'inconclusive')
  assert.equal((raceRetest.replay.evidencePayload.retestHealth as { failureReason?: string } | undefined)?.failureReason, 'receipt_unbuildable')
  raceFixed = true

  // --- 3B. DOM-sink browser proof (browser_sink recipe + runBrowserSession) ---
  // Schema MUST reject unsafe selector / destructive payload.
  assert.equal(declarativeReplaySpecSchema.safeParse({
    ...replayBase(sandpackOrigin),
    kind: 'browser_chain',
    steps: [
      { id: 'c', role: 'control', description: 'Control', origin: sandpackOrigin, pathAndQuery: '/', selector: '<script>alert(1)</script>' },
      { id: 'p', role: 'probe', description: 'Probe', origin: sandpackOrigin, pathAndQuery: '/' },
    ],
    assertionsJq: '{ confirmed: false, controlPassed: true, observed: "x", expected: "y" }',
  }).success, false)

  const canaryMarkup = `<img src=x onerror="document.title='{{canary_token}}'">`
  const encodedMarkup = canaryMarkup.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
  const sinkSteps = [
    { id: 'c', role: 'control', description: 'Render a benign query value', origin: sandpackOrigin, pathAndQuery: '/sink?q=kovo', action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 200 },
    { id: 'p', role: 'probe', description: 'Render the canary through the innerHTML sink', origin: sandpackOrigin, pathAndQuery: `/sink?q=${encodedMarkup}`, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 400 },
  ]
  const browserSinkSpec: DeclarativeReplaySpec = declarativeReplaySpecSchema.parse({
    ...replayBase(sandpackOrigin),
    kind: 'browser_chain',
    title: 'DOM XSS via the sandpack preview innerHTML sink',
    category: 'dom_xss',
    cwe: 'CWE-79',
    steps: sinkSteps,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "recipe", expected: "recipe" }',
    recipe: {
      recipeId: 'browser_sink',
      args: {
        origin: sandpackOrigin,
        method: 'GET',
        pathAndQuery: '/sink?q=kovo',
        vulnClass: 'dom_xss',
        actor: { handle: 'user_a' },
        steps: [
          { role: 'control', action: 'navigate', pathAndQuery: '/sink?q=kovo' },
          { role: 'probe', action: 'navigate', pathAndQuery: `/sink?q=${encodedMarkup}` },
        ],
      },
    },
  })

  const browser = new ScopedBrowser(broker)
  t.after(async () => { await browser.close().catch(() => undefined) })

  // Pooled per-persona session (one Chromium, one context per persona) renders the sink page.
  const sessionVisits = await browser.runBrowserSession([
    { id: 'sink', role: 'probe', origin: sandpackOrigin, pathAndQuery: '/sink?q=kovo', action: 'navigate', waitAfterLoadMs: 200 },
  ], tier2Grant, AbortSignal.timeout(20_000))
  assert.equal(sessionVisits[0]?.status, 200)

  // Out-of-scope step origin MUST be blocked before the recipe launches a browser.
  const outOfScopeBrowserRes = await verifyReplaySpec({
    spec: browserSinkSpec,
    broker,
    browser,
    backend,
    grant: makeGrant({ tier: 2, canRead: o => o === appOrigin, personas }),
    signal: AbortSignal.timeout(20_000),
  })
  assert.equal(outOfScopeBrowserRes.verdict, 'inconclusive')
  assert.match(outOfScopeBrowserRes.outcome.reason ?? '', /not in approved scope/i)

  // The retired browser_chain VM never runs: the persisted browser_sink envelope confirms through
  // the recipe's host-recorded canary trace.
  const browserRes = await verifyReplaySpec({
    spec: browserSinkSpec,
    broker,
    browser,
    backend,
    grant: tier2Grant,
    envelopeTrust: 'host_persisted',
    signal: AbortSignal.timeout(30_000),
  })
  assert.equal(browserRes.verdict, 'confirmed', `Expected confirmed, got ${browserRes.verdict}: ${JSON.stringify(browserRes.outcome)}`)
  assert.equal(browserRes.outcome.controlPassed, true)
  assert.ok(browserRes.receipt?.verification.confirmed, 'the browser_sink receipt must verify')
  // Persona secret MUST NEVER leak into browser replay evidence payload
  assert.ok(!JSON.stringify(browserRes.evidencePayload).includes('opaque-browser-session-555'))

})

// ============================================================================
// 4. Priority #1: Source-First Code Audit Phase (Mounted Temp Repo -> Suspects -> Chain Steps)
// ============================================================================

test('Source-First Code Audit reads mounted /repos via derive_evidence, records code_audit_suspect facts, queues targeted chain_steps, and skips gracefully when no repos are mounted', async t => {
  const prevLocalModel = process.env.KOVO_ALLOW_LOCAL_MODEL
  process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
  t.after(() => {
    if (prevLocalModel === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
    else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocalModel
  })
  const dir = mkdtempSync(join(tmpdir(), 'kovo-code-audit-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  // Mock OpenAI Responses SSE server driving code-auditor:
  // Turn 1: call derive_evidence to inspect /repos/acme/billing-app/app/api/admin/export/route.ts
  // Turn 2: verify stdout had the vulnerable source file, call record_fact(code_audit_suspect) + complete_intent
  let sawMountedSourceInToolOutput = false
  const llmServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
      input?: Array<Record<string, unknown>>
    }
    const input = body.input ?? []
    const outputs = input.filter(item => item.type === 'function_call_output')
    const alreadyCompleted = input.some(item => item.type === 'function_call' && item.name === 'complete_intent')

    let sse: string
    if (alreadyCompleted) {
      sse = sseResponsesPayload('Source-first code audit finished cleanly.')
    } else if (outputs.length === 0) {
      sse = sseResponsesPayload('', [{
        name: 'derive_evidence',
        args: {
          command: 'find /repos -type f && cat /repos/acme/billing-app/app/api/admin/export/route.ts',
        },
      }])
    } else {
      const serializedOutputs = JSON.stringify(outputs)
      if (serializedOutputs.includes('SUPABASE_SERVICE_ROLE') && serializedOutputs.includes('export async function GET')) {
        sawMountedSourceInToolOutput = true
      }
      sse = sseResponsesPayload('', [
        {
          name: 'record_fact',
          args: {
            kind: 'code_audit_suspect',
            origin: appOrigin,
            summary: 'GET /api/admin/export queries all tenant billing records using SUPABASE_SERVICE_ROLE without authentication or ownership check.',
            data: {
              subkind: 'code_audit_suspect',
              repo: 'acme/billing-app',
              file: 'app/api/admin/export/route.ts',
              line: 5,
              routeOrAction: 'GET /api/admin/export',
              authCheck: 'none',
              ownershipCheck: 'none',
              sinkKind: 'api_route',
              hypothesis: 'Unauthenticated caller can dump all tenant billing invoices via GET /api/admin/export.',
              recommendedTier: 1,
            },
          },
        },
        {
          name: 'complete_intent',
          args: {
            status: 'proved',
            summary: 'Audited acme/billing-app and recorded 1 missing-auth API route suspect.',
          },
        },
      ])
    }

    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
  })
  t.after(() => llmServer.close())

  await saveModelProfile({
    name: 'Code Audit Fixture',
    endpoint: llmServer.url,
    model: 'code-audit-fixture',
    protocol: 'responses',
    key: 'code-audit-key-12345',
    priority: 100,
  }, storage, { skipConnectionCheck: true })
  const profiles = privateModelProfiles(storage)

  // Project A: NO mounted repos -> MUST skip gracefully without LLM calls or crashes
  const { id: emptyProjectId } = storage.createProject({
    requestId: randomUUID(), name: 'No Repo Project', seeds: [appOrigin], environment: 'public',
  })
  const { id: emptyRunId } = storage.createRun({
    requestId: randomUUID(), projectId: emptyProjectId, goal: 'Skip code audit when no repos', sourceMode: 'public',
    capabilityTier: 1, budgetUsd: 1, budgetRequests: 20, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 12,
  })
  storage.command({ requestId: randomUUID(), runId: emptyRunId, action: 'discover', consent: true })
  const emptyAsset = storage.run(emptyRunId).candidates[0]
  storage.command({ requestId: randomUUID(), runId: emptyRunId, action: 'scope', expectedScopeRevision: 0, assetIds: [emptyAsset.id], consent: true })

  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const skipped = await execution.runSourceFirstCodeAudit(storage.run(emptyRunId), [], profiles, AbortSignal.timeout(10_000))
  assert.equal(skipped.suspects.length, 0)
  assert.equal(skipped.stepsCreated.length, 0)

  // Project B: Mounted temp repo containing vulnerable missing-auth handler
  const { id: repoProjectId } = storage.createProject({
    requestId: randomUUID(), name: 'Billing Repo Project', seeds: [appOrigin], environment: 'public',
  })
  const repoPath = join(projectReposDir(storage.directory, repoProjectId), 'acme', 'billing-app', 'app', 'api', 'admin', 'export')
  mkdirSync(repoPath, { recursive: true })
  writeFileSync(join(repoPath, 'route.ts'), [
    `import { createClient } from '@supabase/supabase-js'`,
    `const db = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE!)`,
    ``,
    `// Missing auth & ownership check`,
    `export async function GET(req: Request) {`,
    `  const { data } = await db.from('invoices').select('*')`,
    `  return Response.json({ invoices: data })`,
    `}`,
  ].join('\n'))

  const { id: repoRunId } = storage.createRun({
    requestId: randomUUID(), projectId: repoProjectId, goal: 'Source-first audit of billing app', sourceMode: 'public',
    capabilityTier: 1, budgetUsd: 1, budgetRequests: 20, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 12,
  })
  storage.command({ requestId: randomUUID(), runId: repoRunId, action: 'discover', consent: true })
  const repoAsset = storage.run(repoRunId).candidates[0]
  storage.command({ requestId: randomUUID(), runId: repoRunId, action: 'scope', expectedScopeRevision: 0, assetIds: [repoAsset.id], consent: true })

  // Verify codeAuditPrompt structure directly as well
  const promptJson = JSON.parse(codeAuditPrompt({
    goal: 'Source-first audit',
    capabilityTier: 1,
    approvedOrigins: [appOrigin],
    mountedRepos: ['acme/billing-app'],
  })) as { reposRoot: string; mountedRepos: string[]; suspectFactSchema: { kind: string } }
  assert.equal(promptJson.reposRoot, '/repos')
  assert.deepEqual(promptJson.mountedRepos, ['acme/billing-app'])
  assert.equal(promptJson.suspectFactSchema.kind, 'code_audit_suspect')

  const auditRes = await execution.runSourceFirstCodeAudit(storage.run(repoRunId), [], profiles, AbortSignal.timeout(20_000))
  assert.equal(sawMountedSourceInToolOutput, true, 'Expected code-auditor derive_evidence to read the mounted /repos file')
  assert.equal(auditRes.suspects.length, 1)
  assert.equal(auditRes.suspects[0].kind, 'policy_gap')
  assert.equal(auditRes.suspects[0].data.subkind, 'code_audit_suspect')
  assert.equal(auditRes.stepsCreated.length, 1)
  assert.match(auditRes.stepsCreated[0].title, /GET \/api\/admin\/export/)
  assert.ok(auditRes.stepsCreated[0].priority >= 90)
  assert.deepEqual(auditRes.stepsCreated[0].dependsOnFactIds, [auditRes.suspects[0].id])
})

// ============================================================================
// 5. Priority #4: Cross-Host Chain Synthesizer
// ============================================================================


// ============================================================================
// 6. Priority #6 & #3: Header Hygiene Collapse, (origin, cwe) Dedup, 80/20 Budgeting, BOLA Queue & Skills
// ============================================================================

test('Header hygiene noise collapse, (origin, cwe) chain dedup, 80/20 crown-jewel budgeting, BOLA queue, and defensive playbooks', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-rollup-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  // --- 6A. Header Hygiene Noise Collapse (25 noisy checks across 5 origins -> 5 posture summaries) ---
  const origins = [appOrigin, clerkOrigin, sandpackOrigin, docsOrigin, blogOrigin]
  const noisyCheckTemplates = [
    { id: 'content-security-policy' as const, title: 'Content Security Policy is not enforced', severity: 'low' as const, cwe: 'CWE-693' },
    { id: 'frame-protection' as const, title: 'HTML response can be embedded without a recorded frame restriction', severity: 'low' as const, cwe: 'CWE-1021' },
    { id: 'nosniff' as const, title: 'MIME sniffing protection missing', severity: 'low' as const, cwe: 'CWE-16' },
    { id: 'referrer-policy' as const, title: 'Referrer-Policy header is missing', severity: 'informational' as const, cwe: 'CWE-200' },
    { id: 'server-disclosure' as const, title: 'Response discloses server technology details', severity: 'informational' as const, cwe: 'CWE-200' },
  ]

  const noisyFindings: Finding[] = []
  for (const origin of origins) {
    for (const tmpl of noisyCheckTemplates) {
      noisyFindings.push({
        id: randomUUID(),
        origin,
        title: tmpl.title,
        status: 'confirmed',
        severity: tmpl.severity,
        reason: `${tmpl.title} on ${origin}.`,
        remediation: `Configure ${tmpl.id}.`,
        category: 'security-headers',
        cwe: tmpl.cwe,
        confidence: 'high',
        findingKind: 'baseline_check',
        check: { id: tmpl.id, observed: 'missing', expected: 'present' },
        evidenceIds: [`ev-${origin}-${tmpl.id}`],
        scopeRevision: 1,
      })
    }
  }
  assert.equal(noisyFindings.length, 25)
  assert.ok(noisyFindings.every(f => isBaselineHeaderHygieneFinding(f)))

  const realHighChain: Finding = {
    id: randomUUID(),
    origin: clerkOrigin,
    title: 'Wildcard Subdomain Credentialed CORS Exposure',
    status: 'confirmed',
    severity: 'high',
    reason: 'Reflects arbitrary subdomain origin with ACAC: true.',
    remediation: 'Restrict Access-Control-Allow-Origin to exact trusted origins.',
    category: 'cors-client-side',
    cwe: 'CWE-942',
    confidence: 'high',
    findingKind: 'multi_step_chain',
    evidenceIds: ['ev-cors-1'],
    scopeRevision: 1,
  }
  const realMediumBaseline: Finding = {
    id: randomUUID(),
    origin: appOrigin,
    title: 'Sensitive Session Cookie Missing HttpOnly Flag',
    status: 'confirmed',
    severity: 'medium',
    reason: 'Session cookie accessible to document.cookie.',
    remediation: 'Set HttpOnly and Secure flags on session cookies.',
    category: 'auth-identity',
    cwe: 'CWE-1004',
    confidence: 'high',
    findingKind: 'baseline_check',
    evidenceIds: ['ev-cookie-1'],
    scopeRevision: 1,
  }

  const collapsed = collapseBaselineHeaderFindings([...noisyFindings, realHighChain, realMediumBaseline])
  assert.equal(collapsed.collapsedCount, 25)
  assert.equal(collapsed.hygieneSummaries.length, 5)
  // 2 prominent findings + 5 per-origin posture summaries = 7 total (down from 27!)
  assert.equal(collapsed.findings.length, 7)
  assert.ok(collapsed.findings.some(f => f.id === realHighChain.id))
  assert.ok(collapsed.findings.some(f => f.id === realMediumBaseline.id))
  assert.equal(collapsed.findings.filter(isConsolidatedHeaderPostureFinding).length, 5)
  // Idempotent when called a second time
  const collapsedTwice = collapseBaselineHeaderFindings(collapsed.findings)
  assert.equal(collapsedTwice.collapsedCount, 0)
  assert.equal(collapsedTwice.findings.length, collapsed.findings.length)

  // Highlights MUST prioritize real High/Medium findings over collapsed header posture
  const highlights = reportHighlights({
    goal: 'Test',
    goalRevision: 1,
    scopeRevision: 1,
    capabilityTier: 2,
    scope: origins.map((origin, i) => ({
      id: `asset-${i}`,
      origin,
      source: 'seed',
      evidence: 'seed',
      thirdParty: false,
    })),
    coverage: [],
    findings: collapsed.findings,
    gaps: [],
  })
  assert.equal(highlights.headerPostureCount, 5)
  assert.equal(highlights.priority?.finding?.id, realHighChain.id)

  // --- 6B. (origin, cwe) Chain Finding Dedup in SQLite Store & Markdown Export ---
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Dedup & Export Project', seeds: [clerkOrigin, appOrigin, sandpackOrigin], environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Verify dedup and markdown export', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 1, budgetRequests: 30, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 15,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const r0 = storage.run(runId)
  storage.command({
    requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0,
    assetIds: r0.candidates.map(c => c.id), consent: true,
  })
  const run = storage.run(runId)
  const clerkAsset = run.candidates.find(c => c.origin === clerkOrigin)!
  const appAsset = run.candidates.find(c => c.origin === appOrigin)!
  const verifyWorker = storage.makeWorker(run, 'verification', clerkAsset, 'Dedup Replay Evidence', 'CWE-942')
  const makeConfirmedReplaySpec = (findingId: string, origin: string, title: string, cwe: string) => {
    const spec: DeclarativeReplaySpec = {
      version: 1,
      kind: 'http_chain',
      origin,
      title,
      category: 'cors-client-side',
      cwe,
      severity: 'high',
      spaCatchallControl: false,
      severityRationale: 'Verified multi-step chain evidence.',
      impact: 'Cross-origin exposure.',
      remediation: 'Restrict trusted origins.',
      recheckInstructions: 'Replay request.',
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "confirmed", expected: "blocked" }',
      steps: [
        { id: 'c1', role: 'control', description: 'Control', request: { origin, method: 'GET', pathAndQuery: '/api/me', followRedirects: false } },
        { id: 'p1', role: 'probe', description: 'Probe', request: { origin, method: 'GET', pathAndQuery: '/api/me', followRedirects: false } },
      ],
    }
    return storage.createReplaySpec(run, verifyWorker, findingId, spec, [origin], {
      verifiedInline: true,
      lastVerificationDiff: {
        verdict: 'confirmed',
        controlPassed: true,
        assertionSummary: { observed: 'confirmed', expected: 'blocked' },
        stepStatuses: [{ id: 'p1', role: 'probe', status: 200, bodyLen: 32 }],
        retriesRemaining: 0,
      },
    })
  }

  // Upsert confirmed CWE-942 on clerkOrigin
  const confirmed1Id = randomUUID()
  const confirmed1Spec = makeConfirmedReplaySpec(confirmed1Id, clerkOrigin, realHighChain.title, 'CWE-942')
  const confirmed1 = storage.upsertChainFinding(run, clerkAsset.id, {
    ...realHighChain,
    id: confirmed1Id,
    severity: 'medium',
    status: 'confirmed',
    evidenceIds: ['ev-a'],
    exchangeIds: ['ex-a'],
    chainFactIds: ['fact-a'],
  }, confirmed1Spec.id, [clerkOrigin])

  // Upsert duplicate (clerkOrigin, CWE-942) with different ID & pending status -> MUST merge into 1 row and NOT downgrade confirmed!
  const dupPending = storage.upsertChainFinding(run, clerkAsset.id, {
    ...realHighChain,
    id: randomUUID(),
    title: 'Second duplicate CORS report on clerk',
    severity: 'critical',
    status: 'pending',
    evidenceIds: ['ev-b'],
    exchangeIds: ['ex-b'],
    chainFactIds: ['fact-b'],
  }, 'spec-2', [clerkOrigin, sandpackOrigin])

  assert.equal(dupPending.id, confirmed1.id)
  assert.equal(dupPending.status, 'confirmed')
  assert.equal(dupPending.severity, 'medium', 'Unverified pending duplicate MUST NOT upgrade confirmed severity')
  assert.deepEqual(dupPending.evidenceIds.sort(), ['ev-a', 'ev-b'])
  assert.deepEqual(dupPending.exchangeIds?.sort(), ['ex-a', 'ex-b'])
  assert.deepEqual(dupPending.chainFactIds?.sort(), ['fact-a', 'fact-b'])

  // Different CWE on same origin stays separate
  const diffCweId = randomUUID()
  const diffCweSpec = makeConfirmedReplaySpec(diffCweId, clerkOrigin, 'OAuth Open Redirect on Clerk', 'CWE-601')
  const diffCwe = storage.upsertChainFinding(run, clerkAsset.id, {
    ...realHighChain,
    id: diffCweId,
    title: 'OAuth Open Redirect on Clerk',
    cwe: 'CWE-601',
    status: 'confirmed',
    evidenceIds: ['ev-c'],
  }, diffCweSpec.id, [clerkOrigin])
  assert.notEqual(diffCwe.id, confirmed1.id)

  // Same CWE on different origin stays separate
  const diffOriginId = randomUUID()
  const diffOriginSpec = makeConfirmedReplaySpec(diffOriginId, appOrigin, realHighChain.title, 'CWE-942')
  const diffOrigin = storage.upsertChainFinding(run, appAsset.id, {
    ...realHighChain,
    id: diffOriginId,
    origin: appOrigin,
    cwe: 'CWE-942',
    status: 'confirmed',
    evidenceIds: ['ev-d'],
  }, diffOriginSpec.id, [appOrigin])
  assert.notEqual(diffOrigin.id, confirmed1.id)

  const chainRows = storage.runDetail(runId).findings.filter(f => f.findingKind === 'multi_step_chain')
  assert.equal(chainRows.length, 3)

  // Also test pure deduplicateChainFindings & chainFindingDedupKey
  assert.equal(
    chainFindingDedupKey({ origin: clerkOrigin, cwe: 'cwe-942', category: 'cors', title: 'A' }),
    chainFindingDedupKey({ origin: clerkOrigin, cwe: 'CWE-942', category: 'other', title: 'B' }),
  )
  const mergedPure = mergeChainFindings(
    { ...realHighChain, id: 'f1', status: 'confirmed', severity: 'high', evidenceIds: ['e1'] },
    { ...realHighChain, id: 'f2', status: 'inconclusive', severity: 'low', evidenceIds: ['e2'] },
  )
  assert.equal(mergedPure.status, 'confirmed')
  assert.deepEqual(mergedPure.evidenceIds, ['e1', 'e2'])
  assert.equal(deduplicateChainFindings([
    { ...realHighChain, id: 'f1', status: 'confirmed', evidenceIds: ['e1'] },
    { ...realHighChain, id: 'f2', status: 'pending', evidenceIds: ['e2'] },
  ]).length, 1)

  // Write baseline noisy findings into SQLite and verify writeReport + Markdown export table collapse
  const wBaseline = storage.makeWorker(run, 'verification', clerkAsset, 'Baseline', 'Headers')
  const ev = storage.addArtifact(run, wBaseline, 'observation', 'Baseline root', '{}')
  for (const nf of noisyFindings.filter(f => f.origin === clerkOrigin)) {
    storage.db.insert(findingsTable).values({
      id: nf.id,
      runId: run.id,
      assetId: clerkAsset.id,
      goalRevision: run.goalRevision,
      checkId: nf.check?.id ?? 'nosniff',
      caseId: nf.id,
      findingKind: 'baseline_check',
      sourceOrigins: [clerkOrigin],
      finding: { ...nf, evidenceIds: [ev.id] },
    }).run()
  }
  storage.writeReport(storage.run(runId), false)
  const report = storage.runDetail(runId).reports[0]
  assert.ok(report)
  assert.equal(report.body.findings.filter(isConsolidatedHeaderPostureFinding).length, 1)
  assert.equal(report.body.findings.filter(f => f.findingKind === 'multi_step_chain').length, 3)

  const exported = exportReportMarkdown(storage, runId, report.id)
  assert.ok(exported.content.includes('### HTTP Security Header Posture (Baseline Hygiene)'))
  assert.ok(exported.content.includes(HEADER_POSTURE_CATEGORY))
  assert.ok(exported.content.includes('Wildcard Subdomain Credentialed CORS Exposure'))

  // --- 6C. 80/20 Crown-Jewel Host Prioritization & Step Budgeting ---
  const allOrigins = [clerkOrigin, appOrigin, sandpackOrigin, 'https://bulletin.northstar.example', docsOrigin, blogOrigin, wwwOrigin]
  const tiers = computeHostTiers(allOrigins)
  assert.equal(tiers[clerkOrigin], 'crown_jewel')
  assert.equal(tiers[appOrigin], 'crown_jewel')
  assert.equal(tiers[sandpackOrigin], 'crown_jewel')
  assert.equal(tiers['https://bulletin.northstar.example'], 'standard')
  assert.equal(tiers[docsOrigin], 'low_value_static')
  assert.equal(tiers[blogOrigin], 'low_value_static')
  assert.equal(tiers[wwwOrigin], 'low_value_static')
  assert.equal(classifyHostTier('https://stripe-webhooks.example'), 'crown_jewel')

  // Turn cap on low_value_static when crown_jewel hosts exist
  assert.equal(computeStepMaxTurns([clerkOrigin], tiers, 40), 40)
  const staticTurns = computeStepMaxTurns([docsOrigin], tiers, 40)
  assert.ok(staticTurns < 40 && staticTurns <= 15, `Expected capped static turns, got ${staticTurns}`)

  // Budget allocation across 10 mixed candidate steps (6 crown-jewel, 4 static across 3 static origins)
  const candidates = [
    { title: 'Docs step 1', priority: 90, origins: [docsOrigin] },
    { title: 'Docs step 2', priority: 85, origins: [docsOrigin] },
    { title: 'Blog step 1', priority: 80, origins: [blogOrigin] },
    { title: 'WWW step 1', priority: 75, origins: [wwwOrigin] },
    { title: 'Clerk auth 1', priority: 70, origins: [clerkOrigin] },
    { title: 'Clerk auth 2', priority: 68, origins: [clerkOrigin] },
    { title: 'App API 1', priority: 65, origins: [appOrigin] },
    { title: 'App API 2', priority: 64, origins: [appOrigin] },
    { title: 'Sandpack JS 1', priority: 62, origins: [sandpackOrigin] },
    { title: 'Sandpack JS 2', priority: 60, origins: [sandpackOrigin] },
  ]
  const allocated = applyCrownJewelStepBudget(candidates, tiers, [], 8)
  const crownCount = allocated.filter(s => s.origins.some(o => tiers[o] === 'crown_jewel')).length
  const staticSteps = allocated.filter(s => s.origins.every(o => tiers[o] === 'low_value_static'))
  assert.ok(crownCount >= 6, `Expected >=6 crown-jewel steps out of ${allocated.length}, got ${crownCount}`)
  assert.ok(staticSteps.length <= 2, `Expected <=2 static steps (<=20% share), got ${staticSteps.length}`)
  // No static origin gets >1 step
  const docsAllocated = staticSteps.filter(s => s.origins.includes(docsOrigin))
  assert.ok(docsAllocated.length <= 1)

  // --- 6D. Multi-Persona BOLA Resource Tracking & Queue ---
  const extracted = extractPersonaResourcesFromExchange({
    origin: appOrigin,
    method: 'GET',
    pathAndQuery: '/api/projects/proj_99182',
    personaHandle: 'user_a',
    status: 200,
    mediaType: 'application/json',
    body: JSON.stringify({ project_id: 'proj_99182', organization_id: 'org_7731', name: 'Private Roadmap' }),
  })
  assert.ok(extracted.some(item => item.resourceId === 'proj_99182'))
  assert.ok(extracted.some(item => item.resourceId === 'org_7731'))
  // Static JS/CSS assets and unauthenticated requests are ignored
  assert.equal(extractPersonaResourcesFromExchange({
    origin: appOrigin, method: 'GET', pathAndQuery: '/_next/static/chunk.js', personaHandle: 'user_a', status: 200, mediaType: 'application/javascript', body: '{"id":"12345"}',
  }).length, 0)

  const resFact = storage.addFact(run, wBaseline, {
    kind: 'persona_resource',
    origin: appOrigin,
    summary: 'user_a owns project proj_99182',
    data: { ownerPersona: 'user_a', resourceId: 'proj_99182', endpoint: '/api/projects/proj_99182', method: 'GET' },
  })
  assert.equal(resFact.kind, 'object_ref')
  assert.equal(resFact.data.subkind, 'persona_resource')

  const bolaQueue = buildBolaTestQueue(
    [resFact],
    [
      { handle: 'user_a', originAllowlist: [appOrigin] },
      { handle: 'user_b', originAllowlist: [appOrigin] },
    ],
    new Set([appOrigin]),
  )
  assert.equal(bolaQueue.length, 1)
  assert.equal(bolaQueue[0].ownerPersona, 'user_a')
  assert.equal(bolaQueue[0].resourceId, 'proj_99182')
  assert.deepEqual(bolaQueue[0].testAsPersonas, ['user_b', 'anonymous'])

  // --- 6E. New Defensive Playbooks Load Cleanly ---
  for (const name of ['source-first-audit', 'bola-idor-race', 'cross-host-chaining', 'oob-ssrf-browser-chain']) {
    const skill = loadSkill(name)
    assert.ok(skill, `Expected skill "${name}" to load`)
    assert.ok(skill.content.length > 200)
  }
  assert.ok(skillsByTag('source-audit').some(s => s.name === 'source-first-audit'))
  assert.ok(skillsByTag('bola').some(s => s.name === 'bola-idor-race'))
  assert.ok(skillsByTag('cross-host').some(s => s.name === 'cross-host-chaining'))
  assert.ok(skillsByTag('canary').some(s => s.name === 'oob-ssrf-browser-chain'))
})
