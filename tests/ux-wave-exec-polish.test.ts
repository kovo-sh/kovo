import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createPersona, runCommand } from '../src/domain.ts'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { BrokerAuditMeta, Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDRESS = { address: '93.184.216.34', family: 4 }

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-exec-polish-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function makeStubBroker(calls: Array<{ method: string; url: string; ts: number }>): RequestBroker {
  return new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string }) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href, ts: Date.now() })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
}

function createAndApproveRun(
  storage: Store,
  opts: {
    origin?: string
    tier?: 0 | 1 | 2 | 3
    maxRpsPerOrigin?: number
    approvedPersonaIds?: string[]
  } = {},
) {
  const origin = opts.origin ?? APP_ORIGIN
  const project = storage.createProject({
    requestId: randomUUID(),
    name: `UX Exec Polish ${randomUUID().slice(0, 6)}`,
    seeds: [origin],
    environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify live maxRpsPerOrigin and BrokerDenied diagnostic metadata',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 2,
    ...(opts.maxRpsPerOrigin !== undefined ? { maxRpsPerOrigin: opts.maxRpsPerOrigin } : {}),
  } as Parameters<Store['createRun']>[0])

  storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = storage.run(runId)
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    ...(opts.approvedPersonaIds ? { approvedPersonaIds: opts.approvedPersonaIds } : {}),
  }))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { projectId: project.id, runId, origin }
}

function buildExecutionGrant(
  execution: Execution,
  storage: Store,
  runId: string,
  origin = APP_ORIGIN,
): { grant: Grant; assignmentId: string } {
  const run = storage.run(runId)
  const created = storage.makeWorker(run, 'investigation', run.candidates[0], 'Polish worker', 'Verify grant contract', {
    sourceOrigins: [origin],
  })
  const assignment = storage.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
  const job = { assignment, origins: new Set([origin]), controller: new AbortController() }
  const priv = execution as unknown as Record<string, any>
  const built = priv.buildGrant(job, run, new Set([origin])) as { grant: Grant }
  return { grant: built.grant, assignmentId: assignment.id }
}

// ---------------------------------------------------------------------------
// 1. Live dynamic maxRpsPerOrigin on Grant
// ---------------------------------------------------------------------------

test('Live maxRpsPerOrigin: updating run.maxRpsPerOrigin mid-run updates an existing Grant and broker throttle immediately', async t => {
  const storage = makeStorage(t)
  const { runId } = createAndApproveRun(storage, { tier: 2, maxRpsPerOrigin: 10 })
  const calls: Array<{ method: string; url: string; ts: number }> = []
  const execution = new Execution(storage, { broker: makeStubBroker(calls) })
  t.after(() => execution.stop())

  // Build Grant once at worker admission (maxRpsPerOrigin = 10)
  const { grant } = buildExecutionGrant(execution, storage, runId)
  assert.equal(grant.maxRpsPerOrigin, 10)
  assert.equal(grant.getMaxRpsPerOrigin?.(), 10)

  // Spread clone (like ScopedBrowser does) must keep live lookup via getMaxRpsPerOrigin
  const spreadGrant: Grant = { ...grant }

  // Warm the origin bucket at 10 RPS
  await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/ping-1',
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(calls.length, 1)

  // Mid-run RPS slider change via raise_budget command: raise to 15 without rebuilding Grant
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'raise_budget',
    maxRpsPerOrigin: 15,
  }))
  assert.equal(grant.maxRpsPerOrigin, 15, 'existing Grant.maxRpsPerOrigin must immediately reflect raise_budget update')
  assert.equal(grant.getMaxRpsPerOrigin?.(), 15)
  assert.equal(spreadGrant.getMaxRpsPerOrigin?.(), 15, 'spread Grant must still observe live RPS via getMaxRpsPerOrigin')

  // Mid-run throttle DOWN to 1 RPS without rebuilding Grant
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'raise_budget',
    maxRpsPerOrigin: 1,
  }))
  assert.equal(grant.maxRpsPerOrigin, 1, 'existing Grant.maxRpsPerOrigin must immediately reflect lowered RPS')

  // First request after drop clamps tokens to 1 and consumes it; second request must wait ~1s
  await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/slow-1',
  }, grant, AbortSignal.timeout(5_000))
  const tStart = Date.now()
  await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/slow-2',
  }, grant, AbortSignal.timeout(5_000))
  const slowDeltaMs = Date.now() - tStart
  assert.ok(
    slowDeltaMs >= 750,
    `expected 1 RPS live throttle to delay second request by ~1000ms, got ${slowDeltaMs}ms`,
  )

  // Mid-run throttle UP to 20 RPS without rebuilding Grant
  storage.updateRun(runId, { maxRpsPerOrigin: 20 })
  assert.equal(grant.maxRpsPerOrigin, 20)

  // Wait 200ms so at 20 RPS the bucket refills ~4 tokens (at 1 RPS it would still be < 1 token)
  await new Promise(resolve => setTimeout(resolve, 200))
  const fastStart = Date.now()
  await Promise.all([
    execution.broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/fast-1' }, grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/fast-2' }, grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/fast-3' }, grant, AbortSignal.timeout(5_000)),
  ])
  const fastDeltaMs = Date.now() - fastStart
  assert.ok(
    fastDeltaMs < 400,
    `expected 20 RPS live raise to let 3 requests finish rapidly, took ${fastDeltaMs}ms`,
  )
})

// ---------------------------------------------------------------------------
// 2. Diagnostic BrokerDenied metadata (reason, method, path, persona) + redaction
// ---------------------------------------------------------------------------

test('BrokerDenied audit metadata: emits reason, method, path, persona in broker.denied event detail with secrets redacted', async t => {
  const storage = makeStorage(t)
  const secretToken = 'tok_live_99887766554433221100aabbcc'
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'UX Denied Meta Project',
    seeds: [APP_ORIGIN],
    environment: 'public',
  })
  const createdPersona = createProjectPersona(storage, createPersona.parse({
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'alice',
    roleLabel: 'Standard Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'bearer',
    secret: secretToken,
  }))

  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify diagnostic BrokerDenied metadata',
    sourceMode: 'public',
    capabilityTier: 2,
  } as Parameters<Store['createRun']>[0])
  storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = storage.run(runId)
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    approvedPersonaIds: [createdPersona.id],
  }))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })

  const calls: Array<{ method: string; url: string; ts: number }> = []
  const execution = new Execution(storage, { broker: makeStubBroker(calls) })
  t.after(() => execution.stop())

  const { grant, assignmentId } = buildExecutionGrant(execution, storage, runId)

  // Case 1: Tier-2 disallowed POST with approved persona + secret token echoed in query string
  await assert.rejects(
    execution.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/admin/delete?token=${secretToken}`,
      persona: 'alice',
      headers: { 'Content-Type': 'application/json' },
      body: '{"id":42}',
    }, grant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )

  const deniedAfterPost = storage.eventsAfter(runId, 0).filter(e => e.kind === 'broker.denied')
  assert.equal(deniedAfterPost.length, 1)
  const postEv = deniedAfterPost[0]!
  assert.equal(postEv.detail.assignmentId, assignmentId)
  assert.equal(postEv.detail.origin, APP_ORIGIN)
  assert.equal(postEv.detail.method, 'POST')
  assert.equal(postEv.detail.persona, 'alice')
  assert.equal(typeof postEv.detail.reason, 'string')
  assert.ok(
    /Tier 3|read-only|not permitted|POST/i.test(String(postEv.detail.reason)),
    `expected descriptive reason, got: ${postEv.detail.reason}`,
  )
  assert.ok(
    String(postEv.detail.path).startsWith('/api/admin/delete?'),
    `expected path to be recorded, got: ${postEv.detail.path}`,
  )
  assert.ok(
    String(postEv.detail.path).includes('[redacted]'),
    `expected secret query parameter to be redacted, got: ${postEv.detail.path}`,
  )
  assert.ok(
    !String(postEv.detail.path).includes(secretToken),
    'secret token in query string must be redacted from broker.denied detail.path',
  )
  assert.ok(
    !postEv.message.includes(secretToken),
    'secret token must be redacted from broker.denied message',
  )
  assert.ok(
    postEv.message.includes('Broker denied POST ') && postEv.message.includes('app.example.test'),
    `expected descriptive broker.denied message, got: ${postEv.message}`,
  )

  // Case 2: Out-of-scope anonymous GET
  await assert.rejects(
    execution.broker.executeHttp({
      origin: 'https://out-of-scope.example.test',
      method: 'GET',
      pathAndQuery: '/private/data',
    }, grant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )

  const deniedAfterOos = storage.eventsAfter(runId, 0).filter(e => e.kind === 'broker.denied')
  assert.equal(deniedAfterOos.length, 2)
  const oosEv = deniedAfterOos[1]!
  assert.equal(oosEv.detail.origin, 'https://out-of-scope.example.test')
  assert.equal(oosEv.detail.method, 'GET')
  assert.equal(oosEv.detail.path, '/private/data')
  assert.equal(oosEv.detail.persona, undefined)
  assert.equal(oosEv.detail.reason, 'Destination is outside the current assignment scope.')
  assert.equal(
    oosEv.message,
    'Broker denied GET /private/data on out-of-scope.example.test (Destination is outside the current assignment scope.)',
  )

  // Case 3: Legacy 2-argument grant.audit('denied', origin) remains backwards-compatible
  grant.audit('denied', APP_ORIGIN)
  const deniedAfterLegacy = storage.eventsAfter(runId, 0).filter(e => e.kind === 'broker.denied')
  assert.equal(deniedAfterLegacy.length, 3)
  assert.equal(deniedAfterLegacy[2]!.message, 'Broker denied for app.example.test.')
})

test('RequestBroker passes diagnostic meta on WebSocket and forbidden-header denials', async () => {
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async () => ({ status: 200, headers: {}, body: '' }),
  })
  const audits: Array<{ outcome: string; origin: string; meta?: BrokerAuditMeta }> = []
  const grant: Grant = {
    tier: 2,
    canRead: origin => origin === APP_ORIGIN,
    audit: (outcome, origin, _status, meta) => {
      audits.push({ outcome, origin, meta })
    },
  }

  // Forbidden Authorization header on HTTP request
  await assert.rejects(
    broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/profile',
      headers: { Authorization: 'Bearer should-not-be-set' },
    }, grant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )
  const httpAudit = audits.at(-1)!
  assert.equal(httpAudit.outcome, 'denied')
  assert.equal(httpAudit.meta?.method, 'GET')
  assert.equal(httpAudit.meta?.path, '/api/profile')
  assert.match(httpAudit.meta?.reason ?? '', /Header "Authorization" cannot be set directly/)

  // Out-of-scope WebSocket probe
  await assert.rejects(
    broker.probeWebsocket({
      origin: 'wss://other.example.test',
      pathAndQuery: '/ws/live',
      persona: 'bob',
    }, grant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )
  const wsAudit = audits.at(-1)!
  assert.equal(wsAudit.outcome, 'denied')
  assert.equal(wsAudit.meta?.method, 'WS')
  assert.equal(wsAudit.meta?.path, '/ws/live')
  assert.equal(wsAudit.meta?.persona, 'bob')
  assert.match(wsAudit.meta?.reason ?? '', /outside the current assignment scope/i)
})
