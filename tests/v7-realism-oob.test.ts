/**
 * v7 M1 — Realism #2 out-of-band attribution (probe lane).
 *
 * The wan-oob fixture returns `202` before its background worker fetches an injected URL or
 * resolves an external XML entity 15–30 s later. A short synchronous poll can only be a miss, so
 * the durable `pending_oob` subscription is what lets the run-level drain promote the late
 * callback. For the drain to attribute that callback to the injection, the recorded exchange must
 * name the canary token. Request bodies are not searchable; the broker's correlation id is
 * (`X-Guardian-Trace-Id` in a local lab), so every canary-carrying probe request sets `traceId` to
 * the token it injected.
 *
 * Selection/hypothesis-shape tests and the second-order engine helper live in the engine lane; see
 * `plans/REALISM-OOB-NOTES.md` for the proposed engine diff (that file is owned by another stream).
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, test } from 'node:test'

import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { trackFloorCanarySubscriptions } from '../src/server/deterministic-engine.ts'
import type { DiffContext, InjectedRequest } from '../src/server/probes/context.ts'
import { ssrfProbe } from '../src/server/probes/ssrf.ts'
import { xxeProbe } from '../src/server/probes/xxe.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:46527'
const runId = 'run-realism-oob'
const assignmentId = 'asg-realism-oob'

const tempDirs: string[] = []
const brokers: CanaryBroker[] = []

afterEach(() => {
  for (const broker of brokers.splice(0)) {
    try { broker.closeOob() } catch { /* already closed */ }
  }
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function localBroker(): CanaryBroker {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-realism-oob-'))
  tempDirs.push(dir)
  const broker = new CanaryBroker({ oobDirectory: dir })
  brokers.push(broker)
  return broker
}

function grant(): Grant {
  return {
    tier: 3,
    allowLocalLab: true,
    canRead: () => true,
    audit: () => {},
    scopePolicy: { mode: 'ephemeral_lab', targetOrigins: [origin], routeDenylist: [], runId },
  } as unknown as Grant
}

function okExchange(req: InjectedRequest): BrokerExchangeResult {
  return {
    origin: req.headers?.origin ?? origin,
    finalOrigin: origin,
    redirectOrigins: [],
    finalPathAndQuery: req.pathAndQuery,
    method: req.method ?? 'POST',
    pathAndQuery: req.pathAndQuery,
    personaHandle: null,
    status: 202,
    mediaType: 'application/json',
    reqHeaders: req.headers ?? {},
    respHeaders: { 'content-type': 'application/json' },
    setCookies: [],
    bodyPreview: '{"accepted":true}',
    body: '{"accepted":true}',
    bodySha256: 'sha256',
    bodyBytes: 16,
    bodyTruncated: false,
    durationMs: 4,
    secretMatches: [],
  } as unknown as BrokerExchangeResult
}

function context(req: DiffContext['req'], sent: BrokerHttpRequest[]): DiffContext {
  return {
    req,
    origin,
    runner: {} as never,
    notes: [],
    anomalies: [],
    send: async (r: InjectedRequest) => {
      sent.push(r as BrokerHttpRequest)
      return okExchange(r)
    },
  }
}

function tokenIn(value: string, tokens: ReadonlySet<string>): string | undefined {
  for (const token of tokens) if (value.includes(token)) return token
  return undefined
}

// ============================================================================
// SSRF — every injected canary names its own carrying exchange
// ============================================================================

test('the SSRF probe correlates every canary URL it injects with the carrying request', async () => {
  const broker = localBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })
  const sent: BrokerHttpRequest[] = []
  const ctx = context({
    probeClass: 'ssrf_canary',
    origin,
    pathAndQuery: '/v1/integrations/webhook-test',
    method: 'POST',
    param: 'url',
    paramLocation: 'json',
    ssrfParams: ['url'],
    jsonBody: { url: 'http://guardian-control.invalid/' },
    waitMs: 1,
    runId,
    assignmentId,
  }, sent)

  const outcome = await ssrfProbe.run(ctx, { grant: grant(), canaryBroker: tracker.broker, signal: new AbortController().signal })
  assert.equal(outcome.verdict, 'no_signal', 'a 500 ms poll cannot see a callback that arrives 15–30 s later')

  const pending = broker.pending(runId)
  assert.ok(pending.length >= 2, 'the http and dns canaries each registered a durable subscription')
  const tokens = new Set(pending.map(sub => sub.token))

  const carrying = sent.filter(req => typeof req.body === 'string' && tokenIn(req.body, tokens))
  assert.ok(carrying.length >= 2, 'each canary URL is injected by a recorded request')
  for (const req of carrying) {
    const token = tokenIn(req.body as string, tokens)!
    assert.equal(req.traceId, token,
      'the carrying exchange records the canary token as its broker correlation id')
  }
  assert.equal(outcome.details.results && Array.isArray(outcome.details.results), true)
})

// ============================================================================
// XXE — entity payloads are XML and correlated the same way
// ============================================================================

test('the XXE probe correlates every entity canary and sends an XML body', async () => {
  const broker = localBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })
  const sent: BrokerHttpRequest[] = []
  const ctx = context({
    probeClass: 'xxe_canary',
    origin,
    pathAndQuery: '/v1/import/preview',
    method: 'POST',
    waitMs: 1,
    runId,
    assignmentId,
  }, sent)

  const outcome = await xxeProbe.run(ctx, { grant: grant(), canaryBroker: tracker.broker, signal: new AbortController().signal })
  assert.equal(outcome.verdict, 'no_signal', 'the fixture resolves the entity after its 202')

  const pending = broker.pending(runId)
  assert.ok(pending.length >= 3, 'every entity variant registered a durable subscription')
  const tokens = new Set(pending.map(sub => sub.token))

  const payloads = sent.filter(req => typeof req.body === 'string' && req.body.includes('<!DOCTYPE'))
  assert.ok(payloads.length >= 3, 'general, parameter and SVG entity payloads were sent')
  const carrying = payloads.filter(req => tokenIn(req.body as string, tokens))
  assert.ok(carrying.length >= 3, 'each entity payload names its canary URL')
  for (const req of carrying) {
    const token = tokenIn(req.body as string, tokens)!
    assert.equal(req.traceId, token,
      'the entity-carrying exchange records the canary token as its correlation id')
    assert.equal(req.headers?.['Content-Type'], 'application/xml')
  }
})

// ============================================================================
// Attribution — the recorded correlation header is what the drain can search
// ============================================================================

test('a recorded correlation header makes the carrying exchange findable for OOB attribution', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-realism-oob-store-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const { runId: storeRunId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 2 })
  const run = storage.run(storeRunId)
  const asset = run.candidates[0]!
  const worker = storage.workerList(storeRunId)[0]
    ?? storage.makeWorker(run, 'verification', asset, 'oob carrier', 'oob carrier')
  const token = 'guardian-canary-5f08851ce59f23bfd53e9340'
  const exchange = storage.recordExchange({
    runId: storeRunId,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'POST',
    pathAndQuery: '/v1/integrations/webhook-test',
    personaHandle: null,
    status: 202,
    mediaType: 'application/json',
    reqHeaders: { 'content-type': 'application/json', 'x-guardian-trace-id': token },
    respHeaders: { 'content-type': 'application/json' },
    body: '{"accepted":true}',
    durationMs: 4,
  })
  const found = storage.searchExchanges(storeRunId, token, {
    approvedOrigins: new Set([origin]),
    limit: 10,
  })
  assert.equal(found.length, 1, 'the token in the request headers identifies the injection exchange')
  assert.equal(found[0]!.id, exchange.id)
  assert.equal(found[0]!.reqHeaders['x-guardian-trace-id'], token)
})
