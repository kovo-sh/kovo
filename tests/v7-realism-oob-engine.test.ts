/**
 * v7 Realism #2 — engine lane (selection + attribution + attempt accounting).
 *
 * The async WAN fixture accepts a URL/document with `202` and only fetches/resolves it 15–30 s
 * later, in a background worker. Three engine-side properties make that observable:
 *
 *  1. selection: a URL-consuming write (body *or* query carrier) and a document-import/upload
 *     route family are eligible even when the declared surface ships no sample value;
 *  2. trigger pairing: a write whose own last segment is a fetch verb is its own second-order
 *     trigger, so the write exchange is the trigger and a second call would be redundant;
 *  3. attribution/accounting: the canary-carrying request names its broker correlation id
 *     (`traceId`), and a probe that injected a canary but saw no callback inside its window
 *     records a *pending attempt* instead of a silent miss.
 *
 * Fixtures are synthetic route shapes only: no benchmark app or route literal appears here.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, test } from 'node:test'

import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  enumerateHypotheses,
  runDeterministicEngine,
  trackFloorCanarySubscriptions,
} from '../src/server/deterministic-engine.ts'
import type {
  EndpointHarvest,
  EngineEndpoint,
  EnginePersona,
} from '../src/server/deterministic-engine.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

const ORIGIN = 'http://fixture.invalid'
const runId = 'run-realism-oob-engine'
const assignmentId = 'asg-realism-oob-engine'

const PERSONAS: EnginePersona[] = [
  { handle: 'owner_a', roleLabel: 'owner (acme)', privilege: 'member', tenant: 'acme' },
  { handle: 'admin', roleLabel: 'admin (acme)', privilege: 'admin', tenant: 'acme' },
]

function harvestOf(over: Partial<EndpointHarvest> = {}): EndpointHarvest {
  return {
    ownerIds: [], otherIds: [], fields: [], values: {}, otherValues: {},
    seedValues: [], activeQueryParams: [], viewerIds: [], rowIds: {}, ...over,
  }
}

function endpoint(id: string, method: string, pathTemplate: string, params: EngineEndpoint['params'] = []): EngineEndpoint {
  return { id, origin: ORIGIN, method, pathTemplate, params }
}

const tempDirs: string[] = []
const brokers: CanaryBroker[] = []

afterEach(() => {
  for (const broker of brokers.splice(0)) {
    try { broker.closeOob() } catch { /* already closed */ }
  }
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function localBroker(): CanaryBroker {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-realism-oob-engine-'))
  tempDirs.push(dir)
  const broker = new CanaryBroker({ oobDirectory: dir })
  brokers.push(broker)
  return broker
}

function hypothesesFor(endpoints: EngineEndpoint[], harvests = new Map<string, EndpointHarvest>()) {
  return enumerateHypotheses(endpoints, harvests, { tier: 3, personas: PERSONAS })
}

const ssrfParams = (hyps: ReturnType<typeof hypothesesFor>) =>
  hyps.filter(hyp => hyp.probeClass === 'ssrf_canary').map(hyp => hyp.param?.name)
const xxeRoutes = (hyps: ReturnType<typeof hypothesesFor>) =>
  hyps.filter(hyp => hyp.probeClass === 'xxe_canary').map(hyp => hyp.endpoint.pathTemplate)

// ============================================================================
// 1. Selection — URL-consuming writes without a declared sample
// ============================================================================

test('realism oob: a webhook/receiver write with an empty harvest still forms SSRF hypotheses', () => {
  const route = endpoint('POST:/svc/hooks/inbound', 'POST', '/svc/hooks/inbound')
  const hyps = hypothesesFor([route], new Map([[route.id, harvestOf()]]))
  const names = ssrfParams(hyps)
  assert.ok(names.length >= 2, `a receiver family names its URL carriers: ${names.join(',')}`)
  assert.ok(names.includes('url'), 'the canonical URL carrier is always eligible')
  assert.ok(names.includes('callbackUrl'), 'the receiver vocabulary is derived from the route family')
  assert.ok(hyps.every(hyp => hyp.probeClass !== 'ssrf_canary' || hyp.endpoint.pathTemplate === route.pathTemplate))
})

test('realism oob: a URL-shaped query param selects SSRF on a mutating route', () => {
  const route = endpoint('POST:/svc/fetch/jobs', 'POST', '/svc/fetch/jobs', [{ name: 'targetUri', location: 'query' }])
  const hyps = hypothesesFor([route], new Map([[route.id, harvestOf()]]))
  const query = hyps.filter(hyp => hyp.probeClass === 'ssrf_canary' && hyp.param?.name === 'targetUri')
  assert.equal(query.length, 1, 'the URL-shaped query carrier is a first-class SSRF source')
  assert.equal(query[0]!.location, 'query')
  assert.deepEqual(query[0]!.ssrfParams, ['targetUri'])
})

test('realism oob: an observed URL-shaped body value selects SSRF even when the name is opaque', () => {
  const route = endpoint('POST:/svc/forward', 'POST', '/svc/forward', [{ name: 'destination', location: 'json' }])
  const hyps = hypothesesFor([route], new Map([[route.id, harvestOf({
    fields: ['destination'],
    values: { destination: ['https://example.test/sink'] },
  })]]))
  const names = ssrfParams(hyps)
  assert.ok(names.includes('destination'), `observed URL evidence makes the field eligible: ${names.join(',')}`)
})

// ============================================================================
// 2. Trigger pairing — a fetch-verb write is its own second-order trigger
// ============================================================================

test('realism oob: a fetch-verb write pairs itself as the second-order trigger', () => {
  const self = endpoint('POST:/svc/hooks/verify', 'POST', '/svc/hooks/verify', [
    { name: 'url', location: 'json', observedShape: 'url' },
  ])
  const plain = endpoint('POST:/svc/hooks/inbound', 'POST', '/svc/hooks/inbound', [
    { name: 'url', location: 'json', observedShape: 'url' },
  ])
  const hyps = hypothesesFor([self, plain], new Map([
    [self.id, harvestOf()],
    [plain.id, harvestOf()],
  ]))
  const selfHyps = hyps.filter(hyp => hyp.endpoint.pathTemplate === self.pathTemplate && hyp.probeClass === 'ssrf_canary')
  assert.ok(selfHyps.length >= 1)
  assert.ok(selfHyps.every(hyp => hyp.triggerPath === self.pathTemplate),
    'the write route is the trigger, so the probe must not invent a sibling call')

  const plainHyps = hyps.filter(hyp => hyp.endpoint.pathTemplate === plain.pathTemplate && hyp.probeClass === 'ssrf_canary')
  assert.ok(plainHyps.length >= 1)
  assert.ok(plainHyps.every(hyp => hyp.triggerPath === undefined),
    'a non-fetch-verb write without a sibling trigger forms no trigger pair')
})

// ============================================================================
// 3. XXE — the document-import family is eligible; unrelated writes are not
// ============================================================================

test('realism oob: XML import/upload/parse families form XXE, an unrelated write does not', () => {
  const upload = endpoint('POST:/svc/ingest/upload', 'POST', '/svc/ingest/upload')
  const batchImport = endpoint('POST:/svc/batch/import', 'POST', '/svc/batch/import')
  const parse = endpoint('POST:/svc/parse/document', 'POST', '/svc/parse/document')
  const unrelated = endpoint('POST:/svc/orders', 'POST', '/svc/orders', [{ name: 'note', location: 'json' }])
  const hyps = hypothesesFor([upload, batchImport, parse, unrelated], new Map([
    [upload.id, harvestOf()], [batchImport.id, harvestOf()],
    [parse.id, harvestOf()], [unrelated.id, harvestOf()],
  ]))
  const routes = xxeRoutes(hyps)
  for (const route of [upload, batchImport, parse]) {
    assert.ok(routes.includes(route.pathTemplate), `${route.pathTemplate} consumes a document`)
  }
  assert.ok(!routes.includes(unrelated.pathTemplate), 'a non-document write is never XXE-eligible from its shape')
})

test('realism oob: observed XML evidence selects XXE on an opaque route', () => {
  const opaque = endpoint('POST:/svc/render', 'POST', '/svc/render', [{ name: 'body', location: 'json' }])
  const hyps = hypothesesFor([opaque], new Map([[opaque.id, harvestOf({
    fields: ['body'],
    values: { body: ['<?xml version="1.0"?><root/>'] },
  })]]))
  assert.ok(xxeRoutes(hyps).includes(opaque.pathTemplate),
    'wire-format evidence overrides the route noun')
})

// ============================================================================
// 4. Attempt accounting — a canary sent without a callback is inspectable
// ============================================================================

function differential(over: Partial<DifferentialResult> = {}): DifferentialResult {
  return {
    probeClass: 'ssrf_canary',
    origin: ORIGIN,
    pathAndQuery: '/svc/hooks/inbound',
    verdict: 'no_signal',
    summary: 'No out-of-band callback was observed within the probe window.',
    anomalies: [],
    details: {},
    requestsSent: 1,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
    ...over,
  }
}

test('realism oob: a pending canary attempt is recorded, not dropped as a silent miss', () => {
  const broker = localBroker()
  const events: Array<{ kind: string; data?: Record<string, unknown> }> = []
  const tracker = trackFloorCanarySubscriptions(broker, {
    runId, assignmentId, log: (kind, _message, data) => { events.push({ kind, data }) },
  })
  const minted = tracker.broker.mintCanary(runId, 'engine:ssrf:url', ORIGIN)
  const result = differential()
  tracker.finalize(result)

  assert.equal(result.verdict, 'no_signal')
  assert.equal(result.details.canaryProbeStage, 'pending', 'the durable row stays promotable for the drain')
  const attempts = result.details.oobAttempts as Array<Record<string, unknown>>
  assert.equal(attempts.length, 1, 'the injected canary is recorded as an attempt')
  assert.equal(attempts[0].token, minted.token)
  assert.equal(attempts[0].canaryId, minted.id)
  assert.equal(attempts[0].stage, 'pending')
  assert.ok(attempts[0].subscriptionId || attempts[0].subscriptionId === null)
  assert.ok(events.some(event => event.kind === 'deterministic_engine.oob_attempt'
    && event.data?.canaryId === minted.id), 'the attempt is logged with the canary id')
})

test('realism oob: an observed promotion carries no pending attempt', () => {
  const broker = localBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })
  const minted = tracker.broker.mintCanary(runId, 'engine:ssrf:url', ORIGIN)
  broker.recordCallback({
    token: minted.token, canaryId: minted.id, runId, artifact: '',
    sourceIp: '127.0.0.1', method: 'POST', path: `/c/${minted.token}`, receivedAt: Date.now(),
  })
  const result = differential({
    verdict: 'signal',
    anomalies: [{ type: 'canary_callback', variant: 'http', token: minted.token, canaryId: minted.id }],
  })
  tracker.finalize(result)
  assert.equal(result.details.promoted, true)
  assert.equal(result.details.oobAttempts, undefined, 'a promoted callback is not a pending attempt')
})

// ============================================================================
// 5. Engine path — the carrying request names its canary; a pending attempt is
//    published in the report instead of vanishing
// ============================================================================

function engineGrant(): Grant {
  return {
    tier: 3,
    allowLocalLab: true,
    canRead: () => true,
    audit: () => {},
    scopePolicy: { mode: 'ephemeral_lab', targetOrigins: [ORIGIN], routeDenylist: [], runId },
  } as unknown as Grant
}

function acceptedExchange(req: BrokerHttpRequest): BrokerExchangeResult {
  return {
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    finalPathAndQuery: req.pathAndQuery,
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    personaHandle: null,
    status: 202,
    mediaType: 'application/json',
    reqHeaders: req.headers ?? {},
    respHeaders: { 'content-type': 'application/json' },
    setCookies: [],
    bodyPreview: '{"id":"svc-1"}',
    body: '{"id":"svc-1"}',
    bodySha256: '0'.repeat(64),
    bodyBytes: 14,
    bodyTruncated: false,
    durationMs: 2,
    secretMatches: [],
  } as unknown as BrokerExchangeResult
}

test('realism oob: the engine names the injected canary on the carrying request and reports the pending attempt', async () => {
  const broker = localBroker()
  const sent: BrokerHttpRequest[] = []
  const requestBroker = {
    executeHttp: async (req: BrokerHttpRequest) => {
      sent.push(req)
      return acceptedExchange(req)
    },
  } as unknown as RequestBroker

  const report = await runDeterministicEngine({
    runId,
    assignmentId,
    signal: new AbortController().signal,
    endpoints: [{
      id: 'openapi:POST:/svc/jobs/verify',
      origin: ORIGIN,
      method: 'POST',
      pathTemplate: '/svc/jobs/verify',
      params: [{ name: 'url', location: 'json', observedShape: 'url' }],
      riskScore: 80,
      source: 'openapi',
    }],
    personas: [],
    broker: requestBroker,
    grant: engineGrant(),
    backend: {} as never,
    canaryBroker: broker,
    tier: 3,
    maxRequests: 120,
    maxDurationMs: 20_000,
    classes: new Set(['ssrf']),
    environmentMode: 'ephemeral_lab',
    onConfirmed: () => null,
  })

  const pending = broker.pending(runId)
  assert.ok(pending.length >= 1, 'the engine minted a canary and registered a durable subscription')
  const tokens = new Set(pending.map(sub => sub.token))
  const carrying = sent.filter(req => typeof req.body === 'string'
    && [...tokens].some(token => (req.body as string).includes(token)))
  assert.ok(carrying.length >= 1, 'the canary-carrying write is recorded')
  for (const req of carrying) {
    const token = [...tokens].find(candidate => (req.body as string).includes(candidate))!
    assert.equal(req.traceId, token,
      'the carrying exchange records the canary token as its broker correlation id')
    assert.equal(req.pathAndQuery, '/svc/jobs/verify')
  }

  // A self-trigger write is the trigger: control + probe sends only, no redundant sibling calls.
  const lifecycleSends = sent.filter(req => req.pathAndQuery === '/svc/jobs/verify'
    && typeof req.body === 'string'
    && (req.body.includes('guardian-control.invalid') || [...tokens].some(token => req.body!.includes(token))))
  assert.equal(lifecycleSends.length, 2 * carrying.length,
    'one control and one canary send per self-triggering hypothesis, no redundant sibling call')
  assert.ok(!sent.some(req => req.pathAndQuery.includes('{{id}}')))

  assert.ok(report.notes.some(note => /canary attempt\(s\) injected, durable OOB subscription pending/.test(note)),
    `the pending attempt is published in the report: ${report.notes.join(' | ')}`)
})
