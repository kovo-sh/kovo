/**
 * v6 Layer-2 floor OOB wiring (realism #2).
 *
 * Defensive QA framing: the async WAN fixture returns `202` before its background worker fetches
 * an attacker URL 15–30 s later. A floor canary probe that only short-polls therefore proves
 * nothing about the sink. These tests pin the fix: every canary a floor SSRF/XXE probe mints is
 * registered as a durable `pending_oob` subscription before the probe can send it, an immediate
 * miss leaves the subscription pending for the run-level drain, a late callback is promoted once,
 * and the subscription/canary ids plus the callback stage travel with the finding evidence.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, test } from 'node:test'

import type { Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { DifferentialProbeClass, DifferentialResult } from '../src/server/surface-engine.ts'
import {
  floorCanaryClass,
  floorOobImmediateMs,
  floorOobWindowMs,
  runDeterministicEngine,
  trackFloorCanarySubscriptions,
} from '../src/server/deterministic-engine.ts'
import type { EngineHypothesis } from '../src/server/deterministic-engine.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'

const origin = 'https://target.example.com'
const runId = 'run-floor-oob'
const assignmentId = 'asg-floor-oob'

class FakeClock {
  value = 1_700_000_000_000
  now = (): number => this.value
  advance(ms: number): void {
    this.value += ms
  }
}

const brokers: CanaryBroker[] = []
const tempDirs: string[] = []

function fakeClockBroker(): { clock: FakeClock; broker: CanaryBroker } {
  const clock = new FakeClock()
  const dir = mkdtempSync(join(tmpdir(), 'guardian-floor-oob-'))
  tempDirs.push(dir)
  const broker = new CanaryBroker({ now: clock.now, oobDirectory: dir })
  brokers.push(broker)
  return { clock, broker }
}

afterEach(() => {
  for (const broker of brokers.splice(0)) {
    try { broker.closeOob() } catch { /* already closed */ }
  }
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function differential(over: Partial<DifferentialResult> = {}): DifferentialResult {
  return {
    probeClass: 'xxe_canary',
    origin,
    pathAndQuery: '/v1/import/preview',
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

function xxeHypothesis(): EngineHypothesis {
  return {
    key: 'xxe_canary|preview',
    endpoint: { id: 'openapi:POST:/v1/import/preview', origin, method: 'POST', pathTemplate: '/v1/import/preview', params: [] },
    probeClass: 'xxe_canary',
    intent: 'xxe',
    method: 'POST',
    pathAndQuery: '/v1/import/preview',
    risk: 80,
  }
}

/** Record the fixture's late callback for a canary token, as the OOB listener would. */
function recordCallback(broker: CanaryBroker, clock: FakeClock, token: string, canaryId: string) {
  return broker.recordCallback({
    token,
    canaryId,
    runId,
    artifact: '',
    sourceIp: '127.0.0.1',
    method: 'POST',
    path: `/c/${token}`,
    receivedAt: clock.now(),
  })
}

// ============================================================================
// Registration
// ============================================================================

test('floor canary registers a durable pending_oob subscription before the probe can send it', () => {
  const { broker, clock: _clock } = fakeClockBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })

  const minted = tracker.broker.mintCanary(runId, 'ssrf:url:http', origin)
  const pending = broker.pending(runId)
  assert.equal(pending.length, 1, 'the mint itself registered exactly one durable subscription')
  assert.equal(pending[0].token, minted.token)
  assert.equal(pending[0].canaryId, minted.id, 'the subscription binds the canary id the callback carries')
  assert.equal(pending[0].status, 'pending')
  assert.equal(pending[0].immediateMs, floorOobImmediateMs)
  assert.equal(pending[0].immediateMs, 3_000, 'the immediate window matches the probe short-poll')
  assert.equal(pending[0].windowMs, floorOobWindowMs)
  assert.equal(pending[0].artifact, '', 'an empty artifact keeps real callbacks ingestible')

  const records = tracker.subscriptions()
  assert.equal(records.length, 1)
  assert.equal(records[0].subscriptionId, pending[0].id)
  assert.equal(records[0].stage, 'pending')
  assert.equal(records[0].promoted, false)

  // A repeat registration for the same (runId, canary token) reuses the pending row.
  const again = broker.subscribe({ runId, assignmentId, canaryId: minted.id, token: minted.token, artifact: '' })
  assert.equal(again.id, pending[0].id)
  assert.equal(broker.pending(runId).length, 1, 'never two subscriptions for one (runId, token)')
})

test('only SSRF/XXE canary classes get the durable-OOB wrapper', () => {
  assert.equal(floorCanaryClass('ssrf_canary'), true)
  assert.equal(floorCanaryClass('xxe_canary'), true)
  for (const probeClass of ['sqli_boolean', 'ssti_math', 'command_injection', 'xss_context', 'authz_matrix'] as const) {
    assert.equal(floorCanaryClass(probeClass), false, `${probeClass} never needs an OOB subscription`)
  }
})

// ============================================================================
// Immediate miss, then late promotion (run-level drain)
// ============================================================================

test('immediate miss stays pending and a late callback is promoted exactly once', () => {
  const { broker, clock } = fakeClockBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })
  const minted = tracker.broker.mintCanary(runId, 'ssrf:url:http', origin)

  const missed = differential({ probeClass: 'ssrf_canary' })
  tracker.finalize(missed)
  assert.equal(missed.verdict, 'no_signal')
  assert.equal(missed.details.canaryProbeStage, 'pending', 'a miss leaves the durable row promotable')
  assert.equal(missed.details.promoted, false)
  assert.equal(broker.pending(runId).length, 1)
  assert.equal(tracker.subscriptions()[0].stage, 'pending')

  // The fixture's background worker fetches the canary 15 s after the 202 response.
  clock.advance(15_000)
  const first = recordCallback(broker, clock, minted.token, minted.id)
  const duplicate = recordCallback(broker, clock, minted.token, minted.id)
  assert.equal(first.accepted, true)
  assert.equal(duplicate.accepted, true)
  assert.equal(duplicate.duplicate, true, 're-delivery of the same callback is idempotent')
  assert.equal(broker.oob.check({ token: minted.token }).callbacks.length, 1)

  // The run-level drain sweeps pending rows and promotes the late callback.
  const promotions = broker.promoteLate({ runId, now: clock.now() })
  assert.equal(promotions.length, 1)
  assert.equal(promotions[0].stage, 'late')
  assert.equal(promotions[0].subscription.id, tracker.subscriptions()[0].subscriptionId)
  assert.equal(promotions[0].latencyMs, 15_000)

  // A second sweep (drain poll) never double-counts the same callback.
  assert.equal(broker.promoteLate({ runId, now: clock.now() }).length, 0)
  assert.equal(broker.pending(runId).length, 0)
  assert.equal(broker.oob.check({ token: minted.token }).callbacks.length, 1)
})

// ============================================================================
// Observed callback (immediate / late) with evidence correlated into the spec
// ============================================================================

test('a callback seen inside the probe window is promoted immediately', () => {
  const { broker, clock } = fakeClockBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })
  const minted = tracker.broker.mintCanary(runId, 'xxe:general_entity', origin)

  clock.advance(1_000)
  recordCallback(broker, clock, minted.token, minted.id)
  const hit = differential({
    verdict: 'signal',
    anomalies: [{ type: 'xxe_canary_callback', variant: 'general_entity', token: minted.token }],
  })
  tracker.finalize(hit)

  const subscriptionId = tracker.subscriptions()[0].subscriptionId
  assert.equal(tracker.subscriptions()[0].stage, 'immediate')
  assert.equal(tracker.subscriptions()[0].promoted, true)
  assert.equal(hit.details.canaryProbeStage, 'immediate')
  assert.equal(hit.details.promoted, true)
  assert.equal(hit.details.oobSubscriptionId, subscriptionId)
  assert.equal(hit.details.oobCanaryId, minted.id)
  assert.equal(hit.anomalies[0].oobSubscriptionId, subscriptionId)
  assert.equal(hit.anomalies[0].canaryProbeStage, 'immediate')
  assert.equal(hit.anomalies[0].promoted, true)
})

test('a callback after the immediate window is staged late and carried into the finding evidence', () => {
  const { broker, clock } = fakeClockBroker()
  const tracker = trackFloorCanarySubscriptions(broker, { runId, assignmentId })
  const minted = tracker.broker.mintCanary(runId, 'xxe:general_entity', origin)

  // Arrives 15 s after the mint but before the probe's result is finalized.
  clock.advance(15_000)
  recordCallback(broker, clock, minted.token, minted.id)
  const hit = differential({
    verdict: 'signal',
    anomalies: [{ type: 'xxe_canary_callback', variant: 'general_entity', token: minted.token }],
  })
  tracker.finalize(hit)

  const subscriptionId = tracker.subscriptions()[0].subscriptionId
  assert.ok(subscriptionId)
  assert.equal(hit.details.canaryProbeStage, 'late')
  assert.equal(hit.anomalies[0].canaryProbeStage, 'late')

  const specs = synthesizeEngineSpecs(xxeHypothesis(), hit)
  assert.equal(specs.length, 1)
  const parsed = declarativeReplaySpecSchema.safeParse(specs[0].spec)
  assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.issues[0]?.message)

  const evidence = specs[0].evidence
  assert.ok(evidence, 'the synthesized spec carries the OOB correlation')
  assert.equal(evidence!.canaryProbeStage, 'late')
  assert.equal(evidence!.promoted, true)
  assert.equal(evidence!.oobSubscriptionId, subscriptionId)
  assert.equal(evidence!.oobCanaryId, minted.id)
  const subscriptions = evidence!.subscriptions as Array<Record<string, unknown>>
  assert.equal(subscriptions.length, 1)
  assert.equal(subscriptions[0].stage, 'late')
  assert.equal(subscriptions[0].token, minted.token)

  // The persisted replay spec's probe step names the stage and ids, so finalize can correlate.
  const steps = specs[0].spec.steps as Array<{ id: string; description: string }>
  const probeStep = steps.find(step => step.id === 'p1')
  assert.ok(probeStep)
  assert.match(probeStep!.description, /\[oob stage=late promoted/)
  assert.ok(probeStep!.description.includes(String(subscriptionId)))
  assert.ok(probeStep!.description.includes(minted.id))
})

// ============================================================================
// Non-OOB probes are unchanged
// ============================================================================

test('a non-canary probe never registers a pending_oob row and keeps its evidence shape', () => {
  const { broker, clock } = fakeClockBroker()
  const hyp: EngineHypothesis = {
    key: 'sqli_boolean|search',
    endpoint: { id: 'openapi:GET:/api/search', origin, method: 'GET', pathTemplate: '/api/search', params: [] },
    probeClass: 'sqli_boolean',
    intent: 'sqli',
    method: 'GET',
    pathAndQuery: '/api/search',
    param: { name: 'q', location: 'query' },
    location: 'query',
    baselineValue: 'guardian',
    risk: 80,
  }
  const result = differential({
    probeClass: 'sqli_boolean',
    pathAndQuery: '/api/search',
    verdict: 'signal',
    anomalies: [{ type: 'boolean_differential', style: 'single_quote' }],
  })
  assert.equal(floorCanaryClass(hyp.probeClass), false)
  // A canary minted by an unrelated class is not a floor OOB subscription.
  broker.mintCanary(runId, 'unrelated', origin)
  assert.equal(broker.pending(runId).length, 0)

  const specs = synthesizeEngineSpecs(hyp, result)
  assert.ok(specs.length >= 1)
  assert.equal(specs[0].evidence, undefined, 'no OOB evidence is fabricated for a non-canary spec')
  assert.equal(result.details.oob, undefined)
  assert.equal(result.details.oobSubscriptionId, undefined)
})

// ============================================================================
// Engine wiring: the probe receives the durable-OOB broker facade
// ============================================================================

function engineGrant(): Grant {
  return {
    tier: 3,
    canRead: () => true,
    audit: () => {},
    scopePolicy: {
      mode: 'ephemeral_lab',
      targetOrigins: [origin],
      routeDenylist: [],
      runId,
    },
  } as unknown as Grant
}

test('the engine hands SSRF probes a broker facade that has already registered the subscription', async () => {
  const { broker } = fakeClockBroker()
  const seen: Array<{ probeClass: DifferentialProbeClass; pendingBefore: number; pendingAfter: number; token: string }> = []
  const events: Array<{ kind: string; data?: Record<string, unknown> }> = []

  const report = await runDeterministicEngine({
    runId,
    assignmentId,
    signal: new AbortController().signal,
    endpoints: [{
      id: 'openapi:POST:/v1/integrations/webhook-test',
      origin,
      method: 'POST',
      pathTemplate: '/v1/integrations/webhook-test',
      params: [{ name: 'url', location: 'json', observedShape: 'url' }],
      riskScore: 80,
      source: 'openapi',
    }],
    personas: [],
    broker: {} as never,
    grant: engineGrant(),
    backend: {} as never,
    canaryBroker: broker,
    tier: 3,
    maxRequests: 40,
    maxDurationMs: 10_000,
    probe: async (req, _broker, _grant, probeCanaryBroker) => {
      // The real probe layer mints its canary URL, then sends it. Mirror that order here.
      const pendingBefore = broker.pending(runId).length
      const minted = probeCanaryBroker!.mintCanary(runId, `probe:${req.param ?? 'url'}:http`, origin)
      seen.push({
        probeClass: req.probeClass,
        pendingBefore,
        pendingAfter: broker.pending(runId).length,
        token: minted.token,
      })
      return differential({
        probeClass: req.probeClass,
        pathAndQuery: req.pathAndQuery,
        summary: 'No out-of-band callback was observed within the wait window.',
      })
    },
    log: (kind, _message, data) => { events.push({ kind, data }) },
    onConfirmed: () => null,
  })

  assert.equal(report.signals, 0)
  const canaryProbes = seen.filter(entry => floorCanaryClass(entry.probeClass))
  const otherProbes = seen.filter(entry => !floorCanaryClass(entry.probeClass))
  assert.ok(canaryProbes.length >= 1, 'at least one SSRF/XXE hypothesis reached the probe layer')
  assert.ok(canaryProbes.every(entry => entry.pendingAfter === entry.pendingBefore + 1),
    'the durable subscription exists before the probe sends its canary URL')
  assert.ok(otherProbes.length >= 1, 'the same run also exercises a non-canary probe')
  assert.ok(otherProbes.every(entry => entry.pendingAfter === entry.pendingBefore),
    'a non-canary probe never registers a pending_oob row')

  const pending = broker.pending(runId)
  assert.equal(pending.length, canaryProbes.length, 'one durable subscription per canary probe, no duplicates')
  assert.deepEqual(
    pending.map(sub => sub.token).sort(),
    canaryProbes.map(entry => entry.token).sort(),
  )
  assert.ok(pending.every(sub => sub.immediateMs === floorOobImmediateMs))

  const subscribed = events.filter(event => event.kind === 'deterministic_engine.oob_subscribed')
  assert.equal(subscribed.length, canaryProbes.length)
  assert.deepEqual(
    subscribed.map(event => event.data?.subscriptionId).sort(),
    pending.map(sub => sub.id).sort(),
  )
})
