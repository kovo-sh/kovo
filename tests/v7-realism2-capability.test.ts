/**
 * Realism #2 remainder — blind SQLi under WAN jitter.
 *
 * The timing oracle must decide from the *separation between arms*, not from absolute latencies or
 * a single min/max comparison: a 50–300 ms edge-proxy jitter makes `min(probe) > max(baseline)`
 * false roughly half the time for a real sleep, and makes one slow probe sample enough to miss it.
 *
 * These tests pin the robust decision and the adaptive delay, plus one end-to-end probe run against
 * a fake jittered transport.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  adaptiveTimingDelayMs,
  assessTimingDifferential,
  diffSqlTimeDifferential,
  medianAbsoluteDeviation,
} from '../src/server/probes/injection.ts'
import type { BrokerExchangeResult, Grant } from '../src/server/broker.ts'
import type { DiffContext } from '../src/server/probes/context.ts'

/** Deterministic PRNG so jittered samples are reproducible. */
function lcg(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state / 0x1_0000_0000
  }
}

const jitter = (rand: () => number): number => 50 + Math.floor(rand() * 251) // 50..300

describe('realism2: timing spread', () => {
  test('median absolute deviation is robust to one outlier', () => {
    assert.equal(medianAbsoluteDeviation([100, 110, 120]), 10)
    assert.ok(medianAbsoluteDeviation([100, 110, 900]) <= 10)
  })
})

describe('realism2: adaptive delay', () => {
  test('stays at the requested delay on a clean link', () => {
    assert.equal(adaptiveTimingDelayMs([100, 102, 99, 101], 1500), 1500)
  })

  test('rises above a spread that exceeds the requested delay', () => {
    // 50–300 ms jitter is already clear of a 1.5 s sleep; a ~1.1 s spread is not, so the delay rises.
    assert.equal(adaptiveTimingDelayMs([50, 300, 80, 290], 1500), 1500)
    const delay = adaptiveTimingDelayMs([50, 1200, 80, 1100], 1500)
    assert.ok(delay > 1500, `expected a raised delay, got ${delay}`)
    assert.ok(delay >= 3 * 1150, 'delay must be several times the observed spread')
  })

  test('never exceeds the probe bound', () => {
    assert.equal(adaptiveTimingDelayMs([10, 4000], 3000), 5000)
    assert.equal(adaptiveTimingDelayMs([], 900), 1500)
  })
})

describe('realism2: jitter-tolerant timing decision', () => {
  const jitteredBaseline = [60, 280, 120, 300]

  test('confirms a real sleep despite 50–300 ms jitter', () => {
    const assessment = assessTimingDifferential({
      baselineDurations: jitteredBaseline,
      probeDurations: [1580, 1720, 1610, 1690],
      statuses: [200, 200, 200, 200, 200, 200, 200, 200],
      delayMs: 1500,
    })
    assert.equal(assessment.passed, true, assessment.reason)
  })

  test('tolerates one slow control outlier that breaks min > max', () => {
    const assessment = assessTimingDifferential({
      baselineDurations: [80, 120, 295, 90],
      probeDurations: [1600, 1610, 1595, 1620],
      statuses: [200, 200, 200, 200, 200, 200, 200, 200],
      delayMs: 1500,
    })
    assert.equal(assessment.passed, true, assessment.reason)
  })

  test('rejects a uniformly slow server (no separation)', () => {
    const assessment = assessTimingDifferential({
      baselineDurations: [1200, 1250, 1180],
      probeDurations: [1300, 1280, 1310],
      statuses: [200, 200, 200, 200, 200, 200],
      delayMs: 1500,
    })
    assert.equal(assessment.passed, false, assessment.reason)
  })

  test('rejects a jitter-only difference', () => {
    const assessment = assessTimingDifferential({
      baselineDurations: [60, 300, 120, 280],
      probeDurations: [280, 310, 90, 300],
      statuses: [200, 200, 200, 200, 200, 200, 200, 200],
      delayMs: 1500,
    })
    assert.equal(assessment.passed, false, assessment.reason)
  })

  test('rejects a 5xx arm and too few rounds', () => {
    const withError = assessTimingDifferential({
      baselineDurations: [100, 120, 110],
      probeDurations: [1600, 1650, 1620],
      statuses: [200, 500, 200, 200, 200, 200],
      delayMs: 1500,
    })
    assert.equal(withError.passed, false)
    const tooFew = assessTimingDifferential({
      baselineDurations: [100, 110],
      probeDurations: [1600, 1620],
      statuses: [200, 200, 200, 200],
      delayMs: 1500,
    })
    assert.equal(tooFew.passed, false)
    assert.match(tooFew.reason, /too few/i)
  })
})

// ---------------------------------------------------------------------------
// End-to-end probe against a fake jittered transport
// ---------------------------------------------------------------------------

interface FakeTransport {
  /** True when the injected value reaches a real sleep. */
  sleep: boolean
  /** Adds the sleep duration to requests whose injected value carries a delay expression. */
  delayMs: number
}

function fakeProbeContext(transport: FakeTransport, seed = 7): DiffContext {
  const rand = lcg(seed)
  const sleepMarker = /SLEEP|pg_sleep|WAITFOR|RANDOMBLOB/i
  const ctx = {
    req: {
      probeClass: 'sqli_time_diff' as const,
      origin: 'http://127.0.0.1:4100',
      pathAndQuery: '/v1/catalog/search?q=widgets',
      method: 'GET' as const,
      param: 'q',
      paramLocation: 'query' as const,
      baselineValue: 'widgets',
    },
    origin: 'http://127.0.0.1:4100',
    runner: {} as never,
    notes: [],
    anomalies: [] as Array<Record<string, unknown>>,
    send: async (request: { pathAndQuery: string; jsonBody?: unknown; body?: string }): Promise<BrokerExchangeResult> => {
      const encoded = `${request.pathAndQuery} ${typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? {})}`
      const decoded = decodeURIComponent(encoded)
      const injected = sleepMarker.test(decoded)
      const durationMs = (transport.sleep && injected ? transport.delayMs : 0) + jitter(rand)
      return {
        status: 200,
        durationMs,
        body: '{"results":[],"tookMs":12}',
        headers: {},
      } as unknown as BrokerExchangeResult
    },
  }
  return ctx as unknown as DiffContext
}

const localLabGrant = { allowLocalLab: true, tier: 3 } as unknown as Grant

describe('realism2: probe end-to-end', () => {
  test('a real sleep confirms through a 50–300 ms jittered transport', async () => {
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    const ctx = fakeProbeContext({ sleep: true, delayMs: 1500 })
    const outcome = await diffSqlTimeDifferential(ctx, localLabGrant)
    assert.equal(outcome.verdict, 'signal', outcome.summary)
    const details = outcome.details as { delayMs?: number; baselineMedianMs?: number; probeMedianMs?: number }
    assert.ok((details.probeMedianMs ?? 0) > (details.baselineMedianMs ?? 0) + 700, 'probe median must clear the jitter envelope')
  })

  test('identical responses with no delay never confirm', async () => {
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    const ctx = fakeProbeContext({ sleep: false, delayMs: 0 })
    const outcome = await diffSqlTimeDifferential(ctx, localLabGrant)
    assert.notEqual(outcome.verdict, 'signal', outcome.summary)
  })
})
