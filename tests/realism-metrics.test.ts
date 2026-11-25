/**
 * Realism gate wiring-vs-capability contract.
 *
 * These tests are synthetic: they never boot a fixture or run `Execution`. They pin the gate
 * semantics that a capability miss must not be confused with a wiring failure, that wiring
 * failures cannot be papered over, and that a missing measurement fails closed as `unmeasured`.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  buildWiringReport,
  emptyMetrics,
  emptyWiringMetrics,
  evaluateGate,
  evaluateWiring,
  gatePassed,
  percentile,
  wiringPassed,
  wiringStatus,
} from '../scripts/benchmark-realism.ts'
import type { RealismMetrics, WiringMetricValues } from '../scripts/benchmark-realism.ts'

function values(overrides: Partial<WiringMetricValues>): WiringMetricValues {
  return { ...emptyWiringMetrics(), ...overrides }
}

function statusFor(fixture: string, overrides: Partial<WiringMetricValues>) {
  return wiringStatus(evaluateWiring(fixture, values(overrides)))
}

function criterionStatus(fixture: string, overrides: Partial<WiringMetricValues>, id: string) {
  return evaluateWiring(fixture, values(overrides)).find(criterion => criterion.id === id)?.status
}

function metricsWithWiring(fixture: string, overrides: Partial<WiringMetricValues>): RealismMetrics {
  const metrics = emptyMetrics(fixture)
  metrics.wiring = buildWiringReport(fixture, values(overrides))
  metrics.criteria = evaluateGate(fixture, metrics)
  return metrics
}

describe('wiring — WAN async OOB (#2)', () => {
  test('PASS when a durable subscription registered and the drain window was honoured', () => {
    const report = evaluateWiring('wan-oob', values({
      pendingOobRegistered: 2,
      lateCallbacksMatched: 1,
      oobDrainWaitedMs: 15_000,
      latePromotions: 1,
    }))
    assert.equal(wiringStatus(report), 'pass')
    assert.equal(report.find(criterion => criterion.id === 'oob-pending-registered')?.status, 'pass')
    assert.equal(report.find(criterion => criterion.id === 'oob-drain-window')?.status, 'pass')
  })

  test('PASS when there is nothing late to drain (no callback expected)', () => {
    assert.equal(statusFor('wan-oob', {
      pendingOobRegistered: 1,
      lateCallbacksMatched: 0,
      oobDrainWaitedMs: null,
    }), 'pass')
  })

  test('FAIL when no pending_oob subscription was registered', () => {
    assert.equal(criterionStatus('wan-oob', {
      pendingOobRegistered: 0,
      lateCallbacksMatched: 0,
      oobDrainWaitedMs: 0,
    }, 'oob-pending-registered'), 'fail')
    assert.equal(statusFor('wan-oob', { pendingOobRegistered: 0 }), 'fail')
  })

  test('FAIL when a late callback matched but the drain window was short', () => {
    assert.equal(criterionStatus('wan-oob', {
      pendingOobRegistered: 1,
      lateCallbacksMatched: 1,
      oobDrainWaitedMs: 14_999,
    }, 'oob-drain-window'), 'fail')
  })

  test('FAIL closed when a late callback matched but the drain was not measured', () => {
    assert.equal(criterionStatus('wan-oob', {
      pendingOobRegistered: 1,
      lateCallbacksMatched: 1,
      oobDrainWaitedMs: null,
    }, 'oob-drain-window'), 'fail')
  })

  test('UNMEASURED when registration itself was not observed', () => {
    assert.equal(statusFor('wan-oob', {
      pendingOobRegistered: null,
      lateCallbacksMatched: 0,
      oobDrainWaitedMs: null,
    }), 'unmeasured')
  })
})

describe('wiring — staging safety (#3)', () => {
  test('PASS with zero approval blocks, denied mutations and leaked entities', () => {
    assert.equal(statusFor('staging-concurrency', {
      approvalBlocks: 0,
      brokerDeniedMutations: 0,
      leakedEntities: 0,
    }), 'pass')
  })

  test('FAIL when any blocking approval request exists', () => {
    assert.equal(criterionStatus('staging-concurrency', {
      approvalBlocks: 1,
      brokerDeniedMutations: 0,
      leakedEntities: 0,
    }, 'approval-blocks-zero'), 'fail')
  })

  test('FAIL when a mutating request was broker-denied', () => {
    assert.equal(criterionStatus('staging-concurrency', {
      approvalBlocks: 0,
      brokerDeniedMutations: 1,
      leakedEntities: 0,
    }, 'broker-denied-mutations-zero'), 'fail')
  })

  test('FAIL when cleanup leaves kovo-qa- entities', () => {
    assert.equal(criterionStatus('staging-concurrency', {
      approvalBlocks: 0,
      brokerDeniedMutations: 0,
      leakedEntities: 2,
    }, 'leaked-entities-zero'), 'fail')
  })

  test('UNMEASURED when cleanup was not observed (fail closed)', () => {
    assert.equal(statusFor('staging-concurrency', {
      approvalBlocks: 0,
      brokerDeniedMutations: 0,
      leakedEntities: null,
    }), 'unmeasured')
  })

  test('race capability requires a real HTTP/2 single-packet burst', () => {
    const base = emptyMetrics('staging-concurrency')
    base.staging = {
      writeBolaConfirmed: false,
      raceConfirmed: true,
      checkoutConfirmed: false,
      leakedEntities: 0,
      taggedOrphansBeforeCleanup: [],
      cleanup: { removed: 0, restored: 0 },
    }
    base.wiring = buildWiringReport('staging-concurrency', values({
      approvalBlocks: 0,
      brokerDeniedMutations: 0,
      leakedEntities: 0,
      h2SinglePacketBursts: 0,
      http1FallbackBursts: 1,
      raceBursts: 1,
    }))
    const withoutH2 = evaluateGate('staging-concurrency', base).find(criterion => criterion.id === 'h2-race')
    assert.equal(withoutH2?.met, false, 'race confirmation without an HTTP/2 burst is not the gate result')

    base.wiring = buildWiringReport('staging-concurrency', values({
      approvalBlocks: 0,
      brokerDeniedMutations: 0,
      leakedEntities: 0,
      h2SinglePacketBursts: 1,
      http1FallbackBursts: 0,
      raceBursts: 1,
    }))
    const withH2 = evaluateGate('staging-concurrency', base).find(criterion => criterion.id === 'h2-race')
    assert.equal(withH2?.met, true)
  })
})

describe('wiring — monorepo scale (#4)', () => {
  const passing: Partial<WiringMetricValues> = {
    storedEndpoints: 2_500,
    declaredEndpoints: 2_565,
    storeWriteP99Ms: 49.9,
    siblingDerivationSuppressed: true,
    tierA4HopSinks: 2,
  }

  test('PASS at the documented thresholds', () => {
    assert.equal(statusFor('monorepo-whitebox', passing), 'pass')
  })

  test('FAIL when the store holds fewer than 2,500 endpoints', () => {
    assert.equal(criterionStatus('monorepo-whitebox', { ...passing, storedEndpoints: 2_499 }, 'store-scale-2500'), 'fail')
  })

  test('FAIL when endpoint write p99 is 50 ms or slower', () => {
    assert.equal(criterionStatus('monorepo-whitebox', { ...passing, storeWriteP99Ms: 50 }, 'store-write-p99-50'), 'fail')
  })

  test('FAIL when sibling derivation was not suppressed', () => {
    assert.equal(criterionStatus('monorepo-whitebox', { ...passing, siblingDerivationSuppressed: false }, 'sibling-derivation-suppressed'), 'fail')
  })

  test('FAIL when fewer than two 4-hop sinks were ranked Tier A', () => {
    assert.equal(criterionStatus('monorepo-whitebox', { ...passing, tierA4HopSinks: 1 }, 'tier-a-4hop-sinks'), 'fail')
  })

  test('UNMEASURED for every missing #4 measurement (fail closed)', () => {
    for (const id of ['store-scale-2500', 'store-write-p99-50', 'sibling-derivation-suppressed', 'tier-a-4hop-sinks']) {
      assert.equal(criterionStatus('monorepo-whitebox', {}, id), 'unmeasured', id)
    }
    assert.equal(statusFor('monorepo-whitebox', {}), 'unmeasured')
  })
})

describe('wiring does not leak into capability', () => {
  test('fixtures without wiring criteria report PASS', () => {
    assert.equal(statusFor('enterprise-spa', {}), 'pass')
  })

  test('a wiring failure leaves capability verdicts untouched', () => {
    const metrics = metricsWithWiring('staging-concurrency', {
      approvalBlocks: 1,
      brokerDeniedMutations: 0,
      leakedEntities: 0,
    })
    // Synthetic capability criteria are all unmet here; the point is that the two verdicts are
    // computed independently and wiring is never converted into a synthetic capability pass.
    assert.equal(wiringPassed(metrics), false)
    assert.equal(gatePassed(metrics), false)
    assert.ok(metrics.criteria.every(criterion => criterion.id !== 'wiring'))
  })

  test('missing wiring measurements fail closed even when capability criteria are met', () => {
    const metrics = emptyMetrics('wan-oob')
    metrics.oob = {
      blindSqliConfirmed: true,
      asyncSsrfConfirmed: true,
      asyncXxeConfirmed: true,
      webhookForgeryConfirmed: false,
      falseNegativeRate: 0,
      fixtureCallbacks: {},
    }
    metrics.grade = {
      submitted: 3,
      truePositives: 3,
      falsePositives: 0,
      precision: 1,
      recall: 1,
      chains: [{ id: 'wan-oob-exfil', total: 3, covered: 3, complete: true }],
    }
    metrics.wiring = buildWiringReport('wan-oob', emptyWiringMetrics())
    metrics.criteria = evaluateGate('wan-oob', metrics)
    assert.equal(gatePassed(metrics), true, 'capability criteria are independently met')
    assert.equal(wiringPassed(metrics), false, 'unmeasured wiring still fails closed')
  })
})

describe('percentile helper', () => {
  test('uses nearest-rank and rejects tiny samples', () => {
    assert.equal(percentile([], 0.99), null)
    assert.equal(percentile(Array.from({ length: 19 }, () => 1), 0.99), null)
    const samples = Array.from({ length: 100 }, (_, index) => index + 1)
    assert.equal(percentile(samples, 0.99), 99)
    assert.equal(percentile(samples, 0.5), 50)
  })
})
