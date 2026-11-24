/**
 * v6 Realism gate honesty contract.
 *
 * Splits Realism #2 into two orthogonal gates so a capability miss (blind SQLi, an incomplete
 * exfil chain) can never be reported as an async-OOB wiring failure:
 *
 *   - `oob_wiring_fnr`         denominator = async-OOB canaries that actually fired
 *   - `fixture_capability_recall` denominator = every planted #2 target
 *
 * Also pins the Realism #4 per-slice funnel (dispatch → exact route hit → verify → rejection
 * code histogram), which distinguishes brief truncation from oracle rejection without parsing
 * logs.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  buildWiringReport,
  computeOobGates,
  computeSliceFunnels,
  emptyMetrics,
  emptyWiringMetrics,
  evaluateGate,
  evaluateWiring,
  gatePassed,
  renderSliceFunnelMarkdown,
  verificationRejectionCode,
  wiringPassed,
  wiringStatus,
} from '../scripts/benchmark-realism.ts'
import type {
  OobGateResult,
  RealismMetrics,
  SliceFunnelArtifacts,
  WiringMetricValues,
} from '../scripts/benchmark-realism.ts'

function gates(overrides?: {
  ssrf?: { minted: number; fired: number }
  xxe?: { minted: number; fired: number }
  ssrfConfirmed?: boolean
  xxeConfirmed?: boolean
  blindSqli?: boolean
  chainComplete?: boolean
  fixtureCallbacks?: Record<string, boolean>
  canaries?: null
}): OobGateResult {
  return computeOobGates({
    canaries: overrides?.canaries === null
      ? null
      : {
          ssrf: overrides?.ssrf ?? { minted: 8, fired: 1 },
          xxe: overrides?.xxe ?? { minted: 15, fired: 3 },
        },
    confirmed: {
      asyncSsrf: overrides?.ssrfConfirmed ?? true,
      asyncXxe: overrides?.xxeConfirmed ?? true,
      blindSqli: overrides?.blindSqli ?? false,
      chainComplete: overrides?.chainComplete ?? false,
    },
    ...(overrides?.fixtureCallbacks ? { fixtureCallbacks: overrides.fixtureCallbacks } : {}),
  })
}

function wanMetrics(result: OobGateResult, wiringOverrides: Partial<WiringMetricValues> = {}): RealismMetrics {
  const metrics = emptyMetrics('wan-oob')
  metrics.oob = {
    blindSqliConfirmed: result.capability.members.find(member => member.id === 'wan-blind-sqli')?.confirmed ?? false,
    asyncSsrfConfirmed: true,
    asyncXxeConfirmed: true,
    webhookForgeryConfirmed: false,
    falseNegativeRate: 1 / 3,
    fixtureCallbacks: {},
    wiringFnr: result.wiring,
    capability: result.capability,
    canaryEvidence: { ssrf: { minted: 8, fired: 1 }, xxe: { minted: 15, fired: 3 } },
  }
  metrics.grade = {
    submitted: 2,
    truePositives: 2,
    falsePositives: 0,
    precision: 1,
    recall: 0.5,
    chains: [{ id: 'wan-oob-exfil', total: 3, covered: 2, complete: result.capability.members.find(member => member.id === 'wan-oob-exfil')?.confirmed ?? false }],
  }
  metrics.wiring = buildWiringReport('wan-oob', {
    ...emptyWiringMetrics(),
    pendingOobRegistered: 2,
    lateCallbacksMatched: 1,
    oobDrainWaitedMs: 15_000,
    oobWiringFnr: result.wiring,
    ...wiringOverrides,
  })
  metrics.criteria = evaluateGate('wan-oob', metrics)
  return metrics
}

describe('oob_wiring_fnr denominators', () => {
  test('fired async canaries: 2/2 confirmed is 0% even with blind SQLi missed', () => {
    const result = gates()
    assert.equal(result.wiring.basis, 'fired_canaries')
    assert.equal(result.wiring.denominator, 2)
    assert.equal(result.wiring.missed, 0)
    assert.equal(result.wiring.rate, 0)
    assert.deepEqual(result.wiring.firedTargets, ['wan-ssrf-async', 'wan-xxe-async'])
    // Capability is a separate denominator: 2 confirmed of 4 planted.
    assert.equal(result.capability.confirmed, 2)
    assert.equal(result.capability.planted, 4)
    assert.equal(result.capability.recall, 0.5)
    assert.ok(!result.capability.members.find(member => member.id === 'wan-blind-sqli')?.confirmed)
  })

  test('a fired canary without confirmation is the only wiring miss', () => {
    const result = gates({ xxeConfirmed: false })
    assert.equal(result.wiring.basis, 'fired_canaries')
    assert.equal(result.wiring.denominator, 2)
    assert.equal(result.wiring.missed, 1)
    assert.equal(result.wiring.rate, 0.5)
    assert.deepEqual(result.wiring.missedTargets, ['wan-xxe-async'])
  })

  test('falls back to all minted async canaries when nothing fired', () => {
    const result = gates({
      ssrf: { minted: 4, fired: 0 },
      xxe: { minted: 0, fired: 0 },
      ssrfConfirmed: false,
      xxeConfirmed: false,
    })
    assert.equal(result.wiring.basis, 'all_minted_canaries')
    assert.equal(result.wiring.denominator, 1)
    assert.equal(result.wiring.rate, 1)
    assert.deepEqual(result.wiring.mintedTargets, ['wan-ssrf-async'])
  })

  test('no async canary evidence is unmeasured, never a synthetic pass', () => {
    const result = gates({
      canaries: null,
      ssrf: { minted: 0, fired: 0 },
      xxe: { minted: 0, fired: 0 },
      ssrfConfirmed: false,
      xxeConfirmed: false,
    })
    assert.equal(result.wiring.basis, 'none')
    assert.equal(result.wiring.rate, null)
    assert.equal(result.wiring.denominator, 0)
  })

  test('a confirmed async finding proves the callback fired even without canary rows', () => {
    const result = gates({
      canaries: null,
      ssrf: { minted: 0, fired: 0 },
      xxe: { minted: 0, fired: 0 },
    })
    assert.equal(result.wiring.basis, 'fired_canaries')
    assert.equal(result.wiring.rate, 0)
  })

  test('fixture collector callbacks count as fired evidence', () => {
    const result = gates({
      ssrf: { minted: 0, fired: 0 },
      xxe: { minted: 0, fired: 0 },
      ssrfConfirmed: false,
      xxeConfirmed: false,
      fixtureCallbacks: { ssrf: true, xxe: false },
    })
    assert.equal(result.wiring.basis, 'fired_canaries')
    assert.deepEqual(result.wiring.firedTargets, ['wan-ssrf-async'])
    assert.equal(result.wiring.rate, 1)
  })
})

describe('split gate pass/fail matrix', () => {
  test('2/2 async OOB confirmations + blind-SQLi miss: wiring PASS, capability recall is the limiter', () => {
    const metrics = wanMetrics(gates())
    const wiring = evaluateWiring('wan-oob', metrics.wiring.metrics)
    assert.equal(wiringStatus(wiring), 'pass')
    assert.equal(wiringPassed(metrics), true)

    const fnr = wiring.find(criterion => criterion.id === 'oob_wiring_fnr')
    assert.equal(fnr?.status, 'pass')
    assert.match(fnr?.observed ?? '', /0\.0% \(0\/2/)

    assert.equal(gatePassed(metrics), false)
    const required = metrics.criteria.filter(criterion => criterion.required)
    assert.deepEqual(required.map(criterion => criterion.id), ['fixture_capability_recall'])
    assert.equal(required[0]?.met, false)
    assert.match(required[0]?.observed ?? '', /2\/4 \(50\.0%\)/)
    assert.match(required[0]?.observed ?? '', /Blind SQLi/)
  })

  test('legacy blended FNR stays visible but is informational only', () => {
    const metrics = wanMetrics(gates())
    const legacy = metrics.criteria.find(criterion => criterion.id === 'legacy-blended-async-fnr')
    assert.ok(legacy)
    assert.equal(legacy.required, false)
    assert.equal(legacy.met, false, '33.3% blended number is still reported')
    assert.ok(!metrics.criteria.some(criterion => criterion.id === 'async-false-negative-rate'))
  })

  test('oob_wiring_fnr is a wiring criterion, never a capability criterion', () => {
    const metrics = wanMetrics(gates())
    assert.ok(!metrics.criteria.some(criterion => criterion.id === 'oob_wiring_fnr'))
    assert.ok(metrics.wiring.criteria.some(criterion => criterion.id === 'oob_wiring_fnr'))
  })

  test('capability recall at 75% passes (3 of 4 planted targets)', () => {
    const metrics = wanMetrics(gates({ blindSqli: true }))
    assert.equal(gatePassed(metrics), true)
    const criterion = metrics.criteria.find(entry => entry.id === 'fixture_capability_recall')
    assert.equal(criterion?.met, true)
    assert.match(criterion?.observed ?? '', /3\/4 \(75\.0%\)/)
  })

  test('a wiring miss fails wiring but leaves capability recall untouched', () => {
    const metrics = wanMetrics(gates({ xxeConfirmed: false, blindSqli: true, chainComplete: true }))
    assert.equal(wiringPassed(metrics), false)
    const fnr = metrics.wiring.criteria.find(criterion => criterion.id === 'oob_wiring_fnr')
    assert.equal(fnr?.status, 'fail')
    assert.match(fnr?.observed ?? '', /50\.0% \(1\/2/)
    assert.equal(gatePassed(metrics), true, 'capability member 3/4 still meets the threshold')
  })

  test('missing canary evidence marks the wiring gate unmeasured', () => {
    const metrics = wanMetrics(gates({
      canaries: null,
      ssrf: { minted: 0, fired: 0 },
      xxe: { minted: 0, fired: 0 },
      ssrfConfirmed: false,
      xxeConfirmed: false,
      blindSqli: false,
    }))
    const fnr = metrics.wiring.criteria.find(criterion => criterion.id === 'oob_wiring_fnr')
    assert.equal(fnr?.status, 'unmeasured')
    assert.equal(wiringPassed(metrics), false)
  })
})

function emptyArtifacts(): SliceFunnelArtifacts {
  return { dispatches: [], hits: [], verifications: [] }
}

describe('Realism #4 per-slice funnel', () => {
  const slices = [
    { id: 'mono-billing-bola', method: 'GET', route: '/v2/billing/invoices/:invoiceId' },
    { id: 'mono-report-sqli', method: 'GET', route: '/v2/reports/export' },
    { id: 'mono-admin-bfla', method: 'PATCH', route: '/v3/admin/users/:id' },
  ]

  test('distinguishes exact route hit from brief-only dispatch', () => {
    const artifacts = emptyArtifacts()
    // Billing: fact-linked, exact route hit, oracle rejected.
    artifacts.dispatches.push({
      assignmentId: 'asg-billing',
      labels: ['Billing invoice BOLA'],
      factRoutes: [{ method: 'GET', route: '/v2/billing/invoices/:invoiceId' }],
    })
    artifacts.hits.push({ assignmentId: 'asg-billing', method: 'GET', route: '/v2/billing/invoices/inv_42' })
    artifacts.verifications.push({
      method: 'GET',
      route: '/v2/billing/invoices/inv_42',
      verdict: 'dismissed',
      rejectionCode: 'jq_error',
      attempts: 2,
    })
    // Reports: brief mentions the route stem, but the worker never hit it.
    artifacts.dispatches.push({
      assignmentId: 'asg-reports',
      labels: ['Review /v2/reports/export sorting'],
      factRoutes: [],
    })
    // Admin: route was hit but no brief/fact attribution survived.
    artifacts.hits.push({ assignmentId: 'asg-admin', method: 'PATCH', route: '/v3/admin/users/mono-bob' })
    // Method mismatch must not count as an exact route hit.
    artifacts.hits.push({ assignmentId: 'asg-reports', method: 'POST', route: '/v2/reports/export' })

    const rows = computeSliceFunnels({
      slices,
      artifacts,
      confirmedIds: new Set(['mono-billing-bola']),
    })
    const byId = new Map(rows.map(row => [row.id, row]))

    const billing = byId.get('mono-billing-bola')
    assert.equal(billing?.dispatched, 1)
    assert.equal(billing?.targetRouteHit, 1)
    assert.equal(billing?.verifyCalled, 1)
    assert.deepEqual(billing?.oracleRejectedBy, { jq_error: 1 })
    assert.equal(billing?.attribution, 'fact_link')
    assert.equal(billing?.confirmed, true)

    const reports = byId.get('mono-report-sqli')
    assert.equal(reports?.dispatched, 1)
    assert.equal(reports?.targetRouteHit, 0, 'POST is not the slice method')
    assert.equal(reports?.verifyCalled, 0)
    assert.equal(reports?.confirmed, false)
    assert.equal(reports?.attribution, 'brief_target')

    const admin = byId.get('mono-admin-bfla')
    assert.equal(admin?.dispatched, 1)
    assert.equal(admin?.targetRouteHit, 1)
    assert.equal(admin?.verifyCalled, 0)
    assert.equal(admin?.attribution, 'route_hit')
  })

  test('repeated requests inside one replay spec count as one verification call', () => {
    const artifacts = emptyArtifacts()
    artifacts.verifications.push(
      { specId: 1, method: 'GET', route: '/v2/reports/export', verdict: 'dismissed', rejectionCode: 'jq_error', attempts: 1 },
      { specId: 1, method: 'GET', route: '/v2/reports/export', verdict: 'dismissed', rejectionCode: 'jq_error', attempts: 1 },
      { specId: 2, method: 'GET', route: '/v2/reports/export', verdict: 'inconclusive', rejectionCode: 'inconclusive', attempts: 1 },
    )
    const rows = computeSliceFunnels({ slices: [slices[1]!], artifacts, confirmedIds: new Set() })
    assert.equal(rows[0]?.verifyCalled, 2)
    assert.deepEqual(rows[0]?.oracleRejectedBy, { jq_error: 1, inconclusive: 1 })
  })

  test('renders the three funnel numbers plus the rejection histogram', () => {
    const lines = renderSliceFunnelMarkdown([
      {
        id: 'mono-report-sqli',
        method: 'GET',
        route: '/v2/reports/export',
        dispatched: 2,
        targetRouteHit: 0,
        verifyCalled: 0,
        oracleRejectedBy: {},
        confirmed: false,
        attribution: 'brief_target',
      },
      {
        id: 'mono-billing-bola',
        method: 'GET',
        route: '/v2/billing/invoices/:invoiceId',
        dispatched: 1,
        targetRouteHit: 1,
        verifyCalled: 2,
        oracleRejectedBy: { jq_error: 1, step_failed: 1 },
        confirmed: false,
        attribution: 'fact_link',
      },
    ])
    const markdown = lines.join('\n')
    assert.match(markdown, /dispatched/)
    assert.match(markdown, /target route hit/)
    assert.match(markdown, /verify called/)
    assert.match(markdown, /oracle rejected by/)
    assert.match(markdown, /\| mono-report-sqli \| GET \| `\/v2\/reports\/export` \| 2 \| 0 \| 0 \| none \| no \|/)
    assert.match(markdown, /jq_error=1, step_failed=1/)
  })

  test('empty evidence renders an explicit not-measured line', () => {
    assert.deepEqual(renderSliceFunnelMarkdown([]), ['- not measured (no Tier-A 4-hop slices)'])
  })

  test('structural rejection codes come from typed feedback fields only', () => {
    assert.deepEqual(verificationRejectionCode({ verdict: 'confirmed' }), { verdict: 'confirmed', code: null })
    assert.deepEqual(verificationRejectionCode({ verdict: 'dismissed', jqError: 'no match' }), { verdict: 'dismissed', code: 'jq_error' })
    assert.deepEqual(verificationRejectionCode({ verdict: 'inconclusive', spaCatchallMatched: true }), { verdict: 'inconclusive', code: 'spa_catchall' })
    assert.deepEqual(verificationRejectionCode({ verdict: 'dismissed', failedStepId: 'probe' }), { verdict: 'dismissed', code: 'step_failed' })
    assert.deepEqual(verificationRejectionCode({ verdict: 'inconclusive' }), { verdict: 'inconclusive', code: 'inconclusive' })
    assert.deepEqual(verificationRejectionCode(null), { verdict: null, code: null })
  })
})
