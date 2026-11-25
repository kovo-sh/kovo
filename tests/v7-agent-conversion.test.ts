/**
 * v7 agent-conversion — unit tests for Layer-3 `kovo_verify` ergonomics, route obligation
 * coverage from verify transcripts/dynamic scripts, premature early-exit guard on unprobed
 * assigned routes, and semantic non-floor class prioritization.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  KOVO_VERIFY_HELPERS,
  KOVO_VERIFY_SPEC_SHAPE,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  SpecSubmissionTracker,
  coordinatorPlannerPrompt,
  earlyExitEligible,
  gapValidationRejectedMessage,
  specSubmissionRequiredMessage,
} from '../src/server/agent-session.ts'
import { buildAssignmentBrief, renderSettlementSpecDirective } from '../src/server/assignment-brief.ts'
import {
  classifySemanticEndpointClasses,
  createGraphCoordinator,
  prioritizeSemanticEndpoints,
} from '../src/server/graph-coordinator.ts'
import type { CoordinatorEndpoint } from '../src/server/graph-coordinator.ts'

test('kovo_verify tool description and repair directives clearly guide inline script + all 5 typed helpers', () => {
  assert.match(KOVO_VERIFY_TOOL_DESCRIPTION, /pass `script` inline/i)
  for (const helper of KOVO_VERIFY_HELPERS) {
    assert.ok(KOVO_VERIFY_TOOL_DESCRIPTION.includes(helper.name), `missing helper ${helper.name}`)
  }

  const route = { method: 'POST', path: '/api/v1/wallets/:id/redeem', params: ['amount'], origin: 'https://app.example' }
  const reqMsg = specSubmissionRequiredMessage(route)
  assert.match(reqMsg, /kovo_verify\(script=/)
  assert.ok(reqMsg.includes(KOVO_VERIFY_SPEC_SHAPE), 'keeps DeclarativeReplaySpec fallback contract intact')

  const gapMsg = gapValidationRejectedMessage([{ key: 'POST /api/v1/wallets/:id/redeem', code: 'auth_blocked', missing: 'a 401/403' }], route)
  assert.match(gapMsg, /kovo_verify\(script=/)
  assert.ok(gapMsg.includes(KOVO_VERIFY_SPEC_SHAPE))

  const directive = renderSettlementSpecDirective(route, KOVO_VERIFY_SPEC_SHAPE, ['auth_blocked'])
  assert.match(directive, /kovo_verify inline script \(ctx\.prove_\*\)/i)
})

test('SpecSubmissionTracker.noteVerifyScript covers assigned/probed routes via transcript routes and dynamic template paths', () => {
  // 1. Transcript routes cover assigned targets even when `script` is undefined (scriptPath) or dynamic.
  const tracker1 = new SpecSubmissionTracker()
  tracker1.noteAssignedRoutes([{ method: 'POST', path: '/api/v1/coupons/:id/redeem', origin: 'https://app.example' }])
  tracker1.noteVerifyScript(undefined, [{ method: 'POST', path: '/api/v1/coupons/998877/redeem' }])
  const snap1 = tracker1.snapshot()
  assert.equal(snap1.obligation.coveredRoutes, 1)
  assert.equal(snap1.obligations[0]?.covered, true)

  // 2. Dynamic template-literal inline script (`/api/v1/orders/${id}`) covers parameterized assigned family.
  const tracker2 = new SpecSubmissionTracker()
  tracker2.noteAssignedRoutes([{ method: 'GET', path: '/api/v1/orders/:id', origin: 'https://app.example' }])
  tracker2.noteVerifyScript('await ctx.prove_access_boundary({ path: `/api/v1/orders/${victimId}` })')
  const snap2 = tracker2.snapshot()
  assert.equal(snap2.obligation.coveredRoutes, 1)
  assert.equal(snap2.obligations[0]?.covered, true)
})

test('assignment brief preserves confirmed floor findingId for read-only chain primitive handoff', () => {
  const briefText = buildAssignmentBrief({
    missionKind: 'chain_step_2',
    origin: 'https://app.example',
    routes: [{ method: 'POST', path: '/api/v1/admin/settings', riskScore: 85 }],
    personas: [{ handle: 'persona_a', role: 'owner', harvestedIds: ['ord-101', 'ord-102'] }],
    alreadyConfirmedOnOrigin: [
      { method: 'GET', path: '/api/v1/tokens', cwe: 'CWE-200', findingId: 'finding-floor-1' },
    ],
  })
  const parsed = JSON.parse(briefText) as {
    alreadyConfirmedOnOrigin?: Array<{ findingId?: string; path: string }>
    personas?: Array<{ handle: string; harvestedIds?: string[] }>
  }
  assert.equal(parsed.alreadyConfirmedOnOrigin?.[0]?.findingId, 'finding-floor-1')
  assert.deepEqual(parsed.personas?.[0]?.harvestedIds, ['ord-101', 'ord-102'])
})

test('graph-coordinator classifies and prioritizes unconfirmed non-floor semantic classes even after basic floor sweeps', () => {
  const origin = 'https://app.example'
  const endpoints: CoordinatorEndpoint[] = [
    { id: 'ep-confirmed', origin, method: 'POST', pathTemplate: '/api/v1/checkout/confirm', riskScore: 95, coveragePct: 100, testedClasses: [] },
    { id: 'ep-race', origin, method: 'POST', pathTemplate: '/api/v1/wallets/:id/redeem', riskScore: 80, coveragePct: 20, testedClasses: ['sqli'] },
    { id: 'ep-jwt', origin, method: 'GET', pathTemplate: '/api/v1/reports/sales', riskScore: 70, coveragePct: 15, testedClasses: ['authz'] },
    { id: 'ep-read', origin, method: 'GET', pathTemplate: '/api/v1/health', riskScore: 50, coveragePct: 10, testedClasses: ['sqli'] },
  ]

  assert.ok(classifySemanticEndpointClasses(endpoints[1]!).includes('race'))
  assert.ok(classifySemanticEndpointClasses(endpoints[2]!).includes('auth_protocol'))
  assert.deepEqual(classifySemanticEndpointClasses(endpoints[3]!), [])

  const prioritized = prioritizeSemanticEndpoints(endpoints, {
    confirmedPaths: new Set(['/api/v1/checkout/confirm']),
  })
  assert.deepEqual(prioritized.map(entry => entry.endpoint.id), ['ep-race', 'ep-jwt'])

  const coord = createGraphCoordinator({
    deps: {
      listEndpoints: () => endpoints,
      listFacts: () => [],
      listFindings: () => [],
    },
    approvedOrigins: [origin],
  })
  const page = coord.queryEndpoints({ untestedSemanticOnly: true })
  assert.ok(page.items.some(ep => ep.id === 'ep-race'), 'race endpoint surfaced even though floor tested sqli')
  assert.ok(!page.items.some(ep => ep.id === 'ep-read'), 'plain health read excluded from semantic filter')

  const plannerText = coordinatorPlannerPrompt({
    goal: 'Audit app',
    roundNo: 1,
    capabilityTier: 2,
    approvedOrigins: [origin],
    budgetRemaining: { usd: 5, requests: 500 },
    dynamicStepBudget: 24,
    pendingOob: 0,
    chainSteps: [],
  })
  assert.match(plannerText, /untestedSemanticOnly=true/)
  assert.match(plannerText, /read-only chain primitives/)
})

test('earlyExitEligible blocks premature early exit while assigned target routes are still unprobed', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteAssignedRoutes([{ method: 'POST', path: '/api/v1/wallets/:id/redeem', origin: 'https://app.example' }])
  // Two hardened denials on unrelated probe routes should not trigger early exit while assigned route is untouched.
  tracker.noteObservation({ method: 'GET', pathAndQuery: '/api/v1/other?a=1', origin: 'https://app.example', status: 403 })
  tracker.noteObservation({ method: 'GET', pathAndQuery: '/api/v1/other?a=2', origin: 'https://app.example', status: 403 })
  const snap = tracker.snapshot()
  const hasUnprobedAssigned = snap.obligations.some(o => o.assigned && o.attempts === 0 && !o.covered && !o.gap)
  assert.equal(hasUnprobedAssigned, true)

  const blocked = earlyExitEligible({
    evidence: tracker.observationSnapshot(),
    turnsUsed: 5,
    maxTurns: 12,
    unprobedAssignedRoutes: hasUnprobedAssigned,
  })
  assert.deepEqual(blocked, { eligible: false, blockedBy: 'unprobed_assigned_routes' })

  // Once the assigned route is covered via verify transcript, early exit is no longer blocked by it.
  tracker.noteVerifyScript(undefined, [{ method: 'POST', path: '/api/v1/wallets/42/redeem' }])
  const snapAfter = tracker.snapshot()
  const stillUnprobed = snapAfter.obligations.some(o => o.assigned && o.attempts === 0 && !o.covered && !o.gap)
  assert.equal(stillUnprobed, false)
  const allowed = earlyExitEligible({
    evidence: tracker.observationSnapshot(),
    turnsUsed: 5,
    maxTurns: 12,
    unprobedAssignedRoutes: stillUnprobed,
  })
  assert.equal(allowed.eligible, true)
})
