/**
 * v7 M5 gap validation: a route-scoped coded proof gap must be supported by the host-observed
 * Layer-1 exchange transcript for that route.
 *
 * `proof-gap-route` fixed the global-counter loophole by making the obligation per route, but a
 * worker could still emit one vague coded gap per route and discharge everything without ever
 * verifying. These tests pin the deterministic evidence contract:
 *
 *  1. every code maps to the exact exchange evidence it needs (auth/404/405/readback/differential);
 *  2. an unsupported gap is rejected once at settlement with the missing evidence and the route;
 *  3. the reserved wrap-up turn is triggered (onRequired + demand) and a repeat never loops;
 *  4. hosted denials (tier/scope) and approved origins substantiate the host-side codes;
 *  5. `agent.gap_validation` accepted/rejected/byCode totals are exposed.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  SpecSubmissionTracker,
  buildWorkerTools,
  specSubmissionPending,
  type GapValidationStats,
  type SpecRouteEvidence,
} from '../src/server/agent-session.ts'

const ORIGIN = 'https://gap.validation.test'
const ADMIN = { method: 'POST', path: '/api/admin/9001' } as const
const ORDER = { method: 'GET', path: '/api/orders/1001' } as const
const ADMIN_KEY = 'POST /api/admin/:id'
const ORDER_KEY = 'GET /api/orders/:id'

type Observation = Parameters<SpecSubmissionTracker['noteObservation']>[0]
type InvokeResult = { output?: readonly { type: string; text?: string }[]; isError?: boolean }

function toolByName(tools: ReturnType<typeof buildWorkerTools>, name: string) {
  return tools.find(tool => tool.name === name)
}

async function invoke(tool: NonNullable<ReturnType<typeof toolByName>>, args: Record<string, unknown>): Promise<InvokeResult> {
  return tool.execute(args as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never) as Promise<InvokeResult>
}

function textOf(result: InvokeResult): string {
  return (result.output ?? []).map(part => part.text ?? '').join('\n')
}

function trackerWith(observations: readonly Observation[]): SpecSubmissionTracker {
  const tracker = new SpecSubmissionTracker()
  for (const observation of observations) tracker.noteObservation(observation)
  return tracker
}

function gapOn(tracker: SpecSubmissionTracker, route: { method: string; path: string }, code: string) {
  return tracker.noteProofGap({ proofGapReason: `${code}: deterministic mapping fixture`, route: `${route.method} ${route.path}` })
}

function statsOf(tracker: SpecSubmissionTracker): GapValidationStats {
  return tracker.gapValidationStats()
}

// ============================================================================
// 1. no_authenticated_persona / auth_blocked
// ============================================================================

test('no_authenticated_persona needs a 401/403/login-redirect denial and fewer than two persona successes', () => {
  const noDenial = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 200 }])
  assert.equal(gapOn(noDenial, ORDER, 'no_authenticated_persona').ok, true)
  const missingDenial = noDenial.validateGapsForSettlement()
  assert.equal(missingDenial.rejected.length, 1)
  assert.match(missingDenial.rejected[0]!.missing, /401\/403|login-redirect/)

  const denied = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 403 }])
  assert.equal(gapOn(denied, ORDER, 'auth_blocked').ok, true)
  assert.equal(denied.validateGapsForSettlement().rejected.length, 0, 'a denial with no persona success substantiates the gap')
  assert.deepEqual(statsOf(denied), { accepted: 1, rejected: 0, byCode: { auth_blocked: { accepted: 1, rejected: 0 } } })

  const twoPersonas = trackerWith([
    { method: 'GET', pathAndQuery: ORDER.path, status: 403 },
    { method: 'GET', pathAndQuery: ORDER.path, status: 200, persona: 'tenant_a' },
    { method: 'GET', pathAndQuery: ORDER.path, status: 200, persona: 'tenant_b' },
  ])
  assert.equal(gapOn(twoPersonas, ORDER, 'no_authenticated_persona').ok, true)
  const rejected = twoPersonas.validateGapsForSettlement()
  assert.equal(rejected.rejected.length, 1, 'two authenticated personas did succeed, so the gap is unsupported')
  assert.match(rejected.rejected[0]!.missing, /fewer than two authenticated personas/)
})

// ============================================================================
// 2. endpoint_not_found / method_not_allowed
// ============================================================================

test('endpoint_not_found and method_not_allowed need 404/405 on that exact route+method', () => {
  const notFound = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 404 }])
  assert.equal(gapOn(notFound, ORDER, 'endpoint_not_found').ok, true)
  assert.equal(notFound.validateGapsForSettlement().rejected.length, 0)

  const wrongStatus = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 200 }])
  assert.equal(gapOn(wrongStatus, ORDER, 'endpoint_not_found').ok, true)
  const rejected = wrongStatus.validateGapsForSettlement()
  assert.equal(rejected.rejected.length, 1)
  assert.match(rejected.rejected[0]!.missing, /404/)

  const method = trackerWith([{ method: 'POST', pathAndQuery: ADMIN.path, status: 405 }])
  assert.equal(gapOn(method, ADMIN, 'method_not_allowed').ok, true)
  assert.equal(method.validateGapsForSettlement().rejected.length, 0)

  // A 405 on a different method of the same family never substantiates a GET gap.
  const crossMethod = trackerWith([
    { method: 'GET', pathAndQuery: ORDER.path, status: 200 },
    { method: 'POST', pathAndQuery: ORDER.path, status: 405 },
  ])
  assert.equal(gapOn(crossMethod, ORDER, 'method_not_allowed').ok, true)
  assert.equal(crossMethod.validateGapsForSettlement().rejected.length, 1)
})

// ============================================================================
// 3. no_readback_surface (Realism #4 admin case)
// ============================================================================

test('no_readback_surface needs a mutating probe and zero readable GET in the family', () => {
  const accepted = trackerWith([
    { method: 'POST', pathAndQuery: ADMIN.path, status: 201 },
    { method: 'GET', pathAndQuery: ADMIN.path, status: 403 },
  ])
  assert.equal(gapOn(accepted, ADMIN, 'no_readback_surface').ok, true)
  assert.equal(accepted.validateGapsForSettlement().rejected.length, 0, 'mutation with a denied readback is the admin case')

  const readable = trackerWith([
    { method: 'POST', pathAndQuery: ADMIN.path, status: 201 },
    { method: 'GET', pathAndQuery: ADMIN.path, status: 200 },
  ])
  assert.equal(gapOn(readable, ADMIN, 'no_readback_surface').ok, true)
  const rejected = readable.validateGapsForSettlement()
  assert.equal(rejected.rejected.length, 1)
  assert.match(rejected.rejected[0]!.missing, /readable GET/)

  const readOnly = trackerWith([
    { method: 'POST', pathAndQuery: ADMIN.path, status: 403 },
    { method: 'GET', pathAndQuery: ADMIN.path, status: 403 },
  ])
  assert.equal(gapOn(readOnly, ADMIN, 'no_readback_surface').ok, true)
  assert.match(readOnly.validateGapsForSettlement().rejected[0]!.missing, /mutating probe/)
})

// ============================================================================
// 4. hardened_or_no_anomaly / no_reproducible_signal
// ============================================================================

test('hardened_or_no_anomaly and no_reproducible_signal need a control plus a differential probe', () => {
  const hardenedOnly = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 403 }])
  assert.equal(gapOn(hardenedOnly, ORDER, 'hardened_or_no_anomaly').ok, true)
  assert.match(hardenedOnly.validateGapsForSettlement().rejected[0]!.missing, /control exchange/)

  const differential = trackerWith([{
    method: 'GET', pathAndQuery: ORDER.path, status: 403, control: true, differential: true,
  }])
  assert.equal(gapOn(differential, ORDER, 'no_reproducible_signal').ok, true)
  assert.equal(differential.validateGapsForSettlement().rejected.length, 0, 'control + differential substantiates the negative result')
  assert.equal(statsOf(differential).accepted, 1)
})

// ============================================================================
// 5. Host-side codes: tier_blocked, out_of_scope, runtime_unavailable
// ============================================================================

test('tier_blocked needs a tier-denied exchange, not a generic failure', () => {
  const generic = trackerWith([{ method: 'POST', pathAndQuery: ADMIN.path, status: 500 }])
  assert.equal(gapOn(generic, ADMIN, 'tier_blocked').ok, true)
  assert.match(generic.validateGapsForSettlement().rejected[0]!.missing, /tier-denied/)

  const tier = new SpecSubmissionTracker()
  tier.noteDenial({ method: ADMIN.method, pathAndQuery: ADMIN.path, origin: ORIGIN, kind: 'tier' })
  assert.equal(gapOn(tier, ADMIN, 'tier_blocked').ok, true)
  assert.equal(tier.validateGapsForSettlement().rejected.length, 0)
})

test('out_of_scope needs a route outside the approved origins', () => {
  const approved = new SpecSubmissionTracker()
  approved.noteApprovedOrigins([ORIGIN])
  approved.noteObservation({ method: 'GET', pathAndQuery: ORDER.path, origin: ORIGIN, status: 200 })
  assert.equal(gapOn(approved, ORDER, 'out_of_scope').ok, true)
  assert.match(approved.validateGapsForSettlement().rejected[0]!.missing, /outside the approved origins/)

  const outside = new SpecSubmissionTracker()
  outside.noteApprovedOrigins([ORIGIN])
  outside.noteObservation({ method: 'GET', pathAndQuery: ORDER.path, origin: 'https://other.test', status: 200 })
  assert.equal(gapOn(outside, ORDER, 'out_of_scope').ok, true)
  assert.equal(outside.validateGapsForSettlement().rejected.length, 0)
})

test('runtime_unavailable needs no successful exchange on the route', () => {
  const running = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 200 }])
  assert.equal(gapOn(running, ORDER, 'runtime_unavailable').ok, true)
  assert.match(running.validateGapsForSettlement().rejected[0]!.missing, /runtime is unavailable/)

  const down = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 503 }])
  assert.equal(gapOn(down, ORDER, 'runtime_unavailable').ok, true)
  assert.equal(down.validateGapsForSettlement().rejected.length, 0)
})

// ============================================================================
// 6. Keep-codes still need the route to be exercised
// ============================================================================

test('no_spec_shape needs at least one recorded exchange on the route', () => {
  const exercised = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 200 }])
  assert.equal(gapOn(exercised, ORDER, 'no_spec_shape').ok, true)
  assert.equal(exercised.validateGapsForSettlement().rejected.length, 0)

  const untouched = new SpecSubmissionTracker()
  untouched.noteAssignedRoutes([{ method: 'GET', path: ORDER.path }])
  assert.equal(gapOn(untouched, ORDER, 'no_spec_shape').ok, true)
  assert.match(untouched.validateGapsForSettlement().rejected[0]!.missing, /recorded exchange/)
})

// ============================================================================
// 7. Route isolation + free-text gaps are not validated
// ============================================================================

test('a rejected gap on route A never changes the verdict for route B', () => {
  const tracker = trackerWith([
    { method: ADMIN.method, pathAndQuery: ADMIN.path, status: 500, anomaly: true },
    { method: ORDER.method, pathAndQuery: ORDER.path, status: 403 },
  ])
  assert.equal(gapOn(tracker, ADMIN, 'no_authenticated_persona').ok, true)
  assert.equal(gapOn(tracker, ORDER, 'no_authenticated_persona').ok, true)
  const result = tracker.validateGapsForSettlement()
  assert.deepEqual(result.rejected.map(gap => gap.key), [ADMIN_KEY])
  assert.deepEqual(statsOf(tracker), {
    accepted: 1, rejected: 1,
    byCode: { no_authenticated_persona: { accepted: 1, rejected: 1 } },
  })
  assert.equal(result.target?.key, ADMIN_KEY, 'the rejected/first uncovered route is the wrap-up target')
})

test('a free-text gap has no code and is never counted as validated', () => {
  const tracker = trackerWith([{ method: 'GET', pathAndQuery: ORDER.path, status: 200 }])
  tracker.noteProofGap({ proofGapReason: 'ran out of time on this route', route: ORDER.path })
  assert.equal(tracker.validateGapsForSettlement().rejected.length, 0)
  assert.deepEqual(statsOf(tracker), { accepted: 0, rejected: 0, byCode: {} })
})

// ============================================================================
// 8. Settlement rejection happens once and drives the reserved wrap-up turn
// ============================================================================

function fixture() {
  const routes: Array<{ method: string; path: string; result: unknown }> = [
    { method: ADMIN.method, path: ADMIN.path, result: { status: 500, anomalies: ['status-diff'] } },
    { method: ORDER.method, path: ORDER.path, result: { status: 200 } },
  ]
  const tracker = new SpecSubmissionTracker()
  const required: Array<{ status: string; count: number; route?: SpecRouteEvidence }> = []
  const completions: Array<{ status: string; summary: string }> = []
  const tools = buildWorkerTools({
    request_http: async args => routes.find(route =>
      route.method === args.method && args.pathAndQuery.split(/[?#]/, 1)[0] === route.path)?.result ?? { status: 200 },
    record_coverage: async args => ({ id: 'cov-1', status: args.status }),
    complete_intent: async completion => {
      completions.push(completion)
      return { recorded: true }
    },
  }, value => value, AbortSignal.timeout(5_000), 24 * 1024, () => {}, {
    tracker,
    onRequired: info => { required.push(info) },
  })
  return { tracker, required, completions, tools }
}

async function probe(tools: ReturnType<typeof buildWorkerTools>, route: { method: string; path: string }) {
  const result = await invoke(toolByName(tools, 'request_http')!, { origin: ORIGIN, method: route.method, pathAndQuery: route.path })
  assert.notEqual(result.isError, true)
}

function recordGap(route: { method: string; path: string }, code: string) {
  return {
    origin: ORIGIN,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Route-scoped gap fixture.',
    proofGapReason: `${code}: deterministic mapping fixture`,
    route: `${route.method} ${route.path}`,
  }
}

test('an unsupported gap is rejected once with the missing evidence and never loops', async () => {
  const { tracker, required, completions, tools } = fixture()
  await probe(tools, ADMIN)
  await probe(tools, ORDER)

  // ORDER observed 200, so a no_authenticated_persona gap is unsupported.
  const first = await invoke(toolByName(tools, 'record_coverage')!, recordGap(ORDER, 'no_authenticated_persona'))
  assert.notEqual(first.isError, true)
  assert.equal(specSubmissionPending(tracker.snapshot()), true, 'the admin route still owes proof')

  const rejected = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Admin write is likely BOLA.' })
  assert.equal(rejected.isError, true)
  const text = textOf(rejected)
  assert.match(text, /agent\.gap_validation/)
  assert.match(text, /no_authenticated_persona on GET \/api\/orders\/:id/)
  assert.match(text, /401\/403|login-redirect/)
  assert.ok(text.includes('POST /api/admin/9001'), 'the highest-value open route is demanded')
  assert.equal(required.length, 1)
  assert.deepEqual(required[0]!.route, { method: 'POST', path: '/api/admin/9001', params: [], origin: ORIGIN })
  assert.equal(completions.length, 0)
  assert.deepEqual(statsOf(tracker), {
    accepted: 0, rejected: 1,
    byCode: { no_authenticated_persona: { accepted: 0, rejected: 1 } },
  })

  // The next complete_intent is not blocked again by the same route (one rejection, no loop).
  const adminGap = await invoke(toolByName(tools, 'record_coverage')!, recordGap(ADMIN, 'baseline_empty'))
  assert.notEqual(adminGap.isError, true)
  const accepted = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Gaps recorded.' })
  assert.notEqual(accepted.isError, true)
  assert.equal(completions.length, 1)
  assert.equal(required.length, 1, 'no second demand for the already-rejected route')
})

test('a supported gap is accepted without a rejection or a demand', async () => {
  const { tracker, required, completions, tools } = fixture()
  await probe(tools, ORDER)
  // The transcript shows the control + differential exchange the gap claims.
  tracker.noteObservation({ method: ORDER.method, pathAndQuery: ORDER.path, origin: ORIGIN, status: 403, control: true, differential: true })

  const gap = await invoke(toolByName(tools, 'record_coverage')!, recordGap(ORDER, 'no_reproducible_signal'))
  assert.notEqual(gap.isError, true)

  const accepted = await invoke(toolByName(tools, 'complete_intent')!, { status: 'proved', summary: 'Hardened, differential refuted.' })
  assert.notEqual(accepted.isError, true)
  assert.equal(completions.length, 1)
  assert.equal(required.length, 0, 'a substantiated gap is never demanded')
  assert.deepEqual(statsOf(tracker), {
    accepted: 1, rejected: 0,
    byCode: { no_reproducible_signal: { accepted: 1, rejected: 0 } },
  })
})
