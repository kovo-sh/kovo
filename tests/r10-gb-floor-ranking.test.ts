/**
 * R10 Move 1 — Agentic Phase-A floor wall-clock ceiling + `harvestSurface` time/SSE guard,
 * plus generic GB Wave-1 fallback & `selectBriefRoutes` endpoint ranking.
 */
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  MULTIHOP_ATTACKER_ORIGIN_RULE,
  buildAssignmentBriefPacket,
  buildMultiHopProofContract,
  selectBriefRoutes,
} from '../src/server/assignment-brief.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import {
  SurfaceHarvester,
  agenticFloorWallMarginMs,
  defaultEngineMaxDurationMs,
  deterministicWallMarginMs,
  harvestRequestTimeoutMs,
  harvestSurface,
  resolveFloorWallMarginMs,
  runDeterministicEngine,
  type DeterministicEngineInput,
  type EngineEndpoint,
  type EnginePersona,
} from '../src/server/deterministic-engine.ts'
import {
  buildWave1UncoveredOriginFallbackSteps,
  rankOriginFallbackRoutes,
  type Wave1OriginFallbackEndpoint,
} from '../src/server/exec-recon-multiorigin.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const ORIGIN_A = 'https://svc-a.example.test'
const ORIGIN_B = 'https://svc-b.example.test'

function makeGrant(origins: string[]): Grant {
  return {
    runId: 'run-r10-test',
    assignmentId: 'assign-r10-test',
    origins: new Set(origins),
    tier: 3,
    allowLocalLab: true,
    maxRequests: 500,
  } as unknown as Grant
}

function makeExchange(overrides: Partial<BrokerExchangeResult> & { origin: string; pathAndQuery: string }): BrokerExchangeResult {
  const { origin, pathAndQuery, ...rest } = overrides
  return {
    id: `ex-${Math.random().toString(36).slice(2, 8)}`,
    origin,
    method: 'GET',
    pathAndQuery,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: { 'content-type': rest.mediaType ?? 'application/json' },
    body: '{}',
    durationMs: 5,
    truncated: false,
    ...rest,
  } as BrokerExchangeResult
}

test('resolveFloorWallMarginMs bounds agentic floor <= 15s while keeping --no-llm at full 120s', () => {
  assert.equal(deterministicWallMarginMs, 120_000)
  assert.ok(agenticFloorWallMarginMs <= 15_000)
  assert.ok(harvestRequestTimeoutMs <= 2_500)

  // --no-llm default (240s) is untouched
  assert.equal(resolveFloorWallMarginMs(defaultEngineMaxDurationMs), 120_000)
  assert.equal(resolveFloorWallMarginMs(300_000), 120_000)

  // Agentic Phase-A floor budgets (e.g. 75s / 72s / 60s) stay <= 15s margin -> hardDeadline <= 90s
  for (const dur of [75_000, 72_000, 60_000, 45_000]) {
    const margin = resolveFloorWallMarginMs(dur)
    assert.ok(margin <= 15_000, `margin ${margin}ms exceeded 15s for maxDurationMs=${dur}`)
    assert.ok(dur + margin <= 90_000, `hardDeadline ${dur + margin}ms exceeded 90s for maxDurationMs=${dur}`)
  }

  // Explicit override is respected
  assert.equal(resolveFloorWallMarginMs(240_000, 10_000), 10_000)
})

test('harvestSurface bails on text/event-stream and timed-out streaming GETs without re-probing personas or query params', async () => {
  const calls: Array<{ persona?: string; pathAndQuery: string; timeoutMs?: number }> = []
  const broker = {
    async executeHttp(req: { origin: string; method: string; pathAndQuery: string; persona?: string; timeoutMs?: number }) {
      calls.push({ persona: req.persona, pathAndQuery: req.pathAndQuery, timeoutMs: req.timeoutMs })
      if (req.pathAndQuery.startsWith('/api/events')) {
        return makeExchange({
          origin: req.origin,
          pathAndQuery: req.pathAndQuery,
          status: 200,
          mediaType: 'text/event-stream',
          respHeaders: { 'content-type': 'text/event-stream' },
          body: 'data: ping\n\n',
        })
      }
      if (req.pathAndQuery.startsWith('/api/live-stream')) {
        await new Promise(resolve => setTimeout(resolve, 130))
        throw new Error('Request timeout after 120ms')
      }
      return makeExchange({
        origin: req.origin,
        pathAndQuery: req.pathAndQuery,
        status: 200,
        body: JSON.stringify([{ id: 'item-1', name: 'widget' }]),
      })
    },
  } as unknown as RequestBroker

  const personas: EnginePersona[] = [
    { handle: 'owner_a', roleLabel: 'member (org_a)', privilege: 'member', tenant: 'org_a' },
    { handle: 'other_b', roleLabel: 'member (org_b)', privilege: 'member', tenant: 'org_b' },
  ]
  const endpoints: EngineEndpoint[] = [
    { id: 'ep-sse', origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/events', params: [{ name: 'q', location: 'query' }], riskScore: 80, source: 'crawl' },
    { id: 'ep-sse-item', origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/events/:id/ack', params: [], riskScore: 80, source: 'crawl' },
    { id: 'ep-timeout', origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/live-stream/:id/cancel', params: [], riskScore: 80, source: 'crawl' },
    { id: 'ep-ok', origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/items', params: [], riskScore: 70, source: 'crawl' },
  ]
  const ac = new AbortController()
  const input = {
    runId: 'run-r10-sse',
    assignmentId: 'assign-r10-sse',
    signal: ac.signal,
    endpoints,
    personas,
    broker,
    grant: makeGrant([ORIGIN_A]),
    backend: {} as WorkerBackend,
    tier: 3,
    onConfirmed: () => null,
  } as DeterministicEngineInput

  const deadlineAt = Date.now() + 5_000
  const harvester = new SurfaceHarvester(input, () => {}, ORIGIN_A, deadlineAt, 120)
  const budget = { requestsUsed: 0, maxRequests: 50 }
  const t0 = Date.now()
  const res = await harvestSurface(
    input,
    endpoints,
    harvester,
    { owner: personas[0], crossTenant: personas[1], lower: undefined, admin: undefined },
    budget,
    () => {},
    50,
    deadlineAt,
  )
  const elapsed = Date.now() - t0

  assert.ok(elapsed < 1_000, `harvestSurface with SSE + slow stream took ${elapsed}ms (expected < 1000ms)`)
  assert.equal(harvester.isStreamingPath('/api/events'), true)
  assert.equal(harvester.isStreamingPath('/api/live-stream'), true)

  // /api/events must only be hit ONCE (never re-probed for other_b or query variants)
  const sseHits = calls.filter(c => c.pathAndQuery === '/api/events' || c.pathAndQuery.startsWith('/api/events?'))
  assert.equal(sseHits.length, 1, `expected 1 SSE hit on /api/events, got ${JSON.stringify(sseHits)}`)

  // /api/live-stream must only be hit ONCE (timed out on owner_a, skipped for other_b!)
  const timeoutHits = calls.filter(c => c.pathAndQuery === '/api/live-stream')
  assert.equal(timeoutHits.length, 1, `expected 1 slow-stream hit (no second persona retry), got ${JSON.stringify(timeoutHits)}`)
  assert.ok((timeoutHits[0]?.timeoutMs ?? 9999) <= 120)

  // Normal JSON endpoint after streaming endpoints was still harvested cleanly
  assert.deepEqual(res.harvests.get('ep-ok')?.ownerIds, ['item-1'])
})

test('harvestSurface stops promptly when elapsed wall-clock reaches deadlineAt', async () => {
  let requests = 0
  const broker = {
    async executeHttp(req: { origin: string; pathAndQuery: string }) {
      requests += 1
      await new Promise(resolve => setTimeout(resolve, 45))
      return makeExchange({ origin: req.origin, pathAndQuery: req.pathAndQuery, body: JSON.stringify([{ id: `id-${requests}` }]) })
    },
  } as unknown as RequestBroker

  const personas: EnginePersona[] = [
    { handle: 'owner_a', roleLabel: 'member (org_a)', privilege: 'member', tenant: 'org_a' },
  ]
  const endpoints: EngineEndpoint[] = Array.from({ length: 20 }, (_, i) => ({
    id: `ep-${i}`,
    origin: ORIGIN_A,
    method: 'GET',
    pathTemplate: `/api/resources-${i}`,
    params: [],
    riskScore: 70,
    source: 'crawl',
  }))
  const ac = new AbortController()
  const input = {
    runId: 'run-r10-deadline',
    assignmentId: 'assign-r10-deadline',
    signal: ac.signal,
    endpoints,
    personas,
    broker,
    grant: makeGrant([ORIGIN_A]),
    backend: {} as WorkerBackend,
    tier: 3,
    onConfirmed: () => null,
  } as DeterministicEngineInput

  const deadlineAt = Date.now() + 120
  const harvester = new SurfaceHarvester(input, () => {}, ORIGIN_A, deadlineAt, 200)
  const budget = { requestsUsed: 0, maxRequests: 100 }
  const t0 = Date.now()
  await harvestSurface(
    input,
    endpoints,
    harvester,
    { owner: personas[0], crossTenant: undefined, lower: undefined, admin: undefined },
    budget,
    () => {},
    100,
    deadlineAt,
  )
  const elapsed = Date.now() - t0
  assert.ok(elapsed < 400, `expected early deadline stop (< 400ms), got ${elapsed}ms`)
  assert.ok(requests < endpoints.length, `expected harvest to stop before all ${endpoints.length} endpoints, got ${requests}`)
})

test('runDeterministicEngine honors tight agentic wallMarginMs on slow endpoints', async () => {
  const broker = {
    async executeHttp(req: { origin: string; pathAndQuery: string }) {
      await new Promise(resolve => setTimeout(resolve, 60))
      return makeExchange({ origin: req.origin, pathAndQuery: req.pathAndQuery, body: JSON.stringify([{ id: 'r-1' }]) })
    },
  } as unknown as RequestBroker

  const endpoints: EngineEndpoint[] = Array.from({ length: 15 }, (_, i) => ({
    id: `ep-slow-${i}`,
    origin: ORIGIN_A,
    method: 'GET',
    pathTemplate: `/api/slow-${i}`,
    params: [],
    riskScore: 70,
    source: 'crawl',
  }))
  const t0 = Date.now()
  const report = await runDeterministicEngine({
    runId: 'run-r10-engine',
    assignmentId: 'assign-r10-engine',
    signal: new AbortController().signal,
    endpoints,
    personas: [{ handle: 'owner_a', roleLabel: 'member (org_a)', privilege: 'member', tenant: 'org_a' }],
    broker,
    grant: makeGrant([ORIGIN_A]),
    backend: {} as WorkerBackend,
    tier: 2,
    maxRequests: 100,
    maxDurationMs: 1_000,
    wallMarginMs: 200,
    onConfirmed: () => null,
  })
  const elapsed = Date.now() - t0
  assert.ok(elapsed < 1_800, `engine exceeded tight deadline+margin: ${elapsed}ms`)
  assert.ok(report.endpointsHarvested < endpoints.length, 'harvest share cap (<=40%) should prevent harvesting all 15 slow routes')
})

test('rankOriginFallbackRoutes and buildWave1UncoveredOriginFallbackSteps prioritize mutating & parameterized routes while keeping 1 read', () => {
  const originEps: Wave1OriginFallbackEndpoint[] = [
    { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/alpha', riskScore: 60 },
    { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/beta', riskScore: 60 },
    { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/gamma', riskScore: 60 },
    { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/delta', riskScore: 60 },
    { origin: ORIGIN_A, method: 'GET', pathTemplate: '/assets/app.js', riskScore: 65 },
    { origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/releases/:id/promote', riskScore: 55 },
    { origin: ORIGIN_A, method: 'PATCH', pathTemplate: '/api/identities/:id/rebind', riskScore: 55 },
    { origin: ORIGIN_A, method: 'DELETE', pathTemplate: '/api/tokens/:id', riskScore: 50 },
    { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/orders/:id', riskScore: 55 },
  ]

  const top = rankOriginFallbackRoutes(originEps, 4)
  assert.equal(top.length, 4)
  assert.ok(top.includes('POST /api/releases/:id/promote'), `missing mutating sub-resource route in ${JSON.stringify(top)}`)
  assert.ok(top.includes('PATCH /api/identities/:id/rebind'), `missing PATCH sub-resource route in ${JSON.stringify(top)}`)
  assert.ok(top.includes('DELETE /api/tokens/:id'), `missing DELETE parameterized route in ${JSON.stringify(top)}`)
  // 1 read/entry route is preserved alongside the 3 priority routes
  assert.ok(top.some(r => r.startsWith('GET /api/') && !r.includes(':id')), `expected 1 plain read route preserved in ${JSON.stringify(top)}`)
  assert.equal(top.some(r => r.includes('/assets/app.js')), false, 'static asset must not crowd out API routes')

  const res = buildWave1UncoveredOriginFallbackSteps({
    reachableFinalEntries: [{ origin: ORIGIN_A, riskTier: 'high', surfaceTags: ['api'], rationale: 'svc' }],
    seededSteps: [],
    existingSteps: [],
    discoveredEndpointOrigins: new Set([ORIGIN_A]),
    discoveredEndpoints: originEps,
    finalHostTiers: { [ORIGIN_A]: 'crown_jewel' },
    sourceMounted: false,
    codeAuditStepsCreated: 0,
    capabilityTier: 3,
    whiteBoxCapPriority: 80,
    classifyTier: () => 'crown_jewel',
  })
  assert.equal(res.seededSteps.length, 1)
  const hyp = res.seededSteps[0]!.hypothesis
  assert.ok(hyp.includes('POST /api/releases/:id/promote'), `fallback hypothesis missed mutating route: ${hyp}`)
  assert.ok(hyp.includes('PATCH /api/identities/:id/rebind'), `fallback hypothesis missed PATCH route: ${hyp}`)
  assert.ok(hyp.includes('GET /api/alpha'), `fallback hypothesis should keep 1 read entry route: ${hyp}`)
})

test('selectBriefRoutes balances mutating + parameterized + read routes up to 6/origin across single & multi-origin', () => {
  const makeOriginPool = (origin: string) => [
    // 8 noisy plain GET listings with higher raw riskScore than mutating routes
    ...Array.from({ length: 8 }, (_, i) => ({
      origin,
      method: 'GET',
      pathTemplate: `/api/list-${i}`,
      riskScore: 62,
    })),
    { origin, method: 'POST', pathTemplate: '/api/items/:id/promote', riskScore: 55 },
    { origin, method: 'PATCH', pathTemplate: '/api/accounts/:id/rebind', riskScore: 55 },
    { origin, method: 'POST', pathTemplate: '/api/exports', riskScore: 52 },
    { origin, method: 'DELETE', pathTemplate: '/api/tokens/:id', riskScore: 50 },
    { origin, method: 'GET', pathTemplate: '/api/orders/:id', riskScore: 54 },
    { origin, method: 'GET', pathTemplate: '/api/scim/users/:id', riskScore: 54 },
  ]

  // Single-origin: 6 balanced routes (3 mutating + 2 param reads + 1 plain read)
  const single = selectBriefRoutes(makeOriginPool(ORIGIN_A), {
    publicOrigins: [ORIGIN_A],
    targetOrigins: [ORIGIN_A],
    confirmedPaths: new Set(),
    confirmedOriginPaths: new Set(),
    normalizePath: p => p,
  })
  assert.equal(single.length, 6)
  const singleMutating = single.filter(r => ['POST', 'PATCH', 'PUT', 'DELETE'].includes(r.method))
  const singleParamReads = single.filter(r => r.method === 'GET' && r.path.includes(':id'))
  const singlePlainReads = single.filter(r => r.method === 'GET' && !r.path.includes(':id'))
  assert.equal(singleMutating.length, 3, `expected 3 mutating routes, got ${JSON.stringify(single)}`)
  assert.equal(singleParamReads.length, 2, `expected 2 parameterized reads, got ${JSON.stringify(single)}`)
  assert.equal(singlePlainReads.length, 1, `expected 1 plain read, got ${JSON.stringify(single)}`)

  // Multi-origin: preserves <= 4 routes per origin (2 mutating + 1 param read + 1 read), interleaved
  const multi = selectBriefRoutes([...makeOriginPool(ORIGIN_A), ...makeOriginPool(ORIGIN_B)], {
    publicOrigins: [ORIGIN_A, ORIGIN_B],
    targetOrigins: [ORIGIN_A, ORIGIN_B],
    confirmedPaths: new Set(),
    confirmedOriginPaths: new Set(),
    normalizePath: p => p,
  })
  assert.equal(multi.length, 8, `expected 4 balanced routes/origin x 2 origins = 8, got ${multi.length}`)
  const fromA = multi.filter(r => r.origin === ORIGIN_A)
  const fromB = multi.filter(r => r.origin === ORIGIN_B)
  assert.equal(fromA.length, 4)
  assert.equal(fromB.length, 4)
  assert.equal(fromA.filter(r => ['POST', 'PATCH', 'PUT', 'DELETE'].includes(r.method)).length, 2)
  assert.equal(fromB.filter(r => ['POST', 'PATCH', 'PUT', 'DELETE'].includes(r.method)).length, 2)
  assert.ok(fromA.some(r => r.method === 'POST' && r.path === '/api/items/:id/promote'))
  assert.ok(fromB.some(r => r.method === 'PATCH' && r.path === '/api/accounts/:id/rebind'))
  assert.ok(fromA.some(r => r.method === 'GET' && r.path.includes(':id')))
  assert.ok(fromB.some(r => r.method === 'GET' && !r.path.includes(':id')))
})

test('cross-tenant guidance instructs choosing an outsider persona from another tenant within brief caps', () => {
  assert.match(MULTIHOP_ATTACKER_ORIGIN_RULE, /outsider persona/i)
  assert.match(MULTIHOP_ATTACKER_ORIGIN_RULE, /tenant differs|different tenant|another tenant/i)
  assert.match(MULTIHOP_ATTACKER_ORIGIN_RULE, /invite|resolution|rebind/i)

  const compact = buildMultiHopProofContract(true, {
    missionKind: 'class_scan',
    origin: ORIGIN_A,
    routes: [{ method: 'POST', path: '/api/invites/accept', riskScore: 80 }],
  })
  assert.match(compact.attackerOriginRule, /outsider persona/i)

  // Brief stays strictly inside byte caps for both compact (1536 B) and multi-origin (4096 B).
  const singlePacket = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin: ORIGIN_A,
    routes: [{ method: 'POST', path: '/api/invites/accept', riskScore: 80 }],
  })
  assert.ok(singlePacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)

  const multiPacket = buildAssignmentBriefPacket({
    missionKind: 'multihop_chain',
    origin: ORIGIN_A,
    publicOrigins: [ORIGIN_A, ORIGIN_B],
    routes: [
      { origin: ORIGIN_A, method: 'POST', path: '/api/invites/accept', riskScore: 85 },
      { origin: ORIGIN_B, method: 'PATCH', path: '/api/identities/:id/rebind', riskScore: 85 },
    ],
  })
  assert.ok(multiPacket.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
})
