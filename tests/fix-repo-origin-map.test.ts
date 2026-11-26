/**
 * P1 #4a Regression Tests:
 * 1. Deterministic Repo→Origin affinity resolution (`resolveRepoOriginAffinity`) across multi-repo
 *    + multi-origin topologies, eliminating `approvedList[0]` fallback distortion.
 * 2. Single-origin runs still bind mounted repo routes/hypotheses cleanly to the sole approved origin.
 * 3. Uniform edge-protected (401-wall) and dead/unreachable (525 / `skippedDeadHosts`) host quarantine:
 *    records a single structured coverage gap (`edge_protected` / `unreachable`) and excludes quarantined
 *    hosts from Wave-1 / high-risk investigation steps unless an authenticated persona is configured.
 * 4. Per-origin soft fairness / concentration guard (`<= 50%` share when sibling live origins have work).
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import {
  applyCrownJewelStepBudget,
  detectQuarantinedOrigins,
  dispatchFrontierWave,
  enforcePerOriginFairness,
  selectUncoveredHighRiskEndpoints,
  type DispatchLaneStep,
} from '../src/server/exec-dispatch.ts'
import { Execution } from '../src/server/execution.ts'
import {
  resolveRepoOriginAffinity,
  type ExecReconPlanner,
} from '../src/server/exec-recon-planner.ts'
import type { InvariantHypothesis, SynthesizeInvariantsResult } from '../src/server/invariant-synthesizer.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function stubBackend(): WorkerBackend {
  return {
    name: 'stub-repo-origin-map',
    async run() {
      return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} }
    },
  } as unknown as WorkerBackend
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function getPlanner(execution: Execution): ExecReconPlanner {
  return (execution as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

function makeHyp(overrides: Partial<InvariantHypothesis> & { id: string }): InvariantHypothesis {
  return {
    kind: 'policy_asymmetry',
    capabilityKind: 'policy_asymmetry',
    promotionStatus: 'capability_only',
    mode: 'white-box',
    entity: 'item',
    surface: 'http',
    severity: 'high',
    score: 0.88,
    summary: `Authz guard asymmetry on ${overrides.targetRoute ?? '/api/items'}`,
    preconditions: ['two tenants'],
    verificationHint: 'Compare control vs variant access',
    evidence: [],
    ...overrides,
  }
}

describe('P1 #4a: Deterministic Repo→Origin Affinity (no approvedList[0] fallback)', () => {
  test('multi-repo + multi-origin affinity binds dmail, llm-engine, chat-uploader, image-uploader and marks unmapped repos unmapped', () => {
    const approvedOrigins = [
      'https://academy.example',
      'https://billing.example',
      'https://dmail.example',
      'https://docs.example',
      'https://engine.example',
      'https://upload-image.example',
      'https://upload-logs.example',
    ]

    const mappings = resolveRepoOriginAffinity({
      approvedOrigins,
      repos: [
        'dmail',
        'llm-engine',
        'image-uploader',
        'chat-uploader',
        'mystery-cron',
      ],
    })

    const byRepo = new Map(mappings.map(m => [m.repo, m]))
    assert.equal(byRepo.get('dmail')?.origin, 'https://dmail.example')
    assert.equal(byRepo.get('llm-engine')?.origin, 'https://engine.example')
    assert.equal(byRepo.get('image-uploader')?.origin, 'https://upload-image.example')
    assert.equal(byRepo.get('chat-uploader')?.origin, 'https://upload-logs.example')

    const mystery = byRepo.get('mystery-cron')
    assert.ok(mystery, 'mystery-cron mapping record must exist')
    assert.equal(mystery.confidence, 'unmapped', 'unmatched repo on multi-origin run must be marked unmapped')
    assert.equal(mystery.origin, undefined, 'unmatched repo must NEVER fall back to approvedOrigins[0] (academy.example)')
  })

  test('brand-prefixed dyad-* repos resolve deterministically to *.dyad.sh origins without dumping onto academy.dyad.sh', () => {
    const approvedOrigins = [
      'https://academy.dyad.sh',
      'https://billingz.dyad.sh',
      'https://dmail.dyad.sh',
      'https://engine.dyad.sh',
      'https://eve.dyad.sh',
      'https://upload-image.dyad.sh',
      'https://upload-logs.dyad.sh',
    ]

    const mappings = resolveRepoOriginAffinity({
      approvedOrigins,
      repos: [
        '/repos/dmail',
        '/repos/dyad-eve-bot',
        '/repos/dyad-billingz',
        '/repos/dyad-chat-uploader',
        '/repos/dyad-llm-engine',
        '/repos/dyad-image-uploader',
        '/repos/internal-unknown-helper',
      ],
    })

    const byRepo = new Map(mappings.map(m => [m.repo, m]))
    assert.equal(byRepo.get('/repos/dmail')?.origin, 'https://dmail.dyad.sh')
    assert.equal(byRepo.get('/repos/dyad-eve-bot')?.origin, 'https://eve.dyad.sh')
    assert.equal(byRepo.get('/repos/dyad-billingz')?.origin, 'https://billingz.dyad.sh')
    assert.equal(byRepo.get('/repos/dyad-llm-engine')?.origin, 'https://engine.dyad.sh')
    assert.equal(byRepo.get('/repos/dyad-image-uploader')?.origin, 'https://upload-image.dyad.sh')
    assert.equal(byRepo.get('/repos/dyad-chat-uploader')?.origin, 'https://upload-logs.dyad.sh')
    assert.equal(byRepo.get('/repos/internal-unknown-helper')?.confidence, 'unmapped')
    assert.equal(byRepo.get('/repos/internal-unknown-helper')?.origin, undefined)
  })

  test('live-route overlap and package.json homepage/config hints bind opaque repo slugs deterministically', () => {
    const approvedOrigins = [
      'https://academy.example',
      'https://portal.example',
      'https://upload-logs.example',
    ]

    const mappings = resolveRepoOriginAffinity({
      approvedOrigins,
      repos: [
        {
          repo: 'opaque-svc-a',
          declaredRoutes: ['/api/v2/chat-transcripts/:id', '/api/v2/log-bundles'],
        },
        {
          repo: 'opaque-svc-b',
          homepage: 'https://portal.example/dashboard',
        },
        {
          repo: 'opaque-unmapped',
          declaredRoutes: ['/api/nonexistent/only-404'],
        },
      ],
      liveEndpoints: [
        { origin: 'https://upload-logs.example', pathTemplate: '/api/v2/chat-transcripts/99', status: 200 },
        { origin: 'https://upload-logs.example', pathTemplate: '/api/v2/log-bundles', status: 403 },
        // 404 responses and static-only repo_ast rows must NOT count as live-route evidence
        { origin: 'https://academy.example', pathTemplate: '/api/nonexistent/only-404', status: 404 },
        { origin: 'https://academy.example', pathTemplate: '/api/nonexistent/only-404', source: 'repo_ast' },
      ],
    })

    const byRepo = new Map(mappings.map(m => [m.repo, m]))
    assert.equal(byRepo.get('opaque-svc-a')?.origin, 'https://upload-logs.example')
    assert.equal(byRepo.get('opaque-svc-a')?.confidence, 'live_route')
    assert.equal(byRepo.get('opaque-svc-b')?.origin, 'https://portal.example')
    assert.equal(byRepo.get('opaque-svc-b')?.confidence, 'config')
    assert.equal(byRepo.get('opaque-unmapped')?.confidence, 'unmapped')
    assert.equal(byRepo.get('opaque-unmapped')?.origin, undefined)
  })

  test('single-origin run binds mounted repo routes cleanly to the sole approved origin', async (t) => {
    const mappings = resolveRepoOriginAffinity({
      approvedOrigins: ['https://solo.example'],
      repos: ['opaque-monorepo-service'],
    })
    assert.equal(mappings.length, 1)
    assert.equal(mappings[0]!.origin, 'https://solo.example')
    assert.equal(mappings[0]!.confidence, 'single_origin')

    const { storage } = makeStore(t, 'kovo-single-origin-')
    const { runId } = await setupApprovedRun(storage, { seeds: ['https://solo.example'], tier: 2 })
    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = getPlanner(exec)

    const synthesis: SynthesizeInvariantsResult = {
      mode: 'white-box',
      hypotheses: [
        makeHyp({
          id: 'hyp_solo_1',
          entity: 'invoice',
          targetRoute: 'GET /api/invoices/:id',
          location: { file: 'opaque-monorepo-service/routes/invoices.ts', line: 12 },
        }),
      ],
      capabilitySeeds: [],
    }
    const createdIds = planner.promoteInvariantHypothesesToWave1ChainSteps(storage.run(runId), synthesis, {
      mountedRepos: ['opaque-monorepo-service'],
    })
    assert.equal(createdIds.length, 1, 'single-origin run must bind mounted repo hypothesis to the sole origin')
    const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
    assert.deepEqual(steps[0]!.sourceOrigins, ['https://solo.example'])
  })

  test('ExecReconPlanner.promoteInvariantHypothesesToWave1ChainSteps maps multi-repo hypotheses and skips unmapped instead of dumping onto approvedList[0]', async (t) => {
    const origins = [
      'https://academy.example',
      'https://dmail.example',
      'https://engine.example',
      'https://upload-image.example',
      'https://upload-logs.example',
    ]
    const { storage } = makeStore(t, 'kovo-multi-origin-wave1-')
    const { runId } = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = getPlanner(exec)

    const synthesis: SynthesizeInvariantsResult = {
      mode: 'white-box',
      hypotheses: [
        makeHyp({
          id: 'hyp_dmail',
          entity: 'message',
          targetRoute: 'GET /api/messages/:id',
          location: { file: 'dmail/src/routes/messages.ts', line: 22 },
        }),
        makeHyp({
          id: 'hyp_engine',
          entity: 'completion',
          targetRoute: 'POST /v1/completions',
          location: { file: 'llm-engine/src/server.ts', line: 45 },
        }),
        makeHyp({
          id: 'hyp_chat_upload',
          entity: 'transcript',
          targetRoute: 'POST /api/chat/upload',
          location: { file: 'chat-uploader/src/upload.ts', line: 18 },
        }),
        makeHyp({
          id: 'hyp_unmapped_1',
          entity: 'cronjob',
          targetRoute: 'POST /internal/cron/sync',
          location: { file: 'mystery-worker/src/sync.ts', line: 10 },
        }),
        makeHyp({
          id: 'hyp_unmapped_2',
          kind: 'trust_boundary_mismatch',
          entity: 'boundary',
          summary: 'Internal queue worker forwards untrusted metadata',
          location: { file: 'mystery-worker/src/worker.ts', line: 33 },
        }),
      ],
      capabilitySeeds: [],
    }

    const createdIds = planner.promoteInvariantHypothesesToWave1ChainSteps(storage.run(runId), synthesis, {
      mountedRepos: ['dmail', 'llm-engine', 'image-uploader', 'chat-uploader', 'mystery-worker'],
      maxSteps: 10,
    })

    const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
    assert.equal(createdIds.length, 3, 'only the 3 deterministically mapped repos should create Wave-1 steps')
    const originByEntity = new Map(steps.map(s => [s.title.includes('message') ? 'message' : s.title.includes('completion') ? 'completion' : 'transcript', s.sourceOrigins]))
    assert.deepEqual(originByEntity.get('message'), ['https://dmail.example'])
    assert.deepEqual(originByEntity.get('completion'), ['https://engine.example'])
    assert.deepEqual(originByEntity.get('transcript'), ['https://upload-logs.example'])
    assert.equal(
      steps.filter(s => s.sourceOrigins.includes('https://academy.example')).length,
      0,
      'approvedList[0] (academy.example) must receive ZERO misattributed steps from unmapped repos',
    )
    const events = storage.eventsAfter(runId, 0, 50)
    const skippedEvent = events.find(e => e.kind === 'invariants.unmapped_origin_skipped')
    assert.ok(skippedEvent, 'must emit invariants.unmapped_origin_skipped telemetry event')
    assert.equal((skippedEvent.detail as { unmappedCount?: number }).unmappedCount, 2)
  })
})

describe('P1 #4a: Edge-Protected & Dead Host Quarantine', () => {
  test('detectQuarantinedOrigins quarantines Phase-0 edgeProtectedOrigins, skippedDeadHosts, uniform 401-walls, and 525-only hosts when 0 personas exist', () => {
    const approved = [
      'https://live-app.example',
      'https://edge-wall.example',
      'https://dead-525.example',
      'https://telemetry-401.example',
      'https://telemetry-525.example',
    ]

    const resNoPersonas = detectQuarantinedOrigins({
      approvedOrigins: approved,
      edgeProtectedOrigins: [{ origin: 'https://edge-wall.example', reason: 'Cloudflare Access 401 wall', status: 401, requestsUsed: 3 }],
      skippedDeadHosts: [{ origin: 'https://dead-525.example', reason: '525 SSL handshake failed', requestsUsed: 2 }],
      observedExchanges: [
        { origin: 'https://live-app.example', status: 200, pathAndQuery: '/' },
        { origin: 'https://live-app.example', status: 401, pathAndQuery: '/api/admin' },
        { origin: 'https://telemetry-401.example', status: 401, pathAndQuery: '/' },
        { origin: 'https://telemetry-401.example', status: 401, pathAndQuery: '/api/health' },
        { origin: 'https://telemetry-525.example', status: 525, pathAndQuery: '/' },
      ],
      personas: [],
    })

    assert.deepEqual(resNoPersonas.activeOrigins, ['https://live-app.example'])
    assert.equal(resNoPersonas.quarantined.get('https://edge-wall.example')?.reason, 'edge_protected')
    assert.equal(resNoPersonas.quarantined.get('https://dead-525.example')?.reason, 'unreachable')
    assert.equal(resNoPersonas.quarantined.get('https://telemetry-401.example')?.reason, 'edge_protected')
    assert.equal(resNoPersonas.quarantined.get('https://telemetry-525.example')?.reason, 'unreachable')

    // Supplying an authenticated persona for edge-wall.example releases ONLY that edge-protected host;
    // dead-525.example stays unreachable.
    const resWithPersona = detectQuarantinedOrigins({
      approvedOrigins: approved,
      edgeProtectedOrigins: ['https://edge-wall.example'],
      skippedDeadHosts: [{ origin: 'https://dead-525.example', reason: '525 SSL handshake failed', requestsUsed: 2 }],
      personas: [{ handle: 'alice', originAllowlist: ['https://edge-wall.example'] }],
    })
    assert.ok(resWithPersona.activeOrigins.includes('https://edge-wall.example'), 'authenticated persona unlocks edge_protected origin')
    assert.ok(!resWithPersona.activeOrigins.includes('https://dead-525.example'), 'dead 525 host stays quarantined even with personas')
  })

  test('ExecReconPlanner records a single structured coverage gap per quarantined host and blocks Wave-1 / high-risk steps on quarantined origins', async (t) => {
    const liveA = 'https://app-live.example'
    const liveB = 'https://api-live.example'
    const edgeWall = 'https://gated-edge.example'
    const deadHost = 'https://broken-525.example'

    const { storage } = makeStore(t, 'kovo-quarantine-gaps-')
    const { runId } = await setupApprovedRun(storage, { seeds: [edgeWall, deadHost, liveA, liveB], tier: 2 })
    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = getPlanner(exec)
    const run = storage.run(runId)

    // Quarantine edgeWall and deadHost (call twice to prove single idempotent coverage gap per host).
    planner.refreshQuarantinedOriginsFromPhase0(run, {
      edgeProtectedOrigins: [{ origin: edgeWall, reason: 'uniform 401 Access wall', status: 401, requestsUsed: 4 }],
      skippedDeadHosts: [{ origin: deadHost, reason: 'HTTP 525 SSL handshake failed', requestsUsed: 2 }],
    })
    planner.refreshQuarantinedOriginsFromPhase0(run, {
      edgeProtectedOrigins: [{ origin: edgeWall, reason: 'uniform 401 Access wall', status: 401, requestsUsed: 4 }],
      skippedDeadHosts: [{ origin: deadHost, reason: 'HTTP 525 SSL handshake failed', requestsUsed: 2 }],
    })

    const coverage = storage.listCoverageEntries(runId, run.goalRevision)
    assert.equal(coverage.length, 2, 'must record exactly 1 structured coverage gap per quarantined host')
    const edgeGap = coverage.find(c => c.origin === edgeWall)
    const deadGap = coverage.find(c => c.origin === deadHost)
    assert.equal(edgeGap?.proofGapReason, 'edge_protected')
    assert.equal(edgeGap?.status, 'needs_follow_up')
    assert.equal(deadGap?.proofGapReason, 'unreachable')
    assert.equal(deadGap?.status, 'needs_follow_up')

    // Wave-1 invariant promotion must skip quarantined hosts and emit only live-origin steps.
    const synthesis: SynthesizeInvariantsResult = {
      mode: 'white-box',
      hypotheses: [
        makeHyp({ id: 'hyp_edge', serviceOrigin: edgeWall, entity: 'edge_admin', targetRoute: 'GET /admin' }),
        makeHyp({ id: 'hyp_dead', serviceOrigin: deadHost, entity: 'dead_sync', targetRoute: 'POST /sync' }),
        makeHyp({ id: 'hyp_live_a', serviceOrigin: liveA, entity: 'order', targetRoute: 'GET /api/orders/:id' }),
      ],
      capabilitySeeds: [],
    }
    const wave1Ids = planner.promoteInvariantHypothesesToWave1ChainSteps(storage.run(runId), synthesis)
    assert.equal(wave1Ids.length, 1, 'only live reachable origin should receive a Wave-1 step')
    const wave1Steps = storage.listChainSteps(runId, run.goalRevision)
    assert.deepEqual(wave1Steps[0]!.sourceOrigins, [liveA])

    // High-risk endpoint coverage seeding must also skip quarantined hosts and concentrate on liveA & liveB.
    for (const [origin, path] of [
      [edgeWall, '/api/gated/users/:id'],
      [deadHost, '/api/dead/billing/:id'],
      [liveA, '/api/live-a/accounts/:id'],
      [liveB, '/api/live-b/tokens/:id'],
    ] as const) {
      storage.upsertEndpoint({
        runId: run.id,
        scopeRevision: run.scopeRevision,
        origin,
        method: 'GET',
        pathTemplate: path,
        riskScore: 95,
        source: 'spa_crawl',
      })
    }
    const seeded = planner.queueHighRiskCoverageSteps(
      storage.run(runId),
      new Set([edgeWall, deadHost, liveA, liveB]),
      20,
      storage.listChainSteps(runId, run.goalRevision),
      6,
    )
    assert.equal(seeded.seeded, 2)
    const allSteps = storage.listChainSteps(runId, run.goalRevision)
    for (const step of allSteps) {
      assert.ok(!step.sourceOrigins.includes(edgeWall), 'quarantined edge_protected host must never receive investigation steps')
      assert.ok(!step.sourceOrigins.includes(deadHost), 'quarantined unreachable host must never receive investigation steps')
    }

    // FrontierDispatcher wired to ExecReconPlanner also excludes quarantined steps at dispatch time.
    const readySteps: DispatchLaneStep[] = [
      { id: 's-edge', seq: 1, priority: 99, title: 'Edge step', sourceOrigins: [edgeWall] },
      { id: 's-dead', seq: 2, priority: 98, title: 'Dead step', sourceOrigins: [deadHost] },
      { id: 's-live-a', seq: 3, priority: 80, title: 'Live A step', sourceOrigins: [liveA] },
      { id: 's-live-b', seq: 4, priority: 79, title: 'Live B step', sourceOrigins: [liveB] },
    ]
    const plan = planner.frontierDispatcherFor(runId).dispatch(readySteps, 4)
    assert.deepEqual(plan.ordered.map(s => s.id), ['s-live-a', 's-live-b'])
  })
})

describe('P1 #4a: Per-Origin Soft Fairness / Concentration Guard (<= 50%)', () => {
  test('applyCrownJewelStepBudget prevents origin[0] from monopolizing >50% of queued steps across live sibling origins', () => {
    const origin0 = 'https://api-alpha.example'
    const origin1 = 'https://api-beta.example'
    const origin2 = 'https://api-gamma.example'

    const candidates = [
      // 8 higher-priority steps all on origin[0]
      ...Array.from({ length: 8 }, (_, i) => ({
        title: `Alpha route ${i + 1}`,
        priority: 95 - i,
        origins: [origin0],
      })),
      // 4 slightly lower-priority steps on sibling live origins
      ...Array.from({ length: 4 }, (_, i) => ({
        title: `Beta route ${i + 1}`,
        priority: 82 - i,
        origins: [origin1],
      })),
      ...Array.from({ length: 4 }, (_, i) => ({
        title: `Gamma route ${i + 1}`,
        priority: 80 - i,
        origins: [origin2],
      })),
    ]

    const hostTiers = {
      [origin0]: 'crown_jewel' as const,
      [origin1]: 'crown_jewel' as const,
      [origin2]: 'standard' as const,
    }

    const selected = applyCrownJewelStepBudget(candidates, hostTiers, [], 8)
    assert.equal(selected.length, 8)
    const count0 = selected.filter(s => s.origins[0] === origin0).length
    const countSiblings = selected.filter(s => s.origins[0] !== origin0).length
    assert.ok(count0 <= 4, `origin[0] must not exceed 50% (4/8), got ${count0}/8`)
    assert.ok(countSiblings >= 4, `sibling live origins must receive >= 50% (4/8), got ${countSiblings}/8`)
  })

  test('selectUncoveredHighRiskEndpoints and dispatchFrontierWave enforce <=50% per-origin fairness with soft backfill', () => {
    const origin0 = 'https://app0.example'
    const origin1 = 'https://app1.example'
    const origin2 = 'https://app2.example'
    const approved = new Set([origin0, origin1, origin2])

    const resourceNames = ['invoices', 'orders', 'users', 'tokens', 'exports', 'billing']
    const endpoints = [
      ...resourceNames.map((name, i) => ({
        origin: origin0,
        method: 'POST',
        pathTemplate: `/api/a/${name}`,
        riskScore: 98 - i,
      })),
      ...resourceNames.slice(0, 4).map((name, i) => ({
        origin: origin1,
        method: 'POST',
        pathTemplate: `/api/b/${name}`,
        riskScore: 86 - i,
      })),
      ...resourceNames.slice(0, 4).map((name, i) => ({
        origin: origin2,
        method: 'POST',
        pathTemplate: `/api/c/${name}`,
        riskScore: 84 - i,
      })),
    ]

    const pickedEndpoints = selectUncoveredHighRiskEndpoints({
      endpoints,
      approvedOrigins: approved,
      confirmedPaths: new Set(),
      coveredRoutes: new Set(),
      limit: 6,
    })
    assert.equal(pickedEndpoints.length, 6)
    const epCount0 = pickedEndpoints.filter(e => e.origin === origin0).length
    assert.ok(epCount0 <= 3, `origin[0] must not exceed 50% of high-risk picks (3/6), got ${epCount0}/6`)

    const dispatchSteps: DispatchLaneStep[] = [
      ...Array.from({ length: 6 }, (_, i) => ({
        id: `a-${i + 1}`,
        seq: i + 1,
        priority: 95 - i,
        title: `Route check A-${i + 1}`,
        sourceOrigins: [origin0],
        lane: 'route' as const,
      })),
      ...Array.from({ length: 4 }, (_, i) => ({
        id: `b-${i + 1}`,
        seq: 10 + i,
        priority: 85 - i,
        title: `Route check B-${i + 1}`,
        sourceOrigins: [origin1],
        lane: 'route' as const,
      })),
    ]
    const wave = dispatchFrontierWave(dispatchSteps, 6)
    assert.equal(wave.ordered.length, 6)
    const waveCount0 = wave.ordered.filter(s => s.sourceOrigins?.[0] === origin0).length
    assert.ok(waveCount0 <= 3, `origin[0] must not exceed 50% of dispatched wave (3/6), got ${waveCount0}/6`)

    // Soft backfill: when sibling origin has only 1 item and limit is 6, remaining slots backfill instead of idling.
    const softItems = [
      { id: 'x1', origin: origin0 },
      { id: 'x2', origin: origin0 },
      { id: 'x3', origin: origin0 },
      { id: 'x4', origin: origin0 },
      { id: 'x5', origin: origin0 },
      { id: 'y1', origin: origin1 },
    ]
    const backfilled = enforcePerOriginFairness(softItems, {
      limit: 6,
      originOf: item => item.origin,
    })
    assert.equal(backfilled.length, 6, 'soft backfill must fill unused slots when sibling origins are exhausted')
    assert.ok(backfilled.some(item => item.id === 'y1'), 'sibling item must still be selected before backfill')
  })
})
