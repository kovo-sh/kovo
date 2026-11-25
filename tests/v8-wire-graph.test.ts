/**
 * v8 M0/M2/M3 Graph & Orchestrator Wiring Integration Suite.
 *
 * End-to-end verification (real Store SQLite WAL DB, zero Docker, zero benchmark literals):
 *  1. `Store` initializes CapabilityLedger schema at startup & exposes run-scoped
 *     `store.capabilityLedger(runId)` bound to the shared WAL `DatabaseSync` handle (no extra connection).
 *  2. `PAIR_WEIGHTS`, `THREE_HOP_SETS`, and `FOUR_HOP_SETS` are retired from `graph-coordinator.ts`,
 *     and zero v8 benchmark literals appear in our wired `src/server/` modules.
 *  3. `ExecReconPlanner.seedCapabilityLedgerInvariants` wires `synthesizeInvariants` /
 *     `inferRuntimeInvariantHypotheses` / `toCapabilityLedgerSeeds` in BOTH white-box (mounted source:
 *     Entity x Surface Guard Asymmetries, Cross-Service Trust Boundaries, Entity Lifecycle Slices)
 *     and grey-box/black-box runtime parity modes, seeding strictly quarantined `capability_only` nodes.
 *  4. `planChainRound` executes `CapabilityLedger` + `FrontierScheduler` causal frontier planning
 *     (depth 1..6, exact EVI beam ranking, `capability_only` quarantine respect, negative-edge
 *     dead-end filtering, and strictly bounded <= 2 KB hop-checkpoint briefs).
 *  5. `FrontierWaveController` + `coordinatorSchedulerDecision` + `nextPlannerDryRounds` enforce:
 *     - Frontier-progress termination (continue when verified `HopReceipt` expands reach even
 *       before terminal confirmation),
 *     - 2-strike dead-end pruning persisted as negative edges in `CapabilityLedger` and suppressed
 *       from follow-on `planChainRound` and wave selections,
 *     - Pre-hydrated `<= 2 KB` hop-checkpoint briefs on depth `>= 2` assignments.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  CapabilityLedgerError,
  computeArtifactDigest,
  formatDerivedCapabilityHandle,
} from '../src/server/capability-ledger.ts'
import {
  DRY_ROUND_LIMIT,
  FrontierWaveController,
  ReinvestigationGuard,
  chainHypothesisDispatchSteps,
  coordinatorSchedulerDecision,
  formatHopCheckpointForAssignment,
  nextPlannerDryRounds,
} from '../src/server/exec-dispatch.ts'
import {
  ExecReconPlanner,
  seedRecordToLedgerInput,
  type ExecReconPlannerHost,
} from '../src/server/exec-recon-planner.ts'
import {
  FrontierScheduler,
  MAX_CHECKPOINT_BRIEF_BYTES,
  type FrontierBranch,
  type VerifiedHopHandle,
} from '../src/server/frontier-scheduler.ts'
import {
  createGraphCoordinator,
  planChainRound,
  type ChainPrimitive,
  type CoordinatorEndpoint,
} from '../src/server/graph-coordinator.ts'
import {
  synthesizeInvariants,
  toCapabilityLedgerSeeds,
  type SourceFileInput,
} from '../src/server/invariant-synthesizer.ts'
import { ProbePlanRegistry } from '../src/server/probe-plan.ts'
import { extractProgramGraph } from '../src/server/program-graph.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN_APP = 'https://app.wire-synth.invalid'
const ORIGIN_API = 'https://api.wire-synth.invalid'
const ORIGIN_EDGE = 'https://edge.wire-synth.invalid'

const SYNTH_MULTISERVICE_SOURCE: readonly SourceFileInput[] = [
  {
    path: 'services/edge/src/proxy.ts',
    content: [
      "import { Router } from 'express'",
      'export const edgeRouter = Router()',
      "edgeRouter.post('/v1/transfers', async (req: any, res: any) => {",
      "  const actor = req.headers['x-internal-actor']",
      "  const tenant = req.headers['x-tenant-id'] || 'default-org'",
      '  const raw = JSON.parse(req.rawBody)',
      "  const upstream = await fetch(process.env.API_URL + '/internal/transfers', {",
      "    method: 'POST',",
      "    headers: { 'x-internal-actor': actor, 'x-tenant-id': tenant },",
      '    body: JSON.stringify(raw),',
      '  })',
      "  res.setHeader('Cache-Control', 'public, max-age=60')",
      '  res.json(await upstream.json())',
      '})',
    ].join('\n'),
  },
  {
    path: 'services/api/src/transfers.ts',
    content: [
      "import { Router } from 'express'",
      "import { requireAuth, requireTenantScope, requireAdmin, checkRevokedToken } from './guards'",
      'export const transfersRouter = Router()',
      "transfersRouter.get('/api/transfers/:id', requireAuth, requireTenantScope, checkRevokedToken, getTransfer)",
      "transfersRouter.post('/api/transfers/batch', requireAuth, batchTransfers)",
      "transfersRouter.post('/api/transfers/:id/approve', requireAuth, requireAdmin, approveTransfer)",
      "transfersRouter.post('/api/transfers/:id/refund', requireAuth, refundTransfer)",
      'export async function getTransfer(req: any, res: any) {',
      "  const row = await db.query('SELECT * FROM transfers WHERE id = $1', [req.params.id])",
      '  res.json(row)',
      '}',
      'export async function batchTransfers(req: any, res: any) {',
      '  const rows = await Promise.all(req.body.ids.map((id: string) => db.findOne(id)))',
      '  res.json(rows)',
      '}',
      'export async function approveTransfer(req: any, res: any) {',
      '  const transfer = await db.findOne(req.params.id)',
      '  transfer.createdBy = req.user.id',
      "  transfer.status = 'approved'",
      '  res.json(transfer)',
      '}',
      'export async function refundTransfer(req: any, res: any) {',
      '  const wallet = await db.findOne(req.params.id)',
      '  wallet.balance += req.body.amount',
      "  wallet.status = 'settled'",
      '  res.json(wallet)',
      '}',
    ].join('\n'),
  },
  {
    path: 'services/worker/src/stream.ts',
    content: [
      "import { Router } from 'express'",
      'export const streamRouter = Router()',
      "streamRouter.get('/sse/transfers/events', async (req: any, res: any) => {",
      "  res.setHeader('Content-Type', 'text/event-stream')",
      "  const rows = await db.query('SELECT * FROM transfers')",
      '  res.write(JSON.stringify(rows))',
      '})',
    ].join('\n'),
  },
]

function makePlanner(
  storage: ReturnType<typeof makeStore>['storage'],
  opts: { mountedRepos?: string[]; reposDir?: string } = {},
): ExecReconPlanner {
  const host: ExecReconPlannerHost = {
    storage,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    browser: {} as ExecReconPlannerHost['browser'],
    canaryBroker: new CanaryBroker(),
    backend: {} as ExecReconPlannerHost['backend'],
    labRunner: {} as ExecReconPlannerHost['labRunner'],
    maxDurationMs: 0,
    active: new Map(),
    coordinator: new Map(),
    probePlans: new ProbePlanRegistry(),
    startedLabRuns: new Set(),
    startedLabHandles: new Map(),
    prePhase0SeededSteps: new Map(),
    plannerDoneRound: new Map(),
    dispatchFunnels: new Map(),
    detLeadConsumed: new Set(),
    tierAStepIds: new Set(),
    tierAFactIds: new Set(),
    approvedOriginsSet: run => new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin)),
    authorize: () => true,
    currentCoordinator: () => true,
    buildGrant: () => ({ grant: { personas: new Map() } as never, secrets: [], currentSecrets: () => [] }),
    projectReposMount: () => ({
      ...(opts.reposDir ? { reposDir: opts.reposDir } : {}),
      mountedRepos: opts.mountedRepos ?? [],
    }),
    deterministicLaneKey: run => `${run.id}:${run.goalRevision}`,
    notifyCheckpoint: () => undefined,
    seedCodeToRuntimeLeads: () => 0,
    correlateSpecDependencies: async () => undefined,
    runSourceFirstCodeAudit: async () => ({ suspects: [], stepsCreated: [] }),
    baselineFinding: () => undefined,
    saveBaselineFinding: () => undefined,
    completeWorker: () => undefined,
    expandEligibleMultiTrialSteps: () => undefined,
    endpointGraphCatalog: () => ({ endpointParams: [], apiDependencies: [] }),
    noteDryStreak: () => undefined,
    reinvestigationGuardFor: () => new ReinvestigationGuard(),
    highPriorityQueueEmpty: () => false,
    noteCappedReinvestigation: () => undefined,
    recordDispatchFunnel: () => undefined,
    noteStrandedReadySteps: () => undefined,
    tracePlannerDecision: () => undefined,
    codeSliceForAssignment: () => undefined,
    shouldCoordinatorAnswer: () => false,
    resetBoardHops: () => undefined,
  }
  return new ExecReconPlanner(host)
}

describe('v8 M0/M2/M3 Graph & Orchestrator Wiring', () => {
  test('v7 flat chainer tables (PAIR_WEIGHTS / THREE_HOP_SETS / FOUR_HOP_SETS) are retired & zero benchmark literals exist', () => {
    const coordinatorSrc = readFileSync(join(repoRoot, 'src/server/graph-coordinator.ts'), 'utf8')
    assert.equal(coordinatorSrc.includes('PAIR_WEIGHTS'), false, 'PAIR_WEIGHTS must be retired from graph-coordinator.ts')
    assert.equal(coordinatorSrc.includes('THREE_HOP_SETS'), false, 'THREE_HOP_SETS must be retired from graph-coordinator.ts')
    assert.equal(coordinatorSrc.includes('FOUR_HOP_SETS'), false, 'FOUR_HOP_SETS must be retired from graph-coordinator.ts')

    // Zero benchmark contamination across our wired src/server/ files.
    const forbidden = [
      ['pay', 'grid'].join(''),
      ['ship', 'forge'].join(''),
      ['nexus', 'iam'].join(''),
      ['connect', 'hub'].join(''),
      ['vault', '.internal'].join(''),
      ['registry', '.internal'].join(''),
      ['billing', '.internal'].join(''),
      'PG-C', 'SF-C', 'NX-C', 'CH-C',
    ]
    for (const rel of [
      'src/server/store.ts',
      'src/server/graph-coordinator.ts',
      'src/server/exec-recon-planner.ts',
      'src/server/exec-dispatch.ts',
    ]) {
      const text = readFileSync(join(repoRoot, rel), 'utf8').toLowerCase()
      for (const token of forbidden) {
        assert.equal(text.includes(token.toLowerCase()), false, `${rel} must not contain benchmark literal '${token}'`)
      }
    }
  })

  test('Store initializes CapabilityLedger schema on startup and exposes WAL-safe shared-handle store.capabilityLedger(runId)', async (t) => {
    const { storage } = makeStore(t, 'kovo-v8-wire-store-')
    const tables = (storage.client.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'capability_%' ORDER BY name",
    ).all() as Array<{ name: string }>).map(r => r.name)
    assert.deepEqual(tables, ['capability_causal_edges', 'capability_negative_edges', 'capability_nodes'])

    const journal = storage.client.prepare('PRAGMA journal_mode').get() as { journal_mode: string }
    assert.equal(journal.journal_mode.toLowerCase(), 'wal')

    const ledgerA = storage.capabilityLedger('run-wire-a')
    const ledgerB = storage.capabilityLedger('run-wire-b')
    assert.equal(ledgerA.db, storage.client, 'CapabilityLedger must bind directly to Store DatabaseSync handle')
    assert.equal(ledgerB.db, storage.client)

    const capId = formatDerivedCapabilityHandle('w1', 'session_a')
    ledgerA.addCapability({
      capId,
      kind: 'identity_session',
      provenance: 'attacker_seed',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: ORIGIN_APP,
      surface: 'http',
      artifactDigest: computeArtifactDigest('seed-session-a'),
      artifactSummary: 'Attacker baseline session on app origin',
    })
    assert.equal(ledgerA.listCapabilities().length, 1)
    assert.equal(ledgerB.listCapabilities().length, 0, 'run-scoped ledgers must stay isolated by runId')

    // Closing a run-scoped ledger view must NOT close Store's shared connection.
    ledgerA.close()
    assert.equal(storage.capabilityLedger('run-wire-a').getCapability(capId)?.capId, capId)
  })

  test('End-to-end: Store -> synthesizeInvariants -> CapabilityLedger -> depth-4 causal planChainRound -> 2-strike negative-edge suppression -> <= 2 KB hop-checkpoint brief', async (t) => {
    const { storage } = makeStore(t, 'kovo-v8-wire-e2e-')
    const setup = await setupApprovedRun(storage, { seeds: [ORIGIN_EDGE, ORIGIN_API, ORIGIN_APP], tier: 2 })
    const run = storage.run(setup.runId)
    const planner = makePlanner(storage, { mountedRepos: ['synth-saas'] })

    // 1. White-box synthesis via ExecReconPlanner seeds quarantined capability_only nodes across all 3 analyzers.
    const graph = extractProgramGraph({ files: SYNTH_MULTISERVICE_SOURCE, repo: 'synth-saas' })
    const wbSeed = planner.seedCapabilityLedgerInvariants(run, {
      mode: 'white-box',
      graph,
      sourceFiles: SYNTH_MULTISERVICE_SOURCE,
      serviceOrigins: [
        { service: 'edge', root: 'services/edge', origin: ORIGIN_EDGE, confidence: 'exact', evidence: ['test'] },
        { service: 'api', root: 'services/api', origin: ORIGIN_API, confidence: 'exact', evidence: ['test'] },
        { service: 'worker', root: 'services/worker', origin: ORIGIN_APP, confidence: 'exact', evidence: ['test'] },
      ],
      approvedOrigins: new Set([ORIGIN_EDGE, ORIGIN_API, ORIGIN_APP]),
    })
    assert.equal(wbSeed.mode, 'white-box')
    assert.ok(wbSeed.seededCount >= 3, `expected >= 3 synthesized capability seeds, got ${wbSeed.seededCount}`)
    assert.ok((wbSeed.synthesis.guardMatrix?.hypotheses.length ?? 0) >= 1, 'expected Entity x Surface guard asymmetry')
    assert.ok((wbSeed.synthesis.trustBoundaries?.hypotheses.length ?? 0) >= 1, 'expected Cross-Service trust boundary')
    assert.ok((wbSeed.synthesis.lifecycleSlices?.slices.length ?? 0) >= 1, 'expected Entity lifecycle slice')

    const ledger = storage.capabilityLedger(run.id)
    const seededNodes = ledger.listCapabilities()
    assert.ok(seededNodes.length >= wbSeed.seededCount)
    assert.ok(
      seededNodes.every(n => n.promotionStatus === 'capability_only'),
      'all synthesized invariant nodes must remain strictly quarantined as capability_only',
    )
    // Verify standalone quarantine holds via assertPromotable.
    for (const node of seededNodes.slice(0, 3)) {
      assert.throws(() => ledger.assertPromotable(node.capId, false), CapabilityLedgerError)
    }

    // Re-running synthesis is idempotent (0 duplicates).
    const wbRepeat = planner.seedCapabilityLedgerInvariants(run, {
      mode: 'white-box',
      graph,
      sourceFiles: SYNTH_MULTISERVICE_SOURCE,
      approvedOrigins: new Set([ORIGIN_EDGE, ORIGIN_API, ORIGIN_APP]),
    })
    assert.equal(wbRepeat.seededCount, 0, 'repeat synthesis seeding must be idempotent')

    // Also verify standalone synthesizeInvariants + toCapabilityLedgerSeeds -> seedRecordToLedgerInput round-trip.
    const directSynth = synthesizeInvariants({ mode: 'white-box', graph, sourceFiles: SYNTH_MULTISERVICE_SOURCE })
    const directSeeds = toCapabilityLedgerSeeds(directSynth.hypotheses)
    assert.ok(directSeeds.length >= 3)
    const adapted = seedRecordToLedgerInput(directSeeds[0]!, ORIGIN_API)
    assert.equal(adapted.promotionStatus, 'capability_only')
    assert.match(adapted.capId, /^cap:hop_synth:/)

    // 2. Build a real 4-hop causal DAG in Store's CapabilityLedger (depth 4 across 4 typed bindings).
    const c1 = formatDerivedCapabilityHandle('e2e1', 'attacker_session')
    const c2 = formatDerivedCapabilityHandle('e2e2', 'leaked_signer')
    const c3 = formatDerivedCapabilityHandle('e2e3', 'forged_webhook_token')
    const c4 = formatDerivedCapabilityHandle('e2e4', 'cross_tenant_payout_state')

    ledger.addCapability({
      capId: c1,
      kind: 'identity_session',
      provenance: 'attacker_seed',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: ORIGIN_EDGE,
      surface: 'http',
      artifactDigest: computeArtifactDigest('hop1-session'),
      artifactSummary: 'Attacker baseline session on edge ingress',
      metadata: { endpoint: '/v1/transfers', method: 'POST' },
      createdAtMs: 1000,
    })
    ledger.addCapability({
      capId: c2,
      kind: 'signing_material',
      provenance: 'derived_hop',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: ORIGIN_APP,
      surface: 'sse',
      parentHopReceiptIds: ['hop_rcpt_1'],
      artifactDigest: computeArtifactDigest('hop2-signing-salt'),
      artifactSummary: 'Derived signing handle from unrevoked SSE stream',
      metadata: { endpoint: '/sse/transfers/events', method: 'GET' },
      createdAtMs: 2000,
    })
    ledger.addCapability({
      capId: c3,
      kind: 'signed_artifact_or_url',
      provenance: 'derived_hop',
      tenantScope: 'org_b',
      actorPersona: 'member_a',
      serviceOrigin: ORIGIN_API,
      surface: 'webhook',
      parentHopReceiptIds: ['hop_rcpt_2'],
      artifactDigest: computeArtifactDigest('hop3-signed-webhook'),
      artifactSummary: 'Scope-replayed signed settlement callback handle',
      metadata: { endpoint: '/api/transfers/batch', method: 'POST' },
      createdAtMs: 3000,
    })
    ledger.addCapability({
      capId: c4,
      kind: 'state_handle',
      provenance: 'derived_hop',
      tenantScope: 'org_b',
      actorPersona: 'member_a',
      serviceOrigin: ORIGIN_API,
      surface: 'async_job',
      parentHopReceiptIds: ['hop_rcpt_3'],
      artifactDigest: computeArtifactDigest('hop4-payout-approval'),
      artifactSummary: 'Maker-checker overwritten transfer approval state handle',
      metadata: {
        endpoint: '/api/transfers/:id/approve',
        method: 'POST',
        targetSurfaceKey: `${ORIGIN_API}|async_job|/api/transfers/:id/approve`,
        hypothesisKind: 'lifecycle_invariant',
      },
      createdAtMs: 4000,
    })

    ledger.addCausalEdge({
      edgeId: 'e2e_edge_1',
      preconditionCapIds: [c1],
      actorContext: { persona: 'member_a', tenantScope: 'org_a', roleLabel: 'member' },
      hopReceiptId: 'hop_rcpt_1',
      edgeBindingKind: 'value_binding',
      postconditionCapId: c2,
      sourceTimestampMs: 1000,
      targetTimestampMs: 2000,
    })
    ledger.addCausalEdge({
      edgeId: 'e2e_edge_2',
      preconditionCapIds: [c2],
      actorContext: { persona: 'member_a', tenantScope: 'org_a', roleLabel: 'member' },
      hopReceiptId: 'hop_rcpt_2',
      edgeBindingKind: 'derived_crypto_binding',
      postconditionCapId: c3,
      sourceTimestampMs: 2000,
      targetTimestampMs: 3000,
    })
    ledger.addCausalEdge({
      edgeId: 'e2e_edge_3',
      preconditionCapIds: [c3],
      actorContext: { persona: 'member_a', tenantScope: 'org_b', roleLabel: 'viewer' },
      hopReceiptId: 'hop_rcpt_3',
      edgeBindingKind: 'state_transition_binding',
      postconditionCapId: c4,
      sourceTimestampMs: 3000,
      targetTimestampMs: 4000,
    })

    // 3. Plan depth-4 causal frontier via planChainRound backed by CapabilityLedger + FrontierScheduler.
    const scheduler = new FrontierScheduler({ beamWidth: 12 })
    const planned = planChainRound({
      primitives: [],
      endpoints: [
        { id: 'ep-approve', origin: ORIGIN_API, method: 'POST', pathTemplate: '/api/transfers/:id/approve', roleExclusive: true },
      ],
      maxHops: 4,
      limit: 12,
      approvedOrigins: [ORIGIN_EDGE, ORIGIN_API, ORIGIN_APP],
      capabilityLedger: ledger,
      frontierScheduler: scheduler,
      waveNo: 2,
    })
    const depth4 = planned.find(h => h.hops === 4 && h.capabilityIds?.includes(c4))
    assert.ok(depth4, `expected depth-4 causal chain reaching ${c4}, got hops=${planned.map(h => h.hops).join(',')}`)
    assert.deepEqual(depth4!.capabilityIds, [c1, c2, c3, c4])
    assert.deepEqual(depth4!.edgeBindingKinds, ['value_binding', 'derived_crypto_binding', 'state_transition_binding'])
    assert.ok((depth4!.evi ?? 0) > 0, 'expected exact EVI score on planned frontier hypothesis')
    assert.ok(depth4!.checkpointBrief, 'expected pre-hydrated HopCheckpointBrief on depth-4 hypothesis')
    assert.equal(depth4!.checkpointBrief!.doNotRediscover, true)
    assert.ok(
      (depth4!.checkpointBytes ?? Infinity) <= MAX_CHECKPOINT_BRIEF_BYTES,
      `checkpoint brief must be <= ${MAX_CHECKPOINT_BRIEF_BYTES} bytes, got ${depth4!.checkpointBytes}`,
    )
    assert.equal(Buffer.byteLength(depth4!.checkpointJson!, 'utf8'), depth4!.checkpointBytes)

    // Dispatch conversion preserves <= 2 KB checkpoint brief on depth >= 2 steps.
    const dispatchSteps = chainHypothesisDispatchSteps([depth4!])
    assert.equal(dispatchSteps.length, 1)
    assert.ok(dispatchSteps[0]!.checkpointBrief)
    assert.ok(Buffer.byteLength(dispatchSteps[0]!.checkpointJson!, 'utf8') <= MAX_CHECKPOINT_BRIEF_BYTES)

    // Quarantined depth-1 capability_only nodes are NEVER promoted as standalone 1-hop hypotheses.
    const depth1Only = planChainRound({
      primitives: [],
      minHops: 1,
      maxHops: 1,
      approvedOrigins: [ORIGIN_EDGE, ORIGIN_API, ORIGIN_APP],
      capabilityLedger: ledger,
    })
    assert.equal(depth1Only.length, 0, 'quarantined capability_only nodes must never be emitted as standalone 1-hop hypotheses')

    // 4. 2-strike dead-end pruning via FrontierWaveController writes negative edge to CapabilityLedger
    //    and suppresses the pruned branch on subsequent planChainRound & selectNextWave calls.
    const controller = planner.frontierControllerFor(run.id, { beamWidth: 10 })
    const branchToPrune: FrontierBranch = {
      branchKey: depth4!.branchKey!,
      depth: 4,
      verifiedHops: [c1, c2, c3, c4].map((capId, idx): VerifiedHopHandle => ({
        hopIndex: idx + 1,
        hopReceiptId: `hop_rcpt_${idx}`,
        capabilityId: capId,
        kind: idx === 0 ? 'identity_session' : idx === 1 ? 'signing_material' : idx === 2 ? 'signed_artifact_or_url' : 'state_handle',
        surface: idx === 0 ? 'http' : idx === 1 ? 'sse' : idx === 2 ? 'webhook' : 'async_job',
        serviceOrigin: idx === 0 ? ORIGIN_EDGE : idx === 1 ? ORIGIN_APP : ORIGIN_API,
        tenantScope: idx < 2 ? 'org_a' : 'org_b',
        actorPersona: 'member_a',
        endpoint: idx === 3 ? '/api/transfers/:id/approve' : `/step/${idx + 1}`,
        method: 'POST',
      })),
      nextTarget: {
        targetSurfaceKey: `${ORIGIN_API}|async_job|/api/transfers/:id/approve`,
        surface: 'async_job',
        serviceOrigin: ORIGIN_API,
        endpoint: '/api/transfers/:id/approve',
        method: 'POST',
        hypothesisClass: 'lifecycle_invariant',
        goalSummary: 'Attempt approval pivot on hardened twin',
      },
      feasibilityProb: 0.85,
      terminalImpactWeight: 9,
      surfaceNovelty: 1.8,
      attemptsOnBranch: 0,
      consecutiveFailedAttempts: 0,
      createdWave: 2,
      lastUpdatedWave: 2,
    }
    assert.equal(controller.admitBranch(branchToPrune), true)

    // Strike 1: recorded in CapabilityLedger (not pruned yet).
    const s1 = controller.recordPivotOutcome({
      branchKey: branchToPrune.branchKey,
      targetSurfaceKey: branchToPrune.nextTarget.targetSurfaceKey,
      hypothesisClass: 'lifecycle_invariant',
      status: 'failed',
      waveNo: 2,
      failureReason: 'invariant_enforced_hardened',
      falsifiedByExchangeIds: ['ex_hardened_1'],
    })
    assert.equal(s1.pruned, false)
    assert.equal(s1.ledgerNegativeEdge?.attemptCount, 1)
    assert.equal(s1.ledgerNegativeEdge?.pruned, false)

    // Strike 2: pruned in BOTH FrontierScheduler and CapabilityLedger!
    const s2 = controller.recordPivotOutcome({
      branchKey: branchToPrune.branchKey,
      targetSurfaceKey: branchToPrune.nextTarget.targetSurfaceKey,
      hypothesisClass: 'lifecycle_invariant',
      status: 'failed',
      waveNo: 3,
      failureReason: 'invariant_enforced_hardened',
      falsifiedByExchangeIds: ['ex_hardened_2'],
    })
    assert.equal(s2.pruned, true)
    assert.equal(s2.ledgerNegativeEdge?.attemptCount, 2)
    assert.equal(s2.ledgerNegativeEdge?.pruned, true)
    assert.equal(
      ledger.isBranchPruned([c1, c2, c3, c4], branchToPrune.nextTarget.targetSurfaceKey, 'lifecycle_invariant'),
      true,
    )

    // Fresh planChainRound and fresh FrontierWaveController both suppress the pruned 4-hop branch!
    const replanned = planChainRound({
      primitives: [],
      maxHops: 4,
      limit: 12,
      approvedOrigins: [ORIGIN_EDGE, ORIGIN_API, ORIGIN_APP],
      capabilityLedger: ledger,
      frontierScheduler: new FrontierScheduler({ beamWidth: 10 }),
      waveNo: 4,
    })
    assert.equal(
      replanned.some(h => h.branchKey === depth4!.branchKey),
      false,
      '2-strike pruned negative edge in CapabilityLedger must suppress the dead-end branch in planChainRound',
    )

    const siblingController = new FrontierWaveController({ ledger, beamWidth: 10 })
    assert.equal(
      siblingController.admitBranch({ ...branchToPrune, branchKey: 'sibling_retry_branch' }),
      false,
      'sibling FrontierWaveController synced from CapabilityLedger must reject already-pruned negative edges',
    )
  })

  test('Grey-box / black-box runtime parity seeds quarantined hypotheses into CapabilityLedger without mounted source', async (t) => {
    const { storage } = makeStore(t, 'kovo-v8-wire-greybox-')
    const setup = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
    const run = storage.run(setup.runId)
    const planner = makePlanner(storage, { mountedRepos: [] })

    const result = planner.seedCapabilityLedgerInvariants(run, {
      mode: 'grey-box',
      runtime: {
        personaObservations: [
          {
            persona: 'revoked_admin',
            isRevokedOrDemoted: true,
            surface: 'http',
            serviceOrigin: ORIGIN_API,
            method: 'GET',
            path: '/api/secrets/:id',
            status: 401,
          },
          {
            persona: 'revoked_admin',
            isRevokedOrDemoted: true,
            surface: 'sse',
            serviceOrigin: ORIGIN_API,
            method: 'GET',
            path: '/sse/secrets/stream',
            status: 200,
          },
        ],
        openApiOperations: [
          { method: 'GET', path: '/api/secrets/:id', security: [{ bearerAuth: [] }], serviceOrigin: ORIGIN_API },
          { method: 'POST', path: '/api/secrets/batch', security: [], serviceOrigin: ORIGIN_API },
        ],
      },
      approvedOrigins: new Set([ORIGIN_API]),
    })

    assert.equal(result.mode, 'grey-box')
    assert.ok(result.seededCount >= 2, `expected >= 2 grey-box quarantined seeds, got ${result.seededCount}`)
    const ledger = storage.capabilityLedger(run.id)
    const nodes = ledger.listCapabilities()
    assert.ok(nodes.length >= 2)
    assert.ok(nodes.every(n => n.promotionStatus === 'capability_only'))
    assert.ok(nodes.some(n => n.provenance === 'runtime_discovery'))
    assert.ok(nodes.some(n => n.temporalState === 'revoked'))
  })

  test('Frontier-progress termination continues waves on verified HopReceipt reach expansion before terminal confirmation', async (t) => {
    const { storage } = makeStore(t, 'kovo-v8-wire-progress-')
    const setup = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
    const ledger = storage.capabilityLedger(setup.runId)
    const controller = new FrontierWaveController({ ledger, beamWidth: 8, unproductiveWaveLimit: 2 })

    const hop1: VerifiedHopHandle = {
      hopIndex: 1,
      hopReceiptId: 'hop_rcpt_p1',
      capabilityId: 'cap:hop_p1:tok',
      kind: 'scoped_token',
      surface: 'http',
      serviceOrigin: ORIGIN_API,
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      roleLabel: 'member',
      endpoint: '/api/v1/tokens',
      method: 'POST',
    }
    const hop2: VerifiedHopHandle = {
      hopIndex: 2,
      hopReceiptId: 'hop_rcpt_p2',
      capabilityId: 'cap:hop_p2:sse_handle',
      kind: 'state_handle',
      surface: 'sse',
      serviceOrigin: ORIGIN_APP,
      tenantScope: 'org_b',
      actorPersona: 'member_a',
      roleLabel: 'admin',
      endpoint: '/sse/v1/stream',
      method: 'GET',
      edgeBindingKind: 'async_pivot_binding',
    }
    const deepBranch: FrontierBranch = {
      branchKey: 'branch_deep_p2',
      depth: 2,
      verifiedHops: [hop1, hop2],
      nextTarget: {
        targetSurfaceKey: `${ORIGIN_API}|storage|/storage/export`,
        surface: 'storage',
        serviceOrigin: ORIGIN_API,
        endpoint: '/storage/export',
        method: 'GET',
        hypothesisClass: 'temporal_revocation',
        goalSummary: 'Download cross-tenant export using Hop-2 SSE handle',
      },
      feasibilityProb: 0.82,
      terminalImpactWeight: 9,
      surfaceNovelty: 1.6,
      attemptsOnBranch: 0,
      consecutiveFailedAttempts: 0,
      createdWave: 1,
      lastUpdatedWave: 1,
    }
    assert.equal(controller.admitBranch(deepBranch), true)

    // Wave selection produces a depth-2 pre-hydrated brief strictly <= 2 KB.
    const wave = controller.selectNextWave(4)
    assert.equal(wave.assignments.length, 1)
    assert.equal(wave.assignments[0]!.depth, 2)
    assert.equal(wave.assignments[0]!.targetHop, 3)
    assert.ok(wave.assignments[0]!.checkpointBytes <= MAX_CHECKPOINT_BRIEF_BYTES)
    const formatted = formatHopCheckpointForAssignment(wave.assignments[0]!.checkpointBrief, MAX_CHECKPOINT_BRIEF_BYTES)
    assert.ok(formatted.bytes <= MAX_CHECKPOINT_BRIEF_BYTES)
    assert.equal(formatted.brief.doNotRediscover, true)

    // Verified HopReceipt expands reach (new tenant/role/surface) with 0 terminal confirmations -> CONTINUE!
    const progress = controller.evaluateWaveProgress({
      completedAssignments: 1,
      confirmedCompositeReceipts: [],
      verifiedHopReceipts: [{
        hopReceiptId: 'hop_rcpt_p2',
        branchKey: 'branch_deep_p2',
        depth: 2,
        hostVerified: true,
        tenantScope: 'org_b',
        roleLabel: 'admin',
        serviceOrigin: ORIGIN_APP,
        surface: 'sse',
        capabilityId: 'cap:hop_p2:sse_handle',
      }],
    })
    assert.equal(progress.decision, 'continue')
    assert.equal(progress.reason, 'frontier_progress')
    assert.equal(progress.productive, true)
    assert.equal(progress.reachDelta.newHopReceiptIds.length, 1)

    // Wire into nextPlannerDryRounds & coordinatorSchedulerDecision: resets dry streak & continues even
    // when consecutiveDryRounds would otherwise hit DRY_ROUND_LIMIT!
    assert.equal(
      nextPlannerDryRounds({
        roundNo: 3,
        previousDryRounds: DRY_ROUND_LIMIT - 1,
        newRuntimeConfirmed: 0,
        newChainPrimitives: 0,
        completedInvestigations: 6,
        previousCompletedInvestigations: 4,
        verifiedHopReachExpansions: progress.reachDelta.newHopReceiptIds.length,
      }),
      0,
    )
    const schedDecision = coordinatorSchedulerDecision({
      budgetExhausted: false,
      budgetRequests: 1000,
      spentRequests: 20,
      startedAt: Date.now(),
      maxDurationMs: 600_000,
      emptyRounds: 0,
      pendingOob: 0,
      highPriorityQueueEmpty: true,
      consecutiveDryRounds: DRY_ROUND_LIMIT,
      verifiedHopReachExpansions: progress.reachDelta.newHopReceiptIds.length,
      frontierDecision: progress,
    })
    assert.equal(schedDecision.decision, 'continue')
  })

  test('planChainRound supports causal depth up to 6 hops cleanly via FrontierScheduler beam search', () => {
    const primitives: ChainPrimitive[] = [
      { kind: 'leaked_token', origin: ORIGIN_EDGE, value: 'secret:f1', evidenceIds: ['e1'], factIds: ['f1'], endpoint: '/edge/tok', detail: 'hop1' },
      { kind: 'discovered_id', origin: ORIGIN_APP, value: 'obj-1', evidenceIds: ['e2'], factIds: ['f2'], endpoint: '/app/obj', detail: 'hop2' },
      { kind: 'stored_write', origin: ORIGIN_APP, value: 'stored:c1', evidenceIds: ['e3'], factIds: ['f3'], endpoint: '/app/comment', detail: 'hop3' },
      { kind: 'ssrf_internal_reach', origin: ORIGIN_API, value: 'ssrf:hook', evidenceIds: ['e4'], factIds: ['f4'], endpoint: '/api/webhook', detail: 'hop4' },
      { kind: 'workflow_state_handle', origin: ORIGIN_API, value: 'workflow:wf1', evidenceIds: ['e5'], factIds: ['f5'], endpoint: '/api/jobs/wf1', detail: 'hop5' },
      { kind: 'admin_route', origin: ORIGIN_API, value: 'admin:/admin/release', evidenceIds: ['e6'], factIds: ['f6'], endpoint: '/admin/release', detail: 'hop6' },
    ]
    const endpoints: CoordinatorEndpoint[] = [
      { id: 'ep6', origin: ORIGIN_API, method: 'POST', pathTemplate: '/admin/release', roleExclusive: true },
    ]
    const coordinator = createGraphCoordinator({
      deps: {
        listEndpoints: () => endpoints,
        listFacts: () => [],
        listFindings: () => [],
        approvedOrigins: () => [ORIGIN_EDGE, ORIGIN_APP, ORIGIN_API],
      },
      approvedOrigins: [ORIGIN_EDGE, ORIGIN_APP, ORIGIN_API],
    })
    const planned = planChainRound({
      primitives,
      endpoints,
      maxHops: 6,
      limit: 16,
      approvedOrigins: [ORIGIN_EDGE, ORIGIN_APP, ORIGIN_API],
    })
    const depth6 = planned.find(h => h.hops === 6)
    assert.ok(depth6, `expected a 6-hop chain hypothesis, got hops=${planned.map(h => h.hops).join(',')}`)
    assert.equal(depth6!.chainHops?.length, 6)
    assert.ok((depth6!.checkpointBytes ?? Infinity) <= MAX_CHECKPOINT_BRIEF_BYTES)
    assert.ok(coordinator.queryEndpoints({ roleExclusive: true }).total === 1)
  })
})
