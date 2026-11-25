/**
 * Kovo Hunter v8 M3 — Frontier / Beam Multi-Wave Scheduler deterministic simulation tests.
 *
 * Covers:
 *  1. Exact EVI scoring formula, deterministic ordering, and beam-width cap (B = 8..16).
 *  2. Depth 1..6 multi-hop progression and strict depth <= 6 ceiling.
 *  3. High-EVI partial-chain (depth >= 2) wave-quota protection against flat route sweeps,
 *     plus bounded discovery slice for newly unlocked surfaces.
 *  4. Hop-checkpoint branching (<= 2 KB serialized brief, no Hop-1 rediscovery, secret scrubbing).
 *  5. Progress-aware termination (continues across Hop 2..5 reach expansions without premature stop;
 *     enforces outer budget/duration/request bounds and clean stagnation stop).
 *  6. 2-strike dead-end pruning, sibling negative-edge suppression, and <= 5% waste rate across
 *     a deterministic 60-step multi-wave simulation.
 *  7. Module LOC (<= 800) and zero-benchmark-literal anti-contamination invariants.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { test } from 'node:test'
import {
  DEFAULT_BEAM_WIDTH,
  FrontierScheduler,
  MAX_BEAM_WIDTH,
  MAX_CHAIN_DEPTH,
  MAX_CHECKPOINT_BRIEF_BYTES,
  MAX_DEAD_END_WASTE_RATE,
  MIN_BEAM_WIDTH,
  buildHopCheckpointBrief,
  clampBeamWidth,
  computeBranchEvi,
  computeNegativeEdgeKey,
  createEmptyReachState,
  evaluateWaveProgress,
  rankAndPruneBeam,
  resolveBeamWidthForTier,
  selectNextWaveAssignments,
  type DiscoverySurfaceCandidate,
  type FrontierBranch,
  type FrontierSurface,
  type RouteSweepCandidate,
  type VerifiedHopHandle,
} from '../src/server/frontier-scheduler.ts'

function makeHop(hopIndex: number, overrides: Partial<VerifiedHopHandle> = {}): VerifiedHopHandle {
  return {
    hopIndex,
    hopReceiptId: `hop:rcpt_${hopIndex}`,
    capabilityId: `cap:hop_${hopIndex}:slot0`,
    kind: 'scoped_token',
    surface: 'http',
    serviceOrigin: 'https://api.example.invalid',
    tenantScope: 'tenant-alpha',
    actorPersona: 'member_alpha',
    roleLabel: 'member',
    endpoint: `/api/v1/step-${hopIndex}`,
    method: 'POST',
    edgeBindingKind: 'value_binding',
    ...overrides,
  }
}

function makeBranch(
  branchKey: string,
  depth: number,
  overrides: Partial<FrontierBranch> = {},
): FrontierBranch {
  const verifiedHops = overrides.verifiedHops ?? Array.from({ length: depth }, (_, i) => makeHop(i + 1, {
    hopReceiptId: `hop:${branchKey}:${i + 1}`,
    capabilityId: `cap:${branchKey}:h${i + 1}`,
  }))
  return {
    branchKey,
    depth,
    verifiedHops,
    nextTarget: {
      targetSurfaceKey: `svc-api|http|/api/v1/pivot/${branchKey}`,
      surface: 'http',
      serviceOrigin: 'https://api.example.invalid',
      endpoint: `/api/v1/pivot/${branchKey}`,
      method: 'POST',
      hypothesisClass: 'dual_tenant_abac',
      expectedBindingKind: 'value_binding',
      goalSummary: `Verify hop ${depth + 1} pivot from ${branchKey}`,
    },
    feasibilityProb: 0.75,
    terminalImpactWeight: 8,
    surfaceNovelty: 1.5,
    attemptsOnBranch: 0,
    consecutiveFailedAttempts: 0,
    createdWave: 1,
    lastUpdatedWave: 1,
    ...overrides,
  }
}

// ============================================================================
// 1. Exact EVI Formula, Deterministic Ordering & Beam-Width Cap (B = 8..16)
// ============================================================================

test('computeBranchEvi implements exact formula P * Impact * Novelty / (1 + Attempts)', () => {
  const evi0 = computeBranchEvi({
    feasibilityProb: 0.8,
    terminalImpactWeight: 9,
    surfaceNovelty: 1.5,
    attemptsOnBranch: 0,
  })
  assert.ok(Math.abs(evi0 - (0.8 * 9 * 1.5) / 1) < 1e-12)

  const evi2 = computeBranchEvi({
    feasibilityProb: 0.8,
    terminalImpactWeight: 9,
    surfaceNovelty: 1.5,
    attemptsOnBranch: 2,
  })
  assert.ok(Math.abs(evi2 - (0.8 * 9 * 1.5) / 3) < 1e-12)

  // Probability is clamped to [0, 1]; negative attempts clamp to 0.
  assert.equal(computeBranchEvi({ feasibilityProb: 1.5, terminalImpactWeight: 10, surfaceNovelty: 2, attemptsOnBranch: -3 }), 20)
  assert.equal(computeBranchEvi({ feasibilityProb: -0.2, terminalImpactWeight: 10, surfaceNovelty: 2, attemptsOnBranch: 0 }), 0)
})

test('beam width clamps strictly to B = 8..16 and keeps top-B branches by EVI', () => {
  assert.equal(clampBeamWidth(3), MIN_BEAM_WIDTH)
  assert.equal(clampBeamWidth(8), 8)
  assert.equal(clampBeamWidth(12), DEFAULT_BEAM_WIDTH)
  assert.equal(clampBeamWidth(16), MAX_BEAM_WIDTH)
  assert.equal(clampBeamWidth(99), MAX_BEAM_WIDTH)
  assert.equal(resolveBeamWidthForTier('smoke'), 8)
  assert.equal(resolveBeamWidthForTier('standard'), 12)
  assert.equal(resolveBeamWidthForTier('deep'), 16)

  const candidates = Array.from({ length: 24 }, (_, idx) =>
    makeBranch(`branch-${String(idx + 1).padStart(2, '0')}`, (idx % 4) + 1, {
      feasibilityProb: 0.2 + (idx / 30),
      terminalImpactWeight: 5 + (idx % 5),
      surfaceNovelty: 1.0 + ((idx % 3) * 0.25),
      attemptsOnBranch: idx % 2,
    }),
  )

  const beam8 = rankAndPruneBeam(candidates, 8)
  const beam16 = rankAndPruneBeam(candidates, 16)
  assert.equal(beam8.length, 8)
  assert.equal(beam16.length, 16)

  // Strictly non-increasing EVI order and deterministic across repeated calls.
  for (let i = 1; i < beam16.length; i += 1) {
    assert.ok(beam16[i - 1].evi >= beam16[i].evi, `beam[${i - 1}] EVI must be >= beam[${i}]`)
  }
  const beam16Repeat = rankAndPruneBeam([...candidates].reverse(), 16)
  assert.deepEqual(beam16.map(b => b.branch.branchKey), beam16Repeat.map(b => b.branch.branchKey))
})

// ============================================================================
// 2. Depth 1..6 Progression & Hard Depth <= 6 Cap
// ============================================================================

test('multi-hop chain progresses cleanly from Hop 1 to Hop 6 and blocks depth 7 expansion', () => {
  const scheduler = new FrontierScheduler({ beamWidth: 8 })
  assert.equal(scheduler.admitBranch(makeBranch('invalid-0', 0)), false)
  assert.equal(scheduler.admitBranch(makeBranch('invalid-7', 7)), false)

  const seed = makeBranch('chain-a', 1, {
    nextTarget: {
      targetSurfaceKey: 'svc-api|graphql|/graphql:env',
      surface: 'graphql',
      serviceOrigin: 'https://api.example.invalid',
      endpoint: '/graphql',
      method: 'POST',
      hypothesisClass: 'cross_surface_pivot',
      goalSummary: 'Pivot from Hop 1 session to Hop 2 GraphQL resolver',
    },
  })
  assert.equal(scheduler.admitBranch(seed), true)

  const surfaces: FrontierSurface[] = ['graphql', 'async_job', 'webhook', 'sse', 'storage']
  let currentKey = 'chain-a'
  for (let hop = 2; hop <= MAX_CHAIN_DEPTH; hop += 1) {
    const wave = scheduler.selectNextWaveAssignments(2)
    assert.equal(wave.assignments.length, 1)
    assert.equal(wave.assignments[0].branchKey, currentKey)
    assert.equal(wave.assignments[0].depth, hop - 1)
    assert.equal(wave.assignments[0].targetHop, hop)
    assert.ok(wave.assignments[0].checkpointBytes <= MAX_CHECKPOINT_BRIEF_BYTES)

    // Unverified hop must be rejected.
    const rejected = scheduler.recordAttemptOutcome({
      branchKey: currentKey,
      targetSurfaceKey: wave.assignments[0].targetSurfaceKey,
      status: 'hop_verified',
      hostVerified: false,
      newHop: makeHop(hop, { surface: surfaces[hop - 2] }),
    })
    assert.equal(rejected.accepted, false)
    assert.equal(rejected.reason, 'missing_host_verified_hop')

    const advanced = scheduler.recordAttemptOutcome({
      branchKey: currentKey,
      targetSurfaceKey: wave.assignments[0].targetSurfaceKey,
      status: 'hop_verified',
      hostVerified: true,
      newHop: makeHop(hop, {
        hopReceiptId: `hop:chain-a:${hop}`,
        capabilityId: `cap:chain-a:h${hop}`,
        surface: surfaces[hop - 2],
        serviceOrigin: `https://svc-${hop}.example.invalid`,
      }),
      nextTarget: {
        targetSurfaceKey: `svc-${hop + 1}|storage|/v1/target-${hop + 1}`,
        surface: 'storage',
        serviceOrigin: `https://svc-${hop + 1}.example.invalid`,
        endpoint: `/v1/target-${hop + 1}`,
        method: 'GET',
        hypothesisClass: 'cross_surface_pivot',
        goalSummary: `Advance to hop ${hop + 1}`,
      },
    })
    assert.equal(advanced.accepted, true)
    assert.equal(advanced.reason, 'hop_advanced')
    currentKey = advanced.childBranchKey!
  }

  assert.equal(scheduler.getBranch(currentKey)?.depth, MAX_CHAIN_DEPTH)
  assert.equal(scheduler.getTelemetry().maxDepthReached, MAX_CHAIN_DEPTH)

  // Depth-6 branch must NOT be scheduled for Hop 7 expansion or allowed to advance to depth 7.
  const waveAfterMax = scheduler.selectNextWaveAssignments(4)
  assert.equal(waveAfterMax.assignments.length, 0)
  assert.equal(waveAfterMax.quota.skippedMaxDepthBranches, 1)

  const blockedDepth7 = scheduler.recordAttemptOutcome({
    branchKey: currentKey,
    targetSurfaceKey: 'svc-7|storage|/v1/target-7',
    status: 'hop_verified',
    hostVerified: true,
    newHop: makeHop(7),
  })
  assert.equal(blockedDepth7.accepted, false)
  assert.equal(blockedDepth7.reason, 'max_depth_reached')
})

// ============================================================================
// 3. Partial-Chain Quota Protection & Bounded Discovery Slice
// ============================================================================

test('high-EVI partial chains (depth >= 2) are never starved by flat route sweeps while discovery keeps a bounded slice', () => {
  const deepBranches = Array.from({ length: 5 }, (_, i) =>
    makeBranch(`deep-${i + 1}`, i % 2 === 0 ? 3 : 2, {
      feasibilityProb: 0.85 - i * 0.05,
      terminalImpactWeight: 9,
      surfaceNovelty: 1.6,
    }),
  )
  const shallowBranches = [makeBranch('shallow-1', 1, { feasibilityProb: 0.9, terminalImpactWeight: 8 })]
  const discoveries: DiscoverySurfaceCandidate[] = [
    {
      candidateKey: 'disc-worker-sse',
      surface: 'sse',
      serviceOrigin: 'https://worker.example.invalid',
      endpoint: '/events/stream',
      method: 'GET',
      hypothesisClass: 'temporal_revocation',
      noveltyScore: 9.5,
      goalSummary: 'Inspect newly unlocked SSE event stream',
    },
    {
      candidateKey: 'disc-idp-oauth',
      surface: 'idp',
      serviceOrigin: 'https://idp.example.invalid',
      endpoint: '/oauth/authorize',
      method: 'GET',
      hypothesisClass: 'cryptographic_scope_replay',
      noveltyScore: 8.8,
      goalSummary: 'Inspect newly unlocked IdP authorize surface',
    },
  ]
  const routeSweeps: RouteSweepCandidate[] = Array.from({ length: 30 }, (_, i) => ({
    candidateKey: `sweep-${i + 1}`,
    surface: 'http',
    serviceOrigin: 'https://api.example.invalid',
    endpoint: `/api/v1/noise/route-${i + 1}`,
    method: 'GET',
    hypothesisClass: 'generic_route_sweep',
    priorityScore: 999, // Artificially huge priority must STILL never starve depth >= 2 chains!
    goalSummary: `Flat route sweep #${i + 1}`,
  }))

  // Wave capacity = 4: expect 3 deep chains (depth >= 2) + 1 bounded discovery slice + 0 flat route sweeps.
  const wave4 = selectNextWaveAssignments({
    waveNo: 1,
    waveCapacity: 4,
    beamWidth: 12,
    branches: [...deepBranches, ...shallowBranches],
    discoveryCandidates: discoveries,
    routeSweepCandidates: routeSweeps,
  })
  assert.equal(wave4.assignments.length, 4)
  assert.equal(wave4.quota.assignedDeepChainSlots, 3)
  assert.equal(wave4.quota.assignedDiscoverySlots, 1)
  assert.equal(wave4.quota.assignedRouteSweepSlots, 0)
  assert.ok(wave4.assignments.filter(a => a.depth >= 2).length >= 3)

  // Wave capacity = 6: expect 5 deep chains (4 reserved + 1 surplus) + 1 discovery + 0 flat route sweeps.
  const wave6 = selectNextWaveAssignments({
    waveNo: 2,
    waveCapacity: 6,
    beamWidth: 12,
    branches: [...deepBranches, ...shallowBranches],
    discoveryCandidates: discoveries,
    routeSweepCandidates: routeSweeps,
  })
  assert.equal(wave6.assignments.length, 6)
  assert.equal(wave6.quota.assignedDeepChainSlots, 5)
  assert.equal(wave6.quota.assignedDiscoverySlots, 1)
  assert.equal(wave6.quota.assignedRouteSweepSlots, 0)

  // Only when chains + discovery do not exhaust capacity do route sweeps fill leftover slots.
  const waveSpare = selectNextWaveAssignments({
    waveNo: 3,
    waveCapacity: 5,
    beamWidth: 8,
    branches: [deepBranches[0], shallowBranches[0]],
    discoveryCandidates: [discoveries[0]],
    routeSweepCandidates: routeSweeps,
  })
  assert.equal(waveSpare.quota.assignedDeepChainSlots, 1)
  assert.equal(waveSpare.quota.assignedShallowChainSlots, 1)
  assert.equal(waveSpare.quota.assignedDiscoverySlots, 1)
  assert.equal(waveSpare.quota.assignedRouteSweepSlots, 2)
})

// ============================================================================
// 4. Hop-Checkpoint Briefs (<= 2 KB, Secret Scrubbing, Sub-Chain Fusion)
// ============================================================================

test('hop-checkpoint briefs stay strictly <= 2 KB, scrub raw secrets, and support sub-chain fusion', () => {
  const verboseHops: VerifiedHopHandle[] = Array.from({ length: 5 }, (_, idx) => makeHop(idx + 1, {
    hopReceiptId: `hop:rcpt_${idx + 1}`,
    capabilityId: idx === 2
      ? 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_payload'
      : `cap:hop_${idx + 1}:slot_${idx}`,
    endpoint: `/api/v1/organizations/very-long-segment-${'x'.repeat(120)}/step-${idx + 1}`,
    serviceOrigin: `https://service-tier-${idx + 1}.cluster.example.invalid`,
    summary: 'Bearer super_secret_token_should_never_leak ' + 'y'.repeat(400),
  }))

  const branch = makeBranch('fusion-branch-with-long-metadata', 5, {
    verifiedHops: verboseHops,
    fuseWithBranchKey: 'partner-subchain-h2',
    lane: 'subchain_fusion',
    nextTarget: {
      targetSurfaceKey: 'svc-worker|async_job|/internal/jobs/export/final-settlement',
      surface: 'async_job',
      serviceOrigin: 'https://worker.example.invalid',
      endpoint: `/internal/jobs/export/${'z'.repeat(160)}`,
      method: 'POST',
      hypothesisClass: 'economic_conservation',
      expectedBindingKind: 'async_pivot_binding',
      targetTenantScope: 'tenant-beta',
      targetRoleLabel: 'finance_approver',
      goalSummary: `Fuse verified Hop 1..5 handles with partner sub-chain using Bearer abcdef1234567890abcdef1234567890 and ${'g'.repeat(500)}`,
    },
  })

  const built = buildHopCheckpointBrief(branch, 7.25)
  assert.ok(built.checkpointBytes <= MAX_CHECKPOINT_BRIEF_BYTES, `checkpointBytes=${built.checkpointBytes} must be <= 2048`)
  assert.equal(built.checkpointBytes, Buffer.byteLength(built.checkpointJson, 'utf8'))
  assert.equal(built.brief.doNotRediscover, true)
  assert.equal(built.brief.mode, 'fuse')
  assert.equal(built.brief.targetHop, 6)
  assert.equal(built.brief.fuseWithBranchKey, 'partner-subchain-h2')
  // Raw JWT and Bearer tokens must never appear in the serialized brief.
  assert.equal(built.checkpointJson.includes('eyJhbGciOiJIUzI1Ni'), false)
  assert.equal(built.checkpointJson.includes('Bearer '), false)
  assert.ok(built.brief.capabilityHandles.includes('cap:redacted:3'))
  assert.ok(built.brief.capabilityHandles.includes('cap:hop_5:slot_4'))

  // Tight cap (512 B) still stays strictly within budget even with multi-byte UTF-8 input.
  const tight = buildHopCheckpointBrief(makeBranch('utf8-branch-🔥-αβγ', 4, {
    nextTarget: {
      ...branch.nextTarget,
      goalSummary: '🔒'.repeat(200),
    },
  }), 3.5, 512)
  assert.ok(tight.checkpointBytes <= 512, `tight checkpointBytes=${tight.checkpointBytes} must be <= 512`)
})

// ============================================================================
// 5. Progress-Aware Termination (Replaces Flat DRY_ROUND_LIMIT = 2)
// ============================================================================

test('evaluateWaveProgress continues across Hop 2..5 reach expansions without premature stop and enforces outer bounds', () => {
  const reach = createEmptyReachState()
  let streak = 0

  // Wave 1..4: zero terminal CompositeProofReceipts yet, but each wave yields a host-verified HopReceipt
  // expanding surface -> role -> service -> tenant reach. Must continue every time with streak = 0!
  const progressiveHops = [
    { hopReceiptId: 'h1', branchKey: 'b1', depth: 1, hostVerified: true, tenantScope: 'tenant-a', roleLabel: 'member', serviceOrigin: 'svc-api', surface: 'http' as const },
    { hopReceiptId: 'h2', branchKey: 'b1', depth: 2, hostVerified: true, tenantScope: 'tenant-a', roleLabel: 'member', serviceOrigin: 'svc-api', surface: 'graphql' as const },
    { hopReceiptId: 'h3', branchKey: 'b1', depth: 3, hostVerified: true, tenantScope: 'tenant-a', roleLabel: 'admin', serviceOrigin: 'svc-api', surface: 'graphql' as const },
    { hopReceiptId: 'h4', branchKey: 'b1', depth: 4, hostVerified: true, tenantScope: 'tenant-b', roleLabel: 'viewer', serviceOrigin: 'svc-worker', surface: 'async_job' as const },
  ]

  for (let i = 0; i < progressiveHops.length; i += 1) {
    const decision = evaluateWaveProgress({
      waveNo: i + 1,
      completedAssignments: 4,
      confirmedCompositeReceipts: [],
      verifiedHopReceipts: [progressiveHops[i]],
      reach,
      activeFrontierCount: 5,
      consecutiveUnproductiveWaves: streak,
      budgetUsdSpent: (i + 1) * 0.5,
      budgetUsdLimit: 5,
      elapsedMs: (i + 1) * 60_000,
      maxDurationMs: 1_800_000,
      requestsSpent: (i + 1) * 40,
      agentRequestBudget: 1000,
    })
    assert.equal(decision.decision, 'continue', `wave ${i + 1} must continue on reach expansion`)
    assert.equal(decision.reason, 'frontier_progress')
    assert.equal(decision.productive, true)
    assert.equal(decision.nextUnproductiveWaves, 0)
    streak = decision.nextUnproductiveWaves
  }

  // Wave 5: unverified hop + redundant same-reach hop must NOT count as progress.
  const dry1 = evaluateWaveProgress({
    waveNo: 5,
    completedAssignments: 4,
    verifiedHopReceipts: [
      { hopReceiptId: 'h5-unverified', branchKey: 'b2', depth: 2, hostVerified: false, tenantScope: 'tenant-z', roleLabel: 'owner', serviceOrigin: 'svc-new', surface: 'idp' },
      { hopReceiptId: 'h5-same-reach', branchKey: 'b2', depth: 2, hostVerified: true, tenantScope: 'tenant-a', roleLabel: 'member', serviceOrigin: 'svc-api', surface: 'http' },
    ],
    reach,
    activeFrontierCount: 4,
    consecutiveUnproductiveWaves: streak,
  })
  assert.equal(dry1.decision, 'continue')
  assert.equal(dry1.productive, false)
  assert.equal(dry1.nextUnproductiveWaves, 1)

  // Wave 6: pending async/OOB callback prevents stagnation stop while draining.
  const draining = evaluateWaveProgress({
    waveNo: 6,
    completedAssignments: 4,
    reach,
    activeFrontierCount: 4,
    pendingAsyncOrOob: 2,
    consecutiveUnproductiveWaves: dry1.nextUnproductiveWaves,
  })
  assert.equal(draining.decision, 'continue')
  assert.equal(draining.reason, 'async_drain_pending')

  // Wave 7: without pending async/OOB, second consecutive unproductive wave stops cleanly.
  const stagnated = evaluateWaveProgress({
    waveNo: 7,
    completedAssignments: 4,
    reach,
    activeFrontierCount: 4,
    consecutiveUnproductiveWaves: 1,
    unproductiveWaveLimit: 2,
  })
  assert.equal(stagnated.decision, 'stop')
  assert.equal(stagnated.reason, 'frontier_stagnated')

  // Hard outer bounds (budget, duration, request budget) always stop even on a productive wave.
  const overBudget = evaluateWaveProgress({
    waveNo: 8,
    completedAssignments: 4,
    confirmedCompositeReceipts: ['cpr-new-1'],
    reach,
    activeFrontierCount: 4,
    consecutiveUnproductiveWaves: 0,
    budgetUsdSpent: 5.0,
    budgetUsdLimit: 5.0,
  })
  assert.equal(overBudget.decision, 'stop')
  assert.equal(overBudget.reason, 'budget_exhausted')

  const overTime = evaluateWaveProgress({
    waveNo: 9,
    completedAssignments: 4,
    reach,
    activeFrontierCount: 4,
    consecutiveUnproductiveWaves: 0,
    elapsedMs: 1_800_000,
    maxDurationMs: 1_800_000,
  })
  assert.equal(overTime.decision, 'stop')
  assert.equal(overTime.reason, 'duration_exhausted')
})

// ============================================================================
// 6. 2-Strike Pruning, Sibling Negative-Edge Prevention & 60-Step Simulation
// ============================================================================

test('2-strike pruning records negative edge, blocks siblings, and allows upgraded capabilities', () => {
  const scheduler = new FrontierScheduler({ beamWidth: 10 })
  const sharedCap = makeHop(1, { capabilityId: 'cap:shared_member_tok' })
  const target = {
    targetSurfaceKey: 'svc-api|http|/api/v1/admin/transfer',
    surface: 'http' as const,
    serviceOrigin: 'https://api.example.invalid',
    endpoint: '/api/v1/admin/transfer',
    method: 'POST',
    hypothesisClass: 'dual_tenant_abac',
    goalSummary: 'Attempt cross-tenant project transfer',
  }

  scheduler.admitBranch(makeBranch('branch-primary', 1, {
    verifiedHops: [sharedCap],
    nextTarget: target,
    preconditionGroupKey: 'member_alpha_org_a',
  }))
  scheduler.admitBranch(makeBranch('branch-sibling', 1, {
    verifiedHops: [sharedCap],
    nextTarget: target,
    preconditionGroupKey: 'member_alpha_org_a',
  }))

  // Wave 1: same-wave sibling dedupe ensures only 1 worker probes the shared edge, not both.
  const w1 = scheduler.selectNextWaveAssignments(4)
  assert.equal(w1.assignments.length, 1)
  assert.equal(w1.quota.skippedSameWaveSiblings, 1)

  // Strike 1: allowed retry, not pruned yet.
  const f1 = scheduler.recordAttemptOutcome({
    branchKey: w1.assignments[0].branchKey,
    targetSurfaceKey: target.targetSurfaceKey,
    status: 'failed',
    failureReason: 'invariant_enforced_hardened',
    falsifiedByExchangeIds: ['ex-1'],
  })
  assert.equal(f1.pruned, false)
  assert.equal(f1.reason, 'strike_1_of_2')

  // Wave 2 -> Strike 2: prunes branch and writes negative edge blocking sibling too.
  const w2 = scheduler.selectNextWaveAssignments(4)
  assert.equal(w2.assignments.length, 1)
  const f2 = scheduler.recordAttemptOutcome({
    branchKey: w2.assignments[0].branchKey,
    targetSurfaceKey: target.targetSurfaceKey,
    status: 'failed',
    failureReason: 'invariant_enforced_hardened',
    falsifiedByExchangeIds: ['ex-2'],
  })
  assert.equal(f2.pruned, true)
  assert.equal(f2.reason, 'pruned_2_strike')
  assert.equal(
    f2.negativeEdge?.negativeEdgeKey,
    computeNegativeEdgeKey(['cap:shared_member_tok'], target.targetSurfaceKey, target.hypothesisClass),
  )

  // Wave 3: neither primary nor sibling is dispatched (negative edge suppresses sibling!).
  const w3 = scheduler.selectNextWaveAssignments(4)
  assert.equal(w3.assignments.length, 0)
  assert.ok(w3.quota.skippedNegativeEdges >= 1)
  assert.equal(scheduler.hasNegativeEdge(['cap:shared_member_tok'], target.targetSurfaceKey, target.hypothesisClass), true)

  // A new branch carrying a genuinely stronger capability handle IS allowed to probe the same surface.
  const upgradedAdmitted = scheduler.admitBranch(makeBranch('branch-upgraded-admin', 2, {
    verifiedHops: [sharedCap, makeHop(2, { capabilityId: 'cap:elevated_admin_tok', roleLabel: 'admin' })],
    nextTarget: target,
  }))
  assert.equal(upgradedAdmitted, true)
  const w4 = scheduler.selectNextWaveAssignments(4)
  assert.equal(w4.assignments.length, 1)
  assert.equal(w4.assignments[0].branchKey, 'branch-upgraded-admin')
})

test('60-step deterministic multi-wave simulation keeps deadEndReprobeWasteRate <= 5% and advances deep chains', () => {
  const scheduler = new FrontierScheduler({ beamWidth: 12, unproductiveWaveLimit: 3 })

  // Seed 6 dead-end hardened-twin branches (plus 6 sibling clones that must be suppressed after 2 strikes)
  // and 6 productive multi-hop chains that progress from depth 1 -> 4..6 and confirm CompositeProofReceipts.
  for (let i = 1; i <= 6; i += 1) {
    const twinCap = makeHop(1, { capabilityId: `cap:twin_${i}:h1`, tenantScope: `tenant-twin-${i}` })
    const twinTarget = {
      targetSurfaceKey: `svc-api|http|/api/v1/hardened-twin-${i}`,
      surface: 'http' as const,
      serviceOrigin: 'https://api.example.invalid',
      endpoint: `/api/v1/hardened-twin-${i}`,
      method: 'POST',
      hypothesisClass: 'temporal_revocation',
      goalSummary: `Test hardened twin ${i}`,
    }
    scheduler.admitBranch(makeBranch(`twin-${i}`, 1, {
      verifiedHops: [twinCap],
      nextTarget: twinTarget,
      preconditionGroupKey: `twin-group-${i}`,
      feasibilityProb: 0.7,
      terminalImpactWeight: 7,
      surfaceNovelty: 1.2,
    }))
    scheduler.admitBranch(makeBranch(`twin-${i}-sibling`, 1, {
      verifiedHops: [twinCap],
      nextTarget: twinTarget,
      preconditionGroupKey: `twin-group-${i}`,
      feasibilityProb: 0.68,
      terminalImpactWeight: 7,
      surfaceNovelty: 1.2,
    }))
  }

  for (let i = 1; i <= 6; i += 1) {
    scheduler.admitBranch(makeBranch(`chain-${i}`, 1, {
      feasibilityProb: 0.85,
      terminalImpactWeight: 9,
      surfaceNovelty: 1.6,
      nextTarget: {
        targetSurfaceKey: `svc-chain-${i}|graphql|/graphql/pivot-2`,
        surface: 'graphql',
        serviceOrigin: `https://svc-chain-${i}.example.invalid`,
        endpoint: '/graphql/pivot-2',
        method: 'POST',
        hypothesisClass: 'cross_surface_pivot',
        goalSummary: `Advance chain ${i} to Hop 2`,
      },
    }))
  }

  // Add newly unlocked discovery surfaces and route-sweep filler so the simulation runs >= 60 dispatched steps.
  for (let i = 1; i <= 12; i += 1) {
    scheduler.addDiscoverySurface({
      candidateKey: `disc-${i}`,
      surface: i % 2 === 0 ? 'async_job' : 'sse',
      serviceOrigin: `https://svc-disc-${i}.example.invalid`,
      endpoint: `/v1/unlocked-${i}`,
      method: 'GET',
      hypothesisClass: 'parser_cache_differential',
      noveltyScore: 4 + (i * 0.1),
      goalSummary: `Discover newly unlocked surface ${i}`,
    })
  }
  for (let i = 1; i <= 24; i += 1) {
    scheduler.addRouteSweepCandidate({
      candidateKey: `sweep-${i}`,
      surface: 'http',
      serviceOrigin: 'https://api.example.invalid',
      endpoint: `/api/v1/sweep-${i}`,
      method: 'GET',
      hypothesisClass: 'baseline_sweep',
      priorityScore: 1,
      goalSummary: `Sweep route ${i}`,
    })
  }

  const hopSurfaces: FrontierSurface[] = ['http', 'graphql', 'async_job', 'webhook', 'sse', 'storage']
  let totalSteps = 0

  for (let wave = 1; wave <= 18 && totalSteps < 64; wave += 1) {
    const selection = scheduler.selectNextWaveAssignments(4)
    if (selection.assignments.length === 0) break

    const confirmedThisWave: string[] = []
    const verifiedHopsThisWave: Array<{
      hopReceiptId: string
      branchKey: string
      depth: number
      hostVerified: boolean
      tenantScope: string
      roleLabel: string
      serviceOrigin: string
      surface: FrontierSurface
    }> = []

    for (const assignment of selection.assignments) {
      totalSteps += 1
      assert.ok(assignment.checkpointBytes <= MAX_CHECKPOINT_BRIEF_BYTES)

      if (assignment.branchKey.startsWith('twin-')) {
        scheduler.recordAttemptOutcome({
          branchKey: assignment.branchKey,
          targetSurfaceKey: assignment.targetSurfaceKey,
          status: 'failed',
          failureReason: 'invariant_enforced_hardened',
          falsifiedByExchangeIds: [`ex-${wave}-${totalSteps}`],
        })
        // Re-submit a duplicate sibling candidate to prove negative-edge admission suppression works.
        const twinNum = assignment.branchKey.split('-')[1]
        scheduler.admitBranch(makeBranch(`twin-${twinNum}-late-sibling-${wave}`, 1, {
          verifiedHops: [makeHop(1, { capabilityId: `cap:twin_${twinNum}:h1` })],
          nextTarget: {
            targetSurfaceKey: `svc-api|http|/api/v1/hardened-twin-${twinNum}`,
            surface: 'http',
            serviceOrigin: 'https://api.example.invalid',
            endpoint: `/api/v1/hardened-twin-${twinNum}`,
            method: 'POST',
            hypothesisClass: 'temporal_revocation',
            goalSummary: 'Late sibling re-probe attempt',
          },
          preconditionGroupKey: `twin-group-${twinNum}`,
        }))
      } else if (assignment.branchKey.startsWith('chain-')) {
        const rootIdx = Number(assignment.branchKey.split('-')[1].split('>')[0])
        const terminalDepth = rootIdx <= 2 ? 6 : rootIdx <= 4 ? 5 : 4
        if (assignment.targetHop >= terminalDepth) {
          const receiptId = `cpr:chain-${rootIdx}:d${terminalDepth}`
          scheduler.recordAttemptOutcome({
            branchKey: assignment.branchKey,
            targetSurfaceKey: assignment.targetSurfaceKey,
            status: 'confirmed_composite',
            compositeProofReceiptId: receiptId,
            newHop: makeHop(terminalDepth, { surface: hopSurfaces[terminalDepth - 1] }),
          })
          confirmedThisWave.push(receiptId)
        } else {
          const nextHop = assignment.targetHop
          const surface = hopSurfaces[nextHop - 1]
          const hopReceiptId = `hop:chain-${rootIdx}:h${nextHop}`
          scheduler.recordAttemptOutcome({
            branchKey: assignment.branchKey,
            targetSurfaceKey: assignment.targetSurfaceKey,
            status: 'hop_verified',
            hostVerified: true,
            newHop: makeHop(nextHop, {
              hopReceiptId,
              capabilityId: `cap:chain-${rootIdx}:h${nextHop}`,
              surface,
              serviceOrigin: `https://svc-${rootIdx}-${nextHop}.example.invalid`,
              tenantScope: `tenant-${rootIdx}-${nextHop}`,
              roleLabel: `role-${nextHop}`,
            }),
            nextTarget: {
              targetSurfaceKey: `svc-${rootIdx}-${nextHop + 1}|${hopSurfaces[nextHop]}|/v1/pivot-${nextHop + 1}`,
              surface: hopSurfaces[nextHop],
              serviceOrigin: `https://svc-${rootIdx}-${nextHop + 1}.example.invalid`,
              endpoint: `/v1/pivot-${nextHop + 1}`,
              method: 'POST',
              hypothesisClass: 'cross_surface_pivot',
              goalSummary: `Advance chain ${rootIdx} to Hop ${nextHop + 1}`,
            },
          })
          verifiedHopsThisWave.push({
            hopReceiptId,
            branchKey: assignment.branchKey,
            depth: nextHop,
            hostVerified: true,
            tenantScope: `tenant-${rootIdx}-${nextHop}`,
            roleLabel: `role-${nextHop}`,
            serviceOrigin: `https://svc-${rootIdx}-${nextHop}.example.invalid`,
            surface,
          })
        }
      }
    }

    scheduler.evaluateWaveProgress({
      completedAssignments: selection.assignments.length,
      confirmedCompositeReceipts: confirmedThisWave,
      verifiedHopReceipts: verifiedHopsThisWave,
    })
  }

  const telemetry = scheduler.getTelemetry()
  assert.ok(telemetry.totalAssignmentsDispatched >= 60, `expected >= 60 steps, got ${telemetry.totalAssignmentsDispatched}`)
  assert.equal(telemetry.maxDepthReached, MAX_CHAIN_DEPTH)
  assert.equal(telemetry.confirmedCompositeCount, 6)
  assert.equal(telemetry.prunedEdgeCount, 6)
  assert.ok(telemetry.deadEndSuppressedCount >= 12, `expected sibling suppression >= 12, got ${telemetry.deadEndSuppressedCount}`)
  assert.equal(telemetry.deadEndReprobeCount, 0)
  assert.ok(telemetry.deadEndReprobeWasteRate <= MAX_DEAD_END_WASTE_RATE)

  // Even if 2 external concurrent-race stale outcomes arrive late across >= 60 steps, waste stays <= 5%.
  scheduler.recordAttemptOutcome({
    branchKey: 'twin-1',
    targetSurfaceKey: 'svc-api|http|/api/v1/hardened-twin-1',
    status: 'failed',
    failureReason: 'invariant_enforced_hardened',
  })
  scheduler.recordAttemptOutcome({
    branchKey: 'twin-2',
    targetSurfaceKey: 'svc-api|http|/api/v1/hardened-twin-2',
    status: 'failed',
    failureReason: 'invariant_enforced_hardened',
  })
  const afterStaleRace = scheduler.getTelemetry()
  assert.equal(afterStaleRace.deadEndReprobeCount, 2)
  assert.ok(
    afterStaleRace.deadEndReprobeWasteRate <= MAX_DEAD_END_WASTE_RATE,
    `waste rate ${afterStaleRace.deadEndReprobeWasteRate} must be <= 5%`,
  )
})

// ============================================================================
// 7. LOC Budget (<= 800) & Zero-Benchmark-Literal Compliance
// ============================================================================

test('src/server/frontier-scheduler.ts stays <= 800 LOC and contains zero benchmark literals', () => {
  const filePath = resolve(process.cwd(), 'src/server/frontier-scheduler.ts')
  const source = readFileSync(filePath, 'utf8')
  const lineCount = source.split('\n').length
  assert.ok(lineCount <= 800, `frontier-scheduler.ts is ${lineCount} LOC (must be <= 800 LOC)`)

  const forbidden = [
    /\bpaygrid\b/i,
    /\bshipforge\b/i,
    /\bnexusiam\b/i,
    /\bconnecthub\b/i,
    /\b(?:PG|SF|NX|CH)-C\d+\b/,
    /\b(?:vault|registry|billing)\.internal\b/i,
  ]
  for (const pattern of forbidden) {
    assert.equal(pattern.test(source), false, `forbidden benchmark literal matched: ${pattern}`)
  }
})
