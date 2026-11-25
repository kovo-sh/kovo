/**
 * Frontier / Beam Multi-Wave Scheduler — Guardian v8 Layer 3 (plans/v8.md §5 & §M3).
 *
 * Pure, deterministic orchestration primitives ready to plug into `graph-coordinator.ts` and
 * `exec-dispatch.ts`:
 *  1. Bounded Chain Frontier (Beam Search, depth 1..6, beam width B = 8..16) ranked by exact EVI:
 *       EVI(branch) = P(next_hop_feasible | evidence) * TerminalImpactWeight * SurfaceNovelty
 *                     / (1 + AttemptsOnBranch)
 *  2. Explicit wave capacity quotas protecting high-EVI partial chains (depth >= 2) from flat
 *     route-sweep starvation while reserving a bounded discovery slice for newly unlocked surfaces.
 *  3. Hop-Checkpoint Branching (`selectNextWaveAssignments`) emitting strictly bounded (<= 2 KB)
 *     pre-hydrated checkpoint briefs carrying opaque Layer-1 handles and the next-hop goal.
 *  4. Progress-Aware Termination (`evaluateWaveProgress`) replacing flat DRY_ROUND_LIMIT with
 *     frontier-progress accounting across tenant/role/service/surface reach and composite receipts.
 *  5. 2-Strike Dead-End Pruning & Negative-Edge Memoization keeping dead-end re-probe waste <= 5%.
 */

import {
  finalizeHopCheckpointBrief,
  sanitizeCheckpointHandleRef,
  sanitizeCheckpointText,
  truncateBriefText,
  type CompactCheckpointHop,
  type HopCheckpointBrief,
  type HopCheckpointNextGoal,
} from './capability-ledger.ts'

export type { CompactCheckpointHop, HopCheckpointBrief, HopCheckpointNextGoal }

export const MIN_BEAM_WIDTH = 8
export const MAX_BEAM_WIDTH = 16
export const DEFAULT_BEAM_WIDTH = 12
export const MIN_CHAIN_DEPTH = 1
export const MAX_CHAIN_DEPTH = 6
export const MAX_CHECKPOINT_BRIEF_BYTES = 2048
export const DEAD_END_STRIKE_LIMIT = 2
export const MAX_DEAD_END_WASTE_RATE = 0.05
export const DEFAULT_UNPRODUCTIVE_WAVE_LIMIT = 2
export const DEFAULT_PARTIAL_CHAIN_MIN_SHARE = 0.6
export const DEFAULT_DISCOVERY_SLICE_SHARE = 0.25

// ---------------------------------------------------------------------------
// Domain Contracts
// ---------------------------------------------------------------------------

export type FrontierSurface =
  | 'http' | 'graphql' | 'ws' | 'sse' | 'browser' | 'webhook' | 'async_job' | 'idp' | 'cdn' | 'storage'

export type FrontierCapabilityKind =
  | 'identity_session' | 'scoped_token' | 'signing_material' | 'signed_artifact_or_url' | 'opaque_object_ref'
  | 'state_handle' | 'write_sink_handle' | 'internal_reach_handle' | 'parser_or_cache_primitive' | 'policy_asymmetry'

export type CausalEdgeBindingKind = 'value_binding' | 'derived_crypto_binding' | 'state_transition_binding' | 'async_pivot_binding'
export type NegativeEdgeReason = 'invariant_enforced_hardened' | 'control_blocked_cleanly' | 'decoy_guard_verified' | 'stagnation_2_strike'
export type BudgetTier = 'smoke' | 'standard' | 'deep'
export type FrontierLane = 'partial_chain' | 'subchain_fusion' | 'discovery' | 'route_sweep'
export type WaveStopReason = 'budget_exhausted' | 'duration_exhausted' | 'request_budget_exhausted' | 'frontier_exhausted' | 'frontier_stagnated'
export type WaveContinueReason = 'frontier_progress' | 'async_drain_pending' | 'awaiting_completions' | 'frontier_active'

export interface VerifiedHopHandle {
  hopIndex: number; hopReceiptId: string; capabilityId: string; kind: FrontierCapabilityKind
  surface: FrontierSurface; serviceOrigin: string; tenantScope: string; actorPersona: string
  roleLabel?: string; endpoint?: string; method?: string; edgeBindingKind?: CausalEdgeBindingKind; summary?: string
}

export interface FrontierTargetSurface {
  targetSurfaceKey: string; surface: FrontierSurface; serviceOrigin: string; endpoint: string; method?: string
  hypothesisClass: string; expectedBindingKind?: CausalEdgeBindingKind
  targetTenantScope?: string; targetRoleLabel?: string; goalSummary: string
}

export interface FrontierBranch {
  branchKey: string; parentBranchKey?: string | null; depth: number
  verifiedHops: readonly VerifiedHopHandle[]; nextTarget: FrontierTargetSurface
  fuseWithBranchKey?: string | null; preconditionGroupKey?: string | null
  feasibilityProb: number; terminalImpactWeight: number; surfaceNovelty: number
  attemptsOnBranch: number; consecutiveFailedAttempts: number
  lane?: 'partial_chain' | 'subchain_fusion'; createdWave: number; lastUpdatedWave: number
  confirmed?: boolean; expanded?: boolean; pruned?: boolean; pruneReason?: NegativeEdgeReason | null
}

export interface SurfaceSeedCandidate {
  candidateKey: string; surface: FrontierSurface; serviceOrigin: string; endpoint: string
  method?: string; hypothesisClass: string; goalSummary: string; tenantScope?: string
}

export interface DiscoverySurfaceCandidate extends SurfaceSeedCandidate { noveltyScore: number; unlockedByHopReceiptId?: string }
export interface RouteSweepCandidate extends SurfaceSeedCandidate { priorityScore: number }

export interface NegativeEdgeRecord {
  negativeEdgeKey: string; branchKey: string; preconditionCapIds: readonly string[]; preconditionGroupKey?: string | null
  targetSurfaceKey: string; hypothesisClass: string; reason: NegativeEdgeReason
  failedAttempts: number; falsifiedByExchangeIds: readonly string[]; recordedAtWave: number
}

export type EviInput = Pick<FrontierBranch, 'feasibilityProb' | 'terminalImpactWeight' | 'surfaceNovelty' | 'attemptsOnBranch'>
export interface ScoredFrontierBranch { branch: FrontierBranch; evi: number; pairKey: string; negativeEdgeKey: string; siblingEdgeKey: string | null }

export interface WaveAssignment {
  assignmentId: string; waveNo: number; lane: FrontierLane; branchKey: string; depth: number; targetHop: number
  evi: number; targetSurfaceKey: string; hypothesisClass: string; preconditionCapIds: readonly string[]
  negativeEdgeKey: string; checkpointBrief: HopCheckpointBrief; checkpointJson: string; checkpointBytes: number
}

export interface WaveQuotaConfig { partialChainMinShare?: number; discoverySliceShare?: number; maxCheckpointBriefBytes?: number }

export interface WaveQuotaSummary {
  capacity: number; reservedDeepChainSlots: number; reservedDiscoverySlots: number
  assignedDeepChainSlots: number; assignedShallowChainSlots: number; assignedDiscoverySlots: number; assignedRouteSweepSlots: number
  skippedNegativeEdges: number; skippedPrunedBranches: number; skippedMaxDepthBranches: number; skippedSameWaveSiblings: number
}

export interface SelectWaveInput {
  waveNo: number; waveCapacity: number; beamWidth?: number; branches: readonly FrontierBranch[]
  discoveryCandidates?: readonly DiscoverySurfaceCandidate[]; routeSweepCandidates?: readonly RouteSweepCandidate[]
  negativeEdgeKeys?: ReadonlySet<string>; prunedPairKeys?: ReadonlySet<string>; quota?: WaveQuotaConfig
}

export interface WaveSelectionResult {
  waveNo: number; beamWidth: number; activeBeam: readonly ScoredFrontierBranch[]
  assignments: readonly WaveAssignment[]; quota: WaveQuotaSummary
}

export interface VerifiedHopReceiptEvent {
  hopReceiptId: string; branchKey: string; depth: number; hostVerified: boolean
  tenantScope: string; roleLabel?: string; serviceOrigin: string; surface: FrontierSurface; capabilityId?: string
}

export interface FrontierReachState {
  tenants: Set<string>; roles: Set<string>; services: Set<string>; surfaces: Set<string>
  verifiedHopReceiptIds: Set<string>; confirmedCompositeReceiptIds: Set<string>
}

export interface ReachDelta {
  newTenants: string[]; newRoles: string[]; newServices: string[]; newSurfaces: string[]
  newHopReceiptIds: string[]; newCompositeReceiptIds: string[]
}

export interface WaveProgressInput {
  waveNo: number; completedAssignments: number; reach: FrontierReachState
  confirmedCompositeReceipts?: readonly string[]; verifiedHopReceipts?: readonly VerifiedHopReceiptEvent[]
  activeFrontierCount: number; unlockedDiscoveryCount?: number; pendingAsyncOrOob?: number
  consecutiveUnproductiveWaves: number; unproductiveWaveLimit?: number
  budgetUsdSpent?: number; budgetUsdLimit?: number; elapsedMs?: number; maxDurationMs?: number
  requestsSpent?: number; agentRequestBudget?: number; coverageSettledCount?: number
}

export interface WaveProgressDecision {
  decision: 'continue' | 'stop'; reason: WaveStopReason | WaveContinueReason
  productive: boolean; nextUnproductiveWaves: number; reachDelta: ReachDelta; detail: string
}

export interface PivotAttemptOutcome {
  branchKey: string; targetSurfaceKey: string; hypothesisClass?: string
  status: 'confirmed_composite' | 'hop_verified' | 'failed'; waveNo?: number
  compositeProofReceiptId?: string; newHop?: VerifiedHopHandle; nextTarget?: FrontierTargetSurface
  nextFeasibilityProb?: number; nextTerminalImpactWeight?: number; nextSurfaceNovelty?: number
  childBranchKey?: string; keepParentActive?: boolean
  failureReason?: NegativeEdgeReason; falsifiedByExchangeIds?: readonly string[]; hostVerified?: boolean
}

export interface AttemptUpdateResult {
  branchKey: string; status: PivotAttemptOutcome['status']; accepted: boolean; reason: string
  pruned: boolean; negativeEdge?: NegativeEdgeRecord; childBranchKey?: string; wasDeadEndReprobe: boolean
}

export interface FrontierWasteTelemetry {
  wavesScheduled: number; totalAssignmentsDispatched: number; deadEndReprobeCount: number
  deadEndSuppressedCount: number; deadEndReprobeWasteRate: number; prunedEdgeCount: number
  stagnationPrunedBranches: number; activeBeamSize: number; maxDepthReached: number; confirmedCompositeCount: number
  reachCounts: { tenants: number; roles: number; services: number; surfaces: number }
}

export interface FrontierSchedulerOptions {
  beamWidth?: number; budgetTier?: BudgetTier; strikeLimit?: number
  unproductiveWaveLimit?: number; quota?: WaveQuotaConfig
}

// ---------------------------------------------------------------------------
// Pure Scoring, Keying & Sanitization
// ---------------------------------------------------------------------------


export function clampBeamWidth(width: number | undefined): number {
  return typeof width === 'number' && Number.isFinite(width)
    ? Math.max(MIN_BEAM_WIDTH, Math.min(MAX_BEAM_WIDTH, Math.round(width)))
    : DEFAULT_BEAM_WIDTH
}

export function resolveBeamWidthForTier(tier: BudgetTier): number {
  return tier === 'smoke' ? MIN_BEAM_WIDTH : tier === 'deep' ? MAX_BEAM_WIDTH : DEFAULT_BEAM_WIDTH
}

/** Exact v8 EVI: P(next_hop_feasible | evidence) * TerminalImpactWeight * SurfaceNovelty / (1 + AttemptsOnBranch). */
export function computeBranchEvi(input: EviInput): number {
  const p = Number.isFinite(input.feasibilityProb) ? Math.max(0, Math.min(1, input.feasibilityProb)) : 0
  const weight = Number.isFinite(input.terminalImpactWeight) ? Math.max(0, input.terminalImpactWeight) : 0
  const novelty = Number.isFinite(input.surfaceNovelty) ? Math.max(0, input.surfaceNovelty) : 0
  const attempts = Number.isFinite(input.attemptsOnBranch) ? Math.max(0, input.attemptsOnBranch) : 0
  return (p * weight * novelty) / (1 + attempts)
}

export function computeBranchPairKey(branchKey: string, targetSurfaceKey: string): string {
  return `${branchKey.trim()}::${targetSurfaceKey.trim()}`
}

export function computeNegativeEdgeKey(preconditionCapIds: readonly string[], targetSurfaceKey: string, hypothesisClass: string): string {
  const caps = [...new Set(preconditionCapIds.map(id => id.trim()).filter(Boolean))].sort()
  return `${caps.join(',')}|${targetSurfaceKey.trim()}|${hypothesisClass.trim().toLowerCase()}`
}

export function computeSiblingGroupEdgeKey(
  preconditionGroupKey: string | null | undefined,
  targetSurfaceKey: string,
  hypothesisClass: string,
): string | null {
  const group = preconditionGroupKey?.trim()
  return group ? `group:${group}|${targetSurfaceKey.trim()}|${hypothesisClass.trim().toLowerCase()}` : null
}

export function branchPreconditionCapIds(branch: Pick<FrontierBranch, 'branchKey' | 'verifiedHops'>): string[] {
  const caps = [...new Set(branch.verifiedHops.map(h => h.capabilityId.trim()).filter(Boolean))].sort()
  return caps.length > 0 ? caps : [`branch:${branch.branchKey.trim()}`]
}

function branchKeys(branch: FrontierBranch) {
  const caps = branchPreconditionCapIds(branch)
  const { targetSurfaceKey, hypothesisClass } = branch.nextTarget
  return {
    caps,
    pairKey: computeBranchPairKey(branch.branchKey, targetSurfaceKey),
    negativeEdgeKey: computeNegativeEdgeKey(caps, targetSurfaceKey, hypothesisClass),
    siblingEdgeKey: computeSiblingGroupEdgeKey(branch.preconditionGroupKey, targetSurfaceKey, hypothesisClass),
  }
}

export const sanitizeHandleRef = sanitizeCheckpointHandleRef

function compareScoredBranches(a: ScoredFrontierBranch, b: ScoredFrontierBranch): number {
  return (b.evi - a.evi)
    || (b.branch.depth - a.branch.depth)
    || (b.branch.terminalImpactWeight - a.branch.terminalImpactWeight)
    || (a.branch.attemptsOnBranch - b.branch.attemptsOnBranch)
    || (a.branch.branchKey < b.branch.branchKey ? -1 : a.branch.branchKey > b.branch.branchKey ? 1 : 0)
}

/** Score, filter, deterministically sort, and cap active partial chains to beam width B (8..16). */
export function rankAndPruneBeam(
  branches: readonly FrontierBranch[],
  beamWidth?: number,
  negativeEdgeKeys?: ReadonlySet<string>,
  prunedPairKeys?: ReadonlySet<string>,
): ScoredFrontierBranch[] {
  const scored: ScoredFrontierBranch[] = []
  for (const branch of branches) {
    if (branch.confirmed || branch.expanded || branch.pruned) continue
    if (branch.depth < MIN_CHAIN_DEPTH || branch.depth > MAX_CHAIN_DEPTH) continue
    const keys = branchKeys(branch)
    if (prunedPairKeys?.has(keys.pairKey)) continue
    if (negativeEdgeKeys?.has(keys.negativeEdgeKey) || (keys.siblingEdgeKey && negativeEdgeKeys?.has(keys.siblingEdgeKey))) continue
    scored.push({ branch, evi: computeBranchEvi(branch), pairKey: keys.pairKey, negativeEdgeKey: keys.negativeEdgeKey, siblingEdgeKey: keys.siblingEdgeKey })
  }
  scored.sort(compareScoredBranches)
  return scored.slice(0, clampBeamWidth(beamWidth))
}

// ---------------------------------------------------------------------------
// Hop-Checkpoint Brief Serialization (Strictly <= 2 KB UTF-8)
// ---------------------------------------------------------------------------

function compactHop(hop: VerifiedHopHandle, compact: boolean): CompactCheckpointHop {
  const out: CompactCheckpointHop = {
    hop: hop.hopIndex,
    receiptId: sanitizeHandleRef(hop.hopReceiptId, `hop:${hop.hopIndex}`),
    capId: sanitizeHandleRef(hop.capabilityId, `cap:redacted:${hop.hopIndex}`),
    kind: hop.kind, surface: hop.surface,
    service: truncateBriefText(hop.serviceOrigin, compact ? 28 : 48),
    tenant: truncateBriefText(hop.tenantScope, compact ? 24 : 36),
    actor: truncateBriefText(hop.actorPersona, compact ? 24 : 36),
  }
  if (!compact) {
    if (hop.roleLabel) out.role = truncateBriefText(hop.roleLabel, 28)
    if (hop.endpoint) out.at = sanitizeCheckpointText(`${hop.method ? `${hop.method.toUpperCase()} ` : ''}${hop.endpoint}`, 64)
    if (hop.edgeBindingKind) out.binding = hop.edgeBindingKind
  }
  return out
}

/** Build a pre-hydrated Hop-Checkpoint brief strictly <= 2 KB UTF-8 with scrubbed opaque handles. */
export function buildHopCheckpointBrief(
  branch: FrontierBranch,
  evi: number,
  maxBytes = MAX_CHECKPOINT_BRIEF_BYTES,
): { brief: HopCheckpointBrief; checkpointJson: string; checkpointBytes: number } {
  const cap = Math.max(256, Math.min(MAX_CHECKPOINT_BRIEF_BYTES, Math.floor(maxBytes)))
  const ordered = [...branch.verifiedHops].sort((a, b) => a.hopIndex - b.hopIndex)
  const allHandles = [...new Set(ordered.map(h => sanitizeHandleRef(h.capabilityId, `cap:redacted:${h.hopIndex}`)))]
  const make = (hops: CompactCheckpointHop[], omitted: number, handles: string[], gl: number, el: number, opt: boolean): HopCheckpointBrief => ({
    schema: 'v8.hop_checkpoint.v1', branchKey: truncateBriefText(branch.branchKey, 64),
    depth: branch.depth, targetHop: Math.min(MAX_CHAIN_DEPTH, branch.depth + 1),
    mode: branch.fuseWithBranchKey ? 'fuse' : 'pivot', evi: Number(evi.toFixed(6)),
    verifiedHops: hops, ...(omitted > 0 ? { omittedEarlierHops: omitted } : {}),
    capabilityHandles: handles, ...(branch.fuseWithBranchKey ? { fuseWithBranchKey: truncateBriefText(branch.fuseWithBranchKey, 64) } : {}),
    nextGoal: {
      targetSurfaceKey: truncateBriefText(branch.nextTarget.targetSurfaceKey, 80), surface: branch.nextTarget.surface,
      service: truncateBriefText(branch.nextTarget.serviceOrigin, 48), endpoint: sanitizeCheckpointText(branch.nextTarget.endpoint, el),
      ...(branch.nextTarget.method ? { method: branch.nextTarget.method.toUpperCase() } : {}),
      hypothesisClass: truncateBriefText(branch.nextTarget.hypothesisClass, 48),
      ...(opt && branch.nextTarget.expectedBindingKind ? { expectedBinding: branch.nextTarget.expectedBindingKind } : {}),
      ...(opt && branch.nextTarget.targetTenantScope ? { targetTenant: truncateBriefText(branch.nextTarget.targetTenantScope, 36) } : {}),
      ...(opt && branch.nextTarget.targetRoleLabel ? { targetRole: truncateBriefText(branch.nextTarget.targetRoleLabel, 32) } : {}),
      goal: sanitizeCheckpointText(branch.nextTarget.goalSummary, gl),
    },
    doNotRediscover: true,
  })
  for (const pass of [{ compact: false, gl: 180, el: 96, opt: true }, { compact: true, gl: 110, el: 64, opt: false }]) {
    const hops = ordered.map(h => compactHop(h, pass.compact))
    for (let keep = hops.length; keep >= 0; keep -= 1) {
      const slice = keep === 0 ? [] : hops.slice(hops.length - keep)
      const handles = keep === 0 ? allHandles.slice(-Math.min(allHandles.length, 4)) : allHandles
      const brief = make(slice, hops.length - slice.length, handles, pass.gl, pass.el, pass.opt)
      const json = JSON.stringify(brief)
      const bytes = Buffer.byteLength(json, 'utf8')
      if (bytes <= cap) return { brief, checkpointJson: json, checkpointBytes: bytes }
    }
  }
  return finalizeHopCheckpointBrief(make([], ordered.length, allHandles.slice(-2), 48, 40, false), cap)
}

function buildSeedBrief(mode: 'discover' | 'sweep', candidate: SurfaceSeedCandidate, score: number, maxBytes: number) {
  const cap = Math.max(256, Math.min(MAX_CHECKPOINT_BRIEF_BYTES, Math.floor(maxBytes)))
  const targetSurfaceKey = `${candidate.serviceOrigin}|${candidate.surface}|${candidate.endpoint}`
  const make = (gl: number, el: number): HopCheckpointBrief => ({
    schema: 'v8.hop_checkpoint.v1', branchKey: truncateBriefText(candidate.candidateKey, 64),
    depth: 0, targetHop: 1, mode, evi: Number(score.toFixed(6)), verifiedHops: [], capabilityHandles: [],
    nextGoal: {
      targetSurfaceKey: truncateBriefText(targetSurfaceKey, 80), surface: candidate.surface,
      service: truncateBriefText(candidate.serviceOrigin, 48), endpoint: sanitizeCheckpointText(candidate.endpoint, el),
      ...(candidate.method ? { method: candidate.method.toUpperCase() } : {}),
      hypothesisClass: truncateBriefText(candidate.hypothesisClass, 48),
      ...(candidate.tenantScope ? { targetTenant: truncateBriefText(candidate.tenantScope, 36) } : {}),
      goal: sanitizeCheckpointText(candidate.goalSummary, gl),
    },
    doNotRediscover: true,
  })
  for (const [gl, el] of [[160, 96], [80, 56], [40, 36]] as const) {
    const brief = make(gl, el)
    const json = JSON.stringify(brief)
    const bytes = Buffer.byteLength(json, 'utf8')
    if (bytes <= cap) return { brief, checkpointJson: json, checkpointBytes: bytes }
  }
  return finalizeHopCheckpointBrief(make(24, 24), cap)
}

// ---------------------------------------------------------------------------
// Wave Assignment Selection (Explicit Quotas + Sibling Deduplication)
// ---------------------------------------------------------------------------

/** Select next-wave worker assignments protecting depth >= 2 partial chains + discovery slice. */
export function selectNextWaveAssignments(input: SelectWaveInput): WaveSelectionResult {
  const capacity = Math.max(0, Math.floor(input.waveCapacity))
  const beamWidth = clampBeamWidth(input.beamWidth)
  const maxBriefBytes = Math.min(MAX_CHECKPOINT_BRIEF_BYTES, Math.max(256, Math.floor(input.quota?.maxCheckpointBriefBytes ?? MAX_CHECKPOINT_BRIEF_BYTES)))
  const partialMinShare = Math.max(0, Math.min(1, input.quota?.partialChainMinShare ?? DEFAULT_PARTIAL_CHAIN_MIN_SHARE))
  const discoveryShare = Math.max(0, Math.min(0.5, input.quota?.discoverySliceShare ?? DEFAULT_DISCOVERY_SLICE_SHARE))

  let skippedNegativeEdges = 0, skippedPrunedBranches = 0, skippedMaxDepthBranches = 0, skippedSameWaveSiblings = 0
  const expandable: FrontierBranch[] = []
  for (const branch of input.branches) {
    if (branch.confirmed || branch.expanded) continue
    const keys = branchKeys(branch)
    if (branch.pruned || input.prunedPairKeys?.has(keys.pairKey)) { skippedPrunedBranches += 1; continue }
    if (input.negativeEdgeKeys?.has(keys.negativeEdgeKey) || (keys.siblingEdgeKey && input.negativeEdgeKeys?.has(keys.siblingEdgeKey))) {
      skippedNegativeEdges += 1; continue
    }
    if (branch.depth < MIN_CHAIN_DEPTH) continue
    if (branch.depth >= MAX_CHAIN_DEPTH) { skippedMaxDepthBranches += 1; continue }
    expandable.push(branch)
  }

  const activeBeam = rankAndPruneBeam(expandable, beamWidth, input.negativeEdgeKeys, input.prunedPairKeys)
  const deepChains = activeBeam.filter(item => item.branch.depth >= 2)
  const shallowChains = activeBeam.filter(item => item.branch.depth === 1)

  const filterSeeds = <T extends SurfaceSeedCandidate>(items: readonly T[] | undefined, scoreOf: (c: T) => number): T[] =>
    [...(items ?? [])].filter(c => {
      const key = computeNegativeEdgeKey([`branch:${c.candidateKey}`], `${c.serviceOrigin}|${c.surface}|${c.endpoint}`, c.hypothesisClass)
      if (input.negativeEdgeKeys?.has(key)) { skippedNegativeEdges += 1; return false }
      return true
    }).sort((a, b) => scoreOf(b) - scoreOf(a) || (a.candidateKey < b.candidateKey ? -1 : a.candidateKey > b.candidateKey ? 1 : 0))

  const sortedDiscovery = filterSeeds(input.discoveryCandidates, c => c.noveltyScore)
  const sortedSweeps = filterSeeds(input.routeSweepCandidates, c => c.priorityScore)

  const desiredDiscovery = capacity >= 2 && sortedDiscovery.length > 0 && discoveryShare > 0
    ? Math.min(sortedDiscovery.length, Math.max(1, Math.floor(capacity * discoveryShare)))
    : 0
  const reservedDeepChainSlots = deepChains.length > 0 && capacity > 0
    ? Math.min(deepChains.length, Math.min(Math.max(1, capacity - desiredDiscovery), Math.max(1, Math.ceil(capacity * partialMinShare))))
    : 0
  const reservedDiscoverySlots = Math.min(desiredDiscovery, Math.max(0, capacity - reservedDeepChainSlots))

  const assignments: WaveAssignment[] = []
  const usedKeys = new Set<string>()
  const usedWaveEdges = new Set<string>()
  let assignedDeepChainSlots = 0, assignedShallowChainSlots = 0, assignedDiscoverySlots = 0, assignedRouteSweepSlots = 0

  const assignBranch = (scored: ScoredFrontierBranch): boolean => {
    if (assignments.length >= capacity || usedKeys.has(scored.branch.branchKey)) return false
    if (usedWaveEdges.has(scored.negativeEdgeKey) || (scored.siblingEdgeKey && usedWaveEdges.has(scored.siblingEdgeKey))) {
      skippedSameWaveSiblings += 1; return false
    }
    const { brief, checkpointJson, checkpointBytes } = buildHopCheckpointBrief(scored.branch, scored.evi, maxBriefBytes)
    const lane: FrontierLane = scored.branch.fuseWithBranchKey || scored.branch.lane === 'subchain_fusion' ? 'subchain_fusion' : 'partial_chain'
    assignments.push({
      assignmentId: `w${input.waveNo}:${lane}:${scored.branch.branchKey}`, waveNo: input.waveNo, lane,
      branchKey: scored.branch.branchKey, depth: scored.branch.depth, targetHop: Math.min(MAX_CHAIN_DEPTH, scored.branch.depth + 1),
      evi: scored.evi, targetSurfaceKey: scored.branch.nextTarget.targetSurfaceKey, hypothesisClass: scored.branch.nextTarget.hypothesisClass,
      preconditionCapIds: branchPreconditionCapIds(scored.branch), negativeEdgeKey: scored.negativeEdgeKey,
      checkpointBrief: brief, checkpointJson, checkpointBytes,
    })
    usedKeys.add(scored.branch.branchKey)
    usedWaveEdges.add(scored.negativeEdgeKey)
    if (scored.siblingEdgeKey) usedWaveEdges.add(scored.siblingEdgeKey)
    if (scored.branch.depth >= 2) assignedDeepChainSlots += 1; else assignedShallowChainSlots += 1
    return true
  }

  const assignSeed = (lane: 'discovery' | 'route_sweep', c: SurfaceSeedCandidate, score: number): boolean => {
    if (assignments.length >= capacity || usedKeys.has(c.candidateKey)) return false
    const targetSurfaceKey = `${c.serviceOrigin}|${c.surface}|${c.endpoint}`
    const negativeEdgeKey = computeNegativeEdgeKey([`branch:${c.candidateKey}`], targetSurfaceKey, c.hypothesisClass)
    const { brief, checkpointJson, checkpointBytes } = buildSeedBrief(lane === 'discovery' ? 'discover' : 'sweep', c, score, maxBriefBytes)
    assignments.push({
      assignmentId: `w${input.waveNo}:${lane}:${c.candidateKey}`, waveNo: input.waveNo, lane,
      branchKey: c.candidateKey, depth: 0, targetHop: 1, evi: score, targetSurfaceKey, hypothesisClass: c.hypothesisClass,
      preconditionCapIds: [`branch:${c.candidateKey}`], negativeEdgeKey, checkpointBrief: brief, checkpointJson, checkpointBytes,
    })
    usedKeys.add(c.candidateKey)
    if (lane === 'discovery') assignedDiscoverySlots += 1; else assignedRouteSweepSlots += 1
    return true
  }

  for (const s of deepChains) { if (assignedDeepChainSlots >= reservedDeepChainSlots) break; assignBranch(s) }
  for (const c of sortedDiscovery) { if (assignedDiscoverySlots >= reservedDiscoverySlots) break; assignSeed('discovery', c, c.noveltyScore) }
  for (const s of deepChains) { if (assignments.length >= capacity) break; assignBranch(s) }
  for (const s of shallowChains) { if (assignments.length >= capacity) break; assignBranch(s) }
  for (const c of sortedDiscovery) { if (assignments.length >= capacity) break; assignSeed('discovery', c, c.noveltyScore) }
  for (const c of sortedSweeps) { if (assignments.length >= capacity) break; assignSeed('route_sweep', c, c.priorityScore) }

  return {
    waveNo: input.waveNo, beamWidth, activeBeam, assignments,
    quota: {
      capacity, reservedDeepChainSlots, reservedDiscoverySlots,
      assignedDeepChainSlots, assignedShallowChainSlots, assignedDiscoverySlots, assignedRouteSweepSlots,
      skippedNegativeEdges, skippedPrunedBranches, skippedMaxDepthBranches, skippedSameWaveSiblings,
    },
  }
}

// ---------------------------------------------------------------------------
// Progress-Aware Termination
// ---------------------------------------------------------------------------

export function createEmptyReachState(): FrontierReachState {
  return { tenants: new Set(), roles: new Set(), services: new Set(), surfaces: new Set(), verifiedHopReceiptIds: new Set(), confirmedCompositeReceiptIds: new Set() }
}

/**
 * Evaluate frontier progress: productive if yielding EITHER a confirmed CompositeProofReceipt
 * OR a host-verified new HopReceipt expanding tenant/role/service/surface reach.
 */
export function evaluateWaveProgress(input: WaveProgressInput): WaveProgressDecision {
  const delta: ReachDelta = { newTenants: [], newRoles: [], newServices: [], newSurfaces: [], newHopReceiptIds: [], newCompositeReceiptIds: [] }
  for (const rawId of input.confirmedCompositeReceipts ?? []) {
    const id = rawId.trim()
    if (!id || input.reach.confirmedCompositeReceiptIds.has(id)) continue
    input.reach.confirmedCompositeReceiptIds.add(id)
    delta.newCompositeReceiptIds.push(id)
  }
  for (const hop of input.verifiedHopReceipts ?? []) {
    if (hop.hostVerified !== true) continue
    const hopId = hop.hopReceiptId.trim()
    if (!hopId || input.reach.verifiedHopReceiptIds.has(hopId)) continue
    const tenant = hop.tenantScope.trim()
    const roleKey = hop.roleLabel?.trim() ? `${tenant}::${hop.roleLabel.trim()}` : ''
    const service = hop.serviceOrigin.trim()
    const surfaceKey = `${service}::${hop.surface}`
    let expanded = false
    if (tenant && !input.reach.tenants.has(tenant)) { input.reach.tenants.add(tenant); delta.newTenants.push(tenant); expanded = true }
    if (roleKey && !input.reach.roles.has(roleKey)) { input.reach.roles.add(roleKey); delta.newRoles.push(roleKey); expanded = true }
    if (service && !input.reach.services.has(service)) { input.reach.services.add(service); delta.newServices.push(service); expanded = true }
    if (service && !input.reach.surfaces.has(surfaceKey)) { input.reach.surfaces.add(surfaceKey); delta.newSurfaces.push(surfaceKey); expanded = true }
    input.reach.verifiedHopReceiptIds.add(hopId)
    if (expanded) delta.newHopReceiptIds.push(hopId)
  }

  const productive = delta.newCompositeReceiptIds.length > 0 || delta.newHopReceiptIds.length > 0
  const limit = Math.max(1, Math.floor(input.unproductiveWaveLimit ?? DEFAULT_UNPRODUCTIVE_WAVE_LIMIT))
  const nextStreak = productive ? 0 : input.completedAssignments <= 0 ? input.consecutiveUnproductiveWaves : input.consecutiveUnproductiveWaves + 1
  const out = (decision: 'continue' | 'stop', reason: WaveStopReason | WaveContinueReason, detail: string, streak = nextStreak): WaveProgressDecision => ({
    decision, reason, productive, nextUnproductiveWaves: streak, reachDelta: delta, detail,
  })

  if (input.budgetUsdLimit && input.budgetUsdLimit > 0 && (input.budgetUsdSpent ?? 0) >= input.budgetUsdLimit) {
    return out('stop', 'budget_exhausted', `USD budget bound reached (${input.budgetUsdSpent}/${input.budgetUsdLimit}).`, productive ? 0 : input.consecutiveUnproductiveWaves)
  }
  if (input.maxDurationMs && input.maxDurationMs > 0 && (input.elapsedMs ?? 0) >= input.maxDurationMs) {
    return out('stop', 'duration_exhausted', `Wall-clock bound reached (${input.elapsedMs}ms/${input.maxDurationMs}ms).`, productive ? 0 : input.consecutiveUnproductiveWaves)
  }
  if (input.agentRequestBudget && input.agentRequestBudget > 0 && (input.requestsSpent ?? 0) >= input.agentRequestBudget) {
    return out('stop', 'request_budget_exhausted', `Agent request budget bound reached (${input.requestsSpent}/${input.agentRequestBudget}).`, productive ? 0 : input.consecutiveUnproductiveWaves)
  }
  if ((input.pendingAsyncOrOob ?? 0) > 0) return out('continue', 'async_drain_pending', `Continuing wave ${input.waveNo}: ${input.pendingAsyncOrOob} async/OOB callback(s) pending.`)
  if (input.activeFrontierCount <= 0 && (input.unlockedDiscoveryCount ?? 0) <= 0) {
    return out('stop', 'frontier_exhausted', `Frontier exhausted after wave ${input.waveNo} (${input.coverageSettledCount ?? 0} coverage settlement(s)).`)
  }
  if (!productive && nextStreak >= limit) return out('stop', 'frontier_stagnated', `Frontier stagnated for ${nextStreak} consecutive unproductive wave(s).`)
  if (productive) return out('continue', 'frontier_progress', `Wave ${input.waveNo} advanced frontier (${delta.newCompositeReceiptIds.length} composite, ${delta.newHopReceiptIds.length} hop reach expansion(s)).`, 0)
  if (input.completedAssignments <= 0) return out('continue', 'awaiting_completions', `Wave ${input.waveNo} awaiting completed assignments (streak ${nextStreak}).`)
  return out('continue', 'frontier_active', `Wave ${input.waveNo} unproductive (${nextStreak}/${limit}); frontier remains active.`)
}

// ---------------------------------------------------------------------------
// Stateful FrontierScheduler Coordinator (2-Strike Pruning + Waste Telemetry)
// ---------------------------------------------------------------------------

export class FrontierScheduler {
  readonly beamWidth: number
  readonly strikeLimit: number
  readonly unproductiveWaveLimit: number
  readonly quotaConfig: WaveQuotaConfig

  private readonly branches = new Map<string, FrontierBranch>()
  private readonly discoveryQueue = new Map<string, DiscoverySurfaceCandidate>()
  private readonly routeSweepQueue = new Map<string, RouteSweepCandidate>()
  private readonly negativeEdges = new Map<string, NegativeEdgeRecord>()
  private readonly prunedPairs = new Set<string>()
  private readonly consecutiveFailures = new Map<string, number>()
  private readonly reach: FrontierReachState = createEmptyReachState()
  private readonly recordedCompositeReceiptIds = new Set<string>()

  private waveNo = 0
  private consecutiveUnproductiveWaves = 0
  private totalAssignmentsDispatched = 0
  private deadEndReprobeCount = 0
  private deadEndSuppressedCount = 0
  private stagnationPrunedBranches = 0
  private maxDepthReached = 0

  constructor(options: FrontierSchedulerOptions = {}) {
    this.beamWidth = options.beamWidth !== undefined
      ? clampBeamWidth(options.beamWidth)
      : options.budgetTier ? resolveBeamWidthForTier(options.budgetTier) : DEFAULT_BEAM_WIDTH
    this.strikeLimit = Math.max(1, Math.floor(options.strikeLimit ?? DEAD_END_STRIKE_LIMIT))
    this.unproductiveWaveLimit = Math.max(1, Math.floor(options.unproductiveWaveLimit ?? DEFAULT_UNPRODUCTIVE_WAVE_LIMIT))
    this.quotaConfig = options.quota ?? {}
  }

  admitBranch(branch: FrontierBranch): boolean {
    if (branch.depth < MIN_CHAIN_DEPTH || branch.depth > MAX_CHAIN_DEPTH) return false
    const keys = branchKeys(branch)
    if (this.prunedPairs.has(keys.pairKey) || this.negativeEdges.has(keys.negativeEdgeKey) || (keys.siblingEdgeKey && this.negativeEdges.has(keys.siblingEdgeKey))) {
      this.deadEndSuppressedCount += 1
      return false
    }
    this.branches.set(branch.branchKey, { ...branch, verifiedHops: [...branch.verifiedHops] })
    if (branch.depth > this.maxDepthReached) this.maxDepthReached = branch.depth
    return true
  }

  admitBranches(branches: readonly FrontierBranch[]): number {
    let admitted = 0
    for (const branch of branches) if (this.admitBranch(branch)) admitted += 1
    return admitted
  }

  addDiscoverySurface(candidate: DiscoverySurfaceCandidate): void { this.discoveryQueue.set(candidate.candidateKey, candidate) }
  addRouteSweepCandidate(candidate: RouteSweepCandidate): void { this.routeSweepQueue.set(candidate.candidateKey, candidate) }
  getBranch(branchKey: string): FrontierBranch | undefined { return this.branches.get(branchKey) }

  seedNegativeEdges(edges: readonly NegativeEdgeRecord[]): void {
    for (const edge of edges) {
      this.negativeEdges.set(edge.negativeEdgeKey, edge)
      const sibKey = computeSiblingGroupEdgeKey(edge.preconditionGroupKey, edge.targetSurfaceKey, edge.hypothesisClass)
      if (sibKey) this.negativeEdges.set(sibKey, edge)
      this.prunedPairs.add(computeBranchPairKey(edge.branchKey, edge.targetSurfaceKey))
    }
  }

  exportNegativeEdges(): NegativeEdgeRecord[] {
    const unique = new Map<string, NegativeEdgeRecord>()
    for (const edge of this.negativeEdges.values()) unique.set(edge.negativeEdgeKey, edge)
    return [...unique.values()].sort((a, b) =>
      a.recordedAtWave - b.recordedAtWave || (a.negativeEdgeKey < b.negativeEdgeKey ? -1 : a.negativeEdgeKey > b.negativeEdgeKey ? 1 : 0))
  }

  hasNegativeEdge(preconditionCapIds: readonly string[], targetSurfaceKey: string, hypothesisClass: string, preconditionGroupKey?: string | null): boolean {
    const key = computeNegativeEdgeKey(preconditionCapIds, targetSurfaceKey, hypothesisClass)
    if (this.negativeEdges.has(key)) return true
    const sibKey = computeSiblingGroupEdgeKey(preconditionGroupKey, targetSurfaceKey, hypothesisClass)
    return Boolean(sibKey && this.negativeEdges.has(sibKey))
  }

  getActiveBeam(): ScoredFrontierBranch[] {
    return rankAndPruneBeam([...this.branches.values()], this.beamWidth, new Set(this.negativeEdges.keys()), this.prunedPairs)
  }

  selectNextWaveAssignments(waveCapacity: number, quotaOverride?: WaveQuotaConfig): WaveSelectionResult {
    this.waveNo += 1
    const result = selectNextWaveAssignments({
      waveNo: this.waveNo, waveCapacity, beamWidth: this.beamWidth,
      branches: [...this.branches.values()],
      discoveryCandidates: [...this.discoveryQueue.values()],
      routeSweepCandidates: [...this.routeSweepQueue.values()],
      negativeEdgeKeys: new Set(this.negativeEdges.keys()),
      prunedPairKeys: this.prunedPairs,
      quota: { ...this.quotaConfig, ...quotaOverride },
    })
    this.totalAssignmentsDispatched += result.assignments.length
    this.deadEndSuppressedCount += result.quota.skippedNegativeEdges + result.quota.skippedPrunedBranches + result.quota.skippedSameWaveSiblings
    for (const a of result.assignments) {
      if (a.lane === 'discovery') this.discoveryQueue.delete(a.branchKey)
      if (a.lane === 'route_sweep') this.routeSweepQueue.delete(a.branchKey)
    }
    return result
  }

  recordAttemptOutcome(outcome: PivotAttemptOutcome): AttemptUpdateResult {
    const wave = outcome.waveNo ?? this.waveNo
    const branch = this.branches.get(outcome.branchKey)
    const pairKey = computeBranchPairKey(outcome.branchKey, outcome.targetSurfaceKey)
    const hypothesisClass = outcome.hypothesisClass ?? branch?.nextTarget.hypothesisClass ?? 'unknown'
    const preconditionCapIds = branch ? branchPreconditionCapIds(branch) : [`branch:${outcome.branchKey}`]
    const negKey = computeNegativeEdgeKey(preconditionCapIds, outcome.targetSurfaceKey, hypothesisClass)
    const sibKey = computeSiblingGroupEdgeKey(branch?.preconditionGroupKey, outcome.targetSurfaceKey, hypothesisClass)
    const strikeKeys = [pairKey, negKey, ...(sibKey ? [sibKey] : [])]

    const wasAlreadyPruned = this.prunedPairs.has(pairKey) || this.negativeEdges.has(negKey) || Boolean(sibKey && this.negativeEdges.has(sibKey)) || branch?.pruned === true
    if (wasAlreadyPruned) this.deadEndReprobeCount += 1
    if (!branch) return { branchKey: outcome.branchKey, status: outcome.status, accepted: false, reason: 'unknown_branch', pruned: wasAlreadyPruned, wasDeadEndReprobe: wasAlreadyPruned }

    branch.attemptsOnBranch += 1
    branch.lastUpdatedWave = wave
    const resetStrikes = () => { for (const k of strikeKeys) this.consecutiveFailures.set(k, 0); branch.consecutiveFailedAttempts = 0 }

    if (outcome.status === 'confirmed_composite') {
      resetStrikes()
      branch.confirmed = true
      if (outcome.newHop) this.maxDepthReached = Math.max(this.maxDepthReached, Math.min(MAX_CHAIN_DEPTH, branch.depth + 1))
      if (outcome.compositeProofReceiptId) this.recordedCompositeReceiptIds.add(outcome.compositeProofReceiptId)
      return { branchKey: branch.branchKey, status: 'confirmed_composite', accepted: true, reason: 'composite_confirmed', pruned: false, wasDeadEndReprobe: wasAlreadyPruned }
    }

    if (outcome.status === 'hop_verified') {
      if (outcome.hostVerified === false || !outcome.newHop) {
        return { branchKey: branch.branchKey, status: 'hop_verified', accepted: false, reason: 'missing_host_verified_hop', pruned: false, wasDeadEndReprobe: wasAlreadyPruned }
      }
      resetStrikes()
      const nextDepth = branch.depth + 1
      if (nextDepth > MAX_CHAIN_DEPTH) return { branchKey: branch.branchKey, status: 'hop_verified', accepted: false, reason: 'max_depth_reached', pruned: false, wasDeadEndReprobe: wasAlreadyPruned }
      if (outcome.keepParentActive !== true) branch.expanded = true
      const childKey = outcome.childBranchKey ?? `${branch.branchKey}>h${nextDepth}`
      this.admitBranch({
        branchKey: childKey, parentBranchKey: branch.branchKey, depth: nextDepth,
        verifiedHops: [...branch.verifiedHops, { ...outcome.newHop, hopIndex: nextDepth }],
        nextTarget: outcome.nextTarget ?? branch.nextTarget, preconditionGroupKey: null,
        feasibilityProb: outcome.nextFeasibilityProb ?? branch.feasibilityProb,
        terminalImpactWeight: outcome.nextTerminalImpactWeight ?? branch.terminalImpactWeight,
        surfaceNovelty: outcome.nextSurfaceNovelty ?? branch.surfaceNovelty,
        attemptsOnBranch: 0, consecutiveFailedAttempts: 0, lane: 'partial_chain', createdWave: wave, lastUpdatedWave: wave,
      })
      return { branchKey: branch.branchKey, status: 'hop_verified', accepted: true, reason: 'hop_advanced', pruned: false, childBranchKey: childKey, wasDeadEndReprobe: wasAlreadyPruned }
    }

    const prevStrikes = Math.max(branch.consecutiveFailedAttempts, ...strikeKeys.map(k => this.consecutiveFailures.get(k) ?? 0))
    const nextStrikes = prevStrikes + 1
    for (const k of strikeKeys) this.consecutiveFailures.set(k, nextStrikes)
    branch.consecutiveFailedAttempts = nextStrikes
    if (nextStrikes >= this.strikeLimit) {
      const reason: NegativeEdgeReason = outcome.failureReason ?? 'stagnation_2_strike'
      const record: NegativeEdgeRecord = {
        negativeEdgeKey: negKey, branchKey: branch.branchKey, preconditionCapIds,
        ...(branch.preconditionGroupKey ? { preconditionGroupKey: branch.preconditionGroupKey } : {}),
        targetSurfaceKey: outcome.targetSurfaceKey, hypothesisClass, reason,
        failedAttempts: nextStrikes, falsifiedByExchangeIds: [...(outcome.falsifiedByExchangeIds ?? [])], recordedAtWave: wave,
      }
      if (!branch.pruned) this.stagnationPrunedBranches += 1
      branch.pruned = true
      branch.pruneReason = reason
      this.prunedPairs.add(pairKey)
      this.negativeEdges.set(negKey, record)
      if (sibKey) this.negativeEdges.set(sibKey, record)
      return { branchKey: branch.branchKey, status: 'failed', accepted: true, reason: 'pruned_2_strike', pruned: true, negativeEdge: record, wasDeadEndReprobe: wasAlreadyPruned }
    }
    return { branchKey: branch.branchKey, status: 'failed', accepted: true, reason: `strike_${nextStrikes}_of_${this.strikeLimit}`, pruned: false, wasDeadEndReprobe: wasAlreadyPruned }
  }

  evaluateWaveProgress(
    input: Omit<WaveProgressInput, 'waveNo' | 'reach' | 'activeFrontierCount' | 'unlockedDiscoveryCount' | 'consecutiveUnproductiveWaves' | 'unproductiveWaveLimit'>,
  ): WaveProgressDecision {
    const activeExpandable = this.getActiveBeam().filter(item => item.branch.depth < MAX_CHAIN_DEPTH).length
    const decision = evaluateWaveProgress({
      ...input, waveNo: this.waveNo, reach: this.reach, activeFrontierCount: activeExpandable,
      unlockedDiscoveryCount: this.discoveryQueue.size,
      consecutiveUnproductiveWaves: this.consecutiveUnproductiveWaves, unproductiveWaveLimit: this.unproductiveWaveLimit,
    })
    this.consecutiveUnproductiveWaves = decision.nextUnproductiveWaves
    return decision
  }

  getTelemetry(): FrontierWasteTelemetry {
    const uniqueEdges = new Set<string>()
    for (const edge of this.negativeEdges.values()) uniqueEdges.add(edge.negativeEdgeKey)
    const confirmedCount = new Set([...this.recordedCompositeReceiptIds, ...this.reach.confirmedCompositeReceiptIds]).size
    return {
      wavesScheduled: this.waveNo, totalAssignmentsDispatched: this.totalAssignmentsDispatched,
      deadEndReprobeCount: this.deadEndReprobeCount, deadEndSuppressedCount: this.deadEndSuppressedCount,
      deadEndReprobeWasteRate: this.totalAssignmentsDispatched > 0 ? this.deadEndReprobeCount / this.totalAssignmentsDispatched : 0,
      prunedEdgeCount: uniqueEdges.size, stagnationPrunedBranches: this.stagnationPrunedBranches,
      activeBeamSize: this.getActiveBeam().length, maxDepthReached: this.maxDepthReached, confirmedCompositeCount: confirmedCount,
      reachCounts: { tenants: this.reach.tenants.size, roles: this.reach.roles.size, services: this.reach.services.size, surfaces: this.reach.surfaces.size },
    }
  }
}
