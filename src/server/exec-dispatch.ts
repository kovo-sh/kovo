import { createHash } from 'node:crypto'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import {
  defaultWorkerConcurrency,
  maxWorkerConcurrency,
  type Candidate,
  type OwaspCategory,
  type ThreatModelSummary,
} from '../domain.ts'
import {
  classifyHostTier,
  routeStepToSpecialist,
  type CodeAuditSuspectData,
  type HostTier,
  type PersonaResourceQueueItem,
  type WorkerToolHandlers,
} from './agent-session.ts'
import {
  CapabilityLedger,
  type NegativeEdge as LedgerNegativeEdge,
  type NegativeEdgeReason as LedgerNegativeEdgeReason,
} from './capability-ledger.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import { hasDynamicIdSegment, identifierFormsForRoute, intentFamily } from './deterministic-engine.ts'
import {
  FrontierScheduler,
  MAX_CHECKPOINT_BRIEF_BYTES,
  buildHopCheckpointBrief,
  computeNegativeEdgeKey,
  type AttemptUpdateResult,
  type DiscoverySurfaceCandidate,
  type FrontierBranch,
  type FrontierSchedulerOptions,
  type FrontierWasteTelemetry,
  type HopCheckpointBrief,
  type NegativeEdgeRecord,
  type PivotAttemptOutcome,
  type RouteSweepCandidate,
  type VerifiedHopReceiptEvent,
  type WaveProgressDecision,
  type WaveQuotaConfig,
  type WaveSelectionResult,
} from './frontier-scheduler.ts'
import {
  decideNext,
  extractChainHops,
  formatChainHopsBrief,
  type ChainHop,
  type ChainHypothesis,
  type CoordinatorFact,
  type DispatchPlan,
  type DispatchStepInput,
  type GraphCoordinator,
  type SchedulerDecision,
} from './graph-coordinator.ts'
import { selectRankedProbeTargets, type Phase0ProbePlanSummary } from './probe-plan.ts'
import { findings } from './schema.ts'
import { dedupeCodeAuditSuspects } from './semantic-audit.ts'
import {
  isOpaqueResourceId,
  type ChainStep,
  type Fact,
  type ResourceSampleRow,
  type Run,
  type Store,
} from './store.ts'

/** Bounded probe breadth per lane. The cap is a request-budget decision, not a store-read limit. */
export const DETERMINISTIC_PROBE_CAP = 150
export const ENGINE_PROBE_CAP = 220

export interface ProbeSelection<T> {
  targets: T[]
  usedPlan: boolean
  /** Every stored row paged out of the store for this lane, before origin/method filters. */
  storedRows: number
  /** Rows that passed the scope filter — i.e. the rows actually ranked for probing. */
  considered: number
  selected: number
  cap: number
  skippedStored: number
}

/**
 * Filter the losslessly paged surface to the in-scope routes and apply the ranked probe plan.
 * `endpoints` must come from a paged read of the full store: the selected cap bounds probes only,
 * so a route below a fixed page boundary can never be silently ignored during selection.
 */
export function selectProbeCandidates<T extends {
  origin: string
  method: string
  pathTemplate: string
  riskScore?: number
}>(input: {
  endpoints: readonly T[]
  probePlan: Phase0ProbePlanSummary | null | undefined
  cap: number
  approvedOrigins: ReadonlySet<string>
  excludeMethods?: readonly string[]
  planOnly?: boolean
}): ProbeSelection<T> {
  const excluded = new Set((input.excludeMethods ?? []).map(method => method.trim().toUpperCase()))
  const considered = input.endpoints.filter(endpoint =>
    input.approvedOrigins.has(endpoint.origin)
    && !excluded.has(endpoint.method.trim().toUpperCase()))
  const ranked = selectRankedProbeTargets(considered, input.probePlan, { cap: input.cap, planOnly: input.planOnly })
  return {
    targets: ranked.targets,
    usedPlan: ranked.usedPlan,
    storedRows: input.endpoints.length,
    considered: considered.length,
    selected: ranked.targets.length,
    cap: Math.max(1, Math.round(input.cap)),
    skippedStored: ranked.skippedStored,
  }
}

/** Stable metric names for probe-selection events and artifacts. */
export function probeSelectionMetrics(selection: Pick<ProbeSelection<unknown>, 'storedRows' | 'considered' | 'selected' | 'cap'>) {
  return {
    probeCandidatesConsidered: selection.considered,
    probeSelected: selection.selected,
    probeCap: selection.cap,
    storedRows: selection.storedRows,
  }
}

// ---------------------------------------------------------------------------------------------
// Realism #4 — Tier-A code-lead dispatch priority
//
// The engine ranks every candidate route by static risk and then takes a bounded prefix. On a
// 2,500-route monorepo the generic generated routes (risk 83–95) fill that prefix and the
// hypothesis-linked white-box sinks (hand-written GET sinks score lower) never reach the harvest.
// A code lead is a Tier-A hypothesis, not a long-tail route: it must outrank generic schema-typed
// routes for the probe prefix. This does not widen the cap; it only orders it.
// ---------------------------------------------------------------------------------------------

/** Risk floor applied to Program-Graph code-lead routes for the engine's bounded probe prefix. */
export const CODE_LEAD_PRIORITY_RISK = 240
/** Concrete identifier-form read targets derived per Tier-A code-lead object route. */
export const CODE_LEAD_IDENTIFIER_FORMS_PER_ROUTE = 2

export interface CodeLeadTarget {
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  source?: string
  params: Array<{ name: string; location: string }>
}

/**
 * Raise code-lead routes above generic routes for the engine's risk-ranked probe prefix.
 * Pure: only the risk score changes, identity and params are preserved.
 */
export function prioritizeCodeLeadTargets<T extends { riskScore: number }>(targets: readonly T[]): T[] {
  return targets.map(target => (
    target.riskScore >= CODE_LEAD_PRIORITY_RISK
      ? target
      : { ...target, riskScore: CODE_LEAD_PRIORITY_RISK }
  ))
}

/**
 * Derive bounded, concrete read targets for a code-lead object route.
 *
 * A white-box sink route such as `GET /<svc>/invoices/:id` has no readable collection on the
 * target, so the engine's harvester has no identifier to bind an authz read to. The target's own
 * declared tenants plus the route noun give a small, deterministic set of identifier forms
 * (`<noun>-<tenant>-<n>`), and a benign read of those forms seeds the engine's per-origin id pool.
 * Derived targets are read-only, deduped against the stored surface and capped; they add no proof
 * primitive and never bypass the differential verifier.
 */
export function deriveCodeLeadIdentifierTargets(input: {
  targets: readonly CodeLeadTarget[]
  /** Tenant labels declared by the run's personas (e.g. `tenant-alpha`). */
  tenants: readonly string[]
  existing: readonly { origin: string; method: string; pathTemplate: string }[]
  perRoute?: number
}): CodeLeadTarget[] {
  const perRoute = Math.max(0, Math.min(input.perRoute ?? CODE_LEAD_IDENTIFIER_FORMS_PER_ROUTE, 4))
  if (perRoute === 0 || input.tenants.length === 0) return []
  const seen = new Set(input.existing.map(route =>
    `${route.origin}|${route.method.toUpperCase()}|${route.pathTemplate}`))
  const out: CodeLeadTarget[] = []
  for (const target of [...input.targets].sort((a, b) =>
    a.pathTemplate.localeCompare(b.pathTemplate) || a.method.localeCompare(b.method))) {
    if (target.method.toUpperCase() !== 'GET') continue
    const template = target.pathTemplate.split('?')[0] || '/'
    if (!hasDynamicIdSegment(template)) continue
    const forms = identifierFormsForRoute(template, input.tenants).slice(0, perRoute)
    for (const form of forms) {
      const pathTemplate = template.replace(
        /(?:\/:[A-Za-z_][A-Za-z0-9_]*|\/\{[A-Za-z0-9_]+\}|\/\[[^\]]+\])/,
        `/${encodeURIComponent(form)}`,
      )
      if (pathTemplate === template) continue
      const key = `${target.origin}|GET|${pathTemplate}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({
        origin: target.origin,
        method: 'GET',
        pathTemplate,
        riskScore: CODE_LEAD_PRIORITY_RISK,
        source: 'program_graph',
        params: [],
      })
    }
  }
  return out
}

/** Extract declared tenant labels from persona role labels (`member (tenant-alpha)`). */
export function tenantLabelsFromRoleLabels(roleLabels: readonly string[]): string[] {
  const labels = new Set<string>()
  for (const label of roleLabels) {
    const match = /\(([^()]+)\)\s*$/.exec(label)
    if (!match) continue
    const tenant = match[1]!.trim()
    if (tenant.length >= 2 && tenant.length <= 48) labels.add(tenant)
  }
  return [...labels].sort()
}

export const hardChainStepsCeiling = 300
/** Legacy K=6 label retained for observability tests; it is no longer a halt threshold. */
export const diminishingReturnsDryThreshold = 6


export const plannerDebounceMs = 1_200
export const intentLeaseMs = 30 * 60_000
/** Hard ceiling for Phase A (the sequential deterministic floor that runs before agents). */
export const deterministicFloorMaxWallClockMs = 180_000
/** Phase A may consume at most this share of the run's wall clock (25–30% target). */
export const deterministicFloorWallClockShare = 0.28
/** Keep the legacy lane names as aliases so external diagnostics keep compiling. */
export const deterministicLaneMaxWallClockMs = deterministicFloorMaxWallClockMs
export const deterministicLaneWallClockShare = deterministicFloorWallClockShare
export type DeterministicSweepMode = 'off' | 'on' | 'always'

/**
 * v6 budget split (Phase-B starvation fix). The run's `budgetRequests` is one shared ledger, but
 * its consumption is accounted per phase:
 *
 *  - Phase A (deterministic floor) may spend at most `floor` requests, measured from the moment
 *    the floor starts (Phase-0 discovery/scope requests are not charged to it);
 *  - Phase B (agentic investigation and later agent-driven work) may spend at most `agent`
 *    requests, measured from the moment the floor settles;
 *  - neither phase may borrow the other's allowance;
 *  - the run-total request budget (and the USD/wall caps) still applies as a hard outer bound.
 *
 * Split budgets are opt-in. Without an option or env var the engine keeps the legacy single
 * shared budget (the floor is capped only by what remains of `run.budgetRequests`).
 */
export const DEFAULT_FLOOR_REQUEST_BUDGET = 6_000
export const DEFAULT_AGENT_REQUEST_BUDGET = 25_000

export interface PhaseRequestBudgets {
  /** Requests the deterministic floor (Phase A) may spend. */
  floor: number
  /** Requests agentic investigation (Phase B) may spend. Never borrowed from Phase A. */
  agent: number
}

function positiveRequestBudget(value: unknown): number | undefined {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined
  return Math.trunc(parsed)
}

/**
 * Resolve the split request budgets. Returns `null` for the legacy single-budget path (no option
 * and no env var set). A single configured phase keeps the other phase's default so a run can
 * never accidentally starve a phase by configuring only one half.
 */
export function resolvePhaseRequestBudgets(
  options: { floorRequestBudget?: number; agentRequestBudget?: number } = {},
  env: NodeJS.ProcessEnv = process.env,
): PhaseRequestBudgets | null {
  const floor = positiveRequestBudget(options.floorRequestBudget)
    ?? positiveRequestBudget(env.GUARDIAN_FLOOR_REQUEST_BUDGET)
  const agent = positiveRequestBudget(options.agentRequestBudget)
    ?? positiveRequestBudget(env.GUARDIAN_AGENT_REQUEST_BUDGET)
  if (floor === undefined && agent === undefined) return null
  return {
    floor: floor ?? DEFAULT_FLOOR_REQUEST_BUDGET,
    agent: agent ?? DEFAULT_AGENT_REQUEST_BUDGET,
  }
}

function parseSweepMode(
  option: boolean | 'always' | undefined,
  env: NodeJS.ProcessEnv,
  defaultMode: 'on' | 'off',
): DeterministicSweepMode {
  if (option === 'always') return 'always'
  if (option === true) return 'on'
  if (option === false) return 'off'
  const raw = env.GUARDIAN_DETERMINISTIC_SWEEP?.trim().toLowerCase()
  if (raw === 'always') return 'always'
  if (defaultMode === 'off') return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on' ? 'on' : 'off'
  return raw === '0' || raw === 'off' || raw === 'false' || raw === 'no' ? 'off' : 'on'
}

/** Legacy v5.1 parser: unset resolves to `off`. `Execution` uses `resolveFloorLaneMode`. */
export function resolveDeterministicSweepMode(
  option?: boolean | 'always',
  env: NodeJS.ProcessEnv = process.env,
): DeterministicSweepMode {
  return parseSweepMode(option, env, 'off')
}

/** v6 Phase 1: Layer-2 deterministic floor is always-on unless explicitly disabled. */
export function resolveFloorLaneMode(
  option?: boolean | 'always',
  env: NodeJS.ProcessEnv = process.env,
): DeterministicSweepMode {
  return parseSweepMode(option, env, 'on')
}
/** Page a Store listing to exhaustion; the coordinator never plans from a fixed-size snapshot. */
export function collectAllPages<T>(
  fetchPage: (offset: number, limit: number) => readonly T[],
  pageSize = 500,
): T[] {
  const size = Math.max(1, Math.floor(pageSize))
  const out: T[] = []
  for (let offset = 0; ;) {
    const page = fetchPage(offset, size)
    out.push(...page)
    if (page.length < size) return out
    offset += page.length
  }
}

export interface CoordinatorSchedulerState {
  budgetExhausted: boolean
  budgetRequests: number
  spentRequests: number
  startedAt: number
  maxDurationMs: number
  emptyRounds?: number
  coordinatorDone?: boolean
  pendingOob?: number
  /** True when no ready/pending high-priority (det_lead / chain) step remains. */
  highPriorityQueueEmpty?: boolean
  /** Consecutive rounds with no new runtime_confirmed finding and no new chain primitive. */
  consecutiveDryRounds?: number
  /** v8 M3: count of host-verified HopReceipts that expanded tenant/role/service/surface reach. */
  verifiedHopReachExpansions?: number
  /** v8 M3: optional FrontierScheduler wave-progression evaluation for frontier-aware termination. */
  frontierDecision?: WaveProgressDecision | null
}

/**
 * Deterministic v6/v7/v8 scheduler guard: budget, requests, wall clock, K=2 empty rounds,
 * v8 frontier-progress continuation (verified HopReceipt reach expansion continues waves even
 * before terminal confirmation), improving-round precision stop, and done+OOB drain.
 */
export function coordinatorSchedulerDecision(state: CoordinatorSchedulerState): SchedulerDecision {
  const decision = decideNext({
    budgetExhausted: state.budgetExhausted,
    requestsLeft: state.budgetRequests > 0 ? state.budgetRequests - state.spentRequests : null,
    wallClockLeft: state.maxDurationMs > 0 ? state.startedAt + state.maxDurationMs - Date.now() : null,
    consecutiveEmptyPlannerRounds: state.emptyRounds ?? 0,
    coordinatorDone: state.coordinatorDone === true,
    pendingOob: state.pendingOob ?? 0,
  })
  if (decision.decision === 'stop') return decision
  const pending = state.pendingOob ?? 0
  // A done coordinator with OOB subscriptions still draining keeps running (decideNext returned
  // `continue` here), so the precision stop must not pre-empt the callback drain.
  if (state.coordinatorDone === true && pending > 0) return decision
  // v8 M3 frontier-progress termination: verified HopReceipt reach expansion keeps waves running
  // even before terminal CompositeProofReceipt confirmation.
  if (
    (state.verifiedHopReachExpansions ?? 0) > 0
    || (state.frontierDecision?.decision === 'continue' && state.frontierDecision.reason === 'frontier_progress')
  ) {
    return {
      decision: 'continue',
      reason: 'continue',
      detail: state.frontierDecision?.detail
        ?? `Continuing: ${state.verifiedHopReachExpansions ?? 1} host-verified HopReceipt reach expansion(s) advanced the causal frontier.`,
    }
  }
  if (state.frontierDecision?.decision === 'stop' && state.highPriorityQueueEmpty === true) {
    return {
      decision: 'stop',
      reason: 'diminishing_returns',
      detail: state.frontierDecision.detail,
    }
  }
  const dryRounds = state.consecutiveDryRounds ?? 0
  if (state.highPriorityQueueEmpty === true && dryRounds >= DRY_ROUND_LIMIT) {
    return {
      decision: 'stop',
      reason: 'diminishing_returns',
      detail: `High-priority queue drained and ${dryRounds} consecutive dry round(s) produced no new runtime_confirmed finding or chain primitive.`,
    }
  }
  return decision
}

/**
 * Advance the planner's dry-round streak without false-dry kills:
 *  - Round 1 seeds initial agentic work before any specialist wave has run (`-> 0`).
 *  - A mid-wave round with zero newly completed investigation assignments has no new worker
 *    evidence to judge yet, so preserve the existing streak rather than incrementing it.
 *  - Any new runtime confirmation, chain primitive, or v8 verified HopReceipt reach expansion
 *    resets the streak to 0.
 *  - Keeps `DRY_ROUND_LIMIT = 2` intact once real completed waves stop advancing the frontier.
 */
export function nextPlannerDryRounds(input: {
  roundNo: number
  previousDryRounds: number
  newRuntimeConfirmed: number
  newChainPrimitives: number
  completedInvestigations: number
  previousCompletedInvestigations: number
  verifiedHopReachExpansions?: number
}): number {
  if (input.newRuntimeConfirmed + input.newChainPrimitives + (input.verifiedHopReachExpansions ?? 0) > 0) return 0
  if (input.roundNo <= 1) return 0
  if (input.completedInvestigations <= input.previousCompletedInvestigations) return input.previousDryRounds
  return input.previousDryRounds + 1
}

/** 2-wave planner dispatch capacity (`>= 12` or `workerConcurrency * 2`, clamped to remaining budget). */
export function plannerWaveDispatchCap(workerConcurrency: number, remainingBudget: number): number {
  const conc = Math.max(1, Math.min(maxWorkerConcurrency, workerConcurrency || defaultWorkerConcurrency))
  return Math.max(0, Math.min(Math.max(12, conc * 2), remainingBudget))
}

/**
 * Serialize a typed `ChainHop` artifact into a store `fact` payload for cross-round persistence.
 * Strictly non-secret: token references stay opaque handles (`secret:<factId>` / `jwt:<factId>`).
 */
export function chainHopFactPayload(hop: ChainHop): {
  summary: string
  data: Record<string, unknown>
} {
  const endpointPart = hop.endpoint ? ` at ${hop.method ? `${hop.method} ` : ''}${hop.endpoint}` : ''
  const statePart = hop.stateBefore || hop.stateAfter
    ? ` [${hop.stateBefore ?? '*'}→${hop.stateAfter ?? '*'}]`
    : ''
  return {
    summary: `ChainHop r${hop.roundNo} (${hop.artifactKind}): ${hop.artifactRef}${endpointPart}${statePart}`.slice(0, 220),
    data: {
      kind: 'chain_hop',
      subkind: 'chain_hop',
      roundNo: hop.roundNo,
      hopId: hop.hopId,
      artifactKind: hop.artifactKind,
      artifactRef: hop.artifactRef,
      verified: hop.verified,
      ...(hop.endpoint ? { endpoint: hop.endpoint } : {}),
      ...(hop.method ? { method: hop.method } : {}),
      ...(hop.persona ? { persona: hop.persona } : {}),
      ...(hop.targetPersona ? { targetPersona: hop.targetPersona } : {}),
      ...(hop.stateBefore ? { stateBefore: hop.stateBefore } : {}),
      ...(hop.stateAfter ? { stateAfter: hop.stateAfter } : {}),
      ...(hop.parentHopId ? { parentHopId: hop.parentHopId } : {}),
      hop: {
        hopId: hop.hopId,
        roundNo: hop.roundNo,
        hopIndex: hop.hopIndex,
        artifactKind: hop.artifactKind,
        artifactRef: hop.artifactRef,
        origin: hop.origin,
        ...(hop.endpoint ? { endpoint: hop.endpoint } : {}),
        ...(hop.method ? { method: hop.method } : {}),
        ...(hop.persona ? { persona: hop.persona } : {}),
        ...(hop.targetPersona ? { targetPersona: hop.targetPersona } : {}),
        ...(hop.stateBefore ? { stateBefore: hop.stateBefore } : {}),
        ...(hop.stateAfter ? { stateAfter: hop.stateAfter } : {}),
        verified: hop.verified,
        evidenceIds: hop.evidenceIds.slice(0, 8),
        factIds: hop.factIds.slice(0, 8),
        ...(hop.parentHopId ? { parentHopId: hop.parentHopId } : {}),
        summary: hop.summary.slice(0, 160),
      },
    },
  }
}

/** Rehydrate typed `ChainHop` artifacts from untainted parent/store facts. */
export function readChainHopsFromFacts(
  facts: readonly Pick<CoordinatorFact, 'id' | 'origin' | 'kind' | 'summary' | 'data' | 'tainted' | 'evidenceIds' | 'createdAt'>[],
): ChainHop[] {
  const hopFacts = facts.filter(fact => !fact.tainted && (fact.data?.subkind === 'chain_hop' || fact.data?.kind === 'chain_hop'))
  if (!hopFacts.length) return []
  return extractChainHops({ facts: hopFacts })
}

/** Format a pre-hydrated Hop-Checkpoint brief strictly <= `maxBytes` (default 2 KB UTF-8). */
export function formatHopCheckpointForAssignment(
  briefOrBranch: HopCheckpointBrief | { branch: FrontierBranch; evi: number },
  maxBytes = MAX_CHECKPOINT_BRIEF_BYTES,
): { brief: HopCheckpointBrief; json: string; bytes: number } {
  const cap = Math.max(256, Math.min(MAX_CHECKPOINT_BRIEF_BYTES, Math.floor(maxBytes)))
  if ('branch' in briefOrBranch) {
    const built = buildHopCheckpointBrief(briefOrBranch.branch, briefOrBranch.evi, cap)
    return { brief: built.brief, json: built.checkpointJson, bytes: built.checkpointBytes }
  }
  const clone: HopCheckpointBrief = {
    ...briefOrBranch,
    verifiedHops: [...briefOrBranch.verifiedHops],
    capabilityHandles: [...briefOrBranch.capabilityHandles],
    nextGoal: { ...briefOrBranch.nextGoal },
  }
  let json = JSON.stringify(clone)
  let bytes = Buffer.byteLength(json, 'utf8')
  while (bytes > cap && clone.verifiedHops.length > 0) {
    clone.verifiedHops.shift()
    clone.omittedEarlierHops = (clone.omittedEarlierHops ?? 0) + 1
    json = JSON.stringify(clone)
    bytes = Buffer.byteLength(json, 'utf8')
  }
  while (bytes > cap && clone.capabilityHandles.length > 1) {
    clone.capabilityHandles.shift()
    json = JSON.stringify(clone)
    bytes = Buffer.byteLength(json, 'utf8')
  }
  if (bytes > cap) {
    clone.nextGoal.goal = clone.nextGoal.goal.slice(0, 48)
    json = JSON.stringify(clone)
    bytes = Buffer.byteLength(json, 'utf8')
  }
  return { brief: clone, json, bytes }
}

/** Map chained hypotheses onto validated dispatch inputs with typed `ChainHop` + v8 checkpoint briefs. */
export function chainHypothesisDispatchSteps(hypotheses: readonly ChainHypothesis[]): DispatchStepInput[] {
  return hypotheses.map(hypothesis => {
    const hopBlock = hypothesis.chainHops?.length
      ? ` [chain_hops=${formatChainHopsBrief(hypothesis.chainHops, 420)}]`
      : ''
    const baseText = `${hypothesis.title} — ${hypothesis.rationale}`
    const maxBase = Math.max(200, 1200 - hopBlock.length)
    const checkpoint = hypothesis.hops >= 2 && hypothesis.checkpointBrief
      ? formatHopCheckpointForAssignment(hypothesis.checkpointBrief, MAX_CHECKPOINT_BRIEF_BYTES)
      : null
    return {
      hypothesis: `${baseText.slice(0, maxBase)}${hopBlock}`,
      origins: hypothesis.chainOrigins,
      capabilities: hypothesis.capabilities,
      parentEvidenceIds: hypothesis.parentEvidenceIds,
      ...(hypothesis.probeClasses.length ? { probeClass: hypothesis.probeClasses[0] } : {}),
      skills: [...new Set([...hypothesis.primitiveKinds.map(kind => `chain:${kind}`), 'chain-primitives', ...hypothesis.probeClasses])],
      priority: Math.round(hypothesis.confidence * 100),
      ...(hypothesis.chainHops?.length ? { chainHops: hypothesis.chainHops } : {}),
      ...(checkpoint ? { checkpointBrief: checkpoint.brief, checkpointJson: checkpoint.json } : {}),
    }
  })
}

export interface FrontierWaveControllerOptions extends FrontierSchedulerOptions {
  ledger?: CapabilityLedger | null
}

function toLedgerNegativeReason(reason: PivotAttemptOutcome['failureReason']): LedgerNegativeEdgeReason {
  if (reason === 'control_blocked_cleanly' || reason === 'decoy_guard_verified' || reason === 'invariant_enforced_hardened') {
    return reason
  }
  return 'invariant_enforced_hardened'
}

/**
 * v8 M3 wave-progression controller binding `FrontierScheduler` to `CapabilityLedger`:
 *  - Syncs pruned negative edges from SQLite WAL `CapabilityLedger` before wave selection so
 *    dead-end `(preconditionCapIds, targetSurfaceKey, hypothesisClass)` tuples are never re-probed.
 *  - Records 2-strike dead-end pruning directly as negative edges in `CapabilityLedger`.
 *  - Emits strictly `<= 2 KB` pre-hydrated hop-checkpoint briefs on depth `>= 2` assignments.
 *  - Evaluates frontier-progress termination so waves continue whenever a host-verified
 *    `HopReceipt` expands tenant/role/service/surface reach even before terminal confirmation.
 */
export class FrontierWaveController {
  readonly scheduler: FrontierScheduler
  readonly ledger: CapabilityLedger | null

  constructor(options: FrontierWaveControllerOptions = {}) {
    this.scheduler = new FrontierScheduler(options)
    this.ledger = options.ledger ?? null
    this.syncNegativeEdgesFromLedger()
  }

  /** Pull every pruned negative edge from `CapabilityLedger` into `FrontierScheduler`. */
  syncNegativeEdgesFromLedger(): number {
    if (!this.ledger) return 0
    const pruned = this.ledger.listNegativeEdges({ prunedOnly: true })
    if (!pruned.length) return 0
    const records: NegativeEdgeRecord[] = pruned.map(neg => ({
      negativeEdgeKey: computeNegativeEdgeKey(neg.preconditionCapIds, neg.targetSurfaceKey, neg.hypothesisClass),
      branchKey: `ledger:${neg.preconditionKey}`,
      preconditionCapIds: [...neg.preconditionCapIds],
      targetSurfaceKey: neg.targetSurfaceKey,
      hypothesisClass: neg.hypothesisClass,
      reason: neg.reason,
      failedAttempts: neg.attemptCount,
      falsifiedByExchangeIds: [...neg.falsifiedByExchangeIds],
      recordedAtWave: 0,
    }))
    this.scheduler.seedNegativeEdges(records)
    return records.length
  }

  admitBranch(branch: FrontierBranch): boolean {
    this.syncNegativeEdgesFromLedger()
    return this.scheduler.admitBranch(branch)
  }

  admitBranches(branches: readonly FrontierBranch[]): number {
    this.syncNegativeEdgesFromLedger()
    return this.scheduler.admitBranches(branches)
  }

  addDiscoverySurface(candidate: DiscoverySurfaceCandidate): void {
    this.scheduler.addDiscoverySurface(candidate)
  }

  addRouteSweepCandidate(candidate: RouteSweepCandidate): void {
    this.scheduler.addRouteSweepCandidate(candidate)
  }

  selectNextWave(waveCapacity: number, quotaOverride?: WaveQuotaConfig): WaveSelectionResult {
    this.syncNegativeEdgesFromLedger()
    return this.scheduler.selectNextWaveAssignments(waveCapacity, quotaOverride)
  }

  /**
   * Record a pivot attempt outcome in `FrontierScheduler` and persist failure strikes / 2-strike
   * pruning into `CapabilityLedger` as negative edges so sibling workers skip the dead end.
   */
  recordPivotOutcome(outcome: PivotAttemptOutcome): AttemptUpdateResult & { ledgerNegativeEdge?: LedgerNegativeEdge } {
    const branchBefore = this.scheduler.getBranch(outcome.branchKey)
    const result = this.scheduler.recordAttemptOutcome(outcome)
    let ledgerNegativeEdge: LedgerNegativeEdge | undefined
    if (this.ledger && outcome.status === 'failed') {
      const capIds = branchBefore?.verifiedHops.map(h => h.capabilityId).filter(Boolean) ?? []
      const preconditionCapIds = capIds.length > 0 ? capIds : [`branch:${outcome.branchKey}`]
      const hypothesisClass = outcome.hypothesisClass ?? branchBefore?.nextTarget.hypothesisClass ?? 'unknown'
      const exchanges = outcome.falsifiedByExchangeIds?.length
        ? outcome.falsifiedByExchangeIds
        : [`ex_strike_${outcome.waveNo ?? 0}_${outcome.branchKey}`]
      ledgerNegativeEdge = this.ledger.recordNegativeEdge({
        preconditionCapIds,
        targetSurfaceKey: outcome.targetSurfaceKey,
        hypothesisClass,
        falsifiedByExchangeIds: exchanges,
        reason: toLedgerNegativeReason(outcome.failureReason),
        forcePrune: result.pruned,
        notes: result.pruned
          ? `Pruned after ${this.scheduler.strikeLimit}-strike dead-end stagnation on ${outcome.branchKey}.`
          : `Failed pivot attempt (${result.reason}) on ${outcome.branchKey}.`,
      })
    }
    return { ...result, ...(ledgerNegativeEdge ? { ledgerNegativeEdge } : {}) }
  }

  evaluateWaveProgress(input: {
    completedAssignments: number
    confirmedCompositeReceipts?: readonly string[]
    verifiedHopReceipts?: readonly VerifiedHopReceiptEvent[]
    pendingAsyncOrOob?: number
    budgetUsdSpent?: number
    budgetUsdLimit?: number
    elapsedMs?: number
    maxDurationMs?: number
    requestsSpent?: number
    agentRequestBudget?: number
    coverageSettledCount?: number
  }): WaveProgressDecision {
    return this.scheduler.evaluateWaveProgress(input)
  }

  getTelemetry(): FrontierWasteTelemetry {
    return this.scheduler.getTelemetry()
  }
}

export interface CoordinatorPlannerSessionDeps {
  coordinator: GraphCoordinator
  /** Persist validated hypotheses as chain steps. The tool never performs HTTP. */
  onDispatch?: (plan: DispatchPlan) => void
}

/** Compact coordinator pages (≤25 rows) so a compaction-free planner never bloats context. */
const COORDINATOR_PAGE_MAX = 25
const compactLimit = (limit?: number): number =>
  Math.min(COORDINATOR_PAGE_MAX, Math.max(1, Math.floor(limit ?? COORDINATOR_PAGE_MAX)))
export const compactText = (value: string, max = 160): string =>
  value.length <= max ? value : `${value.slice(0, max - 1)}…`
export const compactChainTitle = (hypothesis: string): string => {
  const head = hypothesis.split(' — ')[0] ?? hypothesis
  return compactText(head.trim() || 'Chain hypothesis', 160)
}
const compactPrimitiveTag = (data: Record<string, unknown> | undefined): string | null => {
  for (const candidate of [data?.subkind, data?.probeClass, data?.kind]) {
    if (typeof candidate === 'string' && candidate.trim()) return compactText(candidate.trim(), 48)
  }
  return null
}

/** Map the coordinator's five tools onto agent-session handlers (registered only when supplied). */
export function coordinatorPlannerHandlers(
  deps: CoordinatorPlannerSessionDeps,
): Pick<WorkerToolHandlers, 'query_endpoints' | 'query_program_graph' | 'query_facts' | 'query_findings' | 'dispatch_investigations'> {
  return {
    query_endpoints: async args => {
      const page = deps.coordinator.queryEndpoints({ ...args, limit: compactLimit(args.limit) })
      return {
        ...page,
        items: page.items.map(endpoint => ({
          id: endpoint.id, method: endpoint.method, route: compactText(endpoint.pathTemplate, 160),
          origin: endpoint.origin, risk: endpoint.riskScore ?? 0, coverage: endpoint.coveragePct ?? null,
          tested: endpoint.testedClasses ?? [], sinks: endpoint.sinkKinds ?? [],
          auth: endpoint.authRequirement ?? null, guard: endpoint.ownershipGuard ?? null,
          roleExclusive: endpoint.roleExclusive === true,
        })),
      }
    },
    query_program_graph: async args => {
      const page = deps.coordinator.queryProgramGraph({ ...args, limit: compactLimit(args.limit) })
      return { ...page, items: page.items.slice(0, COORDINATOR_PAGE_MAX) }
    },
    query_facts: async args => {
      // `origin:'*'` spans every approved origin (cross-host chaining never loses its evidence).
      const origin = args.origin?.trim() === '*' ? undefined : args.origin
      const page = deps.coordinator.queryFacts({ ...args, origin, limit: compactLimit(args.limit) })
      return {
        ...page,
        items: page.items.map(fact => ({
          id: fact.id, kind: fact.kind, origin: fact.origin,
          primitiveTag: compactPrimitiveTag(fact.data),
          summary: compactText(fact.summary),
          evidenceIds: fact.evidenceIds ?? [],
        })),
      }
    },
    query_findings: async args => {
      const page = deps.coordinator.queryFindings({ ...args, limit: compactLimit(args.limit) })
      return { ...page, items: page.items.map(item => ({ ...item, title: compactText(item.title, 160), reason: item.reason ? compactText(item.reason, 160) : undefined })) }
    },
    dispatch_investigations: async args => {
      const plan = deps.coordinator.dispatchInvestigations(args.steps, { maxSteps: args.maxSteps })
      if (plan.plan.length) deps.onDispatch?.(plan)
      return plan
    },
  }
}

export function computeDynamicStepBudget(storage: Store, runId: string): number {
  const endpoints = storage.listEndpoints(runId)
  const crownJewels = endpoints.filter(e => e.riskScore >= 80).length
  const suspects = storage.listFacts(runId, { includeTainted: false, kind: 'code_audit_suspect', limit: 500 }).length
  return Math.max(24, Math.min(200, crownJewels * 2 + suspects))
}

export function computeMultiTrialFanout(
  run: Pick<Run, 'multiTrialEnabled' | 'workerConcurrency'>,
  step: Pick<ChainStep, 'priority' | 'dependsOnFactIds' | 'trialGroupId'>,
  highSignalFactIds?: ReadonlySet<string>,
): number {
  if (step.trialGroupId) return 1
  if (run.multiTrialEnabled === false) return 1
  const concurrencyCap = Math.max(1, run.workerConcurrency || defaultWorkerConcurrency)
  const linkedHighSignal = step.dependsOnFactIds.some(id => highSignalFactIds?.has(id))
  if (step.priority >= 96) return Math.min(3, concurrencyCap)
  if (step.priority >= 88 || linkedHighSignal) return Math.min(2, concurrencyCap)
  return 1
}

// ============================================================================
// v7 dispatch funnel — structured coverage accounting
//
// The v7 coverage defect was invisible in logs: the planner reported "added N steps" while the
// scheduler dispatched far fewer, because planned → enqueued → ready → dispatched is a funnel and
// every stage can silently drop work. These helpers make the funnel a structured object (never
// derived from log text) and pin the two product invariants:
//
//   1. multi-trial fanout may only spend *surplus* worker slots; it must never turn one planned
//      hypothesis into the whole fleet while distinct hypotheses wait in the queue, and
//   2. a dry-round/coordinator-done stop may not strand dispatchable ready steps unless the run is
//      genuinely out of budget/requests/wall clock.
// ============================================================================

/** Why the planner/dispatcher stopped (or `running` while it may continue). */
export type DispatchStopReason =
  | 'running'
  | 'dry_rounds'
  | 'coordinator_done'
  | 'budget_exhausted'
  | 'requests_exhausted'
  | 'wallclock_exhausted'
  | 'circuit_open'
  | 'run_paused'
  | 'run_stopped'

/** Stop reasons that must never leave dispatchable planned work behind. */
export const STRANDED_READY_STOP_REASONS: readonly DispatchStopReason[] = ['dry_rounds', 'coordinator_done']

/** Structured per-round dispatch funnel. Every field is a count of step/hypothesis objects. */
export interface DispatchFunnelCounts {
  roundNo: number
  /** Hypotheses the planner/lead lanes produced this round, before any filtering. */
  planned: number
  /** Dropped because the route/class is already confirmed and the step cites no parent evidence. */
  filteredAlreadyConfirmed: number
  /** Dropped by the reinvestigation cap (same route+class re-emitted with no new evidence). */
  filteredCap: number
  /** Pending steps whose declared dependencies can never be satisfied (permanently blocked). */
  filteredDep: number
  /** Dropped as a duplicate title already queued for this goal revision. */
  filteredDedupe: number
  /** Dropped because no approved asset matches the hypothesis origins. */
  filteredNoAsset: number
  /** Dropped because the dynamic step budget had no remaining slot. */
  filteredBudget: number
  /** Steps actually persisted as chain steps this round. */
  enqueued: number
  /** Cumulative distinct steps that reached `running` (assignedWorkerId set). */
  dispatched: number
  /** Distinct steps dispatched during this round window. */
  dispatchedThisRound: number
  /** Steps currently dispatchable (ready, or pending without an unsatisfiable dependency). */
  remainingReady: number
  /** Dispatchable steps left when the stop decision was taken (0 when it may continue). */
  remainingReadyAtStop: number
  stopReason: DispatchStopReason
}

export type DispatchFunnelCountKey =
  | 'planned' | 'filteredAlreadyConfirmed' | 'filteredCap' | 'filteredDep'
  | 'filteredDedupe' | 'filteredNoAsset' | 'filteredBudget' | 'enqueued'

export const DISPATCH_FUNNEL_COUNT_KEYS: readonly DispatchFunnelCountKey[] = [
  'planned', 'filteredAlreadyConfirmed', 'filteredCap', 'filteredDep',
  'filteredDedupe', 'filteredNoAsset', 'filteredBudget', 'enqueued',
]

/** Accumulate one source's funnel counts into the round total (structured objects only). */
export function addFunnelCounts(
  target: DispatchFunnelCounts,
  delta: Partial<Record<DispatchFunnelCountKey, number>>,
): DispatchFunnelCounts {
  for (const key of DISPATCH_FUNNEL_COUNT_KEYS) target[key] += Math.max(0, delta[key] ?? 0)
  return target
}

export function emptyDispatchFunnel(roundNo = 0): DispatchFunnelCounts {
  return {
    roundNo,
    planned: 0,
    filteredAlreadyConfirmed: 0,
    filteredCap: 0,
    filteredDep: 0,
    filteredDedupe: 0,
    filteredNoAsset: 0,
    filteredBudget: 0,
    enqueued: 0,
    dispatched: 0,
    dispatchedThisRound: 0,
    remainingReady: 0,
    remainingReadyAtStop: 0,
    stopReason: 'running',
  }
}

/** Map a scheduler reason onto the funnel vocabulary (`diminishing_returns` is the dry stop). */
export function normalizeDispatchStopReason(reason: string | null | undefined): DispatchStopReason {
  switch ((reason ?? '').trim()) {
    case 'diminishing_returns':
    case 'dry_rounds':
    case 'frontier_stagnated':
    case 'frontier_exhausted':
      return 'dry_rounds'
    case 'coordinator_done':
      return 'coordinator_done'
    case 'budget_exhausted':
      return 'budget_exhausted'
    case 'requests_exhausted':
    case 'request_budget_exhausted':
      return 'requests_exhausted'
    case 'wallclock_exhausted':
    case 'duration_exhausted':
      return 'wallclock_exhausted'
    case 'circuit_open':
      return 'circuit_open'
    case 'paused':
      return 'run_paused'
    case 'stopped':
      return 'run_stopped'
    default:
      return 'running'
  }
}

export interface DispatchFunnelStep {
  id: string
  status: string
  dependsOnFactIds?: readonly string[]
  dependsOnStepIds?: readonly string[]
}

/**
 * Pending steps whose declared dependencies can never resolve: a step dependency that is missing,
 * canceled or tainted, or (when the fact set is supplied) a fact id that does not exist. These are
 * permanently stranded — `refreshReadyChainSteps` can never promote them — so the funnel reports
 * them as `filteredDep` instead of losing them silently.
 */
export function permanentlyBlockedStepIds(
  steps: readonly DispatchFunnelStep[],
  knownFactIds?: ReadonlySet<string>,
): string[] {
  const byId = new Map(steps.map(step => [step.id, step]))
  const blocked: string[] = []
  for (const step of steps) {
    if (step.status !== 'pending') continue
    const deadStepDep = (step.dependsOnStepIds ?? []).some(id => {
      const dep = byId.get(id)
      return !dep || dep.status === 'canceled' || dep.status === 'tainted'
    })
    const missingFactDep = knownFactIds
      ? (step.dependsOnFactIds ?? []).some(id => !knownFactIds.has(id))
      : false
    if (deadStepDep || missingFactDep) blocked.push(step.id)
  }
  return blocked
}

/** Steps the scheduler could still dispatch: `ready`, plus `pending` with satisfiable deps. */
export function dispatchableReadySteps<T extends DispatchFunnelStep>(
  steps: readonly T[],
  knownFactIds?: ReadonlySet<string>,
): T[] {
  const blocked = new Set(permanentlyBlockedStepIds(steps, knownFactIds))
  return steps.filter(step => step.status === 'ready' || (step.status === 'pending' && !blocked.has(step.id)))
}

/**
 * Worker slots a multi-trial fanout may spend without starving a distinct hypothesis: the fleet
 * minus the hypotheses already queued. With 6 slots and 19 planned steps this is 0, so each planned
 * hypothesis gets its own worker; with 1 planned step and 6 slots it is 5, so the intended
 * deterministic-trial fanout still happens.
 */
export function multiTrialSurplusSlots(distinctQueued: number, concurrency: number): number {
  return Math.max(0, Math.max(1, Math.floor(concurrency)) - Math.max(0, Math.floor(distinctQueued)))
}

export interface MultiTrialExpansion<T> {
  step: T
  /** Total size of the trial group (1 = no expansion). Never exceeds the surplus budget. */
  fanout: number
}

/**
 * Choose which queued hypotheses fan out into duplicate trials this tick. Expansion is capped by
 * {@link multiTrialSurplusSlots} so duplicate trials can never occupy a slot a distinct planned
 * hypothesis could use. Order is the caller's (priority/seq) order, so the choice is deterministic.
 */
export function planMultiTrialExpansion<T extends DispatchFunnelStep & {
  priority: number
  trialGroupId?: string | null
}>(input: {
  steps: readonly T[]
  concurrency: number
  multiTrialEnabled?: boolean
  highSignalFactIds?: ReadonlySet<string>
}): MultiTrialExpansion<T>[] {
  if (input.multiTrialEnabled === false) return []
  const concurrency = Math.max(1, Math.floor(input.concurrency))
  if (concurrency <= 1) return []
  const queued = input.steps.filter(step =>
    (step.status === 'pending' || step.status === 'ready') && !step.trialGroupId)
  // Existing queued trial-group members already occupy slots; count them so duplicates never
  // accumulate across ticks beyond actual idle worker capacity.
  const queuedInTrialGroups = input.steps.filter(step =>
    (step.status === 'pending' || step.status === 'ready') && Boolean(step.trialGroupId)).length
  let surplus = multiTrialSurplusSlots(queued.length + queuedInTrialGroups, concurrency)
  if (surplus <= 0) return []
  const expansions: MultiTrialExpansion<T>[] = []
  for (const step of queued) {
    const requested = computeMultiTrialFanout(
      { multiTrialEnabled: true, workerConcurrency: concurrency },
      {
        priority: step.priority,
        dependsOnFactIds: [...(step.dependsOnFactIds ?? [])],
        trialGroupId: step.trialGroupId ?? null,
      },
      input.highSignalFactIds,
    )
    const fanout = Math.min(requested, surplus + 1)
    if (fanout <= 1) continue
    expansions.push({ step, fanout })
    surplus -= fanout - 1
    if (surplus <= 0) break
  }
  return expansions
}

export interface DispatchStopEvaluation {
  /** Decision after the stranded-ready guard (`continue` wins when queued work can use a slot). */
  decision: 'continue' | 'stop'
  stopReason: DispatchStopReason
  remainingReady: number
  /** True when the guard deferred a stop so planned ready work could be dispatched. */
  deferred: boolean
  /** True when a dry/coordinator stop would abandon dispatchable planned work. */
  stranded: boolean
}

/** One step's contribution to Pass-1 coverage (pure input, no store access). */
export interface PassOneCoverageStep {
  id: string
  /** Ready/pending steps can still be dispatched this pass. */
  dispatchable: boolean
  /** True once any assignment was created for the step. */
  dispatched: boolean
  /** Normalized route templates the step names. */
  routes: readonly string[]
  /** `route|class` reinvestigation keys the step belongs to. */
  keys: readonly string[]
}

export interface PassOneCoverage {
  /** Tier-A endpoints (`METHOD /path`) with no dispatched step. */
  uncoveredTierAEndpoints: string[]
  /** Distinct first-pass `route|class` keys with a dispatchable step but no dispatch yet. */
  uninvestigatedFirstPassClasses: string[]
}

/**
 * Pass-1 coverage: what remains genuinely first-pass at a would-be stop. A `route|class` key is
 * first-pass until one of its steps was dispatched; Tier-A endpoints count as covered only after a
 * dispatched step names them. Deterministic ordering (sorted) so the metric is stable.
 */
export function passOneCoverage(input: {
  tierAEndpoints: readonly string[]
  steps: readonly PassOneCoverageStep[]
}): PassOneCoverage {
  const attemptedKeys = new Set<string>()
  const dispatchedRoutes = new Set<string>()
  for (const step of input.steps) {
    if (!step.dispatched) continue
    for (const key of step.keys) attemptedKeys.add(key)
    for (const route of step.routes) dispatchedRoutes.add(route)
  }
  const uncoveredTierAEndpoints = [...new Set(input.tierAEndpoints)]
    .filter(endpoint => {
      const path = endpoint.split(' ').slice(1).join(' ')
      return ![...dispatchedRoutes].some(route => route === path || route === endpoint)
    })
    .sort()
  const firstPass = new Set<string>()
  for (const step of input.steps) {
    if (!step.dispatchable || step.dispatched) continue
    for (const key of step.keys) {
      if (!attemptedKeys.has(key)) firstPass.add(key)
    }
  }
  return {
    uncoveredTierAEndpoints,
    uninvestigatedFirstPassClasses: [...firstPass].sort(),
  }
}

/**
 * v7 coverage guard: never honour a dry-round/coordinator-done stop while dispatchable planned
 * work can still use a free worker slot. Budget/request/wall-clock exhaustion is terminal and is
 * reported as such (those steps are unaffordable, not stranded), and a genuinely empty queue (or a
 * queue waiting only on in-flight slots) still stops.
 */
export function evaluateDispatchStop(input: {
  decision: 'continue' | 'stop'
  reason: string
  remainingReady: number
  freeSlots?: number
  /** Investigation assignments still in flight; they release the slots queued work waits for. */
  inFlight?: number
  budgetExhausted?: boolean
  requestExhausted?: boolean
  wallExhausted?: boolean
  /** Pass-1 keys with a dispatchable step but no dispatch yet (never stop in front of these). */
  uninvestigatedFirstPassClasses?: readonly string[]
  /** Tier-A endpoints with no dispatched step (never stop in front of these). */
  uncoveredTierAEndpoints?: readonly string[]
}): DispatchStopEvaluation {
  const stopReason = normalizeDispatchStopReason(input.reason)
  const remainingReady = Math.max(0, Math.floor(input.remainingReady))
  if (input.decision !== 'stop') {
    return { decision: 'continue', stopReason, remainingReady, deferred: false, stranded: false }
  }
  const exhausted = input.budgetExhausted === true || input.requestExhausted === true || input.wallExhausted === true
  const guarded = STRANDED_READY_STOP_REASONS.includes(stopReason)
  // A dry/coordinator stop may only end *speculative* re-investigation. First-pass work that is
  // still dispatchable, or a Tier-A slice that was never dispatched, must block the stop; budget,
  // request and wall-clock exhaustion still win.
  const firstPassPending = (input.uninvestigatedFirstPassClasses?.length ?? 0) > 0
  const tierAUncovered = (input.uncoveredTierAEndpoints?.length ?? 0) > 0
  if (guarded && !exhausted && (firstPassPending || tierAUncovered)) {
    return { decision: 'continue', stopReason, remainingReady, deferred: true, stranded: false }
  }
  if (guarded && !exhausted && remainingReady > 0) {
    if ((input.freeSlots ?? 0) > 0) {
      return { decision: 'continue', stopReason, remainingReady, deferred: true, stranded: false }
    }
    // A busy fleet is not stranding: every ready step is queued behind an in-flight assignment and
    // the scheduler dispatches it as the slot frees. Only an idle fleet abandons planned work.
    if ((input.inFlight ?? 0) > 0) {
      return { decision: 'stop', stopReason, remainingReady, deferred: false, stranded: false }
    }
    return { decision: 'stop', stopReason, remainingReady, deferred: false, stranded: true }
  }
  return { decision: 'stop', stopReason, remainingReady, deferred: false, stranded: false }
}

/**
 * Breaker policy: a route-scoped 5xx cooldown is evidence (often the target's own response to an
 * approved probe) and must never block traffic or pause a run; only an origin-wide trip does.
 */
export function circuitBreakAction(input: {
  originWide: boolean
  approvedOrigins: readonly string[]
  trippedOrigin: string
  /** Predicate over the *other* approved origins (true when that origin's circuit is also open). */
  isOpen?: (origin: string) => boolean
}): 'continue' | 'block_origin' | 'pause_run' {
  if (!input.originWide) return 'continue'
  const others = input.approvedOrigins.filter(origin => origin !== input.trippedOrigin)
  const allTripped = others.length === 0 || others.every(origin => input.isOpen?.(origin) ?? false)
  return allTripped ? 'pause_run' : 'block_origin'
}

// ============================================================================
// v6 Phase B F2 — dispatch policy
//
// The Phase-B diagnosis found that four `det_lead` upgrade steps (created at priority 88) consumed
// 80% of the agentic wall clock while 8/11 unconfirmed target classes never received a probe. Two
// independent rules fix the ordering without weakening verification:
//
//  1. a deterministic lead is only promoted when it carries contrast evidence (a control that did
//     not collapse, or a near-miss from a verification attempt), and
//  2. the scheduler fills slots round-robin across lanes, with at most
//     {@link DET_LEAD_CONCURRENT_CAP} lead assignments in flight at a time.
//
// The pure helpers below are exported so the scheduler contract is testable without a live run.
// ============================================================================

/** det_lead upgrades sit *below* unproven class/route steps (planner steps start at 60). */
export const DET_LEAD_STEP_PRIORITY = 55
/** At most this many det_lead upgrade assignments may be in flight concurrently. */
export const DET_LEAD_CONCURRENT_CAP = 2
/**
 * Tier-A Program-Graph leads (code dataflow slice on a live route) outrank generic work and are
 * exempt from the generic concurrent-lead cap: all of them must be dispatched in Round 1's first
 * slots, never gated behind class/route steps and never killed by a dry-round stop.
 */
export const TIER_A_STEP_PRIORITY = 90
/** Hard per-run cap on Tier-A lead steps seeded from Program-Graph facts (black-box/default). */
export const TIER_A_MAX_SEEDED_STEPS = 6
/** Expanded Tier-A white-box cap when repository source is mounted (`sourceDir` / `mountedRepos`). */
export const WHITEBOX_TIER_A_MAX_SEEDED_STEPS = 16
/** Maximum initial priority for generic black-box recon steps when source repos are mounted. */
export const WHITEBOX_BLACKBOX_CAP_PRIORITY = 65
/** Up to this many interesting BOLA queue items are injected into a single assignment prompt. */
export const ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS = 10
/** Hard byte ceiling for the per-assignment BOLA queue slice (was 53 KB for the full queue). */
export const ASSIGNMENT_BOLA_QUEUE_MAX_BYTES = 4096
/**
 * v7 precision guard: a `(normalizedRoute, vulnClass)` pair may be re-investigated at most this
 * many times unless new chain-primitive/parent evidence unlocks another pass. Tail-scraping the
 * same route/class is the dominant source of late-run false positives.
 */
export const REINVESTIGATION_CAP = 2
/** Stop the planner after this many consecutive rounds with no new confirmed finding/chain primitive. */
export const DRY_ROUND_LIMIT = 2

/** Canonical `(normalizedRoute, vulnClass)` key for the reinvestigation guard. */
export function reinvestigationKey(route: string, vulnClass: string): string {
  const raw = (route ?? '').trim()
  const withoutMethod = raw.replace(/^[A-Za-z]+\s+/, '')
  const canonicalRoute = normalizeEndpointTemplate(withoutMethod.split(/[?#]/, 1)[0] ?? withoutMethod)
  const canonicalClass = confirmedCategoryFamily((vulnClass ?? '').trim() || 'unknown')
  return `${canonicalRoute}\u0000${canonicalClass}`
}

export interface ReinvestigationVerdict {
  /** False means the scheduler must not queue another pass for this route/class. */
  allowed: boolean
  /** Investigation count *after* this call when allowed (the attempted count when capped). */
  count: number
  capped: boolean
  /** New chain primitive / parent evidence bypassed (or re-opened) the cap. */
  unlocked: boolean
}

/**
 * Deterministic per-route+class reinvestigation counter. Pure bookkeeping: a caller records the
 * attempt and obeys `allowed`. `unlocked` (new chain primitive or parent evidence) lets the
 * investigation proceed beyond {@link REINVESTIGATION_CAP}.
 */
export class ReinvestigationGuard {
  private readonly counts = new Map<string, number>()
  private capped = 0
  readonly cap: number

  constructor(cap = REINVESTIGATION_CAP) {
    this.cap = Math.max(1, Math.floor(cap))
  }

  countFor(key: string): number {
    return this.counts.get(key) ?? 0
  }

  /** Record one investigation attempt for the route/class key. */
  record(key: string, unlocked = false): ReinvestigationVerdict {
    const previous = this.countFor(key)
    const allowed = unlocked || previous < Math.max(1, this.cap)
    if (!allowed) {
      this.capped += 1
      return { allowed: false, count: previous, capped: true, unlocked }
    }
    const count = previous + 1
    this.counts.set(key, count)
    return { allowed: true, count, capped: false, unlocked }
  }

  cappedCount(): number {
    return this.capped
  }

  /** Snapshot of the capped counter and per-key counts (telemetry only). */
  snapshot(): { capped: number; counts: Record<string, number> } {
    return { capped: this.capped, counts: Object.fromEntries([...this.counts.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) }
  }
}

/**
 * Whether a det_lead's evidence unlocks another investigation of the same route/class: a chain
 * primitive or parent evidence id means the assignment is escalating, not re-scraping.
 */
export function detLeadUnlocksReinvestigation(data: Record<string, unknown> | null | undefined): boolean {
  if (!data) return false
  if (typeof data.chainPrimitiveKind === 'string' && data.chainPrimitiveKind.trim()) return true
  if (typeof data.chainPrimitive === 'string' && data.chainPrimitive.trim()) return true
  if (Array.isArray(data.parentEvidenceIds) && data.parentEvidenceIds.length > 0) return true
  if (Array.isArray(data.evidenceExchangeIds) && data.evidenceExchangeIds.length > 0) return true
  return false
}

/** A lead only reaches the scheduler when a control contrast / near-miss exists. */
export interface DetLeadEvidenceGate {
  admitted: boolean
  reason: string
}

/**
 * Reject shapes where the "signal" is explained by the control (idempotent 2xx, nonexistent-id
 * acceptance, duplicate) rather than a real differential. Until the tightened `detlane-leads`
 * contract lands, this consumes the existing `verifyFailureReason`/`failureReason` plus explicit
 * `controlPassed` / `nearMiss` / `contrast` flags so the stricter contract plugs in unchanged.
 */
export function detLeadEvidenceGate(data: Record<string, unknown> | null | undefined): DetLeadEvidenceGate {
  if (!data || data.kind !== 'det_lead') return { admitted: false, reason: 'not_a_det_lead' }
  if (data.controlPassed === false) return { admitted: false, reason: 'control_collapsed' }
  if (data.contrast === false || data.differsFromControl === false) return { admitted: false, reason: 'no_contrast' }
  // A Program-Graph white-box lead carries a bounded dataflow slice (route -> hops -> sink),
  // sibling RBAC/middleware policy diff, or static secret/IaC lead as its evidence: it is
  // admit-eligible without the runtime control contrast a black-box det_lead requires.
  if (data.source === 'program_graph') {
    const slice = data.codeSlice as { hops?: unknown } | undefined
    if (slice && Array.isArray(slice.hops) && slice.hops.length > 0) {
      return { admitted: true, reason: 'code_dataflow_slice' }
    }
    if ((Array.isArray(data.guardDiff) && data.guardDiff.length > 0) || data.policyDiff === true) {
      return { admitted: true, reason: 'rbac_policy_diff' }
    }
    if (data.staticLeadKind === 'secret' || data.staticLeadKind === 'iac') {
      return { admitted: true, reason: 'static_secret_or_iac' }
    }
    return { admitted: false, reason: 'code_slice_missing' }
  }
  // `detlane-leads` contract: emitted leads carry the promotion evidence that justified them. The
  // three kinds are exactly "a boundary was observed but not yet bound into a replay".
  const evidenceKind = typeof data.leadEvidenceKind === 'string' ? data.leadEvidenceKind : ''
  if (evidenceKind === 'near_miss' || evidenceKind === 'denied_control' || evidenceKind === 'data_delta') {
    return { admitted: true, reason: 'failed_control_or_near_miss' }
  }
  if (evidenceKind === 'bare_anomaly' || evidenceKind === 'none') {
    return { admitted: false, reason: 'no_contrast_evidence' }
  }
  const failureCode = typeof data.verifyFailureCode === 'string' ? data.verifyFailureCode : ''
  if (/^(?:status_only|missing_control_differential|control_failed)$/.test(failureCode)) {
    return { admitted: false, reason: 'no_control_contrast' }
  }
  if (/^(?:missing_identifier_binding|missing_state_delta|missing_probe_binding)$/.test(failureCode)) {
    return { admitted: true, reason: 'failed_control_or_near_miss' }
  }
  const failure = typeof data.verifyFailureReason === 'string'
    ? data.verifyFailureReason
    : typeof data.failureReason === 'string'
      ? data.failureReason
      : ''
  if (failure) {
    const collapsed = /control\s*(?:passed\s*[:=]?\s*false)|controlpassed\s*[:=]?\s*false|no\s+contrast|control\s+(?:also|matched|did\s+not\s+differ)|also\s+(?:returned|succeeded)|same\s+(?:result|response|status)|idempoten|non-?existent/i.test(failure)
    const nearMiss = /near[\s_-]?miss|control\s+(?:diverg|mismatch|differ)|differs?\s+from\s+(?:the\s+)?control|contrast|delta|failed\s+control/i.test(failure)
    if (collapsed && !nearMiss) return { admitted: false, reason: 'no_control_contrast' }
    return { admitted: true, reason: 'failed_control_or_near_miss' }
  }
  if (data.controlPassed === true || data.nearMiss === true || data.contrast === true || data.differsFromControl === true) {
    return { admitted: true, reason: 'control_contrast_evidence' }
  }
  const anomalies = Array.isArray(data.anomalies) ? data.anomalies : []
  const contrastAnomaly = anomalies.some(anomaly => {
    if (!anomaly || typeof anomaly !== 'object') return false
    const record = anomaly as Record<string, unknown>
    const tag = typeof record.classification === 'string' ? record.classification : typeof record.type === 'string' ? record.type : ''
    return /control|contrast|delta|differ|near[\s_-]?miss/i.test(tag)
  })
  if (contrastAnomaly) return { admitted: true, reason: 'near_miss_anomaly' }
  return { admitted: false, reason: 'no_contrast_evidence' }
}

export type DispatchLane = 'lead' | 'route' | 'workflow' | 'business_logic' | 'race' | 'chain' | 'other'

/** Non-lead lanes in round-robin order. Multi-hop chains lead so they never starve behind route sweeps. */
export const DISPATCH_LANE_ORDER: readonly Exclude<DispatchLane, 'lead'>[] = [
  'chain', 'route', 'workflow', 'business_logic', 'race', 'other',
]

/** Minimum Phase-B worker concurrency when >= 3 distinct primary steps are ready and budget/RPS allow. */
export const PHASE_B_MIN_CONCURRENCY_FLOOR = 3

export interface EffectivePhaseBConcurrencyInput {
  configuredConcurrency: number
  /** Distinct primary (`trialIndex <= 0`) ready steps waiting in the Phase-B queue. */
  readyPrimarySteps: number
  /** Ready multi-hop chain steps (`isMultiHopChainStep`) waiting in the Phase-B queue. */
  readyChainSteps?: number
  /** Remaining USD budget for the run (omitted = unconstrained). */
  budgetUsdRemaining?: number
  /** Remaining request budget for the run (omitted = unconstrained). */
  budgetRequestsRemaining?: number
  /** Configured per-origin RPS limit (omitted = unconstrained). */
  maxRpsPerOrigin?: number
  /** Optional concurrency ceiling (defaults to `maxWorkerConcurrency`). */
  maxConcurrency?: number
}

/**
 * Resolve effective Phase-B specialist concurrency so a low caller default (e.g., cell concurrency
 * `1` passed as `workerConcurrency`) cannot starve a queued multi-hop frontier behind a single
 * worker when >= 3 distinct primary steps are ready and budget/RPS headroom allow parallel slots.
 */
export function resolveEffectivePhaseBConcurrency(input: EffectivePhaseBConcurrencyInput): number {
  const ceiling = Math.max(1, Math.min(maxWorkerConcurrency, Math.floor(input.maxConcurrency ?? maxWorkerConcurrency)))
  const base = Math.max(1, Math.min(ceiling, Math.floor(input.configuredConcurrency || defaultWorkerConcurrency)))
  const readyPrimary = Math.max(0, Math.floor(input.readyPrimarySteps))
  const readyChains = Math.max(0, Math.floor(input.readyChainSteps ?? 0))
  const usdOk = input.budgetUsdRemaining === undefined || input.budgetUsdRemaining > 0.05
  const reqOk = input.budgetRequestsRemaining === undefined || input.budgetRequestsRemaining >= PHASE_B_MIN_CONCURRENCY_FLOOR * 10
  const rpsOk = input.maxRpsPerOrigin === undefined || input.maxRpsPerOrigin >= PHASE_B_MIN_CONCURRENCY_FLOOR
  if (usdOk && reqOk && rpsOk) {
    if (readyPrimary >= PHASE_B_MIN_CONCURRENCY_FLOOR) {
      return Math.min(ceiling, Math.max(base, PHASE_B_MIN_CONCURRENCY_FLOOR))
    }
    if (readyChains >= 1 && readyPrimary >= 2 && base < 2) {
      return Math.min(ceiling, 2)
    }
  }
  return base
}

export interface DispatchLaneStep {
  id: string
  seq: number
  priority: number
  title: string
  category?: string | null
  hypothesis?: string | null
  skills?: readonly string[]
  dependsOnFactIds?: readonly string[]
  dependsOnStepIds?: readonly string[]
  sourceOrigins?: readonly string[]
  /** Multi-trial sibling index (`0` or omitted = primary hypothesis; `> 0` = unstarted duplicate). */
  trialIndex?: number | null
}

export interface RoundRobinDispatchOptions {
  /** Total concurrent lead assignments allowed (default {@link DET_LEAD_CONCURRENT_CAP}). */
  leadCap?: number
  /** Lead assignments already in flight; subtracted from the cap. */
  activeLeadCount?: number
  /** Host tiers used to order Tier-A/B routes ahead of low-value static hosts. */
  hostTiers?: Record<string, HostTier>
  /**
   * Tier-A Program-Graph step ids. They are dispatched first and do not consume the generic
   * concurrent-lead cap, so every Tier-A slice reaches a slot in Round 1.
   */
  tierALeadIds?: ReadonlySet<string>
  /**
   * v7 M2 white-box-first default: when repository source is mounted (`sourceDir` / `mountedRepos`),
   * AST/RBAC/dataflow/source-audit steps are prioritized strictly ahead of generic black-box steps
   * without being throttled by `DET_LEAD_CONCURRENT_CAP`.
   */
  sourceMounted?: boolean
  /** Additional white-box step ids (e.g. source-audit or RBAC policy diff steps). */
  whiteBoxStepIds?: ReadonlySet<string>
  /** Allow leads past the cap only when no non-lead ready step remains (default true). */
  allowLeadOverflow?: boolean
  /** Dedicated frontier slots reserved for ready multi-hop chain steps before generic lead/route fill. */
  chainReservedSlots?: number
  /** Multi-hop chain assignments already in flight; subtracted from the chain reservation. */
  activeChainCount?: number
}

export interface RoundRobinDispatchPlan<T extends DispatchLaneStep> {
  ordered: T[]
  selectedByLane: Record<DispatchLane, number>
  leadCapRemaining: number
  deferredLeads: number
}

/** Identify white-box AST/RBAC/dataflow/source-audit steps so mounted-source runs prioritize them first. */
export function isWhiteBoxStep(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>,
  whiteBoxFactIds?: ReadonlySet<string>,
): boolean {
  if (whiteBoxFactIds?.size && (step.dependsOnFactIds ?? []).some(id => whiteBoxFactIds.has(id))) return true
  if ((step.skills ?? []).includes('source-first-audit')) return true
  const text = `${step.title} ${step.hypothesis ?? ''}`
  return /\btier[- ]a code lead\b/i.test(text)
    || /\bsource[- ]first code audit\b/i.test(text)
    || /\bsource audit verify\b/i.test(text)
    || /\bsemantic audit\b/i.test(text)
    || /\bwhite[- ]box dataflow slice\b/i.test(text)
    || /\bmiddleware\/rbac policy diff\b|\brbac\/middleware policy diff\b|\bmissing_guard\b/i.test(text)
    || /\bprogram[- ]graph\b/i.test(text)
}

/**
 * Remove black-box-first priority overrides when repository source is mounted (`sourceDir` /
 * `mountedRepos`): white-box steps retain full priority, while generic black-box steps are capped
 * below white-box AST/RBAC/dataflow leads (`<= WHITEBOX_BLACKBOX_CAP_PRIORITY`).
 */
export function prioritizeMountedSourceInitialSteps<T extends {
  title: string
  hypothesis?: string | null
  skills?: readonly string[]
  dependsOnFactIds?: readonly string[]
  priority: number
}>(
  steps: readonly T[],
  options: { sourceMounted: boolean; hasWhiteBoxSteps?: boolean; whiteBoxFactIds?: ReadonlySet<string> },
): T[] {
  if (!options.sourceMounted) return [...steps]
  return steps
    .map(step => {
      if (isWhiteBoxStep(step, options.whiteBoxFactIds)) return step
      return {
        ...step,
        priority: Math.min(step.priority, WHITEBOX_BLACKBOX_CAP_PRIORITY),
      }
    })
    .sort((a, b) =>
      Number(isWhiteBoxStep(b, options.whiteBoxFactIds)) - Number(isWhiteBoxStep(a, options.whiteBoxFactIds))
      || b.priority - a.priority)
}

/** A det_lead upgrade is identified by its title/hypothesis contract, not by numeric priority. */
export function isDetLeadDispatchStep(step: Pick<DispatchLaneStep, 'title' | 'hypothesis'>): boolean {
  const text = `${step.title} ${step.hypothesis ?? ''}`
  return /\bdet[_ ]lead\b/i.test(text) ||
    /\btier[- ]a code lead\b/i.test(text) ||
    /deterministic floor observed an unproven/i.test(text) ||
    /\bunproven\b[^.]{0,80}\blead\b/i.test(text) ||
    /\blead upgrade\b/i.test(text)
}

/** Prefix on `ChainStep.skills` tracking automatic hop-continuation depth (`chain_continuation:1`, `:2`). */
export const CHAIN_CONTINUATION_SKILL_PREFIX = 'chain_continuation:'
/** Maximum automatic hop-continuation steps enqueued per source/planner chain lineage that sealed a capability handle. */
export const MAX_CHAIN_CONTINUATIONS = 2
/** Maximum automatic hop-continuation steps enqueued for generic Wave-1 heuristic boundary chains. */
export const MAX_GENERIC_WAVE1_CHAIN_CONTINUATIONS = 1
/** Maximum targeted multi-hop steps promoted immediately into Wave 1 from Source-First Code Audit. */
export const CODE_AUDIT_WAVE1_MAX_STEPS = 6

const SEALED_HOP_CAP_HANDLE_RE = /\bcap:hop_(?!synth:)[A-Za-z0-9._-]+:[A-Za-z0-9._-]+/
const SOURCE_AUDIT_ORIGIN_TEXT_RE = /\b(?:source[- ]first code audit|source audit verify|semantic audit|code_audit_suspect|code_audit|source_audit|semantic_audit)\b/i
const CAUSAL_ARROW_HYPOTHESIS_RE = /->|→|=>/

/** Extract the continuation depth (`0` for original steps, `1..N` for continuation steps). */
export function extractContinuationDepth(step: { skills?: readonly string[] }): number {
  let maxDepth = 0
  for (const skill of step.skills ?? []) {
    if (!skill.startsWith(CHAIN_CONTINUATION_SKILL_PREFIX)) continue
    const parsed = Number(skill.slice(CHAIN_CONTINUATION_SKILL_PREFIX.length).trim())
    if (Number.isInteger(parsed) && parsed > maxDepth) maxDepth = parsed
  }
  return maxDepth
}

/** True when a step is an automatic hop-continuation step carrying a verified checkpoint. */
export function isChainContinuationStep(step: { skills?: readonly string[] }): boolean {
  return extractContinuationDepth(step) > 0
}

/** True when a step originates from code_audit / source_audit / semantic_audit. */
export function hasSourceAuditOrigin(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills'>,
): boolean {
  if ((step.skills ?? []).some(skill =>
    skill === 'source-first-audit'
    || skill === 'code_audit'
    || skill === 'source_audit'
    || skill === 'semantic_audit',
  )) {
    return true
  }
  return SOURCE_AUDIT_ORIGIN_TEXT_RE.test(`${step.title} ${step.hypothesis ?? ''}`)
}

/**
 * True when a step is a generic Wave-1 heuristic boundary stub (`Wave-1 chain · ...` without
 * `dependsOnFactIds` at depth 0 or concrete source-audit suspect linkage), including any
 * continuation spawned from such a stub.
 */
export function isGenericWave1BoundaryChainStep(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>,
): boolean {
  if (hasSourceAuditOrigin(step)) return false
  const isWave1StubMarker = /^wave-1\s+chain\b/i.test(step.title)
    || /\[inv_hyp=[^\]]+\]/i.test(step.hypothesis ?? '')
    || (step.skills ?? []).includes('wave1-boundary-stub')
  if (!isWave1StubMarker) return false
  if (extractContinuationDepth(step) === 0 && (step.dependsOnFactIds?.length ?? 0) > 0) return false
  return true
}

/**
 * True when a chain step is backed by concrete source-audit findings, upstream facts
 * (`dependsOnFactIds`), or a planner-synthesized causal arrow hypothesis (as opposed to a generic
 * Wave-1 heuristic boundary stub).
 */
export function isHighSignalSourceOrPlannerChainStep(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>,
): boolean {
  if (isGenericWave1BoundaryChainStep(step)) return false
  if (hasSourceAuditOrigin(step)) return true
  if ((step.dependsOnFactIds?.length ?? 0) > 0) return true
  if ((step.skills ?? []).some(skill => skill.startsWith('chain:'))) return true
  return CAUSAL_ARROW_HYPOTHESIS_RE.test(`${step.title} ${step.hypothesis ?? ''}`)
}

/**
 * True when a step carries a runtime-sealed `cap:hop_*` capability handle from `CapabilityLedger`
 * (excluding static `cap:hop_synth:*` invariant seeds).
 */
export function hasSealedHopCapability(
  step: Pick<DispatchLaneStep, 'hypothesis' | 'skills'>,
): boolean {
  if ((step.skills ?? []).some(skill =>
    skill.startsWith('checkpoint_cap:')
    && SEALED_HOP_CAP_HANDLE_RE.test(skill.slice('checkpoint_cap:'.length)),
  )) {
    return true
  }
  return SEALED_HOP_CAP_HANDLE_RE.test(step.hypothesis ?? '')
}

/**
 * Fair multi-hop frontier interleaving rank within the `chain` lane (lower = higher priority):
 *  0. Unstarted (`depth === 0`) source-audit / planner-synthesized multi-hop chains,
 *  1. `depth === 1` continuations that sealed a `cap:hop_*` capability handle,
 *  2. Remaining unstarted (`depth === 0`) Wave-1 boundary chains,
 *  3. `depth === 1` continuations without a sealed `cap:hop_*` handle,
 *  4. `depth >= 2` continuations (only after distinct chains have had their first shot).
 */
export function chainLaneDispatchRank(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>,
): number {
  const depth = extractContinuationDepth(step)
  if (depth === 0) {
    return isHighSignalSourceOrPlannerChainStep(step) ? 0 : 2
  }
  if (depth === 1) {
    return hasSealedHopCapability(step) ? 1 : 3
  }
  return 4
}

/** Identify genuine multi-hop / depth >= 2 chain steps eligible for dedicated frontier slot reservation. */
export function isMultiHopChainStep(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'category' | 'skills' | 'dependsOnStepIds'>,
): boolean {
  if ((step.dependsOnStepIds?.length ?? 0) > 0) return true
  if ((step.skills ?? []).some(skill =>
    skill === 'multihop-chains'
    || skill === 'chain-primitives'
    || skill.startsWith('chain:')
    || skill.startsWith(CHAIN_CONTINUATION_SKILL_PREFIX)
    || skill.startsWith('checkpoint_cap:'),
  )) {
    return true
  }
  const text = `${step.title} ${step.hypothesis ?? ''} ${step.category ?? ''}`
  return /\[chain_hops=|\bhopCheckpoint\b|\bmulti[- ]?hop\b|\bchain_step\b|\bchain_continuation\b/i.test(text)
}

/** Map a step onto the round-robin lane it competes in. */
export function classifyDispatchLane(
  step: DispatchLaneStep,
  hostTiers?: Record<string, HostTier>,
): DispatchLane {
  if (isDetLeadDispatchStep(step)) return 'lead'
  const text = `${step.title} ${step.hypothesis ?? ''} ${step.category ?? ''} ${(step.skills ?? []).join(' ')}`.toLowerCase()
  if (isMultiHopChainStep(step) || /\bchain\b|second[\s_-]?order|cross[\s_-]?host|cross[\s_-]?origin|escalat/.test(text)) return 'chain'
  if (/\brace\b|concurren|toctou|double[\s_-]?spend|simultaneous|parallel/.test(text)) return 'race'
  if (/\bworkflow\b|state[\s_-]?machine|transition|invite|onboard|checkout[\s_-]?flow|approval[\s_-]?bypass/.test(text)) return 'workflow'
  if (/\bbusiness\b|invariant|quantity|price|seat|credit|balance|discount|coupon|refund|quota|entitlement/.test(text)) return 'business_logic'
  const origins = step.sourceOrigins ?? []
  if (hostTiers && origins.length > 0 &&
    origins.every(origin => (hostTiers[origin] ?? classifyHostTier(origin)) === 'low_value_static')) return 'other'
  return 'route'
}

function dispatchTierRank(step: DispatchLaneStep, hostTiers?: Record<string, HostTier>): number {
  if (!hostTiers) return 1
  const origins = step.sourceOrigins ?? []
  if (origins.some(origin => (hostTiers[origin] ?? classifyHostTier(origin)) === 'crown_jewel')) return 0
  if (origins.length > 0 && origins.every(origin => (hostTiers[origin] ?? classifyHostTier(origin)) === 'low_value_static')) return 2
  return 1
}

function isTrialDuplicateStep(step: Pick<DispatchLaneStep, 'trialIndex'>): boolean {
  return typeof step.trialIndex === 'number' && step.trialIndex > 0
}

function compareDispatchSteps(a: DispatchLaneStep, b: DispatchLaneStep, hostTiers?: Record<string, HostTier>): number {
  const trialDup = Number(isTrialDuplicateStep(a)) - Number(isTrialDuplicateStep(b))
  if (trialDup !== 0) return trialDup
  const tier = dispatchTierRank(a, hostTiers) - dispatchTierRank(b, hostTiers)
  if (tier !== 0) return tier
  if (a.priority !== b.priority) return b.priority - a.priority
  if (a.seq !== b.seq) return a.seq - b.seq
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

/**
 * Fill `slots` deterministically: up to the lead cap first, then one step per lane per round so a
 * lead backlog or a single large route lane can never starve the semantic classes. Leads past the
 * cap only run when no non-lead ready step remains. Unstarted trial duplicates (`trialIndex > 0`)
 * are demoted strictly behind every distinct primary ready step across all lanes and only fill
 * remaining surplus capacity.
 */
export function planRoundRobinDispatch<T extends DispatchLaneStep>(
  steps: readonly T[],
  slots: number,
  options: RoundRobinDispatchOptions = {},
): RoundRobinDispatchPlan<T> {
  const capacity = Math.max(0, Math.floor(slots))
  const selectedByLane: Record<DispatchLane, number> = {
    lead: 0, route: 0, workflow: 0, business_logic: 0, race: 0, chain: 0, other: 0,
  }
  const lanes = new Map<DispatchLane, T[]>()
  for (const lane of ['lead', ...DISPATCH_LANE_ORDER] as DispatchLane[]) lanes.set(lane, [])
  const duplicateTrials: Array<{ lane: DispatchLane; step: T }> = []
  for (const step of steps) {
    const lane = classifyDispatchLane(step, options.hostTiers)
    if (isTrialDuplicateStep(step)) duplicateTrials.push({ lane, step })
    else lanes.get(lane)!.push(step)
  }
  for (const lane of lanes.values()) lane.sort((a, b) => compareDispatchSteps(a, b, options.hostTiers))
  // Fair multi-hop frontier interleaving within the chain lane:
  // 0: unstarted (depth 0) source-audit / planner-synthesized multi-hop chains,
  // 1: depth-1 continuations carrying a sealed cap:hop_* capability handle,
  // 2: remaining unstarted (depth 0) Wave-1 boundary chains,
  // 3: depth-1 continuations without a sealed capability handle,
  // 4: depth >= 2 continuations (never preempt unstarted source/planner or Wave-1 chains).
  lanes.get('chain')!.sort((a, b) =>
    chainLaneDispatchRank(a) - chainLaneDispatchRank(b)
    || Number(isGenericWave1BoundaryChainStep(a)) - Number(isGenericWave1BoundaryChainStep(b))
    || compareDispatchSteps(a, b, options.hostTiers),
  )
  duplicateTrials.sort((a, b) => compareDispatchSteps(a.step, b.step, options.hostTiers))

  const leadCap = Math.max(
    0,
    Math.floor(options.leadCap ?? DET_LEAD_CONCURRENT_CAP) - Math.max(0, Math.floor(options.activeLeadCount ?? 0)),
  )
  const ordered: T[] = []
  const leadQueue = lanes.get('lead')!
  const tierALeadIds = options.tierALeadIds
  const whiteBoxStepIds = options.whiteBoxStepIds
  const whiteBoxFirst = options.sourceMounted === true || Boolean(whiteBoxStepIds?.size)

  // v7 M2 white-box-first default: when repository source is mounted, pull every white-box
  // AST/RBAC/dataflow/source-audit step across all lanes strictly ahead of generic black-box steps
  // (never throttled by DET_LEAD_CONCURRENT_CAP).
  let tierASelected = 0
  if (whiteBoxFirst) {
    const isPrioritizedWhiteBox = (step: T): boolean =>
      Boolean(tierALeadIds?.has(step.id))
      || Boolean(whiteBoxStepIds?.has(step.id))
      || isWhiteBoxStep(step)
    const whiteBoxCandidates: Array<{ lane: DispatchLane; step: T }> = []
    for (const [lane, queue] of lanes.entries()) {
      for (let idx = 0; idx < queue.length;) {
        if (!isPrioritizedWhiteBox(queue[idx]!)) { idx += 1; continue }
        whiteBoxCandidates.push({ lane, step: queue.splice(idx, 1)[0]! })
      }
    }
    whiteBoxCandidates.sort((a, b) =>
      Number(isChainContinuationStep(a.step)) - Number(isChainContinuationStep(b.step))
      || (a.lane === 'chain' && b.lane === 'chain'
        ? chainLaneDispatchRank(a.step) - chainLaneDispatchRank(b.step)
        : 0)
      || compareDispatchSteps(a.step, b.step, options.hostTiers),
    )
    const remainingWhiteBox: Array<{ lane: DispatchLane; step: T }> = []
    for (const entry of whiteBoxCandidates) {
      if (ordered.length < capacity) {
        ordered.push(entry.step)
        selectedByLane[entry.lane] += 1
        if (entry.lane === 'lead') tierASelected += 1
      } else {
        remainingWhiteBox.push(entry)
      }
    }
    // Put any overflow white-box steps back at the front of their lanes so deferredLeads stays accurate.
    for (const entry of remainingWhiteBox.reverse()) {
      lanes.get(entry.lane)!.unshift(entry.step)
    }
  } else if (tierALeadIds?.size) {
    // Tier-A first: every Tier-A slice must reach a slot in Round 1, independent of the generic
    // concurrent-lead cap (it is still bounded by the worker capacity).
    for (let idx = 0; idx < leadQueue.length && ordered.length < capacity;) {
      if (!tierALeadIds.has(leadQueue[idx]!.id)) { idx += 1; continue }
      ordered.push(leadQueue.splice(idx, 1)[0]!)
      selectedByLane.lead += 1
      tierASelected += 1
    }
  }
  // Dedicated frontier slots for ready multi-hop / depth >= 2 chain steps so synthesized chains
  // never starve behind generic det_lead or single-route BOLA sweeps.
  const chainQueue = lanes.get('chain')!
  const readyMultiHopCount = chainQueue.filter(step => isMultiHopChainStep(step)).length
  const nonChainPrimaryCount = leadQueue.length +
    DISPATCH_LANE_ORDER.filter(lane => lane !== 'chain').reduce((sum, lane) => sum + lanes.get(lane)!.length, 0)
  const defaultChainReserve = readyMultiHopCount > 0
    ? (capacity >= 3 ? Math.max(1, Math.ceil(capacity / 2)) : 1)
    : 0
  const rawChainReserve = options.chainReservedSlots !== undefined
    ? Math.max(0, Math.floor(options.chainReservedSlots))
    : defaultChainReserve
  const maxChainReserve = nonChainPrimaryCount > 0 && capacity >= 2
    ? Math.min(rawChainReserve, capacity - 1)
    : rawChainReserve
  const chainReserveRemaining = Math.max(0, maxChainReserve - Math.max(0, Math.floor(options.activeChainCount ?? 0)))
  let chainReservedSelected = 0
  for (let idx = 0; idx < chainQueue.length && ordered.length < capacity && chainReservedSelected < chainReserveRemaining;) {
    if (!isMultiHopChainStep(chainQueue[idx]!)) { idx += 1; continue }
    ordered.push(chainQueue.splice(idx, 1)[0]!)
    selectedByLane.chain += 1
    chainReservedSelected += 1
  }

  while (ordered.length < capacity && leadQueue.length > 0 && selectedByLane.lead - tierASelected < leadCap) {
    ordered.push(leadQueue.shift()!)
    selectedByLane.lead += 1
  }

  let progressed = true
  while (ordered.length < capacity && progressed) {
    progressed = false
    for (const lane of DISPATCH_LANE_ORDER) {
      if (ordered.length >= capacity) break
      const queue = lanes.get(lane)!
      if (!queue.length) continue
      ordered.push(queue.shift()!)
      selectedByLane[lane] += 1
      progressed = true
    }
  }

  if (options.allowLeadOverflow ?? true) {
    while (ordered.length < capacity && leadQueue.length > 0) {
      ordered.push(leadQueue.shift()!)
      selectedByLane.lead += 1
    }
  }

  // Surplus slots only: unstarted trial duplicates never displace a distinct primary hypothesis.
  for (const entry of duplicateTrials) {
    if (ordered.length >= capacity) break
    ordered.push(entry.step)
    selectedByLane[entry.lane] += 1
  }

  return {
    ordered,
    selectedByLane,
    leadCapRemaining: Math.max(0, leadCap - selectedByLane.lead),
    deferredLeads: leadQueue.length,
  }
}

export interface HighRiskEndpointCandidate {
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  source?: string | null
  coveragePct?: number | null
  testedClasses?: readonly string[] | null
}

function isWhiteBoxEndpointSource(source?: string | null): boolean {
  const s = (source ?? '').toLowerCase()
  return s === 'repo_ast' || s === 'program_graph' || s === 'code_audit'
}

/**
 * Discovered high-risk endpoints (`riskScore >= minRisk`) that are neither confirmed nor covered
 * by any existing planned/dispatched step. Used by the planner coverage assertion before accepting
 * a dry/coordinator stop so high-risk routes cannot be silently dropped.
 */
export function selectUncoveredHighRiskEndpoints<T extends HighRiskEndpointCandidate>(input: {
  endpoints: readonly T[]
  approvedOrigins: ReadonlySet<string>
  confirmedPaths: ReadonlySet<string>
  coveredRoutes: ReadonlySet<string>
  minRisk?: number
  limit?: number
  /** When repository source is mounted, prioritize AST/Program-Graph endpoints ahead of crawled routes. */
  sourceMounted?: boolean
}): T[] {
  const minRisk = input.minRisk ?? 60
  const limit = Math.max(0, Math.floor(input.limit ?? 6))
  if (limit === 0) return []
  const seen = new Set<string>()
  const eligible: T[] = []
  for (const ep of input.endpoints) {
    if (!input.approvedOrigins.has(ep.origin)) continue
    if (ep.riskScore < minRisk) continue
    const normalizedPath = normalizeEndpointTemplate(ep.pathTemplate)
    if (!normalizedPath || normalizedPath === '/') continue
    if (input.confirmedPaths.has(normalizedPath)) continue
    if (input.coveredRoutes.has(normalizedPath)) continue
    const method = (ep.method || 'GET').toUpperCase()
    const key = `${ep.origin}\u0000${method}\u0000${normalizedPath}`
    if (seen.has(key)) continue
    seen.add(key)
    eligible.push(ep)
  }
  eligible.sort((a, b) =>
    (input.sourceMounted
      ? Number(isWhiteBoxEndpointSource(b.source)) - Number(isWhiteBoxEndpointSource(a.source))
      : 0) ||
    b.riskScore - a.riskScore ||
    (a.coveragePct ?? 0) - (b.coveragePct ?? 0) ||
    a.method.localeCompare(b.method) ||
    a.pathTemplate.localeCompare(b.pathTemplate))
  return eligible.slice(0, limit)
}

/**
 * Extract deduplicated assigned target routes for per-route proof-obligation tracking from a step's
 * title/hypothesis and its parent `det_lead`/Program-Graph facts.
 */
export function extractAssignedTargetRoutes(input: {
  title: string
  hypothesis: string
  parentFacts?: ReadonlyArray<{ origin?: string; data?: Record<string, unknown> | null }>
  defaultOrigin?: string
}): Array<{ method?: string; path?: string; origin?: string }> {
  const routes: Array<{ method?: string; path?: string; origin?: string }> = []
  const seen = new Set<string>()
  const add = (entry: { method?: string; path?: string; origin?: string }) => {
    const rawPath = entry.path?.trim()
    if (!rawPath || !rawPath.startsWith('/')) return
    const normalizedPath = normalizeEndpointTemplate(rawPath.split(/[?#]/, 1)[0] ?? rawPath)
    const method = entry.method ? entry.method.toUpperCase() : undefined
    const key = `${method ?? '*'} ${normalizedPath}`
    if (seen.has(key)) return
    seen.add(key)
    routes.push({
      ...(method ? { method } : {}),
      path: rawPath,
      ...(entry.origin ? { origin: entry.origin } : input.defaultOrigin ? { origin: input.defaultOrigin } : {}),
    })
  }
  for (const fact of input.parentFacts ?? []) {
    const data = fact.data
    if (!data || typeof data !== 'object') continue
    const endpoint = typeof data.endpoint === 'string'
      ? data.endpoint
      : typeof data.path === 'string'
        ? data.path
        : undefined
    const method = typeof data.method === 'string' ? data.method : undefined
    if (endpoint) add({ method, path: endpoint, origin: fact.origin })
  }
  for (const route of templatesMentionedInText(`${input.title} ${input.hypothesis}`)) {
    add({ path: route, origin: input.defaultOrigin })
  }
  return routes.slice(0, 8)
}

/** Endpoint templates named inside free text (title/hypothesis), normalized. */
export function templatesMentionedInText(text: string): string[] {
  const routes = new Set<string>()
  for (const match of text.matchAll(/(?:^|[\s`'"(,])((?:\/[A-Za-z0-9_\-.:{}[\]]+){2,})/g)) {
    const raw = match[1].replace(/[),.;:'"`]+$/, '')
    if (!raw.startsWith('/')) continue
    if (/^\/(?:api|v\d+)$/i.test(raw)) continue
    routes.add(normalizeEndpointTemplate(raw))
  }
  return [...routes]
}

export interface AssignmentBolaQueueInput {
  queue: readonly BolaTestQueueItem[]
  targetOrigins: readonly string[]
  step: {
    title: string
    hypothesis: string
    category?: string | null
    skills?: readonly string[]
    specialistProfile?: string | null
  }
  /** Defaults to {@link ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS}. */
  maxItems?: number
  /** Defaults to {@link ASSIGNMENT_BOLA_QUEUE_MAX_BYTES}. */
  maxBytes?: number
}

export function measureBolaQueueBytes(items: readonly BolaTestQueueItem[]): number {
  return Buffer.byteLength(JSON.stringify(items), 'utf8')
}

function readFirstVariants(variants: readonly BolaConsumerVariant[]): BolaConsumerVariant[] {
  return [...variants].sort((a, b) =>
    (a.method === 'GET' ? 0 : 1) - (b.method === 'GET' ? 0 : 1) ||
    Number(a.destructive) - Number(b.destructive))
}

/**
 * Slice the cross-persona resource queue down to what one assignment can actually use.
 *
 * The full queue (58 items / 53 KB) was injected into every worker, including the cache/CORS
 * specialist, and biased reads towards destructive DELETE variants. Only BOLA/IDOR-relevant
 * assignments get a slice now, ordered by route/resource relevance, read variants first, capped at
 * {@link ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS} items and {@link ASSIGNMENT_BOLA_QUEUE_MAX_BYTES} bytes.
 * The remainder stays queryable through the worker tools.
 */
export function selectAssignmentBolaQueueItems(input: AssignmentBolaQueueInput): BolaTestQueueItem[] {
  const maxItems = Math.max(0, Math.min(
    ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS,
    Math.floor(input.maxItems ?? ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS),
  ))
  const maxBytes = Math.max(0, Math.floor(input.maxBytes ?? ASSIGNMENT_BOLA_QUEUE_MAX_BYTES))
  if (!maxItems || !maxBytes || !input.queue.length) return []
  const text = `${input.step.title} ${input.step.hypothesis} ${input.step.category ?? ''} ${(input.step.skills ?? []).join(' ')}`.toLowerCase()
  const eligible = input.step.specialistProfile === 'bola-bfla-specialist' ||
    (input.step.skills ?? []).includes('bola-idor-race') ||
    /broken-access-control|\bbola\b|\bidor\b|cross[\s_-]?persona/.test(text)
  if (!eligible) return []

  const origins = new Set(input.targetOrigins)
  const mentioned = new Set(templatesMentionedInText(`${input.step.title} ${input.step.hypothesis}`))
  const leadingSegments = new Set(
    [...mentioned].map(template => template.split('/').filter(Boolean)[0]).filter((segment): segment is string => Boolean(segment)),
  )
  const scored = input.queue
    .filter(item => origins.has(item.origin))
    .map(item => {
      const template = normalizeEndpointTemplate(item.endpoint)
      let score = 0
      if (mentioned.has(template)) score += 100
      else if ([...mentioned].some(named => named.startsWith(template) || template.startsWith(named))) score += 60
      const leading = template.split('/').filter(Boolean)[0]
      if (leading && leadingSegments.has(leading)) score += 20
      if ((item.method ?? '').toUpperCase() === 'GET' && item.variants.some(variant => variant.method === 'GET' && !variant.destructive)) score += 15
      if (text.includes(item.resourceKey.toLowerCase())) score += 30
      if (text.includes(item.resourceId.toLowerCase())) score += 15
      return { item, score }
    })
    .sort((a, b) =>
      b.score - a.score ||
      a.item.origin.localeCompare(b.item.origin) ||
      a.item.resourceKey.localeCompare(b.item.resourceKey) ||
      a.item.endpoint.localeCompare(b.item.endpoint) ||
      a.item.resourceId.localeCompare(b.item.resourceId))

  const selected: BolaTestQueueItem[] = []
  for (const { item } of scored) {
    if (selected.length >= maxItems) break
    const normalized: BolaTestQueueItem = { ...item, variants: readFirstVariants(item.variants) }
    const next = [...selected, normalized]
    if (measureBolaQueueBytes(next) > maxBytes) continue
    selected.push(normalized)
  }
  return selected
}

export function countConsecutiveDrySteps(
  storage: Store,
  run: Pick<Run, 'id' | 'goalRevision'>,
  excludedAssignmentIds: ReadonlySet<string> = new Set(),
): number {
  const completedSteps = storage.listChainSteps(run.id, run.goalRevision)
    .filter(s => s.status === 'complete')
    .sort((a, b) => b.updatedAt - a.updatedAt || b.seq - a.seq)
  if (completedSteps.length === 0) return 0

  const productiveWorkerIds = new Set<string>()
  const runFacts = storage.listFacts(run.id, { includeTainted: false, limit: 500 })
  for (const f of runFacts) {
    // The concurrent deterministic lane (v5.1 Slice 3) is not a specialist step: its facts and
    // findings must never reset the K=6 dry-streak counter.
    if (f.data?.source === 'deterministic_engine') continue
    if (f.assignmentId && !excludedAssignmentIds.has(f.assignmentId)) productiveWorkerIds.add(f.assignmentId)
  }
  const runFindings = storage.db.select().from(findings).where(and(
    eq(findings.runId, run.id),
    eq(findings.goalRevision, run.goalRevision),
  )).all()
  const runSpecs = storage.listReplaySpecs(run.id)
  for (const sp of runSpecs) {
    if (sp.assignmentId && excludedAssignmentIds.has(sp.assignmentId)) continue
    if (runFindings.some(f => f.id === sp.findingId && f.finding.status !== 'dismissed')) {
      if (sp.assignmentId) productiveWorkerIds.add(sp.assignmentId)
    }
  }

  let dry = 0
  for (const st of completedSteps) {
    if (!st.assignedWorkerId || !productiveWorkerIds.has(st.assignedWorkerId)) {
      dry += 1
    } else {
      break
    }
  }
  return dry
}

export const threatModelResponseSchema = z.object({
  summary: z.string().min(1).max(2000),
  entries: z.array(z.object({
    origin: z.string(),
    riskTier: z.enum(['critical', 'high', 'medium', 'low']),
    hostTier: z.enum(['crown_jewel', 'standard', 'low_value_static']).optional(),
    surfaceTags: z.array(z.string()).default([]),
    rationale: z.string().min(1).max(500),
  })),
  initialSteps: z.array(z.object({
    title: z.string().min(1).max(200),
    hypothesis: z.string().min(1).max(1200),
    category: z.string().default('misconfig-exposure'),
    priority: z.number().min(0).max(100).default(70),
    origins: z.array(z.string()).min(1),
    skills: z.array(z.string()).default([]),
  })).default([]),
})

export const plannerResponseSchema = z.object({
  summary: z.string().default(''),
  newSteps: z.array(z.object({
    title: z.string().min(1).max(200),
    hypothesis: z.string().min(1).max(1200),
    category: z.string().default('misconfig-exposure'),
    priority: z.number().min(0).max(100).default(60),
    origins: z.array(z.string()).min(1),
    skills: z.array(z.string()).default([]),
    dependsOnFactIds: z.array(z.string()).default([]),
    dependsOnStepIds: z.array(z.string()).default([]),
  })).default([]),
  cancelStepIds: z.array(z.string()).default([]),
  done: z.boolean().default(false),
})

export function derivedResult(result: { exitStatus: number; result: string; stdout: string }) {
  return JSON.stringify({ exitStatus: result.exitStatus, result: (result.result || result.stdout).slice(0, 1200) })
}

export function stripJsonFences(raw: string): string {
  const trimmed = raw.trim()
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed)
  if (fenced) return fenced[1].trim()
  const start = trimmed.indexOf('{')
  const end = trimmed.lastIndexOf('}')
  if (start >= 0 && end > start) return trimmed.slice(start, end + 1)
  return trimmed
}

export const hostTierOrder: Record<HostTier, number> = {
  crown_jewel: 0,
  standard: 1,
  low_value_static: 2,
}

export function classifyHostHeuristic(asset: Candidate): ThreatModelSummary {
  const host = new URL(asset.origin).hostname.toLowerCase()
  const tags: string[] = []
  let riskTier: ThreatModelSummary['riskTier'] = 'medium'

  if (/(?:auth|login|sso|oauth|clerk|account|accounts|academy|id|identity)/.test(host)) { tags.push('auth'); riskTier = 'critical' }
  if (/(?:api|graphql|trpc|gateway|backend|cloud|app|dash|admin|portal)/.test(host)) { tags.push('api'); riskTier = riskTier === 'critical' ? 'critical' : 'high' }
  if (/(?:upload|media|file|storage|cdn|asset|bucket|blob)/.test(host)) { tags.push('upload'); riskTier = riskTier === 'medium' ? 'high' : riskTier }
  if (/(?:billing|pay|stripe|checkout|webhook|hook)/.test(host)) { tags.push('billing'); riskTier = 'critical' }
  if (/(?:llm|ai|chat|engine|model|prompt|agent|proxy)/.test(host)) { tags.push('llm-proxy'); riskTier = 'critical' }
  if (/(?:dev|stage|staging|debug|test|beta|preview|sandbox|sandpack|internal|bundler)/.test(host)) { tags.push('staging-debug'); riskTier = 'high' }
  if (asset.dnsSource?.externalAliases?.length) { tags.push('external-cname') }
  if (/(?:blog|docs|marketing|www|status|landing|static)/.test(host) && !tags.length) { tags.push('static'); riskTier = 'low' }
  if (!tags.length) tags.push('web')

  const hostTier = classifyHostTier(asset.origin, tags)
  if (hostTier === 'crown_jewel' && !tags.includes('crown_jewel')) tags.unshift('crown_jewel')
  if (hostTier === 'low_value_static' && !tags.includes('low_value_static')) tags.push('low_value_static')

  return {
    origin: asset.origin,
    riskTier,
    surfaceTags: tags,
    rationale: `Heuristic surface ranking for ${host} (${hostTier}; ${tags.join(', ')}).`,
  }
}

export function computeHostTiers(
  approvedOrigins: readonly string[],
  threatModel?: readonly ThreatModelSummary[],
): Record<string, HostTier> {
  const map: Record<string, HostTier> = {}
  for (const origin of approvedOrigins) {
    const entry = threatModel?.find(e => e.origin === origin)
    map[origin] = classifyHostTier(origin, entry?.surfaceTags)
  }
  return map
}

export function computeStepMaxTurns(
  stepOrigins: readonly string[],
  hostTiers: Record<string, HostTier>,
  baseMaxTurns: number,
): number {
  const hasCrownJewel = Object.values(hostTiers).some(t => t === 'crown_jewel')
  if (!hasCrownJewel || !stepOrigins.length) return baseMaxTurns
  const allLowValueStatic = stepOrigins.every(o => (hostTiers[o] ?? classifyHostTier(o)) === 'low_value_static')
  if (!allLowValueStatic) return baseMaxTurns
  return Math.max(4, Math.min(baseMaxTurns, 15, Math.floor(baseMaxTurns * 0.2)))
}

// ============================================================================
// Phase-B throughput: assignment budget + provider-stall accounting
//
// The Phase-B measurement showed a median assignment wall of ~150 s at K=6, dominated by
// single-route steps held open for 25+ turns. A slot is the scarce resource, so a step that names
// one or two routes gets a short wall cap and a tight turn budget; only a chain step that cites
// upstream evidence (parent facts / prior steps) is allowed the long cap. The helpers are pure so
// the contract is testable without a live run.
// ============================================================================

/** Turn budget for a single-route / single-step assignment (settlement fires at N-2).
 * Raised 12 -> 18 on 2026-11-24: 14 of 19 held-out `no_spec_submitted` targets hit the turn cap while
 * still probing or repairing a spec (7 of them mid-`verify_replay_spec`), so 12 truncated real work. */
export const SINGLE_STEP_ASSIGNMENT_MAX_TURNS = 18
/** Wall cap for a single-step assignment; a slot must turn over inside ~120 s. */
export const SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS = 120_000
/** Multi-step/race assignments need more turns than a single probe (observed 20–29). */
export const MULTI_STEP_ASSIGNMENT_MIN_TURNS = 20
export const MULTI_STEP_ASSIGNMENT_MAX_TURNS = 30
/** Multi-step evidence work: race bursts, cross-persona matrices, workflow/second-order chains. */
const MULTI_STEP_ASSIGNMENT_RE = /\brace\b|race[_-]|bola|bfla|idor|cross[_-]?persona|multi[_-]?step|second[_-]?order|workflow|business[_-]?logic|\bchain\b|escalat/i
/** Multi-step/race assignments keep the long wall cap (never the 85 s single-step cap). */
export function isMultiStepAssignment(input: {
  title?: string
  hypothesis?: string
  category?: string | null
  skills?: readonly string[]
}): boolean {
  // A det_lead upgrade is one hypothesis, not a multi-step assignment: its prose says "chain it
  // into a higher-impact finding" on every upgrade, and it must keep the 12-turn single-step lane.
  if (/\bdet[_ ]lead\b|\blead upgrade\b/i.test(input.title ?? '')) return false
  const skillText = (input.skills ?? []).join(' ')
  return MULTI_STEP_ASSIGNMENT_RE.test(`${input.title ?? ''} ${input.category ?? ''} ${skillText}`)
}
/** Multi-step chains that cite parent evidence keep the long cap (bounded below). */
export const CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS = 120_000
export const CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS = 180_000
/** Proportional wall-clock bounds for multi-hop `chain` / continuation workers (180s–300s). */
export const MULTI_HOP_CHAIN_MIN_WALL_CLOCK_MS = 180_000
export const MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS = 300_000
export const MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS = 240_000
export const MULTI_HOP_CHAIN_WALL_CLOCK_SHARE = 0.30
/** Settlement buffer for multi-hop `chain` workers (`max(wall - 25s, wall * 0.82)`). */
export const MULTI_HOP_CHAIN_SETTLEMENT_BUFFER_MS = 25_000
export const MULTI_HOP_CHAIN_SETTLEMENT_SHARE = 0.82
/** A provider generation longer than this is recorded as a stall turn (flag threshold). */
export const PROVIDER_STALL_TURN_MS = 10_000
/** Hard-stall abort threshold floor/ceiling (multiple of the observed median turn latency). */
export const PROVIDER_STALL_ABORT_FLOOR_MS = 45_000
export const PROVIDER_STALL_ABORT_CEILING_MS = 75_000
/** Before enough turns have been observed there is no baseline: wait this long before aborting. */
export const PROVIDER_STALL_ABORT_COLD_MS = 90_000
/** Turns needed before the median is trusted for the abort threshold. */
export const PROVIDER_STALL_BASELINE_TURNS = 3
/** One retry only: a stream that stalls twice is treated as an assignment failure. */
export const MAX_PROVIDER_STALL_RETRIES = 1
/**
 * Per-turn no-token watchdog (25–30 s). A turn that has not emitted a single provider token
 * for this long is hung, not slow: abort and requeue instead of waiting out the 45–90 s
 * generation watchdog. The timer resets on every token, so a slow-but-streaming turn is safe.
 */
export const PROVIDER_STALL_NO_TOKEN_MS = 28_000

/** Env override for the no-token watchdog (bounded 5–120 s; the product default is 28 s). */
export function resolveProviderStallNoTokenMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.GUARDIAN_PROVIDER_NO_TOKEN_MS)
  if (!Number.isFinite(raw) || raw <= 0) return PROVIDER_STALL_NO_TOKEN_MS
  return Math.max(5_000, Math.min(120_000, Math.floor(raw)))
}

/**
 * Per-turn watchdog that fires only after `thresholdMs()` of **no token activity**. `noteToken()`
 * re-arms the full threshold, so streaming turns never trip it; a silent provider stream does.
 * Extracted so the reset/fire semantics are unit-testable without a live model.
 */
export class ProviderNoTokenWatchdog {
  private timer?: NodeJS.Timeout
  private lastActivityAt?: number
  private turn = 0
  private readonly thresholdMs: () => number
  private readonly onStall: (info: { turn: number; idleMs: number; thresholdMs: number }) => void
  private readonly clock: () => number
  private readonly setTimer: (fn: () => void, ms: number) => NodeJS.Timeout
  private readonly clearTimer: (timer: NodeJS.Timeout) => void

  constructor(input: {
    thresholdMs: () => number
    onStall: (info: { turn: number; idleMs: number; thresholdMs: number }) => void
    clock?: () => number
    setTimer?: (fn: () => void, ms: number) => NodeJS.Timeout
    clearTimer?: (timer: NodeJS.Timeout) => void
  }) {
    this.thresholdMs = input.thresholdMs
    this.onStall = input.onStall
    this.clock = input.clock ?? (() => Date.now())
    this.setTimer = input.setTimer ?? ((fn, ms) => {
      const timer = setTimeout(fn, ms)
      timer.unref?.()
      return timer
    })
    this.clearTimer = input.clearTimer ?? (timer => clearTimeout(timer))
  }

  get active(): boolean { return this.timer !== undefined }

  /** Start the idle window for `turn`; a fresh request always begins with no token yet. */
  arm(turn: number): void {
    this.clear()
    this.turn = Math.max(0, Math.floor(turn))
    this.lastActivityAt = this.clock()
    this.schedule()
  }

  /** A provider token (text/thinking/tool-call delta) arrived: restart the idle window. */
  noteToken(): void {
    if (this.lastActivityAt === undefined) return
    this.lastActivityAt = this.clock()
    this.schedule()
  }

  clear(): void {
    if (this.timer !== undefined) this.clearTimer(this.timer)
    this.timer = undefined
  }

  private schedule(): void {
    if (this.timer !== undefined) this.clearTimer(this.timer)
    this.timer = undefined
    const threshold = Math.max(0, Math.floor(this.thresholdMs()))
    if (threshold <= 0) return
    this.timer = this.setTimer(() => {
      this.timer = undefined
      const last = this.lastActivityAt
      this.lastActivityAt = undefined
      if (last === undefined) return
      this.onStall({ turn: this.turn, idleMs: Math.max(0, this.clock() - last), thresholdMs: threshold })
    }, threshold)
  }
}

/** Stable fingerprint of persona credential generations: a rotation changes the warm-pool policy. */
export function secretGenerationFingerprint(generations: readonly string[]): string {
  const hash = createHash('sha256')
  for (const entry of [...generations].sort()) {
    hash.update(entry)
    hash.update('\0')
  }
  return hash.digest('hex').slice(0, 16)
}

/** Env override for the single-step wall cap (bounded to 30–120 s so a slot still turns over). */
export function singleStepWallClockMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.GUARDIAN_SINGLE_STEP_WALL_CLOCK_MS)
  if (!Number.isFinite(raw) || raw <= 0) return SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS
  return Math.max(30_000, Math.min(120_000, Math.round(raw)))
}

/**
 * Resolve per-worker wall-clock budget:
 *  - Multi-hop `chain` / continuation steps scale proportionally (`30%` of `runDurationMs`,
 *    clamped to `180s..300s`; default `240s` when `runDurationMs` is unset) so 3–6 hop chains
 *    have enough runway to finish Hops 3–5 and call `ctx.prove_composite(...)`.
 *  - Single-route non-chain steps retain the fast `120s` rotation window so sweeps turn over
 *    quickly and never starve the multi-hop frontier.
 */
export function resolveWorkerWallClockMs(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'category' | 'skills' | 'dependsOnStepIds'>,
  runDurationMs?: number,
  options: { singleStepWallClockMs?: number } = {},
): number {
  if (isMultiHopChainStep(step)) {
    if (typeof runDurationMs === 'number' && Number.isFinite(runDurationMs) && runDurationMs > 0) {
      return Math.min(
        MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS,
        Math.max(MULTI_HOP_CHAIN_MIN_WALL_CLOCK_MS, Math.floor(runDurationMs * MULTI_HOP_CHAIN_WALL_CLOCK_SHARE)),
      )
    }
    return MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS
  }
  return Math.max(
    30_000,
    Math.min(SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS, Math.round(options.singleStepWallClockMs ?? SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)),
  )
}

/**
 * Resolve when the worker settlement nudge fires:
 *  - Multi-hop `chain` steps settle at `max(wallMs - 25s, wallMs * 0.82)` so the worker keeps a
 *    full final turn to emit `ctx.prove_composite(...)`.
 *  - Non-chain steps keep the standard `max(wallMs - 15s, wallMs * 0.80)` schedule.
 */
export function resolveWorkerSettlementMs(wallClockMs: number, isMultiHop: boolean): number {
  const wall = Math.max(1, Math.floor(wallClockMs))
  if (isMultiHop) {
    return Math.max(1, Math.min(wall, Math.max(wall - MULTI_HOP_CHAIN_SETTLEMENT_BUFFER_MS, Math.floor(wall * MULTI_HOP_CHAIN_SETTLEMENT_SHARE))))
  }
  return Math.max(1, Math.min(wall, Math.max(wall - 15_000, Math.floor(wall * 0.8))))
}

export interface AssignmentBudgetInput {
  /** Endpoint templates the step names (see `stepMentionedRoutes`). */
  routes: readonly string[]
  /** Upstream evidence the step cites (`dependsOnFactIds`; the chain signal). */
  parentEvidenceIds: readonly string[]
  dependsOnStepIds: readonly string[]
  /** Race / cross-persona / multi-step evidence work (see `isMultiStepAssignment`). */
  multiStep?: boolean
  /** True when the step is a multi-hop `chain` or hop-continuation step (`isMultiHopChainStep`). */
  multiHopChain?: boolean
  /** Overall run wall-clock duration in ms (scales multi-hop chain budgets proportionally). */
  runDurationMs?: number
  baseMaxTurns: number
  baseWallClockMs: number
  singleStepWallClockMs?: number
}

export interface AssignmentBudget {
  kind: 'single_step' | 'chain'
  maxTurns: number
  wallClockMs: number
  /** Optional wall-clock settlement threshold in ms (multi-hop uses `max(wall - 25s, wall * 0.82)`). */
  wallClockSettlementMs?: number
  /** Turn at which the hard settlement nudge fires (N-2). */
  settlementTurn: number
}

/**
 * Tight budget for a standalone step, long budget for a chain that cites upstream evidence or a
 * multi-step/race assignment. A step that names many routes but cites no evidence is still a
 * standalone assignment: breadth is not depth, and a wall-capped slot is more valuable than a
 * wide, unanchored probe sweep. Race/cross-persona matrices are not breadth — they need 20–30
 * turns to reach the over-count/denied-control step, so they keep the long wall cap too.
 */
export function planAssignmentBudget(input: AssignmentBudgetInput): AssignmentBudget {
  const multiHopChain = input.multiHopChain === true
  const chain = multiHopChain || input.parentEvidenceIds.length > 0 || input.dependsOnStepIds.length > 0
  const multiStep = input.multiStep === true
  const baseTurns = Math.max(4, Math.floor(input.baseMaxTurns))
  const baseWall = Math.max(20_000, Math.round(input.baseWallClockMs))
  if (multiHopChain) {
    const maxTurns = Math.max(20, Math.min(34, baseTurns))
    const wallClockMs = resolveWorkerWallClockMs(
      { title: '', skills: ['multihop-chains'], dependsOnStepIds: [] },
      input.runDurationMs,
    )
    return {
      kind: 'chain',
      maxTurns,
      wallClockMs,
      wallClockSettlementMs: resolveWorkerSettlementMs(wallClockMs, true),
      settlementTurn: Math.max(1, maxTurns - 2),
    }
  }
  if (chain || multiStep) {
    const maxTurns = chain
      ? Math.max(20, Math.min(34, baseTurns))
      : Math.max(MULTI_STEP_ASSIGNMENT_MIN_TURNS, Math.min(MULTI_STEP_ASSIGNMENT_MAX_TURNS, baseTurns))
    return {
      kind: 'chain',
      maxTurns,
      wallClockMs: Math.min(CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS, Math.max(CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS, baseWall)),
      settlementTurn: Math.max(1, maxTurns - 2),
    }
  }
  const maxTurns = Math.max(8, Math.min(SINGLE_STEP_ASSIGNMENT_MAX_TURNS, baseTurns))
  return {
    kind: 'single_step',
    maxTurns,
    wallClockMs: Math.max(30_000, Math.min(input.singleStepWallClockMs ?? SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS, baseWall)),
    settlementTurn: Math.max(1, maxTurns - 2),
  }
}

/** Nearest-rank percentile (0 for an empty sample). */
export function percentile(values: readonly number[], p: number): number {
  if (!values.length) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const rank = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))
  return sorted[rank]!
}

export interface TurnLatencySummary {
  samples: number
  p50: number
  p90: number
  /** Turns whose generation wall exceeded `stallMs`. */
  stallTurns: number
  stallMs: number
}

/** Run-level Phase-B throughput telemetry, mirrored into an event the scorecard can read. */
export interface AssignmentThroughputMetrics {
  reason: string
  assignmentsObserved: number
  assignmentsCompleted: number
  assignmentsPausedAtStop: number
  /** Assignment wall (dispatch → completion/stop) percentiles in ms. */
  assignmentWallP50: number
  assignmentWallP90: number
  assignmentWallSamples: number
  /** Wall p50 over assignments that reached `complete` (excludes wall-capped/failed attempts). */
  completedAssignmentWallP50: number
  completedAssignmentWallSamples: number
  /** Mean turns per observed investigation assignment. */
  turnsPerAssignment: number
  /** Turns saved by earned early exits (`agent.early_exit`) in this run. */
  earlyExitTurnsSaved: number
  providerStallTurns: number
  /** Bounded requeues triggered by the stall watchdog (max one per assignment). */
  providerStallRetries: number
  /** Times the per-turn no-token watchdog fired (28 s of silence). */
  providerStallTimeouts: number
  /** Wall estimated saved versus the previous 45–90 s generation watchdog, summed over timeouts. */
  providerStallWallSavedMs: number
  turnLatencyP50: number
  turnLatencyP90: number
  containersLaunched: number
  containersReused: number
  containerSessions: number
  coldContainerSessions: number
  idleWarmContainers: number
  warmCapacity: number
  /** `containersReused / containerSessions` (0..1); how often a session took a warm container. */
  containerReuseHitRate: number
  /** Warm pools retired because the run/tenant/credential-generation policy changed. */
  warmPoolPolicyRotations: number
  /** Clean bounded worker rotations enforced when an assignment hit its hard `wallClockMs` deadline. */
  wallClockRotations?: number
  /** Aggregated per-route proof-obligation stats forwarded from specialist sessions. */
  proofObligation?: {
    probedRoutes: number
    coveredRoutes: number
    gapRoutes: number
    demandedRoutes: number
    dischargedByGap: number
  }
  /** Aggregated coded proof-gap validation totals forwarded from specialist sessions. */
  gapValidation?: {
    accepted: number
    rejected: number
    byCode: Record<string, { accepted: number; rejected: number }>
  }
}

/** Per-turn generation latencies: p50/p90 + how many turns crossed the stall flag threshold. */
export function summarizeTurnLatencies(samples: readonly number[], stallMs = PROVIDER_STALL_TURN_MS): TurnLatencySummary {
  const clean = samples.filter(ms => Number.isFinite(ms) && ms >= 0)
  return {
    samples: clean.length,
    p50: Math.round(percentile(clean, 50)),
    p90: Math.round(percentile(clean, 90)),
    stallTurns: clean.filter(ms => ms > stallMs).length,
    stallMs,
  }
}

/**
 * Hard-stall abort threshold. With no trusted baseline (fewer than
 * {@link PROVIDER_STALL_BASELINE_TURNS} observed turns) a cold prompt may legitimately take a
 * while, so the watchdog waits the cold floor. After that it scales with the observed median, never
 * below the floor (a slow-but-progressing turn must not be killed) and never above the ceiling.
 */
export function providerStallAbortMs(medianTurnMs: number, samples = PROVIDER_STALL_BASELINE_TURNS): number {
  if (samples < PROVIDER_STALL_BASELINE_TURNS) return PROVIDER_STALL_ABORT_COLD_MS
  const scaled = Number.isFinite(medianTurnMs) && medianTurnMs > 0 ? medianTurnMs * 4 : PROVIDER_STALL_ABORT_FLOOR_MS
  return Math.min(PROVIDER_STALL_ABORT_CEILING_MS, Math.max(PROVIDER_STALL_ABORT_FLOOR_MS, Math.round(scaled)))
}

export function shouldRetryStalledAssignment(attempt: number): boolean {
  return Math.max(0, Math.floor(attempt)) < MAX_PROVIDER_STALL_RETRIES
}

/**
 * Queue drain: a paused/queued assignment whose chain step is still `running` (pause mid-flight,
 * process restart, slot reclaimed) never re-enters dispatch on its own. Reset the step to `ready`
 * and retire the dead assignment so the freed slot is used by the scheduler instead of the step
 * starving forever. Returns the number of recovered steps.
 */
export function requeueInterruptedAssignments(
  storage: Pick<Store, 'workerList' | 'listChainSteps' | 'updateWorker' | 'updateChainStep' | 'event' | 'transaction'>,
  run: Pick<Run, 'id' | 'goalRevision'>,
): number {
  const steps = storage.listChainSteps(run.id, run.goalRevision)
  const stepById = new Map(steps.map(step => [step.id, step]))
  let recovered = 0
  for (const worker of storage.workerList(run.id)) {
    if (worker.phase !== 'investigation' || !worker.stepId) continue
    if (worker.status !== 'paused' && worker.status !== 'queued') continue
    const step = stepById.get(worker.stepId)
    if (!step || (step.status !== 'running' && step.status !== 'ready')) continue
    storage.transaction(() => {
      storage.updateWorker(worker.id, {
        status: 'canceled',
        outcome: 'Requeued after interruption; slot reclaimed by the queue drain.',
        lease: null,
        leaseExpiresAt: null,
      })
      storage.updateChainStep(step.id, { status: 'ready', assignedWorkerId: null })
      storage.event(run.id, 'worker.requeued', `${step.title} requeued after pause; slot returned to the scheduler.`, {
        assignmentId: worker.id,
        stepId: step.id,
        previousStatus: worker.status,
        attempt: worker.attempt,
      })
    }, { behavior: 'immediate' })
    recovered += 1
  }
  return recovered
}

export function applyCrownJewelStepBudget<T extends { title: string; priority: number; origins: string[] }>(
  candidates: readonly T[],
  hostTiers: Record<string, HostTier>,
  existingSteps: readonly Pick<ChainStep, 'title' | 'sourceOrigins' | 'status'>[],
  maxNewSteps: number,
): T[] {
  if (maxNewSteps <= 0 || !candidates.length) return []
  const hasCrownJewel = Object.values(hostTiers).some(t => t === 'crown_jewel')
  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))

  const isPureStatic = (origins: readonly string[]) =>
    origins.length > 0 && origins.every(o => (hostTiers[o] ?? classifyHostTier(o)) === 'low_value_static')
  const hasCrownOrigin = (origins: readonly string[]) =>
    origins.some(o => (hostTiers[o] ?? classifyHostTier(o)) === 'crown_jewel')

  const staticStepsByOrigin = new Map<string, number>()
  let existingActiveSteps = 0
  let existingStaticSteps = 0
  for (const step of existingSteps) {
    if (step.status === 'canceled' || step.status === 'tainted') continue
    existingActiveSteps += 1
    if (isPureStatic(step.sourceOrigins)) {
      existingStaticSteps += 1
      for (const o of step.sourceOrigins) {
        staticStepsByOrigin.set(o, (staticStepsByOrigin.get(o) ?? 0) + 1)
      }
    }
  }

  const normalized = candidates
    .filter(step => step.origins.length > 0 && !existingTitles.has(step.title.trim().toLowerCase()))
    .map(step => {
      if (!hasCrownJewel) return { ...step }
      if (isPureStatic(step.origins)) {
        return { ...step, priority: Math.min(step.priority, 35) }
      }
      if (hasCrownOrigin(step.origins)) {
        return { ...step, priority: Math.min(100, Math.max(75, step.priority + 10)) }
      }
      return { ...step }
    })

  // Sort crown-jewel first, then standard, then low-value static; tie-break by priority descending
  normalized.sort((a, b) => {
    const tierA = hasCrownOrigin(a.origins) ? 0 : isPureStatic(a.origins) ? 2 : 1
    const tierB = hasCrownOrigin(b.origins) ? 0 : isPureStatic(b.origins) ? 2 : 1
    return tierA - tierB || b.priority - a.priority
  })

  if (!hasCrownJewel) {
    const out: T[] = []
    const seenTitles = new Set(existingTitles)
    for (const step of normalized) {
      if (out.length >= maxNewSteps) break
      const key = step.title.trim().toLowerCase()
      if (seenTitles.has(key)) continue
      seenTitles.add(key)
      out.push(step)
    }
    return out
  }

  const crownOrStandardPool = normalized.filter(s => !isPureStatic(s.origins))
  const staticPool = normalized.filter(s => isPureStatic(s.origins))

  const selected: T[] = []
  const seenTitles = new Set(existingTitles)

  // Target ~80% crown-jewel/standard allocation when crown-jewel hosts are present
  const projectedTotal = existingActiveSteps + Math.min(maxNewSteps, normalized.length)
  const maxTotalStaticSteps = Math.max(1, Math.floor(projectedTotal * 0.2))
  const crownTargetSlots = crownOrStandardPool.length > 0
    ? Math.max(1, Math.ceil(maxNewSteps * 0.8))
    : 0

  for (const step of crownOrStandardPool) {
    if (selected.length >= maxNewSteps) break
    const key = step.title.trim().toLowerCase()
    if (seenTitles.has(key)) continue
    seenTitles.add(key)
    selected.push(step)
  }

  let staticAdded = 0
  for (const step of staticPool) {
    if (selected.length >= maxNewSteps) break
    // Cap static marketing hosts to 1 fast step per origin and <= ~20% overall share
    if (existingStaticSteps + staticAdded >= maxTotalStaticSteps) break
    if (step.origins.some(o => (staticStepsByOrigin.get(o) ?? 0) >= 1)) continue
    // Ensure we don't crowd out reserved crown-jewel capacity
    if (crownTargetSlots > 0 && selected.length < maxNewSteps && staticAdded >= Math.max(1, maxNewSteps - crownTargetSlots) && crownOrStandardPool.length >= crownTargetSlots) {
      break
    }
    const key = step.title.trim().toLowerCase()
    if (seenTitles.has(key)) continue
    seenTitles.add(key)
    selected.push(step)
    staticAdded += 1
    for (const o of step.origins) {
      staticStepsByOrigin.set(o, (staticStepsByOrigin.get(o) ?? 0) + 1)
    }
  }

  return selected
}

function sinkCategoryAndSkills(sinkKind: string): { category: OwaspCategory; skills: string[] } {
  switch (sinkKind) {
    case 'server_action':
    case 'api_route':
      return { category: 'broken-access-control', skills: ['source-first-audit', 'bola-idor-race', 'false-positive-elimination'] }
    case 'webhook':
    case 'auth_config':
      return { category: 'auth-identity', skills: ['source-first-audit', 'false-positive-elimination'] }
    case 'outbound_fetch':
    case 'redirect':
      return { category: 'ssrf-redirects', skills: ['source-first-audit', 'oob-ssrf-browser-chain', 'false-positive-elimination'] }
    case 'postmessage_iframe':
      return { category: 'cors-client-side', skills: ['cross-host-chaining', 'oob-ssrf-browser-chain'] }
    case 'upload_storage':
      return { category: 'upload-storage', skills: ['source-first-audit', 'false-positive-elimination'] }
    case 'db_query':
      return { category: 'injection-input', skills: ['source-first-audit', 'false-positive-elimination'] }
    default:
      return { category: 'broken-access-control', skills: ['source-first-audit', 'false-positive-elimination'] }
  }
}

const CODE_AUDIT_DEFECT_SIGNAL_RE = /\b(?:missing|absent|omits?|lacks?|without|bypass(?:es|able)?|unauthenticated|unverified|untrusted|forged?|spoof(?:ed|ing)?|broken|weak|improper|unsafe|inject(?:ion|able)?|idor|bola|bfla|ssrf|csrf|xss|sqli|rce|desync|smuggl(?:ing|ed)?|asymmetry|asymmetric|mismatch|inconsistent|cross[- ]?tenant|privilege\s+escalation|escalat(?:e|ion)|unauthorized|state[- ]?machine|creator\/approver|self[- ]?approv|replay|race\s+condition|toctou|mass\s+assignment|leak(?:s|ed|ing)?|expos(?:e|es|ed|ure)|plaintext|in[- ]?log|log\s+sink|cache\s+poison|trust[- ]?boundary|secret|token|signing\s+key|hmac|jwt|credential|api[- ]?key|private[- ]?key)\b/i
const CODE_AUDIT_BOUNDARY_SINK_RE = /\b(?:cross[- ]?service|multi[- ]?service|multi[- ]?hop|downstream|upstream|outbound[- ]?fetch|async[- ]?worker|background\s+worker|queue\s+consumer|webhook|graphql|websocket|sse|stream|proxy|edge\s+gateway|internal\s+service|x-forwarded|forwarded[- ]?header|cache[- ]?key|storage\s+sink|export\s+sink|server\s+action)\b/i
const CODE_AUDIT_NON_DEFECT_SUBKINDS = new Set(['hop_checkpoint', 'chain_hop'])

/**
 * Identify non-tainted facts produced during Source-First Code Audit that describe a concrete
 * security defect, authz asymmetry, trust-boundary leak, secret/token exposure, or multi-service
 * sink — even when recorded under a general fact kind rather than `code_audit_suspect`.
 */
export function isPromotableCodeAuditFact(fact: {
  kind: string
  summary: string
  data: unknown
  tainted?: boolean
}): boolean {
  if (fact.tainted) return false
  const kind = String(fact.kind)
  const data = (fact.data && typeof fact.data === 'object' ? fact.data : {}) as Record<string, unknown>
  if (data.source === 'deterministic_engine') return false
  const subkind = typeof data.subkind === 'string' ? data.subkind : ''
  if (CODE_AUDIT_NON_DEFECT_SUBKINDS.has(subkind)) return false
  if (kind === 'code_audit_suspect' || subkind === 'code_audit_suspect') return true
  if (kind === 'tech_fingerprint') return false

  const dataPieces: string[] = []
  for (const key of [
    'hypothesis', 'defect', 'vulnerability', 'authCheck', 'ownershipCheck', 'sinkKind',
    'routeOrAction', 'endpoint', 'path', 'file', 'impact', 'trustBoundary', 'asymmetry',
    'category', 'title', 'detail', 'notes', 'summary',
  ]) {
    const val = data[key]
    if (typeof val === 'string' && val.trim()) dataPieces.push(val.trim())
  }
  const combined = `${fact.summary} ${dataPieces.join(' ')}`.slice(0, 2400)
  if (CODE_AUDIT_DEFECT_SIGNAL_RE.test(combined)) return true
  if (CODE_AUDIT_BOUNDARY_SINK_RE.test(combined)) {
    const hasConcreteAnchor = Boolean(
      (typeof data.file === 'string' && data.file.trim())
      || (typeof data.routeOrAction === 'string' && data.routeOrAction.trim())
      || (typeof data.endpoint === 'string' && data.endpoint.trim())
      || (typeof data.sinkKind === 'string' && data.sinkKind.trim())
      || /\/[A-Za-z0-9_\-.:{}[\]]+\/[A-Za-z0-9_\-.:{}[\]]+/.test(combined)
      || /\b[A-Za-z0-9_-]+\.(?:ts|tsx|js|jsx|py|go|java|rb):\d+\b/.test(combined),
    )
    if (hasConcreteAnchor) return true
  }
  return false
}

/**
 * Deduplicate promotable code-audit facts, keeping explicit `code_audit_suspect` facts ahead of
 * general cross-cutting facts and collapsing duplicates by `(repo, file, line, sinkKind)`,
 * normalized endpoint+sink, or normalized summary prefix.
 */
export function dedupePromotableCodeAuditFacts<T extends { id: string; kind: string; summary: string; data: unknown }>(
  facts: readonly T[],
): T[] {
  const ordered = [...facts].sort((a, b) => {
    const aExplicit = String(a.kind) === 'code_audit_suspect' || (a.data as Record<string, unknown> | undefined)?.subkind === 'code_audit_suspect'
    const bExplicit = String(b.kind) === 'code_audit_suspect' || (b.data as Record<string, unknown> | undefined)?.subkind === 'code_audit_suspect'
    return Number(bExplicit) - Number(aExplicit)
  })
  const byLocation = dedupeCodeAuditSuspects(ordered)
  const seenKeys = new Set<string>()
  const out: T[] = []
  for (const fact of byLocation) {
    const data = (fact.data && typeof fact.data === 'object' ? fact.data : {}) as Record<string, unknown>
    const file = typeof data.file === 'string' ? data.file.trim().toLowerCase() : ''
    const line = typeof data.line === 'number' && Number.isFinite(data.line) ? String(data.line) : ''
    const sink = typeof data.sinkKind === 'string' ? data.sinkKind.trim().toLowerCase() : ''
    let key: string
    if (file) {
      // Preserve distinct source locations (matching `codeAuditSuspectLocationKey`), while collapsing
      // duplicate explicit suspects and plain notes that cite the exact same file:line:sink.
      key = `loc:${file}:${line}:${sink}`
    } else {
      const endpoint = typeof data.endpoint === 'string' && data.endpoint.trim()
        ? normalizeEndpointTemplate(data.endpoint.trim())
        : typeof data.routeOrAction === 'string' && data.routeOrAction.trim()
          ? normalizeEndpointTemplate(data.routeOrAction.trim())
          : ''
      const summaryKey = fact.summary.trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 96)
      key = endpoint && sink
        ? `ep:${endpoint}:${sink}`
        : summaryKey
          ? `sum:${summaryKey}`
          : `id:${fact.id}`
    }
    if (seenKeys.has(key)) continue
    seenKeys.add(key)
    out.push(fact)
  }
  return out
}

function inferSinkKindFromFactText(text: string): string {
  const lower = text.toLowerCase()
  if (/\bwebhook\b|hmac|x-signature|x-hub-signature/.test(lower)) return 'webhook'
  if (/\boutbound[- ]?fetch\b|\bssrf\b|internal\s+service|proxy|redirect/.test(lower)) return 'outbound_fetch'
  if (/\bjwt\b|\boauth\b|\boidc\b|signing\s+key|auth[-_ ]?config|token\s+(?:mint|forg|leak|expos)/.test(lower)) return 'auth_config'
  if (/\bupload\b|\bstorage\b|\bbucket\b|\bexport\b/.test(lower)) return 'upload_storage'
  if (/\bsql\b|db[._]query|raw\s+query|injection/.test(lower)) return 'db_query'
  return 'api_route'
}

export function convertCodeAuditSuspectsToChainSteps(
  storage: Store,
  run: Run,
  suspects: readonly Fact[],
  hostTiers?: Record<string, HostTier>,
  options: { maxSteps?: number; promoteMultiHop?: boolean } = {},
): ChainStep[] {
  const approvedOrigins = new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
  const existingSteps = storage.listChainSteps(run.id, run.goalRevision)
  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
  const coveredFactIds = new Set(existingSteps.flatMap(s => s.dependsOnFactIds))
  const created: ChainStep[] = []
  let totalSteps = existingSteps.length
  const maxSteps = options.maxSteps !== undefined ? Math.max(0, Math.floor(options.maxSteps)) : Number.POSITIVE_INFINITY

  for (const fact of dedupePromotableCodeAuditFacts(suspects)) {
    if (created.length >= maxSteps) break
    if (totalSteps >= hardChainStepsCeiling) break
    if (fact.tainted || !approvedOrigins.has(fact.origin)) continue
    if (coveredFactIds.has(fact.id)) continue
    const asset = run.candidates.find(c => c.origin === fact.origin && run.approved.includes(c.id))
    if (!asset) continue

    const data = fact.data as Partial<CodeAuditSuspectData> & Record<string, unknown>
    const routeOrAction = typeof data.routeOrAction === 'string' && data.routeOrAction.trim()
      ? data.routeOrAction.trim()
      : ''
    const summaryRoutes = templatesMentionedInText(fact.summary)
    const endpointHint = typeof data.endpoint === 'string' && data.endpoint.trim()
      ? data.endpoint.trim()
      : routeOrAction || summaryRoutes[0] || ''
    const fileLoc = typeof data.file === 'string' && data.file.trim()
      ? `${data.file.trim()}${typeof data.line === 'number' ? `:${data.line}` : ''}`
      : ''
    const hypothesisBody = typeof data.hypothesis === 'string' && data.hypothesis.trim()
      ? data.hypothesis.trim()
      : fact.summary
    const sinkKind = typeof data.sinkKind === 'string' && data.sinkKind.trim()
      ? data.sinkKind.trim()
      : inferSinkKindFromFactText(`${fact.summary} ${hypothesisBody} ${endpointHint}`)
    const authCheck = typeof data.authCheck === 'string' ? data.authCheck : 'unknown'
    const ownershipCheck = typeof data.ownershipCheck === 'string' ? data.ownershipCheck : 'unknown'

    const host = new URL(fact.origin).hostname
    const title = routeOrAction
      ? `Source audit verify · ${routeOrAction.slice(0, 90)} (${host})`
      : `Source audit verify · ${fact.summary.slice(0, 80)} (${host})`
    if (existingTitles.has(title.toLowerCase())) continue

    const mapped = sinkCategoryAndSkills(sinkKind)
    const explicitCategory = typeof data.category === 'string' && data.category.trim()
      ? data.category.trim()
      : mapped.category
    const specialistProfile = routeStepToSpecialist({
      title: `${fact.summary} ${title}`,
      hypothesis: hypothesisBody,
      category: explicitCategory,
      skills: mapped.skills,
      endpoint: endpointHint,
      sinkKind,
    })
    const stepSkills = options.promoteMultiHop
      ? [...new Set([...mapped.skills, 'multihop-chains', 'chain-primitives'])]
      : mapped.skills
    const missingAuthOrOwner = /missing|none|weak|bypass|absent|unverified|no |asymmetry|leak|expos|untrusted|forged|spoof/i.test(
      `${authCheck} ${ownershipCheck} ${fact.summary}`,
    )
    const isCrown = (hostTiers?.[fact.origin] ?? classifyHostTier(fact.origin)) === 'crown_jewel'
    const priority = missingAuthOrOwner ? (isCrown ? 96 : 92) : (isCrown ? 90 : 85)

    const hypothesis = [
      `Source-First Code Audit suspect${fileLoc ? ` at ${fileLoc}` : ''}${endpointHint ? ` targeting ${endpointHint}` : ''}.`,
      `Auth check: ${authCheck}; Ownership check: ${ownershipCheck}; Sink: ${sinkKind}.`,
      hypothesisBody,
      'Verify live reachability with negative control + differential probe (and cross-persona BOLA check if Tier >= 2) and submit a DeclarativeReplaySpec if confirmed.',
    ].join(' ')

    const step = storage.addChainStep(run, {
      title,
      hypothesis,
      category: explicitCategory,
      priority,
      targetAssetIds: [asset.id],
      skills: stepSkills,
      dependsOnFactIds: [fact.id],
      sourceOrigins: [fact.origin],
      specialistProfile,
    })
    existingTitles.add(title.toLowerCase())
    coveredFactIds.add(fact.id)
    created.push(step)
    totalSteps += 1
  }

  return created
}

export interface BolaConsumerVariant {
  method: 'GET' | 'PUT' | 'PATCH' | 'DELETE'
  endpoint: string
  /** Reversible write variants are benign; DELETE is only replayable at Tier 3 / local-lab. */
  destructive: boolean
  requiresTier: 1 | 2 | 3
}

export interface BolaTestQueueItem extends PersonaResourceQueueItem {
  resourceKey: string
  variants: BolaConsumerVariant[]
  source: 'fact' | 'sample'
}

/**
 * Instantiate consumer item endpoints (`GET/PUT/PATCH/DELETE /…/:resourceId`) from a producer path.
 * Observed concrete item URLs are preserved; collection URLs get the harvested id appended.
 */
export function instantiateConsumerEndpoints(
  endpoint: string,
  resourceId: string,
  method = 'GET',
): BolaConsumerVariant[] {
  const bare = (endpoint.split('?')[0] || '/').replace(/\/+$/, '') || '/'
  let itemEndpoint = bare
  const last = bare.split('/').filter(Boolean).at(-1) ?? ''
  if (!/:[A-Za-z_][A-Za-z0-9_-]*|\{[A-Za-z0-9_-]+\}|\[[A-Za-z0-9_-]+\]/.test(bare)) {
    if (!isOpaqueResourceId(last)) {
      itemEndpoint = `${bare === '/' ? '' : bare}/${encodeURIComponent(resourceId)}`
    }
  } else {
    itemEndpoint = bare.replace(
      /:[A-Za-z_][A-Za-z0-9_-]*|\{[A-Za-z0-9_-]+\}|\[[A-Za-z0-9_-]+\]/,
      encodeURIComponent(resourceId),
    )
  }
  const itemTemplate = normalizeEndpointTemplate(itemEndpoint)
  const hasPlaceholder = /:[A-Za-z_][A-Za-z0-9_-]*/.test(itemTemplate)
  const concrete = hasPlaceholder
    ? itemTemplate.replace(/:[A-Za-z_][A-Za-z0-9_-]*/, encodeURIComponent(resourceId))
    : itemEndpoint
  const methods: Array<BolaConsumerVariant['method']> = ['GET', 'PUT', 'PATCH', 'DELETE']
  const variants = methods.map(variant => ({
    method: variant,
    endpoint: concrete,
    destructive: variant === 'DELETE',
    requiresTier: (variant === 'DELETE' ? 3 : variant === 'GET' ? 2 : 2) as 1 | 2 | 3,
  }))
  // Keep the original method first so existing single-method consumers remain deterministic.
  const requested = method.toUpperCase()
  return variants.sort((a, b) => Number(b.method === requested) - Number(a.method === requested))
}

function testPersonasForOwner(
  ownerPersona: string,
  origin: string,
  personas: readonly { handle: string; originAllowlist: readonly string[] }[],
): string[] {
  const eligible = personas
    .filter(p => p.originAllowlist.includes(origin))
    .map(p => p.handle)
  if (ownerPersona === 'anonymous') return [...new Set(eligible)]
  return [...new Set([...eligible.filter(handle => handle !== ownerPersona), 'anonymous'])]
}

export function buildBolaTestQueue(
  facts: readonly Fact[],
  personas: readonly { handle: string; originAllowlist: readonly string[] }[],
  approvedOrigins: ReadonlySet<string>,
  samples: readonly ResourceSampleRow[] = [],
): BolaTestQueueItem[] {
  if (personas.length < 2) return []
  const queue: BolaTestQueueItem[] = []
  const seen = new Set<string>()
  const perTypeCount = new Map<string, number>()
  const perTypeBudget = 8
  const overallBudget = 80
  const enqueue = (item: Omit<BolaTestQueueItem, 'variants' | 'testAsPersonas'>) => {
    if (queue.length >= overallBudget) return
    const key = `${item.origin}|${item.ownerPersona}|${item.endpoint}|${item.resourceId}|${item.method ?? 'GET'}`
    if (seen.has(key)) return
    const typeKey = `${item.origin}|${item.resourceKey}`
    const used = perTypeCount.get(typeKey) ?? 0
    if (used >= perTypeBudget) return
    if (!item.resourceId || item.resourceId === '[redacted]') return
    const testAsPersonas = testPersonasForOwner(item.ownerPersona, item.origin, personas)
    if (!testAsPersonas.length) return
    seen.add(key)
    perTypeCount.set(typeKey, used + 1)
    queue.push({
      ...item,
      testAsPersonas,
      variants: instantiateConsumerEndpoints(item.endpoint, item.resourceId, item.method ?? 'GET'),
    })
  }

  for (const fact of facts) {
    if (fact.tainted || !approvedOrigins.has(fact.origin)) continue
    const subkind = typeof fact.data?.subkind === 'string' ? fact.data.subkind : ''
    if (subkind !== 'persona_resource' && fact.kind !== 'object_ref') continue

    const data = fact.data ?? {}
    const ownerPersona = typeof data.ownerPersona === 'string' ? data.ownerPersona
      : typeof data.persona === 'string' ? data.persona
        : typeof data.personaHandle === 'string' ? data.personaHandle : ''
    const resourceId = typeof data.resourceId === 'string' ? data.resourceId
      : typeof data.id === 'string' ? data.id
        : typeof data.resourceId === 'number' ? String(data.resourceId) : ''
    const endpoint = typeof data.endpoint === 'string' ? data.endpoint
      : typeof data.path === 'string' ? data.path
        : typeof data.pathAndQuery === 'string' ? data.pathAndQuery : ''
    if (!ownerPersona || !resourceId || !endpoint) continue
    const method = typeof data.method === 'string' ? data.method.toUpperCase() : 'GET'
    const resourceKey = typeof data.field === 'string' ? data.field.replace(/^path:/, '') : 'id'
    enqueue({
      factId: fact.id,
      origin: fact.origin,
      ownerPersona,
      resourceKey,
      resourceId,
      endpoint,
      method,
      summary: fact.summary,
      source: 'fact',
    })
  }

  for (const sample of samples) {
    if (!approvedOrigins.has(sample.origin)) continue
    enqueue({
      origin: sample.origin,
      ownerPersona: sample.ownerPersona,
      resourceKey: sample.resourceKey,
      resourceId: sample.resourceId,
      endpoint: sample.endpoint,
      method: sample.method,
      summary: `${sample.authenticated ? 'Authenticated' : 'Unauthenticated'} sample ${sample.resourceKey}=${sample.resourceId} observed at ${sample.method} ${sample.endpoint}.`,
      source: 'sample',
    })
  }

  // Prioritize authenticated owners and higher-risk item routes deterministically.
  return queue.sort((a, b) =>
    Number(b.ownerPersona !== 'anonymous') - Number(a.ownerPersona !== 'anonymous') ||
    Number(/:(?:id|uuid)|[0-9]{1,}/i.test(b.endpoint)) - Number(/:(?:id|uuid)|[0-9]{1,}/i.test(a.endpoint)) ||
    a.resourceKey.localeCompare(b.resourceKey),
  ).slice(0, overallBudget)
}

const DET_LEAD_CATEGORY_MAP: Record<string, string> = {
  authz_matrix: 'broken-access-control', graphql_audit: 'broken-access-control',
  sqli_boolean: 'injection', sqli_time_diff: 'injection', sql_boolean_diff: 'injection', sql_time_diff: 'injection', ssti_math: 'injection',
  xss_context: 'xss', stored_xss: 'xss', ssrf_canary: 'ssrf', xxe_canary: 'xxe',
  command_injection: 'command-injection', path_traversal_benign: 'path-traversal',
  workflow_invariant: 'business-logic', open_redirect_differential: 'open-redirect',
  csrf_state_change: 'csrf', mass_assignment: 'mass-assignment', cache_poison_deception: 'misconfig-exposure',
}

export function detLeadCategory(probeClass: string): string {
  return DET_LEAD_CATEGORY_MAP[probeClass] ?? 'misconfig-exposure'
}

const CONFIRMED_CATEGORY_FAMILY_RULES: ReadonlyArray<[RegExp, string]> = [
  [/access-control|authz|bola|bfla|idor/, 'authz'], [/injection/, 'sqli'], [/xss/, 'xss'],
  [/ssrf/, 'ssrf'], [/xxe/, 'xxe'], [/traversal/, 'traversal'], [/redirect/, 'redirect'],
  [/mass|overpost/, 'mass_assign'], [/csrf/, 'csrf'], [/logic|business/, 'logic'],
  [/disclos|exposure/, 'disclosure'], [/cmdi|command/, 'cmdi'],
]

/** v6 Phase 1: map a persisted finding category onto the engine family namespace. */
export function confirmedCategoryFamily(category: string): string {
  const raw = category.toLowerCase()
  return CONFIRMED_CATEGORY_FAMILY_RULES.find(([re]) => re.test(raw))?.[1] ?? intentFamily(category)
}

const DET_LEAD_SKILL_MAP: Record<string, string> = {
  authz_matrix: 'bola-idor-race', graphql_audit: 'bola-idor-race',
  sqli_boolean: 'injection-sqli-nosqli', sqli_time_diff: 'injection-sqli-nosqli',
  sql_boolean_diff: 'injection-sqli-nosqli', sql_time_diff: 'injection-sqli-nosqli',
  ssrf_canary: 'oob-ssrf-browser-chain', xss_context: 'client-side-xss-postmessage',
  stored_xss: 'client-side-xss-postmessage', workflow_invariant: 'business-logic-chains',
}

/** v6 Phase 1: the skills a det_lead upgrade assignment should pre-inject. */
export function detLeadSkills(probeClass: string): string[] {
  const primary = DET_LEAD_SKILL_MAP[probeClass]
  return primary ? [primary, 'false-positive-elimination'] : ['false-positive-elimination']
}
