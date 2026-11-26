import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { cpus as osCpus, freemem as osFreemem } from 'node:os'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import {
  defaultWorkerConcurrency,
  maxWorkerConcurrency,
  type Candidate,
  type OwaspCategory,
  type ThreatModelSummary,
} from '../domain.ts'
import { matchesMultiHopStepSignal, wallClockSettlementMs } from './agent-prompts.ts'
import {
  classifyHostTier,
  routeStepToSpecialist,
  type CodeAuditSuspectData,
  type HostTier,
  type PersonaResourceQueueItem,
  type WorkerToolHandlers,
} from './agent-session.ts'
import type { AgentTrace } from './agent-trace.ts'
import type { Grant } from './broker.ts'
import {
  CapabilityLedger,
  type NegativeEdge as LedgerNegativeEdge,
  type NegativeEdgeReason as LedgerNegativeEdgeReason,
} from './capability-ledger.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import type { DerivedCapabilityVault } from './derived-custody.ts'
import { hasDynamicIdSegment, identifierFormsForRoute, intentFamily } from './deterministic-engine.ts'
import type { ExecCoordinatorTask } from './exec-exchange.ts'
import {
  FrontierScheduler,
  MAX_CHECKPOINT_BRIEF_BYTES,
  buildHopCheckpointBrief,
  computeBranchEvi,
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
  planCompositeWorkflows,
  type ChainHop,
  type ChainHypothesis,
  type CompositeWorkflowNode,
  type CompositeWorkflowRole,
  type CoordinatorFact,
  type DispatchPlan,
  type DispatchStepInput,
  type GraphCoordinator,
  type PlannedCompositeWorkflow,
  type SchedulerDecision,
} from './graph-coordinator.ts'
import type { LabTargetHandle } from './lab-runner.ts'
import { selectRankedProbeTargets, type Phase0ProbePlanSummary } from './probe-plan.ts'
import { findings } from './schema.ts'
import { dedupeCodeAuditSuspects } from './semantic-audit.ts'
import {
  isOpaqueResourceId,
  type ChainStep,
  type EndpointRow,
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
    ?? positiveRequestBudget(env.KOVO_FLOOR_REQUEST_BUDGET)
  const agent = positiveRequestBudget(options.agentRequestBudget)
    ?? positiveRequestBudget(env.KOVO_AGENT_REQUEST_BUDGET)
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
  const raw = env.KOVO_DETERMINISTIC_SWEEP?.trim().toLowerCase()
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

export type LlmPlannerGateReason =
  | 'milestone_forced'
  | 'queue_draining'
  | 'milestone_confirmed_finding'
  | 'milestone_cross_origin_capability'
  | 'milestone_open_proof_gap'
  | 'round_one_bootstrap'
  | 'queue_below_buffer'
  | 'queue_saturated_deferred'

export interface LlmPlannerGateInput {
  roundNo: number
  readyStepCount: number
  activeWorkerCount: number
  waveBufferTarget: number
  /** Confirmed findings added since the previous planner round. */
  newConfirmedFindings?: number
  /** Newly sealed cross-origin / causal capabilities since the previous planner round. */
  newCrossOriginCapabilities?: number
  /** Unresolved proof gaps requiring coordinator attention. */
  openProofGaps?: number
  /** True when queue is drained or pre-stop review is required. */
  queueEmptyOrDraining?: boolean
  /** Explicit high-signal milestone override. */
  forceMilestone?: boolean
}

export interface LlmPlannerGateDecision {
  invokeLlm: boolean
  reason: LlmPlannerGateReason
}

/**
 * Pure gate preventing redundant 10-turn LLM planner storms when the dispatch queue is already
 * saturated (`readyStepCount >= waveBufferTarget`). Cheap deterministic synthesis (Tier-A,
 * det-leads, `dispatchChainRound`, BOLA matrix, second-order surfaces) still runs immediately;
 * the LLM session runs only when queue depth drops below buffer or a high-signal milestone fires.
 */
export function shouldInvokeLlmPlanner(input: LlmPlannerGateInput): LlmPlannerGateDecision {
  const ready = Math.max(0, Math.floor(input.readyStepCount))
  const active = Math.max(0, Math.floor(input.activeWorkerCount))
  const target = Math.max(1, Math.floor(input.waveBufferTarget))
  if (input.forceMilestone === true) return { invokeLlm: true, reason: 'milestone_forced' }
  if (input.queueEmptyOrDraining === true || (ready === 0 && active === 0)) {
    return { invokeLlm: true, reason: 'queue_draining' }
  }
  if ((input.newConfirmedFindings ?? 0) > 0) {
    return { invokeLlm: true, reason: 'milestone_confirmed_finding' }
  }
  if ((input.newCrossOriginCapabilities ?? 0) > 0) {
    return { invokeLlm: true, reason: 'milestone_cross_origin_capability' }
  }
  if (ready < target) {
    return { invokeLlm: true, reason: input.roundNo <= 1 ? 'round_one_bootstrap' : 'queue_below_buffer' }
  }
  if ((input.openProofGaps ?? 0) > 0 && ready < target * 2) {
    return { invokeLlm: true, reason: 'milestone_open_proof_gap' }
  }
  return { invokeLlm: false, reason: 'queue_saturated_deferred' }
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

/** Map chained hypotheses onto validated dispatch inputs with typed `ChainHop`, EVI & v8 checkpoint briefs. */
export function chainHypothesisDispatchSteps(hypotheses: readonly ChainHypothesis[]): DispatchStepInput[] {
  return hypotheses.map(hypothesis => {
    const eviTag = typeof hypothesis.evi === 'number' && Number.isFinite(hypothesis.evi) && hypothesis.evi > 0
      ? `[lane=chain] [evi=${hypothesis.evi.toFixed(2)}] `
      : '[lane=chain] '
    const hopBlock = hypothesis.chainHops?.length
      ? ` [chain_hops=${formatChainHopsBrief(hypothesis.chainHops, 420)}]`
      : ''
    const baseText = `${eviTag}${hypothesis.title} — ${hypothesis.rationale}`
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

/** Dynamic AIMD Phase-B worker concurrency defaults & bounds. */
export const PHASE_B_AIMD_MAX_CEILING = 12
export const PHASE_B_AIMD_WARM_START = 6
export const PHASE_B_AIMD_MIN_FLOOR = 2
export const PHASE_B_AIMD_INCREASE_STEP = 2
export const PHASE_B_AIMD_CLEAN_WINDOW_MS = 18_000
export const PHASE_B_AIMD_CLEAN_COMPLETIONS_THRESHOLD = 3
export const PHASE_B_AIMD_USD_PER_SLOT = 0.15
export const PHASE_B_AIMD_RAM_GB_PER_SLOT = 0.75
export const PHASE_B_AIMD_CPU_FRACTION = 0.75
export const PHASE_B_AIMD_SPAWN_LATENCY_WARN_MS = 8_000

export type PhaseBPressureKind =
  | 'llm_429'
  | 'target_429'
  | 'target_503'
  | 'target_timeout'
  | 'container_spawn_error'
  | 'container_pressure'

/** Read Linux `/proc/meminfo` `MemAvailable` when present (more accurate than `os.freemem()`). */
export function detectHostAvailableMemoryBytes(): number {
  try {
    const meminfo = readFileSync('/proc/meminfo', 'utf8')
    const match = /^MemAvailable:\s+(\d+)\s+kB$/m.exec(meminfo)
    if (match) {
      const kb = Number(match[1])
      if (Number.isFinite(kb) && kb > 0) return kb * 1024
    }
  } catch { /* non-Linux or restricted procfs: fall back to os.freemem() */ }
  return osFreemem()
}

/** Parse explicit operator env override (`KOVO_PHASE_B_CONCURRENCY` or `KOVO_WORKER_CONCURRENCY`). */
export function parseEnvPhaseBConcurrencyOverride(env: NodeJS.ProcessEnv = process.env): number | undefined {
  const raw = env.KOVO_PHASE_B_CONCURRENCY ?? env.KOVO_WORKER_CONCURRENCY
  if (raw === undefined || raw.trim() === '') return undefined
  const parsed = Number(raw.trim())
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined
  return Math.max(1, Math.min(maxWorkerConcurrency, Math.floor(parsed)))
}

/** Auto-compute host Phase-B concurrency ceiling from CPU cores and available RAM (~0.75 GiB/slot). */
export function computeHostPhaseBConcurrencyCap(input: {
  cpuCount?: number
  availMemBytes?: number
  ceiling?: number
} = {}): number {
  const hardCeiling = Math.max(
    1,
    Math.min(maxWorkerConcurrency, Math.floor(input.ceiling ?? PHASE_B_AIMD_MAX_CEILING)),
  )
  const cpuCount = Math.max(1, Math.floor(input.cpuCount ?? osCpus().length))
  const availBytes = Math.max(0, input.availMemBytes ?? detectHostAvailableMemoryBytes())
  const availGb = availBytes / (1024 ** 3)
  const cpuCap = Math.max(PHASE_B_AIMD_MIN_FLOOR, Math.floor(cpuCount * PHASE_B_AIMD_CPU_FRACTION))
  const ramCap = Math.max(PHASE_B_AIMD_MIN_FLOOR, Math.floor(availGb / PHASE_B_AIMD_RAM_GB_PER_SLOT))
  return Math.min(hardCeiling, Math.max(PHASE_B_AIMD_MIN_FLOOR, Math.min(cpuCap, ramCap)))
}

/** Cap concurrency by remaining USD budget (`>= 1` slot; winds down cleanly as budget depletes). */
export function computeBudgetPhaseBConcurrencyCap(remainingBudgetUsd?: number): number {
  if (remainingBudgetUsd === undefined || !Number.isFinite(remainingBudgetUsd)) return Number.POSITIVE_INFINITY
  return Math.max(1, Math.floor(Math.max(0, remainingBudgetUsd) / PHASE_B_AIMD_USD_PER_SLOT))
}

export interface PhaseBConcurrencyControllerOptions {
  cpuCount?: number
  availMemBytes?: number
  ceiling?: number
  warmStart?: number
  cleanWindowMs?: number
  cleanCompletionsThreshold?: number
  /** Explicit CLI/API/test concurrency override (always takes precedence over AIMD). */
  explicitOverride?: number
  env?: NodeJS.ProcessEnv
  now?: () => number
}

export interface PhaseBConcurrencySnapshot {
  current: number
  hardwareCap: number
  effectiveMaxCap: number
  override: number | null
  cleanCompletionsInWindow: number
  pressureCount: number
  increases: number
  decreases: number
  lastPressureKind: PhaseBPressureKind | null
}

/**
 * Dynamic AIMD Phase-B specialist concurrency controller.
 * - Auto-computes `hardwareCap` from host CPUs/available RAM (ceiling 12 on 16c/11GiB hosts).
 * - Starts warm at `min(6, hardwareCap)` so Wave 1 fills immediately.
 * - Additive Increase (`+2` up to `effectiveMaxCap`) after a clean window (~18s or clean completions
 *   with zero LLM 429s, low target 5xx/timeout rate, and healthy container spawn latency).
 * - Multiplicative Decrease (`max(2, floor(current / 2))`) immediately on pressure.
 * - Dynamically winds down when remaining USD budget shrinks (`floor(remainingUsd / 0.15)`).
 * - Explicit env/CLI override always wins.
 */
export class PhaseBConcurrencyController {
  readonly hardwareCap: number
  readonly override: number | null
  private readonly cleanWindowMs: number
  private readonly cleanCompletionsThreshold: number
  private readonly now: () => number
  private current: number
  private windowStartedAt: number
  private cleanCompletionsInWindow = 0
  private targetOutcomesInWindow = 0
  private targetErrorsInWindow = 0
  private pressureEventsInWindow = 0
  private maxSpawnLatencyInWindowMs = 0
  private pressureCount = 0
  private increases = 0
  private decreases = 0
  private lastPressureKind: PhaseBPressureKind | null = null

  constructor(options: PhaseBConcurrencyControllerOptions = {}) {
    this.now = options.now ?? (() => Date.now())
    this.hardwareCap = computeHostPhaseBConcurrencyCap({
      ...(options.cpuCount !== undefined ? { cpuCount: options.cpuCount } : {}),
      ...(options.availMemBytes !== undefined ? { availMemBytes: options.availMemBytes } : {}),
      ...(options.ceiling !== undefined ? { ceiling: options.ceiling } : {}),
    })
    const explicit = options.explicitOverride !== undefined && Number.isFinite(options.explicitOverride) && options.explicitOverride > 0
      ? Math.max(1, Math.min(maxWorkerConcurrency, Math.floor(options.explicitOverride)))
      : parseEnvPhaseBConcurrencyOverride(options.env)
    this.override = explicit ?? null
    this.cleanWindowMs = Math.max(1_000, Math.floor(options.cleanWindowMs ?? PHASE_B_AIMD_CLEAN_WINDOW_MS))
    this.cleanCompletionsThreshold = Math.max(1, Math.floor(options.cleanCompletionsThreshold ?? PHASE_B_AIMD_CLEAN_COMPLETIONS_THRESHOLD))
    const warm = Math.max(1, Math.floor(options.warmStart ?? PHASE_B_AIMD_WARM_START))
    this.current = this.override ?? Math.min(warm, this.hardwareCap)
    this.windowStartedAt = this.now()
  }

  private resetWindow(nowMs: number): void {
    this.windowStartedAt = nowMs
    this.cleanCompletionsInWindow = 0
    this.targetOutcomesInWindow = 0
    this.targetErrorsInWindow = 0
    this.pressureEventsInWindow = 0
    this.maxSpawnLatencyInWindowMs = 0
  }

  private effectiveCap(remainingBudgetUsd?: number): number {
    if (this.override !== null) return this.override
    return Math.min(this.hardwareCap, computeBudgetPhaseBConcurrencyCap(remainingBudgetUsd))
  }

  private maybeIncrease(nowMs: number, remainingBudgetUsd?: number): void {
    if (this.override !== null) return
    const cap = this.effectiveCap(remainingBudgetUsd)
    if (this.current >= cap) return
    const errorRate = this.targetOutcomesInWindow > 0 ? this.targetErrorsInWindow / this.targetOutcomesInWindow : 0
    const healthy = this.pressureEventsInWindow === 0
      && errorRate <= 0.15
      && this.maxSpawnLatencyInWindowMs <= PHASE_B_AIMD_SPAWN_LATENCY_WARN_MS
    if (!healthy) return
    const windowElapsed = nowMs - this.windowStartedAt >= this.cleanWindowMs
    const readyByTime = windowElapsed && (this.cleanCompletionsInWindow > 0 || this.targetOutcomesInWindow > 0)
    const readyByCompletions = this.cleanCompletionsInWindow >= this.cleanCompletionsThreshold
    if (readyByTime || readyByCompletions) {
      const next = Math.min(cap, this.current + PHASE_B_AIMD_INCREASE_STEP)
      if (next > this.current) {
        this.current = next
        this.increases += 1
      }
      this.resetWindow(nowMs)
    }
  }

  /** Current effective concurrency cap, applying clean-window ramp-up and remaining-budget wind-down. */
  getEffectiveConcurrency(input: { remainingBudgetUsd?: number; nowMs?: number } = {}): number {
    if (this.override !== null) return this.override
    const nowMs = input.nowMs ?? this.now()
    this.maybeIncrease(nowMs, input.remainingBudgetUsd)
    const cap = this.effectiveCap(input.remainingBudgetUsd)
    return Math.max(1, Math.min(cap, this.current))
  }

  /** Immediate Multiplicative Decrease (`max(2, floor(current / 2))`) on rate-limit, target, or container pressure. */
  recordPressure(kind: PhaseBPressureKind, nowMs = this.now()): number {
    this.pressureCount += 1
    this.lastPressureKind = kind
    this.pressureEventsInWindow += 1
    if (this.override !== null) return this.override
    const floor = Math.min(PHASE_B_AIMD_MIN_FLOOR, this.hardwareCap)
    const next = Math.max(floor, Math.floor(this.current / 2))
    if (next < this.current) {
      this.current = next
      this.decreases += 1
    }
    this.resetWindow(nowMs)
    return this.current
  }

  /** Record a target HTTP status or timeout; backs off immediately on 429/503/timeout spikes. */
  recordTargetOutcome(statusOrError: number | 'timeout', nowMs = this.now()): void {
    this.targetOutcomesInWindow += 1
    const isSpikeError = statusOrError === 'timeout' || statusOrError === 429 || statusOrError === 503
    if (!isSpikeError) return
    this.targetErrorsInWindow += 1
    const errorRate = this.targetErrorsInWindow / this.targetOutcomesInWindow
    if (this.targetErrorsInWindow >= 3 || (this.targetOutcomesInWindow >= 4 && errorRate > 0.25)) {
      const kind: PhaseBPressureKind = statusOrError === 'timeout'
        ? 'target_timeout'
        : statusOrError === 429
          ? 'target_429'
          : 'target_503'
      this.recordPressure(kind, nowMs)
    }
  }

  /** Record a clean specialist completion; high spawn latency triggers backoff instead of ramp-up. */
  recordCleanCompletion(input: {
    spawnLatencyMs?: number
    nowMs?: number
    remainingBudgetUsd?: number
  } = {}): number {
    const nowMs = input.nowMs ?? this.now()
    if (typeof input.spawnLatencyMs === 'number' && Number.isFinite(input.spawnLatencyMs)) {
      this.maxSpawnLatencyInWindowMs = Math.max(this.maxSpawnLatencyInWindowMs, input.spawnLatencyMs)
      if (input.spawnLatencyMs > PHASE_B_AIMD_SPAWN_LATENCY_WARN_MS) {
        return this.recordPressure('container_pressure', nowMs)
      }
    }
    this.cleanCompletionsInWindow += 1
    this.maybeIncrease(nowMs, input.remainingBudgetUsd)
    return this.getEffectiveConcurrency({
      ...(input.remainingBudgetUsd !== undefined ? { remainingBudgetUsd: input.remainingBudgetUsd } : {}),
      nowMs,
    })
  }

  snapshot(remainingBudgetUsd?: number): PhaseBConcurrencySnapshot {
    const cap = this.effectiveCap(remainingBudgetUsd)
    return {
      current: this.override ?? Math.max(1, Math.min(cap, this.current)),
      hardwareCap: this.hardwareCap,
      effectiveMaxCap: cap,
      override: this.override,
      cleanCompletionsInWindow: this.cleanCompletionsInWindow,
      pressureCount: this.pressureCount,
      increases: this.increases,
      decreases: this.decreases,
      lastPressureKind: this.lastPressureKind,
    }
  }
}

export type StepOriginSource =
  | 'whitebox_code_audit'
  | 'whitebox_tier_a'
  | 'runtime_chain'
  | 'det_lead'
  | 'planner'
  | 'boundary_stub'

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
  /** Optional typed routing metadata (avoids free-text regex classification when stamped at creation). */
  lane?: DispatchLane
  evi?: number
  originSource?: StepOriginSource
  hopDepth?: number
  budgetClass?: AssignmentBudgetClass
}

export interface TypedStepDispatchMeta {
  lane: DispatchLane
  evi: number
  originSource: StepOriginSource
  hopDepth: number
  budgetClass: AssignmentBudgetClass
  whiteBox: boolean
  multiHop: boolean
  genericWave1Stub: boolean
  sealedCapability: boolean
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
  /** Optional EVI scores keyed by step ID (wired from `FrontierWaveController` / `planChainRound`). */
  eviByStepId?: ReadonlyMap<string, number>
  /** Optional active `FrontierWaveController` supplying live EVI beam scores & wave ranking. */
  frontierController?: FrontierWaveController | null
  /** Optional pre-registered typed step metadata keyed by step ID. */
  stepMetaById?: ReadonlyMap<string, Partial<TypedStepDispatchMeta>>
}

export type FrontierDispatchOptions = RoundRobinDispatchOptions

export interface RoundRobinDispatchPlan<T extends DispatchLaneStep> {
  ordered: T[]
  selectedByLane: Record<DispatchLane, number>
  leadCapRemaining: number
  deferredLeads: number
}

export interface FrontierDispatchPlan<T extends DispatchLaneStep> extends RoundRobinDispatchPlan<T> {
  whiteBoxSelected: number
  runtimeChainReserved: number
  eviRankedCount: number
  waveSelection?: WaveSelectionResult | null
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
/** Maximum distinct sibling code-audit suspects attached to each Wave-1 multi-hop step. */
export const MAX_CODE_AUDIT_SIBLING_LEADS = 4
/** Maximum composite multi-service chain steps synthesized from complementary code-audit sinks. */
export const MAX_SYNTHESIZED_CODE_AUDIT_COMPOSITE_STEPS = 2
/** Maximum generic cross-origin composite Wave-1 chain steps synthesized from runtime facts/specs when `!sourceMounted`. */
export const MAX_SYNTHESIZED_RUNTIME_COMPOSITE_STEPS = 2

const SEALED_HOP_CAP_HANDLE_RE = /\bcap:hop_(?!synth:)[A-Za-z0-9._-]+:[A-Za-z0-9._-]+/
const SOURCE_AUDIT_ORIGIN_TEXT_RE = /\b(?:source[- ]first code audit|source audit verify|semantic audit|code_audit_suspect|code_audit|source_audit|semantic_audit)\b/i
const CAUSAL_ARROW_HYPOTHESIS_RE = /->|→|=>/
const RUNTIME_BACKED_CHAIN_SKILLS: ReadonlySet<string> = new Set([
  'api-dependency',
  'runtime-dependency',
  'runtime-composite-chain',
  'cross-origin-chain',
  'runtime-cross-origin',
  'persona-differential',
  'runtime-persona-diff',
])
const RUNTIME_API_DEP_HYPOTHESIS_RE = /\b(?:api_dependency:|api_dep_producer=|producer\s*(?:->|→)\s*consumer|resource_key=)/i
const RUNTIME_PERSONA_DIFF_HYPOTHESIS_RE = /\b(?:denied_control:|persona_diff:|runtime_surface_asymmetry|catalog_weaker=|client_roles=)\b|\bis\s+denied\s*\((?:401|403)\)[\s\S]{0,160}\bbut\s+succeeds\s*\(2\d\d\)/i
const RUNTIME_CROSS_ORIGIN_HYPOTHESIS_RE = /\b(?:cross_origin_edge:|cross_origin=|cross-origin\s+(?:transition|api\s+dependency|composite\s+chain))\b/i
const HTTP_ORIGIN_IN_TEXT_RE = /https?:\/\/[A-Za-z0-9.-]+(?::\d+)?/gi

/**
 * True when a grey-box/runtime Wave-1 chain step is backed by concrete runtime evidence:
 * producer->consumer API dependencies, real cross-origin transitions (>= 2 distinct origins),
 * or multi-persona differential observations (exempting it from generic Wave-1 stub demotion).
 */
export function hasRuntimeBackedChainEvidence(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills'> & Partial<Pick<DispatchLaneStep, 'sourceOrigins'>>,
): boolean {
  if ((step.skills ?? []).some(skill => RUNTIME_BACKED_CHAIN_SKILLS.has(skill) || skill.startsWith('api_dep:'))) {
    return true
  }
  const distinctSourceOrigins = new Set((step.sourceOrigins ?? []).filter(Boolean))
  if (distinctSourceOrigins.size >= 2) return true
  const hyp = step.hypothesis ?? ''
  const text = `${step.title} ${hyp}`
  if (RUNTIME_API_DEP_HYPOTHESIS_RE.test(text)) return true
  if (RUNTIME_PERSONA_DIFF_HYPOTHESIS_RE.test(text)) return true
  if (RUNTIME_CROSS_ORIGIN_HYPOTHESIS_RE.test(text)) return true
  const mentionedOrigins = new Set<string>()
  for (const m of hyp.matchAll(HTTP_ORIGIN_IN_TEXT_RE)) {
    mentionedOrigins.add(m[0]!.toLowerCase())
    if (mentionedOrigins.size >= 2) return true
  }
  return false
}

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
 * `dependsOnFactIds` at depth 0, concrete source-audit suspect linkage, or runtime dependency /
 * cross-origin / multi-persona differential backing), including any continuation spawned from
 * such a stub.
 */
export function isGenericWave1BoundaryChainStep(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>
    & Partial<Pick<DispatchLaneStep, 'sourceOrigins'>>,
): boolean {
  if (hasSourceAuditOrigin(step)) return false
  if (hasRuntimeBackedChainEvidence(step)) return false
  const isWave1StubMarker = /^wave-1\s+chain\b/i.test(step.title)
    || /\[inv_hyp=[^\]]+\]/i.test(step.hypothesis ?? '')
    || (step.skills ?? []).includes('wave1-boundary-stub')
  if (!isWave1StubMarker) return false
  if (extractContinuationDepth(step) === 0 && (step.dependsOnFactIds?.length ?? 0) > 0) return false
  return true
}

/**
 * True when a chain step is backed by concrete source-audit findings, upstream facts
 * (`dependsOnFactIds`), runtime dependency/cross-origin/multi-persona evidence, or a
 * planner-synthesized causal arrow hypothesis (as opposed to a generic Wave-1 heuristic stub).
 */
export function isHighSignalSourceOrPlannerChainStep(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>
    & Partial<Pick<DispatchLaneStep, 'sourceOrigins'>>,
): boolean {
  if (isGenericWave1BoundaryChainStep(step)) return false
  if (hasSourceAuditOrigin(step)) return true
  if (hasRuntimeBackedChainEvidence(step)) return true
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
 *  0. Unstarted (`depth === 0`) source-audit / planner-synthesized / runtime-evidence-backed chains,
 *  1. `depth === 1` continuations that sealed a `cap:hop_*` capability handle,
 *  2. Remaining unstarted (`depth === 0`) Wave-1 boundary stubs,
 *  3. `depth === 1` continuations without a sealed `cap:hop_*` handle,
 *  4. `depth >= 2` continuations (only after distinct chains have had their first shot).
 */
export function chainLaneDispatchRank(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'skills' | 'dependsOnFactIds'>
    & Partial<Pick<DispatchLaneStep, 'sourceOrigins'>>,
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
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'category' | 'skills' | 'dependsOnStepIds' | 'dependsOnFactIds'>,
): boolean {
  return matchesMultiHopStepSignal(step)
}

const TYPED_LANE_TAG_RE = /\[lane=(lead|route|workflow|business_logic|race|chain|other)\]/i
const TYPED_EVI_TAG_RE = /\[evi=([0-9]+(?:\.[0-9]+)?)\]/i
const TYPED_CAP_TAG_RE = /\[cap=([^\]]+)\]/i
const VALID_DISPATCH_LANES: ReadonlySet<string> = new Set(['lead', 'route', 'workflow', 'business_logic', 'race', 'chain', 'other'])

/** Map a step onto its dispatch lane: prefers typed `step.lane` and `[lane=...]` tags before regex fallback. */
export function classifyDispatchLane(
  step: DispatchLaneStep,
  hostTiers?: Record<string, HostTier>,
): DispatchLane {
  if (step.lane && VALID_DISPATCH_LANES.has(step.lane)) return step.lane
  if (step.originSource === 'det_lead') return 'lead'
  if (step.originSource === 'runtime_chain') return 'chain'
  const taggedLane = TYPED_LANE_TAG_RE.exec(step.hypothesis ?? '')?.[1]?.toLowerCase()
  if (taggedLane && VALID_DISPATCH_LANES.has(taggedLane)) return taggedLane as DispatchLane
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

/** Resolve typed dispatch metadata for a step (stamped fields + FrontierWaveController EVI first). */
export function resolveStepDispatchMeta(
  step: DispatchLaneStep,
  options: Pick<FrontierDispatchOptions, 'hostTiers' | 'tierALeadIds' | 'whiteBoxStepIds' | 'eviByStepId' | 'stepMetaById'> = {},
  branchEviByCapOrEndpoint?: ReadonlyMap<string, number>,
): TypedStepDispatchMeta {
  const registered = options.stepMetaById?.get(step.id)
  const lane = registered?.lane ?? classifyDispatchLane(step, options.hostTiers)
  const whiteBox = registered?.whiteBox
    ?? (step.originSource === 'whitebox_code_audit'
      || step.originSource === 'whitebox_tier_a'
      || Boolean(options.tierALeadIds?.has(step.id))
      || Boolean(options.whiteBoxStepIds?.has(step.id))
      || isWhiteBoxStep(step))
  const hopDepth = registered?.hopDepth ?? step.hopDepth ?? extractContinuationDepth(step)
  const multiHop = registered?.multiHop ?? (lane === 'chain' && (step.originSource === 'runtime_chain' || hopDepth >= 2 || isMultiHopChainStep(step)))
  const genericWave1Stub = registered?.genericWave1Stub ?? (step.originSource === 'boundary_stub' || (!step.originSource && isGenericWave1BoundaryChainStep(step)))
  const sealedCapability = registered?.sealedCapability ?? hasSealedHopCapability(step)
  const originSource: StepOriginSource = registered?.originSource ?? step.originSource ?? (
    options.tierALeadIds?.has(step.id)
      ? 'whitebox_tier_a'
      : whiteBox
        ? 'whitebox_code_audit'
        : isDetLeadDispatchStep(step)
          ? 'det_lead'
          : genericWave1Stub
            ? 'boundary_stub'
            : hasRuntimeBackedChainEvidence(step)
              ? 'runtime_chain'
              : 'planner'
  )

  let evi = 0
  if (typeof registered?.evi === 'number' && Number.isFinite(registered.evi) && registered.evi > 0) {
    evi = registered.evi
  } else if (typeof step.evi === 'number' && Number.isFinite(step.evi) && step.evi > 0) {
    evi = step.evi
  } else if (options.eviByStepId?.has(step.id)) {
    evi = Math.max(0, options.eviByStepId.get(step.id) ?? 0)
  } else {
    const tagMatch = TYPED_EVI_TAG_RE.exec(step.hypothesis ?? '')
    if (tagMatch?.[1]) {
      const parsed = Number(tagMatch[1])
      if (Number.isFinite(parsed) && parsed > 0) evi = parsed
    }
    if (evi === 0 && branchEviByCapOrEndpoint && branchEviByCapOrEndpoint.size > 0) {
      const capMatch = TYPED_CAP_TAG_RE.exec(step.hypothesis ?? '')?.[1]
      if (capMatch && branchEviByCapOrEndpoint.has(capMatch)) {
        evi = branchEviByCapOrEndpoint.get(capMatch)!
      } else {
        for (const [key, score] of branchEviByCapOrEndpoint.entries()) {
          if (key.length >= 4 && ((step.hypothesis ?? '').includes(key) || step.title.includes(key))) {
            evi = Math.max(evi, score)
          }
        }
      }
    }
  }

  const budgetClass = registered?.budgetClass ?? step.budgetClass ?? classifyAssignmentBudgetClass({
    title: step.title,
    hypothesis: step.hypothesis,
    category: step.category,
    skills: step.skills,
    dependsOnFactIds: step.dependsOnFactIds,
    dependsOnStepIds: step.dependsOnStepIds,
    multiHopChain: multiHop,
  })

  return { lane, evi, originSource, hopDepth, budgetClass, whiteBox, multiHop, genericWave1Stub, sealedCapability }
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

function compareDispatchSteps(
  a: DispatchLaneStep,
  b: DispatchLaneStep,
  hostTiers?: Record<string, HostTier>,
  metaById?: ReadonlyMap<string, TypedStepDispatchMeta>,
): number {
  const trialDup = Number(isTrialDuplicateStep(a)) - Number(isTrialDuplicateStep(b))
  if (trialDup !== 0) return trialDup
  const tier = dispatchTierRank(a, hostTiers) - dispatchTierRank(b, hostTiers)
  if (tier !== 0) return tier
  const eviA = metaById?.get(a.id)?.evi ?? 0
  const eviB = metaById?.get(b.id)?.evi ?? 0
  if (Math.abs(eviB - eviA) > 1e-6) return eviB - eviA
  if (a.priority !== b.priority) return b.priority - a.priority
  if (a.seq !== b.seq) return a.seq - b.seq
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

/**
 * Unified Typed Frontier Dispatcher (Move O3): collapses `FrontierWaveController` EVI wave scoring
 * and multi-lane round-robin dispatch into one deterministic selector.
 *
 * Ordering guarantees:
 *  1. Typed routing metadata (`lane`, `evi`, `originSource`, `hopDepth`) is respected before regexes.
 *  2. White-box source-confirmed steps take priority when `sourceMounted === true` (never throttled
 *     by `DET_LEAD_CONCURRENT_CAP`), while reserving 1 slot for a ready high-signal runtime/grey-box
 *     chain whenever white-box backlogs would otherwise saturate all `>= 2` slots.
 *  3. Within `chain` and across lanes, live EVI scores from `FrontierWaveController` rank high-value
 *     branches ahead of lower-EVI branches while preserving fair depth-0 / continuation interleaving.
 *  4. Dedicated chain frontier slots, lead concurrent cap, round-robin semantic lanes, and surplus-only
 *     trial duplicates stay strictly enforced.
 */
export function dispatchFrontierWave<T extends DispatchLaneStep>(
  steps: readonly T[],
  slots: number,
  options: FrontierDispatchOptions = {},
): FrontierDispatchPlan<T> {
  const capacity = Math.max(0, Math.floor(slots))
  const selectedByLane: Record<DispatchLane, number> = {
    lead: 0, route: 0, workflow: 0, business_logic: 0, race: 0, chain: 0, other: 0,
  }
  const branchEviIndex = new Map<string, number>()
  let waveSelection: WaveSelectionResult | null = null
  if (options.frontierController && capacity > 0) {
    waveSelection = options.frontierController.selectNextWave(capacity)
    const indexEvi = (key: string, score: number) => {
      if (key) branchEviIndex.set(key, Math.max(branchEviIndex.get(key) ?? 0, score))
    }
    for (const item of waveSelection.assignments) {
      const score = Math.max(0, item.evi)
      indexEvi(item.branchKey, score)
      indexEvi(item.targetSurfaceKey, score)
      for (const capId of item.preconditionCapIds) indexEvi(capId, score)
      const branch = options.frontierController.scheduler.getBranch(item.branchKey)
      if (branch) {
        const branchScore = Math.max(score, computeBranchEvi(branch))
        indexEvi(branch.branchKey, branchScore)
        indexEvi(branch.nextTarget.endpoint, branchScore)
        for (const hop of branch.verifiedHops) indexEvi(hop.capabilityId, branchScore)
      }
    }
  }

  const lanes = new Map<DispatchLane, T[]>()
  for (const lane of ['lead', ...DISPATCH_LANE_ORDER] as DispatchLane[]) lanes.set(lane, [])
  const duplicateTrials: Array<{ lane: DispatchLane; step: T }> = []
  const metaById = new Map<string, TypedStepDispatchMeta>()
  const seenStepIds = new Set<string>()
  let eviRankedCount = 0

  for (const step of steps) {
    if (seenStepIds.has(step.id)) continue
    seenStepIds.add(step.id)
    const meta = resolveStepDispatchMeta(step, options, branchEviIndex)
    metaById.set(step.id, meta)
    if (meta.evi > 0) eviRankedCount += 1
    if (isTrialDuplicateStep(step)) duplicateTrials.push({ lane: meta.lane, step })
    else lanes.get(meta.lane)!.push(step)
  }

  for (const lane of lanes.values()) {
    lane.sort((a, b) => compareDispatchSteps(a, b, options.hostTiers, metaById))
  }
  lanes.get('chain')!.sort((a, b) =>
    chainLaneDispatchRank(a) - chainLaneDispatchRank(b)
    || Number(metaById.get(a.id)?.genericWave1Stub ?? false) - Number(metaById.get(b.id)?.genericWave1Stub ?? false)
    || compareDispatchSteps(a, b, options.hostTiers, metaById),
  )
  duplicateTrials.sort((a, b) => compareDispatchSteps(a.step, b.step, options.hostTiers, metaById))

  const leadCap = Math.max(
    0,
    Math.floor(options.leadCap ?? DET_LEAD_CONCURRENT_CAP) - Math.max(0, Math.floor(options.activeLeadCount ?? 0)),
  )
  const ordered: T[] = []
  const leadQueue = lanes.get('lead')!
  const tierALeadIds = options.tierALeadIds
  const whiteBoxStepIds = options.whiteBoxStepIds
  const whiteBoxFirst = options.sourceMounted === true || Boolean(whiteBoxStepIds?.size)

  let tierASelected = 0
  let whiteBoxSelected = 0
  let runtimeChainReserved = 0

  if (whiteBoxFirst) {
    const whiteBoxCandidates: Array<{ lane: DispatchLane; step: T }> = []
    for (const [lane, queue] of lanes.entries()) {
      for (let idx = 0; idx < queue.length;) {
        if (!metaById.get(queue[idx]!.id)?.whiteBox) { idx += 1; continue }
        whiteBoxCandidates.push({ lane, step: queue.splice(idx, 1)[0]! })
      }
    }
    whiteBoxCandidates.sort((a, b) =>
      Number(isChainContinuationStep(a.step)) - Number(isChainContinuationStep(b.step))
      || (a.lane === 'chain' && b.lane === 'chain'
        ? chainLaneDispatchRank(a.step) - chainLaneDispatchRank(b.step)
        : 0)
      || compareDispatchSteps(a.step, b.step, options.hostTiers, metaById),
    )

    // Anti-starvation: when white-box steps alone would fill every slot (capacity >= 2), reserve
    // 1 slot for a ready high-signal non-white-box runtime/grey-box chain if none is active yet.
    const chainQueueNow = lanes.get('chain')!
    const hasHighSignalRuntimeChain = chainQueueNow.some(step => {
      const m = metaById.get(step.id)
      return Boolean(
        m && !m.whiteBox && !m.genericWave1Stub && m.multiHop
        && (m.originSource === 'runtime_chain' || m.evi > 0 || hasRuntimeBackedChainEvidence(step)),
      )
    })
    const reserveSlotForRuntimeChain = capacity >= 2
      && whiteBoxCandidates.length >= capacity
      && hasHighSignalRuntimeChain
      && Math.max(0, Math.floor(options.activeChainCount ?? 0)) === 0
      && options.chainReservedSlots !== 0
      ? 1
      : 0
    const whiteBoxSlotCap = Math.max(0, capacity - reserveSlotForRuntimeChain)

    const remainingWhiteBox: Array<{ lane: DispatchLane; step: T }> = []
    for (const entry of whiteBoxCandidates) {
      if (ordered.length < whiteBoxSlotCap) {
        ordered.push(entry.step)
        selectedByLane[entry.lane] += 1
        whiteBoxSelected += 1
        if (entry.lane === 'lead') tierASelected += 1
      } else {
        remainingWhiteBox.push(entry)
      }
    }
    for (const entry of remainingWhiteBox.reverse()) {
      lanes.get(entry.lane)!.unshift(entry.step)
    }
    if (reserveSlotForRuntimeChain > 0 && ordered.length < capacity) {
      const rtIdx = chainQueueNow.findIndex(step => {
        const m = metaById.get(step.id)
        return Boolean(
          m && !m.whiteBox && !m.genericWave1Stub && m.multiHop
          && (m.originSource === 'runtime_chain' || m.evi > 0 || hasRuntimeBackedChainEvidence(step)),
        )
      })
      if (rtIdx >= 0) {
        ordered.push(chainQueueNow.splice(rtIdx, 1)[0]!)
        selectedByLane.chain += 1
        runtimeChainReserved += 1
      }
    }
  } else if (tierALeadIds?.size) {
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
  const readyMultiHopCount = chainQueue.filter(step => metaById.get(step.id)?.multiHop).length
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
  const chainReserveRemaining = Math.max(
    0,
    maxChainReserve - Math.max(0, Math.floor(options.activeChainCount ?? 0)) - runtimeChainReserved,
  )
  let chainReservedSelected = 0
  for (let idx = 0; idx < chainQueue.length && ordered.length < capacity && chainReservedSelected < chainReserveRemaining;) {
    if (!metaById.get(chainQueue[idx]!.id)?.multiHop) { idx += 1; continue }
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
    whiteBoxSelected,
    runtimeChainReserved,
    eviRankedCount,
    waveSelection,
  }
}

/**
 * Stateful unified Frontier Dispatcher combining a run's `FrontierWaveController` (EVI beam &
 * negative-edge pruning) with typed step routing metadata and multi-lane dispatch.
 */
export class FrontierDispatcher {
  readonly controller: FrontierWaveController | null
  private readonly stepMeta = new Map<string, Partial<TypedStepDispatchMeta>>()

  constructor(options: { controller?: FrontierWaveController | null } = {}) {
    this.controller = options.controller ?? null
  }

  registerStepMeta(stepId: string, meta: Partial<TypedStepDispatchMeta>): void {
    this.stepMeta.set(stepId, { ...(this.stepMeta.get(stepId) ?? {}), ...meta })
  }

  getStepMeta(stepId: string): Partial<TypedStepDispatchMeta> | undefined {
    return this.stepMeta.get(stepId)
  }

  clearStepMeta(stepId?: string): void {
    if (stepId) this.stepMeta.delete(stepId)
    else this.stepMeta.clear()
  }

  selectNextWave(waveCapacity: number, quotaOverride?: WaveQuotaConfig): WaveSelectionResult | null {
    return this.controller ? this.controller.selectNextWave(waveCapacity, quotaOverride) : null
  }

  dispatch<T extends DispatchLaneStep>(
    steps: readonly T[],
    slots: number,
    options: FrontierDispatchOptions = {},
  ): FrontierDispatchPlan<T> {
    return dispatchFrontierWave(steps, slots, {
      ...options,
      frontierController: options.frontierController ?? this.controller,
      stepMetaById: options.stepMetaById ?? this.stepMeta,
    })
  }
}

/**
 * Backwards-compatible entry point delegating directly to the unified `dispatchFrontierWave`.
 */
export function planRoundRobinDispatch<T extends DispatchLaneStep>(
  steps: readonly T[],
  slots: number,
  options: RoundRobinDispatchOptions = {},
): RoundRobinDispatchPlan<T> {
  return dispatchFrontierWave(steps, slots, options)
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
  hypothesis?: string | null
  category?: string | null
  skills?: readonly string[]
}): boolean {
  // A det_lead upgrade is one hypothesis, not a multi-step assignment: its prose says "chain it
  // into a higher-impact finding" on every upgrade, and it must keep the 12-turn single-step lane.
  if (/\bdet[_ ]lead\b|\blead upgrade\b/i.test(input.title ?? '')) return false
  if (matchesMultiHopStepSignal({
    title: input.title ?? '',
    hypothesis: input.hypothesis,
    category: input.category,
    skills: input.skills,
  })) {
    return true
  }
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
  const raw = Number(env.KOVO_PROVIDER_NO_TOKEN_MS)
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
  const raw = Number(env.KOVO_SINGLE_STEP_WALL_CLOCK_MS)
  if (!Number.isFinite(raw) || raw <= 0) return SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS
  return Math.max(30_000, Math.min(120_000, Math.round(raw)))
}

export type AssignmentBudgetClass = 'single_step' | 'multi_step' | 'multi_hop_chain'

export interface AssignmentStepDescriptor {
  title?: string
  hypothesis?: string | null
  category?: string | null
  skills?: readonly string[]
  /** Endpoint templates the step names (see `stepMentionedRoutes`). */
  routes?: readonly string[]
  /** Upstream evidence the step cites (`dependsOnFactIds`; the chain signal). */
  parentEvidenceIds?: readonly string[]
  dependsOnFactIds?: readonly string[]
  dependsOnStepIds?: readonly string[]
  /** Explicit pre-stamped budget class (bypasses heuristic classification when provided). */
  budgetClass?: AssignmentBudgetClass
  /** Explicit multi-step override (race / cross-persona / BOLA). */
  multiStep?: boolean
  /** Explicit multi-hop chain override. */
  multiHopChain?: boolean
}

export interface AssignmentRunPolicy {
  baseMaxTurns: number
  baseWallClockMs: number
  /** Overall run wall-clock duration in ms (scales multi-hop chain budgets proportionally). */
  runDurationMs?: number
  /** Single-step wall cap (default {@link SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS}). */
  singleStepWallClockMs?: number
  /** Explicit run-level wall-clock override (e.g. deterministic rotation tests). */
  wallClockOverrideMs?: number
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
  budgetClass?: AssignmentBudgetClass
  maxTurns: number
  wallClockMs: number
  /** Wall-clock settlement threshold in ms (multi-hop uses `max(wall - 25s, wall * 0.82)`). */
  wallClockSettlementMs?: number
  /** Turn at which the hard settlement nudge fires (N-2). */
  settlementTurn: number
}

/**
 * Resolve when the worker settlement nudge fires — delegates to the single authoritative
 * `wallClockSettlementMs` formula in `agent-prompts.ts` so dispatch, runner, and session
 * share one wall-clock settlement schedule.
 */
export function resolveWorkerSettlementMs(wallClockMs: number, isMultiHop: boolean): number {
  return wallClockSettlementMs(wallClockMs, isMultiHop)
}

/** Classify a step descriptor into its canonical budget tier (`single_step` | `multi_step` | `multi_hop_chain`). */
export function classifyAssignmentBudgetClass(step: AssignmentStepDescriptor): AssignmentBudgetClass {
  if (step.budgetClass) return step.budgetClass
  const parentFactIds = step.parentEvidenceIds ?? step.dependsOnFactIds ?? []
  const depStepIds = step.dependsOnStepIds ?? []
  const isMultiHop = step.multiHopChain === true
    || (step.multiHopChain !== false && isMultiHopChainStep({
      title: step.title ?? '',
      hypothesis: step.hypothesis,
      category: step.category,
      skills: step.skills,
      dependsOnFactIds: parentFactIds,
      dependsOnStepIds: depStepIds,
    }))
  if (isMultiHop) return 'multi_hop_chain'
  const isMultiStep = step.multiStep === true
    || parentFactIds.length > 0
    || depStepIds.length > 0
    || (step.multiStep !== false && isMultiStepAssignment({
      title: step.title,
      hypothesis: step.hypothesis,
      category: step.category,
      skills: step.skills,
    }))
  return isMultiStep ? 'multi_step' : 'single_step'
}

/**
 * Single pure authoritative budget resolver (Move O5): replaces competing `planAssignmentBudget`
 * and `resolveWorkerWallClockMs` calculators so `multiStep` race/BOLA/cross-persona assignments
 * keep their intended 120–180s budgets instead of being silently clamped down to single-step caps.
 */
export function resolveAssignmentBudget(
  stepDescriptor: AssignmentStepDescriptor,
  runPolicy: AssignmentRunPolicy,
): AssignmentBudget & { budgetClass: AssignmentBudgetClass } {
  const budgetClass = classifyAssignmentBudgetClass(stepDescriptor)
  const baseTurns = Math.max(4, Math.floor(runPolicy.baseMaxTurns))
  const baseWall = Math.max(20_000, Math.round(runPolicy.baseWallClockMs))
  const overrideWall = typeof runPolicy.wallClockOverrideMs === 'number'
    && Number.isFinite(runPolicy.wallClockOverrideMs)
    && runPolicy.wallClockOverrideMs > 0
    ? Math.max(1, Math.floor(runPolicy.wallClockOverrideMs))
    : undefined

  if (budgetClass === 'multi_hop_chain') {
    const maxTurns = Math.max(20, Math.min(34, baseTurns))
    const computedWall = typeof runPolicy.runDurationMs === 'number'
      && Number.isFinite(runPolicy.runDurationMs)
      && runPolicy.runDurationMs > 0
      ? Math.min(
          MULTI_HOP_CHAIN_MAX_WALL_CLOCK_MS,
          Math.max(MULTI_HOP_CHAIN_MIN_WALL_CLOCK_MS, Math.floor(runPolicy.runDurationMs * MULTI_HOP_CHAIN_WALL_CLOCK_SHARE)),
        )
      : MULTI_HOP_CHAIN_DEFAULT_WALL_CLOCK_MS
    const wallClockMs = overrideWall ?? computedWall
    return {
      kind: 'chain',
      budgetClass,
      maxTurns,
      wallClockMs,
      wallClockSettlementMs: resolveWorkerSettlementMs(wallClockMs, true),
      settlementTurn: Math.max(1, maxTurns - 2),
    }
  }

  if (budgetClass === 'multi_step') {
    const parentFactIds = stepDescriptor.parentEvidenceIds ?? stepDescriptor.dependsOnFactIds ?? []
    const depStepIds = stepDescriptor.dependsOnStepIds ?? []
    const citesUpstream = parentFactIds.length > 0 || depStepIds.length > 0
    const maxTurns = citesUpstream
      ? Math.max(20, Math.min(34, baseTurns))
      : Math.max(MULTI_STEP_ASSIGNMENT_MIN_TURNS, Math.min(MULTI_STEP_ASSIGNMENT_MAX_TURNS, baseTurns))
    const computedWall = Math.min(CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS, Math.max(CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS, baseWall))
    const wallClockMs = overrideWall ?? computedWall
    return {
      kind: 'chain',
      budgetClass,
      maxTurns,
      wallClockMs,
      wallClockSettlementMs: resolveWorkerSettlementMs(wallClockMs, false),
      settlementTurn: Math.max(1, maxTurns - 2),
    }
  }

  const maxTurns = Math.max(8, Math.min(SINGLE_STEP_ASSIGNMENT_MAX_TURNS, baseTurns))
  const singleCap = Math.max(
    30_000,
    Math.min(SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS, Math.round(runPolicy.singleStepWallClockMs ?? SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)),
  )
  const wallClockMs = overrideWall ?? Math.max(30_000, Math.min(singleCap, baseWall))
  return {
    kind: 'single_step',
    budgetClass,
    maxTurns,
    wallClockMs,
    wallClockSettlementMs: resolveWorkerSettlementMs(wallClockMs, false),
    settlementTurn: Math.max(1, maxTurns - 2),
  }
}

/** Backwards-compatible wrapper over {@link resolveAssignmentBudget}. */
export function resolveWorkerWallClockMs(
  step: Pick<DispatchLaneStep, 'title' | 'hypothesis' | 'category' | 'skills' | 'dependsOnStepIds' | 'dependsOnFactIds'>,
  runDurationMs?: number,
  options: { singleStepWallClockMs?: number } = {},
): number {
  const singleCap = Math.max(
    30_000,
    Math.min(SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS, Math.round(options.singleStepWallClockMs ?? SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)),
  )
  return resolveAssignmentBudget(
    {
      title: step.title,
      hypothesis: step.hypothesis,
      category: step.category,
      skills: step.skills,
      dependsOnFactIds: step.dependsOnFactIds,
      dependsOnStepIds: step.dependsOnStepIds,
      multiHopChain: isMultiHopChainStep(step),
      multiStep: false,
    },
    {
      baseMaxTurns: SINGLE_STEP_ASSIGNMENT_MAX_TURNS,
      baseWallClockMs: singleCap,
      runDurationMs,
      singleStepWallClockMs: singleCap,
    },
  ).wallClockMs
}

/** Backwards-compatible wrapper over {@link resolveAssignmentBudget}. */
export function planAssignmentBudget(input: AssignmentBudgetInput): AssignmentBudget {
  return resolveAssignmentBudget(
    {
      routes: input.routes,
      parentEvidenceIds: input.parentEvidenceIds,
      dependsOnStepIds: input.dependsOnStepIds,
      multiStep: input.multiStep === true,
      multiHopChain: input.multiHopChain === true,
    },
    {
      baseMaxTurns: input.baseMaxTurns,
      baseWallClockMs: input.baseWallClockMs,
      runDurationMs: input.runDurationMs,
      singleStepWallClockMs: input.singleStepWallClockMs,
    },
  )
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

type CodeAuditChainRole = CompositeWorkflowRole

interface NormalizedCodeAuditSuspect extends CompositeWorkflowNode {
  fact: Fact
  asset: Run['candidates'][number]
  explicitSuspect: boolean
  routeOrAction: string
  endpointHint: string
  fileLoc: string
  hypothesisBody: string
  authCheck: string
  ownershipCheck: string
  explicitCategory: string
  mappedSkills: string[]
  isCrown: boolean
  missingAuthOrOwner: boolean
  host: string
}

const COMPOSITE_CODE_AUDIT_TITLE_PREFIX = 'Source audit composite chain ·'
const CODE_AUDIT_SIBLING_BLOCK_MAX_CHARS = 680

function inferServiceScopeFromSuspect(fileLoc: string, endpointHint: string, origin: string): string {
  const cleanFile = fileLoc.replace(/:\d+$/, '').replace(/^\/+/, '')
  if (cleanFile) {
    const parts = cleanFile.split('/').filter(Boolean)
    if (parts.length >= 2 && /^(?:services|apps|packages|microservices|workers|modules|src)$/i.test(parts[0]!)) {
      return `${parts[0]!.toLowerCase()}/${parts[1]!.toLowerCase()}`
    }
    if (parts.length >= 2) return parts[0]!.toLowerCase()
  }
  const routeSeg = endpointHint.replace(/^[A-Z]+\s+/, '').split('/').filter(Boolean)[0]
  const host = (() => {
    try { return new URL(origin).hostname.toLowerCase() } catch { return origin.toLowerCase() }
  })()
  return routeSeg ? `${host}/${routeSeg.toLowerCase()}` : host
}

function classifyCodeAuditChainRoles(input: {
  sinkKind: string
  text: string
}): ReadonlySet<CodeAuditChainRole> {
  const roles = new Set<CodeAuditChainRole>()
  const sink = input.sinkKind.toLowerCase()
  const lower = input.text.toLowerCase()

  if (
    sink === 'outbound_fetch'
    || sink === 'redirect'
    || /\b(?:outbound[- ]?fetch|ssrf|url[- ]?fetch|render(?:er)?|headless|pdf|open\s+redirect|redirect\s+to|edge\s+proxy|reverse\s+proxy|follows?\s+redirects?)\b/.test(lower)
  ) {
    roles.add('outbound_fetch')
  }
  if (
    sink === 'webhook'
    || /\b(?:webhook|hmac|x-signature|x-hub-signature|signature\s+verif|signing[- ]?key|signing[- ]?secret|signing[- ]?material|jwt\s+(?:sign|forg|mint)|jwks|hs256|rs256)\b/.test(lower)
  ) {
    roles.add('signing_webhook')
  }
  if (
    /\b(?:leak(?:s|ed|ing)?|expos(?:e|es|ed|ure)|disclos(?:e|es|ed|ure)|plaintext|in[- ]?log|log\s+sink|debug\s+endpoint|diagnostic|directory(?:\s+(?:listing|leak|expos|lookup|endpoint))?|member\s+list|user\s+lookup|enumerat(?:e|ion)|cache[- ]?key|cache\s+(?:deception|poison))\b/.test(lower)
  ) {
    roles.add('info_disclosure')
  }
  if (
    sink === 'auth_config'
    || /\b(?:session|jwt|oauth|oidc|sso|saml|invite|magic[- ]?link|impersonat|x-forwarded|forwarded[- ]?(?:role|user|identity|header)|trust[- ]?boundary|role[- ]?grant|roles\/grant|identity|token\s+(?:mint|forg|exchange|leak|expos)|revok(?:e|ed|ation)|cookie\s+scope)\b/.test(lower)
  ) {
    roles.add('auth_session')
  }
  if (
    sink === 'upload_storage'
    || sink === 'db_query'
    || /\b(?:transfer|payout|approve|self[- ]?approv|ledger|refund|credit|debit|billing|admin|roles\/grant|export|download|batch|delete|mutat(?:e|ion)|write|state[- ]?(?:machine|change)|creator\/approver|mass\s+assignment|cross[- ]?tenant|bola|bfla|idor|escalat(?:e|ion)|missing\s+authz?)\b/.test(lower)
  ) {
    roles.add('privileged_mutation')
  }
  if (
    /\b(?:async[- ]?worker|background\s+worker|queue|job|export|download|deliver|render(?:er)?|webhook|sse|stream|poll|callback)\b/.test(lower)
  ) {
    roles.add('async_worker')
  }
  if (
    /\b(?:cache[- ]?key|permission[- ]?cache|rbac[- ]?cache|policy[- ]?cache|tenant(?:less)?[- ]?cache|shared[- ]?cache|cache[- ]?(?:prime|priming|poison|deception|bleed)|edge[- ]?cache)\b/.test(lower)
  ) {
    roles.add('cache_permission')
  }
  if (
    /\b(?:request[- ]?pars(?:e|er|ing)|parser[- ]?differential|smuggl(?:e|ing)|desync|path[- ]?normaliz|url[- ]?normaliz|duplicate[- ]?(?:key|param|header)|content[- ]?type\s+(?:mismatch|confusion)|parameter\s+pollution|header\s+override|multipart\s+pars|json\s+pars)\b/.test(lower)
  ) {
    roles.add('request_parsing')
  }
  if (
    /\b(?:concurren(?:t|cy)|race(?:\s+condition|\s+burst)?|toctou|parallel\s+(?:burst|request|settlement)|double[- ]?spend|idempoten(?:cy|t)|over[- ]?credit|settlement|balance\s+conservation|quota\s+bypass|withdrawal\s+race|refund\s+race)\b/.test(lower)
  ) {
    roles.add('concurrent_settlement')
  }
  return roles
}

function compactSuspectCue(text: string, maxLen = 78): string {
  const cleaned = text.replace(/\s+/g, ' ').trim()
  return cleaned.length <= maxLen ? cleaned : `${cleaned.slice(0, maxLen - 1).trimEnd()}…`
}

function selectCrossServiceSiblingLeads(
  anchor: Pick<NormalizedCodeAuditSuspect, 'serviceScope' | 'sinkKind' | 'fileLoc' | 'roles'>,
  pool: readonly NormalizedCodeAuditSuspect[],
  excludeFactIds: ReadonlySet<string>,
  maxSiblings = MAX_CODE_AUDIT_SIBLING_LEADS,
): NormalizedCodeAuditSuspect[] {
  const scored = pool
    .filter(item => !excludeFactIds.has(item.fact.id))
    .map((item, idx) => {
      let score = 0
      if (item.serviceScope !== anchor.serviceScope) score += 4
      if (item.sinkKind !== anchor.sinkKind) score += 3
      if (item.fileLoc && item.fileLoc !== anchor.fileLoc) score += 2
      for (const role of item.roles) {
        if (!anchor.roles.has(role)) {
          score += 2
          break
        }
      }
      if (item.explicitSuspect) score += 1
      return { item, score, idx }
    })
    .sort((a, b) => (b.score - a.score) || (a.idx - b.idx))
  return scored.slice(0, maxSiblings).map(entry => entry.item)
}

function formatCrossServiceSiblingLeadsBlock(siblings: readonly NormalizedCodeAuditSuspect[]): string {
  if (!siblings.length) return ''
  const prefix = 'Cross-Service Sibling Leads (chain across these if composable): '
  const parts: string[] = []
  let totalLen = prefix.length
  for (let i = 0; i < siblings.length; i += 1) {
    const sib = siblings[i]!
    const label = sib.endpointHint || sib.routeOrAction || compactSuspectCue(sib.fact.summary, 48)
    const loc = sib.fileLoc || sib.host
    const cue = compactSuspectCue(sib.fact.summary, 68)
    const entry = `[S${i + 1}] ${label} (${loc}, sink=${sib.sinkKind}): ${cue}`
    const sepLen = parts.length ? 3 : 0
    if (totalLen + sepLen + entry.length > CODE_AUDIT_SIBLING_BLOCK_MAX_CHARS) {
      if (!parts.length) {
        parts.push(entry.slice(0, Math.max(48, CODE_AUDIT_SIBLING_BLOCK_MAX_CHARS - prefix.length)))
      }
      break
    }
    parts.push(entry)
    totalLen += sepLen + entry.length
  }
  return parts.length ? `${prefix}${parts.join(' | ')}` : ''
}

/** Shared composite workflow hypothesis builder for white-box & grey-box causal composites. */
function buildCompositeWorkflowHypothesis(input: {
  hops: readonly { endpoint: string; loc: string; cue: string; roles: ReadonlySet<CompositeWorkflowRole> }[]
  tags?: readonly string[]
  siblingBlock?: string
}): { hopSequence: string; hypothesis: string } {
  const hopEntries = input.hops.map((h, idx) =>
    `Hop ${idx + 1} / Stage ${idx + 1} (${h.endpoint}, ${h.loc}): ${h.cue}`,
  )
  const compRoles = new Set(input.hops.flatMap(h => [...h.roles]))
  const helperHint = compRoles.has('concurrent_settlement')
    ? 'ctx.prove_race_burst + ctx.seal_capability'
    : compRoles.has('signing_webhook')
      ? 'ctx.seal_capability + ctx.hmac_sign/ctx.jwt_sign'
      : compRoles.has('async_worker') || compRoles.has('cache_permission')
        ? 'ctx.seal_capability + ctx.await_async'
        : 'ctx.seal_capability + ctx.hmac_sign/ctx.jwt_sign/ctx.await_async'
  const intermediatePivotStage = input.hops.length === 2 ? [`Stage 3 (pivot via ${helperHint})`] : []
  const terminalStage = 'Terminal Verification (denied control BEFORE Stage 1 -> final readback/state change -> ctx.prove_composite)'
  const hopSequence = [...hopEntries, ...intermediatePivotStage, terminalStage].join(' -> ')
  const stageCount = Math.min(5, Math.max(3, input.hops.length + (input.hops.length === 2 ? 2 : 1)))
  const tagPrefix = [`[chain_hops=${stageCount}]`, '[lane=chain]', ...(input.tags ?? [])].join(' ')
  const parts = [
    `${tagPrefix} Composite workflow (${stageCount} stages): ${hopSequence}.`,
    'Verify ALL stages in ONE kovo_verify script from ONE low-priv persona (never use a target-tenant persona on the probe arm): run clean denied control BEFORE Stage 1, seal via ctx.seal_capability, use ctx.hmac_sign/ctx.jwt_sign/ctx.await_async/ctx.prove_race_burst, and confirm via ctx.prove_composite (fresh_clean_replay) — never stop at an intermediate info-disclosure, job creation, cache prime, or token/link stub.',
  ]
  if (input.siblingBlock) parts.push(input.siblingBlock)
  return { hopSequence, hypothesis: parts.join(' ') }
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
  const promoteMultiHop = options.promoteMultiHop === true

  const normalized: NormalizedCodeAuditSuspect[] = []
  for (const fact of dedupePromotableCodeAuditFacts(suspects)) {
    if (fact.tainted || !approvedOrigins.has(fact.origin)) continue
    const asset = run.candidates.find(c => c.origin === fact.origin && run.approved.includes(c.id))
    if (!asset) continue

    const data = fact.data as Partial<CodeAuditSuspectData> & Record<string, unknown>
    const explicitSuspect = String(fact.kind) === 'code_audit_suspect' || data.subkind === 'code_audit_suspect'
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
    const mapped = sinkCategoryAndSkills(sinkKind)
    const explicitCategory = typeof data.category === 'string' && data.category.trim()
      ? data.category.trim()
      : mapped.category
    const missingAuthOrOwner = /missing|none|weak|bypass|absent|unverified|no |asymmetry|leak|expos|untrusted|forged|spoof/i.test(
      `${authCheck} ${ownershipCheck} ${fact.summary}`,
    )
    const isCrown = (hostTiers?.[fact.origin] ?? classifyHostTier(fact.origin)) === 'crown_jewel'
    const serviceScope = inferServiceScopeFromSuspect(fileLoc, endpointHint, fact.origin)
    const roles = classifyCodeAuditChainRoles({
      sinkKind,
      text: `${fact.summary} ${hypothesisBody} ${endpointHint} ${fileLoc}`,
    })

    normalized.push({
      id: fact.id,
      origin: fact.origin,
      endpoint: endpointHint || routeOrAction || compactSuspectCue(fact.summary, 36),
      summary: fact.summary,
      factId: fact.id,
      fact,
      asset,
      explicitSuspect,
      routeOrAction,
      endpointHint,
      fileLoc,
      serviceScope,
      hypothesisBody,
      sinkKind,
      authCheck,
      ownershipCheck,
      explicitCategory,
      mappedSkills: mapped.skills,
      isCrown,
      missingAuthOrOwner,
      host,
      roles,
    })
  }

  // 1. Delegate multi-service composite synthesis + CapabilityLedger seeding to graph-coordinator.ts.
  if (promoteMultiHop && normalized.length >= 2 && maxSteps > 0) {
    const composites: PlannedCompositeWorkflow<NormalizedCodeAuditSuspect>[] = planCompositeWorkflows(normalized, {
      maxComposites: Math.min(MAX_SYNTHESIZED_CODE_AUDIT_COMPOSITE_STEPS, maxSteps),
      mode: 'whitebox',
      ledger: storage.capabilityLedger(run.id),
    })
    for (const comp of composites) {
      if (created.length >= maxSteps || totalSteps >= hardChainStepsCeiling) break
      const title = `${COMPOSITE_CODE_AUDIT_TITLE_PREFIX} ${comp.label} (${comp.hops[0]!.host})`
      if (existingTitles.has(title.toLowerCase())) continue

      const hopFactIds = comp.hops.map(h => h.fact.id)
      const remainingSiblings = selectCrossServiceSiblingLeads(
        comp.hops[comp.hops.length - 1]!,
        normalized,
        new Set(hopFactIds),
        Math.max(0, MAX_CODE_AUDIT_SIBLING_LEADS - Math.max(0, hopFactIds.length - 1)),
      )
      const { hopSequence, hypothesis } = buildCompositeWorkflowHypothesis({
        hops: comp.hops.map(h => ({
          endpoint: h.endpoint,
          loc: h.fileLoc || h.host,
          cue: compactSuspectCue(h.hypothesisBody, 48),
          roles: h.roles,
        })),
        siblingBlock: formatCrossServiceSiblingLeadsBlock(remainingSiblings),
      })
      const dependsOnFactIds = [
        ...new Set([...hopFactIds, ...remainingSiblings.map(s => s.fact.id)]),
      ].slice(0, MAX_CODE_AUDIT_SIBLING_LEADS + 1)
      const sourceOrigins = [...new Set(comp.hops.map(h => h.fact.origin))]
      const targetAssetIds = [...new Set(comp.hops.map(h => h.asset.id))]
      const skills = [...new Set(['source-first-audit', 'multihop-chains', 'chain-primitives', ...comp.hops.flatMap(h => h.mappedSkills)])]
      const specialistProfile = routeStepToSpecialist({
        title,
        hypothesis: hopSequence,
        category: comp.category,
        skills,
        endpoint: comp.hops[0]!.endpointHint,
        sinkKind: comp.hops[0]!.sinkKind,
      })

      const step = storage.addChainStep(run, {
        title,
        hypothesis,
        category: comp.category,
        priority: comp.priority,
        targetAssetIds,
        skills,
        dependsOnFactIds,
        sourceOrigins,
        specialistProfile,
      })
      existingTitles.add(title.toLowerCase())
      created.push(step)
      totalSteps += 1
    }
  }

  // 2. Emit individual targeted steps for the remaining budget, enriching each Wave-1 multi-hop
  //    step with a compact Cross-Service Sibling Leads block + sibling dependsOnFactIds.
  for (const item of normalized) {
    if (created.length >= maxSteps) break
    if (totalSteps >= hardChainStepsCeiling) break
    if (coveredFactIds.has(item.fact.id)) continue

    const title = item.routeOrAction
      ? `Source audit verify · ${item.routeOrAction.slice(0, 90)} (${item.host})`
      : `Source audit verify · ${item.fact.summary.slice(0, 80)} (${item.host})`
    if (existingTitles.has(title.toLowerCase())) continue

    const specialistProfile = routeStepToSpecialist({
      title: `${item.fact.summary} ${title}`,
      hypothesis: item.hypothesisBody,
      category: item.explicitCategory,
      skills: item.mappedSkills,
      endpoint: item.endpointHint,
      sinkKind: item.sinkKind,
    })
    const stepSkills = promoteMultiHop
      ? [...new Set([...item.mappedSkills, 'multihop-chains', 'chain-primitives'])]
      : item.mappedSkills
    const priority = item.missingAuthOrOwner ? (item.isCrown ? 96 : 92) : (item.isCrown ? 90 : 85)

    const siblings = promoteMultiHop
      ? selectCrossServiceSiblingLeads(item, normalized, new Set([item.fact.id]), MAX_CODE_AUDIT_SIBLING_LEADS)
      : []
    const siblingBlock = promoteMultiHop ? formatCrossServiceSiblingLeadsBlock(siblings) : ''
    const dependsOnFactIds = promoteMultiHop
      ? [item.fact.id, ...siblings.map(s => s.fact.id)]
      : [item.fact.id]

    const hypothesisParts = [
      `Source-First Code Audit suspect${item.fileLoc ? ` at ${item.fileLoc}` : ''}${item.endpointHint ? ` targeting ${item.endpointHint}` : ''}.`,
      `Auth check: ${item.authCheck}; Ownership check: ${item.ownershipCheck}; Sink: ${item.sinkKind}.`,
      item.hypothesisBody,
      promoteMultiHop
        ? 'Verify ALL stages in ONE cohesive kovo_verify script from ONE starting low-privilege persona (never use a target-tenant persona on the probe arm): run clean denied control BEFORE Stage 1, seal intermediate handles/tokens/keys with ctx.seal_capability, chain across sibling services (using ctx.hmac_sign/ctx.jwt_sign/ctx.await_async/ctx.prove_race_burst as needed), and confirm the full DAG via ctx.prove_composite (Mode A fresh_clean_replay) — never stop at an intermediate info-disclosure, job creation, cache prime, or token/link stub.'
        : 'Verify live reachability via kovo_verify with a negative control + differential probe (and cross-persona BOLA check if Tier >= 2).',
    ]
    if (siblingBlock) hypothesisParts.push(siblingBlock)

    const step = storage.addChainStep(run, {
      title,
      hypothesis: hypothesisParts.join(' '),
      category: item.explicitCategory,
      priority,
      targetAssetIds: [item.asset.id],
      skills: stepSkills,
      dependsOnFactIds,
      sourceOrigins: [item.fact.origin],
      specialistProfile,
    })
    existingTitles.add(title.toLowerCase())
    coveredFactIds.add(item.fact.id)
    created.push(step)
    totalSteps += 1
  }

  return created
}

const COMPOSITE_RUNTIME_TITLE_PREFIX = 'Runtime composite chain ·'

export interface RuntimeCompositeApiDependencyInput {
  producer: string
  consumer: string
  resourceKey: string
  producerOrigin?: string
  consumerOrigin?: string
  personaHandle?: string | null
}

export interface SynthesizeRuntimeCompositeWave1Options {
  /** Only synthesize runtime grey-box composites when repository source is NOT mounted. */
  sourceMounted: boolean
  facts?: readonly Fact[]
  endpoints?: readonly Pick<EndpointRow, 'id' | 'origin' | 'method' | 'pathTemplate' | 'authRequirement' | 'riskScore' | 'source' | 'sinkKinds'>[]
  apiDependencies?: readonly RuntimeCompositeApiDependencyInput[]
  specs?: ReadonlyArray<{ kind: string; origin?: string | null; content: string }>
  hostTiers?: Record<string, HostTier>
  maxSteps?: number
}

interface NormalizedRuntimeHopCandidate extends CompositeWorkflowNode {
  key: string
  host: string
  asset: Run['candidates'][number]
  cue: string
  mappedSkills: string[]
  isCrown: boolean
  priorityScore: number
}

/**
 * Grey-box counterpart to WB's `convertCodeAuditSuspectsToChainSteps` composite synthesis:
 * when `!sourceMounted`, synthesize up to `MAX_SYNTHESIZED_RUNTIME_COMPOSITE_STEPS` (default 2)
 * generic cross-origin / producer->consumer composite Wave-1 `ChainStep`s from persisted runtime
 * facts, endpoints, API dependencies, and OpenAPI/GraphQL specs (matching WB's `Composite workflow
 * (3-5 stages)` dispatch shape without any source-code dependence or benchmark literals).
 */
export function synthesizeRuntimeCompositeWave1Steps(
  storage: Store,
  run: Run,
  options: SynthesizeRuntimeCompositeWave1Options,
): ChainStep[] {
  if (options.sourceMounted) return []
  const maxSteps = Math.max(0, Math.min(
    options.maxSteps !== undefined ? Math.floor(options.maxSteps) : MAX_SYNTHESIZED_RUNTIME_COMPOSITE_STEPS,
    MAX_SYNTHESIZED_RUNTIME_COMPOSITE_STEPS,
  ))
  if (maxSteps <= 0) return []

  const assetByOrigin = new Map<string, Run['candidates'][number]>()
  for (const cand of run.candidates) {
    if (run.approved.includes(cand.id) && !assetByOrigin.has(cand.origin)) {
      assetByOrigin.set(cand.origin, cand)
    }
  }
  if (assetByOrigin.size === 0) return []

  const existingSteps = storage.listChainSteps(run.id, run.goalRevision)
  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
  const existingRuntimeComposites = existingSteps.filter(s =>
    s.title.startsWith(COMPOSITE_RUNTIME_TITLE_PREFIX),
  ).length
  const remainingCompositeBudget = Math.max(0, maxSteps - existingRuntimeComposites)
  let totalSteps = existingSteps.length
  if (remainingCompositeBudget <= 0 || totalSteps >= hardChainStepsCeiling) return []

  const candidates: NormalizedRuntimeHopCandidate[] = []
  const seenKeys = new Set<string>()
  const hostOfOrigin = (origin: string): string => {
    try { return new URL(origin).hostname.toLowerCase() } catch { return origin.toLowerCase() }
  }

  const pushCandidate = (input: {
    origin: string
    endpoint: string
    cue: string
    sinkKind?: string
    factId?: string
    resourceKey?: string
    isApiDep?: boolean
    extraText?: string
    baseScore?: number
  }): void => {
    const asset = assetByOrigin.get(input.origin)
    if (!asset) return
    const endpoint = input.endpoint.trim()
    if (!endpoint) return
    const host = hostOfOrigin(input.origin)
    const combinedText = `${endpoint} ${input.cue} ${input.extraText ?? ''}`
    const sinkKind = input.sinkKind?.trim() || inferSinkKindFromFactText(combinedText)
    const roles = classifyCodeAuditChainRoles({ sinkKind, text: combinedText })
    const key = `${input.origin}|${endpoint.toLowerCase()}|${sinkKind}`
    if (seenKeys.has(key)) return
    seenKeys.add(key)
    const mapped = sinkCategoryAndSkills(sinkKind)
    const isCrown = (options.hostTiers?.[input.origin] ?? classifyHostTier(input.origin)) === 'crown_jewel'
    candidates.push({
      id: key,
      key,
      origin: input.origin,
      host,
      asset,
      serviceScope: inferServiceScopeFromSuspect('', endpoint, input.origin),
      endpoint,
      sinkKind,
      summary: compactSuspectCue(input.cue, 76),
      cue: compactSuspectCue(input.cue, 76),
      mappedSkills: mapped.skills,
      roles,
      ...(input.factId ? { factId: input.factId } : {}),
      ...(input.resourceKey ? { resourceKey: input.resourceKey } : {}),
      ...(input.isApiDep ? { isApiDep: true } : {}),
      isCrown,
      priorityScore: (input.baseScore ?? 50) + (isCrown ? 12 : 0) + roles.size * 6 + (input.isApiDep ? 14 : 0),
    })
  }

  // 1. Collect from runtime API dependencies (highest-signal producer -> consumer links).
  const depPairs: Array<{ prod: NormalizedRuntimeHopCandidate; cons: NormalizedRuntimeHopCandidate; resourceKey: string }> = []
  const defaultOrigin = [...assetByOrigin.keys()][0]!
  for (const dep of (options.apiDependencies ?? []).slice(0, 40)) {
    const prodOrigin = dep.producerOrigin && assetByOrigin.has(dep.producerOrigin) ? dep.producerOrigin : defaultOrigin
    const consOrigin = dep.consumerOrigin && assetByOrigin.has(dep.consumerOrigin) ? dep.consumerOrigin : prodOrigin
    const prodBefore = candidates.length
    pushCandidate({
      origin: prodOrigin,
      endpoint: dep.producer,
      cue: `Producer ${dep.producer} yields resource "${dep.resourceKey}"`,
      resourceKey: dep.resourceKey,
      isApiDep: true,
      extraText: `producer resource ${dep.resourceKey}`,
      baseScore: 76,
    })
    const prodCand = candidates.find(c => c.origin === prodOrigin && c.endpoint === dep.producer.trim())
      ?? (candidates.length > prodBefore ? candidates[candidates.length - 1] : undefined)
    const consBefore = candidates.length
    pushCandidate({
      origin: consOrigin,
      endpoint: dep.consumer,
      cue: `Consumer ${dep.consumer} acts on resource "${dep.resourceKey}"`,
      resourceKey: dep.resourceKey,
      isApiDep: true,
      extraText: `consumer resource ${dep.resourceKey} cross-tenant mutation`,
      baseScore: 78,
    })
    const consCand = candidates.find(c => c.origin === consOrigin && c.endpoint === dep.consumer.trim())
      ?? (candidates.length > consBefore ? candidates[candidates.length - 1] : undefined)
    if (prodCand && consCand && prodCand.key !== consCand.key) {
      depPairs.push({ prod: prodCand, cons: consCand, resourceKey: dep.resourceKey })
    }
  }

  // 2. Collect from non-tainted runtime facts (Phase-0 catalogs, persona resources, det leads, notes).
  for (const fact of options.facts ?? []) {
    if (fact.tainted || !assetByOrigin.has(fact.origin)) continue
    const data = (fact.data ?? {}) as Record<string, unknown>
    const subkind = typeof data.subkind === 'string' ? data.subkind : ''
    if (subkind === 'runtime_spa_routes' && Array.isArray(data.spaRoutes)) {
      for (const raw of data.spaRoutes.slice(0, 12)) {
        if (!raw || typeof raw !== 'object') continue
        const route = raw as { path?: string; serviceOrigin?: string; apiCalls?: Array<{ method?: string; path?: string; serviceOrigin?: string }>; requiredRoles?: string[]; stateActions?: string[] }
        const target = route.apiCalls?.[0]
        const targetOrigin = target?.serviceOrigin && assetByOrigin.has(target.serviceOrigin)
          ? target.serviceOrigin
          : route.serviceOrigin && assetByOrigin.has(route.serviceOrigin)
            ? route.serviceOrigin
            : fact.origin
        const epLabel = target?.path ? `${(target.method ?? 'GET').toUpperCase()} ${target.path}` : (route.path ?? '')
        if (!epLabel) continue
        pushCandidate({
          origin: targetOrigin,
          endpoint: epLabel,
          cue: `SPA route ${route.path ?? epLabel} invokes ${epLabel}${route.requiredRoles?.length ? ` (client roles: ${route.requiredRoles.join(',')})` : ''}`,
          factId: fact.id,
          extraText: `${(route.stateActions ?? []).join(' ')} ${(route.requiredRoles ?? []).join(' ')}`,
          baseScore: 72,
        })
      }
      continue
    }
    if (subkind === 'runtime_graphql_catalog') {
      const cat = data.graphqlCatalog as { endpoint?: string; serviceOrigin?: string; fields?: Array<{ name?: string; kind?: string; requiredRole?: string }> } | undefined
      const gqlOrigin = cat?.serviceOrigin && assetByOrigin.has(cat.serviceOrigin) ? cat.serviceOrigin : fact.origin
      const mut = cat?.fields?.find(f => f.kind === 'mutation') ?? cat?.fields?.[0]
      if (mut?.name) {
        pushCandidate({
          origin: gqlOrigin,
          endpoint: `${(mut.kind ?? 'mutation').toUpperCase()} ${cat?.endpoint ?? '/graphql'}#${mut.name}`,
          cue: `GraphQL ${mut.kind ?? 'operation'} ${mut.name} at ${cat?.endpoint ?? '/graphql'}`,
          factId: fact.id,
          extraText: `${mut.name} ${mut.requiredRole ?? ''} mutation batch graphql`,
          baseScore: 72,
        })
      }
      continue
    }
    const routeFromData = typeof data.endpoint === 'string' && data.endpoint.trim()
      ? `${typeof data.method === 'string' ? `${data.method.toUpperCase()} ` : ''}${data.endpoint.trim()}`
      : typeof data.path === 'string' && data.path.trim()
        ? `${typeof data.method === 'string' ? `${data.method.toUpperCase()} ` : ''}${data.path.trim()}`
        : templatesMentionedInText(fact.summary)[0] ?? ''
    if (!routeFromData) continue
    pushCandidate({
      origin: fact.origin,
      endpoint: routeFromData,
      cue: fact.summary,
      factId: fact.id,
      extraText: `${fact.kind} ${subkind} ${typeof data.field === 'string' ? data.field : ''}`,
      baseScore: fact.kind === 'auth' || fact.kind === 'policy_gap' || fact.kind === 'object_ref' || subkind === 'det_lead' ? 74 : 62,
    })
  }

  // 3. Collect from persisted endpoints (prioritizing cross-origin diversity and high-risk routes).
  const endpoints = options.endpoints ?? storage.listEndpoints(run.id, { limit: 200 })
  for (const ep of endpoints) {
    if (!assetByOrigin.has(ep.origin)) continue
    if (ep.pathTemplate === '/' || /^\/(?:health|healthz|ready|metrics|favicon)/i.test(ep.pathTemplate)) continue
    const label = `${ep.method.toUpperCase()} ${ep.pathTemplate}`
    const authHint = ep.authRequirement ? `auth=${ep.authRequirement}` : 'auth=unspecified'
    pushCandidate({
      origin: ep.origin,
      endpoint: label,
      cue: `Discovered ${label} (${authHint}) on ${hostOfOrigin(ep.origin)}`,
      sinkKind: ep.sinkKinds?.[0],
      extraText: `${authHint} ${(ep.sinkKinds ?? []).join(' ')}`,
      baseScore: ep.riskScore ?? 55,
    })
  }

  // 4. Collect from JSON OpenAPI specs when endpoints/facts are sparse.
  for (const spec of (options.specs ?? []).slice(0, 6)) {
    if (spec.kind !== 'openapi') continue
    const specOrigin = spec.origin && assetByOrigin.has(spec.origin) ? spec.origin : defaultOrigin
    try {
      const parsed = JSON.parse(spec.content) as {
        security?: Array<Record<string, string[]>>
        paths?: Record<string, Record<string, { operationId?: string; summary?: string; security?: Array<Record<string, string[]>> }>>
      }
      for (const [pathKey, methods] of Object.entries(parsed.paths ?? {})) {
        if (!methods || typeof methods !== 'object') continue
        for (const [method, op] of Object.entries(methods)) {
          if (!/^(?:get|post|put|patch|delete)$/i.test(method)) continue
          const label = `${method.toUpperCase()} ${pathKey}`
          const sec = Array.isArray(op?.security) ? op.security : parsed.security
          const authText = Array.isArray(sec) && sec.length === 0 ? 'unauthenticated public' : ''
          pushCandidate({
            origin: specOrigin,
            endpoint: label,
            cue: op?.summary || `OpenAPI ${op?.operationId ?? label} on ${hostOfOrigin(specOrigin)}`,
            extraText: `${op?.operationId ?? ''} ${authText}`,
            baseScore: 60,
          })
        }
      }
    } catch { /* ignore non-JSON spec */ }
  }

  if (candidates.length < 2) return []

  const composites = planCompositeWorkflows(candidates, {
    maxComposites: maxSteps,
    mode: 'runtime',
    depPairs,
    ledger: storage.capabilityLedger(run.id),
  })

  const created: ChainStep[] = []
  for (const comp of composites) {
    if (created.length >= remainingCompositeBudget || totalSteps >= hardChainStepsCeiling) break
    const sourceOrigins = [...new Set(comp.hops.map(h => h.origin))]
    const distinctHosts = [...new Set(comp.hops.map(h => h.host))]
    const hostSuffix = distinctHosts.length >= 2
      ? `${distinctHosts[0]} -> ${distinctHosts[1]}`
      : distinctHosts[0]!
    const title = `${COMPOSITE_RUNTIME_TITLE_PREFIX} ${comp.label} (${hostSuffix})`.slice(0, 180)
    if (existingTitles.has(title.toLowerCase())) continue

    const isCrossOrigin = sourceOrigins.length >= 2
    const hasDep = Boolean(comp.resourceKey || comp.hops.some(h => h.isApiDep))
    const extraTags: string[] = []
    if (comp.resourceKey) extraTags.push(`api_dependency:${comp.resourceKey}`)
    if (isCrossOrigin) extraTags.push(`cross_origin_edge:${sourceOrigins[0]}->${sourceOrigins[1]}`)
    const { hopSequence, hypothesis } = buildCompositeWorkflowHypothesis({
      hops: comp.hops.map(h => ({
        endpoint: h.endpoint,
        loc: h.origin,
        cue: compactSuspectCue(h.cue, 54),
        roles: h.roles,
      })),
      tags: extraTags,
    })

    const skills = [
      ...new Set([
        'multihop-chains',
        'chain-primitives',
        'runtime-composite-chain',
        ...(isCrossOrigin ? ['cross-origin-chain'] : []),
        ...(hasDep ? ['api-dependency'] : []),
        ...comp.hops.flatMap(h => h.mappedSkills),
      ]),
    ]
    const targetAssetIds = [...new Set(comp.hops.map(h => h.asset.id))]
    const dependsOnFactIds = [
      ...new Set(comp.hops.map(h => h.factId).filter((id): id is string => Boolean(id))),
    ].slice(0, MAX_CODE_AUDIT_SIBLING_LEADS + 1)
    const specialistProfile = routeStepToSpecialist({
      title,
      hypothesis: hopSequence,
      category: comp.category,
      skills,
      endpoint: comp.hops[0]!.endpoint,
      sinkKind: comp.hops[0]!.sinkKind,
    })

    const step = storage.addChainStep(run, {
      title,
      hypothesis,
      category: comp.category,
      priority: comp.priority,
      targetAssetIds,
      skills,
      dependsOnFactIds,
      sourceOrigins,
      specialistProfile,
    })
    existingTitles.add(title.toLowerCase())
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

// ============================================================================
// Unified per-run orchestration state (Move O5: replaces 40+ parallel Maps/Sets)
// ============================================================================

export interface RunPlannerErrorState {
  goalRevision: number
  consecutiveErrors: number
  backoffUntil: number
  breakerTripped: boolean
}

export interface RunAgenticLaneJob {
  controller: AbortController
  promise: Promise<void>
  key: string
  assignmentId: string
  allowThreatModelPhase?: boolean
}

export interface RunProofObligationCounts {
  probedRoutes: number
  coveredRoutes: number
  gapRoutes: number
  demandedRoutes: number
  dischargedByGap: number
}

export interface RunGapValidationCounts {
  accepted: number
  rejected: number
  byCode: Record<string, { accepted: number; rejected: number }>
}

export interface RunOobDrainSummary {
  oobDrainMs: number
  promotedLate: number
  remaining: number
}

/**
 * Single cohesive per-run orchestration record (Move O5) consolidating planner, lane, auth, lab,
 * telemetry, staging, and frontier bookkeeping so run disposal reclaims every field atomically.
 */
export interface RunOrchestrationState {
  readonly runId: string
  // Coordinator & planner lifecycle
  coordinatorTask?: ExecCoordinatorTask
  threatModelingTask?: ExecCoordinatorTask
  plannerTask?: ExecCoordinatorTask
  plannerTimerCancel?: () => void
  plannerDirty: boolean
  plannerDoneRound?: number
  plannerErrorState?: RunPlannerErrorState
  dryStreakObserved?: number
  dispatchFunnel?: DispatchFunnelCounts
  strandedReadyEvents?: number
  reinvestigationGuard?: ReinvestigationGuard
  plannerEmptyRounds?: number
  plannerDryRounds?: number
  plannerCompletedAtLastRound?: number
  plannerEvidenceFrontier?: { confirmed: number; primitives: number }
  frontierController?: FrontierWaveController
  frontierDispatcher?: FrontierDispatcher
  invariantsSeeded: boolean
  wave1InvariantChainsPromoted: boolean
  seededHypothesisIds?: Set<string>
  runtimeSynthesisWatermark?: string
  postFloorInvariantsSynced: boolean
  runtimeCompositeSeeded: boolean
  plannerSeenCausalEdges?: Set<string>
  stepIds?: Set<string>
  runLifecycleUnsub?: () => void
  // Auth / lab / floor / vault / trace
  recordedPersonaResources?: Set<string>
  runAuthStarted?: string
  runAuthInFlight?: AbortController
  startedLabRun: boolean
  startedLabHandle?: LabTargetHandle
  agenticLaneJob?: RunAgenticLaneJob
  agenticLaneStopping: boolean
  verificationDraining: boolean
  laneStartedAt?: number
  laneWallMs?: number
  agenticFloorDispatchedAt?: number
  agenticFloorStartedAt?: number
  agenticFloorFinishedAt?: number
  phaseBController?: PhaseBConcurrencyController
  runTrace?: AgentTrace
  capabilityVault?: DerivedCapabilityVault
  detLeadConsumedIds?: Set<string>
  // Phase-B throughput & stall telemetry
  assignmentWalls?: number[]
  completedAssignmentWalls?: number[]
  turnLatencies?: number[]
  earlyExitTurnsSaved?: number
  proofObligation?: RunProofObligationCounts
  gapValidation?: RunGapValidationCounts
  providerStallTurns?: number
  providerStallRetries?: number
  providerStallTimeouts?: number
  providerStallWallSaved?: number
  wallClockRotations?: number
  warmSecretEpoch?: string
  warmPoolPolicyRotations?: number
  // Staging isolation
  stagingTaggedMutations?: number
  stagingUntaggedSkipped?: number
  stagingCleaned?: number
  stagingCreatedEntities?: Set<string>
  stagingGrant?: Grant
  // Sub-keyed run-scoped sets/maps (reclaimed in O(1) on disposeRun)
  prePhase0SeededSteps: Map<string, boolean>
  programGraphLeadsSeeded: Set<string>
  circuitNotified: Set<string>
  deterministicInFlight: Set<string>
  deterministicCompleted: Set<string>
  agenticLaneCompleted: Set<string>
  emittedSealedHandleSets: Map<string, Set<string>>
  detLeadStepKeys: Set<string>
  detLeadGateRejected: Set<string>
  cappedLeadReported: Set<string>
  tierAStepKeys: Set<string>
}

export function createRunOrchestrationState(runId: string): RunOrchestrationState {
  return {
    runId,
    plannerDirty: false,
    invariantsSeeded: false,
    wave1InvariantChainsPromoted: false,
    postFloorInvariantsSynced: false,
    runtimeCompositeSeeded: false,
    startedLabRun: false,
    agenticLaneStopping: false,
    verificationDraining: false,
    prePhase0SeededSteps: new Map(),
    programGraphLeadsSeeded: new Set(),
    circuitNotified: new Set(),
    deterministicInFlight: new Set(),
    deterministicCompleted: new Set(),
    agenticLaneCompleted: new Set(),
    emittedSealedHandleSets: new Map(),
    detLeadStepKeys: new Set(),
    detLeadGateRejected: new Set(),
    cappedLeadReported: new Set(),
    tierAStepKeys: new Set(),
  }
}

type RunBooleanField = NonNullable<{
  [K in keyof RunOrchestrationState]-?: RunOrchestrationState[K] extends boolean ? K : never
}[keyof RunOrchestrationState]>

type RunOptionalField = NonNullable<{
  [K in keyof RunOrchestrationState]-?: undefined extends RunOrchestrationState[K] ? K : never
}[keyof RunOrchestrationState]>

type RunSubMapField<V> = NonNullable<{
  [K in keyof RunOrchestrationState]-?: RunOrchestrationState[K] extends Map<string, V> ? K : never
}[keyof RunOrchestrationState]>

type RunSubSetField = NonNullable<{
  [K in keyof RunOrchestrationState]-?: RunOrchestrationState[K] extends Set<string> ? K : never
}[keyof RunOrchestrationState]>

function extractPrefixedRunId(key: string, delimiter: ':' | '\0'): string {
  const idx = key.indexOf(delimiter)
  return idx > 0 ? key.slice(0, idx) : key
}

export interface DisposeRunStateHooks {
  onStepIds?: (stepIds: ReadonlySet<string>) => void
  onDetLeadConsumedIds?: (factIds: ReadonlySet<string>) => void
}

function makeBackedMap<V>(ops: {
  entries: () => Generator<[string, V], void, unknown>
  get: (key: string) => V | undefined
  has: (key: string) => boolean
  set: (key: string, value: V) => void
  delete: (key: string) => boolean
  clear: () => void
  size: () => number
}): Map<string, V> {
  const entries = () => ops.entries() as unknown as MapIterator<[string, V]>
  const view: Map<string, V> = {
    get size() { return ops.size() },
    get: ops.get,
    has: ops.has,
    set(key, value) { ops.set(key, value); return view },
    delete: ops.delete,
    clear: ops.clear,
    forEach(cb, thisArg) { for (const [k, v] of ops.entries()) cb.call(thisArg, v, k, view) },
    entries,
    *keys(): MapIterator<string> { for (const [k] of ops.entries()) yield k },
    *values(): MapIterator<V> { for (const [, v] of ops.entries()) yield v },
    [Symbol.iterator]: entries,
    [Symbol.toStringTag]: 'Map',
  }
  return view
}

function makeBackedSet(ops: {
  values: () => Generator<string, void, unknown>
  has: (key: string) => boolean
  add: (key: string) => void
  delete: (key: string) => boolean
  clear: () => void
  size: () => number
}): Set<string> {
  const values = () => ops.values() as unknown as SetIterator<string>
  const view = {
    get size() { return ops.size() },
    has: ops.has,
    add(key: string) { ops.add(key); return view },
    delete: ops.delete,
    clear: ops.clear,
    forEach(cb: (v: string, v2: string, s: Set<string>) => void, thisArg?: unknown) {
      for (const v of ops.values()) cb.call(thisArg, v, v, view as unknown as Set<string>)
    },
    *entries(): SetIterator<[string, string]> { for (const v of ops.values()) yield [v, v] },
    keys: values,
    values,
    [Symbol.iterator]: values,
    [Symbol.toStringTag]: 'Set',
  } as unknown as Set<string>
  return view
}

/**
 * Cohesive per-run state store backing `Execution` and `ExecReconPlanner`.
 * Exposes live `Map`/`Set` projection views for legacy external adapters while guaranteeing that
 * a single `disposeRun(runId)` call cancels timers/controllers and reclaims every field atomically.
 */
export class RunOrchestrationStateStore {
  private readonly byRun = new Map<string, RunOrchestrationState>()

  get size(): number { return this.byRun.size }
  has(runId: string): boolean { return this.byRun.has(runId) }
  get(runId: string): RunOrchestrationState | undefined { return this.byRun.get(runId) }
  runIds(): string[] { return [...this.byRun.keys()] }

  ensure(runId: string): RunOrchestrationState {
    let state = this.byRun.get(runId)
    if (!state) {
      state = createRunOrchestrationState(runId)
      this.byRun.set(runId, state)
    }
    return state
  }

  /** Single-call atomic cleanup of all per-run orchestration state, timers, and abort controllers. */
  disposeRun(runId: string, hooks?: DisposeRunStateHooks): boolean {
    const state = this.byRun.get(runId)
    if (!state) return false
    try { state.plannerTimerCancel?.() } catch { /* ignore */ }
    try { state.runAuthInFlight?.abort() } catch { /* ignore */ }
    try { state.agenticLaneJob?.controller.abort(new Error('run disposed')) } catch { /* ignore */ }
    try { state.runLifecycleUnsub?.() } catch { /* ignore */ }
    if (state.stepIds && hooks?.onStepIds) hooks.onStepIds(state.stepIds)
    if (state.detLeadConsumedIds && hooks?.onDetLeadConsumedIds) hooks.onDetLeadConsumedIds(state.detLeadConsumedIds)
    state.frontierDispatcher?.clearStepMeta()
    this.byRun.delete(runId)
    return true
  }

  clear(hooks?: DisposeRunStateHooks): void {
    for (const runId of [...this.byRun.keys()]) this.disposeRun(runId, hooks)
  }

  /** Live `Map<runId, V>` projection over an optional field of `RunOrchestrationState`. */
  mapView<K extends RunOptionalField>(field: K): Map<string, NonNullable<RunOrchestrationState[K]>> {
    type V = NonNullable<RunOrchestrationState[K]>
    const byRun = this.byRun
    return makeBackedMap<V>({
      *entries() {
        for (const [runId, state] of byRun.entries()) {
          const val = state[field]
          if (val !== undefined) yield [runId, val as V]
        }
      },
      size() {
        let n = 0
        for (const state of byRun.values()) if (state[field] !== undefined) n += 1
        return n
      },
      get: runId => byRun.get(runId)?.[field] as V | undefined,
      has: runId => byRun.get(runId)?.[field] !== undefined,
      set: (runId, value) => { (this.ensure(runId) as unknown as Record<string, unknown>)[field] = value },
      delete: runId => {
        const state = byRun.get(runId)
        if (!state || state[field] === undefined) return false
        ;(state as unknown as Record<string, unknown>)[field] = undefined
        return true
      },
      clear: () => {
        for (const state of byRun.values()) (state as unknown as Record<string, unknown>)[field] = undefined
      },
    })
  }

  /** Live `Set<runId>` projection over a boolean flag of `RunOrchestrationState`. */
  setView(field: RunBooleanField): Set<string> {
    const byRun = this.byRun
    return makeBackedSet({
      *values() { for (const [runId, state] of byRun.entries()) if (state[field]) yield runId },
      size() {
        let n = 0
        for (const state of byRun.values()) if (state[field]) n += 1
        return n
      },
      has: runId => Boolean(byRun.get(runId)?.[field]),
      add: runId => { this.ensure(runId)[field] = true },
      delete: runId => {
        const state = byRun.get(runId)
        if (!state || !state[field]) return false
        state[field] = false
        return true
      },
      clear: () => { for (const state of byRun.values()) state[field] = false },
    })
  }

  /** Live `Map<prefixedKey, V>` projection where keys carry `${runId}${delimiter}...`. */
  prefixedMapView<V, K extends RunSubMapField<V>>(field: K, delimiter: ':' | '\0'): Map<string, V> {
    const byRun = this.byRun
    const sub = (key: string) => byRun.get(extractPrefixedRunId(key, delimiter))?.[field] as Map<string, V> | undefined
    return makeBackedMap<V>({
      *entries() {
        for (const state of byRun.values()) yield* (state[field] as Map<string, V>).entries()
      },
      size() {
        let n = 0
        for (const state of byRun.values()) n += (state[field] as Map<string, V>).size
        return n
      },
      get: key => sub(key)?.get(key),
      has: key => Boolean(sub(key)?.has(key)),
      set: (key, value) => { (this.ensure(extractPrefixedRunId(key, delimiter))[field] as Map<string, V>).set(key, value) },
      delete: key => Boolean(sub(key)?.delete(key)),
      clear: () => { for (const state of byRun.values()) (state[field] as Map<string, V>).clear() },
    })
  }

  /** Live `Set<prefixedKey>` projection where keys carry `${runId}${delimiter}...`. */
  prefixedSetView(field: RunSubSetField, delimiter: ':' | '\0'): Set<string> {
    const byRun = this.byRun
    const sub = (key: string) => byRun.get(extractPrefixedRunId(key, delimiter))?.[field] as Set<string> | undefined
    return makeBackedSet({
      *values() {
        for (const state of byRun.values()) yield* (state[field] as Set<string>).values()
      },
      size() {
        let n = 0
        for (const state of byRun.values()) n += (state[field] as Set<string>).size
        return n
      },
      has: key => Boolean(sub(key)?.has(key)),
      add: key => { (this.ensure(extractPrefixedRunId(key, delimiter))[field] as Set<string>).add(key) },
      delete: key => Boolean(sub(key)?.delete(key)),
      clear: () => { for (const state of byRun.values()) (state[field] as Set<string>).clear() },
    })
  }
}
