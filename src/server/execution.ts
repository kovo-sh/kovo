import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { and, asc, eq } from 'drizzle-orm'
import { z } from 'zod'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import {
  assetOrigin,
  assetOriginForEnvironment,
  defaultWorkerConcurrency,
  isLocalLabEnvEnabled,
  maxInlineVerifyRetries,
  maxWorkerConcurrency,
  owaspCategories,
  parseBoardMentions,
  responseCheckIds,
  specialistHandleByProfile,
  specialistProfileByHandle,
  workerHistory,
} from '../domain.ts'
import type {
  AssessmentCheckId,
  BoardAuthorRole,
  BoardMessageKind,
  Candidate,
  CheckCoverage,
  CodeLocation,
  Finding,
  InlineVerifyFeedback,
  OwaspCategory,
  ResponseCheckId,
  ThreatModelSummary,
  VerificationTier,
} from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins } from '../replay-spec.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import { suppliedResponseLabel } from '../report-summary.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import {
  authorizeStateChange,
  computeStateChangeBodyHash,
  hasDeclaredMultipartContentType,
  isLocalLabAutoApprovalOrigin,
  evaluateTier3Approval,
  StateChangeApprovalLedger,
} from './approval-judge.ts'
import type { StateChangeFingerprintInput } from './approval-judge.ts'
import {
  AGENTIC_SPECIALIST_MAX_TURNS,
  AGENTIC_SPECIALIST_WALL_CLOCK_MS,
  agentTurn,
  buildBoardDelta,
  classifyHostTier,
  codeAuditPrompt,
  coordinatorPlannerPrompt,
  coordinatorPrompt,
  createBoardTools,
  defaultCodeAuditMaxTurns,
  detLeadsFromParentFacts,
  filterHandlersForSpecialist,
  injectBoardTurnInstructions,
  listSkills,
  loadSkill,
  resolveSpecialistProfile,
  routeStepToSpecialist,
  selectPreInjectionSkills,
  runAgentSession,
  threatModelPrompt,
  WarmSpecialistController,
  workerInvestigationPrompt,
} from './agent-session.ts'
import type {
  AlreadyConfirmedRef,
  CodeAuditSuspectData,
  DetLeadSummary,
  HostTier,
  PersonaResourceQueueItem,
  RequestHttpArgs,
  RequestHttpRaceArgs,
  UnconfirmedSurfaceRef,
  WorkerToolHandlers,
} from './agent-session.ts'
import { createAgentTraceFromEnv } from './agent-trace.ts'
import type { AgentTrace } from './agent-trace.ts'
import { assertAssignmentBriefSize, buildAssignmentBrief } from './assignment-brief.ts'
import { ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE } from './assignment-brief.ts'
import type { MissionKind } from './assignment-brief.ts'
import {
  BrokerApprovalRequired,
  BrokerCircuitOpen,
  BrokerDenied,
  RequestBroker,
  websocketResultToExchange,
} from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, BrokerRaceBurstResult, Grant, PublicObservation } from './broker.ts'
import { CanaryBroker, scanSecondOrderMarkers } from './canary-broker.ts'
import type { SecondOrderStore } from './canary-broker.ts'
import { hasCuratedAdvisory, queryCves, templateIdsForCves } from './cve-broker.ts'
import {
  checkStructuralDuplicate,
  createProviderLlmCall,
  evaluateSubmissionDedupe,
  extractSpecDedupeFields,
  normalizeEndpointTemplate,
} from './dedupe.ts'
import type { ExistingFindingRef } from './dedupe.ts'
import {
  cleanupStagedEntities,
  extractCreatedId,
  intentFamily,
  runDeterministicEngine,
  stagingProbeTag,
  tagStagingEntityBody,
} from './deterministic-engine.ts'
import type { EngineConfirmed, EngineEndpoint, EngineLead, EnginePersona } from './deterministic-engine.ts'
import { checkCoverage, meetsBaseline, readComparisons, verificationCommand } from './evidence-checks.ts'
import type { EvidenceReview } from './evidence-checks.ts'
import { listMountedRepos, parseDependenciesFromFile, projectReposDir } from './github-connector.ts'
import { LabRunner } from './lab-runner.ts'
import type { LabTargetHandle } from './lab-runner.ts'
import {
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
  resolveProfilePoolForRole,
} from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { generateAndReviewPatch } from './patch-workflow.ts'
import { PersonaAuthManager } from './persona-auth.ts'
import type { PersonaSessionClone } from './persona-auth.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { crawlStateGraph, listEndpointsPaged, runPhase0Recon } from './phase0-recon.ts'
import type { CodeDataflowSlice, CodeToRuntimeHypothesis } from './program-graph.ts'
import {
  consumeBurstInstance,
  planTier3ApprovalTargets,
  registerStateChangeGrant,
} from './tier3-approval.ts'
import type {
  StateChangeApprovalInput,
  StateChangeApprovalTarget,
  Tier3ApprovalPlan,
  Tier3ApprovalRequest,
} from './tier3-approval.ts'
import { drainPendingOob, scheduleFinalReport } from './oob-drain.ts'
import type { OobDrainOptions, OobDrainResult } from './oob-drain.ts'
import { buildOobReceipt, verifyReceipt } from './proof-receipt.ts'
import type { ReceiptOobEvent } from './proof-receipt.ts'
export { DEFAULT_OOB_DRAIN_MS, OOB_DRAIN_POLL_MS, resolveOobDrainMs } from './oob-drain.ts'
import { ProbePlanRegistry, selectRankedProbeTargets } from './probe-plan.ts'
import { graphLeadTargets, seedCodeToRuntimeLeads as seedGraphLeads } from './graph-leads.ts'
import {
  createGraphCoordinator,
  decideNext,
} from './graph-coordinator.ts'
import type {
  ChainHypothesis,
  CoordinatorDeps,
  CoordinatorEndpoint,
  CoordinatorProgramGraph,
  DispatchPlan,
  DispatchStepInput,
  GraphCoordinator,
  SchedulerDecision,
} from './graph-coordinator.ts'
import { cloneWorkerPersona } from './session-isolation.ts'
import type { Phase0GraphwireExtras, Phase0ProbePlanSummary } from './probe-plan.ts'
export { selectRankedProbeTargets } from './probe-plan.ts'
export type { Phase0GraphwireExtras, Phase0ProbePlanSummary } from './probe-plan.ts'

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
import { BudgetExceededError } from './provider.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import {
  buildInlineVerifyFeedback,
  retestReplaySpec,
  verifyReplaySpec,
  verifyReplaySpecInline,
} from './replay-verifier.ts'
import { alignClaimClass } from './oracle-invariants.ts'
import { responseReview } from './response-checks.ts'

/**
 * A finding's declared class can disagree with what the proof actually showed (the common case:
 * a protected-field overpost reported as BOLA). The verifier records the verified `evidenceClass`;
 * align the persisted finding with it so the report and the benchmark see the class the evidence
 * supports. Authorization evidence never relabels a claim.
 */
function alignFindingForEvidence(
  finding: Finding,
  replay: { evidencePayload?: Record<string, unknown> | null },
): Finding {
  const payload = replay.evidencePayload
  const evidenceClass = payload && typeof payload.evidenceClass === 'string' ? payload.evidenceClass : null
  const label = alignClaimClass({ cwe: finding.cwe, category: finding.category }, evidenceClass)
  if (!label) return finding
  return { ...finding, cwe: label.cwe, category: label.category }
}
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { approvalRequests, canaries, findings, messages } from './schema.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { tenantTagForRun } from './scope-policy.ts'
import { dedupeCodeAuditSuspects, runThreeStageSemanticAudit, runVariantSweepForFinding, toChainStepInputs } from './semantic-audit.ts'
import { assessmentAssignments, extractResourceRefsFromExchange, isOpaqueResourceId, store } from './store.ts'
import type {
  Assignment,
  BoardMessageRow,
  ChainStep,
  ExtractedResourceRef,
  Fact,
  PatchProposal,
  ReplaySpecRow,
  ResourceHarvestExchange,
  ResourceSampleRow,
  Run,
  Store,
} from './store.ts'
import { probeDifferential, probeSurface, runSafeTemplates } from './surface-engine.ts'
import type { DifferentialProbeClass } from './surface-engine.ts'
import { LinuxWorkerBackend } from './worker-backend.ts'
import type { WorkerBackend } from './worker-backend.ts'

type Active = {
  assignment: Assignment
  origins: Set<string>
  controller: AbortController
  /** Set when the provider-stream watchdog aborted this assignment (retry once). */
  stallAbort?: boolean
}

type Capture = { observation: PublicObservation | null; note: string }
type ReviewInput = { artifactId?: string; reviews: EvidenceReview[]; policy?: AccessPolicySnapshot }
type CoordinatorTask = { controller: AbortController; goalRevision: number; scopeRevision?: number }

const hardChainStepsCeiling = 300
/** Legacy K=6 label retained for observability tests; it is no longer a halt threshold. */
export const diminishingReturnsDryThreshold = 6


const plannerDebounceMs = 1_200
const intentLeaseMs = 30 * 60_000
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

/**
 * Legacy v5.1 parser: an *unset* flag resolves to `off`. Kept exported and unchanged for callers
 * that pin the old opt-in semantics. `Execution` uses `resolveFloorLaneMode` instead.
 */
export function resolveDeterministicSweepMode(
  option?: boolean | 'always',
  env: NodeJS.ProcessEnv = process.env,
): DeterministicSweepMode {
  if (option === 'always') return 'always'
  if (option === true) return 'on'
  if (option === false) return 'off'
  const raw = env.GUARDIAN_DETERMINISTIC_SWEEP?.trim().toLowerCase()
  if (raw === 'always') return 'always'
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return 'on'
  return 'off'
}

/**
 * v6 Phase 1: the Layer-2 deterministic floor is always-on. An agentic run starts the concurrent
 * lane unless the operator explicitly disables it (`deterministicSweep: false` or
 * `GUARDIAN_DETERMINISTIC_SWEEP=0`). `'always'` additionally bypasses the resumed-run guard.
 * `--no-llm` runs the same engine unrestricted in `driveEngineInvestigation` and never starts the
 * lane, so the floor is present on every run either way.
 */
export function resolveFloorLaneMode(
  option?: boolean | 'always',
  env: NodeJS.ProcessEnv = process.env,
): DeterministicSweepMode {
  if (option === 'always') return 'always'
  if (option === false) return 'off'
  if (option === true) return 'on'
  const raw = env.GUARDIAN_DETERMINISTIC_SWEEP?.trim().toLowerCase()
  if (raw === 'always') return 'always'
  if (raw === '0' || raw === 'off' || raw === 'false' || raw === 'no') return 'off'
  return 'on'
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
}

/**
 * Deterministic v6/v7 scheduler guard: budget, requests, wall clock, K=2 empty rounds,
 * improving-round precision stop, and done+OOB drain.
 *
 * The precision stop (v7) ends the planner when the high-priority queue is drained *and* two
 * consecutive rounds produced no new runtime_confirmed finding and no new chain primitive. Budget,
 * request, wall-clock and OOB-drain rules still take precedence, so late callbacks are never lost.
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

/** Map chained hypotheses onto validated dispatch inputs (ordered by the planner's ranking). */
export function chainHypothesisDispatchSteps(hypotheses: readonly ChainHypothesis[]): DispatchStepInput[] {
  return hypotheses.map(hypothesis => ({
    hypothesis: `${hypothesis.title} — ${hypothesis.rationale}`.slice(0, 1200),
    origins: hypothesis.chainOrigins,
    capabilities: hypothesis.capabilities,
    parentEvidenceIds: hypothesis.parentEvidenceIds,
    ...(hypothesis.probeClasses.length ? { probeClass: hypothesis.probeClasses[0] } : {}),
    skills: [...new Set([...hypothesis.primitiveKinds.map(kind => `chain:${kind}`), 'chain-primitives', ...hypothesis.probeClasses])],
    priority: Math.round(hypothesis.confidence * 100),
  }))
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
const compactText = (value: string, max = 160): string =>
  value.length <= max ? value : `${value.slice(0, max - 1)}…`
const compactChainTitle = (hypothesis: string): string => {
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
      return 'dry_rounds'
    case 'coordinator_done':
      return 'coordinator_done'
    case 'budget_exhausted':
      return 'budget_exhausted'
    case 'requests_exhausted':
      return 'requests_exhausted'
    case 'wallclock_exhausted':
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
  let surplus = multiTrialSurplusSlots(queued.length, concurrency)
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
}): DispatchStopEvaluation {
  const stopReason = normalizeDispatchStopReason(input.reason)
  const remainingReady = Math.max(0, Math.floor(input.remainingReady))
  if (input.decision !== 'stop') {
    return { decision: 'continue', stopReason, remainingReady, deferred: false, stranded: false }
  }
  const exhausted = input.budgetExhausted === true || input.requestExhausted === true || input.wallExhausted === true
  const guarded = STRANDED_READY_STOP_REASONS.includes(stopReason)
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

/** Non-lead lanes in round-robin order. Leads are seeded first, capped, then these cycle. */
export const DISPATCH_LANE_ORDER: readonly Exclude<DispatchLane, 'lead'>[] = [
  'route', 'workflow', 'business_logic', 'race', 'chain', 'other',
]

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
}

export interface RoundRobinDispatchOptions {
  /** Total concurrent lead assignments allowed (default {@link DET_LEAD_CONCURRENT_CAP}). */
  leadCap?: number
  /** Lead assignments already in flight; subtracted from the cap. */
  activeLeadCount?: number
  /** Host tiers used to order Tier-A/B routes ahead of low-value static hosts. */
  hostTiers?: Record<string, HostTier>
  /** Allow leads past the cap only when no non-lead ready step remains (default true). */
  allowLeadOverflow?: boolean
}

export interface RoundRobinDispatchPlan<T extends DispatchLaneStep> {
  ordered: T[]
  selectedByLane: Record<DispatchLane, number>
  leadCapRemaining: number
  deferredLeads: number
}

/** A det_lead upgrade is identified by its title/hypothesis contract, not by numeric priority. */
export function isDetLeadDispatchStep(step: Pick<DispatchLaneStep, 'title' | 'hypothesis'>): boolean {
  const text = `${step.title} ${step.hypothesis ?? ''}`
  return /\bdet[_ ]lead\b/i.test(text) ||
    /deterministic floor observed an unproven/i.test(text) ||
    /\bunproven\b[^.]{0,80}\blead\b/i.test(text) ||
    /\blead upgrade\b/i.test(text)
}

/** Map a step onto the round-robin lane it competes in. */
export function classifyDispatchLane(
  step: DispatchLaneStep,
  hostTiers?: Record<string, HostTier>,
): DispatchLane {
  if (isDetLeadDispatchStep(step)) return 'lead'
  const text = `${step.title} ${step.hypothesis ?? ''} ${step.category ?? ''} ${(step.skills ?? []).join(' ')}`.toLowerCase()
  if ((step.dependsOnStepIds?.length ?? 0) > 0 || /\bchain\b|second[\s_-]?order|cross[\s_-]?host|escalat/.test(text)) return 'chain'
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

function compareDispatchSteps(a: DispatchLaneStep, b: DispatchLaneStep, hostTiers?: Record<string, HostTier>): number {
  const tier = dispatchTierRank(a, hostTiers) - dispatchTierRank(b, hostTiers)
  if (tier !== 0) return tier
  if (a.priority !== b.priority) return b.priority - a.priority
  if (a.seq !== b.seq) return a.seq - b.seq
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

/**
 * Fill `slots` deterministically: up to the lead cap first, then one step per lane per round so a
 * lead backlog or a single large route lane can never starve the semantic classes. Leads past the
 * cap only run when no non-lead ready step remains.
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
  for (const step of steps) lanes.get(classifyDispatchLane(step, options.hostTiers))!.push(step)
  for (const lane of lanes.values()) lane.sort((a, b) => compareDispatchSteps(a, b, options.hostTiers))

  const leadCap = Math.max(
    0,
    Math.floor(options.leadCap ?? DET_LEAD_CONCURRENT_CAP) - Math.max(0, Math.floor(options.activeLeadCount ?? 0)),
  )
  const ordered: T[] = []
  const leadQueue = lanes.get('lead')!
  while (ordered.length < capacity && leadQueue.length > 0 && selectedByLane.lead < leadCap) {
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

  return {
    ordered,
    selectedByLane,
    leadCapRemaining: Math.max(0, leadCap - selectedByLane.lead),
    deferredLeads: leadQueue.length,
  }
}

/** Endpoint templates named inside free text (title/hypothesis), normalized. */
function templatesMentionedInText(text: string): string[] {
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

const threatModelResponseSchema = z.object({
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

const plannerResponseSchema = z.object({
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

function stripJsonFences(raw: string): string {
  const trimmed = raw.trim()
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed)
  if (fenced) return fenced[1].trim()
  const start = trimmed.indexOf('{')
  const end = trimmed.lastIndexOf('}')
  if (start >= 0 && end > start) return trimmed.slice(start, end + 1)
  return trimmed
}

const hostTierOrder: Record<HostTier, number> = {
  crown_jewel: 0,
  standard: 1,
  low_value_static: 2,
}

function classifyHostHeuristic(asset: Candidate): ThreatModelSummary {
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

/** Env override for the single-step wall cap (bounded to 30–120 s so a slot still turns over). */
export function singleStepWallClockMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.GUARDIAN_SINGLE_STEP_WALL_CLOCK_MS)
  if (!Number.isFinite(raw) || raw <= 0) return SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS
  return Math.max(30_000, Math.min(120_000, Math.round(raw)))
}

export interface AssignmentBudgetInput {
  /** Endpoint templates the step names (see `stepMentionedRoutes`). */
  routes: readonly string[]
  /** Upstream evidence the step cites (`dependsOnFactIds`; the chain signal). */
  parentEvidenceIds: readonly string[]
  dependsOnStepIds: readonly string[]
  /** Race / cross-persona / multi-step evidence work (see `isMultiStepAssignment`). */
  multiStep?: boolean
  baseMaxTurns: number
  baseWallClockMs: number
  singleStepWallClockMs?: number
}

export interface AssignmentBudget {
  kind: 'single_step' | 'chain'
  maxTurns: number
  wallClockMs: number
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
  const chain = input.parentEvidenceIds.length > 0 || input.dependsOnStepIds.length > 0
  const multiStep = input.multiStep === true
  const baseTurns = Math.max(4, Math.floor(input.baseMaxTurns))
  const baseWall = Math.max(20_000, Math.round(input.baseWallClockMs))
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
  providerStallTurns: number
  /** Bounded requeues triggered by the stall watchdog (max one per assignment). */
  providerStallRetries: number
  turnLatencyP50: number
  turnLatencyP90: number
  containersLaunched: number
  containersReused: number
  containerSessions: number
  coldContainerSessions: number
  idleWarmContainers: number
  warmCapacity: number
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

export function convertCodeAuditSuspectsToChainSteps(
  storage: Store,
  run: Run,
  suspects: readonly Fact[],
  hostTiers?: Record<string, HostTier>,
): ChainStep[] {
  const approvedOrigins = new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
  const existingSteps = storage.listChainSteps(run.id, run.goalRevision)
  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
  const coveredFactIds = new Set(existingSteps.flatMap(s => s.dependsOnFactIds))
  const created: ChainStep[] = []
  let totalSteps = existingSteps.length

  for (const fact of dedupeCodeAuditSuspects(suspects)) {
    if (totalSteps >= hardChainStepsCeiling) break
    if (fact.tainted || !approvedOrigins.has(fact.origin)) continue
    if (coveredFactIds.has(fact.id)) continue
    const asset = run.candidates.find(c => c.origin === fact.origin && run.approved.includes(c.id))
    if (!asset) continue

    const data = fact.data as Partial<CodeAuditSuspectData> & Record<string, unknown>
    const routeOrAction = typeof data.routeOrAction === 'string' && data.routeOrAction.trim()
      ? data.routeOrAction.trim()
      : ''
    const endpointHint = typeof data.endpoint === 'string' && data.endpoint.trim()
      ? data.endpoint.trim()
      : routeOrAction
    const fileLoc = typeof data.file === 'string' && data.file.trim()
      ? `${data.file.trim()}${typeof data.line === 'number' ? `:${data.line}` : ''}`
      : ''
    const sinkKind = typeof data.sinkKind === 'string' ? data.sinkKind : 'api_route'
    const authCheck = typeof data.authCheck === 'string' ? data.authCheck : 'unknown'
    const ownershipCheck = typeof data.ownershipCheck === 'string' ? data.ownershipCheck : 'unknown'
    const hypothesisBody = typeof data.hypothesis === 'string' && data.hypothesis.trim()
      ? data.hypothesis.trim()
      : fact.summary

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
    const missingAuthOrOwner = /missing|none|weak|bypass|absent|unverified|no /i.test(`${authCheck} ${ownershipCheck}`)
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
      skills: mapped.skills,
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

/** Backwards-compatible re-export: harvesting lives in `store.ts` so Phase-0/crawl can share it. */
export function extractPersonaResourcesFromExchange(ex: ResourceHarvestExchange): ExtractedResourceRef[] {
  return extractResourceRefsFromExchange(ex)
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


// --- Deterministic (zero-LLM) investigation fallback helpers ---

/** Parameter names worth a differential SQL probe (generic, engine-level — not app-specific). */
const DETERMINISTIC_PARAM_HINT_RE = /^(?:id|uuid|q|query|search|s|filter|sort|order|orderby|where|name|email|slug|path|file|url|uri|host|cmd|exec|template|view|lang|category|type|limit|offset|page|next|redirect|return)$/i
const DETERMINISTIC_NUMERIC_PARAM_RE = /^(?:id|page|limit|offset|qty|quantity|amount|price|count|num|index)$/i
const DETERMINISTIC_ID_SEGMENT_RE = /(?:\/:[a-z_][a-z0-9_]*|\{\{id\}\}|\/[a-z_][a-z0-9_]*\}|\/\[[^\]]+\]|\/\d{2,16}(?=\/|$)|\/[0-9a-f]{8}-[0-9a-f]{4}-)/i
const DETERMINISTIC_PATH_PARAM_RE = /\/:[a-z_][a-z0-9_]*|\/\{\{id\}\}|\/\{[a-z_][a-z0-9_]*\}|\/\[[^\]]+\]/gi

function deterministicQueryParamNames(pathTemplate: string): string[] {
  const qIdx = pathTemplate.indexOf('?')
  if (qIdx < 0) return []
  return pathTemplate
    .slice(qIdx + 1)
    .split('&')
    .map(pair => pair.split('=')[0]?.trim())
    .filter((name): name is string => Boolean(name && /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(name)))
}

function withQueryParam(pathTemplate: string, name: string, value: string): string {
  const base = pathTemplate.split('?')[0]
  return `${base}?${name}=${encodeURIComponent(value)}`
}

function deterministicIdPath(pathTemplate: string): string | null {
  if (!DETERMINISTIC_ID_SEGMENT_RE.test(pathTemplate)) return null
  const replaced = pathTemplate.replace(DETERMINISTIC_PATH_PARAM_RE, '/{{id}}').replace(/\/\d{2,16}(?=\/|$)/, '/{{id}}')
  return replaced.includes('{{id}}') ? replaced : null
}

const DETERMINISTIC_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * Route admission for briefing/OpenAPI references. A read route still needs an injectable
 * parameter or a resource id to be worth a differential probe, but a write route is a real
 * endpoint even when the reference leaks no body fields (body-only create/action routes such as
 * `POST /api/refunds/lines`). Keep those with their declared method instead of dropping them.
 */
function deterministicRouteIsTestable(method: string, pathTemplate: string, hasInjectable: boolean): boolean {
  if (hasInjectable) return true
  if (deterministicIdPath(pathTemplate)) return true
  return DETERMINISTIC_WRITE_METHODS.has(method.toUpperCase())
}

/** Tolerant OpenAPI extraction for specs whose stored text is redacted or truncated. */
function parseTolerantOpenApiTargets(
  content: string,
  defaultOrigin: string,
  approvedOrigins: ReadonlySet<string>,
): Array<{
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
}> {
  const pathKeyRe = /"(\/[A-Za-z0-9_\-{}\/.:$\[\]]{0,200})"\s*:\s*\{/g
  const matches = [...content.matchAll(pathKeyRe)]
  if (!matches.length) return []
  const out: Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }> = []
  for (let idx = 0; idx < matches.length; idx += 1) {
    const match = matches[idx]
    const pathTemplate = match[1]
    if (!pathTemplate.startsWith('/')) continue
    const start = (match.index ?? 0) + match[0].length
    const end = idx + 1 < matches.length ? (matches[idx + 1].index ?? content.length) : content.length
    const block = content.slice(start, end)
    const methods = [...block.matchAll(/"(get|post|put|patch|delete)"\s*:\s*\{/g)].map(m => m[1].toUpperCase())
    if (!methods.length) continue
    const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
    const paramRe = /"name"\s*:\s*"([A-Za-z0-9_.\-\[\]]{1,64})"[\s\S]{0,200}?"in"\s*:\s*"(query|path|header|formData|body)"/g
    for (const param of block.matchAll(paramRe)) {
      const location = param[2] === 'formData' ? 'form' : param[2] === 'body' ? 'json' : param[2] as 'query' | 'path' | 'header'
      if (!params.some(p => p.name === param[1])) params.push({ name: param[1], location })
    }
    for (const matchPath of pathTemplate.matchAll(/\{([A-Za-z0-9_]+)\}/g)) {
      if (!params.some(p => p.name === matchPath[1])) params.push({ name: matchPath[1], location: 'path' })
    }
    for (const method of methods) {
      const hasInjectable = params.some(p => p.location === 'query' || p.location === 'json' || p.location === 'form')
      if (!deterministicRouteIsTestable(method, pathTemplate, hasInjectable)) continue
      out.push({
        origin: approvedOrigins.has(defaultOrigin) ? defaultOrigin : [...approvedOrigins][0],
        method,
        pathTemplate,
        riskScore: hasInjectable ? 65 : 55,
        params,
      })
    }
  }
  return out.slice(0, 60)
}

/** Shared replay-spec boilerplate for deterministically synthesized specs. */function baseReplaySpecFields(
  _run: Run,
  origin: string,
  overrides: {
    title: string
    category: string
    cwe: string
    severity: Finding['severity']
    severityRationale: string
    impact: string
    remediation: string
    recheckInstructions: string
  },
) {
  return {
    version: 1 as const,
    origin,
    title: overrides.title.slice(0, 200),
    category: overrides.category,
    cwe: overrides.cwe,
    severity: overrides.severity,
    severityRationale: overrides.severityRationale.slice(0, 800),
    impact: overrides.impact.slice(0, 1200),
    remediation: overrides.remediation.slice(0, 1500),
    recheckInstructions: overrides.recheckInstructions.slice(0, 1000),
  }
}

function createBroker(options: { storage: SecondOrderStore; canaryBroker: CanaryBroker }) {
  const target = process.env.GUARDIAN_NETWORK_FIXTURE
  if (!target) {
    return process.env.GUARDIAN_OFFLINE === '1'
      ? new RequestBroker({ resolve: async () => [], storage: options.storage, canaryBroker: options.canaryBroker })
      : new RequestBroker({ storage: options.storage, canaryBroker: options.canaryBroker })
  }
  const fixture = new URL(target)
  if (fixture.origin !== target || fixture.hostname !== '127.0.0.1' || fixture.protocol !== 'http:' || !fixture.port) {
    throw new Error('GUARDIAN_NETWORK_FIXTURE must identify a loopback HTTP origin.')
  }
  return new RequestBroker({
    storage: options.storage,
    canaryBroker: options.canaryBroker,
    source: 'fixture response',
    resolve: async host => host.endsWith('.private-fixture.example')
      ? [{ address: '127.0.0.1', family: 4 }]
      : [{ address: '93.184.216.34', family: 4 }],
    transport: async (url, _address, signal, options) => {
      const reqHeaders: Record<string, string> = {
        ...(options?.headers ?? {}),
        'x-guardian-fixture-target': url.href,
      }
      const response = await fetch(fixture, {
        method: options?.method ?? 'GET',
        headers: reqHeaders,
        body: options?.body,
        signal,
        redirect: 'manual',
      })
      const body = options?.readBody === false ? '' : (await response.text()).slice(0, options?.maxBodyBytes ?? 1024 * 1024)
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body,
        bodyBytes: Buffer.byteLength(body, 'utf8'),
        bodyTruncated: false,
      }
    },
  })
}

/** v6 Phase 1: map a deterministic probe class to the specialist category it best belongs to. */
/**
 * Classify a probe-minted canary purpose (`engine:ssrf:<param> (origin)`, `ssrf:<param>:http
 * (origin)`, `xxe:general_entity (origin)`). Anything else (JWT/JKU, template, auth canaries) is
 * not an async-injection proof and must not be converted into a finding.
 */
export function probeCanaryClass(purpose: string): { vulnClass: 'ssrf' | 'xxe'; origin: string; param: string | null } | null {
  const origin = /\(([^()]+)\)\s*$/.exec(purpose)?.[1]?.trim()
  if (!origin) return null
  const match = /^(?:engine:)?(ssrf|xxe)(?::([^()\s]+))?/.exec(purpose)
  if (!match) return null
  const vulnClass = match[1] as 'ssrf' | 'xxe'
  const segment = match[2] ?? ''
  const variant = new Set(['http', 'dns', 'header', 'custom', 'general_entity', 'param_entity', 'svg_dtd'])
  const param = vulnClass === 'ssrf' && segment && !variant.has(segment)
    ? segment.split(':')[0] ?? null
    : null
  return { vulnClass, origin, param: param || null }
}

function receiptFindingTemplate(vulnClass: 'ssrf' | 'xxe', origin: string, param: string | null) {
  const host = (() => { try { return new URL(origin).hostname } catch { return origin } })()
  if (vulnClass === 'ssrf') {
    return {
      title: `Asynchronous server-side request forgery on ${host}${param ? ` (${param})` : ''}`,
      severity: 'high' as const,
      cwe: 'CWE-918',
      // `Finding.category` is the grader's vulnClass key. A generic OWASP bucket
      // (`ssrf-redirects`) would be scored as an unmatched FP despite the confirmed receipt.
      category: 'ssrf' as const,
      /** Coverage closure keeps the report's OWASP taxonomy. */
      coverageCategory: 'ssrf-redirects' as const,
      impact: 'A server-side fetch of an attacker-controlled URL completes after the HTTP response, so synchronous SSRF filtering and response-time evidence miss it.',
      remediation: 'Resolve and allowlist outbound destinations against a strict scheme/host policy, block metadata and loopback ranges, and perform the fetch inside the request scope so failures are observable.',
      recheck: 'Re-inject the same canary URL and confirm no callback is delivered to the Guardian relay after the response.',
    }
  }
  return {
    title: `Asynchronous XML external entity fetch on ${host}`,
    severity: 'high' as const,
    cwe: 'CWE-611',
    // Canonical vulnClass key (not the generic `injection-input` bucket).
    category: 'xxe' as const,
    coverageCategory: 'injection-input' as const,
    impact: 'An external entity is resolved by a background worker after the upload/preview response, enabling internal file or HTTP exfiltration.',
    remediation: 'Disable DTD and external entity resolution in the XML parser and process imports synchronously with a non-network resolver.',
    recheck: 'Re-submit the same DOCTYPE entity document and confirm the collector receives no request after the response.',
  }
}

function detLeadCategory(probeClass: string): string {
  switch (probeClass) {
    case 'authz_matrix': return 'broken-access-control'
    case 'sqli_boolean':
    case 'sqli_time_diff':
    case 'sql_boolean_diff':
    case 'sql_time_diff':
    case 'ssti_math': return 'injection'
    case 'xss_context':
    case 'stored_xss': return 'xss'
    case 'ssrf_canary': return 'ssrf'
    case 'xxe_canary': return 'xxe'
    case 'command_injection': return 'command-injection'
    case 'path_traversal_benign': return 'path-traversal'
    case 'workflow_invariant': return 'business-logic'
    case 'open_redirect_differential': return 'open-redirect'
    case 'csrf_state_change': return 'csrf'
    case 'mass_assignment': return 'mass-assignment'
    case 'graphql_audit': return 'broken-access-control'
    case 'cache_poison_deception': return 'misconfig-exposure'
    default: return 'misconfig-exposure'
  }
}

/** v6 Phase 1: map a persisted finding category onto the engine family namespace. */
function confirmedCategoryFamily(category: string): string {
  const raw = category.toLowerCase()
  if (/access-control|authz|bola|bfla|idor/.test(raw)) return 'authz'
  if (/injection/.test(raw)) return 'sqli'
  if (/xss/.test(raw)) return 'xss'
  if (/ssrf/.test(raw)) return 'ssrf'
  if (/xxe/.test(raw)) return 'xxe'
  if (/traversal/.test(raw)) return 'traversal'
  if (/redirect/.test(raw)) return 'redirect'
  if (/mass|overpost/.test(raw)) return 'mass_assign'
  if (/csrf/.test(raw)) return 'csrf'
  if (/logic|business/.test(raw)) return 'logic'
  if (/disclos|exposure/.test(raw)) return 'disclosure'
  if (/cmdi|command/.test(raw)) return 'cmdi'
  return intentFamily(category)
}

/** v6 Phase 1: the skills a det_lead upgrade assignment should pre-inject. */
function detLeadSkills(probeClass: string): string[] {
  switch (probeClass) {
    case 'authz_matrix':
    case 'graphql_audit': return ['bola-idor-race', 'false-positive-elimination']
    case 'sqli_boolean':
    case 'sqli_time_diff':
    case 'sql_boolean_diff':
    case 'sql_time_diff': return ['injection-sqli-nosqli', 'false-positive-elimination']
    case 'ssrf_canary': return ['oob-ssrf-browser-chain', 'false-positive-elimination']
    case 'xss_context':
    case 'stored_xss': return ['client-side-xss-postmessage', 'false-positive-elimination']
    case 'workflow_invariant': return ['business-logic-chains', 'false-positive-elimination']
    default: return ['false-positive-elimination']
  }
}

export interface ExecutionOptions {
  broker?: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend?: WorkerBackend
  personaAuth?: PersonaAuthManager
  labRunner?: LabRunner
  /**
   * Explicit `--no-llm` deterministic path. When true the deterministic engine replaces the legacy
   * M1 no-profile fallback. When false (default) the M1 fallback is untouched.
   */
  deterministicOnly?: boolean
  /**
   * v6 Phase 1: run the deterministic floor as a concurrent, isolated sibling lane on **every**
   * agentic run. Default ON; `deterministicSweep: false` (or `GUARDIAN_DETERMINISTIC_SWEEP=0`) is
   * an operator kill switch, and `'always'` bypasses the resumed-run guard. The lane never blocks
   * dispatch, never consumes specialist worker slots, never cancels steps and never hides
   * confirmed routes.
   */
  deterministicSweep?: boolean | 'always'
  /**
   * Wall-clock ceiling the harness will allow for the whole run. The concurrent lane derives its
   * own deadline as `min(240 s, 40% × maxDurationMs)`. Falls back to
   * `GUARDIAN_MAX_DURATION_MS`, then 600 s (which keeps the 240 s lane cap).
   */
  maxDurationMs?: number
  /**
   * Phase/planner-round boundary hook (v5.1 snapshot resume). Called *outside* SQLite
   * transactions with a run id and a boundary label; the harness may capture a checkpoint here.
   * Throwing is swallowed so a best-effort snapshot can never disturb the engine.
   */
  onCheckpoint?: (event: { runId: string; checkpoint: ExecutionCheckpoint }) => void
  /**
   * v6 budget split: per-phase request allowances (see `PhaseRequestBudgets`). Omit both to keep
   * the legacy single shared `run.budgetRequests` behavior. `GUARDIAN_FLOOR_REQUEST_BUDGET` /
   * `GUARDIAN_AGENT_REQUEST_BUDGET` are the env equivalents.
   */
  floorRequestBudget?: number
  agentRequestBudget?: number
}

export type ExecutionCheckpoint = 'phase0' | 'deterministic-lane' | 'post-floor' | 'planner-round'

/** Per-run accounting for the split request budgets (never persisted; telemetry only). */
interface PhaseRequestState {
  floorBudget: number
  agentBudget: number
  /** `run.spentRequests` when the floor started; Phase-A/Phase-B spend are deltas from here. */
  baselineRequests: number
  /** Phase-A requests frozen when the floor settles. */
  floorRequests: number
  floorSettled: boolean
  floorBudgetExhausted: boolean
  agentBudgetExhausted: boolean
  agentExhaustedReported: boolean
  floorExhaustedReported: boolean
  /** Phase-B spend frozen when investigation ends, so verification traffic is not misattributed. */
  agentSettled: boolean
  agentRequests: number
}

export class Execution {
  private readonly storage: Store
  readonly broker: RequestBroker
  readonly browser: ScopedBrowser
  readonly canaryBroker: CanaryBroker
  readonly backend: WorkerBackend
  readonly personaAuth: PersonaAuthManager
  readonly labRunner: LabRunner
  private readonly active = new Map<string, Active>()
  private readonly coordinator = new Map<string, CoordinatorTask>()
  private readonly threatModeling = new Map<string, CoordinatorTask>()
  private readonly plannerTasks = new Map<string, CoordinatorTask>()
  private readonly plannerTimers = new Map<string, NodeJS.Timeout>()
  private readonly plannerDirty = new Set<string>()
  private readonly plannerDoneRound = new Map<string, number>()
  /** runId → last dry-streak length reported as telemetry (never a halt signal in v6). */
  private readonly dryStreakObserved = new Map<string, number>()
  /** Phase-0 ranked probe plans (probe breadth hint; the endpoint store stays lossless). */
  private readonly probePlans = new ProbePlanRegistry()
  /** `${runId}\0${hypothesisId}` leads already persisted as det_lead facts (idempotent seeding). */
  private readonly programGraphLeadsSeeded = new Set<string>()
  /** runId → consecutive planner rounds with zero dispatched work (K=2 diminishing-returns guard). */
  private readonly plannerEmptyRounds = new Map<string, number>()
  /** runId → consecutive rounds with no new runtime_confirmed finding and no new chain primitive. */
  private readonly plannerDryRounds = new Map<string, number>()
  /** runId → last observed (confirmed findings, chain primitives) counts for dry-round accounting. */
  private readonly plannerEvidenceFrontier = new Map<string, { confirmed: number; primitives: number }>()
  /** runId → latest structured dispatch funnel (run meta for the final report / metrics). */
  private readonly dispatchFunnels = new Map<string, DispatchFunnelCounts>()
  /** runId → count of `planner.ready_steps_stranded` violations (never silently tolerated). */
  private readonly strandedReadyEvents = new Map<string, number>()
  /** runId → `(route, class)` reinvestigation guard (v7 precision; cap 2 unless evidence unlocks). */
  private readonly reinvestigationGuards = new Map<string, ReinvestigationGuard>()
  private readonly recordedPersonaResources = new Map<string, Set<string>>()
  private readonly circuitNotified = new Set<string>()
  private readonly runAuthStarted = new Map<string, string>()
  private readonly runAuthInFlight = new Map<string, AbortController>()
  private readonly startedLabRuns = new Set<string>()
  private readonly startedLabHandles = new Map<string, LabTargetHandle>()
  private readonly variantSweptFindings = new Set<string>()
  private readonly variantSweepInFlight = new Set<string>()
  private readonly pendingTier3ApprovalKeys = new Set<string>()
  /** Exact, single-use Tier-3 approvals consumed by the broker fast path (see authorizeStateChange). */
  private readonly stateChangeApprovals = new StateChangeApprovalLedger()
  /**
   * Per-fingerprint instance quota for synchronized multi-request operations (race bursts). A
   * legitimate N-way burst of identical requests registers N single-use instances under the exact
   * same fingerprint; each broker retry consumes one, and the entry disappears after the last.
   * Same 60 s TTL and scope binding as the single-use ledger.
   */
  private readonly burstApprovalInstances = new Map<string, { remaining: number; expiresAt: number }>()
  private readonly deterministicInFlight = new Set<string>()
  private readonly deterministicCompleted = new Set<string>()
  private readonly deterministicOnly: boolean
  /** Slice 3 concurrent lane bookkeeping (never reuses the deterministicInFlight/Completed sets). */
  private readonly deterministicSweep: DeterministicSweepMode
  private readonly maxDurationMs: number
  private readonly prePhase0SeededSteps = new Map<string, boolean>()
  private readonly agenticLaneJobs = new Map<string, { controller: AbortController; promise: Promise<void>; key: string; assignmentId: string }>()
  private readonly agenticLaneCompleted = new Set<string>()
  private readonly agenticLaneStopping = new Set<string>()
  private readonly agenticLaneAssignmentIds = new Set<string>()
  /** runIds whose report is waiting on the bounded pre-report OOB drain (single-flight). */
  private readonly verificationDraining = new Set<string>()
  /** Last drain outcome per run: recorded in run-event meta and exposed for tests/benchmarks. */
  private readonly lastOobDrain = new Map<string, { oobDrainMs: number; promotedLate: number; remaining: number }>()
  /** assignmentId → per-worker composite persona session clones (v6 credential isolation). */
  private readonly workerSessionClones = new Map<string, Array<{ handle: string; clone: PersonaSessionClone }>>()
  /** v6 Phase 1 gate counters (observed inputs, not asserted capability claims). */
  private readonly laneStartedAt = new Map<string, number>()
  private readonly laneWallByRun = new Map<string, number>()
  /** Phase-B throughput telemetry: per-run assignment wall samples and provider turn latencies. */
  private readonly assignmentWallByRun = new Map<string, number[]>()
  /** Wall samples for assignments that actually completed (the slot turned over on its own). */
  private readonly completedAssignmentWallByRun = new Map<string, number[]>()
  private readonly turnLatencyByRun = new Map<string, number[]>()
  private readonly providerStallTurnsByRun = new Map<string, number>()
  private readonly providerStallRetriesByRun = new Map<string, number>()
  private readonly lastAssignmentMetrics = new Map<string, AssignmentThroughputMetrics>()
  /** runId → first agent dispatch time after Phase A, for phase-timing telemetry. */
  private readonly agenticFloorDispatchedAt = new Map<string, number>()
  /** runId → Phase A window (start/finish), retained for finalize-time summaries. */
  private readonly agenticFloorStartedAt = new Map<string, number>()
  private readonly agenticFloorFinishedAt = new Map<string, number>()
  /** v6 budget split: null = legacy single shared budget. */
  private readonly phaseRequestBudgets: PhaseRequestBudgets | null
  private readonly phaseRequestState = new Map<string, PhaseRequestState>()
  /** runId → honest investigation termination reason when a phase budget ends the phase. */
  private readonly phaseTerminationReason = new Map<string, string>()
  private readonly detLeadConsumed = new Set<string>()
  private readonly detLeadStepKeys = new Set<string>()
  /** Facts whose lead contract failed the contrast gate; emit the skip reason once. */
  private readonly detLeadGateRejected = new Set<string>()
  /** det_lead fact ids whose capped reinvestigation was already reported (emit once per fact). */
  private readonly cappedLeadReported = new Set<string>()
  /** Opt-in per-run agentic trace (only populated when GUARDIAN_TRACE_DIR / GUARDIAN_TRACE is set). */
  private readonly runTraces = new Map<string, AgentTrace>()
  private readonly onCheckpoint?: (event: { runId: string; checkpoint: ExecutionCheckpoint }) => void
  /** v5 M5: chain-scoped warm specialist lifecycle (pure in-memory; mirrored to board_members). */
  private readonly warm = new WarmSpecialistController()
  /** v6 staging counters (per run): tagged mutations, locally skipped untaggable probes, cleanup. */
  private readonly stagingTaggedMutations = new Map<string, number>()
  private readonly stagingUntaggedSkipped = new Map<string, number>()
  private readonly stagingCleaned = new Map<string, number>()
  private readonly stagingCreatedEntities = new Map<string, Set<string>>()
  /** runId → grant captured while tagging, so teardown can call the run-scoped cleanup hook. */
  private readonly stagingGrants = new Map<string, Grant>()
  private readonly boardHandleByAssignment = new Map<string, string>()
  private readonly boardAssignmentTokens = new Map<string, number>()
  private readonly boardHandleTokens = new Map<string, number>()
  private readonly wakeHandleByStepId = new Map<string, string>()
  private readonly routedOperatorBoardSeq = new Map<string, number>()
  private readonly wokenBoardMessageKeys = new Set<string>()
  private readonly postedVerdictKeys = new Set<string>()
  private readonly postedCanaryKeys = new Set<string>()
  private readonly boardScopeSync = new Map<string, string>()
  private readonly trackedBoardRuns = new Set<string>()
  private safetyTimer?: NodeJS.Timeout
  private reclaimTimer?: NodeJS.Timeout
  private unsubWake?: () => void
  private wakeScheduled = false
  /** Set by stop(); prevents queued microtasks/timers from touching a closed store. */
  private stopped = false

  constructor(storage: Store, options: ExecutionOptions = {}) {
    this.storage = storage
    this.deterministicOnly = options.deterministicOnly === true
    this.deterministicSweep = resolveFloorLaneMode(options.deterministicSweep)
    const optionMaxDuration = Number(options.maxDurationMs)
    const envMaxDuration = Number(process.env.GUARDIAN_MAX_DURATION_MS)
    this.maxDurationMs = Number.isFinite(optionMaxDuration) && optionMaxDuration > 0
      ? optionMaxDuration
      : Number.isFinite(envMaxDuration) && envMaxDuration > 0
        ? envMaxDuration
        : 600_000
    this.onCheckpoint = options.onCheckpoint
    this.phaseRequestBudgets = resolvePhaseRequestBudgets({
      ...(options.floorRequestBudget !== undefined ? { floorRequestBudget: options.floorRequestBudget } : {}),
      ...(options.agentRequestBudget !== undefined ? { agentRequestBudget: options.agentRequestBudget } : {}),
    })
    this.canaryBroker = options.canaryBroker ?? new CanaryBroker({ storage })
    this.broker = options.broker ?? createBroker({ storage, canaryBroker: this.canaryBroker })
    // `storage` activates second-order canary scanning inside the browser context too.
    this.browser = options.browser ?? new ScopedBrowser(this.broker, { storage })
    this.backend = options.backend ?? new LinuxWorkerBackend({
      workspace: { id: storage.workspace.id, directory: storage.directory },
    })
    this.personaAuth = options.personaAuth ?? new PersonaAuthManager()
    this.labRunner = options.labRunner ?? new LabRunner()
  }

  private isCanaryDnsConfigured(): boolean {
    return Boolean(
      process.env.GUARDIAN_CANARY_DNS_HOST ||
      process.env.GUARDIAN_CANARY_DNS_PORT ||
      process.env.GUARDIAN_CANARY_DNS_DOMAIN,
    )
  }

  private isCanaryListenerConfigured(): boolean {
    return Boolean(
      process.env.GUARDIAN_CANARY_PUBLIC_URL ||
      process.env.GUARDIAN_CANARY_BASE_URL ||
      process.env.GUARDIAN_CANARY_PORT ||
      process.env.GUARDIAN_CANARY_ENABLE === '1' ||
      this.isCanaryDnsConfigured(),
    )
  }

  private parseOriginForRun(run: Run, raw: string): string {
    const project = this.storage.project(run.projectId)
    return assetOriginForEnvironment(project.environment).parse(raw)
  }

  start() {
    if (this.safetyTimer) return
    this.stopped = false
    if (this.isCanaryListenerConfigured()) {
      void this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
    }
    this.unsubWake = this.storage.onWake(() => this.scheduleWake())
    this.safetyTimer = setInterval(() => this.wake(), 2_000)
    this.safetyTimer.unref()
    const reclaim = () => {
      if (this.backend instanceof LinuxWorkerBackend) {
        void this.backend.reclaimInactive().catch(() => { /* retry on next cycle */ })
      }
    }
    reclaim()
    this.reclaimTimer = setInterval(reclaim, 30_000)
    this.reclaimTimer.unref()
    this.scheduleWake()
  }

  async stop() {
    this.stopped = true
    // Finalize the floor summary for every run this engine touched, including runs stopped by the
    // wall-clock/driver before Phase 3 (partial reports). This is the "run finalize" emission the
    // preservation gate reads; per-phase snapshots keep their own reason.
    try {
      const runIds = new Set<string>([
        ...[...this.active.values()].map(job => job.assignment.runId),
        ...this.laneStartedAt.keys(),
        ...this.laneWallByRun.keys(),
        ...this.agenticFloorDispatchedAt.keys(),
      ])
      for (const runId of runIds) {
        try { this.recordFloorMetrics(runId, 'finalize') } catch { /* metrics are best-effort */ }
        try { this.recordAssignmentMetrics(runId, 'finalize') } catch { /* metrics are best-effort */ }
        try { this.recordDispatchFunnelSummary(runId) } catch { /* metrics are best-effort */ }
      }
    } catch { /* store may be unavailable during teardown */ }
    // v6 staging: agent-tool mutations captured a grant while tagging; hand the run tag back to the
    // target's declared cleanup hook so no tagged entity outlives the run. Best-effort only.
    if (this.stagingGrants.size > 0) {
      for (const [runId, grant] of this.stagingGrants) {
        try {
          if ((this.stagingTaggedMutations.get(runId) ?? 0) <= 0) continue
          const removed = await cleanupStagedEntities({
            endpoints: this.storage.listEndpoints(runId),
            runId,
            broker: this.broker,
            grant,
            signal: AbortSignal.timeout(8_000),
            log: (kind, message, data) => {
              try { this.storage.event(runId, kind, message, data ?? {}) } catch { /* run may be gone */ }
            },
          })
          if (removed > 0) this.stagingCleaned.set(runId, (this.stagingCleaned.get(runId) ?? 0) + removed)
          this.storage.event(runId, 'staging.teardown', `Staging teardown cleaned ${removed} tagged entit${removed === 1 ? 'y' : 'ies'}.`, {
            stagingTaggedMutations: this.stagingTaggedMutations.get(runId) ?? 0,
            stagingUntaggedSkipped: this.stagingUntaggedSkipped.get(runId) ?? 0,
            stagingCleaned: this.stagingCleaned.get(runId) ?? 0,
          })
        } catch { /* teardown is best-effort; never block shutdown */ }
      }
      this.stagingGrants.clear()
      this.stagingCreatedEntities.clear()
      this.stagingTaggedMutations.clear()
      this.stagingUntaggedSkipped.clear()
      this.stagingCleaned.clear()
    }
    this.wakeScheduled = false
    this.unsubWake?.()
    this.unsubWake = undefined
    if (this.safetyTimer) { clearInterval(this.safetyTimer); this.safetyTimer = undefined }
    if (this.reclaimTimer) { clearInterval(this.reclaimTimer); this.reclaimTimer = undefined }
    for (const timer of this.plannerTimers.values()) clearTimeout(timer)
    this.plannerTimers.clear()
    for (const job of this.active.values()) job.controller.abort()
    for (const task of this.coordinator.values()) task.controller.abort()
    for (const task of this.threatModeling.values()) task.controller.abort()
    for (const task of this.plannerTasks.values()) task.controller.abort()
    for (const ctrl of this.runAuthInFlight.values()) ctrl.abort()
    this.runAuthInFlight.clear()
    this.runAuthStarted.clear()
    for (const lane of this.agenticLaneJobs.values()) {
      try { lane.controller.abort(new Error('execution stopped')) } catch { /* already aborted */ }
    }
    for (const assignmentId of [...this.workerSessionClones.keys()]) this.disposeWorkerSessions(assignmentId)
    for (const trace of this.runTraces.values()) {
      try { trace.closeTrace() } catch { /* tracing must never break shutdown */ }
    }
    this.runTraces.clear()
    this.agenticLaneJobs.clear()
    this.agenticLaneStopping.clear()
    this.personaAuth.stopAll()
    await this.labRunner.stopAll().catch(() => undefined)
    this.startedLabRuns.clear()
    this.startedLabHandles.clear()
    await this.canaryBroker.stopListener().catch(() => undefined)
  }

  getLabTargetHandle(runId: string): LabTargetHandle | undefined {
    return this.startedLabHandles.get(runId)
  }

  /**
   * Best-effort checkpoint notification. Checkpoints are boundary-only and must never run inside
   * an open SQLite transaction (VACUUM INTO), so callers invoke this after their transaction.
   */
  private notifyCheckpoint(runId: string, checkpoint: ExecutionCheckpoint) {
    this.traceLifecycle(runId, 'checkpoint', { checkpoint })
    if (!this.onCheckpoint) return
    try {
      this.onCheckpoint({ runId, checkpoint })
    } catch { /* snapshot capture is best-effort; never disturb the engine */ }
  }

  /**
   * Opt-in trace writer (v5.1 fast loop). Returns `null` unless GUARDIAN_TRACE_DIR /
   * GUARDIAN_TRACE enabled tracing. Never throws: a trace failure must not disturb a run.
   */
  private ensureRunTrace(
    run: Run,
    profiles: readonly ResolvedModelProfile[] = [],
  ): AgentTrace | null {
    const existing = this.runTraces.get(run.id)
    if (existing) return existing
    try {
      let app = run.id.slice(0, 8)
      try { app = this.storage.project(run.projectId).name } catch { /* project may be gone */ }
      const trace = createAgentTraceFromEnv({
        gitSha: process.env.GUARDIAN_GIT_SHA?.trim() || 'unknown',
        app,
        seed: process.env.GUARDIAN_BENCH_SEED ?? null,
        mode: this.deterministicOnly ? 'deterministic' : 'agentic',
        model: profiles[0]?.model ?? 'none',
      })
      if (!trace) return null
      this.runTraces.set(run.id, trace)
      return trace
    } catch {
      return null
    }
  }

  private traceLifecycle(runId: string, kind: 'lane_start' | 'lane_end' | 'checkpoint' | 'verdict' | 'abort', payload: Record<string, unknown> = {}) {
    const trace = this.runTraces.get(runId)
    if (!trace) return
    try { trace.recordLifecycle(kind, payload) } catch { /* tracing is best-effort */ }
  }

  private tracePlannerDecision(runId: string, payload: {
    roundIdx: number
    factsCount: number
    detLeadsCount: number
    alreadyConfirmedCount: number
    spawnedSteps: number
    k6DryStreak: number
    dynamicStepBudget: number
    durationMs: number
    costUsd: number
    inputStateHash?: string
  }) {
    const trace = this.runTraces.get(runId)
    if (!trace) return
    try {
      trace.recordPlannerDecision({
        roundIdx: payload.roundIdx,
        inputStateHash: payload.inputStateHash ?? '',
        factsCount: payload.factsCount,
        detLeadsCount: payload.detLeadsCount,
        alreadyConfirmedCount: payload.alreadyConfirmedCount,
        spawnedSteps: payload.spawnedSteps,
        k6DryStreak: payload.k6DryStreak,
        dynamicStepBudget: payload.dynamicStepBudget,
        durationMs: payload.durationMs,
        costUsd: payload.costUsd,
      })
    } catch { /* tracing is best-effort */ }
  }

  private scheduleWake() {
    if (this.stopped || this.wakeScheduled) return
    this.wakeScheduled = true
    queueMicrotask(() => {
      this.wakeScheduled = false
      if (this.stopped) return
      this.wake()
    })
  }

  private permitted(run: Run, origin: string) {
    return run.candidates.some(asset => asset.origin === origin && run.approved.includes(asset.id))
  }

  private approvedOriginsSet(run: Run): Set<string> {
    return new Set(run.candidates.filter(asset => run.approved.includes(asset.id)).map(asset => asset.origin))
  }

  private projectReposMount(projectId: string): { reposDir?: string; mountedRepos: string[] } {
    try {
      const dir = projectReposDir(this.storage.directory, projectId)
      const mountedRepos = listMountedRepos(dir)
      return mountedRepos.length > 0 ? { reposDir: dir, mountedRepos } : { mountedRepos: [] }
    } catch {
      return { mountedRepos: [] }
    }
  }

  private authorize(job: Active): boolean {
    let current: Assignment
    let run: Run
    try {
      current = this.storage.worker(job.assignment.id)
      run = this.storage.run(current.runId)
    } catch {
      return false
    }
    if (current.lease !== job.assignment.lease) return false
    if (!['running', 'waiting_approval'].includes(current.status)) return false
    if (current.phase === 'retest') {
      return [...job.origins].every(origin => this.permitted(run, origin))
    }
    return run.status === 'running' &&
      run.phase === current.phase &&
      current.goalRevision === run.goalRevision &&
      [...job.origins].every(origin => this.permitted(run, origin))
  }

  private check(job: Active): Run {
    job.controller.signal.throwIfAborted()
    if (!this.authorize(job)) throw new BrokerDenied('The assignment is no longer authorized.')
    return this.storage.run(job.assignment.runId)
  }

  private currentCoordinator(runId: string, task: CoordinatorTask): boolean {
    try {
      const run = this.storage.run(runId)
      return run.status === 'running' &&
        run.goalRevision === task.goalRevision &&
        (task.scopeRevision === undefined || run.scopeRevision === task.scopeRevision) &&
        !task.controller.signal.aborted
    } catch {
      return false
    }
  }

  private buildGrant(job: Active, run: Run, permittedAtAdmission: ReadonlySet<string>): {
    grant: Grant
    secrets: NamedSecret[]
    currentSecrets: () => NamedSecret[]
  } {
    const project = this.storage.project(run.projectId)
    const resolvedPersonas = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
    // v6: every worker (always-on floor lane and agentic specialists alike) gets its own composite
    // session clone. A logout/rotation in one clone can never 401 a sibling worker.
    const personas = new Map(
      [...resolvedPersonas.entries()].map(([handle, persona]) =>
        [handle, this.clonePersonaForWorker(persona, job.assignment.id)] as const,
      ),
    )
    const secrets = personaSecrets(personas)
    const currentSecrets = () => {
      const latest = personaSecrets(personas)
      const seen = new Set(secrets.map(s => `${s.placeholder}\0${s.value}`))
      for (const item of latest) {
        const key = `${item.placeholder}\0${item.value}`
        if (!seen.has(key)) {
          seen.add(key)
          secrets.push(item)
        }
      }
      return secrets
    }
    const allowLocalLab = project.environment === 'local-lab'

    const grant: Grant = {
      tier: run.capabilityTier,
      maxRpsPerOrigin: run.maxRpsPerOrigin,
      allowLocalLab,
      personas,
      secrets,
      // Second-order canary scanning needs both the store and the minting broker; without these
      // the broker/browser silently skip `scanSecondOrderMarkers`.
      storage: this.storage,
      canaryBroker: this.canaryBroker,
      scopeRevision: run.scopeRevision,
      // v6 Layer-1: every request is evaluated against the run's 3-tier origin policy, and an
      // explicit operator lease (never a body-hash token) authorizes an otherwise-refused route.
      scopePolicy: this.storage.scopePolicy(run),
      // Explicit operator leases authorize otherwise-refused routes for long-lived engagements.
      // Ephemeral local labs keep the exact single-use fingerprint ledger authoritative, so a
      // consumed instance can never be replayed.
      approvalLeases: (origin, method, pathAndQuery) => {
        if (project.environment === 'local-lab') return false
        return this.storage.approvalLeaseAuthorizer(run.id)(origin, method, pathAndQuery)
      },
      mintCanary: (purpose, origin) => {
        const minted = this.canaryBroker.mintCanary(run.id, purpose, origin, {
          storage: this.storage,
          assignmentId: job.assignment.id,
        })
        return { httpUrl: minted.httpUrl, url: minted.url }
      },
      canRead: origin => {
        if (!this.authorize(job)) return false
        const fresh = this.storage.run(run.id)
        return permittedAtAdmission.has(origin) && this.permitted(fresh, origin)
      },
      isStateChangeApproved: (origin, method, pathAndQuery, context) => {
        const fresh = this.storage.run(run.id)
        const localLabAutoApproval =
          project.environment === 'local-lab' &&
          allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1' &&
          fresh.capabilityTier >= 3 &&
          (fresh.approvalPolicy ?? 'auto_review') !== 'strict' &&
          isLocalLabAutoApprovalOrigin(origin)
        const activePatterns = (fresh.approvedEndpointPatterns ?? []).filter(
          p => p.scopeRevision === undefined || p.scopeRevision === fresh.scopeRevision,
        )
        // Skip the safety judge only for the exact request fingerprint (or an explicit operator
        // pattern). Automatic decisions are single-use: a consumed grant can never authorize a
        // later state change on the same origin.
        const verdict = authorizeStateChange({
          runId: run.id,
          origin,
          method,
          pathAndQuery,
          scopeRevision: fresh.scopeRevision,
          context,
          approvedPatterns: activePatterns,
          ledger: this.stateChangeApprovals,
          localLabAutoApproval,
        })
        if (verdict.via === 'local_lab') {
          // Persist the zero-trust audit trail BEFORE the state change leaves the broker:
          // origin-bound local-lab auto-approval is attributed distinctly from rule/judge/yolo.
          this.storage.recordAutoApprovalDecision(fresh, job.assignment, {
            origin,
            method,
            pathAndQuery,
            rationale: `Local-lab Tier-3 state change during step "${job.assignment.stepId ?? 'step'}"`,
            requestPreview: `${method.toUpperCase()} ${origin}${pathAndQuery}`,
            decision: 'approved',
            decidedBy: 'auto-review:local-lab',
            riskLevel: 'medium',
            policyNote: 'Authorized local-lab loopback/lab-internal origin; broker destructive-payload, webshell, SSRF metadata and RPS invariants enforced.',
            secrets: currentSecrets(),
          })
        }
        if (verdict.approved) return true
        // A synchronized burst of identical requests registers one single-use instance per request
        // under the same exact fingerprint; each retry consumes exactly one, never more.
        if (context && this.consumeBurstApprovalInstance({
          runId: run.id,
          origin,
          method,
          pathAndQuery,
          scopeRevision: fresh.scopeRevision,
          personaHandle: context.personaHandle ?? null,
          bodyHash: context.bodyHash,
          body: context.body,
          hasMultipart: context.hasMultipart,
          isRaceBurst: context.isRaceBurst,
          isRceProof: context.isRceProof,
        })) return true
        return false
      },
      audit: (outcome, origin, status) => {
        if (outcome === 'allowed') job.origins.add(origin)
        this.storage.event(run.id, 'broker.' + outcome,
          `Broker ${outcome} for ${new URL(origin).hostname}${status ? ` (${status})` : ''}.`,
          { assignmentId: job.assignment.id, origin, status })
        if (outcome === 'circuit_open') {
          const fresh = this.storage.run(run.id)
          // A `circuit_open` audit also fires for *route-scoped* 5xx cooldowns (a single endpoint
          // returning 5xx, often the target's own response to an approved injection probe). Those
          // are evidence, not target unavailability: only an origin-wide trip may block traffic or
          // pause the run. Pausing on a route trip abandoned every planned step for the rest of the
          // wall clock (the v7 opsportal coverage defect).
          const originWide = this.broker.isCircuitOpen(origin)
          const approvedOrigins = [...this.approvedOriginsSet(fresh)]
          const action = circuitBreakAction({
            originWide, approvedOrigins, trippedOrigin: origin,
            isOpen: candidate => this.broker.isCircuitOpen(candidate),
          })
          if (fresh.status === 'running' && action === 'continue') {
            this.storage.event(run.id, 'broker.route_circuit',
              `Route-level 5xx cooldown on ${new URL(origin).hostname}${status ? ` (${status})` : ''}; dispatch continues.`,
              { assignmentId: job.assignment.id, origin, status })
            return
          }
          if (fresh.status === 'running' && action === 'pause_run') {
            const notifyKey = `${run.id}:${origin}`
            this.storage.setStatus(fresh, 'paused')
            if (!this.circuitNotified.has(notifyKey)) {
              this.circuitNotified.add(notifyKey)
              this.storage.message(run.id, fresh.coordinatorId, 'guardian',
                `Defensive circuit breaker opened for ${origin} due to elevated 5xx/429 responses. Run paused to protect target availability.`)
              this.postBrokerBlocker(fresh, origin, status)
            }
          } else if (fresh.status === 'running' && action === 'block_origin') {
            // Isolate circuit breaker to the affected origin while healthy hosts continue
            for (const st of this.storage.listChainSteps(run.id, fresh.goalRevision)) {
              if ((st.status === 'pending' || st.status === 'ready') &&
                  st.sourceOrigins.length > 0 &&
                  st.sourceOrigins.every(o => o === origin || this.broker.isCircuitOpen(o))) {
                this.storage.updateChainStep(st.id, { status: 'blocked' })
              }
            }
            const notifyKey = `${run.id}:${origin}`
            if (!this.circuitNotified.has(notifyKey)) {
              this.circuitNotified.add(notifyKey)
              this.storage.message(run.id, fresh.coordinatorId, 'guardian',
                `Defensive circuit breaker opened for ${origin} due to elevated 5xx/429 responses. Further traffic to ${origin} is blocked while healthy hosts continue.`)
              this.postBrokerBlocker(fresh, origin, status)
            }
          }
        }
      },
    }
    return { grant, secrets, currentSecrets }
  }

  /**
   * v6 Layer-1 identity isolation: bind one worker to one composite session clone.
   *
   * The clone shares the credential source but keeps its own cookie jar, so a logout/token-swap
   * probe (or a 401-driven rotation) in the floor lane cannot clear a sibling agentic worker's
   * session. The grant reads the clone view lazily, so a coordinated single-flight refresh is
   * visible to every live worker without a shared mutable `.session` file write.
   */
  private clonePersonaForWorker(persona: ResolvedPersona, assignmentId: string): ResolvedPersona {
    const cloned = cloneWorkerPersona(
      persona,
      assignmentId,
      (handle, workerId) => this.personaAuth.cloneSession(handle, workerId),
    )
    if (!cloned) return persona
    const tracked = this.workerSessionClones.get(assignmentId) ?? []
    tracked.push({ handle: cloned.persona.handle, clone: cloned.clone })
    this.workerSessionClones.set(assignmentId, tracked)
    return cloned.persona
  }

  /** Log out one worker's clone without touching siblings (used by logout/rotation probes). */
  logoutWorkerSession(assignmentId: string, handle?: string): number {
    const tracked = this.workerSessionClones.get(assignmentId) ?? []
    let loggedOut = 0
    for (const entry of tracked) {
      if (handle && entry.handle !== handle) continue
      if (entry.clone.isLoggedOut()) continue
      entry.clone.logout()
      loggedOut += 1
    }
    return loggedOut
  }

  private disposeWorkerSessions(assignmentId: string): void {
    const tracked = this.workerSessionClones.get(assignmentId)
    if (!tracked) return
    for (const entry of tracked) entry.clone.dispose()
    this.workerSessionClones.delete(assignmentId)
  }

  // --- v5 M5 Swarm Board wiring -------------------------------------------------

  private boardHost(origin: string): string {
    try { return new URL(origin).hostname } catch { return origin }
  }

  /** Store-level board writes are advisory: a rejected/malformed post must never break the run. */
  private postBoard(run: Run, input: {
    authorHandle: string
    authorRole: BoardAuthorRole
    kind: BoardMessageKind
    body: string
    mentions?: readonly string[]
    refFactIds?: readonly string[]
    refExchangeIds?: readonly string[]
    refFindingIds?: readonly string[]
    refStepId?: string | null
    refApprovalId?: string | null
    sourceOrigins?: readonly string[]
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow | null {
    try {
      this.trackedBoardRuns.add(run.id)
      return this.storage.postBoardMessage(run, input, secrets)
    } catch {
      return null
    }
  }

  private isPeerBoardHandle(handle: string): boolean {
    return !['all', 'system', 'operator', 'coordinator', 'verifier', 'broker', 'canary'].includes(handle)
  }

  /** Plain text (or @coordinator) goes to the legacy coordinator thread; @specialist routes to that peer. */
  private shouldCoordinatorAnswer(content: string): boolean {
    const mentions = parseBoardMentions(content)
    const peers = mentions.filter(handle => this.isPeerBoardHandle(handle))
    return peers.length === 0 || mentions.includes('coordinator')
  }

  private boardBaseHandle(handle: string): string {
    return handle.replace(/-(?:\d+|r\d+)$/, '')
  }

  private boardProfileForHandle(handle: string) {
    return specialistProfileByHandle[this.boardBaseHandle(handle)] ?? null
  }

  private boardMemberMentionable(run: Run, handle: string): boolean {
    const member = this.storage.boardMember(run.id, handle)
    if (member) return member.state !== 'retired'
    return Boolean(this.boardProfileForHandle(handle)) ||
      ['coordinator', 'operator', 'verifier', 'broker', 'canary', 'all'].includes(handle)
  }

  /** Resolve the roster handle for an assignment (mapped at step start, else derived from its step profile). */
  private boardHandleForAssignmentId(run: Run, assignmentId: string): string {
    const mapped = this.boardHandleByAssignment.get(assignmentId)
    if (mapped) return mapped
    const existing = this.storage.listBoardMembers(run.id).find(member => member.activeAssignmentId === assignmentId)
    if (existing) return existing.handle
    try {
      const worker = this.storage.worker(assignmentId)
      const step = worker.stepId
        ? this.storage.listChainSteps(run.id, run.goalRevision).find(candidate => candidate.id === worker.stepId)
        : undefined
      if (step?.specialistProfile) return specialistHandleByProfile[step.specialistProfile]
    } catch { /* assignment may be gone */ }
    return 'coordinator'
  }

  private boardAuthorForAssignmentId(run: Run, assignmentId: string): { handle: string; role: BoardAuthorRole } {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member) return { handle, role: member.role }
    if (handle === 'coordinator') return { handle, role: 'coordinator' }
    if (handle === 'verifier') return { handle, role: 'verifier' }
    return { handle, role: 'specialist' }
  }

  /** Sharded handle allocation: reuse base while free, then base-2..9, then recycle a waiting shard. */
  private allocateBoardHandle(run: Run, profile: NonNullable<ChainStep['specialistProfile']>, step: ChainStep): string {
    const base = specialistHandleByProfile[profile]
    if (step.trialGroupId) return `${base}-${Math.max(1, step.trialIndex + 1)}`
    const members = this.storage.listBoardMembers(run.id)
    if (!members.some(member => member.handle === base)) return base
    for (let shard = 2; shard <= 9; shard += 1) {
      const handle = `${base}-${shard}`
      if (!members.some(member => member.handle === handle)) return handle
    }
    const waiting = members
      .filter(member => member.handle.startsWith(base + '-') && member.state === 'waiting' && !member.activeAssignmentId)
      .sort((a, b) => a.updatedAt - b.updatedAt)[0]
    return waiting?.handle ?? `${base}-r${members.filter(member => member.handle.startsWith(base)).length + 1}`
  }

  /** Deterministic @coordinator brief emitted when a chain step is dispatched. */
  private postCoordinatorBrief(run: Run, step: ChainStep, handle: string, origins: readonly string[]): BoardMessageRow | null {
    if (!this.boardMemberMentionable(run, handle)) return null
    const targets = origins.map(origin => this.boardHost(origin)).join(', ')
    const body = `Brief · ${step.title} [${step.category}] on ${targets}. Hypothesis: ${step.hypothesis}`.slice(0, 900)
    return this.postBoard(run, {
      authorHandle: 'coordinator',
      authorRole: 'coordinator',
      kind: 'brief',
      body,
      mentions: [handle],
      refStepId: step.id,
      sourceOrigins: [...origins],
    })
  }

  /** Deterministic @verifier verdict for inline and Phase-3 Zero-LLM verification. */
  private postVerificationVerdict(run: Run, opts: {
    replaySpecId: string
    findingId?: string | null
    title: string
    status: Finding['status']
    verificationTier?: VerificationTier | null
    feedback?: InlineVerifyFeedback | null
    assignmentId?: string | null
    refStepId?: string | null
    attempt?: number
    secrets?: readonly NamedSecret[]
  }): BoardMessageRow | null {
    const key = `${run.id}:${opts.replaySpecId}:${opts.status}:${opts.findingId ?? ''}:${opts.attempt ?? ''}`
    if (this.postedVerdictKeys.has(key)) return null
    this.postedVerdictKeys.add(key)
    const confirmed = opts.status === 'confirmed' || opts.status === 'static_verified'
    const authorHandle = opts.assignmentId ? this.boardHandleForAssignmentId(run, opts.assignmentId) : 'coordinator'
    const feedback = opts.feedback
    const body = confirmed
      ? `Verdict · ${opts.title.slice(0, 300)} — ${opts.status}${opts.verificationTier ? ` (${opts.verificationTier})` : ''} [spec: ${opts.replaySpecId}${opts.findingId ? `, finding: ${opts.findingId}` : ''}]`
      : [
          `Verdict · spec ${opts.replaySpecId} ${opts.status}:`,
          feedback?.assertionSummary?.observed ?? 'replay did not confirm',
          feedback?.assertionSummary?.expected ? `(expected ${feedback.assertionSummary.expected})` : '',
          feedback?.failedStepId ? `[step: ${feedback.failedStepId}]` : '',
          feedback?.jqError ? `jq=${feedback.jqError.slice(0, 160)}` : '',
        ].filter(Boolean).join(' ').slice(0, 900)
    const mentions = !confirmed && this.boardMemberMentionable(run, authorHandle) ? [authorHandle] : []
    let authorOrigins: string[] = []
    if (opts.assignmentId) {
      try { authorOrigins = this.storage.worker(opts.assignmentId).sourceOrigins } catch { /* assignment may be gone */ }
    }
    const sent = this.postBoard(run, {
      authorHandle: 'verifier',
      authorRole: 'verifier',
      kind: 'verdict',
      body,
      mentions,
      ...(opts.findingId ? { refFindingIds: [opts.findingId] } : {}),
      ...(opts.refStepId ? { refStepId: opts.refStepId } : {}),
      ...(authorOrigins.length ? { sourceOrigins: authorOrigins } : {}),
    }, opts.secrets)
    if (sent) return sent
    // A retired/unknown author handle must not lose the verdict: post without the mention.
    if (!mentions.length) return null
    return this.postBoard(run, {
      authorHandle: 'verifier',
      authorRole: 'verifier',
      kind: 'verdict',
      body,
      ...(opts.findingId ? { refFindingIds: [opts.findingId] } : {}),
      ...(opts.refStepId ? { refStepId: opts.refStepId } : {}),
    }, opts.secrets)
  }

  /** Deterministic @broker blocker for circuit-open / repeated 429 conditions. */
  private postBrokerBlocker(run: Run, origin: string, status?: number): BoardMessageRow | null {
    const reason = status === 429 ? 'HTTP 429 rate limiting' : 'repeated 5xx/429 responses'
    return this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'blocker',
      body: `Blocker · circuit open on ${this.boardHost(origin)} after ${reason}; further traffic to this origin is paused while healthy hosts continue.`,
      mentions: ['all'],
      sourceOrigins: [origin],
    })
  }

  /** Tier-3 gate: pause the warm member and post an approval card linked by refApprovalId. */
  private postApprovalCard(run: Run, assignmentId: string, input: {
    approvalId: string
    origin: string
    method: string
    pathAndQuery: string
    rationale: string
  }, secrets: readonly NamedSecret[] = []): BoardMessageRow | null {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member && member.role === 'specialist') {
      try {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'paused', activeAssignmentId: assignmentId })
        this.warm.register(handle, { sessionId: member.sessionId, state: 'working', lastReadSeq: member.lastReadSeq })
        this.warm.pause(handle, assignmentId)
      } catch { /* roster mirror is best-effort */ }
    }
    return this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'approval',
      body: `Approval required · Tier ${run.capabilityTier} ${input.method.toUpperCase()} ${this.boardHost(input.origin)}${input.pathAndQuery} — ${input.rationale.slice(0, 400)}`,
      mentions: [handle],
      refApprovalId: input.approvalId,
      sourceOrigins: [input.origin],
    }, secrets)
  }

  private postApprovalResolution(run: Run, assignmentId: string, input: {
    approvalId: string
    decision: string
    origin: string
    method: string
    pathAndQuery: string
  }): void {
    const handle = this.boardHandleForAssignmentId(run, assignmentId)
    const member = this.storage.boardMember(run.id, handle)
    if (member && member.role === 'specialist' && member.state === 'paused') {
      try {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'working', activeAssignmentId: assignmentId })
        this.warm.register(handle, { sessionId: member.sessionId, state: 'paused', lastReadSeq: member.lastReadSeq })
        this.warm.resume(handle, assignmentId)
      } catch { /* roster mirror is best-effort */ }
    }
    this.postBoard(run, {
      authorHandle: 'broker',
      authorRole: 'system',
      kind: 'status',
      body: `Tier-3 ${input.decision} · ${input.method.toUpperCase()} ${this.boardHost(input.origin)}${input.pathAndQuery}`,
      mentions: this.boardMemberMentionable(run, handle) ? [handle] : [],
      refApprovalId: input.approvalId,
      sourceOrigins: [input.origin],
    })
  }

  /** Deterministic @canary lead on OOB callbacks and second-order surfaces. */
  private postCanaryLead(run: Run, input: {
    marker?: string
    origin: string
    endpoint?: string
    persona?: string | null
    exchangeId?: string | null
    mediaType?: string | null
    key?: string
  }): BoardMessageRow | null {
    const key = input.key ?? `${run.id}:${input.marker ?? ''}:${input.origin}:${input.endpoint ?? ''}:${input.exchangeId ?? ''}`
    if (this.postedCanaryKeys.has(key)) return null
    this.postedCanaryKeys.add(key)
    const target = /html|render|page|admin/i.test(`${input.endpoint ?? ''} ${input.mediaType ?? ''}`) ? 'browser' : 'injection'
    const body = [
      'Lead · canary surfaced',
      input.endpoint ? `at ${input.endpoint}` : '',
      input.persona ? `via persona ${input.persona}` : '',
      input.mediaType ? `(${input.mediaType})` : '',
      input.exchangeId ? `[exchange: ${input.exchangeId}]` : '',
      '— second-order/cross-persona evidence; treat as a hypothesis until replay-verified.',
    ].filter(Boolean).join(' ').slice(0, 900)
    return this.postBoard(run, {
      authorHandle: 'canary',
      authorRole: 'system',
      kind: 'lead',
      body,
      mentions: [target],
      ...(input.exchangeId ? { refExchangeIds: [input.exchangeId] } : {}),
      sourceOrigins: [input.origin],
    })
  }

  /** Turn-start delta: sanitized peer posts only, plus the cursor to persist atomically. */
  private boardTurnDelta(run: Run, handle: string, lastReadSeq: number): { text: string; cursor: number } {
    const delta = buildBoardDelta({ store: this.storage, run: run.id, handle, lastReadSeq })
    try {
      this.storage.updateBoardMemberState(run.id, handle, { lastReadSeq: delta.cursor })
      this.warm.noteBoardCursor(handle, delta.cursor)
    } catch { /* member may have been retired between turns */ }
    return { text: delta.text, cursor: delta.cursor }
  }

  /** Operator/coordinator intervention resets every member's consecutive peer-hop budget. */
  private resetBoardHops(run: Run): void {
    for (const member of this.storage.listBoardMembers(run.id)) {
      if (member.peerHopsUsed === 0) continue
      try { this.storage.updateBoardMemberState(run.id, member.handle, { peerHopsUsed: 0 }) } catch { /* ignore */ }
    }
    this.warm.noteEvidence()
  }

  /** Retire/sleep warm members on stop, scope revoke, and mirror roster rows into the controller. */
  private syncBoardRoster(run: Run): void {
    this.trackedBoardRuns.add(run.id)
    const signature = `${run.scopeRevision}:${run.status}:${run.phase}`
    if (this.boardScopeSync.get(run.id) !== signature) {
      this.boardScopeSync.set(run.id, signature)
      if (run.status !== 'running' || run.phase === 'complete') {
        for (const member of this.storage.listBoardMembers(run.id)) {
          if (member.role !== 'specialist' || member.state === 'retired') continue
          try { this.storage.retireBoardMember(run, member.handle, `Run ${run.status}.`) } catch { /* ignore */ }
          this.warm.retire(member.handle, `run_${run.status}`)
        }
        this.trackedBoardRuns.delete(run.id)
        return
      } else {
        try {
          const revoked = this.storage.taintBoardMessagesForRevokedOrigins(run.id, this.approvedOriginsSet(run))
          for (const handle of revoked.retiredHandles) this.warm.retire(handle, 'scope_revoked')
        } catch { /* store may be closing */ }
      }
    }
    for (const member of this.storage.listBoardMembers(run.id)) {
      this.warm.register(member.handle, {
        sessionId: member.sessionId,
        state: member.state === 'working' ? 'working' : member.state === 'paused' ? 'paused' : 'waiting',
        turnsUsed: member.turnsUsed,
        postsCount: member.postsCount,
        peerHopsUsed: member.peerHopsUsed,
        lastReadSeq: member.lastReadSeq,
      })
      if (member.state === 'retired') this.warm.retire(member.handle, 'roster_retired')
    }
  }

  /** Operator composer: plain text is handled by the legacy coordinator thread; @handle wakes that peer. */
  private routeOperatorBoardMessages(run: Run): void {
    this.trackedBoardRuns.add(run.id)
    const cursor = this.routedOperatorBoardSeq.get(run.id) ?? 0
    const messages = this.storage.listBoardMessages(run.id, {
      authorHandle: 'operator', sinceSeq: cursor, limit: 100, includeTainted: false,
    })
    if (!messages.length) return
    this.resetBoardHops(run)
    for (const message of messages) {
      const targets = message.mentions.filter(handle => handle !== 'all' && this.isPeerBoardHandle(handle))
      for (const target of targets) this.wakeBoardMember(run, target, message)
    }
    this.routedOperatorBoardSeq.set(run.id, messages[messages.length - 1].seq)
  }

  /** Queue a chain-scoped follow-up step for a woken member (respects budget + workerConcurrency). */
  private wakeBoardMember(run: Run, handle: string, message: BoardMessageRow): ChainStep | null {
    if (run.status !== 'running' || run.phase !== 'investigation') return null
    if (this.storage.checkBudgetExceeded(run.id)) return null
    const profile = this.boardProfileForHandle(handle)
    if (!profile) return null
    const key = `${run.id}:${message.id}:${handle}`
    if (this.wokenBoardMessageKeys.has(key)) return null
    const member = this.storage.boardMember(run.id, handle)
    if (member?.state === 'paused' || member?.state === 'working') return null

    const approved = this.approvedOriginsSet(run)
    const origins = [...new Set([
      ...message.sourceOrigins.filter(origin => approved.has(origin)),
      ...(member?.sourceOrigins ?? []).filter(origin => approved.has(origin)),
    ])]
    if (!origins.length) return null
    const assetIds = run.candidates
      .filter(candidate => run.approved.includes(candidate.id) && origins.includes(candidate.origin))
      .map(candidate => candidate.id)
    if (!assetIds.length) return null

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const pendingWake = steps.some(candidate =>
      this.wakeHandleByStepId.get(candidate.id) === handle &&
      (candidate.status === 'ready' || candidate.status === 'pending'))
    if (pendingWake) return null
    const dynamicBudget = Math.max(1, Math.min(hardChainStepsCeiling, run.dynamicStepBudget ?? computeDynamicStepBudget(this.storage, run.id)))
    if (steps.length >= dynamicBudget) return null

    this.wokenBoardMessageKeys.add(key)
    const step = this.storage.addChainStep(run, {
      title: `Peer handoff · @${handle}`.slice(0, 200),
      hypothesis: `Follow up ${message.kind} from @${message.authorHandle}: ${message.body}`.slice(0, 1200),
      category: 'misconfig-exposure',
      priority: message.kind === 'blocker' ? 92 : 88,
      targetAssetIds: assetIds,
      sourceOrigins: origins,
      dependsOnFactIds: message.refFactIds,
      specialistProfile: profile,
    })
    this.wakeHandleByStepId.set(step.id, handle)
    if (!member) {
      try {
        this.storage.upsertBoardMember(run, {
          handle,
          role: 'specialist',
          specialistProfile: profile,
          state: 'waiting',
          sourceOrigins: origins,
        })
        this.warm.register(handle, { state: 'waiting' })
      } catch { /* roster mirror is best-effort */ }
    }
    this.storage.event(run.id, 'board.wakeup', `@${handle} queued from @${message.authorHandle}'s ${message.kind} (board #${message.seq}).`, {
      handle, messageSeq: message.seq, stepId: step.id,
    })
    this.scheduleWake()
    return step
  }

  /** Sleep (waiting, same session) or retire a warm member after its assignment finishes. */
  private finishBoardMember(run: Run, assignmentId: string): void {
    const handle = this.boardHandleByAssignment.get(assignmentId)
    if (!handle) return
    const tokens = this.boardHandleTokens.get(handle) ?? this.boardAssignmentTokens.get(assignmentId) ?? 0
    this.boardHandleByAssignment.delete(assignmentId)
    this.boardAssignmentTokens.delete(assignmentId)
    let worker: Assignment | undefined
    try { worker = this.storage.worker(assignmentId) } catch { /* deleted */ }
    const succeeded = worker?.status === 'complete'
    const completion = this.warm.completeTurn(handle, { tokensUsed: tokens })
    try {
      if (!succeeded || completion?.state === 'retired') {
        this.warm.retire(handle, completion?.retiredReason ?? 'step_failed')
        this.storage.updateBoardMemberState(run.id, handle, { state: 'retired', activeAssignmentId: null })
        this.boardHandleTokens.delete(handle)
      } else {
        this.storage.updateBoardMemberState(run.id, handle, { state: 'waiting', activeAssignmentId: null })
      }
    } catch { /* roster mirror is best-effort */ }
    if (completion?.closureRequired) {
      const author = this.boardAuthorForAssignmentId(run, assignmentId)
      this.postBoard(run, {
        authorHandle: author.handle,
        authorRole: author.role,
        kind: 'status',
        body: `Closure · @${author.handle}: ${(worker?.outcome ?? 'step complete').slice(0, 700)}`,
        ...(worker?.stepId ? { refStepId: worker.stepId } : {}),
      })
    }
  }

  /**
   * Scan a brokered HTTP exchange (response body + headers) for second-order canary markers.
   * Runs in Execution (not only inside RequestBroker) so injected/custom brokers are covered too.
   */
  /** SQLite endpoint-parameter and API-dependency catalog, resolved to route/method display keys. */
  private endpointGraphCatalog(runId: string): {
    endpointParams: Array<{
      endpoint: string
      origin: string
      method: string
      name: string
      location: string
      inferredType: string | null
      isCsrf: boolean
      isObjectId: boolean
      source: string
    }>
    apiDependencies: Array<{
      producer: string
      consumer: string
      resourceKey: string
      personaHandle: string | null
      testedBola: boolean
    }>
  } {
    const endpoints = this.storage.listEndpoints(runId, { limit: 2000 })
    const byId = new Map(endpoints.map(ep => [ep.id, ep]))
    const endpointParams = this.storage.listEndpointParams(runId).slice(0, 400).map(param => {
      const ep = byId.get(param.endpointId)
      return {
        endpoint: ep ? `${ep.method} ${ep.pathTemplate}` : param.endpointId,
        origin: ep?.origin ?? '',
        method: ep?.method ?? '',
        name: param.name,
        location: param.location,
        inferredType: param.inferredType,
        isCsrf: param.isCsrf,
        isObjectId: param.isObjectId,
        source: param.source,
      }
    })
    const apiDependencies = this.storage.listApiDependencies(runId).slice(0, 200).map(dep => {
      const producer = byId.get(dep.producerEndpointId)
      const consumer = byId.get(dep.consumerEndpointId)
      return {
        producer: producer ? `${producer.method} ${producer.pathTemplate}` : dep.producerEndpointId,
        consumer: consumer ? `${consumer.method} ${consumer.pathTemplate}` : dep.consumerEndpointId,
        resourceKey: dep.resourceKey,
        personaHandle: dep.personaHandle,
        testedBola: dep.testedBola,
      }
    })
    return { endpointParams, apiDependencies }
  }

  /** Persist real per-endpoint coverage for one exercised request. */
  private markEndpointCoverage(
    run: Run,
    origin: string,
    method: string,
    pathAndQuery: string,
    testedClass: string,
  ): void {
    this.storage.noteEndpointProbe({
      runId: run.id,
      scopeRevision: run.scopeRevision,
      origin,
      method,
      pathAndQuery,
      testedClass,
      source: 'surface_probe',
    })
  }

  /** Mark every concrete request embedded in a declarative replay spec as tested. */
  private markReplaySpecCoverage(run: Run, spec: unknown, testedClass: string): void {
    const visited = new Set<unknown>()
    const walk = (node: unknown, depth: number) => {
      if (depth > 8 || !node || typeof node !== 'object') return
      if (visited.has(node)) return
      visited.add(node)
      const record = node as Record<string, unknown>
      if (
        typeof record.origin === 'string' &&
        typeof record.pathAndQuery === 'string' &&
        typeof record.method === 'string'
      ) {
        this.markEndpointCoverage(run, record.origin, record.method, record.pathAndQuery, testedClass)
      }
      for (const value of Object.values(record)) walk(value, depth + 1)
    }
    walk(spec, 0)
  }

  private scanSecondOrderExchange(
    run: Run,
    assignmentId: string,
    res: Pick<BrokerExchangeResult, 'origin' | 'pathAndQuery' | 'personaHandle' | 'mediaType' | 'respHeaders' | 'body'>,
    exchangeId: string | null,
    mediaTypeOverride?: string,
  ) {
    const headerText = Object.entries(res.respHeaders ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')
    const body = typeof res.body === 'string' ? res.body : ''
    if (!body.includes('gn2o_') && !headerText.includes('gn2o_')) return
    const surfaced = scanSecondOrderMarkers({
      text: `${headerText}\n${body}`,
      runId: run.id,
      assignmentId,
      origin: res.origin,
      endpoint: res.pathAndQuery,
      persona: res.personaHandle,
      mediaType: mediaTypeOverride ?? res.mediaType,
      exchangeId,
      storage: this.storage,
    })
    for (const record of surfaced) {
      this.postCanaryLead(run, {
        marker: record.marker,
        origin: res.origin,
        endpoint: res.pathAndQuery,
        persona: res.personaHandle,
        exchangeId,
        mediaType: mediaTypeOverride ?? res.mediaType,
      })
    }
  }

  private consumeBurstApprovalInstance(input: StateChangeFingerprintInput, now = Date.now()): boolean {
    return consumeBurstInstance(this.burstApprovalInstances, input, now)
  }

  private planTier3Approval(
    run: Run,
    requests: ReadonlyArray<Tier3ApprovalRequest>,
    options: { isRaceBurst?: boolean } = {},
  ): Tier3ApprovalPlan {
    return planTier3ApprovalTargets(run, requests, options)
  }

  /**
   * Execute a synchronized race burst, resolving the whole burst with one approval decision.
   * Identical request instances are registered as one single-use grant each, so the legitimate
   * N-way burst is authorized exactly N times without looping through fresh approval cards.
   */
  private async executeApprovedRaceBurst(
    job: Active,
    requests: BrokerHttpRequest[],
    grant: Grant,
    signal: AbortSignal,
    options: {
      stepTitle: string
      rationale?: string
      secrets: readonly NamedSecret[]
      /** Broker entry point (kept in the tool handler so wiring stays visible). */
      execute?: () => Promise<BrokerRaceBurstResult>
    },
  ): Promise<BrokerRaceBurstResult> {
    const execute = options.execute ?? (() => this.broker.executeRaceBurst(requests, grant, signal))
    const run = this.check(job)
    const phaseRemaining = this.phaseRequestRemaining(run)
    if (phaseRemaining !== null && requests.length > phaseRemaining) {
      throw new BudgetExceededError('Race burst would exceed the agent request budget.')
    }
    const approvalPlan = this.planTier3Approval(run, requests, { isRaceBurst: true })
    try {
      return await execute()
    } catch (err) {
      if (!(err instanceof BrokerApprovalRequired)) throw err
      const approval = await this.waitForTier3Approval(job, {
        origin: approvalPlan.primary.origin,
        method: approvalPlan.primary.method,
        pathAndQuery: approvalPlan.primary.pathAndQuery,
        personaHandle: approvalPlan.primary.personaHandle,
        rationale: options.rationale ??
          `Tier 3 concurrent race burst (${requests.length}x) during step "${options.stepTitle}"`,
        requestPreview: JSON.stringify({
          count: requests.length,
          sample: requests[0],
        }, null, 2),
        bodyPreview: approvalPlan.primary.bodyPreview,
        bodyHash: approvalPlan.primary.bodyHash,
        headers: approvalPlan.primary.headers,
        hasMultipart: approvalPlan.primary.hasMultipart,
        isRaceBurst: true,
        approvalInstances: approvalPlan.primary.approvalInstances,
        additionalApprovalTargets: approvalPlan.additional,
        secrets: options.secrets,
      }, signal)
      if (!approval.approved) {
        throw new BrokerDenied(
          approval.deniedReason
            ? `Tier 3 Safety Judge denied race-burst probe: ${approval.deniedReason}`
            : 'Tier 3 race-burst request was denied or expired.',
        )
      }
      return await execute()
    }
  }

  /**
   * Execute a synchronized batch, resolving the whole batch with one approval decision. Items that
   * are already authorized keep working, and the retry registers one single-use instance per
   * state-changing item so a consumed grant never fails the whole batch.
   */
  private async executeApprovedBatch(
    job: Active,
    requests: BrokerHttpRequest[],
    grant: Grant,
    signal: AbortSignal,
    options: {
      stepTitle: string
      rationale?: string
      secrets: readonly NamedSecret[]
      /** Broker entry point (kept in the tool handler so wiring stays visible). */
      execute?: () => Promise<BrokerExchangeResult[]>
    },
  ): Promise<BrokerExchangeResult[]> {
    const execute = options.execute ?? (() => this.broker.executeBatch(requests, grant, signal))
    const run = this.check(job)
    const approvalPlan = this.planTier3Approval(run, requests)
    try {
      return await execute()
    } catch (err) {
      if (!(err instanceof BrokerApprovalRequired)) throw err
      // Broker request preparation runs synchronously for every item before any transport call, so
      // a batch rejected at preparation normally sends nothing. Once the decision registers one
      // exact grant per item, the batch is re-run as a unit; a consumed grant never fails it.
      const approval = await this.waitForTier3Approval(job, {
        origin: approvalPlan.primary.origin,
        method: approvalPlan.primary.method,
        pathAndQuery: approvalPlan.primary.pathAndQuery,
        personaHandle: approvalPlan.primary.personaHandle,
        rationale: options.rationale ??
          `Tier 3 synchronized batch (${requests.length} requests) during step "${options.stepTitle}"`,
        requestPreview: JSON.stringify({
          count: requests.length,
          items: requests.map((request, index) => ({
            index,
            method: request.method,
            origin: request.origin,
            pathAndQuery: request.pathAndQuery,
            persona: request.persona ?? null,
            bodyPreview: request.body?.slice(0, 300) ?? null,
            multipartPartsCount: request.multipartParts?.length ?? 0,
          })),
        }, null, 2),
        bodyPreview: approvalPlan.primary.bodyPreview,
        bodyHash: approvalPlan.primary.bodyHash,
        headers: approvalPlan.primary.headers,
        hasMultipart: approvalPlan.primary.hasMultipart,
        approvalInstances: approvalPlan.primary.approvalInstances,
        additionalApprovalTargets: approvalPlan.additional,
        secrets: options.secrets,
      }, signal)
      if (!approval.approved) {
        throw new BrokerDenied(
          approval.deniedReason
            ? `Tier 3 Safety Judge denied batch probe: ${approval.deniedReason}`
            : 'Tier 3 batch request was denied or expired.',
        )
      }
      return await execute()
    }
  }

  /**
   * Register the exact, single-use grant a decision just authorized. The immediate broker retry
   * consumes it only when origin/method/path/persona/body/flag fingerprint and scope revision match.
   */
  private registerStateChangeApproval(
    run: Run,
    input: StateChangeApprovalInput,
    additional: StateChangeApprovalTarget[] = [],
  ): void {
    registerStateChangeGrant(this.stateChangeApprovals, this.burstApprovalInstances, run, input, additional)
  }

  private async waitForTier3Approval(
    job: Active,
    input: {
      origin: string
      method: string
      pathAndQuery: string
      personaHandle?: string | null
      rationale: string
      requestPreview: string
      bodyPreview?: string | null
      /** Precomputed body/parts digest (must match the broker's computeStateChangeBodyHash). */
      bodyHash?: string | null
      headers?: Record<string, string>
      hasMultipart?: boolean
      isRceProof?: boolean
      isRaceBurst?: boolean
      /** Single-use instances of the primary fingerprint this decision covers (default 1). */
      approvalInstances?: number
      /** Additional exact requests covered by one synchronized decision (e.g. a race burst). */
      additionalApprovalTargets?: Array<{
        origin: string
        method: string
        pathAndQuery: string
        personaHandle?: string | null
        bodyHash?: string | null
        hasMultipart?: boolean
        instances?: number
      }>
      secrets: readonly NamedSecret[]
    },
    signal: AbortSignal,
  ): Promise<{ approved: boolean; deniedReason?: string }> {
    const run = this.check(job)
    const project = this.storage.project(run.projectId)
    if (run.capabilityTier < 3) {
      throw new BrokerDenied('This operation requires Capability Tier 3.')
    }

    // NOTE: local-lab auto-approval is decided exclusively below by evaluateTier3Approval so
    // that every auto-approved action is origin-bound, respects an explicit `strict` policy,
    // and is persisted as an audit record attributed to 'auto-review:local-lab'.

    const activePatterns = (run.approvedEndpointPatterns ?? []).filter(
      p => p.scopeRevision === undefined || p.scopeRevision === run.scopeRevision,
    )
    const evaluation = await evaluateTier3Approval({
      policy: run.approvalPolicy ?? 'auto_review',
      origin: input.origin,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      personaHandle: input.personaHandle ?? null,
      rationale: input.rationale,
      bodyPreview: input.bodyPreview ?? null,
      headers: input.headers,
      hasMultipart: input.hasMultipart,
      isRceProof: input.isRceProof,
      isRaceBurst: input.isRaceBurst,
      environment: project.environment,
      approvedPatterns: activePatterns,
      profiles: resolveProfilePoolForRole('fast', this.storage),
      signal,
      secrets: input.secrets,
      onUsage: usage => {
        this.storage.recordLlmSpend(run.id, {
          usd: usage.costUsd,
          tokens: usage.inputTokens + usage.outputTokens,
        })
      },
    })

    if (evaluation.decision === 'approve') {
      this.storage.recordAutoApprovalDecision(run, job.assignment, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle,
        rationale: input.rationale,
        requestPreview: input.requestPreview,
        decision: 'approved',
        decidedBy: evaluation.decidedBy === 'operator' ? 'auto-review:rule' : evaluation.decidedBy,
        riskLevel: evaluation.riskLevel,
        policyNote: evaluation.reason,
        secrets: input.secrets,
      })
      // The audit row above is never authoritative. Authorize only the exact request the judge
      // evaluated, via a single-use fingerprint the broker retry consumes once.
      this.registerStateChangeApproval(run, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle ?? null,
        bodyHash: input.bodyHash,
        bodyPreview: input.bodyPreview ?? null,
        hasMultipart: input.hasMultipart,
        isRaceBurst: input.isRaceBurst,
        isRceProof: input.isRceProof,
        instances: input.approvalInstances,
      }, input.additionalApprovalTargets ?? [])
      return { approved: true }
    }

    if (evaluation.decision === 'deny') {
      this.storage.recordAutoApprovalDecision(run, job.assignment, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle,
        rationale: input.rationale,
        requestPreview: input.requestPreview,
        decision: 'denied',
        decidedBy: 'auto-review:judge',
        riskLevel: evaluation.riskLevel,
        policyNote: evaluation.reason,
        secrets: input.secrets,
      })
      return { approved: false, deniedReason: evaluation.reason }
    }

    const approvalKey = [
      run.id,
      run.scopeRevision,
      input.origin,
      input.method.toUpperCase(),
      input.pathAndQuery,
      input.personaHandle ?? '',
      input.isRceProof ? 'rce' : '',
      input.isRaceBurst ? 'race' : '',
      input.bodyPreview ?? '',
    ].join('\0')
    if (this.pendingTier3ApprovalKeys.has(approvalKey)) {
      return {
        approved: false,
        deniedReason: 'An identical Tier 3 probe is already awaiting operator approval; duplicate parallel trial suppressed.',
      }
    }
    this.pendingTier3ApprovalKeys.add(approvalKey)

    let decision: 'approved' | 'denied' | 'canceled' | 'expired'
    let postedApprovalId: string | undefined
    try {
      const req = this.storage.createApprovalRequest(run, job.assignment, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle,
        rationale: input.rationale,
        requestPreview: input.requestPreview,
        policyNote: evaluation.reason,
        riskLevel: evaluation.riskLevel,
        secrets: input.secrets,
      })
      postedApprovalId = req.id
      this.postApprovalCard(run, job.assignment.id, {
        approvalId: req.id,
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        rationale: input.rationale,
      }, input.secrets)

      // v6 Layer-1: non-blocking operator opt-in. Persist `awaiting_approval` and release the worker
      // slot immediately; the coroutine waits on the durable decision, not on a busy worker.
      try {
        this.storage.parkWorkerForApproval(run, job.assignment.id)
        this.active.delete(job.assignment.id)
        this.scheduleWake()
      } catch { /* an already-parked or terminal worker keeps its state */ }

      decision = await new Promise<'approved' | 'denied' | 'canceled' | 'expired'>((resolveDecision, rejectDecision) => {
        const checkCurrent = () => {
          try {
            const latest = this.storage.getApprovalRequest(run.id, req.id)
            if (latest.status !== 'pending') {
              cleanup()
              resolveDecision(latest.status)
              return true
            }
            if (Date.now() >= latest.expiresAt) {
              this.storage.db.update(approvalRequests).set({ status: 'expired', decidedAt: Date.now() })
                .where(eq(approvalRequests.id, req.id)).run()
              cleanup()
              resolveDecision('expired')
              return true
            }
          } catch (err) {
            cleanup()
            rejectDecision(err)
            return true
          }
          return false
        }

        const unsub = this.storage.onRunEvent(run.id, () => { checkCurrent() })
        const timer = setInterval(() => { checkCurrent() }, 1_000)
        timer.unref?.()
        const onAbort = () => {
          cleanup()
          rejectDecision(signal.reason instanceof Error ? signal.reason : new Error('Aborted while waiting for approval.'))
        }
        const cleanup = () => {
          unsub()
          clearInterval(timer)
          signal.removeEventListener('abort', onAbort)
        }
        signal.addEventListener('abort', onAbort, { once: true })
        if (signal.aborted) {
          onAbort()
          return
        }
        checkCurrent()
      })
    } finally {
      this.pendingTier3ApprovalKeys.delete(approvalKey)
    }

    if (postedApprovalId) {
      this.postApprovalResolution(run, job.assignment.id, {
        approvalId: postedApprovalId,
        decision,
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
      })
    }
    if (this.authorize(job)) {
      this.storage.updateWorker(job.assignment.id, { status: 'running' })
    }
    if (decision === 'approved') {
      // Resume the parked worker with a fresh lease and re-enter the scheduler. The exact
      // single-use ledger remains: the durable operator lease is route-scoped and auditable.
      try {
        const resumed = this.storage.resumeParkedWorker(this.storage.run(run.id), job.assignment.id)
        job.assignment = resumed
        this.active.set(resumed.id, job)
        this.scheduleWake()
      } catch { /* resume is best-effort; the request still retries under the approval ledger */ }
      // A human/operator approval authorizes exactly this fingerprint once; broader reuse requires
      // an explicit operator pattern (approve_similar_endpoint), never a prefix match on the card.
      this.registerStateChangeApproval(run, {
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle ?? null,
        bodyHash: input.bodyHash,
        bodyPreview: input.bodyPreview ?? null,
        hasMultipart: input.hasMultipart,
        isRaceBurst: input.isRaceBurst,
        isRceProof: input.isRceProof,
        approvalId: postedApprovalId,
        instances: input.approvalInstances,
      }, input.additionalApprovalTargets ?? [])
    } else {
      // A denied/expired/canceled decision ends this assignment; its slot was already released.
      try {
        this.storage.updateWorker(job.assignment.id, {
          status: 'failed',
          approvalParkedAt: null,
          lease: null,
          leaseExpiresAt: null,
          outcome: `Tier 3 approval ${decision}.`,
        })
      } catch { /* worker may already be terminal */ }
    }
    return { approved: decision === 'approved' }
  }

  // --- Event-Driven Scheduler ---

  wake() {
    if (this.stopped) return
    // 0. Mirror roster state and retire warm members on stop/scope revocation.
    for (const runId of [...this.trackedBoardRuns]) {
      try { this.syncBoardRoster(this.storage.run(runId)) } catch { this.trackedBoardRuns.delete(runId) }
    }

    // 1. Revoke/abort any active job that lost authorization
    for (const [id, job] of this.active) {
      if (this.authorize(job)) continue
      job.controller.abort()
      try {
        const current = this.storage.worker(id)
        if ((current.status === 'running' || current.status === 'waiting_approval') && current.lease === job.assignment.lease) {
          this.storage.transaction(() => {
            this.storage.updateWorker(id, { status: 'canceled', lease: null, leaseExpiresAt: null, outcome: 'Assignment authorization changed.' })
            this.storage.event(current.runId, 'worker.canceled', 'Assignment canceled after scope or status change.', { assignmentId: id })
          })
        }
      } catch { /* ignore */ }
    }

    for (const [runId, task] of this.coordinator) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }
    for (const [runId, task] of this.threatModeling) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }
    for (const [runId, task] of this.plannerTasks) {
      if (!this.currentCoordinator(runId, task)) task.controller.abort()
    }

    // Slice 3: stop the concurrent deterministic lane as soon as its run leaves investigation or
    // is no longer authorized. Fire-and-forget here; Phase-3 gates on the settle promise.
    for (const [runId, lane] of this.agenticLaneJobs) {
      try {
        const current = this.storage.run(runId)
        const active = current.status === 'running' && current.phase === 'investigation'
        if (!active) void this.abortAgenticLane(current, 'run left investigation').catch(() => undefined)
      } catch {
        try { lane.controller.abort(new Error('run unavailable')) } catch { /* already aborted */ }
        this.agenticLaneJobs.delete(runId)
      }
    }

    // Stop background login-persona session refreshers for any run that paused, stopped, failed, or completed
    for (const runId of [...this.runAuthStarted.keys()]) {
      try {
        const current = this.storage.run(runId)
        if (current.status !== 'running' || current.phase === 'complete') {
          this.personaAuth.stopRunRefreshers(runId)
          this.runAuthStarted.delete(runId)
        }
      } catch {
        this.personaAuth.stopRunRefreshers(runId)
        this.runAuthStarted.delete(runId)
      }
    }
    for (const [runId, ctrl] of [...this.runAuthInFlight.entries()]) {
      try {
        const current = this.storage.run(runId)
        if (current.status !== 'running') {
          ctrl.abort()
        }
      } catch {
        ctrl.abort()
      }
    }

    // Tear down LabRunner containers for any runs no longer active
    for (const runId of [...this.startedLabRuns]) {
      try {
        const current = this.storage.run(runId)
        if (current.status === 'complete' || current.status === 'failed' || current.status === 'stopped') {
          this.startedLabRuns.delete(runId)
          this.startedLabHandles.delete(runId)
          void this.labRunner.stopLabTarget(runId).catch(() => undefined)
        }
      } catch {
        this.startedLabRuns.delete(runId)
        this.startedLabHandles.delete(runId)
        void this.labRunner.stopLabTarget(runId).catch(() => undefined)
      }
    }

    // 2. Dispatch pending one-click Verify Fix retests (works even on completed runs, Zero-LLM!)
    for (const run of this.storage.runsWithPendingRetests()) {
      const retests = this.storage.workerList(run.id).filter(w => w.phase === 'retest' && w.status === 'queued')
      for (const worker of retests) {
        if (this.active.has(worker.id)) continue
        this.startRetestWorker(run, worker)
      }
    }

    // 3. Process runnable runs
    const profiles = privateModelProfiles(this.storage)
    for (const run of this.storage.runnable()) {
      if (this.storage.checkBudgetExceeded(run.id)) continue
      this.ensureVariantSweepsForConfirmedFindings(run)
      this.routeOperatorBoardMessages(run)

      if (profiles.length) {
        this.startCoordinator(run, profiles)
      }

      if (
        run.capabilityTier >= 2 &&
        run.approvedPersonaIds.length > 0 &&
        (run.phase === 'threat_model' || run.phase === 'investigation' || run.phase === 'verification') &&
        this.needsLoginPersonaAuth(run)
      ) {
        this.ensureRunPersonasAuthenticated(run)
        continue
      }

      if (run.phase === 'threat_model') {
        if (!this.threatModeling.has(run.id)) {
          this.startThreatModel(run, profiles)
        }
        continue
      }

      if (run.phase === 'investigation') {
        this.driveInvestigation(run, profiles)
        continue
      }

      if (run.phase === 'verification') {
        this.driveVerification(run)
        continue
      }
    }
  }

  private runAuthKey(run: Run): string {
    return `${run.scopeRevision}:${[...run.approvedPersonaIds].sort().join(',')}`
  }

  private needsLoginPersonaAuth(run: Run): boolean {
    const key = this.runAuthKey(run)
    if (this.runAuthStarted.get(run.id) === key) return false
    try {
      const resolved = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
      return [...resolved.values()].some(p => p.authKind === 'login')
    } catch {
      return false
    }
  }

  private ensureRunPersonasAuthenticated(run: Run): void {
    if (this.runAuthInFlight.has(run.id)) return
    const key = this.runAuthKey(run)
    const controller = new AbortController()
    this.runAuthInFlight.set(run.id, controller)

    void this.personaAuth.startRunRefreshers(
      this.storage,
      run.id,
      run.projectId,
      run.approvedPersonaIds,
      controller.signal,
    ).then(() => {
      try {
        const current = this.storage.run(run.id)
        if (current.status === 'running' && this.runAuthKey(current) === key) {
          this.runAuthStarted.set(run.id, key)
        } else {
          this.personaAuth.stopRunRefreshers(run.id)
        }
      } catch {
        this.personaAuth.stopRunRefreshers(run.id)
      }
    }).catch(error => {
      this.personaAuth.stopRunRefreshers(run.id)
      if (controller.signal.aborted) return
      let secrets: NamedSecret[] = []
      try {
        secrets = personaSecrets(resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds))
      } catch {
        secrets = []
      }
      const msg = redact(error instanceof Error ? error.message : String(error), secrets).slice(0, 320)
      try {
        this.storage.transaction(() => {
          const current = this.storage.run(run.id)
          if (current.status !== 'running') return
          this.storage.setStatus(current, 'paused')
          this.storage.event(run.id, 'persona.auth_failed', `Persona login failed; run paused: ${msg}`, {
            error: msg,
          })
          this.storage.message(
            run.id,
            run.coordinatorId,
            'guardian',
            `Paused run because Email + Password persona authentication failed: ${msg}`,
          )
        })
      } catch {
        // Ignore if run/storage closed
      }
    }).finally(() => {
      this.runAuthInFlight.delete(run.id)
      this.scheduleWake()
    })
  }

  // --- Phase 1: Round-0 Threat Model & Initial Baseline Checks ---

  private startThreatModel(run: Run, profiles: readonly ResolvedModelProfile[]) {
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.threatModeling.set(run.id, task)
    void this.runThreatModel(run, profiles, task).catch(error => {
      if (!this.currentCoordinator(run.id, task)) return
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
      this.storage.transaction(() => {
        const current = this.storage.run(run.id)
        this.storage.setStatus(current, 'failed')
        this.storage.event(run.id, 'threat_model.failed', `Threat modeling failed: ${msg}`)
        this.storage.writeReport(this.storage.run(run.id), true)
      })
    }).finally(() => {
      this.threatModeling.delete(run.id)
      this.scheduleWake()
    })
  }

  private async runThreatModel(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const approvedAssets = run.candidates.filter(c => run.approved.includes(c.id))
    const approvedOrigins = new Set(approvedAssets.map(a => a.origin))

    // Resolve baseline review plan if pending
    if (run.reviewPlan?.status === 'pending') {
      const available = availableReviewChecks(approvedAssets, run.sourceMode)
      let selection = standardChecks(available)
      if (approvedAssets.length && profiles.length) {
        try {
          const answer = await agentTurn({
            directory: this.storage.directory,
            sessionId: `${run.reviewPlan.goalMessageId}-plan-${run.scopeRevision}`,
            requestId: 'plan',
            profiles: resolveProfilePoolForRole('fast', profiles),
            scenario: 'coordinator-plan',
            roleAffinity: 'fast',
            thinkingLevel: 'off',
            prompt: reviewPlanPrompt(run.goal, run.sourceMode, available),
            signal: task.controller.signal,
            onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
            onProfileSuccess: id => recordProfileSuccess(id, this.storage),
            onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
          })
          selection = parseReviewPlan(answer, available) ?? selection
        } catch {
          // Fall back cleanly to standard checks
        }
      }
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.commitReviewPlan(run, selection)
    }

    const freshRun = this.storage.run(run.id)
    // Slice 3 guard input: remember whether any investigation step was already seeded BEFORE the
    // Phase-0 recon / threat-model seeding ran. A resumed or operator-seeded run skips the
    // concurrent lane (unless deterministicSweep === 'always').
    try {
      this.prePhase0SeededSteps.set(
        this.deterministicLaneKey(freshRun),
        this.storage.listChainSteps(freshRun.id, freshRun.goalRevision).length > 0,
      )
    } catch { /* guard is advisory only */ }
    const tmWorker = this.storage.makeWorker(freshRun, 'threat_model', approvedAssets[0],
      'Round-0 Threat Model & Surface Ranking',
      `Rank ${approvedAssets.length} approved hosts by attack-surface richness and seed prioritized chain investigation steps.`, {
        sourceOrigins: [...approvedOrigins],
      })
    const claimed = this.storage.updateWorker(tmWorker.id, {
      status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller: task.controller }
    this.active.set(claimed.id, job)

    try {
      let { grant, secrets } = this.buildGrant(job, freshRun, approvedOrigins)
      const specs = this.storage.listProjectSpecsFull(freshRun.projectId)
      const { reposDir, mountedRepos } = this.projectReposMount(freshRun.projectId)

      // 0a. Optional LabRunner boot when local-lab project has labConfig.enabled
      try {
        const project = this.storage.project(freshRun.projectId)
        if (
          project.environment === 'local-lab' &&
          project.labConfig?.enabled &&
          isLocalLabEnvEnabled() &&
          !this.startedLabRuns.has(freshRun.id) &&
          reposDir
        ) {
          const primaryRepoRel = mountedRepos[0] ? mountedRepos[0].replace(/^\/repos\//, '') : ''
          const primaryRepoDir = primaryRepoRel ? join(reposDir, primaryRepoRel) : reposDir
          const hasLabLaunchSpec = Boolean(
            project.labConfig.dockerComposeFile ||
            project.labConfig.dockerfile ||
            project.labConfig.image ||
            project.labConfig.startCommand ||
            (Array.isArray(project.labConfig.services) && project.labConfig.services.length > 0) ||
            (existsSync(primaryRepoDir) && existsSync(join(primaryRepoDir, 'Dockerfile'))),
          )
          if (existsSync(primaryRepoDir) && hasLabLaunchSpec) {
            const handle = await this.labRunner.startLabTarget({
              runId: freshRun.id,
              environment: project.environment,
              repoDir: primaryRepoDir,
              labConfig: project.labConfig,
              storage: this.storage,
              projectId: project.id,
              ...(project.labConfig.iastEnabled ? { telemetryDir: join(this.storage.directory, 'evidence', 'lab-telemetry') } : {}),
              signal: task.controller.signal,
            })
            this.startedLabRuns.add(freshRun.id)
            this.startedLabHandles.set(freshRun.id, handle)
            this.storage.event(
              freshRun.id,
              'lab.started',
              `Local lab target booted at ${handle.origin}.`,
              {
                origin: handle.origin,
                baseUrls: handle.baseUrls,
                containerName: handle.containerName,
                seededPersonas: handle.seededPersonas.map(p => p.handle),
              },
            )
            // Expose the booted local-lab origin & any seeded personas into the run scope
            let scopeChanged = false
            if (!approvedOrigins.has(handle.origin)) {
              const latestForOrigin = this.storage.run(freshRun.id)
              this.storage.suggestCandidateHost(latestForOrigin, handle.origin, 'lab_runner', false)
              const withCand = this.storage.run(freshRun.id)
              const cand = withCand.candidates.find(c => c.origin === handle.origin)
              if (cand && !withCand.approved.includes(cand.id)) {
                this.storage.updateRun(freshRun.id, { approved: [...withCand.approved, cand.id] })
              }
              approvedOrigins.add(handle.origin)
              job.origins.add(handle.origin)
              scopeChanged = true
            }
            const seededPersonaIds = handle.seededPersonas
              .map(p => p.personaId)
              .filter((id): id is string => typeof id === 'string' && id.length > 0)
            if (seededPersonaIds.length > 0) {
              const latestForPersonas = this.storage.run(freshRun.id)
              const mergedPersonas = [...new Set([...latestForPersonas.approvedPersonaIds, ...seededPersonaIds])]
              if (mergedPersonas.length !== latestForPersonas.approvedPersonaIds.length) {
                this.storage.updateRun(freshRun.id, { approvedPersonaIds: mergedPersonas })
                scopeChanged = true
              }
            }
            if (scopeChanged) {
              const refreshed = this.buildGrant(job, this.storage.run(freshRun.id), approvedOrigins)
              grant = refreshed.grant
              secrets = refreshed.secrets
            }
          }
        }
      } catch {
        // Best-effort lab boot; proceed cleanly if target is externally managed
      }

      // 0b. Persist initial dynamic step budget from pre-existing endpoints + suspects
      this.storage.updateRunDynamicStepBudget(freshRun.id, computeDynamicStepBudget(this.storage, freshRun.id))

      // 0c. Zero-LLM Phase-0 deterministic surface mapper (runs before LLM Turn 1)
      const phase0RootExchanges = new Map<string, BrokerExchangeResult>()
      if (!freshRun.phase0CompletedAt && approvedOrigins.size > 0 && this.authorize(job)) {
        try {
          const reconResult = await runPhase0Recon({
            storage: this.storage,
            runId: freshRun.id,
            scopeRevision: freshRun.scopeRevision,
            tier: freshRun.capabilityTier,
            origins: [...approvedOrigins],
            budgetRequests: freshRun.budgetRequests,
            reposDir,
            personas: [...(grant.personas?.keys() ?? [])],
            broker: this.broker,
            browser: freshRun.capabilityTier >= 2 ? this.browser : undefined,
            canaryBroker: this.canaryBroker,
            grant,
            signal: task.controller.signal,
            assignmentId: claimed.id,
            onExchange: ex => {
              if (ex.method === 'GET' && ex.pathAndQuery === '/' && !phase0RootExchanges.has(ex.origin)) {
                phase0RootExchanges.set(ex.origin, ex)
              }
              const saved = this.storage.recordExchange({
                runId: freshRun.id,
                assignmentId: claimed.id,
                scopeRevision: freshRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets,
              })
              return saved.id
            },
          }) as Awaited<ReturnType<typeof runPhase0Recon>> & Phase0GraphwireExtras
          // v6 graphwire: the ranked plan bounds probe breadth without trimming the store, and
          // AST code→runtime hypotheses become prioritized leads for the floor/agentic lane.
          this.probePlans.record(this.storage, freshRun.id, reconResult.probePlan)
          this.seedCodeToRuntimeLeads(this.storage.run(freshRun.id), claimed, reconResult.codeToRuntimeHypotheses ?? [])
          this.storage.updateRunDynamicStepBudget(freshRun.id, computeDynamicStepBudget(this.storage, freshRun.id))
        } catch {
          // Phase-0 failure must not block threat model progression
        }
      }

      // Phase-0 boundary: capture the deterministic surface before the LLM threat model. Resuming
      // here is valid (the threat model simply re-runs from the saved discovery state).
      if (this.storage.run(freshRun.id).phase0CompletedAt) {
        this.notifyCheckpoint(freshRun.id, 'phase0')
      }

      // 1. Correlate dependencies from uploaded/synced specs via CVE broker
      const seenDeps = new Set<string>()
      let advisoryLookups = 0
      for (const spec of specs) {
        const deps = parseDependenciesFromFile(spec.name.split(':').pop() ?? spec.name, spec.content)
        // Also parse `:dependencies` note format generated by github-connector
        for (const match of spec.content.matchAll(/^([a-zA-Z0-9_.-]+):([@a-zA-Z0-9_./-]+)@([0-9][0-9A-Za-z.+-]*)/gm)) {
          deps.push({ ecosystem: match[1], package: match[2], version: match[3], sourceFile: spec.name })
        }
        for (const dep of deps) {
          // Every parsed dependency is a candidate (no JS-only high-signal allowlist).
          if (!dep.package || !dep.version) continue
          const key = `${dep.ecosystem}:${dep.package}:${dep.version}`
          if (seenDeps.has(key)) continue
          seenDeps.add(key)
          if (advisoryLookups >= 120) break
          advisoryLookups += 1
          try {
            const advisories = await queryCves({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version }, task.controller.signal)
            // Whether the advisory came from the curated offline corpus or a remote feed matters to
            // the operator (offline workers cannot fetch live feeds).
            const curated = hasCuratedAdvisory(dep.ecosystem, dep.package)
            for (const adv of advisories.slice(0, 3)) {
              const targetOrigin = spec.origin && approvedOrigins.has(spec.origin)
                ? spec.origin
                : approvedAssets[0]?.origin
              if (!targetOrigin) continue
              this.storage.addFact(freshRun, claimed, {
                kind: 'cve_hypothesis',
                origin: targetOrigin,
                summary: `${adv.id} (${adv.severity}) hypothesis for ${dep.package}@${dep.version} from ${spec.name}: ${adv.summary}`,
                data: {
                  cveId: adv.id,
                  package: dep.package,
                  version: dep.version,
                  ecosystem: dep.ecosystem,
                  severity: adv.severity,
                  safeVerificationHint: adv.safeVerificationHint,
                  sourceSpec: spec.name,
                  curatedAdvisory: curated,
                  confidence: 'low',
                },
                sourceOrigins: [targetOrigin],
                secrets,
              })
            }
          } catch { /* advisory lookup is best-effort */ }
        }
      }

      // 2. Capture initial lightweight baseline observations for approved hosts
      const observations: Record<string, unknown>[] = []
      const selectedChecks: readonly AssessmentCheckId[] = freshRun.reviewPlan?.status === 'ready'
        ? freshRun.reviewPlan.checks : responseCheckIds
      const responseChecks = selectedChecks.filter(c => c !== 'access-policy') as ResponseCheckId[]

      for (const asset of approvedAssets) {
        if (!this.authorize(job)) break
        const hostWorker = this.storage.makeWorker(freshRun, 'threat_model', asset,
          `Baseline capture · ${new URL(asset.origin).hostname}`,
          'Capture initial baseline response and access-policy evidence for deterministic checks.', {
            sourceOrigins: [asset.origin],
          })
        this.storage.updateWorker(hostWorker.id, { status: 'running', lease: claimed.lease })

        let capture: Capture
        if (freshRun.sourceMode === 'prepared' || freshRun.capabilityTier === 0) {
          capture = asset.prepared
            ? { observation: { ...asset.prepared, origin: asset.origin, finalOrigin: asset.origin, source: 'supplied observation' }, note: 'Supplied project evidence.' }
            : { observation: null, note: 'No prepared observation was supplied.' }
        } else {
          try {
            const cachedPhase0Root = phase0RootExchanges.get(asset.origin)
            const priorRootRow = !cachedPhase0Root
              ? this.storage.client.prepare(
                  `SELECT id, origin, final_origin AS finalOrigin, status, media_type AS mediaType, resp_headers AS respHeadersJson
                   FROM broker_exchanges
                   WHERE run_id = ? AND origin = ? AND method = 'GET' AND path_and_query = '/'
                   ORDER BY created_at ASC LIMIT 1`,
                ).get(freshRun.id, asset.origin) as {
                  id: string
                  origin: string
                  finalOrigin: string
                  status: number
                  mediaType: string
                  respHeadersJson: string
                } | undefined
              : undefined

            if (cachedPhase0Root) {
              capture = { observation: cachedPhase0Root.observation, note: 'Recorded approved HTTPS root response.' }
              observations.push({
                origin: asset.origin,
                finalOrigin: cachedPhase0Root.finalOrigin,
                status: cachedPhase0Root.status,
                mediaType: cachedPhase0Root.mediaType,
                server: cachedPhase0Root.respHeaders['server'],
                poweredBy: cachedPhase0Root.respHeaders['x-powered-by'],
              })
            } else if (priorRootRow) {
              let headersObj: Record<string, string> = {}
              try { headersObj = JSON.parse(priorRootRow.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
              const h = (name: string): string | undefined => headersObj[name.toLowerCase()]
              const transport = h('strict-transport-security') ?? ''
              const ages = transport.split(';').filter(d => /^\s*max-age\s*(?:=|$)/i.test(d))
              const parsedAge = ages.length === 1 ? ages[0].match(/^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i) : null
              const maxAge = parsedAge ? Number(parsedAge[1] ?? parsedAge[2]) : NaN
              const xcto = h('x-content-type-options')
              const nosniff = xcto?.split(',', 1)[0].trim().toLowerCase() === 'nosniff'
              const cspVal = h('content-security-policy')
              const cspRo = h('content-security-policy-report-only')
              const xfo = h('x-frame-options')
              const frameAncestors = Boolean(cspVal && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(cspVal))
              const validXfo = Boolean(xfo && /^(?:deny|sameorigin)\s*$/i.test(xfo.split(',', 1)[0]))
              const refRaw = h('referrer-policy')
              const validRefs = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'] as const
              const refPolicy: PublicObservation['referrerPolicy'] = refRaw === undefined
                ? 'absent'
                : refRaw.includes('"')
                  ? 'unrecognized'
                  : (refRaw.split(',').map(t => t.trim()).findLast((t): t is typeof validRefs[number] => (validRefs as readonly string[]).includes(t)) ?? 'unrecognized')
              const srv = h('server')?.trim()
              capture = {
                observation: {
                  origin: priorRootRow.origin,
                  finalOrigin: priorRootRow.finalOrigin,
                  status: priorRootRow.status,
                  mediaType: priorRootRow.mediaType || 'unknown',
                  transportMaxAge: Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : null,
                  includeSubDomains: /(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(transport),
                  source: 'public response',
                  contentTypeOptions: xcto === undefined ? 'absent' : nosniff ? 'nosniff' : 'unrecognized',
                  referrerPolicy: refPolicy,
                  contentSecurityPolicy: cspVal !== undefined ? (cspVal.trim() ? 'enforced' : 'unrecognized') : cspRo !== undefined ? (cspRo.trim() ? 'report-only' : 'unrecognized') : 'absent',
                  frameProtection: frameAncestors && validXfo ? 'both' : frameAncestors ? 'csp-frame-ancestors' : validXfo ? 'x-frame-options' : xfo !== undefined ? 'unrecognized' : 'absent',
                  serverDisclosure: h('x-powered-by') ? 'technology' : !srv ? 'absent' : /(?:\d|\/|next|express|php|asp\.net|nginx|apache)/i.test(srv) ? 'technology' : 'generic',
                },
                note: 'Reused recorded approved HTTPS root response.',
              }
              observations.push({
                origin: asset.origin,
                finalOrigin: priorRootRow.finalOrigin,
                status: priorRootRow.status,
                mediaType: priorRootRow.mediaType,
                server: headersObj['server'],
                poweredBy: headersObj['x-powered-by'],
                exchangeId: priorRootRow.id,
              })
            } else {
              const ex = await this.broker.executeHttp({
                origin: asset.origin,
                method: 'GET',
                pathAndQuery: '/',
                followRedirects: true,
                timeoutMs: 12_000,
              }, grant, task.controller.signal)
              const savedEx = this.storage.recordExchange({
                runId: freshRun.id,
                assignmentId: hostWorker.id,
                scopeRevision: freshRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets,
              })
              capture = { observation: ex.observation, note: 'Recorded approved HTTPS root response.' }
              observations.push({
                origin: asset.origin,
                finalOrigin: ex.finalOrigin,
                status: ex.status,
                mediaType: ex.mediaType,
                server: ex.respHeaders['server'],
                poweredBy: ex.respHeaders['x-powered-by'],
                exchangeId: savedEx.id,
              })
            }
          } catch (error) {
            capture = {
              observation: null,
              note: error instanceof BrokerDenied || error instanceof BrokerCircuitOpen
                ? error.message : 'The approved public response could not be read.',
            }
            observations.push({ origin: asset.origin, error: capture.note })
          }
        }

        const obsArtifact = this.storage.addArtifact(
          freshRun, hostWorker, 'observation',
          freshRun.sourceMode === 'prepared' ? suppliedResponseLabel : 'Observed public response',
          JSON.stringify(capture, null, 2), 'capture:' + freshRun.scopeRevision, secrets,
        )
        const reviews = responseChecks.length ? responseReview(capture.observation, capture.note, responseChecks) : []
        const inputs = [{ artifactId: obsArtifact.id, reviews }]

        if (selectedChecks.includes('access-policy')) {
          const snapshot = asset.accessPolicy?.origin === asset.origin ? asset.accessPolicy : undefined
          const apArtifact = this.storage.addArtifact(freshRun, hostWorker, 'access-policy', 'Supplied access policy records',
            JSON.stringify({ origin: asset.origin, snapshot: snapshot ?? null }, null, 2), 'access-policy', secrets)
          inputs.push({ artifactId: apArtifact.id, reviews: accessPolicyReviews(snapshot) })
        }

        for (const { artifactId, reviews: revs } of inputs) {
          for (const rev of revs) {
            if (rev.comparison && !meetsBaseline(rev.comparison)) {
              const earlier = this.baselineFinding(freshRun, asset, rev)
              this.saveBaselineFinding(freshRun, asset, rev, 'pending',
                'The recorded value falls outside the expected policy. Verification is pending.', [artifactId], earlier?.id)
            }
          }
        }
        this.storage.updateWorker(hostWorker.id, { status: 'complete', lease: null, outcome: capture.note })
      }

      // 3. Build prioritized Threat Model via LLM (with deterministic fallback)
      const heuristicEntries = approvedAssets.map(classifyHostHeuristic)
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 }
      heuristicEntries.sort((a, b) =>
        hostTierOrder[classifyHostTier(a.origin, a.surfaceTags)] - hostTierOrder[classifyHostTier(b.origin, b.surfaceTags)] ||
        riskOrder[a.riskTier] - riskOrder[b.riskTier],
      )
      const initialHostTiers = computeHostTiers([...approvedOrigins], heuristicEntries)

      let finalEntries = heuristicEntries
      let tmSummary = `Ranked ${heuristicEntries.length} approved hosts by attack surface.`
      let seededSteps: Array<{
        title: string
        hypothesis: string
        category: string
        priority: number
        origins: string[]
        skills: string[]
      }> = []

      if (profiles.length && freshRun.capabilityTier > 0 && approvedAssets.length > 0) {
        try {
          const personasPub = [...grant.personas?.values() ?? []].map(p => ({
            handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
          }))
          const graphCatalog = this.endpointGraphCatalog(freshRun.id)
          const answer = await agentTurn({
            directory: this.storage.directory,
            sessionId: `tm-${freshRun.id}-${freshRun.goalRevision}-${freshRun.scopeRevision}`,
            requestId: 'threat-model',
            profiles: resolveProfilePoolForRole('tactical', profiles),
            scenario: 'threat-model',
            roleAffinity: 'tactical',
            prompt: threatModelPrompt({
              goal: freshRun.goal,
              capabilityTier: freshRun.capabilityTier,
              approvedOrigins: [...approvedOrigins],
              hostTiers: initialHostTiers,
              personas: personasPub,
              specs: specs.slice(0, 12).map(s => ({
                name: s.name, kind: s.kind, origin: s.origin, preview: s.content.slice(0, 1200),
              })),
              mountedRepos,
              observations: [
                ...observations.slice(0, 38),
                ...(graphCatalog.endpointParams.length || graphCatalog.apiDependencies.length
                  ? [{
                      kind: 'endpoint_graph_catalog',
                      endpointParams: graphCatalog.endpointParams.slice(0, 80),
                      apiDependencies: graphCatalog.apiDependencies.slice(0, 40),
                      note: 'Persisted endpoint_params (injectable locations/CSRF/object-id flags) and producer→consumer api_dependencies harvested from Phase-0, crawl and worker exchanges. Prioritize ID-bearing consumer routes and CSRF-bound write paths.',
                    }]
                  : []),
              ],
            }),
            signal: task.controller.signal,
            secrets,
            onUsage: u => this.storage.recordLlmSpend(freshRun.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
            onProfileSuccess: id => recordProfileSuccess(id, this.storage),
            onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
          })
          const parsed = threatModelResponseSchema.safeParse(JSON.parse(stripJsonFences(answer)))
          if (parsed.success) {
            tmSummary = parsed.data.summary
            const validEntries: ThreatModelSummary[] = parsed.data.entries
              .filter(e => approvedOrigins.has(e.origin))
              .map(e => {
                const tags = [...new Set(e.surfaceTags)]
                const tier = e.hostTier ?? classifyHostTier(e.origin, tags)
                if (tier === 'crown_jewel' && !tags.includes('crown_jewel')) tags.unshift('crown_jewel')
                if (tier === 'low_value_static' && !tags.includes('low_value_static')) tags.push('low_value_static')
                return { origin: e.origin, riskTier: e.riskTier, surfaceTags: tags, rationale: e.rationale }
              })
            if (validEntries.length) {
              const seen = new Set(validEntries.map(e => e.origin))
              finalEntries = [
                ...validEntries,
                ...heuristicEntries.filter(h => !seen.has(h.origin)),
              ].sort((a, b) =>
                hostTierOrder[classifyHostTier(a.origin, a.surfaceTags)] - hostTierOrder[classifyHostTier(b.origin, b.surfaceTags)] ||
                riskOrder[a.riskTier] - riskOrder[b.riskTier],
              )
            }
            seededSteps = parsed.data.initialSteps.filter(s => s.origins.some(o => approvedOrigins.has(o)))
          }
        } catch {
          // Deterministic heuristic fallback guarantees progress even if LLM response isn't valid JSON
        }
      }

      if (!this.authorize(job)) return

      const finalHostTiers = computeHostTiers([...approvedOrigins], finalEntries)

      // Save Threat Model before Source-First Code Audit so audit & planner see ranked hosts
      const savedTm = this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return null
        const tm = this.storage.saveThreatModel(current, finalEntries, tmSummary)
        const tmArtifact = this.storage.addArtifact(current, claimed, 'threat-model', 'Round-0 Threat Model',
          JSON.stringify({ threatModelId: tm.id, summary: tmSummary, entries: finalEntries, hostTiers: finalHostTiers }, null, 2), 'threat-model', secrets)
        return { tm, tmArtifact }
      }, { behavior: 'immediate' })
      if (!savedTm) return

      // 4. Priority #1: Dedicated Source-First Code Audit Phase BEFORE live HTTP investigation rounds
      let codeAuditStepsCreated = 0
      if (mountedRepos.length > 0 && freshRun.capabilityTier > 0 && profiles.length > 0 && this.authorize(job)) {
        try {
          const auditResult = await this.runSourceFirstCodeAudit(
            this.storage.run(freshRun.id),
            finalEntries,
            profiles,
            task.controller.signal,
          )
          codeAuditStepsCreated = auditResult.stepsCreated.length
        } catch {
          // Code audit failure should not block live investigation rounds
        }
      }

      if (!this.authorize(job)) return

      // Ensure at least initial investigation steps exist when Tier >= 1
      if (!seededSteps.length && freshRun.capabilityTier > 0 && approvedAssets.length > 0) {
        const topHosts = finalEntries.slice(0, Math.min(8, finalEntries.length))
        seededSteps = topHosts.map((entry, idx) => {
          const tier = finalHostTiers[entry.origin] ?? classifyHostTier(entry.origin, entry.surfaceTags)
          return {
            title: `Surface & chain investigation · ${new URL(entry.origin).hostname}`,
            hypothesis: `Harvest JS/API routes, inspect DNS/TLS/CORS/auth headers, fingerprint stack & CVEs, and verify any candidate vulnerabilities on ${entry.origin} (${entry.surfaceTags.join(', ')}).`,
            category: entry.surfaceTags.includes('auth') ? 'auth-identity'
              : entry.surfaceTags.includes('api') ? 'broken-access-control'
                : entry.surfaceTags.includes('upload') ? 'upload-storage'
                  : entry.surfaceTags.includes('llm-proxy') ? 'llm-ai-security'
                    : 'misconfig-exposure',
            priority: tier === 'low_value_static' ? 30 : Math.max(55, 95 - idx * 6),
            origins: [entry.origin],
            skills: ['recon-modern-spa', 'cve-runtime-correlation', 'false-positive-elimination'],
          }
        })
      }

      this.storage.transaction(() => {
        const current = this.storage.run(freshRun.id)
        if (current.status !== 'running' || current.phase !== 'threat_model') return

        const existingSteps = this.storage.listChainSteps(current.id, current.goalRevision)
        const remainingInitialSlots = Math.max(0, 12 - existingSteps.length)
        const budgetedSteps = applyCrownJewelStepBudget(
          seededSteps.map(step => ({ ...step, origins: step.origins.filter(o => approvedOrigins.has(o)) })),
          finalHostTiers,
          existingSteps,
          remainingInitialSlots,
        )

        let addedInitial = 0
        for (const step of budgetedSteps) {
          const validOrigins = step.origins.filter(o => approvedOrigins.has(o))
          const assetIds = current.candidates.filter(c => validOrigins.includes(c.origin) && current.approved.includes(c.id)).map(c => c.id)
          if (!assetIds.length) continue
          const specialistProfile = routeStepToSpecialist({
            title: step.title,
            hypothesis: step.hypothesis,
            category: step.category,
            skills: step.skills,
          })
          this.storage.addChainStep(current, {
            title: step.title,
            hypothesis: step.hypothesis,
            category: step.category,
            priority: step.priority,
            targetAssetIds: assetIds,
            skills: step.skills,
            sourceOrigins: validOrigins,
            specialistProfile,
          })
          addedInitial += 1
        }
        this.expandEligibleMultiTrialSteps(current)
        this.storage.updateRunDynamicStepBudget(current.id, computeDynamicStepBudget(this.storage, current.id))

        const totalQueued = codeAuditStepsCreated + addedInitial
        this.completeWorker(claimed, current, tmSummary, [savedTm.tmArtifact.id], undefined, secrets)
        const deterministicMode = !profiles.length && current.capabilityTier > 0
        const nextPhase = current.capabilityTier === 0 ? 'verification' : 'investigation'
        this.storage.updateRun(current.id, { phase: nextPhase })
        this.storage.event(current.id, `${nextPhase}.started`,
          nextPhase === 'investigation'
            ? deterministicMode
              ? 'Threat model complete (no model profile configured). Starting bounded deterministic differential probing.'
              : `Threat model complete${codeAuditStepsCreated ? ` (${codeAuditStepsCreated} source-audit steps + ${addedInitial} initial steps)` : ` (${totalQueued} initial steps)`}. Starting closed-loop chain investigation.`
            : 'Baseline captures complete. Starting deterministic Zero-LLM verification.')
        this.storage.message(current.id, current.coordinatorId, 'guardian',
          nextPhase === 'investigation'
            ? deterministicMode
              ? `Threat model ranked ${finalEntries.length} hosts. No model profile is configured, so Guardian will run a bounded deterministic probe pass over discovered endpoints instead of agentic investigation.`
              : `Threat model ranked ${finalEntries.length} hosts and queued ${totalQueued} initial investigation steps${codeAuditStepsCreated ? ` (including ${codeAuditStepsCreated} from Source-First Code Audit)` : ''}.`
            : 'Baseline capture complete. Deterministic verification is checking the recorded evidence.')
      }, { behavior: 'immediate' })

      // Post-floor boundary: Phase-0 + threat model + deterministic lane are complete and the
      // first agentic assignment has not started yet. This is the primary resume checkpoint.
      const afterFloor = this.storage.run(freshRun.id)
      if (afterFloor.status === 'running' && afterFloor.phase === 'investigation') {
        this.notifyCheckpoint(afterFloor.id, 'post-floor')
      } else if (afterFloor.status === 'running' && afterFloor.phase === 'verification') {
        this.notifyCheckpoint(afterFloor.id, 'deterministic-lane')
      }
    } finally {
      this.active.delete(claimed.id)
    }
  }

  // --- Phase 1B: Source-First Code Audit (Mounted /repos BEFORE live HTTP rounds) ---

  async runSourceFirstCodeAudit(
    run: Run,
    threatModel: readonly ThreatModelSummary[],
    profiles: readonly ResolvedModelProfile[],
    signal: AbortSignal,
  ): Promise<{ suspects: Fact[]; stepsCreated: ChainStep[] }> {
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || !mountedRepos.length || !profiles.length || run.capabilityTier === 0) {
      return { suspects: [], stepsCreated: [] }
    }
    const approvedAssets = run.candidates.filter(c => run.approved.includes(c.id))
    const approvedOrigins = new Set(approvedAssets.map(a => a.origin))
    if (!approvedOrigins.size) return { suspects: [], stepsCreated: [] }

    const auditMaxTurns = Math.max(6, Math.min(run.workerMaxTurns || defaultCodeAuditMaxTurns, defaultCodeAuditMaxTurns))
    const auditPhase = run.phase === 'investigation' ? 'investigation' : 'threat_model'
    const auditWorker = this.storage.makeWorker(
      run,
      auditPhase,
      approvedAssets[0],
      `Source-First Code Audit · ${mountedRepos.slice(0, 2).join(', ')}`,
      `Inspect read-only mounted source repositories (${mountedRepos.join(', ')}) under /repos before live HTTP probing to build a Route/Server Action/Webhook Authz Matrix and record code_audit_suspect facts.`,
      { maxTurns: auditMaxTurns, sourceOrigins: [...approvedOrigins] },
    )
    const claimed = this.storage.updateWorker(auditWorker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    })!
    const controller = new AbortController()
    const onParentAbort = () => controller.abort(signal.reason)
    signal.addEventListener('abort', onParentAbort, { once: true })
    if (signal.aborted) controller.abort(signal.reason)

    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller }
    this.active.set(claimed.id, job)
    this.storage.event(run.id, 'code_audit.started', `Source-First Code Audit started across ${mountedRepos.length} mounted ${mountedRepos.length === 1 ? 'repo' : 'repos'}.`, {
      assignmentId: claimed.id, mountedRepos,
    })

    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, approvedOrigins)
    const session = await this.backend.openSession(claimed.id, controller.signal, { reposDir })
    const startedAt = Date.now()

    try {
      const specs = this.storage.listProjectSpecsFull(run.projectId)
      const stagedSpecs: Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }> = []
      for (const [idx, spec] of specs.slice(0, 8).entries()) {
        try {
          const stagedPath = await session.stage(`specs/spec-${idx + 1}.txt`, spec.content.slice(0, 1_500_000), controller.signal)
          stagedSpecs.push({ name: spec.name, kind: spec.kind, origin: spec.origin, stagedPath })
        } catch { /* skip oversized */ }
      }

      const handlers: WorkerToolHandlers = {
        spillOutput: async (id, content, sig) => session.stage(`tool-output/${id}.txt`, content, sig),
        derive_evidence: async ({ command, outputs, timeoutMs }, sig) => {
          const curRun = this.check(job)
          const res = await session.exec(command, outputs ?? ['result.txt'], sig, timeoutMs ?? 60_000)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis', 'Code audit analysis',
            JSON.stringify({
              command: redact(command, secrets),
              exitStatus: res.exitCode,
              stdout: redact(res.stdout, secrets),
              stderr: redact(res.stderr, secrets),
              outputs: res.outputs,
            }, null, 2), undefined, secrets)
          return { evidenceId: ev.id, exitCode: res.exitCode, stdout: res.stdout, stderr: res.stderr, outputs: res.outputs }
        },
        analyze_artifact: async (args, sig) => {
          this.check(job)
          const { tool, ...rest } = args
          return await session.analyze(tool, rest, sig)
        },
        run_sast_scan: async (args, sig) => {
          const curRun = this.check(job)
          const res = await session.sast(args, sig)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'sast',
            `SAST scan · ${res.repo} (${res.enginesRun.join(', ')})`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          for (const engine of res.enginesRun) {
            const st = res.engineStatus[engine]
            this.storage.recordSastRun({
              runId: curRun.id,
              assignmentId: job.assignment.id,
              repo: res.repo,
              engine,
              rawArtifactId: ev.id,
              findingCount: st?.count ?? 0,
              durationMs: st?.durationMs ?? res.durationMs,
            })
          }
          return { evidenceId: ev.id, ...res }
        },
        run_offline_script: async (args, sig) => {
          const curRun = this.check(job)
          const res = await session.runScript(args, sig)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis',
            `Offline ${args.runtime} script (code audit)`,
            JSON.stringify({
              runtime: res.runtime,
              exitCode: res.exitCode,
              timedOut: res.timedOut,
              durationMs: res.durationMs,
              stdout: redact(res.stdout, currentSecrets()),
              stderr: redact(res.stderr, currentSecrets()),
            }, null, 2), undefined, currentSecrets())
          return { evidenceId: ev.id, ...res }
        },
        query_cves: async (args, sig) => {
          this.check(job)
          const advisories = await queryCves(args, sig)
          return { count: advisories.length, advisories }
        },
        load_skill: async ({ name }) => {
          if (name.trim().toLowerCase() === 'list') return { skills: listSkills() }
          const skill = loadSkill(name)
          if (!skill) return { error: `Unknown skill "${name}".`, available: listSkills().map(s => s.name) }
          return skill
        },
        search_facts: async ({ query, origin, kind, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
            .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
        },
        record_fact: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const fact = this.storage.addFact(curRun, job.assignment, {
            kind: args.kind,
            origin: cleanOrigin,
            summary: args.summary,
            data: args.data,
            exchangeIds: args.exchangeIds,
            evidenceIds: args.evidenceIds,
            sourceOrigins: args.sourceOrigins,
            secrets: currentSecrets(),
          })
          return { factId: fact.id, kind: args.kind, origin: fact.origin }
        },
        record_coverage: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const ext = args as typeof args & { enforcingControl?: string; proofGapReason?: string; linkedFindingId?: string }
          if (args.status === 'ruled_out' && !ext.enforcingControl?.trim()) {
            throw new Error('record_coverage with status "ruled_out" requires a non-empty enforcingControl (exact file:line or negative-control exchangeId proving the control runs on the attacker path).')
          }
          const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
            origin: cleanOrigin,
            category: args.category,
            status: args.status,
            summary: args.summary,
            enforcingControl: ext.enforcingControl,
            proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
            linkedFindingId: ext.linkedFindingId,
          })
          return { id: entry.id, origin: entry.origin, category: entry.category, status: entry.status }
        },
        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const personasPub = [...grant.personas?.values() ?? []].map(p => ({
        handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
      }))

      // Stage 1-3 deterministic + semantic code audit pipeline (IRIS + call-graph + git history)
      try {
        const hostTiersForAudit = computeHostTiers([...approvedOrigins], threatModel)
        const semanticRes = await runThreeStageSemanticAudit({
          storage: this.storage,
          run,
          assignment: claimed,
          backend: this.backend,
          session,
          reposDir,
          mountedRepos,
          approvedOrigins: [...approvedOrigins],
          hostTiers: hostTiersForAudit,
          modelProfiles: resolveProfilePoolForRole('reasoning', profiles),
          signal: controller.signal,
          secrets: currentSecrets(),
          liveEndpoints: this.storage.listEndpoints(run.id)
            .filter(ep => approvedOrigins.has(ep.origin))
            .map(ep => ({ method: ep.method, path: ep.pathTemplate })),
          onUsage: usage => {
            this.storage.recordLlmSpend(run.id, {
              usd: usage.costUsd,
              tokens: usage.inputTokens + usage.outputTokens,
            })
          },
        }, {
          // Budgeted Stage-1 LLM spec + dynamic rule synthesis; opt out with GUARDIAN_STAGE1_LLM=0.
          enableStage1Llm: process.env.GUARDIAN_STAGE1_LLM !== '0',
          persistToStore: true,
        })
        const semanticSteps = toChainStepInputs(run, semanticRes.rankedSuspects, hostTiersForAudit, semanticRes.persistedFactIds)
        const existingTitles = new Set(this.storage.listChainSteps(run.id, run.goalRevision).map(s => s.title.trim().toLowerCase()))
        for (const stInput of semanticSteps) {
          const key = stInput.title.trim().toLowerCase()
          if (existingTitles.has(key)) continue
          this.storage.addChainStep(run, stInput)
          existingTitles.add(key)
        }
      } catch {
        // Semantic audit is additive; continue with interactive code auditor session
      }

      const sessionResult = await runAgentSession({
        directory: this.storage.directory,
        sessionId: claimed.sessionId,
        requestId: `code-audit:${run.id}:${run.goalRevision}:${run.scopeRevision}`,
        profiles: resolveProfilePoolForRole('reasoning', profiles),
        scenario: 'code-auditor',
        roleAffinity: 'reasoning',
        prompt: codeAuditPrompt({
          goal: run.goal,
          capabilityTier: run.capabilityTier,
          approvedOrigins: [...approvedOrigins],
          mountedRepos,
          personas: personasPub,
          specsSummary: stagedSpecs,
          threatModel,
          maxTurns: auditMaxTurns,
        }),
        signal: controller.signal,
        maxTurns: auditMaxTurns,
        compaction: true,
        enableSettlement: true,
        requireCompleteIntent: true,
        shouldSettle: () => (Date.now() - startedAt) >= 8 * 60_000,
        handlers,
        secrets,
        beforeCall: () => {
          this.check(job)
          if (this.storage.checkBudgetExceeded(run.id)) {
            throw new BudgetExceededError('Run spend or request budget exceeded.')
          }
        },
        onUsage: usage => {
          this.storage.recordLlmSpend(run.id, {
            usd: usage.costUsd,
            tokens: usage.inputTokens + usage.outputTokens,
          })
        },
        onTurn: turn => {
          this.storage.updateWorker(claimed.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        onProfileSuccess: id => recordProfileSuccess(id, this.storage),
        onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
      })

      const latestRun = this.storage.run(run.id)
      const suspects = this.storage.listFacts(run.id, { includeTainted: false, kind: 'code_audit_suspect', limit: 100 })
        .filter(f => approvedOrigins.has(f.origin))
      const hostTiers = computeHostTiers([...approvedOrigins], threatModel)
      const stepsCreated = convertCodeAuditSuspectsToChainSteps(this.storage, latestRun, suspects, hostTiers)

      const outcomeText = sessionResult.completion
        ? `[${sessionResult.completion.status}] ${sessionResult.completion.summary} (${suspects.length} suspects → ${stepsCreated.length} targeted chain steps)`
        : `Code audit finished: ${suspects.length} suspects converted into ${stepsCreated.length} targeted chain steps.`
      this.completeWorker(claimed, latestRun, outcomeText, [], undefined, currentSecrets())
      this.storage.event(run.id, 'code_audit.complete', `Source-First Code Audit recorded ${suspects.length} suspects and queued ${stepsCreated.length} targeted steps.`, {
        assignmentId: claimed.id, suspectsCount: suspects.length, stepsCreated: stepsCreated.length,
      })
      return { suspects, stepsCreated }
    } finally {
      signal.removeEventListener('abort', onParentAbort)
      this.active.delete(claimed.id)
      await session.close().catch(() => undefined)
    }
  }

  // --- Phase 2: Closed-Loop Investigation & Debounced Stateless Planner ---

  private expandEligibleMultiTrialSteps(run: Run) {
    if (run.multiTrialEnabled === false) return
    const conc = Math.max(1, run.workerConcurrency || defaultWorkerConcurrency)
    if (conc <= 1) return

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const highSignalFacts = new Set(
      this.storage.listFacts(run.id, { includeTainted: false, limit: 500 })
        .filter(f => {
          const kind = String(f.kind)
          const subkind = typeof f.data?.subkind === 'string' ? f.data.subkind : ''
          return kind === 'code_audit_suspect' || kind === 'cve_hypothesis' || subkind === 'code_audit_suspect' || subkind === 'cve_hypothesis'
        })
        .map(f => f.id),
    )

    // Trial budget = worker slots left after every distinct queued hypothesis. Duplicate trials may
    // fill idle capacity; they must never displace a planned hypothesis (the v7 funnel defect).
    const expansions = planMultiTrialExpansion({
      steps,
      concurrency: conc,
      multiTrialEnabled: true,
      highSignalFactIds: highSignalFacts,
    })
    if (!expansions.length) return
    let expanded = 0
    for (const { step, fanout } of expansions) {
      const trialGroupId = randomUUID()
      this.storage.updateChainStep(step.id, { trialGroupId, trialIndex: 0 })
      for (let idx = 1; idx < fanout; idx += 1) {
        this.storage.addChainStep(run, {
          title: `${step.title.slice(0, 180)} [trial ${idx + 1}]`,
          hypothesis: step.hypothesis,
          category: step.category,
          priority: step.priority,
          targetAssetIds: step.targetAssetIds,
          skills: step.skills,
          dependsOnFactIds: step.dependsOnFactIds,
          dependsOnStepIds: step.dependsOnStepIds,
          sourceOrigins: step.sourceOrigins,
          specialistProfile: step.specialistProfile,
          trialGroupId,
          trialIndex: idx,
        })
      }
      expanded += fanout - 1
    }
    this.storage.event(run.id, 'scheduler.multi_trial', `Expanded ${expansions.length} hypothesis(es) into ${expanded} surplus trial step(s).`, {
      concurrency: conc,
      distinctQueued: steps.filter(s => (s.status === 'pending' || s.status === 'ready') && !s.trialGroupId).length,
      expansions: expansions.map(entry => ({ stepId: entry.step.id, fanout: entry.fanout })),
    })
  }

  private cancelSiblingTrialsOnConfirmation(run: Run, winningStepId: string | null, findingId?: string) {
    if (!winningStepId) return
    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const winningStep = steps.find(s => s.id === winningStepId)
    if (!winningStep?.trialGroupId) return

    const siblings = steps.filter(s =>
      s.trialGroupId === winningStep.trialGroupId &&
      s.id !== winningStep.id &&
      ['pending', 'ready', 'running'].includes(s.status),
    )
    if (!siblings.length) return

    const canceledStepIds: string[] = []
    for (const sib of siblings) {
      this.storage.updateChainStep(sib.id, { status: 'canceled' })
      canceledStepIds.push(sib.id)
      if (sib.assignedWorkerId) {
        const activeSib = this.active.get(sib.assignedWorkerId)
        if (activeSib) {
          activeSib.controller.abort('trial.early_stopped')
        }
        try {
          const w = this.storage.worker(sib.assignedWorkerId)
          if (w.status === 'running' || w.status === 'queued' || w.status === 'waiting_approval') {
            this.storage.updateWorker(w.id, {
              status: 'canceled',
              lease: null,
              leaseExpiresAt: null,
              outcome: 'Canceled via multi-trial early stopping after sibling confirmation.',
            })
          }
        } catch { /* ignore */ }
      }
    }

    if (canceledStepIds.length > 0) {
      this.storage.event(
        run.id,
        'trial.early_stopped',
        `Early-stopped ${canceledStepIds.length} sibling trial(s) in group ${winningStep.trialGroupId} after Zero-LLM confirmation.`,
        {
          trialGroupId: winningStep.trialGroupId,
          winningStepId: winningStep.id,
          findingId: findingId ?? null,
          canceledStepIds,
        },
      )
    }
  }

  private ensureVariantSweepsForConfirmedFindings(run: Run) {
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || mountedRepos.length === 0) return

    const confirmedRows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
    )).all().filter(row =>
      (row.finding.status === 'confirmed' || row.finding.status === 'static_verified') &&
      (row.finding.codeLocations?.length ?? 0) > 0 &&
      !this.variantSweptFindings.has(row.id) &&
      !this.variantSweepInFlight.has(row.id),
    )

    for (const row of confirmedRows) {
      this.scheduleVariantSweepForFinding(run, row)
    }
  }

  private scheduleVariantSweepForFinding(
    run: Run,
    findingRow: typeof findings.$inferSelect,
  ) {
    if (this.variantSweptFindings.has(findingRow.id) || this.variantSweepInFlight.has(findingRow.id)) return
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || mountedRepos.length === 0) return
    const locs = findingRow.finding.codeLocations ?? []
    if (locs.length === 0) return

    this.variantSweepInFlight.add(findingRow.id)
    void this.runPostConfirmationVariantSweep(run, findingRow, reposDir, mountedRepos)
      .catch(() => { /* best-effort variant sweep */ })
      .finally(() => {
        this.variantSweepInFlight.delete(findingRow.id)
        this.variantSweptFindings.add(findingRow.id)
        this.scheduleWake()
      })
  }

  private async runPostConfirmationVariantSweep(
    run: Run,
    findingRow: typeof findings.$inferSelect,
    reposDir: string,
    mountedRepos: readonly string[],
  ) {
    const locs = findingRow.finding.codeLocations ?? []
    const primaryLoc = locs[0]
    if (!primaryLoc) return

    const approvedOrigins = this.approvedOriginsSet(run)
    const targetOrigin = approvedOrigins.has(findingRow.finding.origin)
      ? findingRow.finding.origin
      : [...approvedOrigins][0]
    if (!targetOrigin) return
    const asset = run.candidates.find(c => c.origin === targetOrigin && run.approved.includes(c.id))
      ?? run.candidates.find(c => run.approved.includes(c.id))
    if (!asset) return

    const siblingHits: Array<{ repo: string; file: string; line: number; preview: string }> = []
    const seenHit = new Set<string>()
    const overlapsOriginal = (repo: string, file: string, line: number) =>
      locs.some(l => l.repo === repo && l.file === file && line >= l.startLine - 1 && line <= l.endLine + 1)

    // 1. Fast deterministic sibling pattern sweep over mounted /repos (matches static_ast_proof ruleOrPattern or primary call signature)
    let searchTokens: string[] = []
    if (findingRow.replaySpecId) {
      try {
        const sp = this.storage.getReplaySpec(run.id, findingRow.replaySpecId)
        if (sp.spec.kind === 'static_ast_proof' && sp.spec.ruleOrPattern.trim()) {
          searchTokens.push(sp.spec.ruleOrPattern.trim())
        }
      } catch { /* ignore */ }
    }
    const primaryFilePath = join(reposDir, primaryLoc.repo, primaryLoc.file)
    if (existsSync(primaryFilePath)) {
      try {
        const lines = readFileSync(primaryFilePath, 'utf8').split('\n')
        const lineText = lines[Math.max(0, primaryLoc.startLine - 1)] ?? ''
        const callSig = /[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)/.exec(lineText)
        if (callSig && !searchTokens.includes(callSig[0])) searchTokens.push(callSig[0])
      } catch { /* ignore */ }
    }

    if (searchTokens.length > 0) {
      const scanExt = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.rb'])
      for (const mountedRepo of mountedRepos) {
        const repoRel = mountedRepo.replace(/^\/repos\//, '').replace(/\/+$/, '')
        const repoRoot = join(reposDir, repoRel)
        if (!existsSync(repoRoot)) continue
        const stack = [repoRoot]
        while (stack.length > 0 && siblingHits.length < 20) {
          const dir = stack.pop()!
          let entries: string[]
          try { entries = readdirSync(dir) } catch { continue }
          for (const entry of entries) {
            if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === 'build') continue
            const full = join(dir, entry)
            let st
            try { st = statSync(full) } catch { continue }
            if (st.isDirectory()) {
              stack.push(full)
            } else if (st.isFile() && st.size <= 256 * 1024 && scanExt.has(extname(entry).toLowerCase())) {
              const relFile = relative(repoRoot, full).split(sep).join('/')
              let content: string
              try { content = readFileSync(full, 'utf8') } catch { continue }
              const lines = content.split('\n')
              for (let i = 0; i < lines.length; i += 1) {
                if (searchTokens.some(tok => lines[i].includes(tok))) {
                  const lineNo = i + 1
                  if (overlapsOriginal(repoRel, relFile, lineNo)) continue
                  const key = `${repoRel}:${relFile}:${lineNo}`
                  if (seenHit.has(key)) continue
                  seenHit.add(key)
                  siblingHits.push({ repo: repoRel, file: relFile, line: lineNo, preview: lines[i].trim().slice(0, 180) })
                }
              }
            }
          }
        }
      }
    }

    // 2. Also invoke runVariantSweepForFinding (semantic-audit.ts) when no direct deterministic sibling hits were found
    if (siblingHits.length === 0) {
      try {
        const currentRun = this.storage.run(run.id)
        const profiles = privateModelProfiles(this.storage)
        const sweepRes = await runVariantSweepForFinding({
          storage: this.storage,
          run: currentRun,
          backend: this.backend,
          reposDir,
          mountedRepos,
          approvedOrigins: [...approvedOrigins],
          modelProfiles: resolveProfilePoolForRole('reasoning', profiles),
          signal: AbortSignal.timeout(15_000),
        }, {
          finding: findingRow.finding,
          mountedRepos,
        })
        for (const s of sweepRes.newSuspects) {
          const key = `${s.repo}:${s.file}:${s.line}`
          if (seenHit.has(key)) continue
          seenHit.add(key)
          siblingHits.push({ repo: s.repo, file: s.file, line: s.line, preview: s.hypothesis.slice(0, 180) })
        }
      } catch { /* best-effort */ }
    }

    if (siblingHits.length === 0) return

    const currentRun = this.storage.run(run.id)
    const existingSteps = this.storage.listChainSteps(currentRun.id, currentRun.goalRevision)
    const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
    for (const hit of siblingHits.slice(0, 12)) {
      const title = `Variant sweep · ${hit.file}:${hit.line} (sibling of ${findingRow.finding.title.slice(0, 60)})`
      if (existingTitles.has(title.toLowerCase())) continue
      const specialistProfile = routeStepToSpecialist({
        title: `${title} ${findingRow.finding.title}`,
        hypothesis: hit.preview,
        category: findingRow.finding.category,
      })
      this.storage.addChainStep(currentRun, {
        title,
        hypothesis: `Post-confirmation Variant Sweep matched sibling pattern of confirmed finding ${findingRow.id} (${findingRow.finding.title}) at ${hit.repo}/${hit.file}:${hit.line}: ${hit.preview}`,
        category: findingRow.finding.category ?? 'broken-access-control',
        priority: 92,
        targetAssetIds: [asset.id],
        skills: ['source-first-audit', 'bola-idor-race', 'false-positive-elimination'],
        sourceOrigins: [targetOrigin],
        specialistProfile,
      })
      existingTitles.add(title.toLowerCase())
    }
    this.storage.event(
      currentRun.id,
      'variant_sweep.complete',
      `Variant sweep for finding "${findingRow.finding.title}" discovered ${siblingHits.length} sibling target(s).`,
      { findingId: findingRow.id, siblingsFound: siblingHits.length },
    )
  }

  private deterministicLaneKey(run: Pick<Run, 'id' | 'goalRevision' | 'scopeRevision'>): string {
    return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
  }

  /** `min(240 s, 40% × maxDurationMs)`; deterministicOnly stays unrestricted (no lane there). */
  private deterministicLaneDeadlineMs(): number {
    return Math.max(
      15_000,
      Math.min(deterministicLaneMaxWallClockMs, Math.floor(this.maxDurationMs * deterministicLaneWallClockShare)),
    )
  }

  private shouldStartDeterministicLane(run: Run, profiles: readonly ResolvedModelProfile[]): boolean {
    if (this.deterministicSweep === 'off') return false
    if (this.deterministicOnly) return false
    if (!profiles.length) return false
    if (run.status !== 'running' || run.phase !== 'investigation') return false
    if (run.capabilityTier < 1) return false
    if (this.approvedOriginsSet(run).size === 0) return false
    const key = this.deterministicLaneKey(run)
    if (this.agenticLaneJobs.has(run.id)) return false
    if (this.agenticLaneCompleted.has(key)) return false
    if (this.agenticLaneStopping.has(run.id)) return false
    // Conservative: a missing pre-Phase-0 record means the run may have been resumed with seeded
    // steps, so skip unless the operator forced 'always'.
    const seeded = this.prePhase0SeededSteps.get(key)
    if (seeded !== false && this.deterministicSweep !== 'always') return false
    if (this.deterministicInFlight.has(`${key}:engine`) || this.deterministicCompleted.has(`${key}:engine`)) return false
    return true
  }

  /**
   * Phase A: start the deterministic floor as the first, blocking investigation phase. It uses the
   * exact `--no-llm` implementation and deep policy; agents are not dispatched until it settles.
   * Returns true when the floor is (or remains) in flight, so `driveInvestigation` yields to it.
   */
  private startDeterministicLane(run: Run, profiles: readonly ResolvedModelProfile[]): boolean {
    if (!this.shouldStartDeterministicLane(run, profiles)) return this.agenticLaneJobs.has(run.id)
    const key = this.deterministicLaneKey(run)
    const controller = new AbortController()
    const holder = {
      controller,
      key,
      assignmentId: '',
      promise: Promise.resolve(),
    }
    this.agenticLaneJobs.set(run.id, holder)
    this.laneStartedAt.set(run.id, Date.now())
    this.agenticFloorStartedAt.set(run.id, Date.now())
    // Phase-A allowance starts here: Phase-0 discovery/scope requests stay outside both phases.
    this.beginFloorRequestPhase(this.storage.run(run.id))
    const deadlineMs = this.deterministicLaneDeadlineMs()
    try {
      this.storage.event(
        run.id,
        'deterministic_lane.started',
        `Deterministic floor (Phase A) started before agents (deadline ${Math.round(deadlineMs / 1000)}s, ${Math.round(deterministicFloorWallClockShare * 100)}% of run wall clock).`,
        { deadlineMs, maxDurationMs: this.maxDurationMs, mode: this.deterministicSweep, sequential: true },
      )
    } catch { /* run may be gone */ }
    this.traceLifecycle(run.id, 'lane_start', { deadlineMs, maxDurationMs: this.maxDurationMs, mode: this.deterministicSweep })
    holder.promise = this.runEngineInvestigation(run, {
      signal: controller.signal,
      maxDurationMs: deadlineMs,
      onAssignment: id => {
        holder.assignmentId = id
        this.agenticLaneAssignmentIds.add(id)
      },
    })
      .catch(error => {
        if (controller.signal.aborted) return
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, 'deterministic_lane.failed', `Deterministic floor failed: ${msg}`)
        } catch { /* run may be gone */ }
      })
      .finally(() => {
        this.agenticLaneJobs.delete(run.id)
        this.agenticLaneStopping.delete(run.id)
        this.agenticLaneCompleted.add(key)
        this.agenticFloorFinishedAt.set(run.id, Date.now())
        this.traceLifecycle(run.id, 'lane_end', { aborted: controller.signal.aborted, deadlineMs })
        try { this.settleFloorRequestPhase(run.id, controller.signal.aborted ? 'floor_aborted' : 'floor_complete') } catch { /* metrics only */ }
        try { this.recordFloorMetrics(run.id, controller.signal.aborted ? 'floor_aborted' : 'floor_complete') } catch { /* metrics only */ }
        this.laneStartedAt.delete(run.id)
        try { this.scheduleWake() } catch { /* scheduler stopped */ }
      })
    return true
  }

  /**
   * Abort the lane and wait for a fast settle. Callers gate the Phase-3 transition on the
   * returned promise so no deterministic work is still running when verification/report starts.
   */
  private abortAgenticLane(run: Run, reason: string): Promise<void> {
    const lane = this.agenticLaneJobs.get(run.id)
    if (!lane) return Promise.resolve()
    if (this.agenticLaneStopping.has(run.id)) return lane.promise.then(() => undefined, () => undefined)
    this.agenticLaneStopping.add(run.id)
    try {
      this.storage.event(run.id, 'deterministic_lane.aborting', `Stopping concurrent deterministic lane: ${reason}.`)
    } catch { /* run may be gone */ }
    this.traceLifecycle(run.id, 'abort', { reason })
    try { lane.controller.abort(new Error(reason)) } catch { /* already aborted */ }
    let timer: NodeJS.Timeout | undefined
    const settleTimeout = new Promise<void>(resolve => {
      timer = setTimeout(resolve, 2_000)
      timer.unref?.()
    })
    return Promise.race([lane.promise.then(() => undefined, () => undefined), settleTimeout])
      .finally(() => { if (timer) clearTimeout(timer) })
  }

  /** Verified handler/endpoint reported by the replay verifier's endpoint binding, if any. */
  private verifiedEndpointOf(result: { evidencePayload?: Record<string, unknown> }): string | null {
    const binding = result.evidencePayload?.endpointBinding as
      | { verifiedEndpoint?: { origin?: unknown; method?: unknown; pathAndQuery?: unknown } | null }
      | undefined
    const ve = binding?.verifiedEndpoint
    if (!ve || typeof ve.method !== 'string' || typeof ve.origin !== 'string' || typeof ve.pathAndQuery !== 'string') return null
    return `${ve.method.toUpperCase()} ${ve.origin}${ve.pathAndQuery}`.slice(0, 320)
  }

  // --- v6 split request budgets (Phase A floor / Phase B agents) ------------------------------

  /**
   * Start Phase-A accounting. No-op in legacy mode. Called once, as close as possible to the
   * floor's first request, so Phase-0 discovery/scope requests are not charged to Phase A.
   */
  private beginFloorRequestPhase(run: Run): PhaseRequestState | null {
    if (!this.phaseRequestBudgets) return null
    const existing = this.phaseRequestState.get(run.id)
    if (existing) return existing
    const state: PhaseRequestState = {
      floorBudget: this.phaseRequestBudgets.floor,
      agentBudget: this.phaseRequestBudgets.agent,
      baselineRequests: run.spentRequests,
      floorRequests: 0,
      floorSettled: false,
      floorBudgetExhausted: false,
      agentBudgetExhausted: false,
      agentExhaustedReported: false,
      floorExhaustedReported: false,
      agentSettled: false,
      agentRequests: 0,
    }
    this.phaseRequestState.set(run.id, state)
    try {
      this.storage.event(
        run.id,
        'request_budget.phase_started',
        `Phase A request allowance ${state.floorBudget}; Phase B allowance ${state.agentBudget} (split budgets; no borrowing).`,
        {
          phase: 'floor',
          floorRequestBudget: state.floorBudget,
          agentRequestBudget: state.agentBudget,
          totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
          spentRequestsAtStart: state.baselineRequests,
        },
      )
    } catch { /* telemetry is best-effort */ }
    return state
  }

  /**
   * Start (or adopt) Phase-B accounting when no floor lane ran (e.g. the deterministic sweep is
   * off). A floor that did run settles itself and is not re-baselined here.
   */
  private beginAgentRequestPhase(run: Run): PhaseRequestState | null {
    if (!this.phaseRequestBudgets) return null
    const existing = this.phaseRequestState.get(run.id)
    if (existing) return existing
    const state: PhaseRequestState = {
      floorBudget: this.phaseRequestBudgets.floor,
      agentBudget: this.phaseRequestBudgets.agent,
      baselineRequests: run.spentRequests,
      floorRequests: 0,
      floorSettled: true,
      floorBudgetExhausted: false,
      agentBudgetExhausted: false,
      agentExhaustedReported: false,
      floorExhaustedReported: false,
      agentSettled: false,
      agentRequests: 0,
    }
    this.phaseRequestState.set(run.id, state)
    try {
      this.storage.event(
        run.id,
        'request_budget.phase_started',
        `Phase B request allowance ${state.agentBudget} (no Phase-A floor in this run).`,
        {
          phase: 'agent',
          floorRequestBudget: state.floorBudget,
          agentRequestBudget: state.agentBudget,
          totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
          spentRequestsAtStart: state.baselineRequests,
        },
      )
    } catch { /* telemetry is best-effort */ }
    return state
  }

  /**
   * Freeze Phase-A spend and expose the Phase-B allowance. Called when the floor settles (lane
   * completion or `--no-llm` completion). Idempotent.
   */
  private settleFloorRequestPhase(runId: string, reason: string): void {
    const state = this.phaseRequestState.get(runId)
    if (!state || state.floorSettled) return
    let run: Run
    try { run = this.storage.run(runId) } catch { return }
    state.floorRequests = Math.max(0, run.spentRequests - state.baselineRequests)
    state.floorSettled = true
    state.floorBudgetExhausted = state.floorRequests >= state.floorBudget
    try {
      this.storage.event(
        runId,
        'request_budget.floor_settled',
        `Phase A used ${state.floorRequests}/${state.floorBudget} request(s); Phase B allowance is ${state.agentBudget}.`,
        {
          phase: 'floor',
          reason,
          floorRequests: state.floorRequests,
          floorRequestBudget: state.floorBudget,
          agentRequestBudget: state.agentBudget,
          totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
          spentRequestsAtStart: state.baselineRequests,
          spentRequestsAtSettle: run.spentRequests,
          floorBudgetExhausted: state.floorBudgetExhausted,
        },
      )
    } catch { /* telemetry is best-effort */ }
    if (state.floorBudgetExhausted && !state.floorExhaustedReported) {
      state.floorExhaustedReported = true
      try {
        this.storage.event(
          runId,
          'request_budget.floor_exhausted',
          `Phase A floor exhausted its ${state.floorBudget}-request allowance; Phase B keeps its own allowance.`,
          { phase: 'floor', floorRequests: state.floorRequests, floorRequestBudget: state.floorBudget },
        )
      } catch { /* telemetry is best-effort */ }
    }
  }

  /**
   * Freeze Phase-B spend when agentic investigation ends. Verification (Phase 3) still sends
   * requests from the run-total cap, but they must not be reported as Phase-B consumption.
   * Idempotent; `--no-llm` runs have no Phase B and never reach here.
   */
  private settleAgentRequestPhase(runId: string, reason: string): void {
    const state = this.phaseRequestState.get(runId)
    if (!state || !state.floorSettled || state.agentSettled) return
    let run: Run
    try { run = this.storage.run(runId) } catch { return }
    state.agentRequests = Math.max(0, run.spentRequests - state.baselineRequests - state.floorRequests)
    state.agentSettled = true
    if (state.agentRequests >= state.agentBudget) state.agentBudgetExhausted = true
    try {
      this.storage.event(
        runId,
        'request_budget.phase_ended',
        `Phase B used ${state.agentRequests}/${state.agentBudget} request(s) (floor ${state.floorRequests}/${state.floorBudget}).`,
        {
          phase: 'agent',
          reason,
          agentRequests: state.agentRequests,
          agentRequestBudget: state.agentBudget,
          floorRequests: state.floorRequests,
          floorRequestBudget: state.floorBudget,
          totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
          agentBudgetExhausted: state.agentBudgetExhausted,
          terminationReason: this.phaseTerminationReason.get(runId) ?? null,
        },
      )
    } catch { /* telemetry is best-effort */ }
  }

  /**
   * Requests the current phase may still spend. Legacy mode = remaining run budget. Split mode =
   * `min(run budget remaining, phase allowance remaining)`; phases never borrow from each other.
   */
  private phaseRequestRemaining(run: Run): number | null {
    const runRemaining = run.budgetRequests > 0 ? Math.max(0, run.budgetRequests - run.spentRequests) : null
    if (!this.phaseRequestBudgets) return runRemaining
    const state = this.phaseRequestState.get(run.id)
    if (!state) return runRemaining
    const spent = Math.max(0, run.spentRequests - state.baselineRequests)
    const phaseRemaining = state.floorSettled
      ? Math.max(0, state.agentBudget - Math.max(0, spent - state.floorRequests))
      : Math.max(0, state.floorBudget - spent)
    if (state.floorSettled && phaseRemaining <= 0) state.agentBudgetExhausted = true
    return runRemaining === null ? phaseRemaining : Math.min(phaseRemaining, runRemaining)
  }

  /** Honest telemetry snapshot for metrics (`deterministic_floor.summary`) and tests. */
  private requestBudgetSnapshot(runId: string, floorReportedRequests: number): {
    requestBudgetMode: 'split' | 'single'
    floorRequests: number
    floorRequestBudget: number | null
    agentRequests: number | null
    agentRequestBudget: number | null
    totalRequestBudget: number | null
    floorBudgetExhausted: boolean
    agentBudgetExhausted: boolean
    terminationReason: string | null
  } {
    let run: Pick<Run, 'spentRequests' | 'budgetRequests'>
    try { run = this.storage.run(runId) } catch { run = { spentRequests: 0, budgetRequests: 0 } }
    const state = this.phaseRequestState.get(runId) ?? null
    const totalRequestBudget = run.budgetRequests > 0 ? run.budgetRequests : null
    const terminationReason = this.phaseTerminationReason.get(runId) ?? null
    if (!this.phaseRequestBudgets) {
      return {
        requestBudgetMode: 'single',
        floorRequests: floorReportedRequests,
        floorRequestBudget: null,
        agentRequests: Math.max(0, run.spentRequests - floorReportedRequests),
        agentRequestBudget: null,
        totalRequestBudget,
        floorBudgetExhausted: false,
        agentBudgetExhausted: false,
        terminationReason,
      }
    }
    const floorRequests = state?.floorSettled
      ? state.floorRequests
      : Math.max(0, run.spentRequests - (state?.baselineRequests ?? run.spentRequests))
    const agentRequests = state
      ? state.agentSettled
        ? state.agentRequests
        : Math.max(0, run.spentRequests - state.baselineRequests - floorRequests)
      : 0
    return {
      requestBudgetMode: 'split',
      floorRequests,
      floorRequestBudget: state?.floorBudget ?? this.phaseRequestBudgets.floor,
      agentRequests,
      agentRequestBudget: state?.agentBudget ?? this.phaseRequestBudgets.agent,
      totalRequestBudget,
      floorBudgetExhausted: state?.floorBudgetExhausted ?? false,
      agentBudgetExhausted: state?.agentBudgetExhausted ?? false,
      terminationReason,
    }
  }

  /**
   * Report an exhausted Phase-B allowance once. Dispatch already stopped; this records why the
   * investigation phase ended instead of letting a wall-clock stop mislabel it.
   */
  private reportAgentBudgetExhausted(run: Run, readySteps: number, activeAssignments: number): void {
    const state = this.phaseRequestState.get(run.id)
    if (!state || !state.agentBudgetExhausted || state.agentExhaustedReported) return
    state.agentExhaustedReported = true
    this.phaseTerminationReason.set(run.id, 'agent_budget_exhausted')
    const snapshot = this.requestBudgetSnapshot(run.id, 0)
    try {
      this.storage.event(
        run.id,
        'request_budget.agent_exhausted',
        `Phase B agent request allowance exhausted (${snapshot.agentRequests}/${snapshot.agentRequestBudget}); `
        + `${readySteps} ready step(s) left undispatched, ${activeAssignments} assignment(s) still in flight.`,
        {
          phase: 'agent',
          reason: 'agent_budget_exhausted',
          agentRequests: snapshot.agentRequests,
          agentRequestBudget: snapshot.agentRequestBudget,
          floorRequests: snapshot.floorRequests,
          floorRequestBudget: snapshot.floorRequestBudget,
          readySteps,
          activeAssignments,
        },
      )
    } catch { /* telemetry is best-effort */ }
  }

  /**
   * Record the v6 Phase-1 gate counters (observed attribution, never asserted capability):
   *  - `floorConfirmed`  findings whose id was emitted by a `deterministic_engine.confirmed` event,
   *  - `floorStandaloneExpected` confirmations the floor itself reported (same deep policy as
   *    `--no-llm`), so preservation is measurable without re-running the benchmark,
   *  - `agenticConfirmed` every other confirmed finding,
   *  - `floorLeadsEmitted`/`floorLeadsConsumed` det_lead signals and upgraded assignments,
   *  - `laneWallMs` and phase timings for the sequential Phase A floor.
   */
  private recordFloorMetrics(runId: string, reason: string): void {
    const deterministicIds = new Set<string>()
    let floorRequests = 0
    let floorStandaloneExpected = 0
    let floorLeadsEmitted = 0
    // Paginate: a deep floor emits >3k broker/probe events, so a single capped page silently
    // misses the summary/confirmation events at the tail.
    let after = 0
    for (;;) {
      const page = this.storage.eventsAfter(runId, after, 1_000)
      if (!page.length) break
      for (const event of page) {
        if (event.kind === 'deterministic_engine.confirmed') {
          const id = event.detail?.findingId
          if (typeof id === 'string') deterministicIds.add(id)
        } else if (event.kind === 'deterministic_engine.summary') {
          const used = Number(event.detail?.requestsUsed)
          if (Number.isFinite(used) && used > 0) floorRequests += used
          const confirmed = Number(event.detail?.confirmed)
          if (Number.isFinite(confirmed) && confirmed > 0) floorStandaloneExpected += confirmed
        } else if (event.kind === 'deterministic_engine.lead') {
          floorLeadsEmitted += 1
        }
      }
      after = page[page.length - 1]!.id
      if (page.length < 1_000) break
    }
    let floorConfirmed = 0
    let agenticConfirmed = 0
    try {
      const rows = this.storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
      for (const row of rows) {
        if (row.finding.status !== 'confirmed') continue
        if (deterministicIds.has(row.id)) floorConfirmed += 1
        else agenticConfirmed += 1
      }
    } catch { /* run may be gone */ }
    const startedAt = this.laneStartedAt.get(runId)
    const laneWallMs = startedAt ? Math.max(0, Date.now() - startedAt) : (this.laneWallByRun.get(runId) ?? 0)
    if (startedAt) this.laneWallByRun.set(runId, laneWallMs)
    const floorStartedAt = this.agenticFloorStartedAt.get(runId) ?? startedAt ?? null
    const floorFinishedAt = this.agenticFloorFinishedAt.get(runId)
      ?? (floorStartedAt !== null ? floorStartedAt + laneWallMs : null)
    const preservationRatio = floorStandaloneExpected > 0
      ? Number((floorConfirmed / floorStandaloneExpected).toFixed(4))
      : (floorConfirmed > 0 ? 1 : 0)
    const dispatchedAt = this.agenticFloorDispatchedAt.get(runId)
    const phaseTimings = {
      floorStartedAt,
      floorFinishedAt,
      floorMs: floorStartedAt !== null && floorFinishedAt !== null ? Math.max(0, floorFinishedAt - floorStartedAt) : laneWallMs,
      agentDispatchAt: dispatchedAt ?? null,
      dispatchAfterFloorMs: dispatchedAt && floorFinishedAt ? Math.max(0, dispatchedAt - floorFinishedAt) : null,
    }
    // Split-budget accounting: when the floor settled, its measured request delta is authoritative;
    // legacy mode keeps the engine-reported sum so existing preservation metrics are unchanged.
    const budget = this.requestBudgetSnapshot(runId, floorRequests)
    const detail = {
      reason,
      floorConfirmed,
      floorStandaloneExpected,
      preservationRatio,
      agenticConfirmed,
      floorLeadsEmitted,
      floorLeadsConsumed: this.detLeadConsumed.size,
      laneWallMs,
      floorRequests: budget.floorRequests,
      floorRequestBudget: budget.floorRequestBudget,
      agentRequests: budget.agentRequests,
      agentRequestBudget: budget.agentRequestBudget,
      totalRequestBudget: budget.totalRequestBudget,
      requestBudgetMode: budget.requestBudgetMode,
      floorBudgetExhausted: budget.floorBudgetExhausted,
      agentBudgetExhausted: budget.agentBudgetExhausted,
      terminationReason: budget.terminationReason,
      requestBudgets: budget,
      phaseTimings,
    }
    try {
      this.storage.event(
        runId,
        'deterministic_lane.metrics',
        `Floor ${floorConfirmed} confirmed / agentic ${agenticConfirmed} confirmed; ${this.detLeadConsumed.size} det_lead(s) consumed; lane ${Math.round(laneWallMs / 1000)}s.`,
        detail,
      )
    } catch { /* metrics are best-effort */ }
    try {
      this.storage.event(
        runId,
        'deterministic_floor.summary',
        `Floor ${floorConfirmed}/${floorStandaloneExpected} preserved (${(preservationRatio * 100).toFixed(0)}%), ${floorLeadsEmitted} lead(s) emitted / ${this.detLeadConsumed.size} consumed, ${budget.floorRequests} floor request(s)${budget.floorRequestBudget !== null ? `/${budget.floorRequestBudget}` : ''}, ${budget.agentRequests ?? 0} agent request(s)${budget.agentRequestBudget !== null ? `/${budget.agentRequestBudget}` : ''}, Phase A ${Math.round(laneWallMs / 1000)}s${budget.terminationReason ? `, stopped: ${budget.terminationReason}` : ''}.`,
        detail,
      )
    } catch { /* metrics are best-effort */ }
  }

  /**
   * Phase-B throughput telemetry (observed, never asserted): assignment wall p50/p90, turns per
   * assignment, provider stall turns, and container launches/reuse. `verified_tp_per_100s_phase_b`
   * is driven by these, so they must be readable without parsing raw logs.
   */
  private recordAssignmentMetrics(runId: string, reason: string): AssignmentThroughputMetrics | null {
    let workers: Assignment[] = []
    try {
      workers = this.storage.workerList(runId).filter(worker => worker.phase === 'investigation')
    } catch { return null }
    const walls = this.assignmentWallByRun.get(runId) ?? []
    const completedWalls = this.completedAssignmentWallByRun.get(runId) ?? []
    const turnSamples = this.turnLatencyByRun.get(runId) ?? []
    const turnSummary = summarizeTurnLatencies(turnSamples)
    const containers = this.backend.containerStats?.()
    const turns = workers.map(worker => worker.turnsUsed)
    const metrics: AssignmentThroughputMetrics = {
      reason,
      assignmentsObserved: workers.length,
      assignmentsCompleted: workers.filter(worker => worker.status === 'complete').length,
      assignmentsPausedAtStop: workers.filter(worker => worker.status === 'paused').length,
      assignmentWallP50: Math.round(percentile(walls, 50)),
      assignmentWallP90: Math.round(percentile(walls, 90)),
      assignmentWallSamples: walls.length,
      completedAssignmentWallP50: Math.round(percentile(completedWalls, 50)),
      completedAssignmentWallSamples: completedWalls.length,
      turnsPerAssignment: turns.length ? Math.round((turns.reduce((sum, n) => sum + n, 0) / turns.length) * 10) / 10 : 0,
      providerStallTurns: this.providerStallTurnsByRun.get(runId) ?? 0,
      providerStallRetries: this.providerStallRetriesByRun.get(runId) ?? 0,
      turnLatencyP50: turnSummary.p50,
      turnLatencyP90: turnSummary.p90,
      containersLaunched: containers?.created ?? 0,
      containersReused: containers?.reused ?? 0,
      containerSessions: containers?.sessions ?? 0,
      coldContainerSessions: containers?.coldSessions ?? 0,
      idleWarmContainers: containers?.idle ?? 0,
      warmCapacity: containers?.capacity ?? 0,
    }
    this.lastAssignmentMetrics.set(runId, metrics)
    try {
      this.storage.event(
        runId,
        'agentic.assignment_metrics',
        `Phase B throughput: ${metrics.assignmentsCompleted}/${metrics.assignmentsObserved} assignment(s) complete, p50 ${(metrics.assignmentWallP50 / 1000).toFixed(1)}s / p90 ${(metrics.assignmentWallP90 / 1000).toFixed(1)}s, ${metrics.turnsPerAssignment} turn(s)/assignment, ${metrics.providerStallTurns} stall turn(s) / ${metrics.providerStallRetries} bounded retry(ies), ${metrics.containersLaunched} container launch(es) / ${metrics.containersReused} reuse(s).`,
        { ...metrics },
      )
    } catch { /* metrics are best-effort */ }
    return metrics
  }

  /** Last recorded Phase-B throughput metrics for a run (test/benchmark seam). */
  getAssignmentThroughput(runId: string): AssignmentThroughputMetrics | null {
    return this.lastAssignmentMetrics.get(runId) ?? null
  }

  // --- Slice 3 / agentic value-add: read-only prompt context builders ---
  /** Confirmed + static-verified (endpoint, method, param, cwe) refs. Prompt context only. */
  private alreadyConfirmedRefs(run: Run, limit = 10): AlreadyConfirmedRef[] {
    try {
      const rows = this.storage.db.select().from(findings).where(and(
        eq(findings.runId, run.id),
        eq(findings.goalRevision, run.goalRevision),
      )).all()
      const specById = new Map(this.storage.listReplaySpecs(run.id).map(spec => [spec.id, spec]))
      const refs: AlreadyConfirmedRef[] = []
      const seen = new Set<string>()
      for (const row of rows) {
        if (row.finding.status !== 'confirmed' && row.finding.status !== 'static_verified') continue
        const spec = row.replaySpecId ? specById.get(row.replaySpecId) : undefined
        const fields = spec ? extractSpecDedupeFields(spec.spec) : null
        const path = fields?.endpoint?.trim()
        if (!path) continue
        const method = fields?.method && fields.method !== 'ANY' ? fields.method : null
        const key = `${method ?? ''} ${path} ${fields?.param ?? ''} ${row.finding.cwe ?? ''}`
        if (seen.has(key)) continue
        seen.add(key)
        refs.push({
          origin: row.finding.origin,
          ...(method ? { method } : {}),
          path,
          ...(fields?.param ? { param: fields.param } : {}),
          ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
          ...(row.finding.category ? { probeClass: row.finding.category } : {}),
        })
        if (refs.length >= limit) break
      }
      return refs
    } catch {
      return []
    }
  }

  /** High-risk or under-covered surface that has not been confirmed. Prompt context only. */
  private unconfirmedHardSurfaceRefs(run: Run, confirmed: readonly AlreadyConfirmedRef[], limit = 8): UnconfirmedSurfaceRef[] {
    try {
      const confirmedPaths = new Set(confirmed.map(ref => normalizeEndpointTemplate(ref.path)))
      const refs: UnconfirmedSurfaceRef[] = []
      const seen = new Set<string>()
      for (const gap of this.storage.listOpenProofGaps(run.id, run.goalRevision)) {
        const key = `${gap.category} ${gap.origin} ${gap.summary.slice(0, 40)}`
        if (seen.has(key)) continue
        seen.add(key)
        refs.push({
          path: `${gap.origin} ${gap.category}`,
          category: gap.category,
          reason: gap.proofGapReason || gap.summary,
        })
        if (refs.length >= limit) break
      }
      if (refs.length < limit) {
        const endpoints = this.storage.listEndpoints(run.id, { orderBy: 'risk', limit: 40 })
        for (const ep of endpoints) {
          if (refs.length >= limit) break
          if (confirmedPaths.has(normalizeEndpointTemplate(ep.pathTemplate))) continue
          if (ep.riskScore < 60) continue
          const key = `${ep.method} ${ep.pathTemplate}`
          if (seen.has(key)) continue
          seen.add(key)
          refs.push({
            method: ep.method,
            path: ep.pathTemplate,
            category: ep.testedClasses?.[0] ?? null,
            reason: `risk ${ep.riskScore}, coverage ${ep.coveragePct ?? 0}%`,
          })
        }
      }
      return refs
    } catch {
      return []
    }
  }

  /** All deterministic lead facts for the run (not only parent-fact dependencies). */
  private detLeadSummaries(run: Run): DetLeadSummary[] {
    try {
      const facts = this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
        .filter(f => f.data?.kind === 'det_lead')
      return detLeadsFromParentFacts(facts)
    } catch {
      return []
    }
  }

  /** Endpoint templates a step explicitly names (normalized). Never used for eligibility. */
  private stepMentionedRoutes(step: Pick<ChainStep, 'title' | 'hypothesis'>): string[] {
    return templatesMentionedInText(`${step.title} ${step.hypothesis}`)
  }

  /**
   * A planner step that only names routes the deterministic floor already confirmed is a duplicate
   * dispatch, unless it declares a parent fact/step (that is an explicit chain/escalation).
   */
  private stepRepeatsConfirmedWork(step: Pick<ChainStep, 'title' | 'hypothesis' | 'dependsOnFactIds' | 'dependsOnStepIds'>, confirmed: readonly AlreadyConfirmedRef[]): boolean {
    if ((step.dependsOnFactIds?.length ?? 0) > 0 || (step.dependsOnStepIds?.length ?? 0) > 0) return false
    const routes = this.stepMentionedRoutes(step)
    if (!routes.length) return false
    const confirmedPaths = new Set(confirmed.map(ref => normalizeEndpointTemplate(ref.path)))
    return routes.every(route => confirmedPaths.has(route))
  }

  /**
   * Turn *evidence-backed* deterministic leads into upgrade assignments. A det_lead is only useful
   * to the agentic lane when it is (a) admitted by {@link detLeadEvidenceGate} — a control contrast
   * or near-miss exists, (b) unconfirmed and not a route/class the floor already confirmed, and
   * (c) bound to its originating fact so it becomes a `det_lead_upgrade` mission with a brief.
   *
   * Priority is deliberately below planner-authored class steps; the scheduler also caps lead
   * concurrency independently, so a lead backlog can never pre-empt unproven target classes.
   */
  private queueDetLeadUpgradeSteps(run: Run, approvedOrigins: ReadonlySet<string>, budget: number): number {
    const confirmed = this.alreadyConfirmedRefs(run, 40)
    const confirmedKeys = new Set(confirmed.map(ref =>
      `${normalizeEndpointTemplate(ref.path)}|${confirmedCategoryFamily(ref.probeClass ?? '')}`))
    const facts = [...this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })]
      // det_lead facts are listed in store row order (random row-id tiebreak). The upgrade queue
      // takes the first N, so sort by stable leading fields before choosing.
      .sort((a, b) => {
        const keyOf = (fact: typeof a) => `${String(fact.data?.endpoint ?? '')}\u0000${String(fact.data?.method ?? '')}\u0000${String(fact.data?.probeClass ?? '')}\u0000${fact.id}`
        return keyOf(a).localeCompare(keyOf(b))
      })
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const boundFactIds = new Set(existing.flatMap(step => step.dependsOnFactIds))
    let slots = Math.max(0, budget - existing.length)
    let created = 0
    for (const fact of facts) {
      if (slots <= 0 || created >= 4) break
      if (fact.data?.kind !== 'det_lead') continue
      if (!approvedOrigins.has(fact.origin)) continue
      const endpoint = typeof fact.data.endpoint === 'string' ? fact.data.endpoint : ''
      const probeClass = typeof fact.data.probeClass === 'string' ? fact.data.probeClass : ''
      const method = typeof fact.data.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      if (!endpoint.startsWith('/') || !probeClass) continue
      if (boundFactIds.has(fact.id)) continue
      const routeKey = `${normalizeEndpointTemplate(endpoint)}|${confirmedCategoryFamily(detLeadCategory(probeClass))}`
      if (confirmedKeys.has(routeKey)) continue
      if (this.detLeadStepKeys.has(`${method} ${routeKey}`)) continue
      const gate = detLeadEvidenceGate(fact.data)
      if (!gate.admitted) {
        if (!this.detLeadGateRejected.has(fact.id)) {
          this.detLeadGateRejected.add(fact.id)
          try {
            this.storage.event(
              run.id,
              'deterministic_lane.lead_deferred',
              `det_lead ${probeClass} on ${method} ${endpoint} not promoted: ${gate.reason}.`,
              { probeClass, endpoint, method, factId: fact.id, reason: gate.reason },
            )
          } catch { /* best-effort */ }
        }
        continue
      }
      const asset = run.candidates.find(c => c.origin === fact.origin && run.approved.includes(c.id))
      if (!asset) continue
      const category = detLeadCategory(probeClass)
      // v7 precision guard: cap re-investigation of the same (route, class) at 2 unless the lead
      // carries a new chain primitive / parent evidence that actually escalates the attempt.
      const guardKey = reinvestigationKey(endpoint, category)
      const verdict = this.reinvestigationGuardFor(run.id)
        .record(guardKey, detLeadUnlocksReinvestigation(fact.data))
      if (!verdict.allowed) {
        if (!this.cappedLeadReported.has(fact.id)) {
          this.cappedLeadReported.add(fact.id)
          this.noteCappedReinvestigation(run, guardKey, verdict.count)
        }
        continue
      }
      const reason = typeof fact.data.reason === 'string' ? fact.data.reason.slice(0, 200) : 'differential observation'
      const skills = detLeadSkills(probeClass)
      const title = `det_lead upgrade · ${probeClass} ${method} ${endpoint}`.slice(0, 180)
      const hypothesis = `The deterministic floor observed an unproven ${probeClass} signal at ${method} ${endpoint} (${reason}). Reproduce it, identify the concretely mutated input, and submit a verified proof or chain it into a higher-impact finding.`
      const createdStep = this.storage.addChainStep(run, {
        title,
        hypothesis,
        category,
        priority: DET_LEAD_STEP_PRIORITY,
        targetAssetIds: [asset.id],
        skills,
        dependsOnFactIds: [fact.id],
        sourceOrigins: [fact.origin],
        specialistProfile: routeStepToSpecialist({ title, hypothesis, category, skills }),
      })
      this.storage.updateChainStep(createdStep.id, { status: 'ready' })
      this.detLeadStepKeys.add(`${method} ${routeKey}`)
      this.detLeadConsumed.add(fact.id)
      slots -= 1
      created += 1
      try {
        this.storage.event(
          run.id,
          'deterministic_lane.lead_consumed',
          `det_lead ${probeClass} on ${method} ${endpoint} queued as a prioritized upgrade assignment.`,
          { probeClass, endpoint, method, factId: fact.id, stepId: createdStep.id },
        )
      } catch { /* best-effort */ }
    }
    return created
  }

  private missionKindForStep(step: ChainStep, hasDetLead: boolean): MissionKind {    if (/second.order|stored|canary/i.test(`${step.title} ${step.hypothesis}`)) return 'second_order'
    if (step.dependsOnStepIds.length > 0) return 'chain_step_2'
    if (/workflow|race|double.spend|business|quantity|price/i.test(`${step.title} ${step.hypothesis} ${step.category}`)) return 'business_logic'
    if (step.dependsOnFactIds.length > 0 && hasDetLead) return 'det_lead_upgrade'
    return 'class_scan'
  }

  /** Pre-packaged <=1.5 KB evidence brief for one assignment (routes/params/personas/IDs). */
  private assignmentBriefForStep(input: {
    run: Run
    step: ChainStep
    targetOrigins: readonly string[]
    personas: readonly { handle: string; roleLabel: string }[]
    parentFacts: readonly Fact[]
    confirmed: readonly AlreadyConfirmedRef[]
    detLeads: readonly DetLeadSummary[]
    maxTurns: number
  }): string | undefined {
    const origin = input.targetOrigins[0]
    if (!origin) return undefined
    try {
      const routes = this.storage.listEndpoints(input.run.id, { orderBy: 'risk', limit: 40 })
        .filter(ep => input.targetOrigins.includes(ep.origin))
        .slice(0, 6)
        .map(ep => ({
          method: ep.method,
          path: ep.pathTemplate,
          riskScore: ep.riskScore,
        }))
      const samples = this.storage.listResourceSamples(input.run.id)
        .filter(sample => input.targetOrigins.includes(sample.origin))
      const personas = input.personas.map(persona => ({
        handle: persona.handle,
        role: persona.roleLabel,
        harvestedIds: [...new Set(samples.filter(s => s.ownerPersona === persona.handle).map(s => s.resourceId))].slice(0, 4),
      }))
      const parentDetLead = input.detLeads.find(lead =>
        input.parentFacts.some(f => f.data?.kind === 'det_lead' && f.id === lead.exchangeId) ||
        (Boolean(lead.endpoint) && input.targetOrigins.includes(origin)),
      )
      const missionKind = this.missionKindForStep(input.step, Boolean(parentDetLead))
      // v7 whitebox hop: the persisted slice for this assignment's route reaches the brief.
      // Compact by default; only chain / 4-hop assignments pay for the expanded slice.
      const codeSlice = this.codeSliceForAssignment(input.run, input.step, input.parentFacts)
      const codeExpansion: 'compact' | 'full' = missionKind === 'chain_step_2' ||
        input.step.dependsOnStepIds.length > 0 ||
        (codeSlice?.hops.length ?? 0) >= 4
        ? 'full'
        : 'compact'
      const text = buildAssignmentBrief({
        missionKind,
        origin,
        routes,
        personas,
        alreadyConfirmedOnOrigin: input.confirmed
          .filter(ref => !ref.origin || ref.origin === origin)
          .map(ref => ({
            method: ref.method ?? 'ANY',
            path: ref.path,
            param: ref.param ?? null,
            cwe: ref.cwe ?? null,
            origin: ref.origin ?? origin,
          })),
        ...(parentDetLead
          ? {
              detLead: {
                probeClass: parentDetLead.probeClass,
                exchangeId: parentDetLead.exchangeId ?? null,
                signalSummary: parentDetLead.signalSummary ?? '',
                verifyFailureReason: parentDetLead.verifyFailureReason ?? null,
              },
            }
          : {}),
        ...(codeSlice ? { codeSlice, codeExpansion } : {}),
        targetCount: routes.length > 1 ? 2 : 1,
        turnBudget: input.maxTurns,
      })
      // The renderer owns the ladder; this assert turns a future regression into a loud failure.
      assertAssignmentBriefSize(text, ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
      return text
    } catch {
      return undefined
    }
  }

  private specialistWallClockMs(maxTurns: number): number {
    const envMs = Number(process.env.GUARDIAN_AGENTIC_SPECIALIST_WALL_CLOCK_MS)
    const base = Number.isFinite(envMs) && envMs > 0 ? envMs : AGENTIC_SPECIALIST_WALL_CLOCK_MS
    // Batched micro-specialists sit at AGENTIC_SPECIALIST_MAX_TURNS; longer legacy assignments
    // scale linearly up to 2x the base wall clock, always inside the 30-minute intent lease.
    const turnScale = Math.min(2, Math.max(0.5, maxTurns / Math.max(1, AGENTIC_SPECIALIST_MAX_TURNS)))
    return Math.max(20_000, Math.min(intentLeaseMs * 0.85, Math.round(base * turnScale)))
  }

  /**
   * v6: record the current dry-streak length as telemetry. A productive step resets the streak by
   * definition, so only increases are emitted. This is deliberately **not** a halt: the planner
   * keeps scheduling until the budget/round contract ends the investigation phase.
   */
  private noteDryStreak(run: Pick<Run, 'id' | 'goalRevision'>): void {
    const streak = countConsecutiveDrySteps(this.storage, run, this.agenticLaneAssignmentIds)
    const previous = this.dryStreakObserved.get(run.id) ?? 0
    if (streak <= previous) return
    this.dryStreakObserved.set(run.id, streak)
    this.storage.event(
      run.id,
      'planner.dry_streak',
      `Observed ${streak} consecutive dry step(s); planning continues while budget and work remain.`,
      {
        consecutiveDrySteps: streak,
        threshold: diminishingReturnsDryThreshold,
        halted: false,
      },
    )
  }

  /** Per-run reinvestigation guard (cap 2 per normalized route+class unless evidence unlocks). */
  private reinvestigationGuardFor(runId: string): ReinvestigationGuard {
    let guard = this.reinvestigationGuards.get(runId)
    if (!guard) {
      guard = new ReinvestigationGuard()
      this.reinvestigationGuards.set(runId, guard)
    }
    return guard
  }

  /**
   * True when no ready/pending high-priority step remains. High priority means the `det_lead`
   * upgrade lane or a chain-primitive dispatch; ordinary class scans do not keep a drained planner
   * alive on their own.
   */
  private highPriorityQueueEmpty(run: Pick<Run, 'id' | 'goalRevision'>): boolean {
    try {
      return !this.storage.listChainSteps(run.id, run.goalRevision).some(step =>
        (step.status === 'ready' || step.status === 'pending') &&
        (isDetLeadDispatchStep(step) ||
          step.skills.some(skill => skill.startsWith('chain:') || skill === 'chain-primitives') ||
          step.priority >= 88))
    } catch {
      return true
    }
  }

  /** Record a capped reinvestigation attempt as telemetry (one event per run). */
  private noteCappedReinvestigation(
    run: Pick<Run, 'id'>,
    key: string,
    attempted: number,
  ): void {
    const guard = this.reinvestigationGuardFor(run.id)
    try {
      this.storage.event(
        run.id,
        'planner.capped_reinvestigations',
        `Capped reinvestigation of ${key.replace('\u0000', ' ')} (attempt ${attempted + 1} > cap ${guard.cap}); no new chain primitive or parent evidence.`,
        { routeClass: key, attempted: attempted + 1, cap: guard.cap, ...guard.snapshot() },
      )
    } catch { /* best-effort */ }
  }

  /** Persist the latest structured funnel so the final metrics/report can read it directly. */
  private recordDispatchFunnel(runId: string, funnel: DispatchFunnelCounts): void {
    const previous = this.dispatchFunnels.get(runId)
    if (previous && previous.roundNo >= funnel.roundNo) return
    const cumulative = emptyDispatchFunnel(funnel.roundNo)
    if (previous) {
      // Per-round counts are additive; the remaining/dispatched fields are observations, so the
      // latest round wins for those (the final report wants the end-of-run picture).
      for (const key of DISPATCH_FUNNEL_COUNT_KEYS) cumulative[key] = previous[key] + funnel[key]
      cumulative.filteredDep = funnel.filteredDep
    } else {
      for (const key of DISPATCH_FUNNEL_COUNT_KEYS) cumulative[key] = funnel[key]
    }
    cumulative.dispatched = funnel.dispatched
    cumulative.dispatchedThisRound = Math.max(0, funnel.dispatched - (previous?.dispatched ?? 0))
    cumulative.remainingReady = funnel.remainingReady
    cumulative.remainingReadyAtStop = funnel.remainingReadyAtStop
    cumulative.stopReason = funnel.stopReason
    this.dispatchFunnels.set(runId, cumulative)
  }

  /**
   * Run-meta emission: the structured dispatch funnel for the whole run, plus the stranded-ready
   * invariant verdict. `stopReason` comes from the persisted run status so a wall-clock/budget stop
   * is reported as such (and therefore never counted as a violation).
   */
  private recordDispatchFunnelSummary(runId: string): void {
    const funnel = this.dispatchFunnels.get(runId)
    if (!funnel) return
    let status = ''
    try { status = this.storage.run(runId).status } catch { return }
    const stopReason: DispatchStopReason = status === 'paused'
      ? 'run_paused'
      : status === 'stopped' ? 'run_stopped' : funnel.stopReason
    const latestSteps = this.storage.listChainSteps(runId)
    const knownFacts = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(runId, { includeTainted: true, limit, offset })).map(fact => fact.id))
    const remainingReady = dispatchableReadySteps(latestSteps, knownFacts).length
    const dispatched = latestSteps.filter(step => step.assignedWorkerId !== null).length
    const blocked = permanentlyBlockedStepIds(latestSteps, knownFacts).length
    const evaluation = evaluateDispatchStop({
      decision: STRANDED_READY_STOP_REASONS.includes(stopReason) ? 'stop' : 'continue',
      reason: stopReason,
      remainingReady,
      freeSlots: 0,
      inFlight: latestSteps.filter(step => step.status === 'running').length,
      budgetExhausted: stopReason === 'budget_exhausted',
      requestExhausted: stopReason === 'requests_exhausted',
      wallExhausted: stopReason === 'wallclock_exhausted' || stopReason === 'run_stopped',
    })
    const strandedEventsBefore = this.strandedReadyEvents.get(runId) ?? 0
    if (evaluation.stranded) {
      this.noteStrandedReadySteps(runId, {
        roundNo: funnel.roundNo, stopReason, remainingReady, dispatched, planned: funnel.planned,
      })
    }
    const strandedEvents = this.strandedReadyEvents.get(runId) ?? 0
    try {
      this.storage.event(
        runId,
        'planner.funnel.summary',
        `Dispatch funnel: planned ${funnel.planned}, enqueued ${funnel.enqueued}, dispatched ${dispatched}, ready ${remainingReady}, blocked ${blocked}, stop ${stopReason}, stranded events ${strandedEvents}.`,
        {
          ...funnel, stopReason, remainingReadyAtStop: status === 'running' ? 0 : remainingReady,
          dispatched, filteredDep: blocked, strandedEvents,
          stranded: evaluation.stranded || strandedEventsBefore > 0,
        },
      )
    } catch { /* metrics are best-effort */ }
  }

  /** Loud, counted signal: a terminal planner stop abandoned dispatchable planned work. */
  private noteStrandedReadySteps(runId: string, detail: {
    roundNo: number
    stopReason: DispatchStopReason
    remainingReady: number
    dispatched: number
    planned: number
  }): void {
    this.strandedReadyEvents.set(runId, (this.strandedReadyEvents.get(runId) ?? 0) + 1)
    try {
      this.storage.event(
        runId,
        'planner.ready_steps_stranded',
        `Planner stopped (${detail.stopReason}) with ${detail.remainingReady} dispatchable step(s) undispatched; planned ${detail.planned}, dispatched ${detail.dispatched}.`,
        { ...detail, strandedEvents: this.strandedReadyEvents.get(runId) ?? 1 },
      )
    } catch { /* best-effort */ }
  }

  /**
   * The stored white-box slice for an assignment's route, if any. Parent det_lead facts win; a
   * fallback scan matches det_lead facts to routes the step explicitly names.
   */
  private codeSliceForAssignment(
    run: Pick<Run, 'id'>,
    step: Pick<ChainStep, 'title' | 'hypothesis'>,
    parentFacts: readonly Fact[],
  ): CodeDataflowSlice | undefined {
    const mentioned = new Set(this.stepMentionedRoutes(step).map(route => normalizeEndpointTemplate(route)))
    const text = `${step.title} ${step.hypothesis}`
    const candidates = [
      ...parentFacts.filter(fact => fact.data?.kind === 'det_lead'),
      ...this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
        .filter(fact => fact.data?.kind === 'det_lead'),
    ]
    for (const fact of candidates) {
      const data = fact.data as Record<string, unknown> | undefined
      const slice = data?.codeSlice as CodeDataflowSlice | undefined
      if (!slice || typeof slice !== 'object' || !Array.isArray(slice.hops)) continue
      const endpoint = typeof data?.endpoint === 'string' ? data.endpoint : ''
      const route = normalizeEndpointTemplate(endpoint || slice.route)
      const matched = mentioned.size
        ? mentioned.has(route)
        : Boolean(endpoint && text.includes(endpoint))
      if (!matched) continue
      return slice
    }
    return undefined
  }

  private seedCodeToRuntimeLeads(
    run: Run,
    assignment: Assignment,
    hypotheses: readonly CodeToRuntimeHypothesis[],
  ): number {
    return seedGraphLeads(
      this.storage,
      run,
      assignment,
      hypotheses,
      this.programGraphLeadsSeeded,
      [...this.approvedOriginsSet(run)].sort()[0] ?? '',
    )
  }

  private driveInvestigation(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (!profiles.length) {
      // Explicit --no-llm mode runs the deterministic engine. Without that flag the legacy M1
      // no-profile fallback stays byte-for-byte unchanged; it is suppressed while a worker is
      // parked awaiting an operator decision, because the run is not idle, it is blocked on a human.
      if (this.deterministicOnly) this.driveEngineInvestigation(run)
      else if (this.storage.parkedWorkerCount(run.id) === 0) this.driveDeterministicInvestigation(run)
      return
    }
    // Always compute & persist dynamic step budget clamp(24, crownJewels*2 + suspects, 200)
    const computedBudget = computeDynamicStepBudget(this.storage, run.id)
    if (run.dynamicStepBudget === null || run.dynamicStepBudget < computedBudget) {
      this.storage.updateRunDynamicStepBudget(run.id, computedBudget)
    }

    // Fan out eligible crown-jewel leads into parallel multi-trial branches before scheduling
    this.expandEligibleMultiTrialSteps(run)

    // Queue drain: a paused/queued assignment whose step is still `running` (pause mid-flight,
    // restart, reclaimed slot) never re-enters dispatch by itself. Requeue it so a slot that
    // freed is used instead of the step starving behind a dead assignment.
    try {
      const recovered = requeueInterruptedAssignments(this.storage, run)
      if (recovered > 0) this.storage.event(run.id, 'scheduler.queue_drain', `Requeued ${recovered} interrupted assignment(s).`, { recovered })
    } catch { /* drain is best-effort */ }

    this.storage.refreshReadyChainSteps(run.id, run.goalRevision)

    // Phase A: the deterministic floor runs sequentially *before* any agent dispatch, using the
    // same deep implementation/policy as `--no-llm`. It is not a sibling lane: dispatch yields
    // until it settles, so workers never race or clobber floor probe state and the floor cannot be
    // starved by specialist request/rate/budget pressure.
    try { this.ensureRunTrace(run, profiles) } catch { /* tracing is best-effort */ }
    if (this.startDeterministicLane(run, profiles)) return
    if (!this.agenticFloorDispatchedAt.has(run.id)) this.agenticFloorDispatchedAt.set(run.id, Date.now())
    // Phase B starts here (or adopts the run when no floor lane ran). Split mode keeps a separate
    // allowance, so a floor that ate its whole share can never starve agent dispatch.
    this.beginAgentRequestPhase(this.storage.run(run.id))

    // Round-1 lead seeding: the floor's unproven det_lead signals become prioritized upgrade
    // assignments even before the planner's first LLM turn, so `floorLeadsEmitted > 0` can never
    // silently coexist with `floorLeadsConsumed === 0`.
    try {
      if (!this.detLeadConsumed.size && this.agenticLaneCompleted.has(this.deterministicLaneKey(run))) {
        this.queueDetLeadUpgradeSteps(
          this.storage.run(run.id),
          this.approvedOriginsSet(run),
          computeDynamicStepBudget(this.storage, run.id),
        )
      }
    } catch { /* lead queueing is additive */ }

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const readySteps = steps
      .filter(s => s.status === 'ready')
      .filter(s => !(s.assignedWorkerId && this.active.has(s.assignedWorkerId)))
      .filter(s => {
        if (s.sourceOrigins.length > 0 && s.sourceOrigins.every(o => this.broker.isCircuitOpen(o))) {
          this.storage.updateChainStep(s.id, { status: 'blocked' })
          return false
        }
        return true
      })

    const maxConc = Math.max(1, Math.min(maxWorkerConcurrency, run.workerConcurrency || defaultWorkerConcurrency))
    // One warm session container per worker slot: assignments reuse stopped containers instead of
    // paying a cold `container create` each dispatch.
    try { this.backend.setWarmCapacity?.(maxConc) } catch { /* pooling is best-effort */ }
    const activeForRun = [...this.active.values()].filter(j => j.assignment.runId === run.id && j.assignment.phase === 'investigation').length
    // Honest Phase-B termination: once the agent allowance is gone, dispatch stops and the phase
    // ends as `agent_budget_exhausted` even when ready steps remain (they cannot afford a request).
    // In-flight assignments keep their lease; the handoff waits for them to settle.
    const freshRun = this.storage.run(run.id)
    this.phaseRequestRemaining(freshRun)
    const phaseState = this.phaseRequestState.get(run.id)
    if (this.phaseRequestBudgets && phaseState?.floorSettled && phaseState.agentBudgetExhausted) {
      this.reportAgentBudgetExhausted(freshRun, readySteps.length, activeForRun)
      if (activeForRun === 0) this.advanceToVerification(run)
      return
    }
    const leadStepIds = new Set(steps.filter(step => isDetLeadDispatchStep(step)).map(step => step.id))
    const activeLeadCount = [...this.active.values()].filter(job =>
      job.assignment.runId === run.id &&
      job.assignment.phase === 'investigation' &&
      typeof job.assignment.stepId === 'string' &&
      leadStepIds.has(job.assignment.stepId)).length

    const slots = Math.max(0, maxConc - activeForRun)
    const hostTiers = computeHostTiers(
      [...this.approvedOriginsSet(run)],
      this.storage.latestThreatModel(run.id, run.goalRevision)?.entries,
    )
    const dispatchPlan = planRoundRobinDispatch(readySteps, slots, {
      leadCap: DET_LEAD_CONCURRENT_CAP,
      activeLeadCount,
      hostTiers,
    })
    let dispatched = 0
    for (const step of dispatchPlan.ordered) {
      this.startInvestigationStep(run, step, profiles)
      dispatched += 1
    }
    if (dispatched > 0) {
      try {
        this.storage.event(
          run.id,
          'scheduler.dispatch',
          `Dispatched ${dispatched} step(s): ${Object.entries(dispatchPlan.selectedByLane)
            .filter(([, count]) => count > 0)
            .map(([lane, count]) => `${lane}=${count}`)
            .join(', ') || 'none'}.`,
          {
            slots,
            dispatched,
            selectedByLane: dispatchPlan.selectedByLane,
            activeLeadCount,
            leadConcurrentCap: DET_LEAD_CONCURRENT_CAP,
            deferredLeads: dispatchPlan.deferredLeads,
            stepIds: dispatchPlan.ordered.slice(0, dispatched).map(step => step.id),
          },
        )
      } catch { /* telemetry is best-effort */ }
    }

    // If nothing is running/ready/pending, check diminishing returns or trigger final planner review.
    // v6: a dry streak is observed, never a global kill switch. Termination is budget/requests/wall
    // exhaustion, per-assignment caps, drained OOB, or explicit coordinator completion.
    const updatedSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const anyActive = updatedSteps.some(s => ['pending', 'ready', 'running'].includes(s.status))
    if (!anyActive && !this.plannerTasks.has(run.id) && !this.plannerTimers.has(run.id)) {
      this.noteDryStreak(run)
      const hasCanceledSibling = updatedSteps.some(s => Boolean(s.trialGroupId) && s.status === 'canceled')
      if (hasCanceledSibling) {
        const hasUntestedWork =
          this.storage.listFacts(run.id, { includeTainted: false, limit: 1 }).length > 0 ||
          this.storage.listEndpoints(run.id).length > 0 ||
          this.storage.listOpenProofGaps(run.id, run.goalRevision).length > 0
        if (!hasUntestedWork) {
          this.advanceToVerification(run)
          return
        }
      }
      const doneAt = this.plannerDoneRound.get(run.id)
      if (doneAt !== undefined && doneAt === run.roundNo && !this.plannerDirty.has(run.id)) {
        this.advanceToVerification(run)
      } else {
        this.schedulePlanner(run.id, 100)
      }
    } else if (this.plannerDirty.has(run.id) && !this.plannerTasks.has(run.id) && !this.plannerTimers.has(run.id)) {
      this.schedulePlanner(run.id, plannerDebounceMs)
    }
  }

  // --- Phase 1 (deterministic fallback): bounded zero-LLM probe pass when no model profile exists ---

  private driveDeterministicInvestigation(run: Run) {
    const key = `${run.id}:${run.goalRevision}:${run.scopeRevision}`
    if (this.deterministicCompleted.has(key) || this.deterministicInFlight.has(key)) return
    this.deterministicInFlight.add(key)
    void this.runDeterministicInvestigation(run)
      .catch(error => {
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, 'deterministic_probes.failed', `Deterministic probe pass failed: ${msg}`)
        } catch { /* store closed or run removed */ }
      })
      .finally(() => {
        this.deterministicInFlight.delete(key)
        this.deterministicCompleted.add(key)
        // The store may already be closed (test teardown / run deletion); never let cleanup throw.
        try {
          const latest = this.storage.run(run.id)
          if (latest.status === 'running' && latest.phase === 'investigation') {
            this.storage.event(
              latest.id,
              'deterministic_probes.complete',
              'Deterministic probe pass complete. Advancing to Zero-LLM verification.',
              { reuse: key },
            )
            this.advanceToVerification(latest)
          }
        } catch { /* store closed or run removed */ }
        try { this.notifyCheckpoint(run.id, 'deterministic-lane') } catch { /* best-effort */ }
        try {
          this.scheduleWake()
        } catch { /* scheduler already stopped */ }
      })
  }

  // --- Explicit --no-llm deterministic engine (Slice 2; separate from the M1 fallback above) ---

  private driveEngineInvestigation(run: Run) {
    const key = `${run.id}:${run.goalRevision}:${run.scopeRevision}:engine`
    if (this.deterministicCompleted.has(key) || this.deterministicInFlight.has(key)) return
    this.deterministicInFlight.add(key)
    void this.runEngineInvestigation(run)
      .catch(error => {
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, 'deterministic_engine.failed', `Deterministic engine failed: ${msg}`)
        } catch { /* store closed or run removed */ }
      })
      .finally(() => {
        this.deterministicInFlight.delete(key)
        this.deterministicCompleted.add(key)
        // `--no-llm` has one phase: freeze the floor allowance so the summary reports it as such.
        try { this.settleFloorRequestPhase(run.id, 'no_llm_complete') } catch { /* metrics only */ }
        try {
          const latest = this.storage.run(run.id)
          if (latest.status === 'running' && latest.phase === 'investigation') {
            this.storage.event(
              latest.id,
              'deterministic_engine.complete',
              'Deterministic engine complete. Advancing to Zero-LLM verification.',
              { reuse: key },
            )
            this.advanceToVerification(latest)
          }
        } catch { /* store closed or run removed */ }
        try { this.notifyCheckpoint(run.id, 'deterministic-lane') } catch { /* best-effort */ }
        try {
          this.scheduleWake()
        } catch { /* scheduler already stopped */ }
      })
  }

  /**
   * Extract entry routes from JSON route maps/config docs already fetched during recon
   * (e.g. `/app-config.json`, `/routes`, OpenAPI JSON). Bounded and generic: any object with a
   * `path`/`pathTemplate` string or an array of `/api/...` strings qualifies.
   */
  private async deriveRuntimeRouteMapTargets(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    grant: Grant,
    assignment: Assignment,
    signal: AbortSignal,
    recordExchange: (exchange: BrokerExchangeResult) => string,
  ): Promise<Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }>> {
    const out: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
    }> = []
    let summaries: Array<{ id: string; origin: string; method: string; pathAndQuery: string; status: number; mediaType: string }> = []
    try {
      summaries = [...this.storage.runDetail(run.id).exchangesSummary].sort((a, b) =>
        a.origin.localeCompare(b.origin) ||
        a.pathAndQuery.localeCompare(b.pathAndQuery) ||
        a.method.localeCompare(b.method) ||
        a.id.localeCompare(b.id))
    } catch {
      return []
    }
    const configPathRe = /(?:app-config|config|routes|manifest|openapi|swagger|api-docs)(?:\.[a-z]+)?(?:\?|$)/i
    let configExchanges = summaries
      .filter(ex => ex.method === 'GET' && ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType))
      .filter(ex => configPathRe.test(ex.pathAndQuery))
      .slice(0, 4)

    // Phase-0 may not have fetched the runtime route map yet; fetch at most two generic config
    // candidates so recon-derived routes are still reachable in deterministic mode.
    if (configExchanges.length === 0) {
      const origin = [...approvedOrigins].sort()[0]
      const alreadyFetched = new Set(summaries.map(ex => ex.pathAndQuery))
      for (const candidate of ['/app-config.json', '/api/routes', '/routes.json']) {
        if (configExchanges.length >= 2) break
        if (alreadyFetched.has(candidate) || signal.aborted) continue
        try {
          const ex = await this.broker.executeHttp({
            origin,
            method: 'GET',
            pathAndQuery: candidate,
            followRedirects: false,
            runId: run.id,
            assignmentId: assignment.id,
          }, grant, signal)
          const id = recordExchange(ex)
          if (ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType)) {
            configExchanges.push({
              id,
              origin: ex.origin,
              method: ex.method,
              pathAndQuery: ex.pathAndQuery,
              status: ex.status,
              mediaType: ex.mediaType,
            })
          }
        } catch {
          // Config probing is best-effort; continue with whatever recon already recorded.
        }
      }
    }

    const normalizeTemplate = (value: string) =>
      value.replace(/\{([a-z][a-z0-9_]*):([a-z][a-z0-9_-]*)\}/gi, '$2').slice(0, 300)

    const pushTarget = (origin: string, method: string, rawPath: string) => {
      if (!approvedOrigins.has(origin)) return
      if (!rawPath.startsWith('/') || rawPath.length > 300) return
      const pathTemplate = normalizeTemplate(rawPath)
      if (!/^\/[A-Za-z0-9_\-{}\/.:]*$/.test(pathTemplate)) return
      if (out.some(t => t.origin === origin && t.method === method && t.pathTemplate === pathTemplate)) return
      if (out.length >= 60) return
      const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
      for (const match of pathTemplate.matchAll(/\{([A-Za-z0-9_]+)\}/g)) params.push({ name: match[1], location: 'path' })
      out.push({ origin, method, pathTemplate, riskScore: 70, params })
    }

    const visit = (node: unknown, origin: string, depth: number) => {
      if (depth > 5 || out.length >= 60) return
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 200)) visit(item, origin, depth + 1)
        return
      }
      if (!node || typeof node !== 'object') return
      const obj = node as Record<string, unknown>
      const methodRaw = typeof obj.method === 'string' ? obj.method : typeof obj.verb === 'string' ? obj.verb : null
      const pathRaw = typeof obj.path === 'string' ? obj.path
        : typeof obj.pathTemplate === 'string' ? obj.pathTemplate
          : typeof obj.route === 'string' ? obj.route : null
      if (pathRaw && pathRaw.startsWith('/')) {
        const method = (methodRaw ?? 'GET').toUpperCase()
        // Only read methods are probed deterministically without a declared body schema.
        if (method === 'GET' || method === 'HEAD') pushTarget(origin, method, pathRaw)
      }
      for (const [key, value] of Object.entries(obj).slice(0, 200)) {
        if (typeof value === 'string' && value.startsWith('/api/') && value.length <= 200) {
          pushTarget(origin, 'GET', value)
        } else if (key === 'paths' && value && typeof value === 'object') {
          for (const [pathKey, pathValue] of Object.entries(value as Record<string, unknown>).slice(0, 120)) {
            if (!pathKey.startsWith('/')) continue
            const methods = pathValue && typeof pathValue === 'object'
              ? Object.keys(pathValue as Record<string, unknown>).filter(k => ['get', 'post', 'put', 'patch'].includes(k.toLowerCase()))
              : []
            for (const method of methods.length ? methods : ['get']) pushTarget(origin, method.toUpperCase(), pathKey)
          }
        } else if (value && typeof value === 'object') {
          visit(value, origin, depth + 1)
        }
      }
    }

    for (const summary of configExchanges) {
      let body = ''
      try {
        body = this.storage.getExchange(run.id, summary.id).body
      } catch {
        continue
      }
      if (!body || body.length > 512 * 1024) continue
      let doc: unknown
      try {
        doc = JSON.parse(body)
      } catch {
        continue
      }
      visit(doc, summary.origin, 0)
    }
    return out
  }

  /**
   * Parse imported OpenAPI/route-map project specs into bounded deterministic probe targets.
   * Generic engine behavior: no app, route, or parameter hardcoding.
   */
  private deriveDeterministicRouteTargets(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    existing: ReadonlyArray<{ origin: string; method: string; pathTemplate: string }>,
  ): Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }> {
    let specs: Array<{ name: string; kind: string; content: string }> = []
    try {
      specs = [...this.storage.listProjectSpecsFull(run.projectId)].sort((a, b) =>
        a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name))
    } catch {
      return []
    }
    const seen = new Set(existing.map(ep => `${ep.origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`))
    const out: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
    }> = []
    const defaultOrigin = [...approvedOrigins].sort()[0]
    const mapLocation = (value: unknown): 'query' | 'json' | 'form' | 'path' | 'header' | null => {
      const raw = typeof value === 'string' ? value.toLowerCase() : ''
      if (raw === 'query' || raw === 'path' || raw === 'header') return raw
      if (raw === 'formdata' || raw === 'form') return 'form'
      if (raw === 'body') return 'json'
      return null
    }

    for (const spec of specs.slice(0, 6)) {
      const head = spec.content.slice(0, 400)
      if (!/openapi|swagger/i.test(spec.kind) && !/"(?:openapi|swagger)"\s*:/.test(head) && !/^\s*openapi\s*:/m.test(head)) continue
      let doc: Record<string, unknown> | undefined
      try {
        doc = JSON.parse(spec.content) as Record<string, unknown>
      } catch {
        doc = undefined
      }
      const paths = (doc as { paths?: Record<string, unknown> } | undefined)?.paths
      if (!paths || typeof paths !== 'object') {
        // Tolerant fallback: imported specs can be redacted/truncated before storage, so the JSON
        // may not parse. Extract path keys + methods + parameters textually instead of giving up.
        for (const target of parseTolerantOpenApiTargets(spec.content, defaultOrigin, approvedOrigins)) {
          const key = `${target.origin}|${target.method}|${target.pathTemplate}`
          if (seen.has(key)) continue
          seen.add(key)
          out.push(target)
        }
        continue
      }

      let origin = defaultOrigin
      const servers = (doc as { servers?: Array<{ url?: unknown }> } | undefined)?.servers
      if (Array.isArray(servers) && typeof servers[0]?.url === 'string') {
        try {
          const serverOrigin = new URL(servers[0].url, defaultOrigin).origin
          if (approvedOrigins.has(serverOrigin)) origin = serverOrigin
        } catch { /* keep default */ }
      }

      for (const [rawPath, rawItem] of Object.entries(paths).slice(0, 80)) {
        if (typeof rawPath !== 'string' || !rawPath.startsWith('/') || rawPath.length > 300) continue
        const item = rawItem as Record<string, unknown> | null
        if (!item || typeof item !== 'object') continue
        const sharedParams = Array.isArray(item.parameters) ? item.parameters as Array<Record<string, unknown>> : []
        for (const method of ['get', 'post', 'put', 'patch', 'delete'] as const) {
          const op = item[method] as Record<string, unknown> | undefined
          if (!op || typeof op !== 'object') continue
          const key = `${origin}|${method.toUpperCase()}|${rawPath}`
          if (seen.has(key)) continue
          const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
          const pushParam = (name: unknown, location: unknown) => {
            const mapped = mapLocation(location)
            if (typeof name !== 'string' || !name || !/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(name)) return
            if (!mapped) return
            if (params.some(p => p.name === name)) return
            params.push({ name, location: mapped })
          }
          for (const param of [...sharedParams, ...(Array.isArray(op.parameters) ? op.parameters as Array<Record<string, unknown>> : [])]) {
            pushParam(param?.name, param?.in)
          }
          const jsonSchema = (op.requestBody as { content?: Record<string, { schema?: { properties?: Record<string, unknown> } }> } | undefined)
            ?.content?.['application/json']?.schema
          if (jsonSchema?.properties && typeof jsonSchema.properties === 'object') {
            for (const name of Object.keys(jsonSchema.properties).slice(0, 12)) pushParam(name, 'body')
          }
          for (const match of rawPath.matchAll(/\{([A-Za-z0-9_]+)\}/g)) pushParam(match[1], 'path')
          seen.add(key)
          const hasInjectable = params.some(p => p.location === 'query' || p.location === 'json' || p.location === 'form')
          if (!deterministicRouteIsTestable(method, rawPath, hasInjectable)) continue
          out.push({
            origin,
            method: method.toUpperCase(),
            pathTemplate: rawPath,
            riskScore: hasInjectable ? 65 : 55,
            params,
          })
        }
      }
    }
    return out.slice(0, 60)
  }

  /**
   * Bounded, tier/scope/budget-aware deterministic hypotheses for discovered endpoints. Used only
   * when the run has no model profile: it probes the highest-value discovered routes, records
   * facts, synthesizes DeclarativeReplaySpecs from differential anomalies, and lets the normal
   * Zero-LLM verification queue confirm or dismiss them.
   */
  private async runDeterministicInvestigation(run: Run): Promise<void> {
    const current = this.storage.run(run.id)
    if (current.status !== 'running' || current.phase !== 'investigation') return
    const approvedOrigins = this.approvedOriginsSet(current)
    if (current.capabilityTier < 1 || approvedOrigins.size === 0) return

    // Graphwire: full lossless store in, bounded ranked probe subset out. DELETE stays excluded
    // from this legacy M1 fallback pass (its own tier gate lives in the engine lane).
    const probeSelection = selectProbeCandidates({
      endpoints: listEndpointsPaged(this.storage, current.id, { orderBy: 'risk' }),
      probePlan: this.probePlans.get(this.storage, current.id),
      cap: DETERMINISTIC_PROBE_CAP,
      approvedOrigins,
      excludeMethods: ['DELETE'],
    })
    const endpoints = probeSelection.targets
    try {
      this.storage.event(
        current.id,
        'deterministic_probe.selection',
        `Probe selection ranked ${probeSelection.considered} candidate route(s) from ${probeSelection.storedRows} stored row(s); probing ${probeSelection.selected} (cap ${probeSelection.cap}).`,
        probeSelectionMetrics(probeSelection),
      )
    } catch { /* metrics only */ }

    const allParams = this.storage.listEndpointParams(current.id)
    const paramsByEndpoint = new Map<string, typeof allParams>()
    for (const param of allParams) {
      const list = paramsByEndpoint.get(param.endpointId) ?? []
      list.push(param)
      paramsByEndpoint.set(param.endpointId, list)
    }


    const personas = [...resolveRunPersonas(this.storage, current.projectId, current.approvedPersonaIds).values()]
    const personaHandles = personas.map(p => p.handle)
    const tier = current.capabilityTier

    const resourceQueue = tier >= 2 && personaHandles.length >= 2
      ? buildBolaTestQueue(
          this.storage.listFacts(current.id, { includeTainted: false, limit: 200 }),
          personas.map(p => ({ handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist })),
          approvedOrigins,
          this.storage.listResourceSamples(current.id),
        )
      : []

    const asset = current.candidates.find(c => approvedOrigins.has(c.origin) && current.approved.includes(c.id))
    if (!asset) return

    const worker = this.storage.makeWorker(
      current,
      'investigation',
      asset,
      'Deterministic differential probes',
      'No model profile configured: bounded deterministic probe pass over discovered endpoints.',
      { sourceOrigins: [...approvedOrigins] },
    )
    const claimed = this.storage.updateWorker(worker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    }) ?? worker
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller: new AbortController() }
    const { grant, currentSecrets } = this.buildGrant(job, current, approvedOrigins)

    const recordExchange = (ex: BrokerExchangeResult) => {
      const latest = this.storage.run(current.id)
      const saved = this.storage.recordExchange({
        runId: current.id,
        assignmentId: claimed.id,
        scopeRevision: latest.scopeRevision,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        redirectOrigins: ex.redirectOrigins,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        personaHandle: ex.personaHandle,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: ex.reqHeaders,
        respHeaders: ex.respHeaders,
        body: ex.body,
        durationMs: ex.durationMs,
        secretMatches: ex.secretMatches,
        secrets: currentSecrets(),
      })
      this.storage.trackExchangeResources({
        runId: current.id,
        scopeRevision: latest.scopeRevision,
        exchange: ex,
        source: 'surface_probe',
      })
      this.markEndpointCoverage(latest, ex.origin, ex.method, ex.pathAndQuery, 'http_exchange')
      this.scanSecondOrderExchange(latest, claimed.id, ex, saved.id)
      return saved.id
    }

    const signal = job.controller.signal

    // Route-map/OpenAPI-derived entry routes: grey-box/white-box runs import API references, and
    // phase-0 may not have materialized every path yet on this branch. Parsing them here keeps the
    // deterministic baseline meaningful without depending on an LLM planner.
    const derivedTargets = [
      ...this.deriveDeterministicRouteTargets(current, approvedOrigins, endpoints),
      ...await this.deriveRuntimeRouteMapTargets(current, approvedOrigins, grant, claimed, signal, recordExchange),
    ].filter((target, idx, all) =>
      all.findIndex(other => other.origin === target.origin && other.method === target.method && other.pathTemplate === target.pathTemplate) === idx,
    )
    const syntheticEndpoints = derivedTargets.map(target => ({
      id: `derived:${target.method}:${target.pathTemplate}`,
      runId: current.id,
      scopeRevision: current.scopeRevision,
      origin: target.origin,
      method: target.method,
      pathTemplate: target.pathTemplate,
      source: 'openapi' as const,
      framework: null,
      authRequirement: null,
      ownershipGuard: null,
      sinkKinds: [] as string[],
      testedClasses: [] as string[],
      coveragePct: 0,
      riskScore: target.riskScore,
      codeLocation: null,
      createdAt: current.createdAt,
      updatedAt: current.createdAt,
    }))
    for (const [idx, target] of derivedTargets.entries()) {
      const endpointId = syntheticEndpoints[idx].id
      paramsByEndpoint.set(endpointId, target.params.map((param, paramIdx) => ({
        id: `${endpointId}:p${paramIdx}`,
        runId: current.id,
        endpointId,
        name: param.name,
        location: param.location,
        inferredType: null,
        isCsrf: false,
        isObjectId: /^(?:id|uuid|[a-z][a-z0-9]*Id)$/i.test(param.name),
        source: 'openapi',
        createdAt: current.createdAt,
      })) as unknown as typeof allParams)
    }
    const probeEndpoints = [...endpoints, ...syntheticEndpoints]
    if (!probeEndpoints.length) return

    const injectableLocations = new Set(['query', 'json', 'form'])
    const ranked = probeEndpoints
      .map(ep => {
        const epParams = paramsByEndpoint.get(ep.id) ?? []
        const injectable = epParams
          .filter(p => injectableLocations.has(p.location))
          .sort((a, b) => Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)))
          .slice(0, 2)
        const queryNames = deterministicQueryParamNames(ep.pathTemplate)
        const paramCandidates = injectable.length
          ? injectable.map(p => ({ name: p.name, location: p.location as 'query' | 'json' | 'form' }))
          : queryNames.slice(0, 2).map(name => ({ name, location: 'query' as const }))
        const idPath = deterministicIdPath(ep.pathTemplate)
        const originResources = resourceQueue.filter(item => item.origin === ep.origin)
        let score = ep.riskScore
        if (paramCandidates.length) score += 25
        if (idPath) score += 12
        if ((ep.sinkKinds ?? []).length > 0) score += 10
        if (originResources.length > 0) score += 15
        // Generic hints that a route consumes query input even when recon did not persist params.
        if (/\b(?:search|query|filter|export|report|list|lookup|find|browse)\b/i.test(ep.pathTemplate)) score += 20
        if (/^\/api\/[a-z][a-z0-9_-]{1,40}$/i.test(ep.pathTemplate.replace(/\?.*$/, ''))) score += 8
        // Prefer routes with injectable parameters before path-only id routes.
        if (!paramCandidates.length && !idPath) score -= 20
        return { ep, paramCandidates, idPath, originResources, score }
      })
      .filter(item => {
        // Nothing testable: path placeholders without harvested ids and no injectable parameter.
        const placeholderOnly = /:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\]/.test(item.ep.pathTemplate)
        if (item.paramCandidates.length) return true
        if (item.idPath !== null && item.originResources.length > 0) return true
        return !placeholderOnly
      })
      .sort((a, b) => b.score - a.score)

    if (!ranked.length) return

    const maxEndpoints = Math.min(22, Math.max(4, Math.floor((current.dynamicStepBudget ?? 24) * 0.9)))
    const requestCap = current.budgetRequests > 0
      ? Math.max(0, Math.min(200, current.budgetRequests - current.spentRequests))
      : 200
    if (requestCap < 6) return

    let requestsUsed = 0
    let findingsCreated = 0
    try {
      for (const item of ranked.slice(0, maxEndpoints)) {
        if (requestsUsed >= requestCap || signal.aborted) break
        const latest = this.storage.run(current.id)
        if (latest.status !== 'running' || latest.phase !== 'investigation') break
        if (this.storage.checkBudgetExceeded(current.id)) break
        if (!approvedOrigins.has(item.ep.origin)) continue

        const perEndpointCap = Math.max(4, Math.min(16, requestCap - requestsUsed))
        if (perEndpointCap < 4) break

        const base = {
          origin: item.ep.origin,
          runId: current.id,
          assignmentId: claimed.id,
          storage: this.storage,
          maxRequests: perEndpointCap,
          onExchange: recordExchange,
        }

        // 1) Cross-persona object authz (ID-bearing routes with harvested owner resources).
        if (item.idPath && tier >= 2 && item.originResources.length > 0) {
          const resource = item.originResources[0]
          const owner = resource.ownerPersona
          const other = personaHandles.find(handle => handle !== owner)
          if (other) {
            let outcome
            try {
              outcome = await probeDifferential({
                ...base,
                probeClass: 'authz_matrix',
                method: 'GET',
                pathAndQuery: item.idPath,
                persona: owner,
                ownerPersona: owner,
                otherPersona: other,
                resourceIds: item.originResources.slice(0, 3).map(r => r.resourceId),
                includeAnonymous: false,
                includeHeaderBypass: false,
              }, this.broker, grant, this.canaryBroker, signal)
            } catch (error) {
              if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
              outcome = undefined
            }
            if (outcome) {
              requestsUsed += outcome.requestsSent
              this.markEndpointCoverage(latest, item.ep.origin, 'GET', item.idPath, 'diff:authz_matrix')
              const unauthorized = outcome.anomalies.find(a => a.type === 'unauthorized_access')
              if (outcome.verdict === 'signal' && unauthorized) {
                const resourceId = typeof unauthorized.resourceId === 'string' ? unauthorized.resourceId : resource.resourceId
                const probePath = item.idPath.replace('{{id}}', encodeURIComponent(resourceId))
                const controlPath = item.idPath.replace('{{id}}', encodeURIComponent(resourceId))
                const findingId = this.recordDeterministicFinding({
                  run: latest,
                  assignment: claimed,
                  asset,
                  spec: {
                    ...baseReplaySpecFields(latest, item.ep.origin, {
                      title: `Cross-persona object access · ${item.ep.method} ${item.ep.pathTemplate.slice(0, 80)}`,
                      category: 'broken-access-control',
                      cwe: 'CWE-639',
                      severity: 'high',
                      severityRationale: `Persona ${owner} owns ${resourceId}; persona ${other} received HTTP ${String(unauthorized.status)} on the same object.`,
                      impact: 'Horizontal privilege escalation: one tenant can read another tenant\'s object by ID.',
                      remediation: 'Enforce an ownership/tenant predicate on the object lookup before returning or mutating it.',
                      recheckInstructions: 'Replay the owner control and the cross-persona probe after the fix.',
                    }),
                    kind: 'http_chain',
                    spaCatchallControl: false,
                    assertionsJq: '{ controlPassed: (.steps.ctrl.status == 200), confirmed: (.steps.prb.status == 200), observed: ("probe status " + (.steps.prb.status | tostring)), expected: "cross-persona probe denied" }',
                    steps: [
                      { id: 'ctrl', role: 'control', description: `Owner ${owner} reads its own object`, request: { origin: item.ep.origin, method: 'GET', pathAndQuery: controlPath, persona: owner, followRedirects: false } },
                      { id: 'prb', role: 'probe', description: `Persona ${other} replays the owner object id`, request: { origin: item.ep.origin, method: 'GET', pathAndQuery: probePath, persona: other, followRedirects: false } },
                    ],
                  },
                  factData: {
                    subkind: 'differential_anomaly',
                    probeClass: 'authz_matrix',
                    endpoint: item.ep.pathTemplate,
                    resourceId,
                    ownerPersona: owner,
                    otherPersona: other,
                    anomalies: [unauthorized],
                  },
                  factSummary: `Deterministic authz_matrix signal: ${other} reached ${owner}'s resource ${resourceId} at ${item.ep.method} ${item.ep.pathTemplate} (HTTP ${String(unauthorized.status)}).`,
                  exchangeIds: outcome.exchangeIds,
                  secrets: currentSecrets(),
                })
                if (findingId) findingsCreated += 1
              }
            }
            continue
          }
        }

        // 2) SQL injection differential on parameterized routes (non-destructive boolean/error only).
        // When recon did not persist parameters, discover them first with the deterministic
        // param-differential surface mode (bounded), then inject into the discovered names.
        let candidateParams: Array<{ name: string; location: 'query' | 'json' | 'form' }> = item.paramCandidates
        if (!candidateParams.length && item.ep.method !== 'DELETE' && requestsUsed < requestCap - 6) {
          try {
            const discovery = await probeSurface({
              origin: item.ep.origin,
              mode: 'params',
              basePath: item.ep.pathTemplate.split('?')[0],
              paramLocation: 'query',
              methods: ['GET'],
              persona: personaHandles[0],
              maxRequests: Math.max(4, Math.min(12, requestCap - requestsUsed - 4)),
              onExchange: recordExchange,
            }, this.broker, grant, signal)
            requestsUsed += discovery.requestsSent
            this.markEndpointCoverage(latest, item.ep.origin, 'GET', item.ep.pathTemplate, 'surface:params')
            const discovered = [...new Set(
              discovery.anomalies
                .filter(a => a.kind === 'param' && typeof a.param === 'string')
                .map(a => String(a.param)),
            )].slice(0, 2)
            candidateParams = discovered.map(name => ({ name, location: 'query' as const }))
          } catch (error) {
            if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
          }
        }

        // Search-like routes commonly take a free-text term even when recon/OpenAPI did not record
        // the parameter name; try the conventional term once (bounded, non-destructive).
        if (!candidateParams.length && /(?:search|query|filter|find|lookup|browse)/i.test(item.ep.pathTemplate)) {
          candidateParams = [{ name: 'q', location: 'query' }]
        }

        for (const candidate of candidateParams.slice(0, 2)) {
          if (requestsUsed >= requestCap || signal.aborted) break
          const location = candidate.location
          const method = item.ep.method === 'POST' ? 'POST' : 'GET'
          if (method === 'POST' && !['query', 'json', 'form'].includes(location)) continue
          const baselineValue = DETERMINISTIC_NUMERIC_PARAM_RE.test(candidate.name) ? '1' : 'guardian'
          const quoteStyle: 'single' | 'double' | 'numeric' = DETERMINISTIC_NUMERIC_PARAM_RE.test(candidate.name) ? 'numeric' : 'single'
          const pathAndQuery = location === 'query'
            ? withQueryParam(item.ep.pathTemplate, candidate.name, baselineValue)
            : item.ep.pathTemplate.split('?')[0]
          const jsonBody = method === 'POST' && location === 'json'
            ? { [candidate.name]: baselineValue }
            : undefined
          let outcome
          try {
            outcome = await probeDifferential({
              ...base,
              probeClass: 'sqli_boolean',
              method,
              pathAndQuery,
              param: candidate.name,
              paramLocation: location,
              baselineValue,
              ...(jsonBody ? { jsonBody } : {}),
              ...(personaHandles[0] ? { persona: personaHandles[0] } : {}),
            }, this.broker, grant, this.canaryBroker, signal)
          } catch (error) {
            if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
            outcome = undefined
          }
          if (!outcome) continue
          requestsUsed += outcome.requestsSent
          this.markEndpointCoverage(latest, item.ep.origin, method, pathAndQuery, 'diff:sqli_boolean')
          const booleanSignal = outcome.anomalies.find(a => a.type === 'boolean_differential')
          const dbError = outcome.anomalies.find(a => a.type === 'db_error_fingerprint')
          if (outcome.verdict !== 'signal' || (!booleanSignal && !dbError)) continue
          const dialect = typeof dbError?.dialect === 'string' ? dbError.dialect : null
          const findingId = this.recordDeterministicFinding({
            run: latest,
            assignment: claimed,
            asset,
            spec: {
              ...baseReplaySpecFields(latest, item.ep.origin, {
                title: `SQL parameterization differential · ${method} ${item.ep.pathTemplate.slice(0, 80)} (${candidate.name})`,
                category: 'injection-input',
                cwe: 'CWE-89',
                severity: 'high',
                severityRationale: `Deterministic ${booleanSignal ? 'boolean differential' : 'SQL error fingerprint'} observed on parameter "${candidate.name}"${dialect ? ` (${dialect})` : ''}.`,
                impact: 'Unparameterized SQL handling allows boolean/oracle-based data inference.',
                remediation: 'Bind the parameter with the ORM/query parameterizer and remove string interpolation.',
                recheckInstructions: 'Replay the boolean differential after switching to a bound parameter.',
              }),
              kind: 'sql_boolean_diff',
              targetOrigin: item.ep.origin,
              method,
              pathAndQuery,
              paramName: candidate.name,
              paramLocation: location,
              baselineValue,
              quoteStyle,
              ...(jsonBody ? { jsonBody } : {}),
              assertionsJq: '{ controlPassed: true, confirmed: true, observed: "deterministic boolean differential", expected: "parameterized query" }',
            },
            factData: {
              subkind: 'differential_anomaly',
              probeClass: 'sqli_boolean',
              endpoint: item.ep.pathTemplate,
              param: candidate.name,
              paramLocation: location,
              method,
              dialect,
              anomalies: outcome.anomalies.slice(0, 5),
            },
            factSummary: `Deterministic sqli_boolean signal on ${method} ${item.ep.pathTemplate} parameter "${candidate.name}"${dialect ? ` (${dialect} error fingerprint)` : ''}.`,
            exchangeIds: outcome.exchangeIds,
            secrets: currentSecrets(),
          })
          if (findingId) findingsCreated += 1
        }
      }

      this.storage.event(
        current.id,
        'deterministic_probes.summary',
        `Deterministic probe pass used ${requestsUsed} request(s) across ${Math.min(ranked.length, maxEndpoints)} endpoint(s) and proposed ${findingsCreated} replay spec(s).`,
        { requestsUsed, endpointsConsidered: ranked.length, endpointsProbed: Math.min(ranked.length, maxEndpoints), findingsCreated, requestCap },
      )
      this.storage.message(
        current.id,
        current.coordinatorId,
        'guardian',
        `No model profile is configured, so Guardian ran a bounded deterministic probe pass (${requestsUsed} requests) and proposed ${findingsCreated} deterministic replay spec(s) for Zero-LLM verification.`,
      )
    } finally {
      try {
        this.storage.updateWorker(claimed.id, {
          status: 'complete',
          outcome: `Deterministic probes: ${requestsUsed} request(s), ${findingsCreated} spec(s).`,
          lease: null,
          leaseExpiresAt: null,
        })
      } catch { /* run may have been deleted */ }
    }
  }

  /**
   * v6 staging: apply the run tag to an agent-tool request (headers + entity-creating values).
   * Returns a skip reason for a mutation that cannot be tagged safely; callers must not send it.
   */
  private stagingTagAgentRequest(input: {
    runId: string
    grant: Grant
    mode: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab'
    entityTag: string
    method: string
    pathAndQuery: string
    probeClass?: string
    jsonBody?: unknown
  }): { headers: Record<string, string>; jsonBody?: unknown; skipped?: string } {
    const staging = stagingProbeTag({
      environmentMode: input.mode,
      entityTag: input.entityTag,
      runId: input.runId,
      method: input.method,
      probeClass: (input.probeClass as DifferentialProbeClass | undefined) ?? 'mass_assignment',
      pathAndQuery: input.pathAndQuery,
      mutates: !/^(?:GET|HEAD|OPTIONS)$/i.test(input.method),
      ...(input.jsonBody && typeof input.jsonBody === 'object' && !Array.isArray(input.jsonBody)
        ? { jsonBody: input.jsonBody as Record<string, unknown> }
        : {}),
    })
    if (staging.action === 'skip') {
      this.stagingUntaggedSkipped.set(input.runId, (this.stagingUntaggedSkipped.get(input.runId) ?? 0) + 1)
      this.storage.event(input.runId, 'staging.untagged_skipped',
        `Skipped ${input.method} ${input.pathAndQuery.split('?')[0]} in staging_isolated: ${staging.reason}.`,
        { method: input.method, path: input.pathAndQuery.split('?')[0], reason: staging.reason, surface: 'agent_tool' })
      return { headers: {}, skipped: staging.reason }
    }
    if (staging.action !== 'tag') return { headers: {} }
    this.stagingTaggedMutations.set(input.runId, (this.stagingTaggedMutations.get(input.runId) ?? 0) + 1)
    this.stagingGrants.set(input.runId, input.grant)
    return { headers: staging.headers ?? {}, ...(staging.jsonBody ? { jsonBody: staging.jsonBody } : {}) }
  }

  /** v6 staging: tag every mutating request in an agent race burst (headers + JSON body values). */
  private stageAgentRaceBurst(
    runId: string,
    grant: Grant,
    mode: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab',
    entityTag: string | null,
    requests: readonly BrokerHttpRequest[],
  ): BrokerHttpRequest[] {
    if (!entityTag) return [...requests]
    return requests.map(request => {
      if (/^(?:GET|HEAD|OPTIONS)$/i.test(request.method)) return request
      const headers = { ...(request.headers ?? {}) }
      let parsed: unknown
      try { parsed = request.body ? JSON.parse(request.body) as unknown : undefined } catch { parsed = undefined }
      const tagged = this.stagingTagAgentRequest({
        runId, grant, mode, entityTag,
        method: request.method,
        pathAndQuery: request.pathAndQuery,
        probeClass: request.probeClass ?? 'workflow_invariant',
        ...(parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? { jsonBody: parsed as Record<string, unknown> }
          : {}),
      })
      if (tagged.skipped) {
        throw new BrokerDenied(`staging_isolated cannot safely tag this race burst (${tagged.skipped}); skipped without sending.`)
      }
      Object.assign(headers, tagged.headers)
      const body = tagged.jsonBody !== undefined ? JSON.stringify(tagged.jsonBody) : request.body
      return { ...request, headers, ...(body !== undefined ? { body } : {}) }
    })
  }

  /**
   * Explicit `--no-llm` deterministic closed loop. Risk-ranks the discovered surface, harvests
   * identifiers/fields from the target's own responses, runs the benign differential probes, turns
   * strong signals into identifier-bound DeclarativeReplaySpecs and lets the normal ReplayVerifier
   * decide. Only replay-confirmed runtime findings are persisted; unproven signals become det_lead
   * facts. No specialist steps are cancelled or hidden in this slice.
   */
  private async runEngineInvestigation(run: Run, laneOptions: {
    /** @deprecated Phase A runs the same depth as `--no-llm`; kept for typed callers. */
    lane?: boolean
    signal?: AbortSignal
    maxDurationMs?: number
    onAssignment?: (assignmentId: string) => void
  } = {}): Promise<void> {
    const current = this.storage.run(run.id)
    if (current.status !== 'running' || current.phase !== 'investigation') return
    const approvedOrigins = this.approvedOriginsSet(current)
    if (current.capabilityTier < 1 || approvedOrigins.size === 0) return
    if (laneOptions.signal?.aborted) return

    // DELETE routes are part of the write surface: keep them so the engine can build the
    // function-level authorization hypothesis for them (the engine owns the tier gate).
    // Graphwire: read the full store (lossless), probe only the Phase-0 ranked subset when one
    // exists; otherwise use the risk-ranked cap. The store is never trimmed or rewritten.
    const allEndpoints = listEndpointsPaged(this.storage, current.id, { orderBy: 'risk' })
    const probeSelection = selectProbeCandidates({
      endpoints: allEndpoints,
      probePlan: this.probePlans.get(this.storage, current.id),
      cap: ENGINE_PROBE_CAP,
      approvedOrigins,
    })
    const storedEndpoints = probeSelection.targets
    try {
      this.storage.event(
        current.id,
        'deterministic_engine.probe_selection',
        `Probe selection ranked ${probeSelection.considered} candidate route(s) from ${probeSelection.storedRows} stored row(s); probing ${probeSelection.selected} (cap ${probeSelection.cap}; full store retained).`,
        probeSelectionMetrics(probeSelection),
      )
    } catch { /* metrics only */ }
    if (probeSelection.usedPlan) {
      try {
        this.storage.event(
          current.id,
          'deterministic_engine.probe_plan_applied',
          `Engine probing ${probeSelection.selected} of ${probeSelection.selected + probeSelection.skippedStored} candidate routes from the ranked plan (full store retained).`,
          { usedPlan: true, probed: probeSelection.selected, skippedStored: probeSelection.skippedStored },
        )
      } catch { /* run may be gone */ }
    }
    const allParams = this.storage.listEndpointParams(current.id)
    const paramsByEndpoint = new Map<string, typeof allParams>()
    for (const param of allParams) {
      const list = paramsByEndpoint.get(param.endpointId) ?? []
      list.push(param)
      paramsByEndpoint.set(param.endpointId, list)
    }

    const asset = current.candidates.find(c => approvedOrigins.has(c.origin) && current.approved.includes(c.id))
    if (!asset) return

    const worker = this.storage.makeWorker(
      current,
      'investigation',
      asset,
      'Deterministic differential engine',
      'Deterministic closed loop: risk-ranked triage, differential probes and Zero-LLM replay verification.',
      { sourceOrigins: [...approvedOrigins].sort() },
    )
    const claimed = this.storage.updateWorker(worker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 15 * 60_000,
    }) ?? worker
    if (laneOptions.onAssignment) {
      try { laneOptions.onAssignment(claimed.id) } catch { /* bookkeeping only */ }
    }
    const controller = new AbortController()
    if (laneOptions.signal) {
      if (laneOptions.signal.aborted) controller.abort(laneOptions.signal.reason)
      else laneOptions.signal.addEventListener('abort', () => controller.abort(laneOptions.signal?.reason), { once: true })
    }
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller }
    const { grant, currentSecrets } = this.buildGrant(job, current, approvedOrigins)
    const signal = controller.signal

    const recordExchange = (ex: BrokerExchangeResult) => {
      const latest = this.storage.run(current.id)
      const saved = this.storage.recordExchange({
        runId: current.id,
        assignmentId: claimed.id,
        scopeRevision: latest.scopeRevision,
        origin: ex.origin,
        finalOrigin: ex.finalOrigin,
        redirectOrigins: ex.redirectOrigins,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        personaHandle: ex.personaHandle,
        status: ex.status,
        mediaType: ex.mediaType,
        reqHeaders: ex.reqHeaders,
        respHeaders: ex.respHeaders,
        body: ex.body,
        durationMs: ex.durationMs,
        secretMatches: ex.secretMatches,
        secrets: currentSecrets(),
      })
      this.storage.trackExchangeResources({
        runId: current.id,
        scopeRevision: latest.scopeRevision,
        exchange: ex,
        source: 'surface_probe',
      })
      this.markEndpointCoverage(latest, ex.origin, ex.method, ex.pathAndQuery, 'http_exchange')
      this.scanSecondOrderExchange(latest, claimed.id, ex, saved.id)
      return saved.id
    }

    let leadCount = 0
    try {
      let derivedTargets: Array<{
        origin: string
        method: string
        pathTemplate: string
        riskScore: number
        source?: string
        params: Array<{ name: string; location: string }>
      }> = []
      try {
        derivedTargets = [
          ...this.deriveDeterministicRouteTargets(current, approvedOrigins, storedEndpoints),
          ...await this.deriveRuntimeRouteMapTargets(current, approvedOrigins, grant, claimed, signal, recordExchange),
          // Conventional action/noun wordlists are a local-lab convenience: on a real target the
          // engine relies on discovered routes, JS/router harvesting and the API reference.
          // Graphwire: Program-Graph code→runtime hypotheses are probed first by the floor.
          ...graphLeadTargets(this.storage.listFacts(current.id, { includeTainted: false, limit: 200 })),
          ...(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1'
            ? [...approvedOrigins].sort().flatMap(origin =>
                this.expandConventionalSurfaceTargets(
                  origin,
                  [...storedEndpoints, ...this.deriveDeterministicRouteTargets(current, approvedOrigins, storedEndpoints)],
                ))
            : []),
        ].filter((target, idx, all) =>
          all.findIndex(other => other.origin === target.origin && other.method === target.method && other.pathTemplate === target.pathTemplate) === idx,
        )
      } catch (error) {
        this.storage.event(
          current.id,
          'deterministic_engine.derived_failed',
          `Derived route expansion failed: ${error instanceof Error ? error.message.slice(0, 200) : String(error).slice(0, 200)}`,
        )
      }

      const paramLocation = (value: string): EngineEndpoint['params'][number]['location'] | null => {
        return ['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var'].includes(value)
          ? value as EngineEndpoint['params'][number]['location']
          : null
      }

      const endpoints: EngineEndpoint[] = []
      const seenEndpoints = new Set<string>()
      const pushEndpoint = (endpoint: EngineEndpoint) => {
        const key = `${endpoint.origin}|${endpoint.method.toUpperCase()}|${endpoint.pathTemplate}`
        if (seenEndpoints.has(key)) return
        seenEndpoints.add(key)
        endpoints.push(endpoint)
      }
      for (const endpoint of storedEndpoints) {
        pushEndpoint({
          id: endpoint.id,
          origin: endpoint.origin,
          method: endpoint.method,
          pathTemplate: endpoint.pathTemplate,
          params: (paramsByEndpoint.get(endpoint.id) ?? []).flatMap(param => {
            const location = paramLocation(param.location)
            return location ? [{ name: param.name, location, isObjectId: param.isObjectId, isCsrf: param.isCsrf }] : []
          }),
          riskScore: endpoint.riskScore,
          sinkKinds: endpoint.sinkKinds,
          source: endpoint.source,
        })
      }
      for (const [idx, target] of derivedTargets.entries()) {
        pushEndpoint({
          id: `derived:${idx}:${target.method}:${target.pathTemplate}`,
          origin: target.origin,
          method: target.method,
          pathTemplate: target.pathTemplate,
          params: target.params.flatMap(param => {
            const location = paramLocation(param.location)
            return location ? [{ name: param.name, location }] : []
          }),
          riskScore: target.riskScore,
          source: target.source ?? 'openapi',
        })
      }
      if (!endpoints.length) return

      const tenantOf = (roleLabel: string): string | undefined => {
        const match = /\(([^()]+)\)\s*$/.exec(roleLabel)
        return match?.[1]?.trim() || undefined
      }
      const privilegeOf = (roleLabel: string): EnginePersona['privilege'] => {
        if (/admin|superuser|owner[-_ ]?admin/i.test(roleLabel)) return 'admin'
        if (/viewer|read[-_ ]?only|readonly|guest|auditor|audit/i.test(roleLabel)) return 'viewer'
        return 'member'
      }
      const personas: EnginePersona[] = [...resolveRunPersonas(this.storage, current.projectId, current.approvedPersonaIds).values()]
        .filter(persona => persona.originAllowlist.some(origin => approvedOrigins.has(origin)))
        .map(persona => ({
          handle: persona.handle,
          roleLabel: persona.roleLabel,
          privilege: privilegeOf(persona.roleLabel),
          tenant: tenantOf(persona.roleLabel),
        }))

      const envNumber = (name: string): number | undefined => {
        const parsed = Number(process.env[name])
        return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined
      }
      // Phase A has its own allowance in split mode (`floorRequestBudget`), so the floor can never
      // spend the agents' requests. Legacy mode keeps the shared remainder as the only cap. The
      // deep policy is unchanged: the floor is still never halved just because agents will run.
      this.beginFloorRequestPhase(current)
      const remainingRequests = this.phaseRequestRemaining(current) ?? 700
      const requestCap = Math.max(0, Math.min(envNumber('GUARDIAN_DETERMINISTIC_MAX_REQUESTS') ?? 1800, remainingRequests))
      const durationCap = laneOptions.maxDurationMs ?? envNumber('GUARDIAN_DETERMINISTIC_MAX_MS') ?? 240_000
      // v6 environment contract: shared staging gets a short, tightly capped floor pass so it can
      // never dominate the engagement budget, and every created entity carries the run tag.
      const environmentMode = this.storage.scopePolicy(current).mode
      const entityTag = environmentMode === 'staging_isolated' ? tenantTagForRun(current.id) : undefined
      const stagingCap = environmentMode === 'staging_isolated'
        ? Math.max(50, Math.floor((current.budgetRequests > 0 ? current.budgetRequests : requestCap) * 0.2))
        : requestCap
      const maxRequests = Math.min(requestCap, stagingCap)
      const maxDurationMs = environmentMode === 'staging_isolated'
        ? Math.min(durationCap, 90_000)
        : durationCap
      const maxHypotheses = envNumber('GUARDIAN_DETERMINISTIC_MAX_HYPOTHESES') ?? 90

      this.storage.event(
        current.id,
        'deterministic_engine.started',
        `Deterministic engine triaging ${endpoints.length} endpoint(s) (request cap ${maxRequests}, ${Math.round(maxDurationMs / 1000)}s).`,
        {
          endpoints: endpoints.length,
          stored: storedEndpoints.length,
          derived: derivedTargets.length,
          personas: personas.length,
          maxRequests,
          maxDurationMs,
        },
      )

      const report = await runDeterministicEngine({
        runId: current.id,
        assignmentId: claimed.id,
        signal,
        endpoints,
        personas,
        broker: this.broker,
        grant,
        backend: this.backend,
        canaryBroker: this.canaryBroker,
        browser: this.browser,
        storage: this.storage,
        tier: current.capabilityTier,
        maxRequests,
        maxDurationMs,
        maxHypotheses,
        environmentMode,
        ...(entityTag ? { entityTag } : {}),
        ...(entityTag ? { cleanupEndpoints: allEndpoints } : {}),
        recordExchange,
        log: (kind, message, data) => {
          try { this.storage.event(current.id, kind, message, data ?? {}) } catch { /* run may be gone */ }
        },
        onConfirmed: input => this.persistDeterministicConfirmed({
          run: this.storage.run(current.id),
          assignment: claimed,
          asset,
          confirmed: input,
          secrets: currentSecrets(),
        }),
        onLead: lead => {
          if (leadCount >= 16) return
          leadCount += 1
          this.persistDeterministicLead({
            run: this.storage.run(current.id),
            assignment: claimed,
            lead,
            secrets: currentSecrets(),
          })
        },
      })

      const byClass = Object.entries(report.byClass)
        .map(([intent, stats]) => `${intent}:${stats.confirmed}/${stats.hypotheses}`)
        .join(' ')
      if (report.stagingTaggedMutations > 0 || report.stagingUntaggedSkipped > 0 || report.stagingCleaned > 0) {
        this.stagingTaggedMutations.set(current.id,
          (this.stagingTaggedMutations.get(current.id) ?? 0) + report.stagingTaggedMutations)
        this.stagingUntaggedSkipped.set(current.id,
          (this.stagingUntaggedSkipped.get(current.id) ?? 0) + report.stagingUntaggedSkipped)
        this.stagingCleaned.set(current.id,
          (this.stagingCleaned.get(current.id) ?? 0) + report.stagingCleaned)
        if (report.stagingCreatedEntityIds.length > 0) {
          const set = this.stagingCreatedEntities.get(current.id) ?? new Set<string>()
          for (const id of report.stagingCreatedEntityIds) set.add(id)
          this.stagingCreatedEntities.set(current.id, set)
        }
        this.storage.event(
          current.id,
          'staging.mutations',
          `Staging pass tagged ${report.stagingTaggedMutations} mutation(s), skipped ${report.stagingUntaggedSkipped} untaggable, cleaned ${report.stagingCleaned}.`,
          {
            stagingTaggedMutations: report.stagingTaggedMutations,
            stagingUntaggedSkipped: report.stagingUntaggedSkipped,
            stagingCleaned: report.stagingCleaned,
            createdEntityIds: report.stagingCreatedEntityIds.slice(0, 50),
          },
        )
      }
      this.storage.event(
        current.id,
        'deterministic_engine.summary',
        `Deterministic engine used ${report.requestsUsed} request(s), confirmed ${report.confirmed}, rejected ${report.rejectedSpecs}, leads ${report.leads}.`,
        {
          requestsUsed: report.requestsUsed,
          endpointsConsidered: report.endpointsConsidered,
          endpointsHarvested: report.endpointsHarvested,
          hypothesesFormed: report.hypothesesFormed,
          hypothesesRun: report.hypothesesRun,
          signals: report.signals,
          specsSubmitted: report.specsSubmitted,
          confirmed: report.confirmed,
          rejectedSpecs: report.rejectedSpecs,
          leads: report.leads,
          stoppedReason: report.stoppedReason,
          durationMs: report.durationMs,
          byClass,
          stagingTaggedMutations: report.stagingTaggedMutations,
          stagingUntaggedSkipped: report.stagingUntaggedSkipped,
          stagingCleaned: report.stagingCleaned,
        },
      )
      this.storage.message(
        current.id,
        current.coordinatorId,
        'guardian',
        `Deterministic engine finished: ${report.confirmed} confirmed finding(s) from ${report.hypothesesFormed} hypothesis(es), ${report.specsSubmitted} replay spec(s), ${report.requestsUsed} request(s) (${report.stoppedReason}).${byClass ? ` Classes ${byClass}.` : ''}`,
      )
    } finally {
      try {
        this.storage.updateWorker(claimed.id, {
          status: 'complete',
          outcome: 'Deterministic engine complete.',
          lease: null,
          leaseExpiresAt: null,
        })
      } catch { /* run may have been deleted */ }
    }
  }

  /**
   * Local-lab-only conventional action/noun expansion. Every candidate is still differentially
   * verified, so an extra route can only add a verified finding, never a raw claim.
   */
  private expandConventionalSurfaceTargets(
    origin: string,
    existing: ReadonlyArray<{ method: string; pathTemplate: string }>,
  ): Array<{
    origin: string
    method: string
    pathTemplate: string
    riskScore: number
    params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
  }> {
    const seen = new Set(existing.map(ep => `${origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`))
    const out: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      source?: string
      params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }>
    }> = []
    const add = (method: string, pathTemplate: string, riskScore = 12) => {
      const key = `${origin}|${method}|${pathTemplate}`
      if (seen.has(key)) return
      if (!pathTemplate.startsWith('/') || pathTemplate.length > 200) return
      if (/\.(?:js|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|mp4|pdf|zip|gz)$/i.test(pathTemplate)) return
      seen.add(key)
      const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
      for (const match of pathTemplate.matchAll(/:([A-Za-z0-9_]+)/g)) params.push({ name: match[1], location: 'path' })
      out.push({ origin, method, pathTemplate, riskScore, source: 'conventional', params })
    }
    const conventional: ReadonlyArray<[string, string, number]> = [
      ['GET', '/api/tokens', 18], ['POST', '/api/tokens', 15],
      ['GET', '/api/v1/whoami', 18], ['POST', '/api/v1/login', 12],
      ['GET', '/api/admin/activity', 18], ['GET', '/api/admin/users', 10],
      ['POST', '/api/admin/impersonate', 20],
      ['GET', '/api/staff', 12], ['POST', '/api/staff/:userId/role', 20],
      ['GET', '/api/downloads/reports', 18], ['POST', '/api/apps/import', 25],
      ['GET', '/api/v1/downloads/download', 20],
      ['POST', '/api/seats', 15], ['POST', '/api/credits', 12],
      ['POST', '/api/enrollments/accept', 18],
      ['GET', '/api/v1/search', 22],
      ['GET', '/api/accounts/search', 20],
      ['POST', '/api/queries/run', 22], ['POST', '/api/logs/filter', 22],
      ['GET', '/api/logs/view', 20], ['GET', '/api/logs', 8],
      ['GET', '/api/hooks', 14], ['POST', '/api/hooks', 22],
      ['POST', '/api/hooks/:webhookId/ping', 18],
      ['GET', '/api/links', 16], ['GET', '/api/links/:iid', 14],
      ['POST', '/api/links/:iid/fetch', 18],
      ['GET', '/api/v1/checkout/return', 18], ['GET', '/api/checkout/return', 16],
      ['POST', '/api/v1/orders/:orderId/confirm', 18],
      ['POST', '/api/orders/:orderId/confirm', 16],
      ['GET', '/api/v1/reports/sales', 16], ['GET', '/api/reports/sales', 16],
      ['POST', '/api/issues/:ticketId/notes', 18], ['GET', '/api/issues/:ticketId/view', 14],
      ['POST', '/api/jobs/:jobId/trigger', 16], ['POST', '/api/jobs/:jobId/complete', 14],
      ['POST', '/api/sso/import', 18], ['GET', '/api/sso/start', 10],
      ['GET', '/api/v1/customers/:customerId', 14], ['GET', '/api/v1/orders/:orderId', 14],
      ['GET', '/api/v1/wares/:productId/photos', 16], ['POST', '/api/v1/wares/:productId/photos', 22],
      ['POST', '/api/v1/manifests', 22], ['POST', '/api/v1/product-import', 18],
    ]
    for (const [method, path, risk] of conventional) add(method, path, risk)
    for (const ep of existing) {
      const bare = ep.pathTemplate.split('?')[0] || '/'
      if (bare.split('/').filter(Boolean).length > 4) continue
      if (/:/.test(bare)) continue
      if (ep.method.toUpperCase() === 'GET') add('POST', bare, 8)
      else if (ep.method.toUpperCase() === 'POST') add('GET', bare, 8)
    }
    return out.slice(0, 60)
  }

  /** Persist a replay-confirmed runtime finding. Never called for an unverified signal. */
  private persistDeterministicConfirmed(input: {
    run: Run
    assignment: Assignment
    asset: Candidate
    confirmed: EngineConfirmed
    secrets: readonly NamedSecret[]
  }): string | null {
    const { run, assignment, asset, confirmed, secrets } = input
    const spec = confirmed.spec
    if (spec.kind === 'static_ast_proof') return null
    if (confirmed.result.verdict !== 'confirmed') return null
    const fields = extractSpecDedupeFields(spec)
    const rows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
    )).all()
    const existingRefs: ExistingFindingRef[] = rows.map(row => {
      const existingSpec = row.replaySpecId ? this.storage.getReplaySpec(run.id, row.replaySpecId) : null
      const existingFields = existingSpec ? extractSpecDedupeFields(existingSpec.spec) : undefined
      return {
        id: row.id,
        origin: row.finding.origin,
        title: row.finding.title,
        status: row.finding.status,
        cwe: row.finding.cwe,
        category: row.finding.category,
        severity: row.finding.severity,
        endpoint: existingFields?.endpoint ?? null,
        authState: existingFields?.authState ?? null,
        specKind: existingFields?.specKind ?? null,
        method: existingFields?.method ?? null,
        param: existingFields?.param ?? null,
        graphqlField: existingFields?.graphqlField ?? null,
        mutated: existingFields?.mutated ?? null,
        fingerprintHash: row.fingerprintHash ?? null,
      }
    })
    const duplicate = checkStructuralDuplicate({
      origin: spec.origin,
      title: spec.title,
      cwe: spec.cwe,
      category: spec.category,
      severity: spec.severity,
      endpoint: fields.endpoint,
      authState: fields.authState,
      specKind: fields.specKind,
      method: fields.method,
      param: fields.param,
      graphqlField: fields.graphqlField,
      mutated: fields.mutated ?? null,
      ...(this.verifiedEndpointOf(confirmed.result) ? { verifiedEndpoint: this.verifiedEndpointOf(confirmed.result)! } : {}),
    }, existingRefs)
    if (duplicate.isDuplicate) return null

    const origins = [...new Set(replaySpecOrigins(spec))].filter(origin => this.permitted(run, origin))
    const fact = this.storage.addFact(run, assignment, {
      kind: 'note',
      origin: spec.origin,
      summary: `Replay-verified deterministic finding: ${spec.title}`,
      data: {
        subkind: 'deterministic_engine_confirmed',
        source: 'deterministic_engine',
        attribution: 'deterministic',
        vulnClass: confirmed.vulnClass,
        endpoint: confirmed.endpoint,
        probeClass: confirmed.hypothesis.probeClass,
        specKind: spec.kind,
        verdict: confirmed.result.verdict,
        verificationTier: confirmed.result.verificationTier ?? 'runtime_confirmed',
        controlPassed: confirmed.result.outcome.controlPassed,
        observed: confirmed.result.outcome.observed.slice(0, 400),
      },
      exchangeIds: confirmed.exchangeIds.slice(0, 5),
      sourceOrigins: origins,
      secrets,
    })

    const findingId = randomUUID()
    const specRow = this.storage.createReplaySpec(run, assignment, findingId, spec, origins, {
      verifiedInline: true,
      // Persist the engine's own confirming verdict on the spec so the finding's evidence is
      // self-describing (confirmed ⇒ the linked persisted diff confirms).
      lastVerificationDiff: buildInlineVerifyFeedback(
        spec, confirmed.result, 1, maxInlineVerifyRetries, secrets,
      ),
    })
    const artifact = this.storage.addArtifact(
      run,
      assignment,
      'replay',
      `Deterministic verified · ${spec.title}`,
      JSON.stringify({
        replaySpecId: specRow.id,
        specSha256: specRow.specSha256,
        kind: spec.kind,
        verdict: confirmed.result.verdict,
        verificationTier: confirmed.result.verificationTier ?? 'runtime_confirmed',
        outcome: confirmed.result.outcome,
        exchangeIds: confirmed.result.exchangeIds,
        evidenceSha256: confirmed.result.evidenceSha256,
        evidencePayload: confirmed.result.evidencePayload,
      }, null, 2),
      `replay:${specRow.id}`,
      secrets,
    )
    const uniqueTitle = `${spec.title.slice(0, 150)} · ${confirmed.hypothesis.method} ${confirmed.endpoint}`.slice(0, 200)
    const finding: Finding = {
      id: findingId,
      origin: spec.origin,
      title: uniqueTitle,
      status: 'confirmed',
      verificationTier: 'runtime_confirmed',
      severity: spec.severity,
      reason: redact(confirmed.result.outcome.reason || spec.severityRationale, secrets),
      remediation: spec.remediation,
      impact: spec.impact,
      recheck: spec.recheckInstructions,
      category: spec.category,
      cwe: spec.cwe,
      confidence: 'high',
      verification: `Deterministic Zero-LLM ${spec.kind} replay confirmed (controlPassed=${confirmed.result.outcome.controlPassed}), verified by the engine's own differential pass.`,
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      fingerprintHash: duplicate.fingerprint.hash,
      chainFactIds: [fact.id],
      exchangeIds: [...new Set(confirmed.exchangeIds)].slice(0, 6),
      evidenceIds: [artifact.id],
      scopeRevision: run.scopeRevision,
    }
    const saved = this.storage.upsertChainFinding(
      run, asset.id, finding, specRow.id, origins,
      { provenance: 'floor', verificationClass: 'runtime_confirmed' },
    )
    this.storage.addGraphEdge(run.id, { fromKind: 'fact', fromId: fact.id, toKind: 'finding', toId: saved.id, edgeKind: 'proves' })
    if (owaspCategories.includes(spec.category as OwaspCategory) && this.permitted(run, spec.origin)) {
      this.storage.upsertCoverageEntry(run, assignment.id, {
        origin: spec.origin,
        category: spec.category as OwaspCategory,
        status: 'reported',
        summary: `Deterministic verified: ${spec.title}`,
        linkedFindingId: saved.id,
      })
    }
    this.storage.event(
      run.id,
      'deterministic_engine.confirmed',
      `Deterministic engine confirmed ${confirmed.vulnClass} on ${confirmed.endpoint} (${spec.kind}, attribution=deterministic).`,
      {
        attribution: 'deterministic',
        endpoint: confirmed.endpoint,
        vulnClass: confirmed.vulnClass,
        probeClass: confirmed.hypothesis.probeClass,
        specKind: spec.kind,
        findingId: saved.id,
        exchangeCount: confirmed.exchangeIds.length,
      },
    )
    return saved.id
  }

  /** Persist an unproven deterministic observation as a det_lead fact (never as a finding). */
  private persistDeterministicLead(input: {
    run: Run
    assignment: Assignment
    lead: EngineLead
    secrets: readonly NamedSecret[]
  }): void {
    const { run, assignment, lead, secrets } = input
    const hyp = lead.hypothesis
    if (!this.permitted(run, hyp.endpoint.origin)) return
    const canaryId = lead.probe.anomalies
      .map(anomaly => anomaly.canaryId ?? anomaly.token ?? anomaly.canaryToken)
      .find((value): value is string => typeof value === 'string' && value.length > 0)
    try {
      this.storage.addFact(run, assignment, {
        kind: 'note',
        origin: hyp.endpoint.origin,
        summary: `Unverified deterministic lead (${hyp.probeClass}) on ${hyp.method} ${hyp.endpoint.pathTemplate}: ${lead.summary}`,
        data: {
          subkind: 'deterministic_engine_lead',
          source: 'deterministic_engine',
          kind: 'det_lead',
          attribution: 'deterministic',
          probeClass: hyp.probeClass,
          intent: hyp.intent,
          endpoint: hyp.endpoint.pathTemplate,
          method: hyp.method,
          param: hyp.param?.name ?? null,
          exchangeId: lead.probe.exchangeIds[0] ?? null,
          ...(canaryId ? { canaryId } : {}),
          reason: lead.summary,
          verdict: lead.probe.verdict,
          anomalies: lead.probe.anomalies.slice(0, 4),
        },
        exchangeIds: lead.probe.exchangeIds.slice(0, 5),
        sourceOrigins: [hyp.endpoint.origin],
        secrets,
      })
      this.storage.event(
        run.id,
        'deterministic_engine.lead',
        `Unverified deterministic lead: ${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}.`,
        { attribution: 'deterministic', endpoint: hyp.endpoint.pathTemplate, probeClass: hyp.probeClass },
      )
    } catch { /* lead persistence is best-effort */ }
  }

  private recordDeterministicFinding(input: {
    run: Run
    assignment: Assignment
    asset: Candidate
    spec: unknown
    factData: Record<string, unknown>
    factSummary: string
    exchangeIds: readonly string[]
    secrets: readonly NamedSecret[]
  }): string | null {
    const parsed = declarativeReplaySpecSchema.safeParse(input.spec)
    if (!parsed.success) return null
    const spec = parsed.data

    const fields = extractSpecDedupeFields(spec)
    const existingRows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, input.run.id),
      eq(findings.goalRevision, input.run.goalRevision),
    )).all()
    const existingRefs: ExistingFindingRef[] = existingRows.map(row => {
      const specRow = row.replaySpecId ? this.storage.getReplaySpec(input.run.id, row.replaySpecId) : null
      const existingFields = specRow ? extractSpecDedupeFields(specRow.spec) : undefined
      return {
        id: row.id,
        origin: row.finding.origin,
        title: row.finding.title,
        status: row.finding.status,
        cwe: row.finding.cwe,
        category: row.finding.category,
        severity: row.finding.severity,
        endpoint: existingFields?.endpoint ?? null,
        authState: existingFields?.authState ?? null,
        specKind: existingFields?.specKind ?? null,
        method: existingFields?.method ?? null,
        param: existingFields?.param ?? null,
        graphqlField: existingFields?.graphqlField ?? null,
        mutated: existingFields?.mutated ?? null,
        fingerprintHash: row.fingerprintHash ?? null,
      }
    })
    const duplicate = checkStructuralDuplicate({
      origin: spec.origin,
      title: spec.title,
      cwe: spec.cwe,
      category: spec.category,
      severity: spec.severity,
      endpoint: fields.endpoint,
      authState: fields.authState,
      specKind: fields.specKind,
      method: fields.method,
      param: fields.param,
      graphqlField: fields.graphqlField,
      mutated: fields.mutated ?? null,
    }, existingRefs)
    if (duplicate.isDuplicate) return null

    const fact = this.storage.addFact(input.run, input.assignment, {
      kind: 'note',
      origin: spec.origin,
      summary: input.factSummary,
      data: input.factData,
      exchangeIds: [...input.exchangeIds].slice(0, 5),
      sourceOrigins: [...new Set(replaySpecOrigins(spec))].filter(o => this.permitted(input.run, o)),
      secrets: input.secrets,
    })

    const findingId = randomUUID()
    const specRow = this.storage.createReplaySpec(input.run, input.assignment, findingId, spec, [...new Set(replaySpecOrigins(spec))])
    const artifact = this.storage.addArtifact(
      input.run,
      input.assignment,
      'replay',
      `Deterministic proposed spec · ${spec.title}`,
      JSON.stringify({ replaySpecId: specRow.id, specSha256: specRow.specSha256, spec }, null, 2),
      undefined,
      input.secrets,
    )
    const finding: Finding = {
      id: findingId,
      origin: spec.origin,
      title: spec.title,
      status: 'pending',
      severity: spec.severity,
      reason: spec.severityRationale,
      remediation: spec.remediation,
      impact: spec.impact,
      recheck: spec.recheckInstructions,
      category: spec.category,
      cwe: spec.cwe,
      confidence: 'medium',
      verification: `Pending Zero-LLM ${spec.kind} replay verification proposed deterministically (spec ${specRow.id}).`,
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      fingerprintHash: duplicate.fingerprint.hash,
      chainFactIds: [fact.id],
      exchangeIds: [...new Set(input.exchangeIds)].slice(0, 6),
      evidenceIds: [artifact.id],
      scopeRevision: input.run.scopeRevision,
    }
    const saved = this.storage.upsertChainFinding(input.run, input.asset.id, finding, specRow.id, [...new Set(replaySpecOrigins(spec))])
    this.storage.makeWorker(
      input.run,
      'verification',
      input.asset,
      `Replay verify · ${spec.title.slice(0, 80)}`,
      `Zero-LLM deterministic replay verification of deterministically proposed spec ${specRow.id}.`,
      { stepId: specRow.id, sourceOrigins: [...new Set(replaySpecOrigins(spec))] },
    )
    this.storage.addGraphEdge(input.run.id, { fromKind: 'fact', fromId: fact.id, toKind: 'finding', toId: saved.id, edgeKind: 'proves' })
    return saved.id
  }

  private schedulePlanner(runId: string, delayMs = plannerDebounceMs) {
    this.plannerDirty.add(runId)
    if (this.plannerTimers.has(runId) || this.plannerTasks.has(runId)) return
    const timer = setTimeout(() => {
      this.plannerTimers.delete(runId)
      this.plannerDirty.delete(runId)
      try {
        const run = this.storage.run(runId)
        const profiles = privateModelProfiles(this.storage)
        if (run.status === 'running' && run.phase === 'investigation' && profiles.length) {
          this.startChainPlanner(run, profiles)
        }
      } catch { /* ignore */ }
    }, delayMs)
    timer.unref?.()
    this.plannerTimers.set(runId, timer)
  }

  private startChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (this.plannerTasks.has(run.id)) return
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.plannerTasks.set(run.id, task)
    void this.runChainPlanner(run, profiles, task).catch(() => {
      // Planner errors should not crash active workers; retry on next wake or advance cleanly
    }).finally(() => {
      this.plannerTasks.delete(run.id)
      try {
        const latest = this.storage.run(run.id)
        if (latest.status === 'running' && latest.phase === 'investigation') {
          this.notifyCheckpoint(latest.id, 'planner-round')
        }
      } catch { /* run/store may already be gone */ }
      this.scheduleWake()
    })
  }

  // --- v6 Phase 4: tool-equipped Graph Coordinator planner ---

  /**
   * Lossless Program Graph view assembled from persisted endpoint code locations and sink tags.
   * The full AST graph is not persisted, but every AST-derived route keeps its `codeLocation`, so
   * sink paths and middleware diffs remain queryable without the old snapshot.
   */
  private coordinatorProgramGraph(endpoints: readonly CoordinatorEndpoint[]): CoordinatorProgramGraph | null {
    const routes: CoordinatorProgramGraph['routes'][number][] = []
    const nodes: Array<{ id: string; kind: string; symbol: string; file: string; line: number; sinkKind?: string }> = []
    const edges: Array<{ fromId: string; toId: string }> = []
    for (const endpoint of endpoints) {
      const location = endpoint.codeLocation as { file?: unknown; startLine?: unknown } | null | undefined
      const file = typeof location?.file === 'string' ? location.file : null
      if (!file) continue
      const line = typeof location?.startLine === 'number' ? location.startLine : 1
      routes.push({
        id: endpoint.id, method: endpoint.method, path: endpoint.pathTemplate, file, line, handler: '',
        guards: [endpoint.authRequirement, endpoint.ownershipGuard]
          .filter((guard): guard is string => Boolean(guard && guard.trim())),
      })
      for (const sinkKind of endpoint.sinkKinds ?? []) {
        const sinkId = `${endpoint.id}:${sinkKind}`
        nodes.push({ id: sinkId, kind: 'sink', symbol: sinkKind, file, line, sinkKind })
        edges.push({ fromId: endpoint.id, toId: sinkId })
      }
    }
    return routes.length ? { routes, nodes, edges } : null
  }

  /** Untruncated, paginated data access for the coordinator (never a fixed snapshot). */
  private coordinatorDeps(run: Run): CoordinatorDeps {
    const endpoints = (): CoordinatorEndpoint[] => this.pageAll((offset, limit) =>
      this.storage.listEndpoints(run.id, { limit, offset }))
    return {
      listEndpoints: endpoints,
      listFacts: () => this.pageAll((offset, limit) =>
        this.storage.listFacts(run.id, { includeTainted: false, limit, offset })),
      listFindings: () => this.storage.db.select().from(findings).where(eq(findings.runId, run.id)).all()
        .map(row => ({
          id: row.id, origin: row.finding.origin, title: row.finding.title, status: row.finding.status,
          severity: row.finding.severity, ...(row.finding.reason ? { reason: row.finding.reason } : {}),
          ...(row.finding.category ? { category: row.finding.category } : {}),
          ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
          ...(row.finding.confidence ? { confidence: row.finding.confidence } : {}),
          ...(row.finding.verification ? { verification: row.finding.verification } : {}),
          ...(row.finding.runtimeProofGap ? { runtimeProofGap: row.finding.runtimeProofGap } : {}),
          ...(row.finding.findingKind ? { findingKind: row.finding.findingKind } : {}),
          evidenceIds: row.finding.evidenceIds ?? [], chainFactIds: row.finding.chainFactIds ?? [],
          exchangeIds: row.finding.exchangeIds ?? [],
        }))
      ,
      programGraph: () => this.coordinatorProgramGraph(endpoints()),
      // No persisted commit-signal table in v6; git hotspots remain empty rather than fabricated.
      commitSignals: () => [],
      approvedOrigins: () => [...this.approvedOriginsSet(run)],
    }
  }

  private pageAll<T>(fetchPage: (offset: number, limit: number) => readonly T[], pageSize = 500): T[] {
    return collectAllPages(fetchPage, pageSize)
  }

  /**
   * Persist a validated dispatch plan as chain steps, citing parent facts and capability bundles.
   * Returns the structured funnel counts so a planner round can report exactly where planned
   * hypotheses were dropped (title dedupe, already-confirmed route, no approved asset, cap, budget).
   */
  private persistDispatchPlan(run: Run, plan: DispatchPlan, factIds: ReadonlySet<string>, detLeadFactIds: ReadonlySet<string> = new Set()): Pick<DispatchFunnelCounts, 'planned' | 'enqueued' | 'filteredDedupe' | 'filteredAlreadyConfirmed' | 'filteredNoAsset'> {
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const titles = new Set(existing.map(step => step.title.trim().toLowerCase()))
    const confirmed = this.alreadyConfirmedRefs(run, 40)
    const counts = { planned: plan.plan.length, enqueued: 0, filteredDedupe: 0, filteredAlreadyConfirmed: 0, filteredNoAsset: 0 }
    for (const step of plan.plan) {
      const title = compactChainTitle(step.hypothesis)
      const key = title.toLowerCase()
      if (titles.has(key)) { counts.filteredDedupe += 1; continue }
      const boundFactIds = step.parentEvidenceIds.filter(id => factIds.has(id))
      // Tool-dispatched hypotheses obey the same no-re-dispatch rule as planner JSON steps.
      if (this.stepRepeatsConfirmedWork({
        title, hypothesis: step.hypothesis, dependsOnFactIds: boundFactIds, dependsOnStepIds: [],
      }, confirmed)) { counts.filteredAlreadyConfirmed += 1; continue }
      const assetIds = run.candidates
        .filter(candidate => step.origins.includes(candidate.origin) && run.approved.includes(candidate.id))
        .map(candidate => candidate.id)
      if (!assetIds.length) { counts.filteredNoAsset += 1; continue }
      const category = step.probeClass === 'stored_xss' ? 'cors-client-side'
        : step.probeClass === 'authz_replay' || step.probeClass === 'auth_bypass' ? 'broken-access-control'
          : step.probeClass === 'ssrf' ? 'injection-input' : 'broken-access-control'
      // F2: lead-bound coordinator dispatches obey the same low-priority rule as planner steps.
      const leadBound = boundFactIds.some(id => detLeadFactIds.has(id)) ||
        isDetLeadDispatchStep({ title, hypothesis: step.hypothesis })
      this.storage.addChainStep(run, {
        title: title.slice(0, 200),
        hypothesis: step.hypothesis,
        category,
        priority: leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority,
        targetAssetIds: assetIds,
        skills: step.skills,
        dependsOnFactIds: boundFactIds,
        sourceOrigins: step.origins,
        specialistProfile: routeStepToSpecialist({ title, hypothesis: step.hypothesis, category, skills: step.skills }),
      })
      titles.add(key)
      counts.enqueued += 1
    }
    return counts
  }

  /**
   * Explicit chaining round: derive typed primitives from the untruncated store (same-origin and
   * cross-origin), plan 2–3 hop hypotheses and dispatch each with parent evidence + capabilities.
   */
  private dispatchChainRound(run: Run, coordinator: GraphCoordinator, budget: number, factIds: ReadonlySet<string>, funnel?: DispatchFunnelCounts): number {
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const remaining = Math.max(0, budget - existing.length)
    if (remaining <= 0) return 0
    const hypotheses = coordinator.planChainRound({ maxHops: 3, limit: Math.min(12, remaining) })
    if (!hypotheses.length) return 0
    const plan = coordinator.dispatchInvestigations(chainHypothesisDispatchSteps(hypotheses), { maxSteps: remaining })
    const counts = this.persistDispatchPlan(run, plan, factIds)
    if (funnel) addFunnelCounts(funnel, counts)
    this.storage.event(run.id, 'chain.round', `Chain round dispatched ${counts.enqueued} hypothesis(es) with parent evidence.`, {
      hypotheses: hypotheses.length, dispatched: counts.enqueued, rejected: plan.rejected.length,
      crossOrigin: hypotheses.filter(hypothesis => hypothesis.scope === 'cross_origin').length,
      primitives: [...new Set(hypotheses.flatMap(hypothesis => hypothesis.primitiveKinds))],
    })
    return counts.enqueued
  }

  private async runChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[], task: CoordinatorTask) {
    const fresh = this.storage.run(run.id)
    if (fresh.status !== 'running' || fresh.phase !== 'investigation') return
    if (this.storage.checkBudgetExceeded(run.id)) return

    // Advance the planner round without a compactor: facts stay raw and paginated.
    const roundNo = fresh.roundNo + 1
    const plannerStartedAt = Date.now()
    const updated = this.storage.updateRun(fresh.id, { roundNo })
    const dynamicStepBudget = Math.min(hardChainStepsCeiling, computeDynamicStepBudget(this.storage, fresh.id))
    this.storage.updateRunDynamicStepBudget(fresh.id, dynamicStepBudget)
    this.noteDryStreak(fresh)
    // v7 dispatch funnel: planned → filtered* → enqueued → dispatched, from step objects only.
    const funnel = emptyDispatchFunnel(roundNo)

    // v6 Phase 1: prioritized deterministic leads become upgrade assignments before the planner
    // runs, so the agentic lane never idles on confirmed routes and never loses a floor signal.
    let detLeadSteps = 0
    try {
      detLeadSteps = this.queueDetLeadUpgradeSteps(fresh, this.approvedOriginsSet(fresh), dynamicStepBudget)
    } catch { /* lead queueing is additive */ }
    funnel.planned += detLeadSteps
    funnel.enqueued += detLeadSteps

    const approvedOrigins = this.approvedOriginsSet(updated)
    const factIds = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(fresh.id, { includeTainted: false, limit, offset })).map(fact => fact.id))
    const remainingBudget = Math.max(0, dynamicStepBudget - this.storage.listChainSteps(fresh.id, updated.goalRevision).length)
    const coordinator = createGraphCoordinator({
      deps: this.coordinatorDeps(updated),
      approvedOrigins: [...approvedOrigins],
      budgetUsd: Math.max(0, Number((updated.budgetUsd - updated.spentUsd).toFixed(4))),
      maxDispatchSteps: Math.min(6, remainingBudget),
    })

    // Chain round after the floor + first planner round. Deterministic hypotheses over the full
    // store dispatch *before* the LLM turn, so a planner failure can never leave an empty window.
    let chainSteps = 0
    if (roundNo >= 2) {
      try { chainSteps = this.dispatchChainRound(updated, coordinator, dynamicStepBudget, factIds, funnel) } catch { /* additive */ }
    }

    const allSteps = this.storage.listChainSteps(fresh.id, updated.goalRevision)
    const allUntaintedFacts = this.pageAll((offset, limit) =>
      this.storage.listFacts(fresh.id, { includeTainted: false, limit, offset }))
      .filter(fact => approvedOrigins.has(fact.origin))
    const detLeadFactIds = new Set(allUntaintedFacts
      .filter(fact => fact.data?.kind === 'det_lead')
      .map(fact => fact.id))
    const personas = [...resolveRunPersonas(this.storage, updated.projectId, updated.approvedPersonaIds).values()]
      .map(persona => ({ handle: persona.handle, roleLabel: persona.roleLabel, originAllowlist: persona.originAllowlist }))

    // Priority #3: bounded cross-persona BOLA/IDOR matrix per discovered resource type.
    let bolaAutoSteps = 0
    if (updated.capabilityTier >= 2 && personas.length >= 2 && allSteps.length < dynamicStepBudget) {
      const typeGroups = new Map<string, BolaTestQueueItem[]>()
      for (const item of buildBolaTestQueue(allUntaintedFacts, personas, approvedOrigins, this.storage.listResourceSamples(run.id))) {
        const key = `${item.origin}\u0000${item.resourceKey}`
        typeGroups.set(key, [...(typeGroups.get(key) ?? []), item])
      }
      const perOriginSteps = new Map<string, number>()
      const candidateGroups = [...typeGroups.values()].sort((a, b) =>
        Number(b[0].ownerPersona !== 'anonymous') - Number(a[0].ownerPersona !== 'anonymous') || b.length - a.length)
      for (const itemsForType of candidateGroups) {
        if (allSteps.length + bolaAutoSteps >= dynamicStepBudget) break
        const origin = itemsForType[0].origin
        if ((perOriginSteps.get(origin) ?? 0) >= 3) continue
        const resourceKey = itemsForType[0].resourceKey
        const alreadyPlanned = allSteps.some(step => step.sourceOrigins.includes(origin) &&
          (step.title.includes(`resource:${resourceKey}`) ||
            (step.skills.includes('bola-idor-race') && /\b(?:bola|idor|cross-persona)\b/i.test(step.title))))
        if (alreadyPlanned) continue
        const asset = updated.candidates.find(candidate => candidate.origin === origin && updated.approved.includes(candidate.id))
        if (!asset) continue
        const itemsForOrigin = itemsForType.slice(0, 6)
        const variants = [...new Set(itemsForOrigin.flatMap(item => item.variants.map(variant =>
          `${variant.method} ${variant.endpoint}${variant.destructive ? ' (Tier 3 only)' : ''}`)))].slice(0, 8)
        this.storage.addChainStep(updated, {
          title: `Cross-persona BOLA/IDOR matrix · ${new URL(origin).hostname} · resource:${resourceKey}`,
          hypothesis: `Replay ${itemsForOrigin.length} ${resourceKey} resource(s) owned by ${itemsForOrigin[0].ownerPersona} (e.g. ${itemsForOrigin.map(item => `${item.endpoint} [${item.resourceId}]`).join(', ')}) as ${itemsForOrigin[0].testAsPersonas?.join(', ') ?? 'alternate persona & anonymous'} using bounded consumer item variants: ${variants.join(', ')}. Verify tenant isolation with GET first; use benign PUT/PATCH field deltas only where reversible; DELETE stays Tier 3/local-lab. Submit a DeclarativeReplaySpec if unauthorized access succeeds.`,
          category: 'broken-access-control',
          priority: 92,
          targetAssetIds: [asset.id],
          skills: ['bola-idor-race', 'false-positive-elimination'],
          dependsOnFactIds: itemsForOrigin.map(item => item.factId).filter((id): id is string => Boolean(id)),
          sourceOrigins: [origin],
          specialistProfile: 'bola-bfla-specialist',
        })
        funnel.planned += 1
        funnel.enqueued += 1
        bolaAutoSteps += 1
        perOriginSteps.set(origin, (perOriginSteps.get(origin) ?? 0) + 1)
      }
    }

    // Auto-enqueue verification for each new cross-persona or active-HTML second-order surface.
    let secondOrderAutoSteps = 0
    for (const fact of allUntaintedFacts.filter(candidate =>
      candidate.data?.subkind === 'second_order_surface' && updated.capabilityTier >= 1).slice(0, 20)) {
      if (allSteps.length + bolaAutoSteps + secondOrderAutoSteps >= dynamicStepBudget) break
      const marker = typeof fact.data?.marker === 'string' ? fact.data.marker : ''
      const surfacedOrigin = typeof fact.data?.surfacedOrigin === 'string' ? fact.data.surfacedOrigin : fact.origin
      const surfacedEndpoint = typeof fact.data?.surfacedEndpoint === 'string' ? fact.data.surfacedEndpoint : '/'
      const surfacedMediaType = typeof fact.data?.surfacedMediaType === 'string' ? fact.data.surfacedMediaType : ''
      const crossPersona = fact.data?.crossPersona === true
      const activeHtml = /html/i.test(surfacedMediaType)
      if (!marker || !approvedOrigins.has(surfacedOrigin) || (!crossPersona && !activeHtml)) continue
      if (allSteps.some(step => (step.dependsOnFactIds ?? []).includes(fact.id) ||
        (step.title.includes(marker) && step.sourceOrigins.includes(surfacedOrigin)))) continue
      const asset = updated.candidates.find(candidate => candidate.origin === surfacedOrigin && updated.approved.includes(candidate.id))
      if (!asset) continue
      this.storage.addChainStep(updated, {
        title: `Second-order canary verification · ${marker} → ${new URL(surfacedOrigin).hostname}${surfacedEndpoint.slice(0, 40)}`,
        hypothesis: `Second-order canary ${marker} planted via ${String(fact.data?.injectedEndpoint ?? '/')} (param ${String(fact.data?.injectedParam ?? 'input')}, persona ${String(fact.data?.injectedPersona ?? 'anonymous')}) resurfaced on ${surfacedOrigin}${surfacedEndpoint} as persona ${String(fact.data?.surfacedPersona ?? 'anonymous')} with media type ${surfacedMediaType || 'unknown'}${crossPersona ? ' (cross-persona)' : ''}${activeHtml ? ' (active HTML render)' : ''}. Re-read the surfaced endpoint with a control persona, prove the injected marker is persisted and rendered to a different principal, then submit a ${activeHtml ? 'browser_chain' : 'http_chain'} DeclarativeReplaySpec whose probe step renders the marker verbatim and whose control step does not.`,
        category: crossPersona ? 'broken-access-control' : 'cors-client-side',
        priority: 95,
        targetAssetIds: [asset.id],
        skills: crossPersona
          ? ['oob-ssrf-browser-chain', 'bola-idor-race', 'false-positive-elimination']
          : ['client-side-xss-postmessage', 'oob-ssrf-browser-chain'],
        dependsOnFactIds: [fact.id],
        sourceOrigins: [...new Set([surfacedOrigin, fact.origin])].filter(origin => approvedOrigins.has(origin)),
        specialistProfile: crossPersona ? 'bola-bfla-specialist' : 'client-browser-dom-specialist',
      })
      funnel.planned += 1
      funnel.enqueued += 1
      secondOrderAutoSteps += 1
    }

    // Tool-equipped coordinator session: paginated read tools, explicit dispatch, no snapshot.
    let toolDispatched = 0
    const handlers = coordinatorPlannerHandlers({
      coordinator,
      onDispatch: plan => {
        try {
          const counts = this.persistDispatchPlan(this.storage.run(fresh.id), plan, factIds, detLeadFactIds)
          addFunnelCounts(funnel, counts)
          toolDispatched += counts.enqueued
        } catch { /* additive */ }
      },
    })
    const pendingOob = coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total
    // v7 precision guard: remember the evidence frontier across rounds. A round that adds no
    // runtime_confirmed finding and no chain primitive is dry; two consecutive dry rounds after the
    // high-priority queue drains end the planner.
    const evidenceFrontier = this.plannerEvidenceFrontier.get(run.id) ?? {
      confirmed: coordinator.queryFindings({ status: 'confirmed', limit: 1 }).total,
      primitives: coordinator.deriveChainPrimitives().length,
    }
    const prompt = coordinatorPlannerPrompt({
      goal: updated.goal,
      roundNo,
      capabilityTier: updated.capabilityTier,
      approvedOrigins: [...approvedOrigins],
      budgetRemaining: {
        usd: Math.max(0, Number((updated.budgetUsd - updated.spentUsd).toFixed(4))),
        requests: updated.budgetRequests === 0 ? 'unlimited' : Math.max(0, updated.budgetRequests - updated.spentRequests),
      },
      dynamicStepBudget,
      pendingOob,
      chainSteps: this.storage.listChainSteps(fresh.id, updated.goalRevision)
        .map(step => ({ id: step.id, title: step.title, status: step.status })),
      personas: personas.map(persona => ({ handle: persona.handle, roleLabel: persona.roleLabel })),
      mountedRepos: this.projectReposMount(updated.projectId).mountedRepos,
      openProofGaps: this.storage.listOpenProofGaps(fresh.id, updated.goalRevision)
        .filter(gap => approvedOrigins.has(gap.origin)).length,
    })
    const answer = await agentTurn({
      directory: this.storage.directory,
      sessionId: `planner-${run.id}-r${roundNo}`,
      requestId: `planner:${updated.goalRevision}:${roundNo}`,
      profiles: resolveProfilePoolForRole('tactical', profiles),
      scenario: 'chain-planner',
      roleAffinity: 'tactical',
      prompt,
      signal: task.controller.signal,
      maxTurns: 10,
      handlers,
      onUsage: usage => this.storage.recordLlmSpend(run.id, { usd: usage.costUsd, tokens: usage.inputTokens + usage.outputTokens }),
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, error, hard) => recordProfileFailure(id, error, hard, this.storage),
    })
    if (!this.currentCoordinator(run.id, task)) return

    let parsedPlanner: ReturnType<typeof plannerResponseSchema.safeParse> | null = null
    try { parsedPlanner = plannerResponseSchema.safeParse(JSON.parse(stripJsonFences(answer))) } catch { parsedPlanner = null }
    const currentRun = this.storage.run(run.id)
    const currentApproved = this.approvedOriginsSet(currentRun)
    const existingSteps = this.storage.listChainSteps(run.id, currentRun.goalRevision)
    let addedCount = detLeadSteps + chainSteps + bolaAutoSteps + secondOrderAutoSteps + toolDispatched

    if (parsedPlanner?.success) {
      for (const cancelId of parsedPlanner.data.cancelStepIds) {
        const target = existingSteps.find(step => step.id === cancelId)
        if (target && ['pending', 'ready'].includes(target.status)) this.storage.updateChainStep(target.id, { status: 'canceled' })
      }
      const confirmedForDispatch = this.alreadyConfirmedRefs(currentRun, 40)
      const remainingSlots = Math.max(0, dynamicStepBudget - existingSteps.length)
      const candidateSteps = parsedPlanner.data.newSteps
        .map(step => ({ ...step, origins: step.origins.filter(origin => currentApproved.has(origin)) }))
      const budgetedNewSteps = applyCrownJewelStepBudget(
        candidateSteps,
        computeHostTiers([...currentApproved], this.storage.latestThreatModel(run.id, currentRun.goalRevision)?.entries),
        existingSteps,
        remainingSlots,
      )
      const dispatchableNewSteps = budgetedNewSteps.filter(step => !this.stepRepeatsConfirmedWork(step, confirmedForDispatch))
      // Attribute the budget gate precisely: duplicate titles and unusable origins are their own
      // funnel buckets; only the remaining drops are capacity (step-budget/crown-jewel share).
      const existingTitles = new Set(existingSteps.map(step => step.title.trim().toLowerCase()))
      const preBudgetDedupe = candidateSteps.filter(step => existingTitles.has(step.title.trim().toLowerCase())).length
      const preBudgetNoAsset = candidateSteps.filter(step => step.origins.length === 0).length
      const droppedAtBudget = Math.max(0, candidateSteps.length - budgetedNewSteps.length)
      funnel.planned += candidateSteps.length
      funnel.filteredDedupe += Math.min(preBudgetDedupe, droppedAtBudget)
      funnel.filteredNoAsset += Math.min(preBudgetNoAsset, Math.max(0, droppedAtBudget - preBudgetDedupe))
      funnel.filteredBudget += Math.max(0, droppedAtBudget - preBudgetDedupe - preBudgetNoAsset)
      funnel.filteredAlreadyConfirmed += Math.max(0, budgetedNewSteps.length - dispatchableNewSteps.length)
      // Dependency sanitisation: a planner-emitted id that does not exist can never resolve, and
      // `refreshReadyChainSteps` requires every parent fact/step to exist. Drop unknown ids at
      // enqueue so planned work cannot be stranded as a permanently `pending` step.
      const liveFactIds = new Set(factIds)
      const liveStepIds = new Set(existingSteps.map(step => step.id))
      for (const step of dispatchableNewSteps) {
        const validOrigins = step.origins.filter(origin => currentApproved.has(origin))
        const assetIds = currentRun.candidates
          .filter(candidate => validOrigins.includes(candidate.origin) && currentRun.approved.includes(candidate.id))
          .map(candidate => candidate.id)
        if (!assetIds.length) { funnel.filteredNoAsset += 1; continue }
        // v7 precision guard: a plain re-emission of the same (route, class) is capped at 2
        // investigations unless the step cites a chain primitive or parent evidence.
        const guardRoutes = this.stepMentionedRoutes(step)
        const guardKey = guardRoutes.length ? reinvestigationKey(guardRoutes[0], step.category) : ''
        if (guardKey) {
          const unlocked = step.dependsOnFactIds.length > 0 || step.dependsOnStepIds.length > 0
          const verdict = this.reinvestigationGuardFor(run.id).record(guardKey, unlocked)
          if (!verdict.allowed) {
            this.noteCappedReinvestigation(run, guardKey, verdict.count)
            funnel.filteredCap += 1
            continue
          }
        }
        const parentFactIds = step.dependsOnFactIds.filter(id => liveFactIds.has(id))
        const parentStepIds = step.dependsOnStepIds.filter(id => liveStepIds.has(id))
        // F2: a planner re-emission of a det_lead upgrade must not jump back above class steps.
        const leadBound = parentFactIds.some(id => detLeadFactIds.has(id)) ||
          isDetLeadDispatchStep({ title: step.title, hypothesis: step.hypothesis })
        const specialistProfile = routeStepToSpecialist({
          title: step.title, hypothesis: step.hypothesis, category: step.category, skills: step.skills,
        })
        const created = this.storage.addChainStep(currentRun, {
          title: step.title, hypothesis: step.hypothesis, category: step.category,
          priority: leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority,
          targetAssetIds: assetIds, skills: step.skills, dependsOnFactIds: parentFactIds,
          dependsOnStepIds: parentStepIds, sourceOrigins: validOrigins, specialistProfile,
        })
        liveStepIds.add(created.id)
        funnel.enqueued += 1
        addedCount += 1
      }
    }

    // Deterministic scheduler guard outside the LLM: budget/requests/wall/K=2/done+pending OOB.
    const emptyRounds = addedCount === 0 ? (this.plannerEmptyRounds.get(run.id) ?? 0) + 1 : 0
    this.plannerEmptyRounds.set(run.id, emptyRounds)
    const chainPrimitivesAfterRound = coordinator.deriveChainPrimitives().length
    const confirmedAfterRound = coordinator.queryFindings({ status: 'confirmed', limit: 1 }).total
    const newChainPrimitives = Math.max(0, chainPrimitivesAfterRound - evidenceFrontier.primitives)
    const newRuntimeConfirmed = Math.max(0, confirmedAfterRound - evidenceFrontier.confirmed)
    this.plannerEvidenceFrontier.set(run.id, {
      confirmed: confirmedAfterRound,
      primitives: chainPrimitivesAfterRound,
    })
    const dryRounds = newRuntimeConfirmed + newChainPrimitives > 0
      ? 0
      : (this.plannerDryRounds.get(run.id) ?? 0) + 1
    this.plannerDryRounds.set(run.id, dryRounds)
    const queueDrained = this.highPriorityQueueEmpty({
      id: run.id,
      goalRevision: this.storage.run(run.id).goalRevision,
    })
    this.storage.event(
      run.id,
      'planner.dry_rounds',
      `Planner dry-round ${dryRounds}/${DRY_ROUND_LIMIT}: ${newRuntimeConfirmed} new confirmed, ${newChainPrimitives} new chain primitive(s)${queueDrained ? '; high-priority queue empty' : ''}.`,
      {
        consecutiveDryRounds: dryRounds,
        limit: DRY_ROUND_LIMIT,
        newRuntimeConfirmed,
        newChainPrimitives,
        highPriorityQueueEmpty: queueDrained,
      },
    )
    const latest = this.storage.run(run.id)
    const decision = coordinatorSchedulerDecision({
      budgetExhausted: this.storage.checkBudgetExceeded(run.id),
      budgetRequests: latest.budgetRequests,
      spentRequests: latest.spentRequests,
      startedAt: latest.createdAt,
      maxDurationMs: this.maxDurationMs,
      emptyRounds,
      coordinatorDone: parsedPlanner?.success ? parsedPlanner.data.done : false,
      pendingOob: coordinator.queryFindings({ status: 'pending_oob', limit: 1 }).total,
      highPriorityQueueEmpty: queueDrained,
      consecutiveDryRounds: dryRounds,
    })

    // v7 coverage guard: a dry/coordinator stop must not abandon planned, dispatchable work while a
    // worker slot is free. The stop is deferred (never silently dropped) and the funnel records it.
    const finalSteps = this.storage.listChainSteps(run.id, latest.goalRevision)
    const finalFactIds = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: true, limit, offset })).map(fact => fact.id))
    const remainingReady = dispatchableReadySteps(finalSteps, finalFactIds).length
    const dispatchedTotal = finalSteps.filter(step => step.assignedWorkerId !== null).length
    const maxConc = Math.max(1, Math.min(maxWorkerConcurrency, latest.workerConcurrency || defaultWorkerConcurrency))
    const activeForRun = [...this.active.values()].filter(job =>
      job.assignment.runId === run.id && job.assignment.phase === 'investigation').length
    const stopEval = evaluateDispatchStop({
      decision: decision.decision,
      reason: decision.reason,
      remainingReady,
      freeSlots: Math.max(0, maxConc - activeForRun),
      inFlight: activeForRun,
      budgetExhausted: this.storage.checkBudgetExceeded(run.id),
      requestExhausted: latest.budgetRequests > 0 && latest.budgetRequests - latest.spentRequests <= 0,
      wallExhausted: this.maxDurationMs > 0 && latest.createdAt + this.maxDurationMs <= Date.now(),
    })
    if (stopEval.deferred) {
      this.storage.event(
        run.id,
        'planner.stop_deferred',
        `Planner ${decision.reason} stop deferred: ${remainingReady} dispatchable step(s) still queued for ${Math.max(0, maxConc - activeForRun)} free slot(s).`,
        { roundNo, stopReason: decision.reason, remainingReady, freeSlots: Math.max(0, maxConc - activeForRun) },
      )
    }
    if (stopEval.decision === 'stop') this.plannerDoneRound.set(run.id, roundNo)
    funnel.dispatched = dispatchedTotal
    funnel.dispatchedThisRound = Math.max(0, dispatchedTotal - (this.dispatchFunnels.get(run.id)?.dispatched ?? 0))
    funnel.remainingReady = remainingReady
    funnel.remainingReadyAtStop = stopEval.decision === 'stop' ? remainingReady : 0
    funnel.stopReason = stopEval.decision === 'stop' ? stopEval.stopReason : 'running'
    funnel.filteredDep = permanentlyBlockedStepIds(finalSteps, finalFactIds).length
    if (stopEval.stranded) {
      this.noteStrandedReadySteps(run.id, {
        roundNo, stopReason: stopEval.stopReason, remainingReady,
        dispatched: dispatchedTotal, planned: funnel.planned,
      })
    }
    this.recordDispatchFunnel(run.id, funnel)
    this.storage.event(
      run.id,
      'planner.funnel',
      `Dispatch funnel r${roundNo}: planned ${funnel.planned}, enqueued ${funnel.enqueued}, dispatched ${funnel.dispatched}, ready ${funnel.remainingReady}, stop ${funnel.stopReason}.`,
      { ...funnel, filtered: {
        alreadyConfirmed: funnel.filteredAlreadyConfirmed, cap: funnel.filteredCap,
        dep: funnel.filteredDep, dedupe: funnel.filteredDedupe,
        noAsset: funnel.filteredNoAsset, budget: funnel.filteredBudget,
      } },
    )

    this.tracePlannerDecision(run.id, {
      roundIdx: roundNo, factsCount: allUntaintedFacts.length, detLeadsCount: detLeadSteps,
      alreadyConfirmedCount: funnel.filteredAlreadyConfirmed, spawnedSteps: addedCount, k6DryStreak: emptyRounds,
      dynamicStepBudget, durationMs: Date.now() - plannerStartedAt,
      costUsd: Math.max(0, Number((this.storage.run(run.id).spentUsd - updated.spentUsd).toFixed(6))),
    })
    this.storage.event(run.id, 'planner.round', `Planner round ${roundNo}: added ${addedCount} steps.`, {
      roundNo, addedCount, chainSteps, bolaAutoSteps, secondOrderAutoSteps, detLeadSteps, toolDispatched,
      done: parsedPlanner?.success === true ? parsedPlanner.data.done : false,
      decision: stopEval.decision, reason: stopEval.decision === 'stop' ? decision.reason : 'continue',
      terminationReason: stopEval.decision === 'stop' ? decision.reason : null,
      deferredStopReason: stopEval.deferred ? decision.reason : null,
      consecutiveDryRounds: dryRounds,
      highPriorityQueueEmpty: queueDrained,
      cappedReinvestigations: this.reinvestigationGuardFor(run.id).cappedCount(),
      funnel: {
        planned: funnel.planned, enqueued: funnel.enqueued, dispatched: funnel.dispatched,
        remainingReady: funnel.remainingReady, remainingReadyAtStop: funnel.remainingReadyAtStop,
        filteredCap: funnel.filteredCap, filteredDep: funnel.filteredDep,
        filteredAlreadyConfirmed: funnel.filteredAlreadyConfirmed, stopReason: funnel.stopReason,
      },
      summary: parsedPlanner?.success ? parsedPlanner.data.summary.slice(0, 300) : compactText(answer, 300),
    })
  }

  private startInvestigationStep(run: Run, step: ChainStep, profiles: readonly ResolvedModelProfile[]) {
    const primaryAsset = run.candidates.find(c => step.targetAssetIds.includes(c.id) && run.approved.includes(c.id))
    const targetOrigins = [...new Set([
      ...step.sourceOrigins,
      ...run.candidates.filter(c => step.targetAssetIds.includes(c.id) && run.approved.includes(c.id)).map(c => c.origin),
    ])].filter(o => this.permitted(run, o))
    if (!targetOrigins.length) {
      this.storage.updateChainStep(step.id, { status: 'tainted' })
      return
    }

    const tm = this.storage.latestThreatModel(run.id, run.goalRevision)
    const approvedOriginsList = [...this.approvedOriginsSet(run)]
    const hostTiers = computeHostTiers(approvedOriginsList, tm?.entries)
    const resolvedSpecialistId = step.specialistProfile ?? routeStepToSpecialist({
      title: step.title,
      hypothesis: step.hypothesis,
      category: step.category,
      skills: step.skills,
    })
    const specialistConfig = resolveSpecialistProfile(resolvedSpecialistId)
    const wakeHandle = this.wakeHandleByStepId.get(step.id)
    const warmMember = wakeHandle ? this.storage.boardMember(run.id, wakeHandle) : undefined
    const boardHandle = wakeHandle && warmMember && warmMember.state !== 'retired'
      ? wakeHandle
      : this.allocateBoardHandle(run, resolvedSpecialistId, step)
    const warmSessionId = wakeHandle && warmMember && warmMember.state !== 'retired' ? warmMember.sessionId : undefined
    const baseSpecialistTurns = Math.max(
      25,
      Math.min(specialistConfig.maxTurnsCeiling, run.workerMaxTurns > 0 ? Math.min(run.workerMaxTurns, specialistConfig.defaultMaxTurns) : specialistConfig.defaultMaxTurns),
    )
    const stepMaxTurns = computeStepMaxTurns(targetOrigins, hostTiers, baseSpecialistTurns)
    // Throughput: a standalone step gets a short cap so the slot turns over; only a step that
    // cites upstream evidence keeps the long chain budget.
    const budget = planAssignmentBudget({
      routes: this.stepMentionedRoutes(step),
      parentEvidenceIds: step.dependsOnFactIds,
      dependsOnStepIds: step.dependsOnStepIds,
      multiStep: isMultiStepAssignment({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      }),
      baseMaxTurns: stepMaxTurns,
      baseWallClockMs: this.specialistWallClockMs(stepMaxTurns),
      singleStepWallClockMs: singleStepWallClockMs(),
    })

    const assignment = this.storage.transaction(() => {
      const worker = this.storage.makeWorker(run, 'investigation', primaryAsset, step.title, step.hypothesis, {
        stepId: step.id,
        maxTurns: budget.maxTurns,
        parentFactIds: step.dependsOnFactIds,
        sourceOrigins: targetOrigins,
      })
      const claimed = this.storage.updateWorker(worker.id, {
        status: 'running',
        ...(warmSessionId ? { sessionId: warmSessionId } : {}),
        lease: randomUUID(),
        leaseExpiresAt: Date.now() + intentLeaseMs,
      })!
      this.storage.updateChainStep(step.id, {
        status: 'running',
        assignedWorkerId: claimed.id,
        specialistProfile: resolvedSpecialistId,
      })
      this.storage.addGraphEdge(run.id, {
        fromKind: 'step', fromId: step.id, toKind: 'assignment', toId: claimed.id, edgeKind: 'spawns',
      })
      this.storage.event(run.id, 'worker.started', `${step.title} started.`, {
        assignmentId: claimed.id, stepId: step.id, specialistProfile: resolvedSpecialistId,
        assignmentBudget: budget,
      })
      return claimed
    }, { behavior: 'immediate' })
    const effectiveStep: ChainStep = { ...step, specialistProfile: resolvedSpecialistId }

    const job: Active = { assignment, origins: new Set(targetOrigins), controller: new AbortController() }
    this.active.set(assignment.id, job)
    this.boardHandleByAssignment.set(assignment.id, boardHandle)
    this.trackedBoardRuns.add(run.id)
    try {
      this.storage.upsertBoardMember(run, {
        handle: boardHandle,
        role: 'specialist',
        specialistProfile: resolvedSpecialistId,
        sessionId: assignment.sessionId,
        activeAssignmentId: assignment.id,
        state: 'working',
        sourceOrigins: targetOrigins,
      })
      this.warm.register(boardHandle, {
        sessionId: assignment.sessionId,
        state: 'waiting',
        lastReadSeq: this.storage.boardMember(run.id, boardHandle)?.lastReadSeq ?? 0,
      })
      this.warm.wake(boardHandle, assignment.id)
    } catch { /* roster mirror is best-effort */ }

    this.postCoordinatorBrief(run, effectiveStep, boardHandle, targetOrigins)

    void this.runInvestigationWorker(job, effectiveStep, targetOrigins, profiles, budget).catch(error => {
      if (error instanceof BudgetExceededError) {
        this.storage.checkBudgetExceeded(run.id)
        return
      }
      // Provider-stream stall: aborting the assignment's provider call frees the slot without
      // spending the rest of its wall budget. One retry is allowed per assignment.
      if (job.stallAbort) {
        const attempt = job.assignment.attempt
        if (shouldRetryStalledAssignment(attempt)) {
          this.providerStallRetriesByRun.set(run.id, (this.providerStallRetriesByRun.get(run.id) ?? 0) + 1)
          this.storage.transaction(() => {
            this.storage.updateWorker(assignment.id, {
              status: 'canceled',
              outcome: 'Provider stream stalled; requeued once for a fresh attempt.',
              attempt: attempt + 1,
              lease: null,
              leaseExpiresAt: null,
            })
            this.storage.updateChainStep(step.id, { status: 'ready', assignedWorkerId: null })
            this.storage.event(run.id, 'worker.stall_retry', `${step.title} provider stream stalled; requeued once.`, {
              assignmentId: assignment.id, stepId: step.id, attempt: attempt + 1,
            })
          })
          return
        }
        this.storage.transaction(() => {
          this.storage.updateWorker(assignment.id, {
            status: 'failed',
            outcome: 'Provider stream stalled after retry; slot released.',
            attempt: attempt + 1,
            lease: null,
            leaseExpiresAt: null,
          })
          this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assignment.id })
          this.storage.event(run.id, 'worker.stall_failed', `${step.title} provider stream stalled twice; assignment closed without consuming the wall cap.`, {
            assignmentId: assignment.id, stepId: step.id,
          })
        })
        return
      }
      if (!this.authorize(job) || job.controller.signal.aborted) return
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
      this.storage.transaction(() => {
        this.storage.updateWorker(assignment.id, {
          status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null, attempt: assignment.attempt + 1,
        })
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assignment.id })
        this.storage.event(run.id, 'worker.failed', `${step.title} failed: ${msg}`, { assignmentId: assignment.id, stepId: step.id })
      })
    }).finally(() => {
      this.active.delete(assignment.id)
      try { this.finishBoardMember(this.storage.run(run.id), assignment.id) } catch { /* run may be gone */ }
      this.schedulePlanner(run.id)
      this.scheduleWake()
    })
  }

  private async runInvestigationWorker(
    job: Active,
    step: ChainStep,
    targetOrigins: string[],
    profiles: readonly ResolvedModelProfile[],
    budget: AssignmentBudget,
  ) {
    const run = this.check(job)
    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)

    // Open ONE persistent air-gapped container for the entire intent
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    const session = await this.backend.openSession(
      job.assignment.id,
      job.controller.signal,
      reposDir ? { reposDir } : undefined,
    )
    const startedAt = Date.now()
    // Per-turn generation latencies (provider stream), plus a watchdog that aborts a buffered
    // stream instead of letting it consume the assignment wall.
    const turnLatencies: number[] = []
    let generationStartedAt: number | undefined
    let stallTimer: NodeJS.Timeout | undefined
    const clearStallTimer = () => {
      if (stallTimer) { clearTimeout(stallTimer); stallTimer = undefined }
    }
    const stallAbortMs = () => providerStallAbortMs(percentile(turnLatencies, 50), turnLatencies.length)
    /** Never let the watchdog outlive the assignment wall: leave 10 s (floor 15 s) to requeue. */
    const stallDeadlineMs = () => {
      const remainingWall = Math.max(0, budget.wallClockMs - (Date.now() - startedAt))
      return Math.min(stallAbortMs(), Math.max(15_000, remainingWall - 10_000))
    }
    const armStallTimer = (turn: number) => {
      clearStallTimer()
      generationStartedAt = Date.now()
      if (job.stallAbort) return
      const thresholdMs = stallDeadlineMs()
      stallTimer = setTimeout(() => {
        if (!generationStartedAt) return
        const elapsed = Date.now() - generationStartedAt
        job.stallAbort = true
        try {
          this.storage.event(run.id, 'worker.provider_stall', `Provider stream stalled on turn ${turn} (${Math.round(elapsed / 1000)}s without a response); aborting to free the slot.`, {
            assignmentId: job.assignment.id, stepId: step.id, turn, elapsedMs: elapsed, thresholdMs, stallAbortMs: stallAbortMs(), wallClockMs: budget.wallClockMs,
          })
        } catch { /* telemetry only */ }
        job.controller.abort(new Error('Provider stream stalled.'))
      }, thresholdMs)
      stallTimer.unref?.()
    }
    const recordTurnLatency = () => {
      if (generationStartedAt === undefined) return
      const ms = Math.max(0, Date.now() - generationStartedAt)
      generationStartedAt = undefined
      clearStallTimer()
      turnLatencies.push(ms)
      const stalls = this.providerStallTurnsByRun.get(run.id) ?? 0
      if (ms > PROVIDER_STALL_TURN_MS) this.providerStallTurnsByRun.set(run.id, stalls + 1)
    }

    try {
      // Stage relevant specs and parent facts inside the air-gapped container
      const specs = this.storage.listProjectSpecsFull(run.projectId)
      const stagedSpecs: Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }> = []
      for (const [idx, spec] of specs.slice(0, 8).entries()) {
        const safeName = `specs/spec-${idx + 1}.txt`
        try {
          const stagedPath = await session.stage(safeName, spec.content.slice(0, 1_500_000), job.controller.signal)
          stagedSpecs.push({ name: spec.name, kind: spec.kind, origin: spec.origin, stagedPath })
        } catch { /* skip oversized */ }
      }

      const parentFacts = step.dependsOnFactIds.length
        ? this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
            .filter(f => step.dependsOnFactIds.includes(f.id) && permittedAtAdmission.has(f.origin))
        : []
      if (parentFacts.length) {
        await session.stage('parent-facts.json', JSON.stringify(parentFacts, null, 2), job.controller.signal).catch(() => undefined)
      }

      const trackPersonaResources = (curRun: Run, res: BrokerExchangeResult, exchangeId: string) => {
        // Persist samples + producer->consumer edges for authenticated AND unauthenticated responses.
        // (Unauthenticated leaks can seed later cross-persona BOLA/IDOR replay targets.)
        const observedResources = this.storage.trackExchangeResources({
          runId: curRun.id,
          scopeRevision: curRun.scopeRevision,
          exchange: {
            origin: res.origin,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            personaHandle: res.personaHandle,
            status: res.status,
            mediaType: res.mediaType,
            body: res.body,
            respHeaders: res.respHeaders,
          },
          source: 'surface_probe',
        })
        if (!observedResources.length || !res.personaHandle) return
        if (curRun.capabilityTier < 2 || (grant.personas?.size ?? 0) < 2) return
        let seenSet = this.recordedPersonaResources.get(curRun.id)
        if (!seenSet) {
          seenSet = new Set<string>()
          this.recordedPersonaResources.set(curRun.id, seenSet)
        }
        for (const item of observedResources) {
          if (item.resourceId === '[redacted]') continue
          const dedupKey = `${res.origin}|${res.personaHandle}|${item.endpoint}|${item.resourceId}`
          if (seenSet.has(dedupKey)) continue
          seenSet.add(dedupKey)
          this.storage.addFact(curRun, job.assignment, {
            kind: 'persona_resource',
            origin: res.origin,
            summary: `Persona "${res.personaHandle}" observed owned resource ${item.field}=${item.resourceId} at ${item.method} ${item.endpoint} (HTTP ${res.status}).`,
            data: {
              ownerPersona: res.personaHandle,
              resourceId: item.resourceId,
              endpoint: item.endpoint,
              method: item.method,
              field: item.field,
              status: res.status,
            },
            exchangeIds: [exchangeId],
            sourceOrigins: [res.origin],
            secrets: currentSecrets(),
          })
        }
      }

      const executeBrokerRequest = async (args: RequestHttpArgs, signal: AbortSignal): Promise<{
        exchangeId: string
        stagedPath: string | null
        result: BrokerExchangeResult
      }> => {
        const curRun = this.check(job)
        if (this.storage.checkBudgetExceeded(curRun.id)) {
          throw new BudgetExceededError('Run spend or request budget exceeded.')
        }
        const headers = { ...(args.headers ?? {}) }
        let jsonBody: unknown = args.jsonBody
        let body: string | undefined
        // v6 staging: every agent mutation carries the run tag on entity-creating values and on
        // request headers, so the tenant contract stays strict while the probe is attributable.
        const scopePolicy = this.storage.scopePolicy(curRun)
        const stagingEntityTag = scopePolicy.mode === 'staging_isolated' ? tenantTagForRun(curRun.id) : null
        if (stagingEntityTag) {
          const tagged = this.stagingTagAgentRequest({
            runId: curRun.id, grant, mode: scopePolicy.mode, entityTag: stagingEntityTag,
            method: args.method, pathAndQuery: args.pathAndQuery,
            ...(args.probeClass ? { probeClass: args.probeClass } : {}),
            ...(jsonBody !== undefined ? { jsonBody } : {}),
          })
          if (tagged.skipped) {
            throw new BrokerDenied(`staging_isolated cannot safely tag this mutation (${tagged.skipped}); skipped without sending.`)
          }
          Object.assign(headers, tagged.headers)
          if (tagged.jsonBody !== undefined) jsonBody = tagged.jsonBody
        }
        if (args.textBody !== undefined) {
          body = args.textBody
          if (headers['x-guardian-tenant-tag'] && jsonBody === undefined) {
            try {
              const parsed = JSON.parse(args.textBody) as unknown
              if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                body = JSON.stringify(tagStagingEntityBody(parsed as Record<string, unknown>, stagingEntityTag!))
              }
            } catch { /* non-JSON text bodies stay byte-identical; headers still carry the tag */ }
          }
        } else if (jsonBody !== undefined) {
          body = JSON.stringify(jsonBody)
          if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
        }

        const runHttp = () => this.broker.executeHttp({
          origin: args.origin,
          method: args.method,
          pathAndQuery: args.pathAndQuery,
          headers,
          body,
          multipartParts: args.multipartParts,
          persona: args.persona,
          session: args.session,
          csrfBind: args.csrfBind,
          authMutation: args.authMutation,
          probeClass: args.probeClass,
          traceId: args.traceId,
          runId: curRun.id,
          assignmentId: job.assignment.id,
          scopeRevision: curRun.scopeRevision,
          followRedirects: args.followRedirects ?? false,
        }, grant, signal)

        let res: BrokerExchangeResult
        try {
          res = await runHttp()
        } catch (err) {
          if (err instanceof BrokerApprovalRequired) {
            const approval = await this.waitForTier3Approval(job, {
              origin: err.origin,
              method: err.method,
              pathAndQuery: err.pathAndQuery,
              personaHandle: args.persona ?? null,
              rationale: args.rationale ?? `Tier 3 probe during step "${step.title}"`,
              requestPreview: JSON.stringify({
                method: args.method, origin: args.origin, pathAndQuery: args.pathAndQuery,
                persona: args.persona, headers, bodyPreview: body?.slice(0, 500),
                ...(args.multipartParts?.length ? { multipartPartsCount: args.multipartParts.length } : {}),
              }, null, 2),
              bodyPreview: body,
              bodyHash: computeStateChangeBodyHash(body, args.multipartParts),
              headers,
              hasMultipart: Boolean(args.multipartParts?.length) || hasDeclaredMultipartContentType(headers),
              secrets: currentSecrets(),
            }, signal)
            if (!approval.approved) {
              throw new BrokerDenied(
                approval.deniedReason
                  ? `Tier 3 Safety Judge denied probe: ${approval.deniedReason}`
                  : 'Tier 3 request was denied or expired.',
              )
            }
            res = await runHttp()
          } else {
            throw err
          }
        }

        const saved = this.storage.recordExchange({
          runId: curRun.id,
          assignmentId: job.assignment.id,
          scopeRevision: curRun.scopeRevision,
          origin: res.origin,
          finalOrigin: res.finalOrigin,
          redirectOrigins: res.redirectOrigins,
          method: res.method,
          pathAndQuery: res.pathAndQuery,
          personaHandle: res.personaHandle,
          status: res.status,
          mediaType: res.mediaType,
          reqHeaders: res.reqHeaders,
          respHeaders: res.respHeaders,
          body: res.body,
          durationMs: res.durationMs,
          secretMatches: res.secretMatches,
          secrets: currentSecrets(),
        })

        // Priority #3: Auto-track persona_resource facts when Tier >= 2 and >= 2 personas are approved
        trackPersonaResources(curRun, res, saved.id)
        boardTools.noteEvidence()
        this.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
        this.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)
        // v6 staging: record what a tagged mutation created so the run-scoped cleanup can audit it.
        if (stagingEntityTag && /^(?:POST|PUT|PATCH)$/i.test(args.method) && res.status >= 200 && res.status < 300) {
          const created = extractCreatedId(res.body)
          if (created) {
            const set = this.stagingCreatedEntities.get(curRun.id) ?? new Set<string>()
            set.add(created)
            this.stagingCreatedEntities.set(curRun.id, set)
          }
        }

        let stagedPath: string | null = null
        try {
          stagedPath = await session.stage(`exchanges/${saved.id}.json`, JSON.stringify({
            exchangeId: saved.id,
            origin: res.origin,
            finalOrigin: res.finalOrigin,
            redirectOrigins: res.redirectOrigins,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            status: res.status,
            mediaType: res.mediaType,
            reqHeaders: res.reqHeaders,
            respHeaders: res.respHeaders,
            setCookies: res.setCookies,
            bodySha256: res.bodySha256,
            body: res.body,
          }, null, 2), signal)
        } catch { /* ignore stage error */ }
        return { exchangeId: saved.id, stagedPath, result: res }
      }

      const executeRaceBurstTool = async (args: RequestHttpRaceArgs, signal: AbortSignal) => {
        const curRun = this.check(job)
        if (curRun.capabilityTier < 2) {
          throw new BrokerDenied('Race-condition burst testing requires Capability Tier 2 or Tier 3.')
        }
        if (this.storage.checkBudgetExceeded(curRun.id)) {
          throw new BudgetExceededError('Run spend or request budget exceeded.')
        }
        if (curRun.budgetRequests > 0 && curRun.spentRequests + args.requests.length > curRun.budgetRequests) {
          throw new BudgetExceededError('Race burst would exceed run request budget.')
        }
        const racePolicy = this.storage.scopePolicy(curRun)
        const raceEntityTag = racePolicy.mode === 'staging_isolated' ? tenantTagForRun(curRun.id) : null
        const brokerReqs: BrokerHttpRequest[] = args.requests.map(r => {
          const headers = { ...(r.headers ?? {}) }
          let body: string | undefined
          if (r.textBody !== undefined) body = r.textBody
          else if (r.jsonBody !== undefined) {
            body = JSON.stringify(r.jsonBody)
            if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
          }
          return {
            origin: r.origin,
            method: r.method,
            pathAndQuery: r.pathAndQuery,
            headers,
            body,
            persona: r.persona,
            session: r.session,
            csrfBind: r.csrfBind,
            authMutation: r.authMutation,
            probeClass: r.probeClass,
            traceId: r.traceId,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            followRedirects: r.followRedirects ?? false,
          }
        })
        const stagedReqs = this.stageAgentRaceBurst(curRun.id, grant, racePolicy.mode, raceEntityTag, brokerReqs)

        // One synchronized decision covers every instance of the burst. Identical requests
        // register one single-use instance each (never one shared grant), so the legitimate
        // 3x/5x/10x burst no longer loops through fresh approval cards after the first consume.
        const burst = await this.executeApprovedRaceBurst(job, stagedReqs, grant, signal, {
          stepTitle: step.title,
          rationale: args.rationale,
          secrets: currentSecrets(),
          execute: () => this.broker.executeRaceBurst(stagedReqs, grant, signal),
        })

        const summaries = burst.results.map(res => {
          const saved = this.storage.recordExchange({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            finalOrigin: res.finalOrigin,
            redirectOrigins: res.redirectOrigins,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            personaHandle: res.personaHandle,
            status: res.status,
            mediaType: res.mediaType,
            reqHeaders: res.reqHeaders,
            respHeaders: res.respHeaders,
            body: res.body,
            durationMs: res.durationMs,
            secretMatches: res.secretMatches,
            secrets: currentSecrets(),
          })
          trackPersonaResources(curRun, res, saved.id)
          this.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
          this.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)
          return {
            exchangeId: saved.id,
            origin: res.origin,
            method: res.method,
            pathAndQuery: res.pathAndQuery,
            personaHandle: res.personaHandle,
            status: res.status,
            durationMs: res.durationMs,
            bodySha256: res.bodySha256,
            bodyPreview: res.bodyPreview.slice(0, 800),
          }
        })
        const stagedPath = await session.stage(`exchanges/race-${randomUUID().slice(0, 8)}.json`,
          JSON.stringify({ summary: burst.summary, results: summaries }, null, 2), signal).catch(() => null)
        boardTools.noteEvidence()
        return { count: summaries.length, summary: burst.summary, stagedPath, results: summaries }
      }

      const boardHandle = this.boardHandleByAssignment.get(job.assignment.id) ??
        this.boardHandleForAssignmentId(run, job.assignment.id)
      const boardTools = createBoardTools({
        store: this.storage,
        run: run.id,
        handle: boardHandle,
        redact: (text: string) => redact(text, currentSecrets()),
        onWakeup: (target, message) => {
          try { this.wakeBoardMember(this.storage.run(run.id), target, message) } catch { /* advisory */ }
        },
      })

      const handlers: WorkerToolHandlers = {
        spillOutput: async (id, content, signal) => session.stage(`tool-output/${id}.txt`, content, signal),

        board_post: async (args) => boardTools.board_post(args),
        board_read: async (args) => boardTools.board_read(args),

        request_http: async (args, signal) => {
          const { exchangeId, stagedPath, result } = await executeBrokerRequest(args, signal)
          return {
            exchangeId,
            stagedPath,
            origin: result.origin,
            finalOrigin: result.finalOrigin,
            redirectOrigins: result.redirectOrigins,
            status: result.status,
            mediaType: result.mediaType,
            respHeaders: result.respHeaders,
            setCookies: result.setCookies,
            bodyBytes: result.bodyBytes,
            bodySha256: result.bodySha256,
            bodyPreview: result.bodyPreview.slice(0, 6000),
            durationMs: result.durationMs,
          }
        },

        request_http_batch: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const brokerReqs = args.requests.map(r => {
            const headers = { ...(r.headers ?? {}) }
            let body: string | undefined
            if (r.textBody !== undefined) body = r.textBody
            else if (r.jsonBody !== undefined) {
              body = JSON.stringify(r.jsonBody)
              if (!headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'application/json'
            }
            return {
              origin: r.origin, method: r.method, pathAndQuery: r.pathAndQuery,
              headers, body, persona: r.persona, session: r.session,
              multipartParts: r.multipartParts,
              csrfBind: r.csrfBind, authMutation: r.authMutation, probeClass: r.probeClass,
              traceId: r.traceId, runId: curRun.id, assignmentId: job.assignment.id,
              scopeRevision: curRun.scopeRevision,
              followRedirects: r.followRedirects ?? false,
            }
          })
          // One synchronized approval covers the whole batch. Identical items share a fingerprint
          // and register one single-use instance each, so a retry never fails on an already
          // consumed grant and never spams one card per item.
          const results = await this.executeApprovedBatch(job, brokerReqs, grant, signal, {
            stepTitle: step.title,
            rationale: args.rationale,
            secrets: currentSecrets(),
            execute: () => this.broker.executeBatch(brokerReqs, grant, signal),
          })
          const summaries = results.map(res => {
            const saved = this.storage.recordExchange({
              runId: curRun.id,
              assignmentId: job.assignment.id,
              scopeRevision: curRun.scopeRevision,
              origin: res.origin,
              finalOrigin: res.finalOrigin,
              redirectOrigins: res.redirectOrigins,
              method: res.method,
              pathAndQuery: res.pathAndQuery,
              personaHandle: res.personaHandle,
              status: res.status,
              mediaType: res.mediaType,
              reqHeaders: res.reqHeaders,
              respHeaders: res.respHeaders,
              body: res.body,
              durationMs: res.durationMs,
              secretMatches: res.secretMatches,
              secrets: currentSecrets(),
            })
            trackPersonaResources(curRun, res, saved.id)
            this.markEndpointCoverage(curRun, res.origin, res.method, res.pathAndQuery, 'http_exchange')
            this.scanSecondOrderExchange(curRun, job.assignment.id, res, saved.id)
            return {
              exchangeId: saved.id, status: res.status, durationMs: res.durationMs,
              bodySha256: res.bodySha256, bodyPreview: res.bodyPreview.slice(0, 800),
            }
          })
          const stagedPath = await session.stage(`exchanges/batch-${randomUUID().slice(0, 8)}.json`,
            JSON.stringify(summaries, null, 2), signal).catch(() => null)
          boardTools.noteEvidence()
          return { count: summaries.length, stagedPath, results: summaries }
        },

        requestHttpRace: executeRaceBurstTool,
        request_http_race: executeRaceBurstTool,

        inspect_dns: async ({ origin }, signal) => {
          const curRun = this.check(job)
          const dnsRes = await this.broker.inspectDns(origin, grant, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'dns',
            `DNS inspection · ${dnsRes.hostname}`, JSON.stringify(dnsRes, null, 2), undefined, secrets)
          const stagedPath = await session.stage(`dns-${dnsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`,
            JSON.stringify(dnsRes, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...dnsRes }
        },

        inspect_tls: async ({ origin }, signal) => {
          const curRun = this.check(job)
          const tlsRes = await this.broker.inspectTls(origin, grant, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'tls',
            `TLS audit · ${tlsRes.hostname}`, JSON.stringify(tlsRes, null, 2), undefined, secrets)
          const stagedPath = await session.stage(`tls-${tlsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`,
            JSON.stringify(tlsRes, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...tlsRes }
        },

        browser_visit: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const res = await this.browser.visitPage({
            origin: args.origin,
            pathAndQuery: args.pathAndQuery,
            persona: args.persona,
            session: args.session,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            traceId: randomUUID(),
            checkKind: args.domCheck && args.domCheck !== 'none' ? args.domCheck : undefined,
            actions: args.actions,
            enableSinkHook: args.enableSinkHook,
            waitAfterLoadMs: args.waitAfterLoadMs,
            secrets: currentSecrets(),
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
              return saved.id
            },
          }, grant, signal)
          const summaryObj = {
            origin: res.origin,
            finalUrl: res.finalUrl,
            title: res.title,
            status: res.status,
            links: res.links.slice(0, 60),
            forms: res.forms.slice(0, 30),
            xhrRequests: res.xhrRequests.slice(0, 80),
            blockedOrigins: res.blockedOrigins,
            consoleMessages: res.consoleMessages.slice(0, 40),
            postMessageListeners: res.postMessageListeners,
            cookieNames: res.cookieNames,
            localStorageKeys: res.localStorageKeys,
            sessionStorageKeys: res.sessionStorageKeys,
            canaryCheck: res.canaryCheck,
            actionResults: res.actionResults,
            builtinResults: res.builtinResults,
            domSinkTraces: res.domSinkTraces,
            exchangeIds: res.exchangeIds,
            domSnippet: res.domSnippet.slice(0, 6000),
            durationMs: res.durationMs,
          }
          const ev = this.storage.addArtifact(curRun, job.assignment, 'browser',
            `Browser visit · ${args.origin}${args.pathAndQuery.slice(0, 60)}`,
            JSON.stringify(summaryObj, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`browser-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(summaryObj, null, 2), signal).catch(() => null)
          boardTools.noteEvidence()
          return { evidenceId: ev.id, stagedPath, ...summaryObj }
        },

        browser_session: async ({ steps }, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const visits = await this.browser.runBrowserSession(
            steps.map(s => ({
              ...s,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              secrets: currentSecrets(),
              onExchange: ex => {
                const saved = this.storage.recordExchange({
                  runId: curRun.id,
                  assignmentId: job.assignment.id,
                  scopeRevision: curRun.scopeRevision,
                  origin: ex.origin,
                  finalOrigin: ex.finalOrigin,
                  redirectOrigins: ex.redirectOrigins,
                  method: ex.method,
                  pathAndQuery: ex.pathAndQuery,
                  personaHandle: ex.personaHandle,
                  status: ex.status,
                  mediaType: ex.mediaType,
                  reqHeaders: ex.reqHeaders,
                  respHeaders: ex.respHeaders,
                  body: ex.body,
                  durationMs: ex.durationMs,
                  secretMatches: ex.secretMatches,
                  secrets: currentSecrets(),
                })
                trackPersonaResources(curRun, ex, saved.id)
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
                return saved.id
              },
            })),
            grant,
            signal,
          )
          const summarized = visits.map(({ exchanges: _ex, ...rest }) => ({
            ...rest,
            domSnippet: rest.domSnippet.slice(0, 2000),
          }))
          const ev = this.storage.addArtifact(curRun, job.assignment, 'browser',
            `Browser session (${steps.length} steps)`,
            JSON.stringify(summarized, null, 2), undefined, currentSecrets())
          return { evidenceId: ev.id, stepsCount: visits.length, visits: summarized }
        },

        crawl_state_graph: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          // Phase-aware cap: Phase B spends only its own allowance, never the floor's leftover.
          const remainingReqs = this.phaseRequestRemaining(curRun) ?? undefined
          if (remainingReqs !== undefined && remainingReqs <= 0) {
            throw new BudgetExceededError('Agent request budget exhausted.')
          }
          const crawlRes = await crawlStateGraph({
            storage: this.storage,
            runId: curRun.id,
            scopeRevision: curRun.scopeRevision,
            origin: cleanOrigin,
            personas: args.personas,
            maxPages: args.maxPages,
            maxDepth: args.maxDepth,
            budgetRemaining: remainingReqs,
            browser: this.browser,
            grant,
            signal,
            assignmentId: job.assignment.id,
          })
          return crawlRes
        },

        run_sast_scan: async (args, signal) => {
          const curRun = this.check(job)
          const res = await session.sast(args, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'sast',
            `SAST scan · ${res.repo} (${res.enginesRun.join(', ')})`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          for (const engine of res.enginesRun) {
            const st = res.engineStatus[engine]
            this.storage.recordSastRun({
              runId: curRun.id,
              assignmentId: job.assignment.id,
              repo: res.repo,
              engine,
              rawArtifactId: ev.id,
              findingCount: st?.count ?? 0,
              durationMs: st?.durationMs ?? res.durationMs,
            })
          }

          // SCA (trivy-fs) findings carry CVE ids. Record them as low-confidence hypotheses so the
          // planner and safe-template runner can target real advisories (never auto-confirmed).
          const scaCves = new Map<string, { file: string; severity: string }>()
          for (const finding of res.findings) {
            if (finding.engine !== 'trivy-fs') continue
            for (const match of `${finding.ruleId} ${finding.message}`.matchAll(/CVE-\d{4}-\d{4,}/gi)) {
              const cve = match[0].toUpperCase()
              if (!scaCves.has(cve)) scaCves.set(cve, { file: finding.file, severity: finding.severity })
            }
          }
          if (scaCves.size > 0) {
            const targetOrigin = [...this.approvedOriginsSet(curRun)][0]
            const existingCves = new Set(
              this.storage.listFacts(curRun.id, { includeTainted: false, kind: 'cve_hypothesis', limit: 100 })
                .map(f => (typeof f.data?.cveId === 'string' ? f.data.cveId.toUpperCase() : '')),
            )
            for (const [cve, meta] of [...scaCves.entries()].slice(0, 40)) {
              if (!targetOrigin || existingCves.has(cve)) continue
              existingCves.add(cve)
              this.storage.addFact(curRun, job.assignment, {
                kind: 'cve_hypothesis',
                origin: targetOrigin,
                summary: `trivy-fs flagged ${cve} (${meta.severity}) in ${res.repo}/${meta.file}. Hypothesis only: verify runtime reachability with a non-destructive Replay Spec.`,
                data: {
                  cveId: cve,
                  repo: res.repo,
                  file: meta.file,
                  severity: meta.severity,
                  source: 'trivy-fs',
                  templateIds: templateIdsForCves([cve]),
                  confidence: 'low',
                },
                sourceOrigins: [targetOrigin],
                secrets: currentSecrets(),
              })
            }
          }
          return { evidenceId: ev.id, ...res }
        },

        run_offline_script: async (args, signal) => {
          const curRun = this.check(job)
          const res = await session.runScript(args, signal)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis',
            `Offline ${args.runtime} script`,
            JSON.stringify({
              runtime: res.runtime,
              exitCode: res.exitCode,
              timedOut: res.timedOut,
              durationMs: res.durationMs,
              stdout: redact(res.stdout, currentSecrets()),
              stderr: redact(res.stderr, currentSecrets()),
            }, null, 2), undefined, currentSecrets())
          return { evidenceId: ev.id, ...res }
        },

        probe_surface: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = this.phaseRequestRemaining(curRun) ?? (args.maxRequests ?? 150)
          if (remainingReqs <= 0) {
            throw new BudgetExceededError('Agent request budget exhausted.')
          }
          const cappedMax = args.maxRequests !== undefined
            ? Math.min(args.maxRequests, remainingReqs)
            : Math.min(150, remainingReqs)

          const res = await probeSurface({
            origin: cleanOrigin,
            mode: args.mode,
            wordlists: args.wordlists?.length ? args.wordlists : (args.wordlist ? [args.wordlist] : undefined),
            paths: args.mode === 'paths' ? args.candidates : undefined,
            params: args.mode === 'params' ? args.candidates : undefined,
            basePath: args.basePath,
            paramLocation: args.paramLocation,
            methods: args.methods,
            persona: args.persona,
            maxRequests: cappedMax,
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              trackPersonaResources(curRun, ex, saved.id)
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
              return saved.id
            },
          }, this.broker, grant, signal)

          this.markEndpointCoverage(
            curRun,
            res.origin,
            args.methods?.[0] ?? 'GET',
            args.basePath ?? '/',
            `surface:${res.mode}`,
          )
          this.storage.recordSurfaceProbe({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            probeKind: `surface:${res.mode}`,
            requestsSent: res.requestsSent,
            anomaliesFound: res.anomalies.length,
            baselineSignature: res.baselineSignature,
          })
          const ev = this.storage.addArtifact(curRun, job.assignment, 'surface',
            `Surface probe (${res.mode}) · ${res.origin}`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`surface-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(res, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...res }
        },

        probe_differential: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = this.phaseRequestRemaining(curRun) ?? (args.maxRequests ?? 60)
          if (remainingReqs <= 0) {
            throw new BudgetExceededError('Agent request budget exhausted.')
          }
          const cappedMax = args.maxRequests !== undefined
            ? Math.min(args.maxRequests, remainingReqs)
            : Math.min(60, remainingReqs)

          // Default parameter / resource-ID selection from persisted endpoint_params & api_dependencies.
          const requestedTemplate = normalizeEndpointTemplate(args.pathAndQuery.split('?')[0] || '/')
          const targetEndpoint = this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
            .find(ep => ep.pathTemplate === requestedTemplate &&
              (!args.method || ep.method === args.method.toUpperCase()))
            ?? this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
              .find(ep => ep.pathTemplate === requestedTemplate)
          const targetParams = targetEndpoint ? this.storage.listEndpointParams(curRun.id, targetEndpoint.id) : []
          const injectableParams = targetParams.filter(p => ['query', 'json', 'form', 'path', 'graphql_var'].includes(p.location) && !p.isCsrf)
          const preferredParam = [...injectableParams].sort((a, b) =>
            Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)) ||
            Number(a.isObjectId) - Number(b.isObjectId),
          )[0]
          const resolvedParamName = args.paramName ?? preferredParam?.name
          const preferredParamLocation = preferredParam && preferredParam.location !== 'cookie'
            ? preferredParam.location
            : undefined
          const resolvedParamLocation = args.paramLocation ?? preferredParamLocation
          const resourceSamples = this.storage.listResourceSamples(curRun.id)
            .filter(sample => sample.origin === cleanOrigin && sample.resourceId !== '[redacted]')
          const matchingResourceIds = [...new Set([
            ...resourceSamples
              .filter(sample => normalizeEndpointTemplate(sample.endpoint) === requestedTemplate ||
                requestedTemplate.includes(`:${sample.resourceKey}`) ||
                requestedTemplate.split('/').includes(sample.resourceId))
              .map(sample => sample.resourceId),
            ...resourceSamples.map(sample => sample.resourceId),
          ])].slice(0, 10)
          const resolvedResourceIds = args.resourceIds?.length ? args.resourceIds : matchingResourceIds
          const resolvedSsrfParams = args.ssrfParams?.length
            ? args.ssrfParams
            : injectableParams
                .map(param => param.name)
                .filter(name => /(?:url|uri|link|redirect|callback|dest|host|path|file|fetch|webhook|next|return)/i.test(name))
                .slice(0, 16)

          if (args.probeClass === 'ssrf_canary') {
            const project = this.storage.project(curRun.projectId)
            if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
              await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
            }
          }

          const res = await probeDifferential({
            probeClass: args.probeClass,
            origin: cleanOrigin,
            pathAndQuery: args.pathAndQuery,
            method: args.method,
            param: resolvedParamName,
            paramLocation: resolvedParamLocation,
            jsonBody: args.body,
            baselineValue: args.baselineValue,
            persona: args.persona,
            headers: args.headers,
            ssrfParams: resolvedSsrfParams,
            resourceIds: resolvedResourceIds,
            ownerPersona: args.persona,
            otherPersona: args.otherPersona,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            storage: this.storage,
            maxRequests: cappedMax,
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              trackPersonaResources(curRun, ex, saved.id)
              this.scanSecondOrderExchange(curRun, job.assignment.id, ex, saved.id)
              return saved.id
            },
          }, this.broker, grant, this.canaryBroker, signal)

          this.markEndpointCoverage(
            curRun,
            res.origin,
            args.method ?? 'GET',
            args.pathAndQuery,
            `diff:${res.probeClass}`,
          )
          this.storage.recordSurfaceProbe({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            probeKind: `diff:${res.probeClass}`,
            requestsSent: res.requestsSent,
            anomaliesFound: res.anomalies.length,
            baselineSignature: res.verdict,
          })
          const ev = this.storage.addArtifact(curRun, job.assignment, 'surface',
            `Differential probe (${res.probeClass}) · ${res.origin}${args.pathAndQuery.slice(0, 48)}`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`diff-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(res, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...res }
        },

        run_safe_templates: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const remainingReqs = this.phaseRequestRemaining(curRun) ?? 150
          if (remainingReqs <= 0) {
            throw new BudgetExceededError('Agent request budget exhausted.')
          }

          const techFactTags = this.storage.listFacts(curRun.id, { includeTainted: false, origin: cleanOrigin, kind: 'tech_fingerprint', limit: 30 })
            .flatMap(f => {
              const tags = f.data?.tags
              return Array.isArray(tags) ? tags.filter((t): t is string => typeof t === 'string') : []
            })
          const techFingerprint = [...new Set([...(args.techTags ?? []), ...techFactTags])]

          // Feed recent CVE hypotheses and recon-discovered routes into template selection so
          // dynamic placeholders ({{discovered_protected_path}} / {{discovered_api_path}}) target
          // real live paths instead of hardcoded guesses.
          const cveIds = [...new Set(
            this.storage.listFacts(curRun.id, { includeTainted: false, kind: 'cve_hypothesis', limit: 40 })
              .map(f => (typeof f.data?.cveId === 'string' ? f.data.cveId.trim().toUpperCase() : ''))
              .filter(cve => /^CVE-\d{4}-\d{4,}$/i.test(cve)),
          )]
          const liveOrigins = this.approvedOriginsSet(curRun)
          const runEndpoints = this.storage.listEndpoints(curRun.id)
            .filter(ep => liveOrigins.has(ep.origin))
          const protectedPaths = [...new Set(
            runEndpoints
              .map(ep => ep.pathTemplate.split('?')[0])
              .filter(path => /(admin|account|billing|settings|invoice|dashboard)/i.test(path)),
          )].slice(0, 6)
          const apiPaths = [...new Set(
            runEndpoints
              .map(ep => ep.pathTemplate.split('?')[0])
              .filter(path => /^\/(api|graphql|trpc)/i.test(path)),
          )].slice(0, 6)

          const res = await runSafeTemplates({
            origin: cleanOrigin,
            techFingerprint: techFingerprint.length ? techFingerprint : undefined,
            ...(templateIdsForCves(cveIds).length || args.templateIds?.length
              ? { templateIds: [...new Set([...(args.templateIds ?? []), ...templateIdsForCves(cveIds)])] }
              : {}),
            ...(cveIds.length ? { cveIds } : {}),
            ...(protectedPaths.length || apiPaths.length
              ? { discoveredPaths: { protectedPaths, apiPaths } }
              : {}),
            maxTemplates: args.maxTemplates,
            maxRequests: Math.min(150, remainingReqs),
            persona: args.persona,
            runId: curRun.id,
            assignmentId: job.assignment.id,
            storage: this.storage,
            onExchange: ex => {
              const saved = this.storage.recordExchange({
                runId: curRun.id,
                assignmentId: job.assignment.id,
                scopeRevision: curRun.scopeRevision,
                origin: ex.origin,
                finalOrigin: ex.finalOrigin,
                redirectOrigins: ex.redirectOrigins,
                method: ex.method,
                pathAndQuery: ex.pathAndQuery,
                personaHandle: ex.personaHandle,
                status: ex.status,
                mediaType: ex.mediaType,
                reqHeaders: ex.reqHeaders,
                respHeaders: ex.respHeaders,
                body: ex.body,
                durationMs: ex.durationMs,
                secretMatches: ex.secretMatches,
                secrets: currentSecrets(),
              })
              return saved.id
            },
          }, this.broker, grant, this.canaryBroker, signal)

          this.storage.recordSurfaceProbe({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: res.origin,
            probeKind: 'safe_templates',
            requestsSent: res.requestsSent,
            anomaliesFound: res.matches.length,
            baselineSignature: res.baselineSignature,
          })

          // Record template matches strictly as hypothesis/lead facts (NEVER auto-confirmed!)
          for (const match of res.matches) {
            this.storage.addFact(curRun, job.assignment, {
              kind: match.factKind === 'cve_hypothesis' ? 'cve_hypothesis' : 'note',
              origin: res.origin,
              summary: `[Safe template ${match.templateId}] ${match.name} (${match.severity}) on ${match.method} ${match.path} (HTTP ${match.status})`,
              data: {
                templateId: match.templateId,
                cve: match.cve ?? null,
                cwe: match.cwe ?? null,
                severity: match.severity,
                evidence: match.evidence,
                controlStatus: match.controlStatus,
                confidence: 'low',
              },
              exchangeIds: match.exchangeId ? [match.exchangeId] : [],
              sourceOrigins: [res.origin],
              secrets: currentSecrets(),
            })
          }

          const ev = this.storage.addArtifact(curRun, job.assignment, 'surface',
            `Safe templates · ${res.origin} (${res.matches.length} matches)`,
            JSON.stringify(res, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`templates-${ev.id.slice(0, 8)}.json`,
            JSON.stringify(res, null, 2), signal).catch(() => null)
          return { evidenceId: ev.id, stagedPath, ...res }
        },

        probe_websocket: async (args, signal) => {
          const curRun = this.check(job)
          if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          const wsRes = await this.broker.probeWebsocket({
            origin: cleanOrigin,
            pathAndQuery: args.pathAndQuery,
            originHeader: args.spoofOrigin,
            persona: args.persona,
            subprotocols: args.subprotocols,
            sendMessages: args.messages,
            maxFrames: args.maxFrames,
            timeoutMs: args.timeoutMs,
            secrets: currentSecrets(),
          }, grant, signal)
          const syntheticEx = websocketResultToExchange(wsRes)
          const saved = this.storage.recordExchange({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            scopeRevision: curRun.scopeRevision,
            origin: syntheticEx.origin,
            finalOrigin: syntheticEx.finalOrigin,
            redirectOrigins: syntheticEx.redirectOrigins,
            method: syntheticEx.method,
            pathAndQuery: syntheticEx.pathAndQuery,
            personaHandle: syntheticEx.personaHandle,
            status: syntheticEx.status,
            mediaType: syntheticEx.mediaType,
            reqHeaders: syntheticEx.reqHeaders,
            respHeaders: syntheticEx.respHeaders,
            body: syntheticEx.body,
            durationMs: syntheticEx.durationMs,
            secretMatches: syntheticEx.secretMatches,
            secrets: currentSecrets(),
          })
          // Second-order markers can surface in WebSocket frames or upgrade headers.
          const wsScanText = [
            ...Object.entries(wsRes.upgradeHeaders ?? {}).map(([k, v]) => `${k}: ${v}`),
            ...wsRes.frames.map(frame => frame.data),
          ].join('\n')
          if (wsScanText.includes('gn2o_')) {
            const surfaced = scanSecondOrderMarkers({
              text: wsScanText,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              origin: wsRes.origin,
              endpoint: wsRes.pathAndQuery,
              persona: wsRes.personaHandle,
              mediaType: 'websocket',
              exchangeId: saved.id,
              storage: this.storage,
            })
            for (const record of surfaced) {
              this.postCanaryLead(curRun, {
                marker: record.marker,
                origin: wsRes.origin,
                endpoint: wsRes.pathAndQuery,
                persona: wsRes.personaHandle,
                exchangeId: saved.id,
                mediaType: 'websocket',
              })
            }
          }
          const ev = this.storage.addArtifact(curRun, job.assignment, 'ws',
            `WebSocket probe · ${wsRes.origin}${wsRes.pathAndQuery.slice(0, 60)}`,
            JSON.stringify({ exchangeId: saved.id, ...wsRes }, null, 2), undefined, currentSecrets())
          const stagedPath = await session.stage(`ws-${ev.id.slice(0, 8)}.json`,
            JSON.stringify({ exchangeId: saved.id, ...wsRes }, null, 2), signal).catch(() => null)
          return { exchangeId: saved.id, evidenceId: ev.id, stagedPath, ...wsRes }
        },

        derive_evidence: async ({ command, outputs, timeoutMs }, signal) => {
          const curRun = this.check(job)
          const res = await session.exec(command, outputs ?? ['result.txt'], signal, timeoutMs ?? 60_000)
          const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis', 'Derived evidence',
            JSON.stringify({
              command: redact(command, secrets),
              exitStatus: res.exitCode,
              stdout: redact(res.stdout, secrets),
              stderr: redact(res.stderr, secrets),
              outputs: res.outputs,
            }, null, 2), undefined, secrets)
          return {
            evidenceId: ev.id,
            exitCode: res.exitCode,
            stdout: res.stdout,
            stderr: res.stderr,
            outputs: res.outputs,
          }
        },

        analyze_artifact: async (args, signal) => {
          this.check(job)
          const { tool, ...rest } = args
          return await session.analyze(tool, rest, signal)
        },

        query_cves: async (args, signal) => {
          this.check(job)
          const advisories = await queryCves(args, signal)
          return {
            count: advisories.length,
            advisories,
            note: 'Advisories are hypotheses only. Record a cve_hypothesis fact and verify reachability with a non-destructive Replay Spec before confirming.',
          }
        },

        load_skill: async ({ name }) => {
          if (name.trim().toLowerCase() === 'list') return { skills: listSkills() }
          const skill = loadSkill(name)
          if (!skill) return { error: `Unknown skill "${name}".`, available: listSkills().map(s => s.name) }
          return skill
        },

        mint_canary: async ({ purpose }) => {
          const curRun = this.check(job)
          const project = this.storage.project(curRun.projectId)
          if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
            await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() })
          }
          return this.canaryBroker.mintCanary(curRun.id, purpose, targetOrigins[0], {
            storage: this.storage,
            assignmentId: job.assignment.id,
          })
        },

        check_canary: async ({ token }) => {
          const curRun = this.check(job)
          const result = this.canaryBroker.checkCanary(token, { storage: this.storage, runId: curRun.id })
          if (result.hit) {
            const detail = (result.detail ?? {}) as { origin?: unknown; path?: unknown; pathAndQuery?: unknown; persona?: unknown }
            const origin = typeof detail.origin === 'string' && this.permitted(curRun, detail.origin)
              ? detail.origin
              : [...this.approvedOriginsSet(curRun)][0]
            const endpoint = typeof detail.pathAndQuery === 'string'
              ? detail.pathAndQuery
              : typeof detail.path === 'string' ? detail.path : undefined
            if (origin) {
              this.postCanaryLead(curRun, {
                origin,
                endpoint,
                persona: typeof detail.persona === 'string' ? detail.persona : null,
                key: `${curRun.id}:canary:${token}`,
              })
            }
          }
          return result
        },

        mint_second_order_canary: async (args) => {
          const curRun = this.check(job)
          const cleanOrigin = this.parseOriginForRun(curRun, args.injectedOrigin)
          const project = this.storage.project(curRun.projectId)
          if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
            await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() })
          }
          // Route through the CanaryBroker so the marker is registered for OOB callback
          // correlation and for multi-surface second-order scanning.
          const minted = this.canaryBroker.mintSecondOrderCanary({
            runId: curRun.id,
            assignmentId: job.assignment.id,
            injectedOrigin: cleanOrigin,
            injectedEndpoint: args.injectedEndpoint,
            injectedParam: args.injectedParam,
            injectedPersona: args.injectedPersona ?? null,
            storage: this.storage,
          })
          return {
            canaryId: minted.id ?? null,
            id: minted.id ?? null,
            marker: minted.marker,
            httpUrl: minted.httpUrl,
            dnsHost: minted.dnsHost,
            injectedOrigin: minted.injectedOrigin,
            injectedEndpoint: minted.injectedEndpoint,
            injectedParam: minted.injectedParam,
            injectedPersona: minted.injectedPersona,
            listenerActive: this.canaryBroker.listenerInfo().running,
            note: 'Place the marker verbatim in a stored field, then inspect list_second_order_canaries after other personas/renders read it back. A surfaced cross-persona or HTML surface is a high-priority lead, not a confirmed finding.',
          }
        },

        list_second_order_canaries: async ({ status }) => {
          const curRun = this.check(job)
          return this.storage.listSecondOrderCanaries(curRun.id, status)
        },

        search_exchanges: async ({ query, origin, status, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const rows = this.storage.searchExchanges(curRun.id, query, { approvedOrigins: currentApproved, origin, limit })
          return rows
            .filter(ex => status === undefined || ex.status === status)
            .map(ex => ({
              id: ex.id, origin: ex.origin, method: ex.method, pathAndQuery: ex.pathAndQuery,
              status: ex.status, mediaType: ex.mediaType, bodyPreview: ex.bodyPreview.slice(0, 600),
            }))
        },

        get_exchange: async ({ exchangeId, includeBody }, signal) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const ex = this.storage.getExchange(curRun.id, exchangeId)
          if ([ex.origin, ex.finalOrigin, ...ex.redirectOrigins].some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Exchange touches an origin outside current approved scope.')
          }
          let stagedPath: string | null = null
          if (includeBody) {
            stagedPath = await session.stage(`exchanges/${ex.id}.json`, JSON.stringify(ex, null, 2), signal).catch(() => null)
          }
          return {
            ...ex,
            body: includeBody ? ex.body.slice(0, 12_000) : undefined,
            stagedPath,
          }
        },

        search_facts: async ({ query, origin, kind, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
            .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
        },

        read_peer_trace: async ({ assignmentId, limit }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const peers = this.storage.workerList(curRun.id)
            .filter(w => (!assignmentId || w.id === assignmentId) && w.sourceOrigins.every(o => currentApproved.has(o)))
            .slice(-(limit ?? 15))
          return peers.map(p => ({
            id: p.id, phase: p.phase, status: p.status, title: p.title, outcome: p.outcome,
            turnsUsed: p.turnsUsed, requestsUsed: p.requestsUsed,
            facts: this.storage.listFacts(curRun.id, { includeTainted: false, limit: 20 })
              .filter(f => f.assignmentId === p.id)
              .map(f => ({ id: f.id, kind: f.kind, origin: f.origin, summary: f.summary })),
          }))
        },

        // Store-direct digest expansion: no compactor dependency; missing digests are non-fatal.
        expand_digest: async ({ digestId }) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          try {
            const expanded = this.storage.getDigest(curRun.id, digestId)
            return { digest: expanded.digest, facts: expanded.facts.filter(f => currentApproved.has(f.origin)) }
          } catch {
            return { error: 'Digest not found.' }
          }
        },


        record_fact: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const fact = this.storage.addFact(curRun, job.assignment, {
            kind: args.kind,
            origin: cleanOrigin,
            summary: args.summary,
            data: args.data,
            exchangeIds: args.exchangeIds,
            evidenceIds: args.evidenceIds,
            sourceOrigins: args.sourceOrigins,
            secrets: currentSecrets(),
          })
          boardTools.noteEvidence()
          this.schedulePlanner(curRun.id)
          return { factId: fact.id, kind: args.kind, origin: fact.origin }
        },

        record_coverage: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const cleanOrigin = this.parseOriginForRun(curRun, args.origin)
          if (!currentApproved.has(cleanOrigin)) throw new BrokerDenied(`Origin ${cleanOrigin} is not approved.`)
          const ext = args as typeof args & { enforcingControl?: string; proofGapReason?: string; linkedFindingId?: string }
          if (args.status === 'ruled_out' && !ext.enforcingControl?.trim()) {
            throw new Error('record_coverage with status "ruled_out" requires a non-empty enforcingControl (exact file:line or negative-control exchangeId proving the control runs on the attacker path).')
          }
          const entry = this.storage.upsertCoverageEntry(curRun, job.assignment.id, {
            origin: cleanOrigin,
            category: args.category,
            status: args.status,
            summary: args.summary,
            enforcingControl: ext.enforcingControl,
            proofGapReason: args.status === 'needs_follow_up' ? (ext.proofGapReason?.trim() || args.summary) : ext.proofGapReason,
            linkedFindingId: ext.linkedFindingId,
          })
          return { id: entry.id, origin: entry.origin, category: entry.category, status: entry.status }
        },

        propose_chain_finding: async (args) => {
          const { replaySpec, chainFactIds, exchangeIds } = args
          const ext = args as typeof args & {
            counterevidence?: string
            confidenceRationale?: string
            severityChangeConditions?: string
            codeLocations?: CodeLocation[]
          }
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const parsed = declarativeReplaySpecSchema.parse(replaySpec)
          const specOrigins = replaySpecOrigins(parsed)
          if (specOrigins.some(o => !currentApproved.has(o))) {
            throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
          }
          const isStaticAst = parsed.kind === 'static_ast_proof'
          const asset = curRun.candidates.find(c => c.origin === parsed.origin && curRun.approved.includes(c.id))
            ?? (isStaticAst ? curRun.candidates.find(c => curRun.approved.includes(c.id)) : undefined)
          if (!asset) throw new BrokerDenied(`Primary finding origin ${parsed.origin} is not in approved scope.`)

          const validFactIds = chainFactIds.filter(fid =>
            this.storage.listFacts(curRun.id, { includeTainted: false, limit: 500 }).some(f => f.id === fid))
          const sourceOrigins = new Set<string>(
            isStaticAst
              ? [...specOrigins.filter(o => currentApproved.has(o))]
              : [...specOrigins, ...targetOrigins],
          )

          // Two-stage submission-time deduplication (§4.5B)
          const specDedupeFields = extractSpecDedupeFields(parsed)
          const existingRows = this.storage.db.select().from(findings).where(and(
            eq(findings.runId, curRun.id),
            eq(findings.goalRevision, curRun.goalRevision),
            eq(findings.findingKind, 'multi_step_chain'),
          )).all()
          const specMap = new Map(this.storage.listReplaySpecs(curRun.id).map(s => [s.id, s]))
          const existingRefs: ExistingFindingRef[] = existingRows.map(row => {
            const existingSpec = row.replaySpecId ? specMap.get(row.replaySpecId)?.spec : undefined
            const existingFields = existingSpec ? extractSpecDedupeFields(existingSpec) : undefined
            return {
              id: row.id,
              origin: row.finding.origin,
              title: row.finding.title,
              status: row.finding.status,
              cwe: row.finding.cwe,
              category: row.finding.category,
              severity: row.finding.severity,
              endpoint: existingFields?.endpoint ?? null,
              authState: existingFields?.authState ?? null,
              specKind: existingFields?.specKind ?? null,
              method: existingFields?.method ?? null,
              param: existingFields?.param ?? null,
              graphqlField: existingFields?.graphqlField ?? null,
              mutated: existingFields?.mutated ?? null,
              reason: row.finding.reason,
              impact: row.finding.impact,
              remediation: row.finding.remediation,
              sourceOrigins: row.sourceOrigins,
              fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash ?? null,
            }
          })

          const dedupeLlmCall = profiles.length
            ? createProviderLlmCall(profiles, {
                signal: job.controller.signal,
                secrets: currentSecrets(),
                onUsage: u => this.storage.recordLlmSpend(curRun.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
              })
            : undefined
          const dedupeDecision = await evaluateSubmissionDedupe({
            candidate: {
              origin: parsed.origin,
              title: parsed.title,
              cwe: parsed.cwe,
              category: parsed.category,
              severity: parsed.severity,
              endpoint: specDedupeFields.endpoint,
              authState: specDedupeFields.authState,
              specKind: specDedupeFields.specKind,
              method: specDedupeFields.method,
              param: specDedupeFields.param,
              graphqlField: specDedupeFields.graphqlField,
              mutated: specDedupeFields.mutated ?? null,
              reason: parsed.severityRationale,
              impact: parsed.impact,
              remediation: parsed.remediation,
              sourceOrigins: [...sourceOrigins],
            },
            existingFindings: existingRefs,
            llmCall: dedupeLlmCall,
          })

          const matchedRow = dedupeDecision.duplicateOfId
            ? existingRows.find(r => r.id === dedupeDecision.duplicateOfId)
            : undefined

          if (dedupeDecision.action === 'reject_duplicate' && matchedRow) {
            return {
              findingId: matchedRow.id,
              replaySpecId: matchedRow.replaySpecId,
              status: matchedRow.finding.status,
              deduplicated: true,
              rejected: true,
              stage: dedupeDecision.stage,
              rationale: dedupeDecision.rationale,
              instruction: dedupeDecision.instruction ??
                `Duplicate of existing finding ${matchedRow.id}. Use update_proposed_finding(findingId="${matchedRow.id}") if your replay spec proves higher impact or adds new chain steps.`,
            }
          }

          const dbDupRow = this.storage.findDuplicateChainFinding(curRun.id, curRun.goalRevision, {
            origin: parsed.origin,
            cwe: parsed.cwe,
            category: parsed.category,
            title: parsed.title,
            fingerprintHash: dedupeDecision.fingerprintHash,
            endpoint: specDedupeFields.endpoint,
            method: specDedupeFields.method,
            param: specDedupeFields.param,
            graphqlField: specDedupeFields.graphqlField,
          })
          const matchedCandidates = [matchedRow, dbDupRow].filter(
            (row, idx, arr): row is NonNullable<typeof row> =>
              Boolean(row) && arr.findIndex(other => other?.id === row!.id) === idx,
          )
          const verifiedMatch = matchedCandidates.find(
            r => r.finding.status === 'confirmed' || r.finding.status === 'static_verified',
          )

          // Preserve Zero-LLM invariant: if upgrading/merging into an already-confirmed finding, keep confirmed severity
          // until a new replay spec independently verifies higher impact.
          if (verifiedMatch) {
            const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
              `Additional corroborating spec · ${parsed.title}`,
              JSON.stringify({ existingFindingId: verifiedMatch.id, dedupeStage: dedupeDecision.stage, spec: parsed }, null, 2),
              undefined, currentSecrets())
            const merged = this.storage.upsertChainFinding(
              curRun,
              verifiedMatch.assetId,
              {
                ...verifiedMatch.finding,
                severity: verifiedMatch.finding.severity,
                fingerprintHash: verifiedMatch.fingerprintHash ?? dedupeDecision.fingerprintHash,
                counterevidence: ext.counterevidence ?? verifiedMatch.counterevidence ?? verifiedMatch.finding.counterevidence,
                confidenceRationale: ext.confidenceRationale ?? verifiedMatch.confidenceRationale ?? verifiedMatch.finding.confidenceRationale,
                severityChangeConditions: ext.severityChangeConditions ?? verifiedMatch.severityChangeConditions ?? verifiedMatch.finding.severityChangeConditions,
                ...(ext.codeLocations?.length ? { codeLocations: ext.codeLocations } : {}),
                chainFactIds: [...new Set([...(verifiedMatch.finding.chainFactIds ?? []), ...validFactIds])],
                exchangeIds: [...new Set([...(verifiedMatch.finding.exchangeIds ?? []), ...exchangeIds])],
                evidenceIds: [...new Set([...verifiedMatch.finding.evidenceIds, ev.id])],
                scopeRevision: curRun.scopeRevision,
              },
              verifiedMatch.replaySpecId ?? verifiedMatch.finding.replaySpecId ?? '',
              [...sourceOrigins],
            )
            return {
              findingId: merged.id,
              replaySpecId: merged.replaySpecId,
              status: merged.status,
              deduplicated: true,
              stage: dedupeDecision.stage,
              note: `Merged corroborating evidence into existing verified finding ${merged.id}. Call update_proposed_finding if you need to replace its Replay Spec.`,
            }
          }

          const canonicalMatchedRow = matchedRow ?? dbDupRow
          const maxAttempts = 1 + maxInlineVerifyRetries
          const priorMaxAttempts = canonicalMatchedRow
            ? Math.max(
                0,
                ...matchedCandidates.flatMap(r =>
                  this.storage.listReplaySpecsForFinding(curRun.id, r.id).map(s => s.attemptCount),
                ),
              )
            : 0
          if (canonicalMatchedRow && priorMaxAttempts >= maxAttempts) {
            return {
              findingId: canonicalMatchedRow.id,
              replaySpecId: canonicalMatchedRow.replaySpecId,
              status: canonicalMatchedRow.finding.status,
              ...(canonicalMatchedRow.verificationTier ? { verificationTier: canonicalMatchedRow.verificationTier } : {}),
              severity: canonicalMatchedRow.finding.severity,
              deduplicated: true,
              rejected: true,
              isError: true,
              inlineVerifyFeedback: {
                verdict: 'inconclusive',
                controlPassed: false,
                assertionSummary: {
                  observed: 'retry_limit_exceeded',
                  expected: `<= ${maxAttempts} verification attempts`,
                  reason: `Inline verification retry limit reached for existing finding ${canonicalMatchedRow.id} (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                },
                stepStatuses: [],
                retriesRemaining: 0,
              } satisfies InlineVerifyFeedback,
            }
          }

          const codeLocations: CodeLocation[] | undefined = ext.codeLocations?.length
            ? ext.codeLocations
            : isStaticAst
              ? [{
                  repo: parsed.repo,
                  file: parsed.file,
                  startLine: parsed.startLine,
                  endLine: parsed.endLine,
                  label: parsed.sourceToSinkTrace?.slice(0, 180),
                }]
              : undefined

          const findingId = canonicalMatchedRow?.id ?? randomUUID()
          const verifyNow = args.verifyNow ?? true
          const specRow = this.storage.createReplaySpec(
            curRun,
            job.assignment,
            findingId,
            parsed,
            [...sourceOrigins],
            { initialAttemptCount: canonicalMatchedRow ? priorMaxAttempts : 0 },
          )
          boardTools.noteEvidence()
          const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
            `Proposed replay spec · ${parsed.title}`,
            JSON.stringify({ replaySpecId: specRow.id, specSha256: specRow.specSha256, spec: parsed }, null, 2),
            undefined, currentSecrets())
          const chainTags = step.skills.filter(skill => skill.startsWith('chain:')).map(skill => skill.slice('chain:'.length))
          const finding: Finding = {
            id: findingId,
            origin: parsed.origin,
            title: parsed.title,
            status: 'pending',
            severity: parsed.severity,
            reason: parsed.severityRationale,
            remediation: parsed.remediation,
            impact: parsed.impact,
            recheck: parsed.recheckInstructions,
            category: parsed.category,
            cwe: parsed.cwe,
            confidence: 'medium',
            verification: `Pending Zero-LLM ${parsed.kind} replay verification (spec ${specRow.id}).${chainTags.length ? ` Chain primitives: ${chainTags.join(', ')}.` : ''}`,
            findingKind: 'multi_step_chain',
            replaySpecId: specRow.id,
            fingerprintHash: dedupeDecision.fingerprintHash,
            counterevidence: ext.counterevidence ?? null,
            confidenceRationale: ext.confidenceRationale ?? null,
            severityChangeConditions: ext.severityChangeConditions ?? null,
            ...(isStaticAst ? { runtimeProofGap: parsed.runtimeProofGap } : {}),
            ...(codeLocations?.length ? { codeLocations } : {}),
            chainFactIds: validFactIds,
            exchangeIds: [...new Set(exchangeIds)],
            evidenceIds: [ev.id],
            scopeRevision: curRun.scopeRevision,
          }
          const savedFinding = this.storage.upsertChainFinding(curRun, asset.id, finding, specRow.id, [...sourceOrigins])
          for (const fid of validFactIds) {
            this.storage.addGraphEdge(curRun.id, { fromKind: 'fact', fromId: fid, toKind: 'finding', toId: savedFinding.id, edgeKind: 'proves' })
          }
          this.storage.addGraphEdge(curRun.id, { fromKind: 'assignment', fromId: job.assignment.id, toKind: 'finding', toId: savedFinding.id, edgeKind: 'proves' })
          this.schedulePlanner(curRun.id)

          if (verifyNow) {
            const inline = await this.executeInlineVerification({
              job,
              grant,
              currentSecrets,
              reposDir,
              spec: parsed,
              findingId: savedFinding.id,
              replaySpecId: specRow.id,
              onExchangeObserved: trackPersonaResources,
            })
            return {
              findingId: savedFinding.id,
              replaySpecId: inline.replaySpecId,
              status: inline.status,
              verificationTier: inline.verificationTier,
              inlineVerifyFeedback: inline.feedback,
              deduplicated: Boolean(canonicalMatchedRow),
              upgraded: dedupeDecision.action === 'upgrade_existing',
              note: inline.status === 'confirmed' || inline.status === 'static_verified'
                ? `Inline Zero-LLM verification succeeded (${inline.status}).`
                : `Inline Zero-LLM verification returned ${inline.status}. Inspect inlineVerifyFeedback and call verify_replay_spec or update_proposed_finding to repair (${inline.feedback.retriesRemaining} retries remaining).`,
            }
          }

          return {
            findingId: savedFinding.id,
            replaySpecId: specRow.id,
            status: savedFinding.status,
            deduplicated: Boolean(canonicalMatchedRow),
            upgraded: dedupeDecision.action === 'upgrade_existing',
            note: isStaticAst
              ? 'Candidate static_ast_proof queued for deterministic offline AST/SAST verification (can promote to static_verified only, never runtime confirmed).'
              : 'Candidate finding queued for Zero-LLM Declarative Replay Verification. Only deterministic replay can promote to confirmed.',
          }
        },

        update_proposed_finding: async (args) => {
          const curRun = this.check(job)
          const currentApproved = this.approvedOriginsSet(curRun)
          const existingRow = this.storage.db.select().from(findings).where(and(
            eq(findings.runId, curRun.id), eq(findings.id, args.findingId),
          )).get()
          if (!existingRow) throw new Error(`Finding ${args.findingId} not found in this run.`)

          const isAlreadyVerified = existingRow.finding.status === 'confirmed' || existingRow.finding.status === 'static_verified'
          let nextReplaySpecId = existingRow.replaySpecId ?? undefined
          let nextSourceOrigins = existingRow.sourceOrigins
          const extraEvidenceIds: string[] = []
          let parsedUpdatedSpec: DeclarativeReplaySpec | undefined
          let createdSpecRowId: string | undefined

          if (args.replaySpec) {
            const parsed = declarativeReplaySpecSchema.parse(args.replaySpec)
            const specOrigins = replaySpecOrigins(parsed)
            if (specOrigins.some(o => !currentApproved.has(o))) {
              throw new BrokerDenied('Updated replay spec references an origin outside current approved scope.')
            }
            parsedUpdatedSpec = parsed
            nextSourceOrigins = [...new Set([...existingRow.sourceOrigins, ...specOrigins])]
            const priorSpecs = this.storage.listReplaySpecsForFinding(curRun.id, existingRow.id)
            const priorMaxAttempts = priorSpecs.length ? Math.max(...priorSpecs.map(r => r.attemptCount)) : 0
            const maxAttempts = 1 + maxInlineVerifyRetries
            if (!isAlreadyVerified && priorMaxAttempts >= maxAttempts) {
              return {
                findingId: existingRow.id,
                replaySpecId: existingRow.replaySpecId,
                status: existingRow.finding.status,
                ...(existingRow.verificationTier ? { verificationTier: existingRow.verificationTier } : {}),
                severity: existingRow.finding.severity,
                inlineVerifyFeedback: {
                  verdict: 'inconclusive',
                  controlPassed: false,
                  assertionSummary: {
                    observed: 'retry_limit_exceeded',
                    expected: `<= ${maxAttempts} verification attempts`,
                    reason: `Inline verification retry limit reached (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                  },
                  stepStatuses: [],
                  retriesRemaining: 0,
                } satisfies InlineVerifyFeedback,
                updated: false,
                isError: true,
              }
            }
            const specRow = this.storage.createReplaySpec(
              curRun,
              job.assignment,
              existingRow.id,
              parsed,
              nextSourceOrigins,
              { initialAttemptCount: priorMaxAttempts },
            )
            createdSpecRowId = specRow.id
            boardTools.noteEvidence()
            const ev = this.storage.addArtifact(curRun, job.assignment, 'replay',
              `Updated replay spec · ${parsed.title}`,
              JSON.stringify({ findingId: existingRow.id, replaySpecId: specRow.id, specSha256: specRow.specSha256, spec: parsed }, null, 2),
              undefined, currentSecrets())
            extraEvidenceIds.push(ev.id)
            // Only replace active replaySpecId & reset to pending if not already verified;
            // verified findings keep their verified status/severity unless explicitly re-verified.
            if (!isAlreadyVerified) {
              nextReplaySpecId = specRow.id
            }
          }

          const updated = this.storage.updateProposedFinding(curRun, existingRow.id, {
            replaySpecId: nextReplaySpecId,
            sourceOrigins: nextSourceOrigins,
            ...(args.counterevidence !== undefined ? { counterevidence: args.counterevidence } : {}),
            ...(args.confidenceRationale !== undefined ? { confidenceRationale: args.confidenceRationale } : {}),
            ...(args.severityChangeConditions !== undefined ? { severityChangeConditions: args.severityChangeConditions } : {}),
            ...(args.codeLocations !== undefined ? { codeLocations: args.codeLocations } : {}),
            finding: {
              ...(args.title ? { title: args.title } : {}),
              ...(args.summary ? { reason: args.summary } : {}),
              // Zero-LLM invariant: never escalate severity of an already-confirmed finding without Replay Verification
              ...(!isAlreadyVerified && args.severity ? { severity: args.severity } : {}),
              ...(!isAlreadyVerified && args.replaySpec ? { status: 'pending' as const } : {}),
              ...(extraEvidenceIds.length ? { evidenceIds: extraEvidenceIds } : {}),
            },
          })

          const shouldVerifyNow = Boolean(parsedUpdatedSpec && (args.verifyNow ?? true) && !isAlreadyVerified)
          if (shouldVerifyNow && parsedUpdatedSpec) {
            const inline = await this.executeInlineVerification({
              job,
              grant,
              currentSecrets,
              reposDir,
              spec: parsedUpdatedSpec,
              findingId: existingRow.id,
              replaySpecId: createdSpecRowId ?? nextReplaySpecId,
              onExchangeObserved: trackPersonaResources,
            })
            return {
              findingId: updated.id,
              replaySpecId: inline.replaySpecId,
              status: inline.status,
              verificationTier: inline.verificationTier,
              severity: updated.severity,
              inlineVerifyFeedback: inline.feedback,
              updated: true,
            }
          }

          return {
            findingId: updated.id,
            replaySpecId: updated.replaySpecId,
            status: updated.status,
            severity: updated.severity,
            updated: true,
          }
        },

        verify_replay_spec: async (args) => {
          const spec = args.spec ?? args.replaySpec
          if (!spec) throw new Error('verify_replay_spec requires spec or replaySpec.')
          const inline = await this.executeInlineVerification({
            job,
            grant,
            currentSecrets,
            reposDir,
            spec,
            findingId: args.findingId,
            replaySpecId: args.replaySpecId,
            onExchangeObserved: trackPersonaResources,
          })
          return {
            findingId: inline.findingId ?? args.findingId ?? null,
            replaySpecId: inline.replaySpecId,
            status: inline.status,
            ...(inline.verificationTier ? { verificationTier: inline.verificationTier } : {}),
            inlineVerifyFeedback: inline.feedback,
          }
        },

        suggest_candidate_host: async ({ origin, source, thirdParty }) => {
          const curRun = this.check(job)
          const clean = this.parseOriginForRun(curRun, origin)
          return this.storage.suggestCandidateHost(curRun, clean, source, Boolean(thirdParty))
        },

        complete_intent: async (completion) => ({ recorded: true, status: completion.status }),
      }

      const personasPub = [...grant.personas?.values() ?? []].map(p => ({
        handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist,
      }))

      // F4/F2: never inject the full cross-persona queue (58 items / 53 KB) into every worker.
      // Only BOLA/IDOR-relevant assignments receive a bounded, relevance-ordered slice; the
      // remainder stays queryable through the worker tools.
      const bolaTestQueue = run.capabilityTier >= 2 && personasPub.length >= 2
        ? selectAssignmentBolaQueueItems({
            queue: buildBolaTestQueue(
              this.storage.listFacts(run.id, { includeTainted: false, limit: 200 }),
              personasPub,
              permittedAtAdmission,
              this.storage.listResourceSamples(run.id),
            ),
            targetOrigins,
            step: {
              title: step.title,
              hypothesis: step.hypothesis,
              category: step.category,
              skills: step.skills,
              specialistProfile: step.specialistProfile ?? null,
            },
          })
        : []

      const specialistProfileId = step.specialistProfile ?? routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      })
      const specialistConfig = resolveSpecialistProfile(specialistProfileId)
      const scopedHandlers = filterHandlersForSpecialist(handlers, specialistConfig)

      const techTags = this.storage.listFacts(run.id, { includeTainted: false, kind: 'tech_fingerprint', limit: 30 })
        .flatMap(f => {
          const tags = f.data?.tags
          return Array.isArray(tags) ? tags.filter((t): t is string => typeof t === 'string') : []
        })
      const sinkKind = parentFacts
        .map(f => (typeof f.data?.sinkKind === 'string' ? f.data.sinkKind : ''))
        .find(Boolean)
      const preInjectedSkills = selectPreInjectionSkills({
        profileSkills: specialistConfig.skills,
        techTags: [...new Set(techTags)],
        ...(sinkKind ? { sinkKind } : {}),
        category: step.category,
        title: step.title,
        hypothesis: step.hypothesis,
        limit: 2,
      })

      const confirmedRefs = this.alreadyConfirmedRefs(run)
      const unconfirmedHardSurface = this.unconfirmedHardSurfaceRefs(run, confirmedRefs)
      const detLeads = this.detLeadSummaries(run)
      const assignmentBrief = this.assignmentBriefForStep({
        run,
        step,
        targetOrigins,
        personas: personasPub,
        parentFacts,
        confirmed: confirmedRefs,
        detLeads,
        maxTurns: job.assignment.maxTurns,
      })
      const runTrace = this.ensureRunTrace(run, profiles)

      const sessionResult = await runAgentSession({
        directory: this.storage.directory,
        sessionId: job.assignment.sessionId,
        requestId: `investigate:${step.id}:attempt-${job.assignment.attempt}`,
        profiles: resolveProfilePoolForRole(specialistConfig.roleAffinity, profiles),
        scenario: 'worker-investigation',
        roleAffinity: specialistConfig.roleAffinity,
        prompt: workerInvestigationPrompt({
          goal: run.goal,
          step: {
            id: step.id, title: step.title, hypothesis: step.hypothesis,
            category: step.category, skills: [...new Set([...step.skills, ...specialistConfig.skills])],
            specialistProfile: specialistProfileId,
          },
          origins: targetOrigins,
          capabilityTier: run.capabilityTier,
          maxTurns: job.assignment.maxTurns,
          personas: personasPub,
          ...(bolaTestQueue.length ? { bolaTestQueue } : {}),
          parentFacts: parentFacts.map(f => ({
            id: f.id, kind: f.kind, origin: f.origin, summary: f.summary, data: f.data,
          })),
          specsSummary: stagedSpecs,
          mountedRepos,
          preInjectedSkills,
          alreadyConfirmed: confirmedRefs,
          unconfirmedHardSurface,
          detLeads,
          ...(assignmentBrief ? { assignmentBrief } : {}),
        }),
        signal: job.controller.signal,
        maxTurns: budget.maxTurns,
        wallClockMs: budget.wallClockMs,
        ...(runTrace ? {
          trace: runTrace,
          traceContext: {
            runId: run.id,
            assignmentId: job.assignment.id,
            specialistProfile: specialistProfileId,
          },
        } : {}),
        compaction: true,
        enableSettlement: true,
        requireCompleteIntent: true,
        shouldSettle: () => (Date.now() - startedAt) >= intentLeaseMs * 0.85,
        handlers: scopedHandlers,
        secrets,
        beforeCall: () => {
          this.check(job)
          if (this.storage.checkBudgetExceeded(run.id)) {
            throw new BudgetExceededError('Run spend or request budget exceeded.')
          }
        },
        onUsage: usage => {
          this.storage.recordLlmSpend(run.id, {
            usd: usage.costUsd,
            tokens: usage.inputTokens + usage.outputTokens,
          })
          this.boardAssignmentTokens.set(
            job.assignment.id,
            (this.boardAssignmentTokens.get(job.assignment.id) ?? 0) + usage.inputTokens + usage.outputTokens,
          )
          this.boardHandleTokens.set(
            boardHandle,
            (this.boardHandleTokens.get(boardHandle) ?? 0) + usage.inputTokens + usage.outputTokens,
          )
        },
        onTurn: turn => {
          recordTurnLatency()
          this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        onTurnStart: turn => {
          armStallTimer(turn)
          const member = this.storage.boardMember(run.id, boardHandle)
          const delta = this.boardTurnDelta(this.storage.run(run.id), boardHandle, member?.lastReadSeq ?? 0)
          if (!delta.text) return undefined
          return {
            messages: [turn === 1 ? injectBoardTurnInstructions('', delta.text) : delta.text],
          }
        },
        onProfileSuccess: id => recordProfileSuccess(id, this.storage),
        onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
      })

      const latestRun = this.check(job)
      const outcomeText = sessionResult.completion
        ? `[${sessionResult.completion.status}] ${sessionResult.completion.summary}`
        : sessionResult.answer
      this.storage.transaction(() => {
        this.completeWorker(job.assignment, latestRun, outcomeText, [], undefined, currentSecrets())
        this.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: job.assignment.id })
      }, { behavior: 'immediate' })
    } finally {
      clearStallTimer()
      generationStartedAt = undefined
      const wallMs = Math.max(0, Date.now() - startedAt)
      const walls = this.assignmentWallByRun.get(run.id) ?? []
      walls.push(wallMs)
      this.assignmentWallByRun.set(run.id, walls)
      if (this.storage.worker(job.assignment.id)?.status === 'complete') {
        const completed = this.completedAssignmentWallByRun.get(run.id) ?? []
        completed.push(wallMs)
        this.completedAssignmentWallByRun.set(run.id, completed)
      }
      const samples = this.turnLatencyByRun.get(run.id) ?? []
      samples.push(...turnLatencies)
      this.turnLatencyByRun.set(run.id, samples)
      await session.close().catch(() => undefined)
    }
  }

  // --- Phase 3: Zero-LLM Verification (Replay Specs + Baseline Checks) ---

  /**
   * v6 Phase 3/4: bounded pre-report drain of durable `pending_oob` subscriptions.
   *
   * A background worker can trigger an SSRF/XXE/webhook callback long after the HTTP response.
   * Finalizing the report as soon as verification workers settle dropped exactly those callbacks.
   * This waits up to `GUARDIAN_OOB_DRAIN_MS` (default 45 s), promotes late callbacks on every poll,
   * and records `oobDrainMs` / `promotedLate` in run-event meta. It never waits when nothing is
   * pending, so local-lab benchmark runs keep their zero-latency behavior.
   */
  /**
   * v7 Realism #2: a callback that lands after the synchronous probe/verification window still
   * confirms an async SSRF/XXE. The durable `pending_oob` promotion is host-observed evidence, so it
   * becomes a ProofReceipt validated against the recorded injection exchange and only then a
   * `runtime_confirmed` finding (never a model assertion).
   */
  private promoteReceiptOob(runId: string): number {
    let promotions: ReturnType<CanaryBroker['promoteLate']>
    try { promotions = this.canaryBroker.promoteLate({ runId }) } catch { return 0 }
    return this.convertOobPromotions(runId, promotions)
  }

  private convertOobPromotions(runId: string, promotions: ReturnType<CanaryBroker['promoteLate']>): number {
    if (promotions.length === 0) return 0
    let run: Run
    try { run = this.storage.run(runId) } catch { return 0 }
    if (run.status !== 'running') return 0
    const approved = this.approvedOriginsSet(run)
    let converted = 0
    for (const promotion of promotions) {
      const subscription = promotion.subscription
      let canary: typeof canaries.$inferSelect | undefined
      try {
        canary = this.storage.db.select().from(canaries).where(eq(canaries.id, subscription.canaryId)).get()
      } catch { canary = undefined }
      if (!canary) continue
      const classified = probeCanaryClass(canary.purpose)
      if (!classified) continue
      if (!approved.has(classified.origin)) continue
      // The exact request that carried the canary is the causal binding; a callback alone does not
      // prove that this target reached the listener.
      let carrier: ReturnType<Store['searchExchanges']>[number] | undefined
      try {
        carrier = this.storage.searchExchanges(runId, subscription.token, { approvedOrigins: approved, limit: 10 })
          .find(ex => [ex.pathAndQuery, ex.bodyPreview, JSON.stringify(ex.reqHeaders ?? {})]
            .some(text => String(text).includes(subscription.token)))
      } catch { carrier = undefined }
      if (!carrier) continue
      const receipt = buildOobReceipt({
        vulnClass: classified.vulnClass,
        origin: classified.origin,
        method: carrier.method,
        pathAndQuery: carrier.pathAndQuery,
        ...(classified.param ? { param: classified.param } : {}),
        exchangeIds: [carrier.id],
        oobEventId: subscription.id,
        claimedDelta: `The target fetched the injected ${classified.vulnClass.toUpperCase()} canary after its HTTP response (durable ${promotion.stage} callback).`,
      })
      const oobEvent: ReceiptOobEvent = {
        id: subscription.id,
        callbackId: promotion.callback.callbackId,
        canaryId: subscription.canaryId,
        token: subscription.token,
        targetOrigin: classified.origin,
        delivered: true,
        stage: promotion.stage,
        receivedAtMs: promotion.callback.receivedAt,
        latencyMs: promotion.latencyMs,
      }
      let body = carrier.bodyPreview
      try { body = this.storage.getExchange(runId, carrier.id).body } catch { /* preview is enough */ }
      const verification = verifyReceipt(receipt, {
        entries: [{
          exchangeId: carrier.id,
          step: {
            id: carrier.id,
            arm: 'probe',
            method: carrier.method,
            route: carrier.pathAndQuery.split('?')[0],
            pathAndQuery: carrier.pathAndQuery,
            status: carrier.status,
            actor: { handle: carrier.personaHandle, role: null, tenant: null, auth: 'unknown', sameSite: null },
            body,
            requestHeaders: carrier.reqHeaders ?? null,
            responseHeaders: carrier.respHeaders ?? null,
          },
          carrierText: `${carrier.pathAndQuery}\n${JSON.stringify(carrier.reqHeaders ?? {})}\n${body}`,
        }],
        oobEvents: [oobEvent],
      })
      if (!verification.confirmed) {
        try {
          this.storage.event(runId, 'oob.receipt_rejected', `OOB promotion for canary ${subscription.canaryId} did not verify: ${verification.reason}`, {
            canaryId: subscription.canaryId,
            subscriptionId: subscription.id,
            reason: verification.reason,
          })
        } catch { /* store closed */ }
        continue
      }
      try {
        if (this.persistReceiptFinding(run, {
          vulnClass: classified.vulnClass,
          origin: classified.origin,
          param: classified.param,
          carrier,
          receipt,
          verification,
          subscriptionId: subscription.id,
        })) converted += 1
      } catch { /* persistence is best-effort; never fail the drain */ }
    }
    return converted
  }

  private persistReceiptFinding(run: Run, input: {
    vulnClass: 'ssrf' | 'xxe'
    origin: string
    param: string | null
    carrier: ReturnType<Store['searchExchanges']>[number]
    receipt: ReturnType<typeof buildOobReceipt>
    verification: ReturnType<typeof verifyReceipt>
    subscriptionId: string
  }): boolean {
    const asset = run.candidates.find(candidate => candidate.origin === input.origin && run.approved.includes(candidate.id))
    if (!asset) return false
    const template = receiptFindingTemplate(input.vulnClass, input.origin, input.param)
    const rows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
    )).all()
    // One async callback per (origin, class) target: never let a repeated poll inflate findings.
    const duplicate = rows.find(row => row.finding.origin === input.origin &&
      row.finding.cwe === template.cwe &&
      (row.finding.status === 'confirmed' || row.finding.status === 'static_verified'))
    if (duplicate) return false

    const assignment = this.storage.workerList(run.id).find(worker => worker.id === input.carrier.assignmentId)
      ?? this.storage.workerList(run.id)[0]
    if (!assignment) return false
    const evidence = this.storage.addArtifact(
      run,
      assignment,
      'replay',
      `ProofReceipt · async ${input.vulnClass.toUpperCase()} · ${new URL(input.origin).hostname}`,
      JSON.stringify({
        receipt: input.receipt,
        verification: input.verification,
        carrierExchangeId: input.carrier.id,
        oobSubscriptionId: input.subscriptionId,
      }, null, 2),
      `receipt:oob:${input.subscriptionId}`,
      [],
    )

    // Prefer the replay spec whose probe carried this canary (it has the chain context), else keep
    // `replay_spec_id` null for a receipt-only finding.
    let specRow: ReplaySpecRow | undefined
    try {
      specRow = this.storage.listReplaySpecs(run.id).find(row => {
        const text = JSON.stringify(row.spec)
        return text.includes(input.subscriptionId) || text.includes(input.carrier.id)
      })
    } catch { specRow = undefined }
    const existing = specRow
      ? rows.find(row => row.id === specRow!.findingId)
      : rows.find(row => row.finding.origin === input.origin && row.finding.cwe === template.cwe && row.finding.status !== 'confirmed')
    const findingId = existing?.id ?? randomUUID()
    const finding: Finding = {
      ...(existing?.finding ?? {}),
      id: findingId,
      origin: input.origin,
      title: template.title,
      status: 'confirmed',
      severity: template.severity,
      reason: input.verification.reason,
      remediation: template.remediation,
      impact: template.impact,
      recheck: template.recheck,
      category: template.category,
      cwe: template.cwe,
      confidence: 'high',
      verification: `ProofReceipt ${input.receipt.oobEventIds[0]} · ${input.verification.rule} rule · ${input.verification.reason}`,
      verificationTier: 'runtime_confirmed',
      findingKind: 'multi_step_chain',
      replaySpecId: specRow?.id,
      exchangeIds: [...new Set([...(existing?.finding.exchangeIds ?? []), input.carrier.id])],
      evidenceIds: [...new Set([...(existing?.finding.evidenceIds ?? []), evidence.id])],
      scopeRevision: run.scopeRevision,
    }
    if (specRow) {
      this.storage.upsertChainFinding(run, asset.id, finding, specRow.id, specRow.sourceOrigins)
    } else if (existing) {
      this.storage.db.update(findings).set({
        verificationTier: 'runtime_confirmed',
        verificationClass: 'runtime_confirmed',
        finding,
      }).where(and(eq(findings.runId, run.id), eq(findings.id, findingId))).run()
    } else {
      this.storage.db.insert(findings).values({
        id: findingId,
        runId: run.id,
        assetId: asset.id,
        goalRevision: run.goalRevision,
        checkId: 'chain',
        caseId: findingId,
        findingKind: 'multi_step_chain',
        replaySpecId: null,
        sourceOrigins: [input.origin],
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        verificationClass: 'runtime_confirmed',
        finding,
      }).run()
    }
    try {
      this.storage.upsertCoverageEntry(run, assignment.id, {
        origin: input.origin,
        category: template.coverageCategory,
        status: 'reported',
        summary: `Confirmed async ${input.vulnClass.toUpperCase()} via ProofReceipt ${input.subscriptionId}`,
        linkedFindingId: findingId,
      })
      this.storage.event(run.id, 'oob.receipt_confirmed',
        `Late ${input.vulnClass.toUpperCase()} callback promoted to a runtime_confirmed finding (${input.verification.reason.slice(0, 200)}).`, {
          findingId,
          oobSubscriptionId: input.subscriptionId,
          exchangeId: input.carrier.id,
          rule: input.verification.rule,
        })
    } catch { /* metrics/coverage are best-effort */ }
    return true
  }

  async drainPendingOob(
    runOrId: Pick<Run, 'id'> | string,
    options: OobDrainOptions = {},
  ): Promise<OobDrainResult> {
    const runId = typeof runOrId === 'string' ? runOrId : runOrId.id
    // Convert already-delivered callbacks first: they may have landed while verification workers
    // were finishing, before this drain started. Callbacks that arrive during the bounded wait are
    // converted by the proxy as the shared drain promotes them (a promotion is claim-once, so a
    // post-drain call would never see them again).
    let promotedReceipts = this.promoteReceiptOob(runId)
    const convertingRelay = new Proxy(this.canaryBroker, {
      get: (target, prop, receiver) => {
        if (prop === 'promoteLate') {
          return (opts: { runId?: string; now?: number } = {}) => {
            const promotions = target.promoteLate(opts)
            try { promotedReceipts += this.convertOobPromotions(runId, promotions) } catch { /* best-effort */ }
            return promotions
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const result = await drainPendingOob(convertingRelay, runId, options)
    this.lastOobDrain.set(runId, result)
    try {
      this.storage.event(
        runId,
        'oob.drain_complete',
        `OOB drain finished in ${result.oobDrainMs} ms (${result.promotedLate} late callback(s) promoted, ${promotedReceipts} confirmed by ProofReceipt, ${result.remaining} still pending).`,
        { ...result, promotedReceipts },
      )
    } catch { /* store closed */ }
    return result
  }

  /** Read-only access to the last drain result (benchmark/test report meta). */
  getLastOobDrain(runId: string): { oobDrainMs: number; promotedLate: number; remaining: number } | null {
    return this.lastOobDrain.get(runId) ?? null
  }

  private scheduleFinalReport(run: Run): void {
    scheduleFinalReport({
      storage: this.storage,
      relay: this.canaryBroker,
      draining: this.verificationDraining,
      lastDrain: this.lastOobDrain,
      drain: runId => this.drainPendingOob(runId),
    }, run)
  }

  private advanceToVerification(run: Run) {
    // Never let Phase 3 start while the concurrent deterministic lane is still in flight: abort
    // and fast-settle first, then commit the phase transition exactly once.
    if (this.agenticLaneStopping.has(run.id)) return
    if (this.agenticLaneJobs.has(run.id)) {
      void this.abortAgenticLane(run, 'phase-2 complete').finally(() => this.commitVerificationPhase(run))
      return
    }
    this.commitVerificationPhase(run)
  }

  private commitVerificationPhase(run: Run) {
    this.storage.transaction(() => {
      const current = this.storage.run(run.id)
      if (current.status !== 'running' || current.phase !== 'investigation') return
      const approvedOrigins = this.approvedOriginsSet(current)
      const openProofGaps = this.storage.listOpenProofGaps(current.id, current.goalRevision)
        .filter(g => approvedOrigins.has(g.origin))
      if (openProofGaps.length > 0) {
        this.storage.event(current.id, 'proof_gaps.surfaced',
          `${openProofGaps.length} open proof ${openProofGaps.length === 1 ? 'gap remains' : 'gaps remain'} after investigation and will be reported transparently.`, {
            count: openProofGaps.length,
            gaps: openProofGaps.map(g => ({
              origin: g.origin,
              category: g.category,
              proofGapReason: g.proofGapReason || g.summary,
            })),
          })
      }
      this.storage.updateRun(current.id, { phase: 'verification' })
      this.storage.event(current.id, 'verification.started', 'Investigation complete. Starting Zero-LLM Replay Verification.')
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        `Investigation complete${openProofGaps.length ? ` (${openProofGaps.length} open proof ${openProofGaps.length === 1 ? 'gap' : 'gaps'} surfaced)` : ''}. Deterministic Zero-LLM verification is replaying every proposed finding and checking baselines.`)
    }, { behavior: 'immediate' })
    try {
      this.settleAgentRequestPhase(
        run.id,
        this.phaseTerminationReason.get(run.id) === 'agent_budget_exhausted'
          ? 'agent_budget_exhausted'
          : 'investigation_complete',
      )
    } catch { /* metrics are best-effort */ }
    try { this.recordFloorMetrics(run.id, 'phase3') } catch { /* metrics are best-effort */ }
    try { this.recordAssignmentMetrics(run.id, 'phase3') } catch { /* metrics are best-effort */ }
  }

  private driveVerification(run: Run) {
    const approvedOrigins = this.approvedOriginsSet(run)
    const workers = this.storage.workerList(run.id)
    const maxConc = Math.max(1, Math.min(maxWorkerConcurrency, run.workerConcurrency || defaultWorkerConcurrency))

    // 1. Ensure verification workers exist for every pending replay spec in current goalRevision
    const pendingFindings = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
      eq(findings.findingKind, 'multi_step_chain'),
    )).all().filter(f =>
      f.finding.status === 'pending' &&
      f.replaySpecId &&
      run.approved.includes(f.assetId) &&
      f.sourceOrigins.every(o => approvedOrigins.has(o)),
    )

    for (const row of pendingFindings) {
      const existing = workers.find(w => w.phase === 'verification' && w.stepId === row.replaySpecId && w.status !== 'canceled')
      if (!existing) {
        const asset = run.candidates.find(c => c.id === row.assetId)
        this.storage.makeWorker(run, 'verification', asset,
          `Replay verify · ${row.finding.title.slice(0, 80)}`,
          `Zero-LLM deterministic replay verification of spec ${row.replaySpecId}.`, {
            stepId: row.replaySpecId,
            sourceOrigins: row.sourceOrigins,
          })
      }
    }

    // 2. Ensure baseline verification workers exist for every approved asset
    for (const asset of run.candidates.filter(c => run.approved.includes(c.id))) {
      const existing = workers.find(w =>
        w.phase === 'verification' && w.assetId === asset.id && w.stepId === null &&
        w.goalRevision === run.goalRevision && w.status !== 'canceled')
      if (!existing) {
        const { analysis } = assessmentAssignments(workers, asset.id, run.goalRevision)
        this.storage.makeWorker(run, 'verification', asset,
          `Baseline verify · ${new URL(asset.origin).hostname}`,
          'Verify recorded baseline response and access policy evidence inside an air-gapped container.', {
            input: analysis?.status === 'complete' ? analysis : undefined,
            sourceOrigins: [asset.origin],
          })
      }
    }

    const updatedWorkers = this.storage.workerList(run.id).filter(w =>
      w.phase === 'verification' && w.goalRevision === run.goalRevision &&
      w.sourceOrigins.every(o => approvedOrigins.has(o)))
    const queued = updatedWorkers.filter(w => w.status === 'queued')
    const activeCount = [...this.active.values()].filter(j => j.assignment.runId === run.id).length

    if (!queued.length && updatedWorkers.every(w => w.status === 'complete' || w.status === 'canceled')) {
      // v6: never finalize while async OOB callbacks can still land. A bounded drain promotes late
      // callbacks (Fixture #2 delivers 15–30 s after the response) before the report is written.
      this.scheduleFinalReport(run)
      return
    }

    let slots = Math.max(0, maxConc - activeCount)
    for (const worker of queued) {
      if (slots <= 0) break
      if (this.active.has(worker.id)) continue
      this.startVerificationWorker(run, worker)
      slots -= 1
    }
  }

  private startVerificationWorker(run: Run, worker: Assignment) {
    const claimed = this.storage.transaction(() => {
      const w = this.storage.updateWorker(worker.id, {
        status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000, outcome: null,
      })
      this.storage.event(run.id, 'worker.started', worker.title + ' started.', { assignmentId: worker.id })
      return w
    })
    if (!claimed) return

    const job: Active = { assignment: claimed, origins: new Set(claimed.sourceOrigins), controller: new AbortController() }
    this.active.set(claimed.id, job)

    const work = claimed.stepId
      ? this.verifyReplaySpecJob(job, claimed.stepId)
      : this.verifyBaselineJob(job)

    void work.catch(error => {
      if (!this.authorize(job) || job.controller.signal.aborted) return
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
      this.storage.transaction(() => {
        this.storage.updateWorker(claimed.id, { status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null })
        this.storage.event(run.id, 'worker.failed', `Verification failed: ${msg}`, { assignmentId: claimed.id })
      })
    }).finally(() => {
      this.active.delete(claimed.id)
      this.scheduleWake()
    })
  }

  private async verifyReplaySpecJob(job: Active, replaySpecId: string) {
    const run = this.check(job)
    const specRow = this.storage.getReplaySpec(run.id, replaySpecId)
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, specRow.findingId),
    )).get()
    if (!findingRow) {
      this.completeWorker(job.assignment, run, 'Finding no longer exists.', [])
      return
    }

    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)
    const { reposDir } = this.projectReposMount(run.projectId)

    // Priority #5 / v3 Dual HTTP+DNS CanaryBroker: ensure listener is started when needed or configured
    if ((specRow.spec.kind === 'rce_proof' && specRow.spec.proofMode === 'oob_canary') || this.isCanaryListenerConfigured()) {
      await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
    }

    // Tier 3 HITL gate for rce_proof and upload_probe specs on non-local-lab targets
    if (specRow.spec.kind === 'rce_proof' || specRow.spec.kind === 'upload_probe') {
      const gateReq = specRow.spec.kind === 'rce_proof'
        ? {
            origin: specRow.spec.probeStep.request.origin,
            method: specRow.spec.probeStep.request.method,
            pathAndQuery: specRow.spec.probeStep.request.pathAndQuery,
            personaHandle: specRow.spec.probeStep.request.persona ?? null,
            rationale: `[rce_proof:${specRow.spec.proofMode}] Zero-LLM non-destructive PoE verification for "${specRow.spec.title}"`,
            requestPreview: JSON.stringify({
              proofMode: specRow.spec.proofMode,
              controlStep: specRow.spec.controlStep,
              probeStep: specRow.spec.probeStep,
            }, null, 2),
          }
        : {
            origin: specRow.spec.uploadStep.origin,
            method: specRow.spec.uploadStep.method,
            pathAndQuery: specRow.spec.uploadStep.pathAndQuery,
            personaHandle: specRow.spec.uploadStep.persona ?? null,
            rationale: `[upload_probe] Zero-LLM benign multipart upload verification for "${specRow.spec.title}"`,
            requestPreview: JSON.stringify({
              filename: specRow.spec.uploadStep.filename,
              contentType: specRow.spec.uploadStep.contentType,
              uploadStep: specRow.spec.uploadStep.pathAndQuery,
              fetchStep: specRow.spec.fetchStep.request.pathAndQuery,
            }, null, 2),
          }
      const approval = await this.waitForTier3Approval(job, {
        ...gateReq,
        bodyPreview: specRow.spec.kind === 'rce_proof'
          ? (specRow.spec.probeStep.request.textBody ??
              (specRow.spec.probeStep.request.jsonBody !== undefined
                ? JSON.stringify(specRow.spec.probeStep.request.jsonBody)
                : undefined))
          : specRow.spec.uploadStep.contentTemplate,
        hasMultipart: specRow.spec.kind === 'upload_probe',
        isRceProof: specRow.spec.kind === 'rce_proof',
        secrets,
      }, job.controller.signal)
      if (!approval.approved) {
        const current = this.check(job)
        const updatedFinding: Finding = {
          ...findingRow.finding,
          status: 'inconclusive',
          reason: approval.deniedReason
            ? `Tier 3 Safety Judge denied ${specRow.spec.kind} verification: ${approval.deniedReason}`
            : `Tier 3 approval for ${specRow.spec.kind} verification was denied or expired.`,
          confidence: 'low',
        }
        this.storage.upsertChainFinding(current, findingRow.assetId, updatedFinding, specRow.id, specRow.sourceOrigins)
        this.completeWorker(job.assignment, current, 'Inconclusive: Tier 3 approval denied.', [], undefined, secrets)
        return
      }
    }

    const verifyParams = {
      spec: specRow.spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir,
      grant,
      signal: job.controller.signal,
      storage: this.storage,
      runId: run.id,
      assignmentId: job.assignment.id,
      onExchange: (ex: BrokerExchangeResult) => {
        const saved = this.storage.recordExchange({
          runId: run.id,
          assignmentId: job.assignment.id,
          scopeRevision: run.scopeRevision,
          origin: ex.origin,
          finalOrigin: ex.finalOrigin,
          redirectOrigins: ex.redirectOrigins,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          personaHandle: ex.personaHandle,
          status: ex.status,
          mediaType: ex.mediaType,
          reqHeaders: ex.reqHeaders,
          respHeaders: ex.respHeaders,
          body: ex.body,
          durationMs: ex.durationMs,
          secretMatches: ex.secretMatches,
          secrets: currentSecrets(),
        })
        this.storage.trackExchangeResources({
          runId: run.id,
          scopeRevision: run.scopeRevision,
          exchange: ex,
          source: 'surface_probe',
        })
        this.markEndpointCoverage(run, ex.origin, ex.method, ex.pathAndQuery, `replay:${specRow.spec.kind}`)
        return saved.id
      },
    }
    const result = await verifyReplaySpec(verifyParams)
    this.markReplaySpecCoverage(run, specRow.spec, `replay:${specRow.spec.kind}`)
    if (result.receipt && !result.receipt.verification.confirmed) {
      // Parity telemetry only: shadow receipts never change this verdict.
      try {
        this.storage.event(run.id, 'proof_receipt.shadow_reject',
          `ProofReceipt did not substantiate spec ${specRow.id}: ${result.receipt.verification.reason}`.slice(0, 400), {
            replaySpecId: specRow.id,
            vulnClass: result.receipt.receipt.vulnClass,
            rule: result.receipt.verification.rule,
            mode: result.receipt.mode,
          })
      } catch { /* store closed */ }
    }

    const current = this.check(job)
    let phaseFeedback: InlineVerifyFeedback | undefined
    this.storage.transaction(() => {
      // Strict Tier Separation (Invariant #4): static_ast_proof NEVER promotes to 'confirmed' / 'runtime_confirmed'
      const staticSpec = specRow.spec.kind === 'static_ast_proof' ? specRow.spec : null
      const isStaticAst = staticSpec !== null
      const rawVerdict = result.verdict as Finding['status']
      const finalStatus: Finding['status'] = isStaticAst
        ? (rawVerdict === 'confirmed' || rawVerdict === 'static_verified' ? 'static_verified' : rawVerdict)
        : rawVerdict
      const verificationTier: VerificationTier | undefined = finalStatus === 'static_verified'
        ? 'static_verified'
        : finalStatus === 'confirmed'
          ? 'runtime_confirmed'
          : undefined

      const receipt = this.storage.addArtifact(current, job.assignment, 'replay',
        `${isStaticAst ? 'Deterministic Static AST' : 'Zero-LLM replay'} · ${specRow.spec.title}`,
        JSON.stringify({
          replaySpecId: specRow.id,
          specSha256: specRow.specSha256,
          kind: specRow.spec.kind,
          origin: specRow.spec.origin,
          verdict: finalStatus,
          verificationTier: verificationTier ?? null,
          outcome: result.outcome,
          exchangeIds: result.exchangeIds,
          sourceOrigins: specRow.sourceOrigins,
          evidenceSha256: result.evidenceSha256,
          evidencePayload: result.evidencePayload,
          receipt: result.receipt?.verification ?? null,
          receiptArtifact: result.receipt?.receipt ?? null,
        }, null, 2), 'replay:' + specRow.id, currentSecrets())

      const staticCodeLocations: CodeLocation[] | undefined = staticSpec
        ? [{
            repo: staticSpec.repo,
            file: staticSpec.file,
            startLine: staticSpec.startLine,
            endLine: staticSpec.endLine,
            label: staticSpec.sourceToSinkTrace?.slice(0, 180),
          }]
        : findingRow.finding.codeLocations

      const secretsList = currentSecrets()
      const cleanReason = redact(result.outcome.reason || result.outcome.observed || findingRow.finding.reason, secretsList)
      const cleanObserved = redact(result.outcome.observed, secretsList)
      const updatedFinding: Finding = {
        ...findingRow.finding,
        status: finalStatus,
        verificationTier,
        reason: cleanReason,
        confidence: (finalStatus === 'confirmed' || finalStatus === 'static_verified')
          ? 'high'
          : finalStatus === 'dismissed'
            ? 'medium'
            : 'low',
        verification: `${isStaticAst ? 'Deterministic offline static_ast_proof' : `Zero-LLM ${specRow.spec.kind} replay`} verdict: ${finalStatus} (controlPassed=${result.outcome.controlPassed}, observed: ${cleanObserved}).`,
        ...(staticSpec ? { runtimeProofGap: staticSpec.runtimeProofGap } : {}),
        ...(staticCodeLocations?.length ? { codeLocations: staticCodeLocations } : {}),
        evidenceIds: [...new Set([...findingRow.finding.evidenceIds, receipt.id])],
        exchangeIds: [...new Set([...(findingRow.finding.exchangeIds ?? []), ...result.exchangeIds])],
        scopeRevision: current.scopeRevision,
      }
      const rawFeedback = buildInlineVerifyFeedback(
        specRow.spec,
        result,
        Math.max(1, specRow.attemptCount),
        maxInlineVerifyRetries,
        currentSecrets(),
      )
      phaseFeedback = rawFeedback
      // Route every diff through the store: confirmation writes persist the confirming verdict
      // before the finding write, and a non-confirming retest demotes an already-confirmed claim
      // (and is counted) instead of leaving it contradicted by its own evidence.
      this.storage.recordReplaySpecVerification(
        current.id,
        specRow.id,
        rawFeedback,
        `phase3 ${specRow.spec.kind} attempt ${specRow.attemptCount} returned ${finalStatus}`,
      )
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.storage.upsertChainFinding(current, findingRow.assetId, alignFindingForEvidence(updatedFinding, result), specRow.id, specRow.sourceOrigins)
        if (owaspCategories.includes(specRow.spec.category as OwaspCategory) &&
            this.permitted(current, specRow.spec.origin)) {
          this.storage.upsertCoverageEntry(current, job.assignment.id, {
            origin: specRow.spec.origin,
            category: specRow.spec.category as OwaspCategory,
            status: 'reported',
            summary: `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${specRow.spec.title}`,
            linkedFindingId: findingRow.id,
          })
        }
        const refreshedRow = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, current.id), eq(findings.id, findingRow.id),
        )).get()
        if (refreshedRow) this.scheduleVariantSweepForFinding(current, refreshedRow)
      } else {
        this.storage.updateProposedFinding(current, findingRow.id, {
          verificationTier: null,
          finding: updatedFinding,
        })
      }
      this.completeWorker(
        job.assignment,
        current,
        `Replay verdict: ${finalStatus} (${cleanObserved.slice(0, 160)})`,
        [receipt.id],
        undefined,
        secretsList,
      )
    }, { behavior: 'immediate' })
    const refreshed = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, current.id), eq(findings.id, findingRow.id),
    )).get()
    if (refreshed) {
      this.postVerificationVerdict(current, {
        replaySpecId: specRow.id,
        findingId: refreshed.id,
        title: specRow.spec.title,
        status: refreshed.finding.status,
        verificationTier: refreshed.verificationTier ?? refreshed.finding.verificationTier ?? null,
        feedback: phaseFeedback ?? specRow.lastVerificationDiff ?? null,
        assignmentId: specRow.assignmentId,
        attempt: specRow.attemptCount,
      })
    }
  }

  private async executeInlineVerification(params: {
    job: Active
    grant: Grant
    currentSecrets: () => readonly NamedSecret[]
    reposDir?: string
    spec: DeclarativeReplaySpec
    findingId?: string
    replaySpecId?: string
    onExchangeObserved?: (curRun: Run, ex: BrokerExchangeResult, exchangeId: string) => void
  }): Promise<{
    findingId?: string
    replaySpecId: string
    attemptCount: number
    status: Finding['status']
    verificationTier?: VerificationTier
    feedback: InlineVerifyFeedback
    artifactId?: string
  }> {
    const curRun = this.check(params.job)
    if (this.storage.checkBudgetExceeded(curRun.id)) {
      throw new BudgetExceededError('Run spend or request budget exceeded.')
    }
    const parsed = declarativeReplaySpecSchema.parse(params.spec)
    const specOrigins = replaySpecOrigins(parsed)
    const currentApproved = this.approvedOriginsSet(curRun)
    if (specOrigins.some(o => !currentApproved.has(o))) {
      throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
    }

    const findingRow = params.findingId
      ? this.storage.db.select().from(findings).where(and(
          eq(findings.runId, curRun.id), eq(findings.id, params.findingId),
        )).get()
      : undefined
    const isAlreadyVerified = Boolean(
      findingRow && (findingRow.finding.status === 'confirmed' || findingRow.finding.status === 'static_verified'),
    )

    const standaloneKey = !params.findingId
      ? 'inline:' + params.job.assignment.id + ':' + createHash('sha256')
          .update(`${parsed.kind}|${parsed.origin}|${parsed.cwe}|${parsed.title.trim().toLowerCase()}`)
          .digest('hex').slice(0, 16)
      : undefined
    const trackingFindingId = findingRow?.id ?? params.findingId ?? standaloneKey!

    let specRow: ReplaySpecRow | undefined
    if (params.replaySpecId) {
      specRow = this.storage.getReplaySpec(curRun.id, params.replaySpecId)
    }
    const existingForFinding = this.storage.listReplaySpecsForFinding(curRun.id, trackingFindingId)
    if (!specRow) {
      specRow = existingForFinding[0]
    }
    if (!specRow) {
      specRow = this.storage.createReplaySpec(
        curRun,
        params.job.assignment,
        trackingFindingId,
        parsed,
        specOrigins.length ? specOrigins : [parsed.origin],
        { initialAttemptCount: 0 },
      )
    }

    const currentAttempts = Math.max(
      specRow.attemptCount,
      ...existingForFinding.map(r => r.attemptCount),
      0,
    )
    const nextAttempt = currentAttempts + 1
    const maxAttempts = 1 + maxInlineVerifyRetries

    if (nextAttempt <= maxAttempts) {
      if ((parsed.kind === 'rce_proof' && parsed.proofMode === 'oob_canary') || this.isCanaryListenerConfigured()) {
        await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
      }
      if (parsed.kind === 'rce_proof' || parsed.kind === 'upload_probe') {
        const gateReq = parsed.kind === 'rce_proof'
          ? {
              origin: parsed.probeStep.request.origin,
              method: parsed.probeStep.request.method,
              pathAndQuery: parsed.probeStep.request.pathAndQuery,
              personaHandle: parsed.probeStep.request.persona ?? null,
              rationale: `[rce_proof:${parsed.proofMode}] Inline Zero-LLM verification for "${parsed.title}"`,
              requestPreview: JSON.stringify({
                proofMode: parsed.proofMode,
                controlStep: parsed.controlStep,
                probeStep: parsed.probeStep,
              }, null, 2),
              bodyPreview: parsed.probeStep.request.textBody ??
                (parsed.probeStep.request.jsonBody !== undefined
                  ? JSON.stringify(parsed.probeStep.request.jsonBody)
                  : undefined),
              hasMultipart: false,
              isRceProof: true,
            }
          : {
              origin: parsed.uploadStep.origin,
              method: parsed.uploadStep.method,
              pathAndQuery: parsed.uploadStep.pathAndQuery,
              personaHandle: parsed.uploadStep.persona ?? null,
              rationale: `[upload_probe] Inline Zero-LLM verification for "${parsed.title}"`,
              requestPreview: JSON.stringify({
                filename: parsed.uploadStep.filename,
                contentType: parsed.uploadStep.contentType,
                uploadStep: parsed.uploadStep.pathAndQuery,
                fetchStep: parsed.fetchStep.request.pathAndQuery,
              }, null, 2),
              bodyPreview: parsed.uploadStep.contentTemplate,
              hasMultipart: true,
              isRceProof: false,
            }
        const approval = await this.waitForTier3Approval(params.job, {
          ...gateReq,
          secrets: params.currentSecrets(),
        }, params.job.controller.signal)
        if (!approval.approved) {
          const deniedReason = approval.deniedReason
            ? `Tier 3 Safety Judge denied ${parsed.kind} verification: ${approval.deniedReason}`
            : `Tier 3 approval for ${parsed.kind} verification was denied or expired.`
          const deniedFeedback = redactJsonValue({
            verdict: 'inconclusive',
            controlPassed: false,
            assertionSummary: {
              observed: 'tier3_approval_denied',
              expected: 'Tier 3 approval granted',
              reason: deniedReason,
            },
            stepStatuses: [],
            retriesRemaining: Math.max(0, maxAttempts - nextAttempt),
          } satisfies InlineVerifyFeedback, params.currentSecrets())
          const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, deniedFeedback, {
            spec: parsed,
            sourceOrigins: [...new Set([...specRow.sourceOrigins, ...specOrigins])],
            secrets: params.currentSecrets(),
          })
          if (findingRow && !isAlreadyVerified) {
            const latestRun = this.check(params.job)
            this.storage.updateProposedFinding(latestRun, findingRow.id, {
              replaySpecId: updatedSpec.id,
              verificationTier: null,
              finding: { status: 'inconclusive', verificationTier: undefined, reason: deniedReason, confidence: 'low' },
            })
          }
          const deniedRun = this.check(params.job)
          const deniedRow = findingRow
            ? this.storage.db.select().from(findings).where(and(
                eq(findings.runId, deniedRun.id), eq(findings.id, findingRow.id),
              )).get()
            : undefined
          return {
            findingId: findingRow?.id,
            replaySpecId: updatedSpec.id,
            attemptCount: updatedSpec.attemptCount,
            status: deniedRow?.finding.status ?? 'inconclusive',
            feedback: deniedFeedback,
          }
        }
      }
    }

    const { feedback, replay } = await verifyReplaySpecInline({
      spec: parsed,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir: params.reposDir,
      grant: params.grant,
      signal: params.job.controller.signal,
      storage: this.storage,
      runId: curRun.id,
      assignmentId: params.job.assignment.id,
      findingId: findingRow?.id,
      attemptCount: nextAttempt,
      maxRetries: maxInlineVerifyRetries,
      secrets: params.currentSecrets(),
      onExchange: ex => {
        const latest = this.check(params.job)
        const saved = this.storage.recordExchange({
          runId: latest.id,
          assignmentId: params.job.assignment.id,
          scopeRevision: latest.scopeRevision,
          origin: ex.origin,
          finalOrigin: ex.finalOrigin,
          redirectOrigins: ex.redirectOrigins,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          personaHandle: ex.personaHandle,
          status: ex.status,
          mediaType: ex.mediaType,
          reqHeaders: ex.reqHeaders,
          respHeaders: ex.respHeaders,
          body: ex.body,
          durationMs: ex.durationMs,
          secretMatches: ex.secretMatches,
          secrets: params.currentSecrets(),
        })
        this.storage.trackExchangeResources({
          runId: latest.id,
          scopeRevision: latest.scopeRevision,
          exchange: ex,
          source: 'surface_probe',
        })
        this.markEndpointCoverage(latest, ex.origin, ex.method, ex.pathAndQuery, `replay:${parsed.kind}`)
        params.onExchangeObserved?.(latest, ex, saved.id)
        return saved.id
      },
    })
    const latestForCoverage = this.check(params.job)
    this.markReplaySpecCoverage(latestForCoverage, parsed, `replay:${parsed.kind}`)

    if (nextAttempt > maxAttempts) {
      return {
        findingId: findingRow?.id,
        replaySpecId: specRow.id,
        attemptCount: currentAttempts,
        status: findingRow?.finding.status ?? 'inconclusive',
        verificationTier: findingRow?.verificationTier ?? undefined,
        feedback,
      }
    }

    const isStaticAst = parsed.kind === 'static_ast_proof'
    const rawVerdict = replay.verdict as Finding['status']
    const finalStatus: Finding['status'] = isStaticAst
      ? (rawVerdict === 'confirmed' || rawVerdict === 'static_verified' ? 'static_verified' : rawVerdict)
      : rawVerdict
    const verificationTier: VerificationTier | undefined = finalStatus === 'static_verified'
      ? 'static_verified'
      : finalStatus === 'confirmed'
        ? 'runtime_confirmed'
        : undefined
    const normalizedFeedback: InlineVerifyFeedback = {
      ...feedback,
      verdict: finalStatus as InlineVerifyFeedback['verdict'],
      ...(verificationTier ? { verificationTier } : {}),
    }

    const latestRun = this.check(params.job)
    const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, normalizedFeedback, {
      spec: parsed,
      sourceOrigins: [...new Set([...specRow.sourceOrigins, ...specOrigins])],
      secrets: params.currentSecrets(),
    })

    const receipt = this.storage.addArtifact(
      latestRun,
      params.job.assignment,
      'replay',
      `Inline ${isStaticAst ? 'Static AST' : 'Zero-LLM replay'} attempt #${updatedSpec.attemptCount} · ${parsed.title}`,
      JSON.stringify({
        replaySpecId: updatedSpec.id,
        attemptCount: updatedSpec.attemptCount,
        specSha256: updatedSpec.specSha256,
        kind: parsed.kind,
        origin: parsed.origin,
        verdict: finalStatus,
        verificationTier: verificationTier ?? null,
        outcome: replay.outcome,
        feedback: normalizedFeedback,
        exchangeIds: replay.exchangeIds,
        evidenceSha256: replay.evidenceSha256,
        evidencePayload: replay.evidencePayload,
        receipt: replay.receipt?.verification ?? null,
        receiptArtifact: replay.receipt?.receipt ?? null,
      }, null, 2),
      undefined,
      params.currentSecrets(),
    )

    if (findingRow && !isAlreadyVerified) {
      const staticCodeLocations: CodeLocation[] | undefined = parsed.kind === 'static_ast_proof'
        ? [{
            repo: parsed.repo,
            file: parsed.file,
            startLine: parsed.startLine,
            endLine: parsed.endLine,
            label: parsed.sourceToSinkTrace?.slice(0, 180),
          }]
        : findingRow.finding.codeLocations
      const mergedOrigins = [...new Set([...findingRow.sourceOrigins, ...specOrigins])]
      const secretsList = params.currentSecrets()
      const cleanReason = redact(replay.outcome.reason || replay.outcome.observed || findingRow.finding.reason, secretsList)
      const cleanObserved = redact(replay.outcome.observed, secretsList)
      const nextFindingPatch: Partial<Finding> = {
        status: finalStatus,
        verificationTier,
        reason: cleanReason,
        confidence: (finalStatus === 'confirmed' || finalStatus === 'static_verified')
          ? 'high'
          : finalStatus === 'dismissed'
            ? 'medium'
            : 'low',
        verification: `${isStaticAst ? 'Deterministic offline static_ast_proof' : `Zero-LLM ${parsed.kind} inline replay`} verdict: ${finalStatus} (controlPassed=${replay.outcome.controlPassed}, observed: ${cleanObserved}).`,
        ...(parsed.kind === 'static_ast_proof' ? { runtimeProofGap: parsed.runtimeProofGap } : {}),
        ...(staticCodeLocations?.length ? { codeLocations: staticCodeLocations } : {}),
        evidenceIds: [receipt.id],
        exchangeIds: replay.exchangeIds,
      }
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.storage.upsertChainFinding(
          latestRun,
          findingRow.assetId,
          alignFindingForEvidence(
            { ...findingRow.finding, ...nextFindingPatch, replaySpecId: updatedSpec.id, scopeRevision: latestRun.scopeRevision },
            replay,
          ),
          updatedSpec.id,
          mergedOrigins,
        )
        if (owaspCategories.includes(parsed.category as OwaspCategory) && this.permitted(latestRun, parsed.origin)) {
          this.storage.upsertCoverageEntry(latestRun, params.job.assignment.id, {
            origin: parsed.origin,
            category: parsed.category as OwaspCategory,
            status: 'reported',
            summary: `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${parsed.title}`,
            linkedFindingId: findingRow.id,
          })
        }
        // Multi-Trial Early Stopping: cancel sibling trials immediately on first Zero-LLM confirmation
        this.cancelSiblingTrialsOnConfirmation(latestRun, params.job.assignment.stepId, findingRow.id)
        const refreshedRow = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, latestRun.id), eq(findings.id, findingRow.id),
        )).get()
        if (refreshedRow) this.scheduleVariantSweepForFinding(latestRun, refreshedRow)
      } else {
        this.storage.updateProposedFinding(latestRun, findingRow.id, {
          replaySpecId: updatedSpec.id,
          sourceOrigins: mergedOrigins,
          verificationTier: null,
          finding: nextFindingPatch,
        })
      }
    }

    // The persisted row is the single source of truth: a non-confirming attempt may have just
    // demoted an already-confirmed finding (finding.confirmation_conflict). Never report the
    // pre-attempt status in that case.
    const verdictRun = this.storage.run(params.job.assignment.runId)
    const verdictRow = findingRow
      ? this.storage.db.select().from(findings).where(and(
          eq(findings.runId, verdictRun.id), eq(findings.id, findingRow.id),
        )).get()
      : undefined
    const verdictStatus = verdictRow?.finding.status ?? finalStatus
    const verdictTier = verdictRow?.verificationTier ?? (verdictStatus === 'confirmed' ? verificationTier : undefined)
    this.postVerificationVerdict(verdictRun, {
      replaySpecId: updatedSpec.id,
      findingId: findingRow?.id ?? params.findingId ?? null,
      title: parsed.title,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      assignmentId: specRow.assignmentId ?? params.job.assignment.id,
      refStepId: params.job.assignment.stepId,
      attempt: updatedSpec.attemptCount,
    })
    return {
      findingId: findingRow?.id,
      replaySpecId: updatedSpec.id,
      attemptCount: updatedSpec.attemptCount,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      artifactId: receipt.id,
    }
  }

  private async verifyBaselineJob(job: Active) {
    const run = this.check(job)
    const asset = run.candidates.find(c => c.id === job.assignment.assetId)
    if (!asset) {
      this.completeWorker(job.assignment, run, 'Host is no longer in run inventory.', [])
      return
    }
    const { analysis } = assessmentAssignments(this.storage.workerList(run.id), asset.id, run.goalRevision)
    const ready = analysis?.status === 'complete' ? analysis : undefined
    const selected: readonly AssessmentCheckId[] = run.reviewPlan?.status === 'ready' ? run.reviewPlan.checks : responseCheckIds
    const responseChecks = selected.filter(id => id !== 'access-policy') as ResponseCheckId[]
    const includesAccess = selected.includes('access-policy')

    const response: ReviewInput | undefined = responseChecks.length ? (() => {
      const stored = ready ? this.storage.assignmentObservation(ready.id) : undefined
      const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as Capture : undefined
      const origins = ready && record?.observation ? [...new Set([record.observation.origin, record.observation.finalOrigin, ...this.storage.brokerOrigins(ready)])] : []
      const authorized = origins.every(origin => this.permitted(run, origin))
      const observation = authorized ? record?.observation : null
      const note = authorized ? record?.note : 'The saved observation includes a host outside the current approval.'
      if (authorized) for (const origin of origins) job.origins.add(origin)
      return { artifactId: authorized ? stored?.id : undefined, reviews: responseReview(observation, note, responseChecks) }
    })() : undefined

    const access: ReviewInput | undefined = includesAccess ? (() => {
      const stored = ready ? this.storage.assignmentEvidence(ready.id, 'access-policy') : undefined
      const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as {
        origin: string; snapshot: AccessPolicySnapshot | null
      } : undefined
      const snapshot = record?.origin === asset.origin && record.snapshot?.origin === asset.origin ? record.snapshot : undefined
      return { artifactId: record?.origin === asset.origin ? stored?.id : undefined, reviews: accessPolicyReviews(snapshot), policy: snapshot }
    })() : undefined

    const inputs = [response, access].filter((i): i is ReviewInput => i !== undefined)
    const responseComparisons = response?.reviews.flatMap(r => r.comparison ? [r.comparison] : []) ?? []
    const accessComparisons = access?.reviews.flatMap(r => r.comparison ? [r.comparison] : []) ?? []
    const comparisons = [...responseComparisons, ...accessComparisons]
    const payload = { response: responseComparisons, access: access?.policy ?? null }
    const { reposDir } = this.projectReposMount(run.projectId)
    const result = comparisons.length ? await this.backend.run({
      assignmentId: job.assignment.id,
      files: [{ name: 'verification-input.json', content: JSON.stringify(payload) }],
      command: verificationCommand,
      outputs: ['verification.json'],
    }, job.controller.signal, reposDir ? { reposDir } : undefined) : undefined

    const outcomes = readComparisons(result?.exitCode === 0 ? result.outputs['verification.json'] : undefined, comparisons)
    const verified = inputs.flatMap(({ artifactId, reviews }) =>
      reviews.map(review => ({ artifactId, review, coverage: checkCoverage(review, outcomes) })))
    const checks = verified.map(item => item.coverage)
    const current = this.check(job)
    const assessed = checks.filter(check => check.status === 'met' || check.status === 'gap').length
    const gaps = checks.filter(check => check.status === 'gap').length
    const outcome = assessed
      ? `${assessed} checks verified · ${gaps === 1 ? '1 gap' : gaps + ' gaps'}`
      : 'Inconclusive: ' + (checks[0]?.reason ?? 'No checks evaluated.')

    this.storage.transaction(() => {
      const title = includesAccess ? (responseChecks.length ? 'Evidence verification' : 'Access policy verification') : 'Response policy verification'
      const ev = this.storage.addArtifact(current, job.assignment, 'verification', title,
        JSON.stringify({
          origin: asset.origin,
          inputEvidence: inputs.flatMap(i => i.artifactId ? [i.artifactId] : []),
          checks,
          comparisons,
          accessRecord: access?.artifactId,
          command: result ? verificationCommand : undefined,
          exitStatus: result?.exitCode,
          interpreter: result ? 'just-bash 3.6.1' : undefined,
        }, null, 2), 'verification')
      for (const { artifactId, review, coverage } of verified) {
        const links = artifactId ? [artifactId, ev.id] : [ev.id]
        const earlier = this.baselineFinding(current, asset, review)
        if (coverage.status === 'gap') this.saveBaselineFinding(current, asset, review, 'confirmed', coverage.reason, links, earlier?.id)
        else if (coverage.status === 'inconclusive' && (earlier || review.rule.id === 'hsts')) {
          this.saveBaselineFinding(current, asset, review, 'inconclusive', coverage.reason, links, earlier?.id)
        } else if (earlier) this.saveBaselineFinding(current, asset, review, 'dismissed', coverage.reason, links, earlier.id)
      }
      this.completeWorker(job.assignment, current, outcome, [ev.id], checks)
    }, { behavior: 'immediate' })
  }

  // --- One-Click Verify Fix Retest ---

  private startRetestWorker(run: Run, worker: Assignment) {
    const claimed = this.storage.transaction(() => {
      const w = this.storage.updateWorker(worker.id, {
        status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000, outcome: null,
      })
      this.storage.event(run.id, 'retest.started', worker.title + ' started.', { assignmentId: worker.id })
      return w
    })
    if (!claimed) return

    const job: Active = { assignment: claimed, origins: new Set(claimed.sourceOrigins), controller: new AbortController() }
    this.active.set(claimed.id, job)

    void this.runRetestJob(job).catch(error => {
      const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
      this.storage.updateWorker(claimed.id, { status: 'failed', outcome: msg, lease: null, leaseExpiresAt: null })
      this.storage.event(run.id, 'retest.failed', `Verify Fix retest failed: ${msg}`, { assignmentId: claimed.id })
    }).finally(() => {
      this.active.delete(claimed.id)
      this.scheduleWake()
    })
  }

  private async runRetestJob(job: Active) {
    const run = this.check(job)
    const findingId = job.assignment.stepId
    if (!findingId) throw new Error('Retest worker missing finding reference.')
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, findingId),
    )).get()
    if (!findingRow?.replaySpecId) throw new Error('Finding has no Declarative Replay Spec.')
    const specRow: ReplaySpecRow = this.storage.getReplaySpec(run.id, findingRow.replaySpecId)
    const permittedAtAdmission = this.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, permittedAtAdmission)

    if ((specRow.spec.kind === 'rce_proof' && specRow.spec.proofMode === 'oob_canary') || this.isCanaryListenerConfigured()) {
      await this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() }).catch(() => undefined)
    }

    const { reposDir } = this.projectReposMount(run.projectId)
    const retestRes = await retestReplaySpec({
      spec: specRow.spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir,
      grant,
      signal: job.controller.signal,
      storage: this.storage,
      runId: run.id,
      assignmentId: job.assignment.id,
      onExchange: ex => {
        const saved = this.storage.recordExchange({
          runId: run.id,
          assignmentId: job.assignment.id,
          scopeRevision: run.scopeRevision,
          origin: ex.origin,
          finalOrigin: ex.finalOrigin,
          redirectOrigins: ex.redirectOrigins,
          method: ex.method,
          pathAndQuery: ex.pathAndQuery,
          personaHandle: ex.personaHandle,
          status: ex.status,
          mediaType: ex.mediaType,
          reqHeaders: ex.reqHeaders,
          respHeaders: ex.respHeaders,
          body: ex.body,
          durationMs: ex.durationMs,
          secretMatches: ex.secretMatches,
          secrets: currentSecrets(),
        })
        return saved.id
      },
    })

    const current = this.storage.run(run.id)
    this.storage.transaction(() => {
      const secretsList = currentSecrets()
      const cleanObserved = redact(retestRes.replay.outcome.observed, secretsList)
      const ev = this.storage.addArtifact(current, job.assignment, 'replay',
        `Verify Fix retest · ${findingRow.finding.title}`,
        JSON.stringify({
          findingId,
          replaySpecId: specRow.id,
          verdict: retestRes.verdict,
          outcome: retestRes.replay.outcome,
          exchangeIds: retestRes.replay.exchangeIds,
          evidenceSha256: retestRes.replay.evidenceSha256,
        }, null, 2), 'retest:' + job.assignment.id, secretsList)
      const summary = `${retestRes.verdict}: ${cleanObserved}`
      this.storage.recordRetestRun(current, findingId, specRow.id, retestRes.verdict, summary, [ev.id], retestRes.replay.exchangeIds)
      this.completeWorker(job.assignment, current, `Verify Fix verdict: ${retestRes.verdict}`, [ev.id], undefined, secretsList)
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        `Verify Fix retest for "${findingRow.finding.title}": ${retestRes.verdict}. ${cleanObserved}`, undefined, undefined, secretsList)
    }, { behavior: 'immediate' })
  }

  // --- Coordinator Chat ---

  private startCoordinator(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (this.coordinator.has(run.id)) return
    const thread = this.storage.db.select().from(messages).where(and(
      eq(messages.runId, run.id), eq(messages.threadId, run.coordinatorId),
    )).orderBy(asc(messages.createdAt)).all()
    const answered = new Set(thread.map(item => item.replyTo))
    const next = thread.find(item => item.role === 'operator' && !answered.has(item.id) &&
      item.id !== run.reviewPlan?.goalMessageId && !item.content.startsWith('Steering hint:') &&
      this.shouldCoordinatorAnswer(item.content))
    if (!next) return
    this.resetBoardHops(run)

    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.coordinator.set(run.id, task)

    const detail = this.storage.runDetail(run.id)
    const history = workerHistory(run, detail.assignments)
    const currentWorkers = detail.assignments.filter(worker => !history.has(worker.id))
    const prompt = coordinatorPrompt({
      phase: run.phase,
      status: run.status,
      approved: run.approved.length,
      queued: currentWorkers.filter(w => w.status === 'queued').length,
      complete: currentWorkers.filter(w => w.status === 'complete').length,
      question: next.content,
      capabilityTier: run.capabilityTier,
      facts: detail.facts.filter(f => !f.tainted).length,
      confirmedFindings: detail.findings.filter(f => f.status === 'confirmed').length,
      pendingFindings: detail.findings.filter(f => f.status === 'pending').length,
      pendingApprovals: detail.approvals.filter(a => a.status === 'pending').length,
      spentUsd: run.spentUsd,
      budgetUsd: run.budgetUsd,
      spentRequests: run.spentRequests,
      budgetRequests: run.budgetRequests === 0 ? 'unlimited' : run.budgetRequests,
      turnsUsed: run.turnsUsed,
    })

    void agentTurn({
      directory: this.storage.directory,
      sessionId: run.coordinatorId,
      requestId: `${next.id}:${run.goalRevision}:${run.scopeRevision}`,
      profiles: resolveProfilePoolForRole('fast', profiles),
      scenario: 'coordinator',
      roleAffinity: 'fast',
      thinkingLevel: 'off',
      prompt,
      signal: controller.signal,
      onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      onProfileSuccess: id => recordProfileSuccess(id, this.storage),
      onProfileFailure: (id, err, hard) => recordProfileFailure(id, err, hard, this.storage),
    }).then(answer => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'coordinator', answer, next.id)
        this.storage.event(run.id, 'coordinator.reply', 'The coordinator replied.')
      })
    }).catch(() => {
      if (!this.currentCoordinator(run.id, task)) return
      this.storage.transaction(() => {
        this.storage.message(run.id, run.coordinatorId, 'guardian',
          'The coordinator could not reach the model. Review the workflow for current progress.', next.id)
        this.storage.event(run.id, 'coordinator.unavailable', 'The coordinator could not complete its reply.')
      })
    }).finally(() => {
      this.coordinator.delete(run.id)
    })
  }

  // --- On-Demand / Opt-In Air-Gapped Verified Patch Workflow (§4.6) ---

  async runPatchWorkflow(
    runId: string,
    findingId: string,
    repoOverride?: string,
    signal?: AbortSignal,
  ): Promise<PatchProposal> {
    const run = this.storage.run(runId)
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, findingId),
    )).get()
    if (!findingRow) throw new Error('Finding not found.')

    const hydratedFinding: Finding = {
      ...findingRow.finding,
      verificationTier: findingRow.verificationTier ?? findingRow.finding.verificationTier,
      codeLocations: findingRow.codeLocations ?? findingRow.finding.codeLocations,
    }
    if (hydratedFinding.status !== 'confirmed' && hydratedFinding.status !== 'static_verified') {
      throw new Error('Verified patch generation requires a confirmed or static_verified finding.')
    }

    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    if (!reposDir || !mountedRepos.length) {
      throw new Error('No mounted source repository found for this project. Sync a GitHub repo first.')
    }
    const repo = repoOverride?.trim() || hydratedFinding.codeLocations?.[0]?.repo || mountedRepos[0]
    const profiles = privateModelProfiles(this.storage)
    const personas = resolveRunPersonas(this.storage, run.projectId, run.approvedPersonaIds)
    const secrets = personaSecrets(personas)

    // Gate 6: when a local-lab target exists, rebuild the patched lab and replay the finding's spec.
    // A temporary `retest` assignment supplies the scoped grant (no interactive worker needed).
    let labRetest: Parameters<typeof generateAndReviewPatch>[0]['labRetest'] | undefined
    let retestWorkerId: string | null = null
    const labHandle = this.getLabTargetHandle(run.id)
    const findingSpecId = findingRow.replaySpecId ?? hydratedFinding.replaySpecId ?? null
    if (labHandle && findingSpecId) {
      try {
        const specRow = this.storage.getReplaySpec(run.id, findingSpecId)
        const approvedOrigins = this.approvedOriginsSet(run)
        if (specRow.sourceOrigins.every(o => approvedOrigins.has(o))) {
          const retestWorker = this.storage.makeWorker(
            run,
            'retest',
            run.candidates.find(c => c.id === findingRow.assetId),
            `Patch Gate 6 retest · ${hydratedFinding.title.slice(0, 70)}`,
            `Deterministic post-patch retest of replay spec ${specRow.id}.`,
            { stepId: findingRow.id, sourceOrigins: specRow.sourceOrigins },
          )
          const claimedRetest = this.storage.updateWorker(retestWorker.id, {
            status: 'running',
            lease: randomUUID(),
            leaseExpiresAt: Date.now() + 15 * 60_000,
          }) ?? retestWorker
          retestWorkerId = claimedRetest.id
          const retestJob: Active = { assignment: claimedRetest, origins: new Set(specRow.sourceOrigins), controller: new AbortController() }
          const { grant: retestGrant } = this.buildGrant(retestJob, run, approvedOrigins)
          const controlStep = specRow.spec.kind === 'http_chain'
            ? specRow.spec.steps.find(step => step.role === 'control') ?? specRow.spec.steps[0]
            : undefined
          labRetest = {
            labRunner: this.labRunner,
            runId: run.id,
            replaySpec: specRow.spec,
            broker: this.broker,
            browser: this.browser,
            canaryBroker: this.canaryBroker,
            backend: this.backend,
            grant: retestGrant,
            storage: this.storage,
            assignmentId: claimedRetest.id,
            ...(controlStep ? {
              baselineCaller: {
                origin: controlStep.request.origin,
                method: controlStep.request.method,
                pathAndQuery: controlStep.request.pathAndQuery,
                persona: controlStep.request.persona,
                ...(controlStep.request.headers ? { headers: controlStep.request.headers } : {}),
                ...(controlStep.request.jsonBody !== undefined ? { body: JSON.stringify(controlStep.request.jsonBody) } : {}),
              },
              baselineExpectStatus: [200, 201, 204],
            } : {}),
          }
        }
      } catch {
        // Gate 6 stays unverified when the spec/lab context cannot be resolved.
      }
    }

    let result: Awaited<ReturnType<typeof generateAndReviewPatch>>
    try {
      result = await generateAndReviewPatch({
        runId: run.id,
        finding: hydratedFinding,
        repo,
        reposDir,
        backend: this.backend,
        modelProfiles: profiles,
        signal,
        secrets,
        ...(labRetest ? { labRetest } : {}),
        onUsage: u => this.storage.recordLlmSpend(run.id, { usd: u.costUsd, tokens: u.inputTokens + u.outputTokens }),
      })
    } finally {
      if (retestWorkerId) {
        try {
          this.storage.updateWorker(retestWorkerId, { status: 'complete', outcome: 'Patch Gate 6 retest finished.', lease: null, leaseExpiresAt: null })
        } catch { /* run may be gone */ }
      }
    }

    const saved = this.storage.savePatchProposal({
      id: result.id,
      runId: run.id,
      findingId: hydratedFinding.id,
      repo: result.repo,
      status: result.status,
      callerCompatibility: result.callerCompatibility,
      diff: result.diff,
      codeLocations: result.codeLocations,
      reviewNotes: result.reviewNotes,
      dynamicRetestVerdict: result.dynamicRetestVerdict,
      secrets,
    })

    const anchorWorker = this.storage.workerList(run.id).at(-1)
    if (anchorWorker) {
      this.storage.addArtifact(
        run,
        anchorWorker,
        'patch',
        `Patch proposal (${saved.status}) · ${hydratedFinding.title.slice(0, 80)}`,
        JSON.stringify({
          patchId: saved.id,
          findingId: saved.findingId,
          repo: saved.repo,
          status: saved.status,
          callerCompatibility: saved.callerCompatibility,
          dynamicRetestVerdict: saved.dynamicRetestVerdict,
          gates: result.gates,
          reviewNotes: saved.reviewNotes,
          diff: saved.diff,
        }, null, 2),
        undefined,
        secrets,
      )
    }

    return saved
  }

  // --- Shared Helpers ---

  private baselineFinding(run: Run, asset: Candidate, review: EvidenceReview) {
    return this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.assetId, asset.id), eq(findings.goalRevision, run.goalRevision),
      eq(findings.checkId, review.rule.id), eq(findings.caseId, review.coverage.caseId ?? ''),
    )).get()
  }

  private saveBaselineFinding(
    run: Run,
    asset: Candidate,
    review: EvidenceReview,
    status: Finding['status'],
    reason: string,
    evidenceIds: string[],
    existingId?: string,
  ) {
    const { rule, coverage } = review
    const confirmed = status === 'confirmed'
    const record: Finding = {
      id: existingId ?? randomUUID(),
      origin: asset.origin,
      title: status === 'inconclusive' ? rule.title + ' could not be assessed' : rule.findingTitle,
      status,
      severity: confirmed ? rule.severity : 'informational',
      reason,
      remediation: confirmed ? rule.remediation : status === 'inconclusive'
        ? 'Supply a current record from the approved host and repeat the review.'
        : status === 'pending' ? 'Resume the run to verify the observation.' : 'Review the verification evidence.',
      impact: confirmed ? rule.impact : undefined,
      recheck: confirmed ? rule.recheck : undefined,
      category: rule.category,
      cwe: rule.cwe,
      confidence: confirmed ? 'high' : status === 'inconclusive' ? 'low' : 'medium',
      verification: confirmed ? rule.verification : undefined,
      verificationTier: confirmed ? 'baseline_confirmed' : undefined,
      findingKind: 'baseline_check',
      check: { id: rule.id, caseId: coverage.caseId, expected: coverage.expected, observed: coverage.observed },
      evidenceIds,
      scopeRevision: run.scopeRevision,
    }
    const verificationClass = confirmed
      ? 'runtime_confirmed'
      : status === 'dismissed'
        ? 'dismissed'
        : status === 'inconclusive' || status === 'pending'
          ? 'open_proof_gap'
          : 'static_advisory'
    const persistedRecord = {
      ...record,
      provenance: 'agent_only',
      verificationStatus: verificationClass,
    } as typeof record
    if (existingId) {
      this.storage.db.update(findings).set({
        verificationTier: confirmed ? 'baseline_confirmed' : null,
        verificationClass,
        finding: persistedRecord,
      }).where(eq(findings.id, record.id)).run()
    } else {
      this.storage.db.insert(findings).values({
        id: record.id,
        runId: run.id,
        assetId: asset.id,
        goalRevision: run.goalRevision,
        checkId: rule.id,
        caseId: coverage.caseId ?? '',
        findingKind: 'baseline_check',
        replaySpecId: null,
        sourceOrigins: [asset.origin],
        verificationTier: confirmed ? 'baseline_confirmed' : null,
        provenance: 'agent_only',
        verificationClass,
        finding: persistedRecord,
      }).run()
    }
  }

  private completeWorker(
    worker: Assignment,
    run: Run,
    summary: string,
    artifactIds: string[],
    checks?: CheckCoverage[],
    secrets: readonly NamedSecret[] = [],
  ) {
    const outcome = redact(summary, secrets)
    const result = this.storage.addArtifact(run, worker, 'handoff', 'result.md', [
      '# Result', '', outcome, '', 'Evidence: ' + artifactIds.join(', '),
    ].join('\n'), 'result', secrets)
    this.storage.updateWorker(worker.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome, checks })
    this.disposeWorkerSessions(worker.id)
    this.storage.message(run.id, worker.id, 'worker', outcome, undefined, [...artifactIds, result.id], secrets)
    this.storage.event(run.id, 'worker.complete', worker.title + ' completed.', {
      assignmentId: worker.id, artifactId: artifactIds[0] ?? result.id,
    })
  }
}

let instance: Execution | undefined
export function execution() {
  return instance ??= new Execution(store())
}
