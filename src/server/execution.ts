import { randomUUID } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { and, asc, eq } from 'drizzle-orm'
import {
  assetOriginForEnvironment,
  defaultWorkerConcurrency,
  isLocalLabEnvEnabled,
  maxInlineVerifyRetries,
  maxWorkerConcurrency,
  responseCheckIds,
  workerHistory,
  type AssessmentCheckId,
  type CheckCoverage,
  type CodeLocation,
  type Finding,
  type ResponseCheckId,
  type ThreatModelSummary,
} from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins, type DeclarativeReplaySpec } from '../replay-spec.ts'
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
import {
  AGENTIC_SPECIALIST_MAX_TURNS,
  AGENTIC_SPECIALIST_WALL_CLOCK_MS,
  agentTurn,
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
  summarizeGuardianVerifyOutcome,
  threatModelPrompt,
  WarmSpecialistController,
  workerInvestigationPrompt,
  type AlreadyConfirmedRef,
  type DetLeadSummary,
  type GapValidationEvent,
  type GuardianVerifyArgs,
  type GuardianVerifyRuntime,
  type ProofObligationEvent,
  type RequestHttpArgs,
  type RequestHttpRaceArgs,
  type UnconfirmedSurfaceRef,
  type WorkerToolHandlers,
} from './agent-session.ts'
import { createAgentTraceFromEnv, type AgentTrace } from './agent-trace.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  assertAssignmentBriefSize,
  buildAssignmentBrief,
  type MissionKind,
} from './assignment-brief.ts'
import {
  BrokerApprovalRequired,
  BrokerCircuitOpen,
  BrokerDenied,
  RequestBroker,
  websocketResultToExchange,
  type BrokerExchangeResult,
  type BrokerHttpRequest,
  type BrokerRaceBurstResult,
  type Grant,
  type PublicObservation,
} from './broker.ts'
import { CanaryBroker, scanSecondOrderMarkers, type SecondOrderStore } from './canary-broker.ts'
import { hasCuratedAdvisory, queryCves, templateIdsForCves } from './cve-broker.ts'
import {
  createProviderLlmCall,
  evaluateSubmissionDedupe,
  extractSpecDedupeFields,
  normalizeEndpointTemplate,
} from './dedupe.ts'
import {
  cleanupStagedEntities,
  extractCreatedId,
  stagingProbeTag,
  tagStagingEntityBody,
} from './deterministic-engine.ts'
import { meetsBaseline } from './evidence-checks.ts'
import {
  buildExistingFindingRefs,
  createExchangeRecorder,
  recordBrokerExchange,
  retryLimitExceededFeedback,
  type ExecActiveJob,
  type ExecCapture,
  type ExecCoordinatorTask,
  type ExecReviewInput,
} from './exec-exchange.ts'
import { DETERMINISTIC_PARAM_HINT_RE, ExecFloorLane } from './exec-floor-lane.ts'
import { ExecVerifier } from './exec-verify.ts'
export { agentProofAttribution, probeCanaryClass } from './exec-verify.ts'
import { listMountedRepos, parseDependenciesFromFile, projectReposDir } from './github-connector.ts'
import {
  createGraphCoordinator,
  type CoordinatorDeps,
  type CoordinatorEndpoint,
  type CoordinatorProgramGraph,
  type DispatchPlan,
  type GraphCoordinator,
} from './graph-coordinator.ts'
export { decideNext } from './graph-coordinator.ts'
import { seedCodeToRuntimeLeads as seedGraphLeads } from './graph-leads.ts'
import { LabRunner, type LabTargetHandle } from './lab-runner.ts'
import {
  privateModelProfiles,
  recordProfileFailure,
  recordProfileSuccess,
  resolveProfilePoolForRole,
  type ResolvedModelProfile,
} from './model-settings.ts'
import { drainPendingOob, scheduleFinalReport, type OobDrainOptions, type OobDrainResult } from './oob-drain.ts'
import { generateAndReviewPatch } from './patch-workflow.ts'
import { PersonaAuthManager, type PersonaSessionClone } from './persona-auth.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import { crawlStateGraph, runPhase0Recon } from './phase0-recon.ts'
import { ProbePlanRegistry, selectRankedProbeTargets, type Phase0GraphwireExtras, type Phase0ProbePlanSummary } from './probe-plan.ts'
import type { CodeDataflowSlice, CodeToRuntimeHypothesis } from './program-graph.ts'
import { resolveProfileNoTokenWatchdogMs } from './provider-stream.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, type NamedSecret } from './redact.ts'
import { buildInlineVerifyFeedback, runAgentScriptProof } from './replay-verifier.ts'
import { responseReview } from './response-checks.ts'
import { availableReviewChecks, parseReviewPlan, reviewPlanPrompt, standardChecks } from './review-plan.ts'
import { approvalRequests, findings, messages } from './schema.ts'
import { tenantTagForRun } from './scope-policy.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { runThreeStageSemanticAudit, runVariantSweepForFinding, toChainStepInputs } from './semantic-audit.ts'
import { cloneWorkerPersona } from './session-isolation.ts'
import {
  assessmentAssignments,
  store,
  type Assignment,
  type BoardMessageRow,
  type ChainStep,
  type Fact,
  type PatchProposal,
  type Run,
  type Store,
} from './store.ts'
import { probeDifferential, probeSurface, runSafeTemplates, type DifferentialProbeClass } from './surface-engine.ts'
import {
  consumeBurstInstance,
  planTier3ApprovalTargets,
  registerStateChangeGrant,
} from './tier3-approval.ts'
import { LinuxWorkerBackend, type WorkerBackend } from './worker-backend.ts'
export { DEFAULT_OOB_DRAIN_MS, OOB_DRAIN_POLL_MS, resolveOobDrainMs } from './oob-drain.ts'
export { selectRankedProbeTargets, type Phase0GraphwireExtras, type Phase0ProbePlanSummary } from './probe-plan.ts'
export { extractResourceRefsFromExchange as extractPersonaResourcesFromExchange } from './store.ts'
import {
  hardChainStepsCeiling,
  diminishingReturnsDryThreshold,
  plannerDebounceMs,
  intentLeaseMs,
  deterministicFloorWallClockShare,
  deterministicLaneMaxWallClockMs,
  deterministicLaneWallClockShare,
  resolvePhaseRequestBudgets,
  resolveFloorLaneMode,
  collectAllPages,
  coordinatorSchedulerDecision,
  chainHypothesisDispatchSteps,
  coordinatorPlannerHandlers,
  computeDynamicStepBudget,
  STRANDED_READY_STOP_REASONS,
  DISPATCH_FUNNEL_COUNT_KEYS,
  addFunnelCounts,
  emptyDispatchFunnel,
  permanentlyBlockedStepIds,
  dispatchableReadySteps,
  planMultiTrialExpansion,
  passOneCoverage,
  evaluateDispatchStop,
  circuitBreakAction,
  DET_LEAD_STEP_PRIORITY,
  DET_LEAD_CONCURRENT_CAP,
  TIER_A_STEP_PRIORITY,
  TIER_A_MAX_SEEDED_STEPS,
  DRY_ROUND_LIMIT,
  reinvestigationKey,
  ReinvestigationGuard,
  detLeadUnlocksReinvestigation,
  detLeadEvidenceGate,
  isDetLeadDispatchStep,
  planRoundRobinDispatch,
  selectUncoveredHighRiskEndpoints,
  extractAssignedTargetRoutes,
  selectAssignmentBolaQueueItems,
  countConsecutiveDrySteps,
  threatModelResponseSchema,
  plannerResponseSchema,
  stripJsonFences,
  computeHostTiers,
  computeStepMaxTurns,
  isMultiStepAssignment,
  PROVIDER_STALL_TURN_MS,
  ProviderNoTokenWatchdog,
  secretGenerationFingerprint,
  singleStepWallClockMs,
  planAssignmentBudget,
  percentile,
  summarizeTurnLatencies,
  providerStallAbortMs,
  shouldRetryStalledAssignment,
  requeueInterruptedAssignments,
  applyCrownJewelStepBudget,
  convertCodeAuditSuspectsToChainSteps,
  buildBolaTestQueue,
  classifyHostHeuristic,
  compactChainTitle,
  compactText,
  hostTierOrder,
  templatesMentionedInText,
  detLeadCategory,
  confirmedCategoryFamily,
  detLeadSkills,
  type DeterministicSweepMode,
  type PhaseRequestBudgets,
  type DispatchStopReason,
  type DispatchFunnelCounts,
  type AssignmentBudget,
  type AssignmentThroughputMetrics,
  type BolaTestQueueItem,
} from './exec-dispatch.ts'
export * from './exec-dispatch.ts'
import { ExecBoardManager } from './exec-board.ts'

type Active = ExecActiveJob
type Capture = ExecCapture
type ReviewInput = ExecReviewInput
type CoordinatorTask = ExecCoordinatorTask

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
  /** Turns saved by earned early exits (`agent.early_exit`) in this run. */
  private readonly earlyExitTurnsSavedByRun = new Map<string, number>()
  private readonly proofObligationByRun = new Map<string, {
    probedRoutes: number
    coveredRoutes: number
    gapRoutes: number
    demandedRoutes: number
    dischargedByGap: number
  }>()
  private readonly gapValidationByRun = new Map<string, {
    accepted: number
    rejected: number
    byCode: Record<string, { accepted: number; rejected: number }>
  }>()
  private readonly providerStallTurnsByRun = new Map<string, number>()
  private readonly providerStallRetriesByRun = new Map<string, number>()
  private readonly providerStallTimeoutsByRun = new Map<string, number>()
  private readonly providerStallWallSavedByRun = new Map<string, number>()
  private readonly warmSecretEpochByRun = new Map<string, string>()
  private readonly warmPoolPolicyRotationsByRun = new Map<string, number>()
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
  /** Tier-A Program-Graph facts/steps: seeded first, exempt from the generic lead cap. */
  private readonly tierAFactIds = new Set<string>()
  private readonly tierAStepIds = new Set<string>()
  private readonly tierAStepKeys = new Set<string>()
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
  private readonly board: ExecBoardManager
  private readonly floorLane: ExecFloorLane
  private readonly verifier: ExecVerifier
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
    this.board = new ExecBoardManager({
      storage: this.storage,
      warm: this.warm,
      boardHandleByAssignment: this.boardHandleByAssignment,
      approvedOriginsSet: run => this.approvedOriginsSet(run),
      scheduleWake: () => this.scheduleWake(),
    })
    this.floorLane = new ExecFloorLane({
      storage: this.storage,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      probePlans: this.probePlans,
      stagingTaggedMutations: this.stagingTaggedMutations,
      stagingUntaggedSkipped: this.stagingUntaggedSkipped,
      stagingCleaned: this.stagingCleaned,
      stagingCreatedEntities: this.stagingCreatedEntities,
      approvedOriginsSet: run => this.approvedOriginsSet(run),
      permitted: (run, origin) => this.permitted(run, origin),
      buildGrant: (job, run, permitted) => this.buildGrant(job, run, permitted),
      beginFloorRequestPhase: run => this.beginFloorRequestPhase(run),
      phaseRequestRemaining: run => this.phaseRequestRemaining(run),
      markEndpointCoverage: (run, o, m, p, c) => this.markEndpointCoverage(run, o, m, p, c),
      scanSecondOrderExchange: (run, assignmentId, ex, id) => this.scanSecondOrderExchange(run, assignmentId, ex, id),
      createConfirmedReplaySpec: (run, assignment, findingId, spec, origins, result, secrets) =>
        this.storage.createReplaySpec(run, assignment, findingId, spec, origins, {
          verifiedInline: true,
          lastVerificationDiff: buildInlineVerifyFeedback(spec, result, 1, maxInlineVerifyRetries, secrets),
        }),
    })
    this.verifier = new ExecVerifier({
      storage: this.storage,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      approvedOriginsSet: run => this.approvedOriginsSet(run),
      permitted: (run, origin) => this.permitted(run, origin),
      check: job => this.check(job),
      buildGrant: (job, run, permitted) => this.buildGrant(job, run, permitted),
      projectReposMount: projectId => this.projectReposMount(projectId),
      isCanaryDnsConfigured: () => this.isCanaryDnsConfigured(),
      isCanaryListenerConfigured: () => this.isCanaryListenerConfigured(),
      markEndpointCoverage: (run, o, m, p, c) => this.markEndpointCoverage(run, o, m, p, c),
      markReplaySpecCoverage: (run, spec, c) => this.markReplaySpecCoverage(run, spec, c),
      waitForTier3Approval: (job, input, signal) => this.waitForTier3Approval(job, input, signal),
      postVerificationVerdict: (run, opts) => this.postVerificationVerdict(run, opts),
      cancelSiblingTrialsOnConfirmation: (run, stepId, findingId) => this.cancelSiblingTrialsOnConfirmation(run, stepId, findingId),
      scheduleVariantSweepForFinding: (run, row) => this.scheduleVariantSweepForFinding(run, row),
      completeWorker: (w, r, o, e, c, s) => this.completeWorker(w, r, o, e, c, s),
      recordSpecVerification: (runId, specId, feedback, summary) =>
        this.storage.recordReplaySpecVerification(runId, specId, feedback, summary),
      resolveInlineVerdictRow: (runId, findingRow) => {
        const verdictRow = findingRow
          ? this.storage.db.select().from(findings).where(and(eq(findings.runId, runId), eq(findings.id, findingRow.id))).get()
          : undefined
        return verdictRow
      },
    })
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
    // No idle warm container may outlive the run: a 29 GB host cannot accumulate one pool per
    // benchmark cell. Sessions still finishing release into the closed pool and remove themselves.
    try { await this.backend.closeWarmPool?.() } catch { /* teardown is best-effort */ }
    for (const [assignmentId, tracked] of this.workerSessionClones) {
      for (const entry of tracked) entry.clone.dispose()
      this.workerSessionClones.delete(assignmentId)
    }
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
      [...resolvedPersonas.entries()].map(([handle, persona]) => {
        const cloned = cloneWorkerPersona(persona, job.assignment.id, (h, wid) => this.personaAuth.cloneSession(h, wid))
        if (!cloned) return [handle, persona] as const
        const tracked = this.workerSessionClones.get(job.assignment.id) ?? []
        tracked.push({ handle: cloned.persona.handle, clone: cloned.clone })
        this.workerSessionClones.set(job.assignment.id, tracked)
        return [handle, cloned.persona] as const
      }),
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
        if (context && consumeBurstInstance(this.burstApprovalInstances, {
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

  // --- v5 M5 Swarm Board wiring (delegated to ExecBoardManager) ----------------

  private shouldCoordinatorAnswer(content: string): boolean { return this.board.shouldCoordinatorAnswer(content) }
  private boardHandleForAssignmentId(run: Run, assignmentId: string): string { return this.board.boardHandleForAssignmentId(run, assignmentId) }
  private allocateBoardHandle(run: Run, profile: NonNullable<ChainStep['specialistProfile']>, step: ChainStep): string { return this.board.allocateBoardHandle(run, profile, step) }
  private postCoordinatorBrief(run: Run, step: ChainStep, handle: string, origins: readonly string[]): BoardMessageRow | null { return this.board.postCoordinatorBrief(run, step, handle, origins) }
  private postVerificationVerdict(run: Run, opts: Parameters<ExecBoardManager['postVerificationVerdict']>[1]): BoardMessageRow | null { return this.board.postVerificationVerdict(run, opts) }
  private postBrokerBlocker(run: Run, origin: string, status?: number): BoardMessageRow | null { return this.board.postBrokerBlocker(run, origin, status) }
  private postApprovalCard(run: Run, assignmentId: string, input: Parameters<ExecBoardManager['postApprovalCard']>[2], secrets: readonly NamedSecret[] = []): BoardMessageRow | null { return this.board.postApprovalCard(run, assignmentId, input, secrets) }
  private postApprovalResolution(run: Run, assignmentId: string, input: Parameters<ExecBoardManager['postApprovalResolution']>[2]): void { this.board.postApprovalResolution(run, assignmentId, input) }
  private postCanaryLead(run: Run, input: Parameters<ExecBoardManager['postCanaryLead']>[1]): BoardMessageRow | null { return this.board.postCanaryLead(run, input) }
  private boardTurnDelta(run: Run, handle: string, lastReadSeq: number): { text: string; cursor: number } { return this.board.boardTurnDelta(run, handle, lastReadSeq) }
  private resetBoardHops(run: Run): void { this.board.resetBoardHops(run) }
  private syncBoardRoster(run: Run): void { this.board.syncBoardRoster(run) }
  private routeOperatorBoardMessages(run: Run): void { this.board.routeOperatorBoardMessages(run) }
  private wakeBoardMember(run: Run, handle: string, message: BoardMessageRow): ChainStep | null { return this.board.wakeBoardMember(run, handle, message) }
  private finishBoardMember(run: Run, assignmentId: string): void { this.board.finishBoardMember(run, assignmentId) }

  // --- Deterministic floor lane delegators (ExecFloorLane) ---------------------
  private deriveDeterministicRouteTargets(...a: Parameters<ExecFloorLane['deriveDeterministicRouteTargets']>) { return this.floorLane.deriveDeterministicRouteTargets(...a) }
  private runDeterministicInvestigation(...a: Parameters<ExecFloorLane['runDeterministicInvestigation']>) { return this.floorLane.runDeterministicInvestigation(...a) }
  private runEngineInvestigation(...a: Parameters<ExecFloorLane['runEngineInvestigation']>) { return this.floorLane.runEngineInvestigation(...a) }
  private persistDeterministicConfirmed(...a: Parameters<ExecFloorLane['persistDeterministicConfirmed']>) { return this.floorLane.persistDeterministicConfirmed(...a) }
  private persistDeterministicLead(...a: Parameters<ExecFloorLane['persistDeterministicLead']>) { return this.floorLane.persistDeterministicLead(...a) }

  // --- Verification & receipt delegators (ExecVerifier) ------------------------
  private promoteReceiptOob(...a: Parameters<ExecVerifier['promoteReceiptOob']>) { return this.verifier.promoteReceiptOob(...a) }
  private convertOobPromotions(...a: Parameters<ExecVerifier['convertOobPromotions']>) { return this.verifier.convertOobPromotions(...a) }
  private persistReceiptFinding(...a: Parameters<ExecVerifier['persistReceiptFinding']>) { return this.verifier.persistReceiptFinding(...a) }
  private verifyReplaySpecJob(...a: Parameters<ExecVerifier['verifyReplaySpecJob']>) { return this.verifier.verifyReplaySpecJob(...a) }
  private backendSupportsVerifyScript() { return this.verifier.backendSupportsVerifyScript() }
  private readAgentProofScript(...a: Parameters<ExecVerifier['readAgentProofScript']>) { return this.verifier.readAgentProofScript(...a) }
  private persistAgentScriptProof(...a: Parameters<ExecVerifier['persistAgentScriptProof']>) { return this.verifier.persistAgentScriptProof(...a) }
  private executeInlineVerification(...a: Parameters<ExecVerifier['executeInlineVerification']>) { return this.verifier.executeInlineVerification(...a) }
  private verifyBaselineJob(...a: Parameters<ExecVerifier['verifyBaselineJob']>) { return this.verifier.verifyBaselineJob(...a) }
  private runRetestJob(...a: Parameters<ExecVerifier['runRetestJob']>) { return this.verifier.runRetestJob(...a) }
  private baselineFinding(...a: Parameters<ExecVerifier['baselineFinding']>) { return this.verifier.baselineFinding(...a) }
  private saveBaselineFinding(...a: Parameters<ExecVerifier['saveBaselineFinding']>) { return this.verifier.saveBaselineFinding(...a) }

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

  private planTier3Approval(
    run: Run,
    requests: Parameters<typeof planTier3ApprovalTargets>[1],
    options: Parameters<typeof planTier3ApprovalTargets>[2] = {},
  ) {
    return planTier3ApprovalTargets(run, requests, options)
  }

  private async executeApprovedBrokerGroup<T>(
    job: Active,
    requests: BrokerHttpRequest[],
    signal: AbortSignal,
    options: {
      isRaceBurst: boolean
      rationale: string
      requestPreview: string
      denyLabel: string
      secrets: readonly NamedSecret[]
      execute: () => Promise<T>
    },
  ): Promise<T> {
    const run = this.check(job)
    if (options.isRaceBurst) {
      const phaseRemaining = this.phaseRequestRemaining(run)
      if (phaseRemaining !== null && requests.length > phaseRemaining) {
        throw new BudgetExceededError('Race burst would exceed the agent request budget.')
      }
    }
    const approvalPlan = planTier3ApprovalTargets(run, requests, { isRaceBurst: options.isRaceBurst })
    try {
      return await options.execute()
    } catch (err) {
      if (!(err instanceof BrokerApprovalRequired)) throw err
      const approval = await this.waitForTier3Approval(job, {
        origin: approvalPlan.primary.origin,
        method: approvalPlan.primary.method,
        pathAndQuery: approvalPlan.primary.pathAndQuery,
        personaHandle: approvalPlan.primary.personaHandle,
        rationale: options.rationale,
        requestPreview: options.requestPreview,
        bodyPreview: approvalPlan.primary.bodyPreview,
        bodyHash: approvalPlan.primary.bodyHash,
        headers: approvalPlan.primary.headers,
        hasMultipart: approvalPlan.primary.hasMultipart,
        ...(options.isRaceBurst ? { isRaceBurst: true } : {}),
        approvalInstances: approvalPlan.primary.approvalInstances,
        additionalApprovalTargets: approvalPlan.additional,
        secrets: options.secrets,
      }, signal)
      if (!approval.approved) {
        throw new BrokerDenied(
          approval.deniedReason
            ? `Tier 3 Safety Judge denied ${options.denyLabel} probe: ${approval.deniedReason}`
            : `Tier 3 ${options.denyLabel} request was denied or expired.`,
        )
      }
      return await options.execute()
    }
  }

  /** Execute a synchronized race burst, resolving the whole burst with one approval decision. */
  private executeApprovedRaceBurst(
    job: Active,
    requests: BrokerHttpRequest[],
    grant: Grant,
    signal: AbortSignal,
    options: {
      stepTitle: string
      rationale?: string
      secrets: readonly NamedSecret[]
      execute?: () => Promise<BrokerRaceBurstResult>
    },
  ): Promise<BrokerRaceBurstResult> {
    return this.executeApprovedBrokerGroup(job, requests, signal, {
      isRaceBurst: true,
      rationale: options.rationale ?? `Tier 3 concurrent race burst (${requests.length}x) during step "${options.stepTitle}"`,
      requestPreview: JSON.stringify({ count: requests.length, sample: requests[0] }, null, 2),
      denyLabel: 'race-burst',
      secrets: options.secrets,
      execute: options.execute ?? (() => this.broker.executeRaceBurst(requests, grant, signal)),
    })
  }

  /** Execute a synchronized batch, resolving the whole batch with one approval decision. */
  private executeApprovedBatch(
    job: Active,
    requests: BrokerHttpRequest[],
    grant: Grant,
    signal: AbortSignal,
    options: {
      stepTitle: string
      rationale?: string
      secrets: readonly NamedSecret[]
      execute?: () => Promise<BrokerExchangeResult[]>
    },
  ): Promise<BrokerExchangeResult[]> {
    return this.executeApprovedBrokerGroup(job, requests, signal, {
      isRaceBurst: false,
      rationale: options.rationale ?? `Tier 3 synchronized batch (${requests.length} requests) during step "${options.stepTitle}"`,
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
      denyLabel: 'batch',
      secrets: options.secrets,
      execute: options.execute ?? (() => this.broker.executeBatch(requests, grant, signal)),
    })
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
      registerStateChangeGrant(this.stateChangeApprovals, this.burstApprovalInstances, run, {
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
      registerStateChangeGrant(this.stateChangeApprovals, this.burstApprovalInstances, run, {
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
    this.board.syncTrackedRuns()

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
              return recordBrokerExchange(this.storage, freshRun, claimed.id, ex, secrets).id
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
              const savedEx = recordBrokerExchange(this.storage, freshRun, hostWorker.id, ex, secrets)
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

  private buildSharedSessionHandlers(
    job: Active,
    session: Awaited<ReturnType<WorkerBackend['openSession']>>,
    currentSecrets: () => readonly NamedSecret[],
    options: {
      offlineScriptLabel: string
      onFactRecorded?: (curRun: Run) => void
    },
  ) {
    return {
      spillOutput: async (id: string, content: string, sig: AbortSignal) => session.stage(`tool-output/${id}.txt`, content, sig),
      analyze_artifact: async (args: Parameters<NonNullable<WorkerToolHandlers['analyze_artifact']>>[0], sig: AbortSignal) => {
        this.check(job)
        const { tool, ...rest } = args
        return await session.analyze(tool, rest, sig)
      },
      run_sast_scan: async (args: Parameters<NonNullable<WorkerToolHandlers['run_sast_scan']>>[0], sig: AbortSignal) => {
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
      run_offline_script: async (args: Parameters<NonNullable<WorkerToolHandlers['run_offline_script']>>[0], sig: AbortSignal) => {
        const curRun = this.check(job)
        const res = await session.runScript(args, sig)
        const ev = this.storage.addArtifact(curRun, job.assignment, 'analysis',
          options.offlineScriptLabel.replace('{runtime}', args.runtime),
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
      query_cves: async (args: Parameters<NonNullable<WorkerToolHandlers['query_cves']>>[0], sig: AbortSignal) => {
        this.check(job)
        const advisories = await queryCves(args, sig)
        return { count: advisories.length, advisories }
      },
      load_skill: async ({ name }: { name: string }) => {
        if (name.trim().toLowerCase() === 'list') return { skills: listSkills() }
        const skill = loadSkill(name)
        if (!skill) return { error: `Unknown skill "${name}".`, available: listSkills().map(s => s.name) }
        return skill
      },
      search_facts: async ({ query, origin, kind, limit }: Parameters<NonNullable<WorkerToolHandlers['search_facts']>>[0]) => {
        const curRun = this.check(job)
        const currentApproved = this.approvedOriginsSet(curRun)
        return this.storage.listFacts(curRun.id, { includeTainted: false, query, origin, kind, limit })
          .filter(f => currentApproved.has(f.origin) && f.sourceOrigins.every(o => currentApproved.has(o)))
      },
      record_fact: async (args: Parameters<NonNullable<WorkerToolHandlers['record_fact']>>[0]) => {
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
        options.onFactRecorded?.(curRun)
        return { factId: fact.id, kind: args.kind, origin: fact.origin }
      },
      record_coverage: async (args: Parameters<NonNullable<WorkerToolHandlers['record_coverage']>>[0]) => {
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
      complete_intent: async (completion: Parameters<NonNullable<WorkerToolHandlers['complete_intent']>>[0]) => ({ recorded: true, status: completion.status }),
    } satisfies Partial<WorkerToolHandlers>
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
        ...this.buildSharedSessionHandlers(job, session, currentSecrets, {
          offlineScriptLabel: 'Offline {runtime} script (code audit)',
        }),
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
      // Tier-A leads are distinct hypotheses with their own Round-1 slot; duplicate trials would
      // displace other first-pass work.
      steps: steps.filter(step => !this.tierAStepIds.has(step.id)),
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

  // --- v6 split request budgets (Phase A floor / Phase B agents) ------------------------------

  private beginRequestPhase(run: Run, phase: 'floor' | 'agent'): PhaseRequestState | null {
    if (!this.phaseRequestBudgets) return null
    const existing = this.phaseRequestState.get(run.id)
    if (existing) return existing
    const state: PhaseRequestState = {
      floorBudget: this.phaseRequestBudgets.floor,
      agentBudget: this.phaseRequestBudgets.agent,
      baselineRequests: run.spentRequests,
      floorRequests: 0,
      floorSettled: phase === 'agent',
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
        phase === 'floor'
          ? `Phase A request allowance ${state.floorBudget}; Phase B allowance ${state.agentBudget} (split budgets; no borrowing).`
          : `Phase B request allowance ${state.agentBudget} (no Phase-A floor in this run).`,
        {
          phase,
          floorRequestBudget: state.floorBudget,
          agentRequestBudget: state.agentBudget,
          totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
          spentRequestsAtStart: state.baselineRequests,
        },
      )
    } catch { /* telemetry is best-effort */ }
    return state
  }

  private beginFloorRequestPhase(run: Run): PhaseRequestState | null {
    return this.beginRequestPhase(run, 'floor')
  }

  private beginAgentRequestPhase(run: Run): PhaseRequestState | null {
    return this.beginRequestPhase(run, 'agent')
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
      earlyExitTurnsSaved: this.earlyExitTurnsSavedByRun.get(runId) ?? 0,
      providerStallTurns: this.providerStallTurnsByRun.get(runId) ?? 0,
      providerStallRetries: this.providerStallRetriesByRun.get(runId) ?? 0,
      providerStallTimeouts: this.providerStallTimeoutsByRun.get(runId) ?? 0,
      providerStallWallSavedMs: this.providerStallWallSavedByRun.get(runId) ?? 0,
      turnLatencyP50: turnSummary.p50,
      turnLatencyP90: turnSummary.p90,
      containersLaunched: containers?.created ?? 0,
      containersReused: containers?.reused ?? 0,
      containerSessions: containers?.sessions ?? 0,
      coldContainerSessions: containers?.coldSessions ?? 0,
      idleWarmContainers: containers?.idle ?? 0,
      warmCapacity: containers?.capacity ?? 0,
      containerReuseHitRate: containers && containers.sessions > 0
        ? Math.round((containers.reused / containers.sessions) * 1000) / 1000
        : 0,
      warmPoolPolicyRotations: this.warmPoolPolicyRotationsByRun.get(runId) ?? 0,
      ...(this.proofObligationByRun.has(runId) ? { proofObligation: { ...this.proofObligationByRun.get(runId)! } } : {}),
      ...(this.gapValidationByRun.has(runId)
        ? {
            gapValidation: {
              accepted: this.gapValidationByRun.get(runId)!.accepted,
              rejected: this.gapValidationByRun.get(runId)!.rejected,
              byCode: Object.fromEntries(
                Object.entries(this.gapValidationByRun.get(runId)!.byCode).map(([k, v]) => [k, { ...v }]),
              ),
            },
          }
        : {}),
    }
    this.lastAssignmentMetrics.set(runId, metrics)
    try {
      this.storage.event(
        runId,
        'agentic.assignment_metrics',
        `Phase B throughput: ${metrics.assignmentsCompleted}/${metrics.assignmentsObserved} assignment(s) complete, p50 ${(metrics.assignmentWallP50 / 1000).toFixed(1)}s / p90 ${(metrics.assignmentWallP90 / 1000).toFixed(1)}s, ${metrics.turnsPerAssignment} turn(s)/assignment, ${metrics.providerStallTurns} stall turn(s) / ${metrics.providerStallRetries} bounded retry(ies) / ${metrics.providerStallTimeouts} no-token timeout(s) (${(metrics.providerStallWallSavedMs / 1000).toFixed(1)}s saved), ${metrics.containersLaunched} container launch(es) / ${metrics.containersReused} reuse(s) (${(metrics.containerReuseHitRate * 100).toFixed(0)}% hit rate, ${metrics.idleWarmContainers}/${metrics.warmCapacity} idle).`,
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

  /** Pass-1 coverage view used by the dry-round stop guard and the stop-time telemetry. */
  private passOneCoverageFor(run: Pick<Run, 'id'>, steps: readonly ChainStep[]): {
    uncoveredTierAEndpoints: string[]
    uninvestigatedFirstPassClasses: string[]
    tierAEndpoints: string[]
  } {
    const tierAEndpoints = [...new Set(this.tierALeadFacts(run).map(fact => {
      const method = typeof fact.data?.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      const endpoint = typeof fact.data?.endpoint === 'string' ? fact.data.endpoint : ''
      return `${method} ${endpoint}`
    }).filter(endpoint => endpoint.length > 0))].sort()
    const coverage = passOneCoverage({
      tierAEndpoints,
      steps: steps.map(step => {
        const routes = this.stepMentionedRoutes(step)
        return {
          id: step.id,
          dispatchable: step.status === 'ready' || step.status === 'pending',
          dispatched: step.assignedWorkerId !== null || step.status === 'complete' || step.status === 'running',
          routes,
          keys: routes.map(route => reinvestigationKey(route, step.category)),
        }
      }),
    })
    return { ...coverage, tierAEndpoints }
  }

  /**
   * Planner coverage assertion: before a dry/coordinator stop can terminate Phase B, ensure
   * discovered high-risk unconfirmed endpoints (`riskScore >= 60`) have at least one first-pass
   * investigation step queued (bounded to `min(6, remainingBudget)`).
   */
  private queueHighRiskCoverageSteps(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    dynamicStepBudget: number,
    existingSteps: readonly ChainStep[],
  ): { seeded: number; endpoints: string[] } {
    const remainingBudget = Math.max(0, dynamicStepBudget - existingSteps.length)
    const cap = Math.min(6, remainingBudget)
    if (cap <= 0) return { seeded: 0, endpoints: [] }
    let endpoints: Array<{
      origin: string
      method: string
      pathTemplate: string
      riskScore: number
      coveragePct?: number | null
      testedClasses?: string[] | null
    }> = []
    try {
      endpoints = this.storage.listEndpoints(run.id, { orderBy: 'risk', limit: 40 })
    } catch {
      return { seeded: 0, endpoints: [] }
    }
    const confirmedPaths = new Set(
      this.alreadyConfirmedRefs(run, 100).map(ref => normalizeEndpointTemplate(ref.path)),
    )
    const coveredRoutes = new Set<string>()
    for (const step of existingSteps) {
      for (const route of this.stepMentionedRoutes(step)) coveredRoutes.add(route)
    }
    const candidates = selectUncoveredHighRiskEndpoints({
      endpoints,
      approvedOrigins,
      confirmedPaths,
      coveredRoutes,
      minRisk: 60,
      limit: cap,
    })
    const seededEndpoints: string[] = []
    for (const ep of candidates) {
      const asset = run.candidates.find(candidate => candidate.origin === ep.origin && run.approved.includes(candidate.id))
      if (!asset) continue
      const method = (ep.method || 'GET').toUpperCase()
      const title = `High-risk route coverage · ${method} ${ep.pathTemplate}`
      const hypothesis = `Discovered high-risk endpoint ${method} ${ep.pathTemplate} on ${ep.origin} (risk ${ep.riskScore}, coverage ${ep.coveragePct ?? 0}%) has no first-pass investigation yet. Probe authorization boundaries, state invariants, and input validation with control vs. variant evidence; submit a verified proof or coded record_coverage gap.`
      const category = 'broken-access-control'
      const specialistProfile = routeStepToSpecialist({ title, hypothesis, category, skills: [] })
      this.storage.addChainStep(run, {
        title,
        hypothesis,
        category,
        priority: 70,
        targetAssetIds: [asset.id],
        skills: ['false-positive-elimination'],
        dependsOnFactIds: [],
        sourceOrigins: [ep.origin],
        specialistProfile,
      })
      seededEndpoints.push(`${method} ${ep.pathTemplate}`)
    }
    return { seeded: seededEndpoints.length, endpoints: seededEndpoints }
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
  /** Program-Graph code leads that carry a dataflow slice (Tier-A white-box hypotheses). */
  private tierALeadFacts(run: Pick<Run, 'id'>): Fact[] {
    return this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })
      .filter(fact => {
        const data = fact.data
        if (data?.kind !== 'det_lead' || data.source !== 'program_graph') return false
        const slice = data.codeSlice as { hops?: unknown } | undefined
        return Boolean(slice && Array.isArray(slice.hops) && slice.hops.length > 0)
      })
      .sort((a, b) => {
        const keyOf = (fact: typeof a) =>
          `${String(fact.data?.method ?? '')}\u0000${String(fact.data?.endpoint ?? '')}\u0000${fact.id}`
        return keyOf(a).localeCompare(keyOf(b))
      })
  }

  /**
   * Seed every Tier-A Program-Graph lead as a ready step before the planner's first round. These
   * are the white-box 4-hop hypotheses; they must never wait behind generic class/route steps or a
   * dry-round stop. Idempotent per (route, class), bounded by {@link TIER_A_MAX_SEEDED_STEPS}.
   */
  private queueTierALeadSteps(run: Run, approvedOrigins: ReadonlySet<string>, budget: number): number {
    const facts = this.tierALeadFacts(run)
    if (!facts.length) return 0
    const existing = this.storage.listChainSteps(run.id, run.goalRevision)
    const boundFactIds = new Set(existing.flatMap(step => step.dependsOnFactIds))
    let slots = Math.max(0, Math.min(TIER_A_MAX_SEEDED_STEPS, budget - existing.length))
    let created = 0
    for (const fact of facts) {
      if (slots <= 0) break
      this.tierAFactIds.add(fact.id)
      if (boundFactIds.has(fact.id)) continue
      if (!approvedOrigins.has(fact.origin)) continue
      const endpoint = typeof fact.data?.endpoint === 'string' ? fact.data.endpoint : ''
      const probeClass = typeof fact.data?.probeClass === 'string' ? fact.data.probeClass : ''
      const method = typeof fact.data?.method === 'string' ? fact.data.method.toUpperCase() : 'GET'
      if (!endpoint.startsWith('/') || !probeClass) continue
      const asset = run.candidates.find(c => c.origin === fact.origin && run.approved.includes(c.id))
      if (!asset) continue
      const category = detLeadCategory(probeClass)
      const routeKey = `${normalizeEndpointTemplate(endpoint)}|${confirmedCategoryFamily(category)}`
      const dedupeKey = `${method} ${routeKey}`
      if (this.tierAStepKeys.has(dedupeKey) || this.detLeadStepKeys.has(dedupeKey)) continue
      const reason = typeof fact.data.reason === 'string' ? fact.data.reason.slice(0, 200) : 'white-box dataflow slice'
      const skills = detLeadSkills(probeClass)
      const title = `Tier-A code lead · ${probeClass} ${method} ${endpoint}`.slice(0, 180)
      const hypothesis = `A white-box dataflow slice proves a ${probeClass} sink on ${method} ${endpoint} (${reason}). Prove it on the live route (control/variant differential) or record a coded proofGapReason.`
      const createdStep = this.storage.addChainStep(run, {
        title,
        hypothesis,
        category,
        priority: TIER_A_STEP_PRIORITY,
        targetAssetIds: [asset.id],
        skills,
        dependsOnFactIds: [fact.id],
        sourceOrigins: [fact.origin],
        specialistProfile: routeStepToSpecialist({ title, hypothesis, category, skills }),
      })
      this.storage.updateChainStep(createdStep.id, { status: 'ready' })
      this.tierAStepKeys.add(dedupeKey)
      this.tierAStepIds.add(createdStep.id)
      this.detLeadStepKeys.add(dedupeKey)
      slots -= 1
      created += 1
      try {
        this.storage.event(
          run.id,
          'deterministic_lane.tier_a_seeded',
          `Tier-A code lead ${probeClass} on ${method} ${endpoint} seeded as a Round-1 step.`,
          { probeClass, endpoint, method, factId: fact.id, stepId: createdStep.id, priority: TIER_A_STEP_PRIORITY },
        )
      } catch { /* best-effort */ }
    }
    return created
  }

  private queueDetLeadUpgradeSteps(run: Run, approvedOrigins: ReadonlySet<string>, budget: number): number {
    const confirmed = this.alreadyConfirmedRefs(run, 40)
    const confirmedKeys = new Set(confirmed.map(ref =>
      `${normalizeEndpointTemplate(ref.path)}|${confirmedCategoryFamily(ref.probeClass ?? '')}`))
    const facts = [...this.storage.listFacts(run.id, { includeTainted: false, limit: 200 })]
      // det_lead facts are listed in store row order (random row-id tiebreak). The upgrade queue
      // takes the first N, so sort by stable leading fields before choosing.
      .sort((a, b) => {
        // Program-Graph (Tier-A) leads sort first; the generic cap can then never displace them.
        const keyOf = (fact: typeof a) =>
          `${fact.data?.source === 'program_graph' ? '0' : '1'}\u0000${String(fact.data?.endpoint ?? '')}\u0000${String(fact.data?.method ?? '')}\u0000${String(fact.data?.probeClass ?? '')}\u0000${fact.id}`
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
      const isTierA = fact.data.source === 'program_graph'
      const title = `${isTierA ? 'Tier-A code lead' : 'det_lead upgrade'} · ${probeClass} ${method} ${endpoint}`.slice(0, 180)
      const hypothesis = isTierA
        ? `A white-box dataflow slice proves a ${probeClass} sink on ${method} ${endpoint} (${reason}). Prove it on the live route (control/variant differential) or record a coded proofGapReason.`
        : `The deterministic floor observed an unproven ${probeClass} signal at ${method} ${endpoint} (${reason}). Reproduce it, identify the concretely mutated input, and submit a verified proof or chain it into a higher-impact finding.`
      const createdStep = this.storage.addChainStep(run, {
        title,
        hypothesis,
        category,
        priority: isTierA ? TIER_A_STEP_PRIORITY : DET_LEAD_STEP_PRIORITY,
        targetAssetIds: [asset.id],
        skills,
        dependsOnFactIds: [fact.id],
        sourceOrigins: [fact.origin],
        specialistProfile: routeStepToSpecialist({ title, hypothesis, category, skills }),
      })
      this.storage.updateChainStep(createdStep.id, { status: 'ready' })
      this.detLeadStepKeys.add(`${method} ${routeKey}`)
      if (isTierA) {
        this.tierAStepIds.add(createdStep.id)
        this.tierAFactIds.add(fact.id)
        this.tierAStepKeys.add(`${method} ${routeKey}`)
      }
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

  /**
   * Explicit settlement deliverable for a Tier-A white-box assignment: which typed proof tool to run
   * against the named sink, and the coded-gap alternative. The tool still decides the verdict; this
   * only removes "which proof shape / what do I do when it is unreachable" friction.
   */
  private tierAProofDeliverable(input: {
    category?: string | null
    title?: string | null
    hypothesis?: string | null
    sinkKind?: string | null
  }): string {
    const text = `${input.category ?? ''} ${input.title ?? ''} ${input.hypothesis ?? ''} ${input.sinkKind ?? ''}`.toLowerCase()
    const tool = /bfla|mass.assignment|privilege|role|grant|persist|csrf|workflow|state.change|business.logic/.test(text)
      ? 'prove_persisted_mutation'
      : /sqli|sql|inject|xss|ssti|command|template|xml|xxe/.test(text)
        ? 'prove_boolean_or_timing_diff'
        : 'prove_access_boundary'
    return `Invoke guardian_verify(${tool}) against this sink (control vs variant on the exact route above), or record_coverage(proofGapReason="<status|cannot_build_spec>") with the blocking HTTP status. A bare "leaning true" without either is rejected at settlement.`
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
      // Exact control/variant actors for the differential: deterministic order by handle, the
      // variant prefers another tenant (the object/authorization boundary the sink sits behind).
      const tierAPersonas = [...input.personas].sort((a, b) => a.handle.localeCompare(b.handle))
      const tenantOfPersona = (label: string): string => /\(([^()]+)\)\s*$/.exec(label)?.[1]?.trim() ?? ''
      const controlPersona = tierAPersonas[0]
      const variantPersona = controlPersona
        ? tierAPersonas.find(persona => persona.handle !== controlPersona.handle &&
            tenantOfPersona(persona.roleLabel) !== tenantOfPersona(controlPersona.roleLabel))
          ?? tierAPersonas.find(persona => persona.handle !== controlPersona.handle)
        : undefined
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
        // One explicit proof obligation for a white-box assignment: exact mounted route, declared
        // parameter names, the middleware verdict and the sink chain. Names only; the specialist
        // still has to build and verify the spec through the normal replay path.
        ...(codeSlice
          ? {
              proofObligation: {
                route: codeSlice.route,
                method: codeSlice.methods[0],
                params: [
                  ...(codeSlice.input?.params ?? []),
                  ...(codeSlice.input?.query ?? []),
                  ...(codeSlice.input?.body ?? []),
                ],
                auth: codeSlice.auth,
                ...(codeSlice.sink ? { sink: `${codeSlice.sink.kind}@${codeSlice.sink.at}` } : {}),
                chain: codeSlice.hops.slice(0, 6).map(hop => hop.at).join('→'),
                ...(controlPersona
                  ? {
                      controlPersona: controlPersona.handle,
                      variantPersona: (variantPersona ?? controlPersona).handle,
                    }
                  : {}),
                deliverable: this.tierAProofDeliverable({
                  category: input.step.category,
                  title: input.step.title,
                  hypothesis: input.step.hypothesis,
                  ...(codeSlice.sink ? { sinkKind: codeSlice.sink.kind } : {}),
                }),
              },
            }
          : {}),
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

    // Tier-A white-box leads are Round-1 work: seed them as ready steps before the floor/planner
    // can queue generic class/route steps in front of them. Idempotent per route/class; the
    // deterministic-only (`--no-llm`) lane converts through its own engine instead.
    if (!this.deterministicOnly) {
      try {
        this.queueTierALeadSteps(
          this.storage.run(run.id),
          this.approvedOriginsSet(run),
          computeDynamicStepBudget(this.storage, run.id),
        )
      } catch { /* seeding is additive */ }
    }

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
    // Tier-A leads are exempt from the generic concurrent-lead cap; only generic leads count.
    const activeLeadCount = [...this.active.values()].filter(job =>
      job.assignment.runId === run.id &&
      job.assignment.phase === 'investigation' &&
      typeof job.assignment.stepId === 'string' &&
      leadStepIds.has(job.assignment.stepId) &&
      !this.tierAStepIds.has(job.assignment.stepId)).length

    const slots = Math.max(0, maxConc - activeForRun)
    const hostTiers = computeHostTiers(
      [...this.approvedOriginsSet(run)],
      this.storage.latestThreatModel(run.id, run.goalRevision)?.entries,
    )
    const dispatchPlan = planRoundRobinDispatch(readySteps, slots, {
      leadCap: DET_LEAD_CONCURRENT_CAP,
      activeLeadCount,
      hostTiers,
      tierALeadIds: this.tierAStepIds,
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

  private launchDeterministicPass(
    run: Run,
    key: string,
    eventPrefix: 'deterministic_probes' | 'deterministic_engine',
    label: string,
    execPass: () => Promise<void>,
    onFinallyBeforeAdvance?: () => void,
  ) {
    if (this.deterministicCompleted.has(key) || this.deterministicInFlight.has(key)) return
    this.deterministicInFlight.add(key)
    void execPass()
      .catch(error => {
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, `${eventPrefix}.failed`, `${label} failed: ${msg}`)
        } catch { /* store closed or run removed */ }
      })
      .finally(() => {
        this.deterministicInFlight.delete(key)
        this.deterministicCompleted.add(key)
        onFinallyBeforeAdvance?.()
        // The store may already be closed (test teardown / run deletion); never let cleanup throw.
        try {
          const latest = this.storage.run(run.id)
          if (latest.status === 'running' && latest.phase === 'investigation') {
            this.storage.event(
              latest.id,
              `${eventPrefix}.complete`,
              `${label} complete. Advancing to Zero-LLM verification.`,
              { reuse: key },
            )
            this.advanceToVerification(latest)
          }
        } catch { /* store closed or run removed */ }
        try { this.notifyCheckpoint(run.id, 'deterministic-lane') } catch { /* best-effort */ }
        try { this.scheduleWake() } catch { /* scheduler already stopped */ }
      })
  }

  private driveDeterministicInvestigation(run: Run) {
    const key = `${run.id}:${run.goalRevision}:${run.scopeRevision}`
    this.launchDeterministicPass(run, key, 'deterministic_probes', 'Deterministic probe pass', () => this.runDeterministicInvestigation(run))
  }

  // --- Explicit --no-llm deterministic engine (Slice 2; separate from the M1 fallback above) ---

  private driveEngineInvestigation(run: Run) {
    const key = `${run.id}:${run.goalRevision}:${run.scopeRevision}:engine`
    this.launchDeterministicPass(
      run, key, 'deterministic_engine', 'Deterministic engine',
      () => this.runEngineInvestigation(run),
      () => { try { this.settleFloorRequestPhase(run.id, 'no_llm_complete') } catch { /* metrics only */ } },
    )
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
      const tierABound = boundFactIds.some(id => this.tierAFactIds.has(id))
      this.storage.addChainStep(run, {
        title: title.slice(0, 200),
        hypothesis: step.hypothesis,
        category,
        priority: tierABound ? TIER_A_STEP_PRIORITY : leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority,
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
        const tierABound = parentFactIds.some(id => this.tierAFactIds.has(id))
        const created = this.storage.addChainStep(currentRun, {
          title: step.title, hypothesis: step.hypothesis, category: step.category,
          priority: tierABound ? TIER_A_STEP_PRIORITY : leadBound ? Math.min(step.priority, DET_LEAD_STEP_PRIORITY) : step.priority,
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
    let finalSteps = this.storage.listChainSteps(run.id, latest.goalRevision)
    const finalFactIds = new Set(this.pageAll((offset, limit) =>
      this.storage.listFacts(run.id, { includeTainted: true, limit, offset })).map(fact => fact.id))
    let remainingReady = dispatchableReadySteps(finalSteps, finalFactIds).length
    let coverage = this.passOneCoverageFor(run, finalSteps)
    // A dry stop in front of unseeded Tier-A work is a bug, not a drained queue: seed every
    // remaining Tier-A lead now and re-evaluate the stop against the refreshed queue.
    let tierASeededAtStop = 0
    if (decision.decision === 'stop' && (coverage.uninvestigatedFirstPassClasses.length || coverage.uncoveredTierAEndpoints.length)) {
      tierASeededAtStop = this.queueTierALeadSteps(
        this.storage.run(run.id),
        this.approvedOriginsSet(run),
        computeDynamicStepBudget(this.storage, run.id),
      )
      if (tierASeededAtStop > 0) {
        finalSteps = this.storage.listChainSteps(run.id, latest.goalRevision)
        remainingReady = dispatchableReadySteps(finalSteps, finalFactIds).length
        coverage = this.passOneCoverageFor(run, finalSteps)
      }
    }
    // Planner coverage assertion: before honoring a dry/coordinator stop when budget/requests/wall
    // remain, seed first-pass steps for discovered high-risk unconfirmed routes (`riskScore >= 60`).
    const stopBudgetExhausted = this.storage.checkBudgetExceeded(run.id)
    const stopRequestExhausted = latest.budgetRequests > 0 && latest.budgetRequests - latest.spentRequests <= 0
    const stopWallExhausted = this.maxDurationMs > 0 && latest.createdAt + this.maxDurationMs <= Date.now()
    let highRiskSeededAtStop = 0
    if (decision.decision === 'stop' && !stopBudgetExhausted && !stopRequestExhausted && !stopWallExhausted) {
      const seededHighRisk = this.queueHighRiskCoverageSteps(
        this.storage.run(run.id),
        this.approvedOriginsSet(run),
        computeDynamicStepBudget(this.storage, run.id),
        finalSteps,
      )
      if (seededHighRisk.seeded > 0) {
        highRiskSeededAtStop = seededHighRisk.seeded
        funnel.planned += seededHighRisk.seeded
        funnel.enqueued += seededHighRisk.seeded
        finalSteps = this.storage.listChainSteps(run.id, latest.goalRevision)
        remainingReady = dispatchableReadySteps(finalSteps, finalFactIds).length
        coverage = this.passOneCoverageFor(run, finalSteps)
        try {
          this.storage.event(
            run.id,
            'planner.high_risk_coverage_assert',
            `Planner coverage assertion seeded ${seededHighRisk.seeded} uncovered high-risk route(s) before stop.`,
            { roundNo, seeded: seededHighRisk.seeded, endpoints: seededHighRisk.endpoints },
          )
        } catch { /* telemetry is best-effort */ }
      }
    }
    // An uncovered Tier-A lead with no approved asset/route binding cannot be dispatched by any
    // lane; report it loudly instead of spinning the stop guard forever.
    const tierAUnseedable = coverage.uncoveredTierAEndpoints.length > 0 &&
      coverage.uninvestigatedFirstPassClasses.length === 0 &&
      tierASeededAtStop === 0
    if (tierAUnseedable) {
      try {
        this.storage.event(
          run.id,
          'planner.tier_a_unseedable',
          `${coverage.uncoveredTierAEndpoints.length} Tier-A endpoint(s) have no dispatchable step (no approved asset or route binding).`,
          { endpoints: coverage.uncoveredTierAEndpoints.slice(0, 8) },
        )
      } catch { /* telemetry is best-effort */ }
    }
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
      budgetExhausted: stopBudgetExhausted,
      requestExhausted: stopRequestExhausted,
      wallExhausted: stopWallExhausted,
      uninvestigatedFirstPassClasses: tierAUnseedable ? [] : coverage.uninvestigatedFirstPassClasses,
      uncoveredTierAEndpoints: tierAUnseedable ? [] : coverage.uncoveredTierAEndpoints,
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
    const filteredByReason = {
      alreadyConfirmed: funnel.filteredAlreadyConfirmed,
      cap: funnel.filteredCap,
      dep: funnel.filteredDep,
      dedupe: funnel.filteredDedupe,
      noAsset: funnel.filteredNoAsset,
      budget: funnel.filteredBudget,
    }
    const stopped = stopEval.decision === 'stop'
    const coverageAtStop = {
      stopReason: funnel.stopReason,
      uncoveredTierAEndpointsAtStop: stopped ? coverage.uncoveredTierAEndpoints.length : 0,
      uninvestigatedFirstPassClassesAtStop: stopped ? coverage.uninvestigatedFirstPassClasses.length : 0,
      filteredByReason,
      ...(tierASeededAtStop > 0 ? { tierASeededAtStop } : {}),
      ...(highRiskSeededAtStop > 0 ? { highRiskSeededAtStop } : {}),
      ...(tierAUnseedable ? { tierAUnseedable: true } : {}),
    }
    if (stopped) {
      try {
        this.storage.event(
          run.id,
          'planner.coverage_at_stop',
          `Stop ${funnel.stopReason}: Tier-A uncovered ${coverageAtStop.uncoveredTierAEndpointsAtStop}, first-pass uninvestigated ${coverageAtStop.uninvestigatedFirstPassClassesAtStop}, remaining ready ${funnel.remainingReadyAtStop}.`,
          {
            ...coverageAtStop,
            remainingReadyAtStop: funnel.remainingReadyAtStop,
            tierAExamples: coverage.uncoveredTierAEndpoints.slice(0, 6),
            firstPassExamples: coverage.uninvestigatedFirstPassClasses.slice(0, 6),
          },
        )
      } catch { /* telemetry is best-effort */ }
    }
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
      { ...funnel, filtered: filteredByReason, coverage: coverageAtStop },
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
        coverage: coverageAtStop,
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
    const wakeHandle = this.board.wakeHandleByStepId.get(step.id)
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
    this.board.trackedBoardRuns.add(run.id)
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

    // Warm-pool policy: run identity + persona credential generation. A rotation (or a new run or
    // tenant) retires the pool instead of handing an older container to this assignment.
    const generations = (grant.personas ? [...grant.personas.keys()] : []).sort().map(handle =>
      `${handle}:${this.personaAuth.sessions.generation(handle)}`)
    const secretEpoch = secretGenerationFingerprint(generations)
    const priorEpoch = this.warmSecretEpochByRun.get(run.id)
    if (priorEpoch !== undefined && priorEpoch !== secretEpoch) {
      this.warmPoolPolicyRotationsByRun.set(run.id, (this.warmPoolPolicyRotationsByRun.get(run.id) ?? 0) + 1)
      try {
        this.storage.event(run.id, 'worker.warm_pool_rotated', 'Credential generation changed; rebuilding idle warm containers.', {
          assignmentId: job.assignment.id, stepId: step.id, previous: priorEpoch, next: secretEpoch,
        })
      } catch { /* telemetry only */ }
    }
    this.warmSecretEpochByRun.set(run.id, secretEpoch)
    try { this.backend.setWarmPoolPolicy?.(`${run.id}:${secretEpoch}`) } catch { /* pooling is best-effort */ }

    // Open ONE persistent air-gapped container for the entire intent
    const { reposDir, mountedRepos } = this.projectReposMount(run.projectId)
    const session = await this.backend.openSession(
      job.assignment.id,
      job.controller.signal,
      reposDir ? { reposDir } : undefined,
    )
    const startedAt = Date.now()
    // Per-turn generation latencies (provider stream) plus the no-token watchdog: 28 s of complete
    // provider silence aborts the turn, while every token re-arms the timer so slow streaming is
    // never killed. The old 45–90 s generation watchdog stays only as the wall-saved baseline.
    const turnLatencies: number[] = []
    let generationStartedAt: number | undefined
    // Profile-aware no-token watchdog (backed by real-time per-frame SSE activity resets in
    // provider-stream.ts + provider.ts): reasoning/thinking profiles get 45–60 s TTFT headroom.
    const watchdogSpecialist = resolveSpecialistProfile(
      step.specialistProfile ?? routeStepToSpecialist({
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
      }),
    )
    const primaryProfile = resolveProfilePoolForRole(watchdogSpecialist.roleAffinity, profiles)[0] ?? profiles[0]
    const noTokenMs = resolveProfileNoTokenWatchdogMs(primaryProfile)
    // Always the full no-token window. Never shrink it near the assignment wall: that turned
    // healthy-but-slow final turns into "stalls", burning a bounded retry on work the wall budget
    // was already going to settle.
    const noTokenThresholdMs = () => noTokenMs
    const stallAbortMs = () => providerStallAbortMs(percentile(turnLatencies, 50), turnLatencies.length)
    const stallWatchdog = new ProviderNoTokenWatchdog({
      thresholdMs: noTokenThresholdMs,
      onStall: ({ turn, idleMs, thresholdMs }) => {
        if (generationStartedAt === undefined) return
        generationStartedAt = undefined
        job.stallAbort = true
        this.providerStallTimeoutsByRun.set(run.id, (this.providerStallTimeoutsByRun.get(run.id) ?? 0) + 1)
        this.providerStallTurnsByRun.set(run.id, (this.providerStallTurnsByRun.get(run.id) ?? 0) + 1)
        // What the previous generation watchdog would have waited before aborting this turn.
        const previousThresholdMs = stallAbortMs()
        const wallSavedMs = Math.max(0, previousThresholdMs - idleMs)
        this.providerStallWallSavedByRun.set(run.id, (this.providerStallWallSavedByRun.get(run.id) ?? 0) + wallSavedMs)
        try {
          this.storage.event(run.id, 'worker.provider_stall', `Provider stream stalled on turn ${turn} (${Math.round(idleMs / 1000)}s without a token); aborting to free the slot.`, {
            assignmentId: job.assignment.id, stepId: step.id, turn, elapsedMs: idleMs, thresholdMs,
            previousThresholdMs, wallSavedMs, stallAbortMs: stallAbortMs(), wallClockMs: budget.wallClockMs,
          })
        } catch { /* telemetry only */ }
        job.controller.abort(new Error('Provider stream stalled (no token).'))
      },
    })
    const armStallTimer = (turn: number) => {
      stallWatchdog.clear()
      generationStartedAt = Date.now()
      if (job.stallAbort) return
      stallWatchdog.arm(turn)
    }
    const noteProviderToken = () => stallWatchdog.noteToken()
    const recordTurnLatency = () => {
      if (generationStartedAt === undefined) return
      const ms = Math.max(0, Date.now() - generationStartedAt)
      generationStartedAt = undefined
      stallWatchdog.clear()
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

        const saved = recordBrokerExchange(this.storage, curRun, job.assignment.id, res, currentSecrets())

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
          const saved = recordBrokerExchange(this.storage, curRun, job.assignment.id, res, currentSecrets(), {
            markCoverage: (r, o, m, p) => this.markEndpointCoverage(r, o, m, p, 'http_exchange'),
            onSaved: (r, e, id) => {
              trackPersonaResources(r, e, id)
              this.scanSecondOrderExchange(r, job.assignment.id, e, id)
            },
          })
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

      const prepareBudgetedProbe = (origin: string, requestedMax: number | undefined, defaultMax: number) => {
        const curRun = this.check(job)
        if (this.storage.checkBudgetExceeded(curRun.id)) throw new BudgetExceededError('Run spend or request budget exceeded.')
        const cleanOrigin = this.parseOriginForRun(curRun, origin)
        const remainingReqs = this.phaseRequestRemaining(curRun) ?? (requestedMax ?? defaultMax)
        if (remainingReqs <= 0) throw new BudgetExceededError('Agent request budget exhausted.')
        const cappedMax = requestedMax !== undefined ? Math.min(requestedMax, remainingReqs) : Math.min(defaultMax, remainingReqs)
        return { curRun, cleanOrigin, remainingReqs, cappedMax }
      }
      const stageJsonArtifact = async (
        curRun: Run,
        kind: 'dns' | 'tls' | 'browser' | 'surface' | 'ws',
        title: string,
        filename: string,
        payload: unknown,
        signal: AbortSignal,
        secretsList: readonly NamedSecret[] = currentSecrets(),
      ) => {
        const serialized = JSON.stringify(payload, null, 2)
        const ev = this.storage.addArtifact(curRun, job.assignment, kind, title, serialized, undefined, secretsList)
        const stagedPath = await session.stage(filename.replace('{id}', ev.id.slice(0, 8)), serialized, signal).catch(() => null)
        return { evidenceId: ev.id, stagedPath }
      }
      const makeTrackedExchangeRecorder = (curRun: Run) =>
        createExchangeRecorder(this.storage, () => curRun, job.assignment.id, currentSecrets, {
          onSaved: (r, e, id) => {
            trackPersonaResources(r, e, id)
            this.scanSecondOrderExchange(r, job.assignment.id, e, id)
          },
        })

      const sharedHandlers = this.buildSharedSessionHandlers(job, session, currentSecrets, {
        offlineScriptLabel: 'Offline {runtime} script',
        onFactRecorded: curRun => {
          boardTools.noteEvidence()
          this.schedulePlanner(curRun.id)
        },
      })
      const handlers: WorkerToolHandlers = {
        ...sharedHandlers,

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
            const saved = recordBrokerExchange(this.storage, curRun, job.assignment.id, res, currentSecrets(), {
              markCoverage: (r, o, m, p) => this.markEndpointCoverage(r, o, m, p, 'http_exchange'),
              onSaved: (r, e, id) => {
                trackPersonaResources(r, e, id)
                this.scanSecondOrderExchange(r, job.assignment.id, e, id)
              },
            })
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
          const staged = await stageJsonArtifact(
            curRun, 'dns', `DNS inspection · ${dnsRes.hostname}`,
            `dns-${dnsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`, dnsRes, signal, secrets,
          )
          return { ...staged, ...dnsRes }
        },

        inspect_tls: async ({ origin }, signal) => {
          const curRun = this.check(job)
          const tlsRes = await this.broker.inspectTls(origin, grant, signal)
          const staged = await stageJsonArtifact(
            curRun, 'tls', `TLS audit · ${tlsRes.hostname}`,
            `tls-${tlsRes.hostname.replace(/[^a-z0-9.-]/gi, '_')}.json`, tlsRes, signal, secrets,
          )
          return { ...staged, ...tlsRes }
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
              const saved = recordBrokerExchange(this.storage, curRun, job.assignment.id, ex, currentSecrets())
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
              onExchange: createExchangeRecorder(this.storage, () => curRun, job.assignment.id, currentSecrets, {
                onSaved: (r, e, id) => {
                  trackPersonaResources(r, e, id)
                  this.scanSecondOrderExchange(r, job.assignment.id, e, id)
                },
              }),
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
          const res = await sharedHandlers.run_sast_scan!(args, signal)

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
          return res
        },

        probe_surface: async (args, signal) => {
          const { curRun, cleanOrigin, cappedMax } = prepareBudgetedProbe(args.origin, args.maxRequests, 150)
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
            onExchange: makeTrackedExchangeRecorder(curRun),
          }, this.broker, grant, signal)

          this.markEndpointCoverage(curRun, res.origin, args.methods?.[0] ?? 'GET', args.basePath ?? '/', `surface:${res.mode}`)
          this.storage.recordSurfaceProbe({
            runId: curRun.id, assignmentId: job.assignment.id, scopeRevision: curRun.scopeRevision,
            origin: res.origin, probeKind: `surface:${res.mode}`,
            requestsSent: res.requestsSent, anomaliesFound: res.anomalies.length, baselineSignature: res.baselineSignature,
          })
          const staged = await stageJsonArtifact(curRun, 'surface', `Surface probe (${res.mode}) · ${res.origin}`, 'surface-{id}.json', res, signal)
          return { ...staged, ...res }
        },

        probe_differential: async (args, signal) => {
          const { curRun, cleanOrigin, cappedMax } = prepareBudgetedProbe(args.origin, args.maxRequests, 60)

          // Default parameter / resource-ID selection from persisted endpoint_params & api_dependencies.
          const requestedTemplate = normalizeEndpointTemplate(args.pathAndQuery.split('?')[0] || '/')
          const originEndpoints = this.storage.listEndpoints(curRun.id, { origin: cleanOrigin })
          const targetEndpoint = originEndpoints.find(ep => ep.pathTemplate === requestedTemplate && (!args.method || ep.method === args.method.toUpperCase()))
            ?? originEndpoints.find(ep => ep.pathTemplate === requestedTemplate)
          const targetParams = targetEndpoint ? this.storage.listEndpointParams(curRun.id, targetEndpoint.id) : []
          const injectableParams = targetParams.filter(p => ['query', 'json', 'form', 'path', 'graphql_var'].includes(p.location) && !p.isCsrf)
          const preferredParam = [...injectableParams].sort((a, b) =>
            Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)) ||
            Number(a.isObjectId) - Number(b.isObjectId),
          )[0]
          const resolvedParamName = args.paramName ?? preferredParam?.name
          const resolvedParamLocation = args.paramLocation ?? (preferredParam && preferredParam.location !== 'cookie' ? preferredParam.location : undefined)
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
            onExchange: makeTrackedExchangeRecorder(curRun),
          }, this.broker, grant, this.canaryBroker, signal)

          this.markEndpointCoverage(curRun, res.origin, args.method ?? 'GET', args.pathAndQuery, `diff:${res.probeClass}`)
          this.storage.recordSurfaceProbe({
            runId: curRun.id, assignmentId: job.assignment.id, scopeRevision: curRun.scopeRevision,
            origin: res.origin, probeKind: `diff:${res.probeClass}`,
            requestsSent: res.requestsSent, anomaliesFound: res.anomalies.length, baselineSignature: res.verdict,
          })
          const staged = await stageJsonArtifact(
            curRun, 'surface', `Differential probe (${res.probeClass}) · ${res.origin}${args.pathAndQuery.slice(0, 48)}`,
            'diff-{id}.json', res, signal,
          )
          return { ...staged, ...res }
        },

        run_safe_templates: async (args, signal) => {
          const { curRun, cleanOrigin, remainingReqs } = prepareBudgetedProbe(args.origin, undefined, 150)

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
            onExchange: createExchangeRecorder(this.storage, () => curRun, job.assignment.id, currentSecrets),
          }, this.broker, grant, this.canaryBroker, signal)

          this.storage.recordSurfaceProbe({
            runId: curRun.id, assignmentId: job.assignment.id, scopeRevision: curRun.scopeRevision,
            origin: res.origin, probeKind: 'safe_templates',
            requestsSent: res.requestsSent, anomaliesFound: res.matches.length, baselineSignature: res.baselineSignature,
          })

          // Record template matches strictly as hypothesis/lead facts (NEVER auto-confirmed!)
          for (const match of res.matches) {
            this.storage.addFact(curRun, job.assignment, {
              kind: match.factKind === 'cve_hypothesis' ? 'cve_hypothesis' : 'note',
              origin: res.origin,
              summary: `[Safe template ${match.templateId}] ${match.name} (${match.severity}) on ${match.method} ${match.path} (HTTP ${match.status})`,
              data: {
                templateId: match.templateId, cve: match.cve ?? null, cwe: match.cwe ?? null,
                severity: match.severity, evidence: match.evidence, controlStatus: match.controlStatus, confidence: 'low',
              },
              exchangeIds: match.exchangeId ? [match.exchangeId] : [],
              sourceOrigins: [res.origin],
              secrets: currentSecrets(),
            })
          }

          const staged = await stageJsonArtifact(
            curRun, 'surface', `Safe templates · ${res.origin} (${res.matches.length} matches)`,
            'templates-{id}.json', res, signal,
          )
          return { ...staged, ...res }
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
          const saved = recordBrokerExchange(this.storage, curRun, job.assignment.id, syntheticEx, currentSecrets())
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
          const staged = await stageJsonArtifact(
            curRun, 'ws', `WebSocket probe · ${wsRes.origin}${wsRes.pathAndQuery.slice(0, 60)}`,
            'ws-{id}.json', { exchangeId: saved.id, ...wsRes }, signal,
          )
          return { exchangeId: saved.id, ...staged, ...wsRes }
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

        query_cves: async (args, signal) => {
          const res = await sharedHandlers.query_cves!(args, signal)
          return {
            ...res,
            note: 'Advisories are hypotheses only. Record a cve_hypothesis fact and verify reachability with a non-destructive Replay Spec before confirming.',
          }
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
          const { rows: existingRows, refs: existingRefs } = buildExistingFindingRefs(
            this.storage, curRun.id, curRun.goalRevision, { chainOnly: true, includeDescriptions: true },
          )

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
              inlineVerifyFeedback: retryLimitExceededFeedback(
                maxAttempts,
                `Inline verification retry limit reached for existing finding ${canonicalMatchedRow.id} (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
              ),
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
                inlineVerifyFeedback: retryLimitExceededFeedback(
                  maxAttempts,
                  `Inline verification retry limit reached (maxInlineVerifyRetries=${maxInlineVerifyRetries}).`,
                ),
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

        // v7 M5: the Layer-3 script proof path, persisted as a receipt. Registered only when the
        // worker backend can run an air-gapped verification session; a replay-only backend keeps the
        // (unchanged) declarative compilers instead of producing an inert script tool.
        ...(this.backendSupportsVerifyScript() ? {
          guardian_verify: async (args: GuardianVerifyArgs) => {
            const curRun = this.check(job)
            const runtime: GuardianVerifyRuntime = args.runtime
              ?? (args.scriptPath && /\.py$/i.test(args.scriptPath) ? 'python' : 'ts')
            const script = typeof args.script === 'string' && args.script.trim()
              ? args.script.trim()
              : args.scriptPath
                ? this.readAgentProofScript(reposDir, args.scriptPath)
                : ''
            if (!script) {
              throw new Error('guardian_verify requires `script` (inline) or `scriptPath` (a file in the mounted workspace).')
            }
            const approved = this.approvedOriginsSet(curRun)
            const proof = await runAgentScriptProof({
              script,
              runtime,
              ...(args.title?.trim() ? { title: args.title.trim() } : {}),
              broker: this.broker,
              grant,
              backend: this.backend,
              runId: curRun.id,
              assignmentId: job.assignment.id,
              targetOrigins: [...approved].slice(0, 8),
              signal: job.controller.signal,
              canaryBroker: this.canaryBroker,
              ...(args.timeoutMs ? { timeoutMs: args.timeoutMs } : {}),
            })
            if (!proof.verdict.confirmed) return summarizeGuardianVerifyOutcome(proof.verdict)
            const persisted = this.persistAgentScriptProof({
              run: curRun,
              assignment: job.assignment,
              script,
              runtime,
              title: args.title?.trim() || proof.claimTitle || undefined,
              proof,
              secrets: currentSecrets(),
            })
            return summarizeGuardianVerifyOutcome({
              ...proof.verdict,
              detail: `${proof.verdict.detail} Finding ${persisted.findingId} cites ${persisted.receiptId ? `ProofReceipt ${persisted.receiptId}` : 'the persisted script proof'} (replay spec ${persisted.replaySpecId}).`
                .trim(),
            })
          },
        } : {}),

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
      const assignedTargetRoutes = extractAssignedTargetRoutes({
        title: step.title,
        hypothesis: step.hypothesis,
        parentFacts,
        defaultOrigin: targetOrigins[0],
      })

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
          this.board.noteTokens(job.assignment.id, boardHandle, usage.inputTokens + usage.outputTokens)
        },
        onTurn: turn => {
          recordTurnLatency()
          this.storage.updateWorker(job.assignment.id, { turnsUsed: turn })
          this.storage.recordLlmSpend(run.id, { turns: 1 })
        },
        // Provider token activity resets the no-token watchdog: a slow stream is not a stall.
        onStreamActivity: noteProviderToken,
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
        approvedOrigins: [...permittedAtAdmission],
        ...(assignedTargetRoutes.length ? { assignedTargetRoutes } : {}),
        onProofObligation: (info: ProofObligationEvent) => {
          const prev = this.proofObligationByRun.get(run.id) ?? {
            probedRoutes: 0,
            coveredRoutes: 0,
            gapRoutes: 0,
            demandedRoutes: 0,
            dischargedByGap: 0,
          }
          this.proofObligationByRun.set(run.id, {
            probedRoutes: prev.probedRoutes + info.probedRoutes,
            coveredRoutes: prev.coveredRoutes + info.coveredRoutes,
            gapRoutes: prev.gapRoutes + info.gapRoutes,
            demandedRoutes: prev.demandedRoutes + info.demandedRoutes,
            dischargedByGap: prev.dischargedByGap + info.dischargedByGap,
          })
          try {
            this.storage.event(
              run.id,
              'agent.proof_obligation',
              `Proof obligation: ${info.coveredRoutes}/${info.probedRoutes} probed route(s) covered, ${info.gapRoutes} gap(s), ${info.demandedRoutes} demanded.`,
              { assignmentId: job.assignment.id, stepId: step.id, ...info },
            )
          } catch { /* telemetry is best-effort */ }
        },
        onGapValidation: (info: GapValidationEvent) => {
          const prev = this.gapValidationByRun.get(run.id) ?? { accepted: 0, rejected: 0, byCode: {} }
          const byCode: Record<string, { accepted: number; rejected: number }> = { ...prev.byCode }
          for (const [code, counts] of Object.entries(info.byCode)) {
            const cur = byCode[code] ?? { accepted: 0, rejected: 0 }
            byCode[code] = { accepted: cur.accepted + counts.accepted, rejected: cur.rejected + counts.rejected }
          }
          this.gapValidationByRun.set(run.id, {
            accepted: prev.accepted + info.accepted,
            rejected: prev.rejected + info.rejected,
            byCode,
          })
          try {
            this.storage.event(
              run.id,
              'agent.gap_validation',
              `Gap validation: ${info.accepted} accepted, ${info.rejected} rejected.`,
              { assignmentId: job.assignment.id, stepId: step.id, ...info },
            )
          } catch { /* telemetry is best-effort */ }
        },
        onEarlyExit: info => {
          this.earlyExitTurnsSavedByRun.set(run.id,
            (this.earlyExitTurnsSavedByRun.get(run.id) ?? 0) + info.turnsSaved)
          this.storage.event(run.id, 'agent.early_exit',
            `Early exit (${info.reason}) at turn ${info.turnsUsed}/${info.maxTurns}: `
            + `${info.evidenceCount} distinct attempt(s), ${info.turnsSaved} turn(s) saved`
            + (info.route ? ` on ${info.route.method} ${info.route.path}.` : '.'),
            { ...info })
        },
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
      stallWatchdog.clear()
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
    const trackedClones = this.workerSessionClones.get(worker.id)
    if (trackedClones) {
      for (const entry of trackedClones) entry.clone.dispose()
      this.workerSessionClones.delete(worker.id)
    }
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
