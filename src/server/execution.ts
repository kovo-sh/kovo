import { randomUUID } from 'node:crypto'
import { existsSync, rmSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { and, eq } from 'drizzle-orm'
import { getAppRuntime, type AppRuntime, type KillSwitchState } from './app-runtime.ts'
import {
  assetOriginForEnvironment,
  defaultWorkerConcurrency,
  isLocalLabEnvEnabled,
  maxInlineVerifyRetries,
  maxWorkerConcurrency,
  type CheckCoverage,
  type Finding,
  type ThreatModelSummary,
} from '../domain.ts'
import {
  authorizeStateChange,
  isLocalLabAutoApprovalOrigin,
  evaluateTier3Approval,
  StateChangeApprovalLedger,
} from './approval-judge.ts'
import {
  codeAuditPrompt,
  resolveSpecialistProfile,
  routeStepToSpecialist,
  runAgentSession,
  wallClockSettlementMs,
  WarmSpecialistController,
  type WorkerToolHandlers,
} from './agent-session.ts'
import {
  getRunTokenTelemetrySummary,
  hasRunTokenTelemetry,
  type RunTokenTelemetrySummary,
} from './token-telemetry.ts'
import { createAgentTraceFromEnv, type AgentTrace } from './agent-trace.ts'
import {
  BrokerDenied,
  RequestBroker,
  type BrokerExchangeResult,
  type BrokerHttpRequest,
  type BrokerOptions,
  type BrokerRaceBurstResult,
  type Grant,
} from './broker.ts'
import { CanaryBroker, scanSecondOrderMarkers, type SecondOrderStore } from './canary-broker.ts'
import { hasCuratedAdvisory, queryCves } from './cve-broker.ts'
import { DerivedCapabilityVault, resetRunCustodyBudgets } from './derived-custody.ts'
import { runAllRunDisposers } from './run-disposers.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import {
  conventionalWordlistEnabled,
  defaultEngineMaxDurationMs,
  defaultEngineMaxRequests,
  deterministicWallMarginMs,
  stagingProbeTag,
} from './deterministic-engine.ts'
import { proofReceiptMode } from './proof-receipt.ts'
import { VERIFY_RPC_SDK_VERSION } from './verify-rpc.ts'
import { buildBrokeredTransportHandlers } from './exec-brokered-transport.ts'
import {
  createExchangeRecorder,
  findFindingRow,
  llmRunHooks,
  publicPersonasFromGrant,
  recordBrokerExchange,
  type ExecActiveJob,
  type ExecCoordinatorTask,
  type ExecCoreServices,
} from './exec-exchange.ts'
import { ExecFloorLane } from './exec-floor-lane.ts'
import {
  ExecReconPlanner,
  HOP_CONTINUATION_DIRECTIVE,
  MAX_WORKSPACE_DIGEST_BYTES,
  buildWorkspaceSourceDigest,
} from './exec-recon-planner.ts'
export { HOP_CONTINUATION_DIRECTIVE, MAX_WORKSPACE_DIGEST_BYTES, buildWorkspaceSourceDigest } from './exec-recon-planner.ts'
import { ExecVerifier } from './exec-verify.ts'
import { ExecWorkerRunner, type ExecBrokeredTransportContext } from './exec-worker-runner.ts'
export { agentProofAttribution, probeCanaryClass, runV8AgentScriptProof, syncVerifyArtifactsToLedger } from './exec-verify.ts'
import { listMountedRepos, parseDependenciesFromFile, projectReposDir } from './github-connector.ts'
export { decideNext } from './graph-coordinator.ts'
import { seedCodeToRuntimeLeads as seedGraphLeads } from './graph-leads.ts'
import { getSharedLabRunner, type LabRunner, type LabTargetHandle } from './lab-runner.ts'
import {
  privateModelProfiles,
  resolveProfilePoolForRole,
  type ResolvedModelProfile,
} from './model-settings.ts'
import { drainPendingOob, scheduleFinalReport, type OobDrainOptions, type OobDrainResult } from './oob-drain.ts'
import { generateAndReviewPatch } from './patch-workflow.ts'
import { PersonaAuthManager, type PersonaSessionClone } from './persona-auth.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
import { ProbePlanRegistry } from './probe-plan.ts'
import type { CodeDataflowSlice, CodeToRuntimeHypothesis } from './program-graph.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, type NamedSecret } from './redact.ts'
import { buildInlineVerifyFeedback } from './replay-verifier.ts'
import {
  HOST_PLANNER_PRODUCER,
  PHASE_A_FLOOR_MAX_WALL_CLOCK_MS,
  PHASE_A_FLOOR_WALL_CLOCK_SHARE,
  PLANNER_BACKOFF_BASE_MS,
  PLANNER_BACKOFF_CAP_MS,
  PLANNER_MAX_CONSECUTIVE_ERRORS,
  PhaseRequestBudgetTracker,
  RunActor,
  RunTier3ApprovalCoordinator,
  codeAuditSettlementMessage,
  computePlannerBackoffMs,
  deriveRunActorState,
  drainTimedOutRunActor,
  installRunActorRejectionGuard,
  isExecutionRunTrackedActive,
  isTrustedHostControlFact,
  pauseRunsForKillSwitch,
  recordRunAssignmentMetrics,
  recordRunFloorMetrics,
  recordVerificationOrRetestFailure,
  resolvePhaseAFloorWallClockMs,
  resolveRunTenantId,
  resolveSourceAuditMaxTurns,
  resolveSourceAuditSettlementMs,
  resolveSourceAuditWallClockMs,
  rollbackRejectedInvestigationSpawn,
  rollbackRejectedWorkerSpawn,
  settleCodeAuditSuspects,
  teardownRunStaging,
  trackDetLeadFactForRun,
  type RunActorDisposeOptions,
  type SpawnTaskOptions,
  type SupervisedTask,
  type TerminalRunActorState,
} from './run-actor.ts'
export {
  PHASE_A_FLOOR_MAX_WALL_CLOCK_MS,
  PHASE_A_FLOOR_MIN_WALL_CLOCK_MS,
  PHASE_A_FLOOR_WALL_CLOCK_SHARE,
  PLANNER_BACKOFF_BASE_MS,
  PLANNER_BACKOFF_CAP_MS,
  PLANNER_MAX_CONSECUTIVE_ERRORS,
  SOURCE_AUDIT_DEFAULT_WALL_CLOCK_MS,
  SOURCE_AUDIT_MAX_WALL_CLOCK_MS,
  SOURCE_AUDIT_MIN_WALL_CLOCK_MS,
  SOURCE_AUDIT_SETTLEMENT_SHARE,
  SOURCE_AUDIT_SHORT_RUN_MAX_TURNS,
  SOURCE_AUDIT_SHORT_RUN_THRESHOLD_MS,
  SOURCE_AUDIT_WALL_CLOCK_SHARE,
  codeAuditSettlementMessage,
  computePlannerBackoffMs,
  promoteSemanticAuditSuspects,
  recordVerificationOrRetestFailure,
  resolvePhaseAFloorWallClockMs,
  resolveSourceAuditMaxTurns,
  resolveSourceAuditSettlementMs,
  resolveSourceAuditWallClockMs,
  rollbackRejectedInvestigationSpawn,
  rollbackRejectedWorkerSpawn,
  settleCodeAuditSuspects,
} from './run-actor.ts'
import type { RunDrainReport } from './run-context.ts'
import { approvalRequests, findings } from './schema.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { bindScopedBrowserToGrant, registerScopedBrowserForRun, unregisterScopedBrowserForRun } from './verify-support.ts'
import { runThreeStageSemanticAudit, toChainStepInputs, type SemanticAuditSuspect } from './semantic-audit.ts'
import { cloneWorkerPersona } from './session-isolation.ts'
import { buildStaticWorkspaceSnapshotInWorker } from './static-workspace-snapshot.ts'
import {
  assessmentAssignments,
  dataDirectory,
  RunDeleteBusyError,
  store,
  type Assignment,
  type BoardMessageRow,
  type ChainStep,
  type Fact,
  type PatchProposal,
  type Run,
  type Store,
} from './store.ts'
import type { DifferentialProbeClass } from './surface-engine.ts'
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
  diminishingReturnsDryThreshold,
  plannerDebounceMs,
  intentLeaseMs,
  resolvePhaseRequestBudgets,
  resolveFloorLaneMode,
  chainHypothesisDispatchSteps,
  computeDynamicStepBudget,
  STRANDED_READY_STOP_REASONS,
  DISPATCH_FUNNEL_COUNT_KEYS,
  emptyDispatchFunnel,
  permanentlyBlockedStepIds,
  dispatchableReadySteps,
  hasActiveInvestigationSteps,
  isStepOriginUnavailable,
  reconcileUnavailableOriginSteps,
  planMultiTrialExpansion,
  evaluateDispatchStop,
  circuitBreakAction,
  DET_LEAD_CONCURRENT_CAP,
  ReinvestigationGuard,
  RunOrchestrationStateStore,
  isDetLeadDispatchStep,
  isMultiHopChainStep,
  PHASE_B_MIN_CONCURRENCY_FLOOR,
  PhaseBConcurrencyController,
  parseEnvPhaseBConcurrencyOverride,
  resolveEffectivePhaseBConcurrency,
  type PhaseBConcurrencySnapshot,
  countConsecutiveDrySteps,
  computeHostTiers,
  computeStepMaxTurns,
  resolveAssignmentBudget,
  singleStepWallClockMs,
  requeueInterruptedAssignments,
  CODE_AUDIT_WAVE1_MAX_STEPS,
  convertCodeAuditSuspectsToChainSteps,
  type FrontierWaveController,
  type DeterministicSweepMode,
  type PhaseRequestBudgets,
  type DispatchStopReason,
  type DispatchFunnelCounts,
  type AssignmentBudget,
  type AssignmentThroughputMetrics,
  type RunOobDrainSummary,
  type RunOrchestrationState,
} from './exec-dispatch.ts'
export * from './exec-dispatch.ts'
import { ExecBoardManager } from './exec-board.ts'

type Active = ExecActiveJob
type CoordinatorTask = ExecCoordinatorTask

function createBroker(options: {
  storage: SecondOrderStore
  canaryBroker: CanaryBroker
  reauth?: BrokerOptions['reauth']
}) {
  const target = process.env.KOVO_NETWORK_FIXTURE
  const reauthOpt = options.reauth ? { reauth: options.reauth } : {}
  if (!target) {
    return process.env.KOVO_OFFLINE === '1'
      ? new RequestBroker({ resolve: async () => [], storage: options.storage, canaryBroker: options.canaryBroker, ...reauthOpt })
      : new RequestBroker({ storage: options.storage, canaryBroker: options.canaryBroker, ...reauthOpt })
  }
  const fixture = new URL(target)
  if (fixture.origin !== target || fixture.hostname !== '127.0.0.1' || fixture.protocol !== 'http:' || !fixture.port) {
    throw new Error('KOVO_NETWORK_FIXTURE must identify a loopback HTTP origin.')
  }
  return new RequestBroker({
    storage: options.storage,
    canaryBroker: options.canaryBroker,
    ...reauthOpt,
    source: 'fixture response',
    resolve: async host => host.endsWith('.private-fixture.example')
      ? [{ address: '127.0.0.1', family: 4 }]
      : [{ address: '93.184.216.34', family: 4 }],
    transport: async (url, _address, signal, options) => {
      const reqHeaders: Record<string, string> = {
        ...(options?.headers ?? {}),
        'x-kovo-fixture-target': url.href,
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
   * agentic run. Default ON; `deterministicSweep: false` (or `KOVO_DETERMINISTIC_SWEEP=0`) is
   * an operator kill switch, and `'always'` bypasses the resumed-run guard. The lane never blocks
   * dispatch, never consumes specialist worker slots, never cancels steps and never hides
   * confirmed routes.
   */
  deterministicSweep?: boolean | 'always'
  /**
   * Wall-clock ceiling the harness will allow for the whole run. The concurrent lane derives its
   * own deadline as `min(240 s, 40% × maxDurationMs)`. Falls back to
   * `KOVO_MAX_DURATION_MS`, then 600 s (which keeps the 240 s lane cap).
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
   * the legacy single shared `run.budgetRequests` behavior. `KOVO_FLOOR_REQUEST_BUDGET` /
   * `KOVO_AGENT_REQUEST_BUDGET` are the env equivalents.
   */
  floorRequestBudget?: number
  agentRequestBudget?: number
  /** Optional per-assignment wall-clock cap override (primarily for deterministic rotation tests). */
  assignmentWallClockOverrideMs?: number
  /** Optional explicit Phase-B worker concurrency override (takes precedence over dynamic AIMD). */
  workerConcurrencyOverride?: number
  /** Optional planner retry backoff overrides (defaults: 500ms base, 15s cap, 7 consecutive errors). */
  plannerBackoffBaseMs?: number
  plannerBackoffCapMs?: number
  plannerMaxConsecutiveErrors?: number
  /** Optional AppRuntime composition root (defaults to `getAppRuntime()`). */
  runtime?: AppRuntime
}

export type ExecutionCheckpoint = 'phase0' | 'deterministic-lane' | 'post-floor' | 'planner-round'

export class Execution {
  private readonly storage: Store
  readonly broker: RequestBroker
  readonly browser: ScopedBrowser
  readonly canaryBroker: CanaryBroker
  readonly backend: WorkerBackend
  readonly personaAuth: PersonaAuthManager
  readonly labRunner: LabRunner
  private readonly active = new Map<string, Active>()
  /** Unified per-run orchestration state (Move O5: single-call atomic cleanup on run disposal). */
  readonly runState = new RunOrchestrationStateStore()
  // Live projection views over `runState` keeping legacy external hosts & test seams intact.
  private readonly coordinator = this.runState.mapView('coordinatorTask')
  private readonly threatModeling = this.runState.mapView('threatModelingTask')
  private readonly plannerTasks = this.runState.mapView('plannerTask')
  private readonly plannerTimers = this.runState.mapView('plannerTimerCancel')
  private readonly plannerDirty = this.runState.setView('plannerDirty')
  private readonly plannerDoneRound = this.runState.mapView('plannerDoneRound')
  private readonly plannerErrorState = this.runState.mapView('plannerErrorState')
  private readonly plannerBackoffBaseMs: number
  private readonly plannerBackoffCapMs: number
  private readonly plannerMaxConsecutiveErrors: number
  private readonly dryStreakObserved = this.runState.mapView('dryStreakObserved')
  /** Phase-0 ranked probe plans (probe breadth hint; the endpoint store stays lossless). */
  private readonly probePlans = new ProbePlanRegistry()
  private readonly programGraphLeadsSeeded = this.runState.prefixedSetView('programGraphLeadsSeeded', '\0')
  private readonly dispatchFunnels = this.runState.mapView('dispatchFunnel')
  private readonly strandedReadyEvents = this.runState.mapView('strandedReadyEvents')
  private readonly reinvestigationGuards = this.runState.mapView('reinvestigationGuard')
  private readonly recordedPersonaResources = this.runState.mapView('recordedPersonaResources')
  private readonly circuitNotified = this.runState.prefixedSetView('circuitNotified', ':')
  private readonly strandedBackstopReported = this.runState.prefixedSetView('strandedBackstopReported', ':')
  private readonly runAuthStarted = this.runState.mapView('runAuthStarted')
  private readonly runAuthInFlight = this.runState.mapView('runAuthInFlight')
  private readonly startedLabRuns = this.runState.setView('startedLabRun')
  private readonly startedLabHandles = this.runState.mapView('startedLabHandle')
  private readonly variantSweptFindings = new Set<string>()
  private readonly variantSweepInFlight = new Set<string>()
  private readonly pendingTier3ApprovalKeys = new Set<string>()
  /** Exact, single-use Tier-3 approvals consumed by the broker fast path (see authorizeStateChange). */
  private readonly stateChangeApprovals = new StateChangeApprovalLedger()
  private readonly burstApprovalInstances = new Map<string, { remaining: number; expiresAt: number }>()
  private readonly deterministicInFlight = this.runState.prefixedSetView('deterministicInFlight', ':')
  private readonly deterministicCompleted = this.runState.prefixedSetView('deterministicCompleted', ':')
  private readonly deterministicOnly: boolean
  /** Slice 3 concurrent lane bookkeeping (never reuses the deterministicInFlight/Completed sets). */
  private readonly deterministicSweep: DeterministicSweepMode
  private readonly maxDurationMs: number
  private readonly prePhase0SeededSteps = this.runState.prefixedMapView<boolean, 'prePhase0SeededSteps'>('prePhase0SeededSteps', ':')
  private readonly agenticLaneJobs = this.runState.mapView('agenticLaneJob')
  private readonly agenticLaneCompleted = this.runState.prefixedSetView('agenticLaneCompleted', ':')
  private readonly agenticLaneStopping = this.runState.setView('agenticLaneStopping')
  private readonly agenticLaneAssignmentIds = new Set<string>()
  /** Floor assignment IDs explicitly launched to overlap Phase A (`threat_model` -> `investigation`). */
  private readonly overlappedFloorAssignmentIds = new Set<string>()
  private readonly verificationDraining = this.runState.setView('verificationDraining')
  /** Post-completion drain/throughput summaries (retained after disposeRun, cleared on deleteRun). */
  private readonly lastOobDrain = new Map<string, RunOobDrainSummary>()
  /** assignmentId → per-worker composite persona session clones (v6 credential isolation). */
  private readonly workerSessionClones = new Map<string, Array<{ handle: string; clone: PersonaSessionClone }>>()
  private readonly laneStartedAt = this.runState.mapView('laneStartedAt')
  private readonly laneWallByRun = this.runState.mapView('laneWallMs')
  private readonly assignmentWallByRun = this.runState.mapView('assignmentWalls')
  private readonly completedAssignmentWallByRun = this.runState.mapView('completedAssignmentWalls')
  private readonly turnLatencyByRun = this.runState.mapView('turnLatencies')
  private readonly earlyExitTurnsSavedByRun = this.runState.mapView('earlyExitTurnsSaved')
  private readonly proofObligationByRun = this.runState.mapView('proofObligation')
  private readonly gapValidationByRun = this.runState.mapView('gapValidation')
  private readonly providerStallTurnsByRun = this.runState.mapView('providerStallTurns')
  private readonly providerStallRetriesByRun = this.runState.mapView('providerStallRetries')
  private readonly providerStallTimeoutsByRun = this.runState.mapView('providerStallTimeouts')
  private readonly providerStallWallSavedByRun = this.runState.mapView('providerStallWallSaved')
  private readonly wallClockRotationsByRun = this.runState.mapView('wallClockRotations')
  private readonly wallClockRotatedAssignments = new Set<string>()
  private readonly warmSecretEpochByRun = this.runState.mapView('warmSecretEpoch')
  private readonly warmPoolPolicyRotationsByRun = this.runState.mapView('warmPoolPolicyRotations')
  private readonly lastAssignmentMetrics = new Map<string, AssignmentThroughputMetrics>()
  private readonly agenticFloorDispatchedAt = this.runState.mapView('agenticFloorDispatchedAt')
  private readonly agenticFloorStartedAt = this.runState.mapView('agenticFloorStartedAt')
  private readonly agenticFloorFinishedAt = this.runState.mapView('agenticFloorFinishedAt')
  /** v6 budget split: null = legacy single shared budget. */
  private readonly phaseRequestBudgets: PhaseRequestBudgets | null
  private readonly budgetTracker: PhaseRequestBudgetTracker
  private readonly runtime: AppRuntime
  private readonly ownsLabRunner: boolean
  /** Explicit per-run `RunActor` FSM + structured `TaskSupervisor` registry. */
  private readonly actors = new Map<string, RunActor>()
  private readonly timedOutActors = new Map<string, RunActor>()
  private readonly disposingRuns = new Map<string, Promise<RunDrainReport | null>>()
  private readonly maintenanceTasks = new Set<Promise<unknown>>()
  private releaseRejectionGuard: (() => void) | null = null
  private unregisterRuntimeDisposer: (() => void) | null = null
  private unsubKillSwitch: (() => void) | null = null
  private stopPromise: Promise<void> | null = null
  private activeDetLeadRunId: string | null = null
  private readonly detLeadConsumed = new Set<string>()
  private readonly detLeadConsumedByRun = this.runState.mapView('detLeadConsumedIds')
  /** Tier-A Program-Graph facts/steps: seeded first, exempt from the generic lead cap. */
  private readonly tierAFactIds = new Set<string>()
  private readonly tierAStepIds = new Set<string>()
  private readonly runTraces = this.runState.mapView('runTrace')
  private readonly onCheckpoint?: (event: { runId: string; checkpoint: ExecutionCheckpoint }) => void
  private readonly assignmentWallClockOverrideMs?: number
  private readonly workerConcurrencyOverride?: number
  private readonly phaseBControllers = this.runState.mapView('phaseBController')
  /** v5 M5: chain-scoped warm specialist lifecycle (pure in-memory; mirrored to board_members). */
  private readonly warm = new WarmSpecialistController()
  private readonly stagingTaggedMutations = this.runState.mapView('stagingTaggedMutations')
  private readonly stagingUntaggedSkipped = this.runState.mapView('stagingUntaggedSkipped')
  private readonly stagingCleaned = this.runState.mapView('stagingCleaned')
  private readonly stagingCreatedEntities = this.runState.mapView('stagingCreatedEntities')
  private readonly stagingGrants = this.runState.mapView('stagingGrant')
  private readonly boardHandleByAssignment = new Map<string, string>()
  private readonly board: ExecBoardManager
  private readonly floorLane: ExecFloorLane
  private readonly verifier: ExecVerifier
  private readonly reconPlanner: ExecReconPlanner
  private readonly workerRunner: ExecWorkerRunner
  private readonly tier3Approvals: RunTier3ApprovalCoordinator
  private readonly capabilityVaults = this.runState.mapView('capabilityVault')
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
    const envMaxDuration = Number(process.env.KOVO_MAX_DURATION_MS)
    this.maxDurationMs = Number.isFinite(optionMaxDuration) && optionMaxDuration > 0
      ? optionMaxDuration
      : Number.isFinite(envMaxDuration) && envMaxDuration > 0
        ? envMaxDuration
        : 600_000
    this.onCheckpoint = options.onCheckpoint
    const wallOverride = Number(options.assignmentWallClockOverrideMs)
    this.assignmentWallClockOverrideMs = Number.isFinite(wallOverride) && wallOverride > 0 ? Math.max(1, Math.floor(wallOverride)) : undefined
    const concOverride = Number(options.workerConcurrencyOverride)
    this.workerConcurrencyOverride = Number.isFinite(concOverride) && concOverride > 0
      ? Math.max(1, Math.min(maxWorkerConcurrency, Math.floor(concOverride)))
      : undefined
    const backoffBase = Number(options.plannerBackoffBaseMs)
    this.plannerBackoffBaseMs = Number.isFinite(backoffBase) && backoffBase > 0
      ? Math.floor(backoffBase)
      : PLANNER_BACKOFF_BASE_MS
    const backoffCap = Number(options.plannerBackoffCapMs)
    this.plannerBackoffCapMs = Number.isFinite(backoffCap) && backoffCap >= this.plannerBackoffBaseMs
      ? Math.floor(backoffCap)
      : Math.max(this.plannerBackoffBaseMs, PLANNER_BACKOFF_CAP_MS)
    const maxPlannerErrors = Number(options.plannerMaxConsecutiveErrors)
    this.plannerMaxConsecutiveErrors = Number.isFinite(maxPlannerErrors) && maxPlannerErrors >= 1
      ? Math.floor(maxPlannerErrors)
      : PLANNER_MAX_CONSECUTIVE_ERRORS
    this.phaseRequestBudgets = resolvePhaseRequestBudgets({
      ...(options.floorRequestBudget !== undefined ? { floorRequestBudget: options.floorRequestBudget } : {}),
      ...(options.agentRequestBudget !== undefined ? { agentRequestBudget: options.agentRequestBudget } : {}),
    })
    this.budgetTracker = new PhaseRequestBudgetTracker(
      this.storage,
      this.phaseRequestBudgets,
      (runId, kind, message, detail) => this.safeEvent(runId, kind, message, detail),
    )
    const baseDetLeadAdd = this.detLeadConsumed.add.bind(this.detLeadConsumed)
    this.detLeadConsumed.add = (factId: string) => {
      baseDetLeadAdd(factId)
      this.trackDetLeadConsumed(factId)
      return this.detLeadConsumed
    }
    this.runtime = options.runtime ?? getAppRuntime({
      dataDir: storage.directory,
      store: storage,
    })
    if (options.canaryBroker) {
      this.canaryBroker = options.canaryBroker
      if (!this.runtime.isDisposed && !this.runtime.hasCanaryBroker()) {
        this.runtime.attachCanaryBroker(this.canaryBroker)
      }
    } else if (!this.runtime.isDisposed && this.runtime.hasCanaryBroker()) {
      this.canaryBroker = this.runtime.canaryBroker
    } else {
      this.canaryBroker = new CanaryBroker({ storage })
      if (!this.runtime.isDisposed) {
        this.runtime.attachCanaryBroker(this.canaryBroker)
      }
    }
    this.unregisterRuntimeDisposer = this.runtime.registerDisposer(
      `execution:${randomUUID()}`,
      () => this.stop(),
    )
    this.unsubKillSwitch = this.runtime.killSwitch.onChange(state => {
      if (state.active) this.handleKillSwitchTripped(state)
      else if (!this.stopped) this.scheduleWake()
    })
    this.personaAuth = options.personaAuth ?? new PersonaAuthManager()
    this.broker = options.broker ?? createBroker({ storage, canaryBroker: this.canaryBroker })
    if (!options.broker) {
      this.broker.setReauth(async (personaHandle, runId) => {
        if (runId) {
          if (this.personaAuth.sessions.has(personaHandle, runId)) {
            return this.personaAuth.requestReauth(personaHandle, undefined, runId)
          }
          const runScoped = await this.personaAuth.requestReauth(personaHandle, undefined, runId)
          if (runScoped) return true
          // Backwards-compatible fallback ONLY for legacy unscoped pool registrations (`entry.runId === undefined`);
          // never fall back across runs when the handle belongs to a different run.
          const probe = this.personaAuth.cloneSession(personaHandle)
          if (probe) {
            const isUnscoped = !probe.runId
            probe.dispose()
            if (isUnscoped) {
              return this.personaAuth.requestReauth(personaHandle)
            }
          }
          return false
        }
        return this.personaAuth.requestReauth(personaHandle)
      })
    }
    // `storage` activates second-order canary scanning inside the browser context too.
    this.browser = options.browser ?? new ScopedBrowser(this.broker, { storage })
    this.backend = options.backend ?? new LinuxWorkerBackend({
      workspace: { id: storage.workspace.id, directory: storage.directory },
    })
    this.ownsLabRunner = Boolean(options.labRunner)
    this.labRunner = options.labRunner ?? getSharedLabRunner()
    const core: ExecCoreServices = {
      storage: this.storage, broker: this.broker, browser: this.browser,
      canaryBroker: this.canaryBroker, backend: this.backend,
    }
    const approvedOriginsSet = (run: Run) => this.approvedOriginsSet(run)
    const permitted = (run: Run, origin: string) => this.permitted(run, origin)
    const buildGrant = (job: Active, run: Run, allowed: ReadonlySet<string>) => this.buildGrant(job, run, allowed)
    const projectReposMount = (projectId: string) => this.projectReposMount(projectId)
    const completeWorker = (w: Assignment, r: Run, o: string, e: string[], c?: CheckCoverage[], s?: readonly NamedSecret[]) =>
      this.completeWorker(w, r, o, e, c, s)

    this.board = new ExecBoardManager({
      storage: this.storage, warm: this.warm, boardHandleByAssignment: this.boardHandleByAssignment,
      approvedOriginsSet, scheduleWake: () => this.scheduleWake(),
    })
    this.floorLane = new ExecFloorLane({
      ...core, probePlans: this.probePlans,
      stagingTaggedMutations: this.stagingTaggedMutations, stagingUntaggedSkipped: this.stagingUntaggedSkipped,
      stagingCleaned: this.stagingCleaned, stagingCreatedEntities: this.stagingCreatedEntities,
      approvedOriginsSet, permitted,
      buildGrant: (job, run, allowed) => {
        // ExecFloorLane only reaches buildGrant during `threat_model` when `allowThreatModelPhase`
        // was explicitly enabled; authorize its `investigation` worker across the Phase-A overlap.
        if (run.phase === 'threat_model' && job.assignment.phase === 'investigation') {
          this.overlappedFloorAssignmentIds.add(job.assignment.id)
        }
        return this.buildGrant(job, run, allowed)
      },
      beginFloorRequestPhase: run => this.beginFloorRequestPhase(run),
      phaseRequestRemaining: run => this.phaseRequestRemaining(run),
      markEndpointCoverage: (run, o, m, p, c) => this.markEndpointCoverage(run, o, m, p, c),
      scanSecondOrderExchange: (run, assignmentId, ex, id) => this.scanSecondOrderExchange(run, assignmentId, ex, id),
      createConfirmedReplaySpec: (run, assignment, findingId, spec, origins, result, secrets) =>
        this.storage.createReplaySpec(run, assignment, findingId, spec, origins, {
          verifiedInline: true,
          backingKind: 'floor_engine',
          lastVerificationDiff: buildInlineVerifyFeedback(spec, result, 1, maxInlineVerifyRetries, secrets),
        }),
    })
    this.verifier = new ExecVerifier({
      ...core, approvedOriginsSet, permitted, buildGrant, projectReposMount, completeWorker,
      check: job => this.check(job),
      isCanaryDnsConfigured: () => this.isCanaryDnsConfigured(),
      isCanaryListenerConfigured: () => this.isCanaryListenerConfigured(),
      markEndpointCoverage: (run, o, m, p, c) => this.markEndpointCoverage(run, o, m, p, c),
      markReplaySpecCoverage: (run, spec, c) => this.markReplaySpecCoverage(run, spec, c),
      waitForTier3Approval: (job, input, signal) => this.waitForTier3Approval(job, input, signal),
      postVerificationVerdict: (run, opts) => this.postVerificationVerdict(run, opts),
      cancelSiblingTrialsOnConfirmation: (run, stepId, findingId) => this.cancelSiblingTrialsOnConfirmation(run, stepId, findingId),
      scheduleVariantSweepForFinding: (run, row) => this.scheduleVariantSweepForFinding(run, row),
      recordSpecVerification: (runId, specId, feedback, summary) =>
        this.storage.recordReplaySpecVerification(runId, specId, feedback, summary),
      resolveInlineVerdictRow: (runId, findingRow) => {
        const verdictRow = findingRow ? findFindingRow(this.storage, runId, findingRow.id) : undefined
        return verdictRow
      },
      capabilityVaultFor: runId => this.capabilityVaultFor(runId),
    })
    this.reconPlanner = new ExecReconPlanner({
      ...core, runState: this.runState, labRunner: this.labRunner, maxDurationMs: this.maxDurationMs,
      active: this.active, coordinator: this.coordinator, probePlans: this.probePlans,
      startedLabRuns: this.startedLabRuns, startedLabHandles: this.startedLabHandles,
      prePhase0SeededSteps: this.prePhase0SeededSteps, plannerDoneRound: this.plannerDoneRound,
      dispatchFunnels: this.dispatchFunnels, detLeadConsumed: this.detLeadConsumed,
      tierAStepIds: this.tierAStepIds, tierAFactIds: this.tierAFactIds,
      approvedOriginsSet, buildGrant, projectReposMount, completeWorker,
      authorize: job => this.authorize(job),
      currentCoordinator: (runId, task) => this.currentCoordinator(runId, task),
      deterministicLaneKey: run => this.deterministicLaneKey(run),
      notifyCheckpoint: (runId, cp) => this.notifyCheckpoint(runId, cp),
      seedCodeToRuntimeLeads: (run, assignment, hyps) => this.seedCodeToRuntimeLeads(run, assignment, hyps),
      correlateSpecDependencies: (r, c, s, o, d, sig, sec) => this.correlateSpecDependencies(r, c, s, o, d, sig, sec),
      runSourceFirstCodeAudit: (r, tm, p, sig) => this.runSourceFirstCodeAudit(r, tm, p, sig),
      baselineFinding: (r, a, rev) => this.baselineFinding(r, a, rev),
      saveBaselineFinding: (r, a, rev, st, reason, eIds, exId) => this.verifier.saveBaselineFinding(r, a, rev, st, reason, eIds, exId),
      expandEligibleMultiTrialSteps: run => this.expandEligibleMultiTrialSteps(run),
      endpointGraphCatalog: runId => this.endpointGraphCatalog(runId),
      noteDryStreak: run => this.noteDryStreak(run),
      reinvestigationGuardFor: runId => this.reinvestigationGuardFor(runId),
      highPriorityQueueEmpty: run => this.highPriorityQueueEmpty(run),
      noteCappedReinvestigation: (run, key, attempted) => this.noteCappedReinvestigation(run, key, attempted),
      recordDispatchFunnel: (runId, f) => this.recordDispatchFunnel(runId, f),
      noteStrandedReadySteps: (runId, d) => this.noteStrandedReadySteps(runId, d),
      tracePlannerDecision: (runId, payload) => this.tracePlannerDecision(runId, payload),
      codeSliceForAssignment: (run, step, facts) => this.codeSliceForAssignment(run, step, facts),
      shouldCoordinatorAnswer: content => this.shouldCoordinatorAnswer(content),
      resetBoardHops: run => this.board.resetBoardHops(run),
      spawnRunTask: (runId, label, fn, opts) => this.spawnRunTask(runId, label, fn, opts),
    })
    this.workerRunner = new ExecWorkerRunner({
      ...core, personaAuth: this.personaAuth, board: this.board, verifier: this.verifier, reconPlanner: this.reconPlanner,
      recordedPersonaResources: this.recordedPersonaResources, workerSessionClones: this.workerSessionClones,
      boardHandleByAssignment: this.boardHandleByAssignment, warmSecretEpochByRun: this.warmSecretEpochByRun,
      warmPoolPolicyRotationsByRun: this.warmPoolPolicyRotationsByRun, wallClockRotatedAssignments: this.wallClockRotatedAssignments,
      wallClockRotationsByRun: this.wallClockRotationsByRun, providerStallTimeoutsByRun: this.providerStallTimeoutsByRun,
      providerStallTurnsByRun: this.providerStallTurnsByRun, providerStallRetriesByRun: this.providerStallRetriesByRun,
      providerStallWallSavedByRun: this.providerStallWallSavedByRun, proofObligationByRun: this.proofObligationByRun,
      gapValidationByRun: this.gapValidationByRun, earlyExitTurnsSavedByRun: this.earlyExitTurnsSavedByRun,
      assignmentWallByRun: this.assignmentWallByRun, completedAssignmentWallByRun: this.completedAssignmentWallByRun,
      turnLatencyByRun: this.turnLatencyByRun, approvedOriginsSet, permitted, buildGrant, projectReposMount,
      authorize: job => this.authorize(job),
      check: job => this.check(job),
      parseOriginForRun: (run, raw) => this.parseOriginForRun(run, raw),
      stageProjectSpecs: (projectId, session, signal) => this.stageProjectSpecs(projectId, session, signal),
      safeEvent: (runId, kind, msg, detail) => this.safeEvent(runId, kind, msg, detail),
      ensureCanaryListenerForRun: (run, ignore) => this.ensureCanaryListenerForRun(run, ignore),
      phaseRequestRemaining: run => this.phaseRequestRemaining(run),
      markEndpointCoverage: (run, o, m, p, c) => this.markEndpointCoverage(run, o, m, p, c),
      scanSecondOrderExchange: (run, aid, res, exId, mt) => this.scanSecondOrderExchange(run, aid, res, exId, mt),
      postCanaryLead: (run, input) => this.postCanaryLead(run, input),
      boardTurnDelta: (run, handle, seq) => this.boardTurnDelta(run, handle, seq),
      schedulePlanner: (runId, delayMs) => this.schedulePlanner(runId, delayMs),
      ensureRunTrace: (run, profiles) => this.ensureRunTrace(run, profiles),
      capabilityVaultFor: runId => this.capabilityVaultFor(runId),
      executeInlineVerification: (...a) => this.executeInlineVerification(...a),
      persistAgentScriptProof: (...a) => this.persistAgentScriptProof(...a),
      alreadyConfirmedRefs: (...a) => this.alreadyConfirmedRefs(...a),
      detLeadSummaries: (...a) => this.detLeadSummaries(...a),
      assignmentBriefForStep: (...a) => this.assignmentBriefForStep(...a),
      buildBrokeredTransportHandlers: ctx => this.buildBrokeredTransportHandlers(ctx),
    })
    this.tier3Approvals = new RunTier3ApprovalCoordinator({
      storage: this.storage,
      broker: this.broker,
      active: this.active,
      pendingTier3ApprovalKeys: this.pendingTier3ApprovalKeys,
      stateChangeApprovals: this.stateChangeApprovals,
      burstApprovalInstances: this.burstApprovalInstances,
      authorize: job => this.authorize(job),
      check: job => this.check(job),
      phaseRequestRemaining: run => this.phaseRequestRemaining(run),
      postApprovalCard: (run, aid, input, secrets) => this.postApprovalCard(run, aid, input, secrets),
      postApprovalResolution: (run, aid, input) => this.postApprovalResolution(run, aid, input),
      registerTimer: (runId, name, timer) => this.ensureRunActor(runId).registerTimer(name, timer),
      scheduleWake: () => this.scheduleWake(),
    })
  }

  private isCanaryDnsConfigured(): boolean {
    return Boolean(
      process.env.KOVO_CANARY_DNS_HOST ||
      process.env.KOVO_CANARY_DNS_PORT ||
      process.env.KOVO_CANARY_DNS_DOMAIN,
    )
  }

  private isCanaryListenerConfigured(): boolean {
    return Boolean(
      process.env.KOVO_CANARY_PUBLIC_URL ||
      process.env.KOVO_CANARY_BASE_URL ||
      process.env.KOVO_CANARY_PORT ||
      process.env.KOVO_CANARY_ENABLE === '1' ||
      this.isCanaryDnsConfigured(),
    )
  }

  private async ensureCanaryListenerForRun(run: Run, ignoreErrors = false): Promise<void> {
    const project = this.storage.project(run.projectId)
    if (this.isCanaryListenerConfigured() || (project.environment === 'local-lab' && isLocalLabEnvEnabled())) {
      const p = this.canaryBroker.startListener({ enableDns: this.isCanaryDnsConfigured() })
      await (ignoreErrors ? p.catch(() => undefined) : p)
    }
  }

  private safeEvent(runId: string, kind: string, message: string, detail?: Record<string, unknown>): void {
    try { this.storage.event(runId, kind, message, detail) } catch { /* telemetry is best-effort */ }
  }

  private async stageProjectSpecs(
    projectId: string,
    session: Awaited<ReturnType<WorkerBackend['openSession']>>,
    signal: AbortSignal,
  ): Promise<Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }>> {
    const staged: Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string }> = []
    for (const [idx, spec] of this.storage.listProjectSpecsFull(projectId).slice(0, 8).entries()) {
      try {
        const stagedPath = await session.stage(`specs/spec-${idx + 1}.txt`, spec.content.slice(0, 1_500_000), signal)
        staged.push({ name: spec.name, kind: spec.kind, origin: spec.origin, stagedPath })
      } catch { /* skip oversized */ }
    }
    return staged
  }

  private parseOriginForRun(run: Run, raw: string): string {
    const project = this.storage.project(run.projectId)
    return assetOriginForEnvironment(project.environment).parse(raw)
  }

  /** Return the active `RunActor` for `runId`, if initialized. */
  getRunActor(runId: string): RunActor | undefined {
    return this.actors.get(runId)
  }

  private runTenantId(run: Pick<Run, 'id' | 'projectId'>): string | null {
    return resolveRunTenantId(this.storage, run)
  }

  private trackDetLeadConsumed(factId: string): void {
    trackDetLeadFactForRun(this.storage, this.detLeadConsumedByRun, this.activeDetLeadRunId, factId)
  }

  private trackMaintenance(task: Promise<unknown>): void {
    const tracked = task.catch(() => undefined).finally(() => { this.maintenanceTasks.delete(tracked) })
    this.maintenanceTasks.add(tracked)
  }

  private hasActiveRetest(runId: string): boolean {
    for (const job of this.active.values()) {
      if (job.assignment.runId === runId && job.assignment.phase === 'retest') return true
    }
    return false
  }

  /** Return the cohesive per-run orchestration state record for `runId`, if tracked. */
  getRunOrchestrationState(runId: string): RunOrchestrationState | undefined {
    return this.runState.get(runId)
  }

  private cleanupRunState(runId: string, actor?: RunActor): void {
    this.reconPlanner.clearRunState(runId)
    this.runState.disposeRun(runId, {
      onDetLeadConsumedIds: ids => { for (const factId of ids) this.detLeadConsumed.delete(factId) },
    })
    this.budgetTracker.deleteRun(runId)
    this.board.cleanupRun(runId)
    this.broker.disposeRun(runId)
    unregisterScopedBrowserForRun(runId)
    resetRunCustodyBudgets(runId)
    runAllRunDisposers(runId)
    if (!actor || this.actors.get(runId) === actor) this.actors.delete(runId)
  }

  private scheduleRunDisposal(runId: string, terminalState: TerminalRunActorState, reason: string): Promise<RunDrainReport | null> {
    const p = this.disposeRun(runId, { terminalState, reason })
    this.trackMaintenance(p)
    return p
  }

  private handleKillSwitchTripped(state: KillSwitchState): void {
    if (this.stopped) return
    pauseRunsForKillSwitch(
      this.storage,
      state,
      (id, kind, msg, detail) => this.safeEvent(id, kind, msg, detail),
      runId => { this.scheduleRunDisposal(runId, 'canceled', 'kill switch tripped') },
    )
    for (const [runId, actor] of [...this.actors.entries()]) {
      if (state.tenantId === null || actor.context.tenantId === state.tenantId) {
        this.scheduleRunDisposal(runId, 'canceled', 'kill switch tripped')
      }
    }
  }

  /**
   * Ensure a per-run `RunActor` + `RunContext` exists and owns structured resource disposal
   * (staging cleanup, capability vault RAM+disk eviction, OOB unsubscribe, persona refreshers,
   * lab target teardown, warm pool eviction, trace close, and timer cancellation).
   */
  private ensureRunActor(runOrId: Run | string): RunActor {
    const runId = typeof runOrId === 'string' ? runOrId : runOrId.id
    const existing = this.actors.get(runId)
    if (existing) {
      if (!existing.isDisposed && !existing.isTerminal && existing.state !== 'stopping' && !existing.signal.aborted) {
        return existing
      }
      if (existing.context.isDisposed) {
        this.actors.delete(runId)
      } else {
        if (!this.disposingRuns.has(runId) && !existing.isDraining) {
          this.trackMaintenance(
            this.scheduleRunDisposal(runId, 'canceled', 'dispose stale actor').finally(() => this.scheduleWake()),
          )
        }
        return existing
      }
    }

    let run: Run | undefined = typeof runOrId === 'string' ? undefined : runOrId
    if (!run) {
      try { run = this.storage.run(runId) } catch { run = undefined }
    }
    const tenantId = run ? this.runTenantId(run) : null
    const initialState = run ? deriveRunActorState(run) : 'queued'
    const existingCtx = this.runtime.getRunContext(runId)
    if (existingCtx && (existingCtx.isAborted || existingCtx.isDraining) && !existingCtx.isDisposed) {
      if (!this.disposingRuns.has(runId)) {
        this.trackMaintenance(
          this.scheduleRunDisposal(runId, 'canceled', 'dispose aborted context').finally(() => this.scheduleWake()),
        )
      }
      return new RunActor({ context: existingCtx, initialState })
    }
    const context = existingCtx && !existingCtx.isDisposed
      ? existingCtx
      : this.runtime.createRunContext(runId, { tenantId })
    const actor = new RunActor({ context, initialState })

    actor.registerResource('staging:teardown', () => teardownRunStaging({
      runId,
      storage: this.storage,
      broker: this.broker,
      stagingGrants: this.stagingGrants,
      stagingTaggedMutations: this.stagingTaggedMutations,
      stagingUntaggedSkipped: this.stagingUntaggedSkipped,
      stagingCleaned: this.stagingCleaned,
      stagingCreatedEntities: this.stagingCreatedEntities,
    }))
    actor.registerResource('capability-vault:evict', () => {
      this.evictCapabilityVault(runId)
    })
    actor.registerResource('persona-auth:stop', () => {
      this.personaAuth.stopRunRefreshers(runId)
      this.runAuthStarted.delete(runId)
      const inflight = this.runAuthInFlight.get(runId)
      if (inflight) {
        try { inflight.abort() } catch { /* ignore */ }
        this.runAuthInFlight.delete(runId)
      }
    })
    actor.registerResource('lab:stop', async () => {
      if (!this.startedLabRuns.has(runId) && !this.startedLabHandles.has(runId)) return
      this.startedLabRuns.delete(runId)
      this.startedLabHandles.delete(runId)
      await this.labRunner.stopLabTarget(runId).catch(() => undefined)
    })
    actor.registerResource('warm-pool:evict', async () => {
      try { await this.backend.evictRunWarmPool?.(runId) } catch { /* best-effort warm pool eviction */ }
    })
    actor.registerResource('oob:canary-unsubscribe', () => {
      try { this.canaryBroker.unsubscribeRun(runId) } catch { /* ignore */ }
    })
    actor.registerResource('trace:close', () => {
      const trace = this.runTraces.get(runId)
      if (trace) {
        this.runTraces.delete(runId)
        try { trace.closeTrace() } catch { /* ignore */ }
      }
    })
    actor.registerResource('broker-custody:dispose', () => { this.broker.disposeRun(runId); resetRunCustodyBudgets(runId) })
    actor.registerResource('run-state:cleanup', () => {
      this.cleanupRunState(runId, actor)
    })

    this.actors.set(runId, actor)
    return actor
  }

  /** Spawn a structured async job bound to the run's `RunActor` + `TaskSupervisor`. */
  private spawnRunTask<T = void>(
    runId: string,
    label: string,
    fn: (signal: AbortSignal) => Promise<T> | T,
    options?: SpawnTaskOptions,
  ): SupervisedTask<T> {
    return this.ensureRunActor(runId).spawn(label, fn, options)
  }

  /** Run a background action (e.g. subdomain discovery) supervised by `RunActor` + `TaskSupervisor`. */
  runSupervisedBackgroundTask(
    runId: string,
    label: string,
    fn: (signal: AbortSignal) => Promise<void>,
  ): Promise<void> {
    return this.spawnRunTask(runId, label, fn).promise.then(() => undefined)
  }

  /** True when `runId` has any tracked in-flight actor task, worker, planner, lane, or drain. */
  isRunTrackedActive(runId: string): boolean {
    return isExecutionRunTrackedActive(runId, this as unknown as Parameters<typeof isExecutionRunTrackedActive>[1])
  }

  private evictCapabilityVault(runId: string): void {
    this.capabilityVaults.delete(runId)
    const safeRunId = /^[A-Za-z0-9._-]{1,128}$/.test(runId)
      ? runId
      : runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
    const diskPath = existsSync(this.storage.directory)
      ? join(this.storage.directory, 'capability-vaults', `${safeRunId}.json`)
      : undefined
    if (diskPath) {
      try { rmSync(diskPath, { force: true }) } catch { /* best-effort disk eviction */ }
    }
  }

  /**
   * Deterministically abort + drain all supervised jobs and dispose the run's `RunContext`
   * (evicting `capabilityVaults` RAM + disk, unsubscribing OOB, and releasing lab/auth resources).
   */
  disposeRun(runId: string, options: RunActorDisposeOptions = {}): Promise<RunDrainReport | null> {
    const inflight = this.disposingRuns.get(runId)
    if (inflight) return inflight
    const work = (async () => {
      const actor = this.actors.get(runId)
      let report: RunDrainReport | null = null
      if (actor) {
        report = await actor.drainAndDispose(options)
        if (this.actors.get(runId) === actor) this.actors.delete(runId)
        if (report.tasksTimedOut > 0 && actor.activeTaskCount > 0) this.timedOutActors.set(runId, actor)
        else this.timedOutActors.delete(runId)
      } else if (this.timedOutActors.has(runId)) {
        report = await drainTimedOutRunActor(runId, this.timedOutActors, options.timeoutMs)
      } else if (this.runtime.getRunContext(runId)) {
        report = await this.runtime.disposeRunContext(runId, options.timeoutMs)
      }
      if (!actor) {
        try { await this.backend.evictRunWarmPool?.(runId) } catch { /* best-effort warm pool eviction */ }
      }
      this.evictCapabilityVault(runId)
      this.cleanupRunState(runId)
      try { this.canaryBroker.unsubscribeRun(runId) } catch { /* ignore */ }
      return report
    })().finally(() => {
      if (this.disposingRuns.get(runId) === work) this.disposingRuns.delete(runId)
    })
    this.disposingRuns.set(runId, work)
    return work
  }

  /**
   * Drain and dispose all in-flight tasks for `runId` before deleting its SQLite rows and disk files
   * (`M-16` / `H-26` / `C4`: fail closed if tracked tasks time out instead of deleting under live writers).
   */
  async deleteRun(
    runId: string,
    options: { timeoutMs?: number } = {},
  ): Promise<{ deleted: boolean; projectId: string; runId: string; drainReport: RunDrainReport | null }> {
    const drainReport = await this.disposeRun(runId, {
      terminalState: 'canceled',
      reason: 'run deleted',
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    })
    if (drainReport && drainReport.tasksTimedOut > 0) {
      throw new RunDeleteBusyError([runId])
    }
    this.lastOobDrain.delete(runId)
    this.lastAssignmentMetrics.delete(runId)
    const deleted = this.storage.deleteRun(runId)
    return { ...deleted, drainReport }
  }

  start() {
    if (this.safetyTimer) return
    this.stopped = false
    this.releaseRejectionGuard ??= installRunActorRejectionGuard()
    try { this.storage.session.ensureHighConcurrencyPragmas() } catch { /* pragmas are best-effort */ }
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

  stop(): Promise<void> {
    if (this.stopPromise) return this.stopPromise
    this.stopPromise = this.performStop()
    return this.stopPromise
  }

  private async performStop() {
    this.stopped = true
    unregisterExecutionInstance(this.storage.directory, this)
    this.unregisterRuntimeDisposer?.()
    this.unregisterRuntimeDisposer = null
    this.unsubKillSwitch?.()
    this.unsubKillSwitch = null
    try {
      const runIds = new Set<string>([
        ...[...this.active.values()].map(job => job.assignment.runId),
        ...this.actors.keys(),
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

    this.wakeScheduled = false
    this.unsubWake?.()
    this.unsubWake = undefined
    if (this.safetyTimer) { clearInterval(this.safetyTimer); this.safetyTimer = undefined }
    if (this.reclaimTimer) { clearInterval(this.reclaimTimer); this.reclaimTimer = undefined }

    // Abort & drain every active RunActor + RunContext deterministically before clearing residual state.
    const activeActors = [...this.actors.values()]
    this.actors.clear()
    await Promise.allSettled([
      ...activeActors.map(actor => actor.drainAndDispose({ terminalState: 'canceled', reason: 'execution stopped' })),
      ...this.disposingRuns.values(),
      ...this.maintenanceTasks,
    ])
    this.disposingRuns.clear()

    // Tear down any remaining staging grants not covered by an actor.
    for (const runId of [...this.stagingGrants.keys()]) {
      await teardownRunStaging({
        runId,
        storage: this.storage,
        broker: this.broker,
        stagingGrants: this.stagingGrants,
        stagingTaggedMutations: this.stagingTaggedMutations,
        stagingUntaggedSkipped: this.stagingUntaggedSkipped,
        stagingCleaned: this.stagingCleaned,
        stagingCreatedEntities: this.stagingCreatedEntities,
      })
    }

    for (const job of this.active.values()) job.controller.abort()
    for (const task of this.coordinator.values()) task.controller.abort()
    for (const task of this.threatModeling.values()) task.controller.abort()
    for (const task of this.plannerTasks.values()) task.controller.abort()
    try { await this.backend.closeWarmPool?.() } catch { /* teardown is best-effort */ }
    for (const [assignmentId, tracked] of this.workerSessionClones) {
      for (const entry of tracked) entry.clone.dispose()
      this.workerSessionClones.delete(assignmentId)
    }
    for (const trace of this.runTraces.values()) {
      try { trace.closeTrace() } catch { /* tracing must never break shutdown */ }
    }
    for (const runId of [...this.capabilityVaults.keys()]) {
      this.evictCapabilityVault(runId)
      try { this.canaryBroker.unsubscribeRun(runId) } catch { /* ignore */ }
    }
    const labRunIds = [...new Set([...this.startedLabRuns, ...this.startedLabHandles.keys()])]
    this.runState.clear({
      onDetLeadConsumedIds: ids => { for (const factId of ids) this.detLeadConsumed.delete(factId) },
    })
    this.detLeadConsumed.clear()
    this.warm.clear()
    this.overlappedFloorAssignmentIds.clear()
    this.personaAuth.stopAll()
    if (this.ownsLabRunner) {
      await this.labRunner.stopAll().catch(() => undefined)
    } else {
      await Promise.allSettled(labRunIds.map(runId => this.labRunner.stopLabTarget(runId)))
    }
    await this.canaryBroker.stopListener().catch(() => undefined)
    const releaseGuard = this.releaseRejectionGuard
    this.releaseRejectionGuard = null
    try { releaseGuard?.() } catch { /* ignore */ }
  }

  getLabTargetHandle(runId: string): LabTargetHandle | undefined {
    return this.startedLabHandles.get(runId)
  }

  /**
   * Best-effort checkpoint notification. Checkpoints are boundary-only and must never run inside
   * an open SQLite transaction (VACUUM INTO), so callers invoke this after their transaction.
   */
  private notifyCheckpoint(runId: string, checkpoint: ExecutionCheckpoint) {
    // When Phase A deterministic floor is still in flight (e.g. overlapped with code_audit), defer
    // `post-floor` until `startDeterministicLane` settles so snapshots capture completed floor.
    if (checkpoint === 'post-floor' && this.agenticLaneJobs.has(runId)) return
    this.traceLifecycle(runId, 'checkpoint', { checkpoint })
    if (!this.onCheckpoint) return
    try {
      this.onCheckpoint({ runId, checkpoint })
    } catch { /* snapshot capture is best-effort; never disturb the engine */ }
  }

  /**
   * Opt-in trace writer (v5.1 fast loop). Returns `null` unless KOVO_TRACE_DIR /
   * KOVO_TRACE enabled tracing. Never throws: a trace failure must not disturb a run.
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
        gitSha: process.env.KOVO_GIT_SHA?.trim() || 'unknown',
        app,
        seed: process.env.KOVO_BENCH_SEED ?? null,
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

  private isOverlappedFloorAssignment(runId: string, assignmentId: string): boolean {
    if (this.overlappedFloorAssignmentIds.has(assignmentId)) return true
    const lane = this.agenticLaneJobs.get(runId)
    return Boolean(lane?.allowThreatModelPhase && lane.assignmentId === assignmentId)
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
    const phaseAllowed = run.phase === current.phase
      || (
        current.phase === 'investigation'
        && run.phase === 'threat_model'
        && this.isOverlappedFloorAssignment(run.id, current.id)
      )
    return run.status === 'running' &&
      phaseAllowed &&
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
        let usedUnscopedClone = false
        const cloned = cloneWorkerPersona(
          persona,
          job.assignment.id,
          (h, wid) => {
            const scoped = this.personaAuth.cloneSession(h, wid, run.id)
            if (scoped) return scoped
            // Backwards-compatible fallback ONLY for legacy unscoped pool entries (`entry.runId === undefined`);
            // never attach a clone belonging to a different run.
            const fallback = this.personaAuth.cloneSession(h, wid)
            if (fallback && !fallback.runId) {
              usedUnscopedClone = true
              return fallback
            }
            fallback?.dispose()
            return null
          },
          h => this.personaAuth.sessions.session(h, run.id)
            ?? (usedUnscopedClone ? this.personaAuth.sessions.session(h) : null),
        )
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
    const readLiveMaxRpsPerOrigin = (): number => {
      try {
        return this.storage.run(run.id)?.maxRpsPerOrigin ?? run.maxRpsPerOrigin
      } catch {
        return run.maxRpsPerOrigin
      }
    }

    const grant: Grant = {
      tier: run.capabilityTier,
      tenantId: project.tenantId,
      get maxRpsPerOrigin() {
        return readLiveMaxRpsPerOrigin()
      },
      getMaxRpsPerOrigin: readLiveMaxRpsPerOrigin,
      allowLocalLab,
      personas,
      secrets,
      ...(project.sandboxWriteAllowlist?.length ? { sandboxWriteAllowlist: project.sandboxWriteAllowlist } : {}),
      // Second-order canary scanning needs both the store and the minting broker; without these
      // the broker/browser silently skip `scanSecondOrderMarkers`.
      storage: this.storage,
      canaryBroker: this.canaryBroker,
      scopeRevision: run.scopeRevision,
      // v6 Layer-1: every request is evaluated against the run's 3-tier origin policy, and an
      // explicit operator lease (never a body-hash token) authorizes an otherwise-refused route.
      scopePolicy: this.storage.scopePolicy(run),
      approvalPolicy: run.approvalPolicy,
      // Explicit operator leases authorize otherwise-refused routes for long-lived engagements.
      // Ephemeral local labs keep the exact single-use fingerprint ledger authoritative, so a
      // consumed instance can never be replayed.
      approvalLeases: (origin, method, pathAndQuery, personaHandle) => {
        if (project.environment === 'local-lab') return false
        return this.storage.approvalLeaseAuthorizer(run.id)(origin, method, pathAndQuery, personaHandle)
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
          allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1' &&
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
      audit: (outcome, origin, status, meta) => {
        if (outcome === 'allowed') job.origins.add(origin)
        const ctrl = this.phaseBControllers.get(run.id)
        if (ctrl && outcome === 'observed' && typeof status === 'number') ctrl.recordTargetOutcome(status)
        if (ctrl && outcome === 'circuit_open') ctrl.recordPressure('target_503')
        let host = origin
        try { host = new URL(origin).hostname } catch { /* keep raw origin */ }
        const auditSecrets = currentSecrets()
        const scrubMeta = (value: string | undefined, maxLen: number): string | undefined => {
          if (typeof value !== 'string') return undefined
          const cleaned = redact(value, auditSecrets).replace(/[\r\n\0]+/g, ' ').trim()
          if (!cleaned) return undefined
          return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen)}…` : cleaned
        }
        const reason = scrubMeta(meta?.reason, 512)
        const method = scrubMeta(meta?.method, 32)
        const path = scrubMeta(meta?.path, 512)
        const persona = scrubMeta(meta?.persona, 128)
        let message = `Broker ${outcome} for ${host}${status ? ` (${status})` : ''}.`
        if (outcome === 'denied' && (reason || method || path)) {
          const targetPart = method && path
            ? `${method} ${path} on ${host}`
            : method
              ? `${method} on ${host}`
              : path
                ? `${path} on ${host}`
                : `for ${host}`
          message = reason
            ? `Broker denied ${targetPart} (${reason})`
            : `Broker denied ${targetPart}.`
        }
        this.storage.event(run.id, 'broker.' + outcome, message, {
          assignmentId: job.assignment.id,
          origin,
          status,
          ...(reason !== undefined ? { reason } : {}),
          ...(method !== undefined ? { method } : {}),
          ...(path !== undefined ? { path } : {}),
          ...(persona !== undefined ? { persona } : {}),
        })
        if (outcome === 'circuit_open') {
          const fresh = this.storage.run(run.id)
          // A `circuit_open` audit also fires for *route-scoped* 5xx cooldowns (a single endpoint
          // returning 5xx, often the target's own response to an approved injection probe). Those
          // are evidence, not target unavailability: only an origin-wide trip may block traffic or
          // pause the run. Pausing on a route trip abandoned planned steps for the rest of the wall clock.
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
          if (fresh.status === 'running' && (action === 'pause_run' || action === 'block_origin')) {
            if (action === 'pause_run') {
              this.storage.setStatus(fresh, 'paused')
            } else {
              for (const st of this.storage.listChainSteps(run.id, fresh.goalRevision)) {
                if ((st.status === 'pending' || st.status === 'ready') &&
                    st.sourceOrigins.length > 0 &&
                    st.sourceOrigins.every(o => o === origin || this.broker.isCircuitOpen(o))) {
                  this.storage.updateChainStep(st.id, { status: 'blocked' })
                }
              }
            }
            const notifyKey = `${run.id}:${origin}`
            if (!this.circuitNotified.has(notifyKey)) {
              this.circuitNotified.add(notifyKey)
              this.storage.message(run.id, fresh.coordinatorId, 'kovo',
                action === 'pause_run'
                  ? `Defensive circuit breaker opened for ${origin} due to elevated 5xx/429 responses. Run paused to protect target availability.`
                  : `Defensive circuit breaker opened for ${origin} due to elevated 5xx/429 responses. Further traffic to ${origin} is blocked while healthy hosts continue.`)
              this.postBrokerBlocker(fresh, origin, status)
            }
          }
        }
      },
    }
    if (run.capabilityTier >= 1) {
      bindScopedBrowserToGrant(grant, this.browser)
      registerScopedBrowserForRun(run.id, this.browser)
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

  // --- Delegators preserved for tests & source-level wiring assertions ---------
  private shouldCoordinatorAnswer(content: string): boolean { return this.board.shouldCoordinatorAnswer(content) }
  private postCoordinatorBrief(run: Run, step: ChainStep, handle: string, origins: readonly string[]): BoardMessageRow | null { return this.board.postCoordinatorBrief(run, step, handle, origins) }
  private postVerificationVerdict(run: Run, opts: Parameters<ExecBoardManager['postVerificationVerdict']>[1]): BoardMessageRow | null { return this.board.postVerificationVerdict(run, opts) }
  private postBrokerBlocker(run: Run, origin: string, status?: number): BoardMessageRow | null { return this.board.postBrokerBlocker(run, origin, status) }
  private postApprovalCard(run: Run, assignmentId: string, input: Parameters<ExecBoardManager['postApprovalCard']>[2], secrets: readonly NamedSecret[] = []): BoardMessageRow | null { return this.board.postApprovalCard(run, assignmentId, input, secrets) }
  private postApprovalResolution(run: Run, assignmentId: string, input: Parameters<ExecBoardManager['postApprovalResolution']>[2]): void { this.board.postApprovalResolution(run, assignmentId, input) }
  private postCanaryLead(run: Run, input: Parameters<ExecBoardManager['postCanaryLead']>[1]): BoardMessageRow | null { return this.board.postCanaryLead(run, input) }
  private boardTurnDelta(run: Run, handle: string, lastReadSeq: number): { text: string; cursor: number } { return this.board.boardTurnDelta(run, handle, lastReadSeq) }
  private syncBoardRoster(run: Run): void { this.board.syncBoardRoster(run) }
  private routeOperatorBoardMessages(run: Run): void { this.board.routeOperatorBoardMessages(run) }

  private deriveDeterministicRouteTargets(...a: Parameters<ExecFloorLane['deriveDeterministicRouteTargets']>) { return this.floorLane.deriveDeterministicRouteTargets(...a) }
  private runDeterministicInvestigation(...a: Parameters<ExecFloorLane['runDeterministicInvestigation']>) { return this.floorLane.runDeterministicInvestigation(...a) }
  private runEngineInvestigation(...a: Parameters<ExecFloorLane['runEngineInvestigation']>) { return this.floorLane.runEngineInvestigation(...a) }
  private persistDeterministicConfirmed(...a: Parameters<ExecFloorLane['persistDeterministicConfirmed']>) { return this.floorLane.persistDeterministicConfirmed(...a) }
  private persistDeterministicLead(...a: Parameters<ExecFloorLane['persistDeterministicLead']>) { return this.floorLane.persistDeterministicLead(...a) }

  private persistReceiptFinding(...a: Parameters<ExecVerifier['persistReceiptFinding']>) { return this.verifier.persistReceiptFinding(...a) }
  private verifyReplaySpecJob(...a: Parameters<ExecVerifier['verifyReplaySpecJob']>) { return this.verifier.verifyReplaySpecJob(...a) }
  private persistAgentScriptProof(...a: Parameters<ExecVerifier['persistAgentScriptProof']>) { return this.verifier.persistAgentScriptProof(...a) }
  private executeInlineVerification(...a: Parameters<ExecVerifier['executeInlineVerification']>) { return this.verifier.executeInlineVerification(...a) }
  private baselineFinding(...a: Parameters<ExecVerifier['baselineFinding']>) { return this.verifier.baselineFinding(...a) }

  private coordinatorDeps(...a: Parameters<ExecReconPlanner['coordinatorDeps']>) { return this.reconPlanner.coordinatorDeps(...a) }
  private dispatchChainRound(...a: Parameters<ExecReconPlanner['dispatchChainRound']>) { return this.reconPlanner.dispatchChainRound(...a) }
  private runChainPlanner(...a: Parameters<ExecReconPlanner['runChainPlanner']>) { return this.reconPlanner.runChainPlanner(...a) }
  private alreadyConfirmedRefs(...a: Parameters<ExecReconPlanner['alreadyConfirmedRefs']>) { return this.reconPlanner.alreadyConfirmedRefs(...a) }
  private detLeadSummaries(...a: Parameters<ExecReconPlanner['detLeadSummaries']>) { return this.reconPlanner.detLeadSummaries(...a) }
  private stepRepeatsConfirmedWork(...a: Parameters<ExecReconPlanner['stepRepeatsConfirmedWork']>) { return this.reconPlanner.stepRepeatsConfirmedWork(...a) }
  private queueTierALeadSteps(...a: Parameters<ExecReconPlanner['queueTierALeadSteps']>) { return this.reconPlanner.queueTierALeadSteps(...a) }
  private queueDetLeadUpgradeSteps(...a: Parameters<ExecReconPlanner['queueDetLeadUpgradeSteps']>) {
    this.activeDetLeadRunId = a[0].id
    try {
      return this.reconPlanner.queueDetLeadUpgradeSteps(...a)
    } finally {
      this.activeDetLeadRunId = null
    }
  }
  private assignmentBriefForStep(...a: Parameters<ExecReconPlanner['assignmentBriefForStep']>) { return this.reconPlanner.assignmentBriefForStep(...a) }

  /** Return (or lazily create) the single run-scoped Layer-1 DerivedCapabilityVault shared across all workers. */
  capabilityVaultFor(runId: string): DerivedCapabilityVault {
    let vault = this.capabilityVaults.get(runId)
    if (!vault) {
      const safeRunId = /^[A-Za-z0-9._-]{1,128}$/.test(runId)
        ? runId
        : runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
      const persistPath = existsSync(this.storage.directory)
        ? join(this.storage.directory, 'capability-vaults', `${safeRunId}.json`)
        : undefined
      vault = new DerivedCapabilityVault({
        runId: safeRunId,
        ...(persistPath ? { persistPath } : {}),
      })
      this.capabilityVaults.set(runId, vault)
    }
    return vault
  }

  /** Return the run-scoped v8 FrontierWaveController bound to Store's CapabilityLedger. */
  frontierControllerFor(runId: string): FrontierWaveController {
    return this.reconPlanner.frontierControllerFor(runId)
  }

  /**
   * Record a negative-edge settlement (`invariant_enforced_hardened` | `control_blocked_cleanly` |
   * `decoy_guard_verified`) into `CapabilityLedger` and `FrontierWaveController` so dead-end
   * branches prune after 2 strikes and sibling workers skip re-probing them.
   */
  recordNegativeEdgeCoverage(...a: Parameters<ExecWorkerRunner['recordNegativeEdgeCoverage']>) {
    return this.workerRunner.recordNegativeEdgeCoverage(...a)
  }

  /**
   * Scan a brokered HTTP exchange (response body + headers) for second-order canary markers.
   * Runs in Execution (not only inside RequestBroker) so injected/custom brokers are covered too.
   */
  /** SQLite endpoint-parameter and API-dependency catalog, resolved to route/method display keys. */
  private endpointGraphCatalog(runId: string) {
    const byId = new Map(this.storage.listEndpoints(runId, { limit: 2000 }).map(ep => [ep.id, ep]))
    const endpointParams = this.storage.listEndpointParams(runId).slice(0, 400).map(param => {
      const ep = byId.get(param.endpointId)
      return {
        endpoint: ep ? `${ep.method} ${ep.pathTemplate}` : param.endpointId,
        origin: ep?.origin ?? '', method: ep?.method ?? '', name: param.name, location: param.location,
        inferredType: param.inferredType, isCsrf: param.isCsrf, isObjectId: param.isObjectId, source: param.source,
      }
    })
    const apiDependencies = this.storage.listApiDependencies(runId).slice(0, 200).map(dep => {
      const producer = byId.get(dep.producerEndpointId)
      const consumer = byId.get(dep.consumerEndpointId)
      return {
        producer: producer ? `${producer.method} ${producer.pathTemplate}` : dep.producerEndpointId,
        consumer: consumer ? `${consumer.method} ${consumer.pathTemplate}` : dep.consumerEndpointId,
        ...(producer?.origin ? { producerOrigin: producer.origin } : {}),
        ...(consumer?.origin ? { consumerOrigin: consumer.origin } : {}),
        resourceKey: dep.resourceKey, personaHandle: dep.personaHandle, testedBola: dep.testedBola,
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

  private planTier3Approval(...a: Parameters<RunTier3ApprovalCoordinator['planTargets']>) {
    return this.tier3Approvals.planTargets(...a)
  }

  private executeApprovedRaceBurst(...a: Parameters<RunTier3ApprovalCoordinator['executeApprovedRaceBurst']>) {
    return this.tier3Approvals.executeApprovedRaceBurst(...a)
  }

  private executeApprovedBatch(...a: Parameters<RunTier3ApprovalCoordinator['executeApprovedBatch']>) {
    return this.tier3Approvals.executeApprovedBatch(...a)
  }

  private waitForTier3Approval(...a: Parameters<RunTier3ApprovalCoordinator['waitForTier3Approval']>) {
    return this.tier3Approvals.waitForTier3Approval(...a)
  }

  private reconcileSettledApprovalWorkers(run: Run): void {
    this.tier3Approvals.reconcileSettledApprovalWorkers(run)
  }

  // --- Event-Driven Scheduler ---

  wake() {
    if (this.stopped) return
    // 0. Mirror roster state and retire warm members on stop/scope revocation.
    this.board.syncTrackedRuns()

    // 1. Revoke/abort any active job that lost authorization
    for (const [id, job] of [...this.active.entries()]) {
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
      this.active.delete(id)
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
    // is no longer authorized. Tracked via maintenanceTasks; Phase-3 gates on the settle promise.
    for (const [runId, lane] of this.agenticLaneJobs) {
      try {
        const current = this.storage.run(runId)
        const active = current.status === 'running'
          && (current.phase === 'investigation' || (Boolean(lane.allowThreatModelPhase) && current.phase === 'threat_model'))
        if (!active) this.trackMaintenance(this.abortAgenticLane(current, 'run left investigation'))
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

    // Tear down LabRunner containers and dispose RunActors/RunContexts for runs no longer active
    const trackedRunIds = new Set<string>([
      ...this.actors.keys(),
      ...this.startedLabRuns,
      ...this.capabilityVaults.keys(),
    ])
    for (const runId of trackedRunIds) {
      try {
        const current = this.storage.run(runId)
        if (current.status === 'complete' || current.status === 'failed' || current.status === 'stopped' || current.phase === 'complete') {
          if ((current.status === 'complete' || current.phase === 'complete') && this.hasActiveRetest(runId)) {
            continue
          }
          const terminalState: TerminalRunActorState =
            current.status === 'failed' ? 'failed'
              : current.status === 'stopped' ? 'canceled'
                : 'completed'
          this.evictCapabilityVault(runId)
          this.scheduleRunDisposal(runId, terminalState, `run ${current.status}`)
        } else {
          const actor = this.actors.get(runId)
          if (actor && !actor.isTerminal && actor.state !== 'stopping') {
            const targetState = deriveRunActorState(current)
            actor.reconcileWithPersisted(targetState, `wake:${current.status}:${current.phase}`)
          }
        }
      } catch {
        this.evictCapabilityVault(runId)
        this.scheduleRunDisposal(runId, 'canceled', 'run unavailable')
      }
    }

    // 2. Dispatch pending one-click Verify Fix retests (works even on completed runs, Zero-LLM!)
    for (const run of this.storage.runsWithPendingRetests()) {
      const tenantId = this.runTenantId(run)
      if (this.runtime.killSwitch.isActive(tenantId)) continue
      const draining = this.disposingRuns.get(run.id)
      if (draining) {
        this.trackMaintenance(draining.finally(() => this.scheduleWake()))
        continue
      }
      const existingActor = this.actors.get(run.id)
      if (existingActor && (existingActor.isDisposed || existingActor.isTerminal || existingActor.state === 'stopping' || existingActor.signal.aborted)) {
        if (!existingActor.context.isDisposed) {
          this.trackMaintenance(
            this.scheduleRunDisposal(run.id, 'canceled', 'reset actor before retest').finally(() => this.scheduleWake()),
          )
          continue
        }
        this.actors.delete(run.id)
      }
      const existingCtx = this.runtime.getRunContext(run.id)
      if (existingCtx && (existingCtx.isAborted || existingCtx.isDraining) && !existingCtx.isDisposed) {
        this.trackMaintenance(
          this.scheduleRunDisposal(run.id, 'canceled', 'reset aborted context before retest').finally(() => this.scheduleWake()),
        )
        continue
      }
      const retests = this.storage.workerList(run.id).filter(w => w.phase === 'retest' && w.status === 'queued')
      for (const worker of retests) {
        if (this.active.has(worker.id)) continue
        this.startRetestWorker(run, worker)
      }
    }

    // 3. Process runnable runs
    const profiles = privateModelProfiles(this.storage)
    for (const run of this.storage.runnable()) {
      const tenantId = this.runTenantId(run)
      if (this.runtime.killSwitch.isActive(tenantId)) {
        try {
          if (run.status === 'running') {
            this.storage.updateRun(run.id, { status: 'paused' })
            this.safeEvent(run.id, 'run.kill_switch_paused', 'Run paused because emergency kill switch is active.', {
              tenantId,
            })
          }
        } catch { /* run may be gone */ }
        this.scheduleRunDisposal(run.id, 'canceled', 'kill switch tripped')
        continue
      }
      const draining = this.disposingRuns.get(run.id)
      if (draining) {
        this.trackMaintenance(draining.finally(() => this.scheduleWake()))
        continue
      }
      const existingActor = this.actors.get(run.id)
      if (existingActor && (existingActor.isDisposed || existingActor.isTerminal || existingActor.state === 'stopping' || existingActor.signal.aborted)) {
        if (!existingActor.context.isDisposed) {
          this.trackMaintenance(
            this.scheduleRunDisposal(run.id, 'canceled', 'reset actor on resume').finally(() => this.scheduleWake()),
          )
          continue
        }
        this.actors.delete(run.id)
      }
      const existingCtx = this.runtime.getRunContext(run.id)
      if (existingCtx && (existingCtx.isAborted || existingCtx.isDraining) && !existingCtx.isDisposed) {
        this.trackMaintenance(
          this.scheduleRunDisposal(run.id, 'canceled', 'reset aborted context on resume').finally(() => this.scheduleWake()),
        )
        continue
      }
      const actor = this.ensureRunActor(run)
      const desiredState = deriveRunActorState(run)
      actor.reconcileWithPersisted(desiredState, `runnable:${run.status}:${run.phase}`)
      this.ensureEffectiveConfigRecorded(run, profiles)
      if (this.storage.checkBudgetExceeded(run.id)) continue
      this.ensureVariantSweepsForConfirmedFindings(run)
      this.routeOperatorBoardMessages(run)

      if (profiles.length) {
        this.reconPlanner.startCoordinator(run, profiles)
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

  private ensureEffectiveConfigRecorded(run: Run, profiles: readonly ResolvedModelProfile[]): void {
    try {
      const existing = this.storage.client.prepare(
        `SELECT 1 FROM events WHERE run_id = ? AND kind = 'run.effective_config' LIMIT 1`,
      ).get(run.id)
      if (existing) return
    } catch {
      return
    }
    const scopePolicy = (() => {
      try { return this.storage.scopePolicy(run) } catch { return { mode: 'ephemeral_lab' as const } }
    })()
    const environment = (() => {
      try { return this.storage.project(run.projectId).environment } catch { return scopePolicy.mode === 'ephemeral_lab' ? 'local-lab' : 'public' }
    })()
    const wordlistOn = conventionalWordlistEnabled()
    const conventionalEndpointsProbed = (() => {
      try {
        const row = this.storage.client.prepare(
          `SELECT COUNT(*) AS cnt FROM endpoints WHERE run_id = ? AND source = 'conventional'`,
        ).get(run.id) as { cnt?: number } | undefined
        return Number(row?.cnt ?? 0)
      } catch {
        return 0
      }
    })()
    const resolvedReceiptMode = (() => {
      try { return proofReceiptMode() } catch { return (process.env.KOVO_PROOF_RECEIPT ?? 'strict').trim().toLowerCase() || 'strict' }
    })()
    const siblings = /^(?:1|true|on|yes)$/i.test((process.env.KOVO_RECON_SIBLINGS ?? '').trim())
    const runMaxDuration = Number((run as { maxDurationMs?: number }).maxDurationMs)
    const effectiveMaxDurationMs = Number.isFinite(runMaxDuration) && runMaxDuration > 0
      ? runMaxDuration
      : this.maxDurationMs
    const floorDurationMs = this.deterministicOnly
      ? defaultEngineMaxDurationMs
      : this.deterministicLaneDeadlineMs(run)
    const floorRequestCap = this.phaseRequestBudgets?.floor ?? Math.min(defaultEngineMaxRequests, run.budgetRequests)
    const floorPolicy = this.deterministicOnly
      ? 'no_llm_240s'
      : scopePolicy.mode === 'staging_isolated'
        ? 'staging_isolated'
        : 'phase_a_12pct_cap_75s'
    const modelProfileId = this.deterministicOnly ? null : (profiles[0]?.id ?? null)
    const backendImage = (this.backend as { image?: unknown } | undefined)?.image
    const workerImageId = this.backend instanceof LinuxWorkerBackend
      ? (typeof backendImage === 'string' && backendImage.trim()
          ? backendImage.trim()
          : (process.env.KOVO_WORKER_IMAGE?.trim() || 'kovo-worker:v4'))
      : null
    this.safeEvent(
      run.id,
      'run.effective_config',
      `Effective run config recorded (env=${environment}/${scopePolicy.mode}, tier=${run.capabilityTier}, wordlist=${wordlistOn ? 'on' : 'off'}, floor=${Math.round(floorDurationMs / 1000)}s, sdk=${VERIFY_RPC_SDK_VERSION}).`,
      {
        environment,
        environmentMode: scopePolicy.mode,
        tier: run.capabilityTier,
        approvalPolicy: run.approvalPolicy ?? 'auto_review',
        deterministicOnly: this.deterministicOnly,
        wordlistOn,
        conventionalEndpointsProbed,
        proofReceiptMode: resolvedReceiptMode,
        siblings,
        floorDurationMs,
        floorWallMarginMs: deterministicWallMarginMs,
        maxDurationMs: effectiveMaxDurationMs,
        floorRequestCap,
        floorPolicy,
        modelProfileId,
        workerImageId,
        sdkVersion: VERIFY_RPC_SDK_VERSION,
      },
    )
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

    const spawned = this.spawnRunTask(run.id, 'persona-auth', async signal => {
      try {
        await this.personaAuth.startRunRefreshers(
          this.storage,
          run.id,
          run.projectId,
          run.approvedPersonaIds,
          signal,
        )
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
      } catch (error) {
        this.personaAuth.stopRunRefreshers(run.id)
        if (signal.aborted) return
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
              'kovo',
              `Paused run because Email + Password persona authentication failed: ${msg}`,
            )
          })
        } catch {
          // Ignore if run/storage closed
        }
      } finally {
        this.runAuthInFlight.delete(run.id)
        this.scheduleWake()
      }
    }, { controller })
    if (!spawned.started) {
      this.runAuthInFlight.delete(run.id)
    }
  }

  // --- Phase 1: Round-0 Threat Model & Initial Baseline Checks ---

  private startThreatModel(run: Run, profiles: readonly ResolvedModelProfile[]) {
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.threatModeling.set(run.id, task)
    const spawned = this.spawnRunTask(run.id, 'threat-model', async () => {
      try {
        await this.reconPlanner.runThreatModel(run, profiles, task)
      } catch (error) {
        if (!this.currentCoordinator(run.id, task)) return
        const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
        this.storage.transaction(() => {
          const current = this.storage.run(run.id)
          this.storage.setStatus(current, 'failed')
          this.storage.event(run.id, 'threat_model.failed', `Threat modeling failed: ${msg}`)
          this.storage.writeReport(this.storage.run(run.id), true)
        })
      } finally {
        this.threatModeling.delete(run.id)
        this.scheduleWake()
      }
    }, { controller })
    if (!spawned.started) {
      this.threatModeling.delete(run.id)
    }
  }

  /** Correlate dependencies from uploaded/synced specs via the CVE broker (curated + remote). */
  private async correlateSpecDependencies(
    freshRun: Run,
    claimed: Assignment,
    specs: ReturnType<Store['listProjectSpecsFull']>,
    approvedOrigins: ReadonlySet<string>,
    defaultOrigin: string | undefined,
    signal: AbortSignal,
    secrets: readonly NamedSecret[],
  ): Promise<void> {
    const seenDeps = new Set<string>()
    let advisoryLookups = 0
    for (const spec of specs) {
      const deps = parseDependenciesFromFile(spec.name.split(':').pop() ?? spec.name, spec.content)
      for (const match of spec.content.matchAll(/^([a-zA-Z0-9_.-]+):([@a-zA-Z0-9_./-]+)@([0-9][0-9A-Za-z.+-]*)/gm)) {
        deps.push({ ecosystem: match[1], package: match[2], version: match[3], sourceFile: spec.name })
      }
      for (const dep of deps) {
        if (!dep.package || !dep.version) continue
        const key = `${dep.ecosystem}:${dep.package}:${dep.version}`
        if (seenDeps.has(key)) continue
        seenDeps.add(key)
        if (advisoryLookups >= 120) break
        advisoryLookups += 1
        try {
          const advisories = await queryCves({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version }, signal)
          const curated = hasCuratedAdvisory(dep.ecosystem, dep.package)
          for (const adv of advisories.slice(0, 3)) {
            const targetOrigin = spec.origin && approvedOrigins.has(spec.origin) ? spec.origin : defaultOrigin
            if (!targetOrigin) continue
            this.storage.addFact(freshRun, claimed, {
              kind: 'cve_hypothesis',
              origin: targetOrigin,
              summary: `${adv.id} (${adv.severity}) hypothesis for ${dep.package}@${dep.version} from ${spec.name}: ${adv.summary}`,
              data: {
                cveId: adv.id, package: dep.package, version: dep.version, ecosystem: dep.ecosystem,
                severity: adv.severity, safeVerificationHint: adv.safeVerificationHint,
                sourceSpec: spec.name, curatedAdvisory: curated, confidence: 'low',
              },
              sourceOrigins: [targetOrigin],
              secrets,
            })
          }
        } catch { /* advisory lookup is best-effort */ }
      }
    }
  }

  private buildSharedSessionHandlers(...a: Parameters<ExecWorkerRunner['buildSharedSessionHandlers']>) {
    return this.workerRunner.buildSharedSessionHandlers(...a)
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

    const runMaxDuration = Number((run as { maxDurationMs?: number }).maxDurationMs)
    const effectiveMaxDurationMs = Number.isFinite(runMaxDuration) && runMaxDuration > 0
      ? runMaxDuration
      : this.maxDurationMs
    const auditWallMs = resolveSourceAuditWallClockMs(effectiveMaxDurationMs)
    const auditSettlementMs = resolveSourceAuditSettlementMs(auditWallMs)
    // The agent-session's own 80% wall-clock nudge remains the hard per-session settlement; the
    // code-audit prompt above fires earlier (60%) so suspects land before the slot rotates.
    const sessionSettlementMs = Math.min(Math.floor(auditWallMs * 0.8), wallClockSettlementMs(auditWallMs))
    const semanticTimeoutMs = Math.min(35_000, Math.floor(auditWallMs * 0.45))
    const auditMaxTurns = resolveSourceAuditMaxTurns(run.workerMaxTurns, effectiveMaxDurationMs)
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
    this.storage.event(run.id, 'code_audit.started', `Source-First Code Audit started across ${mountedRepos.length} mounted ${mountedRepos.length === 1 ? 'repo' : 'repos'} (wall cap ${Math.round(auditWallMs / 1000)}s, max ${auditMaxTurns} turns).`, {
      assignmentId: claimed.id, mountedRepos, auditWallMs,
      auditSettlementMs: sessionSettlementMs,
      codeAuditSettlementMs: auditSettlementMs,
      semanticTimeoutMs, auditMaxTurns,
    })

    // Overlap Phase A: start deterministic floor concurrently with `--network none` code_audit
    // (0 target HTTP requests, preserving split `floor_settled` accounting). Phase B still waits.
    if (!controller.signal.aborted) {
      try { this.ensureRunTrace(run, profiles) } catch { /* tracing is best-effort */ }
      this.startDeterministicLane(run, profiles, { allowThreatModelPhase: true })
    }

    const { grant, secrets, currentSecrets } = this.buildGrant(job, run, approvedOrigins)
    const session = await this.backend.openSession(claimed.id, controller.signal, { reposDir, runId: run.id })
    const startedAt = Date.now()
    let codeAuditSettlementPrompted = false
    let semanticSuspects: SemanticAuditSuspect[] = []

    try {
      const stagedSpecs = await this.stageProjectSpecs(run.projectId, session, controller.signal)
      const staticSnapshot = await buildStaticWorkspaceSnapshotInWorker(reposDir, {
        mountedRepos,
        signal: controller.signal,
        workerTimeoutMs: Math.min(15_000, Math.max(2_000, Math.floor(auditWallMs * 0.25))),
      })
      const workspaceDigest = buildWorkspaceSourceDigest(staticSnapshot, MAX_WORKSPACE_DIGEST_BYTES)
      const digestStagedPath = await session.stage('workspace-source-digest.md', workspaceDigest, controller.signal).catch(() => null)
      const auditSpecsSummary: Array<{ name: string; kind: string; origin?: string | null; stagedPath?: string; digest?: string }> = [
        ...stagedSpecs,
        {
          name: 'Pre-Indexed Multi-Service Route, Authz Guard & Sink Digest',
          kind: 'workspace_source_digest',
          origin: [...approvedOrigins][0] ?? null,
          ...(digestStagedPath ? { stagedPath: digestStagedPath } : {}),
          digest: workspaceDigest,
        },
      ]
      const handlers: WorkerToolHandlers = this.buildSharedSessionHandlers(job, session, currentSecrets, {
        offlineScriptLabel: 'Offline {runtime} script (code audit)',
        deriveEvidenceTitle: 'Code audit analysis',
      })

      const personasPub = publicPersonasFromGrant(grant)

      // Stage 1-3 deterministic + semantic code audit pipeline (IRIS + call-graph + git history)
      // Bounded by `semanticTimeoutMs` so Stage 1-3 leaves budget for interactive audit + Phase B.
      const semanticController = new AbortController()
      const onAuditAbortForSemantic = () => semanticController.abort(controller.signal.reason)
      controller.signal.addEventListener('abort', onAuditAbortForSemantic, { once: true })
      if (controller.signal.aborted) semanticController.abort(controller.signal.reason)
      let semanticTimer: NodeJS.Timeout | undefined
      try {
        const hostTiersForAudit = computeHostTiers([...approvedOrigins], threatModel)
        const semanticPromise = runThreeStageSemanticAudit({
          storage: this.storage,
          run,
          assignment: claimed,
          backend: this.backend,
          session,
          reposDir,
          mountedRepos,
          staticSnapshot,
          approvedOrigins: [...approvedOrigins],
          hostTiers: hostTiersForAudit,
          modelProfiles: resolveProfilePoolForRole('reasoning', profiles),
          signal: semanticController.signal,
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
          // Budgeted Stage-1 LLM spec + dynamic rule synthesis; opt out with KOVO_STAGE1_LLM=0.
          enableStage1Llm: process.env.KOVO_STAGE1_LLM !== '0',
          persistToStore: true,
          staticSnapshot,
        })
        semanticPromise.catch(() => undefined)
        const semanticTimeout = new Promise<never>((_, reject) => {
          semanticTimer = setTimeout(() => {
            const err = new Error(`Semantic audit sub-timeout reached (${semanticTimeoutMs}ms).`)
            semanticController.abort(err)
            reject(err)
          }, semanticTimeoutMs)
          semanticTimer.unref?.()
        })
        const semanticRes = await Promise.race([semanticPromise, semanticTimeout])
        semanticSuspects = semanticRes.rankedSuspects
        const semanticSteps = toChainStepInputs(run, semanticRes.rankedSuspects, hostTiersForAudit, semanticRes.persistedFactIds)
        const existingTitles = new Set(this.storage.listChainSteps(run.id, run.goalRevision).map(s => s.title.trim().toLowerCase()))
        for (const stInput of semanticSteps) {
          const key = stInput.title.trim().toLowerCase()
          if (existingTitles.has(key)) continue
          this.storage.addChainStep(run, stInput)
          existingTitles.add(key)
        }
      } catch {
        // Semantic audit is additive and sub-timeout bounded; continue with interactive code auditor session
      } finally {
        if (semanticTimer) clearTimeout(semanticTimer)
        controller.signal.removeEventListener('abort', onAuditAbortForSemantic)
      }

      const preInteractiveSuspectIds = new Set(
        this.storage.listFacts(run.id, { includeTainted: false, limit: 500 })
          .map(fact => fact.id),
      )
      const remainingAuditWallMs = Math.max(0, auditWallMs - Math.max(0, Date.now() - startedAt))
      const sessionResult = remainingAuditWallMs > 2_000 && !controller.signal.aborted
        ? await runAgentSession({
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
              specsSummary: auditSpecsSummary,
              threatModel,
              maxTurns: auditMaxTurns,
            }),
            signal: controller.signal,
            maxTurns: auditMaxTurns,
            wallClockMs: remainingAuditWallMs,
            compaction: true,
            enableSettlement: true,
            requireCompleteIntent: true,
            shouldSettle: () => (Date.now() - startedAt) >= auditSettlementMs,
            onWallClockRotate: info => {
              this.safeEvent(run.id, 'code_audit.wall_clock_rotated',
                `Source-First Code Audit rotated cleanly at wall-clock budget (${Math.round(info.elapsedMs / 1000)}s / ${Math.round(auditWallMs / 1000)}s, ${info.turnsUsed} turn(s)).`,
                { assignmentId: claimed.id, auditWallMs, auditSettlementMs, ...info })
            },
            handlers,
            secrets,
            beforeCall: () => {
              this.check(job)
              if (this.storage.checkBudgetExceeded(run.id)) {
                throw new BudgetExceededError('Run spend or request budget exceeded.')
              }
            },
            ...llmRunHooks(this.storage, run.id),
            onTurn: turn => {
              this.storage.updateWorker(claimed.id, { turnsUsed: turn })
              this.storage.recordLlmSpend(run.id, { turns: 1 })
            },
            onTurnStart: () => {
              if (codeAuditSettlementPrompted) return
              if (Date.now() - startedAt < auditSettlementMs) return
              codeAuditSettlementPrompted = true
              this.safeEvent(run.id, 'code_audit.settlement_prompt',
                `Source-First Code Audit settlement prompt fired at ${Math.round(auditSettlementMs / 1000)}s; committing suspects instead of reading further.`,
                { assignmentId: claimed.id, auditSettlementMs })
              return { messages: [codeAuditSettlementMessage(auditSettlementMs)] }
            },
          })
        : { completion: undefined }

      const latestRun = this.storage.run(run.id)
      const settled = settleCodeAuditSuspects({
        storage: this.storage,
        run: latestRun,
        assignment: claimed,
        approvedOrigins,
        semanticSuspects,
        preInteractiveFactIds: preInteractiveSuspectIds,
        auditStartedAtMs: startedAt,
      })
      if (settled.promoted.length) {
        this.safeEvent(run.id, 'code_audit.semantic_suspects_preserved',
          `Source-First Code Audit preserved ${settled.promoted.length} semantic-audit suspect(s) after the interactive auditor recorded none of its own.`,
          { assignmentId: claimed.id, promotedCount: settled.promoted.length, interactiveRecorded: settled.interactiveRecorded })
      }
      const suspects = settled.suspects
      const hostTiers = computeHostTiers([...approvedOrigins], threatModel)
      const stepsCreated = convertCodeAuditSuspectsToChainSteps(this.storage, latestRun, suspects, hostTiers, {
        maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS,
        promoteMultiHop: true,
      })

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
    const unavailableOrigins = this.reconPlanner.unavailableOriginsForRun(run)
    const dispatchableStepIds = new Set(dispatchableReadySteps(steps, undefined, unavailableOrigins).map(s => s.id))
    const highSignalFacts = new Set(
      this.reconPlanner.pageAll((offset, limit) =>
        this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
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
      // displace other first-pass work. Only expand genuinely dispatchable steps (`R4-H-12`/`R4-H-13`).
      steps: steps.filter(step => !this.tierAStepIds.has(step.id) && dispatchableStepIds.has(step.id)),
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
        const sibling = this.storage.addChainStep(run, {
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
        // R4-H-13: If the primary step is already `ready` (e.g. a retry or continuation step
        // whose lineage `dependsOnStepIds` points at a `turn_capped`/`rotated_partial` parent),
        // preserve `ready` on its trial sibling so the sibling is never stranded `pending`/`blocked`.
        if (step.status === 'ready' && sibling.status !== 'ready') {
          this.storage.updateChainStep(sibling.id, { status: 'ready' })
        }
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
    const spawned = this.spawnRunTask(run.id, `variant-sweep:${findingRow.id}`, async () => {
      try {
        await this.reconPlanner.runPostConfirmationVariantSweep(run, findingRow, reposDir, mountedRepos)
      } catch {
        /* best-effort variant sweep */
      } finally {
        this.variantSweepInFlight.delete(findingRow.id)
        this.variantSweptFindings.add(findingRow.id)
        this.scheduleWake()
      }
    })
    if (!spawned.started) {
      this.variantSweepInFlight.delete(findingRow.id)
    }
  }

  private deterministicLaneKey(run: Pick<Run, 'id' | 'goalRevision' | 'scopeRevision'>): string {
    return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
  }

  /** `min(75 s, 12% × maxDurationMs)` on agentic runs; `--no-llm` / deterministicOnly stays unrestricted. */
  private deterministicLaneDeadlineMs(run?: Pick<Run, 'id'>): number {
    const runMaxDuration = Number((run as { maxDurationMs?: number } | undefined)?.maxDurationMs)
    const effectiveMaxDurationMs = Number.isFinite(runMaxDuration) && runMaxDuration > 0
      ? runMaxDuration
      : this.maxDurationMs
    return resolvePhaseAFloorWallClockMs(effectiveMaxDurationMs, { hasProfiles: true }) ?? PHASE_A_FLOOR_MAX_WALL_CLOCK_MS
  }

  /** Detect whether a restored floor snapshot already populated deterministic floor results for this run. */
  private hasPreHydratedFloorSnapshot(runId: string): boolean {
    try {
      const row = this.storage.client.prepare(
        `SELECT 1 FROM events WHERE run_id = ? AND kind IN ('deterministic_engine.summary', 'deterministic_floor.summary', 'deterministic_lane.metrics') LIMIT 1`,
      ).get(runId)
      return Boolean(row)
    } catch {
      return false
    }
  }

  private shouldStartDeterministicLane(
    run: Run,
    profiles: readonly ResolvedModelProfile[],
    options: { allowThreatModelPhase?: boolean } = {},
  ): boolean {
    if (this.deterministicSweep === 'off') return false
    if (this.deterministicOnly) return false
    if (!profiles.length) return false
    const phaseAllowed = run.phase === 'investigation'
      || (Boolean(options.allowThreatModelPhase) && run.phase === 'threat_model')
    if (run.status !== 'running' || !phaseAllowed) return false
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
    if (this.deterministicSweep !== 'always' && this.hasPreHydratedFloorSnapshot(run.id)) {
      this.agenticLaneCompleted.add(key)
      this.safeEvent(
        run.id,
        'deterministic_lane.skipped',
        'Skipped redundant Phase A deterministic floor sweep: pre-hydrated floor snapshot is already loaded.',
        { reason: 'pre_hydrated_floor_snapshot', mode: this.deterministicSweep },
      )
      return false
    }
    return true
  }

  /**
   * Phase A: start the deterministic floor as the first, blocking investigation phase. It runs the
   * shared deterministic engine under the agentic Phase-A wall-clock cap (`min(75s, 12% × maxDurationMs)`
   * plus the 120s emergency margin, vs. 240s + 120s in `--no-llm` mode; `staging_isolated` uses its
   * own duration branch) with the same default request cap; agents are not dispatched until it settles.
   * Returns true when the floor is (or remains) in flight, so `driveInvestigation` yields to it.
   */
  private startDeterministicLane(
    run: Run,
    profiles: readonly ResolvedModelProfile[],
    options: { allowThreatModelPhase?: boolean } = {},
  ): boolean {
    if (!this.shouldStartDeterministicLane(run, profiles, options)) return this.agenticLaneJobs.has(run.id)
    const key = this.deterministicLaneKey(run)
    const controller = new AbortController()
    const allowThreatModelPhase = Boolean(options.allowThreatModelPhase)
    const holder = {
      controller,
      key,
      assignmentId: '',
      promise: Promise.resolve(),
      allowThreatModelPhase,
    }
    this.agenticLaneJobs.set(run.id, holder)
    this.laneStartedAt.set(run.id, Date.now())
    this.agenticFloorStartedAt.set(run.id, Date.now())
    // Phase-A allowance starts here: Phase-0 discovery/scope requests stay outside both phases.
    this.beginFloorRequestPhase(this.storage.run(run.id))
    const deadlineMs = this.deterministicLaneDeadlineMs(run)
    try {
      this.storage.event(
        run.id,
        'deterministic_lane.started',
        `Deterministic floor (Phase A) started before agents (deadline ${Math.round(deadlineMs / 1000)}s, ${Math.round(PHASE_A_FLOOR_WALL_CLOCK_SHARE * 100)}% of run wall clock).`,
        { deadlineMs, maxDurationMs: this.maxDurationMs, mode: this.deterministicSweep, sequential: true },
      )
    } catch { /* run may be gone */ }
    this.traceLifecycle(run.id, 'lane_start', { deadlineMs, maxDurationMs: this.maxDurationMs, mode: this.deterministicSweep })
    const laneTask = this.spawnRunTask(run.id, 'deterministic-floor', async signal => {
      try {
        await this.runEngineInvestigation(run, {
          signal,
          maxDurationMs: deadlineMs,
          allowThreatModelPhase,
          onAssignment: id => {
            holder.assignmentId = id
            this.agenticLaneAssignmentIds.add(id)
            if (allowThreatModelPhase) this.overlappedFloorAssignmentIds.add(id)
          },
        })
      } catch (error) {
        if (signal.aborted) return
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, 'deterministic_lane.failed', `Deterministic floor failed: ${msg}`)
        } catch { /* run may be gone */ }
      } finally {
        this.agenticLaneJobs.delete(run.id)
        this.agenticLaneStopping.delete(run.id)
        if (holder.assignmentId) this.overlappedFloorAssignmentIds.delete(holder.assignmentId)
        // M-10: do not mark Phase A completed when aborted (e.g. pause mid-floor), so resume re-runs it.
        if (!signal.aborted) {
          this.agenticLaneCompleted.add(key)
        }
        this.agenticFloorFinishedAt.set(run.id, Date.now())
        this.traceLifecycle(run.id, 'lane_end', { aborted: signal.aborted, deadlineMs })
        try { this.settleFloorRequestPhase(run.id, signal.aborted ? 'floor_aborted' : 'floor_complete') } catch { /* metrics only */ }
        try { this.recordFloorMetrics(run.id, signal.aborted ? 'floor_aborted' : 'floor_complete') } catch { /* metrics only */ }
        this.laneStartedAt.delete(run.id)
        try {
          const latest = this.storage.run(run.id)
          if (!signal.aborted && latest.status === 'running' && latest.phase === 'investigation') {
            this.notifyCheckpoint(run.id, 'post-floor')
          }
        } catch { /* run may be gone */ }
        try { this.scheduleWake() } catch { /* scheduler stopped */ }
      }
    }, { controller })
    if (!laneTask.started) {
      this.agenticLaneJobs.delete(run.id)
      this.laneStartedAt.delete(run.id)
      this.agenticFloorStartedAt.delete(run.id)
      return false
    }
    holder.promise = laneTask.promise.then(() => undefined, () => undefined)
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

  // --- v6 split request budgets & telemetry (delegated to run-actor.ts) -----------------------

  private beginFloorRequestPhase(run: Run) { return this.budgetTracker.beginPhase(run, 'floor') }
  private beginAgentRequestPhase(run: Run) { return this.budgetTracker.beginPhase(run, 'agent') }
  private settleFloorRequestPhase(runId: string, reason: string): void { this.budgetTracker.settleFloor(runId, reason) }
  private settleAgentRequestPhase(runId: string, reason: string): void { this.budgetTracker.settleAgent(runId, reason) }
  private phaseRequestRemaining(run: Run): number | null { return this.budgetTracker.remaining(run) }
  private reportAgentBudgetExhausted(run: Run, readySteps: number, activeAssignments: number): void {
    this.budgetTracker.reportAgentExhausted(run, readySteps, activeAssignments)
  }

  private recordFloorMetrics(runId: string, reason: string): void {
    recordRunFloorMetrics({
      storage: this.storage,
      safeEvent: (id, kind, msg, detail) => this.safeEvent(id, kind, msg, detail),
      laneStartedAt: this.laneStartedAt,
      laneWallByRun: this.laneWallByRun,
      agenticFloorStartedAt: this.agenticFloorStartedAt,
      agenticFloorFinishedAt: this.agenticFloorFinishedAt,
      agenticFloorDispatchedAt: this.agenticFloorDispatchedAt,
      detLeadConsumed: this.detLeadConsumed,
      detLeadConsumedByRun: this.detLeadConsumedByRun,
      requestBudgetSnapshot: (id, floorReqs) => this.budgetTracker.snapshot(id, floorReqs),
    }, runId, reason)
  }

  private recordAssignmentMetrics(runId: string, reason: string): AssignmentThroughputMetrics | null {
    return recordRunAssignmentMetrics({
      storage: this.storage,
      backend: this.backend,
      safeEvent: (id, kind, msg, detail) => this.safeEvent(id, kind, msg, detail),
      assignmentWallByRun: this.assignmentWallByRun,
      completedAssignmentWallByRun: this.completedAssignmentWallByRun,
      turnLatencyByRun: this.turnLatencyByRun,
      earlyExitTurnsSavedByRun: this.earlyExitTurnsSavedByRun,
      providerStallTurnsByRun: this.providerStallTurnsByRun,
      providerStallRetriesByRun: this.providerStallRetriesByRun,
      providerStallTimeoutsByRun: this.providerStallTimeoutsByRun,
      providerStallWallSavedByRun: this.providerStallWallSavedByRun,
      warmPoolPolicyRotationsByRun: this.warmPoolPolicyRotationsByRun,
      wallClockRotationsByRun: this.wallClockRotationsByRun,
      proofObligationByRun: this.proofObligationByRun,
      gapValidationByRun: this.gapValidationByRun,
      lastAssignmentMetrics: this.lastAssignmentMetrics,
    }, runId, reason)
  }

  /** Last recorded Phase-B throughput metrics for a run (test/benchmark seam). */
  getAssignmentThroughput(runId: string): AssignmentThroughputMetrics | null {
    return this.lastAssignmentMetrics.get(runId) ?? null
  }

  /** Live structured per-run token, prompt-cache, cost, stall, rotation & tool-bloat telemetry snapshot. */
  getRunTokenTelemetry(runId: string): RunTokenTelemetrySummary | null {
    if (!hasRunTokenTelemetry(runId)) return null
    return getRunTokenTelemetrySummary(runId)
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
      const fullRun = this.storage.run(run.id)
      const unavailableOrigins = this.reconPlanner.unavailableOriginsForRun(fullRun)
      const steps = this.storage.listChainSteps(run.id, run.goalRevision)
      return !dispatchableReadySteps(steps, undefined, unavailableOrigins).some(step =>
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
    let currentRun: Run
    try { currentRun = this.storage.run(runId) } catch { return }
    const status = currentRun.status
    const stopReason: DispatchStopReason = status === 'paused'
      ? 'run_paused'
      : status === 'stopped' ? 'run_stopped' : funnel.stopReason
    const latestSteps = this.storage.listChainSteps(runId)
    const knownFacts = new Set(this.reconPlanner.pageAll((offset, limit) =>
      this.storage.listFacts(runId, { includeTainted: true, limit, offset })).map(fact => fact.id))
    const unavailableOrigins = this.reconPlanner.unavailableOriginsForRun(currentRun)
    const remainingReady = dispatchableReadySteps(latestSteps, knownFacts, unavailableOrigins).length
    const dispatched = latestSteps.filter(step => step.assignedWorkerId !== null).length
    const blocked = permanentlyBlockedStepIds(latestSteps, knownFacts, unavailableOrigins).length
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
    const mentioned = new Set(this.reconPlanner.stepMentionedRoutes(step).map(route => normalizeEndpointTemplate(route)))
    const text = `${step.title} ${step.hypothesis}`
    const candidates = [
      ...parentFacts.filter(fact => isTrustedHostControlFact(fact, 'det_lead')),
      ...this.reconPlanner.pageAll((offset, limit) =>
        this.storage.listFacts(run.id, { includeTainted: false, limit, offset }))
        .filter(fact => isTrustedHostControlFact(fact, 'det_lead')),
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
    // M-47: Stamp explicit host planner provenance on seeded Program-Graph det_lead facts.
    const hostLeadStore = {
      addFact: (r: Run, a: Assignment, input: { kind: 'note'; origin: string; summary: string; data: Record<string, unknown> }) =>
        this.storage.addFact(r, a, {
          ...input,
          data: { ...input.data, producer: HOST_PLANNER_PRODUCER },
        }),
      event: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) =>
        this.storage.event(runId, kind, message, detail),
    }
    return seedGraphLeads(
      hostLeadStore,
      run,
      assignment,
      hypotheses,
      this.programGraphLeadsSeeded,
      [...this.approvedOriginsSet(run)].sort()[0] ?? '',
    )
  }

  private driveInvestigation(run: Run, profiles: readonly ResolvedModelProfile[]) {
    try { this.reconcileSettledApprovalWorkers(run) } catch { /* reconciliation is best-effort */ }

    if (!profiles.length) {
      // Explicit --no-llm mode runs the deterministic engine. Without that flag the legacy M1
      // no-profile fallback stays byte-for-byte unchanged; it is suppressed while any worker is
      // active or parked awaiting an operator decision (prevents deterministic-mode approval race).
      const hasLiveWorker =
        [...this.active.values()].some(j => j.assignment.runId === run.id && j.assignment.phase === 'investigation') ||
        this.storage.parkedWorkerCount(run.id) > 0
      if (this.deterministicOnly) this.driveEngineInvestigation(run)
      else if (!hasLiveWorker) this.driveDeterministicInvestigation(run)
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

    // Phase A: the deterministic floor runs sequentially *before* any agent dispatch, sharing the
    // deterministic engine under the Phase-A wall-clock cap (recorded in `run.effective_config`).
    // It is not a sibling lane: dispatch yields until it settles, so workers never race or clobber
    // floor probe state and the floor cannot be starved by specialist request/rate/budget pressure.
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
      if (!(this.detLeadConsumedByRun.get(run.id)?.size ?? 0) && this.agenticLaneCompleted.has(this.deterministicLaneKey(run))) {
        this.queueDetLeadUpgradeSteps(
          this.storage.run(run.id),
          this.approvedOriginsSet(run),
          computeDynamicStepBudget(this.storage, run.id),
        )
      }
    } catch { /* lead queueing is additive */ }

    // Wave-1 invariant chains: promote high-signal cross-surface / cross-service / entity-lifecycle
    // hypotheses into ready `chain` lane steps BEFORE Phase B's first dispatch tick.
    try {
      this.reconPlanner.ensureWave1InvariantChainSteps(
        this.storage.run(run.id),
        this.approvedOriginsSet(run),
        { postFloor: this.agenticLaneCompleted.has(this.deterministicLaneKey(run)) },
      )
    } catch { /* invariant chain promotion is additive */ }

    // R4-H-12: Route BOTH origin quarantine and circuit-open through ONE terminal-transition
    // primitive so quarantined/circuit-open steps transition to `blocked` (and restore cleanly
    // on unquarantine) + propagate `refreshReadyChainSteps` instead of stranding in `ready`.
    const approvedOriginsForDispatch = this.approvedOriginsSet(run)
    const quarantinedOriginRecords = this.reconPlanner.getQuarantinedOriginRecords(run, approvedOriginsForDispatch)
    const circuitOpenOrigins = new Set(
      [...approvedOriginsForDispatch].filter(origin => this.broker.isCircuitOpen(origin)),
    )
    const unavailableOrigins = new Set<string>([
      ...quarantinedOriginRecords.keys(),
      ...circuitOpenOrigins,
    ])
    reconcileUnavailableOriginSteps({
      storage: this.storage,
      run,
      quarantinedOrigins: quarantinedOriginRecords,
      circuitOpenOrigins,
      activeAssignmentIds: new Set(this.active.keys()),
    })

    const steps = this.storage.listChainSteps(run.id, run.goalRevision)
    const readySteps = steps
      .filter(s => s.status === 'ready')
      .filter(s => !(s.assignedWorkerId && this.active.has(s.assignedWorkerId)))
      .filter(s => !isStepOriginUnavailable(s, unavailableOrigins))

    const configuredConc = Math.max(1, Math.min(maxWorkerConcurrency, run.workerConcurrency || defaultWorkerConcurrency))
    const readyPrimarySteps = readySteps.filter(step => !(typeof step.trialIndex === 'number' && step.trialIndex > 0)).length
    const readyChainSteps = readySteps.filter(step => isMultiHopChainStep(step)).length
    const activeForRun = [...this.active.values()].filter(j => j.assignment.runId === run.id && j.assignment.phase === 'investigation').length
    const budgetUsdRemaining = Math.max(0, run.budgetUsd - run.spentUsd)
    // `budgetRequests === 0` means "Unlimited requests" (uncapped); treat as Infinity so AIMD is
    // not forced into `tightControlBounds` on default uncapped runs.
    const budgetRequestsRemaining = run.budgetRequests > 0
      ? Math.max(0, run.budgetRequests - run.spentRequests)
      : Number.POSITIVE_INFINITY
    const controller = this.phaseBControllerFor(run)
    const explicitOverride = this.workerConcurrencyOverride ?? parseEnvPhaseBConcurrencyOverride()
    const tightControlBounds = run.maxRpsPerOrigin < PHASE_B_MIN_CONCURRENCY_FLOOR
      || budgetRequestsRemaining < PHASE_B_MIN_CONCURRENCY_FLOOR * 10
      || (configuredConc === 1 && readyPrimarySteps + activeForRun < PHASE_B_MIN_CONCURRENCY_FLOOR && !(readyChainSteps >= 1 && readyPrimarySteps + activeForRun >= 2))
    const maxConc = explicitOverride !== undefined
      ? explicitOverride
      : tightControlBounds
        ? resolveEffectivePhaseBConcurrency({
            configuredConcurrency: configuredConc,
            readyPrimarySteps,
            readyChainSteps,
            budgetUsdRemaining,
            budgetRequestsRemaining,
            maxRpsPerOrigin: run.maxRpsPerOrigin,
          })
        : controller.getEffectiveConcurrency({ remainingBudgetUsd: budgetUsdRemaining })
    // One warm session container per worker slot: assignments reuse stopped containers instead of
    // paying a cold `container create` each dispatch.
    try { this.backend.setWarmCapacity?.(maxConc) } catch { /* pooling is best-effort */ }
    // Honest Phase-B termination: once the agent allowance is gone, dispatch stops and the phase
    // ends as `agent_budget_exhausted` even when ready steps remain (they cannot afford a request).
    // In-flight assignments keep their lease; the handoff waits for them to settle.
    const freshRun = this.storage.run(run.id)
    this.phaseRequestRemaining(freshRun)
    const phaseState = this.budgetTracker.stateByRun.get(run.id)
    if (this.phaseRequestBudgets && phaseState?.floorSettled && phaseState.agentBudgetExhausted) {
      this.reportAgentBudgetExhausted(freshRun, readySteps.length, activeForRun)
      if (activeForRun === 0) this.advanceToVerification(run)
      return
    }
    const leadStepIds = new Set(steps.filter(step => isDetLeadDispatchStep(step)).map(step => step.id))
    const chainStepIds = new Set(steps.filter(step => isMultiHopChainStep(step)).map(step => step.id))
    // Tier-A leads are exempt from the generic concurrent-lead cap; only generic leads count.
    const activeLeadCount = [...this.active.values()].filter(job =>
      job.assignment.runId === run.id &&
      job.assignment.phase === 'investigation' &&
      typeof job.assignment.stepId === 'string' &&
      leadStepIds.has(job.assignment.stepId) &&
      !this.tierAStepIds.has(job.assignment.stepId)).length
    const activeChainCount = [...this.active.values()].filter(job =>
      job.assignment.runId === run.id &&
      job.assignment.phase === 'investigation' &&
      typeof job.assignment.stepId === 'string' &&
      chainStepIds.has(job.assignment.stepId)).length

    const slots = Math.max(0, maxConc - activeForRun)
    const hostTiers = computeHostTiers(
      [...this.approvedOriginsSet(run)],
      this.storage.latestThreatModel(run.id, run.goalRevision)?.entries,
    )
    const sourceMounted = this.projectReposMount(run.projectId).mountedRepos.length > 0
    const dispatchPlan = this.reconPlanner.frontierDispatcherFor(run.id).dispatch(readySteps, slots, {
      leadCap: DET_LEAD_CONCURRENT_CAP,
      activeLeadCount,
      activeChainCount,
      hostTiers,
      tierALeadIds: this.tierAStepIds,
      sourceMounted,
    })
    const activeStepIds = new Set(
      [...this.active.values()]
        .filter(job => job.assignment.runId === run.id && job.assignment.phase === 'investigation' && typeof job.assignment.stepId === 'string')
        .map(job => job.assignment.stepId!),
    )
    const dispatchedStepIds: string[] = []
    const dispatchedSet = new Set<string>()
    for (const step of dispatchPlan.ordered) {
      if (activeStepIds.has(step.id) || dispatchedSet.has(step.id)) continue
      dispatchedSet.add(step.id)
      this.startInvestigationStep(run, step, profiles)
      dispatchedStepIds.push(step.id)
    }
    const dispatched = dispatchedStepIds.length
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
            effectiveConcurrency: maxConc,
            configuredConcurrency: configuredConc,
            aimd: controller.snapshot(budgetUsdRemaining),
            readySteps: readySteps.length,
            readyChainSteps,
            activeChainCount,
            dispatched,
            selectedByLane: dispatchPlan.selectedByLane,
            activeLeadCount,
            leadConcurrentCap: DET_LEAD_CONCURRENT_CAP,
            deferredLeads: dispatchPlan.deferredLeads,
            sourceMounted,
            whiteBoxSelected: dispatchPlan.whiteBoxSelected,
            runtimeChainReserved: dispatchPlan.runtimeChainReserved,
            eviRankedCount: dispatchPlan.eviRankedCount,
            stepIds: dispatchedStepIds,
          },
        )
      } catch { /* telemetry is best-effort */ }
    }

    // If nothing is running/ready/pending (via the single quarantine- and terminal-status-aware
    // predicate), or if the run-level backstop fires (0 dispatchable-ready, 0 running, 0 active
    // workers, 0 parked workers), check diminishing returns or trigger final planner review.
    // v6: a dry streak is observed, never a global kill switch. Termination is budget/requests/wall
    // exhaustion, per-assignment caps, drained OOB, or explicit coordinator completion.
    const updatedSteps = this.storage.listChainSteps(run.id, run.goalRevision)
    const pendingNeedsFacts = updatedSteps.some(s => s.status === 'pending' && s.dependsOnFactIds.length > 0)
    const knownFactIds = pendingNeedsFacts
      ? new Set(this.reconPlanner.pageAll((offset, limit) =>
          this.storage.listFacts(run.id, { includeTainted: true, limit, offset })).map(f => f.id))
      : undefined
    const dispatchableSteps = dispatchableReadySteps(updatedSteps, knownFactIds, unavailableOrigins)
    const dispatchableReadyCount = dispatchableSteps.filter(s => s.status === 'ready').length
    const runningStepsCount = updatedSteps.filter(s => s.status === 'running').length
    const activeWorkersForRun = [...this.active.values()].filter(
      j => j.assignment.runId === run.id && j.assignment.phase === 'investigation',
    ).length
    const parkedWorkersForRun = this.storage.parkedWorkerCount(run.id)
    const anyActive = hasActiveInvestigationSteps(updatedSteps, knownFactIds, unavailableOrigins)
    // R4-H-13 run-level stranded-step backstop: when no step is dispatchable-ready or running and
    // no worker is active or parked, advance on a stop decision instead of wedging, emitting
    // structured telemetry for any stranded steps.
    const runLevelBackstop =
      dispatchableReadyCount === 0
      && runningStepsCount === 0
      && activeWorkersForRun === 0
      && parkedWorkersForRun === 0
    if (runLevelBackstop) {
      const strandedSteps = updatedSteps.filter(s => s.status === 'pending' || s.status === 'ready')
      if (strandedSteps.length > 0) {
        const strandedKey = `${run.id}:${run.goalRevision}:${run.roundNo}:${strandedSteps.map(s => s.id).sort().join(',')}`
        if (!this.strandedBackstopReported.has(strandedKey)) {
          this.strandedBackstopReported.add(strandedKey)
          try {
            this.storage.event(
              run.id,
              'scheduler.stranded_steps_backstop',
              `Run-level backstop triggered with ${strandedSteps.length} stranded non-running step(s) (0 dispatchable-ready, 0 running, 0 active workers).`,
              {
                roundNo: run.roundNo,
                strandedCount: strandedSteps.length,
                strandedStepIds: strandedSteps.map(s => s.id),
                strandedStatuses: strandedSteps.map(s => ({ id: s.id, status: s.status })),
                unavailableOrigins: [...unavailableOrigins],
              },
            )
          } catch { /* telemetry is best-effort */ }
        }
      }
    }
    const plannerErr = this.getPlannerErrorState(run.id, run.goalRevision)
    if ((!anyActive || runLevelBackstop) && !this.plannerTasks.has(run.id) && !this.plannerTimers.has(run.id)) {
      if (plannerErr?.breakerTripped) {
        this.advanceToVerification(run)
        return
      }
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
      if (!plannerErr?.breakerTripped) {
        this.schedulePlanner(run.id, plannerDebounceMs)
      }
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
    const spawned = this.spawnRunTask(run.id, `deterministic:${eventPrefix}`, async () => {
      try {
        await execPass()
      } catch (error) {
        try {
          const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
          this.storage.event(run.id, `${eventPrefix}.failed`, `${label} failed: ${msg}`)
        } catch { /* store closed or run removed */ }
      } finally {
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
      }
    })
    if (!spawned.started) {
      this.deterministicInFlight.delete(key)
    }
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

  private getPlannerErrorState(runId: string, goalRevision?: number) {
    const state = this.plannerErrorState.get(runId)
    if (!state) return undefined
    if (goalRevision !== undefined && state.goalRevision !== goalRevision) {
      this.plannerErrorState.delete(runId)
      return undefined
    }
    return state
  }

  private schedulePlanner(runId: string, delayMs = plannerDebounceMs) {
    let goalRevision: number | undefined
    try { goalRevision = this.storage.run(runId).goalRevision } catch { /* run may be gone */ }
    const errState = this.getPlannerErrorState(runId, goalRevision)
    if (errState?.breakerTripped) {
      this.plannerDirty.delete(runId)
      return
    }
    this.plannerDirty.add(runId)
    if (this.plannerTimers.has(runId) || this.plannerTasks.has(runId)) return
    const backoffRemaining = errState ? Math.max(0, errState.backoffUntil - Date.now()) : 0
    const effectiveDelayMs = Math.max(delayMs, backoffRemaining)
    const cancel = this.ensureRunActor(runId).scheduleTimer('planner-debounce', effectiveDelayMs, () => {
      this.plannerTimers.delete(runId)
      this.plannerDirty.delete(runId)
      try {
        const run = this.storage.run(runId)
        const profiles = privateModelProfiles(this.storage)
        if (run.status === 'running' && run.phase === 'investigation' && profiles.length) {
          this.startChainPlanner(run, profiles)
        }
      } catch { /* ignore */ }
    })
    this.plannerTimers.set(runId, cancel)
  }

  private startChainPlanner(run: Run, profiles: readonly ResolvedModelProfile[]) {
    if (this.plannerTasks.has(run.id)) return
    if (this.getPlannerErrorState(run.id, run.goalRevision)?.breakerTripped) return
    const controller = new AbortController()
    const task: CoordinatorTask = { controller, goalRevision: run.goalRevision, scopeRevision: run.scopeRevision }
    this.plannerTasks.set(run.id, task)
    const spawned = this.spawnRunTask(run.id, 'chain-planner', async () => {
      try {
        await this.runChainPlanner(run, profiles, task)
        this.plannerErrorState.delete(run.id)
      } catch (error) {
        if (!this.currentCoordinator(run.id, task) || task.controller.signal.aborted) return
        const prev = this.getPlannerErrorState(run.id, run.goalRevision)
        const consecutiveErrors = (prev?.consecutiveErrors ?? 0) + 1
        const breakerTripped = consecutiveErrors >= this.plannerMaxConsecutiveErrors
        const backoffMs = breakerTripped
          ? 0
          : computePlannerBackoffMs(consecutiveErrors, this.plannerBackoffBaseMs, this.plannerBackoffCapMs)
        this.plannerErrorState.set(run.id, {
          goalRevision: run.goalRevision,
          consecutiveErrors,
          backoffUntil: breakerTripped ? 0 : Date.now() + backoffMs,
          breakerTripped,
        })
        const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 300)
        if (breakerTripped) {
          this.plannerDirty.delete(run.id)
          const cancelTimer = this.plannerTimers.get(run.id)
          if (cancelTimer) {
            cancelTimer()
            this.plannerTimers.delete(run.id)
          }
          this.safeEvent(
            run.id,
            'planner.circuit_open',
            `Planner paused after ${consecutiveErrors} consecutive error(s): ${msg}. Advancing once active steps settle.`,
            { consecutiveErrors, maxConsecutiveErrors: this.plannerMaxConsecutiveErrors, error: msg },
          )
        } else {
          this.safeEvent(
            run.id,
            'planner.error',
            `Planner round failed (${consecutiveErrors}/${this.plannerMaxConsecutiveErrors}); backing off ${backoffMs}ms: ${msg}`,
            { consecutiveErrors, maxConsecutiveErrors: this.plannerMaxConsecutiveErrors, backoffMs, error: msg },
          )
        }
      } finally {
        this.plannerTasks.delete(run.id)
        try {
          const latest = this.storage.run(run.id)
          if (latest.status === 'running' && latest.phase === 'investigation') {
            this.notifyCheckpoint(latest.id, 'planner-round')
          }
        } catch { /* run/store may already be gone */ }
        this.scheduleWake()
      }
    }, { controller })
    if (!spawned.started) {
      this.plannerTasks.delete(run.id)
    }
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
      : this.board.allocateBoardHandle(run, resolvedSpecialistId, step)
    const warmSessionId = wakeHandle && warmMember && warmMember.state !== 'retired' ? warmMember.sessionId : undefined
    const baseSpecialistTurns = Math.max(
      25,
      Math.min(specialistConfig.maxTurnsCeiling, run.workerMaxTurns > 0 ? Math.min(run.workerMaxTurns, specialistConfig.defaultMaxTurns) : specialistConfig.defaultMaxTurns),
    )
    const stepMaxTurns = computeStepMaxTurns(targetOrigins, hostTiers, baseSpecialistTurns)
    // Single unified assignment budget resolver (Move O5): eliminates the silent overwrite that
    // previously clamped multiStep race/BOLA/cross-persona assignments back down to 120s.
    const runMaxDuration = Number((run as { maxDurationMs?: number }).maxDurationMs)
    const effectiveRunDurationMs = Number.isFinite(runMaxDuration) && runMaxDuration > 0
      ? runMaxDuration
      : this.maxDurationMs
    const budget: AssignmentBudget = resolveAssignmentBudget(
      {
        title: step.title,
        hypothesis: step.hypothesis,
        category: step.category,
        skills: step.skills,
        routes: this.reconPlanner.stepMentionedRoutes(step),
        dependsOnFactIds: step.dependsOnFactIds,
        dependsOnStepIds: step.dependsOnStepIds,
      },
      {
        baseMaxTurns: stepMaxTurns,
        runDurationMs: effectiveRunDurationMs,
        singleStepWallClockMs: singleStepWallClockMs(),
        ...(this.assignmentWallClockOverrideMs !== undefined
          ? { wallClockOverrideMs: this.assignmentWallClockOverrideMs }
          : {}),
      },
    )

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

    const baselineFacts = this.storage.listFacts(run.id, { includeTainted: false, limit: 500 }).length
    const baselineFindings = this.storage.db.select().from(findings).where(eq(findings.runId, run.id)).all().length
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
      }, run.id)
      this.warm.wake(boardHandle, assignment.id, run.id)
    } catch { /* roster mirror is best-effort */ }

    this.postCoordinatorBrief(run, effectiveStep, boardHandle, targetOrigins)

    let workerErrored = false
    const spawned = this.spawnRunTask(run.id, `investigation:${assignment.id}`, async () => {
      try {
        await this.runInvestigationWorker(job, effectiveStep, targetOrigins, profiles, budget)
      } catch (error) {
        workerErrored = true
        const msg = error instanceof Error ? error.message : String(error)
        const ctrl = this.phaseBControllers.get(run.id)
        if (ctrl) {
          if (/\b429\b|rate[\s_-]?limit/i.test(msg)) ctrl.recordPressure('llm_429')
          else if (/docker|container|openSession|spawn|EAGAIN|ENOMEM/i.test(msg)) ctrl.recordPressure('container_spawn_error')
          else if (/timeout|timed out|ETIMEDOUT/i.test(msg)) ctrl.recordPressure('target_timeout')
        }
        this.workerRunner.handleInvestigationWorkerError(run, job, effectiveStep, resolvedSpecialistId, budget, error)
      } finally {
        this.active.delete(assignment.id)
        try { this.board.finishBoardMember(this.storage.run(run.id), assignment.id) } catch { /* run may be gone */ }
        // Avoid premature mid-wave planner triggers when Wave 2+ still buffers >= maxConc ready steps
        // and this assignment produced no new fact or finding.
        let shouldPlan = true
        try {
          const latestRun = this.storage.run(run.id)
          const ctrl = this.phaseBControllers.get(run.id)
          const remainingUsd = Math.max(0, latestRun.budgetUsd - latestRun.spentUsd)
          if (ctrl && !workerErrored && !job.stallAbort) {
            ctrl.recordCleanCompletion({ remainingBudgetUsd: remainingUsd })
          }
          const maxConc = ctrl
            ? ctrl.getEffectiveConcurrency({ remainingBudgetUsd: remainingUsd })
            : Math.max(1, Math.min(maxWorkerConcurrency, latestRun.workerConcurrency || defaultWorkerConcurrency))
          const readySteps = dispatchableReadySteps(
            this.storage.listChainSteps(run.id, latestRun.goalRevision),
            undefined,
            this.reconPlanner.unavailableOriginsForRun(latestRun),
          ).filter(s => s.status === 'ready').length
          const newFact = this.storage.listFacts(run.id, { includeTainted: false, limit: 500 }).length > baselineFacts
          const newFinding = this.storage.db.select().from(findings).where(eq(findings.runId, run.id)).all().length > baselineFindings
          shouldPlan = readySteps < maxConc || newFact || newFinding
        } catch { /* run may be gone */ }
        if (shouldPlan) this.schedulePlanner(run.id)
        this.scheduleWake()
      }
    }, { controller: job.controller })
    if (!spawned.started) {
      this.active.delete(assignment.id)
      this.boardHandleByAssignment.delete(assignment.id)
      rollbackRejectedInvestigationSpawn(this.storage, run.id, step.id, assignment)
      const draining = this.disposingRuns.get(run.id)
      if (draining) this.trackMaintenance(draining.finally(() => this.scheduleWake()))
    }
  }

  private phaseBControllerFor(run: Run): PhaseBConcurrencyController {
    let controller = this.phaseBControllers.get(run.id)
    if (!controller) {
      // Respect any non-default run.workerConcurrency as a hard AIMD ceiling (preserving the
      // legacy Queue #17 single-slot `1` starvation guard unless an explicit override is set).
      const explicitCeiling =
        run.workerConcurrency >= 2 && run.workerConcurrency !== defaultWorkerConcurrency
          ? Math.min(maxWorkerConcurrency, Math.floor(run.workerConcurrency))
          : undefined
      controller = new PhaseBConcurrencyController({
        ...(this.workerConcurrencyOverride !== undefined ? { explicitOverride: this.workerConcurrencyOverride } : {}),
        ...(explicitCeiling !== undefined ? { ceiling: explicitCeiling } : {}),
      })
      this.phaseBControllers.set(run.id, controller)
    }
    return controller
  }

  /** Read-only snapshot of the run's dynamic AIMD Phase-B concurrency controller. */
  getPhaseBConcurrencySnapshot(runId: string): PhaseBConcurrencySnapshot | undefined {
    const controller = this.phaseBControllers.get(runId)
    if (!controller) return undefined
    try {
      const run = this.storage.run(runId)
      return controller.snapshot(Math.max(0, run.budgetUsd - run.spentUsd))
    } catch {
      return controller.snapshot()
    }
  }

  private buildBrokeredTransportHandlers(ctx: ExecBrokeredTransportContext): Partial<WorkerToolHandlers> {
    return buildBrokeredTransportHandlers({
      storage: this.storage,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      stagingCreatedEntities: this.stagingCreatedEntities,
      check: job => this.check(job),
      approvedOriginsSet: run => this.approvedOriginsSet(run),
      parseOriginForRun: (run, raw) => this.parseOriginForRun(run, raw),
      markEndpointCoverage: (run, o, m, p, c) => this.markEndpointCoverage(run, o, m, p, c),
      scanSecondOrderExchange: (run, aid, res, exId, mt) => this.scanSecondOrderExchange(run, aid, res, exId, mt),
      postCanaryLead: (run, input) => this.postCanaryLead(run, input),
      stagingTagAgentRequest: input => this.stagingTagAgentRequest(input),
      stageAgentRaceBurst: (runId, grant, mode, entityTag, reqs) =>
        this.stageAgentRaceBurst(runId, grant, mode, entityTag, reqs),
      waitForTier3Approval: (...a) => this.waitForTier3Approval(...a),
      executeApprovedRaceBurst: (...a) => this.executeApprovedRaceBurst(...a),
      executeApprovedBatch: (...a) => this.executeApprovedBatch(...a),
    }, ctx)
  }

  private async runInvestigationWorker(
    job: Active,
    step: ChainStep,
    targetOrigins: string[],
    profiles: readonly ResolvedModelProfile[],
    budget: AssignmentBudget,
  ) {
    return this.workerRunner.runInvestigationWorker(job, step, targetOrigins, profiles, budget)
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
    let promotedReceipts = this.verifier.promoteReceiptOob(runId)
    const convertingRelay = new Proxy(this.canaryBroker, {
      get: (target, prop, receiver) => {
        if (prop === 'promoteLate') {
          return (opts: { runId?: string; now?: number } = {}) => {
            const promotions = target.promoteLate(opts)
            try { promotedReceipts += this.verifier.convertOobPromotions(runId, promotions) } catch { /* best-effort */ }
            return promotions
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const result = await drainPendingOob(convertingRelay, runId, options)
    this.lastOobDrain.set(runId, result)
    this.safeEvent(
      runId, 'oob.drain_complete',
      `OOB drain finished in ${result.oobDrainMs} ms (${result.promotedLate} late callback(s) promoted, ${promotedReceipts} confirmed by ProofReceipt, ${result.remaining} still pending).`,
      { ...result, promotedReceipts },
    )
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
      drain: (runId, signal) => this.drainPendingOob(runId, signal ? { signal } : {}),
      spawn: (label, fn) => this.spawnRunTask(run.id, label, fn),
      onFinalized: finalizedRunId => {
        try {
          const current = this.storage.run(finalizedRunId)
          if (current.status === 'complete' || current.phase === 'complete') {
            this.evictCapabilityVault(finalizedRunId)
            queueMicrotask(() => {
              this.scheduleRunDisposal(finalizedRunId, 'completed', 'final report written')
            })
          }
        } catch {
          this.evictCapabilityVault(finalizedRunId)
          queueMicrotask(() => {
            this.scheduleRunDisposal(finalizedRunId, 'completed', 'final report written')
          })
        }
      },
    }, run)
  }

  private advanceToVerification(run: Run) {
    // Never let Phase 3 start while the concurrent deterministic lane is still in flight: abort
    // and fast-settle first, then commit the phase transition exactly once.
    if (this.agenticLaneStopping.has(run.id)) return
    if (this.agenticLaneJobs.has(run.id)) {
      this.spawnRunTask(run.id, 'advance-to-verification', async () => {
        try {
          await this.abortAgenticLane(run, 'phase-2 complete')
        } finally {
          this.commitVerificationPhase(run)
        }
      })
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
      this.storage.message(current.id, current.coordinatorId, 'kovo',
        `Investigation complete${openProofGaps.length ? ` (${openProofGaps.length} open proof ${openProofGaps.length === 1 ? 'gap' : 'gaps'} surfaced)` : ''}. Deterministic Zero-LLM verification is replaying every proposed finding and checking baselines.`)
    }, { behavior: 'immediate' })
    try {
      const actor = this.actors.get(run.id)
      if (actor && !actor.isTerminal && actor.canTransitionTo('verifying')) {
        actor.syncState('verifying', 'investigation complete')
      }
    } catch { /* actor state sync is best-effort */ }
    try {
      this.settleAgentRequestPhase(
        run.id,
        this.budgetTracker.terminationReasonByRun.get(run.id) === 'agent_budget_exhausted'
          ? 'agent_budget_exhausted'
          : 'investigation_complete',
      )
    } catch { /* metrics are best-effort */ }
    try { this.recordFloorMetrics(run.id, 'phase3') } catch { /* metrics are best-effort */ }
    try { this.recordAssignmentMetrics(run.id, 'phase3') } catch { /* metrics are best-effort */ }
    this.scheduleWake()
  }

  private driveVerification(run: Run) {
    try { this.reconcileSettledApprovalWorkers(run) } catch { /* reconciliation is best-effort */ }
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

    let updatedWorkers = this.storage.workerList(run.id).filter(w =>
      w.phase === 'verification' && w.goalRevision === run.goalRevision &&
      w.sourceOrigins.every(o => approvedOrigins.has(o)))

    // H-27 lease watchdog: reclaim verification workers whose lease expired with no live active job.
    const now = Date.now()
    let reclaimedExpired = false
    for (const w of updatedWorkers) {
      if (w.status === 'running' && !this.active.has(w.id) && w.leaseExpiresAt !== null && w.leaseExpiresAt <= now) {
        recordVerificationOrRetestFailure(this.storage, run, w, 'worker', 'Verification lease expired', 'Worker lease expired before completion.')
        reclaimedExpired = true
      }
    }
    if (reclaimedExpired) {
      updatedWorkers = this.storage.workerList(run.id).filter(w =>
        w.phase === 'verification' && w.goalRevision === run.goalRevision &&
        w.sourceOrigins.every(o => approvedOrigins.has(o)))
    }

    const queued = updatedWorkers.filter(w => w.status === 'queued')
    const activeCount = [...this.active.values()].filter(j => j.assignment.runId === run.id).length

    if (!queued.length && updatedWorkers.every(w => w.status === 'complete' || w.status === 'canceled' || w.status === 'failed')) {
      // v6: never finalize while async OOB callbacks can still land. A bounded drain promotes late
      // callbacks (Fixture #2 delivers 15–30 s after the response) before the report is written.
      this.scheduleFinalReport(run)
      return
    }

    let slots = Math.max(0, maxConc - activeCount)
    for (const worker of queued) {
      if (slots <= 0) break
      if (this.active.has(worker.id)) continue
      if (this.startVerificationWorker(run, worker)) slots -= 1
    }
  }

  private claimAndDispatchWorker(
    run: Run,
    worker: Assignment,
    eventPrefix: 'worker' | 'retest',
    failureLabel: string,
    work: (job: Active) => Promise<void>,
    skipIfUnauthorized: boolean,
  ): boolean {
    const claimed = this.storage.transaction(() => {
      const w = this.storage.updateWorker(worker.id, {
        status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 10 * 60_000, outcome: null,
      })
      this.storage.event(run.id, `${eventPrefix}.started`, worker.title + ' started.', { assignmentId: worker.id })
      return w
    })
    if (!claimed) return false
    const job: Active = { assignment: claimed, origins: new Set(claimed.sourceOrigins), controller: new AbortController() }
    this.active.set(claimed.id, job)
    const runWork = async () => {
      try {
        await work(job)
      } catch (error) {
        if (skipIfUnauthorized && (!this.authorize(job) || job.controller.signal.aborted)) return
        const msg = redact(error instanceof Error ? error.message : String(error)).slice(0, 400)
        recordVerificationOrRetestFailure(this.storage, run, claimed, eventPrefix, failureLabel, msg)
      } finally {
        this.active.delete(claimed.id)
        this.scheduleWake()
      }
    }
    const task = this.spawnRunTask(
      run.id,
      `${eventPrefix === 'worker' ? 'verification' : 'retest'}:${claimed.id}`,
      runWork,
      { controller: job.controller },
    )
    if (!task.started) {
      this.active.delete(claimed.id)
      rollbackRejectedWorkerSpawn(this.storage, claimed)
      const draining = this.disposingRuns.get(run.id)
      if (draining) this.trackMaintenance(draining.finally(() => this.scheduleWake()))
      return false
    }
    return true
  }

  private startVerificationWorker(run: Run, worker: Assignment): boolean {
    return this.claimAndDispatchWorker(
      run, worker, 'worker', 'Verification failed',
      job => (job.assignment.stepId ? this.verifyReplaySpecJob(job, job.assignment.stepId) : this.verifier.verifyBaselineJob(job)),
      true,
    )
  }

  private startRetestWorker(run: Run, worker: Assignment): boolean {
    return this.claimAndDispatchWorker(run, worker, 'retest', 'Verify Fix retest failed', job => this.verifier.runRetestJob(job), false)
  }

  // --- On-Demand / Opt-In Air-Gapped Verified Patch Workflow (§4.6) ---

  async runPatchWorkflow(
    runId: string,
    findingId: string,
    repoOverride?: string,
    signal?: AbortSignal,
  ): Promise<PatchProposal> {
    const run = this.storage.run(runId)
    const findingRow = findFindingRow(this.storage, run.id, findingId)
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
            sanitizedRepoDir: labHandle.sanitizedRepoDir,
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
    return this.workerRunner.completeWorker(worker, run, summary, artifactIds, checks, secrets)
  }
}

const EXECUTION_SINGLETON_SYMBOL = Symbol.for('kovo.execution')
function getExecutionRegistry(): Map<string, Execution> {
  const g = globalThis as Record<symbol, Map<string, Execution> | undefined>
  return (g[EXECUTION_SINGLETON_SYMBOL] ??= new Map<string, Execution>())
}
function unregisterExecutionInstance(directory: string, exec: Execution): void {
  const key = resolve(directory)
  const reg = getExecutionRegistry()
  if (reg.get(key) === exec) reg.delete(key)
}
export function execution(): Execution {
  const key = resolve(dataDirectory())
  const reg = getExecutionRegistry()
  let existing = reg.get(key)
  if (!existing) {
    existing = new Execution(store())
    reg.set(key, existing)
  }
  return existing
}
