/**
 * Canonical Run-Status Classification & Predicates (`src/server/run-status.ts`).
 *
 * Single source of truth for classifying `RunStatus` values from `src/domain.ts` so storage,
 * retention, maintenance, deletion, UI, and static drift audits never disagree on:
 *  - `'complete'` vs legacy `'completed'`
 *  - strictly actively executing (`'running'`) vs resumable non-terminal (`'paused'`,
 *    `'budget_paused'`, `'waiting'`, legacy `'queued'`)
 *  - strictly terminal (`'complete'`, `'stopped'`, `'failed'` + legacy aliases)
 */
import type { RunStatus, WorkerStatus } from '../domain.ts'
import { STEP_STATUS, type ChainStepStatus } from '../step-status.ts'

/** Exhaustiveness helper enforced by TypeScript and `scripts/check-exhaustive.ts`. */
export function assertNever(value: never, context = 'Unexpected union member'): never {
  throw new Error(`${context}: ${String(value)}`)
}

/** Canonical terminal `RunStatus` values in `src/domain.ts`. */
export type TerminalRunStatus = 'complete' | 'stopped' | 'failed'

/** Legacy terminal spelling aliases tolerated by read/retention helpers. */
export type LegacyTerminalRunStatusAlias = 'completed' | 'cancelled' | 'canceled'

/** Canonical status representing a run with actively executing workers / live bind-mounts. */
export type ActivelyExecutingRunStatus = 'running'

/** Canonical non-terminal statuses that are not actively executing and can resume/proceed. */
export type CanonicalResumableNonTerminalRunStatus = 'waiting' | 'paused' | 'budget_paused'

/** Legacy non-terminal queued spelling alias tolerated by classification helpers. */
export type LegacyResumableNonTerminalRunStatusAlias = 'queued'

/** Resumable non-terminal run statuses (canonical + legacy `'queued'`). */
export type ResumableNonTerminalRunStatus =
  | LegacyResumableNonTerminalRunStatusAlias
  | CanonicalResumableNonTerminalRunStatus

/** Exhaustive lifecycle category assigned to every canonical `RunStatus`. */
export type RunStatusCategory =
  | 'terminal'
  | 'actively_executing'
  | 'resumable_non_terminal'

/**
 * Canonical terminal `RunStatus` values (`'complete' | 'stopped' | 'failed'`).
 * Legacy spelling aliases (`'completed'`, `'cancelled'`, `'canceled'`) live in
 * `LEGACY_TERMINAL_RUN_STATUS_ALIASES` and are accepted by `isTerminalRunStatus()`.
 */
export const TERMINAL_RUN_STATUSES = [
  'complete',
  'stopped',
  'failed',
] as const satisfies readonly TerminalRunStatus[]

/** Legacy terminal aliases accepted by `isTerminalRunStatus()` for backward compatibility. */
export const LEGACY_TERMINAL_RUN_STATUS_ALIASES = [
  'completed',
  'cancelled',
  'canceled',
] as const satisfies readonly LegacyTerminalRunStatusAlias[]

/**
 * Strictly runs with live executing workers / bind-mounts (`'running'`).
 * Paused, budget-paused, waiting, and queued runs are non-terminal but NOT actively executing.
 */
export const ACTIVELY_EXECUTING_RUN_STATUSES = [
  'running',
] as const satisfies readonly ActivelyExecutingRunStatus[]

/** Non-terminal statuses that are paused/waiting/queued (resumable, no active worker loop). */
export const RESUMABLE_NON_TERMINAL_RUN_STATUSES = [
  'queued',
  'waiting',
  'paused',
  'budget_paused',
] as const satisfies readonly ResumableNonTerminalRunStatus[]

/** Canonical subset of `RESUMABLE_NON_TERMINAL_RUN_STATUSES` defined in `RunStatus`. */
export const CANONICAL_RESUMABLE_NON_TERMINAL_RUN_STATUSES = [
  'waiting',
  'paused',
  'budget_paused',
] as const satisfies readonly CanonicalResumableNonTerminalRunStatus[]

/** Every canonical `RunStatus` value defined by `src/domain.ts`, in lifecycle order. */
export const RUN_STATUSES = [
  'waiting',
  'running',
  'paused',
  'budget_paused',
  'stopped',
  'failed',
  'complete',
] as const satisfies readonly RunStatus[]

// ---------------------------------------------------------------------------
// Compile-time exhaustiveness & partition proofs over `RunStatus`
// ---------------------------------------------------------------------------

type AssertExact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never
type AssertDisjoint<A, B> = [A & B] extends [never] ? true : never

type ClassifiedCanonicalUnion =
  | TerminalRunStatus
  | ActivelyExecutingRunStatus
  | CanonicalResumableNonTerminalRunStatus

/** Fails `tsc` if any `RunStatus` member is added to `src/domain.ts` without classification. */
const _assertRunStatusUnionExhaustive: AssertExact<ClassifiedCanonicalUnion, RunStatus> = true
const _assertRunStatusesArrayExhaustive: AssertExact<typeof RUN_STATUSES[number], RunStatus> = true
const _assertTerminalActiveDisjoint: AssertDisjoint<TerminalRunStatus, ActivelyExecutingRunStatus> = true
const _assertTerminalResumableDisjoint: AssertDisjoint<TerminalRunStatus, CanonicalResumableNonTerminalRunStatus> = true
const _assertActiveResumableDisjoint: AssertDisjoint<ActivelyExecutingRunStatus, CanonicalResumableNonTerminalRunStatus> = true
void _assertRunStatusUnionExhaustive
void _assertRunStatusesArrayExhaustive
void _assertTerminalActiveDisjoint
void _assertTerminalResumableDisjoint
void _assertActiveResumableDisjoint

/**
 * Exhaustive compile-time classification map over every `RunStatus`.
 * Adding a new member to `RunStatus` in `src/domain.ts` forces an explicit entry here.
 */
export const RUN_STATUS_CLASSIFICATION: Readonly<Record<RunStatus, RunStatusCategory>> = {
  waiting: 'resumable_non_terminal',
  running: 'actively_executing',
  paused: 'resumable_non_terminal',
  budget_paused: 'resumable_non_terminal',
  stopped: 'terminal',
  failed: 'terminal',
  complete: 'terminal',
}

/** Exhaustive classifier over canonical `RunStatus` values (compile-time checked via `never`). */
export function classifyRunStatus(status: RunStatus): RunStatusCategory {
  switch (status) {
    case 'complete':
    case 'stopped':
    case 'failed':
      return 'terminal'
    case 'running':
      return 'actively_executing'
    case 'waiting':
    case 'paused':
    case 'budget_paused':
      return 'resumable_non_terminal'
    default:
      return assertNever(status, 'Unhandled RunStatus')
  }
}

// ---------------------------------------------------------------------------
// Runtime O(1) lookup sets & predicates
// ---------------------------------------------------------------------------

const CANONICAL_RUN_STATUS_SET: ReadonlySet<string> = /*#__PURE__*/ new Set<string>(RUN_STATUSES)

const TERMINAL_RUN_STATUS_SET: ReadonlySet<string> = /*#__PURE__*/ new Set<string>([
  ...TERMINAL_RUN_STATUSES,
  ...LEGACY_TERMINAL_RUN_STATUS_ALIASES,
])

const ACTIVELY_EXECUTING_RUN_STATUS_SET: ReadonlySet<string> = /*#__PURE__*/ new Set<string>(
  ACTIVELY_EXECUTING_RUN_STATUSES,
)

const RESUMABLE_NON_TERMINAL_RUN_STATUS_SET: ReadonlySet<string> = /*#__PURE__*/ new Set<string>(
  RESUMABLE_NON_TERMINAL_RUN_STATUSES,
)

const NON_TERMINAL_RUN_STATUS_SET: ReadonlySet<string> = /*#__PURE__*/ new Set<string>([
  ...ACTIVELY_EXECUTING_RUN_STATUSES,
  ...RESUMABLE_NON_TERMINAL_RUN_STATUSES,
])

function normalizeStatus(status: string | null | undefined): string | null {
  if (typeof status !== 'string') return null
  const normalized = status.trim().toLowerCase()
  return normalized.length > 0 ? normalized : null
}

/** True when `status` is an exact canonical `RunStatus` value from `src/domain.ts`. */
export function isCanonicalRunStatus(status: string | null | undefined): status is RunStatus {
  return typeof status === 'string' && CANONICAL_RUN_STATUS_SET.has(status)
}

/**
 * True strictly for terminal run statuses (`'complete'`, `'stopped'`, `'failed'`) plus legacy
 * terminal aliases (`'completed'`, `'cancelled'`, `'canceled'`).
 * Fail-closed (`false`) for `null`, `undefined`, empty, or unrecognized strings.
 */
export function isTerminalRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && TERMINAL_RUN_STATUS_SET.has(normalized)
}

/**
 * True strictly for actively executing runs (`'running'`) with live workers / bind-mounts.
 * Returns `false` for `'paused'`, `'budget_paused'`, `'waiting'`, `'queued'`, terminal statuses,
 * and unrecognized values.
 */
export function isActivelyExecutingRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && ACTIVELY_EXECUTING_RUN_STATUS_SET.has(normalized)
}

/**
 * True for resumable non-terminal run statuses (`'queued'`, `'waiting'`, `'paused'`, `'budget_paused'`).
 */
export function isResumableNonTerminalRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && RESUMABLE_NON_TERMINAL_RUN_STATUS_SET.has(normalized)
}

/**
 * True for every non-terminal run status — both actively executing (`'running'`) and
 * resumable non-terminal (`'queued'`, `'waiting'`, `'paused'`, `'budget_paused'`).
 * Disjoint from `isTerminalRunStatus()` and collectively exhaustive over all `RUN_STATUSES`.
 */
export function isNonTerminalRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && NON_TERMINAL_RUN_STATUS_SET.has(normalized)
}

// ---------------------------------------------------------------------------
// Canonical WorkerStatus predicates (compile-time exhaustive)
// ---------------------------------------------------------------------------

/** Every canonical `WorkerStatus` value defined by `src/domain.ts`, in lifecycle order. */
export const WORKER_STATUSES = [
  'queued',
  'running',
  'paused',
  'waiting_approval',
  'complete',
  'canceled',
  'failed',
] as const satisfies readonly WorkerStatus[]

const _assertWorkerStatusesExhaustive: AssertExact<typeof WORKER_STATUSES[number], WorkerStatus> = true
void _assertWorkerStatusesExhaustive

const CANONICAL_WORKER_STATUS_SET: ReadonlySet<string> = /*#__PURE__*/ new Set<string>(WORKER_STATUSES)

/** True when `status` is an exact canonical `WorkerStatus` from `src/domain.ts`. */
export function isCanonicalWorkerStatus(status: string | null | undefined): status is WorkerStatus {
  return typeof status === 'string' && CANONICAL_WORKER_STATUS_SET.has(status)
}

/** True when an assignment is actively live/in-progress in workflow visualizations. */
export function isLiveWorkerStatus(status: WorkerStatus): boolean {
  switch (status) {
    case 'running':
    case 'paused':
    case 'waiting_approval':
      return true
    case 'queued':
    case 'complete':
    case 'canceled':
    case 'failed':
      return false
    default:
      return assertNever(status, 'Unhandled WorkerStatus')
  }
}

/** True when an assignment status is stuck/orphaned if observed on a terminal run. */
export function isStuckTerminalAssignmentStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  if (!normalized || !isCanonicalWorkerStatus(normalized)) return false
  switch (normalized) {
    case 'running':
    case 'queued':
      return true
    case 'paused':
    case 'waiting_approval':
    case 'complete':
    case 'canceled':
    case 'failed':
      return false
    default:
      return assertNever(normalized, 'Unhandled WorkerStatus')
  }
}

// ---------------------------------------------------------------------------
// Single authoritative derived RunActivity (`R3-18`)
// ---------------------------------------------------------------------------

export type RunBlockingReasonCode =
  | 'run_running'
  | 'live_workers'
  | 'parked_approvals'
  | 'running_lab_container'
  | 'oob_drain_active'
  | 'tracked_active_tasks'

export interface RunBlockingReason {
  code: RunBlockingReasonCode
  count?: number
  message: string
}

export interface RunActivity {
  lifecycle: RunStatus
  /** True iff live workers, running status, running lab containers, or active runtime drains exist. */
  hasLiveWork: boolean
  /** True iff parked `waiting_approval` assignments or pending operator approvals await a decision. */
  hasParkedApprovals: boolean
  /** Non-empty whenever deleting the run requires explicit stop/confirmation. */
  blockingReasons: RunBlockingReason[]
}

export interface DeriveRunActivityInput {
  status: RunStatus | string | null | undefined
  runningAssignments?: number
  parkedApprovalAssignments?: number
  pendingApprovals?: number
  runningLabContainers?: number
  oobDrainActive?: boolean
  trackedActiveTasks?: boolean
}

function toCanonicalRunStatus(status: RunStatus | string | null | undefined): RunStatus {
  const normalized = normalizeStatus(status)
  if (!normalized) return 'stopped'
  if (isCanonicalRunStatus(normalized)) return normalized
  if (normalized === 'completed') return 'complete'
  if (normalized === 'cancelled' || normalized === 'canceled') return 'stopped'
  if (normalized === 'queued') return 'waiting'
  return 'stopped'
}

/**
 * Single server/UI source of truth for run activity, parked approvals, and delete-blocking reasons.
 * Parked `waiting_approval` rows on a paused run NEVER mark `hasLiveWork = true`, while still
 * populating `hasParkedApprovals = true` and `blockingReasons` so destructive delete requires confirmation.
 */
export function deriveRunActivity(input: DeriveRunActivityInput): RunActivity {
  const lifecycle = toCanonicalRunStatus(input.status)
  const category = classifyRunStatus(lifecycle)
  const runningAssignments = Math.max(0, Math.trunc(input.runningAssignments ?? 0))
  const parkedApprovalAssignments = Math.max(0, Math.trunc(input.parkedApprovalAssignments ?? 0))
  const pendingApprovals = Math.max(0, Math.trunc(input.pendingApprovals ?? 0))
  const runningLabContainers = Math.max(0, Math.trunc(input.runningLabContainers ?? 0))
  const oobDrainActive = Boolean(input.oobDrainActive)
  const trackedActiveTasks = Boolean(input.trackedActiveTasks)

  const runIsRunning = category === 'actively_executing'
  const terminal = category === 'terminal'
  const hasLiveWork =
    runIsRunning
    || runningAssignments > 0
    || runningLabContainers > 0
    || oobDrainActive
    || trackedActiveTasks
  const parkedCount = terminal ? 0 : Math.max(parkedApprovalAssignments, pendingApprovals)
  const hasParkedApprovals = parkedCount > 0

  const blockingReasons: RunBlockingReason[] = []
  if (runIsRunning) {
    blockingReasons.push({
      code: 'run_running',
      message: 'This run is currently running.',
    })
  }
  if (runningAssignments > 0) {
    blockingReasons.push({
      code: 'live_workers',
      count: runningAssignments,
      message: `${runningAssignments} active ${runningAssignments === 1 ? 'worker is' : 'workers are'} still executing.`,
    })
  }
  if (hasParkedApprovals) {
    blockingReasons.push({
      code: 'parked_approvals',
      count: parkedCount,
      message: `${parkedCount} parked approval ${parkedCount === 1 ? 'request is' : 'requests are'} awaiting operator decision.`,
    })
  }
  if (runningLabContainers > 0) {
    blockingReasons.push({
      code: 'running_lab_container',
      count: runningLabContainers,
      message: `${runningLabContainers} local lab ${runningLabContainers === 1 ? 'container is' : 'containers are'} still running.`,
    })
  }
  if (oobDrainActive) {
    blockingReasons.push({
      code: 'oob_drain_active',
      message: 'Out-of-band callback drain is still active.',
    })
  }
  if (trackedActiveTasks) {
    blockingReasons.push({
      code: 'tracked_active_tasks',
      message: 'In-flight runtime tasks are still draining.',
    })
  }

  return {
    lifecycle,
    hasLiveWork,
    hasParkedApprovals,
    blockingReasons,
  }
}

/** True when deleting a run requires explicit stop/confirmation (live work OR parked approvals). */
export function isRunDeleteBlocked(
  activity: Pick<RunActivity, 'hasLiveWork' | 'hasParkedApprovals' | 'blockingReasons'>,
): boolean {
  return activity.hasLiveWork || activity.hasParkedApprovals || activity.blockingReasons.length > 0
}

/** True when a run's configuration/scope/goal can still be edited (non-terminal lifecycle). */
export function isRunEditable(
  activityOrStatus: Pick<RunActivity, 'lifecycle'> | RunStatus | string | null | undefined,
): boolean {
  const status = typeof activityOrStatus === 'object' && activityOrStatus !== null
    ? activityOrStatus.lifecycle
    : activityOrStatus
  return !isTerminalRunStatus(status)
}

/** True when a run is in progress (live work or non-terminal lifecycle: running/waiting/paused/budget_paused). */
export function isRunInProgress(
  activityOrStatus: Pick<RunActivity, 'lifecycle' | 'hasLiveWork'> | RunStatus | string | null | undefined,
): boolean {
  if (typeof activityOrStatus === 'object' && activityOrStatus !== null) {
    return activityOrStatus.hasLiveWork || isNonTerminalRunStatus(activityOrStatus.lifecycle)
  }
  return isNonTerminalRunStatus(activityOrStatus)
}

// ---------------------------------------------------------------------------
// Report chain-step metrics derived directly from `STEP_STATUS` (`R3-18`)
// ---------------------------------------------------------------------------

export interface ReportChainStepMetrics {
  completed: number
  untested: number
  tainted: number
  incompleteByStatus: Partial<Record<ChainStepStatus, number>>
}

/**
 * Derive report step counts exclusively from `STEP_STATUS` partitions so newly added
 * statuses (`turn_capped`, `model_failure`, `infra_failed`, `nudged_out`, `rotated_partial`)
 * are never dropped from report gap accounting.
 */
export function summarizeReportChainSteps(
  steps: readonly { status: ChainStepStatus }[],
): ReportChainStepMetrics {
  let completed = 0
  let untested = 0
  let tainted = 0
  const incompleteByStatus: Partial<Record<ChainStepStatus, number>> = {}

  for (const step of steps) {
    const bucket = classifyReportStepBucket(step.status)
    if (bucket === 'completed') {
      completed += 1
    } else if (bucket === 'tainted') {
      tainted += 1
    } else {
      untested += 1
      incompleteByStatus[step.status] = (incompleteByStatus[step.status] ?? 0) + 1
    }
  }
  return { completed, untested, tainted, incompleteByStatus }
}

/** Compile-time check ensuring every `STEP_STATUS` entry is explicitly classified by `summarizeReportChainSteps`. */
function classifyReportStepBucket(status: ChainStepStatus): 'completed' | 'tainted' | 'untested' {
  const meta = STEP_STATUS[status]
  switch (status) {
    case 'complete':
      return meta.satisfiesDependency ? 'completed' : 'untested'
    case 'tainted':
      return 'tainted'
    case 'pending':
    case 'ready':
    case 'running':
    case 'blocked':
    case 'canceled':
    case 'infra_failed':
    case 'turn_capped':
    case 'nudged_out':
    case 'rotated_partial':
    case 'model_failure':
      return !meta.terminal || meta.lostWork ? 'untested' : 'completed'
    default:
      return assertNever(status, 'Unhandled ChainStepStatus')
  }
}
