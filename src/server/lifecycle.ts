/**
 * Authoritative Persisted Lifecycle State Machine, Co-Transitions, Startup Crash Recovery
 * Contract, and Always-On Emit-Only Liveness Checker (`R3-20`).
 *
 * Single source of truth for:
 *  1. Total transition tables for persisted entities (`run`, `worker`, `chainStep`,
 *     `approval`, `lease`, `boardMember`) in warn mode by default (structured telemetry)
 *     or enforced mode (`KOVO_LIFECYCLE_ENFORCE=1` / `{ mode: 'enforce' }`).
 *  2. Atomic co-transitions when a run changes status (`paused`, `budget_paused`,
 *     `running`, `stopped`, `failed`, `complete`) — preserving in-flight investigation
 *     steps on pause->resume and enforcing full terminal closure on terminal states.
 *  3. Exhaustive startup crash-recovery contract across ALL 7 `RunStatus` values.
 *  4. Always-on, emit-only `checkRunLiveness()` invoked in the scheduler wake loop.
 */
import type { DatabaseSync } from 'node:sqlite'
import type { RunStatus, WorkerStatus } from '../domain.ts'
import { STEP_STATUS, type ChainStepStatus } from '../step-status.ts'
import type { Run } from './store-session.ts'
import { recordQaAnomaly } from './qa-anomalies.ts'
import {
  assertNever,
  isCanonicalRunStatus,
  isTerminalRunStatus,
} from './run-status.ts'

export type ApprovalRequestStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'canceled'
export type ApprovalLeaseStatus = 'active' | 'exhausted' | 'expired' | 'revoked'
export type BoardMemberLifecycleState = 'waiting' | 'working' | 'retired'

export type LifecycleEntityKind =
  | 'run'
  | 'worker'
  | 'chainStep'
  | 'approval'
  | 'lease'
  | 'boardMember'

export type LifecycleEnforcementMode = 'warn' | 'enforce'

export interface ReclaimedLabContainerRef {
  runId: string
  containerName: string
}

const pendingStoreStartupReclaimedContainers = new WeakMap<object, ReclaimedLabContainerRef[]>()
const recoveredStartupStores = new WeakSet<object>()

/** Record that `storeKey` has completed startup recovery at open (preventing duplicate recovery after live runs start). */
export function markStoreStartupRecovered(storeKey: object): void {
  recoveredStartupStores.add(storeKey)
}

/** True when `storeKey` already executed startup recovery (at `Store` open or `AppRuntime.startupRecover()`). */
export function isStoreStartupRecovered(storeKey: object): boolean {
  return recoveredStartupStores.has(storeKey)
}

/**
 * Stash `lab_containers` rows reclaimed during standalone `Store` startup so a subsequent
 * `AppRuntime.startupRecover()` or `Execution.start()` call still hands them to `LabRunner.ensureStartupRecovery`.
 */
export function recordStoreStartupReclaimedContainers(
  storeKey: object,
  containers: readonly ReclaimedLabContainerRef[],
): void {
  markStoreStartupRecovered(storeKey)
  if (containers.length === 0) return
  const existing = pendingStoreStartupReclaimedContainers.get(storeKey) ?? []
  pendingStoreStartupReclaimedContainers.set(storeKey, [...existing, ...containers])
}

/** Drain and return any stashed reclaimed `lab_containers` rows for `storeKey`. */
export function consumeStoreStartupReclaimedContainers(storeKey: object): ReclaimedLabContainerRef[] {
  const existing = pendingStoreStartupReclaimedContainers.get(storeKey)
  if (!existing || existing.length === 0) return []
  pendingStoreStartupReclaimedContainers.delete(storeKey)
  return existing
}

const NON_TERMINAL_STEP_TARGETS: readonly ChainStepStatus[] = [
  'pending',
  'ready',
  'running',
  'blocked',
  'complete',
  'tainted',
  'canceled',
  'infra_failed',
  'turn_capped',
  'nudged_out',
  'rotated_partial',
  'model_failure',
]

function buildChainStepTransitionTable(): Readonly<Record<ChainStepStatus, ReadonlySet<ChainStepStatus>>> {
  const table = {} as Record<ChainStepStatus, ReadonlySet<ChainStepStatus>>
  const allStatuses = Object.keys(STEP_STATUS) as ChainStepStatus[]
  for (const status of allStatuses) {
    switch (status) {
      case 'pending':
        table[status] = new Set<ChainStepStatus>(['ready', 'blocked', 'tainted', 'canceled', 'running'])
        break
      case 'ready':
        table[status] = new Set<ChainStepStatus>(['running', 'blocked', 'tainted', 'canceled', 'pending'])
        break
      case 'running':
        table[status] = new Set<ChainStepStatus>(NON_TERMINAL_STEP_TARGETS.filter(s => s !== 'running'))
        break
      case 'blocked':
        table[status] = new Set<ChainStepStatus>(['pending', 'ready', 'tainted', 'canceled'])
        break
      case 'complete':
      case 'canceled':
      case 'infra_failed':
      case 'turn_capped':
      case 'nudged_out':
      case 'rotated_partial':
      case 'model_failure':
        // Terminal step statuses can only be tainted on retroactive scope revocation or re-opened to ready by explicit retry/requeue.
        table[status] = new Set<ChainStepStatus>(['tainted', 'ready'])
        break
      case 'tainted':
        table[status] = new Set<ChainStepStatus>()
        break
      default:
        assertNever(status, 'Unhandled ChainStepStatus in lifecycle transition table')
    }
  }
  return Object.freeze(table)
}

/**
 * Total persisted transition tables for all 6 lifecycle entities.
 * Terminal run statuses (`stopped`, `failed`, `complete`) have ZERO outgoing edges.
 */
export const LIFECYCLE_TRANSITION_TABLES = Object.freeze({
  run: Object.freeze<Record<RunStatus, ReadonlySet<RunStatus>>>({
    waiting: new Set<RunStatus>(['running', 'paused', 'stopped', 'failed', 'complete']),
    running: new Set<RunStatus>(['waiting', 'paused', 'budget_paused', 'stopped', 'failed', 'complete']),
    paused: new Set<RunStatus>(['waiting', 'running', 'budget_paused', 'stopped', 'failed', 'complete']),
    budget_paused: new Set<RunStatus>(['waiting', 'running', 'paused', 'stopped', 'failed', 'complete']),
    stopped: new Set<RunStatus>(),
    failed: new Set<RunStatus>(),
    complete: new Set<RunStatus>(),
  }),
  worker: Object.freeze<Record<WorkerStatus, ReadonlySet<WorkerStatus>>>({
    queued: new Set<WorkerStatus>(['running', 'paused', 'waiting_approval', 'complete', 'canceled', 'failed']),
    running: new Set<WorkerStatus>(['queued', 'paused', 'waiting_approval', 'complete', 'canceled', 'failed']),
    paused: new Set<WorkerStatus>(['queued', 'running', 'canceled', 'failed']),
    waiting_approval: new Set<WorkerStatus>(['queued', 'running', 'paused', 'canceled', 'failed']),
    complete: new Set<WorkerStatus>(),
    canceled: new Set<WorkerStatus>(),
    failed: new Set<WorkerStatus>(),
  }),
  chainStep: buildChainStepTransitionTable(),
  approval: Object.freeze<Record<ApprovalRequestStatus, ReadonlySet<ApprovalRequestStatus>>>({
    pending: new Set<ApprovalRequestStatus>(['approved', 'denied', 'expired', 'canceled']),
    approved: new Set<ApprovalRequestStatus>(),
    denied: new Set<ApprovalRequestStatus>(),
    expired: new Set<ApprovalRequestStatus>(),
    canceled: new Set<ApprovalRequestStatus>(),
  }),
  lease: Object.freeze<Record<ApprovalLeaseStatus, ReadonlySet<ApprovalLeaseStatus>>>({
    active: new Set<ApprovalLeaseStatus>(['exhausted', 'expired', 'revoked']),
    exhausted: new Set<ApprovalLeaseStatus>(['active', 'revoked']),
    expired: new Set<ApprovalLeaseStatus>(['active', 'revoked']),
    revoked: new Set<ApprovalLeaseStatus>(),
  }),
  boardMember: Object.freeze<Record<BoardMemberLifecycleState, ReadonlySet<BoardMemberLifecycleState>>>({
    waiting: new Set<BoardMemberLifecycleState>(['working', 'retired']),
    working: new Set<BoardMemberLifecycleState>(['waiting', 'retired']),
    retired: new Set<BoardMemberLifecycleState>(['waiting']),
  }),
})

export class IllegalLifecycleTransitionError extends Error {
  readonly code = 'ILLEGAL_LIFECYCLE_TRANSITION'
  readonly entity: LifecycleEntityKind
  readonly from: string
  readonly to: string

  constructor(entity: LifecycleEntityKind, from: string, to: string, context?: string) {
    super(`Illegal ${entity} lifecycle transition: ${from} -> ${to}${context ? ` (${context})` : ''}.`)
    this.name = 'IllegalLifecycleTransitionError'
    this.entity = entity
    this.from = from
    this.to = to
  }
}

export interface TransitionValidationOptions {
  mode?: LifecycleEnforcementMode
  context?: string
  runId?: string | null
  entityId?: string | null
  onWarning?: (warning: LifecycleTransitionWarning) => void
  env?: NodeJS.ProcessEnv
}

export interface LifecycleTransitionWarning {
  entity: LifecycleEntityKind
  from: string
  to: string
  context?: string
  runId?: string | null
  entityId?: string | null
  at: number
}

export interface TransitionValidationResult {
  allowed: boolean
  sameState: boolean
  warning?: LifecycleTransitionWarning
}

function resolveEnforcementMode(options?: TransitionValidationOptions): LifecycleEnforcementMode {
  if (options?.mode) return options.mode
  const env = options?.env ?? process.env
  return env.KOVO_LIFECYCLE_ENFORCE === '1' ? 'enforce' : 'warn'
}

/**
 * Validate a persisted lifecycle transition against `LIFECYCLE_TRANSITION_TABLES`.
 * Runs in warn mode with structured telemetry by default; throws `IllegalLifecycleTransitionError`
 * when `mode === 'enforce'` or `KOVO_LIFECYCLE_ENFORCE=1`.
 */
export function validateLifecycleTransition(
  entity: LifecycleEntityKind,
  from: string,
  to: string,
  options?: TransitionValidationOptions,
): TransitionValidationResult {
  if (from === to) return { allowed: true, sameState: true }
  const table = LIFECYCLE_TRANSITION_TABLES[entity] as Readonly<Record<string, ReadonlySet<string>>>
  const allowedNext = table[from]
  if (allowedNext && allowedNext.has(to)) {
    return { allowed: true, sameState: false }
  }
  const warning: LifecycleTransitionWarning = {
    entity,
    from,
    to,
    ...(options?.context ? { context: options.context } : {}),
    ...(options?.runId !== undefined ? { runId: options.runId } : {}),
    ...(options?.entityId !== undefined ? { entityId: options.entityId } : {}),
    at: Date.now(),
  }
  const mode = resolveEnforcementMode(options)
  if (mode === 'enforce') {
    throw new IllegalLifecycleTransitionError(entity, from, to, options?.context)
  }
  options?.onWarning?.(warning)
  return { allowed: false, sameState: false, warning }
}

// ============================================================================
// Co-Transitions on Persisted Run Status Changes
// ============================================================================

export interface RunCoTransitionContext {
  client: DatabaseSync
  event: (runId: string | null, kind: string, message: string, detail?: Record<string, unknown>) => void
  refreshReadyChainSteps?: (runId: string, goalRevision: number) => void
}

export interface RunCoTransitionReport {
  assignmentsUpdated: number
  chainStepsUpdated: number
  boardMembersUpdated: number
  approvalsUpdated: number
  leasesUpdated: number
}

function settleTerminalRunEntitiesSql(
  client: DatabaseSync,
  runId: string,
  terminalStatus: 'stopped' | 'failed' | 'complete',
  now: number,
  reasonPrefix: string,
): RunCoTransitionReport {
  const outcomeText = `${reasonPrefix} (${terminalStatus}).`
  const assignChanges = terminalStatus === 'complete'
    ? client.prepare(
        `UPDATE assignments
         SET status = 'canceled', lease = NULL, lease_expires_at = NULL, approval_parked_at = NULL,
             outcome = coalesce(outcome, ?)
         WHERE run_id = ? AND phase != 'retest' AND status IN ('queued', 'running', 'paused', 'waiting_approval')`,
      ).run(outcomeText, runId)
    : client.prepare(
        `UPDATE assignments
         SET status = 'canceled', lease = NULL, lease_expires_at = NULL, approval_parked_at = NULL,
             outcome = coalesce(outcome, ?)
         WHERE run_id = ? AND status IN ('queued', 'running', 'paused', 'waiting_approval')`,
      ).run(outcomeText, runId)

  const stepChanges = client.prepare(
    `UPDATE chain_steps
     SET status = 'canceled', assigned_worker_id = NULL, updated_at = ?
     WHERE run_id = ? AND status = 'running'`,
  ).run(now, runId)

  const boardChanges = client.prepare(
    `UPDATE board_members
     SET state = 'retired', active_assignment_id = NULL, updated_at = ?
     WHERE run_id = ? AND state != 'retired'`,
  ).run(now, runId)

  const approvalChanges = client.prepare(
    `UPDATE approval_requests
     SET status = 'canceled', decided_at = ?
     WHERE run_id = ? AND status = 'pending'`,
  ).run(now, runId)

  let leasesUpdated = 0
  try {
    const leaseChanges = client.prepare(
      `UPDATE approval_leases
       SET status = 'revoked', updated_at = ?
       WHERE run_id = ? AND status = 'active'`,
    ).run(now, runId)
    leasesUpdated = Number((leaseChanges as { changes?: number }).changes ?? 0)
  } catch {
    // Legacy test schemas without approval_leases table.
  }

  return {
    assignmentsUpdated: Number((assignChanges as { changes?: number }).changes ?? 0),
    chainStepsUpdated: Number((stepChanges as { changes?: number }).changes ?? 0),
    boardMembersUpdated: Number((boardChanges as { changes?: number }).changes ?? 0),
    approvalsUpdated: Number((approvalChanges as { changes?: number }).changes ?? 0),
    leasesUpdated,
  }
}

/**
 * Apply authoritative co-transitions across `assignments`, `chain_steps`, `board_members`,
 * `approval_requests`, and `approval_leases` when `run` transitions to `nextStatus`.
 */
export function applyRunStatusCoTransitions(
  ctx: RunCoTransitionContext,
  run: Pick<Run, 'id' | 'status' | 'goalRevision'>,
  nextStatus: RunStatus,
  now = Date.now(),
): RunCoTransitionReport {
  validateLifecycleTransition('run', run.status, nextStatus, {
    context: 'setStatus',
    runId: run.id,
    entityId: run.id,
    onWarning: w => {
      ctx.event(run.id, 'lifecycle.transition_warning', `Illegal run transition ${w.from} -> ${w.to}.`, {
        entity: w.entity,
        from: w.from,
        to: w.to,
        context: w.context ?? null,
      })
    },
  })

  switch (nextStatus) {
    case 'paused':
    case 'budget_paused': {
      // Pause active/queued/unparked assignments while preserving operator-parked waiting_approval slots.
      const assignChanges = ctx.client.prepare(
        `UPDATE assignments
         SET status = 'paused', lease = NULL, lease_expires_at = NULL
         WHERE run_id = ?
           AND status IN ('queued', 'running', 'waiting_approval')
           AND NOT (status = 'waiting_approval' AND approval_parked_at IS NOT NULL)`,
      ).run(run.id)

      // Requeue non-parked in-flight investigation steps back to `ready` so pause->resume never drops work.
      const stepChanges = ctx.client.prepare(
        `UPDATE chain_steps
         SET status = 'ready', assigned_worker_id = NULL, updated_at = ?
         WHERE run_id = ? AND goal_revision = ? AND status = 'running'
           AND NOT EXISTS (
             SELECT 1 FROM assignments a
             WHERE a.id = chain_steps.assigned_worker_id
               AND a.status = 'waiting_approval'
               AND a.approval_parked_at IS NOT NULL
           )`,
      ).run(now, run.id, run.goalRevision)

      const boardChanges = ctx.client.prepare(
        `UPDATE board_members
         SET state = 'waiting', active_assignment_id = NULL, updated_at = ?
         WHERE run_id = ? AND state = 'working'`,
      ).run(now, run.id)

      return {
        assignmentsUpdated: Number((assignChanges as { changes?: number }).changes ?? 0),
        chainStepsUpdated: Number((stepChanges as { changes?: number }).changes ?? 0),
        boardMembersUpdated: Number((boardChanges as { changes?: number }).changes ?? 0),
        approvalsUpdated: 0,
        leasesUpdated: 0,
      }
    }
    case 'running': {
      const assignChanges = ctx.client.prepare(
        `UPDATE assignments
         SET status = 'queued', lease = NULL, lease_expires_at = NULL
         WHERE run_id = ? AND goal_revision = ? AND status = 'paused'`,
      ).run(run.id, run.goalRevision)

      // Preserve any stranded running investigation step on resume by requeuing it to ready.
      const stepChanges = ctx.client.prepare(
        `UPDATE chain_steps
         SET status = 'ready', assigned_worker_id = NULL, updated_at = ?
         WHERE run_id = ? AND goal_revision = ? AND status = 'running'
           AND (
             assigned_worker_id IS NULL
             OR NOT EXISTS (
               SELECT 1 FROM assignments a
               WHERE a.id = chain_steps.assigned_worker_id
                 AND a.status IN ('running', 'waiting_approval')
             )
           )`,
      ).run(now, run.id, run.goalRevision)

      const chainStepsUpdated = Number((stepChanges as { changes?: number }).changes ?? 0)
      if (chainStepsUpdated > 0) {
        ctx.refreshReadyChainSteps?.(run.id, run.goalRevision)
      }

      return {
        assignmentsUpdated: Number((assignChanges as { changes?: number }).changes ?? 0),
        chainStepsUpdated,
        boardMembersUpdated: 0,
        approvalsUpdated: 0,
        leasesUpdated: 0,
      }
    }
    case 'waiting':
      return {
        assignmentsUpdated: 0,
        chainStepsUpdated: 0,
        boardMembersUpdated: 0,
        approvalsUpdated: 0,
        leasesUpdated: 0,
      }
    case 'stopped':
    case 'failed':
    case 'complete':
      return settleTerminalRunEntitiesSql(ctx.client, run.id, nextStatus, now, 'Run ended')
    default:
      return assertNever(nextStatus, 'Unhandled RunStatus in applyRunStatusCoTransitions')
  }
}

// ============================================================================
// Exhaustive Startup Crash-Recovery Contract (All 7 RunStatus Values)
// ============================================================================

export interface CrashRecoveryReport {
  pausedRuns: number
  requeuedAssignments: number
  requeuedSteps: number
  closedTerminalRuns: number
  resetBoardMembers: number
  expiredApprovals: number
  expiredLeases: number
  reclaimedContainers: Array<{ runId: string; containerName: string }>
  changed: boolean
}

export interface CrashRecoveryContext {
  client: DatabaseSync
  workspaceId: string
  event: (runId: string | null, kind: string, message: string, detail?: Record<string, unknown>) => void
}

/**
 * Idempotent crash-recovery contract covering EVERY `RunStatus` (`waiting`, `running`,
 * `paused`, `budget_paused`, `stopped`, `failed`, `complete`):
 *  - `running`: transitions to `paused`, requeues `running` chain steps to `ready`, requeues
 *    non-parked active/paused assignments to `queued`, resets `working` board members, emits `interrupted`.
 *  - `paused` / `budget_paused`: keeps status, requeues stranded non-parked `running` chain steps
 *    to `ready`, requeues non-parked `running`/`paused`/`waiting_approval` assignments to `queued`
 *    (explicitly codified contract), resets `working` board members.
 *  - `waiting`: keeps status, requeues any stranded `running` assignments/steps and `working` board members.
 *  - `stopped` / `failed` / `complete`: closes any stranded non-terminal assignments, `running` steps,
 *    non-retired board members, `pending` approvals, and `active` leases (preserving `retest` on `complete`).
 *  - Workspace-wide: expires past-due `approval_requests` and `approval_leases`, and reclaims ALL
 *    `running` and `orphaned` `lab_containers` rows (returning them for `LabRunner.ensureStartupRecovery`).
 *  - Permanently `failed` / `complete` / `canceled` assignments are NEVER re-queued.
 */
function recoverSingleRunRow(
  ctx: CrashRecoveryContext,
  row: { id: string; status: string; goalRevision: number },
  now: number,
  report: CrashRecoveryReport,
  buckets: { interruptedRunIds: string[]; nonTerminalRunIds: string[]; waitingRunIds: string[] },
): void {
  if (!isCanonicalRunStatus(row.status)) {
    if (isTerminalRunStatus(row.status)) {
      const closed = settleTerminalRunEntitiesSql(ctx.client, row.id, 'stopped', now, 'Crash recovery terminal closure')
      const total = closed.assignmentsUpdated + closed.chainStepsUpdated + closed.boardMembersUpdated + closed.approvalsUpdated + closed.leasesUpdated
      if (total > 0) {
        report.closedTerminalRuns += 1
        report.resetBoardMembers += closed.boardMembersUpdated
      }
    }
    return
  }

  const status: RunStatus = row.status
  switch (status) {
    case 'running': {
      ctx.client.prepare('UPDATE runs SET status = ? WHERE id = ?').run('paused', row.id)
      const steps = ctx.client.prepare(
        `UPDATE chain_steps
         SET status = 'ready', assigned_worker_id = NULL, updated_at = ?
         WHERE run_id = ? AND status = 'running'
           AND NOT EXISTS (
             SELECT 1 FROM assignments a
             WHERE a.id = chain_steps.assigned_worker_id
               AND a.status = 'waiting_approval'
               AND a.approval_parked_at IS NOT NULL
           )`,
      ).run(now, row.id)
      report.requeuedSteps += Number((steps as { changes?: number }).changes ?? 0)
      report.pausedRuns += 1
      buckets.interruptedRunIds.push(row.id)
      buckets.nonTerminalRunIds.push(row.id)
      break
    }
    case 'paused':
    case 'budget_paused': {
      const steps = ctx.client.prepare(
        `UPDATE chain_steps
         SET status = 'ready', assigned_worker_id = NULL, updated_at = ?
         WHERE run_id = ? AND status = 'running'
           AND NOT EXISTS (
             SELECT 1 FROM assignments a
             WHERE a.id = chain_steps.assigned_worker_id
               AND a.status = 'waiting_approval'
               AND a.approval_parked_at IS NOT NULL
           )`,
      ).run(now, row.id)
      report.requeuedSteps += Number((steps as { changes?: number }).changes ?? 0)
      buckets.nonTerminalRunIds.push(row.id)
      break
    }
    case 'waiting': {
      const steps = ctx.client.prepare(
        `UPDATE chain_steps
         SET status = 'ready', assigned_worker_id = NULL, updated_at = ?
         WHERE run_id = ? AND status = 'running'`,
      ).run(now, row.id)
      report.requeuedSteps += Number((steps as { changes?: number }).changes ?? 0)
      buckets.waitingRunIds.push(row.id)
      break
    }
    case 'stopped':
    case 'failed':
    case 'complete': {
      const closed = settleTerminalRunEntitiesSql(ctx.client, row.id, status, now, 'Crash recovery terminal closure')
      const total = closed.assignmentsUpdated + closed.chainStepsUpdated + closed.boardMembersUpdated + closed.approvalsUpdated + closed.leasesUpdated
      if (total > 0) {
        report.closedTerminalRuns += 1
        report.resetBoardMembers += closed.boardMembersUpdated
      }
      break
    }
    default:
      assertNever(status, 'Unhandled RunStatus in reconcilePersistedCrashRecovery')
  }
}

export function reconcilePersistedCrashRecovery(
  ctx: CrashRecoveryContext,
  now = Date.now(),
): CrashRecoveryReport {
  const report: CrashRecoveryReport = {
    pausedRuns: 0,
    requeuedAssignments: 0,
    requeuedSteps: 0,
    closedTerminalRuns: 0,
    resetBoardMembers: 0,
    expiredApprovals: 0,
    expiredLeases: 0,
    reclaimedContainers: [],
    changed: false,
  }

  const allRuns = ctx.client.prepare(
    'SELECT id, status, goal_revision AS goalRevision FROM runs WHERE workspace_id = ?',
  ).all(ctx.workspaceId) as Array<{ id: string; status: string; goalRevision: number }>

  const buckets = {
    interruptedRunIds: [] as string[],
    nonTerminalRunIds: [] as string[],
    waitingRunIds: [] as string[],
  }

  for (const row of allRuns) {
    recoverSingleRunRow(ctx, row, now, report, buckets)
  }

  const { interruptedRunIds, nonTerminalRunIds, waitingRunIds } = buckets

  if (nonTerminalRunIds.length > 0) {
    const placeholders = nonTerminalRunIds.map(() => '?').join(', ')
    const requeued = ctx.client.prepare(
      `UPDATE assignments
       SET status = 'queued', lease = NULL, lease_expires_at = NULL
       WHERE run_id IN (${placeholders}) AND (
         status IN ('running', 'paused')
         OR (status = 'waiting_approval' AND approval_parked_at IS NULL)
       )`,
    ).run(...nonTerminalRunIds) as { changes?: number }
    report.requeuedAssignments += Number(requeued.changes ?? 0)

    const resetMembers = ctx.client.prepare(
      `UPDATE board_members
       SET state = 'waiting', active_assignment_id = NULL, updated_at = ?
       WHERE run_id IN (${placeholders}) AND state = 'working'`,
    ).run(now, ...nonTerminalRunIds) as { changes?: number }
    report.resetBoardMembers += Number(resetMembers.changes ?? 0)
  }

  if (waitingRunIds.length > 0) {
    const placeholders = waitingRunIds.map(() => '?').join(', ')
    const requeuedWaiting = ctx.client.prepare(
      `UPDATE assignments
       SET status = 'queued', lease = NULL, lease_expires_at = NULL
       WHERE run_id IN (${placeholders}) AND status = 'running'`,
    ).run(...waitingRunIds) as { changes?: number }
    report.requeuedAssignments += Number(requeuedWaiting.changes ?? 0)

    const resetWaitingMembers = ctx.client.prepare(
      `UPDATE board_members
       SET state = 'waiting', active_assignment_id = NULL, updated_at = ?
       WHERE run_id IN (${placeholders}) AND state = 'working'`,
    ).run(now, ...waitingRunIds) as { changes?: number }
    report.resetBoardMembers += Number(resetWaitingMembers.changes ?? 0)
  }

  const expiredApprovals = ctx.client.prepare(
    `UPDATE approval_requests
     SET status = 'expired', decided_at = ?,
         policy_note = coalesce(policy_note, 'Expired approval lease cleared during crash recovery.')
     WHERE status = 'pending' AND expires_at < ?
       AND run_id IN (SELECT id FROM runs WHERE workspace_id = ?)`,
  ).run(now, now, ctx.workspaceId) as { changes?: number }
  report.expiredApprovals = Number(expiredApprovals.changes ?? 0)

  try {
    const expiredLeases = ctx.client.prepare(
      `UPDATE approval_leases
       SET status = 'expired', updated_at = ?
       WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?
         AND run_id IN (SELECT id FROM runs WHERE workspace_id = ?)`,
    ).run(now, now, ctx.workspaceId) as { changes?: number }
    report.expiredLeases = Number(expiredLeases.changes ?? 0)
  } catch {
    // Legacy test schemas without approval_leases table.
  }

  // Reclaim ALL running/orphaned lab_containers across ALL runs in this workspace (any RunStatus).
  const workspaceRunIdSet = new Set(allRuns.map(r => r.id))
  const containerRows = (ctx.client.prepare(
    `SELECT id, run_id AS runId, container_name AS containerName, status
     FROM lab_containers
     WHERE status IN (?, ?)`,
  ).all('orphaned', 'running') as Array<{ id: string; runId: string; containerName: string; status: string }>)
    .filter(row => row.status === 'orphaned' || workspaceRunIdSet.has(row.runId))

  if (containerRows.length > 0) {
    const unique = new Map(containerRows.map(row => [row.id, row]))
    const ids = [...unique.keys()]
    ctx.client.prepare(
      `DELETE FROM lab_containers WHERE id IN (${ids.map(() => '?').join(', ')})`,
    ).run(...ids)
    report.reclaimedContainers = [...unique.values()].map(row => ({
      runId: row.runId,
      containerName: row.containerName,
    }))
  }

  for (const runId of interruptedRunIds) {
    ctx.event(runId, 'interrupted', 'The application restarted. Resume to continue from saved evidence.')
  }

  report.changed = (
    report.pausedRuns > 0
    || report.requeuedAssignments > 0
    || report.requeuedSteps > 0
    || report.closedTerminalRuns > 0
    || report.resetBoardMembers > 0
    || report.expiredApprovals > 0
    || report.expiredLeases > 0
    || report.reclaimedContainers.length > 0
  )

  if (report.reclaimedContainers.length > 0 || report.expiredApprovals > 0 || report.closedTerminalRuns > 0) {
    ctx.event(null, 'recovery.completed', 'Crash recovery reclaimed runtime state.', {
      pausedRuns: report.pausedRuns,
      requeuedAssignments: report.requeuedAssignments,
      requeuedSteps: report.requeuedSteps,
      closedTerminalRuns: report.closedTerminalRuns,
      resetBoardMembers: report.resetBoardMembers,
      expiredApprovals: report.expiredApprovals,
      expiredLeases: report.expiredLeases,
      reclaimedContainers: report.reclaimedContainers.map(row => row.containerName).slice(0, 50),
    })
  }

  return report
}

// ============================================================================
// Always-On Emit-Only Liveness & Terminal-Closure Checker (`checkRunLiveness`)
// ============================================================================

export type RunLivenessViolationCode =
  | 'terminal_run_active_assignment'
  | 'terminal_run_running_step'
  | 'terminal_run_working_board_member'
  | 'terminal_run_pending_approval'
  | 'terminal_run_active_lease'
  | 'paused_run_running_assignment'
  | 'paused_run_running_step'
  | 'running_step_dead_worker'
  | 'running_assignment_expired_lease'
  | 'working_board_member_idle'
  | 'run_status_phase_mismatch'

export interface RunLivenessViolation {
  code: RunLivenessViolationCode
  runId: string
  entityId?: string | null
  message: string
  detail?: Record<string, unknown>
}

export interface RunLivenessSnapshot {
  run: Pick<Run, 'id' | 'status' | 'phase' | 'goalRevision'>
  assignments: ReadonlyArray<{
    id: string
    phase: string
    status: string
    leaseExpiresAt?: number | null
    approvalParkedAt?: number | null
  }>
  chainSteps: ReadonlyArray<{
    id: string
    goalRevision: number
    status: string
    assignedWorkerId?: string | null
  }>
  boardMembers?: ReadonlyArray<{
    id: string
    handle: string
    state: string
    activeAssignmentId?: string | null
  }>
  approvalRequests?: ReadonlyArray<{
    id: string
    status: string
  }>
  approvalLeases?: ReadonlyArray<{
    id: string
    status: string
  }>
  activeAssignmentIds?: ReadonlySet<string>
  now?: number
}

function collectTerminalRunViolations(
  run: Pick<Run, 'id' | 'status'>,
  assignments: RunLivenessSnapshot['assignments'],
  chainSteps: RunLivenessSnapshot['chainSteps'],
  boardMembers: NonNullable<RunLivenessSnapshot['boardMembers']>,
  approvalRequests: NonNullable<RunLivenessSnapshot['approvalRequests']>,
  approvalLeases: NonNullable<RunLivenessSnapshot['approvalLeases']>,
  violations: RunLivenessViolation[],
): void {
  for (const a of assignments) {
    if (run.status === 'complete' && a.phase === 'retest') continue
    if (a.status === 'running' || a.status === 'paused' || a.status === 'waiting_approval' || a.status === 'queued') {
      violations.push({
        code: 'terminal_run_active_assignment',
        runId: run.id,
        entityId: a.id,
        message: `Terminal run ${run.id} (${run.status}) has non-terminal assignment ${a.id} (${a.status}).`,
        detail: { runStatus: run.status, assignmentId: a.id, assignmentStatus: a.status, phase: a.phase },
      })
    }
  }
  for (const step of chainSteps) {
    if (step.status === 'running') {
      violations.push({
        code: 'terminal_run_running_step',
        runId: run.id,
        entityId: step.id,
        message: `Terminal run ${run.id} (${run.status}) still has running chain step ${step.id}.`,
        detail: { runStatus: run.status, stepId: step.id, assignedWorkerId: step.assignedWorkerId ?? null },
      })
    }
  }
  for (const m of boardMembers) {
    if (m.state === 'working') {
      violations.push({
        code: 'terminal_run_working_board_member',
        runId: run.id,
        entityId: m.id,
        message: `Terminal run ${run.id} (${run.status}) still has working board member ${m.handle}.`,
        detail: { runStatus: run.status, memberId: m.id, handle: m.handle },
      })
    }
  }
  for (const req of approvalRequests) {
    if (req.status === 'pending') {
      violations.push({
        code: 'terminal_run_pending_approval',
        runId: run.id,
        entityId: req.id,
        message: `Terminal run ${run.id} (${run.status}) still has pending approval request ${req.id}.`,
        detail: { runStatus: run.status, approvalId: req.id },
      })
    }
  }
  for (const lease of approvalLeases) {
    if (lease.status === 'active') {
      violations.push({
        code: 'terminal_run_active_lease',
        runId: run.id,
        entityId: lease.id,
        message: `Terminal run ${run.id} (${run.status}) still has active approval lease ${lease.id}.`,
        detail: { runStatus: run.status, leaseId: lease.id },
      })
    }
  }
}

/**
 * Pure, emit-only liveness & terminal-closure invariant checker.
 * NEVER mutates database or runtime state; returns every detected violation for structured telemetry.
 */
export function checkRunLiveness(snapshot: RunLivenessSnapshot): RunLivenessViolation[] {
  const violations: RunLivenessViolation[] = []
  const { run, assignments, chainSteps } = snapshot
  const boardMembers = snapshot.boardMembers ?? []
  const approvalRequests = snapshot.approvalRequests ?? []
  const approvalLeases = snapshot.approvalLeases ?? []
  const activeAssignmentIds = snapshot.activeAssignmentIds
  const now = snapshot.now ?? Date.now()
  const workerById = new Map(assignments.map(a => [a.id, a]))

  if (run.phase === 'complete' && run.status !== 'complete') {
    violations.push({
      code: 'run_status_phase_mismatch',
      runId: run.id,
      message: `Run ${run.id} has phase="complete" but status="${run.status}".`,
      detail: { phase: run.phase, status: run.status },
    })
  }

  if (isTerminalRunStatus(run.status)) {
    collectTerminalRunViolations(run, assignments, chainSteps, boardMembers, approvalRequests, approvalLeases, violations)
    return violations
  }

  if (run.status === 'paused' || run.status === 'budget_paused') {
    for (const a of assignments) {
      if (a.status === 'running') {
        violations.push({
          code: 'paused_run_running_assignment',
          runId: run.id,
          entityId: a.id,
          message: `Paused run ${run.id} (${run.status}) still has running assignment ${a.id}.`,
          detail: { runStatus: run.status, assignmentId: a.id },
        })
      }
    }
    for (const step of chainSteps) {
      if (step.goalRevision !== run.goalRevision || step.status !== 'running') continue
      const assigned = step.assignedWorkerId ? workerById.get(step.assignedWorkerId) : undefined
      const parkedApproval = assigned?.status === 'waiting_approval' && assigned.approvalParkedAt != null
      if (!parkedApproval) {
        violations.push({
          code: 'paused_run_running_step',
          runId: run.id,
          entityId: step.id,
          message: `Paused run ${run.id} (${run.status}) still has unparked running chain step ${step.id}.`,
          detail: { runStatus: run.status, stepId: step.id, assignedWorkerId: step.assignedWorkerId ?? null },
        })
      }
    }
  }

  for (const step of chainSteps) {
    if (step.goalRevision !== run.goalRevision || step.status !== 'running') continue
    const worker = step.assignedWorkerId ? workerById.get(step.assignedWorkerId) : undefined
    const hasLiveHandle = Boolean(step.assignedWorkerId && activeAssignmentIds?.has(step.assignedWorkerId))
    if (!hasLiveHandle && (!worker || worker.status === 'complete' || worker.status === 'failed' || worker.status === 'canceled')) {
      violations.push({
        code: 'running_step_dead_worker',
        runId: run.id,
        entityId: step.id,
        message: `Running chain step ${step.id} on run ${run.id} points to missing/terminal worker ${step.assignedWorkerId ?? 'null'}.`,
        detail: { stepId: step.id, assignedWorkerId: step.assignedWorkerId ?? null, workerStatus: worker?.status ?? null },
      })
    }
  }

  if (run.status === 'running' && activeAssignmentIds) {
    for (const a of assignments) {
      if (a.status !== 'running') continue
      if (activeAssignmentIds.has(a.id)) continue
      if (typeof a.leaseExpiresAt === 'number' && a.leaseExpiresAt < now) {
        violations.push({
          code: 'running_assignment_expired_lease',
          runId: run.id,
          entityId: a.id,
          message: `Running assignment ${a.id} on run ${run.id} has expired lease with no live handle.`,
          detail: { assignmentId: a.id, leaseExpiresAt: a.leaseExpiresAt, now },
        })
      }
    }
  }

  for (const m of boardMembers) {
    if (m.state !== 'working') continue
    const worker = m.activeAssignmentId ? workerById.get(m.activeAssignmentId) : undefined
    if (!worker || worker.status === 'complete' || worker.status === 'failed' || worker.status === 'canceled') {
      violations.push({
        code: 'working_board_member_idle',
        runId: run.id,
        entityId: m.id,
        message: `Working board member ${m.handle} on run ${run.id} has no active assignment.`,
        detail: { memberId: m.id, handle: m.handle, activeAssignmentId: m.activeAssignmentId ?? null },
      })
    }
  }

  return violations
}

export interface EmitRunLivenessStore {
  workerList: (runId: string) => RunLivenessSnapshot['assignments']
  listChainSteps: (runId: string, goalRevision?: number) => RunLivenessSnapshot['chainSteps']
  listBoardMembers?: (runId: string) => NonNullable<RunLivenessSnapshot['boardMembers']>
  listApprovalRequests?: (runId: string) => NonNullable<RunLivenessSnapshot['approvalRequests']>
  listApprovalLeases?: (runId: string) => NonNullable<RunLivenessSnapshot['approvalLeases']>
}

/**
 * Always-on, emit-only wake-loop liveness check: inspects `run`, deduplicates by violation
 * signature per run (clearing resolved signatures), emits `run.invariant_violation` events,
 * and records anomalies in `qa-anomalies.ts` without mutating any DB state.
 */
export function emitRunLivenessViolations(
  storage: EmitRunLivenessStore,
  run: Pick<Run, 'id' | 'status' | 'phase' | 'goalRevision'>,
  activeAssignmentIds: ReadonlySet<string>,
  emittedSignaturesByRun: Map<string, Set<string>>,
  emitEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void,
  now = Date.now(),
): RunLivenessViolation[] {
  const violations = checkRunLiveness({
    run,
    assignments: storage.workerList(run.id),
    chainSteps: storage.listChainSteps(run.id, run.goalRevision),
    boardMembers: storage.listBoardMembers?.(run.id) ?? [],
    approvalRequests: storage.listApprovalRequests?.(run.id) ?? [],
    approvalLeases: storage.listApprovalLeases?.(run.id) ?? [],
    activeAssignmentIds,
    now,
  })

  if (violations.length === 0) {
    emittedSignaturesByRun.delete(run.id)
    return []
  }

  let seen = emittedSignaturesByRun.get(run.id)
  if (!seen) {
    seen = new Set<string>()
    emittedSignaturesByRun.set(run.id, seen)
  }

  const currentSignatures = new Set<string>()
  const newlyEmitted: RunLivenessViolation[] = []
  for (const v of violations) {
    const sig = `${v.code}:${v.entityId ?? ''}`
    currentSignatures.add(sig)
    if (seen.has(sig)) continue
    seen.add(sig)
    newlyEmitted.push(v)
    emitEvent(run.id, 'run.invariant_violation', v.message, {
      code: v.code,
      entityId: v.entityId ?? null,
      ...(v.detail ?? {}),
    })
    recordQaAnomaly(
      {
        kind: 'run_invariant_violation',
        routeOrOrigin: `/runs/${run.id}`,
        summary: v.message,
        detail: {
          runId: run.id,
          code: v.code,
          entityId: v.entityId ?? null,
          ...(v.detail ?? {}),
        },
        ts: now,
      },
      { force: true },
    )
  }

  for (const prev of [...seen]) {
    if (!currentSignatures.has(prev)) seen.delete(prev)
  }
  return newlyEmitted
}
