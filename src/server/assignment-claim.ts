/**
 * Authoritative Assignment Claim Owner, `ClaimHandle`, and Phase-Agnostic Orphan Reaper (`R3-07`).
 *
 * Consolidates assignment claims, lease duration budgeting (`run-safety-budgets.ts`),
 * idempotent settlement with paired chain-step co-transitions, `Symbol.dispose` cleanup,
 * and phase-agnostic orphaned-running reaping into one acyclic module shared by
 * `RunsRepository` (`store-runs.ts`) and `Execution` (`execution.ts`).
 */
import { randomUUID } from 'node:crypto'
import { settleOrReport, type SettlementErrorReporter } from './run-disposers.ts'
import { resolveAssignmentLeaseBudget, type AssignmentLeaseKind } from './run-safety-budgets.ts'
import type { Assignment, ChainStep, Run } from './store-session.ts'

export type ClaimTerminalOrParkedStatus =
  | 'complete'
  | 'failed'
  | 'canceled'
  | 'queued'
  | 'paused'
  | 'waiting_approval'

export interface AssignmentClaimStore {
  worker(assignmentId: string): Assignment
  workerList(runId: string): Assignment[]
  updateWorker(assignmentId: string, state: Partial<Assignment>): Assignment | undefined
  event(runId: string, kind: string, message: string, detail?: Record<string, unknown>): unknown
  transaction<T>(fn: () => T, options?: { behavior?: 'deferred' | 'immediate' | 'exclusive' }): T
  run?(runId: string): Run
  listChainSteps?(runId: string, goalRevision: number): ChainStep[]
  updateChainStep?(stepId: string, state: Partial<ChainStep>): unknown
  refreshReadyChainSteps?(runId: string, goalRevision: number): unknown
}

export interface ClaimSettleInput {
  status: ClaimTerminalOrParkedStatus
  outcome?: string | null
  attempt?: number
  checks?: Assignment['checks']
  approvalParkedAt?: number | null
  stepId?: string | null
  stepStatus?: ChainStep['status']
  clearStepWorker?: boolean
  eventKind?: string
  eventMessage?: string
  eventDetail?: Record<string, unknown>
}

export interface ClaimSettleResult {
  readonly settled: boolean
  readonly assignment?: Assignment
  readonly reason?: string
}

export interface ClaimAssignmentInput {
  runId: string
  assignmentId: string
  leaseKind?: AssignmentLeaseKind
  leaseMs?: number
  sessionId?: string
  outcome?: string | null
  approvalParkedAt?: number | null
  afterClaimInTx?: (claimed: Assignment) => void
  registry?: AssignmentClaimRegistry
  reportError?: SettlementErrorReporter
  releaseStatus?: 'failed' | 'canceled' | 'queued'
  releaseOutcome?: string
}

export interface ClaimHandle {
  readonly assignment: Assignment
  readonly assignmentId: string
  readonly runId: string
  readonly phase: Assignment['phase']
  readonly lease: string
  readonly leaseExpiresAt: number
  readonly leaseClamped: boolean
  readonly isSettled: boolean
  readonly isReleased: boolean
  heartbeat(extendMs?: number): Assignment | undefined
  settle(input: ClaimSettleInput): ClaimSettleResult
  release(fallbackOutcome?: string): void
  [Symbol.dispose](): void
}

/**
 * In-memory owner registry for live `ClaimHandle` instances.
 * Drives the phase-agnostic reaper so legitimately running workers are never
 * reaped while orphaned `running` DB rows without a live handle are reclaimed.
 */
export class AssignmentClaimRegistry {
  private readonly handles = new Map<string, ClaimHandle>()

  register(handle: ClaimHandle): void {
    this.handles.set(handle.assignmentId, handle)
  }

  unregister(assignmentId: string, lease?: string): boolean {
    const existing = this.handles.get(assignmentId)
    if (!existing) return false
    if (lease !== undefined && existing.lease !== lease) return false
    return this.handles.delete(assignmentId)
  }

  has(assignmentId: string): boolean {
    return this.handles.has(assignmentId)
  }

  get(assignmentId: string): ClaimHandle | undefined {
    return this.handles.get(assignmentId)
  }

  listForRun(runId: string): ClaimHandle[] {
    const out: ClaimHandle[] = []
    for (const handle of this.handles.values()) {
      if (handle.runId === runId) out.push(handle)
    }
    return out
  }

  activeLeases(): Set<string> {
    const out = new Set<string>()
    for (const handle of this.handles.values()) {
      out.add(handle.lease)
    }
    return out
  }

  disposeRun(runId: string): number {
    let removed = 0
    for (const [id, handle] of [...this.handles.entries()]) {
      if (handle.runId !== runId) continue
      this.handles.delete(id)
      removed += 1
    }
    return removed
  }

  clear(): void {
    this.handles.clear()
  }
}

function buildWorkerClaimPatch(
  lease: string,
  leaseExpiresAt: number,
  input: ClaimAssignmentInput,
): Partial<Assignment> {
  return {
    status: 'running',
    lease,
    leaseExpiresAt,
    ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
    ...(input.outcome !== undefined ? { outcome: input.outcome } : {}),
    ...(input.approvalParkedAt !== undefined ? { approvalParkedAt: input.approvalParkedAt } : {}),
  }
}

function applyPairedStepCoTransition(
  store: AssignmentClaimStore,
  runId: string,
  assignmentId: string,
  stepId: string,
  stepStatus: ChainStep['status'],
  clearStepWorker: boolean,
): void {
  if (!store.run || !store.listChainSteps || !store.updateChainStep) return
  const latestRun = store.run(runId)
  const step = store.listChainSteps(latestRun.id, latestRun.goalRevision).find(s => s.id === stepId)
  if (!step) return
  const ownsStep = step.status === 'running'
    ? step.assignedWorkerId === assignmentId
    : (!step.assignedWorkerId || step.assignedWorkerId === assignmentId)
  if (!ownsStep) return
  store.updateChainStep(step.id, {
    status: stepStatus,
    ...(clearStepWorker ? { assignedWorkerId: null } : {}),
  })
  store.refreshReadyChainSteps?.(latestRun.id, latestRun.goalRevision)
}

function commitClaimSettlementInTx(
  store: AssignmentClaimStore,
  claimed: Assignment,
  lease: string,
  settleInput: ClaimSettleInput,
): ClaimSettleResult {
  const cur = store.worker(claimed.id)
  if (cur.status !== 'running') {
    return { settled: false, assignment: cur, reason: `already_${cur.status}` }
  }
  if (cur.lease !== null && cur.lease !== lease) {
    return { settled: false, assignment: cur, reason: 'lease_mismatch' }
  }
  const updated = store.updateWorker(claimed.id, {
    status: settleInput.status,
    lease: null,
    leaseExpiresAt: null,
    ...(settleInput.outcome !== undefined ? { outcome: settleInput.outcome } : {}),
    ...(settleInput.attempt !== undefined ? { attempt: settleInput.attempt } : {}),
    ...(settleInput.checks !== undefined ? { checks: settleInput.checks } : {}),
    ...(settleInput.approvalParkedAt !== undefined ? { approvalParkedAt: settleInput.approvalParkedAt } : {}),
  })
  const stepId = settleInput.stepId !== undefined ? settleInput.stepId : cur.stepId
  if (stepId && settleInput.stepStatus) {
    applyPairedStepCoTransition(
      store,
      claimed.runId,
      claimed.id,
      stepId,
      settleInput.stepStatus,
      settleInput.clearStepWorker ?? settleInput.stepStatus === 'ready',
    )
  }
  if (settleInput.eventKind && settleInput.eventMessage) {
    store.event(claimed.runId, settleInput.eventKind, settleInput.eventMessage, {
      assignmentId: claimed.id,
      ...(settleInput.eventDetail ?? {}),
    })
  }
  return { settled: true, assignment: updated ?? cur }
}

/**
 * Authoritative assignment claim owner (`R3-07`).
 *
 * Atomically transitions `assignmentId` to `status: 'running'` with a fresh lease token
 * and budgeted `leaseExpiresAt` from `run-safety-budgets.ts`, emits truncation telemetry
 * if the requested lease was clamped, registers the live `ClaimHandle` in `registry`,
 * and provides idempotent `settle()`, `heartbeat()`, `release()`, and `[Symbol.dispose]()`.
 */
export function claimAssignment(
  store: AssignmentClaimStore,
  input: ClaimAssignmentInput,
): ClaimHandle | null {
  const leaseKind = input.leaseKind ?? 'default'
  const leaseBudget = resolveAssignmentLeaseBudget(leaseKind, {
    ...(input.leaseMs !== undefined ? { requestedMs: input.leaseMs } : {}),
  })
  const lease = randomUUID()
  let currentLeaseExpiresAt = Date.now() + leaseBudget.leaseMs
  const claimed = store.transaction(() => {
    const updated = store.updateWorker(
      input.assignmentId,
      buildWorkerClaimPatch(lease, currentLeaseExpiresAt, input),
    )
    if (!updated) return undefined
    if (leaseBudget.clamped) {
      store.event(
        input.runId,
        'assignment.lease_clamped',
        `Assignment lease clamped to ${leaseBudget.leaseMs}ms (requested ${leaseBudget.requestedMs}ms, max ${leaseBudget.hardMaxMs}ms).`,
        {
          assignmentId: updated.id,
          leaseKind,
          leaseMs: leaseBudget.leaseMs,
          requestedMs: leaseBudget.requestedMs,
          hardMaxMs: leaseBudget.hardMaxMs,
        },
      )
    }
    input.afterClaimInTx?.(updated)
    return updated
  }, { behavior: 'immediate' })
  if (!claimed) return null

  let currentAssignment = claimed
  let settled = false
  let released = false
  const reportError = input.reportError ?? ((runId, kind, msg, detail) => {
    store.event(runId, kind, msg, detail)
  })

  const handle: ClaimHandle = {
    get assignment() { return currentAssignment },
    assignmentId: claimed.id,
    runId: claimed.runId,
    phase: claimed.phase,
    lease,
    get leaseExpiresAt() { return currentLeaseExpiresAt },
    leaseClamped: leaseBudget.clamped,
    get isSettled() { return settled },
    get isReleased() { return released },

    heartbeat(extendMs?: number): Assignment | undefined {
      if (settled || released) return undefined
      const budget = resolveAssignmentLeaseBudget(leaseKind, {
        ...(extendMs !== undefined ? { requestedMs: extendMs } : {}),
      })
      const nextExpiry = Date.now() + budget.leaseMs
      const res = settleOrReport(
        claimed.runId,
        'assignment.heartbeat',
        () => store.transaction(() => {
          const cur = store.worker(claimed.id)
          if (cur.status !== 'running' || cur.lease !== lease) return undefined
          const next = store.updateWorker(claimed.id, { leaseExpiresAt: nextExpiry })
          if (next) {
            currentAssignment = next
            currentLeaseExpiresAt = nextExpiry
          }
          return next
        }, { behavior: 'immediate' }),
        reportError,
        { assignmentId: claimed.id },
      )
      return res.ok ? res.value : undefined
    },

    settle(settleInput: ClaimSettleInput): ClaimSettleResult {
      if (settled) {
        return { settled: false, reason: 'already_settled' }
      }
      settled = true
      released = true
      input.registry?.unregister(claimed.id, lease)
      const res = settleOrReport(
        claimed.runId,
        `assignment.settle:${settleInput.status}`,
        () => store.transaction(() => {
          const out = commitClaimSettlementInTx(store, claimed, lease, settleInput)
          if (out.settled && out.assignment) currentAssignment = out.assignment
          return out
        }, { behavior: 'immediate' }),
        reportError,
        { assignmentId: claimed.id, targetStatus: settleInput.status },
      )
      return res.ok && res.value ? res.value : { settled: false, reason: res.race ?? res.error ?? 'settlement_failed' }
    },

    release(fallbackOutcome?: string): void {
      if (released) return
      released = true
      input.registry?.unregister(claimed.id, lease)
      if (!settled) {
        const status = input.releaseStatus ?? 'failed'
        const outcome = fallbackOutcome ?? input.releaseOutcome ?? 'Assignment claim released without explicit settlement.'
        handle.settle({
          status,
          outcome,
          ...(claimed.phase === 'investigation' && claimed.stepId
            ? { stepId: claimed.stepId, stepStatus: 'ready', clearStepWorker: true }
            : {}),
        })
      }
    },

    [Symbol.dispose](): void {
      handle.release()
    },
  }

  input.registry?.register(handle)
  return handle
}

export interface ReapOrphanedRunningOptions {
  activeAssignmentIds: ReadonlySet<string>
  activeLeases?: ReadonlySet<string>
  claimRegistry?: AssignmentClaimRegistry
  hasActiveDeterministicPass?: boolean
  now?: number
  reportError?: SettlementErrorReporter
  onVerificationOrRetestExpired?: (assignment: Assignment, reason: string) => void
}

export interface ReapOrphanedRunningResult {
  readonly reapedIds: string[]
  readonly skippedLiveHandle: number
  readonly skippedParkedOrNonRunning: number
}

/**
 * Phase-agnostic orphaned assignment reaper (`R3-07`).
 *
 * Scans ALL phases of `run.id` and reclaims any `status === 'running'` assignment row
 * that has no live in-memory owner handle (`claimRegistry`, `activeAssignmentIds`, or
 * shared parent `activeLeases`). Never touches `waiting_approval` parked workers or
 * legitimately long-running sessions that still hold a live owner handle.
 */
export function reapOrphanedRunningAssignments(
  store: AssignmentClaimStore,
  run: Pick<Run, 'id' | 'goalRevision'>,
  options: ReapOrphanedRunningOptions,
): ReapOrphanedRunningResult {
  const now = options.now ?? Date.now()
  const reportError = options.reportError ?? ((runId, kind, msg, detail) => {
    store.event(runId, kind, msg, detail)
  })
  const workers = store.workerList(run.id)
  const reapedIds: string[] = []
  let skippedLiveHandle = 0
  let skippedParkedOrNonRunning = 0

  for (const w of workers) {
    if (w.status !== 'running') {
      skippedParkedOrNonRunning += 1
      continue
    }
    const hasLiveOwner =
      Boolean(options.claimRegistry?.has(w.id))
      || options.activeAssignmentIds.has(w.id)
      || Boolean(w.lease && options.activeLeases?.has(w.lease))
    if (hasLiveOwner) {
      skippedLiveHandle += 1
      continue
    }
    const leaseExpired = w.leaseExpiresAt !== null && w.leaseExpiresAt <= now
    // Protect legacy deterministic floor-lane workers while their deterministic pass is active
    // and their lease has not expired (their module is outside this stream's lease).
    if (options.hasActiveDeterministicPass && w.phase === 'investigation' && !w.stepId && !leaseExpired) {
      skippedLiveHandle += 1
      continue
    }
    const reason = leaseExpired
      ? 'Worker lease expired with no live owner handle.'
      : 'Orphaned running assignment had no live owner handle.'
    if ((w.phase === 'verification' || w.phase === 'retest') && options.onVerificationOrRetestExpired) {
      const res = settleOrReport(
        run.id,
        'assignment.reap_verification',
        () => { options.onVerificationOrRetestExpired!(w, reason) },
        reportError,
        { assignmentId: w.id, phase: w.phase, leaseExpired },
      )
      if (res.ok) reapedIds.push(w.id)
      continue
    }
    const res = settleOrReport(
      run.id,
      'assignment.reap_orphan',
      () => store.transaction(() => {
        const cur = store.worker(w.id)
        if (cur.status !== 'running' || cur.lease !== w.lease) return false
        store.updateWorker(cur.id, {
          status: 'failed',
          lease: null,
          leaseExpiresAt: null,
          outcome: reason,
        })
        if (cur.phase === 'investigation' && cur.stepId) {
          applyPairedStepCoTransition(store, run.id, cur.id, cur.stepId, 'ready', true)
        }
        store.event(
          run.id,
          'assignment.reaped',
          `Reclaimed orphaned ${cur.phase} assignment (${cur.title}): ${reason}`,
          {
            assignmentId: cur.id,
            phase: cur.phase,
            stepId: cur.stepId,
            leaseExpired,
            reason,
          },
        )
        return true
      }, { behavior: 'immediate' }),
      reportError,
      { assignmentId: w.id, phase: w.phase, leaseExpired },
    )
    if (res.ok && res.value) reapedIds.push(w.id)
  }

  return { reapedIds, skippedLiveHandle, skippedParkedOrNonRunning }
}

/**
 * Purge all in-memory active jobs and claim handles belonging to `runId` during
 * `Execution.cleanupRunState(runId)` so a leaked entry never keeps `isRunTrackedActive`
 * true or triggers spurious `RunDeleteBusyError` (`R3-07`).
 */
export function purgeActiveJobsForRun<
  T extends { assignment: { runId: string }; controller: AbortController },
>(
  active: Map<string, T>,
  runId: string,
  claimRegistry?: AssignmentClaimRegistry,
): number {
  let removed = 0
  for (const [id, job] of [...active.entries()]) {
    if (job.assignment.runId !== runId) continue
    try {
      job.controller.abort(new Error('run state cleaned up'))
    } catch (abortErr) {
      void abortErr
    }
    active.delete(id)
    removed += 1
  }
  claimRegistry?.disposeRun(runId)
  return removed
}
