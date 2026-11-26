/**
 * Option 2 — Move 5B: Explicit Per-Run `RunActor` FSM + Structured `TaskSupervisor`.
 *
 * Replaces `Execution`'s implicit poll-loop split-brain and detached `void` async chains with:
 *  1. An explicit finite-state machine (`RunActorState`) and validated transition table
 *     (`canTransition`, `RunActor.transition`) preventing illegal phase/status splits.
 *  2. A structured per-run `TaskSupervisor` backed by `RunContext` (`trackTask` + chained
 *     `AbortController`s + timer registration) so zero untracked async jobs outlive `stop()`
 *     or `deleteRun()`, and `actor.drainAndDispose()` deterministically aborts + drains all
 *     in-flight jobs before hard-delete (`M-16` / `H-26`).
 *  3. Host-only planner control signal trust helpers (`M-47`) preventing untrusted worker
 *     `record_fact` calls from spoofing `det_lead` or `hop_checkpoint` control facts.
 *  4. Per-run budget/telemetry/code-audit helpers extracted from `execution.ts`.
 */
import { eq } from 'drizzle-orm'
import { defaultCodeAuditMaxTurns, wallClockSettlementMs } from './agent-session.ts'
import {
  evaluateTier3Approval,
  StateChangeApprovalLedger,
} from './approval-judge.ts'
import {
  BrokerApprovalRequired,
  BrokerDenied,
  type BrokerExchangeResult,
  type BrokerHttpRequest,
  type BrokerRaceBurstResult,
  type Grant,
  type RequestBroker,
} from './broker.ts'
import { cleanupStagedEntities } from './deterministic-engine.ts'
import type { ExecBoardManager } from './exec-board.ts'
import {
  collectAllPages,
  dedupePromotableCodeAuditFacts,
  isPromotableCodeAuditFact,
  percentile,
  summarizeTurnLatencies,
  type AssignmentThroughputMetrics,
  type PhaseRequestBudgets,
} from './exec-dispatch.ts'
import type { ExecActiveJob, ExecTier3ApprovalInput } from './exec-exchange.ts'
import type { ExecGapValidationCounts, ExecProofObligationCounts } from './exec-worker-runner.ts'
import { KillSwitchTrippedError } from './kill-switch.ts'
import { resolveProfilePoolForRole } from './model-settings.ts'
import { BudgetExceededError } from './provider.ts'
import type { NamedSecret } from './redact.ts'
import { RunContext, type RunDrainReport } from './run-context.ts'
import { approvalRequests, findings } from './schema.ts'
import { codeAuditSuspectLocationKey, type SemanticAuditSuspect } from './semantic-audit.ts'
import type { Assignment, Fact, Run, Store } from './store.ts'
import {
  planTier3ApprovalTargets,
  registerStateChangeGrant,
  type BurstApprovalInstances,
} from './tier3-approval.ts'
import type { WorkerBackend } from './worker-backend.ts'

// ============================================================================
// 1. Explicit Finite-State Machine (`RunActorState`)
// ============================================================================

export type RunActorState =
  | 'queued'
  | 'initializing'
  | 'recon'
  | 'awaiting_scope'
  | 'investigating'
  | 'verifying'
  | 'paused'
  | 'stopping'
  | 'completed'
  | 'failed'
  | 'canceled'

export type TerminalRunActorState = 'completed' | 'failed' | 'canceled'

export const TERMINAL_RUN_ACTOR_STATES: ReadonlySet<RunActorState> = new Set<RunActorState>([
  'completed',
  'failed',
  'canceled',
])

/**
 * Validated explicit FSM transition table.
 * Terminal states (`completed`, `failed`, `canceled`) have zero outgoing edges.
 * `stopping` may only settle into a terminal state.
 * `queued` / `paused` / `investigating` cannot jump directly to `completed` without `verifying` or `stopping`.
 */
export const RUN_ACTOR_TRANSITIONS: Readonly<Record<RunActorState, ReadonlySet<RunActorState>>> = {
  queued: new Set<RunActorState>(['initializing', 'recon', 'paused', 'stopping', 'failed', 'canceled']),
  initializing: new Set<RunActorState>(['recon', 'awaiting_scope', 'investigating', 'paused', 'stopping', 'failed', 'canceled']),
  recon: new Set<RunActorState>(['awaiting_scope', 'initializing', 'investigating', 'paused', 'stopping', 'failed', 'canceled']),
  awaiting_scope: new Set<RunActorState>(['initializing', 'recon', 'investigating', 'paused', 'stopping', 'failed', 'canceled']),
  investigating: new Set<RunActorState>(['verifying', 'initializing', 'awaiting_scope', 'paused', 'stopping', 'failed', 'canceled']),
  verifying: new Set<RunActorState>(['completed', 'investigating', 'paused', 'stopping', 'failed', 'canceled']),
  paused: new Set<RunActorState>(['initializing', 'recon', 'awaiting_scope', 'investigating', 'verifying', 'stopping', 'failed', 'canceled']),
  stopping: new Set<RunActorState>(['completed', 'failed', 'canceled']),
  completed: new Set<RunActorState>(),
  failed: new Set<RunActorState>(),
  canceled: new Set<RunActorState>(),
}

export class InvalidRunTransitionError extends Error {
  readonly code = 'INVALID_RUN_TRANSITION'
  readonly runId: string
  readonly from: RunActorState
  readonly to: RunActorState

  constructor(runId: string, from: RunActorState, to: RunActorState, reason?: string) {
    super(
      `Invalid RunActor transition for run "${runId}": ${from} -> ${to}${reason ? ` (${reason})` : ''}.`,
    )
    this.name = 'InvalidRunTransitionError'
    this.runId = runId
    this.from = from
    this.to = to
  }
}

export function canTransition(from: RunActorState, to: RunActorState): boolean {
  if (from === to) return false
  return RUN_ACTOR_TRANSITIONS[from]?.has(to) ?? false
}

export function isTerminalRunActorState(state: RunActorState): state is TerminalRunActorState {
  return TERMINAL_RUN_ACTOR_STATES.has(state)
}

/** Map persisted Store `(status, phase)` onto canonical `RunActorState`. */
export function deriveRunActorState(run: Pick<Run, 'status' | 'phase'>): RunActorState {
  if (run.status === 'complete' || run.phase === 'complete') return 'completed'
  if (run.status === 'failed') return 'failed'
  if (run.status === 'stopped') return 'canceled'
  if (run.status === 'paused' || run.status === 'budget_paused') return 'paused'
  if (run.phase === 'review') return 'awaiting_scope'
  if (run.phase === 'discovery') return 'recon'
  if (run.phase === 'threat_model') return 'initializing'
  if (run.phase === 'investigation') return 'investigating'
  if (run.phase === 'verification') return 'verifying'
  return 'queued'
}

export interface RunActorTransitionRecord {
  from: RunActorState
  to: RunActorState
  reason: string
  at: number
}

// ============================================================================
// 2. Structured Per-Run `TaskSupervisor`
// ============================================================================

export interface SpawnTaskOptions {
  /** Optional external AbortController to chain with the run's signal (defaults to a fresh one). */
  controller?: AbortController
  /** Optional additional AbortSignal whose abort also cancels this task. */
  signal?: AbortSignal
  /** Optional error observer invoked on non-abort failures (prevents unhandled rejections). */
  onError?: (error: unknown) => void
}

export interface SupervisedTask<T = void> {
  readonly id: number
  readonly label: string
  readonly controller: AbortController
  readonly signal: AbortSignal
  readonly promise: Promise<T | undefined>
  abort(reason?: unknown): void
}

export interface TaskDrainResult {
  total: number
  drained: number
  timedOut: number
  durationMs: number
}

interface ActiveSupervisedTask {
  id: number
  label: string
  controller: AbortController
  settled: Promise<void>
}

export class TaskSupervisor {
  readonly context: RunContext
  private readonly tasks = new Map<number, ActiveSupervisedTask>()
  private nextTaskId = 1
  private draining = false

  constructor(context: RunContext) {
    this.context = context
  }

  get activeCount(): number {
    return this.tasks.size
  }

  activeLabels(): string[] {
    return [...this.tasks.values()].map(task => task.label)
  }

  get isDraining(): boolean {
    return this.draining || this.context.isDisposed
  }

  /**
   * Spawn a structured async job bound to this run's `RunContext`.
   * The task's `AbortSignal` is automatically chained to `RunContext.signal` (which is chained
   * to `GlobalKillSwitch`) and tracked via `RunContext.trackTask()` so `drainAndDispose()` always
   * aborts and awaits its settlement. Rejections are caught cleanly (never unhandled).
   */
  spawn<T = void>(
    label: string,
    fn: (signal: AbortSignal) => Promise<T> | T,
    options: SpawnTaskOptions = {},
  ): SupervisedTask<T> {
    const cleanLabel = label.trim() || 'task'
    const id = this.nextTaskId++
    const controller = options.controller ?? new AbortController()
    const runSignal = this.context.signal

    const abortTask = (reason?: unknown) => {
      if (!controller.signal.aborted) {
        try {
          controller.abort(reason ?? new Error(`Task "${cleanLabel}" aborted.`))
        } catch { /* already aborted */ }
      }
    }

    if (this.draining || this.context.isDisposed || runSignal.aborted) {
      abortTask(runSignal.reason ?? new Error(`Run "${this.context.runId}" is stopping.`))
      return {
        id,
        label: cleanLabel,
        controller,
        signal: controller.signal,
        promise: Promise.resolve(undefined),
        abort: abortTask,
      }
    }

    const onRunAbort = () => abortTask(runSignal.reason)
    runSignal.addEventListener('abort', onRunAbort, { once: true })

    let detachExtra: (() => void) | null = null
    if (options.signal) {
      const extra = options.signal
      if (extra.aborted) {
        abortTask(extra.reason)
      } else {
        const onExtraAbort = () => abortTask(extra.reason)
        extra.addEventListener('abort', onExtraAbort, { once: true })
        detachExtra = () => extra.removeEventListener('abort', onExtraAbort)
      }
    }

    let raw: Promise<T> | T
    try {
      raw = fn(controller.signal)
    } catch (syncError) {
      raw = Promise.reject(syncError)
    }

    const wrapped = Promise.resolve(raw)
      .catch(error => {
        if (!controller.signal.aborted && !runSignal.aborted) {
          try {
            options.onError?.(error)
          } catch { /* error observer must never throw */ }
        }
        return undefined
      })
      .finally(() => {
        runSignal.removeEventListener('abort', onRunAbort)
        try { detachExtra?.() } catch { /* ignore */ }
        this.tasks.delete(id)
      })

    const settled = wrapped.then(() => undefined, () => undefined)
    this.tasks.set(id, { id, label: cleanLabel, controller, settled })
    this.context.trackTask(cleanLabel, settled)

    return {
      id,
      label: cleanLabel,
      controller,
      signal: controller.signal,
      promise: wrapped,
      abort: abortTask,
    }
  }

  /**
   * Schedule a one-shot timer owned by this run's `RunContext`.
   * Automatically cleared if the run stops, aborts, or disposes before firing.
   */
  scheduleTimer(label: string, delayMs: number, fn: () => void): () => void {
    if (this.draining || this.context.isDisposed || this.context.isAborted) {
      return () => {}
    }
    let released = false
    let unregister: () => void = () => {}
    const timer = setTimeout(() => {
      if (released) return
      released = true
      unregister()
      if (this.draining || this.context.isDisposed || this.context.isAborted) return
      fn()
    }, Math.max(0, Math.floor(delayMs)))
    timer.unref?.()
    unregister = this.context.registerTimer(label, timer)
    return () => {
      if (released) return
      released = true
      clearTimeout(timer)
      unregister()
    }
  }

  /** Abort all active child task controllers for this run. */
  abortAll(reason?: unknown): void {
    const abortReason = reason ?? new Error(`TaskSupervisor for run "${this.context.runId}" aborted.`)
    for (const task of this.tasks.values()) {
      if (!task.controller.signal.aborted) {
        try { task.controller.abort(abortReason) } catch { /* ignore */ }
      }
    }
  }

  /** Abort all active tasks and await their settlement up to `timeoutMs`. */
  async drain(timeoutMs = 5_000, reason?: unknown): Promise<TaskDrainResult> {
    const startedAt = Date.now()
    this.draining = true
    this.abortAll(reason)

    const pending = [...this.tasks.values()]
    const total = pending.length
    let drained = 0

    if (total > 0) {
      const tracked = pending.map(entry =>
        entry.settled.then(() => {
          drained += 1
        }),
      )
      const allDone = Promise.allSettled(tracked).then(() => true)
      const capMs = Math.max(0, timeoutMs)
      if (capMs === 0) {
        await Promise.race([allDone, Promise.resolve(false)])
      } else {
        let timer: ReturnType<typeof setTimeout> | undefined
        const timedOut = new Promise<boolean>(resolve => {
          timer = setTimeout(() => resolve(false), capMs)
          timer.unref?.()
        })
        try {
          await Promise.race([allDone, timedOut])
        } finally {
          if (timer !== undefined) clearTimeout(timer)
        }
      }
    }

    return {
      total,
      drained,
      timedOut: Math.max(0, total - drained),
      durationMs: Math.max(0, Date.now() - startedAt),
    }
  }
}

// ============================================================================
// 3. Explicit `RunActor`
// ============================================================================

export interface RunActorOptions {
  context: RunContext
  initialState?: RunActorState
  maxHistory?: number
}

export interface RunActorDisposeOptions {
  terminalState?: TerminalRunActorState
  reason?: string
  timeoutMs?: number
}

const DEFAULT_HISTORY_LIMIT = 64

export class RunActor {
  readonly runId: string
  readonly context: RunContext
  readonly supervisor: TaskSupervisor
  private currentState: RunActorState
  private readonly history: RunActorTransitionRecord[] = []
  private readonly maxHistory: number
  private disposePromise: Promise<RunDrainReport> | null = null

  constructor(options: RunActorOptions) {
    this.context = options.context
    this.runId = options.context.runId
    this.supervisor = new TaskSupervisor(options.context)
    this.currentState = options.initialState ?? 'queued'
    this.maxHistory = Math.max(8, options.maxHistory ?? DEFAULT_HISTORY_LIMIT)
  }

  get state(): RunActorState {
    return this.currentState
  }

  get signal(): AbortSignal {
    return this.context.signal
  }

  get isTerminal(): boolean {
    return isTerminalRunActorState(this.currentState)
  }

  get isDisposed(): boolean {
    return this.context.isDisposed
  }

  get activeTaskCount(): number {
    return this.supervisor.activeCount
  }

  get transitions(): ReadonlyArray<RunActorTransitionRecord> {
    return this.history
  }

  canTransitionTo(to: RunActorState): boolean {
    return canTransition(this.currentState, to)
  }

  /**
   * Perform a validated FSM state transition. Throws `InvalidRunTransitionError` if the edge
   * is illegal according to `RUN_ACTOR_TRANSITIONS`.
   */
  transition(to: RunActorState, reason = ''): RunActorState {
    if (!canTransition(this.currentState, to)) {
      throw new InvalidRunTransitionError(this.runId, this.currentState, to, reason)
    }
    const from = this.currentState
    this.currentState = to
    this.history.push({ from, to, reason, at: Date.now() })
    if (this.history.length > this.maxHistory) {
      this.history.shift()
    }
    return this.currentState
  }

  /**
   * Synchronize actor state to `to`. Returns immediately if already in `to`, otherwise validates
   * via `transition(to, reason)`.
   */
  syncState(to: RunActorState, reason = ''): RunActorState {
    if (this.currentState === to) return this.currentState
    return this.transition(to, reason)
  }

  /**
   * Reconcile a non-terminal actor with a persisted SQLite state jump (e.g. `queued -> verifying`,
   * `recon -> verifying`, `investigating -> completed` after restore/skip) by walking the shortest
   * legal path in `RUN_ACTOR_TRANSITIONS`. Terminal actors are never mutated (caller must dispose
   * and mint a fresh actor on resume).
   */
  reconcileWithPersisted(to: RunActorState, reason = ''): RunActorState {
    if (this.currentState === to || this.isTerminal) return this.currentState
    if (canTransition(this.currentState, to)) {
      return this.transition(to, reason)
    }
    const queue: Array<{ state: RunActorState; path: RunActorState[] }> = [
      { state: this.currentState, path: [] },
    ]
    const visited = new Set<RunActorState>([this.currentState])
    while (queue.length > 0) {
      const current = queue.shift()!
      const nextStates = RUN_ACTOR_TRANSITIONS[current.state]
      if (!nextStates) continue
      for (const next of nextStates) {
        if (visited.has(next)) continue
        if (next === 'stopping' && to !== 'stopping') continue
        const nextPath = [...current.path, next]
        if (next === to) {
          for (let i = 0; i < nextPath.length; i += 1) {
            const hop = nextPath[i]!
            const hopReason = i === nextPath.length - 1 ? reason : `${reason || 'reconcile'}:hop`
            this.transition(hop, hopReason)
          }
          return this.currentState
        }
        visited.add(next)
        if (!isTerminalRunActorState(next)) {
          queue.push({ state: next, path: nextPath })
        }
      }
    }
    return this.currentState
  }

  /** Spawn a supervised async task bound to this run's `RunContext`. */
  spawn<T = void>(
    label: string,
    fn: (signal: AbortSignal) => Promise<T> | T,
    options?: SpawnTaskOptions,
  ): SupervisedTask<T> {
    return this.supervisor.spawn(label, fn, options)
  }

  /** Schedule a run-owned timer cleared automatically on stop/dispose. */
  scheduleTimer(label: string, delayMs: number, fn: () => void): () => void {
    return this.supervisor.scheduleTimer(label, delayMs, fn)
  }

  /** Register a disposable run resource on the underlying `RunContext`. */
  registerResource(name: string, disposeFn: () => void | Promise<void>): () => void {
    return this.context.registerResource(name, disposeFn)
  }

  /** Register a raw Node timer on the underlying `RunContext`. */
  registerTimer(
    name: string,
    timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>,
  ): () => void {
    return this.context.registerTimer(name, timer)
  }

  /**
   * Deterministic teardown barrier:
   *  1. Transitions actor to `stopping` (if not already terminal/stopping).
   *  2. Aborts all supervised tasks & drains them via `TaskSupervisor` + `RunContext.drainAndDispose()`.
   *  3. Executes every registered disposer (vault RAM+disk eviction, OOB unsubscribe, lab stop, etc.).
   *  4. Settles actor into `terminalState` (default `'canceled'`).
   */
  drainAndDispose(options: RunActorDisposeOptions = {}): Promise<RunDrainReport> {
    if (this.disposePromise) {
      return this.disposePromise.then(report => ({ ...report, alreadyDisposed: true }))
    }
    this.disposePromise = this.performDrainAndDispose(options)
    return this.disposePromise
  }

  private async performDrainAndDispose(options: RunActorDisposeOptions): Promise<RunDrainReport> {
    const terminalState: TerminalRunActorState = options.terminalState ?? 'canceled'
    const reason = options.reason ?? `run ${terminalState}`

    if (!this.isTerminal && this.currentState !== 'stopping') {
      if (canTransition(this.currentState, 'stopping')) {
        this.transition('stopping', reason)
      }
    }

    const abortError = new Error(`RunActor "${this.runId}" stopping (${reason}).`)
    this.supervisor.abortAll(abortError)
    this.context.abort(abortError)

    const report = await this.context.drainAndDispose(options.timeoutMs)

    if (!this.isTerminal && canTransition(this.currentState, terminalState)) {
      this.transition(terminalState, reason)
    }

    return report
  }
}

// ============================================================================
// 4. Idempotent `unhandledRejection` Safety-Net Helper
// ============================================================================

export interface OrphanedRejectionLogEntry {
  kind: 'run_actor.orphaned_abort_rejection'
  message: string
  isAbort: boolean
}

const REJECTION_GUARD_SYMBOL = Symbol.for('kovo.runActorRejectionGuard')

export function isOrphanedRunAbortError(reason: unknown): boolean {
  if (reason instanceof KillSwitchTrippedError) return true
  if (reason && typeof reason === 'object') {
    const name = (reason as { name?: unknown }).name
    if (name === 'AbortError') return true
    const message = typeof (reason as { message?: unknown }).message === 'string'
      ? (reason as { message: string }).message
      : ''
    if (
      /\b(?:aborted|RunContext\b.*\bdisposed|RunActor\b.*\bstopping|execution stopped|assignment is no longer authorized)\b/i.test(message)
    ) {
      return true
    }
  }
  if (typeof reason === 'string' && /\b(?:aborted|execution stopped|run deleted)\b/i.test(reason)) {
    return true
  }
  return false
}

/**
 * Install an idempotent `process.on('unhandledRejection')` safety net that records structured
 * diagnostics for orphaned run-abort rejections without crashing the host process.
 * Calling multiple times is a safe no-op; returns an uninstall function.
 */
export function installRunActorRejectionGuard(
  logger: (entry: OrphanedRejectionLogEntry) => void = entry => {
    process.stderr.write(`${JSON.stringify(entry)}\n`)
  },
): () => void {
  const g = globalThis as Record<symbol, { listener: (reason: unknown) => void; refCount: number } | undefined>
  const existing = g[REJECTION_GUARD_SYMBOL]
  if (existing) {
    existing.refCount += 1
    let released = false
    return () => {
      if (released) return
      released = true
      existing.refCount -= 1
      if (existing.refCount <= 0 && g[REJECTION_GUARD_SYMBOL] === existing) {
        process.off('unhandledRejection', existing.listener)
        delete g[REJECTION_GUARD_SYMBOL]
      }
    }
  }

  const listener = (reason: unknown) => {
    const isAbort = isOrphanedRunAbortError(reason)
    if (!isAbort) return
    const message = reason instanceof Error
      ? reason.message.slice(0, 240)
      : String(reason).slice(0, 240)
    try {
      logger({
        kind: 'run_actor.orphaned_abort_rejection',
        message,
        isAbort: true,
      })
    } catch { /* logging must never throw */ }
  }

  const record = { listener, refCount: 1 }
  g[REJECTION_GUARD_SYMBOL] = record
  process.on('unhandledRejection', listener)

  let released = false
  return () => {
    if (released) return
    released = true
    record.refCount -= 1
    if (record.refCount <= 0 && g[REJECTION_GUARD_SYMBOL] === record) {
      process.off('unhandledRejection', record.listener)
      delete g[REJECTION_GUARD_SYMBOL]
    }
  }
}

// ============================================================================
// 5. Host Planner Control Signal Trust (`M-47`)
// ============================================================================

export const HOST_PLANNER_PRODUCER = 'host_planner'
export const HOST_FLOOR_PRODUCER = 'host_floor'
export const WORKER_FACT_PRODUCER = 'worker'

export const TRUSTED_DET_LEAD_SOURCES: ReadonlySet<string> = new Set([
  HOST_PLANNER_PRODUCER,
  HOST_FLOOR_PRODUCER,
  'deterministic_engine',
  'program_graph',
])

/**
 * Verify that a persisted fact carries trusted host provenance before the planner/scheduler
 * honors it as a host control signal (`det_lead` or `hop_checkpoint`).
 * Untrusted worker writes (`producer === 'worker'` or missing host provenance) are rejected.
 */
export function isTrustedHostControlFact(
  fact: Pick<Fact, 'data' | 'tainted'> | null | undefined,
  controlKind: 'det_lead' | 'hop_checkpoint',
): boolean {
  if (!fact || fact.tainted || !fact.data || typeof fact.data !== 'object') return false
  const data = fact.data as Record<string, unknown>
  const producer = typeof data.producer === 'string' ? data.producer : ''
  const source = typeof data.source === 'string' ? data.source : ''

  if (producer === WORKER_FACT_PRODUCER || source === WORKER_FACT_PRODUCER || data.untrusted === true) {
    return false
  }

  if (controlKind === 'hop_checkpoint') {
    if (data.subkind !== 'hop_checkpoint') return false
    return producer === HOST_PLANNER_PRODUCER || source === HOST_PLANNER_PRODUCER
  }

  if (data.kind !== 'det_lead') return false
  return (
    producer === HOST_PLANNER_PRODUCER ||
    producer === HOST_FLOOR_PRODUCER ||
    TRUSTED_DET_LEAD_SOURCES.has(source)
  )
}

/**
 * Sanitize untrusted worker-supplied `record_fact` data so workers can never spoof
 * host planner control signals (`det_lead`, `hop_checkpoint`, `producer: 'host_planner'`).
 */
export function sanitizeWorkerFactData(
  data: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = data && typeof data === 'object' ? { ...data } : {}
  delete out.hostProvenance
  delete out._hostProvenance
  if (out.kind === 'det_lead') {
    out.kind = 'worker_observation'
  }
  if (out.subkind === 'hop_checkpoint') {
    out.subkind = 'worker_note'
  }
  if (typeof out.source === 'string' && TRUSTED_DET_LEAD_SOURCES.has(out.source)) {
    out.source = WORKER_FACT_PRODUCER
  }
  out.producer = WORKER_FACT_PRODUCER
  return out
}

// ============================================================================
// 6. Extracted Per-Run Planner Backoff, Code-Audit, Budget & Metrics Helpers
// ============================================================================

export const PLANNER_BACKOFF_BASE_MS = 500
export const PLANNER_BACKOFF_CAP_MS = 15_000
export const PLANNER_MAX_CONSECUTIVE_ERRORS = 7

/** Exponential backoff for consecutive planner failures: 500ms -> 1s -> 2s -> 4s -> 8s -> 15s cap. */
export function computePlannerBackoffMs(
  consecutiveErrors: number,
  baseMs = PLANNER_BACKOFF_BASE_MS,
  capMs = PLANNER_BACKOFF_CAP_MS,
): number {
  if (!Number.isFinite(consecutiveErrors) || consecutiveErrors <= 0) return 0
  const exp = Math.min(30, Math.max(0, Math.floor(consecutiveErrors) - 1))
  return Math.min(capMs, baseMs * (2 ** exp))
}

export const SOURCE_AUDIT_DEFAULT_WALL_CLOCK_MS = 120_000
export const SOURCE_AUDIT_MIN_WALL_CLOCK_MS = 45_000
export const SOURCE_AUDIT_MAX_WALL_CLOCK_MS = 90_000
export const SOURCE_AUDIT_WALL_CLOCK_SHARE = 0.15
export const SOURCE_AUDIT_SHORT_RUN_THRESHOLD_MS = 15 * 60_000
export const SOURCE_AUDIT_SHORT_RUN_MAX_TURNS = 8
/** Code-audit settle prompt fires at 60% of the audit cap (54s of 90s), leaving ~36s to record. */
export const SOURCE_AUDIT_SETTLEMENT_SHARE = 0.6
export const PHASE_A_FLOOR_MIN_WALL_CLOCK_MS = 15_000
export const PHASE_A_FLOOR_MAX_WALL_CLOCK_MS = 75_000
export const PHASE_A_FLOOR_WALL_CLOCK_SHARE = 0.12

export function resolveSourceAuditWallClockMs(maxDurationMs?: number): number {
  if (typeof maxDurationMs === 'number' && Number.isFinite(maxDurationMs) && maxDurationMs > 0) {
    return Math.max(
      SOURCE_AUDIT_MIN_WALL_CLOCK_MS,
      Math.min(SOURCE_AUDIT_MAX_WALL_CLOCK_MS, Math.floor(maxDurationMs * SOURCE_AUDIT_WALL_CLOCK_SHARE)),
    )
  }
  return SOURCE_AUDIT_DEFAULT_WALL_CLOCK_MS
}

export function resolveSourceAuditMaxTurns(workerMaxTurns?: number, maxDurationMs?: number): number {
  const base = Math.max(6, Math.min(workerMaxTurns || defaultCodeAuditMaxTurns, defaultCodeAuditMaxTurns))
  if (typeof maxDurationMs === 'number' && Number.isFinite(maxDurationMs) && maxDurationMs > 0 && maxDurationMs <= SOURCE_AUDIT_SHORT_RUN_THRESHOLD_MS) {
    return Math.min(base, SOURCE_AUDIT_SHORT_RUN_MAX_TURNS)
  }
  return base
}

export function resolveSourceAuditSettlementMs(auditWallMs: number): number {
  const wall = Math.max(1, Math.floor(auditWallMs))
  return Math.max(1, Math.min(Math.floor(wall * SOURCE_AUDIT_SETTLEMENT_SHARE), wallClockSettlementMs(wall)))
}

export function codeAuditSettlementMessage(auditSettlementMs: number): string {
  const seconds = Math.max(1, Math.round(auditSettlementMs / 1000))
  return [
    `[CODE AUDIT SETTLEMENT — ${seconds}s]`,
    'STOP reading more files now. Do NOT open another repository file, grep sweep, or broad source walk.',
    'Immediately call record_fact(kind="code_audit_suspect") for your top 3-6 highest-signal defects — cross-service trust boundaries, multi-tenant authz or cache-key asymmetries, entity creator/approver state-machine transitions, signing/webhook verification boundaries, and async-worker outbound-fetch or secret-in-log sinks — one fact per defect with the exact repo/file/line and sinkKind.',
    'After those facts are recorded, call complete_intent with status partial|blocked and a concise summary. Recording partial suspects is strictly better than an empty audit.',
  ].join(' ')
}

export function promoteSemanticAuditSuspects(
  storage: Store,
  run: Run,
  assignment: Assignment,
  suspects: readonly SemanticAuditSuspect[],
  approvedOrigins: ReadonlySet<string>,
): Fact[] {
  if (!suspects.length) return []
  const existing = collectAllPages((offset, limit) =>
    storage.listFacts(run.id, { includeTainted: true, kind: 'code_audit_suspect', limit, offset }))
  const seen = new Set(existing.map(fact => codeAuditSuspectLocationKey({
    ...(fact.data as Record<string, unknown>), id: fact.id,
  })))
  const created: Fact[] = []
  for (const suspect of suspects) {
    if (!approvedOrigins.has(suspect.origin)) continue
    const key = codeAuditSuspectLocationKey(suspect)
    if (seen.has(key)) continue
    seen.add(key)
    created.push(storage.addFact(run, assignment, {
      kind: 'code_audit_suspect',
      origin: suspect.origin,
      summary: `[semantic ${suspect.stage}] ${suspect.file}:${suspect.line} (${suspect.sinkKind}) — ${suspect.hypothesis}`,
      data: {
        ...(suspect.data as unknown as Record<string, unknown>),
        producer: HOST_PLANNER_PRODUCER,
      },
    }))
  }
  return created
}

export function settleCodeAuditSuspects(input: {
  storage: Store
  run: Run
  assignment: Assignment
  approvedOrigins: ReadonlySet<string>
  semanticSuspects: readonly SemanticAuditSuspect[]
  preInteractiveFactIds: ReadonlySet<string>
  auditStartedAtMs?: number
}): { suspects: Fact[]; promoted: Fact[]; interactiveRecorded: number } {
  const read = (): Fact[] => {
    const explicitSuspects = collectAllPages((offset, limit) =>
      input.storage.listFacts(input.run.id, { includeTainted: false, kind: 'code_audit_suspect', limit, offset }))
      .filter(fact => input.approvedOrigins.has(fact.origin))
    const explicitIds = new Set(explicitSuspects.map(fact => fact.id))
    const allFacts = collectAllPages((offset, limit) =>
      input.storage.listFacts(input.run.id, { includeTainted: false, limit, offset }))
      .filter(fact => input.approvedOrigins.has(fact.origin))
    const crossCuttingFacts = allFacts.filter(fact => {
      if (explicitIds.has(fact.id)) return false
      const authoredByAudit = fact.assignmentId === input.assignment.id
      const recordedInWindow = !input.preInteractiveFactIds.has(fact.id)
        && input.auditStartedAtMs !== undefined
        && fact.createdAt >= input.auditStartedAtMs
      if (!authoredByAudit && !recordedInWindow) return false
      return isPromotableCodeAuditFact(fact)
    })
    return dedupePromotableCodeAuditFacts([...explicitSuspects, ...crossCuttingFacts])
  }
  let suspects = read()
  const interactiveRecorded = suspects.filter(fact => !input.preInteractiveFactIds.has(fact.id)).length
  let promoted: Fact[] = []
  if (interactiveRecorded === 0 && input.semanticSuspects.length) {
    promoted = promoteSemanticAuditSuspects(
      input.storage, input.run, input.assignment, input.semanticSuspects, input.approvedOrigins,
    )
    if (promoted.length) suspects = read()
  }
  return { suspects, promoted, interactiveRecorded }
}

export function resolvePhaseAFloorWallClockMs(
  maxDurationMs: number | undefined,
  options: { hasProfiles: boolean },
): number | undefined {
  if (!options.hasProfiles) return undefined
  if (typeof maxDurationMs === 'number' && Number.isFinite(maxDurationMs) && maxDurationMs > 0) {
    return Math.max(
      PHASE_A_FLOOR_MIN_WALL_CLOCK_MS,
      Math.min(PHASE_A_FLOOR_MAX_WALL_CLOCK_MS, Math.floor(maxDurationMs * PHASE_A_FLOOR_WALL_CLOCK_SHARE)),
    )
  }
  return PHASE_A_FLOOR_MAX_WALL_CLOCK_MS
}

// --- Per-run split request budget tracker (Phase A floor / Phase B agents) ---

export interface PhaseRequestState {
  floorBudget: number
  agentBudget: number
  baselineRequests: number
  floorRequests: number
  floorSettled: boolean
  floorBudgetExhausted: boolean
  agentBudgetExhausted: boolean
  agentExhaustedReported: boolean
  floorExhaustedReported: boolean
  agentSettled: boolean
  agentRequests: number
}

export interface RequestBudgetSnapshot {
  requestBudgetMode: 'split' | 'single'
  floorRequests: number
  floorRequestBudget: number | null
  agentRequests: number | null
  agentRequestBudget: number | null
  totalRequestBudget: number | null
  floorBudgetExhausted: boolean
  agentBudgetExhausted: boolean
  terminationReason: string | null
}

export class PhaseRequestBudgetTracker {
  private readonly storage: Store
  private readonly budgets: PhaseRequestBudgets | null
  private readonly safeEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void
  readonly stateByRun = new Map<string, PhaseRequestState>()
  readonly terminationReasonByRun = new Map<string, string>()

  constructor(
    storage: Store,
    budgets: PhaseRequestBudgets | null,
    safeEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void,
  ) {
    this.storage = storage
    this.budgets = budgets
    this.safeEvent = safeEvent
  }

  get enabled(): boolean {
    return this.budgets !== null
  }

  beginPhase(run: Run, phase: 'floor' | 'agent'): PhaseRequestState | null {
    if (!this.budgets) return null
    const existing = this.stateByRun.get(run.id)
    if (existing) return existing
    const state: PhaseRequestState = {
      floorBudget: this.budgets.floor,
      agentBudget: this.budgets.agent,
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
    this.stateByRun.set(run.id, state)
    this.safeEvent(
      run.id, 'request_budget.phase_started',
      phase === 'floor'
        ? `Phase A request allowance ${state.floorBudget}; Phase B allowance ${state.agentBudget} (split budgets; no borrowing).`
        : `Phase B request allowance ${state.agentBudget} (no Phase-A floor in this run).`,
      {
        phase, floorRequestBudget: state.floorBudget, agentRequestBudget: state.agentBudget,
        totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null, spentRequestsAtStart: state.baselineRequests,
      },
    )
    return state
  }

  settleFloor(runId: string, reason: string): void {
    const state = this.stateByRun.get(runId)
    if (!state || state.floorSettled) return
    let run: Run
    try { run = this.storage.run(runId) } catch { return }
    state.floorRequests = Math.max(0, run.spentRequests - state.baselineRequests)
    state.floorSettled = true
    state.floorBudgetExhausted = state.floorRequests >= state.floorBudget
    this.safeEvent(
      runId, 'request_budget.floor_settled',
      `Phase A used ${state.floorRequests}/${state.floorBudget} request(s); Phase B allowance is ${state.agentBudget}.`,
      {
        phase: 'floor', reason, floorRequests: state.floorRequests, floorRequestBudget: state.floorBudget,
        agentRequestBudget: state.agentBudget, totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
        spentRequestsAtStart: state.baselineRequests, spentRequestsAtSettle: run.spentRequests,
        floorBudgetExhausted: state.floorBudgetExhausted,
      },
    )
    if (state.floorBudgetExhausted && !state.floorExhaustedReported) {
      state.floorExhaustedReported = true
      this.safeEvent(
        runId, 'request_budget.floor_exhausted',
        `Phase A floor exhausted its ${state.floorBudget}-request allowance; Phase B keeps its own allowance.`,
        { phase: 'floor', floorRequests: state.floorRequests, floorRequestBudget: state.floorBudget },
      )
    }
  }

  settleAgent(runId: string, reason: string): void {
    const state = this.stateByRun.get(runId)
    if (!state || !state.floorSettled || state.agentSettled) return
    let run: Run
    try { run = this.storage.run(runId) } catch { return }
    state.agentRequests = Math.max(0, run.spentRequests - state.baselineRequests - state.floorRequests)
    state.agentSettled = true
    if (state.agentRequests >= state.agentBudget) state.agentBudgetExhausted = true
    this.safeEvent(
      runId, 'request_budget.phase_ended',
      `Phase B used ${state.agentRequests}/${state.agentBudget} request(s) (floor ${state.floorRequests}/${state.floorBudget}).`,
      {
        phase: 'agent', reason, agentRequests: state.agentRequests, agentRequestBudget: state.agentBudget,
        floorRequests: state.floorRequests, floorRequestBudget: state.floorBudget,
        totalRequestBudget: run.budgetRequests > 0 ? run.budgetRequests : null,
        agentBudgetExhausted: state.agentBudgetExhausted,
        terminationReason: this.terminationReasonByRun.get(runId) ?? null,
      },
    )
  }

  remaining(run: Run): number | null {
    const runRemaining = run.budgetRequests > 0 ? Math.max(0, run.budgetRequests - run.spentRequests) : null
    if (!this.budgets) return runRemaining
    const state = this.stateByRun.get(run.id)
    if (!state) return runRemaining
    const spent = Math.max(0, run.spentRequests - state.baselineRequests)
    const phaseRemaining = state.floorSettled
      ? Math.max(0, state.agentBudget - Math.max(0, spent - state.floorRequests))
      : Math.max(0, state.floorBudget - spent)
    if (state.floorSettled && phaseRemaining <= 0) state.agentBudgetExhausted = true
    return runRemaining === null ? phaseRemaining : Math.min(phaseRemaining, runRemaining)
  }

  snapshot(runId: string, floorReportedRequests: number): RequestBudgetSnapshot {
    let run: Pick<Run, 'spentRequests' | 'budgetRequests'>
    try { run = this.storage.run(runId) } catch { run = { spentRequests: 0, budgetRequests: 0 } }
    const state = this.stateByRun.get(runId) ?? null
    const totalRequestBudget = run.budgetRequests > 0 ? run.budgetRequests : null
    const terminationReason = this.terminationReasonByRun.get(runId) ?? null
    if (!this.budgets) {
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
      floorRequestBudget: state?.floorBudget ?? this.budgets.floor,
      agentRequests,
      agentRequestBudget: state?.agentBudget ?? this.budgets.agent,
      totalRequestBudget,
      floorBudgetExhausted: state?.floorBudgetExhausted ?? false,
      agentBudgetExhausted: state?.agentBudgetExhausted ?? false,
      terminationReason,
    }
  }

  reportAgentExhausted(run: Run, readySteps: number, activeAssignments: number): void {
    const state = this.stateByRun.get(run.id)
    if (!state || !state.agentBudgetExhausted || state.agentExhaustedReported) return
    state.agentExhaustedReported = true
    this.terminationReasonByRun.set(run.id, 'agent_budget_exhausted')
    const snap = this.snapshot(run.id, 0)
    this.safeEvent(
      run.id, 'request_budget.agent_exhausted',
      `Phase B agent request allowance exhausted (${snap.agentRequests}/${snap.agentRequestBudget}); `
      + `${readySteps} ready step(s) left undispatched, ${activeAssignments} assignment(s) still in flight.`,
      {
        phase: 'agent', reason: 'agent_budget_exhausted',
        agentRequests: snap.agentRequests, agentRequestBudget: snap.agentRequestBudget,
        floorRequests: snap.floorRequests, floorRequestBudget: snap.floorRequestBudget,
        readySteps, activeAssignments,
      },
    )
  }

  deleteRun(runId: string): void {
    this.stateByRun.delete(runId)
    this.terminationReasonByRun.delete(runId)
  }
}

// --- Extracted Per-Run Telemetry & Staging Cleanup Helpers ---

export interface FloorMetricsContext {
  storage: Store
  safeEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void
  laneStartedAt: Map<string, number>
  laneWallByRun: Map<string, number>
  agenticFloorStartedAt: Map<string, number>
  agenticFloorFinishedAt: Map<string, number>
  agenticFloorDispatchedAt: Map<string, number>
  detLeadConsumed: Set<string>
  detLeadConsumedByRun?: Map<string, Set<string>>
  requestBudgetSnapshot: (runId: string, floorReportedRequests: number) => RequestBudgetSnapshot
}

export function recordRunFloorMetrics(ctx: FloorMetricsContext, runId: string, reason: string): void {
  const deterministicIds = new Set<string>()
  let floorRequests = 0
  let floorStandaloneExpected = 0
  let floorLeadsEmitted = 0
  let after = 0
  for (;;) {
    const page = ctx.storage.eventsAfter(runId, after, 1_000)
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
    const rows = ctx.storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
    for (const row of rows) {
      if (row.finding.status !== 'confirmed') continue
      if (deterministicIds.has(row.id)) floorConfirmed += 1
      else agenticConfirmed += 1
    }
  } catch { /* run may be gone */ }
  const startedAt = ctx.laneStartedAt.get(runId)
  const laneWallMs = startedAt ? Math.max(0, Date.now() - startedAt) : (ctx.laneWallByRun.get(runId) ?? 0)
  if (startedAt) ctx.laneWallByRun.set(runId, laneWallMs)
  const floorStartedAt = ctx.agenticFloorStartedAt.get(runId) ?? startedAt ?? null
  const floorFinishedAt = ctx.agenticFloorFinishedAt.get(runId)
    ?? (floorStartedAt !== null ? floorStartedAt + laneWallMs : null)
  const preservationRatio = floorStandaloneExpected > 0
    ? Number((floorConfirmed / floorStandaloneExpected).toFixed(4))
    : (floorConfirmed > 0 ? 1 : 0)
  const dispatchedAt = ctx.agenticFloorDispatchedAt.get(runId)
  const phaseTimings = {
    floorStartedAt,
    floorFinishedAt,
    floorMs: floorStartedAt !== null && floorFinishedAt !== null ? Math.max(0, floorFinishedAt - floorStartedAt) : laneWallMs,
    agentDispatchAt: dispatchedAt ?? null,
    dispatchAfterFloorMs: dispatchedAt && floorFinishedAt ? Math.max(0, dispatchedAt - floorFinishedAt) : null,
  }
  const budget = ctx.requestBudgetSnapshot(runId, floorRequests)
  const floorLeadsConsumed = ctx.detLeadConsumedByRun
    ? (ctx.detLeadConsumedByRun.get(runId)?.size ?? 0)
    : ctx.detLeadConsumed.size
  const detail = {
    reason,
    floorConfirmed,
    floorStandaloneExpected,
    preservationRatio,
    agenticConfirmed,
    floorLeadsEmitted,
    floorLeadsConsumed,
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
  ctx.safeEvent(
    runId, 'deterministic_lane.metrics',
    `Floor ${floorConfirmed} confirmed / agentic ${agenticConfirmed} confirmed; ${floorLeadsConsumed} det_lead(s) consumed; lane ${Math.round(laneWallMs / 1000)}s.`,
    detail,
  )
  ctx.safeEvent(
    runId, 'deterministic_floor.summary',
    `Floor ${floorConfirmed}/${floorStandaloneExpected} preserved (${(preservationRatio * 100).toFixed(0)}%), ${floorLeadsEmitted} lead(s) emitted / ${floorLeadsConsumed} consumed, ${budget.floorRequests} floor request(s)${budget.floorRequestBudget !== null ? `/${budget.floorRequestBudget}` : ''}, ${budget.agentRequests ?? 0} agent request(s)${budget.agentRequestBudget !== null ? `/${budget.agentRequestBudget}` : ''}, Phase A ${Math.round(laneWallMs / 1000)}s${budget.terminationReason ? `, stopped: ${budget.terminationReason}` : ''}.`,
    detail,
  )
}

export interface ExecutionRunStateCleanupTargets {
  plannerTimers: Map<string, () => void>
  plannerDirty: Set<string>
  plannerDoneRound: Map<string, number>
  plannerErrorState: Map<string, unknown>
  dryStreakObserved: Map<string, number>
  programGraphLeadsSeeded: Set<string>
  dispatchFunnels: Map<string, unknown>
  strandedReadyEvents: Map<string, number>
  reinvestigationGuards: Map<string, unknown>
  recordedPersonaResources: Map<string, Set<string>>
  circuitNotified: Set<string>
  runAuthStarted: Map<string, string>
  runAuthInFlight: Map<string, AbortController>
  deterministicInFlight: Set<string>
  deterministicCompleted: Set<string>
  prePhase0SeededSteps: Map<string, boolean>
  agenticLaneJobs: Map<string, { controller: AbortController }>
  agenticLaneCompleted: Set<string>
  agenticLaneStopping: Set<string>
  verificationDraining: Set<string>
  laneStartedAt: Map<string, number>
  laneWallByRun: Map<string, number>
  assignmentWallByRun: Map<string, number[]>
  completedAssignmentWallByRun: Map<string, number[]>
  turnLatencyByRun: Map<string, number[]>
  earlyExitTurnsSavedByRun: Map<string, number>
  proofObligationByRun: Map<string, unknown>
  gapValidationByRun: Map<string, unknown>
  providerStallTurnsByRun: Map<string, number>
  providerStallRetriesByRun: Map<string, number>
  providerStallTimeoutsByRun: Map<string, number>
  providerStallWallSavedByRun: Map<string, number>
  wallClockRotationsByRun: Map<string, number>
  warmSecretEpochByRun: Map<string, string>
  warmPoolPolicyRotationsByRun: Map<string, number>
  agenticFloorDispatchedAt: Map<string, number>
  agenticFloorStartedAt: Map<string, number>
  agenticFloorFinishedAt: Map<string, number>
  phaseBControllers: Map<string, unknown>
  detLeadConsumed: Set<string>
  detLeadConsumedByRun: Map<string, Set<string>>
  budgetTracker: { deleteRun: (runId: string) => void }
  board: { cleanupRun: (runId: string) => void }
}

/** Deterministically evict all per-run in-memory state from `Execution` on run completion/disposal. */
export function evictRunFromExecutionState(runId: string, targets: ExecutionRunStateCleanupTargets): void {
  const cancelTimer = targets.plannerTimers.get(runId)
  if (cancelTimer) {
    try { cancelTimer() } catch { /* ignore */ }
    targets.plannerTimers.delete(runId)
  }
  targets.plannerDirty.delete(runId)
  targets.plannerDoneRound.delete(runId)
  targets.plannerErrorState.delete(runId)
  targets.dryStreakObserved.delete(runId)
  targets.dispatchFunnels.delete(runId)
  targets.strandedReadyEvents.delete(runId)
  targets.reinvestigationGuards.delete(runId)
  targets.recordedPersonaResources.delete(runId)
  targets.runAuthStarted.delete(runId)
  const inflightAuth = targets.runAuthInFlight.get(runId)
  if (inflightAuth) {
    try { inflightAuth.abort() } catch { /* ignore */ }
    targets.runAuthInFlight.delete(runId)
  }
  targets.prePhase0SeededSteps.delete(runId)
  const lane = targets.agenticLaneJobs.get(runId)
  if (lane) {
    try { lane.controller.abort(new Error('run disposed')) } catch { /* ignore */ }
    targets.agenticLaneJobs.delete(runId)
  }
  targets.agenticLaneStopping.delete(runId)
  targets.verificationDraining.delete(runId)
  targets.laneStartedAt.delete(runId)
  targets.laneWallByRun.delete(runId)
  targets.assignmentWallByRun.delete(runId)
  targets.completedAssignmentWallByRun.delete(runId)
  targets.turnLatencyByRun.delete(runId)
  targets.earlyExitTurnsSavedByRun.delete(runId)
  targets.proofObligationByRun.delete(runId)
  targets.gapValidationByRun.delete(runId)
  targets.providerStallTurnsByRun.delete(runId)
  targets.providerStallRetriesByRun.delete(runId)
  targets.providerStallTimeoutsByRun.delete(runId)
  targets.providerStallWallSavedByRun.delete(runId)
  targets.wallClockRotationsByRun.delete(runId)
  targets.warmSecretEpochByRun.delete(runId)
  targets.warmPoolPolicyRotationsByRun.delete(runId)
  targets.agenticFloorDispatchedAt.delete(runId)
  targets.agenticFloorStartedAt.delete(runId)
  targets.agenticFloorFinishedAt.delete(runId)
  targets.phaseBControllers.delete(runId)
  const consumedForRun = targets.detLeadConsumedByRun.get(runId)
  if (consumedForRun) {
    for (const factId of consumedForRun) targets.detLeadConsumed.delete(factId)
    targets.detLeadConsumedByRun.delete(runId)
  }
  const colonPrefix = `${runId}:`
  const nullPrefix = `${runId}\0`
  for (const key of [...targets.programGraphLeadsSeeded]) {
    if (key.startsWith(nullPrefix)) targets.programGraphLeadsSeeded.delete(key)
  }
  for (const key of [...targets.circuitNotified]) {
    if (key.startsWith(colonPrefix)) targets.circuitNotified.delete(key)
  }
  for (const key of [...targets.deterministicInFlight]) {
    if (key.startsWith(colonPrefix)) targets.deterministicInFlight.delete(key)
  }
  for (const key of [...targets.deterministicCompleted]) {
    if (key.startsWith(colonPrefix)) targets.deterministicCompleted.delete(key)
  }
  for (const key of [...targets.agenticLaneCompleted]) {
    if (key.startsWith(colonPrefix)) targets.agenticLaneCompleted.delete(key)
  }
  targets.budgetTracker.deleteRun(runId)
  targets.board.cleanupRun(runId)
}

export function resolveRunTenantId(storage: Store, run: Pick<Run, 'id' | 'projectId'>): string | null {
  try {
    const t = storage.getRunTenant(run.id)
    return t && t !== 'default' ? t : null
  } catch {
    try {
      const pt = storage.project(run.projectId).tenantId
      return pt && pt !== 'default' ? pt : null
    } catch {
      return null
    }
  }
}

export function trackDetLeadFactForRun(
  storage: Store,
  detLeadConsumedByRun: Map<string, Set<string>>,
  activeRunId: string | null,
  factId: string,
): void {
  let runId = activeRunId
  if (!runId) {
    try {
      const row = storage.client.prepare('SELECT run_id FROM facts WHERE id = ?').get(factId) as { run_id?: string } | undefined
      runId = row?.run_id ?? null
    } catch {
      runId = null
    }
  }
  if (!runId) return
  let perRun = detLeadConsumedByRun.get(runId)
  if (!perRun) {
    perRun = new Set<string>()
    detLeadConsumedByRun.set(runId, perRun)
  }
  perRun.add(factId)
}

export function pauseRunsForKillSwitch(
  storage: Store,
  state: { tenantId: string | null; reason: string | null },
  safeEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void,
  onDispose: (runId: string) => void,
): void {
  try {
    for (const run of storage.runnable()) {
      const tenantId = resolveRunTenantId(storage, run)
      if (state.tenantId !== null && tenantId !== state.tenantId) continue
      try {
        storage.updateRun(run.id, { status: 'paused' })
        safeEvent(run.id, 'run.kill_switch_paused', 'Run paused because emergency kill switch tripped.', {
          tenantId,
          reason: state.reason,
        })
      } catch { /* run may be gone or store closing */ }
      onDispose(run.id)
    }
  } catch { /* store may be closed */ }
}

export interface TrackedActiveRunChecks {
  disposingRuns: Map<string, unknown>
  actors: Map<string, { activeTaskCount: number }>
  timedOutActors: Map<string, { activeTaskCount: number }>
  runtime: { getRunContext: (runId: string) => { activeTaskCount: number } | undefined }
  coordinator: Map<string, unknown>
  threatModeling: Map<string, unknown>
  plannerTasks: Map<string, unknown>
  runAuthInFlight: Map<string, unknown>
  agenticLaneJobs: Map<string, unknown>
  verificationDraining: Set<string>
  active: Map<string, { assignment: { runId: string } }>
}

export function isExecutionRunTrackedActive(runId: string, checks: TrackedActiveRunChecks): boolean {
  const timedOut = checks.timedOutActors.get(runId)
  if (timedOut) {
    if (timedOut.activeTaskCount > 0) return true
    checks.timedOutActors.delete(runId)
  }
  if (
    checks.disposingRuns.has(runId)
    || (checks.actors.get(runId)?.activeTaskCount ?? 0) > 0
    || (checks.runtime.getRunContext(runId)?.activeTaskCount ?? 0) > 0
    || checks.coordinator.has(runId)
    || checks.threatModeling.has(runId)
    || checks.plannerTasks.has(runId)
    || checks.runAuthInFlight.has(runId)
    || checks.agenticLaneJobs.has(runId)
    || checks.verificationDraining.has(runId)
  ) {
    return true
  }
  for (const job of checks.active.values()) {
    if (job.assignment.runId === runId) return true
  }
  return false
}

export async function drainTimedOutRunActor(
  runId: string,
  timedOutActors: Map<string, RunActor>,
  timeoutMs = 2_500,
): Promise<RunDrainReport | null> {
  const lingering = timedOutActors.get(runId)
  if (!lingering) return null
  const drain = await lingering.supervisor.drain(timeoutMs)
  if (lingering.activeTaskCount === 0) timedOutActors.delete(runId)
  return {
    runId,
    aborted: true,
    alreadyDisposed: true,
    tasksTotal: drain.total,
    tasksDrained: drain.drained,
    tasksTimedOut: lingering.activeTaskCount,
    resourcesTotal: 0,
    resourcesDisposed: 0,
    resourceErrors: [],
    durationMs: drain.durationMs,
  }
}

export interface AssignmentMetricsContext {
  storage: Store
  backend: WorkerBackend
  safeEvent: (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => void
  assignmentWallByRun: Map<string, number[]>
  completedAssignmentWallByRun: Map<string, number[]>
  turnLatencyByRun: Map<string, number[]>
  earlyExitTurnsSavedByRun: Map<string, number>
  providerStallTurnsByRun: Map<string, number>
  providerStallRetriesByRun: Map<string, number>
  providerStallTimeoutsByRun: Map<string, number>
  providerStallWallSavedByRun: Map<string, number>
  warmPoolPolicyRotationsByRun: Map<string, number>
  wallClockRotationsByRun: Map<string, number>
  proofObligationByRun: Map<string, ExecProofObligationCounts>
  gapValidationByRun: Map<string, ExecGapValidationCounts>
  lastAssignmentMetrics: Map<string, AssignmentThroughputMetrics>
}

export function recordRunAssignmentMetrics(
  ctx: AssignmentMetricsContext,
  runId: string,
  reason: string,
): AssignmentThroughputMetrics | null {
  let workers: Assignment[] = []
  try {
    workers = ctx.storage.workerList(runId).filter(worker => worker.phase === 'investigation')
  } catch { return null }
  const walls = ctx.assignmentWallByRun.get(runId) ?? []
  const completedWalls = ctx.completedAssignmentWallByRun.get(runId) ?? []
  const turnSamples = ctx.turnLatencyByRun.get(runId) ?? []
  const turnSummary = summarizeTurnLatencies(turnSamples)
  const containers = ctx.backend.containerStats?.()
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
    earlyExitTurnsSaved: ctx.earlyExitTurnsSavedByRun.get(runId) ?? 0,
    providerStallTurns: ctx.providerStallTurnsByRun.get(runId) ?? 0,
    providerStallRetries: ctx.providerStallRetriesByRun.get(runId) ?? 0,
    providerStallTimeouts: ctx.providerStallTimeoutsByRun.get(runId) ?? 0,
    providerStallWallSavedMs: ctx.providerStallWallSavedByRun.get(runId) ?? 0,
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
    warmPoolPolicyRotations: ctx.warmPoolPolicyRotationsByRun.get(runId) ?? 0,
    wallClockRotations: ctx.wallClockRotationsByRun.get(runId) ?? 0,
    ...(ctx.proofObligationByRun.has(runId) ? { proofObligation: { ...ctx.proofObligationByRun.get(runId)! } } : {}),
    ...(ctx.gapValidationByRun.has(runId)
      ? {
          gapValidation: {
            accepted: ctx.gapValidationByRun.get(runId)!.accepted,
            rejected: ctx.gapValidationByRun.get(runId)!.rejected,
            byCode: Object.fromEntries(
              Object.entries(ctx.gapValidationByRun.get(runId)!.byCode).map(([k, v]) => [k, { ...v }]),
            ),
          },
        }
      : {}),
  }
  ctx.lastAssignmentMetrics.set(runId, metrics)
  ctx.safeEvent(
    runId, 'agentic.assignment_metrics',
    `Phase B throughput: ${metrics.assignmentsCompleted}/${metrics.assignmentsObserved} assignment(s) complete, p50 ${(metrics.assignmentWallP50 / 1000).toFixed(1)}s / p90 ${(metrics.assignmentWallP90 / 1000).toFixed(1)}s, ${metrics.turnsPerAssignment} turn(s)/assignment, ${metrics.providerStallTurns} stall turn(s) / ${metrics.providerStallRetries} bounded retry(ies) / ${metrics.providerStallTimeouts} no-token timeout(s) (${(metrics.providerStallWallSavedMs / 1000).toFixed(1)}s saved), ${metrics.containersLaunched} container launch(es) / ${metrics.containersReused} reuse(s) (${(metrics.containerReuseHitRate * 100).toFixed(0)}% hit rate, ${metrics.idleWarmContainers}/${metrics.warmCapacity} idle).`,
    { ...metrics },
  )
  return metrics
}

export async function teardownRunStaging(input: {
  runId: string
  storage: Store
  broker: RequestBroker
  stagingGrants: Map<string, Grant>
  stagingTaggedMutations: Map<string, number>
  stagingUntaggedSkipped: Map<string, number>
  stagingCleaned: Map<string, number>
  stagingCreatedEntities: Map<string, Set<string>>
}): Promise<void> {
  const { runId } = input
  const grant = input.stagingGrants.get(runId)
  if (!grant) return
  input.stagingGrants.delete(runId)
  try {
    if ((input.stagingTaggedMutations.get(runId) ?? 0) > 0) {
      const removed = await cleanupStagedEntities({
        endpoints: input.storage.listEndpoints(runId),
        runId,
        broker: input.broker,
        grant,
        signal: AbortSignal.timeout(8_000),
        log: (kind, message, data) => {
          try { input.storage.event(runId, kind, message, data ?? {}) } catch { /* run may be gone */ }
        },
      })
      if (removed > 0) input.stagingCleaned.set(runId, (input.stagingCleaned.get(runId) ?? 0) + removed)
      input.storage.event(runId, 'staging.teardown', `Staging teardown cleaned ${removed} tagged entit${removed === 1 ? 'y' : 'ies'}.`, {
        stagingTaggedMutations: input.stagingTaggedMutations.get(runId) ?? 0,
        stagingUntaggedSkipped: input.stagingUntaggedSkipped.get(runId) ?? 0,
        stagingCleaned: input.stagingCleaned.get(runId) ?? 0,
      })
    }
  } catch { /* teardown is best-effort; never block shutdown */ }
  input.stagingCreatedEntities.delete(runId)
  input.stagingTaggedMutations.delete(runId)
  input.stagingUntaggedSkipped.delete(runId)
  input.stagingCleaned.delete(runId)
}

// ============================================================================
// 7. Extracted Per-Run Tier-3 Approval & Park/Resume Coordinator
// ============================================================================

export interface Tier3ApprovalCoordinatorHost {
  storage: Store
  broker: RequestBroker
  active: Map<string, ExecActiveJob>
  pendingTier3ApprovalKeys: Set<string>
  stateChangeApprovals: StateChangeApprovalLedger
  burstApprovalInstances: BurstApprovalInstances
  authorize: (job: ExecActiveJob) => boolean
  check: (job: ExecActiveJob) => Run
  phaseRequestRemaining: (run: Run) => number | null
  postApprovalCard: (
    run: Run,
    assignmentId: string,
    input: Parameters<ExecBoardManager['postApprovalCard']>[2],
    secrets?: readonly NamedSecret[],
  ) => unknown
  postApprovalResolution: (
    run: Run,
    assignmentId: string,
    input: Parameters<ExecBoardManager['postApprovalResolution']>[2],
  ) => void
  registerTimer?: (
    runId: string,
    name: string,
    timer: ReturnType<typeof setInterval>,
  ) => () => void
  scheduleWake: () => void
}

export class RunTier3ApprovalCoordinator {
  private readonly host: Tier3ApprovalCoordinatorHost

  constructor(host: Tier3ApprovalCoordinatorHost) {
    this.host = host
  }

  planTargets(
    run: Run,
    requests: Parameters<typeof planTier3ApprovalTargets>[1],
    options: Parameters<typeof planTier3ApprovalTargets>[2] = {},
  ) {
    return planTier3ApprovalTargets(run, requests, options)
  }

  async executeApprovedBrokerGroup<T>(
    job: ExecActiveJob,
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
    const run = this.host.check(job)
    if (options.isRaceBurst) {
      const phaseRemaining = this.host.phaseRequestRemaining(run)
      if (phaseRemaining !== null && requests.length > phaseRemaining) {
        throw new BudgetExceededError('Race burst would exceed the agent request budget.')
      }
    }
    const approvalPlan = planTier3ApprovalTargets(run, requests, { isRaceBurst: options.isRaceBurst })
    try {
      return await options.execute()
    } catch (err) {
      if (!(err instanceof BrokerApprovalRequired)) throw err
      const distinctTargets = approvalPlan.targets
      const multiTarget = distinctTargets.length > 1
      const project = this.host.storage.project(run.projectId)
      const activePatterns = (run.approvedEndpointPatterns ?? []).filter(
        p => p.scopeRevision === undefined || p.scopeRevision === run.scopeRevision,
      )
      const fastProfiles = resolveProfilePoolForRole('fast', this.host.storage)
      const approvedGrants: Array<Parameters<typeof registerStateChangeGrant>[3]> = []
      const escalatedTargets: Array<{
        target: (typeof distinctTargets)[number]
        idx: number
        evaluation: Awaited<ReturnType<typeof evaluateTier3Approval>>
      }> = []

      for (let idx = 0; idx < distinctTargets.length; idx += 1) {
        const target = distinctTargets[idx]!
        const evaluation = await evaluateTier3Approval({
          policy: run.approvalPolicy ?? 'auto_review',
          origin: target.origin,
          method: target.method,
          pathAndQuery: target.pathAndQuery,
          personaHandle: target.personaHandle,
          rationale: multiTarget
            ? `${options.rationale} (target ${idx + 1}/${distinctTargets.length}: ${target.method.toUpperCase()} ${target.pathAndQuery})`
            : options.rationale,
          bodyPreview: target.bodyPreview,
          headers: target.headers,
          hasMultipart: target.hasMultipart,
          isRaceBurst: options.isRaceBurst,
          environment: project.environment,
          approvedPatterns: activePatterns,
          profiles: fastProfiles,
          signal,
          secrets: options.secrets,
          onUsage: usage => {
            this.host.storage.recordLlmSpend(run.id, { usd: usage.costUsd, tokens: usage.inputTokens + usage.outputTokens })
          },
        })
        if (evaluation.decision === 'approve' || evaluation.decision === 'deny') {
          const approved = evaluation.decision === 'approve'
          this.host.storage.recordAutoApprovalDecision(run, job.assignment, {
            origin: target.origin, method: target.method, pathAndQuery: target.pathAndQuery,
            personaHandle: target.personaHandle,
            rationale: multiTarget
              ? `${options.rationale} (target ${idx + 1}/${distinctTargets.length}: ${target.method.toUpperCase()} ${target.pathAndQuery})`
              : options.rationale,
            requestPreview: options.requestPreview,
            riskLevel: evaluation.riskLevel,
            policyNote: evaluation.reason,
            secrets: options.secrets,
            decision: approved ? 'approved' : 'denied',
            decidedBy: approved ? (evaluation.decidedBy === 'operator' ? 'auto-review:rule' : evaluation.decidedBy) : 'auto-review:judge',
          })
          if (!approved) {
            throw new BrokerDenied(`Tier 3 Safety Judge denied ${options.denyLabel} probe: ${evaluation.reason}`)
          }
          approvedGrants.push({
            origin: target.origin, method: target.method, pathAndQuery: target.pathAndQuery,
            personaHandle: target.personaHandle, bodyHash: target.bodyHash, bodyPreview: target.bodyPreview,
            hasMultipart: target.hasMultipart, isRaceBurst: options.isRaceBurst, instances: target.instances,
          })
        } else {
          escalatedTargets.push({ target, idx, evaluation })
        }
      }

      const canCombineHomogeneousBatch =
        !options.isRaceBurst &&
        escalatedTargets.length > 1 &&
        escalatedTargets.every(item =>
          item.target.method.toUpperCase() === escalatedTargets[0]!.target.method.toUpperCase() &&
          item.evaluation.riskLevel === escalatedTargets[0]!.evaluation.riskLevel)

      if (canCombineHomogeneousBatch) {
        const primary = escalatedTargets[0]!
        const human = await this.waitForHumanTier3Card(job, run, {
          origin: primary.target.origin,
          method: primary.target.method,
          pathAndQuery: primary.target.pathAndQuery,
          personaHandle: primary.target.personaHandle,
          rationale: options.rationale,
          requestPreview: options.requestPreview,
          bodyPreview: primary.target.bodyPreview,
          isRaceBurst: false,
          riskLevel: primary.evaluation.riskLevel,
          policyNote: primary.evaluation.reason,
          secrets: options.secrets,
        }, signal)
        if (!human.approved) {
          throw new BrokerDenied(
            human.deniedReason
              ? `Tier 3 Safety Judge denied ${options.denyLabel} probe: ${human.deniedReason}`
              : `Tier 3 ${options.denyLabel} request was denied or expired.`,
          )
        }
        for (const { target } of escalatedTargets) {
          approvedGrants.push({
            origin: target.origin, method: target.method, pathAndQuery: target.pathAndQuery,
            personaHandle: target.personaHandle, bodyHash: target.bodyHash, bodyPreview: target.bodyPreview,
            hasMultipart: target.hasMultipart, isRaceBurst: false, instances: target.instances,
            ...(human.approvalId ? { approvalId: human.approvalId } : {}),
          })
        }
      } else {
        for (const { target, idx, evaluation } of escalatedTargets) {
          const targetPreview = multiTarget
            ? JSON.stringify({
                batchItem: `${idx + 1}/${distinctTargets.length}`,
                totalRequests: requests.length,
                instances: target.instances,
                method: target.method,
                origin: target.origin,
                pathAndQuery: target.pathAndQuery,
                persona: target.personaHandle,
                bodyPreview: target.bodyPreview?.slice(0, 300) ?? null,
                hasMultipart: target.hasMultipart,
              }, null, 2)
            : options.requestPreview
          const human = await this.waitForHumanTier3Card(job, run, {
            origin: target.origin,
            method: target.method,
            pathAndQuery: target.pathAndQuery,
            personaHandle: target.personaHandle,
            rationale: multiTarget
              ? `${options.rationale} (target ${idx + 1}/${distinctTargets.length}: ${target.method.toUpperCase()} ${target.pathAndQuery})`
              : options.rationale,
            requestPreview: targetPreview,
            bodyPreview: target.bodyPreview,
            isRaceBurst: options.isRaceBurst,
            riskLevel: evaluation.riskLevel,
            policyNote: evaluation.reason,
            secrets: options.secrets,
          }, signal)
          if (!human.approved) {
            throw new BrokerDenied(
              human.deniedReason
                ? `Tier 3 Safety Judge denied ${options.denyLabel} probe: ${human.deniedReason}`
                : `Tier 3 ${options.denyLabel} request was denied or expired.`,
            )
          }
          approvedGrants.push({
            origin: target.origin, method: target.method, pathAndQuery: target.pathAndQuery,
            personaHandle: target.personaHandle, bodyHash: target.bodyHash, bodyPreview: target.bodyPreview,
            hasMultipart: target.hasMultipart, isRaceBurst: options.isRaceBurst, instances: target.instances,
            ...(human.approvalId ? { approvalId: human.approvalId } : {}),
          })
        }
      }

      const freshRun = this.host.check(job)
      for (const grantTarget of approvedGrants) {
        registerStateChangeGrant(this.host.stateChangeApprovals, this.host.burstApprovalInstances, freshRun, grantTarget)
      }
      return await options.execute()
    }
  }

  executeApprovedRaceBurst(
    job: ExecActiveJob,
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
      execute: options.execute ?? (() => this.host.broker.executeRaceBurst(requests, grant, signal)),
    })
  }

  executeApprovedBatch(
    job: ExecActiveJob,
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
      execute: options.execute ?? (() => this.host.broker.executeBatch(requests, grant, signal)),
    })
  }

  async waitForTier3Approval(
    job: ExecActiveJob,
    input: ExecTier3ApprovalInput & { deferGrant?: boolean },
    signal: AbortSignal,
  ): Promise<{ approved: boolean; deniedReason?: string; grantTarget?: Parameters<typeof registerStateChangeGrant>[3] }> {
    const run = this.host.check(job)
    const project = this.host.storage.project(run.projectId)
    if (run.capabilityTier < 3) {
      throw new BrokerDenied('This operation requires Capability Tier 3.')
    }
    if (input.additionalApprovalTargets && input.additionalApprovalTargets.length > 0) {
      return {
        approved: false,
        deniedReason: 'Distinct batch targets must each be evaluated individually; piggybacking additionalApprovalTargets is forbidden.',
      }
    }

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
      profiles: resolveProfilePoolForRole('fast', this.host.storage),
      signal,
      secrets: input.secrets,
      onUsage: usage => {
        this.host.storage.recordLlmSpend(run.id, {
          usd: usage.costUsd,
          tokens: usage.inputTokens + usage.outputTokens,
        })
      },
    })

    const grantTarget = (approvalId?: string) => ({
      origin: input.origin,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      personaHandle: input.personaHandle ?? null,
      bodyHash: input.bodyHash,
      bodyPreview: input.bodyPreview ?? null,
      hasMultipart: input.hasMultipart,
      isRaceBurst: input.isRaceBurst,
      isRceProof: input.isRceProof,
      ...(approvalId ? { approvalId } : {}),
      instances: input.approvalInstances,
    })

    if (evaluation.decision === 'approve' || evaluation.decision === 'deny') {
      const approved = evaluation.decision === 'approve'
      this.host.storage.recordAutoApprovalDecision(run, job.assignment, {
        origin: input.origin, method: input.method, pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle, rationale: input.rationale,
        requestPreview: input.requestPreview, riskLevel: evaluation.riskLevel,
        policyNote: evaluation.reason, secrets: input.secrets,
        decision: approved ? 'approved' : 'denied',
        decidedBy: approved ? (evaluation.decidedBy === 'operator' ? 'auto-review:rule' : evaluation.decidedBy) : 'auto-review:judge',
      })
      if (!approved) return { approved: false, deniedReason: evaluation.reason }
      const targetGrant = grantTarget()
      if (!input.deferGrant) {
        registerStateChangeGrant(this.host.stateChangeApprovals, this.host.burstApprovalInstances, run, targetGrant)
      }
      return { approved: true, grantTarget: targetGrant }
    }

    const human = await this.waitForHumanTier3Card(job, run, {
      origin: input.origin,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      personaHandle: input.personaHandle ?? null,
      rationale: input.rationale,
      requestPreview: input.requestPreview,
      bodyPreview: input.bodyPreview ?? null,
      isRceProof: input.isRceProof,
      isRaceBurst: input.isRaceBurst,
      riskLevel: evaluation.riskLevel,
      policyNote: evaluation.reason,
      secrets: input.secrets,
    }, signal)
    if (!human.approved) {
      return { approved: false, ...(human.deniedReason ? { deniedReason: human.deniedReason } : {}) }
    }
    const targetGrant = grantTarget(human.approvalId)
    if (!input.deferGrant) {
      registerStateChangeGrant(this.host.stateChangeApprovals, this.host.burstApprovalInstances, run, targetGrant)
    }
    return { approved: true, grantTarget: targetGrant }
  }

  private async waitForHumanTier3Card(
    job: ExecActiveJob,
    run: Run,
    input: {
      origin: string
      method: string
      pathAndQuery: string
      personaHandle?: string | null
      rationale: string
      requestPreview: string
      bodyPreview?: string | null
      isRceProof?: boolean
      isRaceBurst?: boolean
      riskLevel: Awaited<ReturnType<typeof evaluateTier3Approval>>['riskLevel']
      policyNote: string
      secrets: readonly NamedSecret[]
    },
    signal: AbortSignal,
  ): Promise<{ approved: boolean; approvalId?: string; deniedReason?: string }> {
    const approvalKey = [
      run.id, run.scopeRevision, input.origin, input.method.toUpperCase(), input.pathAndQuery,
      input.personaHandle ?? '', input.isRceProof ? 'rce' : '', input.isRaceBurst ? 'race' : '', input.bodyPreview ?? '',
    ].join('\0')
    if (this.host.pendingTier3ApprovalKeys.has(approvalKey)) {
      return {
        approved: false,
        deniedReason: 'An identical Tier 3 probe is already awaiting operator approval; duplicate parallel trial suppressed.',
      }
    }
    this.host.pendingTier3ApprovalKeys.add(approvalKey)

    let decision: 'approved' | 'denied' | 'canceled' | 'expired'
    let postedApprovalId: string | undefined
    try {
      const req = this.host.storage.createApprovalRequest(run, job.assignment, {
        origin: input.origin, method: input.method, pathAndQuery: input.pathAndQuery,
        personaHandle: input.personaHandle ?? undefined, rationale: input.rationale,
        requestPreview: input.requestPreview, riskLevel: input.riskLevel,
        policyNote: input.policyNote, secrets: input.secrets,
      })
      postedApprovalId = req.id
      this.host.postApprovalCard(run, job.assignment.id, {
        approvalId: req.id,
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        rationale: input.rationale,
      }, input.secrets)

      try {
        this.host.storage.parkWorkerForApproval(run, job.assignment.id)
        this.host.active.delete(job.assignment.id)
        this.host.scheduleWake()
      } catch { /* an already-parked or terminal worker keeps its state */ }

      decision = await new Promise<'approved' | 'denied' | 'canceled' | 'expired'>((resolveDecision, rejectDecision) => {
        const checkCurrent = () => {
          try {
            const latest = this.host.storage.getApprovalRequest(run.id, req.id)
            if (latest.status !== 'pending') {
              cleanup()
              resolveDecision(latest.status)
              return true
            }
            if (Date.now() >= latest.expiresAt) {
              this.host.storage.db.update(approvalRequests).set({ status: 'expired', decidedAt: Date.now() })
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

        const unsub = this.host.storage.onRunEvent(run.id, () => { checkCurrent() })
        const timer = setInterval(() => { checkCurrent() }, 1_000)
        timer.unref?.()
        const unregisterTimer = this.host.registerTimer
          ? this.host.registerTimer(run.id, 'tier3-approval-poll', timer)
          : () => {}
        const onAbort = () => {
          cleanup()
          rejectDecision(signal.reason instanceof Error ? signal.reason : new Error('Aborted while waiting for approval.'))
        }
        const cleanup = () => {
          unsub()
          unregisterTimer()
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
      this.host.pendingTier3ApprovalKeys.delete(approvalKey)
    }

    if (postedApprovalId) {
      this.host.postApprovalResolution(run, job.assignment.id, {
        approvalId: postedApprovalId,
        decision,
        origin: input.origin,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
      })
    }
    if (decision === 'approved') {
      try {
        const resumed = this.host.storage.resumeParkedWorker(this.host.storage.run(run.id), job.assignment.id)
        job.assignment = resumed
        this.host.active.set(resumed.id, job)
        this.host.scheduleWake()
      } catch {
        if (this.host.authorize(job)) {
          try { this.host.storage.updateWorker(job.assignment.id, { status: 'running', approvalParkedAt: null }) } catch { /* ignore */ }
        }
      }
      return { approved: true, approvalId: postedApprovalId }
    }
    this.terminateApprovalBlockedAssignment(run.id, job.assignment.id, decision)
    return { approved: false }
  }

  terminateApprovalBlockedAssignment(
    runId: string,
    assignmentId: string,
    decision: 'denied' | 'expired' | 'canceled',
  ): void {
    try {
      this.host.storage.transaction(() => {
        const current = this.host.storage.worker(assignmentId)
        if (current.status !== 'complete' && current.status !== 'canceled' && current.status !== 'failed') {
          this.host.storage.updateWorker(assignmentId, {
            status: 'failed',
            approvalParkedAt: null,
            lease: null,
            leaseExpiresAt: null,
            outcome: `Tier 3 approval ${decision}.`,
          })
        }
        if (current.phase === 'investigation' && current.stepId) {
          const latestRun = this.host.storage.run(runId)
          const step = this.host.storage.listChainSteps(latestRun.id, latestRun.goalRevision)
            .find(s => s.id === current.stepId)
          if (step && ['pending', 'ready', 'running'].includes(step.status)) {
            this.host.storage.updateChainStep(step.id, {
              status: 'canceled',
              assignedWorkerId: assignmentId,
            })
            this.host.storage.refreshReadyChainSteps(latestRun.id, latestRun.goalRevision)
          }
        }
      }, { behavior: 'immediate' })
    } catch { /* worker or run may already be terminal or removed */ }
    this.host.active.delete(assignmentId)
    this.host.scheduleWake()
  }

  reconcileSettledApprovalWorkers(run: Run): void {
    const now = Date.now()
    const workers = this.host.storage.workerList(run.id)
    const waitingWorkers = workers.filter(w => w.status === 'waiting_approval' && !this.host.active.has(w.id))
    if (waitingWorkers.length > 0) {
      const requests = this.host.storage.listApprovalRequests(run.id)
      for (const worker of waitingWorkers) {
        const forWorker = requests.filter(r => r.assignmentId === worker.id)
        if (!forWorker.length) continue
        let hasLivePending = false
        for (const req of forWorker) {
          if (req.status !== 'pending') continue
          if (now >= req.expiresAt) {
            try {
              this.host.storage.db.update(approvalRequests).set({ status: 'expired', decidedAt: now })
                .where(eq(approvalRequests.id, req.id)).run()
              req.status = 'expired'
              req.decidedAt = now
            } catch { /* ignore */ }
          } else {
            hasLivePending = true
          }
        }
        if (hasLivePending) continue
        const latest = [...forWorker].sort((a, b) => (b.decidedAt ?? b.createdAt) - (a.decidedAt ?? a.createdAt))[0]
        if (latest && (latest.status === 'denied' || latest.status === 'expired' || latest.status === 'canceled')) {
          this.terminateApprovalBlockedAssignment(run.id, worker.id, latest.status)
        }
      }
    }

    if (run.phase === 'investigation') {
      const workerById = new Map(this.host.storage.workerList(run.id).map(w => [w.id, w]))
      for (const step of this.host.storage.listChainSteps(run.id, run.goalRevision)) {
        if (step.status !== 'running' || !step.assignedWorkerId) continue
        if (this.host.active.has(step.assignedWorkerId)) continue
        const assigned = workerById.get(step.assignedWorkerId)
        if (!assigned) continue
        if (assigned.status === 'complete') {
          this.host.storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: assigned.id })
        } else if (assigned.status === 'failed' || assigned.status === 'canceled') {
          this.host.storage.updateChainStep(step.id, { status: 'canceled', assignedWorkerId: assigned.id })
        }
      }
    }
  }
}
