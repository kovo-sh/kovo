/**
 * Move O4 — Pause-Aware `ActiveClock` Primitive & Assignment/Run Clock Registries.
 *
 * Tracks active (non-paused) wall-clock time and schedules pause-aware deadline timers that
 * automatically freeze while paused (e.g. during human Tier-3 approval waits or run pauses)
 * and resume cleanly with the exact remaining active budget. Supports nested/overlapping
 * pause reasons via per-reason reference counts and parent-child clock propagation.
 */

export interface ActiveClockOptions {
  /** Monotonic/wall time source in ms (default `Date.now`). Injectable for deterministic tests. */
  now?: () => number
  /** Optional parent clock (e.g. RunActor clock); pausing the parent pauses this child clock. */
  parent?: ActiveClock
  /** Optional starting active elapsed ms (default `0`). */
  initialActiveMs?: number
}

export interface DeadlineTimerHandle {
  readonly active: boolean
  readonly expired: boolean
  readonly canceled: boolean
  /** Remaining active ms before expiration (0 once expired or canceled). */
  remainingMs(): number
  /** Cancel the deadline timer (idempotent). */
  cancel(): void
}

interface InternalDeadlineTimer {
  readonly targetActiveMs: number
  readonly onExpire: () => void
  active: boolean
  expired: boolean
  canceled: boolean
  timer: ReturnType<typeof setTimeout> | undefined
}

const PARENT_PAUSE_REASON = '__parent_clock_paused__'

export class ActiveClock {
  private readonly now: () => number
  private accumulatedActiveMs: number
  private accumulatedPausedMs = 0
  private runningSinceMs: number | null
  private pausedSinceMs: number | null = null
  private readonly pauseCounts = new Map<string, number>()
  private readonly timers = new Set<InternalDeadlineTimer>()
  private readonly pauseListeners = new Set<(paused: boolean) => void>()
  private detachParent: (() => void) | null = null
  private disposed = false

  constructor(options: ActiveClockOptions = {}) {
    this.now = options.now ?? Date.now
    this.accumulatedActiveMs = Math.max(
      0,
      Number.isFinite(options.initialActiveMs) ? Math.floor(options.initialActiveMs!) : 0,
    )
    this.runningSinceMs = this.now()

    if (options.parent) {
      this.attachParent(options.parent)
    }
  }

  get isPaused(): boolean {
    return this.pauseCounts.size > 0
  }

  get isDisposed(): boolean {
    return this.disposed
  }

  /** Distinct active pause reasons currently freezing this clock (excludes internal parent tag). */
  get activePauseReasons(): readonly string[] {
    return [...this.pauseCounts.keys()].filter(reason => reason !== PARENT_PAUSE_REASON)
  }

  /** Total active (unpaused) elapsed time in milliseconds. */
  activeElapsedMs(): number {
    if (this.runningSinceMs === null) {
      return this.accumulatedActiveMs
    }
    return this.accumulatedActiveMs + Math.max(0, this.now() - this.runningSinceMs)
  }

  /** Total time spent paused in milliseconds. */
  pausedElapsedMs(): number {
    if (this.pausedSinceMs === null) {
      return this.accumulatedPausedMs
    }
    return this.accumulatedPausedMs + Math.max(0, this.now() - this.pausedSinceMs)
  }

  /**
   * Pause the clock for `reason`. Supports both distinct overlapping reasons (e.g.
   * `'approval_wait'` + `'run_paused'`) and re-entrant nested calls with the same reason.
   * The clock remains paused until every matching `pause(reason)` has been resumed.
   */
  pause(reason = 'paused'): void {
    const key = reason.trim() || 'paused'
    const wasPaused = this.isPaused
    this.pauseCounts.set(key, (this.pauseCounts.get(key) ?? 0) + 1)
    if (wasPaused) return

    const t = this.now()
    if (this.runningSinceMs !== null) {
      this.accumulatedActiveMs += Math.max(0, t - this.runningSinceMs)
      this.runningSinceMs = null
    }
    this.pausedSinceMs = t
    this.suspendTimers()
    this.notifyPauseListeners(true)
  }

  /**
   * Resume a prior `pause(reason)`. Idempotent if `reason` is not currently active.
   * Active elapsed time and deadline timers resume only once all active pause reasons clear.
   */
  resume(reason = 'paused'): void {
    const key = reason.trim() || 'paused'
    const count = this.pauseCounts.get(key) ?? 0
    if (count <= 0) return
    if (count === 1) {
      this.pauseCounts.delete(key)
    } else {
      this.pauseCounts.set(key, count - 1)
    }
    if (this.pauseCounts.size > 0) return

    const t = this.now()
    if (this.pausedSinceMs !== null) {
      this.accumulatedPausedMs += Math.max(0, t - this.pausedSinceMs)
      this.pausedSinceMs = null
    }
    this.runningSinceMs = t
    if (!this.disposed) {
      this.resumeTimers()
    }
    this.notifyPauseListeners(false)
  }

  /** Run an async/sync block with the clock paused under `reason`, always resuming in `finally`. */
  async withPause<T>(reason: string, fn: () => Promise<T> | T): Promise<T> {
    this.pause(reason)
    try {
      return await fn()
    } finally {
      this.resume(reason)
    }
  }

  /**
   * Schedule a pause-aware deadline timer that fires once `budgetMs` of *active* (unpaused)
   * time has elapsed from the moment this timer is created. While the clock is paused, the
   * timer is suspended and will never fire until resumed and the remaining active budget elapses.
   */
  createDeadlineTimer(budgetMs: number, onExpire: () => void): DeadlineTimerHandle {
    const clampedBudget = Math.max(0, Number.isFinite(budgetMs) ? Math.floor(budgetMs) : 0)
    const targetActiveMs = this.activeElapsedMs() + clampedBudget

    const entry: InternalDeadlineTimer = {
      targetActiveMs,
      onExpire,
      active: !this.disposed,
      expired: false,
      canceled: this.disposed,
      timer: undefined,
    }

    if (!this.disposed) {
      this.timers.add(entry)
      if (!this.isPaused) {
        this.armTimer(entry)
      }
    }

    return {
      get active() {
        return entry.active
      },
      get expired() {
        return entry.expired
      },
      get canceled() {
        return entry.canceled
      },
      remainingMs: () => {
        if (!entry.active) return 0
        return Math.max(0, entry.targetActiveMs - this.activeElapsedMs())
      },
      cancel: () => {
        if (!entry.active) return
        entry.active = false
        entry.canceled = true
        if (entry.timer !== undefined) {
          clearTimeout(entry.timer)
          entry.timer = undefined
        }
        this.timers.delete(entry)
      },
    }
  }

  /** Observe pause state transitions (`true` = entered paused, `false` = resumed running). */
  onPauseChange(listener: (paused: boolean) => void): () => void {
    if (this.disposed) return () => undefined
    this.pauseListeners.add(listener)
    return () => {
      this.pauseListeners.delete(listener)
    }
  }

  /** Cancel all pending deadline timers and detach from any parent clock. */
  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    for (const entry of this.timers) {
      entry.active = false
      entry.canceled = true
      if (entry.timer !== undefined) {
        clearTimeout(entry.timer)
        entry.timer = undefined
      }
    }
    this.timers.clear()
    this.pauseListeners.clear()
    if (this.detachParent) {
      const detach = this.detachParent
      this.detachParent = null
      detach()
    }
  }

  private attachParent(parent: ActiveClock): void {
    if (parent.isPaused) {
      this.pause(PARENT_PAUSE_REASON)
    }
    this.detachParent = parent.onPauseChange(paused => {
      if (this.disposed) return
      if (paused) {
        this.pause(PARENT_PAUSE_REASON)
      } else {
        this.resume(PARENT_PAUSE_REASON)
      }
    })
  }

  private suspendTimers(): void {
    for (const entry of this.timers) {
      if (entry.timer !== undefined) {
        clearTimeout(entry.timer)
        entry.timer = undefined
      }
    }
  }

  private resumeTimers(): void {
    for (const entry of [...this.timers]) {
      if (entry.active && entry.timer === undefined) {
        this.armTimer(entry)
      }
    }
  }

  private armTimer(entry: InternalDeadlineTimer): void {
    if (!entry.active || this.isPaused || this.disposed) return
    const remaining = Math.max(0, Math.ceil(entry.targetActiveMs - this.activeElapsedMs()))
    entry.timer = setTimeout(() => {
      entry.timer = undefined
      if (!entry.active || this.isPaused || this.disposed) return
      const left = entry.targetActiveMs - this.activeElapsedMs()
      if (left > 1) {
        this.armTimer(entry)
        return
      }
      entry.active = false
      entry.expired = true
      this.timers.delete(entry)
      entry.onExpire()
    }, remaining)
    entry.timer.unref?.()
  }

  private notifyPauseListeners(paused: boolean): void {
    for (const listener of [...this.pauseListeners]) {
      try {
        listener(paused)
      } catch {
        /* clock observers must never throw */
      }
    }
  }
}

// ============================================================================
// Lightweight Run & Assignment Clock Registries
// ============================================================================

const runClocks = new Map<string, ActiveClock>()
const assignmentClocks = new Map<string, ActiveClock>()

export function registerRunClock(runId: string, clock: ActiveClock): () => void {
  runClocks.set(runId, clock)
  let released = false
  return () => {
    if (released) return
    released = true
    if (runClocks.get(runId) === clock) {
      runClocks.delete(runId)
    }
  }
}

export function getRunClock(runId: string): ActiveClock | undefined {
  return runClocks.get(runId)
}

export function registerAssignmentClock(assignmentId: string, clock: ActiveClock): () => void {
  assignmentClocks.set(assignmentId, clock)
  let released = false
  return () => {
    if (released) return
    released = true
    if (assignmentClocks.get(assignmentId) === clock) {
      assignmentClocks.delete(assignmentId)
    }
  }
}

export function getAssignmentClock(assignmentId: string): ActiveClock | undefined {
  return assignmentClocks.get(assignmentId)
}

export function pauseAssignmentClock(assignmentId: string, reason: string): boolean {
  const clock = assignmentClocks.get(assignmentId)
  if (!clock) return false
  clock.pause(reason)
  return true
}

export function resumeAssignmentClock(assignmentId: string, reason: string): boolean {
  const clock = assignmentClocks.get(assignmentId)
  if (!clock) return false
  clock.resume(reason)
  return true
}
