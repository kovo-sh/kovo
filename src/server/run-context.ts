/**
 * Option 2 — Move 2: Mandatory per-run ownership envelope (`RunContext`).
 *
 * Every run owns:
 *  - a strictly validated non-empty, non-`'default'` `runId`,
 *  - a live `AbortController` / `AbortSignal` automatically chained to `GlobalKillSwitch`,
 *  - a structured disposable resource registry (vault eviction, browser context close,
 *    OOB subscription unsubscribe, timers),
 *  - a tracked async task registry drained deterministically during `drainAndDispose()`.
 */
import { KillSwitchTrippedError } from './kill-switch.ts'
import type { GlobalKillSwitch } from './kill-switch.ts'

export class InvalidRunIdError extends Error {
  readonly code = 'INVALID_RUN_ID'

  constructor(message: string) {
    super(message)
    this.name = 'InvalidRunIdError'
  }
}

/**
 * Enforce the non-empty, non-`'default'` `runId` invariant across runtime, OOB, and DI boundaries.
 * Returns the trimmed `runId` or throws `InvalidRunIdError`.
 */
export function assertValidRunId(runId: unknown, context = 'RunContext'): string {
  if (typeof runId !== 'string') {
    throw new InvalidRunIdError(`${context}: runId must be a non-empty string (never 'default').`)
  }
  const trimmed = runId.trim()
  if (trimmed.length === 0) {
    throw new InvalidRunIdError(`${context}: runId must be non-empty.`)
  }
  if (trimmed.toLowerCase() === 'default') {
    throw new InvalidRunIdError(`${context}: runId cannot be 'default'; pass an explicit runId.`)
  }
  return trimmed
}

export interface RunContextOptions {
  runId: string
  tenantId?: string | null
  killSwitch?: GlobalKillSwitch
  parentSignal?: AbortSignal
  onDispose?: (runId: string) => void
  defaultDrainTimeoutMs?: number
}

export interface RunDrainReport {
  runId: string
  aborted: boolean
  tasksTotal: number
  tasksDrained: number
  tasksTimedOut: number
  resourcesTotal: number
  resourcesDisposed: number
  resourceErrors: Array<{ name: string; error: string }>
  durationMs: number
  alreadyDisposed: boolean
}

interface RegisteredResource {
  name: string
  dispose: () => void | Promise<void>
}

interface TrackedTask {
  label: string
  settled: Promise<void>
}

const DEFAULT_DRAIN_TIMEOUT_MS = 5_000

export class RunContext {
  readonly runId: string
  readonly tenantId: string | null
  readonly createdAt: number
  readonly abortController: AbortController
  private readonly defaultDrainTimeoutMs: number
  private readonly onDispose?: (runId: string) => void
  private readonly resources = new Map<number, RegisteredResource>()
  private readonly tasks = new Map<number, TrackedTask>()
  private nextResourceId = 1
  private nextTaskId = 1
  private releaseKillSwitch: (() => void) | null = null
  private releaseParentSignal: (() => void) | null = null
  private disposed = false
  private disposePromise: Promise<RunDrainReport> | null = null

  constructor(options: RunContextOptions) {
    this.runId = assertValidRunId(options.runId, 'RunContext')
    const trimmedTenant = typeof options.tenantId === 'string' ? options.tenantId.trim() : ''
    this.tenantId = trimmedTenant.length > 0 ? trimmedTenant : null
    this.createdAt = Date.now()
    this.abortController = new AbortController()
    this.defaultDrainTimeoutMs = Math.max(0, options.defaultDrainTimeoutMs ?? DEFAULT_DRAIN_TIMEOUT_MS)
    this.onDispose = options.onDispose

    if (options.killSwitch) {
      this.releaseKillSwitch = options.killSwitch.registerAbortController(
        this.abortController,
        this.tenantId,
      )
    }

    if (options.parentSignal) {
      const parent = options.parentSignal
      if (parent.aborted) {
        this.abort(parent.reason ?? new Error(`Parent signal aborted for run "${this.runId}".`))
      } else {
        const onParentAbort = () => {
          this.abort(parent.reason ?? new Error(`Parent signal aborted for run "${this.runId}".`))
        }
        parent.addEventListener('abort', onParentAbort, { once: true })
        this.releaseParentSignal = () => {
          parent.removeEventListener('abort', onParentAbort)
        }
      }
    }
  }

  /** Live AbortSignal chained to `AppRuntime.killSwitch` and any optional parent signal. */
  get signal(): AbortSignal {
    return this.abortController.signal
  }

  get isAborted(): boolean {
    return this.abortController.signal.aborted
  }

  get isDisposed(): boolean {
    return this.disposed
  }

  get resourceCount(): number {
    return this.resources.size
  }

  get activeTaskCount(): number {
    return this.tasks.size
  }

  /** Abort this run immediately with an optional reason. */
  abort(reason?: unknown): void {
    if (!this.abortController.signal.aborted) {
      this.abortController.abort(reason ?? new Error(`Run "${this.runId}" aborted.`))
    }
  }

  /** Throw if this run has been aborted (preserving `KillSwitchTrippedError` when applicable). */
  throwIfAborted(): void {
    if (!this.abortController.signal.aborted) return
    const reason = this.abortController.signal.reason
    if (reason instanceof Error) throw reason
    throw new Error(typeof reason === 'string' ? reason : `Run "${this.runId}" aborted.`)
  }

  /**
   * Register a disposable resource (vault eviction, browser context close, OOB unsubscribe, timer).
   * Returns an unregister callback for resources that close cleanly before `drainAndDispose()`.
   */
  registerResource(name: string, disposeFn: () => void | Promise<void>): () => void {
    const label = name.trim() || 'resource'
    if (this.disposed || this.disposePromise) {
      try {
        const maybePromise = disposeFn()
        if (maybePromise && typeof (maybePromise as Promise<void>).catch === 'function') {
          void (maybePromise as Promise<void>).catch(() => undefined)
        }
      } catch {
        // Late registration on an already-disposed run is best-effort cleanup.
      }
      return () => {}
    }
    const id = this.nextResourceId++
    this.resources.set(id, { name: label, dispose: disposeFn })
    return () => {
      this.resources.delete(id)
    }
  }

  /** Convenience helper to register a Node timeout/interval timer for guaranteed cleanup. */
  registerTimer(
    name: string,
    timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>,
  ): () => void {
    return this.registerResource(name, () => {
      clearTimeout(timer as ReturnType<typeof setTimeout>)
      clearInterval(timer as ReturnType<typeof setInterval>)
    })
  }

  /**
   * Track an in-flight async task so `drainAndDispose()` awaits its settlement (up to `timeoutMs`).
   * Returns the original promise untouched without creating unhandled rejections.
   */
  trackTask<T>(label: string, promise: Promise<T>): Promise<T> {
    const id = this.nextTaskId++
    const settled = promise.then(
      () => undefined,
      () => undefined,
    )
    const entry: TrackedTask = { label: label.trim() || 'task', settled }
    this.tasks.set(id, entry)
    void settled.finally(() => {
      this.tasks.delete(id)
    })
    return promise
  }

  /**
   * Abort `signal`, drain tracked async tasks up to `timeoutMs`, execute ALL registered disposers
   * with `Promise.allSettled` (even when one or more throw), and remove this run from `AppRuntime`.
   */
  drainAndDispose(timeoutMs = this.defaultDrainTimeoutMs): Promise<RunDrainReport> {
    if (this.disposePromise) {
      return this.disposePromise.then(report => ({ ...report, alreadyDisposed: true }))
    }
    this.disposePromise = this.performDrainAndDispose(Math.max(0, timeoutMs))
    return this.disposePromise
  }

  /** Alias for `drainAndDispose()`. */
  dispose(timeoutMs?: number): Promise<RunDrainReport> {
    return this.drainAndDispose(timeoutMs)
  }

  private detachSignals(): void {
    const releaseKs = this.releaseKillSwitch
    this.releaseKillSwitch = null
    try { releaseKs?.() } catch { /* ignore */ }

    const releaseParent = this.releaseParentSignal
    this.releaseParentSignal = null
    try { releaseParent?.() } catch { /* ignore */ }
  }

  private async performDrainAndDispose(timeoutMs: number): Promise<RunDrainReport> {
    const startedAt = Date.now()
    this.abort(new Error(`RunContext "${this.runId}" disposed.`))
    this.detachSignals()

    const pendingTasks = [...this.tasks.values()]
    const tasksTotal = pendingTasks.length
    let tasksDrained = 0

    if (tasksTotal > 0) {
      const tracked = pendingTasks.map(task =>
        task.settled.then(() => {
          tasksDrained += 1
        }),
      )
      const allDone = Promise.allSettled(tracked).then(() => true)
      if (timeoutMs === 0) {
        await Promise.race([allDone, Promise.resolve(false)])
      } else {
        let timer: ReturnType<typeof setTimeout> | undefined
        const timedOut = new Promise<boolean>(resolve => {
          timer = setTimeout(() => resolve(false), timeoutMs)
          timer.unref?.()
        })
        try {
          await Promise.race([allDone, timedOut])
        } finally {
          if (timer !== undefined) clearTimeout(timer)
        }
      }
    }

    const tasksTimedOut = Math.max(0, tasksTotal - tasksDrained)

    // Snapshot and clear all disposers so each resource runs at most once.
    const snapshot = [...this.resources.values()]
    this.resources.clear()

    const results = await Promise.allSettled(
      snapshot.map(entry => Promise.resolve().then(() => entry.dispose())),
    )

    const resourceErrors: Array<{ name: string; error: string }> = []
    let resourcesDisposed = 0
    for (let i = 0; i < results.length; i += 1) {
      const outcome = results[i]!
      const entry = snapshot[i]!
      if (outcome.status === 'fulfilled') {
        resourcesDisposed += 1
      } else {
        const err = outcome.reason
        resourceErrors.push({
          name: entry.name,
          error: err instanceof Error ? err.message : String(err),
        })
      }
    }

    this.disposed = true
    try {
      this.onDispose?.(this.runId)
    } catch {
      // Registry removal must never mask disposal results.
    }

    return {
      runId: this.runId,
      aborted: this.abortController.signal.aborted,
      tasksTotal,
      tasksDrained,
      tasksTimedOut,
      resourcesTotal: snapshot.length,
      resourcesDisposed,
      resourceErrors,
      durationMs: Math.max(0, Date.now() - startedAt),
      alreadyDisposed: false,
    }
  }
}

export { KillSwitchTrippedError }
