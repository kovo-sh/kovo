/**
 * Bounded `worker_threads` pool for untrusted parsing and repo-ingestion tasks (H-33..H-39).
 *
 * Isolates host Node event loop and V8 heap from pathological target repositories, Compose files,
 * and regex/AST inputs:
 *   - Strict V8 `resourceLimits` (`maxOldGenerationSizeMb`, `maxYoungGenerationSizeMb`, `stackSizeMb`)
 *   - Hard wall-clock `timeoutMs` calling `worker.terminate()` on overrun
 *   - Bounded concurrency and bounded queue depth (fail-closed backpressure)
 *   - Idle workers are `unref()`'d so they never pin process shutdown
 */
import { randomUUID } from 'node:crypto'
import { Worker, type ResourceLimits } from 'node:worker_threads'
import {
  ComposeParseError,
  type ComposeParseOptions,
  type ParsedComposeDocument,
} from './compose-parse.ts'

export type UntrustedTaskKind =
  | 'parse_compose'
  | 'parse_compose_env'
  | 'parse_json'
  | 'extract_program_graph'
  | 'build_program_graph'

export interface WorkerTaskRequest {
  id: string
  kind: UntrustedTaskKind | string
  payload: unknown
}

export interface WorkerTaskResponse {
  id: string
  ok: boolean
  result?: unknown
  error?: {
    name: string
    message: string
    lineNumber?: number
    code?: string
  }
}

export const DEFAULT_WORKER_RESOURCE_LIMITS: Readonly<Required<Pick<
  ResourceLimits,
  'maxOldGenerationSizeMb' | 'maxYoungGenerationSizeMb' | 'stackSizeMb'
>>> = {
  maxOldGenerationSizeMb: 64,
  maxYoungGenerationSizeMb: 16,
  stackSizeMb: 4,
}

export const DEFAULT_UNTRUSTED_TASK_TIMEOUT_MS = 5_000
export const DEFAULT_UNTRUSTED_MAX_CONCURRENCY = 2
export const DEFAULT_UNTRUSTED_MAX_QUEUE_SIZE = 64

export class UntrustedComputeTimeoutError extends Error {
  readonly timeoutMs: number
  readonly taskKind: string

  constructor(taskKind: string, timeoutMs: number) {
    super(`Untrusted compute task "${taskKind}" exceeded wall-clock timeout of ${timeoutMs}ms and was terminated.`)
    this.name = 'UntrustedComputeTimeoutError'
    this.taskKind = taskKind
    this.timeoutMs = timeoutMs
  }
}

export class UntrustedComputeQueueFullError extends Error {
  readonly maxQueueSize: number

  constructor(maxQueueSize: number) {
    super(`Untrusted compute pool queue is full (limit: ${maxQueueSize}).`)
    this.name = 'UntrustedComputeQueueFullError'
    this.maxQueueSize = maxQueueSize
  }
}

export class UntrustedComputeAbortedError extends Error {
  constructor(message = 'Untrusted compute task was aborted.') {
    super(message)
    this.name = 'UntrustedComputeAbortedError'
  }
}

export class UntrustedComputeWorkerError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UntrustedComputeWorkerError'
  }
}

export interface UntrustedComputePoolOptions {
  /** Maximum concurrent worker threads (clamped 1..16). Defaults to 2. */
  maxConcurrency?: number
  /** Maximum pending tasks waiting for a worker slot (clamped 1..1024). Defaults to 64. */
  maxQueueSize?: number
  /** Default wall-clock timeout per task in ms (clamped 10..120000). Defaults to 5000ms. */
  defaultTimeoutMs?: number
  /** V8 resource limits enforced per worker isolate. */
  resourceLimits?: ResourceLimits
  /** Recycle a worker after this many completed tasks (defaults to 100). */
  maxTasksPerWorker?: number
  /** Optional custom worker script URL/path (defaults to `./parser-worker-entry.ts`). */
  workerEntry?: URL | string
}

export interface UntrustedTaskOptions {
  timeoutMs?: number
  signal?: AbortSignal
}

export interface ParseComposeInWorkerOptions extends ComposeParseOptions, UntrustedTaskOptions {}

interface PendingTask {
  id: string
  kind: string
  payload: unknown
  timeoutMs: number
  signal?: AbortSignal
  resolve: (value: unknown) => void
  reject: (reason: unknown) => void
  onAbortQueued?: () => void
}

interface PoolWorkerSlot {
  worker: Worker
  busy: boolean
  tasksCompleted: number
  retired: boolean
}

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.max(min, Math.min(max, Math.floor(value)))
}

function reconstructWorkerError(errInfo: NonNullable<WorkerTaskResponse['error']>): Error {
  if (errInfo.name === 'ComposeParseError') {
    // `ComposeParseError` constructor prefixes "Compose parse error ...: "; strip prefix if already formatted.
    const stripped = errInfo.message.replace(/^Compose parse error(?:\s*\(line \d+\))?:\s*/, '')
    return new ComposeParseError(stripped, errInfo.lineNumber)
  }
  const err = new Error(errInfo.message)
  err.name = errInfo.name || 'Error'
  return err
}

export class UntrustedComputePool {
  readonly maxConcurrency: number
  readonly maxQueueSize: number
  readonly defaultTimeoutMs: number
  readonly resourceLimits: ResourceLimits
  readonly maxTasksPerWorker: number
  private readonly workerEntry: URL | string
  private readonly slots = new Set<PoolWorkerSlot>()
  private readonly idle: PoolWorkerSlot[] = []
  private readonly queue: PendingTask[] = []
  private closed = false

  constructor(options: UntrustedComputePoolOptions = {}) {
    this.maxConcurrency = clampInt(options.maxConcurrency, DEFAULT_UNTRUSTED_MAX_CONCURRENCY, 1, 16)
    this.maxQueueSize = clampInt(options.maxQueueSize, DEFAULT_UNTRUSTED_MAX_QUEUE_SIZE, 1, 1024)
    this.defaultTimeoutMs = clampInt(options.defaultTimeoutMs, DEFAULT_UNTRUSTED_TASK_TIMEOUT_MS, 10, 120_000)
    this.maxTasksPerWorker = clampInt(options.maxTasksPerWorker, 100, 1, 10_000)
    this.workerEntry = options.workerEntry ?? new URL('./parser-worker-entry.ts', import.meta.url)
    this.resourceLimits = {
      maxOldGenerationSizeMb: clampInt(
        options.resourceLimits?.maxOldGenerationSizeMb,
        DEFAULT_WORKER_RESOURCE_LIMITS.maxOldGenerationSizeMb,
        8,
        1024,
      ),
      maxYoungGenerationSizeMb: clampInt(
        options.resourceLimits?.maxYoungGenerationSizeMb,
        DEFAULT_WORKER_RESOURCE_LIMITS.maxYoungGenerationSizeMb,
        2,
        256,
      ),
      stackSizeMb: clampInt(
        options.resourceLimits?.stackSizeMb,
        DEFAULT_WORKER_RESOURCE_LIMITS.stackSizeMb,
        1,
        32,
      ),
      ...(options.resourceLimits?.codeRangeSizeMb !== undefined
        ? { codeRangeSizeMb: clampInt(options.resourceLimits.codeRangeSizeMb, 16, 4, 256) }
        : {}),
    }
  }

  stats(): {
    activeCount: number
    idleCount: number
    queuedCount: number
    totalWorkers: number
    maxConcurrency: number
    maxQueueSize: number
    closed: boolean
  } {
    let activeCount = 0
    for (const slot of this.slots) {
      if (slot.busy) activeCount += 1
    }
    return {
      activeCount,
      idleCount: this.idle.length,
      queuedCount: this.queue.length,
      totalWorkers: this.slots.size,
      maxConcurrency: this.maxConcurrency,
      maxQueueSize: this.maxQueueSize,
      closed: this.closed,
    }
  }

  run<TResult = unknown>(
    kind: UntrustedTaskKind | string,
    payload: unknown,
    opts: UntrustedTaskOptions = {},
  ): Promise<TResult> {
    if (this.closed) {
      return Promise.reject(new UntrustedComputeWorkerError('UntrustedComputePool has been closed.'))
    }
    if (opts.signal?.aborted) {
      return Promise.reject(new UntrustedComputeAbortedError())
    }

    const timeoutMs = clampInt(opts.timeoutMs, this.defaultTimeoutMs, 10, 120_000)
    return new Promise<TResult>((resolve, reject) => {
      const task: PendingTask = {
        id: randomUUID(),
        kind,
        payload,
        timeoutMs,
        signal: opts.signal,
        resolve: value => resolve(value as TResult),
        reject,
      }

      const slot = this.acquireSlot()
      if (slot) {
        this.dispatchToSlot(slot, task)
        return
      }

      if (this.queue.length >= this.maxQueueSize) {
        reject(new UntrustedComputeQueueFullError(this.maxQueueSize))
        return
      }

      if (task.signal) {
        const onAbort = () => {
          const idx = this.queue.indexOf(task)
          if (idx >= 0) {
            this.queue.splice(idx, 1)
            reject(new UntrustedComputeAbortedError())
          }
        }
        task.onAbortQueued = onAbort
        task.signal.addEventListener('abort', onAbort, { once: true })
      }
      this.queue.push(task)
    })
  }

  private acquireSlot(): PoolWorkerSlot | null {
    while (this.idle.length > 0) {
      const candidate = this.idle.pop()!
      if (!candidate.retired && this.slots.has(candidate)) {
        candidate.busy = true
        return candidate
      }
    }
    if (this.slots.size >= this.maxConcurrency) {
      return null
    }
    const worker = new Worker(this.workerEntry, {
      resourceLimits: this.resourceLimits,
      execArgv: [],
    })
    const slot: PoolWorkerSlot = {
      worker,
      busy: true,
      tasksCompleted: 0,
      retired: false,
    }
    this.slots.add(slot)
    worker.once('exit', () => {
      slot.retired = true
      this.slots.delete(slot)
      const idleIdx = this.idle.indexOf(slot)
      if (idleIdx >= 0) this.idle.splice(idleIdx, 1)
    })
    return slot
  }

  private retireSlot(slot: PoolWorkerSlot): void {
    slot.retired = true
    slot.busy = false
    this.slots.delete(slot)
    const idleIdx = this.idle.indexOf(slot)
    if (idleIdx >= 0) this.idle.splice(idleIdx, 1)
    void slot.worker.terminate().catch(() => undefined)
  }

  private releaseOrRetireSlot(slot: PoolWorkerSlot): void {
    slot.tasksCompleted += 1
    if (
      this.closed
      || slot.retired
      || !this.slots.has(slot)
      || slot.tasksCompleted >= this.maxTasksPerWorker
    ) {
      this.retireSlot(slot)
      this.drainQueue()
      return
    }
    slot.busy = false
    slot.worker.unref()
    this.idle.push(slot)
    this.drainQueue()
  }

  private drainQueue(): void {
    if (this.closed) return
    while (this.queue.length > 0) {
      const slot = this.acquireSlot()
      if (!slot) return
      const nextTask = this.queue.shift()!
      if (nextTask.signal && nextTask.onAbortQueued) {
        nextTask.signal.removeEventListener('abort', nextTask.onAbortQueued)
      }
      if (nextTask.signal?.aborted) {
        slot.busy = false
        slot.worker.unref()
        this.idle.push(slot)
        nextTask.reject(new UntrustedComputeAbortedError())
        continue
      }
      this.dispatchToSlot(slot, nextTask)
    }
  }

  private dispatchToSlot(slot: PoolWorkerSlot, task: PendingTask): void {
    const { worker } = slot
    worker.ref()
    let settled = false

    const cleanupListeners = () => {
      clearTimeout(timer)
      worker.off('message', onMessage)
      worker.off('error', onError)
      worker.off('exit', onExit)
      if (task.signal) task.signal.removeEventListener('abort', onAbort)
    }

    const onMessage = (raw: unknown) => {
      const msg = raw as WorkerTaskResponse | null | undefined
      if (!msg || msg.id !== task.id || settled) return
      settled = true
      cleanupListeners()
      this.releaseOrRetireSlot(slot)
      if (msg.ok) {
        task.resolve(msg.result)
      } else {
        task.reject(reconstructWorkerError(msg.error ?? { name: 'Error', message: 'Worker task failed.' }))
      }
    }

    const onError = (err: Error) => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeWorkerError(err.message))
    }

    const onExit = (code: number) => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeWorkerError(`Worker thread exited unexpectedly with code ${code}.`))
    }

    const onAbort = () => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeAbortedError())
    }

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      cleanupListeners()
      // Hard wall-clock termination: destroy the isolate so infinite loops/ReDoS cannot linger.
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeTimeoutError(task.kind, task.timeoutMs))
    }, task.timeoutMs)
    timer.unref?.()

    worker.on('message', onMessage)
    worker.once('error', onError)
    worker.once('exit', onExit)
    if (task.signal) {
      if (task.signal.aborted) {
        onAbort()
        return
      }
      task.signal.addEventListener('abort', onAbort, { once: true })
    }

    const request: WorkerTaskRequest = {
      id: task.id,
      kind: task.kind,
      payload: task.payload,
    }
    try {
      worker.postMessage(request)
    } catch (err) {
      if (!settled) {
        settled = true
        cleanupListeners()
        this.retireSlot(slot)
        this.drainQueue()
        task.reject(new UntrustedComputeWorkerError(err instanceof Error ? err.message : String(err)))
      }
    }
  }

  async close(): Promise<void> {
    if (this.closed) return
    this.closed = true
    while (this.queue.length > 0) {
      const pending = this.queue.shift()!
      if (pending.signal && pending.onAbortQueued) {
        pending.signal.removeEventListener('abort', pending.onAbortQueued)
      }
      pending.reject(new UntrustedComputeWorkerError('UntrustedComputePool closed while task was queued.'))
    }
    this.idle.length = 0
    const workers = [...this.slots].map(slot => {
      slot.retired = true
      return slot.worker
    })
    this.slots.clear()
    await Promise.allSettled(workers.map(w => w.terminate()))
  }
}

let sharedPool: UntrustedComputePool | undefined

export function getSharedUntrustedComputePool(): UntrustedComputePool {
  if (!sharedPool) {
    sharedPool = new UntrustedComputePool()
  }
  return sharedPool
}

export function runUntrustedTask<TResult = unknown>(
  kind: UntrustedTaskKind | string,
  payload: unknown,
  opts?: UntrustedTaskOptions,
): Promise<TResult> {
  return getSharedUntrustedComputePool().run<TResult>(kind, payload, opts)
}

/**
 * Parse a Docker Compose YAML document inside an isolated, memory- and wall-clock-bounded
 * `worker_threads` pool (`H-38`). Never forwards `process.env` into the worker.
 */
export function parseComposeInWorker(
  yamlText: string,
  opts: ParseComposeInWorkerOptions = {},
): Promise<ParsedComposeDocument> {
  const safeEnv: Record<string, string | undefined> = {}
  if (opts.env && opts.env !== process.env) {
    for (const [key, val] of Object.entries(opts.env)) {
      if (val === undefined || typeof val === 'string') {
        safeEnv[key] = val
      }
    }
  }
  return runUntrustedTask<ParsedComposeDocument>(
    'parse_compose',
    {
      yamlText,
      options: {
        env: safeEnv,
        ...(opts.maxServices !== undefined ? { maxServices: opts.maxServices } : {}),
        ...(opts.maxBytes !== undefined ? { maxBytes: opts.maxBytes } : {}),
      },
    },
    {
      timeoutMs: opts.timeoutMs,
      signal: opts.signal,
    },
  )
}
