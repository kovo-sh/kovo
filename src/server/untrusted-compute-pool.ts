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
import { fork, type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'
import { isMainThread, parentPort, Worker, workerData, type ResourceLimits } from 'node:worker_threads'
import {
  ComposeParseError,
  type ComposeParseOptions,
  type ParsedComposeDocument,
} from './compose-parse.ts'
import type { SynthesizeInvariantsInput, SynthesizeInvariantsResult } from './invariant-synthesizer.ts'
import type { StaticExtractedRoute, StaticServerActionHint } from './phase0-recon.ts'
import type { MonorepoOriginInput, ProgramGraph, ServiceOriginMapping } from './program-graph.ts'
import { resolveRunSafetyBudgets } from './run-safety-budgets.ts'
import { compileSafeClaimRegex, MAX_CLAIM_REGEX_HAYSTACK } from './safe-regex.ts'
import type { StaticWorkspaceSnapshot } from './static-workspace-snapshot.ts'

export type UntrustedComputeIsolation = 'thread' | 'process'

export type UntrustedTaskKind =
  | 'parse_compose'
  | 'parse_compose_env'
  | 'parse_json'
  | 'parse_json_or_yaml'
  | 'js_harvest'
  | 'extract_html'
  | 'extract_program_graph'
  | 'build_program_graph'
  | 'search_repo'
  | 'synthesize_invariants'
  | 'map_services_to_origins'
  | 'extract_static_framework_routes'

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
export const DEFAULT_UNTRUSTED_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
export const MAX_UNTRUSTED_PAYLOAD_BYTES_CAP = 32 * 1024 * 1024

export class UntrustedComputePayloadTooLargeError extends Error {
  readonly actualBytes: number
  readonly maxBytes: number

  constructor(actualBytes: number, maxBytes: number) {
    super(`Untrusted compute payload exceeds maximum size (${actualBytes} > ${maxBytes} bytes).`)
    this.name = 'UntrustedComputePayloadTooLargeError'
    this.actualBytes = actualBytes
    this.maxBytes = maxBytes
  }
}

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
  /** Maximum concurrent worker isolates/processes (clamped 1..16). Defaults to 2. */
  maxConcurrency?: number
  /** Maximum pending tasks waiting for a worker slot (clamped 1..1024). Defaults to 64. */
  maxQueueSize?: number
  /** Default wall-clock timeout per task in ms (clamped 10..120000). Defaults to 5000ms. */
  defaultTimeoutMs?: number
  /** V8 resource limits enforced per worker isolate / child process. */
  resourceLimits?: ResourceLimits
  /** Recycle a worker after this many completed tasks (defaults to 100). */
  maxTasksPerWorker?: number
  /** Maximum serialized payload size accepted per task in bytes (defaults to 4 MiB). */
  maxPayloadBytes?: number
  /** Optional custom worker script URL/path (defaults to `./parser-worker-entry.ts`). */
  workerEntry?: URL | string
  /** Optional structured-clone `workerData` passed to worker_threads isolates. */
  workerData?: unknown
  /**
   * Isolation backend:
   * - `'thread'`: bounded `worker_threads` V8 isolate (default for pure JS tasks & custom thread entries)
   * - `'process'`: pooled disposable `child_process.fork` IPC worker (full crash/SIGSEGV isolation for native parsers)
   */
  isolation?: UntrustedComputeIsolation
}

export interface UntrustedTaskOptions {
  timeoutMs?: number
  signal?: AbortSignal
  maxPayloadBytes?: number
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
  isolation: UntrustedComputeIsolation
  worker?: Worker
  child?: ChildProcess
  busy: boolean
  tasksCompleted: number
  retired: boolean
}

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.max(min, Math.min(max, Math.floor(value)))
}

/**
 * Bounded iterative byte-size estimator for structured-clone payloads. Short-circuits as soon as
 * `limit` is exceeded so adversarial payloads cannot stall or OOM the host before worker dispatch.
 */
function estimateBoundedPayloadBytes(value: unknown, limit: number): number {
  const seen = new Set<object>()
  const stack: unknown[] = [value]
  let total = 0
  let visited = 0
  const MAX_NODES = 200_000

  while (stack.length > 0) {
    const item = stack.pop()
    visited += 1
    if (visited > MAX_NODES) return limit + 1
    if (item === null || item === undefined) {
      total += 4
    } else if (typeof item === 'string') {
      total += Buffer.byteLength(item, 'utf8')
    } else if (typeof item === 'number' || typeof item === 'boolean') {
      total += 8
    } else if (typeof item === 'bigint' || typeof item === 'symbol') {
      total += 16
    } else if (Buffer.isBuffer(item) || ArrayBuffer.isView(item)) {
      total += item.byteLength
    } else if (item instanceof ArrayBuffer) {
      total += item.byteLength
    } else if (typeof item === 'object') {
      if (seen.has(item)) continue
      seen.add(item)
      if (Array.isArray(item)) {
        total += 16
        for (let i = item.length - 1; i >= 0; i -= 1) stack.push(item[i])
      } else if (item instanceof Map) {
        total += 16
        for (const [k, v] of item.entries()) {
          stack.push(v)
          stack.push(k)
        }
      } else if (item instanceof Set) {
        total += 16
        for (const v of item.values()) stack.push(v)
      } else {
        total += 16
        for (const [k, v] of Object.entries(item)) {
          total += Buffer.byteLength(k, 'utf8')
          stack.push(v)
        }
      }
    }
    if (total > limit) return total
  }
  return total
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
  readonly maxPayloadBytes: number
  readonly resourceLimits: ResourceLimits
  readonly maxTasksPerWorker: number
  readonly isolation: UntrustedComputeIsolation
  private readonly workerEntry: URL | string
  private readonly workerData: unknown
  private readonly slots = new Set<PoolWorkerSlot>()
  private readonly idle: PoolWorkerSlot[] = []
  private readonly queue: PendingTask[] = []
  private closed = false

  constructor(options: UntrustedComputePoolOptions = {}) {
    this.maxConcurrency = clampInt(options.maxConcurrency, DEFAULT_UNTRUSTED_MAX_CONCURRENCY, 1, 16)
    this.maxQueueSize = clampInt(options.maxQueueSize, DEFAULT_UNTRUSTED_MAX_QUEUE_SIZE, 1, 1024)
    this.defaultTimeoutMs = clampInt(options.defaultTimeoutMs, DEFAULT_UNTRUSTED_TASK_TIMEOUT_MS, 10, 120_000)
    this.maxPayloadBytes = clampInt(
      options.maxPayloadBytes,
      DEFAULT_UNTRUSTED_MAX_PAYLOAD_BYTES,
      1024,
      MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
    )
    this.maxTasksPerWorker = clampInt(options.maxTasksPerWorker, 100, 1, 10_000)
    this.isolation = options.isolation === 'process' ? 'process' : 'thread'
    this.workerEntry = options.workerEntry ?? new URL('./parser-worker-entry.ts', import.meta.url)
    this.workerData = options.workerData
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

    const maxPayloadBytes = clampInt(
      opts.maxPayloadBytes,
      this.maxPayloadBytes,
      1024,
      MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
    )
    const payloadBytes = estimateBoundedPayloadBytes(payload, maxPayloadBytes)
    if (payloadBytes > maxPayloadBytes) {
      return Promise.reject(new UntrustedComputePayloadTooLargeError(payloadBytes, maxPayloadBytes))
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
        if (candidate.isolation === 'process' && (!candidate.child || !candidate.child.connected || candidate.child.killed)) {
          this.retireSlot(candidate)
          continue
        }
        candidate.busy = true
        return candidate
      }
    }
    if (this.slots.size >= this.maxConcurrency) {
      return null
    }
    if (this.isolation === 'process') {
      const entryPath = this.workerEntry instanceof URL ? fileURLToPath(this.workerEntry) : this.workerEntry
      const maxOldSpaceMb = Math.max(
        128,
        this.resourceLimits.maxOldGenerationSizeMb ?? DEFAULT_WORKER_RESOURCE_LIMITS.maxOldGenerationSizeMb,
      )
      const child = fork(entryPath, [], {
        execArgv: [`--max-old-space-size=${maxOldSpaceMb}`],
        // Strip host process.env so untrusted child processes never have access to host secrets.
        env: {},
        serialization: 'advanced',
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      })
      const slot: PoolWorkerSlot = {
        isolation: 'process',
        child,
        busy: true,
        tasksCompleted: 0,
        retired: false,
      }
      this.slots.add(slot)
      child.once('exit', () => {
        slot.retired = true
        this.slots.delete(slot)
        const idleIdx = this.idle.indexOf(slot)
        if (idleIdx >= 0) this.idle.splice(idleIdx, 1)
      })
      return slot
    }
    const worker = new Worker(this.workerEntry, {
      resourceLimits: this.resourceLimits,
      execArgv: [],
      // Strip host process.env so untrusted worker tasks never have access to host secrets.
      env: {},
      ...(this.workerData !== undefined ? { workerData: this.workerData } : {}),
    })
    const slot: PoolWorkerSlot = {
      isolation: 'thread',
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

  private unrefSlot(slot: PoolWorkerSlot): void {
    if (slot.worker) {
      slot.worker.unref()
    } else if (slot.child) {
      slot.child.unref()
      ;(slot.child as unknown as { channel?: { unref?: () => void } }).channel?.unref?.()
    }
  }

  private refSlot(slot: PoolWorkerSlot): void {
    if (slot.worker) {
      slot.worker.ref()
    } else if (slot.child) {
      slot.child.ref()
      ;(slot.child as unknown as { channel?: { ref?: () => void } }).channel?.ref?.()
    }
  }

  private terminateSlot(slot: PoolWorkerSlot): Promise<unknown> {
    if (slot.worker) {
      return slot.worker.terminate().catch(() => undefined)
    }
    if (slot.child) {
      const child = slot.child
      if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve()
      return new Promise<void>(resolve => {
        let done = false
        const finish = () => {
          if (done) return
          done = true
          clearTimeout(fallback)
          resolve()
        }
        child.once('exit', finish)
        const fallback = setTimeout(finish, 250)
        fallback.unref?.()
        try {
          child.kill('SIGKILL')
        } catch {
          finish()
        }
      })
    }
    return Promise.resolve()
  }

  private retireSlot(slot: PoolWorkerSlot): void {
    slot.retired = true
    slot.busy = false
    this.slots.delete(slot)
    const idleIdx = this.idle.indexOf(slot)
    if (idleIdx >= 0) this.idle.splice(idleIdx, 1)
    void this.terminateSlot(slot)
  }

  private releaseOrRetireSlot(slot: PoolWorkerSlot): void {
    slot.tasksCompleted += 1
    if (
      this.closed
      || slot.retired
      || !this.slots.has(slot)
      || slot.tasksCompleted >= this.maxTasksPerWorker
      || (slot.isolation === 'process' && (!slot.child || !slot.child.connected || slot.child.killed))
    ) {
      this.retireSlot(slot)
      this.drainQueue()
      return
    }
    slot.busy = false
    this.unrefSlot(slot)
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
        this.unrefSlot(slot)
        this.idle.push(slot)
        nextTask.reject(new UntrustedComputeAbortedError())
        continue
      }
      this.dispatchToSlot(slot, nextTask)
    }
  }

  private dispatchToSlot(slot: PoolWorkerSlot, task: PendingTask): void {
    this.refSlot(slot)
    let settled = false

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

    const onThreadExit = (code: number) => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeWorkerError(`Worker thread exited unexpectedly with code ${code}.`))
    }

    const onProcessExit = (code: number | null, sig: NodeJS.Signals | null) => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeWorkerError(`Worker process exited unexpectedly (code=${code ?? 'null'}, signal=${sig ?? 'none'}).`))
    }

    const onProcessDisconnect = () => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeWorkerError('Worker process IPC channel disconnected unexpectedly.'))
    }

    const onAbort = () => {
      if (settled) return
      settled = true
      cleanupListeners()
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeAbortedError())
    }

    const cleanupListeners = () => {
      clearTimeout(timer)
      if (slot.worker) {
        slot.worker.off('message', onMessage)
        slot.worker.off('error', onError)
        slot.worker.off('exit', onThreadExit)
      }
      if (slot.child) {
        slot.child.off('message', onMessage)
        slot.child.off('error', onError)
        slot.child.off('exit', onProcessExit)
        slot.child.off('disconnect', onProcessDisconnect)
      }
      if (task.signal) task.signal.removeEventListener('abort', onAbort)
    }

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      cleanupListeners()
      // Hard wall-clock termination: destroy the isolate/process so infinite loops/ReDoS cannot linger.
      this.retireSlot(slot)
      this.drainQueue()
      task.reject(new UntrustedComputeTimeoutError(task.kind, task.timeoutMs))
    }, task.timeoutMs)
    timer.unref?.()

    if (slot.worker) {
      slot.worker.on('message', onMessage)
      slot.worker.once('error', onError)
      slot.worker.once('exit', onThreadExit)
    } else if (slot.child) {
      slot.child.on('message', onMessage)
      slot.child.once('error', onError)
      slot.child.once('exit', onProcessExit)
      slot.child.once('disconnect', onProcessDisconnect)
    }
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
      if (slot.worker) {
        slot.worker.postMessage(request)
      } else if (slot.child) {
        slot.child.send(request, err => {
          if (err && !settled) {
            settled = true
            cleanupListeners()
            this.retireSlot(slot)
            this.drainQueue()
            task.reject(new UntrustedComputeWorkerError(err.message))
          }
        })
      }
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
    const activeSlots = [...this.slots]
    for (const slot of activeSlots) slot.retired = true
    this.slots.clear()
    await Promise.allSettled(activeSlots.map(slot => this.terminateSlot(slot)))
  }
}

let sharedPool: UntrustedComputePool | undefined
let sharedProcessPool: UntrustedComputePool | undefined
let sharedHostComputePool: UntrustedComputePool | undefined

const HOST_COMPUTE_TASK_KINDS = new Set<string>([
  'search_repo',
  'synthesize_invariants',
  'map_services_to_origins',
  'extract_static_framework_routes',
])

const HOST_COMPUTE_WORKER_ROLE = 'kovo-host-compute'
const DEFAULT_POST_GRAPH_TASK_TIMEOUT_MS = 10_000

export function getSharedUntrustedComputePool(): UntrustedComputePool {
  if (!sharedPool || sharedPool.stats().closed) {
    sharedPool = new UntrustedComputePool({ isolation: 'thread' })
  }
  return sharedPool
}

/**
 * Shared thread pool dedicated to off-host repo search & post-ProgramGraph repo-content scanners
 * (`R4-H-15`, `R4-H-16`). Runs isolated worker threads backed by this module with hard wall-clock
 * termination on timeout.
 */
function getSharedHostComputePool(): UntrustedComputePool {
  if (!sharedHostComputePool || sharedHostComputePool.stats().closed) {
    sharedHostComputePool = new UntrustedComputePool({
      isolation: 'thread',
      maxConcurrency: 4,
      defaultTimeoutMs: DEFAULT_POST_GRAPH_TASK_TIMEOUT_MS,
      maxPayloadBytes: MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
      resourceLimits: {
        maxOldGenerationSizeMb: 128,
        maxYoungGenerationSizeMb: 32,
        stackSizeMb: 4,
      },
      workerEntry: new URL('./untrusted-compute-pool.ts', import.meta.url),
      workerData: { kovoWorkerRole: HOST_COMPUTE_WORKER_ROLE },
    })
  }
  return sharedHostComputePool
}

/**
 * Shared pooled disposable child-process pool (`child_process.fork` + IPC) used for tasks that may
 * invoke native parsers (e.g. `@swc/core` in `js_harvest`) so even a native SIGSEGV/OOM is isolated
 * from the Kovo host process (`R2-H-23`).
 */
export function getSharedUntrustedProcessPool(): UntrustedComputePool {
  if (!sharedProcessPool || sharedProcessPool.stats().closed) {
    sharedProcessPool = new UntrustedComputePool({ isolation: 'process' })
  }
  return sharedProcessPool
}

export async function closeSharedUntrustedProcessPool(): Promise<void> {
  const pool = sharedProcessPool
  sharedProcessPool = undefined
  if (pool) {
    await pool.close()
  }
}

export async function closeSharedUntrustedComputePool(): Promise<void> {
  const threadPool = sharedPool
  const procPool = sharedProcessPool
  const hostComputePool = sharedHostComputePool
  sharedPool = undefined
  sharedProcessPool = undefined
  sharedHostComputePool = undefined
  await Promise.allSettled([
    ...(threadPool ? [threadPool.close()] : []),
    ...(procPool ? [procPool.close()] : []),
    ...(hostComputePool ? [hostComputePool.close()] : []),
  ])
}

export function runUntrustedTask<TResult = unknown>(
  kind: UntrustedTaskKind | string,
  payload: unknown,
  opts?: UntrustedTaskOptions,
): Promise<TResult> {
  if (kind === 'js_harvest') {
    return getSharedUntrustedProcessPool().run<TResult>(kind, payload, opts)
  }
  if (HOST_COMPUTE_TASK_KINDS.has(kind)) {
    return getSharedHostComputePool().run<TResult>(kind, payload, opts)
  }
  return getSharedUntrustedComputePool().run<TResult>(kind, payload, opts)
}

// ===========================================================================
// Pure bounded parsers shared by host synchronous callers & worker isolates
// ===========================================================================

const POOL_STATIC_ASSET_RE = /\.(?:css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|mp3|zip|tar|gz|pdf)(?:\?|$)/i

export function sanitizeSameOriginPath(raw: string, baseOrigin: string): string | null {
  const trimmed = raw.trim()
  if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('mailto:') || trimmed.startsWith('data:') || trimmed.startsWith('#')) {
    return null
  }
  try {
    const expectedOrigin = new URL(baseOrigin).origin
    const parsed = new URL(trimmed, baseOrigin)
    if (parsed.origin !== expectedOrigin) return null
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    if (/[\r\n\0\\]/.test(parsed.pathname + parsed.search)) return null
    return parsed.pathname + parsed.search
  } catch {
    return null
  }
}

export interface ExtractedHtmlSurface {
  links: string[]
  scripts: string[]
  forms: Array<{ action: string; method: string; inputs: string[]; enctype: string }>
  inputs: Array<{ name: string; id: string | null; type: string | null }>
}

const MAX_HTML_SCAN_BYTES = 512 * 1024

export function extractHtmlLinksAndScripts(html: string, origin: string): ExtractedHtmlSurface {
  const boundedHtml = html.length > MAX_HTML_SCAN_BYTES ? html.slice(0, MAX_HTML_SCAN_BYTES) : html
  const links = new Set<string>()
  const scripts = new Set<string>()
  const forms: Array<{ action: string; method: string; inputs: string[]; enctype: string }> = []
  const inputs: Array<{ name: string; id: string | null; type: string | null }> = []
  const seenInputs = new Set<string>()

  for (const m of boundedHtml.matchAll(/<a\b[^>]{0,1024}\bhref[ \t]{0,8}=[ \t]{0,8}["']([^"'\r\n]{1,1024})["']/gi)) {
    const clean = sanitizeSameOriginPath(m[1] ?? '', origin)
    if (clean && !POOL_STATIC_ASSET_RE.test(clean)) links.add(clean)
  }
  for (const m of boundedHtml.matchAll(/<script\b[^>]{0,1024}\bsrc[ \t]{0,8}=[ \t]{0,8}["']([^"'\r\n]{1,1024})["']/gi)) {
    const clean = sanitizeSameOriginPath(m[1] ?? '', origin)
    if (clean) scripts.add(clean)
  }
  for (const m of boundedHtml.matchAll(/<form\b([^>]{0,1024})>([\s\S]{0,65536}?)<\/form>/gi)) {
    const attrs = m[1] ?? ''
    const inner = m[2] ?? ''
    const actionMatch = /\baction[ \t]{0,8}=[ \t]{0,8}["']([^"'\r\n]{1,1024})["']/i.exec(attrs)
    const methodMatch = /\bmethod[ \t]{0,8}=[ \t]{0,8}["']([a-zA-Z]{1,16})["']/i.exec(attrs)
    const enctypeMatch = /\benctype[ \t]{0,8}=[ \t]{0,8}["']([^"'\r\n]{1,128})["']/i.exec(attrs)
    const action = sanitizeSameOriginPath(actionMatch?.[1] ?? '/', origin) ?? '/'
    const method = (methodMatch?.[1] ?? 'GET').toUpperCase()
    const inputsInForm: string[] = []
    for (const im of inner.matchAll(/<(?:input|select|textarea)\b[^>]{0,512}\bname[ \t]{0,8}=[ \t]{0,8}["']([^"'\r\n]{1,128})["']/gi)) {
      if (im[1]) inputsInForm.push(im[1])
    }
    forms.push({ action, method, inputs: inputsInForm, enctype: (enctypeMatch?.[1] ?? 'application/x-www-form-urlencoded').toLowerCase() })
  }
  for (const tm of boundedHtml.matchAll(/<(?:input|select|textarea)\b([^>]{0,512})>/gi)) {
    const attrs = tm[1] ?? ''
    const nameMatch = /\bname[ \t]{0,8}=[ \t]{0,8}(?:"([^"\r\n]{0,128})"|'([^'\r\n]{0,128})'|([^\s>]{1,128}))/i.exec(attrs)
    const idMatch = /\bid[ \t]{0,8}=[ \t]{0,8}(?:"([^"\r\n]{0,128})"|'([^'\r\n]{0,128})'|([^\s>]{1,128}))/i.exec(attrs)
    const typeMatch = /\btype[ \t]{0,8}=[ \t]{0,8}(?:"([^"\r\n]{0,64})"|'([^'\r\n]{0,64})'|([^\s>]{1,64}))/i.exec(attrs)
    const name = (nameMatch?.[1] ?? nameMatch?.[2] ?? nameMatch?.[3] ?? idMatch?.[1] ?? idMatch?.[2] ?? idMatch?.[3] ?? '').trim()
    if (!name) continue
    const id = (idMatch?.[1] ?? idMatch?.[2] ?? idMatch?.[3] ?? null)
    const type = (typeMatch?.[1] ?? typeMatch?.[2] ?? typeMatch?.[3] ?? null)
    const key = `${name}|${id ?? ''}`
    if (seenInputs.has(key)) continue
    seenInputs.add(key)
    inputs.push({ name, id: id ? id.trim() : null, type: type ? type.toLowerCase() : null })
  }
  return { links: [...links], scripts: [...scripts], forms, inputs }
}

function stripYamlComment(line: string): string {
  let quote: string | null = null
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (quote) {
      if (ch === quote && line[i - 1] !== '\\') quote = null
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; continue }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1] ?? ''))) return line.slice(0, i)
  }
  return line
}

function splitYamlKeyValue(text: string): { key: string; rest: string } | null {
  let quote: string | null = null
  let depth = 0
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (ch === quote && text[i - 1] !== '\\') quote = null
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; continue }
    if (ch === '{' || ch === '[') depth += 1
    else if (ch === '}' || ch === ']') depth -= 1
    else if (ch === ':' && depth === 0 && (i + 1 >= text.length || /\s/.test(text[i + 1] ?? ''))) {
      const rawKey = text.slice(0, i).trim()
      const key = rawKey.replace(/^['"]|['"]$/g, '')
      if (!key) return null
      return { key, rest: text.slice(i + 1).trim() }
    }
  }
  return null
}

function parseYamlScalar(raw: string): unknown {
  const text = raw.trim()
  if (!text) return null
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
    return text.slice(1, -1)
  }
  if (/^(?:true|false)$/i.test(text)) return text.toLowerCase() === 'true'
  if (/^(?:null|~)$/i.test(text)) return null
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text)
  if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
    try { return JSON.parse(text) } catch { return text }
  }
  return text
}

/** Bounded YAML parser for mapping/sequence documents (OpenAPI, route maps). Not a full YAML engine. */
export function parseYamlLikeDocument(text: string): unknown {
  interface Line { indent: number; text: string; raw: string }
  const lines: Line[] = []
  for (const rawLine of text.replace(/\r\n?/g, '\n').split('\n')) {
    if (lines.length > 6000) break
    const stripped = stripYamlComment(rawLine)
    const body = stripped.trimEnd()
    const trimmed = body.trim()
    if (!trimmed || trimmed === '---' || trimmed === '...') continue
    const indent = body.length - body.trimStart().length
    lines.push({ indent, text: trimmed, raw: body })
  }
  if (lines.length === 0) return null
  let index = 0
  const blockScalar = (indent: number): string => {
    const parts: string[] = []
    while (index < lines.length && lines[index]!.indent > indent) {
      parts.push(lines[index]!.text)
      index += 1
    }
    return parts.join('\n')
  }
  const parseNode = (indent: number): unknown => {
    const first = lines[index]
    if (!first) return null
    return first.text === '-' || first.text.startsWith('- ') ? parseSequence(indent) : parseMapping(indent)
  }
  const parseSequence = (indent: number): unknown[] => {
    const out: unknown[] = []
    while (index < lines.length) {
      const line = lines[index]!
      if (line.indent < indent) break
      if (line.indent > indent) { index += 1; continue }
      if (!(line.text === '-' || line.text.startsWith('- '))) break
      const afterDash = line.text.slice(1)
      if (!afterDash.trim()) {
        index += 1
        const next = lines[index]
        out.push(next && next.indent > indent ? parseNode(next.indent) : null)
        continue
      }
      if (splitYamlKeyValue(afterDash.trim())) {
        const dashes = /^(\s*)-(\s*)/.exec(line.raw)
        const childIndent = (dashes?.[1]?.length ?? indent) + 1 + (dashes?.[2]?.length ?? 1)
        lines[index] = { indent: childIndent, text: afterDash.trim(), raw: ' '.repeat(childIndent) + afterDash.trim() }
        out.push(parseMapping(childIndent))
        continue
      }
      out.push(parseYamlScalar(afterDash))
      index += 1
    }
    return out
  }
  const parseMapping = (indent: number): Record<string, unknown> => {
    const out: Record<string, unknown> = {}
    while (index < lines.length) {
      const line = lines[index]!
      if (line.indent < indent) break
      if (line.indent > indent) { index += 1; continue }
      if (line.text === '-' || line.text.startsWith('- ')) break
      const kv = splitYamlKeyValue(line.text)
      if (!kv) { index += 1; continue }
      index += 1
      if (kv.rest) {
        if (/^[|>][+-]?$/.test(kv.rest)) { out[kv.key] = blockScalar(indent); continue }
        out[kv.key] = parseYamlScalar(kv.rest)
        continue
      }
      const next = lines[index]
      out[kv.key] = next && next.indent > indent ? parseNode(next.indent) : null
    }
    return out
  }
  return parseNode(lines[0]!.indent)
}

/** Parse a JSON or YAML document body into an object (null when neither parses). */
export function parseJsonOrYaml(rawBody: string): unknown {
  const text = rawBody.replace(/^\uFEFF/, '').trim()
  if (!text) return null
  if (text.startsWith('{') || text.startsWith('[')) {
    try { return JSON.parse(text) as unknown } catch { /* fall through to YAML */ }
  }
  const parsed = parseYamlLikeDocument(text)
  if (parsed !== null && typeof parsed === 'object') return parsed
  try { return JSON.parse(text) as unknown } catch { return null }
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
      ...(opts.maxBytes !== undefined ? { maxPayloadBytes: opts.maxBytes + 4096 } : {}),
    },
  )
}

/** Parse untrusted JSON or YAML-like text (OpenAPI / route-map) inside the bounded worker pool. */
export function parseJsonOrYamlInWorker(
  rawBody: string,
  opts: UntrustedTaskOptions & { maxBytes?: number } = {},
): Promise<unknown> {
  return runUntrustedTask<unknown>(
    'parse_json_or_yaml',
    {
      text: rawBody,
      ...(opts.maxBytes !== undefined ? { maxBytes: opts.maxBytes } : {}),
    },
    {
      timeoutMs: opts.timeoutMs,
      signal: opts.signal,
      maxPayloadBytes: opts.maxPayloadBytes ?? DEFAULT_UNTRUSTED_MAX_PAYLOAD_BYTES,
    },
  )
}

/** Run `jsHarvest` on untrusted JS bundle / source-map content inside the bounded worker pool. */
export function jsHarvestInWorker(
  content: string,
  sourceName = '',
  options?: Record<string, unknown>,
  taskOpts: UntrustedTaskOptions = {},
): Promise<Record<string, unknown>> {
  return runUntrustedTask<Record<string, unknown>>(
    'js_harvest',
    {
      content,
      sourceName,
      ...(options ? { options } : {}),
    },
    {
      timeoutMs: taskOpts.timeoutMs,
      signal: taskOpts.signal,
      maxPayloadBytes: taskOpts.maxPayloadBytes ?? DEFAULT_UNTRUSTED_MAX_PAYLOAD_BYTES,
    },
  )
}

/** Extract links, scripts, forms, and inputs from untrusted HTML inside the bounded worker pool. */
export function extractHtmlLinksAndScriptsInWorker(
  html: string,
  origin: string,
  opts: UntrustedTaskOptions & { maxBytes?: number } = {},
): Promise<ExtractedHtmlSurface> {
  return runUntrustedTask<ExtractedHtmlSurface>(
    'extract_html',
    {
      html,
      origin,
      ...(opts.maxBytes !== undefined ? { maxBytes: opts.maxBytes } : {}),
    },
    {
      timeoutMs: opts.timeoutMs,
      signal: opts.signal,
      maxPayloadBytes: opts.maxPayloadBytes ?? DEFAULT_UNTRUSTED_MAX_PAYLOAD_BYTES,
    },
  )
}

/** Build a cross-framework `ProgramGraph` from untrusted repository source files inside the bounded worker pool. */
export function extractProgramGraphInWorker(
  input: {
    files?: ReadonlyArray<{ path: string; content: string }>
    repo?: string
    maxFileBytes?: number
  },
  opts: UntrustedTaskOptions = {},
): Promise<ProgramGraph> {
  return runUntrustedTask<ProgramGraph>(
    'extract_program_graph',
    input,
    {
      timeoutMs: opts.timeoutMs,
      signal: opts.signal,
      maxPayloadBytes: opts.maxPayloadBytes ?? MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
    },
  )
}

// ===========================================================================
// R4-H-15 & R4-H-16: Off-host repo search & post-ProgramGraph pipeline workers
// ===========================================================================

export type SearchRepoTruncationReason = 'max_matches' | 'max_files' | 'max_bytes' | 'deadline_exceeded'

export interface SearchRepoWorkerRequest {
  /** Canonical jailed target file or directory path resolved by the host. */
  realTarget: string
  /** Canonical POSIX path relative to repos root ('' when searching the root). */
  relPosix: string
  query: string
  regex: boolean
  caseSensitive: boolean
  maxMatches: number
  maxFiles?: number
  maxFileBytes?: number
  maxBytes?: number
  maxLineChars?: number
  deadlineMs?: number
}

export interface SearchRepoWorkerResult {
  query: string
  mode: 'literal' | 'regex'
  pathPrefix: string
  filesScanned: number
  matchCount: number
  truncated: boolean
  truncationReason?: SearchRepoTruncationReason
  timedOut?: boolean
  deadlineMs: number
  maxBytes: number
  bytesScanned: number
  elapsedMs: number
  matches: Array<{ path: string; line: number; text: string }>
}

export interface StaticFrameworkRoutesWorkerResult {
  routes: StaticExtractedRoute[]
  frameworks: string[]
  serverActions: StaticServerActionHint[]
}

const WORKER_REPO_SKIP_DIRS = new Set([
  '.git', 'node_modules', '.ssh', '.gnupg', '.aws', '.kube', '.docker', '.azure', '.gcloud', '.terraform',
])
const WORKER_REPO_SENSITIVE_FILES = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.netrc', '.npmrc', '.pypirc', '.pgpass', '.my.cnf', '.git-credentials',
])
const WORKER_REPO_SENSITIVE_EXT_RE = /\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk)$/i
const WORKER_REPO_SAFE_ENV_TEMPLATE_RE = /^\.env\.(?:example|sample|template|dist|defaults?)$/i
const WORKER_REPO_SOURCE_EXT_RE = /\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|rb|php|cs|c|cpp|h|hpp|swift|scala)$/i

const DEFAULT_WORKER_SEARCH_FILES = 4_000
const DEFAULT_WORKER_SEARCH_FILE_BYTES = 512 * 1024
const DEFAULT_WORKER_SEARCH_LINE_CHARS = 240

function isSensitiveWorkerRepoSegment(segment: string, isDir: boolean, parentSegments: readonly string[]): boolean {
  const lower = segment.toLowerCase()
  if (WORKER_REPO_SKIP_DIRS.has(lower)) return true
  if (isDir) return false
  if (WORKER_REPO_SENSITIVE_FILES.has(lower)) return true
  if (WORKER_REPO_SENSITIVE_EXT_RE.test(lower)) return true
  if (lower === '.env' || (lower.startsWith('.env.') && !WORKER_REPO_SAFE_ENV_TEMPLATE_RE.test(lower))) return true
  if (parentSegments.some(p => p.toLowerCase() === 'credentials') && !WORKER_REPO_SOURCE_EXT_RE.test(lower)) return true
  return false
}

function isWorkerBinaryBuffer(buf: Buffer): boolean {
  const probeLen = Math.min(buf.length, 8_192)
  for (let i = 0; i < probeLen; i += 1) {
    if (buf[i] === 0) return true
  }
  return false
}

/**
 * Single authoritative bounded repository scanner shared by the off-host `search_repo` worker
 * (`R4-H-15`) and sync test-compat entrypoints. Enforces `searchRepoMaxBytes`, `searchRepoDeadlineMs`,
 * skip-list hygiene, binary filtering, and `compileSafeClaimRegex`.
 */
export function executeSearchRepoScan(request: SearchRepoWorkerRequest): SearchRepoWorkerResult {
  const startedAt = performance.now()
  const query = typeof request.query === 'string' ? request.query : ''
  if (!query || query.length > 256) {
    throw new Error('search_repo query must be a non-empty string up to 256 characters.')
  }
  const budgets = resolveRunSafetyBudgets({
    overrides: {
      ...(request.deadlineMs !== undefined ? { searchRepoDeadlineMs: request.deadlineMs } : {}),
      ...(request.maxBytes !== undefined ? { searchRepoMaxBytes: request.maxBytes } : {}),
    },
  })
  const deadlineMs = budgets.searchRepoDeadlineMs
  const maxBytes = budgets.searchRepoMaxBytes
  const maxMatches = clampInt(request.maxMatches, 50, 1, 200)
  const maxFiles = clampInt(request.maxFiles, DEFAULT_WORKER_SEARCH_FILES, 1, 16_000)
  const maxFileBytes = clampInt(request.maxFileBytes, DEFAULT_WORKER_SEARCH_FILE_BYTES, 1024, 4 * 1024 * 1024)
  const maxLineChars = clampInt(request.maxLineChars, DEFAULT_WORKER_SEARCH_LINE_CHARS, 32, 1024)
  const useRegex = request.regex === true
  const caseSensitive = request.caseSensitive === true

  let regexMatcher: RegExp | null = null
  const literalNeedle = caseSensitive ? query : query.toLowerCase()
  if (useRegex) {
    // Compile without `i`/`u` flags so V8's linear-time fallback engine engages (R3-H-11).
    const compiled = compileSafeClaimRegex(query, { flags: '', maxLength: 256 })
    if (!compiled.ok) {
      throw new Error(`Unsafe or invalid search_repo regex rejected: ${compiled.reason} Use literal search (regex: false) or a simpler linear pattern.`)
    }
    regexMatcher = compiled.regex
  }

  const startStat = lstatSync(request.realTarget)
  const matches: Array<{ path: string; line: number; text: string }> = []
  let filesScanned = 0
  let totalBytesScanned = 0
  let truncated = false
  let truncationReason: SearchRepoTruncationReason | undefined
  let timedOut = false

  const checkDeadline = (): boolean => {
    if (performance.now() - startedAt >= deadlineMs) {
      truncated = true
      timedOut = true
      truncationReason = 'deadline_exceeded'
      return true
    }
    return false
  }

  const scanFile = (absPath: string, relPosix: string): void => {
    if (truncated) return
    if (checkDeadline()) return
    if (matches.length >= maxMatches) {
      truncated = true
      truncationReason = 'max_matches'
      return
    }
    if (filesScanned >= maxFiles) {
      truncated = true
      truncationReason = 'max_files'
      return
    }
    if (totalBytesScanned >= maxBytes) {
      truncated = true
      truncationReason = 'max_bytes'
      return
    }
    let st
    try {
      st = lstatSync(absPath)
    } catch {
      return
    }
    if (!st.isFile() || st.isSymbolicLink() || st.size === 0 || st.size > maxFileBytes) return
    if (totalBytesScanned > 0 && totalBytesScanned + st.size > maxBytes) {
      truncated = true
      truncationReason = 'max_bytes'
      return
    }
    let buf: Buffer
    try {
      buf = readFileSync(absPath)
    } catch {
      return
    }
    if (isWorkerBinaryBuffer(buf)) return
    filesScanned += 1
    totalBytesScanned += buf.length
    const lines = buf.toString('utf8').split(/\r?\n/)
    const checkMask = regexMatcher ? 3 : 31
    for (let i = 0; i < lines.length; i += 1) {
      if ((i & checkMask) === 0 && checkDeadline()) return
      const line = lines[i]!
      let matched = false
      if (regexMatcher) {
        const haystack = line.length > MAX_CLAIM_REGEX_HAYSTACK ? line.slice(0, MAX_CLAIM_REGEX_HAYSTACK) : line
        matched = regexMatcher.test(haystack)
      } else {
        matched = (caseSensitive ? line : line.toLowerCase()).includes(literalNeedle)
      }
      if (!matched) continue
      if (matches.length >= maxMatches) {
        truncated = true
        truncationReason = 'max_matches'
        return
      }
      matches.push({
        path: `/repos/${relPosix}`,
        line: i + 1,
        text: line.trimEnd().slice(0, maxLineChars),
      })
    }
  }

  if (startStat.isFile()) {
    scanFile(request.realTarget, request.relPosix)
  } else if (startStat.isDirectory()) {
    const stack: Array<{ absDir: string; relPrefix: string; parents: string[] }> = [{
      absDir: request.realTarget,
      relPrefix: request.relPosix,
      parents: request.relPosix ? request.relPosix.split('/') : [],
    }]
    while (stack.length > 0 && !truncated) {
      if (checkDeadline()) break
      const cur = stack.pop()!
      let entries
      try {
        entries = readdirSync(cur.absDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))
      } catch {
        continue
      }
      const subdirs: Array<{ absDir: string; relPrefix: string; parents: string[] }> = []
      for (const entry of entries) {
        if (truncated) break
        if (entry.isSymbolicLink()) continue
        const isDir = entry.isDirectory()
        const isFile = entry.isFile()
        if (!isDir && !isFile) continue
        if (isSensitiveWorkerRepoSegment(entry.name, isDir, cur.parents)) continue
        const childAbs = join(cur.absDir, entry.name)
        const childRel = cur.relPrefix ? `${cur.relPrefix}/${entry.name}` : entry.name
        if (isDir) {
          subdirs.push({ absDir: childAbs, relPrefix: childRel, parents: [...cur.parents, entry.name] })
        } else {
          scanFile(childAbs, childRel)
          if (truncated) break
          if (matches.length >= maxMatches) {
            truncated = true
            truncationReason = 'max_matches'
            break
          }
          if (filesScanned >= maxFiles) {
            truncated = true
            truncationReason = 'max_files'
            break
          }
          if (totalBytesScanned >= maxBytes) {
            truncated = true
            truncationReason = 'max_bytes'
            break
          }
        }
      }
      for (let i = subdirs.length - 1; i >= 0; i -= 1) {
        stack.push(subdirs[i]!)
      }
    }
  }

  return {
    query,
    mode: useRegex ? 'regex' : 'literal',
    pathPrefix: request.relPosix ? `/repos/${request.relPosix}` : '/repos',
    filesScanned,
    matchCount: matches.length,
    truncated,
    ...(truncationReason ? { truncationReason } : {}),
    ...(timedOut ? { timedOut: true } : {}),
    deadlineMs,
    maxBytes,
    bytesScanned: totalBytesScanned,
    elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
    matches,
  }
}

/**
 * Run host-jailed `search_repo` inside an isolated `UntrustedComputePool` worker thread (`R4-H-15`)
 * with a hard wall-clock deadline (`searchRepoDeadlineMs`) enforced by terminating the worker
 * thread on overrun. Never blocks the host event loop.
 */
export async function searchRepoInWorker(
  request: SearchRepoWorkerRequest,
  opts: UntrustedTaskOptions = {},
): Promise<SearchRepoWorkerResult> {
  const startedAt = performance.now()
  const budgets = resolveRunSafetyBudgets({
    overrides: {
      ...(request.deadlineMs !== undefined ? { searchRepoDeadlineMs: request.deadlineMs } : {}),
      ...(request.maxBytes !== undefined ? { searchRepoMaxBytes: request.maxBytes } : {}),
    },
  })
  const deadlineMs = clampInt(opts.timeoutMs ?? request.deadlineMs, budgets.searchRepoDeadlineMs, 10, 15_000)
  const maxBytes = budgets.searchRepoMaxBytes
  try {
    return await runUntrustedTask<SearchRepoWorkerResult>(
      'search_repo',
      {
        ...request,
        deadlineMs,
        maxBytes,
      },
      {
        timeoutMs: deadlineMs,
        signal: opts.signal,
        maxPayloadBytes: opts.maxPayloadBytes ?? DEFAULT_UNTRUSTED_MAX_PAYLOAD_BYTES,
      },
    )
  } catch (err) {
    if (err instanceof UntrustedComputeTimeoutError) {
      return {
        query: request.query,
        mode: request.regex ? 'regex' : 'literal',
        pathPrefix: request.relPosix ? `/repos/${request.relPosix}` : '/repos',
        filesScanned: 0,
        matchCount: 0,
        truncated: true,
        truncationReason: 'deadline_exceeded',
        timedOut: true,
        deadlineMs,
        maxBytes,
        bytesScanned: 0,
        elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
        matches: [],
      }
    }
    throw err
  }
}

/**
 * Run `synthesizeInvariants` off the host event loop inside `UntrustedComputePool` with a hard
 * wall-clock deadline (`R4-H-16`). Authoritative worker API for `exec-recon-planner.ts` (WS-10).
 */
export function synthesizeInvariantsInWorker(
  input: SynthesizeInvariantsInput,
  opts: UntrustedTaskOptions = {},
): Promise<SynthesizeInvariantsResult> {
  return runUntrustedTask<SynthesizeInvariantsResult>(
    'synthesize_invariants',
    input,
    {
      timeoutMs: opts.timeoutMs ?? DEFAULT_POST_GRAPH_TASK_TIMEOUT_MS,
      signal: opts.signal,
      maxPayloadBytes: opts.maxPayloadBytes ?? MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
    },
  )
}

/**
 * Run `mapServicesToOrigins` (compose, k8s ingress, and Dockerfile `EXPOSE` scanning) off the
 * host event loop inside `UntrustedComputePool` with a hard wall-clock deadline (`R4-H-16`).
 */
export function mapServicesToOriginsInWorker(
  input: MonorepoOriginInput,
  opts: UntrustedTaskOptions = {},
): Promise<ServiceOriginMapping[]> {
  return runUntrustedTask<ServiceOriginMapping[]>(
    'map_services_to_origins',
    input,
    {
      timeoutMs: opts.timeoutMs ?? DEFAULT_POST_GRAPH_TASK_TIMEOUT_MS,
      signal: opts.signal,
      maxPayloadBytes: opts.maxPayloadBytes ?? MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
    },
  )
}

/**
 * Run `extractStaticFrameworkRoutes` off the host event loop inside `UntrustedComputePool` with a
 * hard wall-clock deadline (`R4-H-16`).
 */
export function extractStaticFrameworkRoutesInWorker(
  input: {
    reposDir: string
    staticSnapshot?: StaticWorkspaceSnapshot
  },
  opts: UntrustedTaskOptions = {},
): Promise<StaticFrameworkRoutesWorkerResult> {
  return runUntrustedTask<StaticFrameworkRoutesWorkerResult>(
    'extract_static_framework_routes',
    input,
    {
      timeoutMs: opts.timeoutMs ?? DEFAULT_POST_GRAPH_TASK_TIMEOUT_MS,
      signal: opts.signal,
      maxPayloadBytes: opts.maxPayloadBytes ?? MAX_UNTRUSTED_PAYLOAD_BYTES_CAP,
    },
  )
}

// Unified post-graph worker registry keeping all three off-host pipeline entrypoints wired in-module
// while external callers (WS-10 `exec-recon-planner.ts` / `phase0-recon.ts`) migrate onto them.
const POST_GRAPH_WORKER_ENTRYPOINTS = {
  synthesize_invariants: synthesizeInvariantsInWorker,
  map_services_to_origins: mapServicesToOriginsInWorker,
  extract_static_framework_routes: extractStaticFrameworkRoutesInWorker,
} as const

async function executeHostComputeTask(kind: string, payload: unknown): Promise<unknown> {
  switch (kind) {
    case 'search_repo': {
      const req = (payload ?? {}) as SearchRepoWorkerRequest
      if (!req || typeof req.realTarget !== 'string' || typeof req.query !== 'string') {
        throw new Error('search_repo worker task requires realTarget and query strings')
      }
      return executeSearchRepoScan(req)
    }
    case 'synthesize_invariants': {
      const req = (payload ?? {}) as SynthesizeInvariantsInput
      if (!req || typeof req.mode !== 'string') {
        throw new Error('synthesize_invariants worker task requires a valid SynthesizeInvariantsInput')
      }
      const { synthesizeInvariants } = await import('./invariant-synthesizer.ts')
      return synthesizeInvariants(req)
    }
    case 'map_services_to_origins': {
      const req = (payload ?? {}) as MonorepoOriginInput
      if (!req || !Array.isArray(req.services) || !Array.isArray(req.origins)) {
        throw new Error('map_services_to_origins worker task requires services and origins arrays')
      }
      const { mapServicesToOrigins } = await import('./program-graph.ts')
      return mapServicesToOrigins(req)
    }
    case 'extract_static_framework_routes': {
      const req = (payload ?? {}) as { reposDir?: string; staticSnapshot?: StaticWorkspaceSnapshot }
      const { extractStaticFrameworkRoutes } = await import('./phase0-recon.ts')
      return extractStaticFrameworkRoutes(typeof req?.reposDir === 'string' ? req.reposDir : '', req?.staticSnapshot)
    }
    default:
      throw new Error(`Unsupported host-compute worker task kind: ${String(kind)} (registered: ${Object.keys(POST_GRAPH_WORKER_ENTRYPOINTS).join(', ')})`)
  }
}

function serializeHostComputeError(err: unknown): NonNullable<WorkerTaskResponse['error']> {
  if (err instanceof Error) {
    return { name: err.name || 'Error', message: err.message }
  }
  return { name: 'Error', message: String(err) }
}

if (
  !isMainThread
  && parentPort
  && workerData
  && typeof workerData === 'object'
  && (workerData as { kovoWorkerRole?: unknown }).kovoWorkerRole === HOST_COMPUTE_WORKER_ROLE
) {
  const port = parentPort
  port.on('message', (msg: WorkerTaskRequest) => {
    void (async () => {
      try {
        const result = await executeHostComputeTask(msg.kind, msg.payload)
        const response: WorkerTaskResponse = { id: msg.id, ok: true, result }
        port.postMessage(response)
      } catch (err) {
        const response: WorkerTaskResponse = {
          id: msg.id,
          ok: false,
          error: serializeHostComputeError(err),
        }
        port.postMessage(response)
      }
    })()
  })
}
