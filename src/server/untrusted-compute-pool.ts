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
import type { ProgramGraph } from './program-graph.ts'

export type UntrustedTaskKind =
  | 'parse_compose'
  | 'parse_compose_env'
  | 'parse_json'
  | 'parse_json_or_yaml'
  | 'js_harvest'
  | 'extract_html'
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
  /** Maximum serialized payload size accepted per task in bytes (defaults to 4 MiB). */
  maxPayloadBytes?: number
  /** Optional custom worker script URL/path (defaults to `./parser-worker-entry.ts`). */
  workerEntry?: URL | string
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
  worker: Worker
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
  private readonly workerEntry: URL | string
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
      // Strip host process.env so untrusted worker tasks never have access to host secrets.
      env: {},
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

export async function closeSharedUntrustedComputePool(): Promise<void> {
  const pool = sharedPool
  sharedPool = undefined
  if (pool) {
    await pool.close()
  }
}

export function runUntrustedTask<TResult = unknown>(
  kind: UntrustedTaskKind | string,
  payload: unknown,
  opts?: UntrustedTaskOptions,
): Promise<TResult> {
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

export function extractHtmlLinksAndScripts(html: string, origin: string): ExtractedHtmlSurface {
  const links = new Set<string>()
  const scripts = new Set<string>()
  const forms: Array<{ action: string; method: string; inputs: string[]; enctype: string }> = []
  const inputs: Array<{ name: string; id: string | null; type: string | null }> = []
  const seenInputs = new Set<string>()

  for (const m of html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi)) {
    const clean = sanitizeSameOriginPath(m[1] ?? '', origin)
    if (clean && !POOL_STATIC_ASSET_RE.test(clean)) links.add(clean)
  }
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    const clean = sanitizeSameOriginPath(m[1] ?? '', origin)
    if (clean) scripts.add(clean)
  }
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = m[1] ?? ''
    const inner = m[2] ?? ''
    const actionMatch = /\baction\s*=\s*["']([^"']+)["']/i.exec(attrs)
    const methodMatch = /\bmethod\s*=\s*["']([a-zA-Z]+)["']/i.exec(attrs)
    const enctypeMatch = /\benctype\s*=\s*["']([^"']+)["']/i.exec(attrs)
    const action = sanitizeSameOriginPath(actionMatch?.[1] ?? '/', origin) ?? '/'
    const method = (methodMatch?.[1] ?? 'GET').toUpperCase()
    const inputsInForm: string[] = []
    for (const im of inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)) {
      if (im[1]) inputsInForm.push(im[1])
    }
    forms.push({ action, method, inputs: inputsInForm, enctype: (enctypeMatch?.[1] ?? 'application/x-www-form-urlencoded').toLowerCase() })
  }
  for (const tm of html.matchAll(/<(?:input|select|textarea)\b([^>]*)>/gi)) {
    const attrs = tm[1] ?? ''
    const nameMatch = /\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs)
    const idMatch = /\bid\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs)
    const typeMatch = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs)
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
