/**
 * Shared parallel-matrix primitives (v5 M6 throughput stream).
 *
 * The matrix runners schedule 6–9 isolated benchmark cells on one host. This module owns the
 * pieces that keep that safe and predictable:
 *
 *   - `Semaphore` / `AimdLimiter` — bounded admission with a global in-flight cap for model
 *     streams. The limiter shrinks on HTTP 429 (AIMD) and honours `Retry-After`; waiters queue
 *     in FIFO order and are never dropped.
 *   - `ModelGate` — a loopback HTTP proxy in front of the model provider. Cells point their
 *     isolated model profile at the gate, so the stream cap is global across child processes
 *     without teaching the engine about the matrix. Request bodies are buffered (bounded) so a
 *     rate-limited request can be retried; responses stream through untouched.
 *   - `ResourceGuard` — pauses launching new cells when MemAvailable < 6 GiB or the number of
 *     active worker containers exceeds 16. Pause/resume episodes are recorded for the summary.
 *   - `CellReaper` — removes containers by `dev.kovo.cell=<id>` label on exit/SIGINT/SIGTERM,
 *     and verifies no orphans remain. Only ever touches the labels it owns.
 *   - `rewriteProfileEndpoints` — rewrites enabled model-profile endpoints inside an isolated
 *     data dir (used to route through the gate); never touches credentials.
 *
 * No raw child output or probe payloads pass through this module.
 */
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { availableParallelism, freemem } from 'node:os'
import { resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

// ---------------------------------------------------------------------------------------------
// Semaphore
// ---------------------------------------------------------------------------------------------

interface Waiter {
  resolve: (release: () => void) => void
  reject: (error: Error) => void
  signal?: AbortSignal
  onAbort?: () => void
}

/** FIFO counting semaphore with a mutable ceiling (used by the AIMD limiter). */
export class Semaphore {
  private limitValue: number
  private readonly minLimit: number
  private readonly maxLimit: number
  private inFlightValue = 0
  private peakValue = 0
  private readonly waiters: Waiter[] = []

  constructor(limit: number, opts: { minLimit?: number; maxLimit?: number } = {}) {
    const max = Math.max(1, Math.floor(opts.maxLimit ?? limit))
    this.minLimit = Math.max(1, Math.min(max, Math.floor(opts.minLimit ?? 1)))
    this.maxLimit = max
    this.limitValue = Math.max(this.minLimit, Math.min(max, Math.floor(limit)))
  }

  get limit(): number { return this.limitValue }
  get inFlight(): number { return this.inFlightValue }
  get queued(): number { return this.waiters.length }
  get peak(): number { return this.peakValue }

  setLimit(next: number): void {
    this.limitValue = Math.max(this.minLimit, Math.min(this.maxLimit, Math.floor(next)))
    this.pump()
  }

  /** Acquire a permit; resolves with an idempotent release function. */
  acquire(signal?: AbortSignal): Promise<() => void> {
    signal?.throwIfAborted()
    if (this.inFlightValue < this.limitValue) {
      this.inFlightValue += 1
      this.peakValue = Math.max(this.peakValue, this.inFlightValue)
      return Promise.resolve(this.releaseFn())
    }
    return new Promise<() => void>((resolvePromise, rejectPromise) => {
      const waiter: Waiter = { resolve: resolvePromise, reject: rejectPromise, ...(signal ? { signal } : {}) }
      if (signal) {
        waiter.onAbort = () => {
          const index = this.waiters.indexOf(waiter)
          if (index >= 0) this.waiters.splice(index, 1)
          rejectPromise(new Error('Semaphore acquisition aborted'))
        }
        signal.addEventListener('abort', waiter.onAbort, { once: true })
      }
      this.waiters.push(waiter)
    })
  }

  private releaseFn(): () => void {
    let released = false
    return () => {
      if (released) return
      released = true
      this.inFlightValue -= 1
      this.pump()
    }
  }

  private pump(): void {
    while (this.waiters.length > 0 && this.inFlightValue < this.limitValue) {
      const waiter = this.waiters.shift()!
      if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort)
      if (waiter.signal?.aborted) {
        waiter.reject(new Error('Semaphore acquisition aborted'))
        continue
      }
      this.inFlightValue += 1
      this.peakValue = Math.max(this.peakValue, this.inFlightValue)
      waiter.resolve(this.releaseFn())
    }
  }
}

// ---------------------------------------------------------------------------------------------
// AIMD limiter (429 backoff)
// ---------------------------------------------------------------------------------------------

const sleepReal = (ms: number): Promise<void> => new Promise(resolvePromise => setTimeout(resolvePromise, Math.max(0, ms)))

/** Parse `Retry-After` (delta seconds or HTTP date) into a bounded millisecond delay. */
export function parseRetryAfter(raw: string | null | undefined, nowMs = Date.now(), fallbackMs = 1_000, maxMs = 30_000): number {
  if (!raw) return Math.min(fallbackMs, maxMs)
  const trimmed = raw.trim()
  if (/^\d+(?:\.\d+)?$/.test(trimmed)) return Math.min(Math.round(Number(trimmed) * 1000), maxMs)
  const at = Date.parse(trimmed)
  if (Number.isFinite(at)) return Math.min(Math.max(0, at - nowMs), maxMs)
  return Math.min(fallbackMs, maxMs)
}

export interface AimdStats {
  limit: number
  inFlight: number
  queued: number
  peak: number
  rateLimited: number
  retries: number
  decreases: number
  increases: number
}

export interface AimdLimiterOptions {
  maxInFlight: number
  minInFlight?: number
  decreaseFactor?: number
  /** Successful streams needed before the ceiling grows by one. */
  increaseEvery?: number
  now?: () => number
  sleep?: (ms: number) => Promise<void>
}

/**
 * Additive-increase / multiplicative-decrease admission control for model streams.
 * On 429 the ceiling shrinks and all acquisitions wait out `Retry-After`; queued work is kept.
 */
export class AimdLimiter {
  readonly semaphore: Semaphore
  private readonly minInFlight: number
  private readonly maxInFlight: number
  private readonly decreaseFactor: number
  private readonly increaseEvery: number
  private readonly now: () => number
  private readonly sleep: (ms: number) => Promise<void>
  private cooldownUntil = 0
  private successStreak = 0
  private rateLimited = 0
  private retries = 0
  private decreases = 0
  private increases = 0

  constructor(opts: AimdLimiterOptions) {
    this.maxInFlight = Math.max(1, Math.floor(opts.maxInFlight))
    this.minInFlight = Math.max(1, Math.min(this.maxInFlight, Math.floor(opts.minInFlight ?? 4)))
    this.decreaseFactor = Math.min(0.95, Math.max(0.3, opts.decreaseFactor ?? 0.7))
    this.increaseEvery = Math.max(1, Math.floor(opts.increaseEvery ?? 8))
    this.now = opts.now ?? Date.now
    this.sleep = opts.sleep ?? sleepReal
    this.semaphore = new Semaphore(this.maxInFlight, { minLimit: this.minInFlight, maxLimit: this.maxInFlight })
  }

  get cooldownRemainingMs(): number { return Math.max(0, this.cooldownUntil - this.now()) }

  /** Wait out any active cooldown, then take a permit. */
  async acquire(signal?: AbortSignal): Promise<() => void> {
    for (;;) {
      signal?.throwIfAborted()
      const wait = this.cooldownRemainingMs
      if (wait <= 0) break
      await this.sleep(Math.min(wait, 250))
    }
    return this.semaphore.acquire(signal)
  }

  onSuccess(): void {
    this.successStreak += 1
    if (this.successStreak < this.increaseEvery) return
    this.successStreak = 0
    if (this.semaphore.limit >= this.maxInFlight) return
    this.semaphore.setLimit(this.semaphore.limit + 1)
    this.increases += 1
  }

  onRateLimited(retryAfterMs: number): void {
    this.rateLimited += 1
    this.successStreak = 0
    const next = Math.max(this.minInFlight, Math.floor(this.semaphore.limit * this.decreaseFactor))
    if (next < this.semaphore.limit) {
      this.semaphore.setLimit(next)
      this.decreases += 1
    }
    this.cooldownUntil = Math.max(this.cooldownUntil, this.now() + Math.max(0, retryAfterMs))
  }

  noteRetry(): void { this.retries += 1 }

  stats(): AimdStats {
    return {
      limit: this.semaphore.limit,
      inFlight: this.semaphore.inFlight,
      queued: this.semaphore.queued,
      peak: this.semaphore.peak,
      rateLimited: this.rateLimited,
      retries: this.retries,
      decreases: this.decreases,
      increases: this.increases,
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Model gate (loopback proxy with global stream admission)
// ---------------------------------------------------------------------------------------------

export interface ModelGateOptions {
  /** Global cap on concurrent model streams across every cell (default 28). */
  maxInFlightStreams?: number
  minInFlightStreams?: number
  fetchImpl?: typeof fetch
  sleep?: (ms: number) => Promise<void>
  now?: () => number
  /** Upstream attempts per request when the provider answers 429. */
  maxAttempts?: number
  defaultRetryAfterMs?: number
  maxRetryAfterMs?: number
  /** Bound on a buffered request body (provider caps are lower). */
  maxRequestBytes?: number
}

const GATE_PATH = '/g/'
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te',
  'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
])

function decodeUpstreamToken(token: string): string | null {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8')
    const url = new URL(decoded)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    if (url.username || url.password) return null
    return decoded.replace(/\/+$/, '')
  } catch { return null }
}

/** Read a request body with a hard byte cap. */
async function readBoundedBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
    total += buf.length
    if (total > maxBytes) throw new Error('Model request exceeded the gate size limit')
    chunks.push(buf)
  }
  return Buffer.concat(chunks)
}

/**
 * Loopback model-provider proxy. `endpointFor(upstream)` returns a URL that can replace a model
 * profile's endpoint; the engine appends its protocol path (`/responses` etc.) and the gate
 * forwards to the original upstream while enforcing the shared stream cap.
 */
export class ModelGate {
  readonly limiter: AimdLimiter
  private readonly fetchImpl: typeof fetch
  private readonly sleep: (ms: number) => Promise<void>
  private readonly maxAttempts: number
  private readonly defaultRetryAfterMs: number
  private readonly maxRetryAfterMs: number
  private readonly maxRequestBytes: number
  private server?: Server
  private portValue = 0
  private readonly openReleases = new Set<() => void>()
  private readonly openCancels = new Set<() => void>()

  constructor(opts: ModelGateOptions = {}) {
    this.limiter = new AimdLimiter({
      maxInFlight: opts.maxInFlightStreams ?? 28,
      ...(opts.minInFlightStreams !== undefined ? { minInFlight: opts.minInFlightStreams } : {}),
      ...(opts.now ? { now: opts.now } : {}),
      ...(opts.sleep ? { sleep: opts.sleep } : {}),
    })
    this.fetchImpl = opts.fetchImpl ?? fetch
    this.sleep = opts.sleep ?? sleepReal
    this.maxAttempts = Math.max(1, Math.floor(opts.maxAttempts ?? 4))
    this.defaultRetryAfterMs = Math.max(0, opts.defaultRetryAfterMs ?? 1_000)
    this.maxRetryAfterMs = Math.max(1_000, opts.maxRetryAfterMs ?? 30_000)
    this.maxRequestBytes = Math.max(64 * 1024, opts.maxRequestBytes ?? 8 * 1024 * 1024)
  }

  get port(): number { return this.portValue }
  get url(): string { return `http://127.0.0.1:${this.portValue}` }

  /** Gate endpoint for an upstream provider base (e.g. https://openrouter.ai/api/v1). */
  endpointFor(upstream: string): string {
    const token = Buffer.from(upstream.replace(/\/+$/, ''), 'utf8').toString('base64url')
    return `${this.url}${GATE_PATH}${token}`
  }

  async start(host = '127.0.0.1'): Promise<{ port: number; url: string }> {
    if (this.server) return { port: this.portValue, url: this.url }
    const server = createServer((req, res) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: { message: 'The model gate could not reach the provider.' } }))
        } else res.destroy()
      })
    })
    await new Promise<void>((resolvePromise, rejectPromise) => {
      server.once('error', rejectPromise)
      server.listen(0, host, () => {
        server.off('error', rejectPromise)
        resolvePromise()
      })
    })
    const address = server.address()
    this.portValue = typeof address === 'object' && address ? address.port : 0
    this.server = server
    return { port: this.portValue, url: this.url }
  }

  async close(): Promise<void> {
    const server = this.server
    if (!server) return
    this.server = undefined
    // Force-close any stream still in flight: a cell can exit between the request and its first
    // byte, and an abandoned upstream socket must never keep the matrix process alive.
    for (const cancel of [...this.openCancels]) { try { cancel() } catch { /* best-effort */ } }
    this.openCancels.clear()
    for (const release of [...this.openReleases]) { try { release() } catch { /* best-effort */ } }
    this.openReleases.clear()
    await new Promise<void>(resolvePromise => {
      const timer = setTimeout(resolvePromise, 2_000)
      server.close(() => { clearTimeout(timer); resolvePromise() })
      server.closeAllConnections?.()
    })
  }

  stats(): AimdStats { return this.limiter.stats() }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { message: 'The model gate only accepts POST.' } }))
      return
    }
    const url = new URL(req.url ?? '/', this.url)
    if (!url.pathname.startsWith(GATE_PATH)) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { message: 'Unknown model gate route.' } }))
      return
    }
    const rest = url.pathname.slice(GATE_PATH.length)
    const slash = rest.indexOf('/')
    const token = slash < 0 ? rest : rest.slice(0, slash)
    const suffix = slash < 0 ? '' : rest.slice(slash)
    const upstream = decodeUpstreamToken(token)
    if (!upstream) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { message: 'Invalid model gate route.' } }))
      return
    }
    let body: Buffer
    try {
      body = await readBoundedBody(req, this.maxRequestBytes)
    } catch (error) {
      res.writeHead(413, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { message: error instanceof Error ? error.message : 'Request too large.' } }))
      return
    }
    const headers: Record<string, string> = {}
    for (const [name, value] of Object.entries(req.headers)) {
      if (!value || HOP_BY_HOP.has(name.toLowerCase())) continue
      headers[name] = Array.isArray(value) ? value.join(', ') : value
    }
    headers['content-length'] = String(body.length)

    // If the cell goes away before the upstream answers (or while queued for a permit), abort the
    // upstream request instead of leaving an orphaned stream behind.
    const downstream = new AbortController()
    const onDownstreamClose = () => downstream.abort()
    res.once('close', onDownstreamClose)
    let response: Response
    try {
      response = await this.forward(`${upstream}${suffix}${url.search}`, { method: 'POST', headers, body }, downstream.signal)
    } catch {
      res.off('close', onDownstreamClose)
      if (!res.destroyed) {
        res.writeHead(502, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { message: 'The model gate request was interrupted.' } }))
      }
      return
    }
    if (res.destroyed) {
      res.off('close', onDownstreamClose)
      await response.body?.cancel().catch(() => undefined)
      return
    }
    res.writeHead(response.status, Object.fromEntries(
      [...response.headers.entries()].filter(([name]) => !HOP_BY_HOP.has(name.toLowerCase())),
    ))
    if (!response.body) {
      res.off('close', onDownstreamClose)
      res.end()
      return
    }
    const reader = response.body.getReader()
    // A cell that exits mid-stream closes the downstream socket. Cancel the upstream reader so
    // the permit is released promptly and `gate.close()` never waits on an abandoned stream.
    const cancelReader = () => { void reader.cancel().catch(() => undefined) }
    res.once('close', cancelReader)
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (res.destroyed) break
        if (!res.write(Buffer.from(value))) {
          await new Promise<void>(resolvePromise => {
            const done = () => {
              res.off('drain', done)
              res.off('close', done)
              resolvePromise()
            }
            res.once('drain', done)
            res.once('close', done)
          })
        }
      }
      if (!res.writableEnded && !res.destroyed) res.end()
    } catch {
      if (!res.destroyed) res.destroy()
    } finally {
      res.off('close', cancelReader)
      res.off('close', onDownstreamClose)
    }
  }

  /**
   * Forward one buffered request through the shared limiter. A 429 is retried after
   * `Retry-After` (bounded attempts) and shrinks the ceiling; the permit is held for the whole
   * response stream, so the cap counts live streams rather than just request dispatch.
   */
  async forward(target: string, init: { method: string; headers: Record<string, string>; body: Buffer }, signal?: AbortSignal): Promise<Response> {
    let last: Response | undefined
    for (let attempt = 0; attempt < this.maxAttempts; attempt += 1) {
      const release = await this.limiter.acquire(signal)
      let response: Response
      try {
        signal?.throwIfAborted()
        response = await this.fetchImpl(target, {
          method: init.method,
          headers: init.headers,
          body: new Uint8Array(init.body),
          redirect: 'error',
          ...(signal ? { signal } : {}),
        })
      } catch (error) {
        release()
        throw error
      }
      if (response.status !== 429 || attempt === this.maxAttempts - 1) {
        this.limiter.onSuccess()
        return this.wrapBody(response, release)
      }
      await response.body?.cancel().catch(() => undefined)
      release()
      const retryAfter = parseRetryAfter(response.headers.get('retry-after'), Date.now(), this.defaultRetryAfterMs, this.maxRetryAfterMs)
      this.limiter.onRateLimited(retryAfter)
      this.limiter.noteRetry()
      await this.sleep(retryAfter)
      last = response
    }
    return last ?? new Response(JSON.stringify({ error: { message: 'The provider rate limit was reached.' } }), {
      status: 429, headers: { 'content-type': 'application/json' },
    })
  }

  /** Release the permit exactly once, when the response stream ends/cancels/errors. */
  private wrapBody(response: Response, release: () => void): Response {
    if (!response.body) { release(); return response }
    const reader = response.body.getReader()
    let released = false
    const releaseOnce = () => {
      if (released) return
      released = true
      this.openReleases.delete(releaseOnce)
      this.openCancels.delete(cancelOnce)
      release()
    }
    const cancelOnce = () => { void reader.cancel().catch(() => undefined) }
    this.openReleases.add(releaseOnce)
    this.openCancels.add(cancelOnce)
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await reader.read()
          if (done) { releaseOnce(); controller.close(); return }
          controller.enqueue(value)
        } catch (error) {
          releaseOnce()
          controller.error(error)
        }
      },
      cancel(reason) {
        releaseOnce()
        return reader.cancel(reason)
      },
    })
    return new Response(body, { status: response.status, headers: response.headers })
  }
}

// ---------------------------------------------------------------------------------------------
// Resource watermark guard
// ---------------------------------------------------------------------------------------------

export interface ResourceSnapshot {
  /** MemAvailable in bytes (falls back to os.freemem). */
  memAvailableBytes: number
  /** Running worker containers carrying a cell label. */
  activeWorkers: number
}

export interface PauseEvent {
  at: number
  reason: 'ram' | 'workers'
  memAvailableBytes: number
  activeWorkers: number
  resumedAt?: number
}

export interface ResourceGuardOptions {
  minFreeMemBytes?: number
  maxActiveWorkers?: number
  probe?: () => ResourceSnapshot | Promise<ResourceSnapshot>
  sleep?: (ms: number) => Promise<void>
  now?: () => number
  pollMs?: number
  onPause?: (event: PauseEvent) => void
  onResume?: (event: PauseEvent) => void
}

/** MemAvailable from /proc/meminfo is the value that tracks reclaimable cache on Linux. */
export function readMemAvailableBytes(): number {
  try {
    const text = readFileSync('/proc/meminfo', 'utf8')
    const match = /^MemAvailable:\s+(\d+)\s+kB/m.exec(text)
    if (match) return Number(match[1]) * 1024
  } catch { /* non-Linux or restricted procfs */ }
  return freemem()
}

/** Count running worker containers that belong to a matrix cell. */
export async function countActiveWorkers(): Promise<number> {
  return new Promise(resolvePromise => {
    const child = spawn('docker', [
      'ps', '--quiet', '--filter', 'label=dev.kovo.cell', '--filter', 'status=running',
    ], { stdio: ['ignore', 'pipe', 'ignore'] })
    let out = ''
    child.stdout?.on('data', (chunk: Buffer) => { if (out.length < 64 * 1024) out += chunk.toString() })
    const timer = setTimeout(() => child.kill('SIGKILL'), 2_000)
    child.on('error', () => { clearTimeout(timer); resolvePromise(0) })
    child.on('close', () => {
      clearTimeout(timer)
      resolvePromise(out.split('\n').filter(line => line.trim().length > 0).length)
    })
  })
}

export class ResourceGuard {
  readonly events: PauseEvent[] = []
  private readonly minFreeMemBytes: number
  private readonly maxActiveWorkers: number
  private readonly probe: () => ResourceSnapshot | Promise<ResourceSnapshot>
  private readonly sleep: (ms: number) => Promise<void>
  private readonly now: () => number
  private readonly pollMs: number
  private readonly onPause?: (event: PauseEvent) => void
  private readonly onResume?: (event: PauseEvent) => void
  private open?: PauseEvent

  constructor(opts: ResourceGuardOptions = {}) {
    this.minFreeMemBytes = Math.max(0, opts.minFreeMemBytes ?? 6 * 1024 ** 3)
    this.maxActiveWorkers = Math.max(1, Math.floor(opts.maxActiveWorkers ?? 16))
    this.probe = opts.probe ?? (async () => ({ memAvailableBytes: readMemAvailableBytes(), activeWorkers: await countActiveWorkers() }))
    this.sleep = opts.sleep ?? sleepReal
    this.now = opts.now ?? Date.now
    this.pollMs = Math.max(50, opts.pollMs ?? 1_000)
    this.onPause = opts.onPause
    this.onResume = opts.onResume
  }

  /** Resolve when a new cell may launch; pauses and resumes exactly once per episode. */
  async waitForCapacity(signal?: AbortSignal): Promise<void> {
    for (;;) {
      signal?.throwIfAborted()
      const snapshot = await this.probe()
      const reason = snapshot.memAvailableBytes < this.minFreeMemBytes
        ? 'ram' as const
        : snapshot.activeWorkers >= this.maxActiveWorkers ? 'workers' as const : undefined
      if (!reason) {
        if (this.open) {
          this.open.resumedAt = this.now()
          this.onResume?.(this.open)
          this.open = undefined
        }
        return
      }
      if (!this.open) {
        this.open = {
          at: this.now(),
          reason,
          memAvailableBytes: snapshot.memAvailableBytes,
          activeWorkers: snapshot.activeWorkers,
        }
        this.events.push(this.open)
        this.onPause?.(this.open)
      }
      await this.sleep(this.pollMs)
    }
  }

  get paused(): boolean { return this.open !== undefined }
}

// ---------------------------------------------------------------------------------------------
// Cell-labeled reaper
// ---------------------------------------------------------------------------------------------

export type DockerTextRunner = (args: string[]) => Promise<string>

const defaultDockerRunner: DockerTextRunner = args => new Promise((resolvePromise, rejectPromise) => {
  const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  let err = ''
  child.stdout?.on('data', (chunk: Buffer) => { if (out.length < 64 * 1024) out += chunk.toString() })
  child.stderr?.on('data', (chunk: Buffer) => { if (err.length < 4 * 1024) err += chunk.toString() })
  const timer = setTimeout(() => child.kill('SIGKILL'), 5_000)
  child.on('error', error => { clearTimeout(timer); rejectPromise(error) })
  child.on('close', code => {
    clearTimeout(timer)
    if (code === 0) resolvePromise(out)
    else rejectPromise(new Error(err.trim() || `docker exited ${code}`))
  })
})

/** Docker label values allow [a-zA-Z0-9_.-]; keep cell ids short and stable. */
export function cellLabel(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63) || 'cell'
}

/**
 * Removes containers by cell label. Each reaper owns an explicit set of ids; `reap()` never
 * queries or removes any other label value, which keeps concurrent matrices independent.
 */
export class CellReaper {
  private readonly cells: Set<string>
  private readonly docker: DockerTextRunner
  private installed = false
  private readonly onExit = (code: number) => {
    void this.reapAll().finally(() => process.exit(code))
  }
  private readonly onSigint = () => this.onExit(130)
  private readonly onSigterm = () => this.onExit(143)

  constructor(cells: readonly string[], opts: { dockerRunner?: DockerTextRunner } = {}) {
    this.cells = new Set(cells.map(cellLabel))
    this.docker = opts.dockerRunner ?? defaultDockerRunner
  }

  get cellIds(): string[] { return [...this.cells] }

  install(): void {
    if (this.installed) return
    this.installed = true
    process.once('SIGINT', this.onSigint)
    process.once('SIGTERM', this.onSigterm)
  }

  dispose(): void {
    if (!this.installed) return
    this.installed = false
    process.off('SIGINT', this.onSigint)
    process.off('SIGTERM', this.onSigterm)
  }

  /** List container ids for the owned cell labels (no removal). */
  async list(cell?: string): Promise<string[]> {
    const ids: string[] = []
    for (const id of cell ? [cellLabel(cell)] : [...this.cells]) {
      if (!this.cells.has(id)) continue
      try {
        const out = await this.docker(['ps', '--all', '--quiet', '--filter', `label=dev.kovo.cell=${id}`])
        for (const line of out.split('\n')) {
          const trimmed = line.trim()
          if (trimmed) ids.push(trimmed)
        }
      } catch { /* daemon unavailable: nothing to remove */ }
    }
    return ids
  }

  async reap(cell: string): Promise<number> {
    const id = cellLabel(cell)
    if (!this.cells.has(id)) return 0
    let removed = 0
    // A child's exit hook and this reaper can race the same `rm`; retry briefly so a
    // "removal already in progress" never leaves a stale container counted as an orphan.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const ids = await this.list(id)
      if (!ids.length) break
      try {
        await this.docker(['rm', '--force', ...ids])
        removed += ids.length
      } catch { /* retry */ }
      await new Promise(resolvePromise => setTimeout(resolvePromise, 120))
    }
    return removed
  }

  async reapAll(): Promise<number> {
    let removed = 0
    for (const cell of this.cells) removed += await this.reap(cell)
    return removed
  }

  /** Remaining containers for owned labels (0 means no orphans). */
  async orphans(): Promise<number> {
    return (await this.list()).length
  }
}

// ---------------------------------------------------------------------------------------------
// Model-profile endpoint rewrite (gate routing)
// ---------------------------------------------------------------------------------------------

/**
 * Rewrite enabled model-profile endpoints in an isolated data dir. Credentials are never read
 * or copied here; the caller is responsible for the isolated dir (see prepareIsolatedDataDir).
 */
export function rewriteProfileEndpoints(
  dataDir: string,
  map: (endpoint: string) => string,
): { updated: number; endpoints: string[] } {
  const dbPath = resolve(dataDir, 'kovo.sqlite')
  if (!existsSync(dbPath)) throw new Error(`model-profile rewrite needs kovo.sqlite in ${dataDir}`)
  const db = new DatabaseSync(dbPath)
  try {
    const rows = db.prepare('select id, endpoint from model_profiles where enabled = 1').all() as Array<{ id: string; endpoint: string }>
    if (!rows.length) throw new Error('model-profile rewrite found no enabled profile')
    const update = db.prepare('update model_profiles set endpoint = ?, updated_at = ? where id = ?')
    const endpoints: string[] = []
    for (const row of rows) {
      const original = String(row.endpoint)
      endpoints.push(original)
      update.run(map(original), Date.now(), String(row.id))
    }
    return { updated: rows.length, endpoints }
  } finally {
    db.close()
  }
}

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

/** Default cell width: leave one core for the parent/docker daemon, cap at 9 cells. */
export function defaultCellConcurrency(): number {
  return Math.min(9, Math.max(1, availableParallelism() - 1))
}

/** Human-readable byte count for summary lines. */
export function formatGiB(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(1)}GiB`
}

/** Environment default for the global stream cap. */
export function defaultMaxInFlightStreams(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.KOVO_MODEL_MAX_STREAMS)
  return Number.isFinite(raw) && raw >= 1 ? Math.min(256, Math.floor(raw)) : 28
}

/** Escape-hatch parsing shared by the matrix CLIs and the worker backend. */
export function envFlagDisabled(env: NodeJS.ProcessEnv, key: string): boolean {
  const value = env[key]
  return value === '0' || value === 'false' || value === 'off'
}
