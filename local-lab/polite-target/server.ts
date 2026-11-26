/**
 * Fast loopback polite-target HTTP fixture server (R2-16).
 *
 * Exercises external target-load politeness controls over real HTTP on `127.0.0.1`
 * without requiring remote targets or toggling env-wide `KOVO_ALLOW_LOCAL_LAB`:
 *   - `GET /health`               -> 200 OK with vhost + request timing telemetry
 *   - `GET /slow?delayMs=N`       -> bounded delay for measuring concurrent in-flight ceilings
 *   - `GET /throttle/once?retryAfter=N&key=K` -> 429 + `Retry-After` on first N hits per key, then 200
 *   - `GET /throttle/always?retryAfter=N`     -> always 429 + `Retry-After` (tests 429 breaker)
 *   - `GET /edge-down/:status`    -> emits 502-504 or Cloudflare 520-526 origin-down status bursts
 *   - `GET /transient/500`        -> emits ordinary 500 for unified status taxonomy checks
 *   - Multi-vhost awareness via incoming `Host` header on a single loopback IP
 */
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { fileURLToPath } from 'node:url'

export interface PoliteTargetRequestRecord {
  timestampMs: number
  host: string
  path: string
  status: number
}

export interface PoliteTargetStats {
  totalRequests: number
  currentInFlight: number
  peakInFlight: number
  requestsByHost: Record<string, number>
  statusCounts: Record<string, number>
  records: readonly PoliteTargetRequestRecord[]
  /** Maximum request count observed in any sliding 1000ms window across all vhosts on this server. */
  maxRequestsIn1sWindow: number
}

export interface PoliteTargetServerHandle {
  server: Server
  host: string
  port: number
  origin: string
  getStats: () => PoliteTargetStats
  resetStats: () => void
  close: () => Promise<void>
}

export interface PoliteTargetServerOptions {
  host?: string
  port?: number
}

const VALID_ORIGIN_DOWN_STATUSES = new Set([502, 503, 504, 520, 521, 522, 523, 524, 525, 526])

function computeMaxInSlidingWindow(records: readonly PoliteTargetRequestRecord[], windowMs: number): number {
  if (records.length === 0) return 0
  let maxCount = 0
  let left = 0
  for (let right = 0; right < records.length; right += 1) {
    const rightTs = records[right]!.timestampMs
    while (left <= right && rightTs - records[left]!.timestampMs >= windowMs) {
      left += 1
    }
    const count = right - left + 1
    if (count > maxCount) maxCount = count
  }
  return maxCount
}

export async function startPoliteTargetServer(
  options: PoliteTargetServerOptions = {},
): Promise<PoliteTargetServerHandle> {
  const bindHost = options.host ?? '127.0.0.1'
  const bindPort = options.port ?? 0

  let currentInFlight = 0
  let peakInFlight = 0
  let totalRequests = 0
  const requestsByHost = new Map<string, number>()
  const statusCounts = new Map<string, number>()
  const throttleHitsByKey = new Map<string, number>()
  const records: PoliteTargetRequestRecord[] = []

  const sendJson = (
    res: ServerResponse,
    status: number,
    payload: Record<string, unknown>,
    extraHeaders: Record<string, string> = {},
  ) => {
    const body = JSON.stringify(payload)
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(Buffer.byteLength(body)),
      ...extraHeaders,
    })
    res.end(body)
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const now = Date.now()
    const rawHost = String(req.headers.host ?? `${bindHost}:${bindPort}`).toLowerCase()
    const vhost = rawHost.replace(/:\d+$/, '')
    const parsedUrl = new URL(req.url ?? '/', `http://${rawHost || '127.0.0.1'}`)
    const pathname = parsedUrl.pathname

    currentInFlight += 1
    if (currentInFlight > peakInFlight) peakInFlight = currentInFlight
    totalRequests += 1
    requestsByHost.set(vhost, (requestsByHost.get(vhost) ?? 0) + 1)

    const finalize = (status: number, body: Record<string, unknown>, extraHeaders?: Record<string, string>) => {
      const statusKey = String(status)
      statusCounts.set(statusKey, (statusCounts.get(statusKey) ?? 0) + 1)
      records.push({ timestampMs: now, host: vhost, path: pathname, status })
      sendJson(res, status, { ...body, vhost, status }, extraHeaders)
      currentInFlight = Math.max(0, currentInFlight - 1)
    }

    if (pathname === '/health') {
      finalize(200, { ok: true, totalRequests, inFlight: currentInFlight, peakInFlight })
      return
    }

    if (pathname === '/slow') {
      const requestedDelay = Number(parsedUrl.searchParams.get('delayMs') ?? '60')
      const delayMs = Number.isFinite(requestedDelay) ? Math.max(0, Math.min(1_000, Math.floor(requestedDelay))) : 60
      setTimeout(() => {
        finalize(200, { ok: true, delayMs, inFlight: currentInFlight, peakInFlight })
      }, delayMs)
      return
    }

    if (pathname === '/throttle/once') {
      const key = parsedUrl.searchParams.get('key') ?? `${vhost}:default`
      const rawRetryAfter = Number(parsedUrl.searchParams.get('retryAfter') ?? '1')
      const retryAfterSec = Number.isFinite(rawRetryAfter) && rawRetryAfter >= 0 ? Math.min(30, rawRetryAfter) : 1
      const rawBurst = Number(parsedUrl.searchParams.get('burst') ?? '1')
      const burst = Number.isFinite(rawBurst) && rawBurst >= 1 ? Math.min(20, Math.floor(rawBurst)) : 1
      const prevHits = throttleHitsByKey.get(key) ?? 0
      throttleHitsByKey.set(key, prevHits + 1)
      if (prevHits < burst) {
        finalize(
          429,
          { ok: false, throttled: true, key, attempt: prevHits + 1, retryAfterSec },
          { 'retry-after': String(retryAfterSec) },
        )
        return
      }
      finalize(200, { ok: true, throttled: false, key, attempt: prevHits + 1 })
      return
    }

    if (pathname === '/throttle/always') {
      const rawRetryAfter = Number(parsedUrl.searchParams.get('retryAfter') ?? '1')
      const retryAfterSec = Number.isFinite(rawRetryAfter) && rawRetryAfter >= 0 ? Math.min(30, rawRetryAfter) : 1
      finalize(
        429,
        { ok: false, throttled: true, retryAfterSec },
        { 'retry-after': String(retryAfterSec) },
      )
      return
    }

    const edgeMatch = /^\/edge-down\/(\d{3})$/.exec(pathname)
    if (edgeMatch) {
      const code = Number(edgeMatch[1])
      if (VALID_ORIGIN_DOWN_STATUSES.has(code)) {
        finalize(code, { ok: false, error: `Simulated origin-down HTTP ${code}` })
        return
      }
    }

    if (pathname === '/transient/500') {
      finalize(500, { ok: false, error: 'Simulated transient HTTP 500' })
      return
    }

    finalize(200, { ok: true, path: pathname, totalRequests })
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(bindPort, bindHost, () => {
      server.off('error', reject)
      resolve()
    })
  })

  const addr = server.address() as AddressInfo
  const port = addr.port
  const origin = `http://${bindHost}:${port}`

  return {
    server,
    host: bindHost,
    port,
    origin,
    getStats: () => ({
      totalRequests,
      currentInFlight,
      peakInFlight,
      requestsByHost: Object.fromEntries(requestsByHost.entries()),
      statusCounts: Object.fromEntries(statusCounts.entries()),
      records: records.map(r => ({ ...r })),
      maxRequestsIn1sWindow: computeMaxInSlidingWindow(records, 1_000),
    }),
    resetStats: () => {
      currentInFlight = 0
      peakInFlight = 0
      totalRequests = 0
      requestsByHost.clear()
      statusCounts.clear()
      throttleHitsByKey.clear()
      records.length = 0
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close(err => (err ? reject(err) : resolve()))
      }),
  }
}

const isDirectEntry =
  process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]

if (isDirectEntry) {
  const port = Number(process.env.PORT ?? '0')
  const handle = await startPoliteTargetServer({
    host: process.env.HOST ?? '127.0.0.1',
    port: Number.isFinite(port) && port >= 0 ? port : 0,
  })
  console.log(`polite-target listening on ${handle.origin}`)
}
