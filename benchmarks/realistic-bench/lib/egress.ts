// Contained egress guard: the ONLY way app features reach the network in the lab. Permits plain
// HTTP to literal loopback 127.0.0.1 and only to ports registered as the app's internal mock
// services or caller-supplied out-of-band callback ports. Every other host (DNS names, IPv6,
// IPv4-mapped, decimal/octal/hex integer IPs, userinfo tricks, trailing-dot) is blocked and logged.
// When a request whose host/port/url was derived from request input reaches a service flagged
// internal, it emits ssrf_internal_fetch so the grader can prove real SSRF impact.
import http from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Oracle } from './oracle.ts'
import { currentCtx, isFromInput } from './oracle.ts'
import { LOOPBACK, assertLocalLabAllowed, listenLoopback, closeServer } from './safety.ts'

const MAX_BYTES = 64 * 1024
const TIMEOUT_MS = 2000
const MAX_REDIRECTS = 3
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308])

export interface InternalServiceRef { name: string; port: number; internal: boolean }

export interface EgressInit {
  method?: string
  headers?: Record<string, string>
  body?: string
  inputDerived?: boolean
}

export interface EgressResponse {
  status: number
  headers: Record<string, string>
  body: string
  url: string
  allowed: true
  reason: string
}

export interface Egress {
  fetch(url: string, init?: EgressInit): Promise<EgressResponse>
}

interface Validation {
  ok: boolean
  reason: string
  port: number
  service?: InternalServiceRef
  target?: URL
}

function validate(rawUrl: string, allowed: Map<number, InternalServiceRef>): Validation {
  let u: URL
  try {
    u = new URL(rawUrl)
  } catch {
    return { ok: false, reason: 'invalid_url', port: 0 }
  }
  if (u.protocol !== 'http:') return { ok: false, reason: `protocol_blocked:${u.protocol}`, port: 0 }
  let host = u.hostname.toLowerCase()
  if (host === 'localhost') host = LOOPBACK
  if (host !== LOOPBACK) return { ok: false, reason: `host_blocked:${u.hostname}`, port: 0 }
  const port = u.port ? Number(u.port) : 80
  const service = allowed.get(port)
  if (!service) return { ok: false, reason: `port_blocked:${port}`, port }
  return { ok: true, reason: 'allowed', port, service, target: u }
}

function doRequest(
  target: URL,
  port: number,
  init: EgressInit,
): Promise<{ status: number; headers: Record<string, string>; body: string; location?: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: LOOPBACK, port, path: target.pathname + target.search, method: init.method ?? 'GET', headers: init.headers ?? {} },
      (res) => {
        const chunks: Buffer[] = []
        let total = 0
        let truncated = false
        let done = false
        const finish = () => {
          if (done) return
          done = true
          const headers: Record<string, string> = {}
          for (const [k, v] of Object.entries(res.headers)) headers[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '')
          const location = Array.isArray(res.headers.location) ? res.headers.location[0] : res.headers.location
          resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString('utf8'), location })
        }
        res.on('data', (c: Buffer) => {
          if (truncated) return
          const room = MAX_BYTES - total
          if (c.length >= room) {
            chunks.push(c.subarray(0, room))
            total = MAX_BYTES
            truncated = true
            res.destroy()
          } else {
            chunks.push(c)
            total += c.length
          }
        })
        res.on('end', finish)
        res.on('close', finish)
      },
    )
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error('egress_timeout')))
    req.on('error', reject)
    if (init.body) req.write(init.body)
    req.end()
  })
}

export function createEgress(opts: {
  oracle: Oracle
  internalServices: InternalServiceRef[]
  oobCallbackPorts?: number[]
}): Egress {
  const { oracle } = opts
  const allowed = new Map<number, InternalServiceRef>()
  for (const s of opts.internalServices) allowed.set(s.port, { name: s.name, port: s.port, internal: s.internal })
  for (const p of opts.oobCallbackPorts ?? []) {
    if (!allowed.has(p)) allowed.set(p, { name: `oob:${p}`, port: p, internal: false })
  }

  return {
    async fetch(rawUrl, init = {}) {
      const routeKey = currentCtx()?.routeKey ?? null
      const baseDerived = init.inputDerived === true || isFromInput(rawUrl)
      let current = rawUrl
      for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        const v = validate(current, allowed)
        oracle.logEgress({ url: current, allowed: v.ok, reason: v.reason, routeKey })
        if (!v.ok || !v.target || !v.service) throw new Error(`egress blocked: ${v.reason}`)
        const derived =
          baseDerived || isFromInput(v.target.hostname) || isFromInput(String(v.port)) || isFromInput(v.target.pathname)
        if (v.service.internal && derived) {
          oracle.emit('ssrf_internal_fetch', { url: current, service: v.service.name, port: v.port }, `egress:${v.service.name}`)
        }
        const res = await doRequest(v.target, v.port, init)
        if (REDIRECT_STATUS.has(res.status) && res.location) {
          if (hop === MAX_REDIRECTS) throw new Error('egress blocked: too_many_redirects')
          current = new URL(res.location, v.target).toString()
          continue
        }
        return { status: res.status, headers: res.headers, body: res.body, url: current, allowed: true, reason: v.reason }
      }
      throw new Error('egress blocked: too_many_redirects')
    },
  }
}

export interface InternalService {
  name: string
  port: number
  internal: boolean
  stop(): Promise<void>
}

export async function startInternalService(opts: {
  name: string
  internal: boolean
  handler: (req: IncomingMessage, res: ServerResponse) => void
}): Promise<InternalService> {
  assertLocalLabAllowed()
  const server = http.createServer(opts.handler)
  const port = await listenLoopback(server)
  return { name: opts.name, port, internal: opts.internal, stop: () => closeServer(server) }
}
