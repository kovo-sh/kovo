import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingHttpHeaders, Server } from 'node:http'
import { isIP } from 'node:net'
import { and, eq } from 'drizzle-orm'
import { redact, redactHeaders } from './redact.ts'
import { canaries } from './schema.ts'
import type { Store } from './store.ts'

export interface CanaryListenerOptions {
  host?: string
  port?: number
  publicBaseUrl?: string
  dnsDomain?: string
}

export interface CanaryListenerInfo {
  running: boolean
  host: string | null
  port: number | null
  localBaseUrl: string | null
  publicBaseUrl: string | null
  effectiveBaseUrl: string | null
  dnsDomain: string
}

export interface CanaryHit {
  token: string
  method: string
  path: string
  query: string
  remoteIp: string
  userAgent: string
  headers: Record<string, string>
  receivedAt: string
  timestamp: number
}

export interface MintedCanary {
  id: string
  token: string
  runId: string
  label: string
  origin: string | null
  httpUrl: string
  url: string
  dnsHost: string
  listenerActive: boolean
  synthetic: boolean
}

export interface CanaryCheckResult {
  found: boolean
  hit: boolean
  triggered: boolean
  hits: CanaryHit[]
  detail: Record<string, unknown> | null
}

interface MintedMeta {
  id: string
  runId: string
  label: string
  origin: string | null
  storage?: Store
  createdAt: number
}

const tokenPattern = /guardian-canary-[a-f0-9]{24}/i
const maxHitsPerToken = 50
const maxTrackedTokens = 5_000
const defaultDnsDomain = 'canary.guardian.invalid'

function normalizePublicBaseUrl(raw: string | undefined): string | null {
  if (!raw) return null
  const trimmed = raw.trim().replace(/\/+$/, '')
  if (!trimmed) return null
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, '')
  } catch {
    return null
  }
}

function inferDnsDomain(explicit: string | undefined, publicBaseUrl: string | null): string {
  const fromExplicit = explicit?.trim().toLowerCase().replace(/^\.+|\.+$/g, '')
  if (fromExplicit) return fromExplicit
  const fromEnv = process.env.GUARDIAN_CANARY_DNS_DOMAIN?.trim().toLowerCase().replace(/^\.+|\.+$/g, '')
  if (fromEnv) return fromEnv
  if (publicBaseUrl) {
    try {
      const host = new URL(publicBaseUrl).hostname.toLowerCase()
      if (host && host !== 'localhost' && isIP(host) === 0) return host
    } catch { /* fall through */ }
  }
  return defaultDnsDomain
}

function parsePort(explicit: number | undefined): number {
  if (typeof explicit === 'number' && Number.isInteger(explicit) && explicit >= 0 && explicit <= 65_535) {
    return explicit
  }
  const envRaw = process.env.GUARDIAN_CANARY_PORT?.trim()
  if (envRaw !== undefined && envRaw !== '') {
    const parsed = Number(envRaw)
    if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 65_535) return parsed
  }
  return 0
}

function normalizeIncomingHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue
    out[k.toLowerCase()] = (Array.isArray(v) ? v.join(', ') : String(v)).slice(0, 1024)
  }
  return redactHeaders(out)
}

function extractTokenFromRequest(url: URL, hostHeader: string | undefined): string | null {
  const pathMatch = tokenPattern.exec(url.pathname)
  if (pathMatch) return pathMatch[0].toLowerCase()
  const queryMatch = tokenPattern.exec(url.search)
  if (queryMatch) return queryMatch[0].toLowerCase()
  if (hostHeader) {
    const hostMatch = tokenPattern.exec(hostHeader)
    if (hostMatch) return hostMatch[0].toLowerCase()
  }
  return null
}

function formatHostForUrl(host: string): string {
  if (host === '0.0.0.0' || host === '::') return '127.0.0.1'
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host
}

function detailToCanaryHit(token: string, detail: Record<string, unknown>): CanaryHit {
  const rawHeaders = detail.headers && typeof detail.headers === 'object' && !Array.isArray(detail.headers)
    ? Object.fromEntries(
        Object.entries(detail.headers as Record<string, unknown>)
          .map(([k, v]) => [k.toLowerCase(), String(v ?? '').slice(0, 1024)]),
      )
    : {}
  const receivedAt = typeof detail.receivedAt === 'string' ? detail.receivedAt : new Date().toISOString()
  const parsedTs = typeof detail.timestamp === 'number' ? detail.timestamp : Date.parse(receivedAt)
  return {
    token,
    method: String(detail.method ?? 'GET').toUpperCase().slice(0, 16),
    path: redact(String(detail.path ?? `/c/${token}`)).slice(0, 512),
    query: redact(String(detail.query ?? '')).slice(0, 512),
    remoteIp: String(detail.remoteIp ?? '').slice(0, 128),
    userAgent: redact(String(detail.userAgent ?? '')).slice(0, 200),
    headers: redactHeaders(rawHeaders),
    receivedAt,
    timestamp: Number.isFinite(parsedTs) ? parsedTs : Date.now(),
  }
}

export class CanaryBroker {
  private readonly secret = randomBytes(32)
  private readonly defaultStorage?: Store
  private server?: Server
  private boundHost: string | null = null
  private boundPort: number | null = null
  private localBaseUrl: string | null = null
  private publicBaseUrl: string | null = null
  private dnsDomain: string
  private readonly minted = new Map<string, MintedMeta>()
  private readonly hitsByToken = new Map<string, CanaryHit[]>()

  constructor(options: { storage?: Store; dnsDomain?: string } = {}) {
    this.defaultStorage = options.storage
    this.publicBaseUrl = normalizePublicBaseUrl(
      process.env.GUARDIAN_CANARY_PUBLIC_URL ?? process.env.GUARDIAN_CANARY_BASE_URL,
    )
    this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)
  }

  private effectiveBaseUrl(): string | null {
    return this.publicBaseUrl ?? this.localBaseUrl
  }

  listenerInfo(): CanaryListenerInfo {
    return {
      running: Boolean(this.server),
      host: this.boundHost,
      port: this.boundPort,
      localBaseUrl: this.localBaseUrl,
      publicBaseUrl: this.publicBaseUrl,
      effectiveBaseUrl: this.effectiveBaseUrl(),
      dnsDomain: this.dnsDomain,
    }
  }

  async startListener(options: CanaryListenerOptions = {}): Promise<CanaryListenerInfo> {
    const resolvedPublic = normalizePublicBaseUrl(
      options.publicBaseUrl ?? process.env.GUARDIAN_CANARY_PUBLIC_URL ?? process.env.GUARDIAN_CANARY_BASE_URL,
    )
    if (resolvedPublic) this.publicBaseUrl = resolvedPublic
    this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)

    if (this.server) {
      return this.listenerInfo()
    }

    const host = (options.host ?? process.env.GUARDIAN_CANARY_HOST ?? '127.0.0.1').trim() || '127.0.0.1'
    const port = parsePort(options.port)

    const server = createServer((req, res) => {
      // Drain inbound request body without buffering untrusted payloads.
      req.resume()
      try {
        const url = new URL(req.url ?? '/', `http://${formatHostForUrl(host)}`)
        const token = extractTokenFromRequest(url, req.headers.host)
        if (token) {
          const now = Date.now()
          const hit: CanaryHit = {
            token,
            method: (req.method ?? 'GET').toUpperCase().slice(0, 16),
            path: redact(url.pathname).slice(0, 512),
            query: redact(url.search).slice(0, 512),
            remoteIp: (req.socket?.remoteAddress ?? '').slice(0, 128),
            userAgent: redact(String(req.headers['user-agent'] ?? '')).slice(0, 200),
            headers: normalizeIncomingHeaders(req.headers),
            receivedAt: new Date(now).toISOString(),
            timestamp: now,
          }
          this.appendHit(hit)
        }
      } catch {
        // Ignore malformed URLs on callback listener; still return benign 200.
      }
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        connection: 'close',
      }).end('guardian-canary-ok')
    })

    server.listen(port, host)
    await once(server, 'listening')
    server.unref()

    const addr = server.address()
    if (!addr || typeof addr === 'string') {
      server.close()
      throw new Error('Could not bind local canary listener.')
    }
    this.server = server
    this.boundHost = addr.address
    this.boundPort = addr.port
    this.localBaseUrl = `http://${formatHostForUrl(addr.address)}:${addr.port}`
    return this.listenerInfo()
  }

  async stopListener(): Promise<void> {
    const srv = this.server
    this.server = undefined
    this.boundHost = null
    this.boundPort = null
    this.localBaseUrl = null
    if (!srv) return
    srv.closeAllConnections?.()
    await new Promise<void>(resolve => srv.close(() => resolve()))
  }

  /** Backwards-compatible alias returning the effective callback base URL. */
  async startLocalListener(options: CanaryListenerOptions = {}): Promise<string> {
    const info = await this.startListener(options)
    if (!info.effectiveBaseUrl) throw new Error('Canary listener did not produce a base URL.')
    return info.effectiveBaseUrl
  }

  /** Backwards-compatible alias for stopListener(). */
  async stop(): Promise<void> {
    await this.stopListener()
    this.publicBaseUrl = null
  }

  private appendHit(hit: CanaryHit) {
    let list = this.hitsByToken.get(hit.token)
    if (!list) {
      if (this.hitsByToken.size >= maxTrackedTokens) {
        const oldestKey = this.hitsByToken.keys().next().value
        if (oldestKey) this.hitsByToken.delete(oldestKey)
      }
      list = []
      this.hitsByToken.set(hit.token, list)
    }
    if (list.length < maxHitsPerToken) {
      list.push(hit)
    }

    const meta = this.minted.get(hit.token)
    const storage = meta?.storage ?? this.defaultStorage
    if (storage && meta) {
      try {
        storage.db.update(canaries).set({
          triggered: true,
          triggerDetail: {
            ...hit,
            hitCount: list.length,
            hits: list.slice(-10),
          },
          triggeredAt: hit.timestamp,
        }).where(eq(canaries.id, meta.id)).run()
      } catch {
        // Best-effort persistence if DB is closed or token is in-memory only.
      }
    }
  }

  recordCallback(token: string, detail: Record<string, unknown>) {
    const normalized = token.trim().toLowerCase()
    const hit = detailToCanaryHit(normalized, detail)
    this.appendHit(hit)
  }

  mintCanary(
    runId: string,
    label: string,
    origin?: string,
    options?: { storage?: Store; assignmentId?: string },
  ): MintedCanary {
    const id = randomUUID()
    const digest = createHmac('sha256', this.secret)
      .update(runId)
      .update(id)
      .update(randomBytes(8))
      .digest('hex')
      .slice(0, 24)
    const token = `guardian-canary-${digest}`
    const createdAt = Date.now()
    const storage = options?.storage ?? this.defaultStorage

    if (this.minted.size >= maxTrackedTokens) {
      const oldestKey = this.minted.keys().next().value
      if (oldestKey) this.minted.delete(oldestKey)
    }
    this.minted.set(token, {
      id,
      runId,
      label,
      origin: origin ?? null,
      storage,
      createdAt,
    })

    if (storage) {
      const purpose = (origin ? `${label} (${origin})` : label).slice(0, 200)
      storage.db.insert(canaries).values({
        id,
        runId,
        assignmentId: options?.assignmentId ?? 'canary-broker',
        token,
        purpose,
        triggered: false,
        createdAt,
      }).run()
    }

    const effective = this.effectiveBaseUrl()
    const dnsHost = `${token}.${this.dnsDomain}`
    const httpUrl = effective ? `${effective}/c/${token}` : `https://${this.dnsDomain}/c/${token}`

    return {
      id,
      token,
      runId,
      label,
      origin: origin ?? null,
      httpUrl,
      url: httpUrl,
      dnsHost,
      listenerActive: Boolean(this.server),
      synthetic: !effective,
    }
  }

  checkCanary(token: string, options?: { storage?: Store; runId?: string }): CanaryCheckResult {
    const normalized = token.trim().toLowerCase()
    const meta = this.minted.get(normalized)
    const storage = options?.storage ?? meta?.storage ?? this.defaultStorage
    const runId = options?.runId ?? meta?.runId

    const memHits = [...(this.hitsByToken.get(normalized) ?? [])]
    let row: typeof canaries.$inferSelect | undefined
    if (storage) {
      try {
        row = runId
          ? storage.db.select().from(canaries).where(and(eq(canaries.runId, runId), eq(canaries.token, normalized))).get()
          : storage.db.select().from(canaries).where(eq(canaries.token, normalized)).get()
      } catch {
        row = undefined
      }
    }

    if (row && memHits.length > 0 && !row.triggered) {
      const latest = memHits[memHits.length - 1]
      try {
        storage!.db.update(canaries).set({
          triggered: true,
          triggerDetail: {
            ...latest,
            hitCount: memHits.length,
            hits: memHits.slice(-10),
          },
          triggeredAt: latest.timestamp,
        }).where(eq(canaries.id, row.id)).run()
      } catch { /* ignore */ }
    }

    let hits = memHits
    if (hits.length === 0 && row?.triggered && row.triggerDetail) {
      const storedHits = Array.isArray((row.triggerDetail as { hits?: unknown[] }).hits)
        ? ((row.triggerDetail as { hits: Record<string, unknown>[] }).hits).map(item => detailToCanaryHit(normalized, item))
        : [detailToCanaryHit(normalized, row.triggerDetail)]
      hits = storedHits
    }

    const found = Boolean(meta || row || hits.length > 0)
    const hit = hits.length > 0 || Boolean(row?.triggered)
    const latestHit = hits.length > 0 ? hits[hits.length - 1] : null
    const detail: Record<string, unknown> | null = latestHit
      ? { ...latestHit, hitCount: hits.length }
      : (row?.triggerDetail ?? null)

    return { found, hit, triggered: hit, hits, detail }
  }

  /** Backwards-compatible DB-backed mint method. */
  mint(
    storage: Store,
    runId: string,
    assignmentId: string,
    purpose: string,
  ): { id: string; token: string; url: string | null; httpUrl: string; dnsHost: string } {
    const minted = this.mintCanary(runId, purpose, undefined, { storage, assignmentId })
    return {
      id: minted.id,
      token: minted.token,
      url: this.effectiveBaseUrl() ? minted.httpUrl : null,
      httpUrl: minted.httpUrl,
      dnsHost: minted.dnsHost,
    }
  }

  /** Backwards-compatible DB-backed check method. */
  check(storage: Store, runId: string, token: string): CanaryCheckResult {
    const row = storage.db.select().from(canaries).where(and(eq(canaries.runId, runId), eq(canaries.token, token))).get()
    if (!row) return { found: false, hit: false, triggered: false, hits: [], detail: null }
    return this.checkCanary(token, { storage, runId })
  }
}
