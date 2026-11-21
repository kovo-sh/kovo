import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { createSocket } from 'node:dgram'
import type { RemoteInfo, Socket as DgramSocket } from 'node:dgram'
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
  enableDns?: boolean
  dnsHost?: string
  dnsPort?: number
  dnsSinkIp?: string
}

export interface CanaryDnsListenerOptions {
  dnsHost?: string
  dnsPort?: number
  dnsDomain?: string
  dnsSinkIp?: string
}

export interface CanaryListenerInfo {
  running: boolean
  host: string | null
  port: number | null
  localBaseUrl: string | null
  publicBaseUrl: string | null
  effectiveBaseUrl: string | null
  dnsDomain: string
  dnsRunning: boolean
  dnsHost: string | null
  dnsPort: number | null
}

export interface CanaryHit {
  protocol: 'http' | 'dns'
  token: string
  method: string
  path: string
  query: string
  queryType?: string
  dnsHost?: string
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
  dnsListenerActive: boolean
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

const dnsTypeNames: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  255: 'ANY',
}

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

function parsePort(explicit: number | undefined, envKey = 'GUARDIAN_CANARY_PORT'): number {
  if (typeof explicit === 'number' && Number.isInteger(explicit) && explicit >= 0 && explicit <= 65_535) {
    return explicit
  }
  const envRaw = process.env[envKey]?.trim()
  if (envRaw !== undefined && envRaw !== '') {
    const parsed = Number(envRaw)
    if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 65_535) return parsed
  }
  return 0
}

function parseIpv4Bytes(ip: string): Buffer {
  const parts = ip.trim().split('.').map(Number)
  if (parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
    return Buffer.from(parts)
  }
  return Buffer.from([127, 0, 0, 1])
}

interface ParsedDnsQuestion {
  id: number
  flags: number
  qname: string
  qtype: number
  qclass: number
  questionEndOffset: number
}

function parseDnsQuery(msg: Buffer): ParsedDnsQuestion | null {
  if (msg.length < 12) return null
  const id = msg.readUInt16BE(0)
  const flags = msg.readUInt16BE(2)
  const qr = (flags >> 15) & 1
  if (qr !== 0) return null // Not a query
  const qdcount = msg.readUInt16BE(4)
  if (qdcount < 1) return null

  const labels: string[] = []
  let offset = 12
  let safety = 0
  while (offset < msg.length && safety < 128) {
    safety += 1
    const len = msg[offset]
    if (len === 0) {
      offset += 1
      break
    }
    if ((len & 0xc0) !== 0) {
      // Compression pointers should not appear in the first question QNAME; reject malformed packets.
      return null
    }
    if (offset + 1 + len > msg.length) return null
    labels.push(msg.subarray(offset + 1, offset + 1 + len).toString('ascii'))
    offset += 1 + len
  }
  if (offset + 4 > msg.length) return null
  const qtype = msg.readUInt16BE(offset)
  const qclass = msg.readUInt16BE(offset + 2)
  const questionEndOffset = offset + 4
  const qname = labels.join('.').toLowerCase()
  return { id, flags, qname, qtype, qclass, questionEndOffset }
}

function buildDnsResponse(
  rawQuery: Buffer,
  parsed: ParsedDnsQuestion,
  hasValidToken: boolean,
  sinkIp: string,
): Buffer {
  const rd = parsed.flags & 0x0100
  const questionSection = rawQuery.subarray(12, parsed.questionEndOffset)

  if (!hasValidToken) {
    // Authoritative NXDOMAIN (QR=1, AA=1, RCODE=3)
    const header = Buffer.alloc(12)
    header.writeUInt16BE(parsed.id, 0)
    header.writeUInt16BE(0x8403 | rd, 2)
    header.writeUInt16BE(1, 4) // QDCOUNT
    header.writeUInt16BE(0, 6) // ANCOUNT
    header.writeUInt16BE(0, 8)
    header.writeUInt16BE(0, 10)
    return Buffer.concat([header, questionSection])
  }

  let rdata: Buffer | null = null
  let answerType = parsed.qtype
  if (parsed.qtype === 1 || parsed.qtype === 255) {
    // A record -> 127.0.0.1 (or configured sink IP)
    answerType = 1
    rdata = parseIpv4Bytes(sinkIp)
  } else if (parsed.qtype === 16) {
    // TXT record -> "guardian-canary-ok"
    const txt = Buffer.from('guardian-canary-ok', 'utf8')
    rdata = Buffer.concat([Buffer.from([txt.length]), txt])
  } else if (parsed.qtype === 28) {
    // AAAA record -> ::1
    rdata = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
  }

  const header = Buffer.alloc(12)
  header.writeUInt16BE(parsed.id, 0)
  header.writeUInt16BE(0x8400 | rd, 2) // QR=1, AA=1, RCODE=0
  header.writeUInt16BE(1, 4) // QDCOUNT
  header.writeUInt16BE(rdata ? 1 : 0, 6) // ANCOUNT
  header.writeUInt16BE(0, 8)
  header.writeUInt16BE(0, 10)

  if (!rdata) {
    return Buffer.concat([header, questionSection])
  }

  // Answer RR using compression pointer 0xc00c to QNAME at offset 12
  const answerPrefix = Buffer.alloc(12)
  answerPrefix.writeUInt16BE(0xc00c, 0)
  answerPrefix.writeUInt16BE(answerType, 2)
  answerPrefix.writeUInt16BE(1, 4) // CLASS IN
  answerPrefix.writeUInt32BE(60, 6) // TTL 60s
  answerPrefix.writeUInt16BE(rdata.length, 10)
  return Buffer.concat([header, questionSection, answerPrefix, rdata])
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
  const protocol: 'http' | 'dns' = detail.protocol === 'dns' || String(detail.method ?? '').toUpperCase() === 'DNS'
    ? 'dns'
    : 'http'
  return {
    protocol,
    token,
    method: String(detail.method ?? (protocol === 'dns' ? 'DNS' : 'GET')).toUpperCase().slice(0, 16),
    path: redact(String(detail.path ?? (protocol === 'dns' ? (detail.dnsHost ?? token) : `/c/${token}`))).slice(0, 512),
    query: redact(String(detail.query ?? (detail.queryType ?? ''))).slice(0, 512),
    ...(detail.queryType ? { queryType: String(detail.queryType).slice(0, 16) } : {}),
    ...(detail.dnsHost ? { dnsHost: redact(String(detail.dnsHost)).slice(0, 256) } : {}),
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
  private dnsSocket?: DgramSocket
  private boundHost: string | null = null
  private boundPort: number | null = null
  private dnsBoundHost: string | null = null
  private dnsBoundPort: number | null = null
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
      dnsRunning: Boolean(this.dnsSocket),
      dnsHost: this.dnsBoundHost,
      dnsPort: this.dnsBoundPort,
    }
  }

  async startDnsListener(options: CanaryDnsListenerOptions = {}): Promise<CanaryListenerInfo> {
    if (options.dnsDomain) {
      this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)
    }
    if (this.dnsSocket) {
      return this.listenerInfo()
    }

    const host = (options.dnsHost ?? process.env.GUARDIAN_CANARY_DNS_HOST ?? '127.0.0.1').trim() || '127.0.0.1'
    const port = parsePort(options.dnsPort, 'GUARDIAN_CANARY_DNS_PORT')
    const sinkIp = (options.dnsSinkIp ?? process.env.GUARDIAN_CANARY_DNS_SINK_IP ?? '127.0.0.1').trim() || '127.0.0.1'

    const socket = createSocket('udp4')
    socket.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
      try {
        const parsed = parseDnsQuery(msg)
        if (!parsed) return
        const match = tokenPattern.exec(parsed.qname)
        const token = match ? match[0].toLowerCase() : null
        const queryType = dnsTypeNames[parsed.qtype] ?? `TYPE${parsed.qtype}`
        const isValid = Boolean(token)
        if (token) {
          const now = Date.now()
          const hit: CanaryHit = {
            protocol: 'dns',
            token,
            method: 'DNS',
            path: redact(parsed.qname).slice(0, 512),
            query: queryType,
            queryType,
            dnsHost: redact(parsed.qname).slice(0, 256),
            remoteIp: (rinfo.address ?? '').slice(0, 128),
            userAgent: '',
            headers: {},
            receivedAt: new Date(now).toISOString(),
            timestamp: now,
          }
          this.appendHit(hit)
        }
        const response = buildDnsResponse(msg, parsed, isValid, sinkIp)
        socket.send(response, rinfo.port, rinfo.address, () => {
          // Best-effort UDP reply
        })
      } catch {
        // Drop malformed UDP packets silently
      }
    })

    socket.bind(port, host)
    await once(socket, 'listening')
    socket.unref()

    const addr = socket.address()
    this.dnsSocket = socket
    this.dnsBoundHost = addr.address
    this.dnsBoundPort = addr.port
    return this.listenerInfo()
  }

  async stopDnsListener(): Promise<void> {
    const sock = this.dnsSocket
    this.dnsSocket = undefined
    this.dnsBoundHost = null
    this.dnsBoundPort = null
    if (!sock) return
    await new Promise<void>(resolve => {
      try {
        sock.close(() => resolve())
      } catch {
        resolve()
      }
    })
  }

  async startListener(options: CanaryListenerOptions = {}): Promise<CanaryListenerInfo> {
    const resolvedPublic = normalizePublicBaseUrl(
      options.publicBaseUrl ?? process.env.GUARDIAN_CANARY_PUBLIC_URL ?? process.env.GUARDIAN_CANARY_BASE_URL,
    )
    if (resolvedPublic) this.publicBaseUrl = resolvedPublic
    this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)

    const shouldStartDns = Boolean(
      options.enableDns ||
      options.dnsHost !== undefined ||
      options.dnsPort !== undefined ||
      process.env.GUARDIAN_CANARY_DNS_HOST ||
      process.env.GUARDIAN_CANARY_DNS_PORT,
    )

    if (!this.server) {
      const host = (options.host ?? process.env.GUARDIAN_CANARY_HOST ?? '127.0.0.1').trim() || '127.0.0.1'
      const port = parsePort(options.port, 'GUARDIAN_CANARY_PORT')

      const server = createServer((req, res) => {
        // Drain inbound request body without buffering untrusted payloads.
        req.resume()
        try {
          const url = new URL(req.url ?? '/', `http://${formatHostForUrl(host)}`)
          const token = extractTokenFromRequest(url, req.headers.host)
          if (token) {
            const now = Date.now()
            const hit: CanaryHit = {
              protocol: 'http',
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
    }

    if (shouldStartDns && !this.dnsSocket) {
      await this.startDnsListener({
        dnsHost: options.dnsHost,
        dnsPort: options.dnsPort,
        dnsDomain: options.dnsDomain,
        dnsSinkIp: options.dnsSinkIp,
      })
    }

    return this.listenerInfo()
  }

  async stopListener(): Promise<void> {
    await this.stopDnsListener()
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
      dnsListenerActive: Boolean(this.dnsSocket),
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
