import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { createSocket } from 'node:dgram'
import type { RemoteInfo, Socket as DgramSocket } from 'node:dgram'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import type { Server as HttpsServer } from 'node:https'
import { createServer as createTcpServer, isIP } from 'node:net'
import type { Server as NetServer } from 'node:net'
import { and, eq } from 'drizzle-orm'
import {
  OobProfileError,
  OobRelay,
  assertPublicProfileStartable,
  resolveOobRelayProfile,
} from './oob-relay.ts'
import type {
  OobAwaitOptions,
  OobCallback,
  OobCallbackInput,
  OobCorrelationResult,
  OobCorrelateOptions,
  OobDnsAnswer,
  OobDnsProvider,
  OobDnsQuery,
  OobPromotion,
  OobPublicRelayConfig,
  OobQuotaTelemetry,
  OobRecordResult,
  OobRelayProfile,
  OobRelayStatus,
  OobSubscription,
  OobSubscriptionInput,
  OobUnsubscribeRunResult,
} from './oob-relay.ts'
import { cancelOobDrainForRun } from './oob-drain.ts'
import { redact, redactHeaders } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { assertValidRunId } from './run-context.ts'
import { canaries } from './schema.ts'
import type { Store } from './store.ts'

export interface SecondOrderCanaryRecord {
  id: string
  runId: string
  assignmentId: string
  marker: string
  injectedOrigin: string
  injectedEndpoint: string
  injectedParam: string
  injectedPersona: string | null
  surfacedOrigin: string | null
  surfacedEndpoint: string | null
  surfacedPersona: string | null
  surfacedExchangeId: string | null
  status: string
  createdAt: number
  surfacedAt: number | null
}

export interface SecondOrderStore {
  insertSecondOrderCanary(input: {
    runId: string
    assignmentId: string
    marker: string
    injectedOrigin: string
    injectedEndpoint: string
    injectedParam: string
    injectedPersona?: string | null
  }): SecondOrderCanaryRecord
  markSecondOrderCanarySurfaced(
    id: string,
    details: {
      surfacedOrigin: string
      surfacedEndpoint: string
      surfacedPersona?: string | null
      surfacedExchangeId?: string | null
      status?: 'surfaced' | 'verified'
    },
  ): SecondOrderCanaryRecord
  listSecondOrderCanaries(runId: string, status?: 'planted' | 'surfaced' | 'verified'): SecondOrderCanaryRecord[]
  /**
   * Structured run event sink. Optional so embedding harnesses can supply only the canary API; the
   * broker uses it best-effort for transport-level invariants (e.g. persona scope mismatches).
   */
  event?(runId: string | null, kind: string, message: string, detail?: Record<string, unknown>): unknown
  runDetail?(runId: string): {
    run: { id: string; scopeRevision: number }
    assignments: Array<{ id: string; goalRevision: number; sourceOrigins: string[] }>
  }
  addFact?(run: never, assignment: never, input: {
    kind: 'note'
    origin: string
    summary: string
    data?: Record<string, unknown>
    evidenceIds?: string[]
    exchangeIds?: string[]
    sourceOrigins?: string[]
    secrets?: readonly NamedSecret[]
  }): unknown
}

export interface CanaryListenerOptions {
  host?: string
  port?: number
  publicBaseUrl?: string
  dnsDomain?: string
  enableDns?: boolean
  dnsHost?: string
  dnsPort?: number
  dnsSinkIp?: string
  /** Optional authoritative DNS hook; consulted before the built-in token answers. */
  dnsProvider?: OobDnsProvider
  /** Override the HTTP callback handler (used by the public profile for ACME HTTP-01). */
  httpHandler?: (req: IncomingMessage, res: ServerResponse) => void
}

export interface CanaryPublicListenerOptions {
  /** Open the HTTPS callback listener (requires ACME hooks or cert/key files). */
  https?: boolean
  /** Open the authoritative TCP DNS listener (public profile only). */
  dnsTcp?: boolean
  /** Delegate SMTP ingestion to the operator-provided provider. */
  smtp?: boolean
}

export interface CanaryDnsListenerOptions {
  dnsHost?: string
  dnsPort?: number
  dnsDomain?: string
  dnsSinkIp?: string
  dnsProvider?: OobDnsProvider
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
  /** Public profile listeners only ever open through explicit activation. */
  publicProfileActive: boolean
  httpsRunning: boolean
  httpsPort: number | null
  dnsTcpRunning: boolean
  dnsTcpPort: number | null
  smtpRunning: boolean
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
  /** Bounded (<=4 KiB), redacted preview of an HTTP POST/webhook callback body. */
  bodyPreview?: string
  bodyBytes?: number
  /** Causal artifact supplied by the verifier when it minted the callback URL. */
  artifact?: string
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
  storage?: Store | SecondOrderStore
  createdAt: number
}

export interface MintedSecondOrderCanary {
  id?: string
  marker: string
  runId: string
  assignmentId: string
  injectedOrigin: string
  injectedEndpoint: string
  injectedParam: string
  injectedPersona: string | null
  httpUrl: string
  dnsHost: string
}

interface MintedSecondOrderMeta {
  id?: string
  runId: string
  assignmentId: string
  injectedOrigin: string
  injectedEndpoint: string
  injectedParam: string
  injectedPersona: string | null
  storage?: Store | SecondOrderStore
}

const tokenPattern = /kovo-canary-[a-f0-9]{24}/i
const secondOrderPattern = /gn2o_[a-f0-9]{8,16}/i
const secondOrderGlobalPattern = /gn2o_[a-f0-9]{8,16}/gi
const maxHitsPerToken = 50
const maxTrackedTokens = 5_000
const defaultDnsDomain = 'canary.kovo.invalid'

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

function isFullStore(s: Store | SecondOrderStore | undefined): s is Store {
  return Boolean(s && 'db' in s && (s as Store).db)
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
  const fromEnv = process.env.KOVO_CANARY_DNS_DOMAIN?.trim().toLowerCase().replace(/^\.+|\.+$/g, '')
  if (fromEnv) return fromEnv
  if (publicBaseUrl) {
    try {
      const host = new URL(publicBaseUrl).hostname.toLowerCase()
      if (host && host !== 'localhost' && isIP(host) === 0) return host
    } catch { /* fall through */ }
  }
  return defaultDnsDomain
}

function parsePort(explicit: number | undefined, envKey = 'KOVO_CANARY_PORT'): number {
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
    // TXT record -> "kovo-canary-ok"
    const txt = Buffer.from('kovo-canary-ok', 'utf8')
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

function encodeDnsName(name: string): Buffer {
  const labels = name.replace(/\.+$/, '').split('.').filter(Boolean)
  const parts: Buffer[] = []
  for (const label of labels) {
    const bytes = Buffer.from(label, 'ascii').subarray(0, 63)
    parts.push(Buffer.from([bytes.length]), bytes)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

function answerToRdata(answer: OobDnsAnswer): { type: number; rdata: Buffer } | null {
  switch (answer.type) {
    case 'A':
      return { type: 1, rdata: parseIpv4Bytes(answer.value) }
    case 'AAAA': {
      const groups = answer.value.split(':')
      if (groups.length < 3) return null
      const buf = Buffer.alloc(16)
      // Minimal expansion for full-form IPv6 answers; compressed forms fall back to ::1.
      if (groups.length === 8) {
        groups.forEach((group, index) => buf.writeUInt16BE(parseInt(group, 16) || 0, index * 2))
        return { type: 28, rdata: buf }
      }
      return { type: 28, rdata: Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) }
    }
    case 'TXT': {
      const text = Buffer.from(answer.value, 'utf8').subarray(0, 255)
      return { type: 16, rdata: Buffer.concat([Buffer.from([text.length]), text]) }
    }
    case 'CNAME':
      return { type: 5, rdata: encodeDnsName(answer.value) }
    case 'NS':
      return { type: 2, rdata: encodeDnsName(answer.value) }
    default:
      return null
  }
}

/** Build a DNS response from an authoritative provider answer (TXT/A/AAAA/CNAME/NS). */
function buildDnsResponseWithAnswer(
  rawQuery: Buffer,
  parsed: ParsedDnsQuestion,
  answer: OobDnsAnswer,
): Buffer {
  const rd = parsed.flags & 0x0100
  const questionSection = rawQuery.subarray(12, parsed.questionEndOffset)
  const encoded = answerToRdata(answer)
  const header = Buffer.alloc(12)
  header.writeUInt16BE(parsed.id, 0)
  header.writeUInt16BE(0x8400 | rd, 2) // QR=1, AA=1, RCODE=0
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE(encoded ? 1 : 0, 6)
  header.writeUInt16BE(0, 8)
  header.writeUInt16BE(0, 10)
  if (!encoded) return Buffer.concat([header, questionSection])
  const answerPrefix = Buffer.alloc(12)
  answerPrefix.writeUInt16BE(0xc00c, 0)
  answerPrefix.writeUInt16BE(encoded.type, 2)
  answerPrefix.writeUInt16BE(1, 4)
  answerPrefix.writeUInt32BE(Math.max(0, Math.min(86_400, answer.ttl ?? 60)), 6)
  answerPrefix.writeUInt16BE(encoded.rdata.length, 10)
  return Buffer.concat([header, questionSection, answerPrefix, encoded.rdata])
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
  const pathMatch = tokenPattern.exec(url.pathname) ?? secondOrderPattern.exec(url.pathname)
  if (pathMatch) return pathMatch[0].toLowerCase()
  const queryMatch = tokenPattern.exec(url.search) ?? secondOrderPattern.exec(url.search)
  if (queryMatch) return queryMatch[0].toLowerCase()
  if (hostHeader) {
    const hostMatch = tokenPattern.exec(hostHeader) ?? secondOrderPattern.exec(hostHeader)
    if (hostMatch) return hostMatch[0].toLowerCase()
  }
  return null
}

/** Causal artifact carried by a callback (`g_art` query param or `x-kovo-artifact`). */
function extractArtifact(url: URL, headerValue: string | string[] | undefined): string | undefined {
  const fromQuery = url.searchParams.get('g_art') ?? url.searchParams.get('artifact')
  if (fromQuery && fromQuery.trim()) return fromQuery.trim().slice(0, 256)
  const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue
  if (raw && raw.trim()) return raw.trim().slice(0, 256)
  return undefined
}

function recordSecondOrderSurfaceFact(
  storage: SecondOrderStore,
  runId: string,
  assignmentId: string | undefined,
  canary: SecondOrderCanaryRecord,
  surfacedOrigin: string,
  surfacedEndpoint: string,
  surfacedPersona: string | null,
  exchangeId: string | null,
  extra?: { mediaType?: string | null; surfaces?: SecondOrderSurface[] },
) {
  if (!storage.runDetail || !storage.addFact) return
  try {
    const detail = storage.runDetail(runId)
    const assignment = (assignmentId
      ? detail.assignments.find(a => a.id === assignmentId)
      : undefined) ?? detail.assignments[0]
    if (!detail?.run || !assignment) return
    const addFactFn = storage.addFact as unknown as (
      run: unknown,
      assignment: unknown,
      input: {
        kind: string
        origin: string
        summary: string
        data?: Record<string, unknown>
        evidenceIds?: string[]
        exchangeIds?: string[]
        sourceOrigins?: string[]
      },
    ) => unknown
    addFactFn.call(storage, detail.run, assignment, {
      kind: 'second_order_surface',
      origin: surfacedOrigin,
      summary: `High-priority second-order canary ${canary.marker} surfaced on ${surfacedOrigin}${surfacedEndpoint} (injected via ${canary.injectedOrigin}${canary.injectedEndpoint} param=${canary.injectedParam}).`,
      data: {
        subkind: 'second_order_surface',
        priority: 'high',
        canaryId: canary.id,
        marker: canary.marker,
        injectedOrigin: canary.injectedOrigin,
        injectedEndpoint: canary.injectedEndpoint,
        injectedParam: canary.injectedParam,
        injectedPersona: canary.injectedPersona,
        surfacedOrigin,
        surfacedEndpoint,
        surfacedPersona,
        surfacedExchangeId: exchangeId,
        surfacedMediaType: extra?.mediaType ?? null,
        crossPersona: (canary.injectedPersona ?? null) !== (surfacedPersona ?? null),
        surfaces: (extra?.surfaces ?? []).slice(-20),
      },
      ...(exchangeId ? { exchangeIds: [exchangeId] } : {}),
      sourceOrigins: [canary.injectedOrigin, surfacedOrigin],
    })
  } catch {
    // Best-effort fact recording if DB closed or assignment missing.
  }
}

export interface ScanSecondOrderInput {
  text: string
  runId?: string
  assignmentId?: string
  origin: string
  endpoint: string
  persona?: string | null
  mediaType?: string | null
  exchangeId?: string | null
  storage?: SecondOrderStore
}

export interface SecondOrderSurface {
  origin: string
  endpoint: string
  persona: string | null
  mediaType: string | null
  exchangeId: string | null
  observedAt: number
}

const maxTrackedSecondOrderSurfaces = 5_000
const maxSurfacesPerCanary = 20
/** Distinct surfaces already observed per canary id, keyed `(origin, endpoint, persona, mediaType)`. */
const observedSecondOrderSurfaces = new Map<string, Map<string, SecondOrderSurface>>()
/** Secondary runId -> canaryIds index so `unsubscribeRun(runId)` evicts observed surfaces cleanly. */
const observedSecondOrderByRun = new Map<string, Set<string>>()

function normalizeSurfaceEndpoint(endpoint: string): string {
  const pathOnly = endpoint.split('?')[0].split('#')[0].trim()
  if (!pathOnly) return '/'
  const withSlash = pathOnly.startsWith('/') ? pathOnly : `/${pathOnly}`
  const collapsed = withSlash.replace(/\/{2,}/g, '/')
  return collapsed.length > 1 ? collapsed.replace(/\/+$/, '').toLowerCase() : collapsed.toLowerCase()
}

function recordObservedSurface(
  canaryId: string,
  input: ScanSecondOrderInput,
): { isNew: boolean; surfaces: SecondOrderSurface[] } {
  let byKey = observedSecondOrderSurfaces.get(canaryId)
  if (!byKey) {
    if (observedSecondOrderSurfaces.size >= maxTrackedSecondOrderSurfaces) {
      const oldest = observedSecondOrderSurfaces.keys().next().value
      if (oldest !== undefined) observedSecondOrderSurfaces.delete(oldest)
    }
    byKey = new Map<string, SecondOrderSurface>()
    observedSecondOrderSurfaces.set(canaryId, byKey)
  }
  if (input.runId) {
    let runCanaries = observedSecondOrderByRun.get(input.runId)
    if (!runCanaries) {
      runCanaries = new Set<string>()
      observedSecondOrderByRun.set(input.runId, runCanaries)
    }
    runCanaries.add(canaryId)
  }
  const endpoint = normalizeSurfaceEndpoint(input.endpoint)
  const mediaType = input.mediaType?.trim().toLowerCase() || null
  const persona = input.persona?.trim() || null
  const key = `${input.origin}|${endpoint}|${persona ?? ''}|${mediaType ?? ''}`
  const isNew = !byKey.has(key)
  if (isNew) {
    if (byKey.size >= maxSurfacesPerCanary) {
      const oldest = byKey.keys().next().value
      if (oldest !== undefined) byKey.delete(oldest)
    }
    byKey.set(key, {
      origin: input.origin,
      endpoint,
      persona,
      mediaType,
      exchangeId: input.exchangeId ?? null,
      observedAt: Date.now(),
    })
  }
  return { isNew, surfaces: [...byKey.values()] }
}

/** Test/diagnostic helper: drop in-memory surface tracking. */
export function resetSecondOrderSurfaceTracking(): void {
  observedSecondOrderSurfaces.clear()
  observedSecondOrderByRun.clear()
}

/** Evict all in-memory second-order surface entries owned by `runId`. */
export function evictSecondOrderSurfacesForRun(runId: string): number {
  const ids = observedSecondOrderByRun.get(runId)
  if (!ids) return 0
  let removed = 0
  for (const canaryId of ids) {
    if (observedSecondOrderSurfaces.delete(canaryId)) removed += 1
  }
  observedSecondOrderByRun.delete(runId)
  return removed
}

/** Diagnostic count of tracked second-order canary surface sets (tests/telemetry). */
export function trackedSecondOrderSurfaceCount(runId?: string): number {
  if (runId !== undefined) return observedSecondOrderByRun.get(runId)?.size ?? 0
  return observedSecondOrderSurfaces.size
}

export function scanSecondOrderMarkers(input: ScanSecondOrderInput): SecondOrderCanaryRecord[] {
  if (!input.runId || !input.storage || !input.text || !input.text.includes('gn2o_')) {
    return []
  }
  const matches = input.text.match(secondOrderGlobalPattern)
  if (!matches || matches.length === 0) return []
  const found = new Set(matches.map(m => m.toLowerCase()))

  let known: SecondOrderCanaryRecord[] = []
  try {
    // Track every canary for the run, not only `planted`: a single early benign JSON echo used to
    // move the row to `surfaced`, permanently blinding cross-persona/admin renders afterwards.
    known = input.storage.listSecondOrderCanaries(input.runId)
  } catch {
    return []
  }
  if (known.length === 0) return []

  const surfacedRecords: SecondOrderCanaryRecord[] = []
  const bareEndpoint = input.endpoint.split('?')[0]
  for (const canary of known) {
    if (!found.has(canary.marker.toLowerCase())) continue
    if (canary.status === 'retired') continue
    const sameOrigin = canary.injectedOrigin === input.origin
    const sameEndpoint = canary.injectedEndpoint === input.endpoint || canary.injectedEndpoint === bareEndpoint
    const samePersona = (canary.injectedPersona ?? null) === (input.persona ?? null)
    if (sameOrigin && sameEndpoint && samePersona) {
      // Benign self-echo (injecting persona viewing its own value) is not evidence of a surface.
      continue
    }

    const { isNew, surfaces } = recordObservedSurface(canary.id, input)
    if (!isNew) continue

    const isFirstSurface = canary.status === 'planted'
    let record: SecondOrderCanaryRecord = canary
    if (isFirstSurface) {
      try {
        record = input.storage.markSecondOrderCanarySurfaced(canary.id, {
          surfacedOrigin: input.origin,
          surfacedEndpoint: input.endpoint,
          surfacedPersona: input.persona ?? null,
          surfacedExchangeId: input.exchangeId ?? null,
          status: 'surfaced',
        })
      } catch {
        // Best-effort update if DB closed concurrently; still record the surface fact.
      }
    }
    recordSecondOrderSurfaceFact(
      input.storage,
      input.runId,
      input.assignmentId ?? canary.assignmentId,
      record,
      input.origin,
      input.endpoint,
      input.persona ?? null,
      input.exchangeId ?? null,
      { mediaType: input.mediaType ?? null, surfaces },
    )
    surfacedRecords.push(record)
  }
  return surfacedRecords
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
    ...(typeof detail.artifact === 'string' && detail.artifact.trim()
      ? { artifact: detail.artifact.trim().slice(0, 256) }
      : {}),
    receivedAt,
    timestamp: Number.isFinite(parsedTs) ? parsedTs : Date.now(),
  }
}

export class CanaryBroker {
  private readonly secret = randomBytes(32)
  private readonly defaultStorage?: Store | SecondOrderStore
  private readonly now: () => number
  private readonly oobRelayInstance: OobRelay
  private readonly publicProfileConfig?: OobPublicRelayConfig
  private server?: Server
  private httpsServer?: HttpsServer
  private dnsSocket?: DgramSocket
  private dnsTcpServer?: NetServer
  private smtpStarted = false
  private publicProfileActive = false
  private boundHost: string | null = null
  private boundPort: number | null = null
  private httpsBoundPort: number | null = null
  private dnsBoundHost: string | null = null
  private dnsBoundPort: number | null = null
  private dnsTcpBoundPort: number | null = null
  private localBaseUrl: string | null = null
  private publicBaseUrl: string | null = null
  private dnsDomain: string
  private dnsProvider?: OobDnsProvider
  private dnsSinkIp = '127.0.0.1'
  private activeRelayProfile?: OobRelayProfile
  private readonly minted = new Map<string, MintedMeta>()
  private readonly mintedSecondOrder = new Map<string, MintedSecondOrderMeta>()
  private readonly hitsByToken = new Map<string, CanaryHit[]>()

  constructor(options: {
    storage?: Store | SecondOrderStore
    dnsDomain?: string
    oobRelay?: OobRelay
    publicProfile?: OobPublicRelayConfig
    oobDirectory?: string
    oobWindowMs?: number
    oobImmediateMs?: number
    now?: () => number
    maxCallbacksPerToken?: number
    maxCallbacksPerRun?: number
    maxProtectedCallbacks?: number
    maxCallbacksPerIpWindow?: number
    ipRateLimitWindowMs?: number
    maxTrackedSourceIps?: number
    maxAssignments?: number
  } = {}) {
    this.defaultStorage = options.storage
    this.now = options.now ?? (() => Date.now())
    this.publicProfileConfig = options.publicProfile
    this.publicBaseUrl = normalizePublicBaseUrl(
      process.env.KOVO_CANARY_PUBLIC_URL ?? process.env.KOVO_CANARY_BASE_URL,
    )
    this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)
    const directory = options.oobDirectory ?? (isFullStore(options.storage) ? options.storage.directory : undefined)
    this.oobRelayInstance = options.oobRelay ?? new OobRelay({
      ...(directory ? { directory } : {}),
      ...(options.publicProfile ? { profile: options.publicProfile } : {}),
      ...(options.now ? { now: options.now } : {}),
      ...(options.oobWindowMs !== undefined ? { windowMs: options.oobWindowMs } : {}),
      ...(options.oobImmediateMs !== undefined ? { immediateMs: options.oobImmediateMs } : {}),
      ...(options.maxCallbacksPerToken !== undefined ? { maxCallbacksPerToken: options.maxCallbacksPerToken } : {}),
      ...(options.maxCallbacksPerRun !== undefined ? { maxCallbacksPerRun: options.maxCallbacksPerRun } : {}),
      ...(options.maxProtectedCallbacks !== undefined ? { maxProtectedCallbacks: options.maxProtectedCallbacks } : {}),
      ...(options.maxCallbacksPerIpWindow !== undefined ? { maxCallbacksPerIpWindow: options.maxCallbacksPerIpWindow } : {}),
      ...(options.ipRateLimitWindowMs !== undefined ? { ipRateLimitWindowMs: options.ipRateLimitWindowMs } : {}),
      ...(options.maxTrackedSourceIps !== undefined ? { maxTrackedSourceIps: options.maxTrackedSourceIps } : {}),
      ...(options.maxAssignments !== undefined ? { maxAssignments: options.maxAssignments } : {}),
      logger: rejection => {
        // Structured, token-free rejection log line; full detail stays in the relay store.
        try {
          console.warn(JSON.stringify({
            event: rejection.event,
            reason: rejection.reason,
            callbackId: rejection.callbackId,
            at: rejection.at,
          }))
        } catch { /* logging is best-effort */ }
      },
    })
  }

  /** Durable async OOB correlation surface for the verifier/executor. */
  get oob(): OobRelay {
    return this.oobRelayInstance
  }

  /** Structured OOB quota, rate-limit, and amortized pruning telemetry. */
  oobQuotaTelemetry(): OobQuotaTelemetry {
    return this.oobRelayInstance.quotaTelemetry()
  }

  relayProfile(): OobRelayProfile {
    return this.activeRelayProfile ?? this.oobRelayInstance.relayProfile()
  }

  subscribe(input: OobSubscriptionInput): OobSubscription {
    return this.oobRelayInstance.subscribe(input)
  }

  awaitAny(
    query: { token?: string; canaryId?: string; runId?: string; assignmentId?: string },
    options?: OobAwaitOptions,
  ): Promise<{ matched: boolean; callback: OobCallback | null }> {
    return this.oobRelayInstance.awaitAny(query, options)
  }

  promoteLate(options?: { runId?: string; now?: number }): OobPromotion[] {
    return this.oobRelayInstance.promoteLate(options)
  }

  pending(runId?: string): OobSubscription[] {
    return this.oobRelayInstance.pending(runId)
  }

  checkOob(query: {
    token?: string
    callbackId?: string
    runId?: string
    canaryId?: string
    assignmentId?: string
  }): ReturnType<OobRelay['check']> {
    return this.oobRelayInstance.check(query)
  }

  /** Two-stage correlation: 3 s immediate window, then durable `pending_oob`. */
  correlate(input: OobSubscriptionInput, options?: OobCorrelateOptions): Promise<OobCorrelationResult> {
    return this.oobRelayInstance.correlate(input, options)
  }

  recordCallback(token: string, detail: Record<string, unknown>): void
  recordCallback(input: OobCallbackInput): OobRecordResult
  recordCallback(tokenOrInput: string | OobCallbackInput, detail?: Record<string, unknown>): OobRecordResult | void {
    if (typeof tokenOrInput === 'string') {
      const normalized = tokenOrInput.trim().toLowerCase()
      const hit = detailToCanaryHit(normalized, detail ?? {})
      this.appendHit(hit)
      return
    }
    return this.oobRelayInstance.recordCallback(tokenOrInput)
  }

  /** Compact relay status for the board (public mode, pending/delivered/promoted counts). */
  relayStatus(): OobRelayStatus & {
    listener: {
      http: string | null
      dns: number | null
      https: boolean
      dnsTcp: number | null
      publicProfileActive: boolean
    }
  } {
    const info = this.listenerInfo()
    const status = this.oobRelayInstance.status()
    const profile = this.relayProfile()
    return {
      ...status,
      mode: profile.mode,
      publicEnabled: profile.publicEnabled,
      problems: [...profile.problems],
      listener: {
        http: info.effectiveBaseUrl,
        dns: info.dnsPort,
        https: info.httpsRunning,
        dnsTcp: info.dnsTcpPort,
        publicProfileActive: info.publicProfileActive,
      },
    }
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
      publicProfileActive: this.publicProfileActive,
      httpsRunning: Boolean(this.httpsServer),
      httpsPort: this.httpsBoundPort,
      dnsTcpRunning: Boolean(this.dnsTcpServer),
      dnsTcpPort: this.dnsTcpBoundPort,
      smtpRunning: this.smtpStarted,
    }
  }

  /** Shared UDP/TCP DNS query handler: records token hits and consults the provider hook. */
  private handleDnsMessage(msg: Buffer, remoteIp: string, respond: (response: Buffer) => void): void {
    try {
      const parsed = parseDnsQuery(msg)
      if (!parsed) return
      const match = tokenPattern.exec(parsed.qname) ?? secondOrderPattern.exec(parsed.qname)
      const token = match ? match[0].toLowerCase() : null
      const queryType = dnsTypeNames[parsed.qtype] ?? `TYPE${parsed.qtype}`
      if (token) {
        const now = this.now()
        const rate = this.oobRelayInstance.consumeIpRateLimit(remoteIp, now)
        if (!rate.allowed) {
          respond(buildDnsResponse(msg, parsed, false, this.dnsSinkIp))
          return
        }
        const hit: CanaryHit = {
          protocol: 'dns',
          token,
          method: 'DNS',
          path: redact(parsed.qname).slice(0, 512),
          query: queryType,
          queryType,
          dnsHost: redact(parsed.qname).slice(0, 256),
          remoteIp: (remoteIp ?? '').slice(0, 128),
          userAgent: '',
          headers: {},
          receivedAt: new Date(now).toISOString(),
          timestamp: now,
        }
        this.appendHit(hit, { ipRateLimitChecked: true })
      }
      const provider = this.dnsProvider
      if (provider) {
        Promise.resolve()
          .then(() => provider.resolve({ name: parsed.qname, type: parsed.qtype, typeName: queryType }))
          .then(answer => {
            respond(answer
              ? buildDnsResponseWithAnswer(msg, parsed, answer)
              : buildDnsResponse(msg, parsed, Boolean(token), this.dnsSinkIp))
          })
          .catch(() => {
            respond(buildDnsResponse(msg, parsed, Boolean(token), this.dnsSinkIp))
          })
        return
      }
      respond(buildDnsResponse(msg, parsed, Boolean(token), this.dnsSinkIp))
    } catch {
      // Drop malformed DNS packets silently
    }
  }

  /** Authoritative DNS over TCP (length-prefixed), for a started public profile. */
  async startDnsTcpListener(options: CanaryDnsListenerOptions = {}): Promise<CanaryListenerInfo> {
    if (this.dnsTcpServer) return this.listenerInfo()
    const host = (options.dnsHost ?? process.env.KOVO_CANARY_DNS_HOST ?? '127.0.0.1').trim() || '127.0.0.1'
    const envTcpPort = Number(process.env.KOVO_OOB_DNS_TCP_PORT ?? '')
    const port = options.dnsPort
      ?? (Number.isInteger(envTcpPort) && envTcpPort >= 0 && envTcpPort <= 65_535 ? envTcpPort : 0)
    if (options.dnsProvider) this.dnsProvider = options.dnsProvider
    const server = createTcpServer(socket => {
      let buffered = Buffer.alloc(0)
      socket.on('data', (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk])
        while (buffered.length >= 2) {
          const length = buffered.readUInt16BE(0)
          if (buffered.length < 2 + length) break
          const query = buffered.subarray(2, 2 + length)
          buffered = buffered.subarray(2 + length)
          this.handleDnsMessage(query, socket.remoteAddress ?? '', response => {
            const prefix = Buffer.alloc(2)
            prefix.writeUInt16BE(response.length, 0)
            socket.write(Buffer.concat([prefix, response]))
          })
        }
      })
      socket.on('error', () => { /* ignore broken DNS TCP clients */ })
    })
    server.listen(port, host)
    await once(server, 'listening')
    server.unref()
    const addr = server.address()
    if (!addr || typeof addr === 'string') {
      server.close()
      throw new Error('Could not bind authoritative DNS TCP listener.')
    }
    this.dnsTcpServer = server
    this.dnsTcpBoundPort = addr.port
    return this.listenerInfo()
  }

  async stopDnsTcpListener(): Promise<void> {
    const server = this.dnsTcpServer
    this.dnsTcpServer = undefined
    this.dnsTcpBoundPort = null
    if (!server) return
    await new Promise<void>(resolve => server.close(() => resolve()))
  }

  async startDnsListener(options: CanaryDnsListenerOptions = {}): Promise<CanaryListenerInfo> {
    if (options.dnsDomain) {
      this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)
    }
    if (this.dnsSocket) {
      return this.listenerInfo()
    }

    const host = (options.dnsHost ?? process.env.KOVO_CANARY_DNS_HOST ?? '127.0.0.1').trim() || '127.0.0.1'
    const port = parsePort(options.dnsPort, 'KOVO_CANARY_DNS_PORT')
    const sinkIp = (options.dnsSinkIp ?? process.env.KOVO_CANARY_DNS_SINK_IP ?? '127.0.0.1').trim() || '127.0.0.1'
    if (options.dnsProvider) this.dnsProvider = options.dnsProvider
    this.dnsSinkIp = sinkIp

    const socket = createSocket('udp4')
    socket.on('message', (msg: Buffer, rinfo: RemoteInfo) => {
      this.handleDnsMessage(msg, rinfo.address, response => {
        socket.send(response, rinfo.port, rinfo.address, () => {
          // Best-effort UDP reply
        })
      })
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

  /**
   * Shared HTTP/HTTPS callback handler. Bounds and redacts POST/webhook bodies (second-order
   * and SSRF proofs often carry evidence in the payload) and forwards the hit to the durable
   * OOB relay for two-stage correlation.
   */
  private callbackHandler(host: string) {
    return (req: IncomingMessage, res: ServerResponse) => {
      const now = this.now()
      const remoteIp = (req.socket?.remoteAddress ?? '').slice(0, 128)
      const rate = this.oobRelayInstance.consumeIpRateLimit(remoteIp, now)
      if (!rate.allowed) {
        req.resume()
        const retryAfterSec = Math.max(1, Math.ceil(Math.max(0, rate.resetAt - now) / 1000))
        res.writeHead(429, {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
          'retry-after': String(retryAfterSec),
          connection: 'close',
        }).end('kovo-canary-rate-limited')
        return
      }
      const maxCallbackBodyBytes = 4096
      const chunks: Buffer[] = []
      let received = 0
      let totalBytes = 0
      let truncated = false
      req.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length
        if (received >= maxCallbackBodyBytes) {
          truncated = true
          return
        }
        const remaining = maxCallbackBodyBytes - received
        const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
        chunks.push(slice)
        received += slice.length
        if (slice.length < chunk.length) truncated = true
      })
      req.on('error', () => { /* ignore malformed callback streams */ })
      const finish = () => {
        try {
          const url = new URL(req.url ?? '/', `http://${formatHostForUrl(host)}`)
          const token = extractTokenFromRequest(url, req.headers.host)
          const artifact = extractArtifact(url, req.headers['x-kovo-artifact'])
          if (token) {
            const receivedTs = this.now()
            const rawBody = Buffer.concat(chunks).toString('utf8')
            const bodyPreview = rawBody
              ? redact(rawBody, []).slice(0, maxCallbackBodyBytes) + (truncated ? '…[truncated]' : '')
              : undefined
            const hit: CanaryHit = {
              protocol: 'http',
              token,
              method: (req.method ?? 'GET').toUpperCase().slice(0, 16),
              path: redact(url.pathname).slice(0, 512),
              query: redact(url.search).slice(0, 512),
              remoteIp,
              userAgent: redact(String(req.headers['user-agent'] ?? '')).slice(0, 200),
              headers: normalizeIncomingHeaders(req.headers),
              ...(bodyPreview ? { bodyPreview, bodyBytes: totalBytes } : {}),
              ...(artifact ? { artifact } : {}),
              receivedAt: new Date(receivedTs).toISOString(),
              timestamp: receivedTs,
            }
            this.appendHit(hit, { ipRateLimitChecked: true })
          }
        } catch {
          // Ignore malformed URLs on callback listener; still return benign 200.
        }
        res.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'close',
        }).end('kovo-canary-ok')
      }
      req.on('end', finish)
      req.on('close', () => {
        if (!req.complete) finish()
      })
    }
  }

  async startListener(options: CanaryListenerOptions = {}): Promise<CanaryListenerInfo> {
    const resolvedPublic = normalizePublicBaseUrl(
      options.publicBaseUrl ?? process.env.KOVO_CANARY_PUBLIC_URL ?? process.env.KOVO_CANARY_BASE_URL,
    )
    if (resolvedPublic) this.publicBaseUrl = resolvedPublic
    this.dnsDomain = inferDnsDomain(options.dnsDomain, this.publicBaseUrl)

    const shouldStartDns = Boolean(
      options.enableDns ||
      options.dnsHost !== undefined ||
      options.dnsPort !== undefined ||
      process.env.KOVO_CANARY_DNS_HOST ||
      process.env.KOVO_CANARY_DNS_PORT,
    )

    if (!this.server) {
      const host = (options.host ?? process.env.KOVO_CANARY_HOST ?? '127.0.0.1').trim() || '127.0.0.1'
      const port = parsePort(options.port, 'KOVO_CANARY_PORT')

      const server = createServer(options.httpHandler ?? this.callbackHandler(host))

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
        ...(options.dnsProvider ? { dnsProvider: options.dnsProvider } : {}),
      })
    }

    return this.listenerInfo()
  }

  async stopListener(): Promise<void> {
    await this.stopPublicProfile()
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

  /**
   * Open the deployable public relay profile (HTTP + ACME HTTPS + authoritative DNS, optional
   * SMTP). Never implicit: fails closed unless the operator configured every required piece.
   */
  async startPublicProfile(
    options: CanaryPublicListenerOptions = {},
    config?: OobPublicRelayConfig,
  ): Promise<CanaryListenerInfo> {
    const effectiveConfig = config ?? this.publicProfileConfig
    const profile = assertPublicProfileStartable(
      resolveOobRelayProfile(effectiveConfig, process.env),
    )
    this.activeRelayProfile = profile
    if (profile.dns.provider) this.dnsProvider = profile.dns.provider
    if (profile.publicBaseUrl) this.publicBaseUrl = profile.publicBaseUrl
    this.dnsDomain = inferDnsDomain(profile.dns.domain, this.publicBaseUrl)

    if (!this.server) {
      await this.startListener({
        host: profile.http.host,
        port: profile.http.port,
        dnsHost: profile.dns.authoritative ? profile.dns.host : '127.0.0.1',
        dnsPort: profile.dns.authoritative ? profile.dns.udpPort : 0,
        dnsDomain: profile.dns.domain,
        ...(profile.dns.provider ? { dnsProvider: profile.dns.provider } : {}),
        httpHandler: this.publicHttpHandler(profile),
      })
    }

    if (options.https !== false) {
      await this.startHttpsListener(profile)
    }
    if (options.dnsTcp !== false && profile.dns.authoritative) {
      await this.startDnsTcpListener({
        dnsHost: profile.dns.host,
        dnsPort: profile.dns.tcpPort,
        dnsDomain: profile.dns.domain,
        ...(profile.dns.provider ? { dnsProvider: profile.dns.provider } : {}),
      })
    }
    if (options.smtp && profile.smtp.provider) {
      await this.startSmtpProvider(profile)
    }
    this.publicProfileActive = true
    return this.listenerInfo()
  }

  /** HTTP handler used by the public profile: ACME HTTP-01 hook first, then callbacks. */
  private publicHttpHandler(profile: OobRelayProfile): (req: IncomingMessage, res: ServerResponse) => void {
    const callback = this.callbackHandler(profile.http.host)
    const acme = profile.https.acme
    if (!acme?.answerHttpChallenge) return callback
    const prefix = (acme.httpChallengePath ?? '/.well-known/acme-challenge').replace(/\/+$/, '')
    return (req: IncomingMessage, res: ServerResponse) => {
      const path = req.url ?? '/'
      if (path === prefix || path.startsWith(`${prefix}/`)) {
        let answer: { status?: number; body: string; contentType?: string } | null = null
        try {
          answer = acme.answerHttpChallenge?.(path) ?? null
        } catch {
          answer = null
        }
        if (answer) {
          res.writeHead(answer.status ?? 200, {
            'content-type': answer.contentType ?? 'text/plain; charset=utf-8',
            'cache-control': 'no-store',
          }).end(answer.body)
          return
        }
      }
      callback(req, res)
    }
  }

  /** HTTPS callback listener backed by operator ACME hooks (no embedded CA). */
  async startHttpsListener(profile: OobRelayProfile = this.relayProfile()): Promise<CanaryListenerInfo> {
    if (this.httpsServer) return this.listenerInfo()
    assertPublicProfileStartable(profile)
    const tls = await this.loadTlsMaterial(profile)
    const server = createHttpsServer({ cert: tls.cert, key: tls.key }, this.callbackHandler(profile.https.host))
    server.listen(profile.https.port, profile.https.host)
    await once(server, 'listening')
    server.unref()
    const addr = server.address()
    if (!addr || typeof addr === 'string') {
      server.close()
      throw new OobProfileError('Could not bind the public HTTPS OOB listener.')
    }
    this.httpsServer = server
    this.httpsBoundPort = addr.port
    return this.listenerInfo()
  }

  private async loadTlsMaterial(profile: OobRelayProfile): Promise<{ cert: string; key: string }> {
    if (profile.https.acme) return await profile.https.acme.loadCertificate()
    if (profile.https.certPath && profile.https.keyPath) {
      return {
        cert: readFileSync(profile.https.certPath, 'utf8'),
        key: readFileSync(profile.https.keyPath, 'utf8'),
      }
    }
    throw new OobProfileError(
      'Public HTTPS profile has no certificate source; configure ACME hooks or cert/key files.',
      profile.problems,
    )
  }

  private async startSmtpProvider(profile: OobRelayProfile): Promise<void> {
    const provider = profile.smtp.provider
    if (!provider) throw new OobProfileError('SMTP profile requires an operator-provided provider.')
    await provider.start({
      onCallback: input => {
        this.recordCallback({
          token: input.token,
          protocol: 'smtp',
          ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
          ...(input.artifact ? { artifact: input.artifact } : {}),
          ...(input.callbackId ? { callbackId: input.callbackId } : {}),
          ...(input.detail ? { detail: input.detail } : {}),
        })
      },
    })
    this.smtpStarted = true
  }

  async stopPublicProfile(): Promise<void> {
    await this.stopHttpsListener()
    await this.stopDnsTcpListener()
    const provider = this.relayProfile().smtp.provider
    if (this.smtpStarted && provider?.stop) await provider.stop()
    this.smtpStarted = false
    this.publicProfileActive = false
  }

  async stopHttpsListener(): Promise<void> {
    const server = this.httpsServer
    this.httpsServer = undefined
    this.httpsBoundPort = null
    if (!server) return
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
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

  /** Close the durable OOB relay store (does not stop listeners). */
  closeOob(): void {
    this.oobRelayInstance.close()
  }

  /**
   * Unsubscribe and evict all OOB subscriptions, bindings, in-flight drains, and in-memory
   * canary state owned by `runId` without affecting any other concurrent run.
   */
  unsubscribeRun(runId: string): OobUnsubscribeRunResult & { evictedCanaries: number } {
    const validRunId = assertValidRunId(runId, 'CanaryBroker.unsubscribeRun')
    cancelOobDrainForRun(validRunId)
    const relayResult = this.oobRelayInstance.unsubscribeRun(validRunId)
    let evictedCanaries = 0
    for (const [token, meta] of [...this.minted.entries()]) {
      if (meta.runId === validRunId) {
        this.minted.delete(token)
        this.hitsByToken.delete(token)
        evictedCanaries += 1
      }
    }
    for (const [marker, meta] of [...this.mintedSecondOrder.entries()]) {
      if (meta.runId === validRunId) {
        this.mintedSecondOrder.delete(marker)
        this.hitsByToken.delete(marker)
        evictedCanaries += 1
      }
    }
    evictSecondOrderSurfacesForRun(validRunId)
    return { ...relayResult, evictedCanaries }
  }

  private appendHit(hit: CanaryHit, options?: { ipRateLimitChecked?: boolean }) {
    if (!options?.ipRateLimitChecked) {
      const rate = this.oobRelayInstance.consumeIpRateLimit(hit.remoteIp, hit.timestamp)
      if (!rate.allowed) return
    }
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
    if (isFullStore(storage) && meta) {
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

    const secondOrderMeta = this.mintedSecondOrder.get(hit.token)
    const secondOrderStorage = secondOrderMeta?.storage ?? this.defaultStorage
    if (secondOrderMeta && secondOrderStorage) {
      const surfacedOrigin = this.effectiveBaseUrl() ?? `https://${this.dnsDomain}`
      const surfacedEndpoint = hit.protocol === 'dns'
        ? `canary-dns:${hit.dnsHost ?? hit.path}`
        : `canary-http:${hit.path}`
      scanSecondOrderMarkers({
        text: hit.token,
        runId: secondOrderMeta.runId,
        assignmentId: secondOrderMeta.assignmentId,
        origin: surfacedOrigin,
        endpoint: surfacedEndpoint,
        persona: 'oob-callback',
        storage: secondOrderStorage,
      })
    }

    // Durable async correlation: every delivered callback is persisted idempotently so a
    // late delivery can promote a pending_oob subscription (and survive a restart).
    try {
      this.oobRelayInstance.recordCallback({
        token: hit.token,
        protocol: hit.protocol,
        sourceIp: hit.remoteIp,
        method: hit.method,
        path: hit.path,
        query: hit.query,
        ...(hit.artifact ? { artifact: hit.artifact } : {}),
        ...(meta ? { runId: meta.runId, canaryId: meta.id } : {}),
        ...(secondOrderMeta ? {
          runId: secondOrderMeta.runId,
          assignmentId: secondOrderMeta.assignmentId,
          ...(secondOrderMeta.id ? { canaryId: secondOrderMeta.id } : {}),
        } : {}),
        receivedAt: hit.timestamp,
        detail: {
          userAgent: hit.userAgent,
          ...(hit.bodyBytes !== undefined ? { bodyBytes: hit.bodyBytes } : {}),
        },
      }, { ipRateLimitAlreadyConsumed: true })
    } catch {
      // Relay persistence is best-effort; in-memory hits remain authoritative for local checks.
    }
  }

  mintCanary(
    runId: string,
    label: string,
    origin?: string,
    options?: { storage?: Store | SecondOrderStore; assignmentId?: string },
  ): MintedCanary {
    const validRunId = assertValidRunId(runId, 'CanaryBroker.mintCanary')
    const id = randomUUID()
    const digest = createHmac('sha256', this.secret)
      .update(validRunId)
      .update(id)
      .update(randomBytes(8))
      .digest('hex')
      .slice(0, 24)
    const token = `kovo-canary-${digest}`
    const createdAt = Date.now()
    const storage = options?.storage ?? this.defaultStorage

    if (this.minted.size >= maxTrackedTokens) {
      const oldestKey = this.minted.keys().next().value
      if (oldestKey) this.minted.delete(oldestKey)
    }
    this.minted.set(token, {
      id,
      runId: validRunId,
      label,
      origin: origin ?? null,
      storage,
      createdAt,
    })
    this.oobRelayInstance.registerCanary({
      token,
      canaryId: id,
      runId: validRunId,
      assignmentId: options?.assignmentId ?? 'canary-broker',
    })

    if (isFullStore(storage)) {
      const purpose = (origin ? `${label} (${origin})` : label).slice(0, 200)
      storage.db.insert(canaries).values({
        id,
        runId: validRunId,
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
      runId: validRunId,
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

  mintSecondOrderCanary(input: {
    runId: string
    assignmentId?: string
    injectedOrigin?: string
    injectedEndpoint?: string
    sourceEndpoint?: string
    injectedParam?: string
    injectedPersona?: string | null
    sourcePersona?: string | null
    storage?: Store | SecondOrderStore
  }): MintedSecondOrderCanary {
    const validRunId = assertValidRunId(input.runId, 'CanaryBroker.mintSecondOrderCanary')
    let marker = ''
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const digest = createHmac('sha256', this.secret)
        .update(validRunId)
        .update(randomBytes(8))
        .digest('hex')
        .slice(0, 8)
      const candidate = `gn2o_${digest}`
      if (!this.mintedSecondOrder.has(candidate)) {
        marker = candidate
        break
      }
    }
    if (!marker) {
      marker = `gn2o_${randomBytes(4).toString('hex')}`
    }

    const assignmentId = input.assignmentId ?? 'canary-broker'
    const injectedOrigin = input.injectedOrigin ?? 'https://second-order.invalid'
    const injectedEndpoint = input.injectedEndpoint ?? input.sourceEndpoint ?? '/'
    const injectedParam = input.injectedParam ?? 'input'
    const injectedPersona = input.injectedPersona ?? input.sourcePersona ?? null
    const storage = input.storage ?? this.defaultStorage

    let id: string | undefined
    if (storage) {
      const row = storage.insertSecondOrderCanary({
        runId: validRunId,
        assignmentId,
        marker,
        injectedOrigin,
        injectedEndpoint,
        injectedParam,
        injectedPersona,
      })
      id = row.id
    }

    if (this.mintedSecondOrder.size >= maxTrackedTokens) {
      const oldestKey = this.mintedSecondOrder.keys().next().value
      if (oldestKey) this.mintedSecondOrder.delete(oldestKey)
    }
    this.mintedSecondOrder.set(marker, {
      id,
      runId: validRunId,
      assignmentId,
      injectedOrigin,
      injectedEndpoint,
      injectedParam,
      injectedPersona,
      storage,
    })
    this.oobRelayInstance.registerCanary({
      token: marker,
      canaryId: id ?? marker,
      runId: validRunId,
      assignmentId,
    })

    const effective = this.effectiveBaseUrl()
    const dnsHost = `${marker}.${this.dnsDomain}`
    const httpUrl = effective ? `${effective}/c/${marker}` : `https://${this.dnsDomain}/c/${marker}`

    return {
      ...(id ? { id } : {}),
      marker,
      runId: validRunId,
      assignmentId,
      injectedOrigin,
      injectedEndpoint,
      injectedParam,
      injectedPersona,
      httpUrl,
      dnsHost,
    }
  }

  checkCanary(token: string, options?: { storage?: Store | SecondOrderStore; runId?: string }): CanaryCheckResult {
    const normalized = token.trim().toLowerCase()
    const meta = this.minted.get(normalized)
    const secondOrderMeta = this.mintedSecondOrder.get(normalized)
    if (options?.runId) {
      if (meta && meta.runId !== options.runId) {
        return { found: false, hit: false, triggered: false, hits: [], detail: null }
      }
      if (!meta && secondOrderMeta && secondOrderMeta.runId !== options.runId) {
        return { found: false, hit: false, triggered: false, hits: [], detail: null }
      }
    }
    const storage = options?.storage ?? meta?.storage ?? this.defaultStorage
    const runId = options?.runId ?? meta?.runId

    let row: typeof canaries.$inferSelect | undefined
    if (isFullStore(storage)) {
      try {
        row = runId
          ? storage.db.select().from(canaries).where(and(eq(canaries.runId, runId), eq(canaries.token, normalized))).get()
          : storage.db.select().from(canaries).where(eq(canaries.token, normalized)).get()
      } catch {
        row = undefined
      }
    }

    const ownedByRequestedRun = !options?.runId
      || meta?.runId === options.runId
      || secondOrderMeta?.runId === options.runId
      || Boolean(row)
    const memHits = ownedByRequestedRun ? [...(this.hitsByToken.get(normalized) ?? [])] : []

    if (row && memHits.length > 0 && !row.triggered && isFullStore(storage)) {
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
