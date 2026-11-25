/**
 * HostFactLog — Dual-Plane Immutable Host Custody Log (Option 2, Move 1).
 *
 * Plane 1 (Host Kernel Truth):
 *   Every brokered HTTP/HTTP2/race exchange, OOB callback, browser trace, and async poll
 *   is recorded once as a deeply frozen `HostExchangeFact` carrying pre-redaction request
 *   and response payloads, host-assigned monotonic `seq`, and host-resolved actor/tenant/
 *   ambient-auth/SameSite metadata. Oracles and verification kernels have strictly read-only
 *   access (`getExchange`, `orderedExchanges`) and never mutate stored facts.
 *
 * Plane 2 (Worker Egress View):
 *   Worker-facing projections (`buildWorkerView`) are derived lazily through `EgressSanitizer`
 *   without ever calling `rescrubBodies()` or mutating the host fact plane.
 */
import { createHash } from 'node:crypto'
import { createEgressSanitizer, EgressSanitizer, type EgressChannel } from './egress-sanitizer.ts'
import { normalizeRole, parseRoleLabel, type AmbientAuth, type ImpactStep, type RoleName } from './oracle-invariants.ts'
import type { BrokerExchangeResult, BrokerHttpRequest } from './broker.ts'
import type {
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostCryptoAttestation,
  HostOobEvent,
  HostSignedTranscript,
  HostTranscriptEntry,
} from './composite-receipt.ts'
import type {
  ReceiptBrowserTrace,
  ReceiptOobEvent,
  ReceiptTranscript,
  ReceiptTranscriptEntry,
  ScriptProofExchange,
} from './proof-receipt.ts'
import type { TranscriptStore, VerifyTranscriptRecord } from './verify-claims.ts'

export interface HostOobCallbackFact {
  readonly id: string
  readonly callbackId?: string
  readonly canaryId?: string
  readonly token?: string
  readonly targetOrigin?: string | null
  readonly delivered: boolean
  readonly stage?: 'immediate' | 'late'
  readonly receivedAtMs: number
  readonly injectedAtMs?: number
  readonly latencyMs?: number
  readonly emittedCapabilities?: readonly string[]
  readonly observedValueDigests?: readonly string[]
  readonly correlationIds?: readonly string[]
  readonly hostSignature?: string
}

export interface HostExchangeFact {
  readonly seq: number
  readonly exchangeId: string
  readonly op?: string
  readonly method: string
  readonly url: string
  readonly origin: string
  readonly pathAndQuery: string
  readonly status: number | null
  readonly requestHeaders: Readonly<Record<string, string>>
  readonly rawRequestBody: string | null
  readonly responseHeaders: Readonly<Record<string, string>>
  readonly rawResponseBody: string | null
  readonly actor: string | null
  readonly actorRole: RoleName | null
  readonly actorRoleLabel?: string | null
  readonly actorTenant: string | null
  readonly ambientAuth: AmbientAuth
  readonly sameSite: string | null
  readonly oobCallbacks: readonly HostOobCallbackFact[]
  readonly durationMs: number
  readonly startedAt?: number
  readonly endedAt?: number
  readonly timestampMs?: number
  readonly arm?: ImpactStep['arm']
  readonly sessionRole?: string | null
  readonly evidenceRole?: string
  readonly sessionId?: string | null
  readonly consumedCapabilityId?: string | null
  readonly consumedCapabilities?: readonly string[]
  readonly emittedCapabilities?: readonly string[]
  readonly observedResponseDigests?: readonly string[]
  readonly injectedRequestDigests?: readonly string[]
  readonly cryptoAttestations?: readonly HostCryptoAttestation[]
  readonly entityId?: string
  readonly correlationIds?: readonly string[]
  readonly cleanSession?: boolean
  readonly replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
  readonly hostSignature?: string
  readonly carrierText?: string
  readonly secretMatches?: readonly string[]
  readonly artifact?: ScriptProofExchange['artifact']
}

export interface HostExchangeFactInput {
  seq?: number
  exchangeId: string
  op?: string
  method: string
  url?: string
  origin: string
  pathAndQuery: string
  status: number | null
  requestHeaders?: Readonly<Record<string, string>> | null
  rawRequestBody?: string | null
  responseHeaders?: Readonly<Record<string, string>> | null
  rawResponseBody?: string | null
  actor?: string | null
  actorRole?: RoleName | null
  actorRoleLabel?: string | null
  actorTenant?: string | null
  ambientAuth?: AmbientAuth
  sameSite?: string | null
  oobCallbacks?: readonly HostOobCallbackFact[]
  durationMs?: number
  startedAt?: number
  endedAt?: number
  timestampMs?: number
  arm?: ImpactStep['arm']
  sessionRole?: string | null
  evidenceRole?: string
  sessionId?: string | null
  consumedCapabilityId?: string | null
  consumedCapabilities?: readonly string[]
  emittedCapabilities?: readonly string[]
  observedResponseDigests?: readonly string[]
  injectedRequestDigests?: readonly string[]
  cryptoAttestations?: readonly HostCryptoAttestation[]
  entityId?: string
  correlationIds?: readonly string[]
  cleanSession?: boolean
  replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
  hostSignature?: string
  carrierText?: string
  secretMatches?: readonly string[]
  artifact?: ScriptProofExchange['artifact']
}

export interface WorkerExchangeView {
  readonly seq: number
  readonly exchangeId: string
  readonly op?: string
  readonly method: string
  readonly url: string
  readonly origin: string
  readonly pathAndQuery: string
  readonly status: number | null
  readonly requestHeaders: Readonly<Record<string, string>>
  readonly requestBody: string | null
  readonly responseHeaders: Readonly<Record<string, string>>
  readonly responseBody: string | null
  readonly actor: string | null
  readonly actorRole: RoleName | null
  readonly actorTenant: string | null
  readonly durationMs: number
}

export interface HostFactLogOptions {
  sanitizer?: EgressSanitizer
}

function headerLookup(headers: Readonly<Record<string, string>> | null | undefined, name: string): string | null {
  if (!headers) return null
  const wanted = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === wanted && typeof v === 'string' && v.length > 0) return v
  }
  return null
}

function freezeHeaderMap(headers: Readonly<Record<string, string>> | null | undefined): Readonly<Record<string, string>> {
  const copy: Record<string, string> = {}
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === 'string') copy[k] = v
    }
  }
  return Object.freeze(copy)
}

function freezeStringList(values: readonly string[] | undefined): readonly string[] | undefined {
  if (!values) return undefined
  return Object.freeze([...values])
}

function freezeHostEntry(entry: HostTranscriptEntry): HostTranscriptEntry {
  const freeze = (value: unknown): unknown => {
    if (Array.isArray(value)) return Object.freeze(value.map(freeze))
    if (value && typeof value === 'object') {
      for (const child of Object.values(value as Record<string, unknown>)) freeze(child)
      return Object.freeze(value)
    }
    return value
  }
  return freeze(entry) as HostTranscriptEntry
}

function freezeOobFact(ev: HostOobCallbackFact): HostOobCallbackFact {
  return Object.freeze({
    ...ev,
    ...(ev.emittedCapabilities ? { emittedCapabilities: Object.freeze([...ev.emittedCapabilities]) } : {}),
    ...(ev.observedValueDigests ? { observedValueDigests: Object.freeze([...ev.observedValueDigests]) } : {}),
    ...(ev.correlationIds ? { correlationIds: Object.freeze([...ev.correlationIds]) } : {}),
  })
}

function normalizeOriginKey(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase()
  }
}

export function deriveAmbientAuthFromHeaders(
  headers: Readonly<Record<string, string>> | null | undefined,
  explicit?: AmbientAuth,
): AmbientAuth {
  if (explicit && explicit !== 'unknown') return explicit
  if (!headers) return 'unknown'
  const auth = headerLookup(headers, 'authorization')
  const cookie = headerLookup(headers, 'cookie')
  if (cookie && !auth) return 'cookie'
  if (auth) return /^bearer\s+/i.test(auth) ? 'bearer' : 'header'
  if (headerLookup(headers, 'x-api-key') || headerLookup(headers, 'x-auth-token')) return 'header'
  return 'unknown'
}

export function extractSameSiteFromHeaders(headers: Readonly<Record<string, string>> | null | undefined): string | null {
  const setCookie = headerLookup(headers, 'set-cookie')
  if (!setCookie) return null
  const m = /;\s*samesite\s*=\s*(strict|lax|none)\b/i.exec(setCookie)
  if (!m?.[1]) return null
  const lower = m[1].toLowerCase()
  return lower === 'strict' ? 'Strict' : lower === 'lax' ? 'Lax' : 'None'
}

function safeJsonParse(raw: string | null | undefined): unknown {
  if (typeof raw !== 'string' || !raw.trim()) return undefined
  try {
    return JSON.parse(raw)
  } catch {
    return undefined
  }
}

function buildUrlString(origin: string, pathAndQuery: string, explicitUrl?: string): string {
  if (explicitUrl && explicitUrl.trim()) return explicitUrl.trim()
  const cleanOrigin = origin.replace(/\/+$/, '')
  const pq = pathAndQuery.startsWith('/') ? pathAndQuery : `/${pathAndQuery}`
  return cleanOrigin ? `${cleanOrigin}${pq}` : pq
}

function buildCarrierText(
  method: string,
  pathAndQuery: string,
  requestHeaders: Readonly<Record<string, string>>,
  rawRequestBody: string | null,
  rawResponseBody: string | null,
): string {
  const parts = [`${method.toUpperCase()} ${pathAndQuery}`]
  if (Object.keys(requestHeaders).length > 0) parts.push(JSON.stringify(requestHeaders))
  if (rawRequestBody) parts.push(rawRequestBody)
  if (rawResponseBody) parts.push(rawResponseBody.slice(0, 32 * 1024))
  return parts.join('\n')
}

function parseBodyFromCarrierText(carrierText: string | undefined): string | null {
  if (!carrierText) return null
  const lines = carrierText.split('\n').map(l => l.trim()).filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i]!
    if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//i.test(line)) continue
    if (/^[A-Za-z0-9-]+:\s/.test(line)) continue
    return line
  }
  return null
}

export class HostFactLog {
  private readonly exchanges = new Map<string, HostExchangeFact>()
  private readonly signedEntries = new Map<string, HostTranscriptEntry>()
  private readonly oobEvents = new Map<string, HostOobCallbackFact>()
  private readonly browserTraces = new Map<string, HostBrowserTrace>()
  private readonly asyncPolls = new Map<string, HostAsyncPollRecord>()
  private readonly sanitizer: EgressSanitizer
  private nextSeq = 0

  constructor(options: HostFactLogOptions = {}) {
    this.sanitizer = options.sanitizer ?? createEgressSanitizer()
  }

  get size(): number {
    return this.exchanges.size
  }

  /** Record one immutable host-observed exchange. Duplicate exchangeIds are rejected (append-only). */
  recordExchange(input: HostExchangeFactInput): Readonly<HostExchangeFact> {
    if (this.exchanges.has(input.exchangeId)) {
      return this.exchanges.get(input.exchangeId)!
    }
    const seq = typeof input.seq === 'number' && Number.isFinite(input.seq)
      ? (this.nextSeq = Math.max(this.nextSeq, input.seq), input.seq)
      : ++this.nextSeq

    const requestHeaders = freezeHeaderMap(input.requestHeaders)
    const responseHeaders = freezeHeaderMap(input.responseHeaders)
    const rawRequestBody = input.rawRequestBody !== undefined && input.rawRequestBody !== null
      ? String(input.rawRequestBody)
      : null
    const rawResponseBody = input.rawResponseBody !== undefined && input.rawResponseBody !== null
      ? String(input.rawResponseBody)
      : null

    const actor = input.actor ?? null
    const roleSource = input.actorRoleLabel ?? actor ?? null
    const parsedLabel = parseRoleLabel(roleSource)
    const actorRole: RoleName | null = input.actorRole ?? parsedLabel.role ?? normalizeRole(actor ?? undefined) ?? null
    const actorTenant: string | null = input.actorTenant ?? parsedLabel.tenant ?? parseRoleLabel(actor ?? null).tenant ?? null
    const ambientAuth = deriveAmbientAuthFromHeaders(requestHeaders, input.ambientAuth)
    const sameSite = input.sameSite !== undefined
      ? input.sameSite
      : extractSameSiteFromHeaders(responseHeaders)
    const method = (input.method || 'GET').toUpperCase()
    const pathAndQuery = input.pathAndQuery || '/'
    const origin = input.origin || ''
    const url = buildUrlString(origin, pathAndQuery, input.url)
    const oobCallbacks = Object.freeze((input.oobCallbacks ?? []).map(freezeOobFact))

    for (const cb of oobCallbacks) {
      if (!this.oobEvents.has(cb.id)) this.oobEvents.set(cb.id, cb)
    }

    const fact: HostExchangeFact = Object.freeze({
      seq,
      exchangeId: input.exchangeId,
      ...(input.op ? { op: input.op } : {}),
      method,
      url,
      origin,
      pathAndQuery,
      status: input.status,
      requestHeaders,
      rawRequestBody,
      responseHeaders,
      rawResponseBody,
      actor,
      actorRole,
      ...(input.actorRoleLabel !== undefined ? { actorRoleLabel: input.actorRoleLabel } : {}),
      actorTenant,
      ambientAuth,
      sameSite,
      oobCallbacks,
      durationMs: Math.max(0, Number.isFinite(input.durationMs ?? 0) ? (input.durationMs ?? 0) : 0),
      ...(input.startedAt !== undefined ? { startedAt: input.startedAt } : {}),
      ...(input.endedAt !== undefined ? { endedAt: input.endedAt } : {}),
      ...(input.timestampMs !== undefined ? { timestampMs: input.timestampMs } : {}),
      ...(input.arm !== undefined ? { arm: input.arm } : {}),
      ...(input.sessionRole !== undefined ? { sessionRole: input.sessionRole } : {}),
      ...(input.evidenceRole !== undefined ? { evidenceRole: input.evidenceRole } : {}),
      ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
      ...(input.consumedCapabilityId !== undefined ? { consumedCapabilityId: input.consumedCapabilityId } : {}),
      ...(input.consumedCapabilities ? { consumedCapabilities: freezeStringList(input.consumedCapabilities) } : {}),
      ...(input.emittedCapabilities ? { emittedCapabilities: freezeStringList(input.emittedCapabilities) } : {}),
      ...(input.observedResponseDigests ? { observedResponseDigests: freezeStringList(input.observedResponseDigests) } : {}),
      ...(input.injectedRequestDigests ? { injectedRequestDigests: freezeStringList(input.injectedRequestDigests) } : {}),
      ...(input.cryptoAttestations
        ? { cryptoAttestations: Object.freeze(input.cryptoAttestations.map(a => Object.freeze({ ...a }))) }
        : {}),
      ...(input.entityId !== undefined ? { entityId: input.entityId } : {}),
      ...(input.correlationIds ? { correlationIds: freezeStringList(input.correlationIds) } : {}),
      ...(input.cleanSession !== undefined ? { cleanSession: input.cleanSession } : {}),
      ...(input.replayAttempt !== undefined ? { replayAttempt: input.replayAttempt } : {}),
      ...(input.hostSignature !== undefined ? { hostSignature: input.hostSignature } : {}),
      ...(input.carrierText !== undefined
        ? { carrierText: input.carrierText }
        : { carrierText: buildCarrierText(method, pathAndQuery, requestHeaders, rawRequestBody, rawResponseBody) }),
      ...(input.secretMatches ? { secretMatches: freezeStringList(input.secretMatches) } : {}),
      ...(input.artifact !== undefined
        ? { artifact: input.artifact ? Object.freeze({ ...input.artifact }) : null }
        : {}),
    })
    this.exchanges.set(fact.exchangeId, fact)
    return fact
  }

  recordOobEvent(event: HostOobCallbackFact | ReceiptOobEvent | HostOobEvent): Readonly<HostOobCallbackFact> {
    const frozen = freezeOobFact(event)
    if (!this.oobEvents.has(frozen.id)) this.oobEvents.set(frozen.id, frozen)
    return this.oobEvents.get(frozen.id)!
  }

  recordBrowserTrace(trace: ReceiptBrowserTrace | HostBrowserTrace): Readonly<HostBrowserTrace> {
    const frozen: HostBrowserTrace = Object.freeze({
      ...trace,
      ...(trace.sinks ? { sinks: Object.freeze([...trace.sinks]) } : {}),
      ...('emittedCapabilities' in trace && trace.emittedCapabilities ? { emittedCapabilities: Object.freeze([...trace.emittedCapabilities]) } : {}),
      ...('observedValueDigests' in trace && trace.observedValueDigests ? { observedValueDigests: Object.freeze([...trace.observedValueDigests]) } : {}),
      ...('correlationIds' in trace && trace.correlationIds ? { correlationIds: Object.freeze([...trace.correlationIds]) } : {}),
    })
    if (!this.browserTraces.has(frozen.id)) this.browserTraces.set(frozen.id, frozen)
    return this.browserTraces.get(frozen.id)!
  }

  recordAsyncPoll(poll: HostAsyncPollRecord): Readonly<HostAsyncPollRecord> {
    const frozen: HostAsyncPollRecord = Object.freeze({
      ...poll,
      ...(poll.correlationIds ? { correlationIds: Object.freeze([...poll.correlationIds]) } : {}),
      ...(poll.emittedCapabilities ? { emittedCapabilities: Object.freeze([...poll.emittedCapabilities]) } : {}),
      ...(poll.observedValueDigests ? { observedValueDigests: Object.freeze([...poll.observedValueDigests]) } : {}),
    })
    if (!this.asyncPolls.has(frozen.id)) this.asyncPolls.set(frozen.id, frozen)
    return this.asyncPolls.get(frozen.id)!
  }

  /** Strictly read-only lookup of an immutable host fact. */
  getExchange(id: string): Readonly<HostExchangeFact> | undefined {
    return this.exchanges.get(id)
  }

  getOobEvent(id: string): Readonly<HostOobCallbackFact> | undefined {
    return this.oobEvents.get(id)
  }

  getBrowserTrace(id: string): Readonly<HostBrowserTrace> | undefined {
    return this.browserTraces.get(id)
  }

  getAsyncPoll(id: string): Readonly<HostAsyncPollRecord> | undefined {
    return this.asyncPolls.get(id)
  }

  listOobEvents(): readonly Readonly<HostOobCallbackFact>[] {
    return [...this.oobEvents.values()]
  }

  listBrowserTraces(): readonly Readonly<HostBrowserTrace>[] {
    return [...this.browserTraces.values()]
  }

  listAsyncPolls(): readonly Readonly<HostAsyncPollRecord>[] {
    return [...this.asyncPolls.values()]
  }

  /**
   * Return exchanges strictly sorted by host monotonic `seq` (with `startedAt` / `timestampMs`
   * tie-breaker). Worker-supplied ID ordering is NEVER trusted.
   */
  orderedExchanges(ids?: readonly string[]): readonly Readonly<HostExchangeFact>[] {
    const list: HostExchangeFact[] = []
    if (ids) {
      const seen = new Set<string>()
      for (const id of ids) {
        if (seen.has(id)) continue
        seen.add(id)
        const fact = this.exchanges.get(id)
        if (fact) list.push(fact)
      }
    } else {
      for (const fact of this.exchanges.values()) list.push(fact)
    }
    list.sort((a, b) => {
      if (a.seq !== b.seq) return a.seq - b.seq
      const ta = a.startedAt ?? a.timestampMs ?? 0
      const tb = b.startedAt ?? b.timestampMs ?? 0
      return ta - tb
    })
    return Object.freeze(list)
  }

  /** Derive host-observed SameSite for an exchange (falling back to same-origin/actor Set-Cookie in this log). */
  resolveSameSite(exchangeId: string): string | null {
    const fact = this.exchanges.get(exchangeId)
    if (!fact) return null
    if (fact.sameSite) return fact.sameSite
    const originKey = normalizeOriginKey(fact.origin)
    for (const item of this.orderedExchanges()) {
      if (originKey && item.origin && normalizeOriginKey(item.origin) !== originKey) continue
      if (fact.actor && item.actor && item.actor !== fact.actor) continue
      if (item.sameSite) return item.sameSite
    }
    return null
  }

  /**
   * Plane-2 projection: derive a scrubbed worker-facing view of a host fact via `EgressSanitizer`.
   * NEVER mutates the stored pre-redaction `HostExchangeFact`.
   */
  buildWorkerView(
    id: string,
    sanitizer: EgressSanitizer = this.sanitizer,
    channel: EgressChannel = 'worker_rpc',
  ): WorkerExchangeView | undefined {
    const fact = this.exchanges.get(id)
    if (!fact) return undefined
    const requestHeaders = Object.freeze(sanitizer.sanitizeHttpHeaders({ ...fact.requestHeaders }, channel))
    const responseHeaders = Object.freeze(sanitizer.sanitizeHttpHeaders({ ...fact.responseHeaders }, channel))
    const requestBody = fact.rawRequestBody !== null ? sanitizer.redactText(fact.rawRequestBody, channel) : null
    const responseBody = fact.rawResponseBody !== null ? sanitizer.redactText(fact.rawResponseBody, channel) : null
    const pathAndQuery = sanitizer.redactText(fact.pathAndQuery, channel)
    const url = sanitizer.redactText(fact.url, channel)
    return Object.freeze({
      seq: fact.seq,
      exchangeId: fact.exchangeId,
      ...(fact.op ? { op: fact.op } : {}),
      method: fact.method,
      url,
      origin: fact.origin,
      pathAndQuery,
      status: fact.status,
      requestHeaders,
      requestBody,
      responseHeaders,
      responseBody,
      actor: fact.actor,
      actorRole: fact.actorRole,
      actorTenant: fact.actorTenant,
      durationMs: fact.durationMs,
    })
  }

  /** Project one host fact onto `ImpactStep` strictly from host-recorded data. */
  toImpactStep(
    exchangeId: string,
    overrides?: { arm?: ImpactStep['arm']; evidenceRole?: string },
  ): ImpactStep | undefined {
    const fact = this.exchanges.get(exchangeId)
    if (!fact) return undefined
    const arm: ImpactStep['arm'] = overrides?.arm
      ?? fact.arm
      ?? (fact.sessionRole === 'control' || fact.sessionRole === 'probe' || fact.sessionRole === 'setup' || fact.sessionRole === 'cleanup'
        ? fact.sessionRole
        : 'setup')
    const json = safeJsonParse(fact.rawResponseBody)
    const requestJson = fact.rawRequestBody !== null
      ? (safeJsonParse(fact.rawRequestBody) ?? fact.rawRequestBody)
      : undefined
    const sameSite = this.resolveSameSite(exchangeId)
    const evidenceRole = overrides?.evidenceRole ?? fact.evidenceRole
    return {
      id: fact.exchangeId,
      arm,
      method: fact.method,
      route: (fact.pathAndQuery || '/').split('?')[0] || '/',
      pathAndQuery: fact.pathAndQuery || '/',
      status: fact.status,
      actor: {
        handle: fact.actor,
        role: fact.actorRole,
        tenant: fact.actorTenant,
        auth: fact.ambientAuth,
        sameSite,
      },
      ...(json !== undefined ? { json } : {}),
      ...(fact.rawResponseBody !== null ? { body: fact.rawResponseBody } : {}),
      ...(requestJson !== undefined ? { requestJson } : {}),
      ...(Object.keys(fact.requestHeaders).length > 0 ? { requestHeaders: { ...fact.requestHeaders } } : {}),
      ...(Object.keys(fact.responseHeaders).length > 0 ? { responseHeaders: { ...fact.responseHeaders } } : {}),
      ...(fact.secretMatches && fact.secretMatches.length > 0 ? { secretMatches: [...fact.secretMatches] } : {}),
      ...(evidenceRole ? { evidenceRole } : {}),
      durationMs: fact.durationMs,
    }
  }

  /** Project the host log onto a `ReceiptTranscript` ordered by host `seq`. */
  toReceiptTranscript(options?: {
    armOverrides?: ReadonlyMap<string, ImpactStep['arm']>
    evidenceRoleOverrides?: ReadonlyMap<string, string>
  }): ReceiptTranscript {
    const entries: ReceiptTranscriptEntry[] = this.orderedExchanges().map(fact => {
      const evidenceRole = options?.evidenceRoleOverrides?.get(fact.exchangeId) ?? fact.evidenceRole ?? fact.sessionRole ?? undefined
      const step = this.toImpactStep(fact.exchangeId, {
        ...(options?.armOverrides?.has(fact.exchangeId) ? { arm: options.armOverrides.get(fact.exchangeId)! } : {}),
        ...(evidenceRole ? { evidenceRole } : {}),
      })!
      return {
        exchangeId: fact.exchangeId,
        step,
        durationMs: fact.durationMs,
        ...(fact.op ? { op: fact.op } : {}),
        seq: fact.seq,
        ...(fact.startedAt !== undefined ? { startedAt: fact.startedAt } : {}),
        ...(fact.endedAt !== undefined ? { endedAt: fact.endedAt } : {}),
        ...(fact.origin ? { origin: fact.origin } : {}),
        ...(fact.consumedCapabilityId !== undefined ? { consumedCapabilityId: fact.consumedCapabilityId } : {}),
        ...(fact.consumedCapabilities ? { consumedCapabilities: [...fact.consumedCapabilities] } : {}),
        ...(fact.sessionId !== undefined ? { sessionId: fact.sessionId } : {}),
        ...(fact.carrierText ? { carrierText: fact.carrierText } : {}),
        ...(evidenceRole ? { evidenceRole } : {}),
      }
    })
    return {
      entries,
      oobEvents: this.listOobEvents().map(ev => ({ ...ev })),
      browserTraces: this.listBrowserTraces().map(tr => ({ ...tr })),
    }
  }

  /** Project the host log onto a `HostSignedTranscript` for unified 1-hop / multi-hop verification. */
  toHostSignedTranscript(options?: {
    armOverrides?: ReadonlyMap<string, ImpactStep['arm']>
    evidenceRoleOverrides?: ReadonlyMap<string, string>
  }): HostSignedTranscript {
    const entries: HostTranscriptEntry[] = this.orderedExchanges().map(fact => {
      // A signature covers the original signed entry, not a later projection with derived defaults.
      const signed = this.signedEntries.get(fact.exchangeId)
      if (signed) return signed
      const evidenceRole = options?.evidenceRoleOverrides?.get(fact.exchangeId) ?? fact.evidenceRole ?? fact.sessionRole ?? undefined
      const step = this.toImpactStep(fact.exchangeId, {
        ...(options?.armOverrides?.has(fact.exchangeId) ? { arm: options.armOverrides.get(fact.exchangeId)! } : {}),
        ...(evidenceRole ? { evidenceRole } : {}),
      })!
      const ts = fact.timestampMs ?? fact.startedAt ?? fact.seq
      const observedDigests = fact.observedResponseDigests && fact.observedResponseDigests.length > 0
        ? [...fact.observedResponseDigests]
        : fact.rawResponseBody !== null
          ? [createHash('sha256').update(fact.rawResponseBody, 'utf8').digest('hex')]
          : undefined
      return {
        exchangeId: fact.exchangeId,
        step,
        durationMs: fact.durationMs,
        ...(fact.op ? { op: fact.op } : {}),
        seq: fact.seq,
        ...(fact.startedAt !== undefined ? { startedAt: fact.startedAt } : {}),
        ...(fact.endedAt !== undefined ? { endedAt: fact.endedAt } : {}),
        ...(fact.origin ? { origin: fact.origin } : {}),
        ...(fact.consumedCapabilityId !== undefined ? { consumedCapabilityId: fact.consumedCapabilityId } : {}),
        ...(fact.consumedCapabilities ? { consumedCapabilities: [...fact.consumedCapabilities] } : {}),
        ...(fact.sessionId !== undefined ? { sessionId: fact.sessionId } : {}),
        ...(fact.carrierText ? { carrierText: fact.carrierText } : {}),
        ...(evidenceRole ? { evidenceRole } : {}),
        timestampMs: ts,
        actorPersona: fact.actor,
        ...(fact.actorRoleLabel !== undefined ? { actorRoleLabel: fact.actorRoleLabel } : {}),
        ...(fact.emittedCapabilities ? { emittedCapabilities: [...fact.emittedCapabilities] } : {}),
        ...(observedDigests ? { observedResponseDigests: observedDigests } : {}),
        ...(fact.injectedRequestDigests ? { injectedRequestDigests: [...fact.injectedRequestDigests] } : {}),
        ...(fact.cryptoAttestations ? { cryptoAttestations: fact.cryptoAttestations.map(a => ({ ...a })) } : {}),
        ...(fact.entityId !== undefined ? { entityId: fact.entityId } : {}),
        ...(fact.correlationIds ? { correlationIds: [...fact.correlationIds] } : {}),
        ...(fact.cleanSession !== undefined ? { cleanSession: fact.cleanSession } : {}),
        ...(fact.replayAttempt !== undefined ? { replayAttempt: fact.replayAttempt } : {}),
        ...(fact.hostSignature !== undefined ? { hostSignature: fact.hostSignature } : {}),
      }
    })
    return {
      entries,
      oobEvents: this.listOobEvents().map(ev => ({ ...ev })),
      browserTraces: this.listBrowserTraces().map(tr => ({ ...tr })),
      asyncPollRecords: this.listAsyncPolls().map(p => ({ ...p })),
    }
  }

  /** Construct an immutable `HostFactLog` from a `ReceiptTranscript` or `HostSignedTranscript`. */
  static fromTranscript(
    transcript: ReceiptTranscript | HostSignedTranscript,
    options?: HostFactLogOptions,
  ): HostFactLog {
    const log = new HostFactLog(options)
    const entries = transcript.entries ?? []
    entries.forEach((rawEntry, index) => {
      const entry = rawEntry as HostTranscriptEntry
      const step = entry.step
      const rawReq = step.requestJson !== undefined
        ? (typeof step.requestJson === 'string' ? step.requestJson : JSON.stringify(step.requestJson))
        : parseBodyFromCarrierText(entry.carrierText)
      const rawResp = typeof step.body === 'string'
        ? step.body
        : step.json !== undefined
          ? JSON.stringify(step.json)
          : null
      log.recordExchange({
        seq: typeof entry.seq === 'number' && Number.isFinite(entry.seq) ? entry.seq : index + 1,
        exchangeId: entry.exchangeId,
        ...(entry.op ? { op: entry.op } : {}),
        method: step.method,
        origin: entry.origin ?? '',
        pathAndQuery: step.pathAndQuery ?? step.route ?? '/',
        status: step.status,
        requestHeaders: step.requestHeaders ?? null,
        rawRequestBody: rawReq,
        responseHeaders: step.responseHeaders ?? null,
        rawResponseBody: rawResp,
        actor: entry.actorPersona !== undefined ? entry.actorPersona : (step.actor.handle ?? null),
        actorRole: step.actor.role ?? null,
        actorRoleLabel: entry.actorRoleLabel ?? null,
        actorTenant: step.actor.tenant ?? null,
        ambientAuth: step.actor.auth,
        sameSite: step.actor.sameSite ?? null,
        durationMs: entry.durationMs ?? step.durationMs ?? 0,
        ...(entry.startedAt !== undefined ? { startedAt: entry.startedAt } : {}),
        ...(entry.endedAt !== undefined ? { endedAt: entry.endedAt } : {}),
        ...(entry.timestampMs !== undefined ? { timestampMs: entry.timestampMs } : {}),
        arm: step.arm,
        ...(entry.evidenceRole ?? step.evidenceRole ? { evidenceRole: entry.evidenceRole ?? step.evidenceRole } : {}),
        ...(entry.sessionId !== undefined ? { sessionId: entry.sessionId } : {}),
        ...(entry.consumedCapabilityId !== undefined ? { consumedCapabilityId: entry.consumedCapabilityId } : {}),
        ...(entry.consumedCapabilities ? { consumedCapabilities: entry.consumedCapabilities } : {}),
        ...(entry.emittedCapabilities ? { emittedCapabilities: entry.emittedCapabilities } : {}),
        ...(entry.observedResponseDigests ? { observedResponseDigests: entry.observedResponseDigests } : {}),
        ...(entry.injectedRequestDigests ? { injectedRequestDigests: entry.injectedRequestDigests } : {}),
        ...(entry.cryptoAttestations ? { cryptoAttestations: entry.cryptoAttestations } : {}),
        ...(entry.entityId !== undefined ? { entityId: entry.entityId } : {}),
        ...(entry.correlationIds ? { correlationIds: entry.correlationIds } : {}),
        ...(entry.cleanSession !== undefined ? { cleanSession: entry.cleanSession } : {}),
        ...(entry.replayAttempt !== undefined ? { replayAttempt: entry.replayAttempt } : {}),
        ...(entry.hostSignature !== undefined ? { hostSignature: entry.hostSignature } : {}),
        ...(entry.carrierText !== undefined ? { carrierText: entry.carrierText } : {}),
        ...(step.secretMatches ? { secretMatches: step.secretMatches } : {}),
      })
      if (entry.hostSignature && !log.signedEntries.has(entry.exchangeId)) {
        log.signedEntries.set(entry.exchangeId, freezeHostEntry(entry))
      }
    })
    for (const oob of transcript.oobEvents ?? []) log.recordOobEvent(oob)
    for (const trace of transcript.browserTraces ?? []) log.recordBrowserTrace(trace)
    if ('asyncPollRecords' in transcript && transcript.asyncPollRecords) {
      for (const poll of transcript.asyncPollRecords) log.recordAsyncPoll(poll)
    }
    return log
  }

  /** Construct an immutable `HostFactLog` from host-recorded `ScriptProofExchange` items. */
  static fromScriptExchanges(
    exchanges: readonly ScriptProofExchange[],
    oobEvents?: readonly ReceiptOobEvent[],
    options?: HostFactLogOptions,
  ): HostFactLog {
    const log = new HostFactLog(options)
    exchanges.forEach((ex, index) => {
      log.recordExchange({
        seq: typeof ex.seq === 'number' && Number.isFinite(ex.seq) ? ex.seq : index + 1,
        exchangeId: ex.exchangeId,
        ...(ex.op ? { op: ex.op } : {}),
        method: ex.method,
        origin: ex.origin,
        pathAndQuery: ex.pathAndQuery,
        status: ex.status,
        requestHeaders: ex.requestHeaders ?? null,
        rawRequestBody: ex.requestBody ?? null,
        responseHeaders: ex.responseHeaders ?? null,
        rawResponseBody: ex.body ?? null,
        actor: ex.personaHandle ?? null,
        actorRoleLabel: ex.actorRoleLabel ?? null,
        ambientAuth: ex.ambientAuth,
        ...(ex.sessionSameSite !== undefined ? { sameSite: ex.sessionSameSite } : {}),
        durationMs: ex.durationMs ?? 0,
        ...(ex.startedAt !== undefined ? { startedAt: ex.startedAt } : {}),
        ...(ex.endedAt !== undefined ? { endedAt: ex.endedAt } : {}),
        ...(ex.sessionRole !== undefined ? { sessionRole: ex.sessionRole } : {}),
        ...(ex.sessionId !== undefined ? { sessionId: ex.sessionId } : {}),
        ...(ex.consumedCapabilityId !== undefined ? { consumedCapabilityId: ex.consumedCapabilityId } : {}),
        ...(ex.consumedCapabilities ? { consumedCapabilities: ex.consumedCapabilities } : {}),
        ...(ex.artifact !== undefined ? { artifact: ex.artifact } : {}),
      })
    })
    for (const ev of oobEvents ?? []) log.recordOobEvent(ev)
    return log
  }

  /** Construct an immutable `HostFactLog` from a Layer-3 `TranscriptStore` + optional host transcript/raw bodies. */
  static fromTranscriptStore(
    store: TranscriptStore,
    opts?: {
      rawRequestBodies?: ReadonlyMap<string, string>
      rawResponseBodies?: ReadonlyMap<string, string>
      hostTranscript?: HostSignedTranscript | null
      sanitizer?: EgressSanitizer
    },
  ): HostFactLog {
    const log = new HostFactLog({ sanitizer: opts?.sanitizer })
    const hostEntriesById = new Map((opts?.hostTranscript?.entries ?? []).map(e => [e.exchangeId, e]))
    for (const record of store.list() as readonly VerifyTranscriptRecord[]) {
      const hostEntry = hostEntriesById.get(record.exchangeId)
      const req = record.request
      const rawReq = opts?.rawRequestBodies?.get(record.exchangeId)
        ?? store.requestBody?.(record.exchangeId)
        ?? (hostEntry?.step.requestJson !== undefined
          ? (typeof hostEntry.step.requestJson === 'string'
            ? hostEntry.step.requestJson
            : JSON.stringify(hostEntry.step.requestJson))
          : null)
      const rawResp = opts?.rawResponseBodies?.get(record.exchangeId)
        ?? hostEntry?.step.body
        ?? store.body(record.exchangeId)
        ?? null
      log.recordExchange({
        seq: record.seq,
        exchangeId: record.exchangeId,
        op: record.op,
        method: req?.method ?? (record.op === 'oob' ? 'OOB' : 'GET'),
        origin: req?.origin ?? '',
        pathAndQuery: req?.pathAndQuery ?? '/',
        status: record.response?.status ?? null,
        requestHeaders: req?.headers ?? hostEntry?.step.requestHeaders ?? null,
        rawRequestBody: rawReq,
        responseHeaders: record.response?.headers ?? hostEntry?.step.responseHeaders ?? null,
        rawResponseBody: rawResp,
        actor: req?.personaHandle ?? hostEntry?.actorPersona ?? null,
        actorRoleLabel: req?.actorRoleLabel ?? hostEntry?.actorRoleLabel ?? null,
        sameSite: hostEntry?.step.actor.sameSite ?? extractSameSiteFromHeaders(record.response?.headers ?? null),
        durationMs: record.durationMs,
        startedAt: record.startedAt,
        endedAt: record.startedAt + Math.max(0, record.durationMs),
        timestampMs: hostEntry?.timestampMs ?? record.startedAt,
        sessionRole: req?.sessionRole ?? null,
        ...(hostEntry?.evidenceRole ? { evidenceRole: hostEntry.evidenceRole } : {}),
        ...(req?.consumedCapabilityId !== undefined ? { consumedCapabilityId: req.consumedCapabilityId } : {}),
        ...(hostEntry?.consumedCapabilities ? { consumedCapabilities: hostEntry.consumedCapabilities } : {}),
        ...(hostEntry?.emittedCapabilities ? { emittedCapabilities: hostEntry.emittedCapabilities } : {}),
        ...(hostEntry?.observedResponseDigests ? { observedResponseDigests: hostEntry.observedResponseDigests } : {}),
        ...(hostEntry?.injectedRequestDigests ? { injectedRequestDigests: hostEntry.injectedRequestDigests } : {}),
        ...(hostEntry?.cryptoAttestations ? { cryptoAttestations: hostEntry.cryptoAttestations } : {}),
        ...(hostEntry?.entityId ? { entityId: hostEntry.entityId } : {}),
        ...(hostEntry?.correlationIds ? { correlationIds: hostEntry.correlationIds } : {}),
        ...(hostEntry?.cleanSession !== undefined ? { cleanSession: hostEntry.cleanSession } : {}),
        ...(hostEntry?.replayAttempt ? { replayAttempt: hostEntry.replayAttempt } : {}),
        ...(hostEntry?.hostSignature ? { hostSignature: hostEntry.hostSignature } : {}),
        ...(hostEntry?.carrierText ? { carrierText: hostEntry.carrierText } : {}),
        ...(record.artifact
          ? {
              artifact: {
                kind: record.artifact.kind,
                token: record.artifact.token,
                url: record.artifact.url,
                dnsHost: record.artifact.dnsHost,
                hit: record.artifact.hit,
              },
            }
          : {}),
      })
    }
    for (const oob of opts?.hostTranscript?.oobEvents ?? []) log.recordOobEvent(oob)
    for (const tr of opts?.hostTranscript?.browserTraces ?? []) log.recordBrowserTrace(tr)
    for (const poll of opts?.hostTranscript?.asyncPollRecords ?? []) log.recordAsyncPoll(poll)
    return log
  }

  /** Record a brokered HTTP exchange + its originating request directly into this log. */
  recordBrokerExchange(
    exchangeId: string,
    request: Pick<BrokerHttpRequest, 'origin' | 'method' | 'pathAndQuery' | 'headers' | 'body' | 'persona' | 'session'>,
    exchange: BrokerExchangeResult,
    meta?: {
      arm?: ImpactStep['arm']
      actorRoleLabel?: string | null
      actorRole?: RoleName | null
      actorTenant?: string | null
      evidenceRole?: string
      startedAt?: number
    },
  ): Readonly<HostExchangeFact> {
    return this.recordExchange({
      exchangeId,
      op: 'http',
      method: exchange.method || request.method,
      origin: exchange.origin || request.origin,
      pathAndQuery: exchange.pathAndQuery || request.pathAndQuery,
      status: exchange.status,
      requestHeaders: { ...(request.headers ?? {}), ...(exchange.reqHeaders ?? {}) },
      rawRequestBody: request.body ?? null,
      responseHeaders: exchange.respHeaders ?? null,
      rawResponseBody: exchange.body,
      actor: exchange.personaHandle ?? request.persona ?? null,
      actorRole: meta?.actorRole ?? null,
      actorRoleLabel: meta?.actorRoleLabel ?? null,
      actorTenant: meta?.actorTenant ?? null,
      durationMs: exchange.durationMs,
      ...(meta?.startedAt !== undefined ? { startedAt: meta.startedAt, endedAt: meta.startedAt + exchange.durationMs } : {}),
      ...(meta?.arm ? { arm: meta.arm } : {}),
      ...(meta?.evidenceRole ? { evidenceRole: meta.evidenceRole } : {}),
      ...(request.session ? { sessionId: request.session } : {}),
      ...(exchange.secretMatches?.length
        ? { secretMatches: exchange.secretMatches.slice(0, 16).map(m => m.sha256Prefix) }
        : {}),
    })
  }
}
