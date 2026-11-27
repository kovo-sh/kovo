import { frameForSessionOrigin, resolveRunPersonas } from './persona-vault.ts'
import type { MintedPersonaSession } from './persona-vault.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'

export interface IsolatedPersonaSession {
  headers: Record<string, string>
  cookies?: Record<string, string>
}

export interface MintIsolatedSessionInput {
  runId: string
  personaHandle: string
  sessionKey: string
  origin?: string
}

export type MintIsolatedSessionHandler = (
  input: MintIsolatedSessionInput,
) => Promise<IsolatedPersonaSession | null>

export interface CachedIsolatedSession {
  headers: Record<string, string>
  mintedAt: number
}

export interface IsolatedPersonaTarget {
  storage: Store
  projectId: string
  personaId: string
}

const DEFAULT_MAX_ISOLATED_SESSIONS_PER_RUN = 64
const DEFAULT_MAX_ISOLATED_SESSION_RUNS = 64
const ISOLATED_SESSION_LABEL_RE = /(?:^|[-_])(?:control|ctrl|clean|isolated|iso|fresh)(?:$|[-_])/i
const ISOLATED_SECRET_HEADER_RE = /^(?:authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|x-session-token)$/i

/**
 * Determine whether a brokered request should use an isolated per-`(runId, sessionKey, personaHandle)`
 * credential instead of the shared run-wide persona session.
 *
 * Triggers for:
 *  - any `sessionGroupRole === 'control'` request (isolated from both shared run state and probe arms), or
 *  - an explicit distinct named `session` (without `sessionGroupRole`, or labeled control/clean/isolated/fresh).
 *
 * Skips anonymous requests, explicit `authMutation` probes, `cleanup` requests, and synchronized race bursts.
 */
export function resolveIsolatedSessionKey(
  req: {
    sessionGroupRole?: string
    session?: string
    assignmentId?: string
    authMutation?: unknown
  },
  options: { raceBurst?: boolean; personaHandle?: string } = {},
): string | null {
  if (!options.personaHandle || req.authMutation || options.raceBurst) return null
  const assignment = typeof req.assignmentId === 'string' && req.assignmentId.trim() ? req.assignmentId.trim() : 'default'
  const rawSession = typeof req.session === 'string' ? req.session.trim() : ''
  if (req.sessionGroupRole === 'control') {
    return `control:${assignment}:${rawSession || 'default'}`
  }
  if (
    rawSession &&
    rawSession !== 'default' &&
    req.sessionGroupRole !== 'cleanup' &&
    (req.sessionGroupRole === undefined || ISOLATED_SESSION_LABEL_RE.test(rawSession))
  ) {
    return `session:${assignment}:${rawSession}`
  }
  return null
}

/** Normalize an `IsolatedPersonaSession` into canonical persona headers preserving Cookie pairs. */
export function isolatedSessionToPersonaHeaders(session: IsolatedPersonaSession | null | undefined): Record<string, string> | null {
  if (!session || typeof session !== 'object') return null
  const out: Record<string, string> = {}
  let cookieKey: string | null = null
  for (const [k, v] of Object.entries(session.headers ?? {})) {
    if (typeof v !== 'string' || !v.trim()) continue
    out[k] = v
    if (k.toLowerCase() === 'cookie') cookieKey = k
  }
  const extraCookies = session.cookies ? Object.entries(session.cookies).filter(([k, v]) => Boolean(k) && typeof v === 'string' && v.length > 0) : []
  if (extraCookies.length > 0) {
    const cookieMap = new Map<string, string>()
    if (cookieKey && out[cookieKey]) {
      for (const pair of out[cookieKey].split(';')) {
        const idx = pair.indexOf('=')
        if (idx <= 0) continue
        const name = pair.slice(0, idx).trim()
        const value = pair.slice(idx + 1).trim()
        if (name) cookieMap.set(name, value)
      }
    }
    for (const [k, v] of extraCookies) {
      if (!cookieMap.has(k)) cookieMap.set(k, v)
    }
    const serialized = [...cookieMap.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
    if (serialized) {
      if (cookieKey && cookieKey !== 'Cookie') delete out[cookieKey]
      out.Cookie = serialized
    }
  }
  return Object.keys(out).length > 0 ? out : null
}

/** Extract non-empty secret needles from isolated persona headers so broker redaction never leaks them. */
export function extractIsolatedSessionSecrets(personaHandle: string, headers: Record<string, string>): NamedSecret[] {
  const out: NamedSecret[] = []
  const seen = new Set<string>()
  const push = (name: string, value: string) => {
    const trimmed = value.trim()
    if (trimmed.length < 6 || seen.has(trimmed)) return
    seen.add(trimmed)
    out.push({ placeholder: `[redacted:${name}]`, value: trimmed })
  }
  for (const [k, v] of Object.entries(headers)) {
    const lower = k.toLowerCase()
    if (ISOLATED_SECRET_HEADER_RE.test(lower)) {
      push(`isolated:${personaHandle}:${lower}`, v)
      const bearer = /^Bearer\s+(.+)$/i.exec(v.trim())
      if (bearer?.[1]) push(`isolated:${personaHandle}:bearer`, bearer[1])
    } else if (lower === 'cookie') {
      for (const pair of v.split(';')) {
        const idx = pair.indexOf('=')
        if (idx <= 0) continue
        const name = pair.slice(0, idx).trim()
        const val = pair.slice(idx + 1).trim()
        if (name && val.length >= 8) push(`isolated:${personaHandle}:cookie:${name}`, val)
      }
    }
  }
  return out
}

/** Project a newly minted `MintedPersonaSession` to `{ headers, cookies? }` for `origin` without persisting. */
export function mintedSessionToIsolatedResult(
  session: MintedPersonaSession,
  allowlist: readonly string[],
  origin: string,
  headerName?: string | null,
): IsolatedPersonaSession | null {
  const frame = frameForSessionOrigin(session, allowlist, origin, headerName)
  if (!frame || Object.keys(frame.headers).length === 0) return null
  const cookies: Record<string, string> = {}
  for (const c of frame.cookies) {
    if (c.name && c.value) cookies[c.name] = c.value
  }
  return {
    headers: { ...frame.headers },
    ...(Object.keys(cookies).length > 0 ? { cookies } : {}),
  }
}

/** Locate `{ storage, projectId, personaId }` for isolated minting from run registry or store fallback. */
export function resolveIsolatedPersonaTarget(
  personaHandle: string,
  runId: string | undefined,
  registered: IsolatedPersonaTarget | undefined,
  options: { storage?: Store; projectId?: string; personaId?: string },
): IsolatedPersonaTarget | null {
  if (registered) return registered
  if (!options.storage) return null
  if (options.projectId && options.personaId) {
    return { storage: options.storage, projectId: options.projectId, personaId: options.personaId }
  }
  if (!runId) return null
  try {
    const run = options.storage.run(runId)
    const found = resolveRunPersonas(options.storage, run.projectId, run.approvedPersonaIds).get(personaHandle)
    if (!found) return null
    return { storage: options.storage, projectId: run.projectId, personaId: found.id }
  } catch {
    return null
  }
}

/** Merge session-jar cookies with Persona Vault cookies, tracking provenance names cleanly for H1 & H2. */
export function mergeJarAndVaultCookieMaps<T extends { value: string }>(params: {
  jarCookieByName: ReadonlyMap<string, T>
  vaultCookies: ReadonlyMap<string, string>
  supersedes: (entry: T, vaultVal: string) => boolean
}): {
  mergedCookies: Map<string, string>
  jarCookieNames: string[]
  vaultCookieNames: string[]
} {
  const mergedCookies = new Map<string, string>()
  const jarCookieNames: string[] = []
  const vaultCookieNames: string[] = []
  for (const [name, entry] of params.jarCookieByName) {
    const vaultVal = params.vaultCookies.get(name)
    if (vaultVal === undefined || params.supersedes(entry, vaultVal)) {
      mergedCookies.set(name, entry.value)
      jarCookieNames.push(name)
    }
  }
  for (const [k, v] of params.vaultCookies) {
    const jarEntry = params.jarCookieByName.get(k)
    if (jarEntry && params.supersedes(jarEntry, v)) continue
    mergedCookies.set(k, v)
    vaultCookieNames.push(k)
  }
  return { mergedCookies, jarCookieNames, vaultCookieNames }
}

/** Apply persona headers (excluding cross-origin sensitive headers on redirect hops) and extract vault Cookie header + names. */
export function injectPersonaHeadersOntoOutbound(params: {
  includePersona: boolean
  personaHeaders: Record<string, string> | undefined
  outboundHeaders: Record<string, string>
  stripSensitiveHeaders: boolean
  crossOriginSensitiveHeaders?: ReadonlySet<string>
  setHeader: (headers: Record<string, string>, name: string, value: string) => void
}): { personaCookieRaw: string | undefined; vaultHeaderNames: string[] } {
  let personaCookieRaw: string | undefined
  const vaultHeaderNames: string[] = []
  if (params.includePersona && params.personaHeaders) {
    for (const [k, v] of Object.entries(params.personaHeaders)) {
      const lower = k.toLowerCase()
      if (lower === 'cookie') {
        personaCookieRaw = v
      } else if (!(params.stripSensitiveHeaders && params.crossOriginSensitiveHeaders?.has(lower))) {
        params.setHeader(params.outboundHeaders, k, v)
        vaultHeaderNames.push(lower)
      }
    }
  }
  return { personaCookieRaw, vaultHeaderNames }
}

/** Filter session-jar cookies eligible for `url` under domain/path/secure/expiry/SameSite rules. */
export function selectEligibleJarCookies<
  T extends { name: string; expiresAt?: number; secure: boolean; path: string; sameSite?: string | null },
>(params: {
  cookies: Iterable<T> | undefined
  url: URL
  isCrossOriginHop: boolean
  activeMethod: string
  domainMatches: (entry: T, url: URL) => boolean
  pathMatches: (requestPath: string, cookiePath: string) => boolean
}): Map<string, T> {
  const jarCookieByName = new Map<string, T>()
  if (!params.cookies) return jarCookieByName
  const now = Date.now()
  for (const entry of params.cookies) {
    if (!params.domainMatches(entry, params.url)) continue
    if (entry.expiresAt !== undefined && entry.expiresAt <= now) continue
    if (entry.secure && params.url.protocol !== 'https:') continue
    if (!params.pathMatches(params.url.pathname, entry.path)) continue
    const sameSiteLower = entry.sameSite?.toLowerCase()
    if (params.isCrossOriginHop && sameSiteLower === 'strict') continue
    if (params.isCrossOriginHop && sameSiteLower === 'lax' && params.activeMethod !== 'GET' && params.activeMethod !== 'HEAD') continue
    jarCookieByName.set(entry.name, entry)
  }
  return jarCookieByName
}

/**
 * Bounded, run-scoped isolated persona credential cache keyed by `(runId, sessionKey, personaHandle, origin)`.
 * Single-flight deduplicates concurrent mints for the same key and clears cleanly via `disposeRun(runId)`.
 */
export class IsolatedSessionCache {
  private readonly entriesByRun = new Map<string, Map<string, CachedIsolatedSession>>()
  private readonly inFlightByRun = new Map<string, Map<string, Promise<CachedIsolatedSession | null>>>()
  private readonly maxPerRun: number
  private readonly maxRuns: number

  constructor(maxPerRun = DEFAULT_MAX_ISOLATED_SESSIONS_PER_RUN, maxRuns = DEFAULT_MAX_ISOLATED_SESSION_RUNS) {
    this.maxPerRun = Math.max(1, maxPerRun)
    this.maxRuns = Math.max(1, maxRuns)
  }

  private cacheKey(sessionKey: string, personaHandle: string, origin: string): string {
    return `${sessionKey}\0${personaHandle}\0${origin}`
  }

  async getOrMint(
    input: { runId: string; sessionKey: string; personaHandle: string; origin: string },
    mint: MintIsolatedSessionHandler,
  ): Promise<CachedIsolatedSession | null> {
    const key = this.cacheKey(input.sessionKey, input.personaHandle, input.origin)
    const runMap = this.entriesByRun.get(input.runId)
    const hit = runMap?.get(key)
    if (hit) {
      runMap!.delete(key)
      runMap!.set(key, hit)
      return { headers: { ...hit.headers }, mintedAt: hit.mintedAt }
    }

    let runInFlight = this.inFlightByRun.get(input.runId)
    const pending = runInFlight?.get(key)
    if (pending) {
      const awaited = await pending
      return awaited ? { headers: { ...awaited.headers }, mintedAt: awaited.mintedAt } : null
    }
    if (!runInFlight) {
      runInFlight = new Map()
      this.inFlightByRun.set(input.runId, runInFlight)
    }

    let task!: Promise<CachedIsolatedSession | null>
    task = (async (): Promise<CachedIsolatedSession | null> => {
      try {
        const raw = await mint({
          runId: input.runId,
          personaHandle: input.personaHandle,
          sessionKey: input.sessionKey,
          origin: input.origin,
        })
        const headers = isolatedSessionToPersonaHeaders(raw)
        if (!headers) return null
        const entry: CachedIsolatedSession = { headers, mintedAt: Date.now() }
        // Guard against race with `disposeRun` while mint was in flight.
        if (this.inFlightByRun.get(input.runId)?.get(key) === task) {
          this.storeEntry(input.runId, key, entry)
        }
        return entry
      } catch {
        return null
      } finally {
        const cur = this.inFlightByRun.get(input.runId)
        if (cur?.get(key) === task) {
          cur.delete(key)
          if (cur.size === 0) this.inFlightByRun.delete(input.runId)
        }
      }
    })()

    runInFlight.set(key, task)
    const minted = await task
    return minted ? { headers: { ...minted.headers }, mintedAt: minted.mintedAt } : null
  }

  private storeEntry(runId: string, key: string, entry: CachedIsolatedSession): void {
    let runMap = this.entriesByRun.get(runId)
    if (!runMap) {
      if (this.entriesByRun.size >= this.maxRuns) {
        const oldestRun = this.entriesByRun.keys().next().value
        if (oldestRun !== undefined) this.entriesByRun.delete(oldestRun)
      }
      runMap = new Map()
      this.entriesByRun.set(runId, runMap)
    }
    if (runMap.has(key)) {
      runMap.delete(key)
    } else if (runMap.size >= this.maxPerRun) {
      const oldestKey = runMap.keys().next().value
      if (oldestKey !== undefined) runMap.delete(oldestKey)
    }
    runMap.set(key, entry)
  }

  evictEntry(runId: string, sessionKey: string, personaHandle: string, origin: string): void {
    const key = this.cacheKey(sessionKey, personaHandle, origin)
    const runMap = this.entriesByRun.get(runId)
    if (runMap) {
      runMap.delete(key)
      if (runMap.size === 0) this.entriesByRun.delete(runId)
    }
    const runInFlight = this.inFlightByRun.get(runId)
    if (runInFlight) {
      runInFlight.delete(key)
      if (runInFlight.size === 0) this.inFlightByRun.delete(runId)
    }
  }

  evictPersona(runId: string, personaHandle: string): void {
    const needle = `\0${personaHandle}\0`
    const runMap = this.entriesByRun.get(runId)
    if (runMap) {
      for (const k of [...runMap.keys()]) {
        if (k.includes(needle)) runMap.delete(k)
      }
      if (runMap.size === 0) this.entriesByRun.delete(runId)
    }
    const runInFlight = this.inFlightByRun.get(runId)
    if (runInFlight) {
      for (const k of [...runInFlight.keys()]) {
        if (k.includes(needle)) runInFlight.delete(k)
      }
      if (runInFlight.size === 0) this.inFlightByRun.delete(runId)
    }
  }

  disposeRun(runId: string): void {
    this.entriesByRun.delete(runId)
    this.inFlightByRun.delete(runId)
  }

  countForRun(runId: string): number {
    return this.entriesByRun.get(runId)?.size ?? 0
  }
}

export async function resolveEffectiveBrokerPersonaHeaders(params: {
  req: { sessionGroupRole?: string; session?: string; assignmentId?: string; authMutation?: unknown }
  runId: string
  initialOrigin: string
  personaHandle: string | undefined
  fallbackHeaders: Record<string, string> | undefined
  refreshedHeaders: Record<string, string> | undefined
  extraSecrets: NamedSecret[]
  isolatedSessions: IsolatedSessionCache
  mintIsolatedSession?: MintIsolatedSessionHandler
  raceBurst?: boolean
}): Promise<{ personaHeaders: Record<string, string> | undefined; isolatedKey: string | null; isolatedMintedAt: number }> {
  const { req, runId, initialOrigin, personaHandle, fallbackHeaders, refreshedHeaders, extraSecrets, isolatedSessions, mintIsolatedSession, raceBurst } = params
  const isolatedKey = resolveIsolatedSessionKey(req, { raceBurst, personaHandle })
  if (refreshedHeaders) {
    if (isolatedKey && personaHandle) extraSecrets.push(...extractIsolatedSessionSecrets(personaHandle, refreshedHeaders))
    return { personaHeaders: refreshedHeaders, isolatedKey, isolatedMintedAt: isolatedKey ? Date.now() : 0 }
  }
  if (isolatedKey && personaHandle && mintIsolatedSession) {
    const cached = await isolatedSessions.getOrMint({ runId, sessionKey: isolatedKey, personaHandle, origin: initialOrigin }, mintIsolatedSession)
    if (cached) {
      extraSecrets.push(...extractIsolatedSessionSecrets(personaHandle, cached.headers))
      return { personaHeaders: cached.headers, isolatedKey, isolatedMintedAt: cached.mintedAt }
    }
  }
  return { personaHeaders: fallbackHeaders, isolatedKey: null, isolatedMintedAt: 0 }
}

export async function refreshBrokerPersonaHeadersForRetry(params: {
  runId: string
  reauthRunId?: string
  initialOrigin: string
  urlOrigin: string
  personaHandle: string
  isolatedKey: string | null
  isolatedSessions: IsolatedSessionCache
  mintIsolatedSession?: MintIsolatedSessionHandler
  reauthHandler?: (personaHandle: string, runId?: string, origin?: string) => Promise<boolean | void>
  rebuildSharedHeaders: () => Record<string, string> | null
  clearJarCookies: (rebuilt: Record<string, string> | null) => void
}): Promise<{ ok: boolean; rebuilt?: Record<string, string> }> {
  const { runId, reauthRunId, initialOrigin, urlOrigin, personaHandle, isolatedKey, isolatedSessions, mintIsolatedSession, reauthHandler, rebuildSharedHeaders, clearJarCookies } = params
  if (isolatedKey && mintIsolatedSession) {
    isolatedSessions.evictEntry(runId, isolatedKey, personaHandle, initialOrigin)
    const reminted = await isolatedSessions.getOrMint({ runId, sessionKey: isolatedKey, personaHandle, origin: initialOrigin }, mintIsolatedSession)
    if (!reminted) return { ok: false }
    clearJarCookies(reminted.headers)
    return { ok: true, rebuilt: reminted.headers }
  }
  if (!reauthHandler) return { ok: false }
  const refreshed = await reauthHandler(personaHandle, reauthRunId, urlOrigin).catch(() => false)
  if (refreshed === false) return { ok: false }
  const rebuilt = rebuildSharedHeaders()
  clearJarCookies(rebuilt)
  return { ok: true, ...(rebuilt ? { rebuilt } : {}) }
}
