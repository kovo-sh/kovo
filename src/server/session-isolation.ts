/**
 * v6 Layer-1 per-worker identity isolation.
 *
 * Concurrent floor and agentic workers must never share one mutable persona `.session`. Each
 * worker gets an independent composite session clone: credentials are shared, the cookie jar is
 * local, and a logout/token-swap in one clone cannot clear a sibling's session. The grant reads
 * the clone view lazily so a coordinated single-flight refresh or periodic `sessionPool.rotate()`
 * stays immediately visible to every live worker.
 */
import type { PersonaSessionClone } from './persona-auth.ts'
import type {
  MintedPersonaSession,
  PersonaCookieRecord,
  PersonaCredentialBundle,
  PersonaOriginAttachment,
  PersonaStorageSnapshot,
  ResolvedPersona,
} from './persona-vault.ts'

export interface ClonedWorkerPersona {
  persona: ResolvedPersona
  clone: PersonaSessionClone
}

interface ExtractedHeaderValue {
  headerType: MintedPersonaSession['headerType']
  headerName?: string
  value: string
}

function extractLiveHeaderValue(
  clone: PersonaSessionClone,
  originAllowlist: readonly string[],
  fallbackHeaderType: MintedPersonaSession['headerType'],
  fallbackHeaderName?: string,
): ExtractedHeaderValue | null {
  for (const origin of originAllowlist) {
    const headers = clone.headersFor(origin)
    if (!headers) continue
    const entries = Object.entries(headers)
    if (!entries.length) continue
    const cookieEntry = entries.find(([k]) => k.toLowerCase() === 'cookie')
    const authEntry = entries.find(([k]) => k.toLowerCase() === 'authorization')
    if (fallbackHeaderType === 'cookie' && cookieEntry?.[1]) {
      return { headerType: 'cookie', value: cookieEntry[1] }
    }
    if (fallbackHeaderType === 'bearer' && authEntry?.[1]) {
      return { headerType: 'bearer', value: authEntry[1].replace(/^Bearer\s+/i, '').trim() }
    }
    if (fallbackHeaderType === 'header') {
      const targetName = fallbackHeaderName?.toLowerCase()
      const matched = targetName
        ? entries.find(([k]) => k.toLowerCase() === targetName)
        : entries.find(([k]) => k.toLowerCase() !== 'cookie')
      if (matched?.[1]) {
        return { headerType: 'header', headerName: matched[0], value: matched[1] }
      }
    }
    // Header type may have changed across a session rotation when no direct pool getter was supplied.
    if (authEntry?.[1] && /^Bearer\s+/i.test(authEntry[1])) {
      return { headerType: 'bearer', value: authEntry[1].replace(/^Bearer\s+/i, '').trim() }
    }
    if (cookieEntry?.[1]) {
      return { headerType: 'cookie', value: cookieEntry[1] }
    }
    const [firstKey, firstVal] = entries[0]!
    if (firstVal) {
      return { headerType: 'header', headerName: firstKey, value: firstVal }
    }
  }
  return null
}

function parseCookieHeaderForOrigin(
  cookieHeader: string,
  origin: string,
  seen: Set<string>,
  out: PersonaCookieRecord[],
): void {
  let host = ''
  try { host = new URL(origin).hostname.toLowerCase() } catch { return }
  if (!host) return
  for (const pair of cookieHeader.split(';')) {
    const eq = pair.indexOf('=')
    if (eq <= 0) continue
    const name = pair.slice(0, eq).trim()
    const value = pair.slice(eq + 1).trim()
    if (!name || !value) continue
    const key = `${name}\0${host}\0/`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ name, value, domain: host, path: '/' })
  }
}

/** Build a clone-backed persona view, or `null` when the persona cannot be cloned. */
export function cloneWorkerPersona(
  persona: ResolvedPersona,
  assignmentId: string,
  cloneSession: (handle: string, workerId: string) => PersonaSessionClone | null,
  currentSession?: (handle: string) => MintedPersonaSession | null,
): ClonedWorkerPersona | null {
  if (persona.authKind !== 'login' || !persona.session) return null
  const clone = cloneSession(persona.handle, `worker:${assignmentId}`)
  if (!clone) return null

  const base = persona.session
  const fallbackHeaderName = base.headerName ?? persona.headerName ?? undefined
  const livePoolSession = (): MintedPersonaSession | null => currentSession?.(persona.handle) ?? null

  const collectCookies = (): PersonaCookieRecord[] => {
    if (clone.isLoggedOut()) return []
    const out: PersonaCookieRecord[] = []
    const seen = new Set<string>()
    for (const origin of persona.originAllowlist) {
      for (const cookie of clone.cookiesFor(origin)) {
        const key = `${cookie.name}\0${cookie.domain}\0${cookie.path}`
        if (seen.has(key)) continue
        seen.add(key)
        out.push(cookie)
      }
    }
    if (!out.length) {
      // Flat single `Cookie` session (no v2 composite bundle, e.g. Clerk `__client` / JSON login):
      // read the live rotated Cookie header dynamically from `clone.headersFor(origin)` so every
      // `sessionPool.rotate()` / 401 refresh propagates immediately to active workers.
      for (const origin of persona.originAllowlist) {
        const headers = clone.headersFor(origin)
        if (!headers) continue
        const cookieHeader = Object.entries(headers).find(([k]) => k.toLowerCase() === 'cookie')?.[1]
        if (cookieHeader) parseCookieHeaderForOrigin(cookieHeader, origin, seen, out)
      }
    }
    return out
  }

  const live: MintedPersonaSession = {
    get headerType(): MintedPersonaSession['headerType'] {
      if (clone.isLoggedOut()) return base.headerType
      const pool = livePoolSession()
      if (pool) return pool.headerType
      return extractLiveHeaderValue(clone, persona.originAllowlist, base.headerType, fallbackHeaderName)?.headerType
        ?? base.headerType
    },
    get headerName(): string | undefined {
      if (clone.isLoggedOut()) return base.headerName
      const pool = livePoolSession()
      if (pool) return pool.headerName
      return extractLiveHeaderValue(clone, persona.originAllowlist, base.headerType, fallbackHeaderName)?.headerName
        ?? base.headerName
    },
    // A logged-out clone exposes no credential value; active clones always read dynamically from the live session/clone.
    get value(): string {
      if (clone.isLoggedOut()) return ''
      const pool = livePoolSession()
      if (pool) return pool.value
      return extractLiveHeaderValue(clone, persona.originAllowlist, base.headerType, fallbackHeaderName)?.value ?? ''
    },
    get adapterUsed(): string {
      return livePoolSession()?.adapterUsed ?? base.adapterUsed
    },
    get expiresAt(): number | undefined {
      return livePoolSession()?.expiresAt ?? base.expiresAt
    },
    get scrubTokens(): string[] | undefined {
      return livePoolSession()?.scrubTokens ?? base.scrubTokens
    },
    get updatedAt(): number | undefined {
      return livePoolSession()?.updatedAt ?? base.updatedAt
    },
    get bundle(): PersonaCredentialBundle {
      // A logged-out clone exposes no credential material at all: no cookies, headers, storage.
      if (clone.isLoggedOut()) return { v: 2 }
      const cookies = collectCookies()
      const pool = livePoolSession()
      if (pool) {
        if (!pool.bundle) {
          return { v: 2, ...(cookies.length ? { cookies } : {}) }
        }
        const { cookies: _poolCookies, ...rest } = pool.bundle
        return { ...rest, v: 2, ...(cookies.length ? { cookies } : {}) }
      }

      // No direct pool getter supplied: reconstruct live bundle metadata dynamically from `clone`.
      let firstStorage: PersonaStorageSnapshot | null = null
      const storageOrigins: string[] = []
      const attachments: PersonaOriginAttachment[] = []
      let hasNonCookieHeaders = false

      for (const origin of persona.originAllowlist) {
        const headers = clone.headersFor(origin)
        const originCookies = clone.cookiesFor(origin)
        const storage = clone.storageFor(origin)
        if (!headers && !originCookies.length && !storage) continue
        const nonCookieHeaders: Record<string, string> = {}
        if (headers) {
          for (const [k, v] of Object.entries(headers)) {
            if (k.toLowerCase() === 'cookie') continue
            nonCookieHeaders[k] = v
            hasNonCookieHeaders = true
          }
        }
        if (storage) {
          if (!firstStorage) firstStorage = storage
          storageOrigins.push(origin)
        }
        const cookieNames = [...new Set(originCookies.map(c => c.name))]
        attachments.push({
          origin,
          ...(cookieNames.length ? { cookies: cookieNames } : {}),
          ...(Object.keys(nonCookieHeaders).length ? { headers: nonCookieHeaders } : {}),
          ...(storage ? {} : { storage: false as const }),
        })
      }

      // Flat bearer / custom-header session (no bundle, no cookies, no storage): return empty
      // bundle so `frameForSessionOrigin` falls through to live `headerType` + `value`.
      if (!base.bundle && !cookies.length && !firstStorage) {
        return { v: 2 }
      }
      // Flat cookie session without any non-cookie headers or storage: expose only live cookies.
      if (!base.bundle && !hasNonCookieHeaders && !firstStorage) {
        return { v: 2, ...(cookies.length ? { cookies } : {}) }
      }

      return {
        v: 2,
        ...(cookies.length ? { cookies } : {}),
        ...(attachments.length ? { attachments } : {}),
        ...(firstStorage ? { storage: firstStorage, storageOrigins } : {}),
      }
    },
  }
  // Drop the shared file path: the clone is the per-worker credential source, not the file.
  return {
    persona: { ...persona, sessionPath: undefined, sessionMtimeMs: undefined, sessionIno: undefined, session: live },
    clone,
  }
}
