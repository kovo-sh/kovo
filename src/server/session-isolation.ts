/**
 * v6 Layer-1 per-worker identity isolation.
 *
 * Concurrent floor and agentic workers must never share one mutable persona `.session`. Each
 * worker gets an independent composite session clone: credentials are shared, the cookie jar is
 * local, and a logout/token-swap in one clone cannot clear a sibling's session. The grant reads
 * the clone view lazily so a coordinated single-flight refresh stays visible to every live worker.
 */
import type { PersonaSessionClone } from './persona-auth.ts'
import type { MintedPersonaSession, PersonaCookieRecord, ResolvedPersona } from './persona-vault.ts'

export interface ClonedWorkerPersona {
  persona: ResolvedPersona
  clone: PersonaSessionClone
}

/** Build a clone-backed persona view, or `null` when the persona cannot be cloned. */
export function cloneWorkerPersona(
  persona: ResolvedPersona,
  assignmentId: string,
  cloneSession: (handle: string, workerId: string) => PersonaSessionClone | null,
): ClonedWorkerPersona | null {
  if (persona.authKind !== 'login' || !persona.session) return null
  const clone = cloneSession(persona.handle, `worker:${assignmentId}`)
  if (!clone) return null

  const base = persona.session
  const legacyCookie = base.headerType === 'cookie' ? base.value : ''
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
    if (!out.length && legacyCookie) {
      // Legacy single `Cookie` value (no composite bundle): scope one record per allowed origin
      // so the clone-local jar remains authoritative for each target host.
      for (const origin of persona.originAllowlist) {
        let host = ''
        try { host = new URL(origin).hostname.toLowerCase() } catch { continue }
        for (const pair of legacyCookie.split(';')) {
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
    }
    return out
  }

  const live: MintedPersonaSession = {
    headerType: base.headerType,
    ...(base.headerName ? { headerName: base.headerName } : {}),
    // A logged-out clone exposes no legacy fallback value either.
    get value(): string { return clone.isLoggedOut() ? '' : base.value },
    adapterUsed: base.adapterUsed,
    get bundle(): NonNullable<MintedPersonaSession['bundle']> {
      // A logged-out clone exposes no credential material at all: no cookies, headers, storage.
      if (clone.isLoggedOut()) return { v: 2 }
      const cookies = collectCookies()
      return { ...(base.bundle ?? {}), v: 2, ...(cookies.length ? { cookies } : {}) }
    },
  }
  // Drop the shared file path: the clone is the per-worker credential source, not the file.
  return {
    persona: { ...persona, sessionPath: undefined, sessionMtimeMs: undefined, sessionIno: undefined, session: live },
    clone,
  }
}
