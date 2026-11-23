// In-memory session store with opaque 128-bit ids and a CSRF-token helper. Zero deps beyond node.
import { randomBytes } from 'node:crypto'

export interface SessionRecord {
  id: string
  data: Record<string, unknown>
  createdAt: number
  expiresAt: number
}

export interface SessionStore {
  /** Look up a session by id. Returns null for unknown or expired ids (expired ones are evicted). */
  get(id: string | null | undefined): SessionRecord | null
  /** Create a fresh session with a new opaque id. */
  create(): SessionRecord
  /** Destroy a session by id. */
  destroy(id: string): void
  /** Extend an existing session's lifetime. */
  touch(rec: SessionRecord): void
}

const CSRF_KEY = '__csrf'

/** Opaque, unguessable 128-bit session id (hex). */
export function newSessionId(): string {
  return randomBytes(16).toString('hex')
}

export function createSessionStore(opts?: { ttlMs?: number; now?: () => number }): SessionStore {
  const ttl = opts?.ttlMs ?? 30 * 60 * 1000
  const clock = opts?.now ?? Date.now
  const sessions = new Map<string, SessionRecord>()

  return {
    get(id) {
      if (!id) return null
      const rec = sessions.get(id)
      if (!rec) return null
      if (rec.expiresAt <= clock()) {
        sessions.delete(id)
        return null
      }
      return rec
    },
    create() {
      const now = clock()
      const rec: SessionRecord = { id: newSessionId(), data: {}, createdAt: now, expiresAt: now + ttl }
      sessions.set(rec.id, rec)
      return rec
    },
    destroy(id) {
      sessions.delete(id)
    },
    touch(rec) {
      rec.expiresAt = clock() + ttl
    },
  }
}

/** Issue (or reuse) a CSRF token bound to a session; returns the token string. */
export function issueCsrfToken(session: SessionRecord): string {
  const existing = session.data[CSRF_KEY]
  if (typeof existing === 'string' && existing.length > 0) return existing
  const token = randomBytes(16).toString('hex')
  session.data[CSRF_KEY] = token
  return token
}

/** True if `presented` matches the session's issued CSRF token (constant-ish compare). */
export function csrfTokenValid(session: SessionRecord | null, presented: string | undefined | null): boolean {
  if (!session || !presented) return false
  const expected = session.data[CSRF_KEY]
  if (typeof expected !== 'string' || expected.length === 0) return false
  if (expected.length !== presented.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ presented.charCodeAt(i)
  return diff === 0
}

// Mutable holder so the request handler and the response writer share one session reference.
export interface SessionHolder {
  rec: SessionRecord | null
}
export interface SessionHandle {
  readonly id: string | null
  get(key: string): unknown
  set(key: string, value: unknown): void
  destroy(): void
}

/**
 * Build the per-request session handle. `onCookie` is called with a Set-Cookie value whenever a new
 * session is created (login) or destroyed (logout), so the HTTP layer can emit it on the response.
 */
export function createSessionHandle(
  store: SessionStore,
  cookieName: string,
  holder: SessionHolder,
  onCookie: (setCookie: string) => void,
): SessionHandle {
  const ensure = (): SessionRecord => {
    if (!holder.rec) {
      holder.rec = store.create()
      onCookie(serializeSessionCookie(cookieName, holder.rec.id))
    }
    return holder.rec
  }
  return {
    get id() {
      return holder.rec?.id ?? null
    },
    get: (k) => holder.rec?.data[k],
    set(k, value) {
      const rec = ensure()
      rec.data[k] = value
      store.touch(rec)
    },
    destroy() {
      if (holder.rec) {
        store.destroy(holder.rec.id)
        onCookie(clearSessionCookie(cookieName))
        holder.rec = null
      }
    },
  }
}

function serializeSessionCookie(name: string, id: string): string {
  return `${name}=${id}; Path=/; HttpOnly; SameSite=Lax`
}
function clearSessionCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; Expires=${new Date(0).toUTCString()}`
}

/** Ensure a session exists then issue/reuse its CSRF token (used by the HTTP layer's reqCtx). */
export function ensureCsrfToken(store: SessionStore, holder: SessionHolder, cookieName: string, onCookie: (s: string) => void): string {
  if (!holder.rec) {
    holder.rec = store.create()
    onCookie(serializeSessionCookie(cookieName, holder.rec.id))
  }
  return issueCsrfToken(holder.rec)
}
