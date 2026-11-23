// Small in-process permission cache. The neutral key includes both the user and the tenant the
// capabilities were evaluated for. `getForUser`/`setForUser` expose the older single-key form so a
// route module can opt into it; every lookup writes a telemetry row the host monitor can inspect.
import type { Db } from '../../../lib/db.ts'

export interface CacheEntry {
  role: string
  permissions: string[]
  org: string
  expiresAt: number
}

export interface PermissionCache {
  get(userExt: string, org: string): CacheEntry | undefined
  set(userExt: string, org: string, entry: Omit<CacheEntry, 'expiresAt' | 'org'> & { org?: string }): void
  getForUser(userExt: string): CacheEntry | undefined
  setForUser(userExt: string, entry: Omit<CacheEntry, 'expiresAt' | 'org'> & { org?: string }): void
  clear(): void
}

const TTL_MS = 30_000

export function createPermissionCache(db: Db, opts?: { ttlMs?: number; now?: () => number }): PermissionCache {
  const ttl = opts?.ttlMs ?? TTL_MS
  const clock = opts?.now ?? Date.now
  const entries = new Map<string, CacheEntry>()

  const record = (key: string, viewer: string, viewerOrg: string, entryOrg: string, hit: boolean, role: string): void => {
    db.run(
      'INSERT INTO perm_cache_events (key, viewer_user, viewer_org, entry_org, hit, detail) VALUES (?,?,?,?,?,?)',
      [key, viewer, viewerOrg, entryOrg, hit ? 1 : 0, JSON.stringify({ role })],
    )
  }

  return {
    get(userExt, org) {
      const key = `${userExt}:${org}`
      const entry = entries.get(key)
      const hit = !!entry && entry.expiresAt > clock()
      record(key, userExt, org, entry?.org ?? '', hit, entry?.role ?? '')
      if (!hit) return undefined
      return entry
    },
    set(userExt, org, entry) {
      entries.set(`${userExt}:${org}`, { ...entry, org: entry.org ?? org, expiresAt: clock() + ttl })
    },
    getForUser(userExt) {
      const key = `${userExt}`
      const entry = entries.get(key)
      const hit = !!entry && entry.expiresAt > clock()
      record(key, userExt, entry?.org ?? '', entry?.org ?? '', hit, entry?.role ?? '')
      if (!hit) return undefined
      return entry
    },
    setForUser(userExt, entry) {
      entries.set(`${userExt}`, { ...entry, org: entry.org ?? '', expiresAt: clock() + ttl })
    },
    clear() { entries.clear() },
  }
}
