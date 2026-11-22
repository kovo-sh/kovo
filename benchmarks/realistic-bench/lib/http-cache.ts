// Optional per-route response cache (bounded LRU). A cache HIT served to an actor of a different
// tenant than the entry's owner, when the cached body carries a foreign canary, is a cache poisoning.
import type { Oracle } from './oracle.ts'
import type { CanaryRegistry } from './canary.ts'

export interface CacheOpts {
  queryKeys?: string[] // query params that participate in the cache key (others ignored)
  headerKey?: string // optional request header name that participates in the cache key
  ttlMs?: number // entry lifetime; default 60s
}

export interface CachedEntry {
  status: number
  body: string
  contentType: string
  tenant: string | null // tenant of the actor whose response populated the entry
  actor: string // actor who populated the entry
  expiresAt: number
}

export interface ResponseCache {
  keyFor(routeKey: string, path: string, query: Record<string, string | string[]>, headers: Record<string, string | undefined>, opts: CacheOpts): string
  get(key: string): CachedEntry | undefined
  set(key: string, entry: CachedEntry): void
  readonly size: number
}

const CANARY_RE = /rb[cs]_[a-z0-9]+_[0-9a-f]{12}/g

function qval(v: string | string[] | undefined): string {
  if (v === undefined) return ''
  return Array.isArray(v) ? v.join(',') : v
}

export function createResponseCache(opts?: { max?: number }): ResponseCache {
  const max = opts?.max ?? 256
  const map = new Map<string, CachedEntry>() // insertion order == LRU order

  return {
    keyFor(routeKey, path, query, headers, cacheOpts) {
      const parts = [routeKey, path]
      for (const qk of cacheOpts.queryKeys ?? []) parts.push(`${qk}=${qval(query[qk])}`)
      if (cacheOpts.headerKey) parts.push(`h:${cacheOpts.headerKey}=${headers[cacheOpts.headerKey.toLowerCase()] ?? ''}`)
      return parts.join('|')
    },
    get(key) {
      const entry = map.get(key)
      if (!entry) return undefined
      if (entry.expiresAt <= Date.now()) {
        map.delete(key)
        return undefined
      }
      // LRU bump
      map.delete(key)
      map.set(key, entry)
      return entry
    },
    set(key, entry) {
      if (map.has(key)) map.delete(key)
      map.set(key, entry)
      while (map.size > max) {
        const oldest = map.keys().next().value
        if (oldest === undefined) break
        map.delete(oldest)
      }
    },
    get size() {
      return map.size
    },
  }
}

/**
 * Inspect a cache HIT about to be served to `currentActor`/`currentTenant`. If the cached body holds
 * a canary owned by a different tenant (or a foreign actor's secret), emit `cache_poisoned`.
 * Returns true if an event was emitted.
 */
export function detectCachePoison(
  oracle: Oracle,
  canaries: CanaryRegistry | undefined,
  entry: CachedEntry,
  key: string,
  currentActor: string,
  currentTenant: string | null,
): boolean {
  if (!canaries) {
    // Without a canary registry, fall back to the host-content heuristic: a foreign owner's entry.
    if (entry.tenant !== null && entry.tenant !== currentTenant && entry.actor !== currentActor) {
      oracle.emit('cache_poisoned', { key, owner: entry.tenant, actorTenant: currentTenant ?? 'none' }, 'cache')
      return true
    }
    return false
  }
  const seen = new Set<string>()
  for (const m of entry.body.matchAll(CANARY_RE)) {
    const token = m[0]
    if (seen.has(token)) continue
    seen.add(token)
    const owner = canaries.ownerOf(token)
    if (!owner) continue
    const foreign = owner.kind === 'tenant' ? owner.owner !== currentTenant : owner.owner !== currentActor && owner.owner !== currentTenant
    if (foreign) {
      oracle.emit('cache_poisoned', { key, token, owner: owner.owner, actorTenant: currentTenant ?? 'none' }, 'cache')
      return true
    }
  }
  return false
}
