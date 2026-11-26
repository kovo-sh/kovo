/**
 * Pure HTTP exchange object-identifier harvesting helpers (v5 M2.1).
 *
 * Extracted from `store.ts` as a standalone, dependency-free leaf module and
 * re-exported by `store.ts` for full backward compatibility.
 */

export interface ExtractedResourceRef {
  /** Opaque object identifier observed in a path, JSON/GraphQL body, HTML link or redirect. */
  resourceId: string
  /** Concrete (or link) endpoint that exposed the identifier. */
  endpoint: string
  method: string
  /** Field/segment that carried the identifier, e.g. `invoiceId` or `path:invoices`. */
  field: string
}

export interface ResourceSampleRow {
  id: string
  runId: string
  ownerPersona: string
  resourceKey: string
  /** Collection the id belongs to (e.g. `/invoices`); absent on legacy rows (treated as `''`). */
  collectionPath?: string
  resourceId: string
  origin: string
  endpoint: string
  method: string
  mediaType: string | null
  authenticated: boolean
  createdAt: number
  updatedAt: number
}

export interface ResourceHarvestExchange {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  status: number
  mediaType: string
  body: string
  respHeaders?: Record<string, string> | null
}

export const RESOURCE_STATIC_ASSET_RE = /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf)(?:\?|$)/i
const RESOURCE_ID_KEY_RE = /^(?:id|uuid|guid|ref|slug|[a-z][a-z0-9]*[-_]?id|[a-z][a-z0-9]*Id|[a-z][a-z0-9_]*_id)$/i
const RESOURCE_IGNORED_VALUES = new Set([
  'true', 'false', 'null', 'undefined', 'default', 'self', 'me', 'current', 'none', 'all', 'new',
  'list', 'index', 'health', 'status', 'public', 'latest', 'recent', 'summary', 'search', 'create',
])
const RESOURCE_SECRET_VALUE_RE = /(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|-----BEGIN [^-\n]*PRIVATE KEY-----|^Bearer\s)/i
const RESOURCE_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const RESOURCE_MONGO_RE = /^[0-9a-f]{24}$/i
const RESOURCE_ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/i
const RESOURCE_NANOID_RE = /^[A-Za-z0-9_-]{12,21}$/
const RESOURCE_HASHID_RE = /^(?=[A-Za-z0-9]{6,32}$)(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9]+$/
const RESOURCE_NUMERIC_RE = /^\d{1,18}$/
const RESOURCE_PREFIXED_RE = /^(?:usr|org|proj|acct|app|ord|inv|doc|file|chat|team|sub|cus|ws|res|msg|pay|txn|evt|job|run|repo|prj|tenant|user|order|invoice|customer)_[A-Za-z0-9_-]{2,64}$/i
const RESOURCE_GENERIC_PREFIXED_RE = /^(?=[a-z]{1,4}_[A-Za-z0-9]{2,64}$)(?=.*[0-9])[A-Za-z0-9_]+$/i

function decodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

/**
 * True when a string looks like an opaque object identifier (never a credential). Supports
 * 1-digit numeric ids, UUIDs, 24-hex Mongo ObjectIDs, ULIDs, NanoIDs, hashids and prefixed ids.
 */
export function isOpaqueResourceId(raw: string, opts?: { keyed?: boolean }): boolean {
  const value = raw.trim()
  if (!value || value.length > 64) return false
  if (/\s/.test(value) || /[/?#]/.test(value)) return false
  if (RESOURCE_IGNORED_VALUES.has(value.toLowerCase())) return false
  if (RESOURCE_SECRET_VALUE_RE.test(value)) return false
  if (RESOURCE_UUID_RE.test(value)) return true
  if (RESOURCE_MONGO_RE.test(value)) return true
  if (RESOURCE_ULID_RE.test(value)) return true
  if (RESOURCE_PREFIXED_RE.test(value)) return true
  if (RESOURCE_GENERIC_PREFIXED_RE.test(value)) return true
  if (RESOURCE_NUMERIC_RE.test(value)) return true
  if (RESOURCE_NANOID_RE.test(value)) {
    // Path segments that are ordinary words should not be mistaken for NanoIDs; mixed case, a digit
    // or an underscore/url-safe separator is a strong opaque-id signal.
    if (opts?.keyed || /[0-9_]/.test(value) || /[a-z][A-Z]/.test(value)) return true
  }
  if (RESOURCE_HASHID_RE.test(value)) return true
  return false
}

/**
 * Normalize the collection a harvested identifier belongs to. Trailing opaque id segments are
 * dropped so `/invoices/42` and `/invoices` share the `/invoices` collection, while `/orders`
 * and `/tickets` never collide on a shared `id` field name.
 */
export function collectionPathFor(endpoint: string): string {
  const bare = (endpoint.split('?')[0]?.split('#')[0] ?? '').trim()
  const segments = bare.split('/').filter(Boolean)
  while (segments.length) {
    const last = decodePathSegment(segments[segments.length - 1]!)
    if (!isOpaqueResourceId(last)) break
    segments.pop()
  }
  const normalized = ('/' + segments.join('/')).slice(0, 512)
  return normalized === '/' ? '' : normalized
}

function sameOriginPath(raw: string, origin: string): string | null {
  const candidate = raw.trim()
  if (!candidate || candidate.startsWith('#') || /^(?:javascript|data|mailto):/i.test(candidate)) return null
  try {
    const base = new URL(origin)
    const parsed = new URL(candidate, base)
    if (parsed.origin !== base.origin) return null
    return `${parsed.pathname}${parsed.search}`
  } catch {
    return null
  }
}

/**
 * Extract object identifiers from an HTTP exchange. Bounded and redaction-safe: static assets,
 * secrets and ignored sentinel values are never returned. Unauthenticated responses are included
 * because they can leak identifiers that later enable cross-persona BOLA chains.
 */
export function extractResourceRefsFromExchange(ex: ResourceHarvestExchange): ExtractedResourceRef[] {
  if (ex.status < 200 || ex.status >= 400) return []
  if (RESOURCE_STATIC_ASSET_RE.test(ex.pathAndQuery) || ex.pathAndQuery.startsWith('/_next/static/')) return []

  const found: ExtractedResourceRef[] = []
  const seen = new Set<string>()
  const push = (rawId: string, endpoint: string, field: string) => {
    const clean = rawId.trim()
    if (!clean || !isOpaqueResourceId(clean, { keyed: !field.startsWith('path:') && !field.startsWith('href:') && !field.startsWith('location:') })) return
    if (found.length >= 16) return
    const key = `${endpoint}|${clean}`
    if (seen.has(key)) return
    seen.add(key)
    found.push({ resourceId: clean, endpoint, method: ex.method.toUpperCase(), field })
  }
  const pushPath = (pathAndQuery: string, fieldPrefix: string) => {
    const bare = pathAndQuery.split('?')[0].split('#')[0] || '/'
    const segments = bare.split('/').filter(Boolean)
    for (let i = 1; i < segments.length; i += 1) {
      const value = decodePathSegment(segments[i])
      const previous = decodePathSegment(segments[i - 1])
      if (/^v\d+$/i.test(previous)) continue
      if (!/^[A-Za-z][A-Za-z0-9_-]{0,40}$/.test(previous)) continue
      if (!isOpaqueResourceId(value)) continue
      push(value, bare, `${fieldPrefix}${previous}`)
    }
  }

  pushPath(ex.pathAndQuery, 'path:')

  // Redirect / creation Location headers commonly reveal the canonical item URL and its id.
  const location = Object.entries(ex.respHeaders ?? {})
    .find(([name]) => name.toLowerCase() === 'location')?.[1]
  if (location && (ex.status === 201 || (ex.status >= 300 && ex.status < 400))) {
    const near = sameOriginPath(location, ex.origin)
    if (near) pushPath(near, 'location:')
  }

  if (ex.mediaType.toLowerCase().includes('json') && ex.body && ex.body.length <= 512 * 1024) {
    try {
      const parsed = JSON.parse(ex.body) as unknown
      const basePath = ex.pathAndQuery.split('?')[0] || '/'
      const graphql = /graphql/i.test(ex.pathAndQuery) ||
        Boolean(parsed && typeof parsed === 'object' && 'data' in (parsed as Record<string, unknown>) &&
          ('errors' in (parsed as Record<string, unknown>) || !Array.isArray(parsed)))
      const maxDepth = graphql ? 24 : 8
      const walk = (node: unknown, depth: number, parentKey: string) => {
        if (depth > maxDepth || found.length >= 16 || !node || typeof node !== 'object') return
        if (Array.isArray(node)) {
          for (const item of node.slice(0, graphql ? 12 : 5)) walk(item, depth + 1, parentKey)
          return
        }
        for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
          if (found.length >= 16) break
          if (RESOURCE_ID_KEY_RE.test(key)) {
            if (typeof val === 'string') push(val, basePath, key)
            else if (typeof val === 'number' && Number.isInteger(val) && val >= 0) push(String(val), basePath, key)
          } else if (val && typeof val === 'object') {
            // Objects keyed by id, e.g. {"invoices": {"<objectId>": {...}}}.
            if (isOpaqueResourceId(key, { keyed: true }) && !parentKey) push(key, basePath, `key:${parentKey || 'map'}`)
            walk(val, depth + 1, key)
          }
        }
      }
      walk(parsed, 1, '')
    } catch {
      // Non-JSON or truncated body: fall through to markup extraction.
    }
  }

  if (/html/i.test(ex.mediaType) || /<a\b[^>]+href=/i.test(ex.body)) {
    for (const match of ex.body.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
      if (found.length >= 16) break
      const href = match[1] ?? match[2] ?? ''
      const near = sameOriginPath(href, ex.origin)
      if (near) pushPath(near, 'href:')
    }
  }

  return found
}

export type ResponseSignalEdgeKind = 'await_async' | 'hmac_sign' | 'lifecycle_state' | 'signed_url'
export interface ExtractedResponseStructuralSignal {
  field: string
  source: 'json' | 'header' | 'status'
  edgeKind: ResponseSignalEdgeKind
}

const SAFE_STRUCTURAL_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/
const ASYNC_JSON_KEY_RE = /^(?:(?:job|task|export|report|batch|run|workflow|operation|async|poll|queue|delivery|build|import|sync)[_-]?(?:id|uid|uuid|key|handle|token|ref|url|uri|href|path|endpoint|status|state)|(?:status|poll|result|progress|check)[_-]?(?:url|uri|href|path|endpoint))$/i
const HMAC_JSON_KEY_RE = /^(?:(?:webhook|signing|hmac|callback|hook|client|shared|integration)[_-]?(?:secret|key|signing[_-]?key|token|signature|hash|digest)|signing[_-]?(?:secret|key|material)|secret[_-]?key|hmac[_-]?(?:secret|key|signature)|signature[_-]?header|x[_-]?signature)$/i
const SIGNED_URL_JSON_KEY_RE = /^(?:(?:signed|presigned|pre[_-]?signed|download|upload|artifact|file|preview|share|temporary|temp|capability|access|storage)[_-]?(?:url|uri|href|link|path|token)|download[_-]?token|capability[_-]?token|share[_-]?token)$/i
const LIFECYCLE_JSON_KEY_RE = /^(?:status|state|phase|stage|lifecycle|workflow[_-]?state|approval[_-]?status|settlement[_-]?status|created[_-]?by|creator[_-]?id|owner[_-]?id|approver[_-]?id|approved[_-]?by|assignee[_-]?id|tenant[_-]?id|org[_-]?id|workspace[_-]?id|account[_-]?id|balance|amount|credit|debit|escrow|quota|version|etag|revision)$/i
const ASYNC_HEADER_RE = /^(?:x-(?:job|task|export|operation|async|queue|batch|run)-id|content-location|retry-after)$/i
const HMAC_HEADER_RE = /^(?:x-(?:hub-)?signature(?:-\d+)?|x-(?:webhook|hmac|request)-signature|x-signing-key|x-signature-timestamp|webhook-signature|signature)$/i
const SIGNED_URL_HEADER_RE = /^(?:x-(?:request|capability)-token|x-(?:download|signed|artifact|storage)-?(?:url|token|link))$/i
const LIFECYCLE_HEADER_RE = /^(?:etag|x-(?:resource|entity)-id|x-state|x-version)$/i
const SIGNED_URL_QUERY_HINT_RE = /[?&](?:sig|signature|token|expires|x-amz-|access_token)=/i

/** Secret-free field/header classifier into typed workflow edge kinds (preserves `RESOURCE_SECRET_VALUE_RE`). */
export function classifyStructuralFieldEdgeKind(
  fieldName: string,
  source: 'json' | 'header' = 'json',
  opts?: { status?: number; headerValueHint?: string },
): ResponseSignalEdgeKind | null {
  const clean = fieldName.trim()
  if (!clean || !SAFE_STRUCTURAL_FIELD_RE.test(clean) || RESOURCE_SECRET_VALUE_RE.test(clean)) return null
  if (source === 'header') {
    const lower = clean.toLowerCase()
    if (HMAC_HEADER_RE.test(lower)) return 'hmac_sign'
    if (ASYNC_HEADER_RE.test(lower)) return 'await_async'
    if (SIGNED_URL_HEADER_RE.test(lower)) return 'signed_url'
    if (lower === 'location') {
      if (opts?.status === 202) return 'await_async'
      if (opts?.headerValueHint && SIGNED_URL_QUERY_HINT_RE.test(opts.headerValueHint)) return 'signed_url'
      return opts?.status === 201 ? 'lifecycle_state' : null
    }
    return LIFECYCLE_HEADER_RE.test(lower) ? 'lifecycle_state' : null
  }
  if (HMAC_JSON_KEY_RE.test(clean)) return 'hmac_sign'
  if (ASYNC_JSON_KEY_RE.test(clean)) return 'await_async'
  if (SIGNED_URL_JSON_KEY_RE.test(clean)) return 'signed_url'
  return LIFECYCLE_JSON_KEY_RE.test(clean) || RESOURCE_ID_KEY_RE.test(clean) ? 'lifecycle_state' : null
}

/** Secret-free structural signal extractor returning ONLY bounded field/header names & edge-kind tags. */
export function extractResponseStructuralSignals(
  ex: Pick<ResourceHarvestExchange, 'status' | 'pathAndQuery' | 'mediaType' | 'body' | 'respHeaders'>,
  maxSignals = 32,
): ExtractedResponseStructuralSignal[] {
  if (ex.status < 200 || ex.status >= 400) return []
  if (RESOURCE_STATIC_ASSET_RE.test(ex.pathAndQuery) || ex.pathAndQuery.startsWith('/_next/static/')) return []
  const cap = Math.max(1, Math.min(64, Math.floor(maxSignals)))
  const out: ExtractedResponseStructuralSignal[] = [], seen = new Set<string>()
  const push = (field: string, source: 'json' | 'header' | 'status', edgeKind: ResponseSignalEdgeKind) => {
    if (out.length >= cap) return
    const key = `${source}:${field.toLowerCase()}:${edgeKind}`
    if (seen.has(key)) return
    seen.add(key); out.push({ field, source, edgeKind })
  }
  if (ex.status === 202) push('status:202', 'status', 'await_async')
  for (const [rawName, rawVal] of Object.entries(ex.respHeaders ?? {})) {
    if (out.length >= cap) break
    const lower = rawName.trim().toLowerCase()
    const hint = typeof rawVal === 'string' && !RESOURCE_SECRET_VALUE_RE.test(rawVal) ? rawVal : undefined
    const edgeKind = classifyStructuralFieldEdgeKind(lower, 'header', { status: ex.status, headerValueHint: hint })
    if (edgeKind) push(lower, 'header', edgeKind)
  }
  if (ex.mediaType.toLowerCase().includes('json') && ex.body && ex.body.length <= 512 * 1024) {
    try {
      const walk = (node: unknown, depth: number) => {
        if (depth > 6 || out.length >= cap || !node || typeof node !== 'object') return
        if (Array.isArray(node)) { for (const item of node.slice(0, 3)) walk(item, depth + 1); return }
        for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
          if (out.length >= cap) break
          const edgeKind = classifyStructuralFieldEdgeKind(key, 'json')
          if (edgeKind) push(key, 'json', edgeKind)
          if (val && typeof val === 'object') walk(val, depth + 1)
        }
      }
      walk(JSON.parse(ex.body) as unknown, 1)
    } catch { /* non-JSON or truncated body */ }
  }
  return out
}
