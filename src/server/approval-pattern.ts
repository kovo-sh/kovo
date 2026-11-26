/**
 * Canonicalizes and matches operator-approved endpoint path patterns through the shared scope
 * path primitive, keeping admission, leases, denylists, and approvals on one interpretation.
 */
import { createHash } from 'node:crypto'
import type { ApprovedEndpointPattern } from '../domain.ts'
import { canonicalPathAndQuery } from './scope-policy.ts'

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MONGO_ID_SEGMENT = /^[0-9a-f]{24}$/i
const NUMERIC_SEGMENT = /^\d+$/
const LONG_HEX_SEGMENT = /^[0-9a-f]{16,}$/i
const PREFIXED_ID_SEGMENT = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
const OPAQUE_TOKEN_SEGMENT = /^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}$/
const PLACEHOLDER_SEGMENT = /^(?::[A-Za-z0-9_]+|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\])$/

/**
 * True only for genuinely identifier-shaped path segments (numeric, UUID, Mongo id, long hex,
 * prefixed id, or a high-entropy opaque token). A wildcard in an approved endpoint pattern must
 * never match a sibling verb or a literal path word: that is how an approval for
 * `POST /api/items/<id>` used to cover `POST /api/items/delete`.
 */
function isIdLikeSegment(segment: string): boolean {
  return (
    PLACEHOLDER_SEGMENT.test(segment) ||
    UUID_SEGMENT.test(segment) ||
    MONGO_ID_SEGMENT.test(segment) ||
    NUMERIC_SEGMENT.test(segment) ||
    LONG_HEX_SEGMENT.test(segment) ||
    PREFIXED_ID_SEGMENT.test(segment) ||
    OPAQUE_TOKEN_SEGMENT.test(segment)
  )
}

export function normalizeOriginKey(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase().replace(/\/+$/, '')
  }
}

/**
 * Canonicalize request headers into a deterministically ordered, lowercased record for approval
 * fingerprinting and batch target grouping (`H-4`).
 */
export function canonicalizeApprovalHeaders(
  headers?: Record<string, string | string[] | undefined>,
): Record<string, string> {
  if (!headers) return {}
  const entries: Array<[string, string]> = []
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const key = rawKey.trim().toLowerCase()
    if (!key) continue
    const value = Array.isArray(rawValue)
      ? rawValue.map(v => v.trim()).join(', ')
      : String(rawValue).trim()
    entries.push([key, value])
  }
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  const out: Record<string, string> = {}
  for (const [k, v] of entries) {
    out[k] = k in out ? `${out[k]}, ${v}` : v
  }
  return out
}

/**
 * Stable SHA-256 digest of canonicalized request headers (`H-4`). Returns `null` when no headers
 * are present so headerless requests have a distinct, explicit digest state.
 */
export function computeApprovalHeadersDigest(
  headers?: Record<string, string | string[] | undefined>,
): string | null {
  const canonical = canonicalizeApprovalHeaders(headers)
  const keys = Object.keys(canonical)
  if (keys.length === 0) return null
  const pairs = keys.map(k => [k, canonical[k]])
  return `hdr:${createHash('sha256').update(JSON.stringify(pairs), 'utf8').digest('hex')}`
}

export function normalizeApprovalPathPattern(pathAndQuery: string): string {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  if (canonical === null) return ''
  let pathname = canonical.split('?', 1)[0]!
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1)
  }

  const segments = pathname.split('/').map((seg, idx) => {
    if (idx === 0 && seg === '') return ''
    if (!seg) return ''
    if (seg === '*' || seg === '**') return seg
    if (isIdLikeSegment(seg)) return '*'
    return seg.toLowerCase()
  })

  return segments.join('/') || '/'
}

/**
 * Normalized segment view used for pattern matching. `wildcard` is true only for `*` and for
 * segments that are genuinely identifier-shaped; literals must match exactly (case-insensitively).
 * `**` is reserved for an explicit operator-approved prefix pattern and is only honoured as the
 * final segment.
 */
interface ApprovalPathSegment {
  value: string
  wildcard: boolean
}

function parseApprovalPathSegments(pathAndQuery: string): ApprovalPathSegment[] {
  const normalized = normalizeApprovalPathPattern(pathAndQuery)
  if (!normalized) return []
  return normalized
    .split('/')
    .filter(Boolean)
    .map(segment => {
      if (segment === '**') return { value: '**', wildcard: false }
      if (segment === '*') return { value: '*', wildcard: true }
      return { value: segment, wildcard: false }
    })
}

export function matchesApprovedEndpointPattern(
  target: { origin: string; method: string; pathAndQuery: string },
  patterns: readonly ApprovedEndpointPattern[] | undefined,
): ApprovedEndpointPattern | undefined {
  if (!patterns?.length) return undefined
  const targetOrigin = normalizeOriginKey(target.origin)
  const targetMethod = target.method.toUpperCase()
  const targetSegs = parseApprovalPathSegments(target.pathAndQuery)

  for (const pattern of patterns) {
    if (normalizeOriginKey(pattern.origin) !== targetOrigin) continue
    if (pattern.method.toUpperCase() !== targetMethod) continue
    const patSegs = parseApprovalPathSegments(pattern.pathPattern)
    if (patSegs.length === 0) continue

    const prefixWildcard = patSegs[patSegs.length - 1]!.value === '**'
    // `**` is an explicit operator-approved prefix pattern. It is only valid as the last segment
    // and only when the operator actually wrote it; a trailing `*` never matches arbitrary depth.
    if (patSegs.some((seg, i) => seg.value === '**' && i !== patSegs.length - 1)) continue
    const fixedLength = prefixWildcard ? patSegs.length - 1 : patSegs.length
    if (prefixWildcard ? targetSegs.length < fixedLength : targetSegs.length !== fixedLength) continue

    let matched = true
    for (let i = 0; i < fixedLength; i += 1) {
      const pat = patSegs[i]!
      const seg = targetSegs[i]!
      if (pat.wildcard) {
        // Wildcards (explicit `*`, `:id`, `{id}`, or an ID-like literal normalized to `*`) only
        // cover genuinely identifier-shaped targets. They never cover a sibling verb.
        if (!seg.wildcard) {
          matched = false
          break
        }
      } else if (pat.value !== seg.value) {
        matched = false
        break
      }
    }
    if (matched) return pattern
  }
  return undefined
}
