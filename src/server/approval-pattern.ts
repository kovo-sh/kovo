/**
 * Pure leaf module for normalizing and matching operator-approved endpoint path patterns.
 * Zero `src/server/*` dependencies so `store-runs.ts` and `approval-judge.ts` can both consume
 * it without creating a runtime import cycle through `model-settings.ts` -> `store.ts`.
 */
import type { ApprovedEndpointPattern } from '../domain.ts'

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

export function normalizeApprovalPathPattern(pathAndQuery: string): string {
  let pathname = (pathAndQuery || '/').trim()
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(pathname)) {
    try {
      pathname = new URL(pathname).pathname || '/'
    } catch {
      // Keep raw string
    }
  }
  const qIdx = pathname.indexOf('?')
  if (qIdx >= 0) pathname = pathname.slice(0, qIdx)
  const hIdx = pathname.indexOf('#')
  if (hIdx >= 0) pathname = pathname.slice(0, hIdx)
  if (!pathname.startsWith('/')) pathname = '/' + pathname
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
