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
function isConcreteIdSegment(segment: string): boolean {
  return (
    UUID_SEGMENT.test(segment) ||
    MONGO_ID_SEGMENT.test(segment) ||
    NUMERIC_SEGMENT.test(segment) ||
    LONG_HEX_SEGMENT.test(segment) ||
    PREFIXED_ID_SEGMENT.test(segment) ||
    OPAQUE_TOKEN_SEGMENT.test(segment)
  )
}

function isIdLikeSegment(segment: string): boolean {
  return PLACEHOLDER_SEGMENT.test(segment) || isConcreteIdSegment(segment)
}

export type ApprovalPathPatternSource = 'card_path' | 'operator_explicit'

export interface NormalizeApprovalPathOptions {
  /**
   * Provenance of the input path (SECURITY-REAUDIT 1.3 / R3-H-9):
   * - `'card_path'` (default): worker-originated path from an approval card or target request.
   *   Literal `*` and `**` segments are escaped to `%2a` / `%2a%2a` so they match ONLY the exact
   *   literal path segment and never produce a wildcard or prefix glob. Concrete ID segments
   *   (numeric, UUID, Mongo ID, etc.) still generalize to `*`.
   * - `'operator_explicit'`: pattern explicitly authored by a human operator. Preserves `*`
   *   (single ID-shaped segment wildcard), `:id`/`{id}`/`[id]` placeholders, and trailing `**`
   *   (prefix wildcard, when accompanied by at least one fixed prefix segment).
   */
  source?: ApprovalPathPatternSource
}

export interface ApprovalPathGlobInspection {
  /** True when any pathname segment contains a `*` glob metacharacter. */
  hasGlobMetacharacters: boolean
  /** True when any pathname segment is an exact `*` or `**` wildcard segment. */
  hasWildcardSegment: boolean
  /** True when any pathname segment is the `**` prefix-glob segment. */
  hasPrefixGlobSegment: boolean
  /** Offending pathname segments containing `*`, in path order. */
  globSegments: string[]
}

const ORIGIN_PREFIX_RE = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i

/**
 * Inspect a worker-submitted request `pathAndQuery` for glob metacharacters (`*`, `**`) in its
 * pathname segments so approval cards can be flagged before operator review (R3-H-9).
 * Query strings and fragments are excluded because approval patterns operate on pathnames only.
 */
export function inspectApprovalPathGlobs(pathAndQuery: string): ApprovalPathGlobInspection {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  let pathname: string
  if (canonical !== null) {
    pathname = canonical.split('?', 1)[0]!
  } else {
    const trimmed = (pathAndQuery || '').trim()
    const withoutOrigin = ORIGIN_PREFIX_RE.test(trimmed) ? trimmed.replace(ORIGIN_PREFIX_RE, '') : trimmed
    const q = withoutOrigin.indexOf('?')
    const h = withoutOrigin.indexOf('#')
    const cut = q >= 0 && h >= 0 ? Math.min(q, h) : q >= 0 ? q : h
    pathname = cut >= 0 ? withoutOrigin.slice(0, cut) : withoutOrigin
  }

  const globSegments: string[] = []
  let hasWildcardSegment = false
  let hasPrefixGlobSegment = false
  for (const seg of pathname.split('/')) {
    if (!seg) continue
    if (seg.includes('*')) {
      globSegments.push(seg)
      if (seg === '*' || seg === '**') hasWildcardSegment = true
      if (seg === '**') hasPrefixGlobSegment = true
    }
  }
  return {
    hasGlobMetacharacters: globSegments.length > 0,
    hasWildcardSegment,
    hasPrefixGlobSegment,
    globSegments,
  }
}

export function hasApprovalPathGlobMetacharacters(pathAndQuery: string): boolean {
  return inspectApprovalPathGlobs(pathAndQuery).hasGlobMetacharacters
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

export function normalizeApprovalPathPattern(
  pathAndQuery: string,
  options?: NormalizeApprovalPathOptions,
): string {
  const source: ApprovalPathPatternSource = options?.source ?? 'card_path'
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
    if (seg === '*' || seg === '**') {
      if (source === 'operator_explicit') return seg
      // Escape literal worker-submitted glob segments so they match only the exact literal segment
      // and never become an ID wildcard or prefix glob (R3-H-9 / SECURITY-REAUDIT 1.3).
      return seg === '**' ? '%2a%2a' : '%2a'
    }
    if (source === 'operator_explicit' ? isIdLikeSegment(seg) : isConcreteIdSegment(seg)) {
      return '*'
    }
    return seg.toLowerCase()
  })

  return segments.join('/') || '/'
}

/**
 * Normalized segment view used for pattern matching. `wildcard` is true only for `*` and for
 * segments that are genuinely identifier-shaped; literals must match exactly (case-insensitively).
 * `**` is reserved for an explicit operator-approved prefix pattern and is only honoured as the
 * final segment with at least one fixed prefix segment.
 */
interface ApprovalPathSegment {
  value: string
  wildcard: boolean
}

function parseApprovalPathSegments(
  pathAndQuery: string,
  source: ApprovalPathPatternSource,
): ApprovalPathSegment[] {
  const normalized = normalizeApprovalPathPattern(pathAndQuery, { source })
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
  patterns: readonly (ApprovedEndpointPattern & { source?: ApprovalPathPatternSource })[] | undefined,
): ApprovedEndpointPattern | undefined {
  if (!patterns?.length) return undefined
  const targetOrigin = normalizeOriginKey(target.origin)
  const targetMethod = target.method.toUpperCase()
  const targetNormalized = normalizeApprovalPathPattern(target.pathAndQuery, { source: 'card_path' })
  if (!targetNormalized) return undefined
  const targetSegs = parseApprovalPathSegments(target.pathAndQuery, 'card_path')

  for (const pattern of patterns) {
    if (normalizeOriginKey(pattern.origin) !== targetOrigin) continue
    if (pattern.method.toUpperCase() !== targetMethod) continue
    const patternSource: ApprovalPathPatternSource = pattern.source ?? 'operator_explicit'
    const patSegs = parseApprovalPathSegments(pattern.pathPattern, patternSource)
    if (patSegs.length === 0) continue

    const prefixWildcard = patSegs[patSegs.length - 1]!.value === '**'
    // `**` is an explicit operator-approved prefix pattern. It is only valid as the last segment,
    // only when explicitly operator-authored, and must carry at least one fixed prefix segment
    // (`fixedLength >= 1`) so a bare `/**` can never become an origin-wide wildcard.
    if (patSegs.some((seg, i) => seg.value === '**' && i !== patSegs.length - 1)) continue
    const fixedLength = prefixWildcard ? patSegs.length - 1 : patSegs.length
    if (prefixWildcard && fixedLength === 0) continue
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
