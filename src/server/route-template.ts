/**
 * Canonical route-template normalizer shared across recon, static program-graph extraction,
 * and execution/planner route matching. Pure leaf module with zero `src/server/*` imports.
 */

export interface RouteTemplateOptions {
  /**
   * Preserve literal segment casing (`true` by default for request/discovery paths such as
   * `/trpc/user.getById` or `/api/getInvoice`; pass `false` for case-insensitive dedupe).
   */
  preserveCase?: boolean
  /**
   * Preserve parameter names (`:orgId`, `{orgId}`, `<int:user_id>` -> `:orgId` / `:user_id`)
   * instead of collapsing placeholders to `:id`. Default `false`.
   */
  preserveParamNames?: boolean
  /**
   * Preserve existing Express `:name` parameter names while collapsing bracketed/braced/angled
   * framework tokens (`[id]`, `{id}`, `<int:id>`) to `:id` (discovery template mode).
   */
  preserveColonParams?: boolean
  /**
   * Collapse concrete runtime ID segments (UUIDs, ULIDs, numeric IDs, hex/base64url opaque
   * tokens, prefixed IDs) to `:id`. Default `true`.
   */
  collapseConcreteIds?: boolean
}

const EXPRESS_PARAM_RE = /^:([A-Za-z_][A-Za-z0-9_-]{0,63})$/
const NEXT_PARAM_RE = /^\[{1,2}(?:\.\.\.)?([A-Za-z_][A-Za-z0-9_-]{0,63})\]{1,2}$/
const OPENAPI_PARAM_RE = /^\{([A-Za-z_][A-Za-z0-9_-]{0,63})\}$/
const DJANGO_PARAM_RE = /^<(?:[A-Za-z0-9_]+:)?([A-Za-z_][A-Za-z0-9_-]{0,63})>$/
const GENERIC_BRACKET_PARAM_RE = /^(?:\[[^\]]{1,64}\]|\{[^}]{1,64}\}|<[^>]{1,64}>)$/

const VERSION_OR_PROTOCOL_SEGMENT_RE =
  /^(?:api[_-]?v\d+|v\d+(?:[_-](?:alpha|beta|rc)\d*)?|oauth[_-]?2|http[_-]?2|2fa|utf[_-]?8|sha[_-]?256|base[_-]?64)$/i
const UUID_SEGMENT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ULID_SEGMENT_RE = /^(?=.*\d)[0-9A-HJKMNP-TV-Z]{26}$/i
const NUMERIC_SEGMENT_RE = /^\d+$/
const PREFIXED_OR_BARE_HEX_RE = /^(?:[a-z]{1,10}[_-])?[0-9a-f]{8,}$/i
const PREFIXED_DIGIT_ID_RE = /^[a-z]{1,12}[_-][0-9a-z]*\d[0-9a-z_-]*$/i
const PREFIXED_MIXED_CASE_ID_RE = /^[a-z]{2,6}_(?=.*[A-Z])(?=.*[a-z])[A-Za-z0-9]{4,}$/
const PREFIXED_ALPHA_SHORT_ID_RE = /^(?!api_|get_|set_|add_|new_|all_|top_|sub_|old_|raw_|app_|web_|dev_|ops_|doc_|log_|map_|tag_|key_|url_|uri_|src_|dst_|pub_|run_|job_)[a-z]{2,6}_[a-z0-9]{4,}$/
const COMPACT_PREFIX_NUM_ID_RE = /^(?!sha256$|base64$|oauth2$|http2$|es20\d\d$)[a-z]{2,8}\d{3,}$/i
const OPAQUE_TOKEN_RE =
  /^(?:(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{14,}|(?=(?:.*\d){2})(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}|(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9_-]{12,})$/
const REDACTED_PLACEHOLDER_RE = /\[redacted(?::[^\]]*)?\]/i
const CAPABILITY_HANDLE_RE = /^cap:[a-z0-9_.:-]+$/i

const STATIC_SNAKE_WORDS = new Set([
  'user_feed',
  'user_profile',
  'api_keys',
  'health_check',
  'audit_log',
  'rate_limit',
  'feature_flags',
  'sign_in',
  'sign_out',
  'sign_up',
])

function decodeSegmentSafe(segment: string): string {
  if (!segment.includes('%')) return segment
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

function isConcreteIdSegment(decoded: string): boolean {
  if (VERSION_OR_PROTOCOL_SEGMENT_RE.test(decoded)) return false
  if (STATIC_SNAKE_WORDS.has(decoded.toLowerCase())) return false
  return (
    UUID_SEGMENT_RE.test(decoded) ||
    ULID_SEGMENT_RE.test(decoded) ||
    NUMERIC_SEGMENT_RE.test(decoded) ||
    PREFIXED_OR_BARE_HEX_RE.test(decoded) ||
    PREFIXED_DIGIT_ID_RE.test(decoded) ||
    PREFIXED_MIXED_CASE_ID_RE.test(decoded) ||
    PREFIXED_ALPHA_SHORT_ID_RE.test(decoded) ||
    COMPACT_PREFIX_NUM_ID_RE.test(decoded) ||
    OPAQUE_TOKEN_RE.test(decoded) ||
    REDACTED_PLACEHOLDER_RE.test(decoded) ||
    CAPABILITY_HANDLE_RE.test(decoded)
  )
}

/**
 * Normalize a route path or URL into a canonical `RouteTemplate` (`/api/orders/:id`).
 *
 * Handles Express (`:id`), OpenAPI (`{id}`), Next.js (`[id]` / `[...slug]`), and Django/Flask
 * (`<int:id>` / `<id>`) param templates as well as concrete runtime IDs (UUIDs, ULIDs, numeric IDs,
 * hex/base64url opaque tokens, and generic prefixed IDs).
 */
export function normalizeRouteTemplate(path?: string | null, options?: RouteTemplateOptions): string {
  const preserveCase = options?.preserveCase !== false
  const preserveParamNames = options?.preserveParamNames === true
  const preserveColonParams = options?.preserveColonParams === true
  const collapseConcreteIds = options?.collapseConcreteIds !== false

  const raw = (path ?? '').trim()
  if (!raw) return '/'

  let pathname = raw
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      pathname = new URL(raw).pathname || '/'
    } catch {
      pathname = raw
    }
  }
  const qIdx = pathname.indexOf('?')
  if (qIdx >= 0) pathname = pathname.slice(0, qIdx)
  const hIdx = pathname.indexOf('#')
  if (hIdx >= 0) pathname = pathname.slice(0, hIdx)

  if (!pathname.startsWith('/')) pathname = `/${pathname}`
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1)
  }

  const segments = pathname.split('/').map((seg, idx) => {
    if (idx === 0 && seg === '') return ''
    if (!seg) return ''

    const decoded = decodeSegmentSafe(seg)

    const expressMatch = EXPRESS_PARAM_RE.exec(decoded)
    if (expressMatch) {
      return preserveParamNames || preserveColonParams ? `:${expressMatch[1]!}` : ':id'
    }

    const frameworkMatch =
      NEXT_PARAM_RE.exec(decoded) ??
      OPENAPI_PARAM_RE.exec(decoded) ??
      DJANGO_PARAM_RE.exec(decoded)
    if (frameworkMatch) {
      return preserveParamNames && !preserveColonParams ? `:${frameworkMatch[1]!}` : ':id'
    }
    if (GENERIC_BRACKET_PARAM_RE.test(decoded)) {
      return ':id'
    }

    if (collapseConcreteIds && isConcreteIdSegment(decoded)) {
      return ':id'
    }

    return preserveCase ? seg : seg.toLowerCase()
  })

  return segments.join('/') || '/'
}
