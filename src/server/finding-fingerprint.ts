/**
 * Pure leaf module for finding fingerprinting, CWE/origin normalization, and endpoint template
 * normalization. Zero `src/server/*` dependencies so `store-findings.ts` and `dedupe.ts` can both
 * consume it without creating a runtime import cycle through `model-settings.ts` -> `store.ts`.
 */
import { createHash } from 'node:crypto'
import { normalizeCwe } from '../finding-keys.ts'

export { ORIGIN_WIDE_CWE_KEYS, isOriginWideCwe, normalizeCwe } from '../finding-keys.ts'

/** The explicitly mutated input reported by a proof script (never inferred from body key order). */
export type MutatedInputKind = 'param' | 'header' | 'graphql' | 'rpc'

export interface MutatedInput {
  kind: MutatedInputKind
  name: string
  /** Where a `param` lives (query/json/form/path/xml). Informational: not part of the key. */
  location?: string
}

export interface FindingFingerprintInput {
  origin: string
  cwe?: string | null
  category?: string | null
  endpoint?: string | null
  authState?: string | null
  specKind?: string | null
  /** HTTP verb of the probed step. Defaults to `any` so findings without a method never fragment. */
  method?: string | null
  /** Primary injectable/read parameter (query/body/header name). Empty when the route itself is the unit. */
  param?: string | null
  /** GraphQL root field/resolver when the route itself is a single `/graphql` endpoint. */
  graphqlField?: string | null
  /** Explicit mutated input from the proof spec; when present it (not `param`) keys the finding. */
  mutated?: MutatedInput | null
  /** Verified handler (reverse-proxy service path / resolved route). Distinct handlers never merge. */
  handler?: string | null
  /** Alias for `handler` as reported by the replay verifier's endpoint binding. */
  verifiedEndpoint?: string | null
}

export interface ComputedFindingFingerprint {
  key: string
  hash: string
  normalizedEndpoint: string
  /** Normalized verified handler, or '' when the finding carries none. */
  handler: string
  /** Explicit mutated input used for the key, or null. */
  mutated: MutatedInput | null
  /** `explicit` when keyed by mutated input; `legacy` when the deprecated first-key heuristic ran. */
  mutatedSource: 'explicit' | 'legacy'
}

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MONGO_ID_SEGMENT = /^[0-9a-f]{24}$/i
const NUMERIC_SEGMENT = /^\d+$/
const LONG_HEX_SEGMENT = /^[0-9a-f]{16,}$/i
const PREFIXED_ID_SEGMENT = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
// Generic prefixed/underscore runtime IDs containing at least one digit (e.g. `pfx_item_9_5ed534`,
// `job_export_38_c4f8e5`, `ord_123`), while preserving static words (`api_keys`, `api_v1`).
const PREFIXED_UNDERSCORE_ID_SEGMENT = /^[a-z]{1,8}_(?!v\d+$)[a-z0-9_]*\d[a-z0-9_]*$/i
// Generic underscore/hyphenated runtime IDs ending in a numeric or mixed alphanumeric/hex ID
// suffix (e.g. `inv-9001`, `ord-a1b2`, `export-job-38-c4f8e5`), preserving static route words
// (`settle-race`, `user-profile`, `health-check`, `api-v2`, `oauth2-callback`).
const SUFFIXED_RUNTIME_ID_SEGMENT =
  /^(?!cwe-|rfc-|iso-|utf-|sha-|aes-|http-|oauth-|saml-)[a-z]{1,12}(?:[_-][a-z0-9]+)*[_-](?:\d+|(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])(?!v\d+$)[a-z0-9]{4,})$/i
const OPAQUE_TOKEN_SEGMENT = /^(?:(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{14,}|(?=(?:.*\d){2})(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,})$/
const REDACTED_PLACEHOLDER_SEGMENT = /\[redacted(?::[^\]]*)?\]/i
const CAPABILITY_HANDLE_SEGMENT = /^cap:[a-z0-9_.:-]+$/i

function decodeSegmentSafe(segment: string): string {
  if (!segment.includes('%')) return segment
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

export function normalizeOrigin(origin: string): string {
  const trimmed = origin.trim().toLowerCase()
  if (!trimmed) return ''
  try {
    return new URL(trimmed).origin.toLowerCase()
  } catch {
    return trimmed.replace(/\/+$/, '')
  }
}

/**
 * Normalize an endpoint path for fingerprinting. Literal segments are lowercased by default because
 * fingerprints must be host-case-insensitive; callers that build *request* paths (recon) pass
 * `preserveCase` so case-sensitive route segments (Next.js server actions, capitalized REST
 * resources) are not corrupted.
 */
export function normalizeEndpointTemplate(endpoint?: string | null, options?: { preserveCase?: boolean }): string {
  const preserveCase = options?.preserveCase === true
  const raw = (endpoint ?? '').trim()
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

  if (!pathname.startsWith('/')) pathname = '/' + pathname
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1)
  }

  const segments = pathname.split('/').map((seg, idx) => {
    if (idx === 0 && seg === '') return ''
    if (!seg) return ''
    const decoded = decodeSegmentSafe(seg)
    if (
      decoded.startsWith(':') ||
      (decoded.startsWith('{') && decoded.endsWith('}')) ||
      (decoded.startsWith('[') && decoded.endsWith(']')) ||
      REDACTED_PLACEHOLDER_SEGMENT.test(decoded) ||
      CAPABILITY_HANDLE_SEGMENT.test(decoded)
    ) {
      return ':id'
    }
    if (
      UUID_SEGMENT.test(decoded) ||
      MONGO_ID_SEGMENT.test(decoded) ||
      NUMERIC_SEGMENT.test(decoded) ||
      LONG_HEX_SEGMENT.test(decoded) ||
      PREFIXED_ID_SEGMENT.test(decoded) ||
      PREFIXED_UNDERSCORE_ID_SEGMENT.test(decoded) ||
      SUFFIXED_RUNTIME_ID_SEGMENT.test(decoded) ||
      OPAQUE_TOKEN_SEGMENT.test(decoded)
    ) {
      return ':id'
    }
    return preserveCase ? seg : seg.toLowerCase()
  })

  const normalized = segments.join('/')
  return normalized || '/'
}

const MUTATED_KINDS: ReadonlySet<MutatedInputKind> = new Set(['param', 'header', 'graphql', 'rpc'])

/**
 * Normalize an explicitly mutated input for fingerprinting. Names are lowercased for
 * parameter/header/GraphQL (`param`/`header`/`graphql` are case-insensitive in practice and the
 * GraphQL root field is already lowercased by `extractGraphqlRootField`); RPC procedure names keep
 * their case because `getUser` and `getuser` are genuinely different procedures.
 */
export function normalizeMutatedInput(input?: MutatedInput | null): MutatedInput | null {
  if (!input || typeof input !== 'object') return null
  if (!MUTATED_KINDS.has(input.kind)) return null
  const name = typeof input.name === 'string' ? input.name.trim() : ''
  if (!name) return null
  const normalizedName = input.kind === 'rpc' ? name : name.toLowerCase()
  const location = typeof input.location === 'string' ? input.location.trim().toLowerCase() : ''
  return location ? { kind: input.kind, name: normalizedName, location } : { kind: input.kind, name: normalizedName }
}

/**
 * Normalize the verified handler/service path so reverse-proxy front paths that map to different
 * microservice handlers never collapse. Accepts a bare path, a URL, or a `"METHOD /path"` string.
 */
export function normalizeHandlerRef(handler?: string | null): string {
  const raw = (handler ?? '').trim()
  if (!raw) return ''
  let value = raw.replace(/^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE)\s+/i, '')
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      value = new URL(value).pathname || '/'
    } catch {
      // Keep the raw value; it is still a stable handler identity.
    }
  }
  return normalizeEndpointTemplate(value)
}

/** Deprecated first-key heuristic token (legacy keys must stay byte-identical). */
function legacyMutationToken(input: Pick<FindingFingerprintInput, 'param' | 'graphqlField'>): string {
  const graphqlField = (input.graphqlField?.trim().toLowerCase() || '')
  return graphqlField ? `gql:${graphqlField}` : (input.param?.trim().toLowerCase() || '')
}

export function computeFindingFingerprint(input: FindingFingerprintInput): ComputedFindingFingerprint {
  const origin = normalizeOrigin(input.origin)
  const cwe = normalizeCwe(input.cwe, input.category)
  const normalizedEndpoint = normalizeEndpointTemplate(input.endpoint)
  const method = (input.method?.trim().toUpperCase() || 'ANY')
  const mutated = normalizeMutatedInput(input.mutated)
  const handler = normalizeHandlerRef(input.handler?.trim() ? input.handler : input.verifiedEndpoint)
  // A distinct verified handler means a distinct unit of work even when the public path matches
  // (`/api/orders/:id` fronted by two microservices). Handler-less findings keep the v5 key shape.
  const endpointComponent = handler ? `${normalizedEndpoint}#${handler}` : normalizedEndpoint
  // The key unit is the *explicitly* mutated input: parameter, header, GraphQL operation or RPC
  // procedure. `Object.keys(jsonBody)[0]` is only consulted when no explicit mutation was reported.
  const mutationToken = mutated ? `mutated:${mutated.kind}:${mutated.name}` : legacyMutationToken(input)
  // Deliberately exclude authState/specKind: one root cause observed through two personas or two
  // replay shapes is still the same finding. `(endpoint, method, mutation)` keeps distinct attack
  // surfaces (GET vs DELETE BOLA, two parameters, two resolvers, two handlers) separate.
  const key = `${origin}|${endpointComponent}|${method}|${mutationToken}|${cwe}`
  const hash = createHash('sha256').update(key).digest('hex')
  return {
    key,
    hash,
    normalizedEndpoint,
    handler,
    mutated,
    mutatedSource: mutated ? 'explicit' : 'legacy',
  }
}
