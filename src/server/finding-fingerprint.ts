/**
 * Pure leaf module for finding fingerprinting, CWE/origin normalization, and endpoint template
 * normalization. Zero `src/server/*` dependencies so `store-findings.ts` and `dedupe.ts` can both
 * consume it without creating a runtime import cycle through `model-settings.ts` -> `store.ts`.
 */
import { createHash } from 'node:crypto'

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

// Origin-wide vulnerability classes where distinct probe paths on the same origin
// typically share a single middleware/edge/server root cause.
export const ORIGIN_WIDE_CWES: ReadonlySet<string> = new Set([
  'CWE-942', // Permissive Cross-domain Policy (CORS)
  'CWE-346', // Origin Validation Error
  'CWE-693', // Protection Mechanism Failure (CSP / security headers)
  'CWE-1021', // Clickjacking / Frame Protection
  'CWE-319', // Cleartext Transmission / HSTS
  'CWE-295', // Improper Certificate Validation / TLS
  'CWE-327', // Broken/Risky Crypto / TLS cipher
  'CWE-614', // Sensitive Cookie without Secure
  'CWE-1004', // Sensitive Cookie without HttpOnly
  'CWE-1275', // Sensitive Cookie SameSite
])

/** True for vulnerability classes whose root cause is shared by every route on an origin. */
export function isOriginWideCwe(cwe?: string | null, category?: string | null): boolean {
  return ORIGIN_WIDE_CWES.has(normalizeCwe(cwe, category))
}

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MONGO_ID_SEGMENT = /^[0-9a-f]{24}$/i
const NUMERIC_SEGMENT = /^\d+$/
const LONG_HEX_SEGMENT = /^[0-9a-f]{16,}$/i
const PREFIXED_ID_SEGMENT = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
const OPAQUE_TOKEN_SEGMENT = /^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}$/

export function normalizeOrigin(origin: string): string {
  const trimmed = origin.trim().toLowerCase()
  if (!trimmed) return ''
  try {
    return new URL(trimmed).origin.toLowerCase()
  } catch {
    return trimmed.replace(/\/+$/, '')
  }
}

export function normalizeCwe(cwe?: string | null, category?: string | null): string {
  const cleanCwe = cwe?.trim().toUpperCase()
  if (cleanCwe && /^CWE-\d{1,5}$/.test(cleanCwe)) return cleanCwe
  const digits = cleanCwe?.match(/(\d{1,5})/)
  if (cleanCwe && digits && cleanCwe.includes('CWE')) return `CWE-${digits[1]}`
  const cleanCat = category?.trim().toLowerCase()
  return cleanCat || 'unknown'
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
    if (seg.startsWith(':') || (seg.startsWith('{') && seg.endsWith('}')) || (seg.startsWith('[') && seg.endsWith(']'))) {
      return ':id'
    }
    if (
      UUID_SEGMENT.test(seg) ||
      MONGO_ID_SEGMENT.test(seg) ||
      NUMERIC_SEGMENT.test(seg) ||
      LONG_HEX_SEGMENT.test(seg) ||
      PREFIXED_ID_SEGMENT.test(seg) ||
      OPAQUE_TOKEN_SEGMENT.test(seg)
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
