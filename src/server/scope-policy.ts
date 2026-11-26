import { createHmac, sign as cryptoSign, timingSafeEqual, verify as cryptoVerify } from 'node:crypto'
import type { KeyLike } from 'node:crypto'

/**
 * v6 Layer-1 origin scope + environment contract.
 *
 * This module is the single source of truth for:
 *  - the three origin roles (`targetOrigins`, `authOrigins`, `assetOrigins`),
 *  - environment modes (`prod_readonly`, `staging_isolated`, `ephemeral_lab`), and
 *  - provenance rules that treat auth/asset hops as benign infrastructure.
 *
 * The broker and the scoped browser both classify requests through
 * `evaluateScopeRequest()` so there is exactly one place where "may this request be
 * sent?" is answered. Pure functions only: no store or network imports.
 */

export const environmentModes = ['prod_readonly', 'staging_isolated', 'ephemeral_lab'] as const
export type EnvironmentMode = typeof environmentModes[number]

export const originRoles = ['target', 'auth', 'asset'] as const
export type OriginRole = typeof originRoles[number]

export const TENANT_TAG_PREFIX = 'kovo-qa-'

export interface ScopePolicy {
  mode: EnvironmentMode
  /** Active probing, mutation (when the mode permits) and verification are allowed. */
  targetOrigins: readonly string[]
  /** External SSO/IdP origins: persona redirects and token exchange only, never probed. */
  authOrigins?: readonly string[]
  /** CDN/static hosts: passive GET asset hydration only, never probed. */
  assetOrigins?: readonly string[]
  /** Optional `staging_isolated` denylist of routes (path prefixes). */
  routeDenylist?: readonly string[]
  /**
   * H-3: Host-confirmed GraphQL endpoints (exact canonical pathnames like `/graphql` or
   * full `origin + pathname` strings). When supplied (even `[]`), ONLY these endpoints qualify
   * for the read-only GraphQL exception — path-suffix guessing is disabled.
   */
  confirmedGraphqlEndpoints?: readonly string[]
  /** Run-scoped synthetic-tenant tag (`kovo-qa-<runId>-`). */
  tenantTag?: string | null
  runId?: string | null
  /**
   * R2-H-1: True when `staging_isolated` was derived automatically (not explicitly declared by
   * the operator). On derived staging runs, host-injected run-tag headers (`x-kovo-tenant-tag`,
   * `x-kovo-run-id`) are NEVER treated as standalone isolation proof.
   */
  derivedEnvironmentMode?: boolean
}

export type ScopeSurface = 'broker' | 'browser'
export type ScopeHook = 'setup' | 'cleanup'

export interface ScopeRequest {
  origin: string
  method: string
  pathAndQuery: string
  body?: string | null
  headers?: Record<string, string | string[] | undefined>
  /** Optional per-request confirmed GraphQL endpoints override (defaults to `policy.confirmedGraphqlEndpoints`). */
  confirmedGraphqlEndpoints?: readonly string[]
  /** R2-H-1: Per-request override indicating a derived (non-explicit) staging environment mode. */
  derivedEnvironmentMode?: boolean
  /**
   * The request is a redirect hop rather than an actively-selected probe. IdP redirects and
   * CDN hydration transit are only reachable under this flag.
   */
  redirectHop?: boolean
  /** Explicit `staging_isolated` setup/cleanup hook context. */
  hook?: ScopeHook | null
  /** Override the surface (defaults to `broker`). */
  surface?: ScopeSurface
}

export type ScopeDecisionCode =
  | 'allowed'
  | 'out_of_scope'
  | 'invalid_path'
  | 'auth_origin_active_probe'
  | 'asset_origin_active_probe'
  | 'readonly_environment'
  | 'staging_denylist'
  | 'staging_untagged_mutation'
  | 'invalid_scope_manifest'

export interface ScopeDecision {
  allowed: boolean
  code: ScopeDecisionCode
  role: OriginRole | null
  reason: string
}

const defaultPorts: Record<string, string> = { 'http:': '80', 'https:': '443' }

/** Canonical origin key (`scheme://host[:non-default-port]`), or `null` when malformed. */
export function normalizeScopeOrigin(value: string): string | null {
  try {
    const parsed = new URL(value)
    const port = defaultPorts[parsed.protocol] === parsed.port ? '' : parsed.port
    const host = parsed.hostname.toLowerCase()
    return `${parsed.protocol}//${host}${port ? `:${port}` : ''}`
  } catch {
    return null
  }
}

const routeUuidSegment = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const routeNumericSegment = /^\d+$/
const routeLongHexSegment = /^[0-9a-f]{16,}$/i
const routePrefixedIdSegment = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
const routeOpaqueSegment = /^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}$/
const ABSOLUTE_URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i
const UNSAFE_PATH_RE = /(?:\.\.|\\|%(?:2e|2f|5c))/i
const INVALID_PATH_CHARS_RE = /[\r\n\0]/

/**
 * Reject path spellings whose URL-parser and downstream/router interpretations may differ.
 * This deliberately rejects rather than decodes: an encoded separator or dot segment is not a
 * canonical request path, even when a particular parser happens to normalize it today.
 */
export function hasUnsafeAdmissionPath(pathAndQuery: string): boolean {
  return UNSAFE_PATH_RE.test(pathAndQuery) || INVALID_PATH_CHARS_RE.test(pathAndQuery)
}

/** Canonical path + query view. All scope/approval/denylist consumers must use this form. */
export function canonicalPathAndQuery(pathAndQuery: string): string | null {
  const raw = (pathAndQuery || '/').trim()
  if (raw.length > 8192 || hasUnsafeAdmissionPath(raw)) return null
  let pathname: string
  let search: string
  if (ABSOLUTE_URL_RE.test(raw)) {
    try {
      const parsed = new URL(raw)
      pathname = parsed.pathname
      search = parsed.search
    } catch {
      return null
    }
  } else {
    if (!raw.startsWith('/') || raw.startsWith('//')) return null
    const q = raw.indexOf('?')
    const h = raw.indexOf('#')
    const end = q >= 0 ? q : h
    pathname = end >= 0 ? raw.slice(0, end) : raw
    search = q >= 0 && (h < 0 || q < h) ? raw.slice(q, h >= 0 ? h : undefined) : ''
  }
  if (!pathname || !pathname.startsWith('/') || hasUnsafeAdmissionPath(pathname) || INVALID_PATH_CHARS_RE.test(search)) return null
  return `${pathname}${search}`
}

/**
 * Stable route key: identifier-shaped segments collapse to `*`, literals are lowercased and the
 * query string is dropped. Shared by durable approval leases and the `staging_isolated` denylist
 * so "same route" means the same thing everywhere.
 */
export function routePatternForPath(pathAndQuery: string): string {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  if (canonical === null) return ''
  const pathname = canonical.split('?', 1)[0]!
  const segments = pathname.split('/').map((segment, index) => {
    if (index === 0 || segment === '') return segment
    if (segment === '*' || segment === '**') return segment
    if (
      routeUuidSegment.test(segment) ||
      routeNumericSegment.test(segment) ||
      routeLongHexSegment.test(segment) ||
      routePrefixedIdSegment.test(segment) ||
      routeOpaqueSegment.test(segment)
    ) {
      return '*'
    }
    return segment.toLowerCase()
  })
  return segments.join('/') || '/'
}

/** The run-scoped synthetic tenant tag required for `staging_isolated` mutations. */
export function tenantTagForRun(runId: string): string {
  return `${TENANT_TAG_PREFIX}${runId}-`
}

function normalizedOriginList(origins: readonly string[] | undefined): Set<string> {
  const set = new Set<string>()
  for (const origin of origins ?? []) {
    const normalized = normalizeScopeOrigin(origin)
    if (normalized) set.add(normalized)
  }
  return set
}

/** Role of an origin in this policy. Target wins if an origin appears in more than one tier. */
export function originRoleFor(policy: ScopePolicy, origin: string): OriginRole | null {
  const normalized = normalizeScopeOrigin(origin)
  if (!normalized) return null
  if (normalizedOriginList(policy.targetOrigins).has(normalized)) return 'target'
  if (normalizedOriginList(policy.authOrigins).has(normalized)) return 'auth'
  if (normalizedOriginList(policy.assetOrigins).has(normalized)) return 'asset'
  return null
}

/** Auth/asset hops are benign infrastructure, never evidence-bearing targets. */
export function isBenignInfrastructureOrigin(policy: ScopePolicy, origin: string): boolean {
  const role = originRoleFor(policy, origin)
  return role === 'auth' || role === 'asset'
}

/** Provenance allow-set: target origins plus benign infrastructure hops. */
export function provenanceOriginsFor(policy: ScopePolicy): Set<string> {
  return new Set([
    ...normalizedOriginList(policy.targetOrigins),
    ...normalizedOriginList(policy.authOrigins),
    ...normalizedOriginList(policy.assetOrigins),
  ])
}

/** A finding survives a cross-origin hop only through a benign auth/asset origin. */
export function isProvenanceOriginAllowed(policy: ScopePolicy, origin: string): boolean {
  return originRoleFor(policy, origin) !== null
}

export function isReadOnlyHttpMethod(method: string, body?: string | null): boolean {
  const upper = method.toUpperCase()
  if (upper === 'GET' || upper === 'HEAD') return true
  if (upper === 'OPTIONS') return body === undefined || body === null || body === ''
  return false
}

// ---------------------------------------------------------------------------
// R2-H-1: Effective HTTP verb & method-override carrier detection
// ---------------------------------------------------------------------------

/** HTTP method-override headers honored by Rails, Laravel, Symfony, Express, Spring, etc. */
export const METHOD_OVERRIDE_HEADERS = new Set([
  'x-http-method-override',
  'x-http-method',
  'x-method-override',
])

/** Host-injected tracing/tagging headers that must NEVER serve as standalone isolation proof. */
export const HOST_INJECTED_TENANT_HEADERS = new Set([
  'x-kovo-tenant-tag',
  'x-kovo-run-id',
])

const HTTP_METHOD_TOKEN_RE = /^[A-Z][A-Z0-9_-]{0,15}$/
const METHOD_OVERRIDE_PRIORITY: readonly string[] = ['DELETE', 'PUT', 'PATCH', 'POST']
const MAX_OVERRIDE_BODY_SCAN_CHARS = 64 * 1024

export interface MethodOverrideDetection {
  /** True whenever any method-override header, query param, or body field is present. */
  hasOverride: boolean
  /** Effective HTTP verb accounting for override carriers (fails closed toward destructive verbs). */
  effectiveMethod: string
  /** Resolved override verb if an override carrier was present, otherwise `null`. */
  overriddenVerb: string | null
  /** Human-readable list of detected override carrier locations (names only, never secret values). */
  carriers: string[]
}

/**
 * Compute the effective HTTP verb including method-override headers (`X-HTTP-Method-Override`,
 * `X-HTTP-Method`, `X-Method-Override`) and `_method` query/form/JSON/multipart fields (`R2-H-1`).
 */
export function detectMethodOverride(input: {
  method: string
  pathAndQuery?: string
  headers?: Record<string, string | string[] | undefined>
  body?: string | null
}): MethodOverrideDetection {
  const baseMethod = (input.method || 'GET').trim().toUpperCase() || 'GET'
  const carriers: string[] = []
  const candidates: string[] = []

  const pushVerb = (raw: string | undefined) => {
    if (!raw) return
    for (const part of raw.split(',')) {
      const token = part.trim().toUpperCase()
      if (token && HTTP_METHOD_TOKEN_RE.test(token)) {
        candidates.push(token)
      }
    }
  }

  // 1. Method-override headers (case-insensitive)
  for (const [key, value] of Object.entries(input.headers ?? {})) {
    const lower = key.toLowerCase()
    if (!METHOD_OVERRIDE_HEADERS.has(lower)) continue
    const raw = Array.isArray(value) ? value.join(',') : (value ?? '')
    if (raw.trim().length > 0) {
      carriers.push(`header:${lower}`)
      pushVerb(raw)
    }
  }

  // 2. `_method` query parameter
  const pathAndQuery = input.pathAndQuery ?? ''
  const qIdx = pathAndQuery.indexOf('?')
  if (qIdx >= 0) {
    const hIdx = pathAndQuery.indexOf('#', qIdx)
    const rawQuery = hIdx >= 0 ? pathAndQuery.slice(qIdx + 1, hIdx) : pathAndQuery.slice(qIdx + 1)
    if (rawQuery) {
      const params = new URLSearchParams(rawQuery)
      for (const [k, v] of params.entries()) {
        if (k.toLowerCase() === '_method' && v.trim().length > 0) {
          carriers.push('query:_method')
          pushVerb(v)
        }
      }
    }
  }

  // 3. `_method` form-urlencoded, JSON, or multipart body field
  const rawBody = input.body
  if (typeof rawBody === 'string' && rawBody.length > 0) {
    const scanBody = rawBody.slice(0, MAX_OVERRIDE_BODY_SCAN_CHARS)
    const contentType = headerValue(input.headers, 'content-type').toLowerCase()

    // Form-urlencoded body (explicit content-type or form-like key=value syntax)
    if (
      contentType.includes('application/x-www-form-urlencoded') ||
      (!contentType.includes('json') && /(?:^|&|%26)_method=/i.test(scanBody))
    ) {
      try {
        const params = new URLSearchParams(scanBody)
        for (const [k, v] of params.entries()) {
          if (k.toLowerCase() === '_method' && v.trim().length > 0) {
            carriers.push('form:_method')
            pushVerb(v)
          }
        }
      } catch {
        if (/(?:^|&)_method=/i.test(scanBody)) {
          carriers.push('form:_method')
        }
      }
    }

    // JSON object body with top-level `_method` field (including escaped key check)
    const trimmed = scanBody.trim()
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed) as unknown
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
            if (k.toLowerCase() === '_method' && typeof v === 'string' && v.trim().length > 0) {
              carriers.push('json:_method')
              pushVerb(v)
            }
          }
        }
      } catch {
        // Malformed JSON containing a `_method` key hint fails closed as an override carrier.
        const fallback = /"(?:_method|\\u005fmethod)"\s*:\s*"([A-Za-z_-]{2,16})"/i.exec(trimmed)
        if (fallback) {
          carriers.push('json:_method')
          pushVerb(fallback[1])
        }
      }
    }

    // Multipart form-data field named `_method`
    if (/content-disposition:\s*form-data;[^;\r\n]*\bname\s*=\s*"?_method"?/i.test(scanBody)) {
      carriers.push('multipart:_method')
      const m = /content-disposition:\s*form-data;[^\r\n]*\bname\s*=\s*"?_method"?[^\r\n]*\r?\n\r?\n\s*([A-Za-z_-]{2,16})/i.exec(scanBody)
      if (m?.[1]) pushVerb(m[1])
    }
  }

  if (carriers.length === 0) {
    return {
      hasOverride: false,
      effectiveMethod: baseMethod,
      overriddenVerb: null,
      carriers: [],
    }
  }

  let chosen: string | null = null
  for (const preferred of METHOD_OVERRIDE_PRIORITY) {
    if (candidates.includes(preferred)) {
      chosen = preferred
      break
    }
  }
  chosen ??= candidates[0] ?? null

  return {
    hasOverride: true,
    effectiveMethod: chosen ?? baseMethod,
    overriddenVerb: chosen,
    carriers: [...new Set(carriers)],
  }
}

export function resolveEffectiveHttpMethod(input: {
  method: string
  pathAndQuery?: string
  headers?: Record<string, string | string[] | undefined>
  body?: string | null
}): string {
  return detectMethodOverride(input).effectiveMethod
}

const MAX_GRAPHQL_READONLY_BODY_CHARS = 64 * 1024
const MAX_JSON_NESTING_DEPTH = 32
const MAX_GRAPHQL_NESTING_DEPTH = 24
const graphqlEnvelopeKeys = new Set(['query', 'operationName', 'variables', 'extensions'])

/**
 * Legacy fallback GraphQL mount paths when a caller has not configured `confirmedGraphqlEndpoints`:
 * ONLY top-level or standard API versioned GraphQL mounts (`/graphql`, `/api/graphql`,
 * `/v1/graphql`, `/api/v1/graphql`), NEVER arbitrary REST resource routes whose parameter happens
 * to equal `"graphql"` (e.g. `/api/users/graphql` or `/items/graphql`).
 */
const CANONICAL_GRAPHQL_MOUNT_RE = /^\/(?:(?:api\/)?(?:v\d+\/)?)?graphql$/i

function isGraphqlEndpointPath(pathAndQuery: string): boolean {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  if (canonical === null) return false
  const pathname = canonical.split('?', 1)[0]!
  const segments = pathname.split('/').filter(Boolean)
  if (segments.length === 0) return false
  if (segments.some(seg => seg === '.' || seg === '..')) return false
  return CANONICAL_GRAPHQL_MOUNT_RE.test(pathname)
}

/**
 * Exact match against host-confirmed GraphQL endpoints (`H-3`).
 * Entries may be canonical pathnames (`/graphql`, `/api/v2/gql`) or full URLs
 * (`https://app.example/graphql`, which additionally bind the origin).
 */
export function matchesConfirmedGraphqlEndpoint(
  pathAndQuery: string,
  confirmedEndpoints: readonly string[],
  origin?: string,
): boolean {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  if (canonical === null) return false
  const reqPathname = canonical.split('?', 1)[0]!.toLowerCase().replace(/\/+$/, '') || '/'
  const reqOrigin = origin ? normalizeScopeOrigin(origin) : null

  for (const rawEntry of confirmedEndpoints) {
    const entry = (rawEntry ?? '').trim()
    if (!entry) continue
    if (ABSOLUTE_URL_RE.test(entry)) {
      try {
        const parsed = new URL(entry)
        const entryOrigin = normalizeScopeOrigin(parsed.origin)
        const entryCanon = canonicalPathAndQuery(`${parsed.pathname}${parsed.search}`)
        if (!entryOrigin || entryCanon === null) continue
        if (reqOrigin && entryOrigin !== reqOrigin) continue
        const entryPathname = entryCanon.split('?', 1)[0]!.toLowerCase().replace(/\/+$/, '') || '/'
        if (entryPathname === reqPathname) return true
      } catch {
        continue
      }
    } else {
      const entryCanon = canonicalPathAndQuery(entry)
      if (entryCanon === null) continue
      const entryPathname = entryCanon.split('?', 1)[0]!.toLowerCase().replace(/\/+$/, '') || '/'
      if (entryPathname === reqPathname) return true
    }
  }
  return false
}

/**
 * Strict RFC 8259 JSON structure validator that rejects:
 *  - ANY backslash-escaped top-level key (e.g. `\u0071uery`),
 *  - ANY duplicate key at any object depth (after JSON decoding),
 *  - ANY case-insensitive duplicate top-level key (e.g. `"query"` + `"Query"`),
 *  - malformed tokens, excessive nesting, or trailing bytes.
 */
export function validateStrictJsonObject(raw: string): boolean {
  const text = raw.trim()
  if (!text.startsWith('{') || !text.endsWith('}')) return false
  let i = 0
  const n = text.length

  const skipWs = () => {
    while (i < n) {
      const c = text.charCodeAt(i)
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i += 1
      else break
    }
  }

  const parseString = (): { value: string; hasEscape: boolean } | undefined => {
    if (text[i] !== '"') return undefined
    const start = i
    i += 1
    let hasEscape = false
    while (i < n) {
      const ch = text[i]!
      const code = text.charCodeAt(i)
      if (code < 0x20) return undefined
      if (ch === '\\') {
        hasEscape = true
        i += 1
        if (i >= n) return undefined
        const esc = text[i]!
        if (esc === 'u') {
          if (i + 4 >= n) return undefined
          for (let k = 1; k <= 4; k += 1) {
            if (!/[0-9a-fA-F]/.test(text[i + k]!)) return undefined
          }
          i += 5
        } else if ('"\\/bfnrt'.includes(esc)) {
          i += 1
        } else {
          return undefined
        }
        continue
      }
      if (ch === '"') {
        i += 1
        try {
          const decoded = JSON.parse(text.slice(start, i)) as unknown
          if (typeof decoded !== 'string') return undefined
          return { value: decoded, hasEscape }
        } catch {
          return undefined
        }
      }
      i += 1
    }
    return undefined
  }

  const parseValue = (depth: number): boolean => {
    if (depth > MAX_JSON_NESTING_DEPTH) return false
    skipWs()
    if (i >= n) return false
    const ch = text[i]!
    if (ch === '{') return parseObject(depth)
    if (ch === '[') {
      i += 1
      skipWs()
      if (i < n && text[i] === ']') {
        i += 1
        return true
      }
      while (i < n) {
        if (!parseValue(depth + 1)) return false
        skipWs()
        if (i < n && text[i] === ',') {
          i += 1
          continue
        }
        if (i < n && text[i] === ']') {
          i += 1
          return true
        }
        return false
      }
      return false
    }
    if (ch === '"') return parseString() !== undefined
    if (text.startsWith('true', i)) { i += 4; return true }
    if (text.startsWith('false', i)) { i += 5; return true }
    if (text.startsWith('null', i)) { i += 4; return true }
    // JSON number
    const numMatch = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i))
    if (!numMatch) return false
    i += numMatch[0].length
    return true
  }

  const parseObject = (depth: number): boolean => {
    if (text[i] !== '{') return false
    i += 1
    skipWs()
    if (i < n && text[i] === '}') {
      i += 1
      return true
    }
    const seenExact = new Set<string>()
    const seenLower = depth === 0 ? new Set<string>() : undefined
    while (i < n) {
      skipWs()
      const key = parseString()
      if (!key) return false
      if (depth === 0 && key.hasEscape) return false
      if (seenExact.has(key.value)) return false
      seenExact.add(key.value)
      if (seenLower) {
        const lower = key.value.toLowerCase()
        if (seenLower.has(lower)) return false
        seenLower.add(lower)
      }
      skipWs()
      if (i >= n || text[i] !== ':') return false
      i += 1
      if (!parseValue(depth + 1)) return false
      skipWs()
      if (i < n && text[i] === ',') {
        i += 1
        continue
      }
      if (i < n && text[i] === '}') {
        i += 1
        return true
      }
      return false
    }
    return false
  }

  if (!parseObject(0)) return false
  skipWs()
  return i === n
}

export function parseStrictJsonObject(raw: string): Record<string, unknown> | undefined {
  const trimmed = raw.trim()
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return undefined
  if (!validateStrictJsonObject(trimmed)) return undefined
  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined
    return parsed as Record<string, unknown>
  } catch {
    return undefined
  }
}

const parseJsonObject = parseStrictJsonObject

type GraphqlTokenKind = 'name' | 'punct' | 'spread' | 'string' | 'number'
interface GraphqlToken {
  kind: GraphqlTokenKind
  value: string
}

function tokenizeGraphqlDocument(source: string): GraphqlToken[] | undefined {
  const tokens: GraphqlToken[] = []
  let i = 0
  const n = source.length
  while (i < n) {
    const ch = source[i]!
    const code = source.charCodeAt(i)
    // Whitespace, BOM, and insignificant commas
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === ',' || code === 0xfeff) {
      i += 1
      continue
    }
    // Line comment
    if (ch === '#') {
      while (i < n && source[i] !== '\n' && source[i] !== '\r') i += 1
      continue
    }
    // Spread `...`
    if (ch === '.') {
      if (source.startsWith('...', i)) {
        tokens.push({ kind: 'spread', value: '...' })
        i += 3
        continue
      }
      return undefined
    }
    // Punctuators
    if ('!$&():=@[]{|}'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch })
      i += 1
      continue
    }
    // Block string `"""..."""` or single-line string `"..."`
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        i += 3
        let closed = false
        while (i < n) {
          if (source.startsWith('\\"""', i)) {
            i += 4
            continue
          }
          if (source.startsWith('"""', i)) {
            i += 3
            closed = true
            break
          }
          i += 1
        }
        if (!closed) return undefined
        tokens.push({ kind: 'string', value: '' })
        continue
      }
      i += 1
      let closed = false
      while (i < n) {
        const c = source[i]!
        const cc = source.charCodeAt(i)
        if (c === '\n' || c === '\r' || cc < 0x20) return undefined
        if (c === '\\') {
          i += 1
          if (i >= n) return undefined
          const esc = source[i]!
          if (esc === 'u') {
            if (i + 4 >= n) return undefined
            for (let k = 1; k <= 4; k += 1) {
              if (!/[0-9a-fA-F]/.test(source[i + k]!)) return undefined
            }
            i += 5
          } else if ('"\\/bfnrt'.includes(esc)) {
            i += 1
          } else {
            return undefined
          }
          continue
        }
        if (c === '"') {
          i += 1
          closed = true
          break
        }
        i += 1
      }
      if (!closed) return undefined
      tokens.push({ kind: 'string', value: '' })
      continue
    }
    // IntValue / FloatValue
    if (ch === '-' || (code >= 0x30 && code <= 0x39)) {
      const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(i))
      if (!match) return undefined
      i += match[0].length
      // Reject numbers immediately followed by a NameStart character (GraphQL spec)
      if (i < n && /[_A-Za-z.]/.test(source[i]!)) return undefined
      tokens.push({ kind: 'number', value: match[0] })
      continue
    }
    // Name
    if (/[_A-Za-z]/.test(ch)) {
      let j = i + 1
      while (j < n && /[_0-9A-Za-z]/.test(source[j]!)) j += 1
      tokens.push({ kind: 'name', value: source.slice(i, j) })
      i = j
      continue
    }
    return undefined
  }
  return tokens
}

/**
 * Strict GraphQL executable document parser for read-only verification:
 *  - Accepts ONLY a single read-only `query` operation (explicit `query` or shorthand `{ ... }`)
 *    plus zero or more `fragment` definitions.
 *  - Rejects `mutation`, `subscription`, SDL definitions, multi-operation documents, field aliases
 *    (`alias: field`), malformed syntax, and mismatched `operationName`.
 */
function isStrictReadOnlyGraphqlDocument(
  source: string,
  expectedOperationName?: string | null,
): boolean {
  const trimmed = source.trim()
  if (!trimmed || trimmed.length > MAX_GRAPHQL_READONLY_BODY_CHARS) return false
  const tokens = tokenizeGraphqlDocument(trimmed)
  if (!tokens || tokens.length === 0) return false

  let pos = 0
  const peek = (offset = 0): GraphqlToken | undefined => tokens[pos + offset]
  const eatPunct = (value: string): boolean => {
    const tok = peek()
    if (tok?.kind === 'punct' && tok.value === value) {
      pos += 1
      return true
    }
    return false
  }
  const eatName = (): string | undefined => {
    const tok = peek()
    if (tok?.kind === 'name') {
      pos += 1
      return tok.value
    }
    return undefined
  }

  const definedFragments = new Set<string>()
  const usedFragments = new Set<string>()

  const parseType = (depth: number): boolean => {
    if (depth > MAX_GRAPHQL_NESTING_DEPTH) return false
    if (eatPunct('[')) {
      if (!parseType(depth + 1)) return false
      if (!eatPunct(']')) return false
    } else if (!eatName()) {
      return false
    }
    eatPunct('!')
    return true
  }

  const parseValue = (depth: number, isConst: boolean): boolean => {
    if (depth > MAX_GRAPHQL_NESTING_DEPTH) return false
    const tok = peek()
    if (!tok) return false
    if (tok.kind === 'punct' && tok.value === '$') {
      if (isConst) return false
      pos += 1
      return eatName() !== undefined
    }
    if (tok.kind === 'number' || tok.kind === 'string') {
      pos += 1
      return true
    }
    if (tok.kind === 'name') {
      pos += 1
      return true
    }
    if (eatPunct('[')) {
      while (peek() && !(peek()!.kind === 'punct' && peek()!.value === ']')) {
        if (!parseValue(depth + 1, isConst)) return false
      }
      return eatPunct(']')
    }
    if (eatPunct('{')) {
      const seenKeys = new Set<string>()
      while (peek() && !(peek()!.kind === 'punct' && peek()!.value === '}')) {
        const key = eatName()
        if (!key || seenKeys.has(key)) return false
        seenKeys.add(key)
        if (!eatPunct(':')) return false
        if (!parseValue(depth + 1, isConst)) return false
      }
      return eatPunct('}')
    }
    return false
  }

  const parseArguments = (depth: number, isConst: boolean): boolean => {
    if (!eatPunct('(')) return true
    let count = 0
    const seenArgs = new Set<string>()
    while (peek() && !(peek()!.kind === 'punct' && peek()!.value === ')')) {
      const argName = eatName()
      if (!argName || seenArgs.has(argName)) return false
      seenArgs.add(argName)
      if (!eatPunct(':')) return false
      if (!parseValue(depth + 1, isConst)) return false
      count += 1
    }
    return count > 0 && eatPunct(')')
  }

  const parseDirectives = (depth: number, isConst: boolean): boolean => {
    while (eatPunct('@')) {
      const name = eatName()
      if (!name) return false
      const lower = name.toLowerCase()
      if (lower === 'mutation' || lower === 'subscription') return false
      if (!parseArguments(depth + 1, isConst)) return false
    }
    return true
  }

  const parseVariableDefinitions = (depth: number): boolean => {
    if (!eatPunct('(')) return true
    let count = 0
    const seenVars = new Set<string>()
    while (peek() && !(peek()!.kind === 'punct' && peek()!.value === ')')) {
      if (!eatPunct('$')) return false
      const varName = eatName()
      if (!varName || seenVars.has(varName)) return false
      seenVars.add(varName)
      if (!eatPunct(':')) return false
      if (!parseType(depth + 1)) return false
      if (eatPunct('=')) {
        if (!parseValue(depth + 1, true)) return false
      }
      if (!parseDirectives(depth + 1, true)) return false
      count += 1
    }
    return count > 0 && eatPunct(')')
  }

  const parseSelectionSet = (depth: number): boolean => {
    if (depth > MAX_GRAPHQL_NESTING_DEPTH) return false
    if (!eatPunct('{')) return false
    let count = 0
    while (peek() && !(peek()!.kind === 'punct' && peek()!.value === '}')) {
      const tok = peek()!
      if (tok.kind === 'spread') {
        pos += 1
        const next = peek()
        if (next?.kind === 'name' && next.value === 'on') {
          // InlineFragment: `... on TypeName Directives? SelectionSet`
          pos += 1
          if (!eatName()) return false
          if (!parseDirectives(depth + 1, false)) return false
          if (!parseSelectionSet(depth + 1)) return false
        } else if (next?.kind === 'punct' && (next.value === '{' || next.value === '@')) {
          // InlineFragment without type condition: `... Directives? SelectionSet`
          if (!parseDirectives(depth + 1, false)) return false
          if (!parseSelectionSet(depth + 1)) return false
        } else {
          // FragmentSpread: `... FragmentName Directives?`
          const fragName = eatName()
          if (!fragName || fragName === 'on') return false
          usedFragments.add(fragName)
          if (!parseDirectives(depth + 1, false)) return false
        }
      } else if (tok.kind === 'name') {
        // Field — reject field aliases (`alias: field`) to prevent alias batching / smuggling tricks
        const fieldName = eatName()!
        if (peek()?.kind === 'punct' && peek()!.value === ':') return false
        const lower = fieldName.toLowerCase()
        if (lower === 'mutation' || lower === 'subscription') return false
        if (!parseArguments(depth + 1, false)) return false
        if (!parseDirectives(depth + 1, false)) return false
        if (peek()?.kind === 'punct' && peek()!.value === '{') {
          if (!parseSelectionSet(depth + 1)) return false
        }
      } else {
        return false
      }
      count += 1
    }
    return count > 0 && eatPunct('}')
  }

  let operationCount = 0
  let parsedOperationName: string | null = null
  let isShorthand = false

  while (pos < tokens.length) {
    const tok = peek()!
    if (tok.kind === 'punct' && tok.value === '{') {
      operationCount += 1
      if (operationCount > 1) return false
      isShorthand = true
      if (!parseSelectionSet(0)) return false
      continue
    }
    if (tok.kind === 'name' && tok.value === 'query') {
      pos += 1
      operationCount += 1
      if (operationCount > 1) return false
      // Reject `query: ...` alias/syntax confusion at definition boundary
      if (peek()?.kind === 'punct' && peek()!.value === ':') return false
      if (peek()?.kind === 'name') {
        const opName = eatName()!
        const lower = opName.toLowerCase()
        if (lower === 'mutation' || lower === 'subscription') return false
        if (peek()?.kind === 'punct' && peek()!.value === ':') return false
        parsedOperationName = opName
      }
      if (!parseVariableDefinitions(0)) return false
      if (!parseDirectives(0, false)) return false
      if (!parseSelectionSet(0)) return false
      continue
    }
    if (tok.kind === 'name' && tok.value === 'fragment') {
      pos += 1
      const fragName = eatName()
      if (!fragName || fragName === 'on') return false
      const lower = fragName.toLowerCase()
      if (lower === 'mutation' || lower === 'subscription') return false
      if (definedFragments.has(fragName)) return false
      definedFragments.add(fragName)
      const onKw = eatName()
      if (onKw !== 'on') return false
      if (!eatName()) return false
      if (!parseDirectives(0, false)) return false
      if (!parseSelectionSet(0)) return false
      continue
    }
    // Reject `mutation`, `subscription`, SDL keywords, or any unknown top-level definition.
    return false
  }

  if (operationCount !== 1) return false
  for (const frag of usedFragments) {
    if (!definedFragments.has(frag)) return false
  }
  const expectedOp = (expectedOperationName ?? '').trim()
  if (expectedOp) {
    if (isShorthand || parsedOperationName !== expectedOp) return false
  }
  return true
}

function headerValue(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string,
): string {
  if (!headers) return ''
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue
    return Array.isArray(value) ? (value[0] ?? '') : (value ?? '')
  }
  return ''
}

function hasDuplicateHeader(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string,
): boolean {
  if (!headers) return false
  let seen = 0
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue
    if (Array.isArray(value)) {
      if (value.length > 1) return true
      if (value.length === 1) seen += 1
    } else if (value !== undefined) {
      seen += 1
    }
    if (seen > 1) return true
  }
  return false
}

export interface VerifiedGraphqlOptions {
  /**
   * Host-confirmed GraphQL endpoints (`H-3`). When supplied (including `[]`), ONLY these
   * exact endpoints qualify — path-suffix inference is disabled.
   */
  confirmedEndpoints?: readonly string[]
  /** When true, require explicit `confirmedEndpoints` (deny if omitted or empty). */
  requireConfirmedEndpoint?: boolean
  /** Request origin (used when `confirmedEndpoints` includes full URLs). */
  origin?: string
  /** Request HTTP method (defaults to `POST`). */
  method?: string
}

/**
 * Verified read-only GraphQL (`H-3`):
 *  - MUST NOT carry any method-override header or `_method` parameter/field.
 *  - MUST target a host-confirmed GraphQL endpoint (or, when `confirmedEndpoints` is omitted in
 *    legacy callers, a canonical mount path — never an arbitrary REST route segment).
 *  - MUST NOT carry duplicate `content-type` / `content-encoding`, non-identity encoding,
 *    multipart, or loose non-GraphQL/non-JSON media types.
 *  - MUST carry either a strict, ambiguity-free JSON `query` envelope or a raw GraphQL `query`
 *    document whose parsed AST is strictly a single read-only `query` operation.
 */
export function isVerifiedReadOnlyGraphqlQuery(
  pathAndQuery: string,
  body: string | null | undefined,
  headers?: Record<string, string | string[] | undefined>,
  options?: VerifiedGraphqlOptions,
): boolean {
  const trimmed = (body ?? '').trim()
  if (!trimmed || trimmed.length > MAX_GRAPHQL_READONLY_BODY_CHARS) return false

  // H-3: deny method overrides on GraphQL reads (headers, query, or body).
  const override = detectMethodOverride({
    method: options?.method ?? 'POST',
    pathAndQuery,
    headers,
    body,
  })
  if (override.hasOverride) return false

  if (options?.confirmedEndpoints !== undefined) {
    if (!matchesConfirmedGraphqlEndpoint(pathAndQuery, options.confirmedEndpoints, options.origin)) {
      return false
    }
  } else if (options?.requireConfirmedEndpoint) {
    return false
  } else if (!isGraphqlEndpointPath(pathAndQuery)) {
    return false
  }

  // H-3: reject duplicate content-type or content-encoding headers.
  if (hasDuplicateHeader(headers, 'content-type') || hasDuplicateHeader(headers, 'content-encoding')) {
    return false
  }

  const contentEncoding = headerValue(headers, 'content-encoding').trim()
  if (contentEncoding && !/^identity$/i.test(contentEncoding)) return false

  const rawContentType = headerValue(headers, 'content-type').toLowerCase().trim()
  const mediaType = rawContentType.split(';', 1)[0]!.trim()
  if (/^multipart\//i.test(mediaType)) return false

  const isRawGraphqlHeader = mediaType === 'application/graphql'
  if (isRawGraphqlHeader) {
    return isStrictReadOnlyGraphqlDocument(trimmed)
  }

  const isJsonOrUnspecified =
    !mediaType ||
    mediaType === 'application/json' ||
    mediaType === 'application/graphql+json' ||
    /^application\/[a-z0-9.+-]+\+json$/i.test(mediaType)
  if (!isJsonOrUnspecified) return false

  if (trimmed.startsWith('{')) {
    const envelope = parseJsonObject(trimmed)
    if (!envelope) return false
    if (!Object.prototype.hasOwnProperty.call(envelope, 'query')) return false
    const keys = Object.keys(envelope)
    if (!keys.every(key => graphqlEnvelopeKeys.has(key))) return false
    const document = envelope.query
    if (typeof document !== 'string' || !document.trim()) return false
    if (
      envelope.operationName !== undefined &&
      envelope.operationName !== null &&
      typeof envelope.operationName !== 'string'
    ) {
      return false
    }
    if (
      envelope.variables !== undefined &&
      envelope.variables !== null &&
      (typeof envelope.variables !== 'object' || Array.isArray(envelope.variables))
    ) {
      return false
    }
    if (envelope.extensions !== undefined && envelope.extensions !== null) {
      if (typeof envelope.extensions !== 'object' || Array.isArray(envelope.extensions)) return false
      // Reject non-empty extensions (e.g. persistedQuery / APQ hashes that can resolve to mutations).
      if (Object.keys(envelope.extensions as Record<string, unknown>).length > 0) return false
    }
    const expectedOp = typeof envelope.operationName === 'string' ? envelope.operationName : null
    return isStrictReadOnlyGraphqlDocument(document, expectedOp)
  }

  if (mediaType) return false
  return isStrictReadOnlyGraphqlDocument(trimmed)
}

const authTokenPath = /(?:^|\/)(?:oauth2?\/token|token|connect\/token|auth\/token|\.well-known\/openid-configuration)(?:$|\/|\?)/i

/** Narrow auth-origin allowance: OIDC/OAuth token exchange (form POST) and discovery GET. */
export function isAuthTokenExchangeRequest(
  pathAndQuery: string,
  method: string,
  headers?: Record<string, string | string[] | undefined>,
): boolean {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  if (canonical === null || !authTokenPath.test(canonical)) return false
  const upper = method.toUpperCase()
  if (upper === 'GET' || upper === 'HEAD') return true
  if (upper !== 'POST') return false
  const contentType = headerValue(headers, 'content-type').toLowerCase()
  return contentType.includes('application/x-www-form-urlencoded') || contentType.includes('application/json')
}

export function isRouteDenylisted(policy: ScopePolicy, pathAndQuery: string): boolean {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  // Ambiguous paths never inherit a safe route's denylist classification.
  if (canonical === null) return true
  const entries = policy.routeDenylist ?? []
  if (!entries.length) return false
  const requestPath = routePatternForPath(canonical)
  if (!requestPath) return true
  for (const entry of entries) {
    const raw = (entry ?? '').trim()
    if (!raw) continue
    const pattern = routePatternForPath(raw.replace(/\*+$/, '') || '/')
    if (!pattern) continue
    const base = pattern !== '/' && pattern.endsWith('/') ? pattern.slice(0, -1) : pattern
    if (requestPath === base) return true
    if (base !== '/' && requestPath.startsWith(`${base}/`)) return true
    if (base === '/') return true
  }
  return false
}

/**
 * Does the request carry the run-scoped synthetic tenant tag (path, body, or headers)?
 *
 * R2-H-1: When `ignoreHostInjectedHeaders` is true (always enforced on derived `staging_isolated`
 * runs), host-injected tagging headers (`x-kovo-tenant-tag`, `x-kovo-run-id`) are excluded so a
 * header stamped by the host itself can never serve as standalone isolation proof.
 */
export function requestCarriesTenantTag(
  request: ScopeRequest,
  tenantTag: string | null | undefined,
  options: { ignoreHostInjectedHeaders?: boolean } = {},
): boolean {
  const tag = (tenantTag ?? '').trim().toLowerCase()
  if (!tag) return false
  const ignoreHostInjected = options.ignoreHostInjectedHeaders === true
  const haystack = [
    request.pathAndQuery,
    request.body ?? '',
    ...Object.entries(request.headers ?? {})
      .filter(([key]) => !ignoreHostInjected || !HOST_INJECTED_TENANT_HEADERS.has(key.toLowerCase()))
      .flatMap(([key, value]) => [
        key,
        Array.isArray(value) ? value.join(' ') : (value ?? ''),
      ]),
  ].join('\n').toLowerCase()
  return haystack.includes(tag)
}

function allow(role: OriginRole, reason = 'Request is inside the approved scope.'): ScopeDecision {
  return { allowed: true, code: 'allowed', role, reason }
}

function deny(code: ScopeDecisionCode, role: OriginRole | null, reason: string): ScopeDecision {
  return { allowed: false, code, role, reason }
}

/**
 * The one place where broker + browser answer "may this request be sent?".
 *
 * Role rules (independent of environment mode):
 *  - `target`: subject to the environment contract below.
 *  - `auth`: redirect transit (GET/HEAD/OPTIONS) and OAuth/OIDC token exchange only.
 *  - `asset`: redirect transit and passive browser GET/HEAD hydration only.
 */
export function evaluateScopeRequest(policy: ScopePolicy, request: ScopeRequest): ScopeDecision {
  const role = originRoleFor(policy, request.origin)
  if (!role) {
    return deny('out_of_scope', null, `Origin ${request.origin} is outside the approved scope.`)
  }
  const canonical = canonicalPathAndQuery(request.pathAndQuery)
  const method = (request.method || 'GET').toUpperCase()
  const override = detectMethodOverride({
    method,
    pathAndQuery: canonical ?? request.pathAndQuery,
    headers: request.headers,
    body: request.body,
  })
  const effectiveMethod = override.effectiveMethod
  const readOnly = !override.hasOverride && isReadOnlyHttpMethod(effectiveMethod, request.body)
  const surface: ScopeSurface = request.surface ?? 'broker'
  const origin = normalizeScopeOrigin(request.origin) ?? request.origin

  if (role === 'auth') {
    if (request.redirectHop && readOnly) {
      return canonical === null
        ? deny('invalid_path', role, 'Request path is not canonical or contains ambiguous path syntax.')
        : allow('auth', `IdP redirect transit to ${origin}.`)
    }
    if (canonical !== null && isAuthTokenExchangeRequest(canonical, method, request.headers)) {
      return allow('auth', `SSO token exchange with ${origin}.`)
    }
    return deny(
      'auth_origin_active_probe',
      'auth',
      `Origin ${origin} is an authentication/IdP origin; active probing is forbidden (redirects and token exchange only).`,
    )
  }

  if (role === 'asset') {
    if (request.redirectHop && readOnly) {
      return canonical === null
        ? deny('invalid_path', role, 'Request path is not canonical or contains ambiguous path syntax.')
        : allow('asset', `Asset redirect transit to ${origin}.`)
    }
    if (surface === 'browser' && (method === 'GET' || method === 'HEAD')) {
      return canonical === null
        ? deny('invalid_path', role, 'Request path is not canonical or contains ambiguous path syntax.')
        : allow('asset', `Passive asset hydration from ${origin}.`)
    }
    return deny(
      'asset_origin_active_probe',
      'asset',
      `Origin ${origin} is a passive asset/CDN origin; only browser GET/HEAD hydration is permitted.`,
    )
  }

  // Target origin. Ambiguous paths keep their normal read-only/mutation classification here;
  // canonical rejection happens at the admission boundary and on every redirect hop.
  if (policy.mode === 'ephemeral_lab') return allow('target')

  if (readOnly) return allow('target')
  const confirmedEndpoints = request.confirmedGraphqlEndpoints ?? policy.confirmedGraphqlEndpoints
  if (
    canonical !== null &&
    !override.hasOverride &&
    effectiveMethod === 'POST' &&
    isVerifiedReadOnlyGraphqlQuery(canonical, request.body, request.headers, {
      ...(confirmedEndpoints !== undefined ? { confirmedEndpoints } : {}),
      origin,
      method: effectiveMethod,
    })
  ) {
    return allow('target', 'Verified read-only GraphQL query.')
  }

  if (policy.mode === 'prod_readonly') {
    const overrideSuffix = override.hasOverride ? ` (method override via ${override.carriers.join(', ')})` : ''
    return deny(
      'readonly_environment',
      'target',
      `prod_readonly refuses state-changing ${effectiveMethod} ${request.pathAndQuery}${overrideSuffix} without an approval prompt.`,
    )
  }

  // staging_isolated
  if (canonical !== null && isRouteDenylisted(policy, canonical)) {
    return deny(
      'staging_denylist',
      'target',
      `Route ${canonical} is on the staging denylist and cannot be mutated.`,
    )
  }
  if (request.hook === 'setup' || request.hook === 'cleanup') {
    return allow('target', `Explicit ${request.hook} hook context.`)
  }
  const ignoreHostInjectedHeaders = Boolean(request.derivedEnvironmentMode ?? policy.derivedEnvironmentMode)
  if (
    canonical !== null &&
    requestCarriesTenantTag({ ...request, pathAndQuery: canonical }, policy.tenantTag, { ignoreHostInjectedHeaders })
  ) {
    return allow('target', 'Mutation targets a run-tagged synthetic test tenant.')
  }
  return deny(
    'staging_untagged_mutation',
    'target',
    `staging_isolated mutations must target the run-tagged tenant "${policy.tenantTag ?? tenantTagForRun(policy.runId ?? '')}" or an explicit setup/cleanup hook.`,
  )
}

/** Browser-facing alias; the classification lives in exactly one place. */
export function evaluateBrowserScopeRequest(policy: ScopePolicy, request: Omit<ScopeRequest, 'surface'>): ScopeDecision {
  return evaluateScopeRequest(policy, { ...request, surface: 'browser' })
}

/** Default mode when an operator has not chosen one: disposable labs stay open, live stays read-only. */
export function defaultEnvironmentMode(projectEnvironment: 'public' | 'local-lab' | string): EnvironmentMode {
  return projectEnvironment === 'local-lab' ? 'ephemeral_lab' : 'prod_readonly'
}

// ============================================================================
// v7 M4: Cryptographically Signed Scope Manifests (HMAC-SHA256 & Ed25519)
// ============================================================================

export type ScopeManifestAlgorithm = 'hmac-sha256' | 'ed25519'

export interface ScopeManifestPayload {
  version: 1
  manifestId: string
  tenantId: string
  issuedAt: string
  expiresAt: string
  policy: ScopePolicy
}

export interface SignedScopeManifest {
  payload: ScopeManifestPayload
  algorithm: ScopeManifestAlgorithm
  keyId?: string
  signature: string
}

export type ScopeManifestSignOptions =
  | { algorithm: 'hmac-sha256'; secret: string | Buffer; keyId?: string }
  | { algorithm: 'ed25519'; privateKey: KeyLike | string | Buffer; keyId?: string }

export interface ScopeManifestVerifyOptions {
  algorithm?: ScopeManifestAlgorithm
  secret?: string | Buffer
  publicKey?: KeyLike | string | Buffer
  now?: number
  expectedTenantId?: string
}

export type ScopeManifestVerifyFailureCode =
  | 'malformed'
  | 'algorithm_mismatch'
  | 'missing_key'
  | 'invalid_signature'
  | 'expired'
  | 'not_yet_valid'
  | 'tenant_mismatch'

export type ScopeManifestVerification =
  | { valid: true; payload: ScopeManifestPayload }
  | { valid: false; code: ScopeManifestVerifyFailureCode; reason: string }

/** Deterministic canonical JSON serialization (recursively sorted keys, undefined omitted). */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return '[' + value.map(item => (item === undefined ? 'null' : canonicalJson(item))).join(',') + ']'
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return '{' + entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',') + '}'
}

function manifestSigningBytes(payload: ScopeManifestPayload): Buffer {
  return Buffer.from(`kovo.scope-manifest.v1\n${canonicalJson(payload)}`, 'utf8')
}

export function signScopeManifest(
  payload: ScopeManifestPayload,
  options: ScopeManifestSignOptions,
): SignedScopeManifest {
  const bytes = manifestSigningBytes(payload)
  let signature: string
  if (options.algorithm === 'hmac-sha256') {
    signature = createHmac('sha256', options.secret).update(bytes).digest('base64url')
  } else {
    signature = cryptoSign(null, bytes, options.privateKey).toString('base64url')
  }
  return {
    payload,
    algorithm: options.algorithm,
    ...(options.keyId ? { keyId: options.keyId } : {}),
    signature,
  }
}

export function verifyScopeManifest(
  manifest: unknown,
  options: ScopeManifestVerifyOptions,
): ScopeManifestVerification {
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, code: 'malformed', reason: 'Scope manifest must be a JSON object.' }
  }
  const candidate = manifest as Partial<SignedScopeManifest>
  const payload = candidate.payload
  if (
    !payload ||
    typeof payload !== 'object' ||
    payload.version !== 1 ||
    typeof payload.manifestId !== 'string' || !payload.manifestId.trim() ||
    typeof payload.tenantId !== 'string' || !payload.tenantId.trim() ||
    typeof payload.issuedAt !== 'string' ||
    typeof payload.expiresAt !== 'string' ||
    !payload.policy ||
    typeof payload.policy !== 'object' ||
    !Array.isArray(payload.policy.targetOrigins) ||
    !environmentModes.includes(payload.policy.mode) ||
    typeof candidate.signature !== 'string' || !candidate.signature.trim() ||
    (candidate.algorithm !== 'hmac-sha256' && candidate.algorithm !== 'ed25519')
  ) {
    return { valid: false, code: 'malformed', reason: 'Scope manifest is missing required fields.' }
  }

  if (options.algorithm && candidate.algorithm !== options.algorithm) {
    return {
      valid: false,
      code: 'algorithm_mismatch',
      reason: `Scope manifest algorithm "${candidate.algorithm}" does not match expected "${options.algorithm}".`,
    }
  }

  const bytes = manifestSigningBytes(payload)
  const providedSig = Buffer.from(candidate.signature, 'base64url')
  if (providedSig.length === 0) {
    return { valid: false, code: 'invalid_signature', reason: 'Scope manifest signature is empty.' }
  }

  if (candidate.algorithm === 'hmac-sha256') {
    if (!options.secret) {
      return { valid: false, code: 'missing_key', reason: 'HMAC secret is required to verify scope manifest.' }
    }
    const expected = createHmac('sha256', options.secret).update(bytes).digest()
    if (expected.length !== providedSig.length || !timingSafeEqual(expected, providedSig)) {
      return { valid: false, code: 'invalid_signature', reason: 'Scope manifest HMAC signature verification failed.' }
    }
  } else {
    if (!options.publicKey) {
      return { valid: false, code: 'missing_key', reason: 'Ed25519 public key is required to verify scope manifest.' }
    }
    let ok = false
    try {
      ok = cryptoVerify(null, bytes, options.publicKey, providedSig)
    } catch {
      ok = false
    }
    if (!ok) {
      return { valid: false, code: 'invalid_signature', reason: 'Scope manifest Ed25519 signature verification failed.' }
    }
  }

  const now = options.now ?? Date.now()
  const issuedMs = Date.parse(payload.issuedAt)
  const expiresMs = Date.parse(payload.expiresAt)
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)) {
    return { valid: false, code: 'malformed', reason: 'Scope manifest timestamps must be valid ISO-8601 strings.' }
  }
  if (now < issuedMs - 60_000) {
    return { valid: false, code: 'not_yet_valid', reason: 'Scope manifest issuedAt is in the future.' }
  }
  if (now >= expiresMs) {
    return { valid: false, code: 'expired', reason: `Scope manifest expired at ${payload.expiresAt}.` }
  }
  if (options.expectedTenantId && payload.tenantId !== options.expectedTenantId) {
    return {
      valid: false,
      code: 'tenant_mismatch',
      reason: `Scope manifest tenant "${payload.tenantId}" does not match "${options.expectedTenantId}".`,
    }
  }

  return { valid: true, payload }
}

/** Fail-closed scope evaluation backed by a cryptographically verified scope manifest. */
export function evaluateSignedScopeRequest(
  manifest: unknown,
  verifyOptions: ScopeManifestVerifyOptions,
  request: ScopeRequest,
): ScopeDecision {
  const verified = verifyScopeManifest(manifest, verifyOptions)
  if (!verified.valid) {
    return deny('invalid_scope_manifest', null, verified.reason)
  }
  return evaluateScopeRequest(verified.payload.policy, request)
}
