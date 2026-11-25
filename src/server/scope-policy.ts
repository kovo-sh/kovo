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

export const TENANT_TAG_PREFIX = 'guardian-qa-'

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
  /** Run-scoped synthetic-tenant tag (`guardian-qa-<runId>-`). */
  tenantTag?: string | null
  runId?: string | null
}

export type ScopeSurface = 'broker' | 'browser'
export type ScopeHook = 'setup' | 'cleanup'

export interface ScopeRequest {
  origin: string
  method: string
  pathAndQuery: string
  body?: string | null
  headers?: Record<string, string | string[] | undefined>
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

/**
 * Stable route key: identifier-shaped segments collapse to `*`, literals are lowercased and the
 * query string is dropped. Shared by durable approval leases and the `staging_isolated` denylist
 * so "same route" means the same thing everywhere.
 */
export function routePatternForPath(pathAndQuery: string): string {
  let pathname = (pathAndQuery || '/').trim()
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(pathname)) {
    try {
      pathname = new URL(pathname).pathname || '/'
    } catch {
      // Keep the raw string.
    }
  }
  const q = pathname.indexOf('?')
  if (q >= 0) pathname = pathname.slice(0, q)
  const h = pathname.indexOf('#')
  if (h >= 0) pathname = pathname.slice(0, h)
  if (!pathname.startsWith('/')) pathname = '/' + pathname
  pathname = pathname.replace(/\/{2,}/g, '/')
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

const graphqlEndpointPath = /(?:^|\/)graphql(?:\/|$|\?)/i
const graphqlEnvelopeKeys = new Set(['query', 'operationname', 'variables', 'extensions'])
const mutationOrSubscription = /\b(?:mutation|subscription)\b/i

function topLevelJsonKeys(raw: string): string[] | undefined {
  const text = raw.trim()
  if (!text.startsWith('{') || !text.endsWith('}')) return undefined
  let i = 0
  let depth = 0
  let inString = false
  let escaped = false
  const keys: string[] = []
  while (i < text.length) {
    const ch = text[i]!
    if (inString) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      i += 1
      continue
    }
    if (ch === '"') {
      let j = i + 1
      let value = ''
      let closed = false
      while (j < text.length) {
        const c = text[j]!
        if (c === '\\') {
          value += text[j + 1] ?? ''
          j += 2
          continue
        }
        if (c === '"') {
          closed = true
          j += 1
          break
        }
        value += c
        j += 1
      }
      if (!closed) return undefined
      if (depth === 1) {
        let k = j
        while (k < text.length && /\s/.test(text[k]!)) k += 1
        if (text[k] === ':') keys.push(value)
      }
      i = j
      continue
    }
    if (ch === '{' || ch === '[') depth += 1
    else if (ch === '}' || ch === ']') {
      depth -= 1
      if (depth < 0) return undefined
    }
    i += 1
  }
  return depth === 0 ? keys : undefined
}

function parseJsonObject(raw: string): Record<string, unknown> | undefined {
  const trimmed = raw.trim()
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return undefined
  const keys = topLevelJsonKeys(trimmed)
  if (!keys || new Set(keys).size !== keys.length) return undefined
  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined
    return parsed as Record<string, unknown>
  } catch {
    return undefined
  }
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

/**
 * Verified read-only GraphQL: an exact `query` envelope (no mutation/subscription, no extra keys)
 * or a raw `query`/`fragment` document on a GraphQL endpoint. This never guesses from path words.
 */
export function isVerifiedReadOnlyGraphqlQuery(
  pathAndQuery: string,
  body: string | null | undefined,
  headers?: Record<string, string | string[] | undefined>,
): boolean {
  const trimmed = (body ?? '').trim()
  if (!trimmed) return false

  const envelope = parseJsonObject(trimmed)
  if (envelope) {
    if (!Object.prototype.hasOwnProperty.call(envelope, 'query')) return false
    const keys = Object.keys(envelope)
    if (!keys.every(key => graphqlEnvelopeKeys.has(key.toLowerCase()))) return false
    const document = envelope.query
    if (typeof document !== 'string' || !document.trim()) return false
    if (mutationOrSubscription.test(document)) return false
    return true
  }

  const contentType = headerValue(headers, 'content-type').toLowerCase()
  const looksGraphql = contentType.includes('application/graphql') || graphqlEndpointPath.test(pathAndQuery)
  if (!looksGraphql) return false
  if (trimmed.startsWith('{')) return false
  if (!/^\s*(?:query|fragment)\b/i.test(trimmed)) return false
  return !mutationOrSubscription.test(trimmed)
}

const authTokenPath = /(?:^|\/)(?:oauth2?\/token|token|connect\/token|auth\/token|\.well-known\/openid-configuration)(?:$|\/|\?)/i

/** Narrow auth-origin allowance: OIDC/OAuth token exchange (form POST) and discovery GET. */
export function isAuthTokenExchangeRequest(
  pathAndQuery: string,
  method: string,
  headers?: Record<string, string | string[] | undefined>,
): boolean {
  if (!authTokenPath.test(pathAndQuery)) return false
  const upper = method.toUpperCase()
  if (upper === 'GET' || upper === 'HEAD') return true
  if (upper !== 'POST') return false
  const contentType = headerValue(headers, 'content-type').toLowerCase()
  return contentType.includes('application/x-www-form-urlencoded') || contentType.includes('application/json')
}

export function isRouteDenylisted(policy: ScopePolicy, pathAndQuery: string): boolean {
  const entries = policy.routeDenylist ?? []
  if (!entries.length) return false
  const requestPath = routePatternForPath(pathAndQuery)
  for (const entry of entries) {
    const raw = (entry ?? '').trim()
    if (!raw) continue
    const pattern = routePatternForPath(raw.replace(/\*+$/, '') || '/')
    const base = pattern !== '/' && pattern.endsWith('/') ? pattern.slice(0, -1) : pattern
    if (requestPath === base) return true
    if (base !== '/' && requestPath.startsWith(`${base}/`)) return true
    if (base === '/') return true
  }
  return false
}

/** Does the request carry the run-scoped synthetic tenant tag (path, body, or headers)? */
export function requestCarriesTenantTag(request: ScopeRequest, tenantTag: string | null | undefined): boolean {
  const tag = (tenantTag ?? '').trim().toLowerCase()
  if (!tag) return false
  const haystack = [
    request.pathAndQuery,
    request.body ?? '',
    ...Object.entries(request.headers ?? {}).flatMap(([key, value]) => [
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
  const method = (request.method || 'GET').toUpperCase()
  const readOnly = isReadOnlyHttpMethod(method, request.body)
  const surface: ScopeSurface = request.surface ?? 'broker'
  const origin = normalizeScopeOrigin(request.origin) ?? request.origin

  if (role === 'auth') {
    if (request.redirectHop && readOnly) return allow('auth', `IdP redirect transit to ${origin}.`)
    if (isAuthTokenExchangeRequest(request.pathAndQuery, method, request.headers)) {
      return allow('auth', `SSO token exchange with ${origin}.`)
    }
    return deny(
      'auth_origin_active_probe',
      'auth',
      `Origin ${origin} is an authentication/IdP origin; active probing is forbidden (redirects and token exchange only).`,
    )
  }

  if (role === 'asset') {
    if (request.redirectHop && readOnly) return allow('asset', `Asset redirect transit to ${origin}.`)
    if (surface === 'browser' && (method === 'GET' || method === 'HEAD')) {
      return allow('asset', `Passive asset hydration from ${origin}.`)
    }
    return deny(
      'asset_origin_active_probe',
      'asset',
      `Origin ${origin} is a passive asset/CDN origin; only browser GET/HEAD hydration is permitted.`,
    )
  }

  // Target origin.
  if (policy.mode === 'ephemeral_lab') return allow('target')

  if (readOnly) return allow('target')
  if (method === 'POST' && isVerifiedReadOnlyGraphqlQuery(request.pathAndQuery, request.body, request.headers)) {
    return allow('target', 'Verified read-only GraphQL query.')
  }

  if (policy.mode === 'prod_readonly') {
    return deny(
      'readonly_environment',
      'target',
      `prod_readonly refuses state-changing ${method} ${request.pathAndQuery} without an approval prompt.`,
    )
  }

  // staging_isolated
  if (isRouteDenylisted(policy, request.pathAndQuery)) {
    return deny(
      'staging_denylist',
      'target',
      `Route ${request.pathAndQuery} is on the staging denylist and cannot be mutated.`,
    )
  }
  if (request.hook === 'setup' || request.hook === 'cleanup') {
    return allow('target', `Explicit ${request.hook} hook context.`)
  }
  if (requestCarriesTenantTag(request, policy.tenantTag)) {
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
  return Buffer.from(`guardian.scope-manifest.v1\n${canonicalJson(payload)}`, 'utf8')
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
