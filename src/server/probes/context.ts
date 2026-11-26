// Shared differential-probe primitives: types, budgets, benign helpers.
// Extracted from surface-engine.ts without semantic changes so probe families can share them.

import { createHash, randomBytes } from 'node:crypto'
import { BrokerDenied } from '../broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest } from '../broker.ts'
import { universalParamLocations } from '../../replay-spec.ts'
import type { CsrfBind, UniversalParamLocation } from '../../replay-spec.ts'
import type { Store } from '../store.ts'

/** Structural view of the probe runner used by family modules (ProbeRunner implements it). */
export interface ProbeRuntime {
  stopReason: StopReason | null
  send(req: BrokerHttpRequest): Promise<SendResult>
  stage(ex: BrokerExchangeResult): string | undefined
  stop(reason: StopReason): never
}

export type SendResult =
  | { ok: true; ex: BrokerExchangeResult }
  | { ok: false; kind: 'denied' | 'approval' | 'error'; message: string }



export const surfaceParamLocations = universalParamLocations


export type SurfaceParamLocation = UniversalParamLocation



// Shared limits & helpers

export const defaultSurfaceMaxRequests = 150


export const surfaceMaxRequestsCeiling = 300



export type StopReason = 'circuit_open' | 'aborted' | 'budget' | 'approval_required' | 'denied'



const EPHEMERAL_KEY_SUFFIX_RE = /(?:(?:request|trace|correlation|span)[_-]?id|etag|server[_-]?time|request[_-]?time)$/i
const EPHEMERAL_KEY_CONTAINS_RE = /csrf|xsrf|nonce/i

function isWsCode(code: number): boolean {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12 || code === 11
}

function isKeyCharCode(code: number): boolean {
  return (code >= 48 && code <= 57) // 0-9
    || (code >= 65 && code <= 90) // A-Z
    || (code >= 97 && code <= 122) // a-z
    || code === 95 // _
    || code === 36 // $
    || code === 45 // -
}

function isUnquotedValueEndCode(code: number): boolean {
  return isWsCode(code) || code === 44 || code === 59 || code === 38 || code === 125 || code === 60 // , ; & } <
}

function isEphemeralKey(key: string): boolean {
  if (key.length < 4) return false
  const tail = key.length > 16 ? key.slice(-16) : key
  if (EPHEMERAL_KEY_SUFFIX_RE.test(tail)) return true
  return EPHEMERAL_KEY_CONTAINS_RE.test(key)
}

/**
 * Single-pass O(n) replacement for keyed ephemeral scalars (request/trace ids,
 * nonces, ETag-ish values, server clocks) — eliminates regex backtracking on
 * large response bodies while preserving exact normalization semantics.
 */
function maskKeyedEphemeralValues(body: string): string {
  const len = body.length
  let chunks: string[] | null = null
  let copyFrom = 0
  let floor = 0
  let i = 0

  while (i < len) {
    const ch = body.charCodeAt(i)
    if (ch !== 58 && ch !== 61) { // ':' or '='
      i += 1
      continue
    }

    // Walk backwards from separator (bounded by `floor` so every char is scanned at most once).
    let kEnd = i - 1
    while (kEnd >= floor && isWsCode(body.charCodeAt(kEnd))) kEnd -= 1
    if (kEnd >= floor) {
      const q = body.charCodeAt(kEnd)
      if (q === 34 || q === 39) kEnd -= 1 // optional closing " or '
    }
    const keyEnd = kEnd + 1
    let kStart = kEnd
    while (kStart >= floor && isKeyCharCode(body.charCodeAt(kStart))) kStart -= 1
    const keyStart = kStart + 1

    const sepNext = i + 1
    floor = sepNext

    if (keyEnd - keyStart < 4 || !isEphemeralKey(body.slice(keyStart, keyEnd))) {
      i = sepNext
      continue
    }

    // Scan forward past optional whitespace to the value start.
    let valStart = sepNext
    while (valStart < len && isWsCode(body.charCodeAt(valStart))) valStart += 1
    if (valStart >= len) break

    let valEnd = -1
    const vCode = body.charCodeAt(valStart)
    if (vCode === 34) { // "..." with \" escapes
      let p = valStart + 1
      while (p < len) {
        const c = body.charCodeAt(p)
        if (c === 92) { // '\'
          p += 2
          continue
        }
        if (c === 34) {
          valEnd = p + 1
          break
        }
        p += 1
      }
    } else if (vCode === 39) { // '...'
      const close = body.indexOf("'", valStart + 1)
      if (close !== -1) valEnd = close + 1
    }

    if (valEnd < 0) {
      // Unquoted scalar: [^\s,;&}<]+
      let p = valStart
      while (p < len && !isUnquotedValueEndCode(body.charCodeAt(p))) p += 1
      if (p > valStart) valEnd = p
    }

    if (valEnd < 0) {
      i = sepNext
      continue
    }

    if (!chunks) chunks = []
    chunks.push(body.slice(copyFrom, valStart), '"<ephemeral>"')
    copyFrom = valEnd
    floor = valEnd
    i = valEnd
  }

  if (!chunks) return body
  chunks.push(body.slice(copyFrom))
  return chunks.join('')
}

/**
 * Mask values that legitimately rotate between two requests to the same endpoint: request/trace
 * ids, CSRF nonces, ETags, ISO-8601 timestamps and epoch-ms values. Masking is deliberately
 * key- or shape-scoped (never a bare UUID) so resource identifiers still distinguish responses and
 * decoy rejection is unchanged.
 */
export function normalizeEphemeralNoise(body: string): string {
  if (!body) return body
  let out = maskKeyedEphemeralValues(body)
  // ISO-8601 timestamps anywhere (a per-request clock value, not a resource identity).
  out = out.replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})\b/g, '<ephemeral>')
  // Epoch milliseconds (>= 2001) are runtime clocks; smaller numbers stay meaningful.
  out = out.replace(/\b1[5-9]\d{11}\b|\b2\d{12}\b/g, '<ephemeral>')
  return out
}



/** Token-set Jaccard similarity of two response bodies (1 = identical). */
export function responseSimilarity(a: string, b: string): number {
  if (a === b) return 1
  const tok = (s: string): Set<string> => {
    const norm = normalizeEphemeralNoise(s)
    const set = new Set<string>()
    let count = 0
    let start = -1
    for (let i = 0; i <= norm.length && count < 4000; i += 1) {
      const code = i < norm.length ? norm.charCodeAt(i) : 0
      const isAlnum =
        (code >= 48 && code <= 57)
        || (code >= 65 && code <= 90)
        || (code >= 97 && code <= 122)
      if (isAlnum) {
        if (start < 0) start = i
      } else if (start >= 0) {
        set.add(norm.slice(start, i).toLowerCase())
        count += 1
        start = -1
      }
    }
    return set
  }
  const ta = tok(a)
  const tb = tok(b)
  if (ta.size === 0 && tb.size === 0) {
    const max = Math.max(a.length, b.length, 1)
    return Number((1 - Math.abs(a.length - b.length) / max).toFixed(4))
  }
  let inter = 0
  for (const t of ta) if (tb.has(t)) inter += 1
  const union = ta.size + tb.size - inter
  return union === 0 ? 1 : Number((inter / union).toFixed(4))
}



export function clampMaxRequests(requested?: number): number {
  if (requested === undefined || !Number.isFinite(requested)) return defaultSurfaceMaxRequests
  return Math.max(1, Math.min(Math.floor(requested), surfaceMaxRequestsCeiling))
}



export function sha8(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 8)
}



export function randToken(len = 8): string {
  return randomBytes(len).toString('hex').slice(0, len)
}



export function isPrivateOrLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '')
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0.0.0.0') return true
  if (h === 'metadata.google.internal' || h.startsWith('fe80:') || /^fd[0-9a-f]{2}:/.test(h)) return true
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (!m) return false
  const a = Number(m[1])
  const b = Number(m[2])
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}



/** Reduce a redirect Location to a scheme+host+path base (drops per-request code/state parameters). */
export function redirectBaseFromLocation(location: string): string | null {
  if (!location || /[\r\n\0]/.test(location)) return null
  try {
    const u = new URL(location, 'http://kovo.invalid')
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    if (!u.hostname) return null
    return `${u.protocol}//${u.host}${u.pathname || '/'}`
  } catch {
    return null
  }
}



export function setQueryParam(pathAndQuery: string, name: string, value: string): string {
  const url = new URL(pathAndQuery, 'http://kovo.invalid')
  url.searchParams.set(name, value)
  return url.pathname + url.search
}



export const FORBIDDEN_PROTO_KEYS = new Set<string>(['__proto__', 'constructor', 'prototype'])
const MAX_JSON_PATH_DEPTH = 32
const MAX_PARAM_NAME_LENGTH = 256

export function isForbiddenProtoSegment(segment: string): boolean {
  return FORBIDDEN_PROTO_KEYS.has(segment) || FORBIDDEN_PROTO_KEYS.has(segment.trim())
}

/**
 * Returns true if any dot-separated or bracket-delimited segment of a parameter path targets a
 * JavaScript prototype accessor (`__proto__`, `constructor`, `prototype`).
 */
export function hasForbiddenProtoSegment(paramPath: string): boolean {
  if (!paramPath) return false
  for (const dotPart of paramPath.split('.')) {
    if (isForbiddenProtoSegment(dotPart)) return true
    if (dotPart.includes('[') || dotPart.includes(']')) {
      for (const sub of dotPart.split(/[[\]]/)) {
        if (sub && isForbiddenProtoSegment(sub)) return true
      }
    }
  }
  return false
}

export function assertSafeParamName(paramPath: string, contextLabel = 'Parameter'): void {
  if (typeof paramPath !== 'string' || paramPath.length === 0) {
    throw new BrokerDenied(`${contextLabel} name must be a non-empty string.`)
  }
  if (paramPath.length > MAX_PARAM_NAME_LENGTH || /[\r\n\0]/.test(paramPath)) {
    throw new BrokerDenied(`${contextLabel} name is too long or contains invalid control characters.`)
  }
  if (hasForbiddenProtoSegment(paramPath)) {
    throw new BrokerDenied(`${contextLabel} "${paramPath}" contains a forbidden prototype property segment.`)
  }
}

/**
 * Deep-clone untrusted JSON values into null-prototype object containers while stripping any
 * prototype accessor keys (`__proto__`, `constructor`, `prototype`) at every depth.
 */
export function toSafeJsonContainer(value: unknown, depth = 0): unknown {
  if (depth > MAX_JSON_PATH_DEPTH || value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) {
    return value.map(item => toSafeJsonContainer(item, depth + 1))
  }
  const out = Object.create(null) as Record<string, unknown>
  for (const key of Object.keys(value as Record<string, unknown>)) {
    if (isForbiddenProtoSegment(key)) continue
    Object.defineProperty(out, key, {
      value: toSafeJsonContainer((value as Record<string, unknown>)[key], depth + 1),
      writable: true,
      enumerable: true,
      configurable: true,
    })
  }
  return out
}

export function setJsonPath(target: Record<string, unknown>, dotPath: string, value: unknown): void {
  assertSafeParamName(dotPath, 'JSON path')
  const parts = dotPath.split('.')
  if (parts.length > MAX_JSON_PATH_DEPTH) {
    throw new BrokerDenied(`JSON path "${dotPath}" exceeds maximum nesting depth (${MAX_JSON_PATH_DEPTH}).`)
  }
  for (const part of parts) {
    if (!part || isForbiddenProtoSegment(part)) {
      throw new BrokerDenied(`JSON path "${dotPath}" contains an empty or forbidden segment.`)
    }
  }
  let cur: Record<string, unknown> | unknown[] = target
  for (let i = 0; i < parts.length - 1; i += 1) {
    const part = parts[i]!
    const nextIsIndex = /^\d{1,3}$/.test(parts[i + 1] ?? '')
    if (Array.isArray(cur)) {
      const index = /^\d{1,3}$/.test(part) ? Number(part) : 0
      const existing = Object.hasOwn(cur, index) ? cur[index] : undefined
      if (!existing || typeof existing !== 'object') {
        cur[index] = nextIsIndex ? [] : (Object.create(null) as Record<string, unknown>)
      }
      cur = cur[index] as Record<string, unknown> | unknown[]
    } else {
      const existing = Object.hasOwn(cur, part) ? cur[part] : undefined
      if (!existing || typeof existing !== 'object') {
        const nextContainer = nextIsIndex ? [] : (Object.create(null) as Record<string, unknown>)
        Object.defineProperty(cur, part, {
          value: nextContainer,
          writable: true,
          enumerable: true,
          configurable: true,
        })
      }
      cur = cur[part] as Record<string, unknown> | unknown[]
    }
  }
  const last = parts[parts.length - 1]!
  if (Array.isArray(cur)) {
    cur[/^\d{1,3}$/.test(last) ? Number(last) : 0] = value
  } else {
    Object.defineProperty(cur, last, {
      value,
      writable: true,
      enumerable: true,
      configurable: true,
    })
  }
}



export const forbiddenParamHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|x-kovo-trace-id)$/i



export function escapeXmlText(value: string): string {
  // Escape &, <, > while intentionally preserving ' and " so SQLi quotes reach XML parsers intact.
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}



export function escapeXmlAttr(value: string): string {
  return escapeXmlText(value).replace(/"/g, '&quot;').replace(/'/g, '&apos;')
}



export function appendCacheBuster(pathAndQuery: string, gcb: string): string {
  const url = new URL(pathAndQuery, 'http://kovo.invalid')
  url.searchParams.set('_gcb', gcb)
  return url.pathname + url.search
}



export interface UniversalInjectInput {
  pathAndQuery: string
  param: string
  paramLocation: SurfaceParamLocation
  value: string | number | boolean | Record<string, unknown>
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH'
  headers?: Record<string, string>
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  session?: string
  csrfBind?: CsrfBind
  runId?: string
  assignmentId?: string
}



export function injectUniversalParam(input: UniversalInjectInput): InjectedRequest {
  const param = input.param || 'q'
  assertSafeParamName(param, 'Parameter')
  const location = input.paramLocation
  const strVal = typeof input.value === 'string'
    ? input.value
    : (typeof input.value === 'number' || typeof input.value === 'boolean' ? String(input.value) : JSON.stringify(input.value))
  const baseExtras: Partial<InjectedRequest> = {
    ...(input.session ? { session: input.session } : {}),
    ...(input.csrfBind !== undefined ? { csrfBind: input.csrfBind } : {}),
    ...(input.runId ? { runId: input.runId } : {}),
    ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
  }

  if (location === 'json') {
    const body = toSafeJsonContainer(input.jsonBody ?? {}) as Record<string, unknown>
    setJsonPath(body, param, input.value)
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json', ...(input.headers ?? {}) },
      ...baseExtras,
    }
  }

  if (location === 'form') {
    const params = new URLSearchParams()
    if (input.formBody) {
      for (const [k, v] of Object.entries(input.formBody)) {
        if (!hasForbiddenProtoSegment(k)) params.set(k, v)
      }
    } else if (input.jsonBody) {
      for (const [k, v] of Object.entries(input.jsonBody)) {
        if (!hasForbiddenProtoSegment(k) && v !== undefined && v !== null) {
          params.set(k, typeof v === 'object' ? JSON.stringify(v) : String(v))
        }
      }
    }
    if (typeof input.value === 'string' || typeof input.value === 'number' || typeof input.value === 'boolean') {
      params.set(param, String(input.value))
    } else {
      for (const op of Object.keys(input.value)) {
        if (hasForbiddenProtoSegment(op)) continue
        params.set(`${param}[${op}]`, String(input.value[op]))
      }
    }
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(input.headers ?? {}) },
      ...baseExtras,
    }
  }

  if (location === 'path') {
    const qIdx = input.pathAndQuery.indexOf('?')
    const rawPath = qIdx >= 0 ? input.pathAndQuery.slice(0, qIdx) : input.pathAndQuery
    const qs = qIdx >= 0 ? input.pathAndQuery.slice(qIdx) : ''
    const encoded = encodeURIComponent(strVal)
    const tokenPatterns = [`{{val}}`, `{{${param}}}`, `{${param}}`, `:${param}`]
    let nextPath = rawPath
    let replaced = false
    for (const pat of tokenPatterns) {
      if (nextPath.includes(pat)) {
        nextPath = nextPath.split(pat).join(encoded)
        replaced = true
      }
    }
    if (!replaced) {
      nextPath = `${nextPath.replace(/\/+$/, '')}/${encoded}`
    }
    return {
      method: input.method ?? 'GET',
      pathAndQuery: `${nextPath}${qs}`,
      headers: input.headers,
      ...baseExtras,
    }
  }

  if (location === 'header') {
    if (forbiddenParamHeaders.test(param) || /[\r\n\0]/.test(param) || /[\r\n\0]/.test(strVal)) {
      throw new BrokerDenied(`Header parameter "${param}" is forbidden or contains invalid characters.`)
    }
    const headers: Record<string, string> = {}
    if (input.headers) {
      for (const [k, v] of Object.entries(input.headers)) {
        if (!isForbiddenProtoSegment(k)) {
          Object.defineProperty(headers, k, { value: v, writable: true, enumerable: true, configurable: true })
        }
      }
    }
    Object.defineProperty(headers, param, { value: strVal, writable: true, enumerable: true, configurable: true })
    return {
      method: input.method ?? 'GET',
      pathAndQuery: input.pathAndQuery,
      headers,
      ...baseExtras,
    }
  }

  if (location === 'xml') {
    const safeTag = param.replace(/[^A-Za-z0-9_:-]/g, '') || 'param'
    let xmlBody: string
    if (input.xmlTemplate) {
      xmlBody = input.xmlTemplate.replace(/(=["'])\{\{(?:val|[A-Za-z0-9_.-]+)\}\}/g, (_m, prefix: string) =>
        `${prefix}${escapeXmlAttr(strVal)}`,
      )
      xmlBody = xmlBody
        .replaceAll('{{val}}', escapeXmlText(strVal))
        .replaceAll(`{{${param}}}`, escapeXmlText(strVal))
    } else {
      xmlBody = `<?xml version="1.0" encoding="UTF-8"?><request><${safeTag}>${escapeXmlText(strVal)}</${safeTag}></request>`
    }
    const headers: Record<string, string> = { ...(input.headers ?? {}) }
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/xml'
    }
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: xmlBody,
      headers,
      ...baseExtras,
    }
  }

  if (location === 'graphql_var') {
    const baseJson = toSafeJsonContainer(input.jsonBody ?? {}) as Record<string, unknown>
    const rawVars = Object.hasOwn(baseJson, 'variables') ? baseJson.variables : undefined
    const variables = (
      rawVars && typeof rawVars === 'object' && !Array.isArray(rawVars)
        ? rawVars
        : (Object.create(null) as Record<string, unknown>)
    ) as Record<string, unknown>
    setJsonPath(variables, param, input.value)
    const rootVar = param.split('.')[0].replace(/[^A-Za-z0-9_]/g, '') || 'q'
    const query = input.graphqlQuery ??
      (Object.hasOwn(baseJson, 'query') && typeof baseJson.query === 'string' && baseJson.query.trim()
        ? baseJson.query
        : `query($${rootVar}: String) { __typename }`)
    const payload = Object.create(null) as Record<string, unknown>
    for (const k of Object.keys(baseJson)) {
      if (isForbiddenProtoSegment(k)) continue
      Object.defineProperty(payload, k, { value: baseJson[k], writable: true, enumerable: true, configurable: true })
    }
    Object.defineProperty(payload, 'query', { value: query, writable: true, enumerable: true, configurable: true })
    Object.defineProperty(payload, 'variables', { value: variables, writable: true, enumerable: true, configurable: true })
    return {
      method: input.method && input.method !== 'GET' ? input.method : 'POST',
      pathAndQuery: input.pathAndQuery,
      body: JSON.stringify(payload),
      headers: { 'Content-Type': 'application/json', ...(input.headers ?? {}) },
      ...baseExtras,
    }
  }

  // Default: query
  if (typeof input.value === 'object' && input.value !== null) {
    const url = new URL(input.pathAndQuery, 'http://kovo.invalid')
    for (const op of Object.keys(input.value)) {
      if (hasForbiddenProtoSegment(op)) continue
      url.searchParams.set(`${param}[${op}]`, String(input.value[op]))
    }
    return {
      method: input.method ?? 'GET',
      pathAndQuery: url.pathname + url.search,
      headers: input.headers,
      ...(input.method === 'POST' && input.jsonBody ? { body: JSON.stringify(toSafeJsonContainer(input.jsonBody)) } : {}),
      ...baseExtras,
    }
  }
  return {
    method: input.method ?? 'GET',
    pathAndQuery: setQueryParam(input.pathAndQuery, param, String(input.value)),
    headers: input.headers,
    ...(input.method === 'POST' && input.jsonBody ? { body: JSON.stringify(toSafeJsonContainer(input.jsonBody)) } : {}),
    ...baseExtras,
  }
}



// probe_differential: benign, non-destructive control-vs-probe matrices

export type DifferentialProbeClass =
  | 'sqli_boolean' | 'sqli_time_diff' | 'ssti_math' | 'ssrf_canary' | 'nosqli_type'
  | 'path_traversal_benign' | 'graphql_audit' | 'authz_matrix' | 'workflow_invariant'
  | 'xss_context' | 'auth_protocol_audit' | 'xxe_canary' | 'cache_poison_deception' | 'mass_assignment'
  | 'command_injection' | 'csrf_state_change' | 'webhook_signature_bypass' | 'open_redirect_differential'



export interface ProbeDifferentialRequest {
  probeClass: DifferentialProbeClass
  origin: string
  /** Endpoint path+query. authz_matrix requires a {{id}} placeholder. */
  pathAndQuery: string
  /** True when the probe runs under the run-scoped staging tenant contract. */
  staging?: boolean
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** Parameter under test (sqli_boolean, sqli_time_diff, ssti_math, nosqli_type, xss_context) */
  param?: string
  paramLocation?: SurfaceParamLocation
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  baselineValue?: string
  persona?: string
  session?: string
  csrfBind?: CsrfBind
  headers?: Record<string, string>
  /** ssrf_canary: candidate URL/webhook/redirect parameter names */
  ssrfParams?: string[]
  injectHeaders?: boolean
  waitMs?: number
  delayMs?: number
  dialect?: 'mysql' | 'postgres' | 'mssql' | 'sqlite'
  customPayload?: string
  candidateFields?: string[]
  jwksUrl?: string
  testHostPoison?: boolean
  runId?: string
  assignmentId?: string
  storage?: Store
  /** authz_matrix function-level bodies (positional array for server actions or keyed object). */
  functionBody?: unknown
  /** authz_matrix & producer-consumer BOLA lifecycle */
  dependencyId?: string
  producerPath?: string
  producerBody?: Record<string, unknown>
  resourceIds?: string[]
  ownerPersona?: string
  otherPersona?: string
  includeAnonymous?: boolean
  includeHeaderBypass?: boolean
  /** workflow_invariant */
  quantityField?: string
  createPath?: string
  expectedTransitions?: string[]
  /** workflow_invariant: readable route whose JSON state proves the conserved value/bound. */
  workflowReadPath?: string
  /** workflow_invariant: collection list used to resolve a seeded transition target. */
  workflowListPath?: string
  /** workflow_invariant: endpoint template (with its original path placeholder) for the transition. */
  workflowTargetTemplate?: string
  /** workflow_invariant: the same transition must be rejected once the object left its prior state. */
  repeatTransition?: boolean
  /** workflow_invariant: a write carrying a numeric price must not rewrite the server-side catalog. */
  priceTrust?: boolean
  /** workflow_invariant: repeating a settled money mutation must not create a second settlement. */
  repeatMutation?: boolean
  /** graphql_audit schema-driven SDL resolver fuzzer */
  sdl?: string
  /**
   * csrf_state_change: GET route that exposes the mutated value, the JSON field that carries it,
   * and the mutation body field. `controlValue` restores/keeps the baseline state and
   * `expectedValue` is the value only the tokenless probe write should produce.
   */
  readPath?: string
  stateField?: string
  bodyField?: string
  controlValue?: string | number | boolean
  expectedValue?: string | number | boolean
  /** GET routes to visit before a CSRF control write so the session jar holds the token. */
  csrfPrimePaths?: string[]
  /** Ordered read routes for CSRF state proof (detail page, parent, collection list). */
  readPathCandidates?: string[]
  /** Body encodings the endpoint actually accepts; the CSRF probe must not send a mismatched one. */
  bodyEncodings?: Array<'json' | 'form'>
  /** Identifier used to locate the mutated record inside a collection read. */
  stateRecordId?: string
  /** Foreign Origin header for the tokenless CSRF probe (never sent on the control). */
  foreignOrigin?: string
  /** bodyShape hints for CSRF writes that use an action envelope (e.g. {field,value}). */
  writeBody?: Record<string, unknown>
  /** webhook_signature_bypass: signature header/body hints and read-back state. */
  webhookHeader?: string
  webhookBody?: Record<string, unknown>
  readStateField?: string
  readStateValue?: string | number | boolean
  /** open_redirect_differential: benign target and observed trusted prefixes for prefix-bypass variants. */
  redirectBaseTargets?: string[]
  /** authz_matrix write-path BOLA: verify cross-tenant mutation with an owner read-back. */
  writePathRead?: boolean
  /** authz_matrix: non-entitled viewer actor for secret-marker disclosure scanning. */
  secretScan?: boolean
  viewerPersona?: string
  /** Persona user ids used to interpret ownership fields in cross-persona GraphQL reads. */
  ownerUserId?: string
  otherUserId?: string
  testMutations?: boolean
  maxDepth?: number
  maxAliases?: number
  maxRequests?: number
  /** ssrf_canary: loopback origins published by the target's own config/discovery routes. */
  internalTargets?: string[]
  /** graphql_audit: candidate root fields mined from discovered collection nouns (no SDL needed). */
  graphqlRoots?: string[]
  /** graphql_audit: other-actor object ids harvested from each root's own collection route. */
  graphqlSeedsByRoot?: Record<string, string[]>
  /** auth_protocol_audit: body/header field names that carry a token. */
  tokenFields?: string[]
  /** auth_protocol_audit: session-derived scalar claims for a forged token payload. */
  identityClaims?: Record<string, string>
  /** csrf_state_change: create-shaped write that is read back through its detail template. */
  createReadTemplate?: string
  /** cache_poison_deception: a different resource path that is guaranteed to be a cache miss. */
  crossControlPath?: string
  /** cache_poison_deception: resolved owner/other resource ids (diagnostics + spec selection). */
  crossActorSeeds?: { owner?: string; other?: string }
  /** cache_poison_deception: tenant/store markers observed in each actor's own session claims. */
  actorMarkers?: { owner?: string; other?: string }
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}



export interface DifferentialResult {
  probeClass: DifferentialProbeClass
  origin: string
  pathAndQuery: string
  verdict: 'signal' | 'no_signal' | 'inconclusive'
  summary: string
  anomalies: Array<Record<string, unknown>>
  details: Record<string, unknown>
  requestsSent: number
  exchangeIds: string[]
  stoppedReason: StopReason | null
  notes: string[]
  durationMs: number
}



export type InjectedRequest = Pick<
  BrokerHttpRequest,
  'pathAndQuery' | 'body' | 'headers' | 'method' | 'persona' | 'session' | 'csrfBind' | 'authMutation' | 'probeClass' | 'cacheVerify' | 'runId' | 'assignmentId'
>



export function injectParam(req: ProbeDifferentialRequest, value: string | Record<string, unknown>): InjectedRequest {
  const param = req.param ?? 'q'
  const location: SurfaceParamLocation = req.paramLocation ?? (req.method && req.method !== 'GET' ? 'json' : 'query')
  return injectUniversalParam({
    pathAndQuery: req.pathAndQuery,
    param,
    paramLocation: location,
    value,
    method: req.method === 'DELETE' ? 'POST' : req.method,
    headers: req.headers,
    jsonBody: req.jsonBody,
    formBody: req.formBody,
    xmlTemplate: req.xmlTemplate,
    graphqlQuery: req.graphqlQuery,
    session: req.session,
    csrfBind: req.csrfBind,
    runId: req.runId,
    assignmentId: req.assignmentId,
  })
}



export interface DiffContext {
  req: ProbeDifferentialRequest
  origin: string
  runner: ProbeRuntime
  notes: string[]
  anomalies: Array<Record<string, unknown>>
  send: (r: InjectedRequest) => Promise<BrokerExchangeResult | null>
}



export interface DiffOutcome {
  verdict: DifferentialResult['verdict']
  summary: string
  details: Record<string, unknown>
}



export const dbErrorFingerprints: Array<{ dialect: string; pattern: RegExp }> = [
  { dialect: 'postgresql', pattern: /PostgreSQL.*ERROR|unterminated quoted string at or near|syntax error at or near|PSQLException|org\.postgresql|pg_query\(/i },
  { dialect: 'mysql', pattern: /You have an error in your SQL syntax|MySQLSyntaxErrorException|check the manual that corresponds to your (?:MySQL|MariaDB)|SQLSTATE\[42000\]/i },
  { dialect: 'sqlite', pattern: /SQLITE_ERROR|sqlite3\.OperationalError|SQLite\/JDBCDriver|unrecognized token: |near ".{0,40}": syntax error/i },
  { dialect: 'mssql', pattern: /Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|System\.Data\.SqlClient\.SqlException|\[SQL Server\]/i },
  { dialect: 'oracle', pattern: /ORA-\d{5}|Oracle error/i },
]



export function dbErrorDialect(body: string): string | null {
  return dbErrorFingerprints.find(f => f.pattern.test(body))?.dialect ?? null
}



export function extractCreatedIdFromJson(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as unknown
    const scan = (node: unknown, depth: number): string | null => {
      if (depth > 4 || !node || typeof node !== 'object') return null
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 3)) {
          const hit = scan(item, depth + 1)
          if (hit) return hit
        }
        return null
      }
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (/^(?:id|uuid|[a-z0-9_]*_?id)$/i.test(k) && (typeof v === 'string' || typeof v === 'number')) {
          const s = String(v).trim()
          if (s.length >= 1 && s.length <= 128) return s
        }
      }
      for (const v of Object.values(node as Record<string, unknown>)) {
        if (v && typeof v === 'object') {
          const hit = scan(v, depth + 1)
          if (hit) return hit
        }
      }
      return null
    }
    return scan(parsed, 0)
  } catch {
    return null
  }
}



export function jsonRecord(body: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(body) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  } catch { return null }
}



export function scalarMatches(actual: unknown, expected: unknown): boolean {
  if (actual === undefined || actual === null) return false
  if (typeof actual === 'object') return false
  return String(actual) === String(expected)
}



export const csrfStateFields = [
  'name', 'status', 'state', 'title', 'label', 'displayName', 'display_name', 'description',
  'note', 'notes', 'tier', 'plan', 'enabled', 'active', 'value',
]


/** Fields safe to mutate for a write-path authorization proof (lifecycle state is excluded). */
export const bolaWriteFields = [
  'name', 'title', 'label', 'note', 'notes', 'description', 'return_url', 'returnUrl', 'returnTo',
  'amount', 'amountCents', 'amount_cents', 'total', 'tier', 'plan', 'enabled', 'active', 'value',
  'status', 'state',
]



export function firstStateField(record: Record<string, unknown> | null, preferred?: string): string | null {
  if (!record) return null
  if (preferred && !hasForbiddenProtoSegment(preferred) && Object.hasOwn(record, preferred) && typeof record[preferred] !== 'object') {
    return preferred
  }
  return csrfStateFields.find(f => Object.hasOwn(record, f) && typeof record[f] !== 'object') ?? null
}



/**
 * Locate the mutated scalar on a read response: a top-level field, or the matching record inside a
 * collection (`items`, `jobs`, …) when only list routes are exposed.
 */
export function stateViewOf(
  record: Record<string, unknown> | null,
  preferred?: string,
  recordId?: string,
): { field: string; value: unknown } | null {
  if (!record) return null
  const direct = firstStateField(record, preferred)
  if (direct) return { field: direct, value: record[direct] }
  for (const value of Object.values(record)) {
    if (!Array.isArray(value)) continue
    const rows = value.filter((r): r is Record<string, unknown> => Boolean(r) && typeof r === 'object' && !Array.isArray(r))
    const match = recordId
      ? rows.find(r => Object.values(r).some(v => (typeof v === 'string' || typeof v === 'number') && String(v) === recordId))
      : rows[0]
    if (!match) continue
    const field = preferred && !hasForbiddenProtoSegment(preferred) && Object.hasOwn(match, preferred) && typeof match[preferred] !== 'object'
      ? preferred
      : csrfStateFields.find(f => Object.hasOwn(match, f) && typeof match[f] !== 'object')
    if (field) return { field, value: match[field] }
  }
  return null
}



export function stateValueCandidate(current: unknown, field: string): string | number | boolean {
  if (typeof current === 'number' && Number.isFinite(current)) return Math.round(current) + 73_337
  if (typeof current === 'boolean') return !current
  if (/url|uri|link|callback|redirect|return/i.test(field)) return `https://kovo-state-${randToken(8)}.invalid/cb`
  if (/status|state/i.test(field)) return `kovo_state_${randToken(6)}`
  return `kovo_state_${randToken(10)}`
}
