/** Shared helpers for replay-spec synthesis (target-agnostic; built only from probe observations). */
import { randomBytes } from 'node:crypto'
import { fillPlaceholders, hasPathPlaceholder, needsCsrf, probePathFor } from './benchmark-probes.ts'
import type { Hypothesis, HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

export interface SynthesizedSpec {
  kind: string
  spec: Record<string, unknown>
}

export type Severity = 'high' | 'critical' | 'medium' | 'low'

export function baseFields(env: ProbeEnv, title: string, cwe: string, category: string, severity: Severity, jq: string) {
  return {
    version: 1,
    origin: env.origin,
    title,
    category,
    cwe,
    severity,
    severityRationale: 'Deterministic differential evidence was reproduced by the Zero-LLM verifier.',
    impact: 'An attacker can read or alter data outside their authorization.',
    remediation: 'Validate and parameterize input; enforce server-side authentication, ownership and role checks.',
    recheckInstructions: 'Replay the control and probe requests and compare the responses.',
    assertionsJq: jq,
  }
}

export const jqStr = (v: string) => JSON.stringify(v)
export const is2xx = (stepId: string) => `(.steps.${stepId}.status >= 200 and .steps.${stepId}.status < 300)`

/**
 * A syntactically valid identifier that must not resolve to any real object. Used as a negative
 * control so a route that ignores its identifier (and serves the caller's own session object)
 * cannot be mistaken for object-level authorization failure.
 */
export function bogusIdFor(id: string): string {
  if (/^\d{1,12}$/.test(id)) {
    const n = Number(id)
    if (Number.isSafeInteger(n)) {
      const bumped = n + 9_000_001
      if (String(bumped).length <= 12) return String(bumped)
    }
  }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    const tail = id.slice(-1) === '0' ? '1' : '0'
    return `${id.slice(0, -1)}${tail}`
  }
  if (/^[A-Za-z]+[-_][A-Za-z0-9]+$/.test(id)) {
    const sep = id.includes('_') ? '_' : '-'
    return `${id.split(/[-_]/)[0]}${sep}gx9000001`
  }
  return `gx${randomBytes(8).toString('hex')}`
}
/** Probe body equals control body, or has the same JSON shape and a non-trivial payload. */
export const sameAsControl = (probe: string, control: string) =>
  `((.steps.${probe}.body == .steps.${control}.body) or (((.steps.${probe}.json | keys?) // []) == ((.steps.${control}.json | keys?) // []) and ((.steps.${probe}.body | length) > 2)))`

/** Sibling body parameters observed on the same endpoint, for body-located probes. */
export function siblingBody(h: Hypothesis): Record<string, unknown> | undefined {
  if (h.location !== 'json' && h.location !== 'form' && h.location !== 'graphql_var') return undefined
  const body: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.name === h.param?.name || p.location !== h.location || p.isCsrf) continue
    body[p.name] = 'guardian'
  }
  return body
}

/** Session jar + CSRF binding for a replayed request, mirroring the probe environment. */
export function sessionFields(env: ProbeEnv, h: Hypothesis) {
  return {
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    ...(env.caps.sessionAndCsrf && needsCsrf(h) ? { csrfBind: true } : {}),
  }
}

/** Append a query parameter to a path that may already carry a query string. */
export function appendQuery(pathAndQuery: string, name: string, rawValue: string, encodeValue = true): string {
  const sep = pathAndQuery.includes('?') ? '&' : '?'
  const encodedName = encodeURIComponent(name)
  const encodedValue = encodeValue ? encodeURIComponent(rawValue) : rawValue
  return `${pathAndQuery}${sep}${encodedName}=${encodedValue}`
}

export interface RequestParts {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  pathAndQuery: string
  headers?: Record<string, string>
  jsonBody?: unknown
  textBody?: string
}

const enc = (v: string) => (v.includes('{{') ? v : encodeURIComponent(v))

/** Build one request for a hypothesis with `value` placed in its parameter, using only observed shapes. */
export function requestParts(o: HypothesisOutcome, env: ProbeEnv, value: string): RequestParts | null {
  const h: Hypothesis = o.hyp
  const param = h.param
  if (!param || !h.location) return null
  const siblings: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.name !== param.name && p.location === h.location && !p.isCsrf) siblings[p.name] = 'guardian'
  }
  const path = hasPathPlaceholder(h.endpoint.path) ? fillPlaceholders(h.endpoint.path, '1') : h.endpoint.path
  switch (h.location) {
    case 'query': return { method: 'GET', pathAndQuery: `${path}?${encodeURIComponent(param.name)}=${enc(value)}` }
    case 'path': return { method: 'GET', pathAndQuery: probePathFor(h).replace('{{val}}', enc(value)) }
    case 'header': return { method: 'GET', pathAndQuery: path, headers: { [param.name]: value } }
    case 'json': return { method: h.method === 'GET' ? 'POST' : h.method, pathAndQuery: path, jsonBody: { ...siblings, [param.name]: value } }
    case 'form': {
      const all = { ...siblings, [param.name]: value }
      return {
        method: h.method === 'GET' ? 'POST' : h.method, pathAndQuery: path,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${enc(String(v))}`).join('&'),
      }
    }
    case 'xml': {
      const tpl = o.ctx?.xmlTemplate ?? `<request><${param.name}>{{val}}</${param.name}></request>`
      return { method: 'POST', pathAndQuery: path, headers: { 'Content-Type': 'application/xml' }, textBody: tpl.replaceAll('{{val}}', value) }
    }
    case 'graphql_var': {
      const query = o.ctx?.graphqlQuery
      if (!query) return null
      return { method: 'POST', pathAndQuery: path, jsonBody: { query, variables: { ...siblings, [param.name]: value } } }
    }
    default: return null
  }
}

/** Like requestParts, but allows a structured (non-string) value for JSON / GraphQL-variable bodies. */
export function requestPartsForValue(o: HypothesisOutcome, env: ProbeEnv, value: unknown): RequestParts | null {
  const h: Hypothesis = o.hyp
  const param = h.param
  if (!param || !h.location) return null
  const siblings: Record<string, unknown> = {}
  for (const p of h.endpoint.params) {
    if (p.name !== param.name && p.location === h.location && !p.isCsrf) siblings[p.name] = 'guardian'
  }
  const path = hasPathPlaceholder(h.endpoint.path) ? fillPlaceholders(h.endpoint.path, '1') : h.endpoint.path
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  switch (h.location) {
    case 'query': return { method: 'GET', pathAndQuery: appendQuery(path, param.name, text) }
    case 'header': return { method: 'GET', pathAndQuery: path, headers: { [param.name]: text } }
    case 'json': return { method: h.method === 'GET' ? 'POST' : h.method, pathAndQuery: path, jsonBody: { ...siblings, [param.name]: value } }
    case 'form': {
      const all = { ...siblings, [param.name]: text }
      return {
        method: h.method === 'GET' ? 'POST' : h.method, pathAndQuery: path,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    case 'graphql_var': {
      const query = o.ctx?.graphqlQuery
      if (!query) return null
      return { method: 'POST', pathAndQuery: path, jsonBody: { query, variables: { ...siblings, [param.name]: value } } }
    }
    default: return null
  }
}

export function stepOf(
  env: ProbeEnv, id: string, role: 'control' | 'probe' | 'setup' | 'cleanup', description: string, parts: RequestParts,
  persona: string | null | undefined = env.owner, extra: Record<string, unknown> = {}, expectedStatus?: number[],
) {
  return {
    id, role, description,
    ...(expectedStatus ? { expectedStatus } : {}),
    request: {
      origin: env.origin,
      method: parts.method,
      pathAndQuery: parts.pathAndQuery,
      ...(parts.headers ? { headers: parts.headers } : {}),
      ...(parts.jsonBody !== undefined ? { jsonBody: parts.jsonBody } : {}),
      ...(parts.textBody !== undefined ? { textBody: parts.textBody } : {}),
      ...(persona ? { persona } : {}),
      ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
      followRedirects: false,
      ...extra,
    },
  }
}
